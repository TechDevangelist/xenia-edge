/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2026 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include "xenia/net/system_link.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <iterator>
#include <map>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>

#include "third_party/fmt/include/fmt/format.h"
#include "xenia/base/clock.h"
#include "xenia/base/logging.h"
#include "xenia/base/threading.h"

namespace xe::net {
namespace {

using secure::Address;
using secure::AssociationConfig;
using secure::AssociationEvent;
using secure::Associations;
using secure::Kind;
using secure::Packet;

// XNADDR is ina, inaOnline, wPortOnline, abEnet[6], abOnline[20].
constexpr size_t kEnetOffset = 10;
// SGADDR.platform_type within abOnline.
constexpr size_t kPlatformOffset = 32;
constexpr uint8_t kXbox360Platform = 1;

constexpr size_t kKeyLimit = 8, kPeerLimit = 32;
constexpr size_t kInboxLimit = 64, kPortLimit = 128;
constexpr uint64_t kRepeatWindowMs = 500;
constexpr size_t kRepeatLimit = 512;
constexpr uint16_t kFirstDynamicPort = 49152;
constexpr uint32_t kBroadcast = 0xFFFFFFFF;
// A QoS lookup asks a host this often for its data before giving up.
constexpr unsigned kQosAttempts = 4;
constexpr uint64_t kQosRetryMs = 400;
// First probes of pairs from other consoles wait this long for the second.
constexpr auto kQosPairWindow = std::chrono::seconds(2);
constexpr size_t kQosPairLimit = 256;

uint64_t Now() { return Clock::QueryHostUptimeMillis(); }

uint32_t Ina(const Address& address) {
  return uint32_t(address[0]) << 24 | uint32_t(address[1]) << 16 |
         uint32_t(address[2]) << 8 | address[3];
}

secure::Mac Enet(const Address& address) {
  secure::Mac mac;
  std::copy_n(address.begin() + kEnetOffset, mac.size(), mac.begin());
  return mac;
}

std::string MacText(const secure::Mac& mac) {
  return fmt::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", mac[0],
                     mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// System Link keys keep the top three bits clear. Online peer keys share the
// registry but never get an association.
bool ValidKeyId(const KeyId& id) {
  return !(id[0] & 0xE0) || (id[0] & 0xF0) == 0x80;
}

struct Datagram {
  Endpoint source;
  std::vector<uint8_t> data;
};

struct Inbox {
  mutable std::mutex mutex;
  std::condition_variable changed;
  std::deque<Datagram> packets;
  std::function<void()> ready;
  // What every call fails with once the port is closed or the LAN is down.
  uint32_t error = 0;

  void Push(Datagram packet) {
    std::function<void()> notify;
    {
      std::lock_guard lock(mutex);
      if (error || packets.size() >= kInboxLimit) {
        return;
      }
      if (packets.empty()) {
        notify = ready;
      }
      packets.push_back(std::move(packet));
    }
    changed.notify_all();
    if (notify) {
      notify();
    }
  }

  void Fail(uint32_t code, bool wake) {
    std::function<void()> notify;
    {
      std::lock_guard lock(mutex);
      if (!error) {
        error = code;
      }
      packets.clear();
      notify = std::exchange(ready, nullptr);
    }
    changed.notify_all();
    if (wake && notify) {
      notify();
    }
  }

  void Retire(uint32_t address) {
    std::lock_guard lock(mutex);
    std::erase_if(packets, [&](const Datagram& packet) {
      return packet.source.address == address;
    });
  }
};

}  // namespace

struct SystemLink::State {
  struct QosListen {
    bool enabled = false;
    std::vector<uint8_t> data;
  };
  // A lookup target still waiting for its host to answer.
  struct QosProbing {
    size_t target = 0;
    Address address{};
    KeyId id{};
    secure::RegistrationKeys keys;
    unsigned attempts = 0;
    uint64_t next_ms = 0;
  };
  struct QosLookup {
    secure::Block nonce{};
    std::vector<QosProbing> probing;
    std::function<void(size_t, const QosResult&)> done;
  };
  // A console's first probe of a pair, by prober, nonce, target and sequence.
  using QosPair = std::tuple<secure::Mac, secure::Block, uint16_t, uint8_t>;

  std::shared_ptr<secure::PacketTransport> transport;
  const Address identity;
  const Key broadcast_auth;
  // Guards everything below.
  std::mutex mutex;
  std::map<KeyId, Key> keys;
  std::map<uint32_t, Peer> peers;
  uint32_t next_address = 1;
  Associations associations;
  std::map<std::pair<uint16_t, bool>, std::weak_ptr<Inbox>> ports;
  uint16_t next_port = kFirstDynamicPort;
  std::map<KeyId, QosListen> qos_listens;
  std::map<uint32_t, QosLookup> qos_lookups;
  std::map<QosPair, std::chrono::steady_clock::time_point> qos_pairs;
  std::vector<secure::Frame> qos_outbound;
  // Hashes of recently received frames with their arrival time, oldest first.
  // Only the worker touches them.
  std::deque<std::pair<uint64_t, size_t>> recent;
  bool reported_repeat = false;
  std::jthread worker;

  State(std::shared_ptr<secure::PacketTransport> io, AssociationConfig config)
      : transport(std::move(io)),
        identity(config.identity),
        broadcast_auth(config.broadcast.authentication),
        associations(WithCredential(std::move(config), keys)) {
    worker = std::jthread([this](std::stop_token stop) { Run(stop); });
  }

  // Associations only ask for a credential with mutex held.
  static AssociationConfig WithCredential(AssociationConfig config,
                                          const std::map<KeyId, Key>& keys) {
    config.credential = [&keys](const KeyId& id) -> std::optional<Key> {
      auto found = keys.find(id);
      return found != keys.end() ? std::optional(found->second) : std::nullopt;
    };
    return config;
  }

  // Only this thread sends and receives on the transport so calls that queue
  // frames wake it.
  void Run(std::stop_token stop) {
    threading::set_name("XNet System Link");
    while (!stop.stop_requested()) {
      std::vector<uint8_t> wire;
      const bool received =
          transport->Receive(wire, 25) && !Repeat(wire, Now());
      std::vector<secure::Frame> outbound;
      {
        std::lock_guard lock(mutex);
        if (!transport->healthy()) {
          XELOGE("System Link packet transport lost");
          associations.Reset();
          peers.clear();
          CloseInboxes(kWsaNetworkDown);
          FinishQos();
          return;
        }
        if (received) {
          if (auto frame = secure::DecodeFrame(wire)) {
            if (!ReceiveQos(*frame)) {
              associations.Receive(*frame, Now());
            }
          }
        }
        associations.Tick(Now());
        TickQos(Now());
        Deliver();
        outbound = associations.TakeOutbound();
        std::move(qos_outbound.begin(), qos_outbound.end(),
                  std::back_inserter(outbound));
        qos_outbound.clear();
      }
      for (const auto& frame : outbound) {
        if (auto encoded = secure::EncodeFrame(frame)) {
          if (transport->Send(*encoded) != static_cast<int>(encoded->size())) {
            XELOGE("System Link packet transmission failed");
          }
        }
      }
    }
  }

  // Copies of a frame can arrive through several subnets or a bridge. The
  // protocol never sends the same frame twice so only such copies repeat.
  bool Repeat(std::span<const uint8_t> wire, uint64_t now) {
    const size_t hash = std::hash<std::string_view>()(std::string_view(
        reinterpret_cast<const char*>(wire.data()), wire.size()));
    while (!recent.empty() && now - recent.front().first > kRepeatWindowMs) {
      recent.pop_front();
    }
    if (std::any_of(recent.begin(), recent.end(),
                    [&](const auto& entry) { return entry.second == hash; })) {
      if (!reported_repeat) {
        reported_repeat = true;
        XELOGI("System Link: dropping copies of frames that arrived twice");
      }
      return true;
    }
    if (recent.size() >= kRepeatLimit) {
      recent.pop_front();
    }
    recent.emplace_back(now, hash);
    return false;
  }

  // The rest expects mutex held.

  // QoS records travel outside any association.
  bool ReceiveQos(const secure::Frame& frame) {
    const auto header = secure::PeekQos(frame.payload);
    if (!header) {
      return false;
    }
    if (header->reply) {
      QosReplied(frame, *header);
    } else {
      QosProbed(frame, *header);
    }
    return true;
  }

  void QosProbed(const secure::Frame& frame, const secure::QosHeader& header) {
    auto listen = qos_listens.find(header.id);
    auto key = keys.find(header.id);
    if (listen == qos_listens.end() || key == keys.end()) {
      return;
    }
    const auto registration =
        secure::DeriveRegistration(broadcast_auth, header.id, key->second);
    const auto probe = secure::DecodeQosProbe(registration, frame.payload);
    // System Link probes name the host by its MAC.
    if (!probe || Enet(probe->address) != Enet(identity)) {
      return;
    }
    secure::QosReply reply;
    reply.nonce = probe->nonce;
    reply.target = probe->target;
    reply.sequence = probe->sequence;
    if ((probe->flags & secure::kQosProbeDataRequest) ||
        !listen->second.enabled) {
      reply.flags = secure::kQosReplyData;
      if (!listen->second.enabled) {
        reply.flags |= secure::kQosReplyDisabled;
      }
      reply.data = listen->second.data;
      SendQos(frame.source, registration, reply);
      XELOGD("System Link QoS: sent {} bytes to {}", reply.data.size(),
             MacText(frame.source));
      return;
    }
    // Both replies of a timed pair leave once its second probe arrives.
    const auto now = std::chrono::steady_clock::now();
    std::erase_if(qos_pairs, [&](const auto& entry) {
      return now - entry.second > kQosPairWindow;
    });
    const QosPair pair{frame.source, probe->nonce, probe->target,
                       probe->sequence};
    if (!(probe->flags & secure::kQosProbeSecond)) {
      if (qos_pairs.size() < kQosPairLimit) {
        qos_pairs[pair] = now;
      }
      return;
    }
    auto first = qos_pairs.find(pair);
    if (first == qos_pairs.end()) {
      return;
    }
    const uint32_t gap = uint32_t(std::clamp<int64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(now -
                                                              first->second)
            .count(),
        1, UINT32_MAX));
    qos_pairs.erase(first);
    reply.delay = gap;
    SendQos(frame.source, registration, reply);
    reply.flags = secure::kQosReplySecond;
    if (listen->second.data.empty()) {
      reply.flags |= secure::kQosReplyNoData;
    }
    reply.delay = 0;
    reply.gap = gap;
    SendQos(frame.source, registration, reply);
    XELOGD("System Link QoS: timed probes from {}, {} us apart",
           MacText(frame.source), gap);
  }

  void SendQos(const secure::Mac& destination,
               const secure::RegistrationKeys& registration,
               const secure::QosReply& reply) {
    if (auto payload = secure::EncodeQosReply(registration, reply)) {
      qos_outbound.push_back(
          {transport->identity(), destination, false, std::move(*payload)});
    }
  }

  void QosReplied(const secure::Frame& frame, const secure::QosHeader& header) {
    for (auto lookup = qos_lookups.begin(); lookup != qos_lookups.end();
         ++lookup) {
      if (lookup->second.nonce != header.nonce) {
        continue;
      }
      auto& probing = lookup->second.probing;
      auto target = std::find_if(probing.begin(), probing.end(),
                                 [&](const QosProbing& entry) {
                                   return entry.target == header.target;
                                 });
      // Hosts answer from their own MAC.
      if (target == probing.end() || Enet(target->address) != frame.source) {
        return;
      }
      auto reply = secure::DecodeQosReply(target->keys, frame.payload);
      // Only data replies answer what this console asks.
      if (!reply || !(reply->flags & secure::kQosReplyData) ||
          reply->data.size() > kQosDataLimit) {
        return;
      }
      QosResult result;
      result.contacted = true;
      result.disabled = reply->flags & secure::kQosReplyDisabled;
      result.data = std::move(reply->data);
      XELOGD("System Link QoS: {} answered with {} bytes{}",
             MacText(frame.source), result.data.size(),
             result.disabled ? ", not listening" : "");
      const size_t index = target->target;
      probing.erase(target);
      lookup->second.done(index, result);
      if (probing.empty()) {
        qos_lookups.erase(lookup);
      }
      return;
    }
  }

  void TickQos(uint64_t now) {
    for (auto lookup = qos_lookups.begin(); lookup != qos_lookups.end();) {
      auto& probing = lookup->second.probing;
      for (auto target = probing.begin(); target != probing.end();) {
        if (now < target->next_ms) {
          ++target;
          continue;
        }
        if (target->attempts == kQosAttempts) {
          XELOGD("System Link QoS: no answer from {}",
                 MacText(Enet(target->address)));
          const size_t index = target->target;
          target = probing.erase(target);
          lookup->second.done(index, {});
          continue;
        }
        secure::QosProbe probe;
        probe.nonce = lookup->second.nonce;
        probe.target = uint16_t(target->target);
        probe.sequence = uint8_t(++target->attempts);
        probe.flags = secure::kQosProbeDataRequest;
        probe.id = target->id;
        probe.address = target->address;
        qos_outbound.push_back({transport->identity(), Enet(target->address),
                                false,
                                secure::EncodeQosProbe(target->keys, probe)});
        target->next_ms = now + kQosRetryMs;
        ++target;
      }
      lookup = probing.empty() ? qos_lookups.erase(lookup) : std::next(lookup);
    }
  }

  // Ends every lookup without an answer.
  void FinishQos() {
    auto lookups = std::move(qos_lookups);
    qos_lookups.clear();
    for (auto& [tag, lookup] : lookups) {
      for (const auto& target : lookup.probing) {
        lookup.done(target.target, {});
      }
    }
  }

  QosResult LocalQos(const KeyId& id) const {
    QosResult result;
    auto listen = qos_listens.find(id);
    if (listen != qos_listens.end()) {
      result.contacted = true;
      result.disabled = !listen->second.enabled;
      result.data = listen->second.data;
    }
    return result;
  }

  uint32_t Map(const Address& address, const KeyId& id, uint32_t& secure) {
    secure = 0;
    const uint32_t ina = Ina(address);
    if (!keys.contains(id) || !ina || ina == kBroadcast) {
      return kWsaInvalid;
    }
    for (const auto& [token, peer] : peers) {
      if (peer.key_id == id && peer.address == address) {
        secure = token;
        return 0;
      }
    }
    if (peers.size() >= kPeerLimit) {
      return kWsaNoBuffers;
    }
    // 0.0.0.0/8 is reserved and cannot alias a physical LAN endpoint.
    do {
      secure = next_address++;
      if (next_address >= 0x01000000) {
        next_address = 1;
      }
    } while (peers.contains(secure));
    peers[secure] = Peer{address, id, secure};
    return 0;
  }

  void Retire(const Address& address, const KeyId& id) {
    std::erase_if(peers, [&](const auto& entry) {
      if (entry.second.key_id != id || entry.second.address != address) {
        return false;
      }
      for (auto& [port, weak] : ports) {
        if (auto inbox = weak.lock()) {
          inbox->Retire(entry.first);
        }
      }
      return true;
    });
  }

  void CloseInboxes(uint32_t error) {
    for (auto& [port, weak] : ports) {
      if (auto inbox = weak.lock()) {
        inbox->Fail(error, true);
      }
    }
  }

  void Deliver() {
    for (auto& event : associations.TakeEvents()) {
      const bool discovery = event.packet.kind == Kind::Discovery;
      uint32_t source = 0;
      if (discovery) {
        // Discovery comes from the virtual 0.0.0.1, so it gets no mapping.
        source = 1;
      } else if (event.type == AssociationEvent::Type::Retired) {
        Retire(event.peer, event.id);
        continue;
      } else if (Map(event.peer, event.id, source) ||
                 event.type == AssociationEvent::Type::Connected) {
        // Mapping on Connected shows the peer to the side that accepted.
        continue;
      }
      const bool vdp = event.packet.kind == Kind::Vdp;
      if (!discovery) {
        XELOGD(
            "System Link datagram received: vdp={}, encrypted={}, clear={}, "
            "source port={}, destination port={}",
            vdp, event.packet.encrypted.size(), event.packet.clear.size(),
            event.packet.source_port, event.packet.destination_port);
      }
      auto data =
          vdp ? secure::ToGuestVdp(event.packet) : event.packet.encrypted;
      if (vdp && data.empty()) {
        continue;
      }
      for (auto it = ports.begin(); it != ports.end();) {
        auto inbox = it->second.lock();
        if (!inbox) {
          it = ports.erase(it);
          continue;
        }
        if (it->first.first == event.packet.destination_port &&
            (discovery || it->first.second == vdp)) {
          inbox->Push({{source, event.packet.source_port}, data});
        }
        ++it;
      }
    }
  }
};

class SystemLink::Port final : public SystemLinkPort {
 public:
  Port(std::shared_ptr<State> state, std::shared_ptr<Inbox> inbox,
       uint16_t port, bool vdp)
      : state_(std::move(state)),
        inbox_(std::move(inbox)),
        port_(port),
        vdp_(vdp) {}
  ~Port() override { Close(); }

  uint16_t port() const override { return port_; }

  // What a blocking Winsock call returns when another thread closes its
  // socket.
  void Close() override { inbox_->Fail(kWsaInterrupted, false); }

  size_t PendingBytes() const override {
    std::lock_guard lock(inbox_->mutex);
    return inbox_->packets.empty() ? 0 : inbox_->packets.front().data.size();
  }

  bool Readable() const override {
    std::lock_guard lock(inbox_->mutex);
    return inbox_->error || !inbox_->packets.empty();
  }

  void SetReadyCallback(std::function<void()> callback) override {
    bool readable;
    {
      std::lock_guard lock(inbox_->mutex);
      inbox_->ready = callback;
      readable = inbox_->error || !inbox_->packets.empty();
    }
    if (readable && callback) {
      callback();
    }
  }

  int Send(Endpoint destination, std::span<const uint8_t> bytes,
           uint32_t& error) override {
    {
      std::lock_guard lock(inbox_->mutex);
      if (inbox_->error) {
        error = inbox_->error;
        return -1;
      }
    }
    std::lock_guard lock(state_->mutex);
    if (!state_->transport->healthy()) {
      error = kWsaNetworkDown;
      return -1;
    }
    Packet packet;
    bool sent;
    if (destination.address == kBroadcast) {
      packet.source_port = port_;
      packet.destination_port = destination.port;
      packet.encrypted.assign(bytes.begin(), bytes.end());
      sent = state_->associations.Discover(std::move(packet));
    } else {
      auto found = state_->peers.find(destination.address);
      if (found == state_->peers.end()) {
        error = kWsaHostUnreachable;
        return -1;
      }
      if (vdp_) {
        auto converted = secure::FromGuestVdp(port_, destination.port, bytes);
        if (!converted) {
          error = kWsaInvalid;
          return -1;
        }
        packet = std::move(*converted);
      } else {
        packet.source_port = port_;
        packet.destination_port = destination.port;
        packet.encrypted.assign(bytes.begin(), bytes.end());
      }
      sent =
          state_->associations.Send(found->second.address, found->second.key_id,
                                    std::move(packet), Now());
      XELOGD(
          "System Link datagram sent: vdp={}, bytes={}, source port={}, "
          "destination port={}, accepted={}",
          vdp_, bytes.size(), port_, destination.port, sent);
    }
    if (!sent) {
      error = kWsaMessageSize;
      return -1;
    }
    state_->transport->Wake();
    return static_cast<int>(bytes.size());
  }

  int Receive(std::span<uint8_t> buffer, bool peek, Endpoint& source,
              uint32_t wait_ms, uint32_t& error) override {
    std::unique_lock lock(inbox_->mutex);
    auto ready = [&] { return inbox_->error || !inbox_->packets.empty(); };
    if (wait_ms == kWaitForever) {
      inbox_->changed.wait(lock, ready);
    } else if (wait_ms) {
      inbox_->changed.wait_for(lock, std::chrono::milliseconds(wait_ms), ready);
    }
    if (inbox_->packets.empty()) {
      error = inbox_->error ? inbox_->error
              : wait_ms     ? kWsaTimedOut
                            : kWsaWouldBlock;
      return -1;
    }
    const auto& packet = inbox_->packets.front();
    source = packet.source;
    const size_t size = std::min(buffer.size(), packet.data.size());
    std::copy_n(packet.data.begin(), size, buffer.begin());
    const bool truncated = size < packet.data.size();
    if (!peek) {
      inbox_->packets.pop_front();
    }
    if (truncated) {
      error = kWsaMessageSize;
      return -1;
    }
    return static_cast<int>(size);
  }

 private:
  std::shared_ptr<State> state_;
  std::shared_ptr<Inbox> inbox_;
  uint16_t port_;
  bool vdp_;
};

SystemLink::SystemLink(uint32_t address,
                       std::shared_ptr<secure::PacketTransport> transport,
                       AssociationConfig association) {
  for (size_t i = 0; i < 4; ++i) {
    identity_[i] = uint8_t(address >> (24 - 8 * i));
  }
  const auto mac = transport->identity();
  std::copy(mac.begin(), mac.end(), identity_.begin() + kEnetOffset);
  // Offline, but SGADDR still names the console platform.
  identity_[kPlatformOffset] = kXbox360Platform;
  association.identity = identity_;
  state_ =
      std::make_shared<State>(std::move(transport), std::move(association));
}

SystemLink::~SystemLink() {
  // Bound ports keep the state alive, but nothing may run it any more.
  state_->worker.request_stop();
  state_->transport->Wake();
  state_->worker.join();
  {
    // Lookups end without writing results once the System Link is gone.
    std::lock_guard lock(state_->mutex);
    state_->qos_lookups.clear();
  }
  Reset();
}

uint64_t SystemLink::MachineId(const Address& address) {
  uint64_t id = 0;
  for (size_t i = 0; i < 6; ++i) {
    id = (id << 8) | address[kEnetOffset + i];
  }
  return 0xFA00000000000000ull | id;
}

void SystemLink::CreateKey(KeyId& id, Key& key) {
  Random(id);
  // XNKID_SYSTEM_LINK.
  id[0] &= 0x0F;
  Random(key);
}

uint32_t SystemLink::RegisterKey(const KeyId& id, const Key& key) {
  std::lock_guard lock(state_->mutex);
  if (!ValidKeyId(id)) {
    return kWsaInvalid;
  }
  if (state_->keys.contains(id)) {
    return kWsaAlready;
  }
  if (state_->keys.size() >= kKeyLimit) {
    return kWsaNoBuffers;
  }
  state_->keys.emplace(id, key);
  return 0;
}

uint32_t SystemLink::UnregisterKey(const KeyId& id) {
  std::lock_guard lock(state_->mutex);
  if (!state_->keys.erase(id)) {
    return kWsaInvalid;
  }
  state_->qos_listens.erase(id);
  // Retiring the associations also drops the datagrams they queued.
  state_->associations.Unregister(id, Now());
  state_->transport->Wake();
  state_->Deliver();
  std::erase_if(state_->peers,
                [&](const auto& entry) { return entry.second.key_id == id; });
  return 0;
}

bool SystemLink::GetKey(const KeyId& id, Key& key) const {
  key = {};
  std::lock_guard lock(state_->mutex);
  auto found = state_->keys.find(id);
  if (found == state_->keys.end()) {
    return false;
  }
  key = found->second;
  return true;
}

uint32_t SystemLink::Map(const Address& address, const KeyId& id,
                         uint32_t& secure) {
  std::lock_guard lock(state_->mutex);
  return state_->Map(address, id, secure);
}

uint32_t SystemLink::Reverse(uint32_t secure, Address& address,
                             KeyId& id) const {
  address = {};
  id = {};
  std::lock_guard lock(state_->mutex);
  auto found = state_->peers.find(secure);
  if (found == state_->peers.end()) {
    return kWsaInvalid;
  }
  address = found->second.address;
  id = found->second.key_id;
  return 0;
}

uint32_t SystemLink::Unmap(uint32_t secure) {
  std::lock_guard lock(state_->mutex);
  auto found = state_->peers.find(secure);
  if (found == state_->peers.end()) {
    return kWsaInvalid;
  }
  const Peer peer = found->second;
  // Retiring the association removes the mapping and drops what it queued, a
  // peer that never connected has neither.
  state_->associations.Close(peer.address, peer.key_id, Now());
  state_->transport->Wake();
  state_->Deliver();
  state_->peers.erase(secure);
  return 0;
}

uint32_t SystemLink::Connect(uint32_t secure) {
  std::lock_guard lock(state_->mutex);
  auto found = state_->peers.find(secure);
  if (found == state_->peers.end()) {
    return kWsaInvalid;
  }
  if (!state_->transport->healthy()) {
    return kWsaNetworkDown;
  }
  if (!state_->associations.Connect(found->second.address, found->second.key_id,
                                    Now())) {
    return kWsaNoBuffers;
  }
  state_->transport->Wake();
  return 0;
}

uint32_t SystemLink::ConnectStatus(uint32_t secure) const {
  std::lock_guard lock(state_->mutex);
  auto found = state_->peers.find(secure);
  if (found == state_->peers.end() || !state_->transport->healthy()) {
    return 0;
  }
  return static_cast<uint32_t>(
      state_->associations.Status(found->second.address, found->second.key_id));
}

std::vector<Peer> SystemLink::peers() const {
  std::lock_guard lock(state_->mutex);
  std::vector<Peer> peers;
  for (const auto& [secure, peer] : state_->peers) {
    peers.push_back(peer);
  }
  return peers;
}

uint32_t SystemLink::QosListen(const KeyId& id, uint32_t flags,
                               std::span<const uint8_t> data) {
  std::lock_guard lock(state_->mutex);
  if (!state_->keys.contains(id)) {
    return kWsaInvalid;
  }
  if (flags & kQosListenRelease) {
    state_->qos_listens.erase(id);
    return 0;
  }
  auto& listen = state_->qos_listens[id];
  if (flags & kQosListenSetData) {
    listen.data.assign(data.begin(),
                       data.begin() + std::min(data.size(), kQosDataLimit));
  }
  if (flags & (kQosListenEnable | kQosListenDisable)) {
    listen.enabled = flags & kQosListenEnable;
  }
  return 0;
}

void SystemLink::QosLookup(
    uint32_t tag, std::vector<QosTarget> targets,
    std::function<void(size_t target, const QosResult& result)> done) {
  std::lock_guard lock(state_->mutex);
  State::QosLookup lookup;
  Random(lookup.nonce);
  const auto mac = Enet(state_->identity);
  for (size_t i = 0; i < targets.size(); ++i) {
    const auto& target = targets[i];
    const auto host = Enet(target.address);
    if (host == mac) {
      done(i, state_->LocalQos(target.id));
      continue;
    }
    // Only System Link keys cross the LAN.
    // Replies name targets in 16 bits.
    if ((target.id[0] & 0xE0) || host == secure::Mac{} || i > 0xFFFF ||
        !state_->transport->healthy()) {
      done(i, {});
      continue;
    }
    lookup.probing.push_back(
        {i, target.address, target.id,
         secure::DeriveRegistration(state_->broadcast_auth, target.id,
                                    target.key)});
  }
  if (lookup.probing.empty()) {
    return;
  }
  lookup.done = std::move(done);
  state_->qos_lookups[tag] = std::move(lookup);
  state_->transport->Wake();
}

void SystemLink::CancelQos(uint32_t tag) {
  std::lock_guard lock(state_->mutex);
  state_->qos_lookups.erase(tag);
}

std::unique_ptr<SystemLinkPort> SystemLink::Bind(uint16_t port, bool vdp,
                                                 uint32_t& error) {
  std::lock_guard lock(state_->mutex);
  if (!state_->transport->healthy()) {
    error = kWsaNetworkDown;
    return nullptr;
  }
  std::erase_if(state_->ports, [](const auto& entry) {
    auto inbox = entry.second.lock();
    if (!inbox) {
      return true;
    }
    std::lock_guard lock(inbox->mutex);
    return inbox->error != 0;
  });
  if (state_->ports.size() >= kPortLimit) {
    error = kWsaNoBuffers;
    return nullptr;
  }
  if (!port) {
    do {
      port = state_->next_port++;
      if (!state_->next_port) {
        state_->next_port = kFirstDynamicPort;
      }
    } while (state_->ports.contains({port, vdp}));
  } else if (state_->ports.contains({port, vdp})) {
    error = kWsaAddressInUse;
    return nullptr;
  }
  auto inbox = std::make_shared<Inbox>();
  state_->ports[{port, vdp}] = inbox;
  return std::make_unique<Port>(state_, std::move(inbox), port, vdp);
}

void SystemLink::Reset() {
  std::lock_guard lock(state_->mutex);
  state_->associations.Reset();
  state_->keys.clear();
  state_->peers.clear();
  state_->qos_listens.clear();
  state_->FinishQos();
  state_->qos_pairs.clear();
  state_->qos_outbound.clear();
  state_->CloseInboxes(kWsaNetworkDown);
}

}  // namespace xe::net

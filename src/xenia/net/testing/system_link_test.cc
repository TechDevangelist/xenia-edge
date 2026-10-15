/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2026 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

#include "xenia/net/system_link.h"
#include "xenia/net/xnet_tcp.h"

#include "third_party/catch/include/catch.hpp"

namespace xe::net::secure::test {
namespace {

struct Wire {
  std::mutex mutex;
  std::condition_variable changed;
  std::deque<std::vector<uint8_t>> frames[2];
};

class TestTransport : public PacketTransport {
 public:
  TestTransport(std::shared_ptr<Wire> wire, unsigned side)
      : wire_(std::move(wire)), side_(side) {}

  Mac identity() const override {
    return {2, 17, 34, 51, 68, uint8_t(side_ + 1)};
  }
  uint32_t mtu() const override { return 1500; }
  bool healthy() const override { return healthy_; }

  void Disconnect() {
    healthy_ = false;
    wire_->changed.notify_all();
  }

  // Delivers every frame sent from now on twice.
  void Duplicate() { duplicate_ = true; }

  // Receives from now on ignore their timeout, only a frame, Wake() or
  // Disconnect() ends them.
  void Stall() { stall_ = true; }
  int stalled() const { return stalled_; }

  // Sends wait from now on until Release() so frames pile up in the System
  // Link meanwhile.
  void Hold() {
    std::lock_guard lock(wire_->mutex);
    hold_ = true;
  }
  void Release() {
    {
      std::lock_guard lock(wire_->mutex);
      hold_ = false;
    }
    wire_->changed.notify_all();
  }
  int held() const { return held_; }

  void Wake() override {
    {
      std::lock_guard lock(wire_->mutex);
      woken_ = true;
    }
    wire_->changed.notify_all();
  }

  int Send(std::span<const uint8_t> bytes) override {
    std::unique_lock lock(wire_->mutex);
    if (hold_) {
      ++held_;
      wire_->changed.wait(lock, [&] { return !hold_ || !healthy_; });
    }
    for (int i = duplicate_ ? 2 : 1; i; --i) {
      wire_->frames[1 - side_].emplace_back(bytes.begin(), bytes.end());
    }
    wire_->changed.notify_all();
    return static_cast<int>(bytes.size());
  }

  bool Receive(std::vector<uint8_t>& bytes, uint32_t timeout_ms) override {
    std::unique_lock lock(wire_->mutex);
    auto ready = [&] {
      return !healthy_ || woken_ || !wire_->frames[side_].empty();
    };
    if (stall_) {
      ++stalled_;
      wire_->changed.wait(lock, ready);
    } else {
      wire_->changed.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                              ready);
    }
    woken_ = false;
    if (!healthy_ || wire_->frames[side_].empty()) {
      return false;
    }
    bytes = std::move(wire_->frames[side_].front());
    wire_->frames[side_].pop_front();
    return true;
  }

 private:
  std::shared_ptr<Wire> wire_;
  unsigned side_;
  std::atomic<bool> healthy_{true};
  std::atomic<bool> duplicate_{false};
  std::atomic<bool> stall_{false};
  std::atomic<int> stalled_{0};
  std::atomic<int> held_{0};
  // Guarded by the wire's mutex.
  bool woken_ = false;
  bool hold_ = false;
};

struct Pair {
  std::shared_ptr<Wire> wire = std::make_shared<Wire>();
  KeyId id{1, 3, 5, 7, 9, 11, 13, 15};
  Key key{2, 4, 6, 8, 10, 12, 14, 16};
  ProtectionKeys broadcast;
  std::shared_ptr<TestTransport> transports[2];
  std::unique_ptr<SystemLink> a, b;

  Pair() {
    auto derived = DeriveBroadcast(key, [&](auto input, auto& digest) {
      digest = HmacSha1(key, {input});
      return true;
    });
    REQUIRE(derived);
    broadcast = *derived;
    a = Make(0, broadcast);
    b = Make(1, broadcast);
    REQUIRE(a->RegisterKey(id, key) == 0);
    REQUIRE(b->RegisterKey(id, key) == 0);
  }

  std::unique_ptr<SystemLink> Make(unsigned side,
                                   const ProtectionKeys& broadcast) {
    auto transport = std::make_shared<TestTransport>(wire, side);
    transports[side] = transport;
    AssociationConfig association;
    association.broadcast = broadcast;
    association.mtu = transport->mtu();
    // Documentation range addresses.
    return std::make_unique<SystemLink>(0xC0000201 + side, transport,
                                        std::move(association));
  }
};

std::unique_ptr<SystemLinkPort> Bind(SystemLink& link, uint16_t port,
                                     bool vdp) {
  uint32_t error = 0;
  auto bound = link.Bind(port, vdp, error);
  CHECK(error == 0);
  return bound;
}

bool WaitFor(const std::function<bool()>& condition) {
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (!condition()) {
    if (std::chrono::steady_clock::now() >= deadline) {
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  return true;
}

bool Ready(SystemLinkPort& port) {
  return WaitFor([&] { return port.Readable(); });
}

std::unique_ptr<SystemLinkStream> Stream(SystemLink& link) {
  uint32_t error = 0;
  auto stream = link.CreateStream(error);
  CHECK(error == 0);
  return stream;
}

std::unique_ptr<SystemLinkStream> Listen(SystemLink& link, uint16_t port) {
  auto stream = Stream(link);
  REQUIRE(stream);
  REQUIRE(stream->Bind(port) == 0);
  REQUIRE(stream->Listen(5) == 0);
  return stream;
}

constexpr uint32_t kWait = 5000;

// Reads until |size| bytes arrived or the stream ends.
std::vector<uint8_t> ReceiveAll(SystemLinkStream& stream, size_t size) {
  std::vector<uint8_t> received;
  std::array<uint8_t, 1500> buffer;
  while (received.size() < size) {
    uint32_t error = 0;
    const int read = stream.Receive(buffer, false, kWait, error);
    if (read <= 0) {
      break;
    }
    received.insert(received.end(), buffer.begin(), buffer.begin() + read);
  }
  return received;
}

// Runs on other threads too so it asserts nothing itself.
bool SendAll(SystemLinkStream& stream, std::span<const uint8_t> data) {
  while (!data.empty()) {
    uint32_t error = 0;
    const int sent = stream.Send(data, kWait, error);
    if (sent <= 0) {
      return false;
    }
    data = data.subspan(sent);
  }
  return true;
}

std::vector<uint8_t> Pattern(size_t size, uint8_t seed) {
  std::vector<uint8_t> bytes(size);
  for (size_t i = 0; i < size; ++i) {
    bytes[i] = uint8_t(seed + i * 13);
  }
  return bytes;
}

// XNADDR.abEnet.
constexpr size_t kEnetOffset = 10;

struct QosResults {
  std::mutex mutex;
  std::map<size_t, QosResult> results;
  // Assertions only run on the test thread.
  size_t repeats = 0;

  ~QosResults() { CHECK(repeats == 0); }

  std::function<void(size_t, const QosResult&)> Done() {
    return [this](size_t target, const QosResult& result) {
      std::lock_guard lock(mutex);
      if (!results.emplace(target, result).second) {
        ++repeats;
      }
    };
  }
  size_t Count() {
    std::lock_guard lock(mutex);
    return results.size();
  }
  QosResult Get(size_t target) {
    std::lock_guard lock(mutex);
    return results[target];
  }
};

}  // namespace

TEST_CASE("System Link ports deliver broadcasts and secure datagrams",
          "[net][system_link]") {
  for (bool reverse : {false, true}) {
    Pair pair;
    auto& sender = reverse ? *pair.b : *pair.a;
    auto& receiver = reverse ? *pair.a : *pair.b;
    auto tx = Bind(sender, 1001, false);
    auto rx = Bind(receiver, 1001, false);
    REQUIRE(tx);
    REQUIRE(rx);
    uint32_t error = 0;
    CHECK_FALSE(receiver.Bind(1001, false, error));
    CHECK(error == kWsaAddressInUse);
    CHECK_FALSE(rx->Readable());
    std::atomic<int> wakeups{0};
    rx->SetReadyCallback([&] { ++wakeups; });
    CHECK(wakeups.load() == 0);

    const std::vector<uint8_t> data{0, 1, 2, 3, 4, 5, 6};
    const int data_size = static_cast<int>(data.size());
    REQUIRE(tx->Send({0xFFFFFFFF, 1001}, data, error) == data_size);
    REQUIRE(WaitFor([&] { return wakeups.load() == 1; }));
    CHECK(rx->Readable());
    CHECK(rx->PendingBytes() == data.size());
    std::array<uint8_t, 32> buffer{};
    Endpoint source;
    REQUIRE(rx->Receive(buffer, true, source, 0, error) == data_size);
    CHECK(source == Endpoint{1, 1001});
    CHECK(rx->Readable());
    CHECK(rx->Receive(std::span(buffer).first(2), true, source, 0, error) ==
          -1);
    CHECK(error == kWsaMessageSize);
    CHECK(rx->PendingBytes() == data.size());
    REQUIRE(rx->Receive(buffer, false, source, 0, error) == data_size);
    CHECK_FALSE(rx->Readable());
    CHECK(rx->Receive(buffer, false, source, 0, error) == -1);
    CHECK(error == kWsaWouldBlock);
    CHECK(rx->Receive(buffer, false, source, 10, error) == -1);
    CHECK(error == kWsaTimedOut);
    rx->SetReadyCallback(nullptr);

    uint32_t address;
    REQUIRE(sender.Map(receiver.identity(), pair.id, address) == 0);
    REQUIRE(sender.Connect(address) == 0);
    REQUIRE(tx->Send({address, 1001}, data, error) == data_size);
    REQUIRE(Ready(*rx));
    REQUIRE(rx->Receive(buffer, false, source, 0, error) == data_size);
    CHECK(std::equal(data.begin(), data.end(), buffer.begin()));
    CHECK(sender.ConnectStatus(address) == 2);
    REQUIRE(receiver.peers().size() == 1);
    Address peer;
    KeyId id;
    REQUIRE(receiver.Reverse(source.address, peer, id) == 0);
    CHECK(peer == sender.identity());
    CHECK(id == pair.id);

    REQUIRE(rx->Send({source.address, 1001}, data, error) == data_size);
    REQUIRE(Ready(*tx));
    CHECK(tx->PendingBytes() == data.size());
    // Unmapping retires the association and drops what it queued.
    REQUIRE(sender.Unmap(address) == 0);
    CHECK(tx->PendingBytes() == 0);
    CHECK_FALSE(tx->Readable());
    CHECK(sender.ConnectStatus(address) == 0);
    tx->Close();
    rx->Close();
  }
}

TEST_CASE("System Link VDP ports keep the guest prefix", "[net][system_link]") {
  Pair pair;
  auto tx = Bind(*pair.a, 1000, true);
  auto rx = Bind(*pair.b, 1000, true);
  REQUIRE(tx);
  REQUIRE(rx);
  uint32_t address;
  REQUIRE(pair.a->Map(pair.b->identity(), pair.id, address) == 0);
  const std::vector<uint8_t> vdp{0, 3, 10, 20, 30, 40, 50};
  uint32_t error = 0;
  REQUIRE(tx->Send({address, 1000}, vdp, error) ==
          static_cast<int>(vdp.size()));
  REQUIRE(Ready(*rx));
  std::array<uint8_t, 32> buffer{};
  Endpoint source;
  REQUIRE(rx->Receive(buffer, false, source, 0, error) ==
          static_cast<int>(vdp.size()));
  CHECK(std::equal(vdp.begin(), vdp.end(), buffer.begin()));
  // The prefix claims more encrypted bytes than follow it.
  const std::vector<uint8_t> short_vdp{0, 9, 1, 2};
  CHECK(tx->Send({address, 1000}, short_vdp, error) == -1);
  CHECK(error == kWsaInvalid);
}

TEST_CASE("System Link ports pick a free port and unblock on close",
          "[net][system_link]") {
  Pair pair;
  auto auto_bound = Bind(*pair.a, 0, false);
  REQUIRE(auto_bound);
  CHECK(auto_bound->port() >= 49152);
  auto rx = Bind(*pair.b, 1000, false);
  REQUIRE(rx);
  uint32_t error = 0;
  auto blocked = std::async(std::launch::async, [&] {
    uint8_t byte;
    Endpoint source;
    return rx->Receive(std::span(&byte, 1), false, source,
                       SystemLinkPort::kWaitForever, error);
  });
  // Lets the receive start waiting, the result is the same either way.
  std::this_thread::sleep_for(std::chrono::milliseconds(20));
  rx->Close();
  REQUIRE(blocked.wait_for(std::chrono::seconds(5)) ==
          std::future_status::ready);
  CHECK(blocked.get() == -1);
  CHECK(error == kWsaInterrupted);
  // A closed port frees its number.
  CHECK(Bind(*pair.b, 1000, false));
}

TEST_CASE("System Link delivers a frame that arrives twice once",
          "[net][system_link]") {
  Pair pair;
  pair.transports[0]->Duplicate();
  auto tx = Bind(*pair.a, 1001, false);
  auto rx = Bind(*pair.b, 1001, false);
  REQUIRE(tx);
  REQUIRE(rx);
  const std::array<uint8_t, 3> data{1, 3, 5};
  uint32_t error = 0;
  REQUIRE(tx->Send({0xFFFFFFFF, 1001}, data, error) == 3);
  std::array<uint8_t, 16> buffer{};
  Endpoint source;
  REQUIRE(rx->Receive(buffer, false, source, 2000, error) == 3);
  CHECK(rx->Receive(buffer, false, source, 200, error) == -1);
  CHECK(error == kWsaTimedOut);
}

TEST_CASE("System Link sends without waiting for a frame to arrive",
          "[net][system_link]") {
  Pair pair;
  auto tx = Bind(*pair.a, 1001, false);
  auto rx = Bind(*pair.b, 1001, false);
  REQUIRE(tx);
  REQUIRE(rx);
  // The sender's receive now ends only on a frame or a wake.
  pair.transports[0]->Stall();
  CHECK(WaitFor([&] { return pair.transports[0]->stalled() > 0; }));
  const std::vector<uint8_t> data{1, 2, 3};
  uint32_t error = 0;
  CHECK(tx->Send({0xFFFFFFFF, 1001}, data, error) == 3);
  CHECK(Ready(*rx));
  pair.transports[0]->Disconnect();
}

TEST_CASE("System Link QoS lookups bring back the data a host listens with",
          "[net][system_link][qos]") {
  Pair pair;
  const std::vector<uint8_t> data{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2,
                                  3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4};
  CHECK(pair.a->QosListen(KeyId{2}, kQosListenEnable, {}) == kWsaInvalid);
  REQUIRE(pair.a->QosListen(pair.id, kQosListenEnable | kQosListenSetData,
                            data) == 0);
  const QosTarget host{pair.a->identity(), pair.id, pair.key};
  QosResults results;
  pair.b->QosLookup(1, {host, host}, results.Done());
  REQUIRE(WaitFor([&] { return results.Count() == 2; }));
  for (size_t target : {0, 1}) {
    const auto result = results.Get(target);
    CHECK(result.contacted);
    CHECK_FALSE(result.disabled);
    CHECK(result.data == data);
  }

  // A host that stopped listening still answers with the disabled flag.
  REQUIRE(pair.a->QosListen(pair.id, kQosListenDisable, {}) == 0);
  QosResults disabled;
  pair.b->QosLookup(2, {host}, disabled.Done());
  REQUIRE(WaitFor([&] { return disabled.Count() == 1; }));
  CHECK(disabled.Get(0).contacted);
  CHECK(disabled.Get(0).disabled);
  CHECK(disabled.Get(0).data == data);
}

TEST_CASE("System Link QoS lookups give up on hosts that do not answer",
          "[net][system_link][qos]") {
  Pair pair;
  auto absent = pair.a->identity();
  absent[kEnetOffset + 5] ^= 0x40;
  QosResults results;
  // Neither a host that never listened nor an online key gets an answer.
  KeyId online = pair.id;
  online[0] |= 0x80;
  pair.b->QosLookup(1,
                    {{pair.a->identity(), pair.id, pair.key},
                     {absent, pair.id, pair.key},
                     {pair.a->identity(), online, pair.key}},
                    results.Done());
  REQUIRE(WaitFor([&] { return results.Count() == 3; }));
  for (size_t target : {0, 1, 2}) {
    CHECK_FALSE(results.Get(target).contacted);
  }
}

TEST_CASE("System Link answers its own QoS lookups",
          "[net][system_link][qos]") {
  Pair pair;
  const std::vector<uint8_t> data{1, 2, 3};
  REQUIRE(pair.a->QosListen(pair.id, kQosListenEnable | kQosListenSetData,
                            data) == 0);
  QosResults results;
  pair.a->QosLookup(1, {{pair.a->identity(), pair.id, pair.key}},
                    results.Done());
  REQUIRE(results.Count() == 1);
  CHECK(results.Get(0).contacted);
  CHECK(results.Get(0).data == data);

  // Releasing the listener leaves nothing to answer with.
  REQUIRE(pair.a->QosListen(pair.id, kQosListenRelease, {}) == 0);
  QosResults released;
  pair.a->QosLookup(2, {{pair.a->identity(), pair.id, pair.key}},
                    released.Done());
  REQUIRE(released.Count() == 1);
  CHECK_FALSE(released.Get(0).contacted);
}

TEST_CASE("System Link stops a canceled QoS lookup",
          "[net][system_link][qos]") {
  Pair pair;
  auto absent = pair.a->identity();
  absent[kEnetOffset + 5] ^= 0x40;
  QosResults results;
  pair.b->QosLookup(1, {{absent, pair.id, pair.key}}, results.Done());
  pair.b->CancelQos(1);
  pair.b->CancelQos(2);
  std::this_thread::sleep_for(std::chrono::seconds(2));
  CHECK(results.Count() == 0);
}

TEST_CASE("System Link ends pending QoS lookups when the LAN goes away",
          "[net][system_link][qos]") {
  for (bool reset : {true, false}) {
    Pair pair;
    QosResults results;
    // The host never listens so the lookup keeps asking.
    pair.a->QosLookup(1, {{pair.b->identity(), pair.id, pair.key}},
                      results.Done());
    CHECK(results.Count() == 0);
    if (reset) {
      pair.a->Reset();
    } else {
      pair.transports[0]->Disconnect();
    }
    REQUIRE(WaitFor([&] { return results.Count() == 1; }));
    CHECK_FALSE(results.Get(0).contacted);
  }
}

TEST_CASE("System Link answers the QoS probe pairs of a console",
          "[net][system_link][qos]") {
  Pair pair;
  // The test probes in place of the second console.
  pair.b.reset();
  const std::vector<uint8_t> data{4, 5, 6, 7, 8};
  REQUIRE(pair.a->QosListen(pair.id, kQosListenEnable | kQosListenSetData,
                            data) == 0);
  const auto keys =
      DeriveRegistration(pair.broadcast.authentication, pair.id, pair.key);
  const Mac host = pair.transports[0]->identity();
  const Mac prober = pair.transports[1]->identity();
  auto send = [&](const QosProbe& probe) {
    auto wire = EncodeFrame({prober, host, false, EncodeQosProbe(keys, probe)});
    REQUIRE(wire);
    {
      std::lock_guard lock(pair.wire->mutex);
      pair.wire->frames[0].push_back(std::move(*wire));
    }
    pair.wire->changed.notify_all();
  };
  auto receive = [&](uint32_t wait_ms) -> std::optional<QosReply> {
    std::unique_lock lock(pair.wire->mutex);
    if (!pair.wire->changed.wait_for(
            lock, std::chrono::milliseconds(wait_ms),
            [&] { return !pair.wire->frames[1].empty(); })) {
      return std::nullopt;
    }
    auto wire = std::move(pair.wire->frames[1].front());
    pair.wire->frames[1].pop_front();
    auto frame = DecodeFrame(wire);
    REQUIRE(frame);
    CHECK(frame->source == host);
    CHECK(frame->destination == prober);
    return DecodeQosReply(keys, frame->payload);
  };

  QosProbe probe;
  probe.nonce = {1, 2, 3, 4, 5, 6, 7, 8};
  probe.target = 5;
  probe.sequence = 1;
  probe.id = pair.id;
  probe.address = pair.a->identity();
  send(probe);
  std::this_thread::sleep_for(std::chrono::milliseconds(5));
  probe.flags = kQosProbeSecond;
  send(probe);
  const auto first = receive(5000);
  REQUIRE(first);
  CHECK(first->nonce == probe.nonce);
  CHECK(first->target == 5);
  CHECK(first->sequence == 1);
  CHECK(first->flags == 0);
  CHECK(first->delay >= 5000);
  const auto second = receive(5000);
  REQUIRE(second);
  CHECK(second->sequence == 1);
  // The prober asks for the data next.
  CHECK(second->flags == kQosReplySecond);
  CHECK(second->gap >= 5000);
  CHECK(second->data.empty());

  // A second probe without its first goes unanswered.
  probe.sequence = 2;
  send(probe);
  CHECK_FALSE(receive(300));

  probe.sequence = 3;
  probe.flags = kQosProbeDataRequest;
  send(probe);
  const auto reply = receive(5000);
  REQUIRE(reply);
  CHECK(reply->sequence == 3);
  CHECK(reply->flags == kQosReplyData);
  CHECK(reply->data == data);

  // Without data the prober is done after the pair.
  REQUIRE(pair.a->QosListen(pair.id, kQosListenSetData, {}) == 0);
  probe.sequence = 4;
  probe.flags = 0;
  send(probe);
  probe.flags = kQosProbeSecond;
  send(probe);
  REQUIRE(receive(5000));
  const auto last = receive(5000);
  REQUIRE(last);
  CHECK(last->flags == (kQosReplySecond | kQosReplyNoData));

  // Probes name the host they are for.
  probe.sequence = 5;
  probe.flags = kQosProbeDataRequest;
  probe.address[kEnetOffset] ^= 0x40;
  send(probe);
  CHECK_FALSE(receive(300));
}

TEST_CASE("System Link registry checks key ids", "[net][system_link]") {
  Pair pair;
  Key key;
  auto id = pair.id;
  CHECK(pair.a->RegisterKey(id, pair.key) == kWsaAlready);
  id[0] = 0x1F;
  REQUIRE(pair.a->RegisterKey(id, pair.key) == 0);
  CHECK(pair.a->GetKey(id, key));
  CHECK(key == pair.key);
  REQUIRE(pair.a->UnregisterKey(id) == 0);
  CHECK_FALSE(pair.a->GetKey(id, key));
  CHECK(pair.a->UnregisterKey(id) == kWsaInvalid);
  id[0] = 0x20;
  CHECK(pair.a->RegisterKey(id, pair.key) == kWsaInvalid);
}

TEST_CASE("System Link unmaps a peer that never connected",
          "[net][system_link]") {
  Pair pair;
  uint32_t address;
  REQUIRE(pair.a->Map(pair.b->identity(), pair.id, address) == 0);
  REQUIRE(pair.a->Unmap(address) == 0);
  Address peer;
  KeyId id;
  CHECK(pair.a->Reverse(address, peer, id) == kWsaInvalid);
  CHECK(pair.a->peers().empty());
  CHECK(pair.a->Unmap(address) == kWsaInvalid);
}

TEST_CASE("System Link keeps a peer through a simultaneous connect",
          "[net][system_link]") {
  Pair pair;
  uint32_t to_b, to_a;
  REQUIRE(pair.a->Map(pair.b->identity(), pair.id, to_b) == 0);
  REQUIRE(pair.b->Map(pair.a->identity(), pair.id, to_a) == 0);
  // Both key exchange requests are on their way before either arrives.
  pair.transports[0]->Hold();
  pair.transports[1]->Hold();
  CHECK(pair.a->Connect(to_b) == 0);
  CHECK(pair.b->Connect(to_a) == 0);
  CHECK(WaitFor([&] {
    return pair.transports[0]->held() > 0 && pair.transports[1]->held() > 0;
  }));
  pair.transports[0]->Release();
  pair.transports[1]->Release();
  CHECK(WaitFor([&] {
    return pair.a->ConnectStatus(to_b) == 2 && pair.b->ConnectStatus(to_a) == 2;
  }));
  Address peer;
  KeyId id;
  CHECK(pair.a->Reverse(to_b, peer, id) == 0);
  CHECK(pair.b->Reverse(to_a, peer, id) == 0);
  CHECK(peer == pair.a->identity());
}

TEST_CASE("System Link loops datagrams to its own address back",
          "[net][system_link]") {
  Pair pair;
  // The key is not looked at.
  KeyId unregistered = pair.id;
  unregistered[7] ^= 1;
  uint32_t address = 0;
  REQUIRE(pair.a->Map(pair.a->identity(), unregistered, address) == 0);
  CHECK(address == 0x7F000001);
  CHECK(pair.a->peers().empty());
  Address own;
  KeyId id;
  REQUIRE(pair.a->Reverse(address, own, id) == 0);
  CHECK(own == pair.a->identity());
  CHECK(id == KeyId{});
  // There is no association to connect or drop.
  CHECK(pair.a->Connect(address) == kWsaInvalid);
  CHECK(pair.a->Unmap(address) == kWsaInvalid);

  for (bool vdp : {false, true}) {
    auto tx = Bind(*pair.a, 1004, vdp);
    auto rx = Bind(*pair.a, 1005, vdp);
    auto other_kind = Bind(*pair.a, 1005, !vdp);
    auto remote = Bind(*pair.b, 1005, vdp);
    REQUIRE(tx);
    REQUIRE(rx);
    REQUIRE(other_kind);
    REQUIRE(remote);
    const std::vector<uint8_t> data{0, 2, 7, 8, 9};
    const int data_size = static_cast<int>(data.size());
    uint32_t error = 0;
    REQUIRE(tx->Send({address, 1005}, data, error) == data_size);
    // A host joins its own session through the port it sends from.
    REQUIRE(tx->Send({address, 1004}, data, error) == data_size);
    std::array<uint8_t, 16> buffer{};
    Endpoint source;
    REQUIRE(rx->Receive(buffer, false, source, 0, error) == data_size);
    CHECK(std::equal(data.begin(), data.end(), buffer.begin()));
    CHECK(source == Endpoint{address, 1004});
    buffer = {};
    REQUIRE(tx->Receive(buffer, false, source, 0, error) == data_size);
    CHECK(std::equal(data.begin(), data.end(), buffer.begin()));
    CHECK(source == Endpoint{address, 1004});
    CHECK_FALSE(other_kind->Readable());
    CHECK(remote->Receive(buffer, false, source, 100, error) == -1);
    CHECK(error == kWsaTimedOut);
    if (!vdp) {
      const std::vector<uint8_t> oversized(kMaxDatagramSize + 1);
      CHECK(tx->Send({address, 1005}, oversized, error) == -1);
      CHECK(error == kWsaMessageSize);
      CHECK_FALSE(rx->Readable());
    }
  }
  CHECK(pair.a->peers().empty());
}

TEST_CASE("System Link unregistering a key retires its peers",
          "[net][system_link]") {
  Pair pair;
  auto tx = Bind(*pair.a, 1001, false);
  auto rx = Bind(*pair.b, 1001, false);
  REQUIRE(tx);
  REQUIRE(rx);
  uint32_t address;
  REQUIRE(pair.a->Map(pair.b->identity(), pair.id, address) == 0);
  const std::array<uint8_t, 3> data{1, 3, 5};
  uint32_t error = 0;
  REQUIRE(tx->Send({address, 1001}, data, error) == 3);
  REQUIRE(Ready(*rx));
  REQUIRE(pair.b->peers().size() == 1);
  REQUIRE(pair.b->UnregisterKey(pair.id) == 0);
  CHECK(pair.b->peers().empty());
  CHECK(rx->PendingBytes() == 0);
  CHECK_FALSE(rx->Readable());
}

TEST_CASE(
    "System Link transport loss retires peers and wakes receives but keeps "
    "keys",
    "[net][system_link]") {
  Pair pair;
  auto tx = Bind(*pair.a, 1001, false);
  auto rx = Bind(*pair.b, 1001, false);
  REQUIRE(tx);
  REQUIRE(rx);
  uint32_t address;
  REQUIRE(pair.a->Map(pair.b->identity(), pair.id, address) == 0);
  const std::array<uint8_t, 3> data{1, 3, 5};
  uint32_t error = 0;
  REQUIRE(tx->Send({address, 1001}, data, error) == 3);
  REQUIRE(Ready(*rx));
  std::promise<void> woken;
  tx->SetReadyCallback([&] { woken.set_value(); });
  uint32_t blocked_error = 0;
  auto blocked = std::async(std::launch::async, [&] {
    uint8_t byte;
    Endpoint source;
    return tx->Receive(std::span(&byte, 1), false, source,
                       SystemLinkPort::kWaitForever, blocked_error);
  });
  pair.transports[0]->Disconnect();
  REQUIRE(blocked.wait_for(std::chrono::seconds(5)) ==
          std::future_status::ready);
  CHECK(blocked.get() == -1);
  CHECK(blocked_error == kWsaNetworkDown);
  CHECK(woken.get_future().wait_for(std::chrono::seconds(5)) ==
        std::future_status::ready);
  CHECK(pair.a->peers().empty());
  CHECK(pair.a->ConnectStatus(address) == 0);
  CHECK(tx->Send({address, 1001}, data, error) == -1);
  CHECK(error == kWsaNetworkDown);
  CHECK_FALSE(pair.a->Bind(1002, false, error));
  CHECK(error == kWsaNetworkDown);
  Key key;
  CHECK(pair.a->GetKey(pair.id, key));
  CHECK(key == pair.key);
}

TEST_CASE("System Link streams connect, carry data and close",
          "[net][system_link][tcp]") {
  for (bool reverse : {false, true}) {
    Pair pair;
    auto& client_link = reverse ? *pair.b : *pair.a;
    auto& host_link = reverse ? *pair.a : *pair.b;
    auto listener = Listen(host_link, 1003);
    uint32_t host;
    REQUIRE(client_link.Map(host_link.identity(), pair.id, host) == 0);
    auto client = Stream(client_link);
    REQUIRE(client);
    CHECK_FALSE(client->peer());
    REQUIRE(client->Connect({host, 1003}, kWait) == 0);
    CHECK(client->port() >= 49152);
    CHECK(client->peer() == Endpoint{host, 1003});
    CHECK(client->Connect({host, 1003}, kWait) == kWsaIsConnected);

    Endpoint source;
    uint32_t error = 0;
    auto accepted = listener->Accept(source, kWait, error);
    REQUIRE(accepted);
    CHECK(source.port == client->port());
    CHECK(accepted->port() == 1003);
    CHECK(accepted->peer() == source);
    Address peer;
    KeyId id;
    REQUIRE(host_link.Reverse(source.address, peer, id) == 0);
    CHECK(peer == client_link.identity());

    const auto request = Pattern(5000, 1);
    REQUIRE(SendAll(*client, request));
    CHECK(ReceiveAll(*accepted, request.size()) == request);
    const auto reply = Pattern(7, 3);
    REQUIRE(SendAll(*accepted, reply));
    CHECK(ReceiveAll(*client, reply.size()) == reply);

    // The client finishes sending, the host still answers.
    REQUIRE(client->Shutdown(1) == 0);
    std::array<uint8_t, 16> buffer;
    CHECK(accepted->Receive(buffer, false, kWait, error) == 0);
    CHECK(client->Send(reply, 0, error) == -1);
    CHECK(error == kWsaShutdown);
    REQUIRE(SendAll(*accepted, reply));
    CHECK(ReceiveAll(*client, reply.size()) == reply);
    accepted->Close(false);
    CHECK(client->Receive(buffer, false, kWait, error) == 0);
    CHECK(accepted->Receive(buffer, false, 0, error) == -1);
    CHECK(error == kWsaInterrupted);
  }
}

TEST_CASE("System Link streams carry more than a window",
          "[net][system_link][tcp]") {
  Pair pair;
  auto listener = Listen(*pair.b, 28001);
  uint32_t host;
  REQUIRE(pair.a->Map(pair.b->identity(), pair.id, host) == 0);
  auto client = Stream(*pair.a);
  REQUIRE(client->Connect({host, 28001}, kWait) == 0);
  Endpoint source;
  uint32_t error = 0;
  auto accepted = listener->Accept(source, kWait, error);
  REQUIRE(accepted);
  const auto data = Pattern(300000, 7);
  auto sending =
      std::async(std::launch::async, [&] { return SendAll(*client, data); });
  CHECK(ReceiveAll(*accepted, data.size()) == data);
  CHECK(sending.get());
}

TEST_CASE("System Link streams refuse ports nobody listens on",
          "[net][system_link][tcp]") {
  Pair pair;
  uint32_t host;
  REQUIRE(pair.a->Map(pair.b->identity(), pair.id, host) == 0);
  auto client = Stream(*pair.a);
  CHECK(client->Connect({host, 1004}, kWait) == kWsaConnectionRefused);
  CHECK(client->Failed());
  CHECK(client->ConnectError() == kWsaConnectionRefused);
  uint32_t error = 0;
  std::array<uint8_t, 4> buffer;
  CHECK(client->Receive(buffer, false, 0, error) == -1);
  CHECK(error == kWsaConnectionRefused);

  // Nor does an address that maps to no peer lead anywhere.
  auto lost = Stream(*pair.a);
  CHECK(lost->Connect({0x00000777, 1003}, kWait) == kWsaHostUnreachable);
  CHECK(lost->Connect({host, 0}, kWait) == kWsaAddressNotAvailable);
}

TEST_CASE("System Link streams report readiness as Winsock events",
          "[net][system_link][tcp]") {
  Pair pair;
  auto listener = Listen(*pair.b, 1003);
  std::atomic<uint32_t> listener_events{0};
  listener->SetReadyCallback(
      [&](uint32_t events) { listener_events |= events; });
  CHECK(listener_events.load() == 0);
  CHECK_FALSE(listener->Readable());
  Endpoint source;
  uint32_t error = 0;
  CHECK_FALSE(listener->Accept(source, 0, error));
  CHECK(error == kWsaWouldBlock);

  uint32_t host;
  REQUIRE(pair.a->Map(pair.b->identity(), pair.id, host) == 0);
  auto client = Stream(*pair.a);
  std::atomic<uint32_t> client_events{0};
  client->SetReadyCallback([&](uint32_t events) { client_events |= events; });
  // The connect stays under way while its key exchange is held back.
  pair.transports[0]->Hold();
  CHECK(client->Connect({host, 1003}, 0) == kWsaWouldBlock);
  CHECK(client->Connect({host, 1003}, 0) == kWsaAlready);
  CHECK_FALSE(client->Writable());
  std::array<uint8_t, 8> buffer;
  CHECK(client->Send(buffer, 0, error) == -1);
  CHECK(error == kWsaNotConnected);
  pair.transports[0]->Release();
  REQUIRE(WaitFor([&] {
    return (client_events.load() & (kStreamConnect | kStreamWrite)) ==
           (kStreamConnect | kStreamWrite);
  }));
  CHECK(client->Writable());
  CHECK(client->Connect({host, 1003}, 0) == kWsaIsConnected);
  REQUIRE(WaitFor([&] { return listener_events.load() & kStreamAccept; }));
  CHECK(listener->Readable());
  auto accepted = listener->Accept(source, 0, error);
  REQUIRE(accepted);
  CHECK_FALSE(listener->Readable());

  std::atomic<uint32_t> host_events{0};
  accepted->SetReadyCallback([&](uint32_t events) { host_events |= events; });
  // Arming reports what holds already.
  CHECK(host_events.load() == kStreamWrite);
  host_events = 0;
  CHECK(accepted->Receive(buffer, false, 0, error) == -1);
  CHECK(error == kWsaWouldBlock);
  const auto data = Pattern(6, 2);
  REQUIRE(SendAll(*client, data));
  REQUIRE(WaitFor([&] { return host_events.load() & kStreamRead; }));
  CHECK(accepted->PendingBytes() == data.size());
  host_events = 0;
  // A read that leaves data behind reports it again.
  CHECK(accepted->Receive(std::span(buffer).first(2), true, 0, error) == 2);
  CHECK(accepted->Receive(std::span(buffer).first(2), false, 0, error) == 2);
  CHECK(buffer[0] == data[0]);
  CHECK(host_events.load() == kStreamRead);
  host_events = 0;
  CHECK(accepted->Receive(buffer, false, 0, error) == 4);
  CHECK(host_events.load() == 0);
  CHECK_FALSE(accepted->Readable());

  client->Close(false);
  REQUIRE(WaitFor([&] { return host_events.load() & kStreamClose; }));
  CHECK(accepted->Readable());
  CHECK(accepted->Receive(buffer, false, 0, error) == 0);
}

TEST_CASE("System Link streams loop back to this console",
          "[net][system_link][tcp]") {
  Pair pair;
  auto listener = Listen(*pair.a, 1003);
  uint32_t self;
  REQUIRE(pair.a->Map(pair.a->identity(), pair.id, self) == 0);
  auto client = Stream(*pair.a);
  REQUIRE(client->Connect({self, 1003}, kWait) == 0);
  Endpoint source;
  uint32_t error = 0;
  auto accepted = listener->Accept(source, kWait, error);
  REQUIRE(accepted);
  CHECK(source == Endpoint{self, client->port()});
  const auto data = Pattern(100000, 9);
  auto sending =
      std::async(std::launch::async, [&] { return SendAll(*client, data); });
  CHECK(ReceiveAll(*accepted, data.size()) == data);
  CHECK(sending.get());
  client->Close(false);
  std::array<uint8_t, 4> buffer;
  CHECK(accepted->Receive(buffer, false, kWait, error) == 0);
  CHECK(pair.a->peers().empty());
}

TEST_CASE("System Link stream ports are their own", "[net][system_link][tcp]") {
  Pair pair;
  auto first = Stream(*pair.a);
  REQUIRE(first->Bind(1003) == 0);
  CHECK(first->Bind(1004) == kWsaInvalid);
  auto second = Stream(*pair.a);
  CHECK(second->Bind(1003) == kWsaAddressInUse);
  // UDP and VDP ports are apart from TCP ones.
  CHECK(Bind(*pair.a, 1003, false));
  auto dynamic = Stream(*pair.a);
  REQUIRE(dynamic->Bind(0) == 0);
  CHECK(dynamic->port() >= 49152);
  CHECK(second->Listen(1) == kWsaInvalid);
  first->Close(false);
  CHECK(second->Bind(1003) == 0);
}

TEST_CASE("System Link streams wake calls when closed or the LAN goes away",
          "[net][system_link][tcp]") {
  for (bool lan : {false, true}) {
    Pair pair;
    auto listener = Listen(*pair.b, 1003);
    uint32_t host;
    REQUIRE(pair.a->Map(pair.b->identity(), pair.id, host) == 0);
    auto client = Stream(*pair.a);
    REQUIRE(client->Connect({host, 1003}, kWait) == 0);
    uint32_t error = 0;
    auto blocked = std::async(std::launch::async, [&] {
      uint8_t byte;
      return client->Receive(std::span(&byte, 1), false,
                             SystemLinkStream::kWaitForever, error);
    });
    Endpoint source;
    uint32_t accept_error = 0;
    // Kept open, as closing it would end the client's receive.
    auto accepted = listener->Accept(source, kWait, accept_error);
    REQUIRE(accepted);
    auto accepting = std::async(std::launch::async, [&] {
      return listener->Accept(source, SystemLinkStream::kWaitForever,
                              accept_error);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    if (lan) {
      pair.transports[0]->Disconnect();
      pair.transports[1]->Disconnect();
    } else {
      client->Close(false);
      listener->Close(false);
    }
    REQUIRE(blocked.wait_for(std::chrono::seconds(5)) ==
            std::future_status::ready);
    CHECK(blocked.get() == -1);
    CHECK(error == (lan ? kWsaNetworkDown : kWsaInterrupted));
    REQUIRE(accepting.wait_for(std::chrono::seconds(5)) ==
            std::future_status::ready);
    CHECK_FALSE(accepting.get());
    CHECK(accept_error == (lan ? kWsaNetworkDown : kWsaInterrupted));
  }
}

TEST_CASE("System Link streams end when the peer goes away",
          "[net][system_link][tcp]") {
  Pair pair;
  auto listener = Listen(*pair.b, 1003);
  uint32_t host;
  REQUIRE(pair.a->Map(pair.b->identity(), pair.id, host) == 0);
  auto client = Stream(*pair.a);
  REQUIRE(client->Connect({host, 1003}, kWait) == 0);
  Endpoint source;
  uint32_t error = 0;
  auto accepted = listener->Accept(source, kWait, error);
  REQUIRE(accepted);
  std::atomic<uint32_t> events{0};
  accepted->SetReadyCallback([&](uint32_t happened) { events |= happened; });
  REQUIRE(pair.b->UnregisterKey(pair.id) == 0);
  CHECK(events.load() & kStreamClose);
  std::array<uint8_t, 4> buffer;
  CHECK(accepted->Receive(buffer, false, 0, error) == -1);
  CHECK(error == kWsaConnectionReset);
  CHECK(accepted->Send(buffer, 0, error) == -1);
  CHECK(error == kWsaConnectionReset);
}

// A connected stream on each side, the client on a and the host on b.
struct StreamPair {
  Pair pair;
  std::unique_ptr<SystemLinkStream> listener, client, accepted;
  uint32_t host = 0;
  Endpoint source;

  explicit StreamPair(uint16_t port = 0) {
    listener = Listen(*pair.b, 1003);
    REQUIRE(pair.a->Map(pair.b->identity(), pair.id, host) == 0);
    client = Stream(*pair.a);
    if (port) {
      REQUIRE(client->Bind(port) == 0);
    }
    REQUIRE(client->Connect({host, 1003}, kWait) == 0);
    uint32_t error = 0;
    accepted = listener->Accept(source, kWait, error);
    REQUIRE(accepted);
  }
};

TEST_CASE("System Link datagrams still leave while a stream bursts",
          "[net][system_link][tcp]") {
  StreamPair streams;
  auto& pair = streams.pair;
  // Warm up until a burst fills the peer's whole window.
  const auto warmup = Pattern(300000, 1);
  auto sending = std::async(std::launch::async,
                            [&] { return SendAll(*streams.client, warmup); });
  CHECK(ReceiveAll(*streams.accepted, warmup.size()) == warmup);
  CHECK(sending.get());
  auto tx = Bind(*pair.a, 1001, false);
  REQUIRE(tx);
  const std::array<uint8_t, 4> datagram{1, 2, 3, 4};
  uint32_t error = 0;
  // Lets the last acknowledgments open the whole window.
  std::this_thread::sleep_for(std::chrono::milliseconds(200));
  // The worker sends nothing more for now.
  pair.transports[0]->Hold();
  CHECK(tx->Send({streams.host, 1001}, datagram, error) == 4);
  CHECK(WaitFor([&] { return pair.transports[0]->held() > 0; }));
  const auto burst = Pattern(tcp::kBufferSize, 2);
  CHECK(streams.client->Send(burst, 0, error) > 0);
  int failed = 0;
  for (int i = 0; i < 20; ++i) {
    failed += tx->Send({streams.host, 1001}, datagram, error) < 0;
  }
  CHECK(failed == 0);
  pair.transports[0]->Release();
}

TEST_CASE("System Link streams reconnect from the port of a closed one",
          "[net][system_link][tcp]") {
  StreamPair streams(1500);
  // The host keeps its end open after the client is done.
  streams.client->Close(false);
  std::array<uint8_t, 4> buffer;
  uint32_t error = 0;
  REQUIRE(streams.accepted->Receive(buffer, false, kWait, error) == 0);
  auto again = Stream(*streams.pair.a);
  REQUIRE(again->Bind(1500) == 0);
  CHECK(again->Connect({streams.host, 1003}, 3000) == 0);
  Endpoint source;
  auto second = streams.listener->Accept(source, 3000, error);
  REQUIRE(second);
  CHECK(source.port == 1500);
}

TEST_CASE("System Link streams keep data when their ports are taken again",
          "[net][system_link][tcp]") {
  StreamPair streams(1500);
  // The host finishes first and waits out TIME_WAIT with data unread.
  REQUIRE(streams.accepted->Shutdown(1) == 0);
  std::array<uint8_t, 8> buffer;
  uint32_t error = 0;
  REQUIRE(streams.client->Receive(buffer, false, kWait, error) == 0);
  const auto data = Pattern(5, 4);
  REQUIRE(SendAll(*streams.client, data));
  streams.client->Close(false);
  REQUIRE(WaitFor([&] { return streams.accepted->PendingBytes() == 5; }));
  auto again = Stream(*streams.pair.a);
  REQUIRE(again->Bind(1500) == 0);
  REQUIRE(again->Connect({streams.host, 1003}, kWait) == 0);
  CHECK(ReceiveAll(*streams.accepted, data.size()) == data);
}

TEST_CASE("System Link streams report a finished connect when armed",
          "[net][system_link][tcp]") {
  StreamPair streams;
  uint32_t events = 0;
  streams.client->SetReadyCallback([&](uint32_t ready) { events |= ready; });
  CHECK(events == (kStreamConnect | kStreamWrite));
  // Only once.
  events = 0;
  streams.client->SetReadyCallback([&](uint32_t ready) { events |= ready; });
  CHECK(events == kStreamWrite);
  streams.client->SetReadyCallback(nullptr);
}

TEST_CASE("System Link connects end when their peer is dropped",
          "[net][system_link][tcp]") {
  for (bool unregister : {false, true}) {
    Pair pair;
    // Nobody answers for this address so the connect stays under way.
    auto absent = pair.b->identity();
    absent[kEnetOffset + 5] ^= 0x40;
    uint32_t address;
    REQUIRE(pair.a->Map(absent, pair.id, address) == 0);
    auto client = Stream(*pair.a);
    REQUIRE(client->Connect({address, 1003}, 0) == kWsaWouldBlock);
    REQUIRE(client->Connect({address, 1003}, 0) == kWsaAlready);
    if (unregister) {
      REQUIRE(pair.a->UnregisterKey(pair.id) == 0);
    } else {
      REQUIRE(pair.a->Unmap(address) == 0);
    }
    CHECK(client->Connect({address, 1003}, 0) == kWsaHostUnreachable);
    CHECK(client->Failed());
  }
}

TEST_CASE("System Link streams keep what arrived before the peer left",
          "[net][system_link][tcp]") {
  StreamPair streams;
  std::atomic<uint32_t> events{0};
  streams.client->SetReadyCallback(
      [&](uint32_t happened) { events |= happened; });
  const auto data = Pattern(100, 5);
  REQUIRE(SendAll(*streams.accepted, data));
  streams.accepted->Close(false);
  REQUIRE(WaitFor([&] { return events.load() & kStreamClose; }));
  REQUIRE(streams.pair.b->Unmap(streams.source.address) == 0);
  // The association is gone before the client read anything.
  REQUIRE(WaitFor([&] { return streams.pair.a->peers().empty(); }));
  CHECK(ReceiveAll(*streams.client, data.size()) == data);
  std::array<uint8_t, 4> buffer;
  uint32_t error = 0;
  CHECK(streams.client->Receive(buffer, false, 0, error) == 0);
}

TEST_CASE("System Link stream shutdowns wake blocked calls",
          "[net][system_link][tcp]") {
  StreamPair streams;
  uint32_t error = 0;
  auto blocked = std::async(std::launch::async, [&] {
    uint8_t byte;
    return streams.client->Receive(std::span(&byte, 1), false,
                                   SystemLinkStream::kWaitForever, error);
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(20));
  REQUIRE(streams.client->Shutdown(0) == 0);
  const bool woke =
      blocked.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
  CHECK(woke);
  // Ends the receive either way.
  streams.client->Close(false);
  CHECK(blocked.get() == -1);
  if (woke) {
    CHECK(error == kWsaShutdown);
  }
}

TEST_CASE("System Link streams reset data sent to a closed socket",
          "[net][system_link][tcp]") {
  StreamPair streams;
  streams.client->Close(false);
  std::array<uint8_t, 16> buffer;
  uint32_t error = 0;
  REQUIRE(streams.accepted->Receive(buffer, false, kWait, error) == 0);
  // Nobody reads on the client side any more.
  REQUIRE(
      WaitFor([&] { return streams.accepted->Send(buffer, 0, error) < 0; }));
  CHECK(error == kWsaConnectionReset);
}

}  // namespace xe::net::secure::test

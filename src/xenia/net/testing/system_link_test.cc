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

  void Wake() override {
    {
      std::lock_guard lock(wire_->mutex);
      woken_ = true;
    }
    wire_->changed.notify_all();
  }

  int Send(std::span<const uint8_t> bytes) override {
    std::lock_guard lock(wire_->mutex);
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
  // Guarded by the wire's mutex.
  bool woken_ = false;
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

}  // namespace xe::net::secure::test

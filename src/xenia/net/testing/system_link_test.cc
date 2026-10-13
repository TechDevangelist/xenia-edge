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
#include <memory>
#include <mutex>
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
  std::shared_ptr<TestTransport> transports[2];
  std::unique_ptr<SystemLink> a, b;

  Pair() {
    auto broadcast = DeriveBroadcast(key, [&](auto input, auto& digest) {
      digest = HmacSha1(key, {input});
      return true;
    });
    REQUIRE(broadcast);
    a = Make(0, *broadcast);
    b = Make(1, *broadcast);
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

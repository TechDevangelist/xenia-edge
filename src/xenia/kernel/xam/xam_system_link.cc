/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2026 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

// Asio must be included before Windows headers to avoid macro conflicts
#include <asio.hpp>

#include "xenia/kernel/xam/xam_system_link.h"

#include <algorithm>
#include <optional>
#include <span>
#include <string>

#include "xenia/base/clock.h"
#include "xenia/base/cvar.h"
#include "xenia/base/logging.h"
#include "xenia/kernel/kernel_state.h"
#include "xenia/kernel/user_module.h"
#include "xenia/kernel/xam/xam_module.h"
#include "xenia/kernel/xboxkrnl/xboxkrnl_crypt.h"
#include "xenia/net/packet_transport.h"

DEFINE_string(systemlink_transport, "tunnel",
              "How System Link traffic travels. \"tunnel\" sends it straight "
              "to other Xenia instances on this LAN and is the better choice "
              "for Xenia-to-Xenia play. \"kai\" goes through an XLink Kai "
              "engine, which is required to play with Xbox 360 consoles and "
              "also reaches players over the internet. \"off\" turns System "
              "Link off.",
              "Network");
DEFINE_string(systemlink_kai_engine, "127.0.0.1",
              "IPv4 address of the XLink Kai engine. An engine on another "
              "machine needs \"Allow remote DDS connections\" turned on in its "
              "settings.",
              "Network");
DEFINE_int32(systemlink_tunnel_port, 36020,
             "UDP port of the System Link tunnel, the same on every instance.",
             "Network");
DEFINE_string(systemlink_tunnel_address, "255.255.255.255",
              "Where the System Link tunnel sends: the LAN broadcast address "
              "or the IPv4 address of one other instance.",
              "Network");

namespace xe {
namespace kernel {
namespace xam {
namespace {

// A Microsoft block from while the 360 was made. XLink Kai only forwards
// frames from console vendors.
constexpr uint8_t kMacPrefix[] = {0x00, 0x1D, 0xD8};

std::optional<uint32_t> ParseAddress(const std::string& text) {
  asio::error_code ec;
  const auto address = asio::ip::make_address_v4(text, ec);
  if (ec) {
    XELOGE("System Link: \"{}\" is not an IPv4 address", text);
    return std::nullopt;
  }
  return address.to_uint();
}

std::unique_ptr<net::secure::PacketTransport> OpenTransport(
    const net::secure::Mac& mac) {
  const std::string& name = cvars::systemlink_transport;
  std::string error;
  std::unique_ptr<net::secure::PacketTransport> transport;
  if (name == "kai") {
    const auto engine = ParseAddress(cvars::systemlink_kai_engine);
    if (!engine) {
      return nullptr;
    }
    transport = net::secure::OpenKaiTransport(
        mac, {*engine, net::secure::kKaiEngine.port}, error);
  } else if (name == "tunnel") {
    const auto destination = ParseAddress(cvars::systemlink_tunnel_address);
    const int32_t port = cvars::systemlink_tunnel_port;
    if (!destination) {
      return nullptr;
    }
    if (port <= 0 || port > 0xFFFF) {
      XELOGE("System Link: tunnel port {} is out of range", port);
      return nullptr;
    }
    transport = net::secure::OpenUdpTunnelTransport(
        mac, uint16_t(port), {{*destination, uint16_t(port)}}, error);
  } else {
    XELOGE("System Link: unknown transport \"{}\"", name);
    return nullptr;
  }
  if (!transport) {
    XELOGE("System Link: {}", error);
  }
  return transport;
}

}  // namespace

bool SystemLinkEnabled() { return cvars::systemlink_transport != "off"; }

std::unique_ptr<net::SystemLink> CreateSystemLink(KernelState* kernel_state) {
  if (!SystemLinkEnabled()) {
    return nullptr;
  }
  auto module = kernel_state->GetExecutableModule();
  xex2_opt_lan_key* lan_key = nullptr;
  const xex2_opt_execution_info* execution =
      module ? module->xex_module()->opt_execution_info() : nullptr;
  if (!execution ||
      !module->xex_module()->GetOptHeader(XEX_HEADER_LAN_KEY, &lan_key) ||
      !lan_key) {
    XELOGE("System Link: the title has no LAN key");
    return nullptr;
  }
  net::Key key;
  std::copy_n(lan_key->key, key.size(), key.begin());
  auto broadcast = net::secure::DeriveBroadcast(
      key, [](std::span<const uint8_t> input, net::secure::Sha1Digest& digest) {
        return xboxkrnl::XeKeysHmacSha(
            0x19, input.data(), uint32_t(input.size()), nullptr, 0, nullptr, 0,
            digest.data(), uint32_t(digest.size()));
      });
  if (!broadcast) {
    XELOGE("System Link: no platform key to derive the LAN keys");
    return nullptr;
  }

  // New for every title so instances on one machine never share it.
  net::secure::Mac mac;
  std::copy(std::begin(kMacPrefix), std::end(kMacPrefix), mac.begin());
  net::Random(std::span(mac).subspan(std::size(kMacPrefix)));
  auto transport = OpenTransport(mac);
  if (!transport) {
    return nullptr;
  }

  net::secure::AssociationConfig association;
  association.broadcast = *broadcast;
  association.freshness_time = [] { return Clock::QueryGuestSystemTime(); };
  const auto* version = kernel_state->GetKernelVersion();
  association.metadata = net::secure::MakeMetadata(
      execution->title_id, execution->version_value, version->major,
      version->minor, version->build, uint8_t(version->qfe));
  association.mtu = transport->mtu();
  // A console without DHCP picks an RFC 3927 address. Peers only display it
  // since frames go by MAC.
  const uint32_t address =
      0xA9FE0000 | (uint32_t(1 + mac[4] % 254) << 8) | mac[5];
  XELOGI(
      "System Link: {} transport, MAC "
      "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
      cvars::systemlink_transport, mac[0], mac[1], mac[2], mac[3], mac[4],
      mac[5]);
  return std::make_unique<net::SystemLink>(address, std::move(transport),
                                           std::move(association));
}

std::shared_ptr<net::SystemLink> GetSystemLink(KernelState* kernel_state) {
  if (!SystemLinkEnabled()) {
    return nullptr;
  }
  return kernel_state->GetKernelModule<XamModule>("xam.xex")->system_link();
}

}  // namespace xam
}  // namespace kernel
}  // namespace xe

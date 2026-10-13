/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2026 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include "xenia/kernel/xsession.h"

#include <span>

#include "xenia/base/logging.h"
#include "xenia/kernel/kernel_state.h"
#include "xenia/kernel/xam/xam_system_link.h"
#include "xenia/net/system_link.h"

namespace xe {
namespace kernel {

XSession::XSession(KernelState* kernel_state)
    : XObject(kernel_state, kObjectType) {}

X_STATUS XSession::Initialize() {
  // ObDereferenceObject finds the object by the handle CreateNative stashes.
  if (!CreateNative(sizeof(X_DISPATCH_HEADER))) {
    return X_STATUS_NO_MEMORY;
  }
  return X_STATUS_SUCCESS;
}

object_ref<XSession> XSession::FromGuest(KernelState* kernel_state,
                                         uint32_t guest_ptr) {
  if (!guest_ptr) {
    return nullptr;
  }
  auto header =
      kernel_state->memory()->TranslateVirtual<X_DISPATCH_HEADER*>(guest_ptr);
  if (header->wait_list.flink_ptr != kXObjSignature) {
    return nullptr;
  }
  auto session = kernel_state->object_table()->LookupObject<XSession>(
      header->wait_list.blink_ptr);
  // The handle may have been recycled for another object.
  if (!session || session->guest_object() != guest_ptr) {
    return nullptr;
  }
  return session;
}

X_RESULT XSession::Create(uint32_t flags, uint32_t session_info_ptr,
                          uint32_t nonce_ptr) {
  if (!session_info_ptr) {
    return X_ERROR_SUCCESS;
  }

  auto info = memory()->TranslateVirtual<XSESSION_INFO*>(session_info_ptr);
  const bool peer_network = flags & SessionFlags::PEER_NETWORK;
  // Only a peer network session needs System Link.
  auto link = peer_network ? xam::GetSystemLink(kernel_state_) : nullptr;
  if (flags & SessionFlags::HOST) {
    net::SystemLink::CreateKey(info->session_id, info->key_exchange_key);
    info->host_address = link ? link->identity() : net::secure::Address{};
    if (nonce_ptr) {
      net::Random(std::span(memory()->TranslateVirtual(nonce_ptr), 8));
    }
  } else if (!peer_network) {
    *info = {};
  }
  if (!link) {
    return X_ERROR_SUCCESS;
  }

  // The title may have registered the key itself.
  const uint32_t error =
      link->RegisterKey(info->session_id, info->key_exchange_key);
  if (error && error != net::kWsaAlready) {
    XELOGW("XSession: System Link refused the session key, error {}", error);
    return 0x8015520D;
  }
  system_link_ = link;
  registered_key_ = info->session_id;
  return X_ERROR_SUCCESS;
}

X_RESULT XSession::DeleteSession() {
  if (registered_key_) {
    if (auto link = system_link_.lock()) {
      link->UnregisterKey(*registered_key_);
    }
    registered_key_.reset();
  }
  return X_ERROR_SUCCESS;
}

}  // namespace kernel
}  // namespace xe

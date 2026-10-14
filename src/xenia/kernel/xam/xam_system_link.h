/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2026 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#ifndef XENIA_KERNEL_XAM_XAM_SYSTEM_LINK_H_
#define XENIA_KERNEL_XAM_XAM_SYSTEM_LINK_H_

#include <memory>

#include "xenia/net/system_link.h"

namespace xe {
namespace kernel {

class KernelState;

namespace xam {

// Whether System Link is on, which is also whether the console has a network
// link.
bool SystemLinkEnabled();

// Starts System Link for the running title over the configured transport.
// Null when it is off or cannot start.
std::unique_ptr<net::SystemLink> CreateSystemLink(KernelState* kernel_state);

// The running title's System Link, started on first use. Null when it is off
// or could not start, then the title gets no System Link at all.
std::shared_ptr<net::SystemLink> GetSystemLink(KernelState* kernel_state);

}  // namespace xam
}  // namespace kernel
}  // namespace xe

#endif  // XENIA_KERNEL_XAM_XAM_SYSTEM_LINK_H_

/*
 * UniFlash-Core / Physical Access
 *
 * Geometry-bound raw storage access for NV backup and verification.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once
#include <uniflash/device/sprd_device.h>
namespace uniflash::session {
// Binds exact geometry to a connection. Verifies both GPT copies and wide
// addressing before exposing ranges used by NV backup/verification. The owner
// must re-open after repartition and serialize access to the device; connection
// identity alone does not prove that previously observed geometry is current.
class PhysicalAccess {
public:
    static std::expected<PhysicalAccess,std::errc> open(device::SprdDevice&,std::stop_token = {});
    const layout::GptLayout& layout() const { return layout_; }
    std::expected<void,std::errc> read(device::SprdDevice&,uint64_t,uint64_t,const io::Writer&,std::stop_token = {}) const;
    std::expected<std::vector<uint8_t>,std::errc> read_small(device::SprdDevice&,uint64_t,size_t,std::stop_token = {}) const;
private:
    layout::GptLayout layout_;
    std::shared_ptr<const uint8_t> connection_;
    bool wide_ = false;
};
}

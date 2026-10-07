/*
 * UniFlash-Core / Raw Image Contract
 *
 * Byte preserving replay validation performed before any write.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/session/raw_image_contract.h>
#include "image_fields.h"
#include <array>
namespace uniflash::session {
std::expected<void,std::errc> validate_raw_replay(const io::Reader& reader,uint64_t size,
    const device::DeviceProfile& profile,std::stop_token stop) {
    if(!reader || size<4) return std::unexpected(std::errc::message_size);
    if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    std::array<uint8_t,4> magic{};
    auto got=reader(0,magic,stop);if(!got) return got;
    const auto value=image_fields::le(magic,0);
    if(value==0xed26ff3a) return std::unexpected(std::errc::not_supported);
    if(value!=0x42544844) return {};
    // Exact loader audit: a non-special GPT alias bypasses named security,
    // backup and filesystem routes. BTHD only moves sparse detection to +512;
    // it does not strip the header on that ordinary route.
    if(!profile.bthd_alias_replay) return std::unexpected(std::errc::not_supported);
    if(size<540) return std::unexpected(std::errc::message_size);
    got=reader(512,magic,stop);if(!got) return got;
    if(image_fields::le(magic,0)==0xed26ff3a) return std::unexpected(std::errc::not_supported);
    return {};
}
}

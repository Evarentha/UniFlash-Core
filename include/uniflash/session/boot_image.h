/*
 * UniFlash-Core / Boot Image Header
 *
 * sys_img_header validation of bounds and the declared payload hash.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <uniflash/io/stream.h>
namespace uniflash::session {
struct BootImageHeader { uint32_t payload_size=0; bool declares_hash=false; };
// Unpacked sys_img_header v1 (512 bytes). Validates bounds and declared
// payload hash; does NOT verify certificates or infer a device trust decision.
std::expected<BootImageHeader,std::errc> validate_boot_image(const io::Reader&,uint64_t size,std::stop_token = {});
}

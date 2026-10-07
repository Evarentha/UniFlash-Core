/*
 * UniFlash-Core / RAM Frames
 *
 * RAM payload frame encoding within payload and wire limits.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once
#include <uniflash/protocol/bsl.h>

namespace uniflash::protocol {
struct RamFrame {
    size_t payload_size;
    std::vector<uint8_t> wire;
};
// Largest prefix satisfying decoded capacity, encoded limit and escape rules.
// Selection is entirely local: no probe writes or retransmission.
std::expected<RamFrame, std::errc> encode_ram_midst(std::span<const uint8_t> data,
    BslCodec::Chk checksum, size_t payload_limit, size_t wire_limit,
    size_t packet_size, bool avoid_checksum_escapes);
}

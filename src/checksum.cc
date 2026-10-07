/*
 * UniFlash-Core / CRC-32
 *
 * Table driven CRC-32 matching the sparse image definition.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/io/checksum.h>
#include <array>
namespace uniflash::io {
uint32_t crc32_update(uint32_t crc, std::span<const uint8_t> data) {
    static constexpr auto table = [] {
        std::array<uint32_t, 256> result{};
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (unsigned j = 0; j < 8; ++j) c = (c & 1) ? (0xedb88320u ^ (c >> 1)) : (c >> 1);
            result[i] = c;
        }
        return result;
    }();
    crc ^= 0xffffffff;
    for (auto byte : data) crc = table[(crc ^ byte) & 255] ^ (crc >> 8);
    return crc ^ 0xffffffff;
}
}

/*
 * UniFlash-Core / Chip Identifier Formatting
 *
 * Presentation of chip UID wire payloads in their inspected encodings.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <algorithm>
#include <span>
#include <string>
#include <cstdint>

namespace uniflash::device {
// Keep ChipInfo::chip_uid as the original wire payload. Only presentation
// recognizes the inspected 12-byte length-prefixed and ASCII-hex formats.
inline std::string format_chip_uid(std::span<const uint8_t> bytes) {
    if (bytes.empty() || std::all_of(bytes.begin(), bytes.end(), [](auto b) { return b == 0; })) return {};
    if (bytes.size() == 12 && bytes[0] == 8 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0)
        bytes = bytes.subspan(4);
    auto text = bytes;
    while (!text.empty() && text.back() == 0) text = text.first(text.size() - 1);
    if (text.size() >= 16 && std::all_of(text.begin(), text.end(), [](auto b) {
        return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F');
    })) return std::string(text.begin(), text.end());
    if (std::all_of(bytes.begin(), bytes.end(), [](auto b) { return b == 0; })) return {};
    constexpr char hex[] = "0123456789ABCDEF";
    std::string result;
    for (auto b : bytes) { result += hex[b >> 4]; result += hex[b & 15]; }
    return result;
}
}

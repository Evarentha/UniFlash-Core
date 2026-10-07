/*
 * UniFlash-Core / Partition Filename Encoding
 *
 * Maps partition names to portable filenames without path traversal.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once
#include <algorithm>
#include <string>
#include <string_view>

namespace uniflash::io {
// Use readable partition names where portable; encode unusual device names
// into a disjoint namespace to avoid path traversal and Windows device names.
inline std::string partition_filename(std::string_view name) {
    bool portable = !name.empty() && name != "." && name != ".." && name.back() != '.' &&
        std::all_of(name.begin(), name.end(), [](unsigned char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
        });
    std::string base(name.substr(0, name.find('.')));
    for (auto& c : base) if (c >= 'a' && c <= 'z') c -= 'a' - 'A';
    if (base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" ||
        (base.size() == 4 && (base.starts_with("COM") || base.starts_with("LPT")) &&
         base[3] >= '1' && base[3] <= '9')) portable = false;
    if (portable) return std::string(name) + ".bin";
    // Base32 stays below NAME_MAX for the largest UTF-8 GPT name (108 B),
    // and remains injective on case-insensitive filesystems.
    constexpr char digits[] = "abcdefghijklmnopqrstuvwxyz234567";
    std::string out = "%";
    unsigned bits = 0, value = 0;
    for (unsigned char c : name) {
        value = (value << 8) | c; bits += 8;
        while (bits >= 5) { bits -= 5; out += digits[(value >> bits) & 31]; }
    }
    if (bits) out += digits[(value << (5 - bits)) & 31];
    return out + ".bin";
}
}

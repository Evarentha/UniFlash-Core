#pragma once
#include <algorithm>
#include <string_view>

namespace uniflash::protocol {
// Current encoder supports printable ASCII in 36 UTF-16LE units, with NUL.
inline bool valid_partition_name(std::string_view name) {
    return !name.empty() && name.size() <= 35 &&
        std::all_of(name.begin(), name.end(), [](unsigned char c) {
            return c >= 0x20 && c < 0x7f;
        });
}
}

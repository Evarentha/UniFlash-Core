#pragma once
#include <cstdint>
#include <string>
#include <string_view>

namespace uniflash::text {
struct Scalar { uint32_t value; size_t bytes; bool valid; };
inline Scalar decode(std::string_view input, size_t offset) {
    if (offset >= input.size()) return {0, 0, false};
    const auto c = static_cast<unsigned char>(input[offset]);
    size_t n = c < 128 ? 1 : c >= 0xc2 && c <= 0xdf ? 2 :
        c >= 0xe0 && c <= 0xef ? 3 : c >= 0xf0 && c <= 0xf4 ? 4 : 0;
    if (!n || n > input.size() - offset) return {c, 1, false};
    uint32_t cp = n == 1 ? c : c & (n == 2 ? 31 : n == 3 ? 15 : 7);
    for (size_t j = 1; j < n; ++j) {
        const auto tail = static_cast<unsigned char>(input[offset+j]);
        if ((tail & 0xc0) != 0x80) return {c, 1, false};
        cp = (cp << 6) | (tail & 63);
    }
    if ((n == 2 && cp < 0x80) || (n == 3 && cp < 0x800) || (n == 4 && cp < 0x10000) ||
        (cp >= 0xd800 && cp <= 0xdfff) || cp > 0x10ffff) return {c, 1, false};
    return {cp, n, true};
}
inline size_t scalar_width(uint32_t cp) {
    if ((cp >= 0x300 && cp <= 0x36f) || (cp >= 0x1ab0 && cp <= 0x1aff) ||
        (cp >= 0x1dc0 && cp <= 0x1dff) || (cp >= 0x20d0 && cp <= 0x20ff) ||
        (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xfe20 && cp <= 0xfe2f) || cp == 0x200d) return 0;
    return (cp >= 0x1100 && cp <= 0x115f) || (cp >= 0x2e80 && cp <= 0xa4cf && cp != 0x303f) ||
        (cp >= 0xac00 && cp <= 0xd7a3) || (cp >= 0xf900 && cp <= 0xfaff) ||
        (cp >= 0xfe30 && cp <= 0xfe4f) || (cp >= 0xff01 && cp <= 0xff60) ||
        (cp >= 0xffe0 && cp <= 0xffe6) || (cp >= 0x1f300 && cp <= 0x1faff) ||
        (cp >= 0x20000 && cp <= 0x3fffd) ? 2 : 1;
}
inline size_t width(std::string_view input) {
    size_t columns = 0;
    for (size_t i = 0; i < input.size();) {
        auto cp = decode(input, i);
        columns += cp.valid ? scalar_width(cp.value) : 1;
        i += cp.bytes;
    }
    return columns;
}
inline std::string record(std::string_view input) {
    std::string out;
    constexpr char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < input.size();) {
        auto cp = decode(input, i);
        if (!cp.valid || cp.value < 32 || cp.value == 127 || (cp.value >= 0x80 && cp.value <= 0x9f)) {
            for (size_t j = 0; j < cp.bytes; ++j) {
                const auto c = static_cast<unsigned char>(input[i+j]);
                if (c == '\n') out += "\\n";
                else if (c == '\r') out += "\\r";
                else if (c == '\t') out += "    ";
                else { out += "\\x"; out += hex[c >> 4]; out += hex[c & 15]; }
            }
        } else out.append(input.substr(i, cp.bytes));
        i += cp.bytes;
    }
    return out;
}
inline std::string clip(std::string_view input, size_t columns) {
    size_t end = 0, used = 0;
    while (end < input.size()) {
        auto cp = decode(input, end);
        const auto n = cp.valid ? scalar_width(cp.value) : 1;
        if (n > columns - used) break;
        used += n; end += cp.bytes;
    }
    return std::string(input.substr(0, end));
}
}

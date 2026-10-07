#pragma once

#include <uniflash/io/partition_filename.h>
#include <uniflash/protocol/partition_name.h>
#include <uniflash/cli/arguments.h>
#include <charconv>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

// Private command-layer helpers. Throwing failures are translated at Shell::exec.
namespace uniflash::cli::detail {
inline uint64_t unsigned_number(std::string_view text, uint64_t maximum) {
    int base = 10;
    if (text.starts_with("0x") || text.starts_with("0X")) {
        text.remove_prefix(2);
        base = 16;
    }
    if (text.empty()) throw std::invalid_argument("empty unsigned number");
    uint64_t value = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (error != std::errc{} || end != text.data() + text.size() || value > maximum)
        throw std::invalid_argument("invalid or out-of-range unsigned number");
    return value;
}
inline std::vector<std::string> arguments(std::string_view line) {
    return cli::parse_arguments(line);
}
inline bool safe_partition_name(std::string_view name) {
    return protocol::valid_partition_name(name);
}
using io::partition_filename;
} // namespace uniflash::cli::detail

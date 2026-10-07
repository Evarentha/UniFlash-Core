#include <uniflash/protocol/pctool.h>

#include <array>
#include <charconv>

namespace uniflash::protocol {

std::expected<uint8_t, std::errc> parse_pc_mode(std::string_view value) {
    int base = 10;
    if (value.starts_with("0x") || value.starts_with("0X")) {
        value.remove_prefix(2);
        base = 16;
    }
    unsigned mode = 0;
    const auto [end, error] = std::from_chars(
        value.data(), value.data() + value.size(), mode, base);
    if (error != std::errc{} || end != value.data() + value.size() ||
        mode == 0 || mode > 0x3f)
        return std::unexpected(std::errc::invalid_argument);
    return static_cast<uint8_t>(mode);
}

std::expected<PcToolConfirmation, std::errc>
decode_pctool_confirmation(std::span<const uint8_t> frame) {
    // 8-byte header + 4-byte confirmation + two flags; at most every
    // inner byte is escaped. Bounds checked before any indexing.
    if (frame.size() < 14 || frame.size() > 26 ||
        frame.front() != 0x7e || frame.back() != 0x7e)
        return std::unexpected(std::errc::bad_message);
    std::array<uint8_t, 12> body{};
    size_t size = 0;
    for (size_t i = 1; i + 1 < frame.size(); ++i) {
        uint8_t byte = frame[i];
        if (byte == 0x7d) {
            if (++i >= frame.size() - 1 ||
                (frame[i] != 0x5e && frame[i] != 0x5d))
                return std::unexpected(std::errc::bad_message);
            byte = frame[i] ^ 0x20;
        } else if (byte == 0x7e) {
            return std::unexpected(std::errc::bad_message);
        }
        if (size == body.size()) return std::unexpected(std::errc::message_size);
        body[size++] = byte;
    }
    if (size != body.size() || body[4] != 12 || body[5] != 0 ||
        body[6] != 0x62 || body[7] != 0 || body[10] != 2 || body[11] != 0)
        return std::unexpected(std::errc::bad_message);
    const uint32_t sequence = static_cast<uint32_t>(body[0]) |
        (static_cast<uint32_t>(body[1]) << 8) |
        (static_cast<uint32_t>(body[2]) << 16) |
        (static_cast<uint32_t>(body[3]) << 24);
    return PcToolConfirmation{sequence,
        static_cast<uint16_t>(body[8] | (body[9] << 8))};
}

}  // namespace uniflash::protocol

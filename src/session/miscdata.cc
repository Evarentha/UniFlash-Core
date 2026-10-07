#include <uniflash/session/miscdata.h>
#include <algorithm>
#include <string_view>

namespace uniflash::session {
std::expected<std::pair<std::string, std::string>, std::errc>
parse_miscdata_serials(std::span<const uint8_t> data) {
    if (data.size() < 4) return std::unexpected(std::errc::message_size);
    const uint32_t magic = uint32_t(data[0]) | (uint32_t(data[1]) << 8) |
        (uint32_t(data[2]) << 16) | (uint32_t(data[3]) << 24);
    if (magic != 0x53503135 && magic != 0x53503039 && magic != 0x53503035)
        return std::unexpected(std::errc::not_supported);
    const size_t width = magic == 0x53503135 ? 64 : 24;
    if (data.size() < 4 + 2 * width) return std::unexpected(std::errc::message_size);
    const auto text = [&](size_t offset) {
        auto bytes = data.subspan(offset, width);
        return std::string(bytes.begin(), std::find(bytes.begin(), bytes.end(), uint8_t{0}));
    };
    return std::pair{text(4), text(4 + width)};
}
std::expected<MiscDataInfo, std::errc> parse_miscdata(std::span<const uint8_t> data) {
    if (data.size() < 4) return std::unexpected(std::errc::message_size);
    const auto number = [&](size_t at, size_t length) {
        uint64_t value = 0;
        for (size_t i=0; i<length; ++i) value |= uint64_t(data[at+i]) << (i*8);
        return value;
    };
    const auto text = [&](size_t at, size_t length) {
        std::string value;
        for (auto c : data.subspan(at, length)) {
            if (!c) break;
            value += static_cast<char>(c);
        }
        return value;
    };
    const auto magic = number(0,4);
    const bool sp15 = magic == 0x53503135;
    if (!sp15 && magic != 0x53503039 && magic != 0x53503035)
        return std::unexpected(std::errc::not_supported);
    if (data.size() < (sp15 ? 492u : 256u)) return std::unexpected(std::errc::message_size);
    const size_t sn = sp15 ? 64 : 24, maximum = sp15 ? 20 : 15, name = sp15 ? 15 : 10;
    const auto count = number(4+2*sn,4);
    if (count > maximum) return std::unexpected(std::errc::bad_message);
    MiscDataInfo info;
    info.format = sp15 ? "SP15" : magic == 0x53503039 ? "SP09" : "SP05";
    info.sn1 = text(4,sn); info.sn2 = text(4+sn,sn);
    const size_t stations = 8+2*sn, reserved = stations+maximum*name;
    info.sign_flag = data[reserved+13];
    info.last_failure = text(reserved+14,32);
    info.tested_bits = number(sp15 ? 484 : 252, sp15 ? 4 : 2);
    info.result_bits = number(sp15 ? 488 : 254, sp15 ? 4 : 2);
    if (sp15 && data.size() >= 504) {
        info.alternate_tested_bits = number(488,8);
        info.alternate_result_bits = number(496,8);
        info.ambiguous_status = info.tested_bits != info.alternate_tested_bits ||
            info.result_bits != info.alternate_result_bits;
    }
    const auto status = [](uint64_t tested, uint64_t result, size_t i) {
        return tested & (uint64_t{1} << i) ? StationResult::NotTested :
            result & (uint64_t{1} << i) ? StationResult::Fail : StationResult::Pass;
    };
    for (size_t i=0; i<count; ++i) {
        auto result = status(info.tested_bits, info.result_bits, i);
        if (sp15 && data.size() >= 504 && result != status(info.alternate_tested_bits, info.alternate_result_bits, i))
            result = StationResult::Unknown;
        info.stations.push_back({text(stations+i*name,name),result});
    }
    return info;
}

BootLockRecord parse_boot_lock_record(std::span<const uint8_t> data) {
    if (data.size() < 64) return BootLockRecord::Unavailable;
    data = data.first(64);
    const auto matches = [&](std::string_view marker) {
        return std::equal(marker.begin(), marker.end(), data.begin()) &&
            std::all_of(data.begin() + marker.size(), data.end(), [](uint8_t b) { return b == 0; });
    };
    if (matches("VerifiedBoot-UNLOCK")) return BootLockRecord::UnlockMarker;
    if (matches("VerifiedBoot-LOCK")) return BootLockRecord::LockMarker;
    if (std::all_of(data.begin(), data.end(), [](uint8_t b) { return b == 0; }) ||
        std::all_of(data.begin(), data.end(), [](uint8_t b) { return b == 255; })) return BootLockRecord::Empty;
    return BootLockRecord::Opaque;
}
}

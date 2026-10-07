#ifndef UNIFLASH_CLI_PING_H
#define UNIFLASH_CLI_PING_H

#include <uniflash/device/sprd_device.h>

namespace uniflash::cli {

// Internal check for accepted Enter events in the interactive FDL2 shell.
// Not exposed as a command or inserted by scripts or operation services.
// A failed exchange leaves the session untrusted (including a late ACK).
// Drop its handle and cached layout before any operation can proceed.
inline std::expected<void, std::errc> ping_fdl2(
    std::optional<device::SprdDevice>& dev,
    std::vector<device::PartitionInfo>& parts,
    std::stop_token stop) {
    if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    if (!dev) return std::unexpected(std::errc::not_connected);
    if (dev->info().stage != device::Stage::Fdl2)
        return std::unexpected(std::errc::not_supported);
    auto result = dev->end_process(stop);
    if (!result) {
        dev.reset();
        parts.clear();
    }
    return result;
}

}  // namespace uniflash::cli

#endif

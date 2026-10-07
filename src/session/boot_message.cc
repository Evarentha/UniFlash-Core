/*
 * UniFlash-Core / Boot Message
 *
 * BCB rewriting that preserves stage, reserved and A/B metadata.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#include <uniflash/session/boot_message.h>

#include <algorithm>

namespace uniflash::session {

std::expected<std::vector<uint8_t>, std::errc>
make_boot_message(std::span<const uint8_t> original, RebootTarget target) {
    if (original.size() != BCB_BLOCK_SIZE)
        return std::unexpected(std::errc::message_size);
    const RebootTargetSpec* spec = nullptr;
    for (const auto& candidate : reboot_targets)
        if (candidate.target == target) spec = &candidate;
    if (!spec) return std::unexpected(std::errc::invalid_argument);

    std::vector<uint8_t> modified(original.begin(), original.end());
    std::fill(modified.begin(), modified.begin() + 0x340, 0);
    constexpr std::string_view command = "boot-recovery";
    std::copy(command.begin(), command.end(), modified.begin());
    const std::string options = "recovery\n" + std::string(spec->argument) + "\n";
    std::copy(options.begin(), options.end(), modified.begin() + 0x40);
    return modified;
}

std::expected<void, RebootError>
request_boot_target(device::SprdDevice& dev, RebootTarget target,
          std::stop_token stop) {
    using enum RebootStep;
    // Shared BSP ABI, not a UD710-specific address. Confirm the partition and
    // its capacity first; devices without miscdata use the BCB path directly.
    if (dev.profile().firstmode_offset) {
        auto parts = dev.list_partitions(stop, false);
        if (!parts) return std::unexpected(RebootError{FirstModeRead, parts.error()});
        const auto found = std::find_if(parts->begin(), parts->end(), [](const auto& p) { return p.name == "miscdata"; });
        if (found != parts->end()) {
            const auto offset = *dev.profile().firstmode_offset;
            if (offset > found->size || found->size - offset < 4)
                return std::unexpected(RebootError{FirstModeRead, std::errc::message_size});
            auto first = dev.read_partition("miscdata", offset, 4, stop);
            if (!first) return std::unexpected(RebootError{FirstModeRead, first.error()});
            if (first->size() != 4)
                return std::unexpected(RebootError{FirstModeRead, std::errc::message_size});
            const uint32_t word = uint32_t((*first)[0]) | (uint32_t((*first)[1]) << 8) |
                (uint32_t((*first)[2]) << 16) | (uint32_t((*first)[3]) << 24);
            if ((word & 0xffffff00) == 0x53464d00 && (word & 0x7f) != 0)
                return std::unexpected(RebootError{FirstModeConflict,
                    std::errc::operation_not_permitted, static_cast<uint8_t>(word)});
        }
    }

    auto original = dev.read_partition("misc", 0, BCB_BLOCK_SIZE, stop);
    if (!original) return std::unexpected(RebootError{MiscRead, original.error()});
    auto modified = make_boot_message(*original, target);
    if (!modified) return std::unexpected(RebootError{BuildMessage, modified.error()});
    if (stop.stop_requested())
        return std::unexpected(RebootError{BuildMessage, std::errc::interrupted});

    device::FlashPartition part;
    part.name = "misc";
    part.data = std::move(*modified);
    part.size = part.data.size();
    auto written = dev.write_partition(part, stop);
    if (!written) return std::unexpected(RebootError{MiscWrite, written.error()});
    auto verified = dev.read_partition("misc", 0, BCB_BLOCK_SIZE, stop);
    if (!verified) return std::unexpected(RebootError{MiscVerify, verified.error()});
    if (*verified != part.data)
        return std::unexpected(RebootError{MiscVerify, std::errc::bad_message});
    if (stop.stop_requested())
        return std::unexpected(RebootError{MiscVerify, std::errc::interrupted});
    return {};
}

std::expected<void, RebootError>
reboot_to(device::SprdDevice& dev,RebootTarget target,std::stop_token stop) {
    auto requested=request_boot_target(dev,target,stop);
    if(!requested)return requested;
    auto reset = dev.reset(stop);
    if (!reset) return std::unexpected(RebootError{RebootStep::Reset, reset.error()});
    return {};
}

}  // namespace uniflash::session

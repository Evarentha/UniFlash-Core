/*
 * UniFlash-Core / Boot Message
 *
 * BCB editing for targeted reboots and the Recovery wipe request.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef UNIFLASH_SESSION_BOOT_MESSAGE_H
#define UNIFLASH_SESSION_BOOT_MESSAGE_H

#include <uniflash/device/sprd_device.h>

#include <array>
#include <string_view>

namespace uniflash::session {

enum class RebootTarget { Recovery, Sideload, SideloadAutoReboot, Rescue, Fastbootd, RecoveryWipe };

struct RebootTargetSpec {
    RebootTarget target;
    std::string_view name;
    std::string_view argument;
    bool hidden = false;
};

inline constexpr std::array reboot_targets{
    RebootTargetSpec{RebootTarget::Recovery, "recovery", "--show_text"},
    RebootTargetSpec{RebootTarget::Sideload, "sideload", "--sideload"},
    RebootTargetSpec{RebootTarget::SideloadAutoReboot, "sideload-auto-reboot", "--sideload_auto_reboot"},
    RebootTargetSpec{RebootTarget::Rescue, "rescue", "--rescue"},
    RebootTargetSpec{RebootTarget::Fastbootd, "fastbootd", "--fastboot"},
    RebootTargetSpec{RebootTarget::RecoveryWipe, "recovery-wipe",
                    "--prompt_and_wipe_data\n--reason=Factory reset requested through UniFlash (erase userdata).", true},
};

constexpr const RebootTargetSpec* find_reboot_target(std::string_view name) {
    for (const auto& spec : reboot_targets)
        if (spec.name == name) return &spec;
    return nullptr;
}

inline constexpr size_t BCB_BLOCK_SIZE = 4096;

// Android BCB: command[32], status[32], recovery[768]. Preserve everything
// from 0x340 onward (stage, reserved, A/B metadata), not the old BSP's
// larger recovery[1024] field. No arbitrary Recovery arguments accepted.
std::expected<std::vector<uint8_t>, std::errc>
make_boot_message(std::span<const uint8_t> original, RebootTarget target);

enum class RebootStep { FirstModeRead, FirstModeConflict, MiscRead, BuildMessage,
                        MiscWrite, MiscVerify, Reset };
struct RebootError {
    RebootStep step;
    std::errc reason;
    uint8_t first_mode = 0;

    bool message_may_be_written() const {
        return step == RebootStep::MiscWrite || step == RebootStep::MiscVerify ||
               step == RebootStep::Reset;
    }
};

// Store and read back a next-boot request. Does not reset or retire the FDL2
// connection. The bootloader/Recovery interprets it on a later boot.
std::expected<void, RebootError>
request_boot_target(device::SprdDevice&,RebootTarget,std::stop_token = {});

// Every request validates its own reply; no separate liveness ping. Never
// erases misc, changes firstmode, retries writes, or resets before readback
// matches the entire modified block. Success means RESET ACK, not boot proof.
std::expected<void, RebootError>
reboot_to(device::SprdDevice& dev, RebootTarget target,
          std::stop_token stop = {});

}  // namespace uniflash::session

#endif

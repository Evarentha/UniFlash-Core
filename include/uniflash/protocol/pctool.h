/*
 * UniFlash-Core / PC Tool Mode
 *
 * PC mode values and confirmation frame decoding.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef UNIFLASH_PROTOCOL_PCTOOL_H
#define UNIFLASH_PROTOCOL_PCTOOL_H

#include <cstdint>
#include <expected>
#include <span>
#include <string_view>
#include <system_error>

namespace uniflash::protocol {

// calibration_detect.h / check_pctool_cmd: subtype occupies six bits.
// This interface uses frequency=0; values must not be truncated or masked.
inline constexpr uint8_t PC_MODE_AUTO_DOWNLOAD = 0x02;
inline constexpr uint8_t PC_MODE_AUTOTEST = 0x15;
inline constexpr uint8_t PC_MODE_PROGRAMKEY = 0x17;

std::expected<uint8_t, std::errc> parse_pc_mode(std::string_view value);

struct PcToolConfirmation {
    uint32_t sequence;
    uint16_t status;
};

// Decode one complete escaped MSG_HEAD_T + TOOLS_DIAG_AP_CNF_T frame.
// This is the PC-tool diagnostic protocol, not a checksummed BSL packet.
std::expected<PcToolConfirmation, std::errc>
decode_pctool_confirmation(std::span<const uint8_t> frame);

}  // namespace uniflash::protocol

#endif

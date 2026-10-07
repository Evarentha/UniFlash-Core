/*
 * UniFlash-Core / Miscdata Inspection
 *
 * Serial parsing and the documented boot lock record heuristic.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <system_error>
#include <vector>

namespace uniflash::session {
// Storage evidence, not the secure world's authenticated runtime decision.
inline constexpr uint64_t boot_lock_record_offset = 8192;
enum class BootLockRecord { Unavailable, Empty, LockMarker, UnlockMarker, Opaque };
BootLockRecord parse_boot_lock_record(std::span<const uint8_t>);
enum class StationResult { NotTested, Pass, Fail, Unknown };
struct MiscStation {
    std::string name;
    StationResult result = StationResult::Unknown;
};
struct MiscDataInfo {
    std::string format, sn1, sn2, last_failure;
    uint8_t sign_flag = 0;
    bool ambiguous_status = false;
    uint64_t tested_bits = 0, result_bits = 0;
    uint64_t alternate_tested_bits = 0, alternate_result_bits = 0;
    std::vector<MiscStation> stations;
};
// Fixed-width, little-endian decoding; never cast on-disk bytes to host structs.
// SP15 unsigned-long variants are reported as ambiguous when results differ.
std::expected<MiscDataInfo, std::errc> parse_miscdata(std::span<const uint8_t>);
std::expected<std::pair<std::string, std::string>, std::errc> parse_miscdata_serials(std::span<const uint8_t>);
}

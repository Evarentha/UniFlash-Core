/*
 * UniFlash-Core / Device Profile
 *
 * Library overrides for externally established firmware contracts.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <optional>
#include <string_view>
#include <uniflash/device/nv_contract.h>
#include <uniflash/device/capability.h>

namespace uniflash::device {
enum class LoaderChecksum { Crc16, Add };
// Library overrides for externally established firmware contracts. CLI uses
// automatic defaults and never asks the user to identify a SoC.
struct TransferPolicy {
    bool operator==(const TransferPolicy&) const = default;
    // Receiver limits are separate from framing limits. Partition transfers
    // retain the verified 64 KiB FDL2 baseline; unknown RAM loaders use the
    // minimum capacity found in the inspected implementations.
    static constexpr size_t frame_overhead = 8;
    static constexpr size_t wire_frame_limit = 65536;
    static constexpr size_t escaped_payload_limit = (wire_frame_limit - frame_overhead) / 2;
    static constexpr size_t raw_payload_limit = wire_frame_limit - frame_overhead;
    size_t bootrom_chunk = 1024 - 6;
    // Unknown FDL1 uses the smallest decoded receive capacity found in the
    // supported BSP builds. A verified contract may raise it independently of
    // wire limits; this does not reduce the FDL2 flash/read throughput baseline.
    size_t fdl1_receive_capacity = 0x300;
    // Encoded-wire limit is independent of decoded packet capacity. Unknown
    // builds retain the ROM-compatible bound; audited loader images raise it.
    size_t fdl1_wire_limit = 1023;
    size_t fdl1_chunk = (4096 - frame_overhead) / 2;
    size_t escaped_write_chunk = 32760;
    size_t raw_write_chunk = 63488;
    uint32_t escaped_read_chunk = 32760;
    uint32_t raw_read_chunk = 65024;
    bool avoid_checksum_escapes = true;
    bool allow_disable_transcode = true;
    // Prefer whole-file raw when the adopted FDL advertises mode 2.
    // Mode 1/absent capability stays framed; callers may explicitly opt out.
    // Uncertain/multiblock failures stop; the separate recovery policy below
    // permits a narrow synchronized single-block framed restart.
    bool allow_whole_file_raw = true;
    // Narrow recovery: one complete raw block, explicit failure, ordinary raw
    // filesystem image, recognizable query barriers before/after END.
    bool allow_whole_file_recovery = true;
    bool keep_charge = false;
    bool reset_usb_configuration = false;
    bool split_usb_packet = true;
    static constexpr size_t whole_file_chunk = 0x200000;
};

enum class RawRecoveryContract { Unknown, SingleBlockEndAckRestarts };
struct LoaderFacts {
    bool operator==(const LoaderFacts&) const = default;
    // Independent of raw capability advertisement and user policy. No current
    // bundled loader is audited for recovery; external verified callers may
    // supply this contract. New loader uploads always clear it.
    RawRecoveryContract raw_recovery = RawRecoveryContract::Unknown;
    // Conservative execution contract for the inspected GPT implementations.
    // Independent from the generic wire encoder and overridable by verified callers.
    size_t gpt_max_entries = 128;
    size_t gpt_max_name = 30;
    // Exact-file audit facts carried through loader re-enumeration.
    Capability flash_type_query = Capability::Unknown;
    Capability partition_query = Capability::Unknown;
    Capability user_area_read = Capability::Unknown;
    bool framed_write_u64 = false; // verified 88-byte START parser and u64 write counters
    NvDialect nv_dialect = NvDialect::Unknown;
    bool legacy_gpt_rebuild = false; // audited v0 parser and GPT writer
    bool mirrors_signed_boot_images = false; // audited stored-byte/mirror contract
    bool raw_partition_relocation = false; // byte-preserving ordinary named writes, excluding special routes
    bool bthd_alias_replay = false; // opaque BTHD on non-special aliases, excluding inner sparse
    bool ufs_boot_roles = false; // splloader/_bak map through firmware's boot-role LU table
    uint32_t mbr_sector_size = 0; // 0 unknown; 512 only when externally established
    LoaderChecksum fdl1_checksum = LoaderChecksum::Add;
};
struct DeviceProfile : TransferPolicy, LoaderFacts {
    bool operator==(const DeviceProfile&) const = default;
    // Shared Spreadtrum U-Boot ABI, checked only when miscdata exists and
    // covers this range. Not a SoC identity or a load address.
    std::optional<uint64_t> firstmode_offset = 9 * 1024 + 32;
    constexpr bool valid() const {
        const auto capability=[](Capability c){return c==Capability::Unknown || c==Capability::Supported || c==Capability::Unsupported;};
        return capability(flash_type_query) && capability(partition_query) && capability(user_area_read) &&
            (raw_recovery==RawRecoveryContract::Unknown || raw_recovery==RawRecoveryContract::SingleBlockEndAckRestarts) &&
            (nv_dialect == NvDialect::Unknown || nv_dialect == NvDialect::Signed7MiB) &&
            (mbr_sector_size == 0 || mbr_sector_size == 512) &&
            gpt_max_entries && gpt_max_entries <= 744 && gpt_max_name && gpt_max_name <= 35 &&
            fdl1_receive_capacity > 6 && fdl1_receive_capacity <= wire_frame_limit &&
            fdl1_wire_limit >= 9 && fdl1_wire_limit <= wire_frame_limit &&
            bootrom_chunk && bootrom_chunk <= 1024 - 6 &&
            fdl1_chunk && fdl1_chunk <= escaped_payload_limit &&
            escaped_write_chunk && escaped_write_chunk <= escaped_payload_limit &&
            raw_write_chunk && raw_write_chunk <= raw_payload_limit &&
            escaped_read_chunk && escaped_read_chunk <= escaped_payload_limit &&
            raw_read_chunk && raw_read_chunk <= raw_payload_limit;
    }
};
}

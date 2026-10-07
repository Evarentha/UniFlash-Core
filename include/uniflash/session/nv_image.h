#pragma once
#include <span>
#include <vector>
#include <expected>
#include <system_error>
#include <cstdint>
#include <string>

namespace uniflash::session {
enum class NvChecksumWidth { Bits32, Bits64 };
// R27 validates both LE/BE item headers and, separately, buffers with every
// four-byte word reversed. Caller must establish the representation; item
// payloads cannot generically be byte-swapped based on their ID alone.
// BigItemHeaders keeps the leading update counter LE32; ReversedWords
// reverses the entire LE representation, including that counter.
// R27 INDX outer metadata stays LE while per-core item headers can be BE.
enum class NvByteOrder { Little, BigItemHeaders, ReversedWords, LittleIndexBigItemHeaders };
uint16_t nv_disk_checksum(std::span<const uint8_t>, NvChecksumWidth);
uint32_t nv_transfer_checksum(std::span<const uint8_t>);
// Physical input must have the disk header. Logical input is never inferred
// from an extension or a failed checksum of purported physical input.
std::expected<std::vector<uint8_t>, std::errc> nv_decode_physical(std::span<const uint8_t>, uint32_t expected_size);
std::vector<uint8_t> nv_physical_image(std::span<const uint8_t>, NvChecksumWidth);
enum class NvItemKind { Ordinary, GsmCalibration, TdCalibration, BluetoothConfig };
struct NvMergeItem {
    uint16_t id;
    bool allow_missing = false;
    std::string core{};
    NvItemKind kind = NvItemKind::Ordinary;
};
std::expected<void,std::errc> validate_nv_merge_rules(std::span<const NvMergeItem>,NvByteOrder,NvByteOrder);
// Explicit item IDs only; group IDs and device-specific migrations require
// their own verified schema rather than truncation to a 16-bit item ID.
// Cross-header-order merges require explicit BluetoothConfig rules (ID 0x191,
// 8 bytes). Only xtal_dac changes byte order; the six address bytes are opaque.
std::expected<std::vector<uint8_t>, std::errc> nv_merge_items(
    std::span<const uint8_t> old_payload, std::span<const uint8_t> new_payload,
    uint32_t output_size, std::span<const NvMergeItem>,
    NvByteOrder old_order = NvByteOrder::Little, NvByteOrder new_order = NvByteOrder::Little);
}

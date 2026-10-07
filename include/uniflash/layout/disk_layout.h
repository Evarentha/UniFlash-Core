#pragma once
#include <uniflash/io/stream.h>
#include <array>
#include <string>
#include <vector>

namespace uniflash::layout {
struct GptHeader {
    uint32_t sector_size = 0;
    uint64_t current_lba = 0, alternate_lba = 0;
    uint64_t first_usable = 0, last_usable = 0, entries_lba = 0;
    uint32_t entry_count = 0, entry_size = 0, entries_crc = 0;
    std::array<uint8_t, 16> disk_guid{};
};
struct GptPartition {
    std::string name;
    uint64_t offset = 0, size = 0;
    uint8_t mbr_type = 0;
};
struct GptLayout {
    GptHeader header;
    std::vector<GptPartition> partitions;
    std::vector<uint8_t> primary_sector, entries;
    uint64_t disk_bytes = 0;
    bool mbr = false;
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> extended_sectors;
};
std::expected<GptHeader, std::errc> parse_gpt_header(
    std::span<const uint8_t> sector, uint32_t sector_size, uint64_t expected_lba);
std::expected<GptLayout, std::errc> read_primary_gpt(const io::Reader&, std::stop_token = {});
std::expected<GptLayout, std::errc> read_partition_layout(const io::Reader&, std::stop_token = {},
    uint32_t mbr_sector_size = 0);
bool matching_gpt_headers(const GptHeader&, const GptHeader&);
std::expected<void, std::errc> verify_backup_gpt(const GptLayout&, const io::Reader&, std::stop_token = {});
std::expected<std::string, std::errc> make_layout_xml(const GptLayout&);
}

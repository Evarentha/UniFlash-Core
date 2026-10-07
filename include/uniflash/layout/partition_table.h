/*
 * UniFlash-Core / Partition Table Build
 *
 * Partition specifications and MBR or GPT table construction.
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
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <vector>
namespace uniflash::layout {
struct PartitionSpec {
    std::string name;
    std::string file_path;
    uint64_t size=0;
    uint32_t checksum=0;
    bool has_checksum=false;
    uint64_t flash_addr=0;
    bool has_address=false;
    std::optional<uint64_t> gap;
    bool erase=false,has_erase=false;
    // Preserve XML syntax independently of legacy repartition sentinel values.
    bool has_size=false,size_remaining=false;
};
struct PartitionTableSpec {
    std::string project,version;
    std::vector<PartitionSpec> partitions;
    bool nand=false;
    uint32_t sector_size=512;
    std::optional<uint64_t> disk_size;
    bool legacy_gpt=false,physical_snapshot=false;
};
std::expected<std::vector<uint8_t>,std::errc> build_partition_table(const PartitionTableSpec&);
std::expected<void,std::errc> validate_partition_table(std::span<const uint8_t>,bool legacy_gpt=false,
    uint32_t sector_size=512,std::optional<uint64_t> disk_size={});
}

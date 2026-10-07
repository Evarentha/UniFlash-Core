#include <uniflash/layout/partition_table.h>
#include <uniflash/protocol/bsl.h>
#include <uniflash/protocol/partition_name.h>

#include <algorithm>
#include <limits>
#include <set>

namespace uniflash::layout {
namespace {

constexpr uint64_t MiB = 1024 * 1024;
constexpr uint64_t remaining = std::numeric_limits<uint64_t>::max();

void put(std::vector<uint8_t>& out, size_t offset, uint64_t value, size_t width) {
    for (size_t i = 0; i < width; ++i)
        out[offset + i] = static_cast<uint8_t>(value >> (8 * i));
}

uint64_t get(std::span<const uint8_t> data, size_t offset, size_t width) {
    uint64_t value = 0;
    for (size_t i = 0; i < width; ++i)
        value |= uint64_t(data[offset + i]) << (8 * i);
    return value;
}

bool valid_name(const std::string& name) {
    return protocol::valid_partition_name(name);
}

}  // namespace

std::expected<std::vector<uint8_t>, std::errc>
build_partition_table(const PartitionTableSpec& img) {
    const size_t count = img.partitions.size();
    const bool legacy = img.nand || img.legacy_gpt;
    if (img.nand && img.legacy_gpt) return std::unexpected(std::errc::invalid_argument);
    const size_t header = legacy ? 0 : 16;
    const size_t cell = legacy ? 76 : 88;
    if (count == 0 || count > (protocol::MAX_PAYLOAD_SIZE - header) / cell)
        return std::unexpected(std::errc::invalid_argument);
    if (img.sector_size < 512 || img.sector_size > 4096 || (img.sector_size & (img.sector_size - 1)))
        return std::unexpected(std::errc::invalid_argument);
    if (img.disk_size && (*img.disk_size % img.sector_size != 0 ||
                         *img.disk_size == 0))
        return std::unexpected(std::errc::invalid_argument);

    // eMMC/UFS: v1, byte units, 16-byte header + 88-byte cells.
    // NAND BSP ignores v1/unit parameters: send legacy 76-byte MiB cells.
    std::vector<uint8_t> out(header + cell * count, 0);
    if (!legacy) {
        put(out, 0, 0x3a726170, 4); // "par:"
        out[4] = 1;
        out[5] = 3;
        out[6] = 1;
        put(out, 12, header, 2);
        put(out, 14, count * cell, 2);
    }

    uint64_t end = img.legacy_gpt ? MiB : 0;
    std::set<std::string> names;
    for (size_t i = 0; i < count; ++i) {
        const auto& part = img.partitions[i];
        const bool fill = part.size == remaining || part.size == 0xffffffff;
        if (!valid_name(part.name) || !names.insert(part.name).second ||
            part.size == 0 || (fill && i + 1 != count) ||
            (!fill && (part.size & 0xffffffff) == 0xffffffff))
            return std::unexpected(std::errc::invalid_argument);
        const size_t base = header + i * cell;
        for (size_t j = 0; j < part.name.size(); ++j)
            out[base + 2 * j] = static_cast<uint8_t>(part.name[j]);

        const bool addressed = part.has_address || part.flash_addr != 0;
        if (legacy) {
            if ((img.nand && (addressed || part.gap)) || (!fill &&
                (part.size % MiB != 0 || part.size / MiB >= 0xffffffff)))
                return std::unexpected(std::errc::invalid_argument);
            if (img.legacy_gpt) {
                // v0 cannot encode gaps or arbitrary starts. Never round or
                // silently move a partition while converting from GPT/v1.
                if ((addressed && part.flash_addr != end) || part.gap.value_or(0) != 0)
                    return std::unexpected(std::errc::not_supported);
                if (!fill && part.size > remaining - end)
                    return std::unexpected(std::errc::value_too_large);
                end += fill ? 0 : part.size;
                if (img.disk_size && (end > *img.disk_size || (fill && end >= *img.disk_size)))
                    return std::unexpected(std::errc::no_space_on_device);
            }
            put(out, base + 72, fill ? 0xffffffff : part.size / MiB, 4);
            continue;
        }
        if ((addressed && part.gap) || (!fill && part.size % img.sector_size != 0))
            return std::unexpected(std::errc::invalid_argument);

        uint64_t gap = part.gap.value_or(0);
        if (addressed) {
            if (part.flash_addr < end || (i == 0 && part.flash_addr == 0))
                return std::unexpected(std::errc::invalid_argument);
            gap = part.flash_addr - end;
        }
        if (gap > uint64_t(std::numeric_limits<int64_t>::max()) ||
            gap % img.sector_size != 0)
            return std::unexpected(std::errc::invalid_argument);
        const uint64_t actual_gap = i == 0 && gap == 0 ? MiB : gap;
        if ((i == 0 && actual_gap / img.sector_size < 2) || actual_gap > remaining - end)
            return std::unexpected(std::errc::invalid_argument);
        const uint64_t start = end + actual_gap;
        if (!fill && part.size > remaining - start)
            return std::unexpected(std::errc::value_too_large);
        end = fill ? start : start + part.size;
        // Usable-LBA bounds and GPT entry-array geometry belong to the loader.
        if (img.disk_size && (end > *img.disk_size || (fill && start >= *img.disk_size)))
            return std::unexpected(std::errc::no_space_on_device);
        put(out, base + 72, fill ? remaining : part.size, 8);
        put(out, base + 80, gap, 8);
    }
    return out;
}

std::expected<void, std::errc>
validate_partition_table(std::span<const uint8_t> table, bool legacy_gpt,
    uint32_t sector_size, std::optional<uint64_t> disk_size) {
    const bool v1 = table.size() >= 16 && get(table, 0, 4) == 0x3a726170;
    const size_t header = v1 ? 16 : 0;
    const size_t cell = v1 ? 88 : 76;
    if (table.size() <= header || (table.size() - header) % cell != 0)
        return std::unexpected(std::errc::invalid_argument);
    const size_t count = (table.size() - header) / cell;
    if (table.size() > protocol::MAX_PAYLOAD_SIZE || (v1 &&
        (table[4] != 1 || table[5] != 3 || table[6] != 1 || table[7] != 0 ||
         get(table, 8, 4) != 0 || get(table, 12, 2) != 16 ||
         get(table, 14, 2) != table.size() - 16)))
        return std::unexpected(std::errc::invalid_argument);
    PartitionTableSpec image;
    if (legacy_gpt && v1) return std::unexpected(std::errc::invalid_argument);
    image.nand = !v1 && !legacy_gpt;
    image.legacy_gpt = legacy_gpt;
    image.sector_size = sector_size;
    image.disk_size = disk_size;
    for (size_t i = 0; i < count; ++i) {
        const size_t base = header + i * cell;
        PartitionSpec part;
        bool terminated = false;
        for (size_t j = 0; j < 36; ++j) {
            if (table[base + j * 2 + 1] != 0)
                return std::unexpected(std::errc::invalid_argument);
            const auto c = table[base + j * 2];
            if (c == 0) terminated = true;
            else if (terminated) return std::unexpected(std::errc::invalid_argument);
            else part.name.push_back(static_cast<char>(c));
        }
        const uint64_t size = get(table, base + 72, v1 ? 8 : 4);
        part.size = v1 ? size : size == 0xffffffff ? remaining : size * MiB;
        if (v1) part.gap = get(table, base + 80, 8);
        image.partitions.push_back(std::move(part));
    }
    auto rebuilt = build_partition_table(image);
    if (!rebuilt) return std::unexpected(rebuilt.error());
    return {};
}

}  // namespace uniflash::session

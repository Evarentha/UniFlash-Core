/*
 * UniFlash-Core / Disk Layout Verification
 *
 * GPT parsing and cross-checks against a reader.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/layout/disk_layout.h>
#include <uniflash/io/checksum.h>
#include <algorithm>
#include <set>
#include <optional>

namespace uniflash::layout {
using io::crc32_update;
std::expected<void, std::errc> verify_backup_gpt(const GptLayout& primary,
    const io::Reader& read, std::stop_token stop) {
    const auto& h = primary.header;
    if (primary.mbr || !h.sector_size || h.alternate_lba > UINT64_MAX / h.sector_size)
        return std::unexpected(std::errc::invalid_argument);
    std::vector<uint8_t> sector(h.sector_size);
    auto got = read(h.alternate_lba * h.sector_size, sector, stop);
    if (!got) return got;
    auto backup = parse_gpt_header(sector, h.sector_size, h.alternate_lba);
    if (!backup || !matching_gpt_headers(h, *backup)) return std::unexpected(std::errc::bad_message);
    std::vector<uint8_t> entries(primary.entries.size());
    got = read(backup->entries_lba * h.sector_size, entries, stop);
    if (!got) return got;
    if (crc32_update(0, entries) != backup->entries_crc || entries != primary.entries)
        return std::unexpected(std::errc::bad_message);
    return {};
}
namespace {
uint64_t le(std::span<const uint8_t> bytes, size_t offset, size_t count) {
    uint64_t value = 0;
    for (size_t i = 0; i < count; ++i) value |= uint64_t(bytes[offset + i]) << (i * 8);
    return value;
}
// GPT names are UTF-16LE; do not collapse them to low bytes or guess aliases.
std::expected<std::string, std::errc> name_of(std::span<const uint8_t> entry) {
    std::string name;
    for (size_t i = 56; i < 128; i += 2) {
        uint32_t c = static_cast<uint32_t>(le(entry, i, 2));
        if (!c) break;
        if (c >= 0xd800 && c <= 0xdbff) {
            if (i + 2 >= 128) return std::unexpected(std::errc::illegal_byte_sequence);
            const auto low = le(entry, i + 2, 2);
            if (low < 0xdc00 || low > 0xdfff) return std::unexpected(std::errc::illegal_byte_sequence);
            c = 0x10000 + ((c - 0xd800) << 10) + static_cast<uint32_t>(low - 0xdc00);
            i += 2;
        } else if (c >= 0xdc00 && c <= 0xdfff) return std::unexpected(std::errc::illegal_byte_sequence);
        if (c < 0x80) name += static_cast<char>(c);
        else if (c < 0x800) {
            name += static_cast<char>(0xc0 | (c >> 6)); name += static_cast<char>(0x80 | (c & 63));
        } else if (c < 0x10000) {
            name += static_cast<char>(0xe0 | (c >> 12)); name += static_cast<char>(0x80 | ((c >> 6) & 63));
            name += static_cast<char>(0x80 | (c & 63));
        } else {
            name += static_cast<char>(0xf0 | (c >> 18)); name += static_cast<char>(0x80 | ((c >> 12) & 63));
            name += static_cast<char>(0x80 | ((c >> 6) & 63)); name += static_cast<char>(0x80 | (c & 63));
        }
    }
    if (name.empty()) return std::unexpected(std::errc::bad_message);
    return name;
}
}

std::expected<GptHeader, std::errc> parse_gpt_header(
    std::span<const uint8_t> sector, uint32_t sector_size, uint64_t expected_lba) {
    if (sector.size() != sector_size || sector_size < 512 || sector_size > 4096 ||
        (sector_size & (sector_size - 1))) return std::unexpected(std::errc::invalid_argument);
    constexpr std::array<uint8_t, 8> magic{'E','F','I',' ','P','A','R','T'};
    if (!std::equal(magic.begin(), magic.end(), sector.begin()))
        return std::unexpected(std::errc::bad_message);
    const auto length = le(sector, 12, 4);
    if (le(sector, 8, 4) != 0x10000 || length < 92 || length > sector_size || le(sector, 20, 4))
        return std::unexpected(std::errc::bad_message);
    std::vector<uint8_t> header(sector.begin(), sector.begin() + length);
    std::fill(header.begin() + 16, header.begin() + 20, 0);
    if (crc32_update(0, header) != le(sector, 16, 4)) return std::unexpected(std::errc::bad_message);
    GptHeader h;
    h.sector_size = sector_size;
    h.current_lba = le(sector, 24, 8); h.alternate_lba = le(sector, 32, 8);
    h.first_usable = le(sector, 40, 8); h.last_usable = le(sector, 48, 8);
    std::copy_n(sector.begin() + 56, 16, h.disk_guid.begin());
    h.entries_lba = le(sector, 72, 8);
    h.entry_count = static_cast<uint32_t>(le(sector, 80, 4));
    h.entry_size = static_cast<uint32_t>(le(sector, 84, 4));
    h.entries_crc = static_cast<uint32_t>(le(sector, 88, 4));
    if (h.current_lba != expected_lba || h.alternate_lba == expected_lba ||
        h.current_lba >= UINT64_MAX / sector_size || h.alternate_lba >= UINT64_MAX / sector_size ||
        !h.entry_count || h.entry_size < 128 || h.entry_size % 128 ||
        ((h.entry_size / 128) & (h.entry_size / 128 - 1)) ||
        h.first_usable < 2 || h.last_usable < h.first_usable)
        return std::unexpected(std::errc::bad_message);
    const uint64_t table_bytes = uint64_t(h.entry_count) * h.entry_size;
    // Bound untrusted table allocation independently of the device's capacity.
    if (table_bytes > 16 * 1024 * 1024) return std::unexpected(std::errc::value_too_large);
    const uint64_t table_blocks = (table_bytes + sector_size - 1) / sector_size;
    if (expected_lba == 1) {
        if (h.alternate_lba <= h.last_usable || h.alternate_lba >= UINT64_MAX / sector_size ||
            h.entries_lba < 2 || h.entries_lba >= h.first_usable ||
            table_blocks > h.first_usable - h.entries_lba)
            return std::unexpected(std::errc::bad_message);
    } else if (h.alternate_lba != 1 || h.current_lba <= h.last_usable ||
        h.entries_lba <= h.last_usable || h.entries_lba >= h.current_lba ||
        table_blocks > h.current_lba - h.entries_lba)
        return std::unexpected(std::errc::bad_message);
    return h;
}

bool matching_gpt_headers(const GptHeader& a, const GptHeader& b) {
    return a.current_lba == b.alternate_lba && a.alternate_lba == b.current_lba &&
        a.disk_guid == b.disk_guid && a.sector_size == b.sector_size &&
        a.first_usable == b.first_usable && a.last_usable == b.last_usable &&
        a.entry_count == b.entry_count && a.entry_size == b.entry_size && a.entries_crc == b.entries_crc;
}

std::expected<std::string, std::errc> make_layout_xml(const GptLayout& layout) {
    if (layout.mbr) {
        std::string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<disk-layout scheme=\"mbr\" sector_size=\"512\" names=\"unavailable\">\n";
        for (const auto& p : layout.partitions)
            xml += "  <region label=\"" + p.name + "\" type=\"" + std::to_string(p.mbr_type) +
                "\" address=\"" + std::to_string(p.offset) + "\" size=\"" + std::to_string(p.size) + "\"/>\n";
        return xml + "</disk-layout>\n";
    }
    auto partitions = layout.partitions;
    const auto sector_size = layout.header.sector_size;
    // GPT entry order need not be physical order; the wire builder is sequential.
    std::sort(partitions.begin(), partitions.end(),
        [](const auto& a, const auto& b) { return a.offset < b.offset; });
    // Preserve fill-to-end intent using the actual GPT usable boundary.
    if (!partitions.empty() &&
        sector_size >= 512 && sector_size <= 4096 &&
        layout.disk_bytes % sector_size == 0 &&
        layout.disk_bytes / sector_size > 1 &&
        layout.header.last_usable < layout.disk_bytes / sector_size - 1) {
        auto& last = partitions.back();
        const uint64_t end = (layout.header.last_usable + 1) * sector_size;
        if (last.offset < end && last.size == end - last.offset)
            last.size = UINT64_MAX;
    }
    // Export describes evidence. Wire-format suitability is checked when a
    // caller explicitly prepares a repartition, not while displaying a disk.
    const auto attribute = [](std::string_view name) {
        std::string escaped;
        for (char c : name) {
            switch (c) {
            case '&': escaped += "&amp;"; break;
            case '<': escaped += "&lt;"; break;
            case '>': escaped += "&gt;"; break;
            case '"': escaped += "&quot;"; break;
            default: escaped += c; break;
            }
        }
        return escaped;
    };
    std::string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!-- Byte units. Partition geometry only; GUIDs and GPT attributes are not preserved. -->\n"
        "<rom storage=\"gpt\" sector_size=\"" + std::to_string(sector_size) +
        "\" disk_size=\"" + std::to_string(layout.disk_bytes) + "\">\n";
    for (const auto& part : partitions)
        xml += "  <partition name=\"" + attribute(part.name) + "\" size=\"" +
            (part.size == UINT64_MAX ? std::string("remaining") : std::to_string(part.size)) +
            "\" address=\"" + std::to_string(part.offset) + "\"/>\n";
    xml += "</rom>\n";
    return xml;
}

std::expected<GptLayout, std::errc> read_partition_layout(const io::Reader& read, std::stop_token stop,
    uint32_t mbr_sector_size) {
    std::vector<uint8_t> boot(512);
    auto got = read(0, boot, stop);
    if (!got) return std::unexpected(got.error());
    // Probe GPT independently: some loaders omit the protective MBR.
    for (uint32_t sector : {512u, 1024u, 2048u, 4096u}) {
        std::vector<uint8_t> signature(8);
        got = read(sector, signature, stop);
        if (!got) return std::unexpected(got.error());
        if (std::string(signature.begin(), signature.end()) == "EFI PART") return read_primary_gpt(read, stop);
    }
    if (boot[510] != 0x55 || boot[511] != 0xaa) return std::unexpected(std::errc::bad_message);
    // MBR contains no logical-sector-size field. The caller must supply a
    // verified storage contract; a signature alone cannot distinguish 4Kn.
    if (mbr_sector_size != 512) return std::unexpected(std::errc::not_supported);
    GptLayout layout;
    layout.mbr = true;
    layout.header.sector_size = 512; // conventional 512-byte MBR LBA units
    layout.primary_sector = boot;
    struct Range { uint64_t start, end; };
    std::vector<Range> occupied;
    std::vector<uint64_t> ebr_sectors;
    const auto extended = [](uint8_t type) { return type == 5 || type == 0x0f || type == 0x85; };
    const auto entry = [](const auto& bytes, size_t i) { return std::span(bytes).subspan(446 + 16*i, 16); };
    const auto valid = [&](std::span<const uint8_t> e) {
        return (e[0] == 0 || e[0] == 0x80) && e[4] != 0xee &&
            (e[4] ? le(e, 8, 4) && le(e, 12, 4) : !le(e, 8, 4) && !le(e, 12, 4));
    };
    unsigned logical = 5;
    for (size_t i = 0; i < 4; ++i) {
        const auto e = entry(boot, i);
        if (!valid(e)) return std::unexpected(std::errc::bad_message);
        if (!e[4]) continue;
        const uint64_t base = le(e, 8, 4), end = base + le(e, 12, 4);
        for (auto r : occupied) if (base < r.end && r.start < end) return std::unexpected(std::errc::bad_message);
        occupied.push_back({base,end});
        if (!extended(e[4])) {
            layout.partitions.push_back({"mbr" + std::to_string(i+1), base*512, (end-base)*512, e[4]});
            continue;
        }
        uint64_t current = base;
        std::set<uint64_t> visited;
        for (;;) {
            if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
            if (current < base || current >= end || !visited.insert(current).second || visited.size() > 4096)
                return std::unexpected(std::errc::bad_message);
            std::vector<uint8_t> ebr(512);
            got = read(current*512, ebr, stop);
            if (!got) return std::unexpected(got.error());
            if (ebr[510] != 0x55 || ebr[511] != 0xaa) return std::unexpected(std::errc::bad_message);
            ebr_sectors.push_back(current);
            layout.extended_sectors.emplace_back(current * 512, ebr);
            for (size_t j=0; j<4; ++j) if (!valid(entry(ebr,j))) return std::unexpected(std::errc::bad_message);
            if (entry(ebr,2)[4] || entry(ebr,3)[4]) return std::unexpected(std::errc::bad_message);
            auto data = entry(ebr,0), next = entry(ebr,1);
            if (data[4]) {
                const uint64_t start = current + le(data,8,4), size = le(data,12,4);
                if (extended(data[4]) || start >= end || size > end-start) return std::unexpected(std::errc::bad_message);
                layout.partitions.push_back({"mbr" + std::to_string(logical++), start*512, size*512, data[4]});
            }
            if (!next[4]) break;
            if (!extended(next[4])) return std::unexpected(std::errc::bad_message);
            current = base + le(next,8,4);
            if (current >= end || le(next,12,4) > end-current) return std::unexpected(std::errc::bad_message);
        }
    }
    auto sorted = layout.partitions;
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.offset < b.offset; });
    for (size_t i=0; i<sorted.size(); ++i) {
        if (i && sorted[i].offset < sorted[i-1].offset + sorted[i-1].size) return std::unexpected(std::errc::bad_message);
        for (auto lba : ebr_sectors) if (lba*512 >= sorted[i].offset && lba*512 < sorted[i].offset+sorted[i].size)
            return std::unexpected(std::errc::bad_message);
    }
    if (sorted.empty()) return std::unexpected(std::errc::bad_message);
    return layout;
}

std::expected<GptLayout, std::errc> read_primary_gpt(const io::Reader& read, std::stop_token stop) {
    // One small request detects 512/1K/2K/4K logical blocks without guessing
    // that the entry array always starts at LBA2 or contains exactly 128 rows.
    std::vector<uint8_t> prefix(8192);
    auto got = read(0, prefix, stop);
    if (!got) return std::unexpected(got.error());
    std::optional<GptHeader> found;
    for (uint32_t sector : {512u, 1024u, 2048u, 4096u}) {
        auto header = parse_gpt_header(std::span(prefix).subspan(sector, sector), sector, 1);
        if (!header) continue;
        if (found) return std::unexpected(std::errc::bad_message);
        found = *header;
    }
    if (!found) return std::unexpected(std::errc::bad_message);
    GptLayout layout;
    layout.header = *found;
    const auto& h = layout.header;
    layout.disk_bytes = (h.alternate_lba + 1) * h.sector_size;
    layout.primary_sector.assign(prefix.begin() + h.sector_size, prefix.begin() + 2 * h.sector_size);
    layout.entries.resize(size_t(h.entry_count) * h.entry_size);
    if (h.entries_lba > UINT64_MAX / h.sector_size) return std::unexpected(std::errc::value_too_large);
    auto entries = read(h.entries_lba * h.sector_size, layout.entries, stop);
    if (!entries) return std::unexpected(entries.error());
    if (crc32_update(0, layout.entries) != h.entries_crc) return std::unexpected(std::errc::bad_message);
    std::set<std::string> names;
    std::set<std::array<uint8_t, 16>> guids;
    for (uint32_t i = 0; i < h.entry_count; ++i) {
        auto entry = std::span(layout.entries).subspan(size_t(i) * h.entry_size, h.entry_size);
        if (std::all_of(entry.begin(), entry.begin() + 16, [](auto b) { return b == 0; })) continue;
        const auto first = le(entry, 32, 8), last = le(entry, 40, 8);
        if (first < h.first_usable || last > h.last_usable || first > last)
            return std::unexpected(std::errc::bad_message);
        auto name = name_of(entry);
        if (!name || !names.insert(*name).second) return std::unexpected(std::errc::bad_message);
        std::array<uint8_t, 16> guid;
        std::copy_n(entry.begin() + 16, 16, guid.begin());
        if (std::all_of(guid.begin(), guid.end(), [](auto b) { return !b; }) || !guids.insert(guid).second)
            return std::unexpected(std::errc::bad_message);
        layout.partitions.push_back({std::move(*name), first * h.sector_size, (last - first + 1) * h.sector_size});
    }
    auto sorted = layout.partitions;
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.offset < b.offset; });
    for (size_t i = 1; i < sorted.size(); ++i)
        if (sorted[i].offset < sorted[i - 1].offset + sorted[i - 1].size)
            return std::unexpected(std::errc::bad_message);
    if (layout.partitions.empty()) return std::unexpected(std::errc::bad_message);
    return layout;
}
}

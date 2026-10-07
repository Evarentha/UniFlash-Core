/*
 * UniFlash-Core Test / Repartition
 *
 * Covers strategy handling and terminal action outcomes.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/session/pac_parser.h>

#include <filesystem>
#include <fstream>
#include <uniflash/log.h>
#include <limits>
#include "temp_directory.h"

using namespace uniflash::session;

int main() {
    int failures = 0;
    auto check = [&](bool ok, const char* message) {
        if (!ok) { uniflash::log_err(std::string("FAIL: ") + message); ++failures; }
    };
    auto le = [](const std::vector<uint8_t>& data, size_t offset, size_t width) {
        uint64_t value = 0;
        for (size_t i = 0; i < width; ++i) value |= uint64_t(data[offset+i]) << (i*8);
        return value;
    };
    constexpr uint64_t MiB = 1024*1024;
    PacPartition boot, data;
    boot.name = "boot"; boot.size = 2*MiB;
    data.name = "userdata"; data.size = std::numeric_limits<uint64_t>::max();
    data.has_address = true; data.flash_addr = 8*MiB;
    PacImage image;
    image.partitions = {boot, data};
    image.disk_size = 32*MiB;
    auto table = PacParser::build_repartition_table(image);
    check(table && table->size() == 192, "v1 table length");
    if (!table) return 1;
    check(le(*table, 0, 4) == 0x3a726170 && (*table)[4] == 1 && (*table)[5] == 3,
          "BSP v1 magic/version/byte units");
    check(le(*table,12,2) == 16 && le(*table,14,2) == 176, "BSP header offsets");
    check(le(*table,16+72,8) == 2*MiB && le(*table,16+80,8) == 0,
          "first partition reserves implicit 1 MiB");
    check(le(*table,104+80,8) == 5*MiB && le(*table,104+72,8) == data.size,
          "absolute address converted to gap and final remaining sentinel");
    check(bool(PacParser::validate_repartition_table(*table)), "wire table validates");
    auto malformed = *table;
    malformed[14] = 1;
    check(!PacParser::validate_repartition_table(malformed), "table length mismatch rejected");
    malformed = *table; malformed[5] = 0;
    check(!PacParser::validate_repartition_table(malformed), "unsupported units rejected");

    auto invalid = image;
    invalid.partitions[0].size = 0;
    check(!PacParser::build_repartition_table(invalid), "zero/missing size rejected");
    invalid = image; invalid.partitions[0].size = data.size;
    check(!PacParser::build_repartition_table(invalid), "remaining must be last");
    invalid = image; invalid.partitions[1].flash_addr = MiB;
    check(!PacParser::build_repartition_table(invalid), "overlap rejected");
    invalid = image; invalid.partitions[1].gap = 0;
    check(!PacParser::build_repartition_table(invalid), "address and gap conflict rejected");
    invalid = image; invalid.partitions[0].name = "splloader";
    check(bool(PacParser::build_repartition_table(invalid)), "partition role not inferred from name");
    invalid = image; invalid.partitions[0].name = "userdata";
    check(!PacParser::build_repartition_table(invalid), "duplicate name rejected");
    invalid = image; invalid.partitions[0].name = std::string(35,'a');
    check(bool(PacParser::build_repartition_table(invalid)), "full wire name accepted");
    invalid.partitions[0].name += 'a';
    check(!PacParser::build_repartition_table(invalid), "wire name terminator required");
    invalid = image; invalid.partitions[0].name = "";
    check(!PacParser::build_repartition_table(invalid), "empty name rejected");
    invalid = image; invalid.partitions[0].size = 513;
    check(!PacParser::build_repartition_table(invalid), "no silent sector rounding");
    invalid = image; invalid.partitions[0].size = 0x1ffffffffull;
    check(!PacParser::build_repartition_table(invalid), "accidental BSP remaining alias rejected");
    invalid = image; invalid.disk_size = 4*MiB;
    check(!PacParser::build_repartition_table(invalid), "layout exceeds capacity");
    invalid = image; invalid.partitions[1].flash_addr = ~uint64_t{511};
    check(!PacParser::build_repartition_table(invalid), "signed gap overflow rejected");
    invalid = image; invalid.partitions.resize(129, boot);
    check(!PacParser::build_repartition_table(invalid), "duplicate entries rejected");
    invalid.partitions.clear();
    for (unsigned i=0;i<129;++i) {
        auto p = boot; p.name = "p" + std::to_string(i); p.size = 512;
        invalid.partitions.push_back(p);
    }
    check(bool(PacParser::build_repartition_table(invalid)), "more than 128 entries accepted");
    invalid.partitions.resize(1000, boot);
    check(!PacParser::build_repartition_table(invalid), "table must fit protocol frame");

    {
        auto legacy = image;
        legacy.legacy_gpt = true;
        check(!PacParser::build_repartition_table(legacy), "legacy GPT refuses a gap");
        legacy.partitions[1].flash_addr = 3*MiB;
        auto encoded = PacParser::build_repartition_table(legacy);
        check(encoded && encoded->size()==152 && le(*encoded,72,4)==2 &&
              le(*encoded,148,4)==0xffffffff, "legacy GPT MiB cells preserve contiguous layout");
        legacy.partitions[0].size += 512;
        check(!PacParser::build_repartition_table(legacy), "legacy GPT refuses fractional MiB");
    }
    image.nand = true;
    image.partitions[1].has_address = false; image.partitions[1].flash_addr = 0;
    table = PacParser::build_repartition_table(image);
    check(table && table->size() == 152 && le(*table,72,4) == 2 &&
          le(*table,148,4) == 0xffffffff, "NAND legacy 76-byte MiB cells");
    check(table && bool(PacParser::validate_repartition_table(*table)), "NAND table validates");
    image.partitions[0].size = MiB+512;
    check(!PacParser::build_repartition_table(image), "NAND fractional MiB rejected");

    // Run the actual XML parser. No device operations, unique temp file.
    TempDirectory directory;
    const auto name = directory.path / "layout.xml";
    auto parse = [&](const char* xml) {
        { std::ofstream f(name); f << xml; }
        return PacParser::parse_xml(name);
    };
    auto parsed = parse("<rom storage='emmc' sector_size='512' disk_size='33554432'>"
                        "<partition name='boot' size='2097152'/>"
                        "<partition name='userdata' size='remaining' address='8388608'/></rom>");
    check(parsed && parsed->partitions.size() == 2 &&
          bool(PacParser::build_repartition_table(*parsed)), "complete XML layout builds");
    parsed = parse("<rom storage='gpt' repartition_format='legacy-gpt'><partition name='boot' size='1048576' address='1048576'/></rom>");
    check(parsed && parsed->legacy_gpt && PacParser::build_repartition_table(*parsed)->size()==76,
          "restore XML selects legacy GPT");
    check(!parse("<rom><partition name='boot' size='512'/><partition name='bad' size='oops'/></rom>"),
          "one invalid entry invalidates whole document");
    check(!parse("<rom><partition name='bad' size='-1'/></rom>"), "negative unsigned size rejected");
    check(!parse("<rom><partition name='bad' size='18446744073709551616'/></rom>"), "overflow rejected");
    check(!parse("<rom><partition name='bad' size=512/></rom>"), "unquoted attribute rejected");
    check(!parse("<rom><partition name='bad' size='512' size='1024'/></rom>"), "duplicate attribute rejected");
    check(!parse("<rom/></wrong>"), "trailing closing tag rejected without loop");
    check(!parse("<"), "truncated tag rejected");
    parsed = parse("<?xml version='1.0'?><rom> <!-- note --> <partition name = 'boot' size = '512'/></rom>\n");
    check(parsed && parsed->partitions.size() == 1, "XML declaration/comments/attribute whitespace");
    std::filesystem::remove(name);
    if (failures) return 1;
    uniflash::log_info("Repartition layout and XML tests passed");
}

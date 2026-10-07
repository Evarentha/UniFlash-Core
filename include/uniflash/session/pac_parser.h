#ifndef UNIFLASH_SESSION_PAC_PARSER_H
#define UNIFLASH_SESSION_PAC_PARSER_H

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <system_error>

#include <filesystem>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <uniflash/layout/partition_table.h>

namespace uniflash::session {
class PacArchive;
class PacConfigReader;

using PacPartition=layout::PartitionSpec;
using PacImage=layout::PartitionTableSpec;

class PacParser {
public:
    static std::expected<PacImage, std::errc>
    parse_xml(const std::filesystem::path& xml_path);

    static std::expected<std::vector<uint8_t>, std::errc>
    build_repartition_table(const PacImage& img) { return layout::build_partition_table(img); }

    // Validate externally supplied wire tables before issuing command 0x0B.
    static std::expected<void, std::errc>
    validate_repartition_table(std::span<const uint8_t> table, bool legacy_gpt = false,
        uint32_t sector_size = 512, std::optional<uint64_t> disk_size = {}) {
        return layout::validate_partition_table(table,legacy_gpt,sector_size,disk_size);
    }

private:
    friend class PacArchive;
    friend class PacConfigReader;
    struct XmlElement {
        std::string tag;
        std::map<std::string, std::string> attrs;
        std::string text;
        std::vector<std::unique_ptr<XmlElement>> children;
    };

    static std::expected<std::unique_ptr<XmlElement>, std::errc>
    parse_xml_fragment(const std::string& text, size_t& pos, size_t depth = 0);
    static std::expected<std::unique_ptr<XmlElement>,std::errc> parse_document(std::string text,size_t limit);

    static std::expected<std::string, std::errc>
    read_file_text(const std::filesystem::path& p);

};

}

#endif

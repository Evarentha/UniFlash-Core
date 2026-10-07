/*
 * UniFlash-Core / PAC Parsing
 *
 * Structured and flat PAC parsing with bounded XML handling.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#include <uniflash/session/pac_parser.h>
#include <uniflash/protocol/bsl.h>
#include <uniflash/platform.h>

#include <fstream>
#include <sstream>
#include <iostream>
#include <cctype>
#include <algorithm>
#include <cstring>
#include <charconv>
#include <limits>
#include <set>
#include <uniflash/text.h>

namespace uniflash::session {

namespace fs = std::filesystem;

namespace {

constexpr size_t xml_limit = 8 * 1024 * 1024;
std::expected<std::string, std::errc> xml_value(std::string_view input) {
    std::string out;
    for (size_t i = 0; i < input.size(); ++i) {
        const auto c = static_cast<unsigned char>(input[i]);
        if (c == '<' || (c < 32 && c != 9 && c != 10 && c != 13))
            return std::unexpected(std::errc::invalid_argument);
        if (c != '&') { out += static_cast<char>(c); continue; }
        const auto end = input.find(';', i + 1);
        if (end == input.npos) return std::unexpected(std::errc::invalid_argument);
        auto entity = input.substr(i + 1, end - i - 1);
        uint32_t cp = 0;
        if (entity == "amp") cp = '&';
        else if (entity == "quot") cp = '"';
        else if (entity == "apos") cp = '\'';
        else if (entity == "lt") cp = '<';
        else if (entity == "gt") cp = '>';
        else if (entity.starts_with('#')) {
            entity.remove_prefix(1);
            int base = 10;
            if (entity.starts_with('x')) { base = 16; entity.remove_prefix(1); }
            const auto [ptr, ec] = std::from_chars(entity.data(), entity.data() + entity.size(), cp, base);
            if (entity.empty() || ec != std::errc{} || ptr != entity.data() + entity.size())
                return std::unexpected(std::errc::invalid_argument);
        } else return std::unexpected(std::errc::not_supported);
        if ((cp < 32 && cp != 9 && cp != 10 && cp != 13) || cp > 0x10ffff ||
            (cp >= 0xd800 && cp <= 0xdfff) || cp == 0xfffe || cp == 0xffff)
            return std::unexpected(std::errc::illegal_byte_sequence);
        if (cp < 0x80) out += static_cast<char>(cp);
        else {
            if (cp < 0x800) out += static_cast<char>(0xc0 | (cp >> 6));
            else {
                if (cp < 0x10000) out += static_cast<char>(0xe0 | (cp >> 12));
                else { out += static_cast<char>(0xf0 | (cp >> 18)); out += static_cast<char>(0x80 | ((cp >> 12) & 63)); }
                out += static_cast<char>(0x80 | ((cp >> 6) & 63));
            }
            out += static_cast<char>(0x80 | (cp & 63));
        }
        i = end;
    }
    return out;
}


std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b-1]))) --b;
    return s.substr(a, b - a);
}

bool parse_u32(const std::string& s, uint32_t& out, int base = 0) {
    std::string_view text(s);
    if (text.starts_with("0x") || text.starts_with("0X")) {
        text.remove_prefix(2);
        base = 16;
    }
    if (base == 0) base = 10;
    if (text.empty()) return false;
    const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), out, base);
    return ec == std::errc{} && end == text.data() + text.size();
}

bool parse_u64(const std::string& s, uint64_t& out, int base = 0) {
    std::string_view text(s);
    if (text.starts_with("0x") || text.starts_with("0X")) {
        text.remove_prefix(2);
        base = 16;
    }
    if (base == 0) base = 10;
    if (text.empty()) return false;
    const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), out, base);
    return ec == std::errc{} && end == text.data() + text.size();
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

}

std::expected<std::string, std::errc>
PacParser::read_file_text(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return std::unexpected(std::errc::no_such_file_or_directory);
    std::string text;
    char buffer[4096];
    while (f.read(buffer, sizeof buffer) || f.gcount()) {
        if (static_cast<size_t>(f.gcount()) > xml_limit - text.size())
            return std::unexpected(std::errc::file_too_large);
        text.append(buffer, static_cast<size_t>(f.gcount()));
    }
    if (f.bad()) return std::unexpected(std::errc::io_error);
    return text;
}

std::expected<std::unique_ptr<PacParser::XmlElement>, std::errc>
PacParser::parse_xml_fragment(const std::string& text, size_t& pos, size_t depth) {
    if (depth >= 64) return std::unexpected(std::errc::value_too_large);
    while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) ++pos;

    if (pos >= text.size() || text[pos] != '<') {
        return std::unexpected(std::errc::invalid_argument);
    }

    if (text.compare(pos, 4, "<!--") == 0) {
        auto end = text.find("-->", pos + 4);
        if (end == std::string::npos) return std::unexpected(std::errc::invalid_argument);
        pos = end + 3;
        return nullptr;
    }
    if (pos + 1 >= text.size()) return std::unexpected(std::errc::invalid_argument);
    if (text[pos+1] == '?') {
        auto end = text.find("?>", pos + 2);
        if (end == std::string::npos) return std::unexpected(std::errc::invalid_argument);
        pos = end + 2;
        return nullptr;
    }
    if (text[pos+1] == '/') return std::unexpected(std::errc::invalid_argument);

    ++pos;
    auto elem = std::make_unique<XmlElement>();
    auto tag_end = text.find_first_of(" \t\r\n/>", pos);
    if (tag_end == std::string::npos || tag_end == pos)
        return std::unexpected(std::errc::invalid_argument);
    elem->tag = text.substr(pos, tag_end - pos);
    pos = tag_end;

    while (pos < text.size() && text[pos] != '>' && text[pos] != '/') {
        while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) ++pos;
        if (pos == text.size() || text[pos] == '>' || text[pos] == '/') break;
        auto name_end = text.find_first_of("= \t\r\n/>", pos);
        if (name_end == std::string::npos || name_end == pos)
            return std::unexpected(std::errc::invalid_argument);
        std::string name = text.substr(pos, name_end - pos);
        pos = name_end;
        while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) ++pos;
        if (pos == text.size() || text[pos++] != '=')
            return std::unexpected(std::errc::invalid_argument);
        while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) ++pos;
        if (pos < text.size() && (text[pos] == '"' || text[pos] == '\'')) {
            char q = text[pos];
            ++pos;
            auto val_end = text.find(q, pos);
            if (val_end == std::string::npos) return std::unexpected(std::errc::invalid_argument);
            auto value = xml_value(std::string_view(text).substr(pos, val_end - pos));
            if (!value) return std::unexpected(value.error());
            if (!elem->attrs.emplace(name, std::move(*value)).second)
                return std::unexpected(std::errc::invalid_argument);
            pos = val_end + 1;
        } else {
            return std::unexpected(std::errc::invalid_argument);
        }
    }

    while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) ++pos;

    if (pos < text.size() && text[pos] == '/') {
        ++pos;
        if (pos == text.size() || text[pos++] != '>')
            return std::unexpected(std::errc::invalid_argument);
        return elem;
    }
    if (pos >= text.size() || text[pos] != '>')
        return std::unexpected(std::errc::invalid_argument);
    ++pos;

    std::string text_buf;
    while (pos < text.size()) {
        if (text[pos] == '<' && pos + 1 < text.size() && text[pos+1] == '/') {
            pos += 2;
            auto close_end = text.find('>', pos);
            if (close_end == std::string::npos) return std::unexpected(std::errc::invalid_argument);
            std::string close_tag = trim(text.substr(pos, close_end - pos));
            if (close_tag != elem->tag) {
                return std::unexpected(std::errc::invalid_argument);
            }
            pos = close_end + 1;
            auto value = xml_value(trim(text_buf));
            if (!value) return std::unexpected(value.error());
            elem->text = std::move(*value);
            return elem;
        }
        if (text[pos] == '<') {
            auto sub = parse_xml_fragment(text, pos, depth + 1);
            if (!sub) return std::unexpected(sub.error());
            if (sub.value()) elem->children.push_back(std::move(sub.value()));
        } else {
            text_buf.push_back(text[pos]);
            ++pos;
        }
    }
    return std::unexpected(std::errc::invalid_argument);
}

std::expected<std::unique_ptr<PacParser::XmlElement>,std::errc>
PacParser::parse_document(std::string text,size_t limit) {
    if(text.size()>limit)return std::unexpected(std::errc::file_too_large);
    if(text.starts_with("\xef\xbb\xbf"))text.erase(0,3);
    for(size_t at=0;at<text.size();) {
        const auto cp=uniflash::text::decode(text,at);
        if(!cp.valid || (cp.value<32 && cp.value!=9 && cp.value!=10 && cp.value!=13) || cp.value==0xfffe || cp.value==0xffff)
            return std::unexpected(std::errc::illegal_byte_sequence);
        at+=cp.bytes;
    }
    size_t pos=0;std::unique_ptr<XmlElement> root;
    while(pos<text.size()) {
        if(text[pos]==' ' || text[pos]=='\t' || text[pos]=='\r' || text[pos]=='\n'){++pos;continue;}
        if(root && text.compare(pos,4,"<!--")!=0)return std::unexpected(std::errc::invalid_argument);
        auto node=parse_xml_fragment(text,pos);if(!node)return std::unexpected(node.error());
        if(*node)root=std::move(*node);
    }
    if(!root)return std::unexpected(std::errc::invalid_argument);
    return root;
}

std::expected<PacImage, std::errc>
PacParser::parse_xml(const fs::path& xml_path) {
    auto text = read_file_text(xml_path);
    if (!text) return std::unexpected(text.error());
    auto document=parse_document(std::move(*text),xml_limit);
    if(!document)return std::unexpected(document.error());
    auto root=std::move(*document);
    // Ordinary layout schema is deliberately separate from BMAConfig/PAC.
    if(lower(root->tag)!="rom" || !root->text.empty())return std::unexpected(std::errc::not_supported);
    const std::set<std::string> root_fields{"name","version","storage","sector_size","disk_size","repartition_format","image_semantics"};
    const std::set<std::string> part_fields{"name","file","size","checksum","address","gap","erase"};
    for(const auto& [key,value]:root->attrs) {
        (void)value;if(!root_fields.contains(key))return std::unexpected(std::errc::not_supported);
    }
    std::set<std::string> names;
    for(const auto& node:root->children) {
        if(lower(node->tag)!="partition" || !node->children.empty() || !node->text.empty())
            return std::unexpected(std::errc::not_supported);
        for(const auto& [key,value]:node->attrs) {
            (void)value;if(!part_fields.contains(key))return std::unexpected(std::errc::not_supported);
        }
        const auto name=node->attrs.find("name");
        if(name==node->attrs.end() || name->second.empty() || !names.insert(name->second).second)
            return std::unexpected(std::errc::invalid_argument);
    }
    PacImage image;
    auto get_attr = [&](XmlElement* e, const std::string& key, std::string& out) {
        auto it = e->attrs.find(key);
        if (it != e->attrs.end()) { out = it->second; return true; }
        return false;
    };

    std::string proj, ver;
    std::string semantics;
    if (get_attr(root.get(), "image_semantics", semantics)) {
        if (semantics != "physical-snapshot") return std::unexpected(std::errc::not_supported);
        image.physical_snapshot = true;
    }
    if (get_attr(root.get(), "name", proj)) image.project = proj;
    if (get_attr(root.get(), "version", ver)) image.version = ver;
    std::string storage, sector, capacity;
    if (get_attr(root.get(), "storage", storage)) {
        storage = lower(storage);
        if (storage == "nand") image.nand = true;
        else if (storage != "gpt" && storage != "emmc" && storage != "ufs")
            return std::unexpected(std::errc::invalid_argument);
    }
    std::string format;
    if (get_attr(root.get(), "repartition_format", format)) {
        if (format == "legacy-gpt" && !image.nand) image.legacy_gpt = true;
        else if (format != "v1" || image.nand) return std::unexpected(std::errc::invalid_argument);
    }
    if (get_attr(root.get(), "sector_size", sector) &&
        (!parse_u32(sector, image.sector_size) ||
         (image.sector_size < 512 || image.sector_size > 4096 ||
          (image.sector_size & (image.sector_size - 1)))))
        return std::unexpected(std::errc::invalid_argument);
    if (get_attr(root.get(), "disk_size", capacity)) {
        uint64_t bytes;
        if (!parse_u64(capacity, bytes) || bytes == 0)
            return std::unexpected(std::errc::invalid_argument);
        image.disk_size = bytes;
    }

    auto load_partition = [&](XmlElement* p_elem) -> std::expected<PacPartition, std::errc> {
        PacPartition part;
        std::string s;
        if (get_attr(p_elem, "name", s))    part.name = s;
        if (get_attr(p_elem, "file", s))    part.file_path = s;
        if (get_attr(p_elem, "size", s)) {
            part.has_size = true;
            part.size_remaining = s == "remaining";
            uint64_t v;
            if (s == "remaining") v = std::numeric_limits<uint64_t>::max();
            else if (!parse_u64(s, v)) return std::unexpected(std::errc::invalid_argument);
            part.size = v;
        }
        if (get_attr(p_elem, "checksum", s)) {
            part.has_checksum = true;
            uint32_t v; if (!parse_u32(s, v, 16)) return std::unexpected(std::errc::invalid_argument);
            part.checksum = v;
        }
        if (get_attr(p_elem, "address", s)) {
            uint64_t v; if (!parse_u64(s, v)) return std::unexpected(std::errc::invalid_argument);
            part.flash_addr = v;
            part.has_address = true;
        }
        if (get_attr(p_elem, "gap", s)) {
            uint64_t v;
            if (!parse_u64(s, v)) return std::unexpected(std::errc::invalid_argument);
            part.gap = v;
        }
        std::string erase_str;
        if (get_attr(p_elem, "erase", erase_str)) {
            const auto value = lower(erase_str);
            if (value != "true" && value != "false" && value != "1" && value != "0")
                return std::unexpected(std::errc::invalid_argument);
            part.has_erase = true;
            part.erase = value == "true" || value == "1";
        }
        return part;
    };

    for(const auto& node:root->children) {
        auto part=load_partition(node.get());if(!part)return std::unexpected(part.error());
        image.partitions.push_back(std::move(*part));
    }

    return image;
} 

}

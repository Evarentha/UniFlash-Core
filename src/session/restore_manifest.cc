/*
 * UniFlash-Core / Restore Manifest
 *
 * Strict bounded manifest parser with depth and size limits.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#include <uniflash/session/restore_manifest.h>
#include <uniflash/text.h>
#include <uniflash/protocol/partition_name.h>
#include <uniflash/io/sha256.h>
#include <charconv>
#include <fstream>
#include <map>
#include <set>
#include <variant>

namespace uniflash::session {
namespace {
struct Value {
    using Object=std::map<std::string,Value>;
    using Array=std::vector<Value>;
    std::variant<std::nullptr_t,bool,uint64_t,std::string,Object,Array> data=nullptr;
};
class Parser {
public:
    explicit Parser(std::string_view source):text_(source) {}
    std::expected<Value,std::errc> document() {
        auto value=parse(0);space();
        if(!value || at_!=text_.size()) return std::unexpected(std::errc::bad_message);
        return value;
    }
private:
    std::string_view text_;
    size_t at_=0,nodes_=0;
    void space() {while(at_<text_.size() && (text_[at_]==' ' || text_[at_]=='\n' || text_[at_]=='\r' || text_[at_]=='\t')) ++at_;}
    bool take(char c) {space();if(at_==text_.size() || text_[at_]!=c) return false;++at_;return true;}
    std::expected<uint32_t,std::errc> hex4() {
        if(text_.size()-at_<4) return std::unexpected(std::errc::bad_message);
        uint32_t n=0;auto [end,ec]=std::from_chars(text_.data()+at_,text_.data()+at_+4,n,16);
        if(ec!=std::errc{} || end!=text_.data()+at_+4) return std::unexpected(std::errc::bad_message);
        at_+=4;return n;
    }
    static void utf8(std::string& out,uint32_t cp) {
        if(cp<128) out+=static_cast<char>(cp);
        else if(cp<0x800) {out+=static_cast<char>(0xc0|(cp>>6));out+=static_cast<char>(0x80|(cp&63));}
        else {
            if(cp<0x10000) out+=static_cast<char>(0xe0|(cp>>12));
            else {out+=static_cast<char>(0xf0|(cp>>18));out+=static_cast<char>(0x80|((cp>>12)&63));}
            out+=static_cast<char>(0x80|((cp>>6)&63));out+=static_cast<char>(0x80|(cp&63));
        }
    }
    std::expected<std::string,std::errc> string() {
        if(!take('"')) return std::unexpected(std::errc::bad_message);
        std::string out;
        while(at_<text_.size()) {
            const auto c=static_cast<unsigned char>(text_[at_++]);
            if(c=='"') return out;
            if(c<32) return std::unexpected(std::errc::bad_message);
            if(c!='\\') {out+=static_cast<char>(c);continue;}
            if(at_==text_.size()) break;
            const char escape=text_[at_++];
            switch(escape) {
            case '"':case '\\':case '/':out+=escape;break;
            case 'b':out+='\b';break;case 'f':out+='\f';break;
            case 'n':out+='\n';break;case 'r':out+='\r';break;case 't':out+='\t';break;
            case 'u': {
                auto cp=hex4();if(!cp) return std::unexpected(cp.error());
                if(*cp>=0xd800 && *cp<=0xdbff) {
                    if(text_.substr(at_,2)!="\\u") return std::unexpected(std::errc::bad_message);
                    at_+=2;auto low=hex4();
                    if(!low || *low<0xdc00 || *low>0xdfff) return std::unexpected(std::errc::bad_message);
                    *cp=0x10000+((*cp-0xd800)<<10)+(*low-0xdc00);
                } else if(*cp>=0xdc00 && *cp<=0xdfff) return std::unexpected(std::errc::bad_message);
                utf8(out,*cp);break;
            }
            default:return std::unexpected(std::errc::bad_message);
            }
        }
        return std::unexpected(std::errc::bad_message);
    }
    std::expected<Value,std::errc> parse(size_t depth) {
        if(depth>32 || ++nodes_>65536) return std::unexpected(std::errc::value_too_large);
        space();if(at_==text_.size()) return std::unexpected(std::errc::bad_message);
        Value result;
        if(text_[at_]=='"') {auto s=string();if(!s) return std::unexpected(s.error());result.data=std::move(*s);return result;}
        if(take('{')) {
            Value::Object object;
            if(take('}')) {result.data=std::move(object);return result;}
            do {
                auto key=string();if(!key || !take(':')) return std::unexpected(std::errc::bad_message);
                auto value=parse(depth+1);if(!value) return value;
                if(!object.emplace(std::move(*key),std::move(*value)).second) return std::unexpected(std::errc::bad_message);
                if(take('}')) {result.data=std::move(object);return result;}
            } while(take(','));
            return std::unexpected(std::errc::bad_message);
        }
        if(take('[')) {
            Value::Array array;
            if(take(']')) {result.data=std::move(array);return result;}
            do {
                auto value=parse(depth+1);if(!value) return value;array.push_back(std::move(*value));
                if(take(']')) {result.data=std::move(array);return result;}
            } while(take(','));
            return std::unexpected(std::errc::bad_message);
        }
        for(const auto literal:{std::string_view("true"),std::string_view("false"),std::string_view("null")}) {
            if(text_.substr(at_,literal.size())==literal) {
                at_+=literal.size();if(literal!="null") result.data=literal=="true";return result;
            }
        }
        const auto begin=at_;
        while(at_<text_.size() && text_[at_]>='0' && text_[at_]<='9') ++at_;
        if(at_==begin || (at_-begin>1 && text_[begin]=='0')) return std::unexpected(std::errc::bad_message);
        uint64_t number=0;auto [end,ec]=std::from_chars(text_.data()+begin,text_.data()+at_,number);
        if(ec!=std::errc{} || end!=text_.data()+at_) return std::unexpected(std::errc::bad_message);
        result.data=number;return result;
    }
};
template<class T> const T* field(const Value::Object& object,const char* name) {
    const auto found=object.find(name);return found==object.end()?nullptr:std::get_if<T>(&found->second.data);
}
}
std::expected<RestoreManifest,std::errc> read_restore_manifest(const std::filesystem::path& file) {
    std::ifstream in(file,std::ios::binary);
    if(!in) return std::unexpected(std::errc::no_such_file_or_directory);
    std::string text;char buffer[4096];
    while(in.read(buffer,sizeof buffer) || in.gcount()) {
        if(text.size()+static_cast<size_t>(in.gcount())>8*1024*1024) return std::unexpected(std::errc::file_too_large);
        text.append(buffer,static_cast<size_t>(in.gcount()));
    }
    if(in.bad()) return std::unexpected(std::errc::io_error);
    for(size_t at=0;at<text.size();) {auto cp=uniflash::text::decode(text,at);if(!cp.valid) return std::unexpected(std::errc::illegal_byte_sequence);at+=cp.bytes;}
    auto parsed=Parser(text).document();if(!parsed) return std::unexpected(parsed.error());
    const auto root=std::get_if<Value::Object>(&parsed->data);if(!root) return std::unexpected(std::errc::bad_message);
    const auto format=field<std::string>(*root,"format"),scheme=field<std::string>(*root,"partition_scheme");
    const auto complete=field<bool>(*root,"complete");
    const auto disk=field<uint64_t>(*root,"user_area_bytes_from_gpt"),sector=field<uint64_t>(*root,"sector_size");
    const auto entries=field<Value::Array>(*root,"partitions");
    if(!format || (*format!="raw-partition-backup-v1" && *format!="raw-partition-backup-v2" && *format!="raw-partition-backup-v3") ||
        !scheme || *scheme!="gpt" || !complete || !*complete || !disk || !*disk || !sector ||
        (*sector!=512 && *sector!=1024 && *sector!=2048 && *sector!=4096) || !entries || entries->empty() || entries->size()>1024)
        return std::unexpected(std::errc::bad_message);
    const bool hashed=*format=="raw-partition-backup-v3";
    if(hashed) {
        auto semantics=field<std::string>(*root,"image_semantics");
        if(!semantics || *semantics!="physical-snapshot") return std::unexpected(std::errc::bad_message);
    }
    if(const auto limitation=field<std::string>(*root,"limitation");!limitation || !limitation->empty())
        return std::unexpected(std::errc::not_supported);
    RestoreManifest manifest;manifest.disk_bytes=*disk;manifest.sector_size=static_cast<uint32_t>(*sector);
    if(hashed) {
        const auto header_hash=field<std::string>(*root,"primary_header_sha256");
        const auto entries_hash=field<std::string>(*root,"partition_entries_sha256");
        if(!header_hash || !entries_hash || !io::valid_sha256(*header_hash) || !io::valid_sha256(*entries_hash))
            return std::unexpected(std::errc::bad_message);
        manifest.header_sha256=*header_hash;manifest.entries_sha256=*entries_hash;
    }
    std::set<std::string> names,files;uint64_t total=0;
    for(const auto& value:*entries) {
        const auto o=std::get_if<Value::Object>(&value.data);if(!o) return std::unexpected(std::errc::bad_message);
        const auto name=field<std::string>(*o,"name"),path=field<std::string>(*o,"file"),source=field<std::string>(*o,"source"),status=field<std::string>(*o,"status");
        const auto expected=field<uint64_t>(*o,"expected_bytes"),actual=field<uint64_t>(*o,"actual_bytes"),offset=field<uint64_t>(*o,"offset_bytes");
        if(!name || !protocol::valid_partition_name(*name) || !path || path->empty() || !source || !status || *status!="saved" ||
            !expected || !*expected || !actual || *expected!=*actual || !offset || !names.insert(*name).second ||
            path->find_first_of("/\\:")!=std::string::npos || *path=="." || *path==".." || path->find('\0')!=std::string::npos ||
            name->find('\0')!=std::string::npos || source->find('\0')!=std::string::npos ||
            (*source!="user_partition" && *source!=*name) || *expected>UINT64_MAX-total) return std::unexpected(std::errc::bad_message);
        auto folded=*path;for(auto& c:folded) if(c>='A' && c<='Z') c+=32;
        if(!files.insert(folded).second) return std::unexpected(std::errc::bad_message);
        if(*source=="user_partition" && (*offset>*disk || *expected>*disk-*offset ||
            *offset%*sector || *expected%*sector)) return std::unexpected(std::errc::bad_message);
        const auto digest=field<std::string>(*o,"sha256");
        if((hashed && !digest) || (digest && !io::valid_sha256(*digest))) return std::unexpected(std::errc::bad_message);
        total+=*expected;manifest.entries.push_back({*name,*path,*source,*expected,*offset,digest?*digest:std::string{}});
    }
    const auto recorded_total=field<uint64_t>(*root,"total_read"),count=field<uint64_t>(*root,"partitions_read");
    if(!recorded_total || *recorded_total!=total || !count || *count!=manifest.entries.size()) return std::unexpected(std::errc::bad_message);
    return manifest;
}
}

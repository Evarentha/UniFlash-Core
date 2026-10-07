/*
 * UniFlash-Core / Packed Image Formats
 *
 * SCI1 directory, modem range and verification view parsing.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/session/packed_image.h>
#include <uniflash/session/signed_image.h>
#include <uniflash/io/output.h>
#include <uniflash/io/sha256.h>
#include "image_fields.h"
#include <algorithm>
#include <array>
#include <vector>

namespace uniflash::session {
using namespace image_fields;
std::expected<SciModemRange,std::errc> parse_sci_modem(const io::Reader& reader,uint64_t size,std::stop_token stop) {
    if(!reader || size<24) return std::unexpected(std::errc::message_size);
    std::array<uint8_t,12> row{};
    if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    auto got=reader(0,row,stop);if(!got) return std::unexpected(got.error());
    if(le(row,0)!=0x31494353 || row[4]) return std::unexpected(std::errc::bad_message);
    std::vector<std::pair<uint64_t,uint64_t>> regions;
    SciModemRange modem;
    uint64_t directory_end=0,last_end=0;
    for(size_t i=1;i<=10;++i) {
        const uint64_t at=i*12;
        if(!range(at,12,size)) return std::unexpected(std::errc::message_size);
        if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
        got=reader(at,row,stop);if(!got) return std::unexpected(got.error());
        const auto flags=le(row,0),offset=le(row,4),length=le(row,8),type=flags&255;
        if(!type || flags&~uint64_t(0x7ff)) return std::unexpected(std::errc::not_supported);
        if(!length || !range(offset,length,size) || ((flags&0x400) && length<=20))
            return std::unexpected(std::errc::message_size);
        regions.emplace_back(offset,offset+length);
        if(type==1) {
            if(modem.size) return std::unexpected(std::errc::bad_message);
            modem={offset,length,(flags&0x400)!=0};
            if(modem.sha1_prefix) {modem.offset+=20;modem.size-=20;}
        }
        if(flags&0x100) {directory_end=at+12;last_end=offset+length;break;}
    }
    if(!directory_end || !modem.size) return std::unexpected(std::errc::bad_message);
    std::sort(regions.begin(),regions.end());
    if(regions.front().first<directory_end || regions.back().second!=last_end)
        return std::unexpected(std::errc::bad_message);
    for(size_t i=1;i<regions.size();++i) if(regions[i].first<regions[i-1].second)
        return std::unexpected(std::errc::bad_message);
    return modem;
}
namespace {
// Validate the copied Sansa preamble in the coordinate system actually used
// by SB_MemoryRead. Do not "repair" certificate offsets/signatures in place.
std::expected<void,std::errc> sansa_tail(std::span<const uint8_t,1024> tail,uint64_t base) {
    if(std::any_of(tail.begin(),tail.begin()+16,[](auto b){return b!=0;}) ||
        std::any_of(tail.begin()+64,tail.begin()+96,[](auto b){return b!=0;}))
        return std::unexpected(std::errc::not_supported);
    const auto a=le(tail,16,8),b=le(tail,32,8),c=le(tail,48,8);
    if(!c || (!a && b)) return std::unexpected(std::errc::bad_message);
    std::vector<std::pair<uint64_t,uint64_t>> ranges;
    for(size_t at:{size_t(16),size_t(32),size_t(48)}) {
        const auto length=le(tail,at,8),offset=le(tail,at+8,8);
        if(!length) continue;
        if(offset<base+96 || !range(offset,length,base+tail.size()) || length<16)
            return std::unexpected(std::errc::message_size);
        const auto local=static_cast<size_t>(offset-base);
        if(le(tail,local)!=0xe291f358) return std::unexpected(std::errc::bad_message);
        const auto sizes=le(tail,local+8),flags=le(tail,local+12);
        const auto signature=(sizes&0xffff)*4;
        if(signature<16 || !range(signature,256,length) || ((flags>>17)&3)!=(at==48?2u:1u))
            return std::unexpected(std::errc::bad_message);
        // An encrypted content certificate may cause secure-world mutation of
        // the view; no audited offline decryption contract for that ABI.
        if(flags&0x10000) return std::unexpected(std::errc::not_supported);
        ranges.emplace_back(offset,offset+length);
    }
    std::sort(ranges.begin(),ranges.end());
    for(size_t i=1;i<ranges.size();++i) if(ranges[i].first<ranges[i-1].second)
        return std::unexpected(std::errc::bad_message);
    return {};
}
}
std::expected<uint64_t,io::OutputError> unpack_image(const io::Image& image,PackedImageFormat format,
    const std::filesystem::path& destination,std::string_view expected,std::stop_token stop,
    const io::PrepareObserver& progress) {
    if(!io::valid_sha256(expected)) return std::unexpected(std::errc::invalid_argument);
    const std::string expected_digest(expected);
    if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    const auto reader=image.reader();
    uint64_t payload_offset=0,payload_size=0;
    std::array<uint8_t,512> header{};
    std::array<uint8_t,1024> tail{};
    bool view=false;
    if(format==PackedImageFormat::Sci1) {
        auto modem=parse_sci_modem(reader,image.size(),stop);
        if(!modem) return std::unexpected(modem.error());
        payload_offset=modem->offset;payload_size=modem->size;
    } else if(format==PackedImageFormat::SprdSignedSci1 || format==PackedImageFormat::SansaVerificationView) {
        if(image.size()<512) return std::unexpected(std::errc::message_size);
        auto got=reader(0,header,stop);if(!got) return std::unexpected(got.error());
        if(le(header,0)!=0x42544844 || le(header,4)!=1 || le(header,52)!=1)
            return std::unexpected(std::errc::bad_message);
        const auto size=static_cast<uint32_t>(le(header,48));
        const auto firmware=le(header,56);
        if(!size || !firmware || !range(512,size,image.size())) return std::unexpected(std::errc::message_size);
        if(std::any_of(header.begin()+8,header.begin()+40,[](auto b){return b!=0;})) {
            auto digest=io::sha256([&](uint64_t at,std::span<uint8_t> bytes,std::stop_token token) {
                return reader(512+at,bytes,token);
            },size,stop);
            if(!digest) return std::unexpected(digest.error());
            if(*digest!=hex(std::span(header).subspan(8,32))) return std::unexpected(std::errc::bad_message);
        }
        if(format==PackedImageFormat::SprdSignedSci1) {
            const io::Reader payload=[&](uint64_t at,std::span<uint8_t> bytes,std::stop_token token)->std::expected<void,std::errc> {
                if(!range(at,bytes.size(),size)) return std::unexpected(std::errc::message_size);
                return reader(512+at,bytes,token);
            };
            auto modem=parse_sci_modem(payload,size,stop);
            if(!modem) return std::unexpected(modem.error());
            // BSP signer scans only the first seven entries and differs from
            // runtime on SHA1 modem lengths. Accept the unambiguous intersection.
            std::array<uint8_t,96> directory{};
            if(size<directory.size()) return std::unexpected(std::errc::message_size);
            got=payload(0,directory,stop);if(!got) return std::unexpected(got.error());
            bool signer_finds=false;
            for(size_t i=1;i<8;++i) if((le(directory,i*12)&255)==1) {signer_finds=true;break;}
            if(!signer_finds || modem->sha1_prefix || firmware!=modem->size)
                return std::unexpected(std::errc::not_supported);
            payload_offset=512+modem->offset;payload_size=modem->size;
            auto signed_payload=validate_sprd_signed_payload(reader,image.size(),size,{payload_offset,payload_size},stop);
            if(!signed_payload) return std::unexpected(signed_payload.error());
        } else {
            view=true;payload_offset=le(header,60);payload_size=firmware;
            const uint64_t original_tail=512+uint64_t(size),new_tail=512+firmware;
            if(payload_offset<512 || !range(payload_offset,firmware,original_tail) ||
                image.size()!=original_tail+tail.size() || new_tail+tail.size()>0x1400000)
                return std::unexpected(std::errc::message_size);
            got=reader(original_tail,tail,stop);if(!got) return std::unexpected(got.error());
            auto checked=sansa_tail(tail,new_tail);if(!checked) return std::unexpected(checked.error());
            // Reproduce the loader view, including preserved packed fields;
            // changing these fields or re-signing would be a different format.
            put(header,48,static_cast<uint32_t>(firmware));
        }
    } else return std::unexpected(std::errc::invalid_argument);
    const uint64_t total=payload_size+(view?1536:0);
    auto output=io::AtomicOutput::open(destination);if(!output) return std::unexpected(output.error());
    io::Sha256 hash;uint64_t completed=0;
    const auto emit=[&](std::span<const uint8_t> bytes)->std::expected<void,std::errc> {
        if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
        hash.update(bytes);auto wrote=output->write(bytes,stop);if(!wrote) return wrote;
        completed+=bytes.size();if(progress) progress({io::PreparePhase::Checksum,completed,total});return {};
    };
    if(view) {auto wrote=emit(header);if(!wrote) return std::unexpected(wrote.error());}
    std::vector<uint8_t> buffer(1024*1024);
    for(uint64_t at=0;at<payload_size;) {
        if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
        auto bytes=std::span(buffer).first(static_cast<size_t>(std::min<uint64_t>(buffer.size(),payload_size-at)));
        auto got=reader(payload_offset+at,bytes,stop);if(!got) return std::unexpected(got.error());
        auto wrote=emit(bytes);if(!wrote) return std::unexpected(wrote.error());at+=bytes.size();
    }
    if(view) {auto wrote=emit(tail);if(!wrote) return std::unexpected(wrote.error());}
    if(hash.hex()!=expected_digest) return std::unexpected(std::errc::bad_message);
    if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    auto committed=output->commit_result();if(!committed) return std::unexpected(committed.error());
    return total;
}
}

/*
 * UniFlash-Core / Boot Image Header
 *
 * Header bounds, declared hash and payload size validation.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/session/boot_image.h>
#include <uniflash/io/sha256.h>
#include <array>
#include <algorithm>
namespace uniflash::session {
std::expected<BootImageHeader,std::errc> validate_boot_image(const io::Reader& reader,uint64_t size,std::stop_token stop) {
    if(size<512 || !reader) return std::unexpected(std::errc::message_size);
    std::array<uint8_t,512> header{};
    auto got=reader(0,header,stop);if(!got) return std::unexpected(got.error());
    const auto word=[&](size_t at) {return uint32_t(header[at])|(uint32_t(header[at+1])<<8)|(uint32_t(header[at+2])<<16)|(uint32_t(header[at+3])<<24);};
    if(word(0)!=0x42544844 || word(4)!=1) return std::unexpected(std::errc::bad_message);
    if(word(52)) return std::unexpected(std::errc::not_supported); // packed modem transformation is a separate ABI
    const auto length=word(48);
    if(!length || length>size-512) return std::unexpected(std::errc::message_size);
    // These fields describe packed runtime subranges only. An unpacked image
    // must not carry an out-of-bounds range that another loader might follow.
    if(word(56) && (word(60)>size || word(56)>size-word(60)))
        return std::unexpected(std::errc::message_size);
    const bool declares=std::any_of(header.begin()+8,header.begin()+40,[](auto b){return b!=0;});
    if(declares) {
        constexpr char digits[]="0123456789abcdef";std::string expected;
        for(auto b:std::span(header).subspan(8,32)) {expected+=digits[b>>4];expected+=digits[b&15];}
        auto digest=io::sha256([&](uint64_t at,std::span<uint8_t> bytes,std::stop_token token) {
            return reader(512+at,bytes,token);
        },length,stop);
        if(!digest) return std::unexpected(digest.error());
        if(*digest!=expected) return std::unexpected(std::errc::bad_message);
    }
    return BootImageHeader{length,declares};
}
}

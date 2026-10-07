/*
 * UniFlash-Core / PAC SecBinPack Table
 *
 * XOR table decoding and CRC verification.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/session/pac_table.h>
#include <array>
#include <algorithm>
namespace uniflash::session {
uint16_t pac_crc16(uint16_t crc,std::span<const uint8_t> bytes) {
    static constexpr auto table=[] {
        std::array<uint16_t,256> out{};
        for(unsigned i=0;i<256;++i) {
            unsigned v=i;
            for(unsigned j=0;j<8;++j) v=(v>>1)^((v&1)?0xa001:0);
            out[i]=static_cast<uint16_t>(v);
        }
        return out;
    }();
    for(auto byte:bytes) crc=(crc>>8)^table[(crc^byte)&255];
    return crc;
}
std::expected<std::vector<uint8_t>,std::errc> decode_pac_table(
    std::span<const uint8_t> encoded,uint16_t expected,std::stop_token stop) {
    constexpr size_t cell=2580;
    if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    if(encoded.empty() || encoded.size()%cell || encoded.size()>cell*16384) return std::unexpected(std::errc::message_size);
    const uint8_t mask=encoded[0]^0x14; // FILE_INFO.dwSize == 0x00000a14
    std::vector<uint8_t> decoded(encoded.begin(),encoded.end());
    uint16_t crc=0;
    for(size_t at=0;at<decoded.size();at+=cell) {
        if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
        auto row=std::span(decoded).subspan(at,cell);
        for(auto& byte:row) byte^=mask;
        if(row[0]!=0x14 || row[1]!=0x0a || row[2] || row[3]) return std::unexpected(std::errc::bad_message);
        crc=pac_crc16(crc,row);
    }
    if(crc!=expected) return std::unexpected(std::errc::bad_message);
    return decoded;
}
}

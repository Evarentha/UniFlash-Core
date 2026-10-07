/*
 * UniFlash-Core Test / RAM Frames
 *
 * Covers frame encoding within payload and wire limits.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#include <uniflash/protocol/ram_frame.h>
#include "../src/device/loader_contract.h"
#include <uniflash/log.h>

using namespace uniflash;
int main() {
    using C = protocol::BslCodec::Chk;
    const auto hash = [](std::string_view text) {
        return device::detail::loader_sha256(std::span(reinterpret_cast<const uint8_t*>(text.data()),text.size()));
    };
    if (hash("") != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ||
        hash("abc") != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ||
        hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") !=
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") return 1;
    if (device::detail::audited_fdl1(std::vector<uint8_t>(56376))) return 1;

    for (C checksum : {C::Crc16,C::Add}) for(size_t packet : {64,512,1024})
        for(size_t capacity : {size_t(762),size_t(1018),size_t(4090)})
        for(unsigned pattern=0;pattern<4;++pattern) {
            const size_t wire_limit = capacity==4090 ? 4095 : 1023;
            std::vector<uint8_t> data(capacity);
            for(size_t i=0;i<data.size();++i)
                data[i]=pattern==0 ? 0x42 : pattern==1 ? 0x7e : pattern==2 ? uint8_t(i*37+3) : 0;
            if(pattern==3 && packet-6<data.size()) data[packet-6]=0x7d;
            auto selected=protocol::encode_ram_midst(data,checksum,capacity,wire_limit,packet,true);
            if(!selected) return 1;
            std::vector<uint8_t> body;
            for (size_t i=1; i+1<selected->wire.size(); ++i) {
                auto byte = selected->wire[i];
                if (byte == 0x7d) byte = selected->wire[++i] ^ 0x20;
                body.push_back(byte);
            }
            if (body.size() != selected->payload_size+6 || body[0] != 0 || body[1] != 2 ||
                size_t((body[2]<<8)|body[3]) != selected->payload_size ||
                !std::equal(body.begin()+4, body.end()-2, data.begin())) return 1;
            if (checksum == C::Add) {
                uint32_t sum=0;
                for(size_t i=0;i<body.size();i+=2)
                    sum += body[i] | (i+1<body.size() ? uint32_t(body[i+1])<<8 : 0);
                while(sum>>16) sum=(sum&65535)+(sum>>16);
                if(sum!=65535) return 1;
            } else if(!protocol::BslCodec::decode_hdlc(selected->wire,checksum)) return 1;
            // Independent brute-force oracle: no larger legal prefix may fit.
            for(size_t n=selected->payload_size;n<=capacity;++n) {
                const auto bytes=std::span(data).first(n);
                auto frame=protocol::BslCodec::encode_hdlc_chk(2,bytes,checksum);
                bool legal=frame && frame->size()<=wire_limit &&
                    !protocol::BslCodec::chk_carries_escape(checksum,2,bytes);
                if(frame) for(size_t k=packet-1;k+1<frame->size();k+=packet)
                    if((*frame)[k]==0x7d) legal=false;
                if(legal != (n==selected->payload_size)) return 1;
            }
        }
    std::vector<uint8_t> plain(56376,0x42);
    size_t off=0, packets=0;
    while(off<plain.size()) {
        auto f=protocol::encode_ram_midst(std::span(plain).subspan(off),C::Crc16,1018,1023,512,true);
        if(!f) return 1;
        off+=f->payload_size; ++packets;
    }
    if(packets>60) return 1; // old half split needed roughly 112 frames
    auto large=protocol::encode_ram_midst(plain,C::Add,4090,4095,512,true);
    if(!large || large->payload_size<4000) return 1;
    uniflash::log_info("RAM frame packing and loader digest checks passed");
}

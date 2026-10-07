/*
 * UniFlash-Core Test / PAC Archive
 *
 * Covers archive structure, checksums and entry classification.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/session/pac_archive.h>
#include <uniflash/session/pac_table.h>
#include <uniflash/cli/arguments.h>
#include "temp_directory.h"
#include <fstream>
#include <uniflash/log.h>
#include <algorithm>

using Bytes=std::vector<uint8_t>;
void put(Bytes& b,size_t at,uint64_t n,size_t width=4) {
    for(size_t i=0;i<width;++i) b[at+i]=static_cast<uint8_t>(n>>(8*i));
}
void text(Bytes& b,size_t at,std::string_view value) {
    for(size_t i=0;i<value.size();++i) b[at+2*i]=value[i];
}
uint16_t crc(std::span<const uint8_t> bytes) {
    uint16_t value=0;
    for(auto byte:bytes) {
        value^=byte;
        for(unsigned i=0;i<8;++i) value=(value>>1)^((value&1)?0xa001:0);
    }
    return value;
}
void seal(Bytes& b) {
    put(b,2120,crc(std::span(b).first(2120)),2);
    put(b,2122,crc(std::span(b).subspan(2124)),2);
}
int main() {
    using namespace uniflash;
    TempDirectory root;
    const auto path=root.path/"firmware.pac";
    const std::string xml="<?xml version=\"1.0\"?><BMAConfig><ProductList><Product name=\"fixture\">"
        "<SchemeName>fixture</SchemeName><Partitions><Partition id=\"boot\" size=\"1\"/></Partitions>"
        "</Product></ProductList><SchemeList><Scheme name=\"fixture\">"
        "<File><ID>BOOT</ID><Type>CODE2</Type><Block id=\"boot\"><Base>0x0</Base><Size>0x0</Size>"
        "</Block><Flag>1</Flag></File></Scheme></SchemeList></BMAConfig>";
    constexpr size_t payload=2124+2*2580;
    Bytes b(payload+5+xml.size());
    text(b,0,"BP_R1.0.0"); put(b,48,b.size()); text(b,52,"fixture");
    put(b,1076,2); put(b,1080,2124); put(b,2116,0xfffafffa);
    put(b,2124,2580); text(b,2128,"boot"); text(b,2124+516,"../ignored.img");
    put(b,2124+1540,5); put(b,2124+1544,1); put(b,2124+1548,1); put(b,2124+1552,payload);
    const size_t x=2124+2580;
    put(b,x,2580); text(b,x+516,"fixture.xml"); put(b,x+1540,xml.size());
    put(b,x+1544,2); put(b,x+1552,payload+5);
    for(size_t i=0;i<5;++i) b[payload+i]=static_cast<uint8_t>(i+1);
    std::copy(xml.begin(),xml.end(),b.begin()+payload+5); seal(b);
    auto save=[&] { std::ofstream f(path,std::ios::binary|std::ios::trunc); f.write(reinterpret_cast<const char*>(b.data()),b.size()); };
    save();
    auto archive=session::PacArchive::open(path,0x102);
    if(!archive || archive->actions().size()!=1 || archive->actions()[0].partition!="boot") return 1;
    if(archive->repartition_strategy()!=0 || archive->partition_layout().partitions.size()!=1 ||
        archive->partition_layout().partitions[0].size!=1048576) return 1;
    auto selected=archive->selected_actions(0x102);
    if(!selected || selected->size()!=1 || archive->selected_actions(0x101)) return 1;
    auto image=archive->image(archive->actions()[0],5);
    const auto original=b;
    // Duplicate optional singleton nodes must not silently remove layout.
    auto duplicate_xml=xml;
    duplicate_xml.insert(duplicate_xml.find("</Product>"),"<Partitions><Partition id=\"other\" size=\"1\"/></Partitions>");
    b.resize(payload+5+duplicate_xml.size());put(b,48,b.size());put(b,x+1540,duplicate_xml.size());put(b,1092,2);
    std::copy(duplicate_xml.begin(),duplicate_xml.end(),b.begin()+payload+5);seal(b);save();
    if(session::PacArchive::open(path,0x102))return 1;
    b=original;
    const auto table_crc=crc(std::span(b).subspan(2124,5160));
    put(b,1316,1,2);put(b,1318,table_crc,2);put(b,1320,5160);put(b,1324,5160);
    for(size_t i=2124;i<payload;++i) b[i]^=0xf8; // ~byte XOR default 0x07
    seal(b);save();
    auto encrypted=session::PacArchive::open(path,0x102);
    if(!encrypted || encrypted->actions().size()!=1 || encrypted->actions()[0].partition!="boot") return 1;
    put(b,1320,5159);seal(b);save();
    if(session::PacArchive::open(path,0x102)) return 1;
    b=original;
    const auto plain_table=std::span(original).subspan(2124,5160);
    for(unsigned mask:{0u,0x01u,0x07u,0x80u,0xffu}) {
        Bytes encoded(plain_table.begin(),plain_table.end());
        for(auto& byte:encoded) byte^=static_cast<uint8_t>(mask);
        auto decoded=session::decode_pac_table(encoded,table_crc);
        if(!decoded || !std::equal(decoded->begin(),decoded->end(),plain_table.begin())) return 1;
        encoded[0]^=1;
        if(session::decode_pac_table(encoded,table_crc)) return 1;
    }
    b[payload]=99; save(); // prepared package owns a snapshot
    Bytes actual(5);
    if(!image || !image->reader()(0,actual,{}) || actual!=Bytes({1,2,3,4,5})) return 1;
    if(session::PacArchive::open(path,0x102)) return 1; // body CRC mismatch
    seal(b); put(b,2124+1552,payload+5); seal(b); save();
    if(session::PacArchive::open(path,0x102)) return 1; // overlapping XML/image ranges
    const std::string unusual="a'\"\\镜像 name.bin";
    const auto args=cli::parse_arguments("write boot "+cli::quote_argument(unusual));
    if(args.size()!=3 || args[2]!=unusual) return 1;
    uniflash::log_info("PAC CRC, mapping, region and snapshot checks passed");
}

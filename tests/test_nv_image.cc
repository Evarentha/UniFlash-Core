/*
 * UniFlash-Core Test / NV Image
 *
 * Covers item headers, checksums and word orders.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#include <uniflash/session/nv_image.h>
#include <uniflash/device/sprd_device.h>
#include <deque>
#include <uniflash/log.h>
#include <algorithm>

using namespace uniflash;
using Bytes=std::vector<uint8_t>;
namespace {
void put(Bytes& data,size_t at,uint32_t n,size_t width=4) {
    for(size_t i=0;i<width;++i) data[at+i]=static_cast<uint8_t>(n>>(8*i));
}
uint32_t get(std::span<const uint8_t> data,size_t at) {
    uint32_t n=0; for(size_t i=0;i<4;++i) n|=uint32_t(data[at+i])<<(8*i); return n;
}
class Loader final:public transport::Transport {
public:
    std::deque<Bytes> replies;
    uint32_t checksum=0,length=0,sum=0;
    uint64_t received=0;
    unsigned starts=0,ends=0;
    Loader() { replies.push_back(*protocol::BslCodec::encode_hdlc_chk(0x96,
        Bytes{0x6e,0x65,0x77,0x74,6,0,4,0,2,1,0,0},protocol::BslCodec::Chk::Add)); }
    std::expected<void,std::errc> bulk_write(std::span<const uint8_t> wire,transport::Timeout,std::stop_token) override {
        Bytes body;
        for(size_t i=1;i+1<wire.size();++i) {
            auto b=wire[i]; if(b==0x7d) b=wire[++i]^0x20; body.push_back(b);
        }
        if(body.size()<6) return std::unexpected(std::errc::bad_message);
        uint32_t residue=0;
        for(size_t i=0;i<body.size();i+=2) residue+=body[i] | (i+1<body.size()?uint32_t(body[i+1])<<8:0);
        while(residue>>16) residue=(residue&65535)+(residue>>16);
        if(residue!=65535) return std::unexpected(std::errc::bad_message);
        auto payload=std::span(body).subspan(4,body.size()-6);
        if(body[1]==1) {
            if(payload.size()!=80) return std::unexpected(std::errc::bad_message);
            ++starts; length=get(payload,72); checksum=get(payload,76);
        } else if(body[1]==2) {
            for(auto byte:payload) sum+=byte;
            received+=payload.size();
        } else if(body[1]==3) {
            ++ends;
            if(received!=length || checksum!=sum) return std::unexpected(std::errc::bad_message);
        } else return std::unexpected(std::errc::not_supported);
        replies.push_back(*protocol::BslCodec::encode_hdlc_chk(0x80,{},protocol::BslCodec::Chk::Add));
        return {};
    }
    std::expected<Bytes,std::errc> bulk_read(size_t,transport::Timeout,std::stop_token) override {
        if(replies.empty()) return std::unexpected(std::errc::io_error);
        auto b=std::move(replies.front()); replies.pop_front(); return b;
    }
    std::expected<void,std::errc> bulk_write_frame(std::span<const uint8_t>,transport::Timeout,std::stop_token) override {
        return std::unexpected(std::errc::not_supported);
    }
    bool supports_raw_frames() const override {return false;}
    uint16_t out_maxpacket() const override {return 512;}
    bool device_gone() const override {return false;}
    bool device_silent() const override {return false;}
};
}
int main() {
    using namespace session;
    if(nv_disk_checksum(Bytes{1,2,3},NvChecksumWidth::Bits64)!=0xfdfb || nv_transfer_checksum(Bytes{1,2,3})!=6) return 1;
    // 65538 LE16 words of 0xffff overflow a 32-bit accumulator once.
    const Bytes overflowing(65538*2,0xff);
    if(nv_disk_checksum(overflowing,NvChecksumWidth::Bits32)!=1 ||
       nv_disk_checksum(overflowing,NvChecksumWidth::Bits64)!=0) return 1;
    Bytes old(64,0xff),fresh(64,0xff);
    put(old,0,7);put(fresh,0,3);
    put(old,4,5,2);put(old,6,3,2);old[8]=1;old[9]=2;old[10]=3;
    put(fresh,4,5,2);put(fresh,6,3,2);fresh[8]=4;fresh[9]=5;fresh[10]=6;
    const NvMergeItem rules[]{{5,false}};
    auto merged=nv_merge_items(old,fresh,64,rules);
    if(!merged || get(*merged,0)!=8 || (*merged)[8]!=1 || (*merged)[10]!=3) return 1;
    auto big_old=old,big_new=fresh;
    for(auto* b:{&big_old,&big_new}) {std::swap((*b)[4],(*b)[5]);std::swap((*b)[6],(*b)[7]);}
    auto big=nv_merge_items(big_old,big_new,64,rules,NvByteOrder::BigItemHeaders,NvByteOrder::BigItemHeaders);
    if(!big || (*big)[8]!=1 || (*big)[4]!=0 || (*big)[5]!=5) return 1;
    if(nv_merge_items(big_old,fresh,64,rules,NvByteOrder::BigItemHeaders,NvByteOrder::Little)) return 1;
    auto reversed=old;
    for(size_t i=0;i<reversed.size();i+=4) std::reverse(reversed.begin()+i,reversed.begin()+i+4);
    auto normalized=nv_merge_items(reversed,fresh,64,rules,NvByteOrder::ReversedWords,NvByteOrder::Little);
    if(!normalized || *normalized!=*merged) return 1;
    auto reverse_template=fresh;
    for(size_t i=0;i<reverse_template.size();i+=4) std::reverse(reverse_template.begin()+i,reverse_template.begin()+i+4);
    auto reverse_result=nv_merge_items(old,reverse_template,64,rules,NvByteOrder::Little,NvByteOrder::ReversedWords);
    if(!reverse_result) return 1;
    for(size_t i=0;i<reverse_result->size();i+=4) std::reverse(reverse_result->begin()+i,reverse_result->begin()+i+4);
    if(*reverse_result!=*merged) return 1;
    // Known BT_CONFIG bytes, with the target item deliberately relocated.
    // Compare the entire result to ensure unrelated template fields survive.
    const NvMergeItem bluetooth[]{{0x191,false,{},NvItemKind::BluetoothConfig}};
    Bytes bt_old(64,0xff),bt_new(64,0xff);
    put(bt_old,0,0x12345678);put(bt_new,0,9);
    put(bt_old,4,0x191,2);put(bt_old,6,8,2);
    const Bytes bt_fields{0x02,0x17,0x31,0x54,0x76,0x98,0x34,0x12};
    std::copy(bt_fields.begin(),bt_fields.end(),bt_old.begin()+8);
    put(bt_new,4,9,2);put(bt_new,6,4,2);put(bt_new,8,0xabcdef01);
    put(bt_new,12,0x191,2);put(bt_new,14,8,2);
    std::fill(bt_new.begin()+16,bt_new.begin()+24,0x66);
    const auto encode=[](Bytes bytes,NvByteOrder order,bool target) {
        if(order==NvByteOrder::BigItemHeaders) {
            std::swap(bytes[4],bytes[5]);std::swap(bytes[6],bytes[7]);
            if(target) {
                std::swap(bytes[12],bytes[13]);std::swap(bytes[14],bytes[15]);
            }
            const size_t field=target?22:14;
            std::swap(bytes[field],bytes[field+1]);
        } else if(order==NvByteOrder::ReversedWords) {
            for(size_t i=0;i<bytes.size();i+=4) std::reverse(bytes.begin()+i,bytes.begin()+i+4);
        }
        return bytes;
    };
    for(auto from:{NvByteOrder::Little,NvByteOrder::BigItemHeaders,NvByteOrder::ReversedWords}) {
        for(auto to:{NvByteOrder::Little,NvByteOrder::BigItemHeaders,NvByteOrder::ReversedWords}) {
            auto source=encode(bt_old,from,false),target=encode(bt_new,to,true);
            auto expected=bt_new;
            put(expected,0,0x12345679);
            std::copy(bt_fields.begin(),bt_fields.end(),expected.begin()+16);
            expected=encode(expected,to,true);
            auto result=nv_merge_items(source,target,64,bluetooth,from,to);
            if(!result || *result!=expected) return 1;
        }
    }
    auto bt_be=encode(bt_new,NvByteOrder::BigItemHeaders,true);
    const NvMergeItem generic_bt[]{{0x191,false}};
    if(nv_merge_items(bt_old,bt_be,64,generic_bt,NvByteOrder::Little,NvByteOrder::BigItemHeaders)) return 1;
    const NvMergeItem mixed_bt[]{{0x191,false,{},NvItemKind::BluetoothConfig},{9,true}};
    if(nv_merge_items(bt_old,bt_be,64,mixed_bt,NvByteOrder::Little,NvByteOrder::BigItemHeaders)) return 1;
    const NvMergeItem wrong_bt[]{{9,true,{},NvItemKind::BluetoothConfig}};
    if(nv_merge_items(bt_old,bt_new,64,wrong_bt)) return 1;
    const NvMergeItem invalid_kind[]{{0x191,false,{},static_cast<NvItemKind>(255)}};
    if(nv_merge_items(bt_old,bt_new,64,invalid_kind)) return 1;
    auto short_bt=bt_old,short_template=bt_new;
    put(short_bt,6,7,2);put(short_template,14,7,2);
    if(nv_merge_items(short_bt,short_template,64,bluetooth)) return 1;
    put(bt_old,0,UINT32_MAX);
    auto wrapped=nv_merge_items(bt_old,bt_new,64,bluetooth);
    if(!wrapped || get(*wrapped,0)!=0) return 1;
    auto physical=nv_physical_image(old,NvChecksumWidth::Bits64);
    auto decoded=nv_decode_physical(physical,64);
    if(!decoded || *decoded!=old) return 1;
    physical[520]^=1;
    if(nv_decode_physical(physical,64)) return 1;
    physical=nv_physical_image(old,NvChecksumWidth::Bits64);
    put(physical,4,UINT32_MAX);
    if(nv_decode_physical(physical,64)) return 1;
    auto duplicate=old;
    put(duplicate,12,5,2); put(duplicate,14,1,2); duplicate[16]=0;
    if(nv_merge_items(duplicate,fresh,64,rules)) return 1;
    const NvMergeItem absent[]{{9,true}};
    if(!nv_merge_items(old,fresh,64,absent)) return 1;
    const NvMergeItem required[]{{9,false}};
    if(nv_merge_items(old,fresh,64,required)) return 1;
    put(fresh,6,4,2);
    if(nv_merge_items(old,fresh,64,rules)) return 1;
    const auto multicore=[](uint8_t value) {
        Bytes b(1024,0xff);
        put(b,0,7);put(b,4,0,2);put(b,6,32,2);put(b,8,0x58444e49);
        put(b,12,0,2);put(b,14,1,2);
        std::fill(b.begin()+16,b.begin()+32,0);b[16]='L';b[17]='T';b[18]='E';
        put(b,32,512);put(b,36,512);
        put(b,512,5,2);put(b,514,4,2);put(b,516,value);
        put(b,520,0xfffe,2);put(b,522,500,2);
        return b;
    };
    auto multi_old=multicore(23),multi_new=multicore(42);
    auto multi=nv_merge_items(multi_old,multi_new,1024,rules);
    if(!multi || get(*multi,516)!=23 || get(*multi,32)!=512) return 1;
    auto be_core_old=multi_old,be_core_new=multi_new;
    for(auto* bytes:{&be_core_old,&be_core_new}) {
        for(size_t at:{size_t(512),size_t(514),size_t(520),size_t(522)}) std::swap((*bytes)[at],(*bytes)[at+1]);
    }
    auto be_core=nv_merge_items(be_core_old,be_core_new,1024,rules,
        NvByteOrder::LittleIndexBigItemHeaders,NvByteOrder::LittleIndexBigItemHeaders);
    if(!be_core || get(*be_core,516)!=23 || (*be_core)[512]!=0 || (*be_core)[513]!=5 || get(*be_core,32)!=512) return 1;
    if(nv_merge_items(be_core_old,be_core_new,1024,rules,NvByteOrder::BigItemHeaders,NvByteOrder::BigItemHeaders)) return 1;
    if(nv_merge_items(old,fresh,64,rules,NvByteOrder::LittleIndexBigItemHeaders,NvByteOrder::LittleIndexBigItemHeaders)) return 1;
    // Reordered core storage is matched by name, not by its original offset.
    auto moved_core=be_core_new;moved_core.resize(1536,0xff);
    std::copy_n(be_core_new.begin()+512,512,moved_core.begin()+1024);
    std::fill(moved_core.begin()+512,moved_core.begin()+1024,0xff);put(moved_core,32,1024);
    auto larger_old=be_core_old;larger_old.resize(1536,0xff);
    auto moved_merge=nv_merge_items(larger_old,moved_core,1536,rules,
        NvByteOrder::LittleIndexBigItemHeaders,NvByteOrder::LittleIndexBigItemHeaders);
    if(!moved_merge || get(*moved_merge,1028)!=23 || get(*moved_merge,32)!=1024) return 1;
    put(multi_new,32,16);
    if(nv_merge_items(multi_old,multi_new,1024,rules)) return 1;
    for(auto version:{uint16_t(0xff0a),uint16_t(0xff0b)}) {
        const size_t length=version==0xff0a?0x1784:0x1cc4;
        Bytes from(length+12,0xff),to(length+12,0xff);
        put(from,0,7);put(to,0,0);
        put(from,4,2,2);put(to,4,2,2);put(from,6,length,2);put(to,6,length,2);
        std::fill(from.begin()+8,from.begin()+8+length,0x22);
        std::fill(to.begin()+8,to.begin()+8+length,0x66);
        put(from,8,version,2);put(to,8,version,2);
        const NvMergeItem calibration[]{{2,false,{},NvItemKind::GsmCalibration}};
        auto combined=nv_merge_items(from,to,from.size(),calibration);
        if(!combined || (*combined)[8+2]!=0x22 || (*combined)[8+0x80+0x40]!=0x66 ||
            (*combined)[8+length-1]!=0x22 || (*combined)[8+0x80+0x88]!=0x22) return 1;
        put(to,8,0xff0c,2);
        if(nv_merge_items(from,to,from.size(),calibration)) return 1;
    }
    for(auto version:{uint16_t(3),uint16_t(4),uint16_t(5)}) {
        const size_t length=version==3?0x233c:version==4?0x2a0c:64;
        Bytes from(length+12,0xff),to(length+12,0xff);
        put(from,0,9);put(to,0,0);
        put(from,4,0x516,2);put(to,4,0x516,2);put(from,6,length,2);put(to,6,length,2);
        std::fill(from.begin()+8,from.begin()+8+length,0x22);
        std::fill(to.begin()+8,to.begin()+8+length,0x66);
        put(from,8,version,2);put(to,8,version,2);
        const NvMergeItem calibration[]{{0x516,false,{},NvItemKind::TdCalibration}};
        auto combined=nv_merge_items(from,to,from.size(),calibration);
        if(!combined || get(*combined,0)!=10) return 1;
        if(version==3 && ((*combined)[8+0x14]!=0x22 || (*combined)[8+0x12]!=0x66 || (*combined)[8+length-1]!=0x66)) return 1;
        if(version==4 && ((*combined)[8+length-3]!=0x22 || (*combined)[8+length-1]!=0x66)) return 1;
        if(version==5 && (*combined)[8+length-1]!=0x22) return 1;
    }
    put(fresh,6,65535,2);
    if(nv_merge_items(old,fresh,64,rules)) return 1;
    auto transport=std::make_unique<Loader>(); auto* observed=transport.get();
    device::DeviceProfile profile; profile.nv_dialect=device::NvDialect::Signed7MiB;
    device::SprdDevice dev(std::move(transport),profile);
    if(!dev.resync_fdl2(std::chrono::seconds(1))) return 1;
    Bytes payload(0x700000,0x37);
    if(!dev.write_nv("nr_fixnv1",payload) || observed->starts!=1 || observed->ends!=1 ||
        observed->length!=payload.size() || observed->checksum!=nv_transfer_checksum(payload)) return 1;
    if(dev.write_nv("nr_fixnv2",payload) || observed->starts!=1) return 1;
    if(dev.write_partition_stream("nr_fixnv1",payload.size(),[](auto,auto,auto)->std::expected<void,std::errc>{return {};}) ||
        observed->starts!=1) return 1;
    uniflash::log_info("NV physical format, merge bounds and 80-byte START checks passed");
}

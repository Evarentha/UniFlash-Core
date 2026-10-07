/*
 * UniFlash-Core Test / NV Restore
 *
 * Covers snapshot, merge, update and verified readback.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#include <uniflash/session/nv_restore.h>
#include <uniflash/session/operations.h>
#include <uniflash/io/checksum.h>
#include "temp_directory.h"
#include <algorithm>
#include <deque>
#include <fstream>
#include <uniflash/log.h>

using namespace uniflash;
using Bytes=std::vector<uint8_t>;
namespace {
constexpr size_t MiB=1048576, nv_size=7*MiB, primary=MiB, backup=9*MiB;
void put(Bytes& bytes,size_t at,uint64_t value,size_t width=4) {
    for(size_t i=0;i<width;++i) bytes[at+i]=static_cast<uint8_t>(value>>(8*i));
}
uint64_t get(std::span<const uint8_t> bytes,size_t at,size_t width=4) {
    uint64_t value=0;
    for(size_t i=0;i<width;++i) value|=uint64_t(bytes[at+i])<<(8*i);
    return value;
}
class Loader:public transport::Transport {
public:
    Bytes disk=Bytes(32*MiB), incoming;
    std::deque<Bytes> replies;
    unsigned starts=0,ends=0,commands=0,ordinary_starts=0;
    bool ordinary=false;
    uint32_t checksum=0;
    bool fail_backup=false;
    Loader() {
        const std::string magic="EFI PART";
        std::copy(magic.begin(),magic.end(),disk.begin()+512);
        const uint64_t last=disk.size()/512-1;
        put(disk,520,0x10000);put(disk,524,92);
        put(disk,536,1,8);put(disk,544,last,8);put(disk,552,34,8);put(disk,560,last-33,8);
        disk[568]=1;put(disk,584,2,8);put(disk,592,128);put(disk,596,128);
        for(unsigned i=0;i<2;++i) {
            const size_t at=1024+i*128;
            disk[at]=1;disk[at+16]=static_cast<uint8_t>(i+2);
            const uint64_t offset=i?backup:primary;
            put(disk,at+32,offset/512,8);put(disk,at+40,(offset+8*MiB)/512-1,8);
            const std::string name=i?"nr_fixnv2":"nr_fixnv1";
            for(size_t j=0;j<name.size();++j) disk[at+56+2*j]=name[j];
        }
        const size_t data=1024+2*128;disk[data]=1;disk[data+16]=4;
        put(disk,data+32,18*MiB/512,8);put(disk,data+40,19*MiB/512-1,8);
        const std::string data_name="data";for(size_t j=0;j<data_name.size();++j)disk[data+56+2*j]=data_name[j];
        put(disk,600,io::crc32_update(0,std::span(disk).subspan(1024,16384)));
        put(disk,528,io::crc32_update(0,std::span(disk).subspan(512,92)));
        const size_t head=last*512,entries=(last-32)*512;
        std::copy_n(disk.begin()+512,512,disk.begin()+head);
        std::copy_n(disk.begin()+1024,16384,disk.begin()+entries);
        put(disk,head+24,last,8);put(disk,head+32,1,8);put(disk,head+72,last-32,8);
        put(disk,head+16,0);put(disk,head+16,io::crc32_update(0,std::span(disk).subspan(head,92)));
        auto nv=session::nv_physical_image(Bytes(nv_size,0x55),session::NvChecksumWidth::Bits64);
        std::copy(nv.begin(),nv.end(),disk.begin()+primary);
        std::copy(nv.begin(),nv.end(),disk.begin()+backup);
        reply(0x96,Bytes{0x6e,0x65,0x77,0x74,6,0,4,0,2,1,0,0});
    }
    void reply(uint8_t code,const Bytes& data={}) {
        replies.push_back(*protocol::BslCodec::encode_hdlc_chk(code,data,protocol::BslCodec::Chk::Add));
    }
    std::expected<void,std::errc> bulk_write(std::span<const uint8_t> wire,transport::Timeout,std::stop_token) override {
        ++commands;
        Bytes b;
        for(size_t i=1;i+1<wire.size();++i) {
            auto c=wire[i];
            if(c==0x7d) {if(i+2>=wire.size()) return std::unexpected(std::errc::bad_message);c=wire[++i]^0x20;}
            b.push_back(c);
        }
        if(b.size()<6) return std::unexpected(std::errc::bad_message);
        uint32_t sum=0;
        for(size_t i=0;i<b.size();i+=2) sum+=b[i]|(i+1<b.size()?uint32_t(b[i+1])<<8:0);
        while(sum>>16) sum=(sum&65535)+(sum>>16);
        if(sum!=65535 || size_t((b[2]<<8)|b[3])+6!=b.size()) return std::unexpected(std::errc::bad_message);
        const auto p=std::span(b).subspan(4,b.size()-6);
        switch(b[1]) {
        case 0x10: {
            std::string name;
            for(size_t i=0;i<72 && i<p.size() && p[i];i+=2) name+=char(p[i]);
            // A named NV read would repair the disk; this test refuses it.
            if(name!="user_partition") return std::unexpected(std::errc::not_supported);
            reply(0x80);break;
        }
        case 0x11: {
            if(p.size()<8) return std::unexpected(std::errc::bad_message);
            const auto size=get(p,0),offset=get(p,4);
            if(offset>disk.size() || size>disk.size()-offset) return std::unexpected(std::errc::message_size);
            reply(0x93,Bytes(disk.begin()+offset,disk.begin()+offset+size));break;
        }
        case 0x12: reply(0x80);break;
        case 1: {
            std::string name;for(size_t i=0;i<72 && i<p.size() && p[i];i+=2)name+=char(p[i]);
            ordinary=name=="data";
            if(ordinary) {if(p.size()!=76 || get(p,72)!=4096)return std::unexpected(std::errc::bad_message);++ordinary_starts;}
            else {if(p.size()!=80 || get(p,72)!=nv_size || name!="nr_fixnv1")return std::unexpected(std::errc::bad_message);
                ++starts;checksum=static_cast<uint32_t>(get(p,76));}
            incoming.clear();reply(0x80);break;
        }
        case 2:
            if(ordinary) {incoming.insert(incoming.end(),p.begin(),p.end());reply(0x80);break;}
            if(p.size()>nv_size-incoming.size()) return std::unexpected(std::errc::message_size);
            incoming.insert(incoming.end(),p.begin(),p.end());
            if(incoming.size()==nv_size) {
                if(session::nv_transfer_checksum(incoming)!=checksum) return std::unexpected(std::errc::bad_message);
                const auto image=session::nv_physical_image(incoming,session::NvChecksumWidth::Bits64);
                std::copy(image.begin(),image.end(),disk.begin()+primary);
                if(!fail_backup) std::copy(image.begin(),image.end(),disk.begin()+backup);
            }
            reply(0x80);break;
        case 3:
            if(ordinary)std::copy(incoming.begin(),incoming.end(),disk.begin()+18*MiB);
            else ++ends;
            reply(0x80);break;
        default:return std::unexpected(std::errc::not_supported);
        }
        return {};
    }
    std::expected<Bytes,std::errc> bulk_read(size_t,transport::Timeout,std::stop_token) override {
        if(replies.empty()) return std::unexpected(std::errc::io_error);
        auto bytes=std::move(replies.front());replies.pop_front();return bytes;
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
    TempDirectory root;
    const Bytes payload(nv_size,0x33);
    for(unsigned scenario=0;scenario<4;++scenario) {
        auto transport=std::make_unique<Loader>();auto* observed=transport.get();
        device::DeviceProfile profile;profile.nv_dialect=device::NvDialect::Signed7MiB;
        device::SprdDevice device(std::move(transport),profile);
        if(!device.resync_fdl2(std::chrono::seconds(1))) return 1;
        const session::NvMergeItem invalid_rule{0};
        if(session::NvRestore::prepare_merge(device,"nr_fixnv1",payload,std::span(&invalid_rule,1)) || observed->commands)return 1;
        auto plan=session::NvRestore::prepare_payload(device,"nr_fixnv1",payload);
        if(!plan || observed->starts) return 1;
        if(scenario==1) {
            if(session::NvRestore::execute(device,*plan) || observed->starts) return 1;
            continue;
        }
        const auto directory=root.path/("case-"+std::to_string(scenario));
        if(!session::NvRestore::save_recovery(*plan,directory)) return 1;
        if(scenario==2) observed->disk[primary+512]^=1;
        observed->fail_backup=scenario==3;
        const auto result=session::NvRestore::execute(device,*plan);
        if(scenario==0) {
            if(!result || *result!=nv_size || observed->starts!=1 || observed->ends!=1) return 1;
            if(session::NvRestore::execute(device,*plan) || observed->starts!=1) return 1;
        } else if(result || observed->starts!=(scenario==3?1u:0u)) return 1;
    }
    for(unsigned scenario=0;scenario<7;++scenario) {
        const auto directory=root.path/("batch-"+std::to_string(scenario));std::filesystem::create_directory(directory);
        auto first=session::nv_physical_image(payload,session::NvChecksumWidth::Bits64),second=first;
        if(scenario==1)second=session::nv_physical_image(Bytes(nv_size,0x44),session::NvChecksumWidth::Bits64);
        if(scenario==2)first[0]=0;
        const auto save=[&](const char* name,const Bytes& b){std::ofstream out(directory/name,std::ios::binary);out.write(reinterpret_cast<const char*>(b.data()),b.size());};
        save("nr_fixnv1.bin",first);save("nr_fixnv2.bin",second);save("data.bin",Bytes(4096,0x62));
        {
            std::ofstream xml(directory/"layout.xml");
            xml<<"<rom>";
            // Mirror-first exercises normalization without consuming the pair twice.
            xml<<"<partition name=\"nr_fixnv2\"/>";
            xml<<"<partition name=\"data\"/>";
            if(scenario!=3)xml<<"<partition name=\"nr_fixnv1\"/>";
            if(scenario==4)xml<<"<partition name=\"missing\"/>";
            xml<<"</rom>";
        }
        auto channel=std::make_unique<Loader>();auto* observed=channel.get();
        device::DeviceProfile profile;profile.nv_dialect=device::NvDialect::Signed7MiB;
        device::SprdDevice dev(std::move(channel),profile);if(!dev.resync_fdl2(std::chrono::seconds(1)))return 1;
        session::DirectoryPrepareOptions budget;budget.max_encoded_file=8;
        if(session::Operations::prepare_directory(dev,directory,budget) || observed->commands)return 1;
        budget.max_encoded_file=16*MiB;budget.max_encoded_total=first.size();
        if(session::Operations::prepare_directory(dev,directory,budget) || observed->commands)return 1;
        std::error_code link_error;
        const auto outside=root.path/("outside-"+std::to_string(scenario)+".bin");
        {std::ofstream out(outside);out<<"outside";}
        std::filesystem::remove(directory/"data.bin");
        std::filesystem::create_symlink(outside,directory/"data.bin",link_error);
        if(!link_error) {
            if(session::Operations::prepare_directory(dev,directory) || observed->commands)return 1;
            std::filesystem::remove(directory/"data.bin");
        }
        save("data.bin",Bytes(4096,0x62));
        auto plan=session::Operations::prepare_directory(dev,directory);
        if(scenario>=1 && scenario<=4) {if(plan || observed->commands)return 1;continue;}
        if(!plan || !plan->requires_recovery() || plan->entries().size()!=2 ||
            !plan->entries()[1].physical_nv() || plan->entries()[1].partition!="nr_fixnv1")return 1;
        if(session::Operations::execute(dev,*plan) || observed->starts || observed->ordinary_starts)return 1;
        if(!session::Operations::save_recovery(dev,*plan,root.path/("batch-recovery-"+std::to_string(scenario))))return 1;
        if(scenario==5)observed->disk[primary+512]^=1;
        if(scenario==6) {save("nr_fixnv1.bin",Bytes(1));save("data.bin",Bytes(1));}
        auto written=session::Operations::execute(dev,*plan);
        if(scenario==5) {if(written || observed->starts || observed->ordinary_starts)return 1;continue;}
        if(!written || observed->starts!=1 || observed->ordinary_starts!=1 || written->bytes!=nv_size+4096 ||
            !std::equal(payload.begin(),payload.end(),observed->disk.begin()+primary+512) ||
            !std::equal(payload.begin(),payload.end(),observed->disk.begin()+backup+512) ||
            !std::all_of(observed->disk.begin()+18*MiB,observed->disk.begin()+18*MiB+4096,[](auto b){return b==0x62;}))return 1;
        if(session::Operations::execute(dev,*plan) || observed->starts!=1)return 1;
    }
    uniflash::log_info("NV physical backup, directory batch, stale-plan and mirror-readback checks passed");
}

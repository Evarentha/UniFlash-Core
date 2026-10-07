/*
 * UniFlash-Core Test / Rename Write
 *
 * Covers alias transactions, recovery directories and GPT rebinding.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/session/rename_write.h>
#include <uniflash/session/raw_directory_restore.h>
#include <uniflash/io/sha256.h>
#include <uniflash/session/sparse.h>
#include <uniflash/session/raw_image_contract.h>
#include <fstream>
#include <deque>
#include <uniflash/log.h>
#include "temp_directory.h"

using namespace uniflash;
namespace {
using Bytes = std::vector<uint8_t>;
void put(Bytes& b, size_t at, uint64_t value, size_t count) {
    for (size_t i=0; i<count; ++i) b[at+i] = value >> (i*8);
}
uint64_t get(std::span<const uint8_t> b, size_t at, size_t count) {
    uint64_t n=0;
    for (size_t i=0;i<count;++i) n |= uint64_t(b[at+i]) << (8*i);
    return n;
}
class Loader : public transport::Transport {
public:
    Bytes disk = Bytes(32768*512), written;
    std::deque<Bytes> replies;
    unsigned repartitions=0, unlocks=0, starts=0,commands=0;
    bool reject_rename=false, corrupt_geometry=false, corrupt_backup=false;
    bool store_bytes=false, corrupt_data=false, two_partitions=false, change_guids=false;
    bool fail_write=false,fail_restore=false;
    uint64_t write_offset=1048576;
    std::string destination;
    Loader() {
        const std::string magic="EFI PART";
        std::copy(magic.begin(),magic.end(),disk.begin()+512);
        put(disk,520,0x10000,4); put(disk,524,92,4);
        put(disk,536,1,8); put(disk,544,32767,8);
        put(disk,552,34,8); put(disk,560,32734,8); disk[568]=1;
        put(disk,584,2,8); put(disk,592,128,4); put(disk,596,128,4);
        disk[1024]=1; disk[1040]=2;
        put(disk,1056,2048,8); put(disk,1064,4095,8);
        name("boot");
        reply(0x96, {0x6e,0x65,0x77,0x74,6,0,4,0,2,1,0,0});
    }
    void name(const std::string& value) {
        std::fill(disk.begin()+1080,disk.begin()+1152,0);
        for(size_t i=0;i<value.size();++i) disk[1080+2*i]=value[i];
        checksums();
    }
    void checksums() {
        put(disk,600,session::crc32_update(0,std::span(disk).subspan(1024,16384)),4);
        put(disk,528,0,4);
        put(disk,528,session::crc32_update(0,std::span(disk).subspan(512,92)),4);
        const size_t backup = 32767 * 512, entries = 32735 * 512;
        std::copy_n(disk.begin()+512,512,disk.begin()+backup);
        std::copy_n(disk.begin()+1024,16384,disk.begin()+entries);
        put(disk,backup+24,32767,8); put(disk,backup+32,1,8); put(disk,backup+72,32735,8);
        put(disk,backup+16,0,4);
        put(disk,backup+16,session::crc32_update(0,std::span(disk).subspan(backup,92)),4);
    }
    void reply(uint8_t code, const Bytes& bytes={}) {
        replies.push_back(*protocol::BslCodec::encode_hdlc_chk(code,bytes,protocol::BslCodec::Chk::Add));
    }
    std::expected<void,std::errc> bulk_write(std::span<const uint8_t> bytes, transport::Timeout, std::stop_token) override {
        ++commands;
        auto decoded=protocol::BslCodec::decode_hdlc(bytes,protocol::BslCodec::Chk::Add);
        if(!decoded) return std::unexpected(decoded.error());
        const auto& p=decoded->second;
        switch(decoded->first) {
        case 0x10: case 0x12: reply(0x80); break;
        case 0x11: {
            const auto size=get(p,0,4), offset=get(p,4,4);
            if(offset>disk.size() || size>disk.size()-offset) return std::unexpected(std::errc::bad_message);
            reply(0x93,Bytes(disk.begin()+offset,disk.begin()+offset+size)); break;
        }
        case 0x1b: ++unlocks; reply(0xfe); break;
        case 0x0b: {
            ++repartitions;
            if(fail_restore && repartitions==2){reply(0x84);break;}
            if(reject_rename) { reply(0x84); break; }
            std::string value;
            if (p.size()!=(two_partitions?152u:76u) || get(p,72,4)!=1) return std::unexpected(std::errc::bad_message);
            for(size_t at=0;at<72 && p[at];at+=2) value+=char(p[at]);
            name(value);
            if(two_partitions) {
                if(get(p,148,4)!=1) return std::unexpected(std::errc::bad_message);
                std::fill(disk.begin()+1208,disk.begin()+1280,0);
                for(size_t at=76;at<148 && p[at];at+=2) disk[1208+at-76]=p[at];
            }
            if(change_guids) {disk[568]=static_cast<uint8_t>(repartitions+1);disk[1040]=static_cast<uint8_t>(repartitions+2);}
            if(corrupt_geometry && repartitions==1) put(disk,1056,2049,8);
            else put(disk,1056,2048,8);
            checksums();
            if (corrupt_backup && repartitions==1) disk[32767*512+16]^=1;
            reply(0x80); break;
        }
        case 1:
            ++starts; destination.clear();written.clear();
            if(fail_write){reply(0x84);break;}
            for(size_t at=0;at<72 && p[at];at+=2) destination+=char(p[at]);
            write_offset=1048576;
            if(two_partitions) {
                std::string second;
                for(size_t at=1208;at<1280 && disk[at];at+=2) second+=char(disk[at]);
                if(destination==second) write_offset=2*1048576;
            }
            reply(0x80); break;
        case 2:
            if(store_bytes) {
                if(written.size()+p.size()>1048576) return std::unexpected(std::errc::message_size);
                std::copy(p.begin(),p.end(),disk.begin()+write_offset+written.size());
            }
            written.insert(written.end(),p.begin(),p.end()); reply(0x80); break;
        case 3: if(store_bytes && corrupt_data) disk[write_offset]^=1; reply(0x80); break;
        default: return std::unexpected(std::errc::not_supported);
        }
        return {};
    }
    std::expected<Bytes,std::errc> bulk_read(size_t,transport::Timeout,std::stop_token) override {
        if(replies.empty()) return std::unexpected(std::errc::io_error);
        auto b=std::move(replies.front()); replies.pop_front(); return b;
    }
    std::expected<void,std::errc> bulk_write_frame(std::span<const uint8_t>,transport::Timeout,std::stop_token) override {
        return std::unexpected(std::errc::not_supported);
    }
    bool supports_raw_frames() const override { return false; }
    uint16_t out_maxpacket() const override { return 512; }
    bool device_gone() const override { return false; }
    bool device_silent() const override { return false; }
};
}
int main() {
    TempDirectory root;
    const Bytes image(1024,0x42);
    const auto path=root.path/"boot.bin";
    { std::ofstream f(path,std::ios::binary); f.write(reinterpret_cast<const char*>(image.data()),image.size()); }
    // The exact loader only sniffs sparse at BTHD+512 on a temporary alias.
    // A physical header is opaque and can even have an invalid package hash.
    auto bthd=Bytes(1048576,0x42);put(bthd,0,0x42544844,4);
    const io::Reader bthd_reader=[&](uint64_t at,std::span<uint8_t> out,std::stop_token)->std::expected<void,std::errc> {
        if(at>bthd.size() || out.size()>bthd.size()-at) return std::unexpected(std::errc::message_size);
        std::copy_n(bthd.begin()+at,out.size(),out.begin());return {};
    };
    device::DeviceProfile replay_profile;
    if(session::validate_raw_replay(bthd_reader,bthd.size(),replay_profile)) return 1;
    replay_profile.bthd_alias_replay=true;
    if(!session::validate_raw_replay(bthd_reader,bthd.size(),replay_profile)) return 1;
    put(bthd,512,0xed26ff3a,4);
    if(session::validate_raw_replay(bthd_reader,bthd.size(),replay_profile)) return 1;
    put(bthd,512,0x42424242,4);
    for(unsigned scenario=0;scenario<6;++scenario) {
        auto tr=std::make_unique<Loader>(); auto* observed=tr.get();
        observed->reject_rename=scenario==1;
        observed->corrupt_geometry=scenario==2;
        observed->corrupt_backup=scenario==4;
        const auto original=observed->disk;
        device::SprdDevice dev(std::move(tr));
        if(!dev.resync_fdl2(std::chrono::seconds(1))) return 1;
        auto plan=session::RenameWrite::prepare(dev,"boot",path);
        if(!plan || observed->repartitions || observed->starts) return 1;
        if(scenario==5) {
            auto denied=session::RenameWrite::execute(dev,*plan);
            if(denied || observed->repartitions || observed->starts) return 1;
            continue;
        }
        if(!session::RenameWrite::save_recovery(*plan,root.path)) return 1;
        std::stop_source cancelled;
        if(scenario==3) cancelled.request_stop();
        auto result=session::RenameWrite::execute(dev,*plan,cancelled.get_token());
        if(observed->unlocks || observed->disk!=original) return 1;
        if(scenario==0) {
            if(!result || *result!=image.size() || observed->repartitions!=2 ||
                observed->written!=image || observed->destination!=plan->temporary_partition()) return 1;
        } else {
            if(result || observed->starts) return 1;
            if(observed->repartitions!=(scenario==1?1u:(scenario==2 || scenario==4)?2u:0u)) return 1;
        }
    }
    const auto raw_path=root.path/"physical.bin";
    {
        auto channel=std::make_unique<Loader>();auto* peer=channel.get();peer->fail_write=true;peer->fail_restore=true;
        device::SprdDevice dev(std::move(channel));if(!dev.resync_fdl2(std::chrono::seconds(1)))return 1;
        auto plan=session::RenameWrite::prepare(dev,"boot",path);if(!plan)return 1;
        const auto recovery=root.path/"dual-failure";std::filesystem::create_directory(recovery);
        if(!session::RenameWrite::save_recovery(*plan,recovery))return 1;
        auto result=session::RenameWrite::execute(dev,*plan);
        if(result || !result.error().exchange || result.error().exchange->command!=1 ||
            !result.error().cleanup_failure || !result.error().cleanup_failure->exchange ||
            result.error().cleanup_failure->exchange->command!=0xb)return 1;
    }
    Bytes physical(1048576,0x37);
    {std::ofstream f(raw_path,std::ios::binary);f.write(reinterpret_cast<const char*>(physical.data()),physical.size());}
    const auto interpreted_path=root.path/"sparse-magic.bin";
    auto interpreted=physical;interpreted[0]=0x3a;interpreted[1]=0xff;interpreted[2]=0x26;interpreted[3]=0xed;
    {std::ofstream f(interpreted_path,std::ios::binary);f.write(reinterpret_cast<const char*>(interpreted.data()),interpreted.size());}
    const auto bthd_path=root.path/"physical-bthd.bin";
    {std::ofstream f(bthd_path,std::ios::binary);f.write(reinterpret_cast<const char*>(bthd.data()),bthd.size());}
    for(unsigned scenario=0;scenario<4;++scenario) {
        const bool corrupt=scenario==1;
        auto tr=std::make_unique<Loader>();auto* observed=tr.get();
        const std::string target=scenario==0?"miscdata":scenario==1?"userdata":"nr_fixnv2";
        observed->name(target);
        observed->store_bytes=true;observed->corrupt_data=corrupt;
        device::DeviceProfile profile;profile.raw_partition_relocation=true;profile.legacy_gpt_rebuild=true;
        profile.bthd_alias_replay=scenario==3;
        device::SprdDevice dev(std::move(tr),profile);
        if(!dev.resync_fdl2(std::chrono::seconds(1))) return 1;
        // An ordinary short image is not a full raw snapshot.
        if(session::RenameWrite::prepare_raw(dev,target,path)) return 1;
        if(session::RenameWrite::prepare_raw(dev,target,interpreted_path) || observed->repartitions) return 1;
        auto plan=session::RenameWrite::prepare_raw(dev,target,scenario==3?bthd_path:raw_path);
        if(!plan || observed->repartitions) return 1;
        const auto dir=root.path/("raw-"+std::to_string(scenario));std::filesystem::create_directory(dir);
        if(session::RenameWrite::execute(dev,*plan) || observed->repartitions) return 1;
        if(!session::RenameWrite::save_raw_recovery(dev,*plan,dir)) return 1;
        if(std::filesystem::file_size(dir/"before-partition.bin")!=physical.size()) return 1;
        if(scenario==2) {
            observed->disk[1048576]^=1;
            if(session::RenameWrite::execute(dev,*plan) || observed->repartitions) return 1;
            continue;
        }
        auto result=session::RenameWrite::execute(dev,*plan);
        if(bool(result)==corrupt || observed->repartitions!=2 || observed->unlocks) return 1;
        if(observed->destination!=plan->temporary_partition() || observed->destination==target) return 1;
        const auto& expected=scenario==3?bthd:physical;
        if(!corrupt && !std::equal(expected.begin(),expected.end(),observed->disk.begin()+1048576)) return 1;
        if(session::RenameWrite::execute(dev,*plan) || observed->repartitions!=2) return 1;
    }
    for(unsigned scenario=0;scenario<7;++scenario) {
        auto tr=std::make_unique<Loader>();auto* observed=tr.get();observed->store_bytes=true;
        observed->two_partitions=true;observed->change_guids=true;
        observed->disk[1152]=1;observed->disk[1168]=0x70;
        put(observed->disk,1184,4096,8);put(observed->disk,1192,6143,8);
        const std::string second="miscdata";
        for(size_t i=0;i<second.size();++i) observed->disk[1208+2*i]=second[i];
        observed->checksums();
        device::DeviceProfile profile;profile.raw_partition_relocation=true;profile.legacy_gpt_rebuild=true;
        device::SprdDevice dev(std::move(tr),profile);
        if(!dev.resync_fdl2(std::chrono::seconds(1))) return 1;
        const auto input=root.path/("bundle-"+std::to_string(scenario));std::filesystem::create_directory(input);
        const auto save=[&](const char* file,std::span<const uint8_t> bytes) {
            std::ofstream out(input/file,std::ios::binary);
            out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());
        };
        save("boot.bin",physical);
        const Bytes second_image(1048576,0x63);
        save("miscdata.bin",second_image);
        save("gpt-primary-header.bin",std::span(observed->disk).subspan(512,512));
        save("gpt-entries.bin",std::span(observed->disk).subspan(1024,16384));
        {
            std::ofstream out(input/"manifest.json");
            io::Sha256 first_hash,second_hash;first_hash.update(physical);second_hash.update(second_image);
            io::Sha256 header_hash,entries_hash;
            header_hash.update(std::span(observed->disk).subspan(512,512));entries_hash.update(std::span(observed->disk).subspan(1024,16384));
            out<<R"({"format":"raw-partition-backup-v3","image_semantics":"physical-snapshot","partition_scheme":"gpt","complete":true,
"primary_header_sha256":")"<<header_hash.hex()<<R"(","partition_entries_sha256":")"<<entries_hash.hex()<<R"(",
"sector_size":512,"user_area_bytes_from_gpt":16777216,"limitation":"",
"partitions":[{"name":"boot","file":"boot.bin","source":"user_partition","status":"saved",
"expected_bytes":1048576,"actual_bytes":1048576,"offset_bytes":1048576,"sha256":")"<<first_hash.hex()<<R"("},
{"name":"miscdata","file":"miscdata.bin","source":"user_partition","status":"saved",
"expected_bytes":1048576,"actual_bytes":1048576,"offset_bytes":2097152,"sha256":")"<<second_hash.hex()<<R"("}],
"total_read":2097152,"partitions_read":2})";
        }
        if(scenario==3) {
            // A late missing file must stop the whole batch before any writes.
            std::filesystem::remove(input/"miscdata.bin");
            if(session::RawDirectoryRestore::prepare(dev,input) || observed->repartitions || observed->starts) return 1;
            continue;
        }
        if(scenario==4) {
            auto broken=Bytes(observed->disk.begin()+1024,observed->disk.begin()+17408);broken[56]^=1;
            save("gpt-entries.bin",broken);
            if(session::RawDirectoryRestore::prepare(dev,input) || observed->commands) return 1;
            continue;
        }
        if(scenario==5) {
            auto changed=second_image;changed[123]^=1;save("miscdata.bin",changed);
            if(session::RawDirectoryRestore::prepare(dev,input) || observed->repartitions || observed->starts) return 1;
            continue;
        }
        auto plan=session::RawDirectoryRestore::prepare(dev,input);
        if(!plan || plan->count()!=2 || observed->repartitions || observed->starts) return 1;
        if(session::RawDirectoryRestore::execute(dev,*plan) || observed->starts) return 1;
        if(scenario==2) {
            if(session::RawDirectoryRestore::save_recovery(dev,*plan,input/"recovery") || observed->repartitions) return 1;
            continue;
        }
        {
            struct RestoreWorkingDirectory {
                std::filesystem::path previous=std::filesystem::current_path();
                ~RestoreWorkingDirectory(){std::error_code ec;std::filesystem::current_path(previous,ec);}
            } working_directory;
            std::filesystem::current_path(root.path);
            const auto name="bundle-recovery-"+std::to_string(scenario);
            const auto recovery=scenario==0?std::filesystem::path(name):scenario==1?std::filesystem::path(".")/name:root.path/name;
            if(!session::RawDirectoryRestore::save_recovery(dev,*plan,recovery))return 1;
        }
        // The directory's files can be changed after preparation, but their
        // frozen bytes remain the restore input. Device changes must fail.
        {std::ofstream changed(input/"boot.bin",std::ios::binary);changed<<"changed";}
        if(scenario==1) observed->disk[1048576]^=1;
        std::stop_source cancelled;
        const auto result=session::RawDirectoryRestore::execute(dev,*plan,cancelled.get_token(),[&](const session::OperationProgress& event){
            if(scenario==6 && event.step==session::OperationStep::Write && event.target_completed==event.target_total && event.target_total)
                cancelled.request_stop();
        });
        if(scenario==6) {
            if(result || result.error().code!=std::errc::interrupted || observed->starts!=1 || observed->repartitions!=2)return 1;
            continue;
        }
        if(scenario==1) {if(result || observed->starts || observed->repartitions) return 1;}
        else {
            if(!result || *result!=2*physical.size() || observed->repartitions!=4 ||
                !std::equal(physical.begin(),physical.end(),observed->disk.begin()+1048576) ||
                !std::equal(second_image.begin(),second_image.end(),observed->disk.begin()+2097152)) return 1;
            if(session::RawDirectoryRestore::execute(dev,*plan)) return 1;
        }
    }
    uniflash::log_info("Temporary rename/write/restore transactions passed");
}

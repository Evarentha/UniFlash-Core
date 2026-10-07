/*
 * UniFlash-Core Test / FDL2 Commands
 *
 * Covers chip query caching, BCB staging and raw list fallback.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/device/sprd_device.h>
#include <uniflash/session/pac_parser.h>
#include <uniflash/cli/ping.h>
#include <uniflash/session/boot_message.h>
#include <uniflash/session/operations.h>
#include "temp_directory.h"
#include <fstream>

#include <algorithm>
#include <deque>
#include <functional>
#include <uniflash/log.h>
#include <utility>

// Injected in-memory channel: no replacement of production linker symbols.
namespace {
using namespace uniflash;
using Bytes = std::vector<uint8_t>;
std::deque<std::expected<Bytes, std::errc>> replies;
std::function<void(const Bytes&, transport::Timeout)> on_write;
bool raw = false;
bool reject_raw_start = true;
std::errc write_error{};
class FakeTransport final : public transport::Transport {
public:
    bool supports_raw_frames() const override { return true; }
    uint16_t out_maxpacket() const override { return 512; }
    bool device_gone() const override { return false; }
    bool device_silent() const override { return false; }
    std::expected<void,std::errc> bulk_write(std::span<const uint8_t> bytes,
        transport::Timeout timeout,std::stop_token stop) override {
        if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
        // Legacy command fixtures explicitly lack raw USER-area access, so
        // discovery must fall back to their existing 0x2d handlers.
        if (reject_raw_start) {
            Bytes body;
            for (size_t i=1;i+1<bytes.size();++i) {
                auto b=bytes[i];
                if (!raw && b==0x7d) { if(i+2>=bytes.size()) return std::unexpected(std::errc::bad_message); b=bytes[++i]^0x20; }
                body.push_back(b);
            }
            if (body.size()>=82 && body[0]==0 && body[1]==0x10) {
                std::string name;
                for(size_t i=4;i<76 && body[i];i+=2) name+=char(body[i]);
                if(name=="user_partition") {
                    replies.push_back(Bytes{0x7e,0,0xfe,0,0,0xff,1,0x7e});
                    return {};
                }
            }
        }
        on_write(Bytes(bytes.begin(),bytes.end()),timeout);
        if(write_error != std::errc{}) return std::unexpected(std::exchange(write_error,std::errc{}));
        return {};
    }
    std::expected<void,std::errc> bulk_write_frame(std::span<const uint8_t> bytes,
        transport::Timeout timeout,std::stop_token stop) override {
        if(bytes.empty() || bytes.size()>65536) return std::unexpected(std::errc::message_size);
        return bulk_write(bytes,timeout,stop);
    }
    std::expected<Bytes,std::errc> bulk_read(size_t,transport::Timeout,std::stop_token stop) override {
        if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
        if(replies.empty()) return std::unexpected(std::errc::io_error);
        auto result=std::move(replies.front()); replies.pop_front(); return result;
    }
};
int failures = 0;
void check(bool ok, const char* name) {
    if (!ok) { uniflash::log_err(std::string("FAIL: ")+name); ++failures; }
}
uint64_t le(std::span<const uint8_t> bytes) {
    uint64_t value = 0;
    for (size_t i=0;i<bytes.size();++i) value |= uint64_t(bytes[i]) << (8*i);
    return value;
}
Bytes frame(uint8_t type, const Bytes& payload = {}, bool escaped = false) {
    Bytes body{0,type,static_cast<uint8_t>(payload.size()>>8),static_cast<uint8_t>(payload.size())};
    body.insert(body.end(),payload.begin(),payload.end());
    uint32_t sum=0;
    for(size_t i=0;i<body.size();++i) sum += uint32_t(body[i]) << ((i%2==0)?8:0);
    while(sum>>16) sum=(sum&65535)+(sum>>16);
    auto crc=static_cast<uint16_t>(~sum);
    body.push_back(crc>>8); body.push_back(crc&255);
    Bytes out{0x7e};
    for(auto b:body) {
        if(escaped && (b==0x7e || b==0x7d)) { out.push_back(0x7d); out.push_back(b^0x20); }
        else out.push_back(b);
    }
    out.push_back(0x7e);
    return out;
}
Bytes command(const Bytes& tx) {
    Bytes body;
    for(size_t i=1;i+1<tx.size();++i) {
        if(!raw && tx[i]==0x7d) body.push_back(tx[++i]^0x20);
        else body.push_back(tx[i]);
    }
    check(body.size()>=6,"command minimum size");
    if(body.size()<6) return {};
    uint32_t sum=0;
    for(size_t i=0;i<body.size();++i) sum += uint32_t(body[i]) << ((i%2)*8);
    while(sum>>16) sum=(sum&65535)+(sum>>16);
    check((sum&65535)==65535,"command passes BSP whole-packet ADD checksum");
    check(size_t((body[2]<<8)|body[3])+6==body.size(),"command length, including raw escape bytes");
    body.resize(body.size()-2);
    return body;
}
void ack(uint8_t code=0x80) { replies.push_back(frame(code,{},!raw)); }

device::SprdDevice enter(bool mode, device::DeviceProfile profile = {}, uint8_t storage_low = 2) {
    raw=false; replies.clear(); write_error={};
    FakeTransport tr;
    mode = mode && tr.supports_raw_frames();
    // Real resync consumes DA_INFO and negotiates 0x21.
    replies.push_back(frame(0x96,{0x6e,0x65,0x77,0x74,
        0,0,4,0,1,0,0,0,       // disable HDLC capability
        6,0,4,0,storage_low,1,0,0},true)); // E_STORAGE_TYPE
    on_write=[mode](const Bytes& tx, auto) {
        auto b=command(tx); check(b[1]==0x21,"negotiate transcode");
        ack(mode?0x80:0xfe);
    };
    device::SprdDevice dev{std::make_unique<FakeTransport>(std::move(tr)), profile};
    check(bool(dev.resync_fdl2(std::chrono::seconds(1))),"FDL2 fixture handshake");
    raw=mode;
    return dev;
}

void chip_cache_scenario(bool mode, unsigned scenario) {
    auto dev=enter(mode);
    on_write=[&](const Bytes& tx,auto) {
        switch(command(tx)[1]) {
        case 0x07: replies.push_back(frame(0x94,{0x98,0x76,0x54,0x32},!raw)); break;
        case 0x1a: replies.push_back(frame(0xab,{1,2,3},!raw)); break;
        case 0x0c: replies.push_back(frame(0x9d,{0,0,0x10,0,0,0,0xf8,0},!raw)); break;
        default: check(false,"unexpected initial chip query"); break;
        }
    };
    auto initial=dev.read_chip_info();
    check(initial && initial->chip_type==0x98765432 && initial->ddr_mb==4096 &&
        initial->emmc_mb==63488 && initial->chip_uid==Bytes{1,2,3},"seed known chip cache");
    if(!initial)return;
    unsigned queries=0;
    std::vector<uint8_t> commands;
    on_write=[&](const Bytes& tx,auto) {
        const auto code=command(tx)[1];++queries;commands.push_back(code);
        if(scenario==1) {ack(0xfe);return;}
        switch(code) {
        case 0x07:
            if(scenario==2) replies.push_back(frame(0x94,{1,2},!raw));
            else replies.push_back(frame(0x94,scenario==5?Bytes(4):Bytes{0,0,0,7},!raw));
            break;
        case 0x1a:
            if(scenario==3) ack(0x84);
            else replies.push_back(frame(0xab,scenario==5?Bytes{}:Bytes{4,5},!raw));
            break;
        case 0x0c:
            if(scenario==4) replies.push_back(frame(0x9d,{1,2,3},!raw));
            else if(scenario==6) replies.push_back(frame(0x9d,{0,0,8,0},!raw));
            else replies.push_back(frame(0x9d,Bytes(8),!raw));
            break;
        default: check(false,"unexpected chip cache query"); break;
        }
    };
    std::stop_source stop;
    if(scenario==7)stop.request_stop();
    auto refreshed=dev.read_chip_info(stop.get_token(),scenario!=0);
    auto expected=*initial;
    if(scenario==0)expected.chip_uid={4,5};
    if(scenario>=3 && scenario<=6)expected.chip_type=scenario==5?0:7;
    if(scenario>=4 && scenario<=6)expected.chip_uid=scenario==5?Bytes{}:Bytes{4,5};
    if(scenario==5) {expected.ddr_mb=0;expected.emmc_mb=0;}
    if(scenario==6)expected.ddr_mb=2048;
    auto matches=[&](const device::ChipInfo& actual) {
        return actual.chip_type==expected.chip_type && actual.ddr_mb==expected.ddr_mb &&
            actual.emmc_mb==expected.emmc_mb && actual.chip_uid==expected.chip_uid &&
            actual.version==expected.version;
    };
    check(matches(dev.info().chip),"only successfully queried chip fields update the cache");
    const bool success=scenario==0 || scenario==1 || scenario==5 || scenario==6;
    check(bool(refreshed)==success,"chip refresh reports failed queries");
    if(refreshed)check(matches(*refreshed),"chip refresh returns the complete session cache");
    if(scenario==0)check(commands==std::vector<uint8_t>{0x1a},"brief refresh queries only UID");
    if(scenario==2)check(queries==1,"malformed chip type stops refresh");
    if(scenario==3)check(queries==2,"failed UID stops refresh after caching successful chip type");
    if(scenario==7)check(queries==0 && !refreshed && refreshed.error()==std::errc::interrupted,
        "pre-cancelled refresh preserves identity without sending");
    check(!dev.link_silent(),"consumed query failures preserve chip-query synchronization");
    if(scenario==1) {
        const auto before=queries;
        auto brief=dev.read_chip_info({},false);
        check(brief && matches(*brief) && queries==before+1,
            "unsupported brief UID refresh preserves prior identity");
    }
    if(scenario==6) {
        auto capacities=dev.read_flash_type();
        check(capacities && capacities->first==2048 && capacities->second==63488 &&
            matches(dev.info().chip),"short capacity reply returns preserved eMMC capacity");
    }
}

void reboot_scenario(bool mode, session::RebootTarget target, int fault, bool restart=true) {
    // Faults: firstmode conflict, pre-command cancellation, write rejection,
    // corrupt readback, reset failure, firstmode read failure, cancellation,
    // misc read failure, verification read failure, END write rejection,
    // allowed persistent mode zero, invalid firstmode index.
    auto dev = enter(mode);
    Bytes original(session::BCB_BLOCK_SIZE);
    for (size_t i=0;i<original.size();++i) original[i]=static_cast<uint8_t>(i*37+3);
    Bytes misc=original, uploaded;
    Bytes first(4,0);
    if (fault==1 || fault==11 || fault==12)
        first={static_cast<uint8_t>(fault==11 ? 0x80 : fault==12 ? 0x7f : 0x91),0x4d,0x46,0x53};
    std::string part;
    bool original_read=false, attempted_write=false, reset_sent=false;
    std::stop_source cancelled;
    if (fault==2) cancelled.request_stop();
    on_write=[&](const Bytes& tx,auto) {
        auto b=command(tx);
        switch (b[1]) {
        case 0x2d: {
            Bytes table(152, 0);
            const std::string names[]{"miscdata", "misc"};
            for (size_t i = 0; i < 2; ++i) {
                for (size_t j = 0; j < names[i].size(); ++j) table[i*76+j*2] = names[i][j];
                table[i*76+73] = 4; // 1024 KiB
            }
            replies.push_back(frame(0xba, table, !raw));
            break;
        }
        case 0x10: case 0x01:
            part.clear();
            for(size_t i=4;i<76 && b[i];i+=2) part.push_back(static_cast<char>(b[i]));
            if(b[1]==0x01) {
                check(original_read,"original BCB read precedes first device write");
                check(part=="misc" && le(std::span(b).subspan(76,4))==4096,
                      "only first 4096 misc bytes are written");
                attempted_write=true; uploaded.clear();
            }
            if ((fault==6 && part=="miscdata") || (fault==8 && part=="misc") ||
                (fault==9 && b[1]==0x10 && attempted_write)) ack(0x84);
            else ack();
            break;
        case 0x11: {
            const auto size=le(std::span(b).subspan(4,4));
            const auto offset=le(std::span(b).subspan(8,4));
            Bytes payload;
            if(part=="miscdata") {
                check(size==4 && offset==0x2420,"firstmode is read, never changed");
                payload=first;
            } else {
                check(part=="misc" && size==4096 && offset==0,"read full BCB block");
                payload=misc;
                if(fault==4 && attempted_write) payload[3500]^=1;
            }
            replies.push_back(frame(0x93,payload,!raw)); break;
        }
        case 0x12:
            ack();
            if (part=="misc" && !attempted_write) {
                original_read=true;
                if (fault==7) cancelled.request_stop();
            }
            break;
        case 0x02:
            uploaded.insert(uploaded.end(),b.begin()+4,b.end());
            if(fault==3) ack(0x84); else { misc=uploaded; ack(); }
            break;
        case 0x03: ack(fault==10 ? 0x84 : 0x80); break;
        case 0x05:
            check(attempted_write,"BCB written before reset");
            reset_sent=true; ack(fault==5 ? 0x84 : 0x80); break;
        default: check(false,"no erase, firstmode write or unrelated operation during targeted reboot");
        }
    };
    auto result=restart?session::reboot_to(dev,target,cancelled.get_token()):
        session::request_boot_target(dev,target,cancelled.get_token());
    const bool success=fault==0 || fault==11 || (!restart && fault==5);
    check(bool(result)==success,"targeted reboot result reflects the failed step");
    check(reset_sent==(restart && (success || fault==5)),"reset sent only when explicitly requested after verification");
    if(success && !restart) {
        check(dev.info().stage==device::Stage::Fdl2 && !dev.session_ended() && !dev.link_silent(),"staged BCB retains FDL2 session");
        on_write=[&](const Bytes& tx,auto){auto b=command(tx);check(b[1]==0x7f,"next command remains usable after staging BCB");ack();};
        check(bool(dev.end_process()),"FDL2 responds after staging BCB without reset");
    }
    if(fault==1 || fault==2 || fault==6 || fault==7 || fault==8 || fault==12)
        check(!attempted_write,"early failure leaves misc untouched");
    if(success) {
        check(std::string(misc.begin(),misc.begin()+13)=="boot-recovery","U-Boot BCB command");
        check(std::equal(original.begin()+0x340,original.end(),misc.begin()+0x340),
              "stage, reserved and A/B metadata preserved");
    }
}
}

int main() {
    for(bool mode:{false,true})for(unsigned scenario=0;scenario<8;++scenario)
        chip_cache_scenario(mode,scenario);
    for(bool mode:{false,true})for(int fault=0;fault<=12;++fault)
        reboot_scenario(mode,session::RebootTarget::RecoveryWipe,fault,false);
    for(bool mode:{false,true})for(unsigned fault=0;fault<4;++fault) {
        auto dev=enter(mode);unsigned writes=0;
        on_write=[&](const Bytes& tx,auto) {
            const auto b=command(tx);++writes;
            if(b[1]==0x10) {
                if(fault==0) {replies.push_back(frame(0x93,{1,2},!raw));ack();}
                else if(fault==1)replies.push_back(frame(0x80,{1},!raw));
                else if(fault==2)ack(0xfe);
                else ack();
            } else if(b[1]==0x11)ack(0x84);
            else ack();
        };
        auto read=dev.read_partition("boot",0,4);
        check(!read,"invalid START or failed MIDST rejected");
        if(fault<2) {
            check(dev.link_silent(),"unrelated START reply or payload ACK retires session");
            const auto count=writes;
            check(!dev.end_process() && writes==count,"late START ACK cannot authorize subsequent command");
        } else if(fault==2) {
            check(read.error()==std::errc::not_supported && !dev.link_silent(),"explicit START refusal preserves idle session");
        } else {
            check(!dev.link_silent() && dev.last_exchange().response==protocol::BslResponse::REP_OPERATION_FAILED &&
                dev.cleanup_exchange() && dev.cleanup_exchange()->response==protocol::BslResponse::REP_ACK,
                "MIDST failure preserved independently of successful END");
        }
    }
    for(bool verified:{false,true}) {
        device::DeviceProfile profile;profile.ufs_boot_roles=verified;
        auto dev=enter(false,profile,3);
        on_write=[&](const Bytes& tx,auto) {
            const auto b=command(tx);
            check(b[1]==0x2d,"UFS fixture enumerates user partitions");
            Bytes table(76,0);table[0]='b';table[2]='o';table[4]='o';table[6]='t';table[73]=4;
            replies.push_back(frame(0xba,table,true));
        };
        auto parts=dev.list_partitions({},false);
        check(parts && parts->size()==(verified?3u:1u),"UFS boot roles require a verified firmware mapping");
        if(parts && verified) check((*parts)[1].hw_boot && (*parts)[1].name=="splloader" &&
            (*parts)[2].hw_boot && (*parts)[2].name=="splloader_bak","UFS roles use firmware aliases, not numeric LUN guesses");
    }
    for (bool mode : {false, true}) {
        auto dev = enter(mode);
        unsigned lists=0, starts=0;
        on_write = [&](const Bytes& tx, auto) {
            const auto b=command(tx);
            if (b[1]==0x2d) { ++lists; ack(0xfe); }
            else { if (b[1]==1) ++starts; ack(); }
        };
        TempDirectory dir;
        const auto path=dir.path/"boot.bin";
        { std::ofstream f(path,std::ios::binary); f << "test-image"; }
        auto plan=session::Operations::prepare_write(dev,"boot",path);
        check(plan && starts==0, "unavailable enumeration allows preparation without device write");
        if (plan) {
            dev.invalidate_layout();
            auto result=session::Operations::execute(dev,*plan);
            check(result && result->bytes==10 && starts==1 && lists==1,
                  "explicit named write survives revalidation without repeated unsupported queries");
        }
    }
    for (bool mode : {false, true}) for (bool end_ok : {false, true}) {
        auto dev = enter(mode);
        reject_raw_start = false;
        unsigned starts=0, ends=0, lists=0;
        on_write = [&](const Bytes& tx, auto) {
            const auto b = command(tx);
            switch (b[1]) {
            case 0x10: ++starts; ack(); break;
            case 0x11: ack(0x84); break;
            case 0x12: ++ends; ack(end_ok ? 0x80 : 0x84); break;
            case 0x2d: {
                ++lists;
                Bytes table(76,0); table[0]='b'; table[2]='o'; table[4]='o'; table[6]='t'; table[73]=4;
                replies.push_back(frame(0xba, table, !raw)); break;
            }
            default: check(false, "unexpected layout fallback command"); break;
            }
        };
        auto parts = dev.list_partitions({}, false);
        check(starts==1 && ends==1, "rejected first raw read is closed exactly once");
        if (end_ok) {
            check(parts && lists==1 && !dev.link_silent(), "END ACK permits named-list fallback");
            parts = dev.list_partitions({}, false);
            check(parts && starts==1 && lists==2, "unavailable raw route is cached");
        } else check(!parts && lists==0 && dev.link_silent(), "failed END prohibits fallback");
        reject_raw_start = true;
    }
    for (bool mode : {false, true}) {
        // Matching malformed payloads and definite rejection consume the
        // query; unrelated replies/timeouts must still retire the stream.
        for (unsigned scenario = 0; scenario < 6; ++scenario) {
            auto dev = enter(mode);
            unsigned queries = 0;
            on_write = [&](const Bytes& tx, auto) {
                auto request = command(tx);
                ++queries;
                if (request[1] == 0x7f) { ack(); return; }
                if (scenario == 0) replies.push_back(frame(0x94, {1,2}, !raw));
                if (scenario == 1) ack(0x84);
                if (scenario == 2) replies.push_back(frame(0x9d, {1,2,3}, !raw));
                if (scenario == 3) replies.push_back(frame(0xba, {1,2,3}, !raw));
                if (scenario == 4) replies.push_back(frame(0xab, {1,2,3}, !raw));
                if (scenario == 5) replies.push_back(std::unexpected(std::errc::io_error));
            };
            bool succeeded = false;
            if (scenario < 2) succeeded = bool(dev.read_chip_info());
            else if (scenario == 3) succeeded = bool(dev.list_partitions({}, false));
            else succeeded = bool(dev.read_flash_type());
            check(!succeeded && queries == 1, "failed query stops without sending another request");
            if (scenario < 4) {
                check(!dev.link_silent(), "consumed query failure preserves synchronization");
                check(bool(dev.end_process()), "connection remains usable after query failure");
            } else check(dev.link_silent(), "unrelated reply or receive failure retires connection");
        }
        for (uint8_t code : {0x82, 0x83, 0x84, 0x8b, 0xa0, 0xfe}) {
            auto dev = enter(mode);
            on_write = [code](const Bytes& tx, auto) {
                auto request = command(tx);
                ack(request[1] == 0x7f ? 0x80 : code);
            };
            check(!dev.read_flash_type() && !dev.link_silent(), "explicit query rejection retains connection");
            check(bool(dev.end_process()), "ping after explicit rejection");
        }
    }
    for (bool mode : {false, true}) {
        for (size_t size : {size_t(0), size_t(64), size_t(128), size_t(256)}) {
            auto dev = enter(mode);
            const Bytes uid(size, 'a');
            on_write = [&](const Bytes& tx, auto) {
                const auto request = command(tx);
                switch (request[1]) {
                case 0x07: ack(0xfe); break;
                case 0x1a: replies.push_back(frame(0xab, uid, !raw)); break;
                case 0x0c: replies.push_back(frame(0x9d,
                    {0,0,0x10,0, 0,0,0xf8,0, 0,0,0,0, 0,0,0,0}, !raw)); break;
                case 0x2d: {
                    Bytes table(76, 0);
                    table[0] = 'b'; table[2] = 'o'; table[4] = 'o'; table[6] = 't';
                    table[73] = 4;
                    replies.push_back(frame(0xba, table, !raw));
                    break;
                }
                default: check(false, "unexpected UID scenario command"); break;
                }
            };
            auto info = dev.read_chip_info();
            check(info && info->chip_uid == uid && info->ddr_mb == 4096 && info->emmc_mb == 63488,
                  "firmware UID payload length does not block capacity query");
            check(!dev.link_silent() && dev.info().stage == device::Stage::Fdl2,
                  "matching UID reply preserves FDL2 synchronization");
            auto parts = dev.list_partitions({}, false);
            check(parts && !parts->empty() && parts->front().name == "boot",
                  "partition query works after variable-length UID");
        }
    }
    for(bool mode:{false,true}) {
        for(const auto& target:session::reboot_targets)
            reboot_scenario(mode,target.target,0);
        for(int fault=1;fault<=12;++fault)
            reboot_scenario(mode,session::RebootTarget::Recovery,fault);
    }
    for(bool mode:{false,true}) {
        auto dev=enter(mode);
        uint8_t expected=0;
        Bytes payload;
        unsigned calls=0;
        on_write=[&](const Bytes& tx,auto) {
            auto b=command(tx); ++calls;
            check(b[1]==expected,"FDL2 command byte");
            check(Bytes(b.begin()+4,b.end())==payload,"FDL2 payload exact");
            ack();
        };
        expected=0x2a; payload={0x80};
        check(bool(dev.set_first_mode(0x80)),"firstmode persistent byte");
        for (unsigned value = 0; value <= 255; ++value) {
            payload = {static_cast<uint8_t>(value)};
            check(bool(dev.set_first_mode(value)), "all firstmode byte values accepted unchanged");
        }
        const auto before=calls;
        check(!dev.set_first_mode(0x100) && calls==before,
               "firstmode rejects byte truncation before I/O");
        expected=0x25; payload={'a',0x7e,0x7d};
        check(bool(dev.set_debuginfo("a~}")),"debug string odd checksum and escaping");
        payload={}; check(bool(dev.set_debuginfo("")),"empty debug selects firmware default");
        payload = Bytes(32, 'a');
        check(bool(dev.set_debuginfo(std::string(32,'a'))),"debug limit belongs to firmware");
        expected=0x22; payload={'2','0','2','6','~','}','x'};
        check(bool(dev.write_datetime(payload)),"datetime exact bytes in both modes");
        payload = Bytes(1025, 'a');
        check(bool(dev.write_datetime(payload)), "datetime limit belongs to firmware");
        check(!dev.write_datetime(Bytes(protocol::MAX_PAYLOAD_SIZE + 1)) && !dev.write_datetime({}), "datetime frame bounds");
        expected=0x1b; payload={}; check(bool(dev.enable_write_flash()),"unlock ACK");
        expected=0x7f; check(bool(dev.end_process()),"endproc ACK");

        session::PacImage image;
        session::PacPartition p; p.name="boot"; p.size=0x7e00;
        image.partitions.push_back(p);
        auto table=session::PacParser::build_repartition_table(image);
        check(bool(table),"test repartition layout");
        {
            unsigned step=0;
            on_write=[&](const Bytes& tx,auto timeout) {
                auto b=command(tx);
                ++step;
                check(b[1]==0x0b && Bytes(b.begin()+4,b.end())==*table,"repartition exact table without unlock");
                check(timeout==std::chrono::seconds(120),"repartition timeout covers GPT writes"); ack();
            };
            check(bool(dev.repartition(*table)) && step==1,"repartition sends only one command");
        }
        {
            unsigned commands=0;
            auto many=image;
            for(unsigned i=1;i<129;++i) { auto item=p; item.name="p"+std::to_string(i); many.partitions.push_back(item); }
            auto encoded=session::PacParser::build_repartition_table(many);
            on_write=[&](const Bytes&,auto) { ++commands; ack(); };
            check(encoded && !dev.repartition(*encoded) && commands==0,
                "wire encoder capacity does not override GPT receiver capacity");
        }
        unsigned writes=0;
        on_write=[&](const Bytes&,auto) { ++writes; replies.push_back(std::unexpected(std::errc::io_error)); };
        auto result=dev.repartition(*table);
        check(!result && result.error()==std::errc::io_error && writes==1,"repartition I/O failure is not retried");
        check(dev.link_silent(),"uncertain reply invalidates the session");
        check(!dev.end_process() && writes==1,"a ping cannot consume a late ACK after failure");
        dev=enter(mode);
        writes=0;
        on_write=[&](const Bytes&,auto) { ++writes; ack(0x84); };
        check(!dev.repartition(*table) && writes==1,"repartition refusal returned");
        writes=0;
        check(!dev.repartition(Bytes{1,2,3}) && writes==0,"malformed wire table rejected before I/O");
        dev=enter(mode);
        on_write=[&](const Bytes&,auto) { ++writes; write_error=std::errc::timed_out; };
        result=dev.repartition(*table);
        check(!result && result.error()==std::errc::timed_out && writes==1,
               "repartition write timeout is not retried");
        for(uint8_t code:{0xac,0x84}) {
            dev=enter(mode);
            writes=0;
            on_write=[&](const Bytes& tx,auto) {
                auto b=command(tx); ++writes;
                check(b[1]==0x0b,"no automatic write unlock"); ack(code);
            };
            result=dev.repartition(*table);
            check(!result && writes==1,"repartition refusal is not retried or automatically unlocked");
        }
        writes=0;
        on_write=[&](const Bytes& tx,auto) {
            auto b=command(tx); ++writes;
            check(b[1]==0x0b,"only repartition sent");
            replies.push_back(std::unexpected(std::errc::no_such_device));
        };
        result=dev.repartition(*table);
        check(!result && result.error()==std::errc::no_such_device && writes==1,
               "lost repartition reply does not trigger destructive retry");

        dev=enter(mode);
        unsigned step=0;
        Bytes ref(256,0x7e); ref[1]=0x7d;
        on_write=[&](const Bytes& tx,auto) {
            auto b=command(tx);
            switch(step++) {
            case 0:
                check(b[1]==0x10 && le(std::span(b).subspan(76,4))==0xfa100,
                       "read START covers requested offset+size"); ack(); break;
            case 1:
                check(b[1]==0x11 && le(std::span(b).subspan(4,4))==256 &&
                      le(std::span(b).subspan(8,4))==0xfa000,"read MIDST uses requested offset");
                replies.push_back(frame(0x93,ref,!raw)); break;
            case 2: check(b[1]==0x12,"read closes session"); ack(); break;
            default: check(false,"unexpected read request");
            }
        };
        auto read=dev.read_partition("miscdata",0xfa000,256);
        check(read && *read==ref && step==3,"offset read returns exact bytes without writes");

        // A local file failure and a user cancellation both arrive at a full
        // reply boundary: END must be consumed before the next command.
        for (auto reason : {std::errc::no_space_on_device, std::errc::interrupted}) {
            step = 0;
            on_write = [&](const Bytes& tx, auto) {
                const auto b = command(tx);
                if (step == 0) { check(b[1] == 0x10, "local failure starts read"); ack(); }
                else if (step == 1) { check(b[1] == 0x11, "local failure gets payload"); replies.push_back(frame(0x93, ref, !raw)); }
                else { check(b[1] == 0x12, "local failure closes read"); ack(); }
                ++step;
            };
            auto failed = dev.read_partition_stream("misc", 0, ref.size(),
                [reason](auto, auto) -> std::expected<void, std::errc> { return std::unexpected(reason); });
            check(!failed && failed.error() == reason && step == 3 && !dev.link_silent(),
                "local failure preserves original error and synchronized session");
        }

        unsigned data_acks = 0;
        bool end_acked = false;
        on_write = [&](const Bytes& tx, auto) {
            const auto b = command(tx);
            if (b[1] == 0x02) ++data_acks;
            if (b[1] == 0x03) end_acked = true;
            ack();
        };
        unsigned progress_calls = 0;
        auto written = dev.write_partition_stream("misc", 70000,
            [](uint64_t, std::span<uint8_t> bytes, auto) -> std::expected<void, std::errc> {
                std::fill(bytes.begin(), bytes.end(), 0x25); return {};
            }, {}, [&](const io::TransferProgress& event) {
                ++progress_calls;
                check(event.total == 70000 && event.completed <= event.total, "structured write byte counts");
                if (event.completed) check(data_acks > 0 && !end_acked, "progress follows data ACK before END");
            });
        check(written && progress_calls > 2 && end_acked, "write exposes intermediate structured progress");
        {
            device::DeviceProfile profile;
            profile.framed_write_u64 = true;
            dev = enter(mode, profile);
            unsigned commands = 0;
            on_write = [&](const Bytes& tx, auto) {
                const auto b = command(tx); ++commands;
                if (b[1] == 1) {
                    check(b.size()==92 && b[76]==0 && b[77]==0 && b[78]==0 && b[79]==0 && b[80]==2,
                        "verified large framed START uses full 64-bit length");
                } else check(b[1]==3, "local error closes large framed START");
                ack();
            };
            auto large = dev.write_partition_stream("userdata", uint64_t{2}<<32,
                [](uint64_t,std::span<uint8_t>,auto)->std::expected<void,std::errc> {
                    return std::unexpected(std::errc::io_error);
                });
            check(!large && commands==2 && !dev.link_silent(), "64-bit START does not require whole-file raw");
            dev = enter(mode);
        }
        for (bool throws : {false, true}) {
            unsigned starts=0, ends=0, data=0;
            on_write=[&](const Bytes& tx,auto) {
                const auto b=command(tx);
                starts += b[1]==1; ends += b[1]==3; data += b[1]==2;
                ack(b[1]==3 ? 0x84 : 0x80);
            };
            auto failed=dev.write_partition_stream("misc",4096,
                [throws](uint64_t,std::span<uint8_t>,auto)->std::expected<void,std::errc> {
                    if(throws) throw std::runtime_error("local snapshot I/O failure");
                    return std::unexpected(std::errc::io_error);
                });
            check(!failed && failed.error()==std::errc::io_error && starts==1 && ends==1 && data==0 &&
                !dev.link_silent() && !dev.write_timings().cancelled,
                "source I/O error closes framed transaction and is not reported as user cancellation");
        }

        // Cancel before START, in START, during source preparation, during
        // MIDST, and in final END. Never leave an ACK for the next command.
        for (unsigned phase = 0; phase < 6; ++phase) {
            for (bool reject_end : {false, true}) {
                dev = enter(mode);
                std::stop_source stop;
                unsigned starts = 0, midst = 0, ends = 0;
                if (phase == 0) stop.request_stop();
                on_write = [&](const Bytes& tx, auto) {
                    auto b = command(tx);
                    if (b[1] == 1) {
                        ++starts;
                        if (phase == 1) stop.request_stop();
                        ack();
                    } else if (b[1] == 2) {
                        ++midst;
                        if (phase == 3) stop.request_stop();
                        ack();
                    } else if (b[1] == 3) {
                        ++ends;
                        if (phase == 5) stop.request_stop();
                        ack(reject_end ? 0x84 : 0x80);
                    } else check(false, "cancel only sends START/MIDST/END");
                };
                auto cancelled_write = dev.write_partition_stream("vendor", 70000,
                    [&](uint64_t, std::span<uint8_t> bytes, auto) -> std::expected<void, std::errc> {
                        if (phase == 2) { stop.request_stop(); return std::unexpected(std::errc::interrupted); }
                        std::fill(bytes.begin(), bytes.end(), 0x25);
                        return {};
                    }, stop.get_token(), [&](const io::TransferProgress& event) {
                        if (phase == 4 && event.completed) stop.request_stop();
                    });
                check(!cancelled_write, "cancelled write never reports success");
                if (phase == 0) {
                    check(starts == 0 && ends == 0 && !dev.link_silent(), "pre-cancel sends nothing");
                } else {
                    check(starts == 1 && ends == 1 && replies.empty(), "cancel consumes ACKs and sends END exactly once");
                    check(!dev.link_silent(), "consumed END ACK or operation failure retains framed session");
                    check(dev.write_timings().cancel_end_rejected == reject_end, "END rejection is distinct from missing response");
                    if (phase <= 2) check(midst == 0, "early cancellation sends no data");
                    if (phase == 3 || phase == 4) check(midst == 1, "cancel stops after current complete block");
                    check(cancelled_write.error() == std::errc::interrupted,
                        "END response is still cancellation, not image success");
                    on_write = [&](const Bytes&, auto) { ack(); };
                    auto retry = dev.write_partition_stream("vendor", 16,
                        [](uint64_t, std::span<uint8_t> bytes, auto) -> std::expected<void, std::errc> {
                            std::fill(bytes.begin(), bytes.end(), 0x25); return {};
                        });
                    check(bool(retry) && replies.empty(), "fresh START/write/END succeeds after cancelled framed write");
                }
            }
        }
        dev = enter(mode);
        {
            std::stop_source stop;
            unsigned ends = 0;
            on_write = [&](const Bytes& tx, auto) {
                const auto b = command(tx);
                if (b[1] == 1) ack();
                else if (b[1] == 2) {
                    stop.request_stop();
                    replies.push_back(std::unexpected(std::errc::io_error));
                } else if (b[1] == 3) { ++ends; ack(); }
            };
            auto broken = dev.write_partition_stream("vendor", 70000,
                [](uint64_t, std::span<uint8_t> bytes, auto) -> std::expected<void, std::errc> {
                    std::fill(bytes.begin(), bytes.end(), 0x25); return {};
                }, stop.get_token());
            check(!broken && dev.link_silent() && ends == 0,
                "missing current reply forbids injecting END into uncertain session");
        }
        dev = enter(mode);

        for (unsigned fault = 0; fault < 3; ++fault) {
            dev = enter(mode);
            unsigned requests = 0;
            on_write = [&](const Bytes& tx, auto) {
                const auto b = command(tx);
                ++requests;
                check(b[1] == 0x0a, "erase sends only ERASE, never END/reset");
                if (fault == 2) replies.push_back(std::unexpected(std::errc::no_such_device));
                else ack(fault == 1 ? 0x84 : 0x80);
            };
            auto erased = dev.erase_partition("userdata", 0);
            check(bool(erased) == (fault == 0) && requests == 1, "erase reports actual device result");
            check(dev.link_silent() == (fault == 2), "complete erase reply retains session, lost reply retires it");
            check(replies.empty(), "erase consumes final reply");
            if (fault == 0) {
                on_write = [&](const Bytes& tx, auto) {
                    check(command(tx)[1] == 0x7f, "next request follows consumed erase ACK"); ack();
                };
                check(bool(dev.end_process()), "connection usable after erase completes");
            }
        }
        dev = enter(mode);
        std::optional<device::SprdDevice> connected(std::move(dev));
        std::vector<device::PartitionInfo> parts(1);
        writes=0;
        on_write=[&](const Bytes& tx,auto) {
            auto b=command(tx); ++writes;
            check(b[1]==0x7f && b.size()==4,"explicit ping is one empty END_PROCESS command");
            ack();
        };
        check(bool(cli::ping_fdl2(connected,parts,{})) && writes==1 &&
              connected && parts.size()==1,"ACK preserves session and cached partitions");
        std::stop_source cancelled;
        cancelled.request_stop();
        auto stopped=cli::ping_fdl2(connected,parts,cancelled.get_token());
        check(!stopped && stopped.error()==std::errc::interrupted && writes==1 && connected,
              "cancelled-before-ping sends nothing and preserves session");

        for(auto error:{std::errc::timed_out,std::errc::no_such_device,
                        std::errc::protocol_error}) {
            connected.emplace(enter(mode));
            parts.resize(1); writes=0;
            on_write=[&](const Bytes& tx,auto) {
                auto b=command(tx); ++writes;
                check(b[1]==0x7f,"only ping sent before failure");
                if(error==std::errc::protocol_error) ack(0xfe);
                else write_error=error;
            };
            auto probe=cli::ping_fdl2(connected,parts,{});
            check(!probe && probe.error()==error && writes==1 && !connected && parts.empty(),
                  "timeout/disconnect/bad reply invalidates handle and partition cache");
        }
    }
    if(failures) return 1;
    uniflash::log_info("FDL2 configuration/repartition wire tests passed");
}

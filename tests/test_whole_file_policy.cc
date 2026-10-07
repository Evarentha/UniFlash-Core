/*
 * UniFlash-Core Test / Whole-File Policy
 *
 * Covers whole-file raw route selection and fallback.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/device/sprd_device.h>
#include <algorithm>
#include <deque>
#include <uniflash/log.h>
using namespace uniflash;
using Bytes=std::vector<uint8_t>;
class Loader final:public transport::Transport {
public:
    std::deque<Bytes> replies;
    std::vector<uint16_t> commands;
    std::vector<size_t> raw_blocks;
    uint64_t remaining=0;bool raw=false,fail_data=false,fail_enable=false;
    bool late_error=false,reject_query=false,reject_end=false,reject_framed=false;
    bool partial_out=false,failed_end=false;
    bool bad_error=false;std::stop_source* cancel=nullptr;
    unsigned queries=0,ends=0;Bytes framed;
    explicit Loader(int mode) {
        Bytes da{0x6e,0x65,0x77,0x74,6,0,4,0,2,1,0,0};
        if(mode>=0)da.insert(da.end(),{2,0,1,0,static_cast<uint8_t>(mode)});
        reply(0x96,da);
    }
    void reply(uint16_t code,const Bytes& data={}) {replies.push_back(*protocol::BslCodec::encode_hdlc_chk(code,data,protocol::BslCodec::Chk::Add));}
    std::expected<void,std::errc> bulk_write(std::span<const uint8_t> data,transport::Timeout,std::stop_token) override {
        if(raw) {
            if(data.size()>remaining)return std::unexpected(std::errc::bad_message);
            if(partial_out)return std::unexpected(std::errc::io_error);
            raw_blocks.push_back(data.size());remaining-=data.size();
            if(fail_data) {raw=false;reply(0x84,bad_error?Bytes{1}:Bytes{});if(cancel)cancel->request_stop();}
            else if(late_error) {raw=false;reply(0x80);reply(0xa2);}
            else {raw=remaining!=0;reply(0x80);}
            return {};
        }
        auto packet=protocol::BslCodec::decode_hdlc(data,protocol::BslCodec::Chk::Add);
        if(!packet)return std::unexpected(packet.error());
        const auto cmd=packet->first;const auto& body=packet->second;commands.push_back(cmd);
        if(cmd==1) {
            if(body.size()!=76 && body.size()!=88)return std::unexpected(std::errc::message_size);
            remaining=0;for(size_t i=0;i<(body.size()==88?8u:4u);++i)remaining|=uint64_t(body[72+i])<<(i*8);
        } else if(cmd==0xd) {++queries;reply(reject_query?0x80:0x9b,reject_query?Bytes{}:Bytes(12,0));return {};}
        else if(cmd==3) {++ends;if(reject_end && queries) {reply(failed_end?0xa2:0xfe);return {};}}
        else if(cmd==2) {
            framed.insert(framed.end(),body.begin(),body.end());
            if(reject_framed) {reply(0xa2);return {};}
        } else if(cmd==0x33)raw=true;
        else if(cmd!=0x28 && cmd!=2 && cmd!=3)return std::unexpected(std::errc::not_supported);
        reply(cmd==0x28 && fail_enable?0xfe:0x80);return {};
    }
    static int recovery_checks() {
    for(unsigned scenario=0;scenario<13;++scenario) {
        auto transport=std::make_unique<Loader>(2);auto* observed=transport.get();
        observed->fail_data=scenario!=1;
        observed->late_error=scenario==1;observed->reject_query=scenario==2;
        observed->reject_end=scenario==3 || scenario==12;observed->failed_end=scenario==12;observed->partial_out=scenario==4;
        observed->reject_framed=scenario==5;
        device::DeviceProfile profile;if(scenario==6)profile.allow_whole_file_recovery=false;
        profile.raw_recovery=device::RawRecoveryContract::SingleBlockEndAckRestarts;
        if(scenario==11)profile.raw_recovery=device::RawRecoveryContract::Unknown;
        device::SprdDevice dev(std::move(transport),profile);
        if(!dev.resync_fdl2(std::chrono::seconds(1)))return 1;
        Bytes expected(65536,0x35);expected[1080]=0x53;expected[1081]=0xef;
        if(scenario==7) {expected[0]=0x3a;expected[1]=0xff;expected[2]=0x26;expected[3]=0xed;}
        unsigned reads=0;std::stop_source cancel;
        if(scenario==9)observed->cancel=&cancel;
        observed->bad_error=scenario==10;
        auto result=dev.write_partition_stream(scenario==8?"userdata":"system",expected.size(),
            [&](uint64_t at,std::span<uint8_t> out,std::stop_token)->std::expected<void,std::errc> {
                if(++reads>1)return std::unexpected(std::errc::io_error); // must use retained bytes on restart
                std::copy_n(expected.begin()+at,out.size(),out.begin());return {};
            },cancel.get_token(),[](const io::TransferProgress&){});
        if(scenario==0 || scenario==1) {
            if(!result || observed->queries!=2 || observed->ends!=(scenario==1?3u:2u) ||
                observed->framed!=expected || !dev.write_timings().raw_fallback || !dev.write_timings().raw_failure || reads!=1)return 1;
        } else if(scenario==2 || scenario==3 || scenario==12) {
            if(result || observed->queries!=1 || !observed->framed.empty() || !dev.link_silent())return 1;
        } else if(scenario==5) {
            if(result || observed->queries!=2 || !dev.write_timings().raw_fallback ||
                std::count(observed->commands.begin(),observed->commands.end(),1)!=2)return 1;
        } else {
            if(result || observed->queries || !observed->framed.empty() || observed->ends)return 1;
            if(scenario==4 && (!dev.last_exchange().bare_data || dev.last_exchange().offset!=0 ||
                dev.last_exchange().requested_bytes!=expected.size() || dev.last_exchange().response ||
                dev.last_exchange().outcome!=protocol::ExchangeOutcome::Unknown ||
                dev.last_exchange().transport_error!=std::errc::io_error))return 1;
        }
    }
    return 0;
    }
    std::expected<Bytes,std::errc> bulk_read(size_t,transport::Timeout,std::stop_token) override {
        if(replies.empty())return std::unexpected(std::errc::io_error);
        auto b=std::move(replies.front());replies.pop_front();return b;
    }
    std::expected<void,std::errc> bulk_write_frame(std::span<const uint8_t>,transport::Timeout,std::stop_token) override{return std::unexpected(std::errc::not_supported);}
    bool supports_raw_frames()const override{return false;}
    uint16_t out_maxpacket()const override{return 512;}
    bool device_gone()const override{return false;}
    bool device_silent()const override{return false;}
};
int main() {
    if(Loader::recovery_checks())return 1;
    if(!device::DeviceProfile{}.allow_whole_file_raw)return 1;
    for(unsigned scenario=0;scenario<8;++scenario) {
        const int mode=scenario==1?1:scenario==2?-1:scenario==7?0:2;
        auto transport=std::make_unique<Loader>(mode);auto* observed=transport.get();
        observed->fail_data=scenario==4;observed->fail_enable=scenario==5;
        device::DeviceProfile profile;if(scenario==3)profile.allow_whole_file_raw=false;
        device::SprdDevice dev(std::move(transport),profile);
        if(!dev.resync_fdl2(std::chrono::seconds(1)))return 1;
        const uint64_t size=scenario==6?1024:0x200000+4096;
        auto result=dev.write_partition_stream("boot",size,[](uint64_t,std::span<uint8_t> out,std::stop_token)->std::expected<void,std::errc>{
            std::fill(out.begin(),out.end(),0x35);return {};
        },{},[](const io::TransferProgress&){});
        if(scenario==4) {
            if(result || observed->commands!=std::vector<uint16_t>{0x28,1,0x33} || observed->raw_blocks.size()!=1)return 1;
        } else if(scenario==5) {
            if(result || observed->commands!=std::vector<uint16_t>{0x28} || !observed->raw_blocks.empty())return 1;
        } else if(scenario==0) {
            if(!result || observed->commands!=std::vector<uint16_t>{0x28,1,0x33,3} ||
                observed->raw_blocks!=std::vector<size_t>{0x200000,4096})return 1;
        } else {
            if(!result || !observed->raw_blocks.empty() || observed->commands.front()!=1 || observed->commands.back()!=3 ||
                std::find(observed->commands.begin(),observed->commands.end(),0x28)!=observed->commands.end())return 1;
        }
    }
    uniflash::log_info("Whole-file capability routing and no-replay checks passed");
}

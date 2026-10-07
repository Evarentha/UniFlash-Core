#include <uniflash/device/sprd_device.h>
#include <algorithm>
#include <deque>
#include <uniflash/log.h>
using namespace uniflash;
using Bytes=std::vector<uint8_t>;
class Loader final:public transport::Transport {
public:
    std::deque<Bytes> replies;
    std::vector<std::pair<uint16_t,Bytes>> sent;
    unsigned auth_status=0;bool malformed=false;
    bool auth_trace_protected=true;
    bool stray_ack=false;
    Loader(){reply(0x96,{0x6e,0x65,0x77,0x74,6,0,4,0,2,1,0,0});}
    void reply(uint16_t cmd,const Bytes& data={}) {replies.push_back(*protocol::BslCodec::encode_hdlc_chk(cmd,data,protocol::BslCodec::Chk::Add));}
    std::expected<void,std::errc> bulk_write(std::span<const uint8_t> wire,transport::Timeout,std::stop_token) override {
        auto decoded=protocol::BslCodec::decode_hdlc(wire,protocol::BslCodec::Chk::Add);
        if(!decoded)return std::unexpected(decoded.error());
        sent.push_back(*decoded);
        if(stray_ack){reply(0x80);reply(0x93,Bytes(4,0));return {};}
        if(decoded->first==0x41 || decoded->first==0x42)auth_trace_protected &= sensitive();
        if(decoded->first==0x41) {
            Bytes m1(malformed?289:290,0);m1[0]=0x74;if(!malformed)m1[288]=static_cast<uint8_t>(auth_status);reply(0xbd,m1);
        } else if(decoded->first==6) {reply(0x93,{0xff,0xaa,0xbb,0xcc});}
        else if(decoded->first==0x2e)reply(0xbc,{0x41,0,0,0});
        else if(decoded->first==0x15)reply(0x9e,Bytes(8,0x23));
        else if(decoded->first==0x16)reply(0x9f,Bytes(10,0x45));
        else reply(0x80);
        return {};
    }
    std::expected<Bytes,std::errc> bulk_read(size_t,transport::Timeout,std::stop_token) override {
        if(replies.empty())return std::unexpected(std::errc::io_error);
        auto decoded=protocol::BslCodec::decode_hdlc(replies.front(),protocol::BslCodec::Chk::Add);
        if(decoded && (decoded->first==0xbd || (!sent.empty() && sent.back().first==0x42)))auth_trace_protected &= sensitive();
        auto b=std::move(replies.front());replies.pop_front();return b;
    }
    std::expected<void,std::errc> bulk_write_frame(std::span<const uint8_t>,transport::Timeout,std::stop_token) override {return std::unexpected(std::errc::not_supported);}
    bool supports_raw_frames()const override{return false;}
    uint16_t out_maxpacket()const override{return 512;}
    bool device_gone()const override{return false;}
    bool device_silent()const override{return false;}
};
int main(){
    auto tr=std::make_unique<Loader>();auto* observed=tr.get();device::SprdDevice dev(std::move(tr));
    if(!dev.resync_fdl2(std::chrono::seconds(1)))return 1;
    const Bytes data{1,2,3,4};
    const io::Reader source=[&](uint64_t at,std::span<uint8_t> out,std::stop_token)->std::expected<void,std::errc>{
        if(at>data.size()||out.size()>data.size()-at)return std::unexpected(std::errc::message_size);
        std::copy_n(data.begin()+at,out.size(),out.begin());return {};
    };
    if(!dev.write_address_stream(0x12345678,4,source,device::AddressWordOrder::Big))return 1;
    if(observed->sent.size()!=3 || observed->sent[0].second!=Bytes({0x12,0x34,0x56,0x78,0,0,0,4}) ||
        observed->sent[1].second!=data || observed->sent[2].first!=3)return 1;
    observed->sent.clear();
    if(!dev.write_address_stream(0x12345678,4,source,device::AddressWordOrder::Little) ||
        observed->sent[0].second!=Bytes({0x78,0x56,0x34,0x12,4,0,0,0}))return 1;
    auto count=observed->sent.size();
    if(dev.write_address_stream(UINT32_MAX,4,source,device::AddressWordOrder::Little) ||
        dev.write_address_stream(0,3,source,device::AddressWordOrder::Little) || observed->sent.size()!=count)return 1;
    Bytes read;
    if(!dev.read_address_stream(0x1001,3,[&](auto bytes,auto)->std::expected<void,std::errc>{read.assign(bytes.begin(),bytes.end());return {};},
        device::AddressWordOrder::Little) || read!=Bytes({0xaa,0xbb,0xcc}) ||
        observed->sent.back().second!=Bytes({1,0x10,0,0,4,0,0,0}))return 1;
    if(!dev.erase_address(0x1000,5,device::AddressWordOrder::Big) ||
        observed->sent.back().second!=Bytes({0,0,0x10,0,0,0,0,6}))return 1;
    count=observed->sent.size();
    if(dev.erase_address(UINT32_MAX,1,device::AddressWordOrder::Little) || observed->sent.size()!=count ||
        device::address_erase_size(UINT32_MAX,1) || !device::address_erase_size(UINT32_MAX,UINT32_MAX))return 1;
    if(!dev.write_factory_timestamp(0x12345678) || observed->sent.back().first!=0x2c ||
        observed->sent.back().second.size()!=8)return 1;
    const auto stamp=observed->sent.back().second;
    if(!std::equal(stamp.begin(),stamp.begin()+6,Bytes({0x78,0x56,0x34,0x12,0x70,0x73}).begin()))return 1;
    // CRC16/IBM residue over the appended LE checksum is zero.
    uint16_t crc=0;for(auto b:stamp){crc^=b;for(unsigned j=0;j<8;++j)crc=(crc>>1)^((crc&1)?0xa001:0);}
    if(crc)return 1;
    if(!dev.write_factory_efuse() || observed->sent.back().first!=0x47 || !observed->sent.back().second.empty())return 1;
    auto vpac=dev.read_vpac();if(!vpac || *vpac!=Bytes({0x41,0,0,0}))return 1;
    if(!dev.write_vpac(*vpac) || observed->sent.back().first!=0x2f || observed->sent.back().second!=*vpac)return 1;
    count=observed->sent.size();if(dev.write_vpac(Bytes{0,0,0x41,0,0,0}) || observed->sent.size()!=count)return 1;
    auto uid=dev.read_softsim_identity(false),eid=dev.read_softsim_identity(true);
    if(!uid||!eid||*uid!=Bytes(8,0x23)||*eid!=Bytes(10,0x45))return 1;
    if(!dev.write_logical_nv("nr_fixnv1",data) || observed->sent[observed->sent.size()-3].second.size()!=80 ||
        observed->sent[observed->sent.size()-3].second[76]!=10)return 1;
    unsigned calls=0;
    device::AuthResponder responder=[&](auto m1,auto)->std::expected<Bytes,std::errc>{
        ++calls;if(m1.size()!=290 || m1[0]!=0x74)return std::unexpected(std::errc::bad_message);
        return Bytes(288,0x56);
    };
    if(!dev.authenticate(responder) || calls!=1 || observed->sent.back().first!=0x42 || observed->sent.back().second!=Bytes(288,0x56))return 1;
    observed->auth_status=1;count=observed->sent.size();
    if(!dev.authenticate(responder)||calls!=1||observed->sent.size()!=count+1)return 1;
    observed->auth_status=0;count=observed->sent.size();
    if(dev.authenticate([](auto,auto)->std::expected<Bytes,std::errc>{return Bytes(287);}) || observed->sent.size()!=count+1)return 1;
    std::stop_source cancel;cancel.request_stop();count=observed->sent.size();
    if(dev.authenticate(responder,cancel.get_token())||observed->sent.size()!=count)return 1;
    if(!observed->auth_trace_protected || observed->sensitive())return 1;
    if(dev.authenticate([](auto,auto)->std::expected<Bytes,std::errc>{throw 1;}) || observed->sensitive())return 1;
    for(unsigned query=0;query<5;++query) {
        auto channel=std::make_unique<Loader>();auto* peer=channel.get();device::SprdDevice d(std::move(channel));
        if(!d.resync_fdl2(std::chrono::seconds(1)))return 1;
        peer->stray_ack=query<4;peer->malformed=query==4;
        bool failed=false;
        if(query==0)failed=!d.read_softsim_identity(false);
        if(query==1)failed=!d.read_vpac();
        if(query==2)failed=!d.read_address_stream(0,4,[](auto,auto)->std::expected<void,std::errc>{return {};},device::AddressWordOrder::Little);
        if(query>=3)failed=!d.authenticate(responder);
        const auto count=peer->sent.size();
        if(!failed || !d.link_silent() || d.end_process() || peer->sent.size()!=count || peer->sensitive())return 1;
    }
    for(bool power:{false,true}) {
        auto channel=std::make_unique<Loader>();auto* peer=channel.get();device::SprdDevice terminal(std::move(channel));
        if(!terminal.resync_fdl2(std::chrono::seconds(1)) || !(power?terminal.power_down():terminal.reset()))return 1;
        const auto sent=peer->sent.size();
        if(!terminal.session_ended() || terminal.info().stage!=device::Stage::Offline || terminal.end_process() || peer->sent.size()!=sent)return 1;
    }
    uniflash::log_info("Package address, logical NV and authentication protocol checks passed");
}

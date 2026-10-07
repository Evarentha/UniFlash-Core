#include <uniflash/session/operations.h>
#include <uniflash/session/pac_archive.h>
#include <uniflash/session/pac_table.h>
#include <uniflash/io/checksum.h>
#include "temp_directory.h"
#include <algorithm>
#include <deque>
#include <fstream>
#include <uniflash/log.h>

using namespace uniflash;
using Bytes=std::vector<uint8_t>;
namespace {
constexpr uint64_t MiB=1048576;
void put(Bytes& bytes,size_t at,uint64_t value,size_t width=4) {
    for(size_t i=0;i<width;++i) bytes[at+i]=static_cast<uint8_t>(value>>(8*i));
}
uint64_t get(std::span<const uint8_t> bytes,size_t at,size_t width=4) {
    uint64_t value=0;for(size_t i=0;i<width;++i) value|=uint64_t(bytes[at+i])<<(8*i);return value;
}
void text(Bytes& bytes,size_t at,std::string_view value) {
    for(size_t i=0;i<value.size();++i) bytes[at+2*i]=value[i];
}
class Disk:public transport::Transport {
public:
    Bytes bytes=Bytes(16*MiB);
    std::deque<Bytes> replies;
    unsigned repartitions=0,starts=0;
    uint64_t write_at=0,received=0,total=0;
    bool drop_first_restore=false;
    Disk() {
        std::copy_n("EFI PART",8,bytes.begin()+512);
        put(bytes,520,0x10000);put(bytes,524,92);put(bytes,536,1,8);
        put(bytes,544,bytes.size()/512-1,8);put(bytes,552,34,8);put(bytes,560,bytes.size()/512-34,8);
        bytes[568]=1;put(bytes,584,2,8);put(bytes,592,128);put(bytes,596,128);
        layout(false);
        std::fill_n(bytes.begin()+MiB,MiB,0x31);
        std::fill_n(bytes.begin()+2*MiB,MiB,0x62);
        reply(0x96,Bytes{0x6e,0x65,0x77,0x74,6,0,4,0,2,1,0,0});
    }
    void layout(bool swapped) {
        std::fill_n(bytes.begin()+1024,16384,0);
        for(size_t i=0;i<3;++i) {
            const size_t at=1024+i*128;
            bytes[at]=1;bytes[at+16]=static_cast<uint8_t>(i+2);
            put(bytes,at+32,(i+1)*MiB/512,8);
            put(bytes,at+40,i==2?bytes.size()/512-34:(i+2)*MiB/512-1,8);
            text(bytes,at+56,i==2?"c":i==0?(swapped?"b":"a"):(swapped?"a":"b"));
        }
        put(bytes,600,io::crc32_update(0,std::span(bytes).subspan(1024,16384)));
        put(bytes,528,0);put(bytes,528,io::crc32_update(0,std::span(bytes).subspan(512,92)));
        const size_t head=bytes.size()-512,table=bytes.size()-33*512;
        std::copy_n(bytes.begin()+512,512,bytes.begin()+head);
        std::copy_n(bytes.begin()+1024,16384,bytes.begin()+table);
        put(bytes,head+24,bytes.size()/512-1,8);put(bytes,head+32,1,8);put(bytes,head+72,table/512,8);
        put(bytes,head+16,0);put(bytes,head+16,io::crc32_update(0,std::span(bytes).subspan(head,92)));
    }
    void reply(uint8_t code,const Bytes& payload={}) {
        replies.push_back(*protocol::BslCodec::encode_hdlc_chk(code,payload,protocol::BslCodec::Chk::Add));
    }
    std::expected<void,std::errc> bulk_write(std::span<const uint8_t> wire,transport::Timeout,std::stop_token) override {
        Bytes body;
        for(size_t i=1;i+1<wire.size();++i) {
            auto b=wire[i];if(b==0x7d) {if(i+2>=wire.size()) return std::unexpected(std::errc::bad_message);b=wire[++i]^0x20;}
            body.push_back(b);
        }
        if(body.size()<6) return std::unexpected(std::errc::bad_message);
        uint32_t sum=0;for(size_t i=0;i<body.size();i+=2) sum+=body[i]|(i+1<body.size()?uint32_t(body[i+1])<<8:0);
        while(sum>>16) sum=(sum&65535)+(sum>>16);
        if(sum!=65535) return std::unexpected(std::errc::bad_message);
        auto p=std::span(body).subspan(4,body.size()-6);
        switch(body[1]) {
        case 0x10:case 0x12:reply(0x80);break;
        case 0x11: {
            if(p.size()!=8) return std::unexpected(std::errc::bad_message);
            const auto size=get(p,0),offset=get(p,4);
            if(offset>bytes.size() || size>bytes.size()-offset) return std::unexpected(std::errc::message_size);
            reply(0x93,Bytes(bytes.begin()+offset,bytes.begin()+offset+size));break;
        }
        case 0xb:
            if(p.size()!=228 || p[0]!='b' || p[76]!='a' || p[152]!='c' ||
                get(p,72)!=1 || get(p,148)!=1 || get(p,224)!=UINT32_MAX) return std::unexpected(std::errc::bad_message);
            ++repartitions;layout(true);reply(0x80);break;
        case 1: {
            if(p.size()!=76) return std::unexpected(std::errc::bad_message);
            const char name=static_cast<char>(p[0]);
            write_at=name=='a'?2*MiB:name=='b'?MiB:name=='c'?3*MiB:UINT64_MAX;
            if(write_at>=bytes.size()) return std::unexpected(std::errc::invalid_argument);
            total=get(p,72);received=0;++starts;reply(0x80);break;
        }
        case 2:
            if(p.size()>total-received || write_at+received+p.size()>bytes.size()) return std::unexpected(std::errc::message_size);
            if(!(drop_first_restore && starts==1)) std::copy(p.begin(),p.end(),bytes.begin()+write_at+received);
            received+=p.size();reply(0x80);break;
        case 3: if(received!=total) return std::unexpected(std::errc::bad_message);reply(0x80);break;
        default:return std::unexpected(std::errc::not_supported);
        }
        return {};
    }
    std::expected<Bytes,std::errc> bulk_read(size_t,transport::Timeout,std::stop_token) override {
        if(replies.empty()) return std::unexpected(std::errc::io_error);
        auto b=std::move(replies.front());replies.pop_front();return b;
    }
    std::expected<void,std::errc> bulk_write_frame(std::span<const uint8_t>,transport::Timeout,std::stop_token) override {return std::unexpected(std::errc::not_supported);}
    bool supports_raw_frames() const override {return false;}
    uint16_t out_maxpacket() const override {return 512;}
    bool device_gone() const override {return false;}
    bool device_silent() const override {return false;}
};
}
int main() {
    TempDirectory root;
    const std::string xml="<BMAConfig><ProductList><Product name=\"fixture\"><SchemeName>fixture</SchemeName>"
        "<Partitions><Partition id=\"b\" size=\"1\"/><Partition id=\"a\" size=\"1\"/><Partition id=\"c\" size=\"0xffffffff\"/>"
        "</Partitions></Product></ProductList><SchemeList><Scheme name=\"fixture\"><File><ID>C</ID><Type>CODE2</Type>"
        "<Flag>1</Flag><Block id=\"c\"><Base>0</Base><Size>0</Size></Block></File></Scheme></SchemeList></BMAConfig>";
    constexpr size_t data=2124+2*2580;
    Bytes pac(data+1024+xml.size());
    text(pac,0,"BP_R1.0.0");put(pac,48,pac.size());text(pac,52,"fixture");put(pac,1076,2);put(pac,1080,2124);put(pac,2116,0xfffafffa);
    put(pac,2124,2580);text(pac,2128,"C");text(pac,2640,"c.bin");
    put(pac,2124+1540,1024);put(pac,2124+1544,1);put(pac,2124+1548,1);put(pac,2124+1552,data);
    const size_t x=2124+2580;
    put(pac,x,2580);text(pac,x+516,"fixture.xml");put(pac,x+1540,xml.size());put(pac,x+1544,2);put(pac,x+1552,data+1024);
    std::fill_n(pac.begin()+data,1024,0x43);std::copy(xml.begin(),xml.end(),pac.begin()+data+1024);
    put(pac,2120,session::pac_crc16(0,std::span(pac).first(2120)),2);
    put(pac,2122,session::pac_crc16(0,std::span(pac).subspan(2124)),2);
    const auto file=root.path/"fixture.pac";
    {std::ofstream out(file,std::ios::binary);out.write(reinterpret_cast<const char*>(pac.data()),pac.size());}
    for(unsigned scenario=0;scenario<3;++scenario) {
        auto transport=std::make_unique<Disk>();auto* disk=transport.get();
        device::DeviceProfile profile;profile.legacy_gpt_rebuild=true;profile.raw_partition_relocation=true;
        device::SprdDevice dev(std::move(transport),profile);
        if(!dev.resync_fdl2(std::chrono::seconds(1))) return 1;
        auto archive=session::PacArchive::open(file,0x102);
        if(!archive) return 1;
        session::PacPrepareOptions options;options.physical_recovery=true;
        auto plan=session::Operations::prepare_pac_with_options(dev,*archive,options);
        if(!plan || disk->repartitions || disk->starts) return 1;
        if(!session::Operations::save_pac_recovery(dev,*plan,root.path/("recovery-"+std::to_string(scenario)))) return 1;
        if(scenario==1) disk->bytes[MiB]^=1;
        disk->drop_first_restore=scenario==2;
        auto result=session::Operations::execute(dev,*plan);
        if(scenario==0) {
            if(!result || disk->repartitions!=1 || disk->starts!=3 ||
                !std::all_of(disk->bytes.begin()+MiB,disk->bytes.begin()+2*MiB,[](auto b){return b==0x62;}) ||
                !std::all_of(disk->bytes.begin()+2*MiB,disk->bytes.begin()+3*MiB,[](auto b){return b==0x31;})) return 1;
        } else if(result || disk->repartitions!=(scenario==1?0u:1u) || disk->starts!=(scenario==1?0u:1u)) return 1;
    }
    // Same named sizes but swapped physical locations must not count as a
    // matching layout in the standard package policy either.
    for(uint32_t strategy:{1u,3u}) {
        put(pac,1092,strategy);put(pac,2120,session::pac_crc16(0,std::span(pac).first(2120)),2);
        {std::ofstream out(file,std::ios::binary);out.write(reinterpret_cast<const char*>(pac.data()),pac.size());}
        auto transport=std::make_unique<Disk>();auto* disk=transport.get();
        device::SprdDevice dev(std::move(transport));if(!dev.resync_fdl2(std::chrono::seconds(1)))return 1;
        auto plan=session::Operations::prepare_pac(dev,file);
        if(strategy==1) {if(plan || disk->repartitions || disk->starts)return 1;continue;}
        if(!plan || !session::Operations::save_pac_recovery(dev,*plan,root.path/"strategy3"))return 1;
        if(!session::Operations::execute(dev,*plan) || disk->repartitions!=1 || disk->starts!=1)return 1;
    }
    uniflash::log_info("PAC overlapping relocation, stale source and failed readback checks passed");
}

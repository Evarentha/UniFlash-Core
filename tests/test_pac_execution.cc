/*
 * UniFlash-Core Test / PAC Execution
 *
 * Covers the prepare API surface and address-only NAND execution.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/session/operations.h>
#include <uniflash/session/pac_services.h>
#include <uniflash/session/pac_table.h>
#include <uniflash/session/pac_archive.h>
#include "temp_directory.h"
#include <algorithm>
#include <deque>
#include <fstream>
#include <uniflash/log.h>
using namespace uniflash;
using Bytes=std::vector<uint8_t>;
namespace {
// Compile-only consumer coverage: braces must uniquely select the legacy API,
// including its optional progress argument, for paths and archives alike.
template<class Source>
constexpr bool pac_prepare_api = requires(device::SprdDevice& dev, const Source& source,
    const session::PacPrepareOptions& options, std::stop_token stop,
    const session::ProgressObserver& progress) {
    session::Operations::prepare_pac(dev,source);
    session::Operations::prepare_pac(dev,source,{});
    session::Operations::prepare_pac(dev,source,{},{});
    session::Operations::prepare_pac(dev,source,stop,progress);
    session::Operations::prepare_pac_with_options(dev,source,options);
    session::Operations::prepare_pac_with_options(dev,source,{},{});
    session::Operations::prepare_pac_with_options(dev,source,options,stop,progress);
};
static_assert(pac_prepare_api<std::filesystem::path>);
static_assert(pac_prepare_api<session::PacArchive>);

void put(Bytes& b,size_t at,uint64_t n,size_t count=4) {
    for(size_t i=0;i<count;++i) b[at+i]=static_cast<uint8_t>(n>>(8*i));
}
void text(Bytes& b,size_t at,std::string_view s) {for(size_t i=0;i<s.size();++i) b[at+i*2]=s[i];}
void package(const std::filesystem::path& path,uint32_t strategy,bool oversized=false,bool sparse=false,bool wide=false,bool read=false,bool control=false,bool table=false,std::string terminal={}) {
    const std::string xml="<BMAConfig><ProductList><Product name=\"fixture\"><SchemeName>fixture</SchemeName>"
        "<Partitions><Partition id=\"boot\" size=\"1\"/></Partitions></Product></ProductList>"
        "<SchemeList><Scheme name=\"fixture\"><File><ID>ERASE</ID><Type>EraseFlash2</Type><Flag>0</Flag>"
        "<Block id=\"boot\"><Base>0</Base><Size>0</Size></Block></File>"
        "<File><ID>BOOT</ID><Type>"+(!terminal.empty()?terminal:std::string(table?"EXTTABLE":control?"EndProcess":read?"ReadFlashAndDirectSave2_64":wide?"CODE2_64":"CODE2"))+"</Type><Flag>"+((read||control)?"0":"1")+"</Flag>"
        "<Block id=\"boot\"><Base>0</Base><Size>"+(read?"1024":"0")+"</Size></Block></File></Scheme></SchemeList></BMAConfig>";
    constexpr size_t begin=2124+3*2580;
    const size_t length=(read||control)?0:sparse?44:oversized?1048577:1024;
    Bytes b(begin+length+xml.size());
    text(b,0,"BP_R1.0.0");put(b,48,b.size());text(b,52,"fixture");put(b,1076,3);put(b,1080,2124);
    put(b,2116,0xfffafffa);
    // PAC header repartition strategy; matches the archive parser's R27 field.
    put(b,1092,strategy);
    size_t row=2124;put(b,row,2580);text(b,row+4,"ERASE");put(b,row+1548,1);
    row+=2580;put(b,row,2580);text(b,row+4,"BOOT");text(b,row+516,"boot.bin");
    put(b,row+1540,length);put(b,row+1544,(read||control)?0:1);put(b,row+1548,1);put(b,row+1552,(read||control)?0:begin);
    row+=2580;put(b,row,2580);text(b,row+516,"fixture.xml");put(b,row+1540,xml.size());put(b,row+1544,2);put(b,row+1552,begin+length);
    if(sparse) {
        put(b,begin,0xed26ff3a);put(b,begin+4,1,2);put(b,begin+8,28,2);put(b,begin+10,12,2);
        put(b,begin+12,4096);put(b,begin+16,256);put(b,begin+20,1);
        put(b,begin+28,0xcac2,2);put(b,begin+32,256);put(b,begin+36,16);put(b,begin+40,0x42424242);
    } else if(length) {std::fill_n(b.begin()+begin,length,0x42);put(b,begin,0x42544844);put(b,begin+52,1);}
    std::copy(xml.begin(),xml.end(),b.begin()+begin+length);
    put(b,2120,session::pac_crc16(0,std::span(b).first(2120)),2);
    put(b,2122,session::pac_crc16(0,std::span(b).subspan(2124)),2);
    std::ofstream out(path,std::ios::binary);out.write(reinterpret_cast<const char*>(b.data()),b.size());
}
class Loader final:public transport::Transport {
public:
    std::deque<Bytes> replies;
    std::vector<uint16_t> commands;
    bool reject=false,read_mode=false;Bytes written,logical;size_t start_length=0,write_start_length=0;
    std::filesystem::path break_journal;
    explicit Loader(uint8_t storage=2) {reply(0x96,{0x6e,0x65,0x77,0x74,6,0,4,0,storage,1,0,0});}
    void reply(uint16_t code,const Bytes& data={}) {replies.push_back(*protocol::BslCodec::encode_hdlc_chk(code,data,protocol::BslCodec::Chk::Add));}
    std::expected<void,std::errc> bulk_write(std::span<const uint8_t> wire,transport::Timeout,std::stop_token) override {
        auto decoded=protocol::BslCodec::decode_hdlc(wire,protocol::BslCodec::Chk::Add);
        if(!decoded) return std::unexpected(decoded.error());
        const auto cmd=decoded->first;commands.push_back(cmd);
        if(reject && cmd==0xb && !break_journal.empty()) {
            std::filesystem::remove(break_journal);
            std::filesystem::create_directory(break_journal);
        }
        if(read_mode) {
            if(cmd==0x10) {start_length=decoded->second.size();reply(0x80);return {};}
            if(cmd==0x11) {reply(0x93,logical.empty()?Bytes(1024,0x35):logical);return {};}
            if(cmd==0x12) {reply(0x80);return {};}
        }
        // Any enumeration, physical read, unlock or implicit mirror command is
        // a failure: this loader only provides the package's required commands.
        if(cmd!=0xb && cmd!=0xa && cmd!=1 && cmd!=2 && cmd!=3 && cmd!=0x7f && cmd!=0x14 && cmd!=5 && cmd!=0x17) return std::unexpected(std::errc::not_supported);
        if(cmd==2) written.insert(written.end(),decoded->second.begin(),decoded->second.end());
        if(cmd==0x14) written=decoded->second;
        if(cmd==1) {start_length=decoded->second.size();write_start_length=start_length;}
        reply(reject && cmd==0xb?0x84:0x80);return {};
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
    {
        const auto path=root.path/"address-nand.pac";
        const std::string xml="<BMAConfig><ProductList><Product name='fixture'><SchemeName>fixture</SchemeName></Product></ProductList>"
            "<SchemeList><Scheme name='fixture'><File><ID>CODE</ID><Type>CODE</Type><Flag>1</Flag>"
            "<Block><Base>4096</Base><Size>4</Size></Block></File></Scheme></SchemeList></BMAConfig>";
        constexpr size_t start=2124+2*2580;
        Bytes bytes(start+4+xml.size());text(bytes,0,"BP_R1.0.0");put(bytes,48,bytes.size());text(bytes,52,"fixture");
        put(bytes,1076,2);put(bytes,1080,2124);put(bytes,1092,2);put(bytes,2116,0xfffafffa);
        put(bytes,2124,2580);text(bytes,2128,"CODE");text(bytes,2124+516,"image.bin");
        put(bytes,2124+1540,4);put(bytes,2124+1544,1);put(bytes,2124+1548,1);put(bytes,2124+1552,start);
        const size_t row=2124+2580;put(bytes,row,2580);text(bytes,row+516,"fixture.xml");
        put(bytes,row+1540,xml.size());put(bytes,row+1544,2);put(bytes,row+1552,start+4);
        std::fill_n(bytes.begin()+start,4,0x42);std::copy(xml.begin(),xml.end(),bytes.begin()+start+4);
        put(bytes,2120,session::pac_crc16(0,std::span(bytes).first(2120)),2);
        put(bytes,2122,session::pac_crc16(0,std::span(bytes).subspan(2124)),2);
        {std::ofstream file(path,std::ios::binary);file.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());}
        auto channel=std::make_unique<Loader>(1);auto* peer=channel.get();
        device::SprdDevice dev(std::move(channel));if(!dev.resync_fdl2(std::chrono::seconds(1)))return 1;
        auto archive=session::PacArchive::open(path,0x101);if(!archive)return 1;
        session::PacPrepareOptions options;options.address_word_order=device::AddressWordOrder::Little;
        auto from_path=session::Operations::prepare_pac_with_options(dev,path,options);
        auto from_archive=session::Operations::prepare_pac_with_options(dev,*archive,options);
        if(!from_path || !from_archive || from_path->bytes()!=4 || from_archive->bytes()!=4 || !peer->commands.empty())return 1;
        const auto recovery=root.path/"nand-journal";
        if(!session::Operations::save_recovery(dev,*from_path,recovery) || !session::Operations::execute(dev,*from_path) ||
            peer->commands!=std::vector<uint16_t>{1,2,3} || peer->write_start_length!=8 || peer->written!=Bytes(4,0x42))return 1;
        package(path,0);
        if(session::PacArchive::open(path,0x101))return 1;
    }
    for(unsigned scenario=0;scenario<11;++scenario) {
        const auto path=root.path/(std::to_string(scenario)+".pac");
        package(path,0,scenario==2,scenario==4,scenario==5,scenario==6,scenario==7 || scenario>=9,scenario==8,
            scenario==9?"Reset":scenario==10?"PowerOff":"");
        auto transport=std::make_unique<Loader>();auto* observed=transport.get();observed->reject=scenario==1;
        observed->read_mode=scenario==6;
        device::SprdDevice dev(std::move(transport));
        if(!dev.resync_fdl2(std::chrono::seconds(1))) return 1;
        auto archive=session::PacArchive::open(path,dev.da_info().storage);
        if(!archive)return 1;
        auto compiled=session::PacCompiler::compile(*archive,{},dev.profile(),dev.da_info());
        if(!observed->commands.empty())return 1;
        if(scenario==2) {if(compiled)return 1;continue;}
        if(!compiled)return 1;
        if(scenario==0) {
            auto other=std::make_unique<Loader>();auto* other_observed=other.get();
            device::DeviceProfile different;different.allow_whole_file_raw=false;
            device::SprdDevice changed(std::move(other),different);
            if(!changed.resync_fdl2(std::chrono::seconds(1)))return 1;
            if(session::PacResolver::resolve(changed,*compiled) || !other_observed->commands.empty())return 1;
            auto cancelled=session::PacResolver::resolve(dev,*compiled);if(!cancelled)return 1;
            std::stop_source stopped;stopped.request_stop();
            if(session::PacRecoveryStore::save(dev,*cancelled,root.path/"cancelled-persist",stopped.get_token()) ||
                cancelled->phase()!=session::PlanPhase::Persisting ||
                session::PacRecoveryStore::save(dev,*cancelled,root.path/"retry-persist") ||
                session::PlanExecutor::execute(dev,*cancelled) || !observed->commands.empty())return 1;
            auto exceptional=session::PacResolver::resolve(dev,*compiled);if(!exceptional)return 1;
            if(!session::PacRecoveryStore::save(dev,*exceptional,root.path/"exception-recovery"))return 1;
            auto failed=session::PlanExecutor::execute(dev,*exceptional,{}, {},[]()->std::shared_ptr<void>{throw std::bad_alloc();});
            if(failed || failed.error().code!=std::errc::not_enough_memory || !observed->commands.empty())return 1;
        }
        auto plan=session::PacResolver::resolve(dev,*compiled);
        if(!plan || !observed->commands.empty()) return 1;
        if(plan->phase()!=session::PlanPhase::ReadyToPersist)return 1;
        if(session::Operations::execute(dev,*plan) || !observed->commands.empty()) return 1;
        if(!session::PacRecoveryStore::save(dev,*plan,root.path/("journal-"+std::to_string(scenario)))) return 1;
        if(plan->phase()!=session::PlanPhase::ReadyToExecute)return 1;
        if(scenario==1)observed->break_journal=root.path/"journal-1"/"execution.txt";
        std::stop_source stop;if(scenario==3) stop.request_stop();
        bool reentry_checked=false,reentry_failed=false;
        auto result=session::PlanExecutor::execute(dev,*plan,stop.get_token(),[&](const session::OperationProgress&) {
            if(reentry_checked)return;
            reentry_checked=true;const auto count=observed->commands.size();
            auto nested=session::PlanExecutor::execute(dev,*plan);
            reentry_failed=bool(nested) || observed->commands.size()!=count;
        });
        if(!reentry_checked || reentry_failed)return 1;
        if(!std::filesystem::exists(root.path/("journal-"+std::to_string(scenario))/"execution.txt"))return 1;
        if(scenario==3) {if(result || !observed->commands.empty()) return 1;continue;}
        if(scenario>=9) {
            if(!result || !dev.session_ended() || dev.info().stage!=device::Stage::Offline ||
                observed->commands!=std::vector<uint16_t>{0xb,0xa,static_cast<uint16_t>(scenario==9?5:0x17)})return 1;
        } else if(scenario==1) {if(result || !result.error().journal_failure ||
            !result.error().exchange || result.error().exchange->response!=protocol::BslResponse::REP_OPERATION_FAILED ||
            observed->commands!=std::vector<uint16_t>{0xb}) return 1;}
        else if(scenario==8) {
            if(!result || observed->commands!=std::vector<uint16_t>{0xb,0xa,0x14} || observed->written.size()!=1024) return 1;
        } else if(scenario==7) {
            if(!result || observed->commands!=std::vector<uint16_t>{0xb,0xa,0x7f} || !observed->written.empty()) return 1;
        } else if(scenario==6) {
            if(!result || observed->commands!=std::vector<uint16_t>{0xb,0xa,0x10,0x11,0x12} || observed->start_length!=88) return 1;
            std::ifstream file(root.path/"journal-6"/"read-2-boot.bin",std::ios::binary);
            Bytes data{std::istreambuf_iterator<char>(file),{}};
            if(data!=Bytes(1024,0x35)) return 1;
        } else {
            if(!result || observed->commands!=std::vector<uint16_t>{0xb,0xa,1,2,3} ||
                observed->written.size()!=(scenario==4?44u:1024u) || observed->written[0]!=(scenario==4?0x3a:0x44) ||
                observed->start_length!=(scenario==5?88u:76u)) return 1;
        }
        const auto count=observed->commands.size();
        if(session::Operations::execute(dev,*plan) || observed->commands.size()!=count) return 1;
    }
    // Logical NV uses package/product length with an unknown loader, without
    // GPT reads. Original and merged bytes must be saved before submission.
    const auto nv_path=root.path/"nv.pac";
    const std::string nv_xml="<BMAConfig><ProductList><Product name=\"fixture\"><SchemeName>fixture</SchemeName>"
        "<NVBackup backup=\"1\"><NVItem name=\"IMEI\" backup=\"1\"><ID>5</ID></NVItem></NVBackup>"
        "</Product></ProductList><SchemeList><Scheme name=\"fixture\"><File><ID>NV</ID><Type>NV_COMM</Type><Flag>1</Flag>"
        "<Block id=\"nr_fixnv1\"><Base>0</Base><Size>64</Size></Block></File>"
        "<File><ID>CHECK</ID><Type>CHECK_NV2</Type><Flag>0</Flag><Block id=\"nr_fixnv1\"><Base>0</Base><Size>64</Size></Block></File>"
        "</Scheme></SchemeList></BMAConfig>";
    constexpr size_t start=2124+3*2580;
    Bytes b(start+64+nv_xml.size());text(b,0,"BP_R1.0.0");put(b,48,b.size());text(b,52,"fixture");
    put(b,1076,3);put(b,1080,2124);put(b,1092,2);put(b,2116,0xfffafffa);
    put(b,2124,2580);text(b,2128,"NV");text(b,2640,"nv.bin");put(b,2124+1540,64);
    put(b,2124+1544,1);put(b,2124+1548,1);put(b,2124+1552,start);
    const size_t x=2124+2580;put(b,x,2580);text(b,x+516,"fixture.xml");put(b,x+1540,nv_xml.size());
    put(b,x+1544,2);put(b,x+1552,start+64);
    put(b,x+2580,2580);text(b,x+2580+4,"CHECK");put(b,x+2580+1548,1);
    Bytes fresh(64,0xff);put(fresh,0,2);put(fresh,4,5,2);put(fresh,6,8,2);
    std::fill_n(fresh.begin()+8,8,0x55);
    std::copy(fresh.begin(),fresh.end(),b.begin()+start);std::copy(nv_xml.begin(),nv_xml.end(),b.begin()+start+64);
    put(b,2120,session::pac_crc16(0,std::span(b).first(2120)),2);put(b,2122,session::pac_crc16(0,std::span(b).subspan(2124)),2);
    {std::ofstream file(nv_path,std::ios::binary);file.write(reinterpret_cast<const char*>(b.data()),b.size());}
    auto tr=std::make_unique<Loader>();auto* loader=tr.get();loader->read_mode=true;loader->logical=fresh;
    put(loader->logical,0,7);std::fill_n(loader->logical.begin()+8,8,0x33);
    device::SprdDevice dev(std::move(tr));if(!dev.resync_fdl2(std::chrono::seconds(1)))return 1;
    auto archive=session::PacArchive::open(nv_path,0x102);if(!archive)return 1;
    session::PacPrepareOptions options; // Block/Size provides 64; no loader hash or GPT contract.
    if(session::Operations::prepare_pac_with_options(dev,*archive,options) || !loader->commands.empty())return 1;
    options.nv_representations.push_back({"nr_fixnv1",session::NvByteOrder::Little,session::NvByteOrder::Little,64,true});
    {
        auto incompatible=options;
        incompatible.nv_representations[0].device_order=session::NvByteOrder::BigItemHeaders;
        bool authenticated=false;
        incompatible.authentication=[&](auto,auto)->std::expected<Bytes,std::errc>{authenticated=true;return Bytes(288);};
        if(session::Operations::prepare_pac_with_options(dev,*archive,incompatible) || authenticated || !loader->commands.empty())return 1;
    }
    auto plan=session::Operations::prepare_pac_with_options(dev,*archive,options);if(!plan)return 1;
    if(loader->commands!=std::vector<uint16_t>{0x10,0x11,0x12})return 1;
    if(!session::Operations::save_pac_recovery(dev,*plan,root.path/"nv-journal"))return 1;
    if(!session::Operations::execute(dev,*plan) || loader->write_start_length!=80 || loader->written.size()!=64 ||
        loader->written[0]!=8 || !std::all_of(loader->written.begin()+8,loader->written.begin()+16,[](auto v){return v==0x33;}))return 1;
    if(loader->commands!=std::vector<uint16_t>{0x10,0x11,0x12,0x10,0x11,0x12,1,2,3,0x10,0x11,0x12})return 1;
    // Invalid later CHECK range is rejected locally before any earlier NV read.
    auto bad_xml=nv_xml;
    auto check=bad_xml.find("<ID>CHECK</ID>");auto base=bad_xml.find("<Base>0</Base>",check);
    bad_xml.replace(base,std::string("<Base>0</Base>").size(),"<Base>1</Base>");
    b.resize(start+64+bad_xml.size());put(b,48,b.size());put(b,x+1540,bad_xml.size());
    std::copy(bad_xml.begin(),bad_xml.end(),b.begin()+start+64);
    put(b,2120,session::pac_crc16(0,std::span(b).first(2120)),2);put(b,2122,session::pac_crc16(0,std::span(b).subspan(2124)),2);
    {std::ofstream file(nv_path,std::ios::binary);file.write(reinterpret_cast<const char*>(b.data()),b.size());}
    if(session::PacArchive::open(nv_path,0x102))return 1;
    // A late invalid dependency must fail before AUTH41 or the first NV read.
    bad_xml=nv_xml;
    check=bad_xml.find("<ID>CHECK</ID>");auto size=bad_xml.find("<Size>64</Size>",check);
    bad_xml.replace(size,14,"<Size>62</Size>");
    b.resize(start+64+bad_xml.size());put(b,48,b.size());put(b,x+1540,bad_xml.size());
    std::copy(bad_xml.begin(),bad_xml.end(),b.begin()+start+64);
    put(b,2120,session::pac_crc16(0,std::span(b).first(2120)),2);put(b,2122,session::pac_crc16(0,std::span(b).subspan(2124)),2);
    {std::ofstream file(nv_path,std::ios::binary);file.write(reinterpret_cast<const char*>(b.data()),b.size());}
    auto invalid=session::PacArchive::open(nv_path,0x102);if(!invalid)return 1;
    bool auth_called=false;options.authentication=[&](auto,auto)->std::expected<Bytes,std::errc>{auth_called=true;return Bytes(288);};
    const auto commands=loader->commands.size();
    if(session::Operations::prepare_pac_with_options(dev,*invalid,options) || auth_called || loader->commands.size()!=commands)return 1;
    for(bool erase:{false,true}) {
        auto xml=nv_xml;
        if(erase) {
            const auto at=xml.find("<File><ID>CHECK</ID>");
            xml.replace(at,xml.find("</File>",at)+7-at,
                "<File><ID>CHECK</ID><Type>EraseFlash</Type><Flag>0</Flag><Block><Base>0xffffffff</Base><Size>1</Size></Block></File>");
        } else {
            const auto at=xml.find("<Type>NV_COMM</Type>");xml.replace(at,std::string("<Type>NV_COMM</Type>").size(),"<Type>CODE2</Type>");
        }
        b.resize(start+64+xml.size());put(b,48,b.size());put(b,x+1540,xml.size());
        std::copy(xml.begin(),xml.end(),b.begin()+start+64);
        put(b,2120,session::pac_crc16(0,std::span(b).first(2120)),2);put(b,2122,session::pac_crc16(0,std::span(b).subspan(2124)),2);
        {std::ofstream file(nv_path,std::ios::binary);file.write(reinterpret_cast<const char*>(b.data()),b.size());}
        auto package=session::PacArchive::open(nv_path,0x102);if(!package)return 1;
        auto configured=options;configured.address_word_order=device::AddressWordOrder::Little;
        if(!erase)configured.nv_representations.clear();
        if(session::Operations::prepare_pac_with_options(dev,*package,configured) || auth_called || loader->commands.size()!=commands)return 1;
    }
    uniflash::log_info("PAC package order, no physical prerequisites and no retry checks passed");
}

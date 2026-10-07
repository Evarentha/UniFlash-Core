/*
 * UniFlash-Core / FDL2 Package Commands
 *
 * Address I/O, AUTH41, SoftSIM and VPAC command implementations.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/device/sprd_device.h>
#include <algorithm>
#include <array>
namespace uniflash::device {
std::expected<std::vector<uint8_t>,std::errc> SprdDevice::read_softsim_identity(bool eid,std::stop_token stop) {
    if(info_.stage!=Stage::Fdl2)return std::unexpected(std::errc::not_supported);
    if(stop.stop_requested())return std::unexpected(std::errc::interrupted);
    auto frame=encode_fdl2_command(static_cast<protocol::BslCommand>(eid?0x16:0x15));
    if(!frame)return std::unexpected(frame.error());
    auto reply=send_recv(*frame,{},std::chrono::seconds(15));
    if(!reply)return std::unexpected(reply.error());
    auto accepted=expect_query_reply(*reply,static_cast<protocol::BslResponse>(eid?0x9f:0x9e),"SoftSIM");
    if(!accepted)return std::unexpected(accepted.error());
    if(reply->payload.size()!=(eid?10u:8u)){desynchronized_=true;return std::unexpected(std::errc::message_size);}
    return std::move(reply->payload);
}
std::expected<void,std::errc> SprdDevice::write_factory_efuse(std::stop_token stop) {
    if(info_.stage!=Stage::Fdl2)return std::unexpected(std::errc::not_supported);
    if(stop.stop_requested())return std::unexpected(std::errc::interrupted);
    auto frame=encode_fdl2_command(static_cast<protocol::BslCommand>(0x47));
    if(!frame)return std::unexpected(frame.error());
    auto reply=send_recv(*frame,{},std::chrono::seconds(120));
    if(!reply)return std::unexpected(reply.error());
    return expect_ack(*reply);
}
std::expected<std::vector<uint8_t>,std::errc> SprdDevice::read_vpac(std::stop_token stop) {
    if(info_.stage!=Stage::Fdl2)return std::unexpected(std::errc::not_supported);
    if(stop.stop_requested())return std::unexpected(std::errc::interrupted);
    auto frame=encode_fdl2_command(static_cast<protocol::BslCommand>(0x2e));
    if(!frame)return std::unexpected(frame.error());
    auto reply=send_recv(*frame,{},std::chrono::seconds(15));
    if(!reply)return std::unexpected(reply.error());
    auto accepted=expect_query_reply(*reply,static_cast<protocol::BslResponse>(0xbc),"VPAC");
    if(!accepted)return std::unexpected(accepted.error());
    if(reply->payload.size()>512){desynchronized_=true;return std::unexpected(std::errc::message_size);}
    return std::move(reply->payload);
}
std::expected<void,std::errc> SprdDevice::write_vpac(std::span<const uint8_t> data,std::stop_token stop) {
    if(info_.stage!=Stage::Fdl2)return std::unexpected(std::errc::not_supported);
    if(stop.stop_requested())return std::unexpected(std::errc::interrupted);
    if(data.size()<4||data.size()>512||(data.size()&1)||data[data.size()-1]||data[data.size()-2])return std::unexpected(std::errc::invalid_argument);
    for(size_t i=0;i+2<data.size();i+=2)if(!data[i]&&!data[i+1])return std::unexpected(std::errc::invalid_argument);
    auto frame=encode_fdl2_command(static_cast<protocol::BslCommand>(0x2f),data);
    if(!frame)return std::unexpected(frame.error());
    auto reply=send_recv(*frame,{},std::chrono::seconds(15));
    if(!reply)return std::unexpected(reply.error());
    return expect_ack(*reply);
}
std::expected<void,std::errc> SprdDevice::write_factory_timestamp(uint32_t seconds,std::stop_token stop) {
    if(info_.stage!=Stage::Fdl2) return std::unexpected(std::errc::not_supported);
    if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    std::array<uint8_t,8> data{};
    for(unsigned i=0;i<4;++i)data[i]=static_cast<uint8_t>(seconds>>(8*i));
    data[4]=0x70;data[5]=0x73;
    uint16_t crc=0;
    for(size_t i=0;i<6;++i) {
        crc^=data[i];for(unsigned bit=0;bit<8;++bit)crc=static_cast<uint16_t>((crc>>1)^((crc&1)?0xa001:0));
    }
    data[6]=static_cast<uint8_t>(crc);data[7]=static_cast<uint8_t>(crc>>8);
    auto frame=encode_fdl2_command(static_cast<protocol::BslCommand>(0x2c),data);
    if(!frame)return std::unexpected(frame.error());
    auto reply=send_recv(*frame,{},std::chrono::seconds(15));
    if(!reply)return std::unexpected(reply.error());
    return expect_ack(*reply);
}
namespace {
std::vector<uint8_t> address_fields(uint32_t address,uint32_t size,AddressWordOrder order) {
    std::vector<uint8_t> result;
    for(auto v:{address,size}) for(unsigned i=0;i<4;++i)
        result.push_back(static_cast<uint8_t>(v>>(order==AddressWordOrder::Little?8*i:8*(3-i))));
    return result;
}
bool valid(AddressWordOrder order) {return order==AddressWordOrder::Little || order==AddressWordOrder::Big;}
}
std::expected<void,std::errc> SprdDevice::write_address_stream(uint32_t address,uint64_t size,
    const io::Reader& source,AddressWordOrder order,std::stop_token stop,const io::TransferObserver& observer,size_t chunk) {
    // R27 rounds odd lengths, but the padding byte depends on its source
    // preparation. Until that producer rule is established, never invent it.
    if(!source || !valid(order) || !size || (size&1) || size>UINT32_MAX) return std::unexpected(std::errc::invalid_argument);
    if(size>uint64_t(UINT32_MAX)+1-address) return std::unexpected(std::errc::value_too_large);
    return write_framed_stream("address",size,source,stop,observer,{},false,address,order,chunk);
}
std::expected<void,std::errc> SprdDevice::read_address_stream(uint32_t address,uint32_t size,
    const io::Writer& sink,AddressWordOrder order,std::stop_token stop) {
    if(info_.stage!=Stage::Fdl2) return std::unexpected(std::errc::not_supported);
    if(!sink || !size || !valid(order) || uint64_t(size)>uint64_t(UINT32_MAX)+1-address)
        return std::unexpected(std::errc::invalid_argument);
    // R27 ReadFlash requests leading alignment bytes, then trims them locally.
    // Individual reads are self-contained; no START/END and no uncertain retry.
    for(uint64_t at=0;at<size;) {
        if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
        const uint32_t base=address+static_cast<uint32_t>(at),prefix=base&3;
        const auto n=static_cast<uint32_t>(std::min<uint64_t>(0x3000-prefix,size-at));
        auto frame=encode_fdl2_command(protocol::BslCommand::CMD_READ_FLASH,address_fields(base,n+prefix,order));
        if(!frame) return std::unexpected(frame.error());
        auto reply=send_recv(*frame,{},std::chrono::seconds(15));
        if(!reply) return std::unexpected(reply.error());
        auto accepted=expect_query_reply(*reply,protocol::BslResponse::REP_READ_FLASH,"address read");
        if(!accepted)return std::unexpected(accepted.error());
        if(reply->payload.size()!=n+prefix){desynchronized_=true;return std::unexpected(std::errc::message_size);}
        auto saved=sink(std::span<const uint8_t>(reply->payload).subspan(prefix,n),stop);
        if(!saved) return saved;
        at+=n;
    }
    return {};
}
std::expected<void,std::errc> SprdDevice::erase_address(uint32_t address,uint32_t size,AddressWordOrder order) {
    if(info_.stage!=Stage::Fdl2) return std::unexpected(std::errc::not_supported);
    if(!valid(order)) return std::unexpected(std::errc::invalid_argument);
    const auto padded=address_erase_size(address,size);if(!padded)return std::unexpected(padded.error());
    auto frame=encode_fdl2_command(protocol::BslCommand::CMD_ERASE_FLASH,address_fields(address,*padded,order));
    if(!frame) return std::unexpected(frame.error());
    invalidate_layout();
    auto reply=send_recv(*frame,{},std::chrono::seconds(120));
    if(!reply) return std::unexpected(reply.error());
    return expect_ack(*reply);
}
std::expected<void,std::errc> SprdDevice::authenticate(const AuthResponder& responder,std::stop_token stop) {
    if(info_.stage!=Stage::Fdl2) return std::unexpected(std::errc::not_supported);
    if(!responder) return std::unexpected(std::errc::invalid_argument);
    const auto connection=connection_token();
    struct Sensitive {
        transport::Channel& channel;bool previous;
        explicit Sensitive(transport::Channel& c):channel(c),previous(c.sensitive()){channel.set_sensitive(true);}
        ~Sensitive(){channel.set_sensitive(previous);}
    } sensitive{transport_};
    if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    auto frame=encode_fdl2_command(static_cast<protocol::BslCommand>(0x41));
    if(!frame) return std::unexpected(frame.error());
    auto reply=send_recv(*frame,{},std::chrono::seconds(15));
    if(!reply) return std::unexpected(reply.error());
    auto accepted=expect_query_reply(*reply,static_cast<protocol::BslResponse>(0xbd),"AUTH41");
    if(!accepted)return std::unexpected(accepted.error());
    if(reply->payload.size()!=290){desynchronized_=true;return std::unexpected(std::errc::message_size);}
    const auto status=uint16_t(reply->payload[288])|(uint16_t(reply->payload[289])<<8);
    if(status==1) return {};
    if(status!=0) return std::unexpected(std::errc::bad_message);
    if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    std::expected<std::vector<uint8_t>,std::errc> response;
    try {response=responder(reply->payload,stop);} catch(...) {return std::unexpected(std::errc::io_error);}
    if(!response) return std::unexpected(response.error());
    struct Clear {std::vector<uint8_t>& b;~Clear(){volatile uint8_t* p=b.data();for(size_t i=0;i<b.size();++i)p[i]=0;}} clear{*response};
    if(response->size()!=288) return std::unexpected(std::errc::message_size);
    if(connection!=connection_token() || info_.stage!=Stage::Fdl2 || link_dead() || link_silent())
        return std::unexpected(std::errc::state_not_recoverable);
    if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    frame=encode_fdl2_command(static_cast<protocol::BslCommand>(0x42),*response);
    if(!frame) return std::unexpected(frame.error());
    reply=send_recv(*frame,{},std::chrono::seconds(15));
    if(!reply) return std::unexpected(reply.error());
    return expect_ack(*reply);
}
}

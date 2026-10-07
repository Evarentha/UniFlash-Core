/*
 * UniFlash-Core Test / BootROM Reconnect
 *
 * Covers EXEC, DDR, RAM completion and keep-charge fault paths.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/device/sprd_device.h>
#include <uniflash/device/chip_uid.h>
#include <algorithm>
#include <uniflash/log.h>
#include <thread>
#include <deque>
#include <stdexcept>

using namespace uniflash;
namespace {
class VersionTransport final : public transport::Transport {
public:
    std::vector<uint8_t> pending;
    bool loader = false, da = false, crc_loader = false;
    bool delayed_banner = false;
    unsigned connects = 0;
    unsigned writes = 0;
    std::expected<void, std::errc> bulk_write(std::span<const uint8_t> bytes,
        transport::Timeout, std::stop_token) override {
        ++writes;
        if (bytes.size() == 1 && bytes.front() == 0x7e) {
            if (delayed_banner && writes == 1) return {};
            const std::string version = crc_loader ? "Spreadtrum Boot Block version 1.1" : "Other vendor loader v1";
            std::vector<uint8_t> payload(version.begin(), version.end());
            if (da) payload = {0x6e,0x65,0x77,0x74}; // valid DA, no optional capabilities
            pending = *protocol::BslCodec::encode_hdlc_chk(da ? 0x96 : 0x81, payload,
                (loader && !crc_loader) || da ? protocol::BslCodec::Chk::Add : protocol::BslCodec::Chk::Crc16);
        } else {
            ++connects;
            const auto checksum = loader && !crc_loader ? protocol::BslCodec::Chk::Add : protocol::BslCodec::Chk::Crc16;
            auto decoded = protocol::BslCodec::decode_hdlc(bytes, checksum);
            if (!decoded || (decoded->first != 0 && decoded->first != 0x26 && decoded->first != 0x27))
                return std::unexpected(std::errc::protocol_error);
            pending = *protocol::BslCodec::encode_hdlc_chk(0x80, {}, checksum);
        }
        return {};
    }
    std::expected<std::vector<uint8_t>, std::errc> bulk_read(size_t, transport::Timeout timeout, std::stop_token) override {
        if (pending.empty() && delayed_banner && writes == 1) {
            std::this_thread::sleep_for(timeout);
            return std::unexpected(std::errc::timed_out);
        }
        if (pending.empty()) return std::unexpected(std::errc::io_error);
        return std::exchange(pending, {});
    }
    std::expected<void,std::errc> bulk_write_frame(std::span<const uint8_t>, transport::Timeout, std::stop_token) override {
        return std::unexpected(std::errc::not_supported);
    }
    bool supports_raw_frames() const override { return true; }
    uint16_t out_maxpacket() const override { return 512; }
    bool device_gone() const override { return false; }
    bool device_silent() const override { return false; }
};
// Script malformed completions independently of the host's reply classifier.
class CompletionTransport final : public transport::Transport {
public:
    using Bytes = std::vector<uint8_t>;
    protocol::BslCodec::Chk checksum;
    uint8_t fault_command=0xff, response=0x80;
    Bytes payload;
    bool throw_read=false, disconnect=false, silent=false, late_ack=false;
    bool rom=false;
    unsigned writes=0, execs=0;
    std::deque<Bytes> replies;
    explicit CompletionTransport(bool crc):checksum(crc?protocol::BslCodec::Chk::Crc16:protocol::BslCodec::Chk::Add) {}
    void reply(uint8_t code,const Bytes& data={}) {
        // Device ADD replies use canonical checksum, including odd payloads.
        if(checksum==protocol::BslCodec::Chk::Crc16) {
            replies.push_back(*protocol::BslCodec::encode_hdlc(code,data));return;
        }
        Bytes body{0,code,static_cast<uint8_t>(data.size()>>8),static_cast<uint8_t>(data.size())};
        body.insert(body.end(),data.begin(),data.end());
        auto sum=protocol::BslCodec::add_checksum(body);
        body.push_back(static_cast<uint8_t>(sum>>8));body.push_back(static_cast<uint8_t>(sum));
        Bytes wire{0x7e};
        for(auto b:body) {if(b==0x7e || b==0x7d){wire.push_back(0x7d);wire.push_back(b^0x20);}else wire.push_back(b);}
        wire.push_back(0x7e);replies.push_back(std::move(wire));
    }
    std::expected<void,std::errc> bulk_write(std::span<const uint8_t> bytes,transport::Timeout,std::stop_token) override {
        ++writes;
        if(bytes.size()==1) {reply(0x81,rom?Bytes{'S','P','R','D','3'}:Bytes{'S','p','r','e','a','d','t','r','u','m',' ','B','o','o','t'});return {};}
        auto decoded=protocol::BslCodec::decode_hdlc(bytes,checksum);
        if(!decoded)return std::unexpected(decoded.error());
        if(decoded->first==4)++execs;
        if(decoded->first==fault_command) {reply(response,payload);if(late_ack)reply(0x80);}
        else reply(0x80);
        return {};
    }
    std::expected<Bytes,std::errc> bulk_read(size_t,transport::Timeout timeout,std::stop_token) override {
        if(throw_read)throw std::runtime_error("receive fault after EXEC");
        if(disconnect)return std::unexpected(std::errc::no_such_device);
        if(silent){std::this_thread::sleep_for(timeout);return std::unexpected(std::errc::timed_out);}
        if(replies.empty())return std::unexpected(std::errc::io_error);
        auto bytes=std::move(replies.front());replies.pop_front();return bytes;
    }
    std::expected<void,std::errc> bulk_write_frame(std::span<const uint8_t>,transport::Timeout,std::stop_token) override {return std::unexpected(std::errc::not_supported);}
    bool supports_raw_frames() const override {return false;}
    uint16_t out_maxpacket() const override {return 64;}
    bool device_gone() const override {return false;}
    bool device_silent() const override {return false;}
};
class RomTransport final : public transport::Transport {
public:
    unsigned writes = 0;
    bool add_reply = false;
    bool valid_requests = true;
    std::expected<void, std::errc> bulk_write(std::span<const uint8_t> bytes,
        transport::Timeout, std::stop_token stop) override {
        if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
        ++writes;
        if (writes == 1) valid_requests &= bytes.size() == 1 && bytes.front() == 0x7e;
        else {
            auto expected = writes == 3 && add_reply ? protocol::BslCodec::encode_connect_add()
                                                    : protocol::BslCodec::encode_connect();
            valid_requests &= (writes == 2 || (writes == 3 && add_reply)) && expected && std::ranges::equal(bytes, *expected);
        }
        return {};
    }
    std::expected<std::vector<uint8_t>, std::errc> bulk_read(size_t,
        transport::Timeout timeout, std::stop_token) override {
        if (writes < 2) {
            std::this_thread::sleep_for(timeout);
            return std::unexpected(std::errc::timed_out);
        }
        // Independent captured ACKs: ROM CRC16 versus loader ADD checksum.
        return add_reply ? std::vector<uint8_t>{0x7e,0,0x80,0,0,0xff,0x7f,0x7e}
                         : std::vector<uint8_t>{0x7e,0,0x80,0,0,0x3b,0x5a,0x7e};
    }
    std::expected<void,std::errc> bulk_write_frame(std::span<const uint8_t>,
        transport::Timeout, std::stop_token) override { return std::unexpected(std::errc::not_supported); }
    bool supports_raw_frames() const override { return false; }
    uint16_t out_maxpacket() const override { return 64; }
    bool device_gone() const override { return false; }
    bool device_silent() const override { return false; }
};
class RunningLoader final : public transport::Transport {
public:
    unsigned writes = 0, connects = 0;
    std::expected<void, std::errc> bulk_write(std::span<const uint8_t> bytes, transport::Timeout, std::stop_token) override {
        ++writes;
        if (bytes.size() != 1) {
            ++connects;
            auto request = protocol::BslCodec::decode_hdlc(bytes, protocol::BslCodec::Chk::Add);
            if (!request || request->first != 0) return std::unexpected(std::errc::bad_message);
        }
        return {};
    }
    std::expected<std::vector<uint8_t>, std::errc> bulk_read(size_t, transport::Timeout timeout, std::stop_token) override {
        if (!connects) { std::this_thread::sleep_for(timeout); return std::unexpected(std::errc::timed_out); }
        return std::vector<uint8_t>{0x7e,0,0x80,0,0,0xff,0x7f,0x7e};
    }
    std::expected<void,std::errc> bulk_write_frame(std::span<const uint8_t>, transport::Timeout, std::stop_token) override {
        return std::unexpected(std::errc::not_supported);
    }
    bool supports_raw_frames() const override { return false; }
    uint16_t out_maxpacket() const override { return 64; }
    bool device_gone() const override { return false; }
    bool device_silent() const override { return false; }
};
class TransitionTransport final : public transport::Transport {
public:
    unsigned mode = 0, execs = 0;
    uint16_t packet_size = 64;
    std::vector<uint8_t> downloaded;
    bool executed = false;
    std::vector<uint8_t> pending;
    std::expected<void, std::errc> bulk_write(std::span<const uint8_t> bytes,
        transport::Timeout, std::stop_token) override {
        using C = protocol::BslCodec::Chk;
        if (bytes.size() == 1) {
            const std::string banner = executed ? "FDL test" : "SPRD3";
            pending = *protocol::BslCodec::encode_hdlc_chk(0x81,
                std::span(reinterpret_cast<const uint8_t*>(banner.data()), banner.size()), executed ? C::Add : C::Crc16);
            return {};
        }
        auto frame = protocol::BslCodec::decode_hdlc(bytes, executed ? C::Add : C::Crc16);
        if (!frame) return std::unexpected(frame.error());
        if (frame->first == 2) {
            if (bytes.size() >= 1024) return std::unexpected(std::errc::bad_message);
            // ROM receive refill loses an escape prefix at this boundary.
            for (size_t k = packet_size - 1; k + 1 < bytes.size(); k += packet_size)
                if (bytes[k] == 0x7d) return std::unexpected(std::errc::bad_message);
            downloaded.insert(downloaded.end(), frame->second.begin(), frame->second.end());
        }
        if (frame->first == 4) {
            ++execs;
            if (!frame->second.empty()) return std::unexpected(std::errc::bad_message);
            executed = true;
            if (mode == 0) pending = *protocol::BslCodec::encode_hdlc(0x80, {});
            if (mode == 1) {
                const std::vector<uint8_t> version{'F','D','L'};
                pending = *protocol::BslCodec::encode_hdlc_chk(0x81, version, C::Add);
            }
        } else pending = *protocol::BslCodec::encode_hdlc_chk(0x80, {}, executed ? C::Add : C::Crc16);
        return {};
    }
    std::expected<std::vector<uint8_t>, std::errc> bulk_read(size_t, transport::Timeout timeout, std::stop_token) override {
        if (!pending.empty()) return std::exchange(pending, {});
        std::this_thread::sleep_for(timeout);
        return std::unexpected(std::errc::timed_out);
    }
    std::expected<void,std::errc> bulk_write_frame(std::span<const uint8_t>, transport::Timeout, std::stop_token) override {
        return std::unexpected(std::errc::not_supported);
    }
    bool supports_raw_frames() const override { return false; }
    uint16_t out_maxpacket() const override { return packet_size; }
    bool device_gone() const override { return false; }
    bool device_silent() const override { return false; }
};
}
int main() {
    for(bool crc:{false,true}) {
        for(unsigned scenario=0;scenario<4;++scenario) {
            auto channel=std::make_unique<CompletionTransport>(crc);auto* peer=channel.get();
            device::SprdDevice dev(std::move(channel));if(!dev.handshake_fdl1())return 1;
            peer->throw_read=scenario==1;peer->disconnect=scenario==2;peer->silent=scenario==3;
            auto exec=protocol::BslCodec::encode_hdlc_chk(4,{},peer->checksum);
            bool threw=false;
            try {if(!dev.send_exec_raw(*exec))return 1;} catch(const std::runtime_error&) {threw=true;}
            if(threw!=(scenario==1) || dev.info().stage!=device::Stage::Offline || !dev.link_silent())return 1;
            const auto count=peer->writes;
            if(dev.download_image(std::vector<uint8_t>(16,0x42),0x1000) || peer->writes!=count || peer->execs!=1)return 1;
            if(scenario==0 && dev.last_exchange().response!=protocol::BslResponse::REP_ACK)return 1;
            if(scenario!=0 && dev.last_exchange().outcome!=protocol::ExchangeOutcome::Unknown)return 1;
        }
        for(bool sr:{false,true})for(unsigned scenario=0;scenario<5;++scenario) {
            auto channel=std::make_unique<CompletionTransport>(crc);auto* peer=channel.get();
            device::SprdDevice dev(std::move(channel));if(!dev.handshake_fdl1())return 1;
            peer->fault_command=sr?0x27:0x26;
            peer->response=scenario==0?0x93:scenario==1?0x80:scenario==4?0xfe:sr?0xb7:0xb6;
            peer->payload=scenario==1 || scenario==2?std::vector<uint8_t>{1,2}:std::vector<uint8_t>{};
            peer->late_ack=scenario==0;
            auto result=sr?dev.ddr_sr_test(1):dev.ddr_verify();
            if(scenario<3) {
                if(result || !dev.link_silent())return 1;
                const auto count=peer->writes;
                if(dev.download_image(std::vector<uint8_t>(16,0x42),0x1000) || peer->writes!=count)return 1;
            } else if(scenario==3) {if(!result || *result || dev.link_silent())return 1;}
            else if(result || result.error()!=std::errc::not_supported || dev.link_silent())return 1;
        }
        for(uint8_t response:{uint8_t(0x80),uint8_t(0x8f)})for(bool malformed:{false,true}) {
            auto channel=std::make_unique<CompletionTransport>(crc);auto* peer=channel.get();
            device::SprdDevice dev(std::move(channel));if(!dev.handshake_fdl1())return 1;
            peer->fault_command=3;peer->response=response;if(malformed)peer->payload={1,2};
            auto uploaded=dev.upload_fdl2(std::vector<uint8_t>(16,0x42),0x1000);
            if(malformed) {if(uploaded || !dev.link_silent() || peer->execs)return 1;}
            else if(!uploaded || peer->execs!=1)return 1;
        }
        auto channel=std::make_unique<CompletionTransport>(crc);auto* peer=channel.get();
        peer->fault_command=static_cast<uint8_t>(protocol::BslCommand::CMD_OFF_CHG);peer->payload={1,2};
        device::DeviceProfile profile;profile.keep_charge=true;
        device::SprdDevice dev(std::move(channel),profile);
        if(dev.handshake_fdl1() || !dev.link_silent())return 1;
    }
    for(uint8_t response:{uint8_t(0x80),uint8_t(0x8f)})for(bool malformed:{false,true}) {
        auto channel=std::make_unique<CompletionTransport>(true);auto* peer=channel.get();peer->rom=true;
        device::SprdDevice dev(std::move(channel));if(!dev.handshake())return 1;
        peer->fault_command=3;peer->response=response;if(malformed)peer->payload={1,2};
        auto uploaded=dev.upload_fdl1(std::vector<uint8_t>(16,0x42),0x1000);
        if(malformed) {if(uploaded || !dev.link_silent() || peer->execs)return 1;}
        else if(!uploaded || peer->execs!=1)return 1;
    }
    for (uint16_t packet : {64, 512}) {
        auto channel = std::make_unique<TransitionTransport>();
        auto* observed = channel.get();
        observed->packet_size = packet;
        device::SprdDevice dev(std::move(channel));
        if (!dev.handshake()) return 1;
        std::vector<uint8_t> image(1018, 0x42);
        // First payload escape lands exactly on the end of a USB packet.
        image[packet - 6] = 0x7d;
        if (!dev.download_image(image, 0x5500) || observed->downloaded != image) return 1;
        observed->downloaded.clear();
        image.assign(3000, 0x7e);
        if (!dev.download_image(image, 0x5000) || observed->downloaded != image) return 1;
    }
    {
        const std::vector<uint8_t> uid{8,0,0,0,0x41,7,0x80,0,0x99,7,0xb,0xc};
        if (device::format_chip_uid(uid) != "4107800099070B0C") return 1;
        const std::string text(64, 'a');
        if (device::format_chip_uid(std::span(reinterpret_cast<const uint8_t*>(text.data()), text.size())) != text) return 1;
        if (!device::format_chip_uid(std::vector<uint8_t>(64, 0)).empty()) return 1;
    }
    {
        auto channel = std::make_unique<VersionTransport>();
        auto* observed = channel.get();
        observed->loader = true;
        observed->delayed_banner = true;
        device::SprdDevice dev(std::move(channel));
        if (!dev.handshake_fdl1() || observed->writes != 3 || observed->connects != 1) return 1;
    }
    {
        auto channel = std::make_unique<RunningLoader>();
        auto* observed = channel.get();
        device::SprdDevice dev(std::move(channel));
        if (!dev.handshake_fdl1() || observed->connects != 1 || dev.info().stage != device::Stage::Fdl1 ||
            !dev.info().chip.version.empty()) return 1;
    }
    for (unsigned mode = 0; mode < 3; ++mode) {
        auto channel = std::make_unique<TransitionTransport>();
        auto* observed = channel.get(); observed->mode = mode;
        device::SprdDevice dev(std::move(channel));
        if (!dev.handshake()) return 1;
        const std::vector<uint8_t> image(600, 0x42);
        if (!dev.upload_fdl1(image, 0x1000) || dev.info().stage != device::Stage::Offline) return 1;
        if (!dev.handshake_fdl1() || dev.info().stage != device::Stage::Fdl1 || observed->execs != 1) return 1;
    }
    std::vector<uint8_t> legacy_da(256, 0);
    legacy_da[0] = 4; legacy_da[4] = 1; legacy_da[9] = 2; legacy_da[13] = 8;
    auto capabilities = protocol::parse_da_info(legacy_da);
    if (!capabilities || !capabilities->disable_hdlc || !capabilities->support_raw ||
        capabilities->flush_kb != 2048 || capabilities->storage != 0) return 1;
    legacy_da.resize(16);
    if (protocol::parse_da_info(legacy_da)) return 1;
    for (bool crc : {false, true}) {
        auto channel = std::make_unique<VersionTransport>();
        auto* observed = channel.get();
        observed->loader = true; observed->crc_loader = crc;
        device::SprdDevice dev(std::move(channel));
        auto result = dev.handshake_fdl1();
        if (!result || observed->writes != 2 || dev.info().stage != device::Stage::Fdl1 ||
            (dev.profile().fdl1_checksum == device::LoaderChecksum::Crc16) != crc) return 1;
        auto verified = dev.ddr_verify();
        if (!verified || !*verified) return 1;
        verified = dev.ddr_sr_test(10);
        if (!verified || !*verified) return 1;
    }
    const device::DeviceProfile generic;
    if (generic.whole_file_chunk != 0x200000 || generic.fdl1_receive_capacity != 0x300) return 1;
    auto invalid = generic;
    invalid.bootrom_chunk = 32760;
    if (invalid.valid()) return 1;
    if (!generic.valid() || generic.keep_charge || !generic.avoid_checksum_escapes ||
        generic.firstmode_offset != 0x2420 || generic.reset_usb_configuration || !generic.split_usb_packet) return 1;
    for (unsigned mode = 0; mode < 3; ++mode) {
        auto channel = std::make_unique<VersionTransport>();
        auto* observed = channel.get();
        observed->loader = mode == 1;
        observed->da = mode == 2;
        device::SprdDevice dev(std::move(channel));
        auto result = dev.handshake();
        const auto expected = mode == 0 ? device::Stage::Memory : mode == 1 ? device::Stage::Fdl1 : device::Stage::Fdl2;
        if (!result || result->stage != expected || observed->writes != (mode == 2 ? 1u : 2u) || dev.raw_tx()) return 1;
    }
    for (bool add : {false, true}) {
        auto channel = std::make_unique<RomTransport>();
        auto* observed = channel.get();
        observed->add_reply = add;
        device::SprdDevice dev(std::move(channel));
        auto connected = dev.handshake();
        if (!observed->valid_requests || observed->writes != (add ? 3u : 2u)) return 1;
        if (add) {
            if (!connected || dev.info().stage != device::Stage::Fdl1 || dev.link_silent()) return 1;
        } else if (!connected || connected->stage != device::Stage::Memory ||
                   !connected->chip.version.empty() || dev.link_silent()) return 1;
    }
    {
        auto channel = std::make_unique<RomTransport>();
        auto* observed = channel.get();
        device::SprdDevice dev(std::move(channel));
        const auto adopted = dev.resync_fdl2(std::chrono::milliseconds(0));
        if (adopted || adopted.error() != std::errc::not_supported || observed->writes ||
            dev.info().stage != device::Stage::Offline) return 1;
    }
    auto channel = std::make_unique<RomTransport>();
    auto* observed = channel.get();
    device::SprdDevice dev(std::move(channel));
    std::stop_source stop;
    stop.request_stop();
    auto result = dev.handshake(stop.get_token());
    if (result || result.error() != std::errc::interrupted || observed->writes) return 1;
    uniflash::log_info("BootROM reconnect classification passed");
}

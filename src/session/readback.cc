/*
 * UniFlash-Core / Range Readback
 *
 * Range comparison against prepared images.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/session/readback.h>
#include <algorithm>
#include <vector>
namespace uniflash::session {
namespace {
template<class Read>
std::expected<void,std::errc> compare(Read&& read,const io::Image& image,uint64_t length,
    std::stop_token stop,const io::PrepareObserver& progress,std::errc mismatch) {
    if(!length || length<image.size()) return std::unexpected(std::errc::message_size);
    if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    const auto source=image.reader();uint64_t done=0;
    std::vector<uint8_t> expected;
    auto result=read([&](std::span<const uint8_t> bytes,std::stop_token token)->std::expected<void,std::errc> {
        if(stop.stop_requested() || token.stop_requested()) return std::unexpected(std::errc::interrupted);
        if(done>length || bytes.size()>length-done) return std::unexpected(std::errc::message_size);
        expected.assign(bytes.size(),0xff);
        const size_t n=done<image.size()?static_cast<size_t>(std::min<uint64_t>(bytes.size(),image.size()-done)):0;
        if(n) {auto got=source(done,std::span(expected).first(n),token);if(!got) return got;}
        if(!std::equal(bytes.begin(),bytes.end(),expected.begin())) return std::unexpected(mismatch);
        done+=bytes.size();if(progress) progress({io::PreparePhase::Checksum,done,length});
        return {};
    });
    if(!result) return result;
    if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    if(done!=length) return std::unexpected(std::errc::message_size);
    return {};
}
}
std::expected<void,std::errc> compare_physical(device::SprdDevice& dev,const PhysicalAccess& access,
    uint64_t offset,const io::Image& image,uint64_t length,std::stop_token stop,
    const io::PrepareObserver& progress,std::errc mismatch) {
    return compare([&](const io::Writer& sink){return access.read(dev,offset,length,sink,stop);},
        image,length,stop,progress,mismatch);
}
std::expected<void,std::errc> compare_named(device::SprdDevice& dev,const std::string& name,
    const io::Image& image,uint64_t length,std::stop_token stop,const io::PrepareObserver& progress) {
    return compare([&](const io::Writer& sink){return dev.read_partition_stream(name,0,length,sink,stop);},
        image,length,stop,progress,std::errc::bad_message);
}
}

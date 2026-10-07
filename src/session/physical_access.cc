#include <uniflash/session/physical_access.h>
#include <algorithm>
namespace uniflash::session {
std::expected<PhysicalAccess,std::errc> PhysicalAccess::open(device::SprdDevice& dev,std::stop_token stop) {
    dev.invalidate_layout();
    auto layout=dev.read_disk_layout(stop);
    if(!layout) return std::unexpected(layout.error());
    if(layout->mbr) return std::unexpected(std::errc::not_supported);
    PhysicalAccess result;
    result.layout_=std::move(*layout); result.connection_=dev.connection_token();
    result.wide_=result.layout_.disk_bytes>UINT32_MAX;
    const io::Reader reader=[&](uint64_t offset,std::span<uint8_t> bytes,std::stop_token token)
        ->std::expected<void,std::errc> {
        size_t done=0;
        auto read=dev.read_user_area(offset,bytes.size(),[&](auto data,auto)->std::expected<void,std::errc> {
            if(data.size()>bytes.size()-done) return std::unexpected(std::errc::message_size);
            std::copy(data.begin(),data.end(),bytes.begin()+done); done+=data.size(); return {};
        },result.wide_,token);
        if(!read) return read;
        if(done!=bytes.size()) return std::unexpected(std::errc::message_size);
        return {};
    };
    std::vector<uint8_t> primary(result.layout_.primary_sector.size());
    auto checked=reader(result.layout_.header.sector_size,primary,stop);
    if(!checked) return std::unexpected(checked.error());
    if(primary!=result.layout_.primary_sector) return std::unexpected(std::errc::bad_message);
    checked=layout::verify_backup_gpt(result.layout_,reader,stop);
    if(!checked) return std::unexpected(checked.error());
    return result;
}
std::expected<void,std::errc> PhysicalAccess::read(device::SprdDevice& dev,uint64_t offset,uint64_t size,
    const io::Writer& sink,std::stop_token stop) const {
    if(!connection_ || connection_!=dev.connection_token() || dev.link_dead() || dev.link_silent())
        return std::unexpected(std::errc::state_not_recoverable);
    if(offset>layout_.disk_bytes || size>layout_.disk_bytes-offset) return std::unexpected(std::errc::message_size);
    return dev.read_user_area(offset,size,sink,wide_,stop);
}
std::expected<std::vector<uint8_t>,std::errc> PhysicalAccess::read_small(device::SprdDevice& dev,
    uint64_t offset,size_t size,std::stop_token stop) const {
    if(size>16*1024*1024) return std::unexpected(std::errc::file_too_large);
    std::vector<uint8_t> result;
    result.reserve(size);
    auto got=read(dev,offset,size,[&](auto bytes,auto)->std::expected<void,std::errc> {
        if(bytes.size()>size-result.size()) return std::unexpected(std::errc::message_size);
        result.insert(result.end(),bytes.begin(),bytes.end()); return {};
    },stop);
    if(!got) return std::unexpected(got.error());
    if(result.size()!=size) return std::unexpected(std::errc::message_size);
    return result;
}
}

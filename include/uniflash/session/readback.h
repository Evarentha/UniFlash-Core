#pragma once
#include <uniflash/io/image.h>
#include <uniflash/session/physical_access.h>
namespace uniflash::session {
// One range comparison implementation for recovery, migration and PAC.
// Never repair/read named NV here: physical offsets retain disk semantics.
std::expected<void,std::errc> compare_physical(device::SprdDevice&,const PhysicalAccess&,
    uint64_t offset,const io::Image&,uint64_t length,std::stop_token = {},
    const io::PrepareObserver& = {},std::errc mismatch = std::errc::bad_message);
std::expected<void,std::errc> compare_named(device::SprdDevice&,const std::string&,
    const io::Image&,uint64_t length,std::stop_token = {},const io::PrepareObserver& = {});
}

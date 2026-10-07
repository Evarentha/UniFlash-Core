#pragma once
#include <uniflash/io/stream.h>
#include <uniflash/device/profile.h>
namespace uniflash::session {
// Validate byte-preserving ordinary/temporary-alias writes. Physical BTHD
// snapshots are opaque bytes; do not apply package payload/hash semantics.
std::expected<void,std::errc> validate_raw_replay(const io::Reader&,uint64_t size,
    const device::DeviceProfile&,std::stop_token = {});
}

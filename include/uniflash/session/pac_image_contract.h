#pragma once
#include <uniflash/io/image.h>
#include <uniflash/device/profile.h>
#include <string>
#include <vector>
namespace uniflash::session {
struct PacImageContract {
    uint64_t verify_size=0;
    std::vector<std::string> verify_targets;
};
bool mirrored_boot_target(std::string_view);
// Pure frozen-image/loader-policy preflight. No device commands. The signed
// loader's mirrors preserve the complete image; hashes do not authenticate it.
std::expected<PacImageContract,std::errc> prepare_pac_image_contract(
    const std::string& partition,const io::Image&,const device::DeviceProfile&,std::stop_token = {});
}

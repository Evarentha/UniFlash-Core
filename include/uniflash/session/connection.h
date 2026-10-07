#pragma once
#include <uniflash/device/sprd_device.h>
#include <uniflash/transport/usb.h>

namespace uniflash::session {
using AdoptDevice = std::expected<void, std::errc> (*)(device::SprdDevice&, std::stop_token);
class Connection {
public:
    static std::expected<device::SprdDevice, std::errc>
    open(const transport::UsbDevice&, std::stop_token = {}, device::DeviceProfile = {});
    static std::expected<device::SprdDevice, std::errc>
    reopen(std::span<const uint16_t> vendors, const std::vector<uint8_t>& identity,
           AdoptDevice, std::chrono::milliseconds timeout, std::stop_token = {}, device::DeviceProfile = {});
};
}

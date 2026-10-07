/*
 * UniFlash-Core / Device Connection
 *
 * Transport opening, handshake and device adoption.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#include <uniflash/session/connection.h>
#include <map>
#include <thread>
#include <condition_variable>
#include <mutex>
#include <uniflash/log.h>

namespace uniflash::session {
std::expected<device::SprdDevice, std::errc>
Connection::open(const transport::UsbDevice& candidate, std::stop_token stop, device::DeviceProfile profile) {
    auto opened = transport::UsbContext::instance().open_device(candidate, profile.reset_usb_configuration, profile.split_usb_packet);
    if (!opened) {
        if (log_diag_trace_enabled()) log_diag("{connect} open failed: " + std::make_error_code(opened.error()).message());
        return std::unexpected(opened.error());
    }
    if (log_performance_enabled()) {
        const char* speed = candidate.speed == transport::UsbDevice::Super ? "SuperSpeed" :
            candidate.speed == transport::UsbDevice::High ? "high-speed" :
            candidate.speed == transport::UsbDevice::Full ? "full-speed" : "unknown";
        log_diag("{usb} link=" + std::string(speed) + " out-maxpacket=" +
            std::to_string(opened->out_maxpacket()) + " B" +
            (opened->supports_raw_frames() ? " backend=USB" : " backend=COM (packet size estimated)"));
    }
    device::SprdDevice device(std::make_unique<transport::UsbTransport>(std::move(*opened)), profile);
    auto handshake = device.handshake(stop);
    if (!handshake) {
        if (log_diag_trace_enabled()) log_diag("{connect} BSL handshake failed: " + std::make_error_code(handshake.error()).message());
        return std::unexpected(handshake.error());
    }
    return device;
}

std::expected<device::SprdDevice, std::errc>
Connection::reopen(std::span<const uint16_t> vendors, const std::vector<uint8_t>& identity,
    AdoptDevice adopt, std::chrono::milliseconds timeout, std::stop_token stop, device::DeviceProfile profile) {
    if (identity.empty() || !adopt) return std::unexpected(std::errc::invalid_argument);
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::stop_source bounded;
    std::stop_callback cancelled(stop, [&] { bounded.request_stop(); });
    std::mutex mutex;
    std::condition_variable_any condition;
    std::jthread timer([&](std::stop_token shutdown) {
        std::unique_lock lock(mutex);
        condition.wait_until(lock, shutdown, deadline, [] { return false; });
        if (!shutdown.stop_requested()) bounded.request_stop();
    });
    std::map<std::string, std::chrono::steady_clock::time_point> retry;
    auto& context = transport::UsbContext::instance();
    while (std::chrono::steady_clock::now() < deadline) {
        if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
        auto devices = context.find_devices(vendors);
        if (!devices) return std::unexpected(devices.error());
        for (const auto& candidate : *devices) {
            if (candidate.port_path != identity) continue;
            const auto key = candidate.path_string() + candidate.port_name;
            if (std::chrono::steady_clock::now() < retry[key]) continue;
            auto opened = context.open_device(candidate, profile.reset_usb_configuration, profile.split_usb_packet);
            if (opened) {
                device::SprdDevice device(std::make_unique<transport::UsbTransport>(std::move(*opened)), profile);
                auto adopted = adopt(device, bounded.get_token());
                if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
                if (std::chrono::steady_clock::now() >= deadline) return std::unexpected(std::errc::timed_out);
                if (adopted) return device;
            }
            retry[key] = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return std::unexpected(std::errc::timed_out);
}
}

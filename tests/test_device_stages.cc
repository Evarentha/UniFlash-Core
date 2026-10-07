/*
 * UniFlash-Core Test / Device Stages
 *
 * Covers stage gating that runs before any transport access.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/device/sprd_device.h>
#include <uniflash/transport/usb.h>

#include <uniflash/log.h>
#include <stop_token>

namespace {

int failures = 0;

template <typename T>
void rejected(const std::expected<T, std::errc>& result, const char* operation) {
    // With no USB handle, an unguarded call would return no_such_device.
    // not_supported proves the stage gate ran before transport access.
    if (!result && result.error() == std::errc::not_supported) return;
    uniflash::log_err(std::string("FAIL: missing stage guard for ")+operation);
    ++failures;
}

}  // namespace

int main() {
    using namespace uniflash;
    device::SprdDevice dev{transport::UsbTransport{}};
    device::FlashPartition partition;
    partition.name = "test";

    rejected(dev.upload_fdl1({}, 0x100), "upload_fdl1");
    rejected(dev.upload_fdl2({}, 0x100), "upload_fdl2");
    rejected(dev.download_image({}, 0x100), "download_image");
    rejected(dev.download_image_add({}, 0x100), "download_image_add");
    rejected(dev.send_exec_raw({}), "send_exec_raw");
    rejected(dev.sprd4_enter_fdl2(), "sprd4_enter_fdl2");
    rejected(dev.write_partition(partition), "write_partition");
    rejected(dev.read_partition("test", 0, 1), "read_partition");
    rejected(dev.erase_partition("test", 0), "erase_partition");
    rejected(dev.list_partitions(), "list_partitions");
    rejected(dev.read_chip_info(), "read_chip_info");
    rejected(dev.repartition({}), "repartition");
    rejected(dev.reset(), "reset");
    rejected(dev.power_down(), "power_down");
    rejected(dev.write_datetime({}), "write_datetime");
    rejected(dev.end_process(), "end_process");
    rejected(dev.root_flag(), "root_flag");
    rejected(dev.enable_write_flash(), "enable_write_flash");
    rejected(dev.set_first_mode(0), "set_first_mode");
    rejected(dev.set_debuginfo("enable"), "set_debuginfo");
    rejected(dev.read_mcp_type(), "read_mcp_type");
    rejected(dev.read_flash_type(), "read_flash_type");
    rejected(dev.ddr_verify(), "ddr_verify");
    rejected(dev.ddr_sr_test(1), "ddr_sr_test");
    rejected(dev.check_nv_type(), "check_nv_type");
    rejected(dev.probe_hw_part_size("splloader"), "probe_hw_part_size");

    // Discovery is different from a stage-specific operation. A fresh
    // handle has no known stage; cancellation must reach the discovery
    // loop rather than failing an impossible "already FDL1/FDL2" gate.
    std::stop_source source;
    source.request_stop();
    const auto fdl1 = dev.handshake_fdl1(source.get_token());
    const auto fdl2 = dev.resync_fdl2(std::chrono::seconds(1), source.get_token());
    if (fdl1 || fdl1.error() != std::errc::interrupted ||
        fdl2 || fdl2.error() != std::errc::interrupted) {
        uniflash::log_err("FAIL: stage discovery must accept an unknown-stage handle");
        ++failures;
    }
    if (dev.info().stage != device::Stage::Offline) {
        uniflash::log_err("FAIL: rejected calls changed the device stage");
        ++failures;
    }
    if (failures) return 1;
    uniflash::log_info("Device stage guards passed without USB I/O");
    return 0;
}

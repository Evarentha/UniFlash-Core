/*
 * UniFlash-Core / Partition Access
 *
 * Named partition lookup, capacity discovery and bounded backup I/O.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <uniflash/session/operation_result.h>
#include <uniflash/device/sprd_device.h>
#include <filesystem>
namespace uniflash::session {
// Shared named-partition lookup, capacity discovery and bounded backup I/O.
// Plan services use this directly; Operations is only a public facade.
class PartitionAccess {
public:
    static OperationResult<device::PartitionInfo> find(
        std::span<const device::PartitionInfo>,const std::string&);
    static OperationResult<std::vector<device::PartitionInfo>> capacities(device::SprdDevice&,
        std::span<const std::string>,std::stop_token,const ProgressObserver&);
    static OperationResult<uint64_t> backup(device::SprdDevice&,const std::string&,uint64_t,
        const std::filesystem::path&,std::stop_token,const ProgressObserver&);
};
}

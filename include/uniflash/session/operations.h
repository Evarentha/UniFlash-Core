/*
 * UniFlash-Core / Operations Facade
 *
 * Public convenience entry points for preparation, persistence and writes.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <uniflash/session/flash_plan.h>

namespace uniflash::session {
struct DirectoryPrepareOptions {
    uint64_t max_encoded_file=64ull*1024*1024*1024;
    uint64_t max_encoded_total=256ull*1024*1024*1024;
};
// Public convenience facade. PAC stage services also work independently and
// own their phase, connection, persistence and execution checks.
class Operations {
public:
    static OperationResult<device::PartitionInfo> find_partition(
        std::span<const device::PartitionInfo>,const std::string& name);
    static OperationResult<FlashPlan> prepare_flash(const std::filesystem::path& xml,
        std::span<const device::PartitionInfo> capacities,std::stop_token = {},const ProgressObserver& = {});
    static OperationResult<FlashPlan> prepare_write(const std::string& partition,
        const std::filesystem::path& image,std::span<const device::PartitionInfo> capacities,
        std::stop_token = {},const ProgressObserver& = {});
    // Immediate-use capacities are bound to a connection generation for five
    // seconds. Retained plans re-query as needed; submitted plans are single-use.
    static OperationResult<FlashPlan> prepare_write(device::SprdDevice&,const std::string&,
        const std::filesystem::path&,std::stop_token = {},const ProgressObserver& = {});
    static OperationResult<FlashPlan> prepare_flash(device::SprdDevice&,
        const std::filesystem::path&,std::stop_token = {},const ProgressObserver& = {});
    static OperationResult<FlashPlan> prepare_directory(device::SprdDevice&,
        const std::filesystem::path&,std::stop_token = {},const ProgressObserver& = {});
    static OperationResult<FlashPlan> prepare_directory(device::SprdDevice&,
        const std::filesystem::path&,const DirectoryPrepareOptions&,std::stop_token = {},const ProgressObserver& = {});
    static OperationResult<FlashPlan> prepare_pac(device::SprdDevice&,
        const std::filesystem::path&,std::stop_token = {},const ProgressObserver& = {});
    // Named configuration entry points keep legacy brace-initialized stop and
    // progress arguments unambiguous for both paths and open archives.
    static OperationResult<FlashPlan> prepare_pac_with_options(device::SprdDevice&,
        const std::filesystem::path&,const PacPrepareOptions&,std::stop_token = {},const ProgressObserver& = {});
    static OperationResult<FlashPlan> prepare_pac(device::SprdDevice&,
        const PacArchive&,std::stop_token = {},const ProgressObserver& = {});
    static OperationResult<FlashPlan> prepare_pac_with_options(device::SprdDevice&,
        const PacArchive&,const PacPrepareOptions&,std::stop_token = {},const ProgressObserver& = {});
    static OperationResult<> save_pac_recovery(device::SprdDevice&,FlashPlan&,const std::filesystem::path&,
        std::stop_token = {},const ProgressObserver& = {});
    static OperationResult<> save_recovery(device::SprdDevice&,FlashPlan&,const std::filesystem::path&,
        std::stop_token = {},const ProgressObserver& = {});
    static OperationResult<OperationReport> execute(device::SprdDevice&,const FlashPlan&,
        std::stop_token = {},const ProgressObserver& = {},const EraseScopeFactory& = {});
    static OperationResult<uint64_t> backup(device::SprdDevice&,const std::string& partition,
        uint64_t size,const std::filesystem::path& destination,std::stop_token = {},const ProgressObserver& = {});
private:
    static OperationResult<FlashPlan> prepare_package(device::SprdDevice&,const PacArchive&,
        const PacPrepareOptions&,std::stop_token,const ProgressObserver&);
    static OperationResult<FlashPlan> prepare_parsed(const PacImage&,const std::filesystem::path& base,
        std::span<const device::PartitionInfo>,std::stop_token,const ProgressObserver&,
        const DirectoryPrepareOptions& = {});
};
}

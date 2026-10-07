/*
 * UniFlash-Core / PAC Services
 *
 * Compiled plans and the PAC execution service.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <uniflash/session/flash_plan.h>
#include <uniflash/session/pac_archive.h>
#include <map>
namespace uniflash::session {
// Immutable local compilation result. Device resolution cannot reopen paths
// or consume a different archive/options object after local validation.
class CompiledPac {
    friend class PacCompiler;
    friend class PacResolver;
    struct LocalImage { io::Image bytes; uint64_t expanded; };
    explicit CompiledPac(const PacArchive& archive):archive_(archive) {}
    PacArchive archive_;
    PacPrepareOptions options_;
    std::vector<PacAction> actions_;
    std::map<std::string,LocalImage> images_;
    std::map<std::string,uint32_t> nv_lengths_;
    std::vector<uint8_t> partition_table_;
    struct PhysicalImage { io::Image bytes; uint64_t verify_size=0;std::vector<std::string> verify_targets; };
    std::map<std::string,PhysicalImage> physical_images_;
    device::DeviceProfile profile_;
    device::SessionCapabilities capabilities_;
};
class PacCompiler {
public:
    static OperationResult<CompiledPac> compile(const PacArchive&,const PacPrepareOptions&,
        const device::DeviceProfile&,const device::SessionCapabilities&,std::stop_token = {},const ProgressObserver& = {});
private:
    static OperationResult<CompiledPac> compile_physical(const PacArchive&,const PacPrepareOptions&,
        const device::DeviceProfile&,const device::SessionCapabilities&,std::stop_token,const ProgressObserver&);
};
class PacResolver {
public:
    static OperationResult<FlashPlan> resolve(device::SprdDevice&,const CompiledPac&,
        std::stop_token = {},const ProgressObserver& = {});
private:
    static OperationResult<FlashPlan> resolve_physical(device::SprdDevice&,const CompiledPac&,
        std::stop_token,const ProgressObserver&);
};
class PacRecoveryStore {
public:
    static OperationResult<> save(device::SprdDevice&,FlashPlan&,const std::filesystem::path&,
        std::stop_token = {},const ProgressObserver& = {});
private:
    static OperationResult<> save_package(device::SprdDevice&,FlashPlan&,const std::filesystem::path&,
        std::stop_token,const ProgressObserver&);
};
class PlanExecutor {
public:
    static OperationResult<OperationReport> execute(device::SprdDevice&,const FlashPlan&,
        std::stop_token = {},const ProgressObserver& = {},const EraseScopeFactory& = {});
private:
    static OperationResult<OperationReport> run(device::SprdDevice&,const FlashPlan&,
        std::stop_token,const ProgressObserver&,const EraseScopeFactory&,OperationStep&);
};
}

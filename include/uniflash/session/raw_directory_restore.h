/*
 * UniFlash-Core / Raw Directory Restore
 *
 * Whole-directory restore from a complete committed manifest.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <uniflash/session/rename_write.h>
#include <uniflash/session/physical_access.h>
#include <uniflash/session/restore_manifest.h>
namespace uniflash::session {
class RawDirectoryPlan {
public:
    RawDirectoryPlan(RawDirectoryPlan&&) noexcept = default;
    RawDirectoryPlan& operator=(RawDirectoryPlan&&) noexcept = default;
    RawDirectoryPlan(const RawDirectoryPlan&) = delete;
    size_t count() const {return entries_.size();}
private:
    RawDirectoryPlan() = default;
    friend class RawDirectoryRestore;
    std::vector<RenameWritePlan> entries_;
    PhysicalAccess access_;
    std::filesystem::path source_, recovery_;
    bool saved_=false,save_attempted_=false,consumed_=false;
    uint64_t bytes_=0;
};
class RawDirectoryRestore {
public:
    // Only complete, matching GPT USER snapshots supported by prepare_raw.
    // Hardware areas and loader-transformed images reject the entire batch.
    static OperationResult<RawDirectoryPlan> prepare(device::SprdDevice&,const std::filesystem::path&,std::stop_token = {});
    static OperationResult<> save_recovery(device::SprdDevice&,RawDirectoryPlan&,const std::filesystem::path&,std::stop_token = {});
    // Cancellation is observed before and between alias transactions, and in
    // final aggregate verification. Each active transaction restores its GPT.
    static OperationResult<uint64_t> execute(device::SprdDevice&,RawDirectoryPlan&,std::stop_token = {},const ProgressObserver& = {});
};
}

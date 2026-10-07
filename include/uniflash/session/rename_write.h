/*
 * UniFlash-Core / Rename Write
 *
 * Temporary GPT alias writes with per-partition commit and recovery.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <uniflash/session/operation_result.h>
#include <uniflash/session/gpt.h>
#include <uniflash/device/sprd_device.h>
#include <uniflash/io/image.h>

namespace uniflash::session {
class RawDirectoryRestore;
class RenameWritePlan {
public:
    RenameWritePlan(RenameWritePlan&&) noexcept = default;
    RenameWritePlan& operator=(RenameWritePlan&&) noexcept = default;
    RenameWritePlan(const RenameWritePlan&) = delete;
    RenameWritePlan& operator=(const RenameWritePlan&) = delete;
    const std::string& temporary_partition() const { return temporary_name; }
private:
    friend class RenameWrite;
    friend class RawDirectoryRestore;
    RenameWritePlan(GptLayout layout, std::string name, std::string alias,
        std::vector<uint8_t> temporary, std::vector<uint8_t> restore, std::string xml,
        io::Image source, std::shared_ptr<const uint8_t> connection)
        : original(std::move(layout)), partition(std::move(name)), temporary_name(std::move(alias)),
          temporary_table(std::move(temporary)), restore_table(std::move(restore)),
          restore_xml(std::move(xml)), image(std::move(source)), connection_(std::move(connection)) {}
    GptLayout original;
    std::string partition, temporary_name;
    std::vector<uint8_t> temporary_table, restore_table;
    std::string restore_xml;
    io::Image image;
    std::shared_ptr<const uint8_t> connection_;
    mutable bool recovery_saved_ = false;
    mutable bool consumed_ = false;
    bool physical_snapshot_ = false;
    uint64_t physical_offset_ = 0;
    mutable std::filesystem::path recovery_directory_;
    mutable bool physical_backup_saved_ = false;
    mutable std::optional<io::Image> before_image_;
};
class RenameWrite {
public:
    static OperationResult<RenameWritePlan> prepare(device::SprdDevice&, const std::string&,
        const std::filesystem::path&, std::stop_token = {});
    // Exact partition bytes through a verified temporary GPT alias. Never
    // interpret sparse/NV headers or silently choose a paired NV source.
    static OperationResult<RenameWritePlan> prepare_raw(device::SprdDevice&,const std::string&,
        const std::filesystem::path&,std::stop_token = {});
    static OperationResult<RenameWritePlan> prepare_raw(device::SprdDevice&,const std::string&,
        io::Image frozen,std::stop_token = {});
    // Persist restoration inputs before the first device modification.
    static OperationResult<> save_recovery(const RenameWritePlan&, const std::filesystem::path&);
    static OperationResult<> save_raw_recovery(device::SprdDevice&,const RenameWritePlan&,
        const std::filesystem::path&,std::stop_token = {});
    // Always attempt restoration after a modification while the connection is
    // synchronized, including on cancellation or exceptions. Never retry a
    // timed-out transaction. Success includes a fresh geometry/name readback.
    static OperationResult<uint64_t> execute(device::SprdDevice&, const RenameWritePlan&,
        std::stop_token = {}, const io::TransferObserver& = {});
private:
    static OperationResult<RenameWritePlan> prepare_impl(device::SprdDevice&,const std::string&,
        const std::filesystem::path&,std::stop_token,bool,std::optional<io::Image> = {});
};
}

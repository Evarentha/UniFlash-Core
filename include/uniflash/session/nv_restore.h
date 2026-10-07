#pragma once
#include <uniflash/session/operation_result.h>
#include <uniflash/io/image.h>
#include <uniflash/session/physical_access.h>
#include <uniflash/session/nv_image.h>

namespace uniflash::session {
class NvRestorePlan {
public:
    NvRestorePlan(NvRestorePlan&&) noexcept = default;
    NvRestorePlan& operator=(NvRestorePlan&&) noexcept = default;
    NvRestorePlan(const NvRestorePlan&) = delete;
    const std::string& primary() const { return primary_; }
    uint64_t size() const { return payload_.size(); }
private:
    friend class NvRestore;
    NvRestorePlan() = default;
    std::string primary_, backup_;
    uint64_t primary_offset_=0, backup_offset_=0;
    std::vector<uint8_t> payload_, before_primary_, before_backup_, expected_;
    PhysicalAccess access_;
    std::shared_ptr<const uint8_t> connection_;
    bool persisted_=false, consumed_=false;
    std::filesystem::path recovery_directory_;
};
class NvRestore {
public:
    // Decode a frozen physical NV snapshot without device I/O. Used by batch
    // preflight so every source is checked before reading the current device.
    static OperationResult<std::vector<uint8_t>> decode_snapshot(const io::Image&,uint32_t,std::stop_token = {});
    static OperationResult<NvRestorePlan> prepare(device::SprdDevice&,const std::string&,
        const std::filesystem::path&,std::stop_token = {});
    static OperationResult<NvRestorePlan> prepare_payload(device::SprdDevice&,const std::string&,
        std::span<const uint8_t>,std::stop_token = {});
    static OperationResult<NvRestorePlan> prepare_merge(device::SprdDevice&,const std::string&,
        std::span<const uint8_t>,std::span<const NvMergeItem>,std::stop_token = {},
        NvByteOrder old_order = NvByteOrder::Little,NvByteOrder new_order = NvByteOrder::Little);
    static OperationResult<> save_recovery(NvRestorePlan&,const std::filesystem::path&);
    static OperationResult<> validate(device::SprdDevice&,const NvRestorePlan&,std::stop_token = {});
    static OperationResult<uint64_t> execute(device::SprdDevice&,NvRestorePlan&,std::stop_token = {},
        const io::TransferObserver& = {});
};
}

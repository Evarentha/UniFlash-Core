#pragma once
#include <uniflash/device/sprd_device.h>
#include <uniflash/io/image.h>
#include <uniflash/io/output.h>
#include <filesystem>
#include <uniflash/session/physical_access.h>
#include <string_view>
#include <uniflash/session/nv_image.h>
#include <uniflash/session/pac_parser.h>
#include <uniflash/session/gpt.h>
#include <uniflash/session/operation_kind.h>
#include <uniflash/session/operation_result.h>
#include <uniflash/session/device_error.h>

namespace uniflash::session {
class PacArchive;
class NvRestorePlan;
struct PacNvRepresentation {
    std::string partition;
    NvByteOrder device_order=NvByteOrder::Little;
    NvByteOrder template_order=NvByteOrder::Little;
    // Explicit logical NV_COMM read/write length established by the package
    // or product configuration. Zero uses Block/Size or an audited NV length;
    // it never infers logical length from the physical partition capacity.
    uint32_t logical_size=0;
    // Explicit product contract, independent of length/representation.
    // R27 named NV: 80-byte checksum-bearing START and loader-managed mirrors.
    bool r27_named_protocol=false;
};
struct PacPrepareOptions {
    // Optional host-managed preservation/physical verification workflow.
    // Ordinary PAC execution follows the package and uses named FDL commands.
    bool physical_recovery = false;
    // Host-established representations, never inferred from filenames/SoC.
    // Unspecified NV targets keep the original LE contract.
    std::vector<PacNvRepresentation> nv_representations;
    std::optional<device::AddressWordOrder> address_word_order;
    device::AuthResponder authentication;
    std::optional<uint32_t> factory_timestamp;
    bool factory_write_efuse=false;
    std::vector<uint8_t> vpac_utf16le;
    std::vector<uint8_t> softsim_expected_eid;
};

struct FlashEntry {
    std::string partition;
    OperationAction action;
    const WriteAction* write() const {return std::get_if<WriteAction>(&action);}
    const LogicalNvAction* logical_nv() const {return std::get_if<LogicalNvAction>(&action);}
    const PhysicalNvAction* physical_nv() const {return std::get_if<PhysicalNvAction>(&action);}
    bool erases() const {return std::holds_alternative<EraseAction>(action) || (write() && write()->erase_first);}
    const AddressTarget* address_target() const {
        return std::visit([](const auto& a)->const AddressTarget* {
            if constexpr(requires {a.address;})return a.address?&*a.address:nullptr;
            else return nullptr;
        },action);
    }
    std::span<const std::string> verification_targets() const {
        return write()?std::span<const std::string>(write()->verify_targets):std::span<const std::string>{};
    }
    bool valid_action() const {
        if(const auto* w=write())return w->image.size()!=0 && !(w->address && w->erase_first);
        if(const auto* nv=logical_nv())return !nv->payload.empty() && nv->payload.size()==nv->before.size();
        if(const auto* nv=physical_nv())return bool(nv->plan());
        if(const auto* r=std::get_if<ReadAction>(&action))return r->length!=0;
        if(const auto* c=std::get_if<CheckNvAction>(&action))return c->expected.size()>=8;
        if(const auto* c=std::get_if<ControlAction>(&action))return !control_name(*c).empty();
        return true;
    }
};
enum class PlanPhase { ResolvingInputs, ReadyToPersist, Persisting, ReadyToExecute, Validating, Submitted };
// Plans can only be built by validating preparation functions. Images own
// snapshots; path replacement cannot change the prepared bytes.
class FlashPlan {
public:
    FlashPlan(FlashPlan&&) noexcept = default;
    FlashPlan& operator=(FlashPlan&&) noexcept = default;
    FlashPlan(const FlashPlan&) = delete;
    FlashPlan& operator=(const FlashPlan&) = delete;
    const std::vector<FlashEntry>& entries() const { return entries_; }
    uint64_t bytes() const { return bytes_; }
    PlanPhase phase() const { return phase_; }
    bool requires_recovery() const {return pac_ || nv_batch_;}
private:
    FlashPlan() = default;
    friend class Operations;
    friend class PacResolver;
    friend class PacRecoveryStore;
    friend class PlanExecutor;
    std::vector<FlashEntry> entries_;
    mutable PlanPhase phase_=PlanPhase::ResolvingInputs;
    bool pac_ = false;
    bool nv_batch_ = false;
    bool package_execution_ = false;
    std::vector<device::PartitionInfo> backup_capacities_;
    std::vector<device::PartitionInfo> comparison_capacities_;
    uint64_t bytes_ = 0;
    std::shared_ptr<const uint8_t> layout_token_;
    std::vector<device::PartitionInfo> capacities_;
    std::chrono::steady_clock::time_point prepared_at_;
    std::optional<PhysicalAccess> physical_;
    std::vector<uint8_t> repartition_table_;
    std::optional<layout::GptLayout> expected_layout_;
    std::string recovery_layout_;
    std::shared_ptr<const uint8_t> connection_;
    std::filesystem::path journal_directory_;
    std::vector<std::string> backup_targets_;
    std::vector<layout::GptPartition> relocation_sources_;
    std::vector<FlashEntry> relocations_;
};

}

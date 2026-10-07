#pragma once
#include <uniflash/session/gpt.h>
#include <uniflash/session/operation_result.h>
#include <uniflash/device/sprd_device.h>

namespace uniflash::session {
enum class BackupRoute { UserArea, BootHardware };
struct BackupEntry {
    std::string name;
    uint64_t offset = 0, size = 0;
    BackupRoute route = BackupRoute::UserArea;
    std::string unavailable;
    std::string sha256{};
};
class RawBackupPlan {
public:
    const GptLayout& layout() const { return layout_; }
    const std::vector<BackupEntry>& entries() const { return entries_; }
    bool wide_verified() const { return wide_; }
    const std::string& limitation() const { return limitation_; }
private:
    friend class RawBackup;
    GptLayout layout_;
    std::vector<BackupEntry> entries_;
    std::shared_ptr<const uint8_t> token_;
    bool wide_ = false;
    std::string limitation_;
};
class RawBackup {
public:
    static OperationResult<GptLayout> read_layout(device::SprdDevice&, std::stop_token = {});
    static OperationResult<RawBackupPlan> discover(device::SprdDevice&, std::stop_token = {});
    static OperationResult<uint64_t> save(device::SprdDevice&, RawBackupPlan&, size_t entry,
        const std::filesystem::path&, std::stop_token = {}, const ProgressObserver& = {});
};
}

#pragma once
#include <uniflash/session/raw_backup.h>
#include <filesystem>

namespace uniflash::session {
struct BackupRecord {
    std::string file, status = "pending", reason;
    uint64_t actual = 0;
};
struct BackupIdentity { std::string stage, loader_version, chip_type; };
// On-disk batch evidence, shared by CLI and embedding clients. A bundle owns a
// fresh directory; failed files never fall back to an earlier backup generation.
class BackupBundle {
public:
    static OperationResult<BackupBundle> create(const std::filesystem::path&, const RawBackupPlan&,
        BackupIdentity = {});
    OperationResult<> checkpoint(const RawBackupPlan&, bool complete) const;
    std::vector<BackupRecord>& records() { return records_; }
    const std::filesystem::path& directory() const { return directory_; }
private:
    std::filesystem::path directory_;
    std::vector<BackupRecord> records_;
    BackupIdentity identity_;
};
}

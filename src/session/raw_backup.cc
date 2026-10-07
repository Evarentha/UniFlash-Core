#include <uniflash/session/raw_backup.h>
#include <uniflash/session/device_error.h>
#include <uniflash/session/sparse.h>
#include <uniflash/io/output.h>
#include <uniflash/io/buffered_output.h>
#include <uniflash/io/sha256.h>
#include <uniflash/platform.h>
#include <algorithm>
#include <uniflash/progress.h>

namespace uniflash::session {
namespace {
io::Reader physical_reader(device::SprdDevice& device, bool wide) {
    return [&device, wide](uint64_t offset, std::span<uint8_t> bytes, std::stop_token stop)
        -> std::expected<void, std::errc> {
        size_t done = 0;
        auto result = device.read_user_area(offset, bytes.size(),
            [&](std::span<const uint8_t> chunk, std::stop_token) -> std::expected<void, std::errc> {
                if (chunk.size() > bytes.size() - done) return std::unexpected(std::errc::message_size);
                std::copy(chunk.begin(), chunk.end(), bytes.begin() + done);
                done += chunk.size();
                return {};
            }, wide, stop);
        if (!result) return result;
        if (done != bytes.size()) return std::unexpected(std::errc::message_size);
        return {};
    };
}

}

OperationResult<GptLayout> RawBackup::read_layout(device::SprdDevice& device, std::stop_token stop) try {
    const auto storage = device.da_info().storage;
    if (device.da_info().valid && storage == 0x101)
        return std::unexpected(OperationError{OperationStep::Validate, std::errc::not_supported,
            "NAND has no supported USER-area GPT layout"});
    auto gpt = device.read_disk_layout(stop);
    if (!gpt) return std::unexpected(OperationError{OperationStep::Read, gpt.error(),
        "USER-area partition layout unavailable"});
    return std::move(*gpt);
} catch(...) {return std::unexpected(device_exception_error(device,OperationStep::Read));}

OperationResult<RawBackupPlan> RawBackup::discover(device::SprdDevice& device, std::stop_token stop) try {
    const auto storage = device.da_info().storage;
    auto gpt = read_layout(device, stop);
    if (!gpt) return std::unexpected(gpt.error());
    RawBackupPlan plan;
    plan.layout_ = std::move(*gpt);
    if (plan.layout_.mbr)
        plan.limitation_ = "MBR regions and EBR evidence only; total media capacity unavailable";
    plan.token_ = device.layout_token();
    // Verify wide offsets only when needed. An unsupported dialect must not
    // prevent backing up low-address NV partitions through the proven form.
    for (const auto& partition : plan.layout_.partitions) {
        BackupEntry entry{partition.name, partition.offset, partition.size, BackupRoute::UserArea, {}};
        plan.entries_.push_back(std::move(entry));
    }
    // UFS boot roles are exposed only for a verified firmware LU mapping.
    if (device.da_info().valid && (storage == 0x102 || (storage == 0x103 && device.profile().ufs_boot_roles))) {
        for (const char* name : {"splloader", "splloader_bak"}) {
            if (std::any_of(plan.entries_.begin(), plan.entries_.end(),
                [&](const auto& p) { return p.name == name; }))
                return std::unexpected(OperationError{OperationStep::Validate, std::errc::bad_message,
                    "ambiguous GPT and boot hardware partition name"});
            BackupEntry entry{name, 0, 0, BackupRoute::BootHardware, {}};
            auto size = device.probe_hw_part_size(name, stop);
            if (!size) {
                if (stop.stop_requested() || device.link_dead() || device.link_silent())
                    return std::unexpected(OperationError{OperationStep::Read, size.error(), name});
                entry.unavailable = "hardware partition capacity query failed";
            } else {
                entry.size = *size;
                if (entry.size > UINT32_MAX) entry.unavailable = "unsupported hardware partition read size";
            }
            plan.entries_.push_back(std::move(entry));
        }
    } else {
        if (!plan.limitation_.empty()) plan.limitation_ += "; ";
        plan.limitation_ += "USER-area GPT only; boot hardware areas not enumerated for UFS/unknown storage";
    }
    if(storage==0x103 && device.profile().ufs_boot_roles) {
        if(!plan.limitation_.empty()) plan.limitation_+="; ";
        plan.limitation_+="UFS USER and boot roles only; additional LUs/RPMB are not enumerated";
    }
    return plan;
} catch(...) {return std::unexpected(device_exception_error(device,OperationStep::Prepare));}

OperationResult<uint64_t> RawBackup::save(device::SprdDevice& device, RawBackupPlan& plan,
    size_t index, const std::filesystem::path& destination, std::stop_token stop, const ProgressObserver& progress) {
    OperationStep step=OperationStep::Validate;
    try {
    if (plan.token_ != device.layout_token() || device.link_dead() || device.link_silent())
        return std::unexpected(OperationError{OperationStep::Validate, std::errc::state_not_recoverable, "backup plan connection/layout changed"});
    if (index >= plan.entries_.size()) return std::unexpected(OperationError{OperationStep::Validate, std::errc::invalid_argument, "backup entry"});
    const auto& entry = plan.entries_[index];
    plan.entries_[index].sha256.clear();
    if (!entry.unavailable.empty() || !entry.size || entry.size>UINT64_MAX/8)
        return std::unexpected(OperationError{OperationStep::Validate, std::errc::not_supported, entry.unavailable});
    const bool needs_wide = entry.route == BackupRoute::UserArea &&
        (entry.offset > UINT32_MAX || entry.size > UINT32_MAX - entry.offset);
    if (needs_wide && !plan.wide_) {
        if (plan.layout_.mbr) return std::unexpected(OperationError{OperationStep::Validate, std::errc::not_supported,
            "MBR region needs 64-bit addressing; no backup GPT available to verify this loader's address dialect"});
        WaitProgress waiting("verifying 64-bit USER-area reads against backup GPT");
        // ACK alone is insufficient: detect loaders silently truncating u64.
        auto wide = physical_reader(device, true);
        std::vector<uint8_t> primary(plan.layout_.header.sector_size);
        auto probe = wide(plan.layout_.header.sector_size, primary, stop);
        if (probe && primary != plan.layout_.primary_sector) probe = std::unexpected(std::errc::bad_message);
        if (probe) probe = verify_backup_gpt(plan.layout_, wide, stop);
        if (!probe) return std::unexpected(OperationError{OperationStep::Validate, probe.error(),
            "64-bit USER-area offsets not verified against backup GPT; refusing truncated-address backup"});
        plan.wide_ = true;
    }
    step=OperationStep::Save;
    auto output = io::AtomicOutput::open(destination);
    if (!output) return std::unexpected(OperationError{OperationStep::Save, output.error(), platform::utf8_path(destination)});
    io::BufferedOutput buffered(*output);
    io::Sha256 hash;
    const io::Writer sink = [&](std::span<const uint8_t> bytes, std::stop_token token) {
        auto written = buffered.write(bytes, token);
        if(written) hash.update(bytes);
        if (written && progress) progress({OperationStep::Read, entry.name, buffered.accepted(), entry.size});
        return written;
    };
    step=OperationStep::Read;
    auto read = entry.route == BackupRoute::UserArea
        ? device.read_user_area(entry.offset, entry.size, sink,
            needs_wide, stop, entry.name)
        : device.read_partition_stream(entry.name, 0, entry.size, sink, stop);
    if (!read) return std::unexpected(device_operation_error(device,OperationStep::Read,read.error(),"raw read "+entry.name));
    step=OperationStep::Save;
    auto drained = buffered.finish(stop);
    if (!drained) return std::unexpected(OperationError{OperationStep::Save, drained.error(), entry.name});
    if (stop.stop_requested()) return std::unexpected(OperationError{OperationStep::Save, std::errc::interrupted, entry.name});
    if (output->size() != entry.size) return std::unexpected(OperationError{OperationStep::Read, std::errc::message_size, entry.name});
    // Allocate the digest text before the durable commit. An allocation
    // failure must not turn an already replaced image into an untracked save.
    auto digest=hash.hex();
    auto committed = output->commit();
    if (!committed) return std::unexpected(OperationError{OperationStep::Save, committed.error(), entry.name,
        output->commit_state(), output->commit_state() == io::CommitState::NotCommitted ? 0 : output->size()});
    plan.entries_[index].sha256=std::move(digest);
    return entry.size;
    } catch(...) {return std::unexpected(device_exception_error(device,step));}
}
}

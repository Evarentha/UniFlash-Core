/*
 * UniFlash-Core / Rename Write
 *
 * Temporary GPT alias writes with commit and GPT restoration.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/session/rename_write.h>
#include <uniflash/session/journal.h>
#include <uniflash/session/device_error.h>
#include <uniflash/session/pac_parser.h>
#include <uniflash/protocol/partition_name.h>
#include <uniflash/log.h>
#include <uniflash/session/physical_access.h>
#include <uniflash/io/buffered_output.h>
#include <uniflash/session/raw_image_contract.h>
#include <uniflash/session/readback.h>
#include <algorithm>
#include <array>

namespace uniflash::session {
namespace {
std::expected<GptLayout, std::errc> verified_layout(device::SprdDevice& dev, std::stop_token stop) {
    dev.invalidate_layout();
    auto layout = dev.read_disk_layout(stop);
    if (!layout) return layout;
    if (layout->mbr) return std::unexpected(std::errc::not_supported);
    const bool wide = layout->disk_bytes > UINT32_MAX;
    const io::Reader read = [&](uint64_t offset, std::span<uint8_t> bytes, std::stop_token token)
        -> std::expected<void, std::errc> {
        size_t done = 0;
        auto result = dev.read_user_area(offset, bytes.size(),
            [&](std::span<const uint8_t> chunk, std::stop_token) -> std::expected<void, std::errc> {
                if (chunk.size() > bytes.size() - done) return std::unexpected(std::errc::message_size);
                std::copy(chunk.begin(), chunk.end(), bytes.begin() + done); done += chunk.size(); return {};
            }, wide, token);
        if (!result) return result;
        if (done != bytes.size()) return std::unexpected(std::errc::message_size);
        return {};
    };
    if (wide) {
        std::vector<uint8_t> primary(layout->primary_sector.size());
        auto r = read(layout->header.sector_size, primary, stop);
        if (!r) return std::unexpected(r.error());
        if (primary != layout->primary_sector) return std::unexpected(std::errc::bad_message);
    }
    auto verified = verify_backup_gpt(*layout, read, stop);
    if (!verified) return std::unexpected(verified.error());
    return layout;
}
OperationError error(OperationStep step, std::errc code, std::string message) {
    return {step, code, std::move(message)};
}
bool same_geometry(const GptLayout& actual, const GptLayout& original,
                   const std::string& from = {}, const std::string& to = {}) {
    if (actual.mbr || actual.disk_bytes != original.disk_bytes ||
        actual.header.sector_size != original.header.sector_size ||
        actual.partitions.size() != original.partitions.size()) return false;
    for (const auto& p : original.partitions) {
        const auto& name = p.name == from ? to : p.name;
        const auto found = std::find_if(actual.partitions.begin(), actual.partitions.end(),
            [&](const auto& candidate) { return candidate.name == name; });
        if (found == actual.partitions.end() || found->offset != p.offset || found->size != p.size) return false;
    }
    return true;
}
}

OperationResult<RenameWritePlan> RenameWrite::prepare(device::SprdDevice& dev,
    const std::string& name, const std::filesystem::path& path, std::stop_token stop) {
    return prepare_impl(dev,name,path,stop,false);
}
OperationResult<RenameWritePlan> RenameWrite::prepare_raw(device::SprdDevice& dev,
    const std::string& name,const std::filesystem::path& path,std::stop_token stop) {
    return prepare_impl(dev,name,path,stop,true);
}
OperationResult<RenameWritePlan> RenameWrite::prepare_raw(device::SprdDevice& dev,
    const std::string& name,io::Image frozen,std::stop_token stop) {
    return prepare_impl(dev,name,{},stop,true,std::move(frozen));
}
OperationResult<RenameWritePlan> RenameWrite::prepare_impl(device::SprdDevice& dev,
    const std::string& name,const std::filesystem::path& path,std::stop_token stop,bool physical,std::optional<io::Image> frozen) try {
    if(physical && (!dev.profile().raw_partition_relocation || !dev.profile().legacy_gpt_rebuild))
        return std::unexpected(error(OperationStep::Validate,std::errc::not_supported,
            "physical restore needs a verified alias-write and GPT contract"));
    dev.invalidate_layout();
    auto layout = verified_layout(dev, stop);
    if (!layout) return std::unexpected(error(OperationStep::Read, layout.error(), "original GPT"));
    // This transaction rebuilds GPT through the inspected FDL format, not a
    // generic GPT editor. Reject layouts that this sequence cannot preserve.
    const auto& h = layout->header;
    if (layout->mbr || dev.da_info().storage != 0x102 || !dev.da_info().valid ||
        h.sector_size != 512 || h.entry_count != 128 || h.entry_size != 128 ||
        h.first_usable != 34 || h.last_usable != layout->disk_bytes / 512 - 34 ||
        layout->partitions.size() > 128 || layout->partitions.size() > dev.profile().gpt_max_entries)
        return std::unexpected(error(OperationStep::Validate, std::errc::not_supported,
            "temporary rename requires the inspected eMMC GPT geometry (512-byte sectors, 128 entries)"));
    auto found = std::find_if(layout->partitions.begin(), layout->partitions.end(),
        [&](const auto& p) { return p.name == name; });
    if (found == layout->partitions.end())
        return std::unexpected(error(OperationStep::Validate, std::errc::no_such_device, "partition '" + name + "' not found"));
    auto image = frozen ? std::expected<io::Image,std::errc>(std::move(*frozen)) :
        physical ? io::Image::prepare_blob(path,found->size,stop) : io::Image::prepare(path, found->size, stop);
    if (!image) return std::unexpected(error(OperationStep::Prepare, image.error(), name));
    if(physical) {
        if(image->size()!=found->size) return std::unexpected(error(OperationStep::Validate,std::errc::message_size,
            "physical snapshot must cover the exact partition size; header-stripped NV is not a physical snapshot"));
        auto replay=validate_raw_replay(image->reader(),image->size(),dev.profile(),stop);
        if(!replay) return std::unexpected(error(OperationStep::Validate,replay.error(),
            "physical snapshot lacks a byte-preserving alias contract: "+name));
    }
    if (image->size() > UINT32_MAX && !dev.profile().framed_write_u64 &&
        !(dev.profile().allow_whole_file_raw && dev.da_info().support_raw))
        return std::unexpected(error(OperationStep::Validate, std::errc::file_too_large, name));
    std::string alias;
    for (size_t i=1; i<=129; ++i) {
        alias = "uniflash_tmp_" + std::to_string(i);
        if (std::none_of(layout->partitions.begin(), layout->partitions.end(),
            [&](const auto& p) { return p.name == alias; })) break;
    }
    if(alias.size()>dev.profile().gpt_max_name)
        return std::unexpected(error(OperationStep::Validate,std::errc::not_supported,"temporary name exceeds GPT receiver contract"));
    auto ordered = layout->partitions;
    std::sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b) { return a.offset < b.offset; });
    PacImage config;
    config.legacy_gpt = true;
    config.sector_size = h.sector_size;
    config.disk_size = layout->disk_bytes;
    for (size_t i=0; i<ordered.size(); ++i) {
        const auto& p = ordered[i];
        if (!protocol::valid_partition_name(p.name) || p.name.size() > 30 || p.name.size()>dev.profile().gpt_max_name)
            return std::unexpected(error(OperationStep::Validate, std::errc::not_supported,
                "partition name cannot round-trip through the inspected FDL: " + p.name));
        PacPartition entry;
        entry.name = p.name; entry.size = p.size; entry.flash_addr = p.offset; entry.has_address = true;
        if (i+1 == ordered.size() && p.offset+p.size == (h.last_usable+1)*512)
            entry.size = UINT64_MAX;
        else if ((p.offset+p.size)/512 >= h.last_usable)
            return std::unexpected(error(OperationStep::Validate, std::errc::not_supported,
                "fixed partition endpoint cannot round-trip through the inspected FDL"));
        config.partitions.push_back(std::move(entry));
    }
    auto restore = PacParser::build_repartition_table(config);
    auto xml = make_layout_xml(*layout);
    if (!restore || !xml) return std::unexpected(error(OperationStep::Prepare,
        !restore ? restore.error() : xml.error(), "restore layout"));
    // Record the same wire dialect for manual recovery, rather than producing
    // a v1 XML that fails in the very loader this transaction targets.
    const auto root = xml->find("<rom ");
    if (root == std::string::npos)
        return std::unexpected(error(OperationStep::Prepare, std::errc::bad_message, "restore XML root"));
    xml->insert(root + 5, "repartition_format=\"legacy-gpt\" ");
    for (auto& p : config.partitions) if (p.name == name) p.name = alias;
    auto temporary = PacParser::build_repartition_table(config);
    if (!temporary) return std::unexpected(error(OperationStep::Prepare, temporary.error(), "temporary layout"));
    const auto offset=found->offset;
    RenameWritePlan plan{std::move(*layout), name, alias, std::move(*temporary),
        std::move(*restore), std::move(*xml), std::move(*image), dev.connection_token()};
    plan.physical_snapshot_=physical;plan.physical_offset_=offset;
    return plan;
} catch(...) {return std::unexpected(device_exception_error(dev,OperationStep::Prepare));}

OperationResult<> RenameWrite::save_recovery(const RenameWritePlan& plan, const std::filesystem::path& directory) try {
    if(plan.recovery_saved_ || plan.consumed_)
        return std::unexpected(error(OperationStep::Validate,std::errc::operation_not_permitted,"rename recovery already saved or plan consumed"));
    const auto save = [&](const char* name, std::span<const uint8_t> bytes) -> OperationResult<> {
        auto output = io::AtomicOutput::open(directory / name);
        if (!output) return std::unexpected(error(OperationStep::Save, output.error(), name));
        auto result = output->write(bytes);
        if (!result) return std::unexpected(error(OperationStep::Save, result.error(), name));
        return commit_output(*output,name);
    };
    auto result = save("original-gpt-header.bin", plan.original.primary_sector);
    if (result) result = save("original-gpt-entries.bin", plan.original.entries);
    if (result) result = save("restore-table.bin", plan.restore_table);
    if (result) result = save("restore-layout.xml", std::span(
        reinterpret_cast<const uint8_t*>(plan.restore_xml.data()), plan.restore_xml.size()));
    const std::string note = "Partition: " + plan.partition + "\nTemporary name: " + plan.temporary_name +
        "\nRecovery: reload FDL2, then repartition restore-layout.xml using its full path.\n"
        "Restores names and geometry, not original GPT GUIDs/attributes. Boot AVB is unchanged.\n"+
        (plan.physical_snapshot_?std::string("before-partition.bin contains the complete original region. Restoring GPT alone does not undo partition writes.\n"):std::string{});
    if (result) result = save("recovery.txt", std::span(reinterpret_cast<const uint8_t*>(note.data()), note.size()));
    if(result)result=Journal::seal_directory(directory);
    if (result) {plan.recovery_directory_=std::filesystem::absolute(directory);plan.recovery_saved_ = true;}
    return result;
} catch(...) {return std::unexpected(exception_error(OperationStep::Save));}

OperationResult<> RenameWrite::save_raw_recovery(device::SprdDevice& dev,const RenameWritePlan& plan,
    const std::filesystem::path& directory,std::stop_token stop) try {
    if(!plan.physical_snapshot_ || plan.connection_!=dev.connection_token() || plan.consumed_ || plan.recovery_saved_ || plan.physical_backup_saved_)
        return std::unexpected(error(OperationStep::Validate,std::errc::operation_not_permitted,"physical restore plan state"));
    std::error_code ec;
    if(!std::filesystem::is_empty(directory,ec) || ec)
        return std::unexpected(error(OperationStep::Save,ec?std::errc::io_error:std::errc::directory_not_empty,
            "physical restore recovery directory must be empty"));
    auto access=PhysicalAccess::open(dev,stop);
    if(!access) return std::unexpected(error(OperationStep::Read,access.error(),"physical restore pre-backup"));
    if(access->layout().primary_sector!=plan.original.primary_sector || access->layout().entries!=plan.original.entries)
        return std::unexpected(error(OperationStep::Validate,std::errc::state_not_recoverable,"GPT changed before physical pre-backup"));
    auto output=io::AtomicOutput::open(directory/"before-partition.bin");
    if(!output) return std::unexpected(error(OperationStep::Save,output.error(),"physical restore pre-backup"));
    io::BufferedOutput buffered(*output);
    auto read=access->read(dev,plan.physical_offset_,plan.image.size(),[&](auto bytes,auto token){return buffered.write(bytes,token);},stop);
    if(!read) return std::unexpected(error(OperationStep::Read,read.error(),"physical restore pre-backup"));
    auto r=buffered.finish(stop);
    if(!r) return std::unexpected(error(OperationStep::Save,r.error(),"physical restore pre-backup"));
    if(output->size()!=plan.image.size()) return std::unexpected(error(OperationStep::Save,std::errc::message_size,"physical restore pre-backup"));
    auto committed=commit_output(*output,"physical restore pre-backup");if(!committed)return committed;
    auto before=io::Image::prepare_blob(directory/"before-partition.bin",plan.image.size(),stop);
    if(!before || before->size()!=plan.image.size()) return std::unexpected(error(OperationStep::Save,
        before?std::errc::message_size:before.error(),"freeze physical restore pre-backup"));
    auto saved=save_recovery(plan,directory);
    if(!saved) return saved;
    const auto& h=access->layout().header;
    auto secondary=access->read_small(dev,h.alternate_lba*h.sector_size,h.sector_size,stop);
    if(!secondary) return std::unexpected(error(OperationStep::Read,secondary.error(),"original backup GPT"));
    auto parsed=parse_gpt_header(*secondary,h.sector_size,h.alternate_lba);
    if(!parsed || !matching_gpt_headers(h,*parsed))
        return std::unexpected(error(OperationStep::Validate,std::errc::bad_message,"original backup GPT changed"));
    auto entries=access->read_small(dev,parsed->entries_lba*h.sector_size,plan.original.entries.size(),stop);
    if(!entries || *entries!=plan.original.entries)
        return std::unexpected(error(OperationStep::Validate,entries?std::errc::bad_message:entries.error(),"original backup GPT entries changed"));
    const auto save=[&](const char* name,std::span<const uint8_t> bytes)->OperationResult<> {
        auto file=io::AtomicOutput::open(directory/name);
        if(!file) return std::unexpected(error(OperationStep::Save,file.error(),name));
        auto result=file->write(bytes,stop);
        if(!result) return std::unexpected(error(OperationStep::Save,result.error(),name));
        return commit_output(*file,name);
    };
    saved=save("original-backup-gpt-header.bin",*secondary);
    if(saved) saved=save("original-backup-gpt-entries.bin",*entries);
    if(!saved) return saved;
    plan.before_image_=std::move(*before);
    plan.physical_backup_saved_=true;
    return {};
} catch(...) {return std::unexpected(device_exception_error(dev,OperationStep::Save));}

OperationResult<uint64_t> RenameWrite::execute(device::SprdDevice& dev, const RenameWritePlan& plan,
    std::stop_token stop, const io::TransferObserver& progress) try {
    if (!plan.recovery_saved_ || plan.consumed_ || plan.connection_ != dev.connection_token())
        return std::unexpected(error(OperationStep::Validate, std::errc::operation_not_permitted,
            "rename plan requires saved recovery inputs and its original connection; plans are single-use"));
    if(plan.physical_snapshot_ && (!plan.physical_backup_saved_ || !plan.before_image_))
        return std::unexpected(error(OperationStep::Validate,std::errc::operation_not_permitted,"physical restore requires original bytes saved"));
    const auto record=[&](std::string_view text)->OperationResult<> {
        if(!plan.physical_snapshot_) return {};
        return Journal::attempt([&]{return Journal::write(plan.recovery_directory_/"execution.txt",text,"physical restore journal");});
    };
    const auto verify_bytes=[&](const io::Image& image,bool temporary)->OperationResult<> {
        auto access=PhysicalAccess::open(dev,{});
        if(!access) return std::unexpected(device_operation_error(dev,OperationStep::Validate,access.error(),"physical restore readback route"));
        if(!same_geometry(access->layout(),plan.original,temporary?plan.partition:std::string{},
            temporary?plan.temporary_name:std::string{}))
            return std::unexpected(error(OperationStep::Validate,std::errc::state_not_recoverable,"physical restore readback geometry changed"));
        auto checked=compare_physical(dev,*access,plan.physical_offset_,image,image.size());
        if(!checked) return std::unexpected(device_operation_error(dev,OperationStep::Validate,
            checked.error(),"physical restore bytes not verified"));
        return {};
    };
    auto current = verified_layout(dev, stop);
    if (!current) return std::unexpected(device_operation_error(dev,OperationStep::Read,current.error(),"recheck original GPT"));
    if (current->primary_sector != plan.original.primary_sector || current->entries != plan.original.entries)
        return std::unexpected(error(OperationStep::Validate, std::errc::state_not_recoverable, "GPT changed since preparation"));
    if(plan.physical_snapshot_) {
        auto before=verify_bytes(*plan.before_image_,false);
        if(!before) {
            auto detail=before.error();detail.target="device partition no longer matches saved pre-backup";
            return std::unexpected(std::move(detail));
        }
    }
    if (stop.stop_requested()) return std::unexpected(error(OperationStep::Prepare, std::errc::interrupted, "cancelled before rename"));
    if(auto logged=record("State: submitting temporary GPT; original bytes and GPT saved\n");!logged) return std::unexpected(logged.error());
    plan.consumed_ = true;
    OperationResult<> operation;
    OperationStep active_step=OperationStep::Write;
    const auto failed_cleanup=[&](OperationError cleanup)->OperationResult<uint64_t> {
        cleanup.session_synchronized=!dev.link_dead() && !dev.link_silent();
        auto failure=operation?cleanup:operation.error();
        if(!operation) {
            failure.cleanup_exchange=cleanup.exchange;
            failure.cleanup_failure=std::make_shared<OperationError>(std::move(cleanup));
            failure.session_synchronized=!dev.link_dead() && !dev.link_silent();
        }
        auto saved=record("State: failed; partition contents or GPT restoration unconfirmed\nInspect original failure and cleanup evidence; no replay\n");
        if(!saved)attach_journal_failure(failure,saved.error());
        return std::unexpected(std::move(failure));
    };
    try {
        log_status(LogLevel::Info, "rename", plan.partition + " -> " + plan.temporary_name);
        log_status(LogLevel::Info, "repartition format", "legacy GPT v0 (sequential MiB)");
        auto changed = dev.repartition(plan.temporary_table, {}, true, plan.original.header.sector_size, plan.original.disk_bytes);
        if (!changed) operation = std::unexpected(device_operation_error(dev,OperationStep::Write, changed.error(), "temporary repartition"));
        else {
            active_step=OperationStep::Validate;
            auto readback = verified_layout(dev, {});
            if (!readback || !same_geometry(*readback, plan.original, plan.partition, plan.temporary_name))
                operation = std::unexpected(device_operation_error(dev,OperationStep::Validate,
                    readback ? std::errc::bad_message : readback.error(), "temporary layout readback"));
            else {
                log_status(LogLevel::Info, "write", plan.temporary_name);
                active_step=OperationStep::Save;
                operation=record("State: temporary GPT verified; partition write about to submit\n");
                if(operation) {
                    active_step=OperationStep::Write;
                    auto written = dev.write_partition_stream(plan.temporary_name, plan.image.size(), plan.image.reader(), stop, progress);
                    if (!written) {
                        auto failure=device_operation_error(dev,OperationStep::Write,written.error(),"image write");
                        if(dev.write_timings().raw_recovery_attempted)failure.initial_raw_failure=dev.write_timings().raw_failure;
                        operation=std::unexpected(std::move(failure));
                    }
                    else if(plan.physical_snapshot_) {active_step=OperationStep::Validate;operation=verify_bytes(plan.image,true);}
                }
            }
        }
    } catch (...) {
        operation = std::unexpected(device_exception_error(dev,active_step));
    }
    if (dev.link_dead() || dev.link_silent()) {
        return failed_cleanup(device_operation_error(dev,OperationStep::Finish,std::errc::state_not_recoverable,
            "connection lost; layout restoration unconfirmed, use saved restore-layout.xml"));
    }
    try {
        dev.invalidate_layout();
        auto check = verified_layout(dev, {});
        bool restored_layout = false;
        // A rejected repartition may have left the original table intact.
        if (!check || !same_geometry(*check, plan.original)) {
            if (dev.link_dead() || dev.link_silent())
                return failed_cleanup(device_operation_error(dev,OperationStep::Finish,std::errc::state_not_recoverable,"layout restoration unconfirmed"));
            log_status(LogLevel::Info, "restore layout", plan.partition);
            auto restored = dev.repartition(plan.restore_table, {}, true, plan.original.header.sector_size, plan.original.disk_bytes);
            if (!restored) {
                return failed_cleanup(device_operation_error(dev,OperationStep::Finish,restored.error(),"layout restoration failed"));
            }
            check = verified_layout(dev, {});
            if (!check || !same_geometry(*check, plan.original))
                return failed_cleanup(device_operation_error(dev,OperationStep::Finish,
                    check?std::errc::bad_message:check.error(),"restored layout readback failed"));
            restored_layout = true;
        }
        log_status(LogLevel::Info, restored_layout ? "layout restored" : "layout verified",
            "primary and backup GPT, original names and geometry verified");
    } catch (...) {
        return failed_cleanup(device_exception_error(dev,OperationStep::Finish));
    }
    if (!operation) {
        operation.error().session_synchronized=!dev.link_dead() && !dev.link_silent();
        operation.error().cleanup_exchange=dev.last_exchange();
        auto saved=record("State: failed; partition contents unconfirmed; original GPT names/geometry restored\n");
        if(!saved)attach_journal_failure(operation.error(),saved.error());
        return std::unexpected(operation.error());
    }
    if(plan.physical_snapshot_) {
        auto verified=verify_bytes(plan.image,false);
        if(!verified) {
            auto saved=record("State: GPT restored; final physical byte verification failed\n");
            if(!saved)attach_journal_failure(verified.error(),saved.error());
            return std::unexpected(verified.error());
        }
        auto logged=record("State: completed; full partition bytes verified after original names/geometry restored\nGPT GUIDs/attributes may differ\n");
        if(!logged) return std::unexpected(logged.error());
    }
    return plan.image.size();
} catch(...) {return std::unexpected(device_exception_error(dev,OperationStep::Validate));}
}

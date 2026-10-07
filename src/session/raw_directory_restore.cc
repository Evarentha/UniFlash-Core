#include <uniflash/session/raw_directory_restore.h>
#include <uniflash/session/journal.h>
#include <uniflash/session/device_error.h>
#include <uniflash/session/pac_layout.h>
#include <uniflash/platform.h>
#include <uniflash/io/sha256.h>
#include <uniflash/session/readback.h>
#include <uniflash/session/raw_image_contract.h>
#include <algorithm>
#include <set>

namespace uniflash::session {
namespace {
OperationError error(OperationStep step,std::errc code,std::string target) {return {step,code,std::move(target)};}
OperationResult<> journal(const std::filesystem::path& directory,const std::string& text) {
    return Journal::write(directory/"directory-execution.txt",text,"directory restore journal");
}
bool within(const std::filesystem::path& path,const std::filesystem::path& parent) {
    // Filesystem identity handles Windows case-insensitive paths and alternate
    // spellings; lexical prefix checks alone do not protect source directories.
    for(auto current=path;!current.empty();) {
        std::error_code ec;
        if(std::filesystem::equivalent(current,parent,ec) && !ec) return true;
        const auto up=current.parent_path();if(up==current) break;current=up;
    }
    return false;
}
}
OperationResult<RawDirectoryPlan> RawDirectoryRestore::prepare(device::SprdDevice& dev,
    const std::filesystem::path& directory,std::stop_token stop) try {
    auto manifest=read_restore_manifest(directory/"manifest.json");
    if(!manifest) return std::unexpected(error(OperationStep::Validate,manifest.error(),
        "raw restore requires a complete v1/v2/v3 manifest; no inference from loose files"));
    std::error_code ec;
    const auto root=std::filesystem::canonical(directory,ec);
    if(ec) return std::unexpected(error(OperationStep::Prepare,std::errc::io_error,"backup directory"));
    // Resolve all file paths and sizes before the first device request.
    std::vector<io::Image> images;
    for(const auto& entry:manifest->entries) {
        if(stop.stop_requested()) return std::unexpected(error(OperationStep::Prepare,std::errc::interrupted,entry.name));
        auto path=std::filesystem::canonical(root/platform::path(entry.file),ec);
        if(ec || !within(path,root) || !std::filesystem::is_regular_file(path,ec) || ec)
            return std::unexpected(error(OperationStep::Prepare,std::errc::invalid_argument,"snapshot path outside backup or unavailable: "+entry.file));
        if(std::filesystem::file_size(path,ec)!=entry.size || ec)
            return std::unexpected(error(OperationStep::Validate,std::errc::message_size,"snapshot length: "+entry.name));
        if(entry.source!="user_partition") return std::unexpected(error(OperationStep::Validate,std::errc::not_supported,
            "whole batch rejected: no byte-preserving hardware-region writer for "+entry.name));
        auto frozen=io::Image::prepare_blob(path,entry.size,stop);
        if(!frozen || frozen->size()!=entry.size) return std::unexpected(error(OperationStep::Prepare,
            frozen?std::errc::message_size:frozen.error(),"snapshot freeze: "+entry.name));
        if(!entry.sha256.empty()) {
            auto hash=io::sha256(frozen->reader(),frozen->size(),stop);
            if(!hash || *hash!=entry.sha256) return std::unexpected(error(OperationStep::Validate,
                hash?std::errc::bad_message:hash.error(),"snapshot SHA-256 mismatch: "+entry.name));
        }
        auto replay=validate_raw_replay(frozen->reader(),frozen->size(),dev.profile(),stop);
        if(!replay) return std::unexpected(error(OperationStep::Validate,replay.error(),"snapshot alias contract: "+entry.name));
        images.push_back(std::move(*frozen));
    }
    // Saved GPT is evidence about the backup, not the current device. Compare
    // the manifest with its own CRC-verified header/table before trusting offsets.
    auto header_path=std::filesystem::canonical(root/"gpt-primary-header.bin",ec);
    if(ec || !within(header_path,root)) return std::unexpected(error(OperationStep::Validate,
        std::errc::invalid_argument,"backup GPT header path"));
    auto table_path=std::filesystem::canonical(root/"gpt-entries.bin",ec);
    if(ec || !within(table_path,root)) return std::unexpected(error(OperationStep::Validate,
        std::errc::invalid_argument,"backup GPT entries path"));
    auto header=io::Image::prepare_blob(header_path,4096,stop);
    auto table=io::Image::prepare_blob(table_path,16*1024*1024,stop);
    if(!header || !table || header->size()!=manifest->sector_size)
        return std::unexpected(error(OperationStep::Validate,std::errc::bad_message,"backup GPT evidence missing"));
    if(!manifest->header_sha256.empty()) {
        auto header_hash=io::sha256(header->reader(),header->size(),stop);
        auto table_hash=io::sha256(table->reader(),table->size(),stop);
        if(!header_hash || !table_hash) return std::unexpected(error(OperationStep::Read,
            !header_hash?header_hash.error():table_hash.error(),"backup GPT digest read"));
        if(*header_hash!=manifest->header_sha256 || *table_hash!=manifest->entries_sha256)
            return std::unexpected(error(OperationStep::Validate,std::errc::bad_message,"backup GPT SHA-256 mismatch"));
    }
    std::vector<uint8_t> sector(manifest->sector_size);
    auto got=header->reader()(0,sector,stop);
    if(!got) return std::unexpected(error(OperationStep::Read,got.error(),"backup GPT header"));
    auto saved_header=layout::parse_gpt_header(sector,manifest->sector_size,1);
    if(!saved_header || (saved_header->alternate_lba+1)*manifest->sector_size!=manifest->disk_bytes ||
        uint64_t(saved_header->entry_count)*saved_header->entry_size!=table->size())
        return std::unexpected(error(OperationStep::Validate,std::errc::bad_message,"backup GPT header geometry"));
    const io::Reader evidence=[&](uint64_t at,std::span<uint8_t> bytes,std::stop_token token)->std::expected<void,std::errc>{
        std::fill(bytes.begin(),bytes.end(),0);
        const auto overlay=[&](uint64_t begin,const io::Image& source)->std::expected<void,std::errc>{
            const auto left=std::max(at,begin),right=std::min(at+bytes.size(),begin+source.size());
            if(left>=right) return {};
            return source.reader()(left-begin,bytes.subspan(left-at,right-left),token);
        };
        auto r=overlay(manifest->sector_size,*header);if(!r) return r;
        return overlay(saved_header->entries_lba*manifest->sector_size,*table);
    };
    auto saved_layout=layout::read_primary_gpt(evidence,stop);
    if(!saved_layout || saved_layout->disk_bytes!=manifest->disk_bytes || saved_layout->partitions.size()!=manifest->entries.size())
        return std::unexpected(error(OperationStep::Validate,std::errc::bad_message,"backup GPT/manifest geometry mismatch"));
    for(const auto& entry:manifest->entries) {
        if(std::none_of(saved_layout->partitions.begin(),saved_layout->partitions.end(),[&](const auto& p){
            return p.name==entry.name && p.offset==entry.offset && p.size==entry.size;
        })) return std::unexpected(error(OperationStep::Validate,std::errc::state_not_recoverable,"backup/device geometry: "+entry.name));
    }
    auto access=PhysicalAccess::open(dev,stop);
    if(!access)return std::unexpected(error(OperationStep::Read,access.error(),"restore GPT evidence"));
    if(!same_partition_geometry(*saved_layout,access->layout()))return std::unexpected(error(OperationStep::Validate,
        std::errc::state_not_recoverable,"backup and device geometry differs"));
    RawDirectoryPlan plan;plan.source_=root;plan.access_=std::move(*access);
    for(size_t i=0;i<manifest->entries.size();++i) {
        auto entry=RenameWrite::prepare_raw(dev,manifest->entries[i].name,std::move(images[i]),stop);
        if(!entry) return std::unexpected(entry.error());
        if(entry->original.primary_sector!=plan.access_.layout().primary_sector || entry->original.entries!=plan.access_.layout().entries)
            return std::unexpected(error(OperationStep::Validate,std::errc::state_not_recoverable,"GPT changed during directory preparation"));
        plan.entries_.push_back(std::move(*entry));
        plan.bytes_+=manifest->entries[i].size; // total overflow checked by manifest parser
    }
    return plan;
} catch(...) {return std::unexpected(device_exception_error(dev,OperationStep::Prepare));}
OperationResult<> RawDirectoryRestore::save_recovery(device::SprdDevice& dev,RawDirectoryPlan& plan,
    const std::filesystem::path& directory,std::stop_token stop) try {
    if(plan.save_attempted_ || plan.consumed_) return std::unexpected(error(OperationStep::Validate,
        std::errc::operation_not_permitted,"directory restore recovery already attempted"));
    plan.save_attempted_=true;
    std::error_code ec;
    const auto parent=std::filesystem::canonical(directory.has_parent_path()?directory.parent_path():std::filesystem::path("."),ec);
    if(ec || within(parent,plan.source_)) return std::unexpected(error(OperationStep::Save,std::errc::invalid_argument,
        "recovery directory must be outside the source backup"));
    if(!std::filesystem::create_directory(directory,ec)) return std::unexpected(error(OperationStep::Save,
        ec?std::errc::io_error:std::errc::file_exists,"new directory restore recovery"));
    plan.recovery_=std::filesystem::canonical(directory);
    if(within(plan.recovery_,plan.source_)) return std::unexpected(error(OperationStep::Save,
        std::errc::invalid_argument,"resolved recovery path is inside source backup"));
    auto r=journal(plan.recovery_,"State: preparing original-data backups; no device writes submitted\n");
    if(!r) return r;
    std::string listing="Directory raw restore order; all source snapshots frozen\n";
    for(size_t i=0;i<plan.entries_.size();++i) listing+=std::to_string(i+1)+". "+plan.entries_[i].partition+
        " offset="+std::to_string(plan.entries_[i].physical_offset_)+" bytes="+std::to_string(plan.entries_[i].image.size())+
        " recovery="+std::to_string(i+1)+"/\n";
    auto plan_file=io::AtomicOutput::open(plan.recovery_/"plan.txt");
    if(!plan_file) return std::unexpected(error(OperationStep::Save,plan_file.error(),"directory restore plan"));
    auto wrote=plan_file->write(std::span(reinterpret_cast<const uint8_t*>(listing.data()),listing.size()),stop);
    if(!wrote) return std::unexpected(error(OperationStep::Save,wrote.error(),"directory restore plan"));
    auto committed=commit_output(*plan_file,"directory restore plan");if(!committed)return committed;
    for(size_t i=0;i<plan.entries_.size();++i) {
        const auto sub=plan.recovery_/std::to_string(i+1);
        if(!std::filesystem::create_directory(sub,ec)) return std::unexpected(error(OperationStep::Save,std::errc::io_error,"partition recovery directory"));
        r=RenameWrite::save_raw_recovery(dev,plan.entries_[i],sub,stop);
        if(!r) return r;
    }
    r=journal(plan.recovery_,"State: prepared; every source frozen and every original partition saved\nGPT GUIDs/attributes may change during restore\n");
    if(r)r=Journal::seal_directory(plan.recovery_);
    if(r) plan.saved_=true;
    return r;
} catch(...) {return std::unexpected(device_exception_error(dev,OperationStep::Save));}
OperationResult<uint64_t> RawDirectoryRestore::execute(device::SprdDevice& dev,RawDirectoryPlan& plan,
    std::stop_token stop,const ProgressObserver& progress) try {
    if(!plan.saved_ || plan.consumed_ || plan.entries_.empty()) return std::unexpected(error(OperationStep::Validate,
        std::errc::operation_not_permitted,"directory restore plan not executable"));
    if(plan.entries_.front().connection_!=dev.connection_token())
        return std::unexpected(error(OperationStep::Validate,std::errc::state_not_recoverable,"directory restore connection changed"));
    auto initial=PhysicalAccess::open(dev,stop);
    if(!initial || initial->layout().primary_sector!=plan.access_.layout().primary_sector ||
        initial->layout().entries!=plan.access_.layout().entries)
        return std::unexpected(device_operation_error(dev,OperationStep::Validate,initial?std::errc::state_not_recoverable:initial.error(),"directory restore initial GPT changed"));
    // Validate ALL originals before modifying ANY of them. Each partition
    // transaction repeats its own check at the actual submission boundary.
    for(const auto& entry:plan.entries_) {
        if(entry.connection_!=dev.connection_token() || !entry.before_image_)
            return std::unexpected(error(OperationStep::Validate,std::errc::state_not_recoverable,"directory restore connection changed"));
        auto matched=compare_physical(dev,plan.access_,entry.physical_offset_,*entry.before_image_,entry.image.size(),
            stop,{},std::errc::state_not_recoverable);
        if(!matched) return std::unexpected(device_operation_error(dev,OperationStep::Validate,
            matched.error(),"original partition changed: "+entry.partition));
    }
    if(stop.stop_requested()) return std::unexpected(error(OperationStep::Write,std::errc::interrupted,"directory restore cancelled"));
    plan.consumed_=true;uint64_t total=0;
    OperationStep step=OperationStep::Validate;
    const auto run=[&]()->OperationResult<uint64_t> {
    std::optional<layout::GptLayout> previous;
    for(size_t i=0;i<plan.entries_.size();++i) {
        auto& entry=plan.entries_[i];
        // Each alias transaction must restore its GPT names. Cancellation is
        // honored between transactions, before starting another partition.
        if(stop.stop_requested()) return std::unexpected(error(OperationStep::Write,std::errc::interrupted,
            "directory restore cancelled at partition boundary"));
        auto fresh=PhysicalAccess::open(dev,{});
        if(!fresh) return std::unexpected(error(OperationStep::Validate,fresh.error(),"directory restore GPT readback"));
        const auto& evidence=previous?*previous:plan.access_.layout();
        if(fresh->layout().primary_sector!=evidence.primary_sector || fresh->layout().entries!=evidence.entries ||
            !same_partition_geometry(fresh->layout(),plan.access_.layout()))
            return std::unexpected(error(OperationStep::Validate,std::errc::state_not_recoverable,"unexpected GPT change between restore steps"));
        // Earlier transactions can regenerate GUIDs. Only this owning batch
        // rebinds the next immutable plan to its verified restored GPT bytes.
        entry.original=fresh->layout();
        step=OperationStep::Save;
        auto logged=journal(plan.recovery_,"State: executing\nStep: "+std::to_string(i+1)+"/"+std::to_string(plan.entries_.size())+
            "\nTarget: "+entry.partition+"\nCompleted bytes: "+std::to_string(total)+"\n");
        if(!logged) return std::unexpected(logged.error());
        step=OperationStep::Write;
        auto result=RenameWrite::execute(dev,entry,{},[&](const io::TransferProgress& event){
            if(progress) progress({OperationStep::Write,entry.partition,total+event.completed,plan.bytes_,"transfer",event.completed,event.total,event.seconds});
        });
        if(!result) {
            return std::unexpected(result.error());
        }
        total+=*result;
        step=OperationStep::Validate;
        auto after=PhysicalAccess::open(dev,{});
        if(!after || !same_partition_geometry(after->layout(),plan.access_.layout()))
            return std::unexpected(error(OperationStep::Validate,after?std::errc::bad_message:after.error(),"directory restored GPT"));
        previous=after->layout();
    }
    // Verify the final aggregate state too, not only each intermediate write.
    auto final_access=PhysicalAccess::open(dev,stop);
    if(!final_access || !previous || final_access->layout().primary_sector!=previous->primary_sector ||
        final_access->layout().entries!=previous->entries)
        return std::unexpected(error(OperationStep::Validate,final_access?std::errc::bad_message:final_access.error(),"final directory GPT evidence"));
    for(const auto& entry:plan.entries_) {
        auto verified=compare_physical(dev,*final_access,entry.physical_offset_,entry.image,entry.image.size(),stop,
            [&](const io::PrepareProgress& event) {
                if(progress) progress({OperationStep::Validate,entry.partition,event.completed,event.total,"physical readback"});
            });
        if(!verified) return std::unexpected(device_operation_error(dev,OperationStep::Validate,
            verified.error(),"final directory byte verification: "+entry.partition));
    }
    step=OperationStep::Save;
    auto logged=journal(plan.recovery_,"State: completed\nAll listed GPT partition bytes verified\nBytes: "+std::to_string(total)+
        "\nGPT GUIDs/attributes are not a byte-identical restoration\n");
    if(!logged) return std::unexpected(logged.error());
    return total;
    };
    OperationResult<uint64_t> result;
    try {result=run();}
    catch(...) {result=std::unexpected(device_exception_error(dev,step));}
    if(!result) {
        auto saved=Journal::attempt([&]{return journal(plan.recovery_,"State: failed\nCompleted bytes: "+std::to_string(total)+
        "\nError: "+result.error().target+"\nCode: "+std::make_error_code(result.error().code).message()+
        "\nInspect individual step execution.txt files; no automatic replay\n");});
        if(!saved)attach_journal_failure(result.error(),saved.error());
        result.error().session_synchronized=!dev.link_dead() && !dev.link_silent();
    }
    return result;
} catch(...) {return std::unexpected(device_exception_error(dev,OperationStep::Validate));}
}

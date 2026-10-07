/*
 * UniFlash-Core / NV Restore
 *
 * Snapshot, header regeneration, update and verified readback.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/session/nv_restore.h>
#include <uniflash/session/journal.h>
#include <uniflash/session/device_error.h>
#include <uniflash/platform.h>
#include <algorithm>

namespace uniflash::session {
namespace {
OperationError error(OperationStep step,std::errc code,std::string text) { return {step,code,std::move(text)}; }
}
OperationResult<NvRestorePlan> NvRestore::prepare(device::SprdDevice& dev,const std::string& name,
    const std::filesystem::path& path,std::stop_token stop) try {
    const uint32_t size=device::nv_payload_size(dev.profile().nv_dialect);
    if(!size) return std::unexpected(error(OperationStep::Validate,std::errc::not_supported,"NV loader contract unavailable"));
    auto image=io::Image::prepare_blob(path,16*1024*1024,stop);
    if(!image) return std::unexpected(error(OperationStep::Prepare,image.error(),"NV physical snapshot"));
    auto decoded=decode_snapshot(*image,size,stop);
    if(!decoded)return std::unexpected(decoded.error());
    return prepare_payload(dev,name,*decoded,stop);
} catch(...) {return std::unexpected(device_exception_error(dev,OperationStep::Prepare));}
OperationResult<std::vector<uint8_t>> NvRestore::decode_snapshot(const io::Image& image,uint32_t size,std::stop_token stop) try {
    if(!size || size>16*1024*1024 || image.size()>16*1024*1024)
        return std::unexpected(error(OperationStep::Validate,std::errc::not_supported,"NV loader/size contract"));
    if(image.size()<uint64_t(size)+512) return std::unexpected(error(OperationStep::Validate,
        std::errc::message_size,"NV restore expects a physical snapshot including the 512-byte header"));
    std::vector<uint8_t> bytes(size+512);
    auto got=image.reader()(0,bytes,stop);
    if(!got) return std::unexpected(error(OperationStep::Prepare,got.error(),"NV snapshot"));
    if(std::all_of(bytes.begin(),bytes.end(),[](uint8_t byte){return byte==0;}) ||
        std::all_of(bytes.begin(),bytes.end(),[](uint8_t byte){return byte==0xff;}))
        return std::unexpected(error(OperationStep::Validate,std::errc::bad_message,
            "NV snapshot is blank; no valid header or calibration payload to restore"));
    auto decoded=nv_decode_physical(bytes,size);
    if(!decoded) return std::unexpected(error(OperationStep::Validate,decoded.error(),"NV header/length/checksum"));
    return std::move(*decoded);
} catch(...) {return std::unexpected(exception_error(OperationStep::Prepare));}
OperationResult<NvRestorePlan> NvRestore::prepare_payload(device::SprdDevice& dev,const std::string& name,
    std::span<const uint8_t> payload,std::stop_token stop) try {
    const auto* pair=device::nv_pair(name);
    const auto size=device::nv_payload_size(dev.profile().nv_dialect);
    if(!pair || pair->primary!=name || !size || payload.size()!=size)
        return std::unexpected(error(OperationStep::Validate,std::errc::not_supported,"NV primary/loader/length contract"));
    if(stop.stop_requested()) return std::unexpected(error(OperationStep::Prepare,std::errc::interrupted,"NV cancelled"));
    // Freeze caller data before any I/O or progress callbacks can run.
    std::vector<uint8_t> frozen(payload.begin(),payload.end());
    auto access=PhysicalAccess::open(dev,stop);
    if(!access) return std::unexpected(device_operation_error(dev,OperationStep::Read,access.error(),"NV physical verification route"));
    NvRestorePlan plan;
    plan.primary_=pair->primary; plan.backup_=pair->backup; plan.access_=std::move(*access);
    const auto& parts=plan.access_.layout().partitions;
    const auto find=[&](const std::string& target) {
        return std::find_if(parts.begin(),parts.end(),[&](const auto& p){return p.name==target;});
    };
    const auto primary=find(plan.primary_), backup=find(plan.backup_);
    if(primary==parts.end() || backup==parts.end() || primary->size<uint64_t(size)+512 || backup->size<uint64_t(size)+512)
        return std::unexpected(error(OperationStep::Validate,std::errc::no_space_on_device,"NV primary and backup capacities"));
    plan.primary_offset_=primary->offset; plan.backup_offset_=backup->offset;
    auto a=plan.access_.read_small(dev,primary->offset,size+512,stop);
    if(!a) return std::unexpected(device_operation_error(dev,OperationStep::Read,a.error(),plan.primary_));
    auto b=plan.access_.read_small(dev,backup->offset,size+512,stop);
    if(!b) return std::unexpected(device_operation_error(dev,OperationStep::Read,b.error(),plan.backup_));
    plan.before_primary_=std::move(*a); plan.before_backup_=std::move(*b);
    plan.payload_=std::move(frozen);
    plan.expected_=nv_physical_image(plan.payload_,NvChecksumWidth::Bits64);
    plan.connection_=dev.connection_token();
    return plan;
} catch(...) {return std::unexpected(device_exception_error(dev,OperationStep::Prepare));}
OperationResult<> NvRestore::save_recovery(NvRestorePlan& plan,const std::filesystem::path& directory) try {
    if(plan.persisted_ || plan.consumed_) return std::unexpected(error(OperationStep::Validate,
        std::errc::operation_not_permitted,"NV recovery already saved or transaction consumed"));
    std::error_code ec;
    if(!std::filesystem::create_directory(directory,ec)) return std::unexpected(error(OperationStep::Save,
        ec?std::errc::io_error:std::errc::file_exists,"NV recovery directory must be new"));
    const auto save=[&](const std::string& name,std::span<const uint8_t> bytes)->OperationResult<> {
        return Journal::write(directory/platform::path(name),bytes,name);
    };
    auto r=save(plan.primary_+".before.bin",plan.before_primary_);
    if(r) r=save(plan.backup_+".before.bin",plan.before_backup_);
    if(r) r=save("expected-nv.bin",plan.expected_);
    const std::string note="Logical NV restore: "+plan.primary_+" -> "+plan.backup_+
        "\nBoth copies can commit in the final MIDST. Never retry an uncertain write automatically.\n"
        "Before files preserve the header and effective NV data, not the unused partition tail.\n";
    if(r) r=save("recovery.txt",std::span(reinterpret_cast<const uint8_t*>(note.data()),note.size()));
    if(r)r=Journal::seal_directory(directory);
    if(r) { plan.recovery_directory_=std::filesystem::absolute(directory);plan.persisted_=true; }
    return r;
} catch(...) {return std::unexpected(exception_error(OperationStep::Save));}
OperationResult<NvRestorePlan> NvRestore::prepare_merge(device::SprdDevice& dev,const std::string& name,
    std::span<const uint8_t> replacement,std::span<const NvMergeItem> rules,std::stop_token stop,
    NvByteOrder old_order,NvByteOrder new_order) try {
    const auto size=device::nv_payload_size(dev.profile().nv_dialect);
    if(!size || replacement.size()>size) return std::unexpected(error(OperationStep::Validate,
        std::errc::not_supported,"NV merge loader/size contract"));
    const std::vector<uint8_t> template_bytes(replacement.begin(),replacement.end());
    const std::vector<NvMergeItem> frozen_rules(rules.begin(),rules.end());
    std::vector<uint8_t> padded(size,0xff);
    std::copy(template_bytes.begin(),template_bytes.end(),padded.begin());
    auto rules_valid=validate_nv_merge_rules(frozen_rules,old_order,new_order);
    if(!rules_valid)return std::unexpected(error(OperationStep::Validate,rules_valid.error(),"NV merge rules"));
    if((old_order==NvByteOrder::ReversedWords || new_order==NvByteOrder::ReversedWords) &&
        (size%4 || replacement.size()%4))return std::unexpected(error(OperationStep::Validate,std::errc::message_size,"NV word alignment"));
    auto template_valid=nv_merge_items(padded,template_bytes,size,frozen_rules,new_order,new_order);
    if(!template_valid)return std::unexpected(error(OperationStep::Validate,template_valid.error(),"NV template"));
    auto plan=prepare_payload(dev,name,padded,stop);
    if(!plan) return plan;
    auto primary=nv_decode_physical(plan->before_primary_,size);
    auto backup=nv_decode_physical(plan->before_backup_,size);
    if(!primary && !backup) return std::unexpected(error(OperationStep::Validate,
        std::errc::bad_message,"both NV copies invalid; calibration merge unavailable"));
    if(primary && backup && *primary!=*backup) return std::unexpected(error(OperationStep::Validate,
        std::errc::state_not_recoverable,"valid NV copies disagree; refusing to guess which calibration to preserve"));
    auto merged=nv_merge_items(primary?*primary:*backup,template_bytes,size,frozen_rules,old_order,new_order);
    if(!merged) return std::unexpected(error(OperationStep::Prepare,merged.error(),"NV item merge"));
    plan->payload_=std::move(*merged);
    plan->expected_=nv_physical_image(plan->payload_,NvChecksumWidth::Bits64);
    return plan;
} catch(...) {return std::unexpected(device_exception_error(dev,OperationStep::Prepare));}
OperationResult<> NvRestore::validate(device::SprdDevice& dev,const NvRestorePlan& plan,std::stop_token stop) try {
    if(!plan.persisted_ || plan.consumed_ || dev.connection_token()!=plan.connection_)
        return std::unexpected(error(OperationStep::Validate,std::errc::operation_not_permitted,"NV plan requires persisted recovery and its original connection"));
    auto fresh=PhysicalAccess::open(dev,stop);
    if(!fresh) return std::unexpected(device_operation_error(dev,OperationStep::Read,fresh.error(),"NV GPT recheck"));
    const auto& before=plan.access_.layout();
    const auto& after=fresh->layout();
    if(before.disk_bytes!=after.disk_bytes || before.header.sector_size!=after.header.sector_size ||
        std::any_of(before.partitions.begin(),before.partitions.end(),[&](const auto& p){
            if(p.name!=plan.primary_ && p.name!=plan.backup_) return false;
            return std::none_of(after.partitions.begin(),after.partitions.end(),[&](const auto& q){return p.name==q.name && p.offset==q.offset && p.size==q.size;});
        }))
        return std::unexpected(error(OperationStep::Validate,std::errc::state_not_recoverable,"NV layout changed"));
    for(const auto& [offset,before]:{std::pair{plan.primary_offset_,&plan.before_primary_},std::pair{plan.backup_offset_,&plan.before_backup_}}) {
        auto current=fresh->read_small(dev,offset,before->size(),stop);
        if(!current || *current!=*before) return std::unexpected(device_operation_error(dev,OperationStep::Validate,
            current?std::errc::state_not_recoverable:current.error(),"NV contents changed after preparation"));
    }
    return {};
} catch(...) {return std::unexpected(device_exception_error(dev,OperationStep::Validate));}
OperationResult<uint64_t> NvRestore::execute(device::SprdDevice& dev,NvRestorePlan& plan,
    std::stop_token stop,const io::TransferObserver& progress) {
    OperationStep step=OperationStep::Validate;
    try {
    auto validated=validate(dev,plan,stop);
    if(!validated) return std::unexpected(validated.error());
    if(stop.stop_requested()) return std::unexpected(error(OperationStep::Write,std::errc::interrupted,"NV cancelled before START"));
    const auto record=[&](std::string text)->OperationResult<> {
        return Journal::attempt([&]{return Journal::write(plan.recovery_directory_/"execution.txt",text,"NV execution record");});
    };
    step=OperationStep::Save;
    auto recorded=record("State: submitting\nTarget: "+plan.primary_+"\nBoth copies may change in the final MIDST.\n");
    if(!recorded) return std::unexpected(recorded.error());
    plan.consumed_=true;
    step=OperationStep::Write;
    std::expected<void,std::errc> written;
    try { written=dev.write_nv(plan.primary_,plan.payload_,stop,progress); }
    catch(...) {
        auto failure=device_exception_error(dev,OperationStep::Write);
        auto saved=Journal::attempt([&]{return record("State: write exception\nPrimary and backup contents unconfirmed; no automatic retry.\n");});
        if(!saved)attach_journal_failure(failure,saved.error());
        return std::unexpected(std::move(failure));
    }
    if(!written) {
        auto failure=device_operation_error(dev,OperationStep::Write,written.error(),"NV write not confirmed; both copies may have changed");
        auto saved=Journal::attempt([&]{return record("State: write failed\nError: "+std::make_error_code(written.error()).message()+
            "\nPrimary and backup contents unconfirmed; no automatic retry.\n");});
        if(!saved)attach_journal_failure(failure,saved.error());
        return std::unexpected(std::move(failure));
    }
    step=OperationStep::Save;
    recorded=record("State: END acknowledged; physical readback pending\n");
    if(!recorded) return std::unexpected(recorded.error());
    for(auto offset:{plan.primary_offset_,plan.backup_offset_}) {
        step=OperationStep::Validate;
        auto actual=plan.access_.read_small(dev,offset,plan.expected_.size(),stop);
        if(!actual || *actual!=plan.expected_) {
            auto failure=device_operation_error(dev,OperationStep::Validate,
                actual?std::errc::bad_message:actual.error(),"NV primary/backup physical readback not verified");
            auto saved=Journal::attempt([&]{return record("State: readback failed\nPhysical offset: "+std::to_string(offset)+"\nNo automatic retry.\n");});
            if(!saved)attach_journal_failure(failure,saved.error());
            return std::unexpected(std::move(failure));
        }
    }
    step=OperationStep::Save;
    recorded=record("State: completed\nPrimary and backup headers and payload physically verified.\nUnused partition tails were not restored.\n");
    if(!recorded) return std::unexpected(recorded.error());
    return plan.payload_.size();
    } catch(...) {return std::unexpected(device_exception_error(dev,step));}
}
}

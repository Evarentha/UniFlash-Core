/*
 * UniFlash-Core / PAC Execution
 *
 * Order aware execution with relocation, NV merging and the terminal action.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/session/operations.h>
#include <uniflash/session/pac_services.h>
#include <uniflash/session/journal.h>
#include <uniflash/session/partition_access.h>
#include <uniflash/session/pac_archive.h>
#include <uniflash/io/partition_filename.h>
#include <uniflash/platform.h>
#include <uniflash/log.h>
#include <algorithm>
#include <set>
#include <map>

namespace uniflash::session {
namespace {
bool same_geometry(std::span<const device::PartitionInfo> a,std::span<const device::PartitionInfo> b) {
    const auto count=[](auto parts){return std::count_if(parts.begin(),parts.end(),[](const auto& p){return !p.hw_boot;});};
    if(count(a)!=count(b)) return false;
    return std::all_of(a.begin(),a.end(),[&](const auto& p) {
        if(p.hw_boot) return true;
        return !p.unverified && p.size && std::any_of(b.begin(),b.end(),[&](const auto& q) {
            return !q.hw_boot && !q.unverified && q.name==p.name && q.size==p.size && q.offset==p.offset;
        });
    });
}
OperationError error(OperationStep step,std::errc code,std::string text) {return {step,code,std::move(text)};}
}
OperationResult<FlashPlan> Operations::prepare_package(device::SprdDevice& dev,const PacArchive& archive,
    const PacPrepareOptions& options,std::stop_token stop,const ProgressObserver& progress) {
    auto compiled=PacCompiler::compile(archive,options,dev.profile(),dev.da_info(),stop,progress);
    if(!compiled)return std::unexpected(compiled.error());
    return PacResolver::resolve(dev,*compiled,stop,progress);
}
OperationResult<CompiledPac> PacCompiler::compile(const PacArchive& archive,const PacPrepareOptions& options,
    const device::DeviceProfile& profile,const device::SessionCapabilities& capabilities,std::stop_token stop,const ProgressObserver& progress) try {
    if(!profile.valid())
        return std::unexpected(error(OperationStep::Validate,std::errc::invalid_argument,"standard PAC compiler context"));
    if(options.physical_recovery)return compile_physical(archive,options,profile,capabilities,stop,progress);
    const auto representations=options.nv_representations;
    const auto address_order=options.address_word_order;
    const auto timestamp=options.factory_timestamp;
    const auto vpac=options.vpac_utf16le;
    const auto softsim_eid=options.softsim_expected_eid;
    auto actions=archive.selected_actions(capabilities.storage);
    if(!actions) return std::unexpected(error(OperationStep::Validate,actions.error(),"PAC storage selection"));
    for(const auto& action:*actions) {
        if(!action.erase && !pac_read_operation(action.type) && !pac_address_operation(action.type) &&
            !pac_control_operation(action.type) && action.type!="NV_COMM" && device::nv_pair(action.partition))
            return std::unexpected(error(OperationStep::Validate,std::errc::not_supported,"PAC NV requires NV_COMM: "+action.id));
        if(action.type=="EraseFlash") {
            auto size=device::address_erase_size(action.load_address,action.declared_size);
            if(!size)return std::unexpected(error(OperationStep::Validate,size.error(),"PAC address erase range: "+action.id));
        }
        if(pac_control_operation(action.type) && action.type!="EXTTABLE" && action.type!="WriteVpac" && !control_command(action.type))
            return std::unexpected(error(OperationStep::Validate,std::errc::not_supported,"PAC control: "+action.type));
        if(action.type=="Soft_SIM" && softsim_eid.size()!=10)
            return std::unexpected(error(OperationStep::Validate,std::errc::invalid_argument,"PAC Soft_SIM requires expected 10-byte EID"));
        if(action.type=="WriteEfuse" && !options.factory_write_efuse)
            return std::unexpected(error(OperationStep::Validate,std::errc::operation_not_permitted,"PAC WriteEfuse requires product WriteEfuse setting"));
        if(action.type=="WriteVpac") {
            if(vpac.size()<4||vpac.size()>512||(vpac.size()&1)||vpac[vpac.size()-1]||vpac[vpac.size()-2])
                return std::unexpected(error(OperationStep::Validate,std::errc::invalid_argument,"PAC VPAC UTF16LE value"));
            for(size_t i=0;i+2<vpac.size();i+=2)if(!vpac[i]&&!vpac[i+1])
                return std::unexpected(error(OperationStep::Validate,std::errc::invalid_argument,"PAC VPAC embedded NUL"));
        }
    }
    if(!timestamp && std::any_of(actions->begin(),actions->end(),[](const auto& a){return a.type=="MiscDataCode" || a.type=="MiscDataCode2";}))
        return std::unexpected(error(OperationStep::Validate,std::errc::invalid_argument,"PAC MiscDataCode requires configured factory timestamp"));
    if(std::any_of(actions->begin(),actions->end(),[](const auto& a){return pac_address_operation(a.type);}) &&
        (!address_order || (*address_order!=device::AddressWordOrder::Little && *address_order!=device::AddressWordOrder::Big)))
        return std::unexpected(error(OperationStep::Validate,std::errc::not_supported,"PAC address operations require product word-order configuration"));
    std::set<std::string> configured;
    const auto valid=[](NvByteOrder o) {return o==NvByteOrder::Little || o==NvByteOrder::BigItemHeaders ||
        o==NvByteOrder::ReversedWords || o==NvByteOrder::LittleIndexBigItemHeaders;};
    for(const auto& r:representations) if((r.logical_size && (r.logical_size<8 || (r.logical_size&1))) ||
        r.logical_size>16*1024*1024 || !configured.insert(r.partition).second || !valid(r.device_order) ||
        !valid(r.template_order) || std::none_of(actions->begin(),actions->end(),[&](const auto& a) {
            return a.partition==r.partition && a.type=="NV_COMM";
        })) return std::unexpected(error(OperationStep::Validate,std::errc::invalid_argument,"PAC NV representation: "+r.partition));
    for(const auto& action:*actions) if(action.type=="NV_COMM" || action.type=="NV" || action.type=="NV_NAND") {
        const auto r=std::find_if(representations.begin(),representations.end(),[&](const auto& v){return v.partition==action.partition;});
        if(action.type=="NV_COMM" && profile.nv_dialect==device::NvDialect::Unknown &&
            (r==representations.end() || !r->r27_named_protocol))return std::unexpected(error(OperationStep::Validate,
                std::errc::not_supported,"NV_COMM requires an audited loader or explicit product r27-named protocol: "+action.id));
        auto valid=validate_nv_merge_rules(action.nv_items,r==representations.end()?NvByteOrder::Little:r->device_order,
            r==representations.end()?NvByteOrder::Little:r->template_order);
        if(!valid)return std::unexpected(error(OperationStep::Validate,valid.error(),"PAC NV representation contract: "+action.id));
    }
    if(stop.stop_requested()) return std::unexpected(error(OperationStep::Prepare,std::errc::interrupted,"PAC cancelled"));
    // Stage 1: compile every local input and dependency before authentication,
    // enumeration or repair-capable named NV reads. These retained images are
    // reused below; there is no second open or sparse indexing pass.
    using LocalImage=CompiledPac::LocalImage;
    std::map<std::string,LocalImage> local_images;
    std::map<std::string,uint32_t> nv_lengths;
    std::map<std::string,uint32_t> preceding_nv;
    std::vector<uint8_t> partition_table;
    const auto& local_layout=archive.partition_layout();
    if(local_layout.partitions.empty() && archive.repartition_strategy()==0 &&
        std::any_of(actions->begin(),actions->end(),[](const auto& a){return !pac_address_operation(a.type) && !pac_control_operation(a.type);}))
        return std::unexpected(error(OperationStep::Validate,std::errc::bad_message,"PAC requires a partition table"));
    if(!local_layout.partitions.empty()) {
        auto table=layout::build_partition_table(local_layout);
        if(!table)return std::unexpected(error(OperationStep::Validate,table.error(),"PAC local partition table"));
        if(local_layout.partitions.size()>profile.gpt_max_entries || std::any_of(local_layout.partitions.begin(),local_layout.partitions.end(),[&](const auto& p){return p.name.size()>profile.gpt_max_name;}))
            return std::unexpected(error(OperationStep::Validate,std::errc::not_supported,"PAC local table receiver limits"));
        partition_table=std::move(*table);
    }
    const auto nv_key=[](const PacAction& a) {
        return pac_address_operation(a.type)?"address:"+std::to_string(a.load_address):"name:"+a.partition;
    };
    uint64_t total_bytes=0;
    for(const auto& action:*actions) {
        if(stop.stop_requested())return std::unexpected(error(OperationStep::Prepare,std::errc::interrupted,action.id));
        if(pac_read_operation(action.type) && (action.read_offset>UINT64_MAX-action.declared_size ||
            (!action.type.ends_with("_64") && action.read_offset+action.declared_size>UINT32_MAX)))
            return std::unexpected(error(OperationStep::Validate,std::errc::message_size,"PAC local read range"));
        if(pac_address_operation(action.type)) {
            const size_t chunk=action.type=="BOOT_LOADER"?2112:action.type=="YAFFS_IMG"?0x3180:0x800;
            if(chunk>std::min(profile.raw_write_chunk,profile.escaped_write_chunk))
                return std::unexpected(error(OperationStep::Validate,std::errc::message_size,"PAC local address frame size"));
        }
        if(action.type=="CHECK_NV" || action.type=="CHECK_NV2") {
            const auto previous=preceding_nv.find(nv_key(action));
            if((action.type=="CHECK_NV2" && action.read_offset) || previous==preceding_nv.end() || previous->second!=action.declared_size)
                return std::unexpected(error(OperationStep::Validate,std::errc::invalid_argument,"CHECK_NV local dependency/range: "+action.id));
        }
        if(!action.length)continue;
        const bool nv=action.type=="NV_COMM" || action.type=="NV" || action.type=="NV_NAND";
        uint64_t limit=UINT64_MAX;
        if(nv) {
            const auto representation=std::find_if(representations.begin(),representations.end(),[&](const auto& r){return r.partition==action.partition;});
            limit=action.type=="NV_COMM" && representation!=representations.end() && representation->logical_size?
                representation->logical_size:action.declared_size?action.declared_size:device::nv_payload_size(profile.nv_dialect);
            if(limit<8 || (limit&1) || limit>16*1024*1024)return std::unexpected(error(OperationStep::Validate,std::errc::message_size,"PAC logical NV length: "+action.id));
            if(action.type=="NV_COMM") {
                const auto* pair=device::nv_pair(action.partition);
                if(!pair || pair->primary!=action.partition || std::any_of(actions->begin(),actions->end(),[&](const auto& other){
                    return &other!=&action && other.type!="CHECK_NV2" && (other.partition==pair->primary || other.partition==pair->backup);
                }))return std::unexpected(error(OperationStep::Validate,std::errc::invalid_argument,"PAC overlapping NV transaction"));
            }
            nv_lengths.emplace(action.id,static_cast<uint32_t>(limit));preceding_nv[nv_key(action)]=static_cast<uint32_t>(limit);
        } else if(action.type=="EXTTABLE")limit=device::DeviceProfile::raw_payload_limit;
        uint64_t expanded=0;
        auto image=archive.transfer_image(action,limit,stop,[&](const io::PrepareProgress& e){
            if(progress)progress({OperationStep::Prepare,action.id,e.completed,e.total,"local image preflight"});
        },&expanded);
        if(!image)return std::unexpected(error(OperationStep::Prepare,image.error(),action.id));
        if(!pac_address_operation(action.type) && archive.repartition_strategy()==0) {
            const auto part=std::find_if(local_layout.partitions.begin(),local_layout.partitions.end(),[&](const auto& p){return p.name==action.partition;});
            if(part!=local_layout.partitions.end() && part->size!=UINT64_MAX && expanded>part->size)
                return std::unexpected(error(OperationStep::Validate,std::errc::file_too_large,"PAC local target capacity: "+action.id));
        }
        if(pac_address_operation(action.type) && ((image->size()&1) || image->size()>UINT32_MAX ||
            image->size()>uint64_t(UINT32_MAX)+1-action.load_address))return std::unexpected(error(OperationStep::Validate,std::errc::value_too_large,action.id));
        if(!pac_address_operation(action.type) && !nv && !pac_control_operation(action.type) && image->size()>UINT32_MAX &&
            !action.type.ends_with("_64") && !profile.framed_write_u64 && !(profile.allow_whole_file_raw && capabilities.valid && capabilities.support_raw))
            return std::unexpected(error(OperationStep::Validate,std::errc::file_too_large,action.id));
        if(nv || action.type=="EXTTABLE") {
            std::vector<uint8_t> bytes(static_cast<size_t>(image->size()));auto got=image->reader()(0,bytes,stop);
            if(!got)return std::unexpected(error(OperationStep::Prepare,got.error(),action.id));
            if(nv) {
                auto padded=bytes;padded.resize(static_cast<size_t>(limit),0xff);
                const auto r=std::find_if(representations.begin(),representations.end(),[&](const auto& v){return v.partition==action.partition;});
                const auto order=r==representations.end()?NvByteOrder::Little:r->template_order;
                if(r!=representations.end() && (r->device_order==NvByteOrder::ReversedWords || order==NvByteOrder::ReversedWords) &&
                    ((limit%4) || (bytes.size()%4)))
                    return std::unexpected(error(OperationStep::Validate,std::errc::message_size,"PAC reversed NV alignment: "+action.id));
                auto valid_template=nv_merge_items(padded,bytes,static_cast<uint32_t>(limit),action.nv_items,order,order);
                if(!valid_template)return std::unexpected(error(OperationStep::Validate,valid_template.error(),"NV template: "+action.id));
            } else {
                auto frame=protocol::BslCodec::encode_hdlc_chk(0x14,bytes,protocol::BslCodec::Chk::Add);
                if(!frame || frame->size()>device::DeviceProfile::wire_frame_limit)return std::unexpected(error(OperationStep::Validate,std::errc::message_size,action.id));
            }
        }
        const auto accounted=nv?limit:image->size();
        if(accounted>UINT64_MAX-total_bytes)return std::unexpected(error(OperationStep::Validate,std::errc::value_too_large,"PAC bytes"));
        total_bytes+=accounted;
        local_images.emplace(action.id,LocalImage{std::move(*image),expanded});
    }
    CompiledPac compiled(archive);compiled.options_=options;compiled.actions_=std::move(*actions);
    compiled.images_=std::move(local_images);compiled.nv_lengths_=std::move(nv_lengths);
    compiled.partition_table_=std::move(partition_table);
    compiled.profile_=profile;compiled.capabilities_=capabilities;return compiled;
} catch(...) {return std::unexpected(exception_error(OperationStep::Prepare));}
OperationResult<FlashPlan> PacResolver::resolve(device::SprdDevice& dev,const CompiledPac& compiled,
    std::stop_token stop,const ProgressObserver& progress) try {
    const auto& archive=compiled.archive_;const auto& options=compiled.options_;
    const auto* actions=&compiled.actions_;const auto& local_images=compiled.images_;const auto& nv_lengths=compiled.nv_lengths_;
    const auto& representations=options.nv_representations;const auto address_order=options.address_word_order;
    const auto timestamp=options.factory_timestamp;const auto& vpac=options.vpac_utf16le;const auto& softsim_eid=options.softsim_expected_eid;
    const auto& authenticate=options.authentication;
    if(dev.profile()!=compiled.profile_ || dev.da_info()!=compiled.capabilities_)
        return std::unexpected(error(OperationStep::Validate,std::errc::state_not_recoverable,"PAC compilation context changed"));
    if(stop.stop_requested())return std::unexpected(error(OperationStep::Prepare,std::errc::interrupted,"PAC cancelled"));
    if(options.physical_recovery)return resolve_physical(dev,compiled,stop,progress);
    if(progress)progress({OperationStep::Prepare,archive.product(),0,0,"resolve device inputs"});
    if(authenticate) {
        auto result=dev.authenticate(authenticate,stop);
        if(!result) return std::unexpected(device_operation_error(dev,OperationStep::Prepare,result.error(),"PAC AUTH41"));
    }
    FlashPlan plan;plan.pac_=true;plan.package_execution_=true;plan.connection_=dev.connection_token();
    plan.backup_targets_=archive.backup_targets();
    std::erase_if(plan.backup_targets_,[&](const auto& name) {
        return std::any_of(actions->begin(),actions->end(),[&](const auto& a){return a.partition==name && a.type=="NV_COMM";});
    });
    const auto& layout=archive.partition_layout();
    const auto strategy=archive.repartition_strategy();
    // Only package decisions that actually require current geometry query it.
    // Strategy 0 supplies the new table; strategy 2 explicitly ignores mismatch.
    const bool compare_layout=!layout.partitions.empty() && (strategy==1 || strategy==3);
    std::vector<device::PartitionInfo> current;
    if(compare_layout || !plan.backup_targets_.empty()) {
        auto parts=dev.list_partitions(stop,false);
        if(!parts) return std::unexpected(device_operation_error(dev,OperationStep::Validate,parts.error(),
            "PAC requires current partition sizes for layout policy or requested backup"));
        current=std::move(*parts);
    }
    std::optional<layout::GptLayout> comparison_disk;
    if(compare_layout) {
        dev.invalidate_layout();
        auto disk=dev.read_disk_layout(stop);
        if(!disk || disk->mbr)return std::unexpected(error(OperationStep::Validate,disk?std::errc::not_supported:disk.error(),
            "PAC layout policy requires geometry, not only names/sizes"));
        comparison_disk=std::move(*disk);
        std::erase_if(current,[](const auto& p){return !p.hw_boot;});
        for(const auto& p:comparison_disk->partitions)current.push_back({p.name,p.size,p.offset});
    }
    std::vector<device::PartitionInfo> target;
    uint64_t target_offset=1048576;
    for(const auto& p:layout.partitions) {
        const bool remaining=p.size==UINT64_MAX;
        device::PartitionInfo part;part.name=p.name;part.size=remaining?0:p.size;part.unverified=remaining;
        part.offset=target_offset;
        if(remaining && compare_layout) {
            // Resolve the fill-to-end region using read-only current geometry;
            // arbitrary GPT recovery/rewriting is not required.
            const auto& disk=comparison_disk;
            const uint64_t end=target_offset;
            const auto& h=disk->header;
            if(disk->mbr || h.last_usable==UINT64_MAX || h.last_usable+1>UINT64_MAX/h.sector_size ||
                (h.last_usable+1)*h.sector_size<=end) return std::unexpected(error(OperationStep::Validate,std::errc::bad_message,"PAC usable disk range"));
            part.size=(h.last_usable+1)*h.sector_size-end;part.unverified=false;
        }
        if(part.size>UINT64_MAX-target_offset)return std::unexpected(error(OperationStep::Validate,std::errc::value_too_large,"PAC layout sizes"));
        target_offset+=part.size;
        target.push_back(std::move(part));
    }
    bool repartition=false;
    if(!target.empty()) {
        const bool matches=compare_layout && same_geometry(target,current);
        if(strategy==1 && !matches) return std::unexpected(error(OperationStep::Validate,std::errc::state_not_recoverable,"PAC partition geometry mismatch"));
        repartition=strategy==0 || (strategy==3 && !matches);
        if(compare_layout) plan.comparison_capacities_=current;
    } else if(strategy==0 && std::any_of(actions->begin(),actions->end(),[](const auto& a) {
        return !pac_address_operation(a.type) && !pac_control_operation(a.type);
    })) return std::unexpected(error(OperationStep::Validate,std::errc::bad_message,"PAC requires a partition table"));
    if(repartition)plan.repartition_table_=compiled.partition_table_;
    // No layout-preservation migration is inserted into the package sequence.
    // Capacity comes from the table we actually submit, or a compared current
    // table. Ignore-mismatch must not mistake package sizes for device sizes.
    plan.capacities_=repartition?target:current;
    for(auto& p:plan.capacities_) if(p.hw_boot && !p.size) p.unverified=true;
    const bool enumerated_targets=!plan.capacities_.empty();
    // Check every known capacity before the first repair-capable NV read.
    for(const auto& action:*actions) {
        if(pac_address_operation(action.type)||pac_control_operation(action.type))continue;
        const auto p=std::find_if(plan.capacities_.begin(),plan.capacities_.end(),[&](const auto& v){return v.name==action.partition;});
        if(p==plan.capacities_.end()) {
            if(enumerated_targets && action.partition!="splloader" && action.partition!="splloader_bak")
                return std::unexpected(error(OperationStep::Validate,std::errc::no_such_device,action.partition));
            continue;
        }
        if(p->unverified)continue;
        if(const auto image=local_images.find(action.id);image!=local_images.end() && image->second.expanded>p->size)
            return std::unexpected(error(OperationStep::Validate,std::errc::file_too_large,action.id));
        if(pac_read_operation(action.type) && (action.read_offset>p->size || action.declared_size>p->size-action.read_offset))
            return std::unexpected(error(OperationStep::Validate,std::errc::message_size,action.id));
        if(const auto n=nv_lengths.find(action.id);n!=nv_lengths.end() && n->second>p->size)
            return std::unexpected(error(OperationStep::Validate,std::errc::message_size,action.id));
    }
    std::set<std::string> backup_files;
    for(const auto& name:plan.backup_targets_) {
        auto part=PartitionAccess::find(current,name);
        if(!part || part->hw_boot || part->unverified || !part->size || device::nv_pair(name))
            return std::unexpected(error(OperationStep::Validate,std::errc::not_supported,"PAC named backup semantics/capacity: "+name));
        auto file=io::partition_filename(name);
        for(auto& c:file) if(c>='A' && c<='Z') c+=32;
        if(!backup_files.insert(file).second) return std::unexpected(error(OperationStep::Validate,std::errc::invalid_argument,"PAC backup filename collision"));
        plan.backup_capacities_.push_back(*part);
    }
    for(const auto& action:*actions) {
        if(action.type=="CHECK_NV" || action.type=="CHECK_NV2") {
            // R27 CHECK_NV compares the saved merged image, excluding the
            // first four counter bytes. Never substitute a factory template.
            const bool address=action.type=="CHECK_NV";
            auto previous=std::find_if(plan.entries_.rbegin(),plan.entries_.rend(),[&](const auto& e) {
                const auto* nv=e.logical_nv();return nv && (address?(nv->address && nv->address->address==action.load_address):(!nv->address && e.partition==action.partition));
            });
            if(previous==plan.entries_.rend() || previous->logical_nv()->payload.size()!=action.declared_size || action.declared_size<8)
                return std::unexpected(error(OperationStep::Validate,std::errc::invalid_argument,"CHECK_NV requires preceding prepared NV result with matching range"));
            FlashEntry entry{address?action.id:action.partition,CheckNvAction{previous->logical_nv()->payload,previous->logical_nv()->address}};
            plan.entries_.push_back(std::move(entry));continue;
        }
        if(pac_address_operation(action.type)) {
            const AddressTarget target{action.load_address,*address_order,
                action.type=="BOOT_LOADER"?size_t{2112}:action.type=="YAFFS_IMG"?size_t{0x3180}:size_t{0x800}};
            if(action.type=="NV" || action.type=="NV_NAND") {
                const auto size=static_cast<uint32_t>(action.declared_size);
                const auto& source=local_images.at(action.id).bytes;
                std::vector<uint8_t> replacement(static_cast<size_t>(source.size())),before;
                auto got=source.reader()(0,replacement,stop);if(!got)return std::unexpected(error(OperationStep::Prepare,got.error(),action.id));
                auto read=dev.read_address_stream(action.load_address,size,[&](auto bytes,auto)->std::expected<void,std::errc>{
                    if(bytes.size()>size-before.size())return std::unexpected(std::errc::message_size);
                    before.insert(before.end(),bytes.begin(),bytes.end());return {};
                },*address_order,stop);
                if(!read)return std::unexpected(device_operation_error(dev,OperationStep::Read,read.error(),action.id));
                // Wire parameter endianness says nothing about NV item layout.
                // This path accepts only the established LE item representation.
                auto merged=nv_merge_items(before,replacement,size,action.nv_items);
                if(!merged)return std::unexpected(error(OperationStep::Prepare,merged.error(),"PAC address NV merge: "+action.id));
                if(size>UINT64_MAX-plan.bytes_)return std::unexpected(error(OperationStep::Validate,std::errc::value_too_large,"PAC bytes"));
                plan.bytes_+=size;
                plan.entries_.push_back({action.id,LogicalNvAction{std::move(*merged),std::move(before),target}});continue;
            }
            if(action.erase)plan.entries_.push_back({action.id,EraseAction{target,action.declared_size}});
            else if(pac_address_read(action.type))plan.entries_.push_back({action.id,ReadAction{0,action.declared_size,false,target}});
            else {
                WriteAction write{local_images.at(action.id).bytes};
                write.expanded_size=local_images.at(action.id).expanded;write.address=target;
                if(action.type=="Soft_SIM")write.softsim_eid=softsim_eid;
                if(action.type=="MiscDataCode")write.timestamp=timestamp;
                plan.bytes_+=write.image.size();plan.entries_.push_back({action.id,std::move(write)});
            }
            continue;
        }
        if(pac_control_operation(action.type)) {
            if(action.type=="EXTTABLE")plan.entries_.push_back({action.id,ControlAction{ExtTableWrite{local_images.at(action.id).bytes}}});
            else if(action.type=="WriteVpac")plan.entries_.push_back({action.id,ControlAction{VpacWrite{vpac}}});
            else plan.entries_.push_back({action.id,ControlAction{*control_command(action.type)}});
            continue;
        }
        auto found=std::find_if(plan.capacities_.begin(),plan.capacities_.end(),[&](const auto& p){return p.name==action.partition;});
        if(found==plan.capacities_.end()) {
            // A selected hardware target or a loader without enumeration is
            // validated by START. Do not invent physical role/GPT mappings.
            if(enumerated_targets && action.partition!="splloader" && action.partition!="splloader_bak")
                return std::unexpected(error(OperationStep::Validate,std::errc::no_such_device,action.partition));
            device::PartitionInfo part;part.name=action.partition;part.unverified=true;
            plan.capacities_.push_back(std::move(part));found=std::prev(plan.capacities_.end());
        }
        if(pac_read_operation(action.type)) {
            ReadAction read{action.read_offset,action.declared_size,action.type.ends_with("_64")};
            if(!found->unverified && read.offset+read.length>found->size)
                return std::unexpected(error(OperationStep::Validate,std::errc::message_size,"PAC read range: "+action.id));
            plan.entries_.push_back({action.partition,std::move(read)});
        } else if(action.type=="NV_COMM") {
            auto r=std::find_if(representations.begin(),representations.end(),[&](const auto& v){return v.partition==action.partition;});
            const auto logical_size=nv_lengths.at(action.id);
            const auto& source=local_images.at(action.id).bytes;
            std::vector<uint8_t> bytes(static_cast<size_t>(source.size()));
            auto got=source.reader()(0,bytes,stop);if(!got) return std::unexpected(error(OperationStep::Prepare,got.error(),action.id));
            // Local schema/pair/length and all capacities are already checked.
            // Named reads may repair the physical pair: this is device resolve.
            auto before=dev.read_partition(action.partition,0,logical_size,stop);
            if(!before) return std::unexpected(device_operation_error(dev,OperationStep::Read,before.error(),"PAC logical NV backup"));
            if(std::all_of(before->begin(),before->end(),[](auto b){return b==0;}) ||
                std::all_of(before->begin(),before->end(),[](auto b){return b==0xff;}))
                return std::unexpected(error(OperationStep::Validate,std::errc::bad_message,"PAC logical NV is blank"));
            auto merged=nv_merge_items(*before,bytes,logical_size,action.nv_items,
                r==representations.end()?NvByteOrder::Little:r->device_order,
                r==representations.end()?NvByteOrder::Little:r->template_order);
            if(!merged) return std::unexpected(error(OperationStep::Prepare,merged.error(),"PAC logical NV merge"));
            plan.bytes_+=merged->size();
            plan.entries_.push_back({action.partition,LogicalNvAction{std::move(*merged),std::move(*before),{}}});
        } else if(!action.erase) {
            if(device::nv_pair(action.partition)) return std::unexpected(error(OperationStep::Validate,std::errc::not_supported,"PAC NV requires NV_COMM"));
            WriteAction write{local_images.at(action.id).bytes};
            write.expanded_size=local_images.at(action.id).expanded;
            write.wide=action.type=="CODE2_64" || action.type=="YAFFS_IMG2_64";
            if(action.type=="MiscDataCode2")write.timestamp=timestamp;
            plan.bytes_+=write.image.size();plan.entries_.push_back({action.partition,std::move(write)});
        } else plan.entries_.push_back({action.partition,EraseAction{}});
    }
    plan.phase_=PlanPhase::ReadyToPersist;
    plan.layout_token_=dev.layout_token();plan.prepared_at_=std::chrono::steady_clock::now();
    log_status(LogLevel::Info,"PAC",archive.product(),"package-directed FDL operations");
    return plan;
} catch(...) {return std::unexpected(device_exception_error(dev,OperationStep::Prepare));}
OperationResult<> PacRecoveryStore::save_package(device::SprdDevice& dev,FlashPlan& plan,
    const std::filesystem::path& directory,std::stop_token stop,const ProgressObserver& progress) {
    if(!plan.package_execution_ || plan.phase_!=PlanPhase::Persisting || plan.connection_!=dev.connection_token())
        return std::unexpected(error(OperationStep::Validate,std::errc::operation_not_permitted,"PAC recovery phase/connection"));
    if(stop.stop_requested())return std::unexpected(error(OperationStep::Save,std::errc::interrupted,"PAC cancelled"));
    std::error_code ec;
    if(!std::filesystem::create_directory(directory,ec)) return std::unexpected(error(OperationStep::Save,
        ec?std::errc::io_error:std::errc::file_exists,"PAC journal directory must be new"));
    if(!plan.backup_capacities_.empty()) {
        auto current=dev.list_partitions(stop,false);
        if(!current) return std::unexpected(device_operation_error(dev,OperationStep::Read,current.error(),"PAC backup capacities"));
        for(const auto& p:plan.backup_capacities_) {
            auto actual=PartitionAccess::find(*current,p.name);
            if(!actual || actual->size!=p.size || actual->offset!=p.offset || actual->hw_boot!=p.hw_boot || actual->unverified)
                return std::unexpected(error(OperationStep::Validate,std::errc::state_not_recoverable,"PAC backup target changed: "+p.name));
            auto saved=PartitionAccess::backup(dev,p.name,p.size,directory/platform::path("before-"+io::partition_filename(p.name)),stop,progress);
            if(!saved) return std::unexpected(saved.error());
        }
    }
    for(size_t i=0;i<plan.entries_.size();++i) if(const auto* nv=plan.entries_[i].logical_nv()) {
        for(bool before:{true,false}) {
            auto saved=Journal::write(directory/("nv-"+std::to_string(i+1)+(before?"-before.bin":"-merged.bin")),
                before?nv->before:nv->payload,"PAC logical NV backup",stop);
            if(!saved)return saved;
        }
    }
    std::string text="PAC package-directed execution; named backups are not physical restore bundles.\n";
    if(!plan.repartition_table_.empty()) text+="0. package repartition (no automatic preservation migration)\n";
    for(size_t i=0;i<plan.entries_.size();++i) text+=std::to_string(i+1)+". "+plan.entries_[i].partition+" "+
        operation_name(plan.entries_[i].action)+"\n";
    auto saved=Journal::write(directory/"plan.txt",text,"PAC plan",stop);
    if(!saved)return saved;
    auto sealed=Journal::seal_directory(directory);if(!sealed)return sealed;
    plan.journal_directory_=std::filesystem::absolute(directory);
    plan.phase_=PlanPhase::ReadyToExecute;
    return {};
}
}

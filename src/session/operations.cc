#include <uniflash/session/operations.h>
#include <uniflash/session/pac_services.h>
#include <uniflash/session/journal.h>
#include <uniflash/session/partition_access.h>
#include <uniflash/session/pac_parser.h>
#include <uniflash/session/pac_archive.h>
#include <uniflash/session/boot_image.h>
#include <uniflash/session/pac_layout.h>
#include <uniflash/session/nv_restore.h>
#include <uniflash/session/raw_image_contract.h>
#include <uniflash/session/readback.h>
#include <uniflash/session/pac_image_contract.h>
#include <uniflash/io/output.h>
#include <uniflash/io/buffered_output.h>
#include <uniflash/io/partition_filename.h>
#include <uniflash/protocol/partition_name.h>
#include <uniflash/platform.h>
#include <algorithm>
#include <set>
#include <array>
#include <iterator>
#include <uniflash/log.h>
#include <uniflash/progress.h>

namespace uniflash::session {
namespace {
OperationError device_error(device::SprdDevice& device, OperationStep step,
    std::errc code, const std::string& target) {
    return device_operation_error(device,step,code,target);
}
bool valid_name(std::string_view name) {
    return protocol::valid_partition_name(name);
}
io::PrepareObserver preparation(const std::string& target, const ProgressObserver& progress) {
    return [target, progress](const io::PrepareProgress& event) {
        if (!progress) return;
        const auto detail = event.phase == io::PreparePhase::Snapshot ? "snapshot" :
                            event.phase == io::PreparePhase::Index ? "sparse index" : "checksum";
        progress({OperationStep::Prepare, target, event.completed, event.total, detail});
    };
}
}
OperationResult<std::vector<device::PartitionInfo>> PartitionAccess::capacities(device::SprdDevice& device,
    std::span<const std::string> names, std::stop_token stop, const ProgressObserver& progress) {
    if (progress) progress({OperationStep::Validate, {}, 0, 0, "partition capacities"});
    WaitProgress waiting("checking partition capacities");
    auto parts = device.list_partitions(stop, false);
    if (!parts) {
        if (parts.error() != std::errc::not_supported || device.link_dead() || device.link_silent() || stop.stop_requested())
            return std::unexpected(OperationError{OperationStep::Validate, parts.error(), "cannot list partitions"});
        std::vector<device::PartitionInfo> requested;
        for (const auto& name : names) {
            if (!valid_name(name)) return std::unexpected(OperationError{OperationStep::Validate, std::errc::invalid_argument, name});
            if (std::any_of(requested.begin(), requested.end(), [&](const auto& p) { return p.name == name; })) continue;
            device::PartitionInfo p; p.name = name; p.unverified = true;
            requested.push_back(std::move(p));
        }
        log_status(LogLevel::Warn, "partitions", "enumeration unavailable; target names and capacities will be checked by the loader");
        return requested;
    }
    for (auto& part : *parts) {
        if (part.hw_boot && !part.size && std::find(names.begin(), names.end(), part.name) != names.end()) {
            auto size = device.probe_hw_part_size(part.name, stop);
            if (!size) return std::unexpected(OperationError{OperationStep::Validate, size.error(), part.name});
            part.size = *size;
        }
    }
    return std::move(*parts);
}

OperationResult<device::PartitionInfo> Operations::find_partition(
    std::span<const device::PartitionInfo> parts, const std::string& name) {
    return PartitionAccess::find(parts,name);
}
OperationResult<device::PartitionInfo> PartitionAccess::find(
    std::span<const device::PartitionInfo> parts, const std::string& name) {
    auto error = [&](std::errc code, std::string detail) -> OperationResult<device::PartitionInfo> {
        OperationError result{OperationStep::Validate, code, name};
        result.detail = std::move(detail);
        return std::unexpected(std::move(result));
    };
    if (!valid_name(name))
        return error(std::errc::invalid_argument, "invalid partition name '" + name + "'");
    const device::PartitionInfo* found = nullptr;
    for (const auto& part : parts) if (part.name == name) {
        if (found)
            return error(std::errc::bad_message, "duplicate partition '" + name + "' in partition table");
        found = &part;
    }
    if (!found)
        return error(std::errc::no_such_device, "partition '" + name + "' not found");
    if (found->address_only)
        return error(std::errc::not_supported, "region '" + name + "' has no firmware partition-name mapping; use read all for raw backup");
    return *found;
}

OperationResult<FlashPlan> Operations::prepare_write(const std::string& name,
    const std::filesystem::path& path, std::span<const device::PartitionInfo> parts,
    std::stop_token stop, const ProgressObserver& progress) try {
    auto part = find_partition(parts, name);
    if (!part) return std::unexpected(part.error());
    if (!part->size && !part->unverified) {
        OperationError error{OperationStep::Validate, std::errc::invalid_argument, name};
        error.detail = "partition '" + name + "' capacity unavailable";
        return std::unexpected(std::move(error));
    }
    auto image = io::Image::prepare(path, part->unverified ? UINT64_MAX : part->size, stop,
                                  preparation(name, progress));
    if (!image) return std::unexpected(OperationError{OperationStep::Prepare, image.error(), name});
    FlashPlan plan;
    plan.bytes_ = image->size();
    WriteAction write{std::move(*image)};
    plan.entries_.push_back({name,std::move(write)});
    plan.phase_=PlanPhase::ReadyToExecute;
    return plan;
} catch(...) {return std::unexpected(exception_error(OperationStep::Prepare));}

OperationResult<FlashPlan> Operations::prepare_flash(const std::filesystem::path& xml,
    std::span<const device::PartitionInfo> parts, std::stop_token stop, const ProgressObserver& progress) try {
    if (std::filesystem::exists(xml.parent_path() / "manifest.json"))
        return std::unexpected(OperationError{OperationStep::Validate, std::errc::not_supported,
            "backup manifest requires a physical restore backend"});
    auto parsed = PacParser::parse_xml(xml);
    if (!parsed) return std::unexpected(OperationError{OperationStep::Prepare, parsed.error(), platform::utf8_path(xml)});
    return prepare_parsed(*parsed, xml.parent_path(), parts, stop, progress);
} catch(...) {return std::unexpected(exception_error(OperationStep::Prepare));}

OperationResult<FlashPlan> Operations::prepare_parsed(const PacImage& parsed,
    const std::filesystem::path& base, std::span<const device::PartitionInfo> parts,
    std::stop_token stop, const ProgressObserver& progress,const DirectoryPrepareOptions& budget) {
    if (parsed.physical_snapshot)
        return std::unexpected(OperationError{OperationStep::Validate, std::errc::not_supported,
            "physical snapshots require a byte-preserving restore backend; named writes may transform NV and miscdata"});
    FlashPlan plan;
    uint64_t encoded_total=0;
    std::set<std::string> names;
    for (const auto& entry : parsed.partitions) {
        if (entry.has_checksum || entry.checksum)
            return std::unexpected(OperationError{OperationStep::Validate, std::errc::not_supported,
                entry.name + ": XML checksum algorithm is unspecified"});
        if (stop.stop_requested()) return std::unexpected(OperationError{OperationStep::Prepare, std::errc::interrupted, entry.name});
        if (!valid_name(entry.name) || !names.insert(entry.name).second)
            return std::unexpected(OperationError{OperationStep::Validate, std::errc::invalid_argument, entry.name});
        if (entry.file_path.empty() && !(entry.has_erase && entry.erase)) continue;
        auto named = find_partition(parts, entry.name);
        if (!named) return std::unexpected(named.error());
        uint64_t limit = named->unverified ? UINT64_MAX : named->size;
        if (!limit) return std::unexpected(OperationError{OperationStep::Validate, std::errc::invalid_argument, entry.name});
        if (!entry.file_path.empty()) {
            if (entry.has_size && !entry.size_remaining && !entry.size)
                return std::unexpected(OperationError{OperationStep::Validate, std::errc::invalid_argument,
                    entry.name + ": XML write size must be positive"});
            if (!entry.size_remaining && (entry.has_size || entry.size))
                limit = std::min(limit, entry.size);
            const bool nv=device::nv_pair(entry.name)!=nullptr;
            const auto encoded_limit=std::min(budget.max_encoded_file,budget.max_encoded_total-encoded_total);
            const auto source_limit=nv?std::min({encoded_limit,limit,uint64_t{16*1024*1024}}):encoded_limit;
            auto frozen=io::Image::prepare_blob(base/platform::path(entry.file_path),source_limit,stop,preparation(entry.name,progress));
            if(!frozen)return std::unexpected(OperationError{OperationStep::Prepare,frozen.error(),entry.name});
            encoded_total+=frozen->size();
            auto image=nv?frozen->blob_region(0,frozen->size()):frozen->region(0,frozen->size(),limit,stop,preparation(entry.name,progress));
            if (!image) return std::unexpected(OperationError{OperationStep::Prepare, image.error(), entry.name});
            if (image->size() > UINT64_MAX - plan.bytes_)
                return std::unexpected(OperationError{OperationStep::Validate, std::errc::value_too_large, entry.name});
            plan.bytes_ += image->size();
            WriteAction write{std::move(*image),entry.erase};
            plan.entries_.push_back({entry.name,std::move(write)});
        } else plan.entries_.push_back({entry.name,EraseAction{}});
    }
    if (plan.entries_.empty()) return std::unexpected(OperationError{OperationStep::Validate, std::errc::invalid_argument, "empty plan"});
    plan.phase_=PlanPhase::ReadyToExecute;
    return plan;
}

OperationResult<FlashPlan> Operations::prepare_write(device::SprdDevice& device,
    const std::string& name, const std::filesystem::path& image, std::stop_token stop,
    const ProgressObserver& progress) try {
    const std::string names[]{name};
    auto parts = PartitionAccess::capacities(device, names, stop, progress);
    if (!parts) return std::unexpected(parts.error());
    const auto token = device.layout_token();
    auto plan = prepare_write(name, image, *parts, stop, progress);
    if (plan) {
        plan->layout_token_ = token; plan->capacities_ = std::move(*parts);
        plan->prepared_at_ = std::chrono::steady_clock::now();
    }
    return plan;
} catch(...) {return std::unexpected(device_exception_error(device,OperationStep::Prepare));}

OperationResult<FlashPlan> Operations::prepare_flash(device::SprdDevice& device,
    const std::filesystem::path& xml, std::stop_token stop, const ProgressObserver& progress) try {
    if (std::filesystem::exists(xml.parent_path() / "manifest.json"))
        return std::unexpected(OperationError{OperationStep::Validate, std::errc::not_supported,
            "backup manifest requires a physical restore backend"});
    auto parsed = PacParser::parse_xml(xml);
    if (!parsed) return std::unexpected(OperationError{OperationStep::Prepare, parsed.error(), platform::utf8_path(xml)});
    if (parsed->physical_snapshot) return std::unexpected(OperationError{OperationStep::Validate,
        std::errc::not_supported, "physical snapshots need a byte-preserving restore backend"});
    std::vector<std::string> names;
    for (const auto& part : parsed->partitions) {
        if (part.has_checksum || part.checksum)
            return std::unexpected(OperationError{OperationStep::Validate, std::errc::not_supported,
                part.name + ": XML checksum algorithm is unspecified"});
        if (!part.file_path.empty() || (part.has_erase && part.erase)) names.push_back(part.name);
    }
    auto parts = PartitionAccess::capacities(device, names, stop, progress);
    if (!parts) return std::unexpected(parts.error());
    const auto token = device.layout_token();
    auto plan = prepare_parsed(*parsed, xml.parent_path(), *parts, stop, progress);
    if (plan) {
        plan->layout_token_ = token; plan->capacities_ = std::move(*parts);
        plan->prepared_at_ = std::chrono::steady_clock::now();
    }
    return plan;
} catch(...) {return std::unexpected(device_exception_error(device,OperationStep::Prepare));}

OperationResult<FlashPlan> Operations::prepare_directory(device::SprdDevice& device,
    const std::filesystem::path& directory, std::stop_token stop, const ProgressObserver& progress) {
    return prepare_directory(device,directory,DirectoryPrepareOptions{},stop,progress);
}
OperationResult<FlashPlan> Operations::prepare_directory(device::SprdDevice& device,
    const std::filesystem::path& directory,const DirectoryPrepareOptions& budget,std::stop_token stop,const ProgressObserver& progress) try {
    // Includes older raw-backup directories, whose XML predates semantics tags.
    std::error_code manifest_error;
    if (std::filesystem::exists(directory / "manifest.json", manifest_error))
        return std::unexpected(OperationError{OperationStep::Validate, std::errc::not_supported,
            "raw backup directory cannot be restored through named loader writes"});
    if (manifest_error) return std::unexpected(OperationError{OperationStep::Prepare,
        std::errc::io_error, "cannot inspect backup manifest: " + manifest_error.message()});
    const auto xml = directory / "layout.xml";
    auto parsed = PacParser::parse_xml(xml);
    if (!parsed) return std::unexpected(OperationError{OperationStep::Prepare, parsed.error(), platform::utf8_path(xml)});
    if(parsed->physical_snapshot)return std::unexpected(OperationError{OperationStep::Validate,std::errc::not_supported,
        "physical snapshot directories require restore-raw"});
    std::error_code root_error;
    const auto root=std::filesystem::canonical(directory,root_error);
    if(root_error)return std::unexpected(OperationError{OperationStep::Prepare,std::errc::io_error,"directory root"});
    std::vector<std::string> names;
    for (auto& part : parsed->partitions) {
        if (!valid_name(part.name))
            return std::unexpected(OperationError{OperationStep::Validate, std::errc::invalid_argument, part.name});
        if (part.file_path.empty()) part.file_path = io::partition_filename(part.name);
        const auto path = platform::path(part.file_path);
        if (path.is_absolute() || path.has_root_name() ||
            std::any_of(path.begin(), path.end(), [](const auto& component) { return component == ".."; }))
            return std::unexpected(OperationError{OperationStep::Validate, std::errc::invalid_argument,
                part.name + ": image path must be inside the directory"});
        std::error_code ec;
        const auto resolved=std::filesystem::canonical(root/path,ec);
        bool inside=false;
        if(!ec)for(auto parent=resolved.parent_path();!parent.empty();) {
            std::error_code identity;
            if(std::filesystem::equivalent(parent,root,identity) && !identity){inside=true;break;}
            auto next=parent.parent_path();if(next==parent)break;parent=std::move(next);
        }
        if(!inside)return std::unexpected(OperationError{OperationStep::Prepare,std::errc::invalid_argument,
            part.name+": source resolves outside directory or is unavailable"});
        if (!std::filesystem::is_regular_file(resolved, ec))
            return std::unexpected(OperationError{OperationStep::Prepare,
                ec ? (ec.default_error_condition().category() == std::generic_category()
                    ? static_cast<std::errc>(ec.default_error_condition().value()) : std::errc::io_error)
                    : std::errc::no_such_file_or_directory,
                part.name + ": " + platform::utf8_path(directory / path)});
        part.file_path=platform::utf8_path(resolved);
        // Directory write is a write-only batch, never an erase/repartition request.
        part.erase = false;
        part.has_erase = false;
        names.push_back(part.name);
    }
    // Freeze every file before discovery or any NV device reads. Unknown
    // capacities here are resolved and checked for the entire batch below.
    std::vector<device::PartitionInfo> local_parts;
    for(const auto& name:names) {device::PartitionInfo p;p.name=name;p.unverified=true;local_parts.push_back(std::move(p));}
    auto plan=prepare_parsed(*parsed,root,local_parts,stop,progress,budget);
    if(!plan)return plan;
    struct NvInput {std::string primary;std::vector<uint8_t> payload;size_t entry;bool has_primary;};
    std::vector<NvInput> nv_inputs;
    std::set<size_t> redundant;
    for(size_t i=0;i<plan->entries_.size();++i) {
        const auto& entry=plan->entries_[i];const auto* pair=device::nv_pair(entry.partition);
        if(!pair)continue;
        auto payload=NvRestore::decode_snapshot(entry.write()->image,device::nv_payload_size(device.profile().nv_dialect),stop);
        if(!payload)return std::unexpected(payload.error());
        auto previous=std::find_if(nv_inputs.begin(),nv_inputs.end(),[&](const auto& v){return v.primary==pair->primary;});
        if(previous!=nv_inputs.end()) {
            if(previous->payload!=*payload)return std::unexpected(OperationError{OperationStep::Validate,std::errc::bad_message,
                "directory NV primary/backup payloads disagree: "+std::string(pair->primary)});
            if(entry.partition==pair->primary) {
                redundant.insert(previous->entry);previous->entry=i;previous->has_primary=true;
            } else redundant.insert(i);
        } else nv_inputs.push_back({std::string(pair->primary),std::move(*payload),i,entry.partition==pair->primary});
    }
    for(const auto& nv:nv_inputs) {
        if(!nv.has_primary)return std::unexpected(OperationError{OperationStep::Validate,std::errc::invalid_argument,
            "directory NV requires explicit primary image: "+nv.primary});
        const auto* pair=device::nv_pair(nv.primary);
        names.push_back(std::string(pair->primary));names.push_back(std::string(pair->backup));
    }
    auto parts=PartitionAccess::capacities(device,names,stop,progress);
    if(!parts)return std::unexpected(parts.error());
    for(const auto& entry:plan->entries_) {
        auto part=find_partition(*parts,entry.partition);
        if(!part)return std::unexpected(part.error());
        if(!part->unverified && (!part->size || entry.write()->image.size()>part->size))
            return std::unexpected(OperationError{OperationStep::Validate,std::errc::file_too_large,entry.partition});
        if(!device::nv_pair(entry.partition) && entry.write()->image.size()>UINT32_MAX &&
            !device.profile().framed_write_u64 && !(device.profile().allow_whole_file_raw && device.da_info().valid && device.da_info().support_raw))
            return std::unexpected(OperationError{OperationStep::Validate,std::errc::file_too_large,entry.partition});
    }
    for(const auto& nv:nv_inputs) {
        const auto* pair=device::nv_pair(nv.primary);
        for(auto name:{pair->primary,pair->backup}) {
            auto part=find_partition(*parts,std::string(name));
            if(!part || part->unverified || part->size<nv.payload.size()+512)
                return std::unexpected(OperationError{OperationStep::Validate,std::errc::not_supported,"NV pair capacity: "+std::string(name)});
        }
    }
    // NV dedicated transactions regenerate headers and update both copies.
    // Equal supplied mirror payloads are one operation, never two overwrites.
    for(auto& nv:nv_inputs) {
        auto prepared=NvRestore::prepare_payload(device,nv.primary,nv.payload,stop);
        if(!prepared)return std::unexpected(prepared.error());
        plan->entries_[nv.entry]={nv.primary,PhysicalNvAction{std::make_shared<NvRestorePlan>(std::move(*prepared))}};
    }
    for(auto i=redundant.rbegin();i!=redundant.rend();++i)plan->entries_.erase(plan->entries_.begin()+*i);
    plan->bytes_=0;
    for(const auto& entry:plan->entries_) {
        const auto size=entry.physical_nv()?entry.physical_nv()->plan()->size():entry.write()->image.size();
        if(size>UINT64_MAX-plan->bytes_)return std::unexpected(OperationError{OperationStep::Validate,std::errc::value_too_large,"directory total"});
        plan->bytes_+=size;
    }
    plan->nv_batch_=!nv_inputs.empty();plan->connection_=device.connection_token();
    plan->phase_=plan->nv_batch_?PlanPhase::ReadyToPersist:PlanPhase::ReadyToExecute;
    plan->layout_token_=device.layout_token();plan->capacities_=std::move(*parts);
    plan->prepared_at_=std::chrono::steady_clock::now();return plan;
} catch(...) {return std::unexpected(device_exception_error(device,OperationStep::Prepare));}

OperationResult<FlashPlan> Operations::prepare_pac(device::SprdDevice& device,
    const std::filesystem::path& path, std::stop_token stop, const ProgressObserver& progress) {
    return prepare_pac_with_options(device,path,PacPrepareOptions{},stop,progress);
}
OperationResult<FlashPlan> Operations::prepare_pac_with_options(device::SprdDevice& device,
    const std::filesystem::path& path,const PacPrepareOptions& options,std::stop_token stop,const ProgressObserver& progress) try {
    // Archive parsing is local; selected_actions resolves storage requirements.
    auto archive = PacArchive::open(path, 0, stop, preparation("PAC", progress));
    if (!archive) return std::unexpected(OperationError{OperationStep::Prepare, archive.error(),
        "PAC structure, checksum or selected operation unsupported"});
    return prepare_pac_with_options(device, *archive, options, stop, progress);
} catch(...) {return std::unexpected(device_exception_error(device,OperationStep::Prepare));}
OperationResult<FlashPlan> Operations::prepare_pac(device::SprdDevice& device,
    const PacArchive& archive, std::stop_token stop, const ProgressObserver& progress) {
    return prepare_pac_with_options(device,archive,PacPrepareOptions{},stop,progress);
}
OperationResult<FlashPlan> Operations::prepare_pac_with_options(device::SprdDevice& device,
    const PacArchive& archive,const PacPrepareOptions& options,std::stop_token stop,const ProgressObserver& progress) {
    return prepare_package(device,archive,options,stop,progress);
}
OperationResult<CompiledPac> PacCompiler::compile_physical(const PacArchive& archive,const PacPrepareOptions& options,
    const device::DeviceProfile& profile,const device::SessionCapabilities& capabilities,
    std::stop_token stop,const ProgressObserver& progress) {
    if(options.address_word_order || options.authentication || options.factory_timestamp || options.factory_write_efuse ||
        !options.vpac_utf16le.empty() || !options.softsim_expected_eid.empty())
        return std::unexpected(OperationError{OperationStep::Validate,std::errc::not_supported,
            "product factory/auth options require standard PAC execution"});
    const auto representations=options.nv_representations;
    auto actions = archive.selected_actions(capabilities.storage);
    if (!actions) return std::unexpected(OperationError{OperationStep::Validate,actions.error(),"PAC storage selection"});
    if(std::any_of(actions->begin(),actions->end(),[](const auto& a){return pac_address_operation(a.type) || pac_read_operation(a.type) || pac_control_operation(a.type);}))
        return std::unexpected(OperationError{OperationStep::Validate,std::errc::not_supported,
            "PAC read operations require package-directed execution"});
    // Enhanced recovery has device-dependent capacity checks, but corrupt
    // local images must still fail before any discovery/repair-capable read.
    CompiledPac compiled(archive);compiled.options_=options;compiled.profile_=profile;compiled.capabilities_=capabilities;
    for(const auto& action:*actions) if(!action.erase) {
        const auto limit=action.type=="NV_COMM"?uint64_t(device::nv_payload_size(profile.nv_dialect)):UINT64_MAX;
        auto image=archive.image(action,limit,stop,preparation(action.id,progress));
        if(!image)return std::unexpected(OperationError{OperationStep::Prepare,image.error(),action.id});
        CompiledPac::PhysicalImage local{std::move(*image),0,{}};
        if(action.type!="NV_COMM") {
            auto checked=prepare_pac_image_contract(action.partition,local.bytes,profile,stop);
            if(!checked)return std::unexpected(OperationError{OperationStep::Validate,checked.error(),action.id});
            local.verify_size=checked->verify_size;local.verify_targets=std::move(checked->verify_targets);
        }
        compiled.physical_images_.emplace(action.id,std::move(local));
    }
    std::set<std::string> configured;
    const auto valid_order=[](NvByteOrder order) {
        return order==NvByteOrder::Little || order==NvByteOrder::BigItemHeaders ||
            order==NvByteOrder::ReversedWords || order==NvByteOrder::LittleIndexBigItemHeaders;
    };
    for(const auto& representation:representations) {
        if((representation.logical_size && representation.logical_size!=device::nv_payload_size(profile.nv_dialect)) ||
            !configured.insert(representation.partition).second || !valid_order(representation.device_order) ||
            !valid_order(representation.template_order) || std::none_of(actions->begin(),actions->end(),[&](const auto& action) {
                return action.partition==representation.partition && action.type=="NV_COMM";
            })) return std::unexpected(OperationError{OperationStep::Validate,std::errc::invalid_argument,
                "PAC NV representation has duplicate, invalid or unselected target: "+representation.partition});
    }
    for(const auto& action:*actions) if(action.type=="NV_COMM") {
        const auto& image=compiled.physical_images_.at(action.id).bytes;
        std::vector<uint8_t> bytes(static_cast<size_t>(image.size()));
        auto read=image.reader()(0,bytes,stop);
        if(!read)return std::unexpected(OperationError{OperationStep::Prepare,read.error(),action.id});
        const auto size=device::nv_payload_size(profile.nv_dialect);
        auto padded=bytes;padded.resize(size,0xff);
        const auto representation=std::find_if(representations.begin(),representations.end(),[&](const auto& r){return r.partition==action.partition;});
        const auto order=representation==representations.end()?NvByteOrder::Little:representation->template_order;
        if(representation!=representations.end() && (representation->device_order==NvByteOrder::ReversedWords || order==NvByteOrder::ReversedWords) &&
            ((size%4) || (bytes.size()%4)))return std::unexpected(OperationError{OperationStep::Validate,std::errc::message_size,"NV reversed alignment: "+action.id});
        auto contract=validate_nv_merge_rules(action.nv_items,representation==representations.end()?NvByteOrder::Little:representation->device_order,order);
        if(!contract)return std::unexpected(OperationError{OperationStep::Validate,contract.error(),"NV representation contract: "+action.id});
        auto merged=nv_merge_items(padded,bytes,size,action.nv_items,order,order);
        if(!merged)return std::unexpected(OperationError{OperationStep::Validate,merged.error(),"NV template: "+action.id});
    }
    for (const auto& action : *actions) {
        if(!action.erase && action.type!="NV_COMM" && device::nv_pair(action.partition))
            return std::unexpected(OperationError{OperationStep::Validate,std::errc::not_supported,"NV requires NV_COMM: "+action.id});
        if(action.erase) {
            const auto* pair=device::nv_pair(action.partition);
            if(pair && std::any_of(actions->begin(),actions->end(),[&](const auto& a){return a.type=="NV_COMM" && a.partition==pair->primary;}))
                return std::unexpected(OperationError{OperationStep::Validate,std::errc::not_supported,
                    "PAC both erases and merges the same NV pair: "+action.partition});
        }
    }
    compiled.actions_=std::move(*actions);return compiled;
}
OperationResult<FlashPlan> PacResolver::resolve_physical(device::SprdDevice& device,const CompiledPac& compiled,
    std::stop_token stop,const ProgressObserver& progress) {
    const auto& archive=compiled.archive_;const auto* actions=&compiled.actions_;
    const auto& representations=compiled.options_.nv_representations;
    std::vector<std::string> names;
    for(const auto& action:*actions) {
        names.push_back(action.partition);
        if(action.partition=="splloader") names.push_back("splloader_bak");
    }
    auto parts = PartitionAccess::capacities(device, names, stop, progress);
    if (!parts) return std::unexpected(parts.error());
    FlashPlan plan;
    auto physical=PhysicalAccess::open(device,stop);
    if(!physical) return std::unexpected(OperationError{OperationStep::Validate,physical.error(),"PAC requires physical GPT readback"});
    plan.pac_=true;plan.physical_=std::move(*physical); plan.connection_=device.connection_token();
    // The capacity list and physical evidence must describe the same layout.
    for(const auto& partition:plan.physical_->layout().partitions) {
        auto found=std::find_if(parts->begin(),parts->end(),[&](const auto& p){return p.name==partition.name;});
        if(found==parts->end() || found->size!=partition.size || found->offset!=partition.offset || found->unverified)
            return std::unexpected(OperationError{OperationStep::Validate,std::errc::state_not_recoverable,"PAC capacity/layout evidence mismatch"});
    }
    plan.backup_targets_=archive.backup_targets();
    for(const auto& name:plan.backup_targets_) {
        const auto& entries=plan.physical_->layout().partitions;
        if(std::none_of(entries.begin(),entries.end(),[&](const auto& p){return p.name==name && p.size;}))
            return std::unexpected(OperationError{OperationStep::Validate,std::errc::not_supported,"PAC backup target missing: "+name});
    }
    const auto& requested=archive.partition_layout();
    std::vector<std::string> replaced;
    // Replaced regions use package images; other moved regions must be frozen
    // and restored through an established byte-preserving route below.
    for(const auto& action:*actions) if(!action.erase && action.type!="NV_COMM") {
        replaced.push_back(action.partition);
        if(device.profile().mirrors_signed_boot_images && mirrored_boot_target(action.partition) && action.partition!="splloader")
            replaced.push_back(action.partition+"_bak");
    }
    const auto& disk=plan.physical_->layout();
    auto layout_plan=prepare_pac_layout(disk,requested,archive.repartition_strategy(),replaced);
    if(!layout_plan) return std::unexpected(OperationError{OperationStep::Validate,layout_plan.error(),
        "PAC layout policy cannot preserve unselected regions"});
    for(const auto& source:layout_plan->relocate) {
        if(std::any_of(actions->begin(),actions->end(),[&](const auto& a){return a.partition==source.name;}))
            return std::unexpected(OperationError{OperationStep::Validate,std::errc::not_supported,
                "relocation overlaps an explicit package operation: "+source.name});
        // These named write routes rebuild headers, mirror other partitions or
        // erase metadata. They need specialized relocation, not raw replay.
        if(device::nv_pair(source.name) || source.name=="miscdata" || source.name=="userdata" || source.name=="splloader" ||
            source.name=="splloader_bak" || source.name=="uboot" || source.name=="uboot_bak" ||
            source.name=="trustos" || source.name=="trustos_bak" || source.name=="sml" ||
            source.name=="sml_bak" || source.name=="vbmeta" || source.name=="vbmeta_bak" ||
            source.name=="teecfg" || source.name=="teecfg_bak") return std::unexpected(OperationError{
                OperationStep::Validate,std::errc::not_supported,"special partition relocation contract required: "+source.name});
        if(!device.profile().raw_partition_relocation || (source.size>UINT32_MAX && !device.profile().framed_write_u64))
            return std::unexpected(OperationError{OperationStep::Validate,std::errc::not_supported,"relocation write contract: "+source.name});
        if(!protocol::valid_partition_name(source.name)) return std::unexpected(OperationError{
            OperationStep::Validate,std::errc::not_supported,"relocation name is not representable: "+source.name});
        plan.relocation_sources_.push_back(source);
        if(std::find(plan.backup_targets_.begin(),plan.backup_targets_.end(),source.name)==plan.backup_targets_.end())
            plan.backup_targets_.push_back(source.name);
    }
    std::set<std::string> backup_files;
    for(const auto& target:plan.backup_targets_) {
        auto file=io::partition_filename(target);
        for(auto& c:file) if(c>='A' && c<='Z') c+=32;
        if(!backup_files.insert(file).second) return std::unexpected(OperationError{
            OperationStep::Validate,std::errc::invalid_argument,"PAC recovery filenames collide: "+target});
    }
    if(!layout_plan->table.empty()) {
        if(!device.profile().legacy_gpt_rebuild || device.da_info().storage!=0x102)
            return std::unexpected(OperationError{OperationStep::Validate,std::errc::not_supported,"PAC repartition firmware contract"});
        if(requested.partitions.size()>device.profile().gpt_max_entries || std::any_of(requested.partitions.begin(),requested.partitions.end(),
            [&](const auto& p){return p.name.size()>device.profile().gpt_max_name;})) return std::unexpected(OperationError{
                OperationStep::Validate,std::errc::not_supported,"PAC GPT receiver limits"});
        // Recovery through v0 must itself be representable, not merely exported.
        PacImage restore; restore.legacy_gpt=true; restore.disk_size=disk.disk_bytes;
        auto ordered=disk.partitions;
        std::sort(ordered.begin(),ordered.end(),[](const auto& a,const auto& b){return a.offset<b.offset;});
        for(const auto& p:ordered) {
            if(p.offset+p.size!=(disk.header.last_usable+1)*512 && (p.offset+p.size)/512>=disk.header.last_usable)
                return std::unexpected(OperationError{OperationStep::Validate,std::errc::not_supported,"original GPT endpoint cannot round-trip through v0"});
            PacPartition entry; entry.name=p.name; entry.has_address=true; entry.flash_addr=p.offset;
            entry.size=p.offset+p.size==(disk.header.last_usable+1)*512?UINT64_MAX:p.size;
            restore.partitions.push_back(std::move(entry));
        }
        auto restored=layout::build_partition_table(restore);
        if(!restored) return std::unexpected(OperationError{OperationStep::Validate,restored.error(),"original GPT cannot be restored through v0"});
        if(restore.partitions.size()>device.profile().gpt_max_entries || std::any_of(restore.partitions.begin(),restore.partitions.end(),
            [&](const auto& p){return p.name.size()>device.profile().gpt_max_name;})) return std::unexpected(OperationError{
                OperationStep::Validate,std::errc::not_supported,"original GPT exceeds recovery receiver limits"});
        plan.repartition_table_=std::move(layout_plan->table);
        plan.expected_layout_=std::move(layout_plan->expected);
        auto xml=layout::make_layout_xml(disk);
        if(!xml) return std::unexpected(OperationError{OperationStep::Prepare,xml.error(),"PAC recovery layout"});
        const auto root=xml->find("<rom ");
        if(root==std::string::npos) return std::unexpected(OperationError{OperationStep::Prepare,std::errc::bad_message,"PAC recovery XML"});
        xml->insert(root+5,"repartition_format=\"legacy-gpt\" "); plan.recovery_layout_=std::move(*xml);
        // All subsequent image capacity checks use the post-repartition layout.
        std::erase_if(*parts,[](const auto& p){return !p.hw_boot;});
        for(const auto& p:plan.expected_layout_->partitions) parts->push_back({p.name,p.size,p.offset,false,false,0});
        log_status(LogLevel::Info,"PAC repartition",layout_plan->changed?
            "layout changes; preserved regions backed up before relocation; GUIDs may change":
            "required by package strategy; geometry retained, GUIDs may change");
    }
    for (const auto& action : *actions) {
        if (device::nv_pair(action.partition) && action.type!="NV_COMM" && !action.erase) return std::unexpected(OperationError{
            OperationStep::Validate,std::errc::not_supported,"NV target requires a prepared NV transaction: " + action.id});
        auto part = PartitionAccess::find(*parts, action.partition);
        if (!part) return std::unexpected(part.error());
        if((device.da_info().storage==0x102 || device.profile().ufs_boot_roles) &&
            (action.partition=="splloader" || action.partition=="splloader_bak") && !part->hw_boot)
            return std::unexpected(OperationError{OperationStep::Validate,std::errc::not_supported,"ambiguous GPT/hardware SPL target"});
        if (action.type=="NV_COMM") {
            if(action.length>device::nv_payload_size(device.profile().nv_dialect)) return std::unexpected(OperationError{
                OperationStep::Validate,std::errc::not_supported,"NV loader/size contract: "+action.id});
            const auto& source=compiled.physical_images_.at(action.id).bytes;
            std::vector<uint8_t> bytes(static_cast<size_t>(source.size()));
            auto got=source.reader()(0,bytes,stop);
            if(!got) return std::unexpected(OperationError{OperationStep::Prepare,got.error(),action.id});
            const auto representation=std::find_if(representations.begin(),representations.end(),[&](const auto& r) {
                return r.partition==action.partition;
            });
            auto nv=NvRestore::prepare_merge(device,action.partition,bytes,action.nv_items,stop,
                representation==representations.end()?NvByteOrder::Little:representation->device_order,
                representation==representations.end()?NvByteOrder::Little:representation->template_order);
            if(!nv) return std::unexpected(nv.error());
            if(nv->size()>UINT64_MAX-plan.bytes_) return std::unexpected(OperationError{
                OperationStep::Validate,std::errc::value_too_large,"PAC byte count"});
            plan.bytes_+=nv->size();
            plan.entries_.push_back({action.partition,PhysicalNvAction{std::make_shared<NvRestorePlan>(std::move(*nv))}});
        } else if (!action.erase) {
            const auto& local=compiled.physical_images_.at(action.id);
            if(!part->unverified && local.bytes.size()>part->size)
                return std::unexpected(OperationError{OperationStep::Validate,std::errc::file_too_large,action.id});
            if (local.bytes.size() > UINT64_MAX - plan.bytes_)
                return std::unexpected(OperationError{OperationStep::Validate, std::errc::value_too_large, action.id});
            plan.bytes_ += local.bytes.size();
            WriteAction write{local.bytes};
            if(plan.expected_layout_) {
                const auto& original=plan.physical_->layout().partitions;
                const auto before=std::find_if(original.begin(),original.end(),[&](const auto& p){return p.name==action.partition;});
                const bool moved=!part->hw_boot && (before==original.end() || before->offset!=part->offset || before->size!=part->size);
                if(moved && write.image.size()!=part->size)
                    return std::unexpected(OperationError{OperationStep::Validate,std::errc::not_supported,
                        "PAC moved/resized region requires a full replacement image: "+action.partition});
            }
            write.verify_size=local.verify_size;write.verify_targets=local.verify_targets;
            for(const auto& target:write.verify_targets) {
                auto found=PartitionAccess::find(*parts,target);
                if(!found || found->unverified || !found->size || found->size<write.verify_size)
                    return std::unexpected(OperationError{OperationStep::Validate,std::errc::not_supported,"PAC readback capacity: "+target});
                if(plan.expected_layout_ && target!=action.partition && !found->hw_boot) {
                    const auto& original=plan.physical_->layout().partitions;
                    const auto before=std::find_if(original.begin(),original.end(),[&](const auto& p){return p.name==target;});
                    if((before==original.end() || before->offset!=found->offset || before->size!=found->size) &&
                        write.verify_size!=found->size)
                        return std::unexpected(OperationError{OperationStep::Validate,std::errc::not_supported,
                            "PAC moved mirror requires a full replacement: "+target});
                }
            }
            plan.entries_.push_back({action.partition,std::move(write)});
        } else plan.entries_.push_back({action.partition,EraseAction{}});
    }
    for(size_t i=0;i<plan.entries_.size();++i) {
        const auto& entry=plan.entries_[i];
        for(size_t j=0;j<plan.entries_.size();++j) if(i!=j) {
            const auto& other=plan.entries_[j];
            if(entry.write() && j>i && other.erases() && other.partition==entry.partition)
                return std::unexpected(OperationError{OperationStep::Validate,std::errc::invalid_argument,
                    "PAC erases a previously written image: "+entry.partition});
            if(entry.physical_nv()) {
                const auto* pair=device::nv_pair(entry.partition);
                if(pair && (other.partition==pair->primary || other.partition==pair->backup))
                    return std::unexpected(OperationError{OperationStep::Validate,std::errc::invalid_argument,"PAC overlaps an NV pair transaction"});
            }
            for(const auto& target:entry.verification_targets()) if(target!=entry.partition && other.partition==target)
                return std::unexpected(OperationError{OperationStep::Validate,std::errc::invalid_argument,"PAC explicitly modifies an implicitly mirrored target: "+target});
        }
    }
    plan.layout_token_ = device.layout_token(); plan.capacities_ = std::move(*parts);
    plan.prepared_at_ = std::chrono::steady_clock::now();
    plan.phase_=PlanPhase::ReadyToPersist;
    log_status(LogLevel::Info, "PAC", archive.product(), std::to_string(plan.entries_.size()) + " operations");
    return plan;
}

OperationResult<> Operations::save_pac_recovery(device::SprdDevice& device,FlashPlan& plan,
    const std::filesystem::path& directory,std::stop_token stop,const ProgressObserver& progress) {
    return PacRecoveryStore::save(device,plan,directory,stop,progress);
}
OperationResult<> Operations::save_recovery(device::SprdDevice& device,FlashPlan& plan,
    const std::filesystem::path& directory,std::stop_token stop,const ProgressObserver& progress) {
    return PacRecoveryStore::save(device,plan,directory,stop,progress);
}
OperationResult<> PacRecoveryStore::save(device::SprdDevice& device,FlashPlan& plan,
    const std::filesystem::path& directory,std::stop_token stop,const ProgressObserver& progress) try {
    if(!plan.requires_recovery() || plan.phase_!=PlanPhase::ReadyToPersist) return std::unexpected(OperationError{
        OperationStep::Validate,std::errc::operation_not_permitted,"recovery already prepared or plan consumed"});
    // A failed save can leave partial recovery material. Re-prepare instead of
    // reusing a half-mutated plan or overwriting evidence from that attempt.
    plan.phase_=PlanPhase::Persisting;
    if(stop.stop_requested()) return std::unexpected(OperationError{OperationStep::Save,std::errc::interrupted,"recovery backup cancelled"});
    if(plan.connection_!=device.connection_token()) return std::unexpected(OperationError{
        OperationStep::Validate,std::errc::state_not_recoverable,"recovery backup connection changed"});
    if(plan.package_execution_) return save_package(device,plan,directory,stop,progress);
    if(plan.nv_batch_) {
        std::error_code ec;
        if(!std::filesystem::create_directory(directory,ec))return std::unexpected(OperationError{
            OperationStep::Save,ec?std::errc::io_error:std::errc::file_exists,"directory NV recovery must be new"});
        std::string listing="Directory write with dedicated NV transactions; NV tails are not restored.\n";
        for(const auto& entry:plan.entries_)listing+=entry.partition+" "+operation_name(entry.action)+"\n";
        auto saved=Journal::write(directory/"plan.txt",listing,"directory plan",stop);if(!saved)return saved;
    }
    if(plan.physical_) {
        auto current=PhysicalAccess::open(device,stop);
        if(!current || current->layout().primary_sector!=plan.physical_->layout().primary_sector ||
            current->layout().entries!=plan.physical_->layout().entries)
            return std::unexpected(OperationError{OperationStep::Validate,
                current?std::errc::state_not_recoverable:current.error(),"PAC layout changed before recovery backup"});
        std::error_code ec;
        if(!std::filesystem::create_directory(directory,ec)) return std::unexpected(OperationError{
            OperationStep::Save,ec?std::errc::io_error:std::errc::file_exists,"PAC recovery directory must be new"});
        const auto save=[&](const char* name,std::span<const uint8_t> bytes)->OperationResult<> {
            return Journal::write(directory/name,bytes,name,stop);
        };
        auto r=save("original-gpt-header.bin",plan.physical_->layout().primary_sector);
        if(r) r=save("original-gpt-entries.bin",plan.physical_->layout().entries);
        if(r && !plan.repartition_table_.empty()) r=save("repartition-table.bin",plan.repartition_table_);
        if(r && !plan.recovery_layout_.empty()) r=save("restore-layout.xml",std::span(
            reinterpret_cast<const uint8_t*>(plan.recovery_layout_.data()),plan.recovery_layout_.size()));
        if(!r) return r;
        const auto& header=plan.physical_->layout().header;
        auto secondary=plan.physical_->read_small(device,header.alternate_lba*header.sector_size,header.sector_size,stop);
        if(!secondary) return std::unexpected(OperationError{OperationStep::Read,secondary.error(),"PAC backup GPT evidence"});
        auto parsed=layout::parse_gpt_header(*secondary,header.sector_size,header.alternate_lba);
        if(!parsed || !layout::matching_gpt_headers(header,*parsed)) return std::unexpected(OperationError{
            OperationStep::Validate,std::errc::bad_message,"PAC backup GPT changed"});
        auto entries=plan.physical_->read_small(device,parsed->entries_lba*header.sector_size,plan.physical_->layout().entries.size(),stop);
        if(!entries || *entries!=plan.physical_->layout().entries) return std::unexpected(OperationError{
            OperationStep::Validate,entries?std::errc::bad_message:entries.error(),"PAC backup GPT entries changed"});
        if(r) r=save("original-backup-gpt-header.bin",*secondary);
        if(r) r=save("original-backup-gpt-entries.bin",*entries);
        if(!r) return r;
        for(const auto& name:plan.backup_targets_) {
            const auto& parts=plan.physical_->layout().partitions;
            const auto found=std::find_if(parts.begin(),parts.end(),[&](const auto& p){return p.name==name;});
            if(found==parts.end()) return std::unexpected(OperationError{OperationStep::Validate,std::errc::bad_message,name});
            auto out=io::AtomicOutput::open(directory/platform::path("before-"+io::partition_filename(name)));
            if(!out) return std::unexpected(OperationError{OperationStep::Save,out.error(),name});
            io::BufferedOutput buffered(*out);
            auto read=plan.physical_->read(device,found->offset,found->size,[&](auto bytes,auto token) {
                auto saved=buffered.write(bytes,token);
                if(saved && progress) progress({OperationStep::Read,name,buffered.accepted(),found->size,"PAC pre-backup"});
                return saved;
            },stop);
            if(!read) return std::unexpected(OperationError{OperationStep::Read,read.error(),"PAC pre-backup: "+name});
            auto drained=buffered.finish(stop);
            if(!drained) return std::unexpected(OperationError{OperationStep::Save,drained.error(),name});
            if(out->size()!=found->size) return std::unexpected(OperationError{OperationStep::Save,std::errc::message_size,name});
            auto committed=commit_output(*out,name);
            if(!committed) return committed;
        }
        for(const auto& source:plan.relocation_sources_) {
            const auto file=directory/platform::path("before-"+io::partition_filename(source.name));
            auto frozen=io::Image::prepare_blob(file,source.size,stop);
            if(!frozen || frozen->size()!=source.size) return std::unexpected(OperationError{OperationStep::Prepare,
                frozen?std::errc::message_size:frozen.error(),"relocation snapshot: "+source.name});
            // Ordinary named routes can still be security-sensitive even when
            // they are not mirrored: retain the conservative BTHD rejection.
            auto relocation_profile=device.profile();relocation_profile.bthd_alias_replay=false;
            auto replay=validate_raw_replay(frozen->reader(),frozen->size(),relocation_profile,stop);
            if(!replay) return std::unexpected(OperationError{OperationStep::Validate,replay.error(),
                "relocation bytes trigger a loader image transformation: "+source.name});
            WriteAction write{std::move(*frozen)};
            write.verify_targets={source.name};write.verify_size=source.size;
            if(source.size>UINT64_MAX-plan.bytes_) return std::unexpected(OperationError{OperationStep::Validate,std::errc::value_too_large,"relocation bytes"});
            plan.relocations_.push_back({source.name,std::move(write)});
        }
        // Every source has been frozen before any destination is overwritten;
        // cycles and overlapping old/new ranges are therefore safe to order.
        std::string description="PAC recovery evidence. Physical backups are not ordinary named-write images.\n"
            "Repartition is never retried automatically. GPT restoration preserves names/geometry, not original GUIDs/attributes.\n"
            "Restoring an old GPT does not roll back image writes to moved partitions. Do not replay a failed batch blindly.\n";
        for(const auto& name:plan.backup_targets_) description+="Physical pre-backup: "+name+"\n";
        r=save("recovery.txt",std::span(reinterpret_cast<const uint8_t*>(description.data()),description.size()));
        if(!r) return r;
        std::string listing="PAC execution order (all sources frozen before execution):\n";
        if(!plan.repartition_table_.empty()) listing+="0. repartition; verify primary and backup GPT\n";
        size_t i=1;
        for(const auto& entry:plan.relocations_) {
            listing+=std::to_string(i++)+". "+entry.partition+" relocate preserved bytes, write/readback\n";
            listing+="   snapshot: before-"+io::partition_filename(entry.partition)+
                " bytes="+std::to_string(entry.write()->verify_size)+"\n";
        }
        for(const auto& entry:plan.entries_) {
            listing+=std::to_string(i++)+". "+entry.partition+" "+
                operation_name(entry.action)+"\n";
            if(entry.write()) listing+="   source bytes: "+std::to_string(entry.write()->image.size())+"\n";
            for(const auto& target:entry.verification_targets()) {
                const auto found=std::find_if(plan.capacities_.begin(),plan.capacities_.end(),[&](const auto& p){return p.name==target;});
                listing+="   verify: "+target+" size="+std::to_string(entry.write()->verify_size);
                if(found!=plan.capacities_.end()) listing+=found->hw_boot?" hardware":" physical-offset="+std::to_string(found->offset);
                listing+='\n';
            }
        }
        r=save("plan.txt",std::span(reinterpret_cast<const uint8_t*>(listing.data()),listing.size()));
        if(!r) return r;
    }
    for(size_t i=0;i<plan.entries_.size();++i) if(const auto* nv=plan.entries_[i].physical_nv()) {
        if(stop.stop_requested())return std::unexpected(OperationError{OperationStep::Save,std::errc::interrupted,"NV batch recovery cancelled"});
        auto saved=NvRestore::save_recovery(*nv->plan_,directory/("pac-nv-"+std::to_string(i)));
        if(!saved) return saved;
    }
    uint64_t total=plan.bytes_;
    for(const auto& entry:plan.relocations_) {
        if(entry.write()->verify_size>UINT64_MAX-total) return std::unexpected(OperationError{
            OperationStep::Validate,std::errc::value_too_large,"relocation total bytes"});
        total+=entry.write()->verify_size;
    }
    if(!plan.relocations_.empty()) {
        plan.entries_.insert(plan.entries_.begin(),std::make_move_iterator(plan.relocations_.begin()),
            std::make_move_iterator(plan.relocations_.end()));
        plan.relocations_.clear();
    }
    plan.bytes_=total;
    if(stop.stop_requested())return std::unexpected(OperationError{OperationStep::Save,std::errc::interrupted,"recovery cancelled"});
    auto sealed=Journal::seal_directory(directory);if(!sealed)return sealed;
    plan.journal_directory_=std::filesystem::absolute(directory);
    plan.phase_=PlanPhase::ReadyToExecute;
    return {};
} catch(...) {return std::unexpected(device_exception_error(device,OperationStep::Save));}

OperationResult<OperationReport> Operations::execute(device::SprdDevice& device,
    const FlashPlan& plan, std::stop_token stop, const ProgressObserver& progress,
    const EraseScopeFactory& acquire_erase_scope) {
    return PlanExecutor::execute(device,plan,stop,progress,acquire_erase_scope);
}
OperationResult<OperationReport> PlanExecutor::execute(device::SprdDevice& device,
    const FlashPlan& plan, std::stop_token stop, const ProgressObserver& progress,
    const EraseScopeFactory& acquire_erase_scope) try {
    // Acquire ownership before any callbacks or I/O. Callers serialize access;
    // this also rejects same-thread observer reentrancy during preflight.
    if(plan.phase_!=PlanPhase::ReadyToExecute ||
        (plan.requires_recovery() && plan.connection_!=device.connection_token()))
        return std::unexpected(OperationError{OperationStep::Validate,std::errc::operation_not_permitted,"plan not executable"});
    plan.phase_=PlanPhase::Validating;
    struct Release {
        PlanPhase& phase;
        ~Release(){if(phase==PlanPhase::Validating)phase=PlanPhase::ReadyToExecute;}
    } release{plan.phase_};
    OperationStep active_step=OperationStep::Validate;
    const auto invoke=[&](const ProgressObserver& observer)->OperationResult<OperationReport> {
        try {return run(device,plan,stop,observer,acquire_erase_scope,active_step);}
        catch(...) {return std::unexpected(device_exception_error(device,active_step));}
    };
    if(!plan.requires_recovery()) return invoke(progress);
    const auto record=[&](std::string_view text)->OperationResult<> {
        try {return Journal::write(plan.journal_directory_/"execution.txt",text,"PAC journal");}
        catch(const std::bad_alloc&) {return std::unexpected(OperationError{OperationStep::Save,std::errc::not_enough_memory,"PAC journal"});}
        catch(...) {return std::unexpected(OperationError{OperationStep::Save,std::errc::io_error,"PAC journal"});}
    };
    std::string active="preflight";
    auto started=record("State: running\nIf interrupted, do not assume the last device operation was not executed.\n");
    if(!started) return std::unexpected(started.error());
    const ProgressObserver observer=[&](const OperationProgress& event) {
        active=std::string(event.target)+" "+std::string(event.detail);
        if(progress) progress(event);
    };
    auto result=invoke(observer);
    const auto journal=Journal::attempt([&]()->OperationResult<> {
    std::string evidence;
    if(!result) {
        const auto describe=[&](const char* label,const std::optional<protocol::ExchangeEvidence>& e) {
            if(!e)return;
            evidence+=std::string(label)+": outcome="+std::to_string(static_cast<unsigned>(e->outcome));
            if(e->command)evidence+=" command="+std::to_string(*e->command);
            if(e->response)evidence+=" response="+std::to_string(static_cast<unsigned>(*e->response));
            if(e->bare_data)evidence+=" raw-offset="+std::to_string(e->offset)+" bytes="+std::to_string(e->requested_bytes);
            evidence+=" transport-error="+std::make_error_code(e->transport_error).message()+"\n";
        };
        describe("Failure exchange",result.error().exchange);describe("Cleanup exchange",result.error().cleanup_exchange);
        describe("Initial raw failure",result.error().initial_raw_failure);
    }
    return record(result ? (plan.nv_batch_?
        "State: completed\nOrdinary writes acknowledged; NV primary/backup effective data physically verified. NV tails not restored.\n":plan.package_execution_?
        "State: completed\nPackage commands acknowledged; ordinary images and logical NV were not physically read back. Physical NV transactions include verification.\n":
        "State: completed\nAll written images passed configured readback verification.\n") :
        "State: failed\nLast activity: "+active+"\nTarget: "+result.error().target+"\nError: "+
        std::make_error_code(result.error().code).message()+"\nSession synchronized: "+
        ((!device.link_dead() && !device.link_silent())?"yes":"no")+"\n"+evidence+"No batch replay or rollback was performed; inspect attempt-N.txt for transport recovery.\n");
    });
    if(!result) {
        if(!journal)result.error().journal_failure=io::OutputError{journal.error().code,journal.error().commit_state,journal.error().actual_bytes};
        return result;
    }
    if(!journal) return std::unexpected(journal.error());
    return result;
} catch(...) {return std::unexpected(device_exception_error(device,OperationStep::Save));}

OperationResult<OperationReport> PlanExecutor::run(device::SprdDevice& device,
    const FlashPlan& plan, std::stop_token stop, const ProgressObserver& progress,
    const EraseScopeFactory& acquire_erase_scope,OperationStep& active_step) {
    if (plan.entries_.empty()) return std::unexpected(OperationError{OperationStep::Validate, std::errc::invalid_argument, "empty plan"});
    if(plan.phase_!=PlanPhase::Validating || (plan.requires_recovery() && plan.connection_!=device.connection_token()))
        return std::unexpected(OperationError{OperationStep::Validate,std::errc::operation_not_permitted,"plan requires recovery and original connection; single use"});
    const auto checkpoint=[&](std::string text)->OperationResult<> {
        active_step=OperationStep::Save;
        if(!plan.requires_recovery()) return {};
        return Journal::write(plan.journal_directory_/"last-operation.txt",text,"PAC operation journal");
    };
    OperationReport report;
    using Clock = std::chrono::steady_clock;
    auto phase_start = Clock::now();
    auto seconds = [&]() { return std::chrono::duration<double>(Clock::now() - phase_start).count(); };
    if (device.link_dead() || device.link_silent())
        return std::unexpected(OperationError{OperationStep::Validate, std::errc::state_not_recoverable, "connection"});
    if(progress)progress({OperationStep::Validate,{},0,plan.bytes_,"plan preflight"});
    // Only a same-connection, unchanged generation may reuse the snapshot.
    std::vector<device::PartitionInfo> parts = plan.capacities_;
    if (!plan.package_execution_ && (!plan.layout_token_ || plan.layout_token_ != device.layout_token() ||
        Clock::now() - plan.prepared_at_ > std::chrono::seconds(5))) {
        std::vector<std::string> names;
        for (const auto& entry : plan.entries_) {
            names.push_back(entry.partition);
            const auto targets=entry.verification_targets();names.insert(names.end(),targets.begin(),targets.end());
        }
        device.invalidate_layout();
        auto refreshed = PartitionAccess::capacities(device, names, stop, progress);
        if (!refreshed) return std::unexpected(refreshed.error());
        parts = std::move(*refreshed);
    }
    if(plan.package_execution_ && !plan.comparison_capacities_.empty()) {
        device.invalidate_layout();
        auto current=device.list_partitions(stop,false);
        if(!current) return std::unexpected(device_error(device,OperationStep::Validate,current.error(),"PAC layout policy recheck"));
        if(current->size()!=plan.comparison_capacities_.size() || std::any_of(plan.comparison_capacities_.begin(),plan.comparison_capacities_.end(),[&](const auto& before) {
            return std::none_of(current->begin(),current->end(),[&](const auto& now){return before.name==now.name && before.size==now.size && before.offset==now.offset && before.hw_boot==now.hw_boot;});
        })) return std::unexpected(OperationError{OperationStep::Validate,std::errc::state_not_recoverable,"PAC layout changed after policy comparison"});
    }
    if(plan.expected_layout_) {
        // User-area capacities refer to the target GPT. Current media is
        // checked separately against the original evidence before repartition.
        // Preserve freshly probed hardware capacities for the checks below.
        std::erase_if(parts,[](const auto& p){return !p.hw_boot;});
        for(const auto& p:plan.expected_layout_->partitions)
            parts.push_back({p.name,p.size,p.offset,false,false,0});
    }
    for (const auto& entry : plan.entries_) {
        if(!entry.valid_action())return std::unexpected(OperationError{OperationStep::Validate,std::errc::invalid_argument,"invalid operation state: "+entry.partition});
        if(std::holds_alternative<ControlAction>(entry.action) || entry.address_target()) continue;
        if(plan.physical_ && entry.erases() && entry.partition=="splloader") {
            // The package can erase SPL before reaching its replacement.
            // A prepared replacement is required before the first erase.
            if(std::none_of(plan.entries_.begin(),plan.entries_.end(),[](const auto& e){return e.partition=="splloader" && e.write();}))
                return std::unexpected(OperationError{OperationStep::Validate,std::errc::invalid_argument,"PAC erases SPL without a selected replacement"});
        }
        if(const auto* nv=entry.physical_nv()) {
            auto valid=NvRestore::validate(device,*nv->plan(),stop);
            if(!valid) return std::unexpected(valid.error());
        }
        auto part = PartitionAccess::find(parts, entry.partition);
        if (!part) return std::unexpected(part.error());
        const auto limit = part->unverified ? UINT64_MAX : part->size;
        if (!limit) {
            OperationError error{OperationStep::Validate, std::errc::invalid_argument, entry.partition};
            error.detail = "partition '" + entry.partition + "' capacity unavailable";
            return std::unexpected(std::move(error));
        }
        const auto* write=entry.write();
        if (write && (plan.package_execution_?write->expanded_size:write->image.size()) > limit)
            return std::unexpected(OperationError{OperationStep::Validate, std::errc::file_too_large, entry.partition});
        if(write && device::nv_pair(entry.partition)) return std::unexpected(OperationError{
            OperationStep::Validate,std::errc::not_supported,"NV requires its dedicated transaction: "+entry.partition});
        if (write && write->image.size() > UINT32_MAX &&
            !(plan.package_execution_ && write->wide) && !device.profile().framed_write_u64 &&
            !(device.profile().allow_whole_file_raw && device.da_info().valid && device.da_info().support_raw))
            return std::unexpected(OperationError{OperationStep::Validate, std::errc::file_too_large,
                entry.partition + ": no verified 64-bit write contract"});
    }
    report.validate_seconds = seconds();
    // Logical NV is frozen before repartition. Recheck while old names/layout
    // are still active, not after a package has intentionally moved the pair.
    for(const auto& entry:plan.entries_) if(const auto* nv=entry.logical_nv()) {
        active_step=OperationStep::Read;
        std::expected<std::vector<uint8_t>,std::errc> current;
        if(nv->address) {
            std::vector<uint8_t> bytes;
            auto read=device.read_address_stream(nv->address->address,static_cast<uint32_t>(nv->before.size()),
                [&](auto data,auto)->std::expected<void,std::errc>{
                    if(data.size()>nv->before.size()-bytes.size())return std::unexpected(std::errc::message_size);
                    bytes.insert(bytes.end(),data.begin(),data.end());return {};
                },nv->address->order,stop);
            if(read)current=std::move(bytes);else current=std::unexpected(read.error());
        } else current=device.read_partition(entry.partition,0,nv->before.size(),stop);
        if(!current) return std::unexpected(device_error(device,OperationStep::Read,current.error(),"PAC NV recheck"));
        if(*current!=nv->before) return std::unexpected(OperationError{OperationStep::Validate,
            std::errc::state_not_recoverable,"PAC logical NV changed after preparation"});
    }
    if(plan.physical_) {
        active_step=OperationStep::Validate;
        auto current=PhysicalAccess::open(device,stop);
        if(!current || current->layout().primary_sector!=plan.physical_->layout().primary_sector ||
            current->layout().entries!=plan.physical_->layout().entries) return std::unexpected(OperationError{
                OperationStep::Validate,current?std::errc::state_not_recoverable:current.error(),"PAC layout changed since preparation"});
        for(const auto& source:plan.relocation_sources_) {
            const auto entry=std::find_if(plan.entries_.begin(),plan.entries_.end(),[&](const auto& e){return e.partition==source.name && e.write();});
            if(entry==plan.entries_.end()) return std::unexpected(OperationError{OperationStep::Validate,
                std::errc::state_not_recoverable,"relocation snapshot missing: "+source.name});
            auto checked=compare_physical(device,*current,source.offset,entry->write()->image,source.size,stop,{},std::errc::state_not_recoverable);
            if(!checked) return std::unexpected(device_error(device,OperationStep::Validate,
                checked.error(),"relocation source changed after backup: "+source.name));
        }
        for(const auto& entry:plan.entries_) for(const auto& target:entry.verification_targets()) {
            const auto old=std::find_if(plan.capacities_.begin(),plan.capacities_.end(),[&](const auto& p){return p.name==target;});
            const auto now=std::find_if(parts.begin(),parts.end(),[&](const auto& p){return p.name==target;});
            if(old==plan.capacities_.end() || now==parts.end() || old->size!=now->size || old->offset!=now->offset || old->hw_boot!=now->hw_boot)
                return std::unexpected(OperationError{OperationStep::Validate,std::errc::state_not_recoverable,"PAC verification target changed: "+target});
        }
    }
    std::optional<PhysicalAccess> execution_access=plan.physical_;
    plan.phase_=PlanPhase::Submitted;
    if(!plan.repartition_table_.empty()) {
        if(stop.stop_requested()) return std::unexpected(OperationError{OperationStep::Write,std::errc::interrupted,"cancelled before PAC repartition"});
        if(progress) progress({OperationStep::Write,"GPT",0,plan.bytes_,"repartition"});
        auto recorded=checkpoint("Operation: repartition\nState: about to submit; not yet acknowledged\n");
        if(!recorded) return std::unexpected(recorded.error());
        active_step=OperationStep::Write;
        auto scope=acquire_erase_scope?acquire_erase_scope():std::shared_ptr<void>{};
        auto changed=device.repartition(plan.repartition_table_,{},true,512,
            plan.physical_?std::optional<uint64_t>(plan.physical_->layout().disk_bytes):std::nullopt);
        if(!changed) return std::unexpected(device_error(device,OperationStep::Write,changed.error(),"PAC repartition (not retried)"));
        if(plan.physical_) {
            active_step=OperationStep::Validate;
            auto readback=PhysicalAccess::open(device,{});
            if(!readback) return std::unexpected(OperationError{OperationStep::Validate,readback.error(),"PAC GPT readback"});
            if(!plan.expected_layout_ || !same_partition_geometry(*plan.expected_layout_,readback->layout()))
                return std::unexpected(OperationError{OperationStep::Validate,std::errc::bad_message,"PAC repartition differs from planned geometry"});
            execution_access=std::move(*readback);
            recorded=checkpoint("Operation: repartition\nState: primary and backup GPT verified against planned geometry\n");
            if(!recorded) return std::unexpected(recorded.error());
        } else {
            recorded=checkpoint("Operation: repartition\nState: FDL acknowledged; physical GPT readback not requested\n");
            if(!recorded) return std::unexpected(recorded.error());
        }
    }
    // Submission consumes the plan; callers prepare a new plan for another write.
    device.invalidate_layout();
    size_t operation_index=0;
    for (const auto& entry : plan.entries_) {
        ++operation_index;
        if (stop.stop_requested()) return std::unexpected(OperationError{OperationStep::Write, std::errc::interrupted, entry.partition});
        auto recorded=checkpoint("Target: "+entry.partition+"\nState: about to submit\nOperation: "+
            operation_name(entry.action)+"\n");
        if(!recorded) return std::unexpected(recorded.error());
        if(const auto* check=std::get_if<CheckNvAction>(&entry.action)) {
            active_step=OperationStep::Read;
            std::vector<uint8_t> data;
            const io::Writer sink=[&](auto bytes,auto)->std::expected<void,std::errc>{
                if(bytes.size()>check->expected.size()-data.size())return std::unexpected(std::errc::message_size);
                data.insert(data.end(),bytes.begin(),bytes.end());return {};
            };
            auto read=check->address?device.read_address_stream(check->address->address,static_cast<uint32_t>(check->expected.size()),sink,check->address->order,stop):
                device.read_partition_stream(entry.partition,0,check->expected.size(),sink,stop);
            if(!read)return std::unexpected(device_error(device,OperationStep::Read,read.error(),"CHECK_NV"));
            if(data.size()!=check->expected.size() || data.size()<8 ||
                !std::equal(data.begin()+4,data.end(),check->expected.begin()+4))
                return std::unexpected(OperationError{OperationStep::Validate,std::errc::bad_message,"CHECK_NV mismatch; no automatic rewrite"});
            recorded=checkpoint("Target: "+entry.partition+"\nState: logical NV verified excluding counter\n");
            if(!recorded)return std::unexpected(recorded.error());
            ++report.partitions;continue;
        }
        if(const auto* control_action=std::get_if<ControlAction>(&entry.action)) {
            active_step=OperationStep::Finish;
            const auto control=control_name(*control_action);
            const auto* command=std::get_if<ControlCommand>(&control_action->payload);
            const auto is=[&](ControlCommand c){return command && *command==c;};
            std::expected<void,std::errc> result;
            if(is(ControlCommand::EndProcess)) result=device.end_process(stop);
            else if(is(ControlCommand::Reset)) result=device.reset(stop);
            else if(is(ControlCommand::PowerOff)) result=device.power_down(stop);
            else if(is(ControlCommand::WriteEfuse))result=device.write_factory_efuse(stop);
            else if(const auto* vpac=std::get_if<VpacWrite>(&control_action->payload))result=device.write_vpac(vpac->bytes,stop);
            else if(is(ControlCommand::ReadVpac)) {
                active_step=OperationStep::Read;
                auto bytes=device.read_vpac(stop);
                if(!bytes)return std::unexpected(device_error(device,OperationStep::Read,bytes.error(),control));
                active_step=OperationStep::Save;
                auto saved=Journal::write(plan.journal_directory_/("vpac-"+std::to_string(operation_index)+".bin"),*bytes,control,stop);
                if(!saved)return std::unexpected(saved.error());
            }
            else if(const auto* table=std::get_if<ExtTableWrite>(&control_action->payload)) {
                std::vector<uint8_t> bytes(static_cast<size_t>(table->image.size()));
                result=table->image.reader()(0,bytes,stop);
                if(result) result=device.send_ext_table(bytes,stop);
            }
            else if(is(ControlCommand::ReadFlashType) || is(ControlCommand::CheckMcpType) ||
                is(ControlCommand::ReadFlashInfo) || is(ControlCommand::ReadRfChipType) || is(ControlCommand::ReadPartitionInfo)) {
                active_step=OperationStep::Read;
                std::string text;
                if(is(ControlCommand::ReadFlashType) || is(ControlCommand::CheckMcpType)) {
                    auto reply=device.read_flash_type(stop);
                    if(!reply) result=std::unexpected(reply.error());
                    else text="ddr_mb="+std::to_string(reply->first)+"\nstorage_mb="+std::to_string(reply->second)+"\n";
                } else if(is(ControlCommand::ReadFlashInfo)) {
                    auto reply=device.read_mcp_type(stop);
                    if(!reply) result=std::unexpected(reply.error());
                    else text="flag="+std::to_string(reply->flag)+"\npage_size="+std::to_string(reply->page_size)+
                        "\nblock_size="+std::to_string(reply->block_size)+"\n";
                } else if(is(ControlCommand::ReadRfChipType)) {
                    auto reply=device.check_nv_type(stop);
                    if(!reply) result=std::unexpected(reply.error());else text="rf_type="+std::to_string(*reply)+"\n";
                } else {
                    auto reply=device.list_partitions(stop,false);
                    if(!reply) result=std::unexpected(reply.error());
                    else for(const auto& p:*reply) text+=p.name+" size="+std::to_string(p.size)+" offset="+std::to_string(p.offset)+"\n";
                }
                if(!result) return std::unexpected(device_error(device,OperationStep::Read,result.error(),control));
                const auto name="result-"+std::to_string(operation_index)+".txt";
                active_step=OperationStep::Save;
                auto saved=Journal::write(plan.journal_directory_/name,text,name,stop);
                if(!saved)return std::unexpected(saved.error());
            }
            else if(!is(ControlCommand::Noop)) result=std::unexpected(std::errc::not_supported);
            if(!result) return std::unexpected(device_error(device,OperationStep::Finish,result.error(),control));
            recorded=checkpoint("Operation: "+control+"\nState: "+
                (is(ControlCommand::Noop)?"explicit no-op completed":"FDL acknowledged")+"\n");
            if(!recorded) return std::unexpected(recorded.error());
            ++report.partitions;continue;
        }
        if(const auto* nv=entry.logical_nv()) {
            active_step=OperationStep::Write;
            const io::Reader source=[&](uint64_t at,std::span<uint8_t> out,std::stop_token)->std::expected<void,std::errc>{
                if(at>nv->payload.size()||out.size()>nv->payload.size()-at)return std::unexpected(std::errc::message_size);
                std::copy_n(nv->payload.begin()+at,out.size(),out.begin());return {};
            };
            auto written=nv->address?device.write_address_stream(nv->address->address,nv->payload.size(),source,nv->address->order,stop,{},nv->address->chunk):
                device.write_logical_nv(entry.partition,nv->payload,stop);
            if(!written) return std::unexpected(device_error(device,OperationStep::Write,written.error(),"PAC logical NV write"));
            recorded=checkpoint("Target: "+entry.partition+"\nState: logical NV acknowledged; physical pair verification not requested\n");
            if(!recorded) return std::unexpected(recorded.error());
            report.bytes+=nv->payload.size();++report.partitions;continue;
        }
        if(const auto* request=std::get_if<ReadAction>(&entry.action)) {
            active_step=OperationStep::Save;
            const auto filename="read-"+std::to_string(operation_index)+"-"+io::partition_filename(entry.partition);
            auto out=io::AtomicOutput::open(plan.journal_directory_/platform::path(filename));
            if(!out) return std::unexpected(OperationError{OperationStep::Save,out.error(),filename});
            io::BufferedOutput buffered(*out);
            const io::Writer sink=[&](auto bytes,auto token) {
                    auto saved=buffered.write(bytes,token);
                    if(saved && progress) progress({OperationStep::Read,entry.partition,buffered.accepted(),request->length,"PAC named read"});
                    return saved;
                };
            active_step=OperationStep::Read;
            auto read=request->address?device.read_address_stream(request->address->address,static_cast<uint32_t>(request->length),sink,request->address->order,stop):
                device.read_package_stream(entry.partition,request->offset,request->length,sink,request->wide,stop);
            if(!read) return std::unexpected(device_error(device,OperationStep::Read,read.error(),entry.partition));
            active_step=OperationStep::Save;
            auto saved=buffered.finish(stop);
            if(saved && out->size()!=request->length) saved=std::unexpected(std::errc::message_size);
            if(saved && stop.stop_requested()) saved=std::unexpected(std::errc::interrupted);
            if(!saved) return std::unexpected(OperationError{OperationStep::Save,saved.error(),filename});
            auto committed=commit_output(*out,filename);if(!committed)return std::unexpected(committed.error());
            recorded=checkpoint("Target: "+entry.partition+"\nState: named read completed and file committed\nFile: "+filename+"\n");
            if(!recorded) return std::unexpected(recorded.error());
            ++report.partitions;continue;
        }
        if (const auto* nv=entry.physical_nv()) {
            active_step=OperationStep::Write;
            if(progress) progress({OperationStep::Write,entry.partition,report.bytes,plan.bytes_,"NV merge/write/verify"});
            const io::TransferObserver transfer=[&](const io::TransferProgress& event) {
                if(progress) progress({OperationStep::Write,entry.partition,report.bytes+event.completed,plan.bytes_,
                    "transfer",event.completed,event.total,event.seconds});
            };
            auto restored=NvRestore::execute(device,*nv->plan_,stop,transfer);
            if(!restored) return std::unexpected(restored.error());
            recorded=checkpoint("Target: "+entry.partition+"\nState: primary and backup physically verified\n");
            if(!recorded) return std::unexpected(recorded.error());
            report.bytes+=*restored; ++report.partitions;
            continue;
        }
        if (entry.erases()) {
            active_step=OperationStep::Erase;
            auto erase_scope = acquire_erase_scope ? acquire_erase_scope() : std::shared_ptr<void>{};
            phase_start = Clock::now();
            if (progress) progress({OperationStep::Erase, entry.partition, report.bytes, plan.bytes_});
            if (stop.stop_requested()) return std::unexpected(OperationError{OperationStep::Erase, std::errc::interrupted, entry.partition});
            const auto* erase=std::get_if<EraseAction>(&entry.action);
            auto erased = erase && erase->address?device.erase_address(erase->address->address,static_cast<uint32_t>(erase->size),erase->address->order):
                device.erase_partition(entry.partition, 0);
            if (!erased) return std::unexpected(device_error(device, OperationStep::Erase, erased.error(), entry.partition));
            report.erase_seconds += seconds();
            if (progress) progress({OperationStep::Erase, entry.partition, report.bytes, plan.bytes_, "complete"});
        }
        if (const auto* write=entry.write()) {
            active_step=OperationStep::Write;
            if (stop.stop_requested()) return std::unexpected(OperationError{OperationStep::Write, std::errc::interrupted, entry.partition});
            if(!write->softsim_eid.empty()) {
                auto uid=device.read_softsim_identity(false,stop);
                if(!uid)return std::unexpected(device_error(device,OperationStep::Read,uid.error(),"Soft_SIM flash UID"));
                auto saved=Journal::write(plan.journal_directory_/("softsim-"+std::to_string(operation_index)+"-uid.bin"),*uid,"Soft_SIM UID",stop);
                if(!saved)return std::unexpected(saved.error());
            }
            phase_start = Clock::now();
            if (progress) progress({OperationStep::Write, entry.partition, report.bytes, plan.bytes_});
            const io::TransferObserver transfer = progress ? io::TransferObserver([&](const io::TransferProgress& event) {
                progress({OperationStep::Write, entry.partition, report.bytes + event.completed, plan.bytes_,
                    "transfer", event.completed, event.total, event.seconds});
            }) : io::TransferObserver{};
            auto written = write->address?device.write_address_stream(write->address->address,write->image.size(),write->image.reader(),write->address->order,stop,transfer,write->address->chunk):plan.package_execution_ ?
                device.write_package_stream(entry.partition,write->image.size(),write->image.reader(),write->wide,stop,transfer):
                device.write_partition_stream(entry.partition,write->image.size(),write->image.reader(),stop,transfer);
            const auto& attempts=device.write_timings();
            std::optional<io::OutputError> attempt_journal_failure;
            if(attempts.raw_recovery_attempted) {
                report.attempts.push_back({entry.partition,attempts.raw_fallback,attempts.raw_attempt_seconds,attempts.raw_failure});
                std::string record="Target: "+entry.partition+"\nRaw recovery attempted: yes\nFramed restart: "+
                    (attempts.raw_fallback?"yes":"no")+"\nRaw attempt seconds: "+std::to_string(attempts.raw_attempt_seconds)+"\n";
                if(attempts.raw_failure && attempts.raw_failure->response)
                    record+="Original raw response: "+std::to_string(static_cast<uint16_t>(*attempts.raw_failure->response))+"\n";
                if(plan.requires_recovery()) {
                    auto saved=Journal::write(plan.journal_directory_/("attempt-"+std::to_string(operation_index)+".txt"),record,"attempt journal");
                    if(!saved && written)return std::unexpected(saved.error());
                    if(!saved)attempt_journal_failure=io::OutputError{saved.error().code,saved.error().commit_state,saved.error().actual_bytes};
                }
            }
            if (!written) {
                auto failure=device_error(device,OperationStep::Write,written.error(),entry.partition);
                if(attempts.raw_recovery_attempted)failure.initial_raw_failure=attempts.raw_failure;
                failure.journal_failure=attempt_journal_failure;
                return std::unexpected(std::move(failure));
            }
            if(!write->softsim_eid.empty()) {
                auto eid=device.read_softsim_identity(true,stop);
                if(!eid)return std::unexpected(device_error(device,OperationStep::Validate,eid.error(),"Soft_SIM EID after download"));
                if(*eid!=write->softsim_eid)return std::unexpected(OperationError{OperationStep::Validate,std::errc::bad_message,
                    "Soft_SIM EID mismatch after acknowledged write; no replay"});
            }
            report.write_seconds += seconds();
            const auto verify_started=Clock::now();
            active_step=OperationStep::Validate;
            if(plan.physical_) for(const auto& target:write->verify_targets) {
                const auto found=std::find_if(plan.capacities_.begin(),plan.capacities_.end(),[&](const auto& p){return p.name==target;});
                if(found==plan.capacities_.end()) return std::unexpected(OperationError{OperationStep::Validate,std::errc::bad_message,"PAC readback target"});
                const io::PrepareObserver observer=[&](const io::PrepareProgress& event) {
                    if(progress) progress({OperationStep::Validate,target,event.completed,event.total,"physical readback"});
                };
                auto checked=found->hw_boot ? compare_named(device,target,write->image,write->verify_size,stop,observer)
                    : compare_physical(device,*execution_access,found->offset,write->image,write->verify_size,stop,observer);
                if(!checked) return std::unexpected(device_error(device,OperationStep::Validate,checked.error(),"PAC image readback: "+target));
            }
            if(plan.physical_) report.verify_seconds+=std::chrono::duration<double>(Clock::now()-verify_started).count();
            report.bytes += write->image.size();
            report.open_seconds += device.write_timings().open_seconds;
            report.transfer_seconds += device.write_timings().transfer_seconds;
            report.sync_seconds += device.write_timings().sync_seconds;
            report.source_seconds += device.write_timings().source_seconds;
            report.encode_seconds += device.write_timings().encode_seconds;
            report.send_seconds += device.write_timings().send_seconds;
            report.ack_seconds += device.write_timings().ack_seconds;
            report.slow_ack_count += device.write_timings().slow_ack_count;
            report.slow_ack_seconds += device.write_timings().slow_ack_seconds;
            report.max_ack_seconds = std::max(report.max_ack_seconds, device.write_timings().max_ack_seconds);
            if (progress) progress({OperationStep::Write, entry.partition, report.bytes, plan.bytes_, "complete"});
            if(write->timestamp) {
                recorded=checkpoint("Target: "+entry.partition+"\nState: image acknowledged; factory timestamp about to submit\n");
                if(!recorded)return std::unexpected(recorded.error());
                active_step=OperationStep::Write;
                auto stamped=device.write_factory_timestamp(*write->timestamp,stop);
                if(!stamped)return std::unexpected(device_error(device,OperationStep::Write,stamped.error(),"PAC SetTimeStamp after "+entry.partition));
            }
        }
        ++report.partitions;
        recorded=checkpoint("Target: "+entry.partition+"\nState: "+(entry.write()?
            (!plan.physical_?"write acknowledged; no physical readback":"write readback verified"):
            "erase acknowledged (readback unspecified by protocol)")+"\n");
        if(!recorded) return std::unexpected(recorded.error());
    }
    // Each write has already completed END_DATA and checked its final ACK.
    // Finish is a local notification, not a second device liveness exchange.
    if (progress) progress({OperationStep::Finish, {}, report.bytes, plan.bytes_});
    return report;
}

OperationResult<uint64_t> Operations::backup(device::SprdDevice& device, const std::string& name,
    uint64_t size, const std::filesystem::path& destination, std::stop_token stop,
    const ProgressObserver& progress) {
    return PartitionAccess::backup(device,name,size,destination,stop,progress);
}
OperationResult<uint64_t> PartitionAccess::backup(device::SprdDevice& device, const std::string& name,
    uint64_t size, const std::filesystem::path& destination, std::stop_token stop,
    const ProgressObserver& progress) {
    OperationStep step=OperationStep::Validate;
    try {
    if (!size || !valid_name(name))
        return std::unexpected(OperationError{OperationStep::Validate, std::errc::invalid_argument, name});
    step=OperationStep::Save;
    auto file = io::AtomicOutput::open(destination);
    if (!file) return std::unexpected(OperationError{OperationStep::Save, file.error(), platform::utf8_path(destination)});
    io::BufferedOutput buffered(*file);
    step=OperationStep::Read;
    auto read = device.read_partition_stream(name, 0, size,
        [&](std::span<const uint8_t> bytes, std::stop_token token) {
            auto saved = buffered.write(bytes, token);
            if (saved && progress) progress({OperationStep::Read, name, buffered.accepted(), size});
            return saved;
        }, stop);
    if (!read) return std::unexpected(device_operation_error(device,OperationStep::Read,read.error(),name));
    step=OperationStep::Save;
    auto drained = buffered.finish(stop);
    if (!drained) return std::unexpected(OperationError{OperationStep::Save, drained.error(), platform::utf8_path(destination)});
    if (file->size() != size) return std::unexpected(OperationError{OperationStep::Read, std::errc::message_size, name});
    if (stop.stop_requested()) return std::unexpected(OperationError{OperationStep::Save, std::errc::interrupted, name});
    auto committed = file->commit();
    if (!committed) return std::unexpected(OperationError{OperationStep::Save, committed.error(), platform::utf8_path(destination),
        file->commit_state(), file->commit_state() == io::CommitState::NotCommitted ? 0 : file->size()});
    return size;
    } catch(...) {return std::unexpected(device_exception_error(device,step));}
}
}

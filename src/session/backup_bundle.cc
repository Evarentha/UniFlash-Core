#include <uniflash/session/backup_bundle.h>
#include <uniflash/session/journal.h>
#include <uniflash/io/partition_filename.h>
#include <uniflash/platform.h>
#include <uniflash/text.h>
#include <uniflash/io/sha256.h>
#include <set>
#include <sstream>

namespace uniflash::session {
namespace {
std::string json(std::string_view input) {
    std::string out="\"";
    constexpr char hex[]="0123456789abcdef";
    for(size_t at=0;at<input.size();) {
        const auto scalar=text::decode(input,at);
        const auto c=static_cast<unsigned char>(input[at]);
        if(c=='"' || c=='\\') { out+='\\'; out+=char(c); ++at; }
        else if(c<32 || !scalar.valid) {
            out+="\\u00"; out+=hex[c>>4]; out+=hex[c&15]; ++at;
        } else { out.append(input.substr(at,scalar.bytes)); at+=scalar.bytes; }
    }
    return out+'"';
}
std::string xml(std::string_view input) {
    std::string out;
    for(char c:input) {
        switch(c) {
        case '&': out+="&amp;"; break;
        case '<': out+="&lt;"; break;
        case '>': out+="&gt;"; break;
        case '"': out+="&quot;"; break;
        case '\r': out+="&#13;"; break;
        case '\n': out+="&#10;"; break;
        case '\t': out+="&#9;"; break;
        default: out+=c;
        }
    }
    return out;
}
OperationResult<> save(const std::filesystem::path& path,std::span<const uint8_t> bytes) {
    return Journal::write(path,bytes,platform::utf8_path(path));
}
OperationResult<> save(const std::filesystem::path& path,const std::string& text) {
    return save(path,std::span(reinterpret_cast<const uint8_t*>(text.data()),text.size()));
}
}
OperationResult<BackupBundle> BackupBundle::create(const std::filesystem::path& directory,const RawBackupPlan& plan,
    BackupIdentity identity) try {
    std::error_code ec;
    std::filesystem::create_directories(directory,ec);
    if(ec || !std::filesystem::is_empty(directory,ec) || ec)
        return std::unexpected(OperationError{OperationStep::Save,ec?std::errc::io_error:std::errc::directory_not_empty,
            "backup requires an empty directory: "+platform::utf8_path(directory)});
    BackupBundle bundle;
    bundle.directory_=std::filesystem::absolute(directory);
    bundle.identity_=std::move(identity);
    std::set<std::string> names,files{"gpt-primary-header.bin","gpt-entries.bin","mbr.bin"};
    for(const auto& sector:plan.layout().extended_sectors)
        files.insert("ebr-offset-"+std::to_string(sector.first)+".bin");
    for(const auto& entry:plan.entries()) {
        BackupRecord record;
        record.file=io::partition_filename(entry.name);
        auto folded=record.file;
        for(auto& c:folded) if(c>='A' && c<='Z') c+=32;
        if(entry.name.empty() || !names.insert(entry.name).second || !files.insert(folded).second)
            return std::unexpected(OperationError{OperationStep::Validate,std::errc::invalid_argument,"duplicate backup name: "+entry.name});
        if(!entry.size || !entry.unavailable.empty()) {
            record.status="unavailable"; record.reason=entry.unavailable.empty()?"unknown or zero size":entry.unavailable;
        }
        bundle.records_.push_back(std::move(record));
    }
    auto r=bundle.checkpoint(plan,false);
    if(!r) return std::unexpected(r.error());
    const auto& layout=plan.layout();
    r=save(directory/(layout.mbr?"mbr.bin":"gpt-primary-header.bin"),layout.primary_sector);
    if(r && !layout.mbr) r=save(directory/"gpt-entries.bin",layout.entries);
    for(const auto& [offset,bytes]:layout.extended_sectors) {
        if(!r) break;
        r=save(directory/("ebr-offset-"+std::to_string(offset)+".bin"),bytes);
    }
    if(!r) return std::unexpected(r.error());
    std::string listing="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!-- Physical snapshots; named loader writes are not a byte-preserving inverse. -->\n"
        "<rom image_semantics=\"physical-snapshot\">\n";
    for(size_t i=0;i<plan.entries().size();++i) {
        const auto& e=plan.entries()[i];
        listing+="  <partition name=\""+xml(e.name)+"\" size=\""+std::to_string(e.size)+
            "\" file=\""+bundle.records_[i].file+"\"/>\n";
    }
    listing+="</rom>\n";
    r=save(directory/"layout.xml",listing);
    if(!r) return std::unexpected(r.error());
    r=Journal::seal_directory(directory);
    if(!r)return std::unexpected(r.error());
    return bundle;
} catch(...) {return std::unexpected(exception_error(OperationStep::Save));}
OperationResult<> BackupBundle::checkpoint(const RawBackupPlan& plan,bool complete) const try {
    if(records_.size()!=plan.entries().size()) return std::unexpected(OperationError{
        OperationStep::Validate,std::errc::invalid_argument,"backup record count"});
    uint64_t total=0; size_t saved=0;
    bool all=!records_.empty();
    std::ostringstream m;
    const auto& layout=plan.layout();
    io::Sha256 header_hash,entries_hash;
    header_hash.update(layout.primary_sector);entries_hash.update(layout.entries);
    m<<"{\n  \"format\": \"raw-partition-backup-v3\",\n  \"image_semantics\": \"physical-snapshot\",\n  \"partition_scheme\": "<<json(layout.mbr?"mbr":"gpt")
      <<",\n  \"stage\": "<<json(identity_.stage)<<",\n  \"version\": "<<json(identity_.loader_version)
      <<",\n  \"chip_type\": "<<json(identity_.chip_type)
      <<",\n  \"sector_size\": "<<layout.header.sector_size
      <<",\n  \"sector_size_verified\": true"
      <<",\n  \"primary_header_sha256\": "<<json(header_hash.hex())
      <<",\n  \"partition_entries_sha256\": "<<json(entries_hash.hex())
      <<",\n  \"user_area_bytes_from_gpt\": "<<layout.disk_bytes
      <<",\n  \"gpt_entries_offset_bytes\": "<<layout.header.entries_lba*layout.header.sector_size
      <<",\n  \"gpt_entry_count\": "<<layout.header.entry_count
      <<",\n  \"gpt_entry_size\": "<<layout.header.entry_size
      <<",\n  \"wide_offsets_verified\": "<<(plan.wide_verified()?"true":"false")
      <<",\n  \"limitation\": "<<json(plan.limitation())<<",\n  \"partitions\": [\n";
    for(size_t i=0;i<records_.size();++i) {
        const auto& r=records_[i]; const auto& e=plan.entries()[i];
        all &= r.status=="saved" && r.actual==e.size;
        if(r.status=="saved" && !io::valid_sha256(e.sha256)) return std::unexpected(OperationError{
            OperationStep::Validate,std::errc::bad_message,"saved backup lacks SHA-256: "+e.name});
        if(r.status=="saved") {
            if(r.actual>UINT64_MAX-total) return std::unexpected(OperationError{
                OperationStep::Validate,std::errc::value_too_large,"backup byte count"});
            ++saved; total+=r.actual;
        }
        if(i) m<<",\n";
        m<<"    {\"name\": "<<json(e.name)<<", \"file\": "<<json(r.file)
         <<", \"expected_bytes\": "<<e.size<<", \"actual_bytes\": "<<r.actual
         <<", \"offset_bytes\": "<<e.offset<<", \"source\": "<<json(e.route==BackupRoute::UserArea?"user_partition":e.name)
         <<", \"sha256\": "<<json(e.sha256)
         <<", \"status\": "<<json(r.status)<<", \"reason\": "<<json(r.reason)<<"}";
    }
    if(complete && (!all || !plan.limitation().empty())) return std::unexpected(OperationError{
        OperationStep::Validate,std::errc::state_not_recoverable,"cannot commit an incomplete backup bundle"});
    m<<"\n  ],\n  \"complete\": "<<(complete?"true":"false")<<",\n  \"total_read\": "<<total
     <<",\n  \"partitions_read\": "<<saved<<"\n}\n";
    return save(directory_/"manifest.json",m.str());
} catch(...) {return std::unexpected(exception_error(OperationStep::Save));}
}

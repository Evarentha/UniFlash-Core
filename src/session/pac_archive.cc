#include <uniflash/session/pac_archive.h>
#include <uniflash/session/pac_parser.h>
#include <uniflash/session/pac_table.h>
#include <uniflash/protocol/partition_name.h>
#include <uniflash/text.h>
#include <uniflash/log.h>
#include <algorithm>
#include <array>
#include <charconv>
#include <map>
#include <set>

namespace uniflash::session {
namespace {
std::string key(std::string value) {
    for (auto& c : value) if (c >= 'a' && c <= 'z') c -= 32;
    return value;
}
uint64_t le(std::span<const uint8_t> bytes, size_t at, size_t width = 4) {
    uint64_t value = 0;
    for (size_t i=0;i<width;++i) value |= uint64_t(bytes[at+i]) << (8*i);
    return value;
}
std::expected<uint64_t,std::errc> number(std::string_view text) {
    int base=10;
    if(text.starts_with("0x") || text.starts_with("0X")) {text.remove_prefix(2);base=16;}
    if(text.empty()) return std::unexpected(std::errc::invalid_argument);
    uint64_t value=0;
    const auto [end,error]=std::from_chars(text.data(),text.data()+text.size(),value,base);
    if(error!=std::errc{} || end!=text.data()+text.size()) return std::unexpected(std::errc::invalid_argument);
    return value;
}
std::expected<std::string,std::errc> utf16(std::span<const uint8_t> bytes) {
    std::string result;
    for (size_t i=0;i<bytes.size();i+=2) {
        uint32_t cp=static_cast<uint32_t>(le(bytes,i,2));
        if (!cp) return result;
        if (cp>=0xd800 && cp<=0xdbff) {
            if (i+3>=bytes.size()) return std::unexpected(std::errc::illegal_byte_sequence);
            auto low=le(bytes,i+2,2);
            if(low<0xdc00 || low>0xdfff) return std::unexpected(std::errc::illegal_byte_sequence);
            cp=0x10000+((cp-0xd800)<<10)+static_cast<uint32_t>(low-0xdc00); i+=2;
        } else if(cp>=0xdc00 && cp<=0xdfff) return std::unexpected(std::errc::illegal_byte_sequence);
        if(cp<128) result+=static_cast<char>(cp);
        else {
            if(cp<0x800) result+=static_cast<char>(0xc0|(cp>>6));
            else {
                if(cp<0x10000) result+=static_cast<char>(0xe0|(cp>>12));
                else { result+=static_cast<char>(0xf0|(cp>>18)); result+=static_cast<char>(0x80|((cp>>12)&63)); }
                result+=static_cast<char>(0x80|((cp>>6)&63));
            }
            result+=static_cast<char>(0x80|(cp&63));
        }
    }
    return std::unexpected(std::errc::bad_message); // fixed strings require a terminator
}
}

std::expected<PacArchive, std::errc> PacArchive::open(const std::filesystem::path& path,
    uint32_t storage, std::stop_token stop, const io::PrepareObserver& progress) {
    auto frozen=io::Image::prepare_blob(path,UINT64_MAX,stop,progress);
    if(!frozen) return std::unexpected(frozen.error());
    PacArchive archive(std::move(*frozen));
    auto read=archive.container_.reader();
    std::array<uint8_t,2124> header{};
    if(auto r=read(0,header,stop); !r) return std::unexpected(r.error());
    auto version=utf16(std::span(header).first(44));
    if(!version || (*version!="BP_R1.0.0" && *version!="BP_R2.0.0"))
        return std::unexpected(std::errc::not_supported);
    const auto size=le(header,48)+(le(header,44)<<32);
    if(size!=archive.container_.size() || le(header,2116)!=0xfffafffa ||
        pac_crc16(0,std::span(header).first(2120))!=le(header,2120,2))
        return std::unexpected(std::errc::bad_message);
    const bool encrypted=le(header,1316,2)!=0;
    const auto count=le(header,1076), table=le(header,1080);
    constexpr uint64_t cell=2580;
    if(!count || table<header.size() || table>size || count>(size-table)/cell || count>16384)
        return std::unexpected(std::errc::message_size);
    const uint64_t table_size=encrypted?le(header,1324):count*cell;
    if(table_size!=count*cell || table_size>size-table ||
        (encrypted && le(header,1320)!=count*cell)) return std::unexpected(std::errc::bad_message);
    auto product=utf16(std::span(header).subspan(52,512));
    if(!product) return std::unexpected(product.error());
    archive.product_=std::move(*product);
    archive.repartition_strategy_=static_cast<uint32_t>(le(header,1092));
    if(archive.repartition_strategy_>3) return std::unexpected(std::errc::not_supported);
    // Validate the complete retained bytes, including unused images, before I/O.
    std::vector<uint8_t> buffer(1024*1024);
    uint16_t crc=0;
    for(uint64_t at=header.size();at<size;) {
        auto bytes=std::span(buffer).first(static_cast<size_t>(std::min<uint64_t>(buffer.size(),size-at)));
        if(auto r=read(at,bytes,stop); !r) return std::unexpected(r.error());
        crc=pac_crc16(crc,bytes); at+=bytes.size();
        if(progress) progress({io::PreparePhase::Checksum,at,size});
    }
    if(crc!=le(header,2122,2)) return std::unexpected(std::errc::bad_message);
    std::vector<uint8_t> file_table(static_cast<size_t>(table_size));
    if(auto r=read(table,file_table,stop);!r) return std::unexpected(r.error());
    if(encrypted) {
        auto decoded=decode_pac_table(file_table,static_cast<uint16_t>(le(header,1318,2)),stop);
        if(!decoded) return std::unexpected(decoded.error());
        file_table=std::move(*decoded);
    }
    struct Entry { std::string name; uint64_t offset,length; uint32_t flag,selected; };
    std::map<std::string,Entry> entries;
    std::vector<std::pair<uint64_t,uint64_t>> ranges;
    std::string xml;
    for(uint64_t i=0;i<count;++i) {
        const auto bytes=std::span<const uint8_t>(file_table).subspan(static_cast<size_t>(i*cell),cell);
        auto id=utf16(std::span(bytes).subspan(4,512));
        auto name=utf16(std::span(bytes).subspan(516,512));
        if(le(bytes,0)!=cell || !id || !name || le(bytes,1560)>5)
            return std::unexpected(std::errc::bad_message);
        const auto length=le(bytes,1540)+(le(bytes,1532)<<32);
        const auto offset=le(bytes,1552)+(le(bytes,1536)<<32);
        if(length && (offset<table+count*cell || offset>size || length>size-offset))
            return std::unexpected(std::errc::message_size);
        if(length) ranges.emplace_back(offset,offset+length);
        const auto flag=static_cast<uint32_t>(le(bytes,1544));
        const auto selected=static_cast<uint32_t>(le(bytes,1548));
        std::string extension=*name;
        for(auto& c:extension) if(c>='A' && c<='Z') c+=32;
        if(extension.ends_with(".xml")) {
            if(flag!=2 || selected || !xml.empty() || length>8*1024*1024 || !length)
                return std::unexpected(std::errc::bad_message);
            std::vector<uint8_t> data(static_cast<size_t>(length));
            if(auto r=read(offset,data,stop); !r) return std::unexpected(r.error());
            xml.assign(data.begin(),data.end());
            continue;
        }
        if(id->empty() || selected>1 || (flag!=0 && flag!=1 && flag!=257) || ((flag!=0)!=bool(length)))
            return std::unexpected(std::errc::not_supported);
        if(!entries.emplace(key(*id),Entry{*name,offset,length,flag,selected}).second)
            return std::unexpected(std::errc::bad_message);
    }
    std::sort(ranges.begin(),ranges.end());
    for(size_t i=1;i<ranges.size();++i) if(ranges[i].first<ranges[i-1].second)
        return std::unexpected(std::errc::bad_message);
    using Node=PacParser::XmlElement;
    auto document=PacParser::parse_document(std::move(xml),8*1024*1024);
    if(!document)return std::unexpected(document.error());
    auto root=std::move(*document);
    if(!root || root->tag!="BMAConfig") return std::unexpected(std::errc::bad_message);
    // Repeated list elements are valid; singleton children are not. Reject
    // ambiguity before child() can conflate a duplicate with an absent node.
    const auto unique_children=[&](auto&& self,const Node& node)->bool {
        std::set<std::string> seen;
        for(const auto& item:node.children) {
            const bool list=(node.tag=="ProductList" && item->tag=="Product") ||
                (node.tag=="SchemeList" && item->tag=="Scheme") || (node.tag=="Scheme" && item->tag=="File") ||
                (node.tag=="Partitions" && item->tag=="Partition") || (node.tag=="NVBackup" && item->tag=="NVItem") ||
                (node.tag=="BackupFlag" && item->tag=="NVFlag");
            if((!list && !seen.insert(item->tag).second) || !self(self,*item)) return false;
        }
        return true;
    };
    if(!unique_children(unique_children,*root)) return std::unexpected(std::errc::bad_message);
    const auto child=[](const Node& node,std::string_view tag)->const Node* {
        const Node* result=nullptr;
        for(const auto& n:node.children) if(n->tag==tag) { if(result) return nullptr; result=n.get(); }
        return result;
    };
    const auto text_of=[&](const Node& node,std::string_view tag) {
        const auto* n=child(node,tag); return n?n->text:std::string{};
    };
    const auto named=[](const Node* parent,std::string_view tag,std::string_view name)->const Node* {
        const Node* result=nullptr;
        if(!parent) return nullptr;
        for(const auto& node:parent->children) if(node->tag==tag && node->attrs.contains("name") && node->attrs.at("name")==name) {
            if(result) return nullptr;
            result=node.get();
        }
        return result;
    };
    auto products=child(*root,"ProductList");
    auto prod=named(products,"Product",archive.product_);
    auto schemes=child(*root,"SchemeList");
    auto scheme=prod?named(schemes,"Scheme",text_of(*prod,"SchemeName")):nullptr;
    if(!prod || !scheme || !prod->attrs.contains("name") || prod->attrs.at("name")!=archive.product_ ||
        !scheme->attrs.contains("name") || scheme->attrs.at("name")!=text_of(*prod,"SchemeName"))
        return std::unexpected(std::errc::bad_message);
    // A Scheme is executable input. Unknown child operations cannot disappear
    // merely because the ordinary image loop does not recognize their tag.
    for(const auto& node:scheme->children) if(node->tag!="File") {
        log_diag("{pac} unsupported Scheme element: "+node->tag);
        return std::unexpected(std::errc::not_supported);
    }
    archive.partition_layout_.legacy_gpt=true;
    if(const auto partitions=child(*prod,"Partitions")) {
        std::set<std::string> names;
        for(const auto& partition:partitions->children) {
            if(partition->tag!="Partition" || !partition->attrs.contains("id") || !partition->attrs.contains("size"))
                return std::unexpected(std::errc::bad_message);
            const auto& name=partition->attrs.at("id");
            if(!protocol::valid_partition_name(name) || !names.insert(name).second) return std::unexpected(std::errc::bad_message);
            auto value=partition->attrs.at("size"); int radix=10;
            if(value.starts_with("0x") || value.starts_with("0X")) {value.erase(0,2);radix=16;}
            uint64_t size=0;
            auto [end,ec]=std::from_chars(value.data(),value.data()+value.size(),size,radix);
            if(ec!=std::errc{} || end!=value.data()+value.size() || !size || size>UINT32_MAX)
                return std::unexpected(std::errc::bad_message);
            PacPartition p; p.name=name; p.size=size==UINT32_MAX?UINT64_MAX:size*1048576;
            archive.partition_layout_.partitions.push_back(std::move(p));
        }
        auto table=PacParser::build_repartition_table(archive.partition_layout_);
        if(!table) return std::unexpected(table.error());
    }
    const auto nv_rules=[&]() -> std::expected<std::vector<NvMergeItem>,std::errc> {
        const auto config=child(*prod,"NVBackup");
        if(!config || !config->attrs.contains("backup") || config->attrs.at("backup")!="1")
            return std::unexpected(std::errc::not_supported);
        std::vector<NvMergeItem> rules;
        std::set<uint16_t> seen;
        bool add_imei_slots=false;
        for(const auto& item:config->children) {
            if(item->tag!="NVItem") return std::unexpected(std::errc::not_supported);
            if(!item->attrs.contains("backup")) return std::unexpected(std::errc::bad_message);
            if(item->attrs.at("backup")=="0") continue;
            if(item->attrs.at("backup")!="1") return std::unexpected(std::errc::bad_message);
            auto value=text_of(*item,"ID");
            int radix=10;
            if(value.starts_with("0x") || value.starts_with("0X")) { value.erase(0,2); radix=16; }
            uint32_t id=0;
            auto [end,ec]=std::from_chars(value.data(),value.data()+value.size(),id,radix);
            NvItemKind kind=NvItemKind::Ordinary;
            bool imei_group=false;
            if(ec==std::errc{} && end==value.data()+value.size() && id==UINT32_MAX && item->attrs.contains("name")) {
                const auto& group=item->attrs.at("name");
                // DLFramework 0x2ec79/0x2ed8a supplies these defaults. IMEI
                // additionally uses an INI-configured list, handled separately.
                if(group=="Calibration") {id=2;kind=NvItemKind::GsmCalibration;}
                else if(group=="TD_Calibration") {id=0x516;kind=NvItemKind::TdCalibration;}
                else if(group=="W_Calibration") id=0x12d;
                else if(group=="LTE_Calibration") id=0x9c4;
                else if(group=="IMEI") {id=5;imei_group=true;}
            }
            if(id==2 || id==0x8036) kind=NvItemKind::GsmCalibration;
            if(id==0x516 || id==0x8295) kind=NvItemKind::TdCalibration;
            if(id==0x191) kind=NvItemKind::BluetoothConfig;
            if(ec!=std::errc{} || end!=value.data()+value.size() || id==0 || id>=0xfffe) {
                log_diag("{pac} NV group/schema is not implemented: "+(item->attrs.contains("name")?item->attrs.at("name"):value));
                return std::unexpected(std::errc::not_supported);
            }
            bool missing=false;
            const auto flags=child(*item,"BackupFlag");
            if(flags && flags->attrs.contains("use") && flags->attrs.at("use")=="1") {
                std::set<std::string> flag_names;
                for(const auto& flag:flags->children) {
                    if(flag->tag!="NVFlag" || !flag->attrs.contains("name") || !flag->attrs.contains("check"))
                        return std::unexpected(std::errc::bad_message);
                    const auto& check=flag->attrs.at("check");
                    if(!flag_names.insert(flag->attrs.at("name")).second) return std::unexpected(std::errc::bad_message);
                    if(check!="0" && check!="1") return std::unexpected(std::errc::bad_message);
                    if(flag->attrs.at("name")=="Continue") missing=check=="1";
                    else if(flag->attrs.at("name")=="Replace") {
                        // Generic 0x10028290 copies equal-size items regardless
                        // of Replace. GSM/TD use separate versioned handlers.
                        // Calibration schema versions are checked against both
                        // images by nv_merge_items; no whole-record fallback.
                    } else return std::unexpected(std::errc::not_supported);
                }
            } else if(flags && (!flags->attrs.contains("use") || flags->attrs.at("use")!="0"))
                return std::unexpected(std::errc::bad_message);
            if(!seen.insert(static_cast<uint16_t>(id)).second) return std::unexpected(std::errc::bad_message);
            rules.push_back({static_cast<uint16_t>(id),missing,{},kind});
            // R27 BMFileType.ini [IMEI_ID]. The primary item is required;
            // additional SIM slots are optional because not every model has
            // all slots. Explicit XML rules take precedence over these defaults.
            add_imei_slots |= imei_group;
        }
        if(add_imei_slots) for(uint16_t slot:{uint16_t(0x179),uint16_t(0x186),uint16_t(0x1e4)})
            if(seen.insert(slot).second) rules.push_back({slot,true});
        if(rules.empty()) return std::unexpected(std::errc::not_supported);
        return rules;
    };
    std::set<std::string> consumed, ids, written;
    for(const auto& node:scheme->children) {
        if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
        const auto id=key(text_of(*node,"ID")), type=text_of(*node,"Type");
        if(id.empty() || !ids.insert(id).second) return std::unexpected(std::errc::bad_message);
        const auto found=entries.find(id);
        if(found==entries.end() || !found->second.selected) {
            if(text_of(*node,"CheckFlag")=="1") return std::unexpected(std::errc::no_such_file_or_directory);
            continue;
        }
        consumed.insert(id);
        const auto& entry=found->second;
        const std::set<std::string> fields{"ID","IDAlias","Type","Block","Flag","CheckFlag","Description"};
        std::set<std::string> present;
        for(const auto& field:node->children) {
            if(!fields.contains(field->tag)) {
                log_diag("{pac} unsupported File field: "+id+"/"+field->tag);
                return std::unexpected(std::errc::not_supported);
            }
            if(!present.insert(field->tag).second) return std::unexpected(std::errc::bad_message);
        }
        if(const auto check=child(*node,"CheckFlag");check && check->text!="0" && check->text!="1" && check->text!="2")
            return std::unexpected(std::errc::bad_message);
        if(const auto block=child(*node,"Block")) {
            std::set<std::string> block_fields;
            for(const auto& field:block->children)
                if((field->tag!="Base" && field->tag!="Size") || !block_fields.insert(field->tag).second)
                    return std::unexpected(std::errc::not_supported);
            for(const auto& [attribute,value]:block->attrs) {
                (void)value;
                if(attribute!="id") return std::unexpected(std::errc::not_supported);
            }
        }
        const auto flag=text_of(*node,"Flag");
        if((flag!="0" && flag!="1") || (flag=="1" && !entry.length))
            return std::unexpected(std::errc::bad_message);
        if(!node->attrs.empty()) for(const auto& [attribute,value]:node->attrs)
            if(attribute!="backup" || (value!="0" && value!="1")) return std::unexpected(std::errc::not_supported);
        if(node->attrs.contains("backup") && node->attrs.at("backup")=="1" && type!="NV" && type!="NV_NAND") {
            const auto block=child(*node,"Block");
            if(!block || !block->attrs.contains("id") || !protocol::valid_partition_name(block->attrs.at("id")))
                return std::unexpected(std::errc::bad_message);
            if(std::find(archive.backup_targets_.begin(),archive.backup_targets_.end(),block->attrs.at("id"))==archive.backup_targets_.end())
                archive.backup_targets_.push_back(block->attrs.at("id"));
        }
        if(pac_control_operation(type)) {
            const bool table=type=="EXTTABLE";
            if((table?(!entry.length || entry.length>65528 || flag!="1"):(entry.length || flag!="0")) || node->attrs.contains("backup"))
                return std::unexpected(std::errc::bad_message);
            if(const auto block=child(*node,"Block")) {
                auto base=number(text_of(*block,"Base")),size=number(text_of(*block,"Size"));
                if(!base || !size || *base || *size) return std::unexpected(std::errc::bad_message);
            }
            archive.actions_.push_back({id,{},type,entry.offset,entry.length,false});
            continue;
        }
        if(pac_address_operation(type)) {
            const auto block=child(*node,"Block");
            if(!block || (node->attrs.contains("backup") && type!="NV" && type!="NV_NAND")) return std::unexpected(std::errc::not_supported);
            auto base=number(text_of(*block,"Base")),size=number(text_of(*block,"Size"));
            const bool reading=pac_address_read(type),erasing=type=="EraseFlash";
            if(!base || !size || *base>UINT32_MAX || *size>UINT32_MAX ||
                ((reading||erasing)?(entry.length || !*size):!entry.length)) return std::unexpected(std::errc::bad_message);
            const auto length=(reading||erasing)?*size:entry.length+(entry.length&1);
            if(!(erasing && *size==UINT32_MAX) && length>uint64_t(UINT32_MAX)+1-*base)
                return std::unexpected(std::errc::value_too_large);
            PacAction action{id,"address",type,entry.offset,entry.length,erasing};
            action.load_address=static_cast<uint32_t>(*base);action.declared_size=*size;
            if(type=="NV" || type=="NV_NAND") {
                if(*size<8||(*size&1)||*size>16*1024*1024||entry.length>*size||*size>uint64_t(UINT32_MAX)+1-*base)
                    return std::unexpected(std::errc::message_size);
                auto rules=nv_rules();if(!rules)return std::unexpected(rules.error());action.nv_items=std::move(*rules);
            }
            archive.actions_.push_back(std::move(action));continue;
        }
        if(type=="FDL" || type=="NAND_FDL") {
            const auto block=child(*node,"Block");
            if(!block || !entry.length || entry.length>16*1024*1024) return std::unexpected(std::errc::bad_message);
            auto address=text_of(*block,"Base");
            int radix=10;
            if(address.starts_with("0x") || address.starts_with("0X")) { address.erase(0,2); radix=16; }
            uint32_t value=0;
            auto [end,ec]=std::from_chars(address.data(),address.data()+address.size(),value,radix);
            if(ec!=std::errc{} || end!=address.data()+address.size() || address.empty() ||
                entry.length>uint64_t(UINT32_MAX)+1-value) return std::unexpected(std::errc::bad_message);
            if(std::any_of(archive.loaders_.begin(),archive.loaders_.end(),[&](const auto& l){return l.type==type;}))
                return std::unexpected(std::errc::bad_message);
            archive.loaders_.push_back({id,{},type,entry.offset,entry.length,false,value});
            continue;
        }
        // PhaseCheck without a payload is the factory backup placeholder,
        // not a request to erase or overwrite miscdata.
        if(id=="PHASECHECK" && type=="CODE2" && !entry.flag && !entry.length &&
            text_of(*node,"Flag")=="0" && node->attrs.contains("backup") && node->attrs.at("backup")=="1") {
            log_status(LogLevel::Info,"PAC preserve","miscdata (PhaseCheck has no replacement image)");
            continue;
        }
        const auto block=child(*node,"Block");
        if(!block || !block->attrs.contains("id") || !protocol::valid_partition_name(block->attrs.at("id")))
            return std::unexpected(std::errc::bad_message);
        auto base=number(text_of(*block,"Base"));
        if(type=="CHECK_NV2" && (!base || *base!=0)) return std::unexpected(std::errc::invalid_argument);
        const bool read_operation=pac_read_operation(type);
        const bool spl_address=type=="UBOOT_LOADER2" && block->attrs.at("id")=="splloader" && base && *base==0x80000000;
        if(!base || (!read_operation && !spl_address && *base!=0))
            return std::unexpected(std::errc::not_supported);
        const bool erase=type=="EraseFlash2";
        if(!erase && !read_operation && type!="CODE2" && type!="MiscDataCode2" && type!="YAFFS_IMG2" && type!="CODE2_64" && type!="YAFFS_IMG2_64" && type!="BOOT_LOADER2" && type!="UBOOT_LOADER2" && type!="NV_COMM") {
            log_diag("{pac} unsupported selected operation: "+id+" type="+type);
            return std::unexpected(std::errc::not_supported); // NV merge/security transformations require separate semantics
        }
        auto block_size=number(text_of(*block,"Size"));
        if(!block_size || (read_operation ? (entry.length!=0 || !*block_size || *base>UINT64_MAX-*block_size) :
            erase ? (entry.length!=0 || *block_size!=0) : entry.length==0))
            return std::unexpected(std::errc::bad_message);
        if(!erase && type=="NV_COMM" && *block_size && entry.length>*block_size)
            return std::unexpected(std::errc::message_size);
        const auto& target=block->attrs.at("id");
        const bool spl=id=="SPLLOADEREMMC" || id=="SPLLOADERUFS" || id=="SPLLOADER";
        if(!erase && !read_operation && !spl && !written.insert(target).second) return std::unexpected(std::errc::bad_message);
        archive.actions_.push_back({id,target,type,entry.offset,entry.length,erase});
        archive.actions_.back().declared_size=*block_size;
        archive.actions_.back().read_offset=read_operation?*base:0;
        if(type=="NV_COMM") {
            auto rules=nv_rules();
            if(!rules) return std::unexpected(rules.error());
            archive.actions_.back().nv_items=std::move(*rules);
        }
    }
    // Official OperationHelper::GetDLFiles iterates the XML product's file
    // list, not every PAC record. Old packages retain obsolete selection IDs.
    for(const auto& [id,entry]:entries) if(entry.selected && !consumed.contains(id))
        log_status(LogLevel::Info,"PAC unused record",id + " (absent from selected XML scheme)");
    if(archive.actions_.empty()) return std::unexpected(std::errc::invalid_argument);
    if(storage) {
        auto selected=archive.selected_actions(storage);
        if(!selected)return std::unexpected(selected.error());
    }
    return archive;
}
std::expected<std::vector<PacAction>,std::errc> PacArchive::selected_actions(uint32_t storage) const {
    if(storage!=0x102 && storage!=0x103) {
        // Legacy address packages need no UFS/eMMC name/role routing. An absent
        // storage announcement is not evidence against that explicit dialect.
        if(!partition_layout_.partitions.empty() || !backup_targets_.empty() ||
            std::any_of(actions_.begin(),actions_.end(),[](const auto& a){return !pac_address_operation(a.type) && !pac_control_operation(a.type);}))
            return std::unexpected(std::errc::not_supported);
    }
    const std::string id=storage==0x102?"SPLLOADEREMMC":"SPLLOADERUFS";
    const bool specific=std::any_of(actions_.begin(),actions_.end(),[&](const auto& a){return a.id==id;});
    std::vector<PacAction> result;
    std::set<std::string> writes;
    bool terminal=false;
    for(const auto& action:actions_) {
        const bool spl=action.id=="SPLLOADEREMMC" || action.id=="SPLLOADERUFS" || action.id=="SPLLOADER";
        if(spl && (specific ? action.id!=id : action.id!="SPLLOADER")) continue;
        if(terminal) return std::unexpected(std::errc::invalid_argument);
        if(pac_control_operation(action.type)) {
            terminal=action.type=="Reset" || action.type=="PowerOff";
            result.push_back(action);continue;
        }
        if(pac_address_operation(action.type)) {result.push_back(action);continue;}
        if(!action.erase && !pac_read_operation(action.type) && !writes.insert(action.partition).second) return std::unexpected(std::errc::bad_message);
        result.push_back(action);
    }
    if(result.empty()) return std::unexpected(std::errc::bad_message);
    return result;
}
std::expected<std::vector<uint8_t>,std::errc> PacArchive::loader_bytes(const PacAction& loader,std::stop_token stop) const {
    if(loader.length>16*1024*1024 || !loader.length) return std::unexpected(std::errc::file_too_large);
    std::vector<uint8_t> data(static_cast<size_t>(loader.length));
    auto read=container_.reader()(loader.offset,data,stop);
    if(!read) return std::unexpected(read.error());
    // Loader bytes are already bounded and covered by the PAC CRC. Their
    // signature/wrapper ABI belongs to the preceding boot stage, not to the
    // host's optional offline BTHD parser.
    return data;
}
std::expected<io::Image,std::errc> PacArchive::image(const PacAction& action,uint64_t capacity,
    std::stop_token stop,const io::PrepareObserver& progress) const {
    if(action.declared_size) capacity=std::min(capacity,action.declared_size);
    if(action.type=="NV_COMM" || action.type=="NV" || action.type=="NV_NAND" || action.type=="EXTTABLE") {
        if(action.length>capacity) return std::unexpected(std::errc::file_too_large);
        return container_.blob_region(action.offset,action.length);
    }
    return container_.region(action.offset,action.length,capacity,stop,progress);
}
std::expected<io::Image,std::errc> PacArchive::transfer_image(const PacAction& action,uint64_t capacity,
    std::stop_token stop,const io::PrepareObserver& progress,uint64_t* expanded_size) const {
    auto checked=image(action,capacity,stop,progress);
    if(!checked) return std::unexpected(checked.error());
    if(expanded_size) *expanded_size=checked->size();
    return container_.blob_region(action.offset,action.length);
}
}

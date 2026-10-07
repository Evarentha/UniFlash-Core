#include <uniflash/session/nv_image.h>
#include <algorithm>
#include <map>

namespace uniflash::session {
namespace {
uint32_t le(std::span<const uint8_t> data, size_t at, size_t count=4) {
    uint32_t value=0;
    for(size_t i=0;i<count;++i) value |= uint32_t(data[at+i])<<(8*i);
    return value;
}
void put(std::span<uint8_t> data,size_t at,uint32_t value) {
    for(size_t i=0;i<4;++i) data[at+i]=static_cast<uint8_t>(value>>(8*i));
}
struct Item { size_t offset, size; };
std::expected<std::map<uint16_t,Item>,std::errc> index(std::span<const uint8_t> data,size_t at=4,bool big=false) {
    std::map<uint16_t,Item> result;
    const auto word=[&](size_t offset){return big?uint32_t(data[offset])*256+data[offset+1]:le(data,offset,2);};
    while(at<=data.size() && data.size()-at>=2) {
        const auto id=static_cast<uint16_t>(word(at));
        if(id==0xffff) return result;
        // INDX is parsed as a container by cores(), never as an ordinary item.
        if(id==0) return std::unexpected(std::errc::not_supported);
        if(data.size()-at<4) return std::unexpected(std::errc::bad_message);
        const auto length=word(at+2);
        at+=4;
        if(length>data.size()-at)
            return std::unexpected(std::errc::bad_message);
        if(id==0xfffe) {
            // R27 emits a final padding record to reach a 512-byte core size.
            if(at+length!=data.size()) return std::unexpected(std::errc::bad_message);
            return result;
        }
        if(!result.emplace(id,Item{at,length}).second) return std::unexpected(std::errc::bad_message);
        at+=length;
        const auto padding=(4-at%4)%4;
        if(padding>data.size()-at) return std::unexpected(std::errc::bad_message);
        at+=padding;
    }
    return std::unexpected(std::errc::bad_message);
}
using Items=std::map<uint16_t,Item>;
using Cores=std::map<std::string,Items>;
std::expected<Cores,std::errc> cores(std::span<const uint8_t> data,bool big=false,bool indexed_big=false) {
    Cores result;
    if(data.size()<8) return std::unexpected(std::errc::bad_message);
    if(le(data,4,2)!=0) {
        if(indexed_big) return std::unexpected(std::errc::bad_message);
        auto flat=index(data,4,big);
        if(!flat) return std::unexpected(flat.error());
        result.emplace("",std::move(*flat));return result;
    }
    if(big && !indexed_big) return std::unexpected(std::errc::not_supported); // no BE outer INDX ABI
    // Header at payload+8, descriptors at +16; descriptor offsets are
    // absolute within the NV payload. Core item lists start at byte zero.
    if(data.size()<16 || le(data,8)!=0x58444e49 || le(data,12,2)!=0)
        return std::unexpected(std::errc::not_supported);
    const auto count=le(data,14,2), length=le(data,6,2);
    if(!count || count>(data.size()-16)/24 || length<8+count*24 || length>data.size()-8)
        return std::unexpected(std::errc::bad_message);
    const size_t table_end=8+((size_t(length)+3)&~size_t(3));
    std::vector<std::pair<size_t,size_t>> ranges;
    for(size_t i=0;i<count;++i) {
        const auto at=16+i*24;
        const auto name_bytes=data.subspan(at,16);
        auto end=std::find(name_bytes.begin(),name_bytes.end(),uint8_t{0});
        if(end==name_bytes.begin()) return std::unexpected(std::errc::bad_message);
        const std::string name(name_bytes.begin(),end);
        const size_t offset=le(data,at+16),size=le(data,at+20);
        if(offset<table_end || offset%4 || offset>data.size() || !size || size>data.size()-offset)
            return std::unexpected(std::errc::bad_message);
        ranges.emplace_back(offset,offset+size);
        auto items=index(data.subspan(offset,size),0,big);
        if(!items) return std::unexpected(items.error());
        for(auto& [id,item]:*items) { (void)id;item.offset+=offset; }
        if(!result.emplace(name,std::move(*items)).second) return std::unexpected(std::errc::bad_message);
    }
    std::sort(ranges.begin(),ranges.end());
    for(size_t i=1;i<ranges.size();++i) if(ranges[i].first<ranges[i-1].second)
        return std::unexpected(std::errc::bad_message);
    return result;
}
}
uint16_t nv_disk_checksum(std::span<const uint8_t> data,NvChecksumWidth width) {
    uint64_t sum=0;
    for(size_t i=0;i<data.size();i+=2) {
        sum+=uint64_t(data[i]) | (i+1<data.size()?uint64_t(data[i+1])<<8:0);
        if(width==NvChecksumWidth::Bits32) sum=static_cast<uint32_t>(sum);
    }
    // Match the actual firmware's two folds, including unsigned-long width.
    sum=(sum>>16)+(sum&0xffff);
    sum+=sum>>16;
    return static_cast<uint16_t>(~sum);
}
uint32_t nv_transfer_checksum(std::span<const uint8_t> data) {
    uint32_t sum=0;
    for(auto byte:data) sum+=byte;
    return sum;
}
std::expected<std::vector<uint8_t>,std::errc> nv_decode_physical(
    std::span<const uint8_t> data,uint32_t expected_size) {
    if(data.size()<512 || !expected_size || le(data,0)!=0x4e56 || le(data,12)!=101 ||
        le(data,4)!=expected_size || expected_size>data.size()-512 || le(data,8)>0xffff)
        return std::unexpected(std::errc::bad_message);
    const auto payload=data.subspan(512,expected_size);
    if(nv_disk_checksum(payload,NvChecksumWidth::Bits32)!=le(data,8) &&
       nv_disk_checksum(payload,NvChecksumWidth::Bits64)!=le(data,8))
        return std::unexpected(std::errc::bad_message);
    return std::vector<uint8_t>(payload.begin(),payload.end());
}
std::vector<uint8_t> nv_physical_image(std::span<const uint8_t> payload,NvChecksumWidth width) {
    std::vector<uint8_t> result(512+payload.size());
    put(result,0,0x4e56); put(result,4,static_cast<uint32_t>(payload.size()));
    put(result,8,nv_disk_checksum(payload,width)); put(result,12,101);
    std::copy(payload.begin(),payload.end(),result.begin()+512);
    return result;
}
std::expected<void,std::errc> validate_nv_merge_rules(std::span<const NvMergeItem> rules,
    NvByteOrder old_order,NvByteOrder new_order) {
    const auto valid=[](NvByteOrder o){return o==NvByteOrder::Little || o==NvByteOrder::BigItemHeaders ||
        o==NvByteOrder::ReversedWords || o==NvByteOrder::LittleIndexBigItemHeaders;};
    if(!valid(old_order) || !valid(new_order)) return std::unexpected(std::errc::invalid_argument);
    std::map<std::pair<std::string,uint16_t>,bool> seen;
    for(const auto& rule:rules) {
        if(!rule.id || rule.id>=0xfffe || !seen.emplace(std::pair{rule.core,rule.id},true).second)
            return std::unexpected(std::errc::invalid_argument);
        switch(rule.kind) {
        case NvItemKind::Ordinary:
        case NvItemKind::GsmCalibration:
        case NvItemKind::TdCalibration: break;
        case NvItemKind::BluetoothConfig:
            if(rule.id!=0x191) return std::unexpected(std::errc::invalid_argument);
            break;
        default: return std::unexpected(std::errc::invalid_argument);
        }
    }
    const bool old_big=old_order==NvByteOrder::BigItemHeaders || old_order==NvByteOrder::LittleIndexBigItemHeaders;
    const bool new_big=new_order==NvByteOrder::BigItemHeaders || new_order==NvByteOrder::LittleIndexBigItemHeaders;
    if(old_big!=new_big && (rules.empty() || std::any_of(rules.begin(),rules.end(),[](const auto& r){return r.kind!=NvItemKind::BluetoothConfig;})))
        return std::unexpected(std::errc::not_supported);
    if((old_big || new_big) && std::any_of(rules.begin(),rules.end(),[](const auto& r){return r.kind!=NvItemKind::Ordinary && r.kind!=NvItemKind::BluetoothConfig;}))
        return std::unexpected(std::errc::not_supported);
    return {};
}
std::expected<std::vector<uint8_t>,std::errc> nv_merge_items(std::span<const uint8_t> old_payload,
    std::span<const uint8_t> new_payload,uint32_t output_size,std::span<const NvMergeItem> rules,
    NvByteOrder old_order,NvByteOrder new_order) {
    auto contract=validate_nv_merge_rules(rules,old_order,new_order);
    if(!contract)return std::unexpected(contract.error());
    if(old_order==NvByteOrder::ReversedWords || new_order==NvByteOrder::ReversedWords) {
        if(output_size<8 || new_payload.size()>output_size || old_payload.size()!=output_size)
            return std::unexpected(std::errc::message_size);
        if(old_payload.size()%4 || new_payload.size()%4 || output_size%4) return std::unexpected(std::errc::message_size);
        std::vector<uint8_t> old_bytes(old_payload.begin(),old_payload.end()),new_bytes(new_payload.begin(),new_payload.end());
        const auto reverse=[](std::vector<uint8_t>& bytes){for(size_t i=0;i<bytes.size();i+=4) std::reverse(bytes.begin()+i,bytes.begin()+i+4);};
        if(old_order==NvByteOrder::ReversedWords) reverse(old_bytes);
        if(new_order==NvByteOrder::ReversedWords) reverse(new_bytes);
        auto result=nv_merge_items(old_bytes,new_bytes,output_size,rules,
            old_order==NvByteOrder::ReversedWords?NvByteOrder::Little:old_order,
            new_order==NvByteOrder::ReversedWords?NvByteOrder::Little:new_order);
        if(result && new_order==NvByteOrder::ReversedWords) reverse(*result);
        return result;
    }
    // Different header orders can imply different payload layouts. Only the
    // explicitly selected, audited BT_CONFIG schema can cross this boundary.
    const bool old_big=old_order==NvByteOrder::BigItemHeaders || old_order==NvByteOrder::LittleIndexBigItemHeaders;
    const bool new_big=new_order==NvByteOrder::BigItemHeaders || new_order==NvByteOrder::LittleIndexBigItemHeaders;
    const bool cross_order=old_big!=new_big;
    if(output_size<8 || new_payload.size()>output_size || old_payload.size()!=output_size)
        return std::unexpected(std::errc::message_size);
    auto old_cores=cores(old_payload,old_big,old_order==NvByteOrder::LittleIndexBigItemHeaders);
    auto new_cores=cores(new_payload,new_big,new_order==NvByteOrder::LittleIndexBigItemHeaders);
    if(!old_cores) return std::unexpected(old_cores.error());
    if(!new_cores) return std::unexpected(new_cores.error());
    if(old_cores->contains("")!=new_cores->contains("")) return std::unexpected(std::errc::not_supported);
    if(!old_cores->contains("")) {
        if(old_cores->size()!=new_cores->size()) return std::unexpected(std::errc::not_supported);
        for(const auto& [name,items]:*old_cores) {
            (void)items;
            if(!new_cores->contains(name)) return std::unexpected(std::errc::not_supported);
        }
    }
    std::vector<uint8_t> result(output_size,0xff);
    std::copy(new_payload.begin(),new_payload.end(),result.begin());
    for(const auto& rule:rules) {
        bool matched=false;
        for(const auto& [core,new_items]:*new_cores) {
            if(!rule.core.empty() && core!=rule.core) continue;
            const auto old_core=old_cores->find(core);
            const auto fresh=new_items.find(rule.id);
            if(fresh==new_items.end()) {
                if(!rule.allow_missing && old_core!=old_cores->end() && old_core->second.contains(rule.id))
                    return std::unexpected(std::errc::no_such_file_or_directory);
                continue;
            }
            if(old_core==old_cores->end()) {
                if(rule.allow_missing) continue;
                return std::unexpected(std::errc::no_such_file_or_directory);
            }
            const auto old=old_core->second.find(rule.id);
            if(old==old_core->second.end()) {
                if(rule.allow_missing) continue;
                return std::unexpected(std::errc::no_such_file_or_directory);
            }
            if(old->second.size!=fresh->second.size) return std::unexpected(std::errc::message_size);
            if(rule.kind==NvItemKind::BluetoothConfig) {
                // R27 DLFWNvDef.h BT_CONFIG and DLL 0x10028388..0x10028411:
                // byte[6] address followed by WORD xtal_dac, never a u64 swap.
                if(old->second.size!=8) return std::unexpected(std::errc::message_size);
                std::copy_n(old_payload.begin()+old->second.offset,8,result.begin()+fresh->second.offset);
                if(cross_order) std::swap(result[fresh->second.offset+6],result[fresh->second.offset+7]);
                matched=true;continue;
            }
            if(rule.kind!=NvItemKind::Ordinary) {
                if(old->second.size<2) return std::unexpected(std::errc::bad_message);
                const auto old_version=le(old_payload,old->second.offset,2);
                const auto new_version=le(new_payload,fresh->second.offset,2);
                if(old_version!=new_version) return std::unexpected(std::errc::not_supported);
                const auto copy=[&](size_t at,size_t count) {
                    std::copy_n(old_payload.begin()+old->second.offset+at,count,result.begin()+fresh->second.offset+at);
                };
                // R27 BMFileType.ini GSMCaliVaPolicy=2, DLFramework
                // 0x26ef0/0x27660: copy calibration fields into NEW template,
                // preserving version and non-calibration defaults.
                if(rule.kind==NvItemKind::GsmCalibration && (old_version==0xff0a || old_version==0xff0b)) {
                    const bool vb=old_version==0xff0b;
                    const size_t length=vb?0x1cc4:0x1784, stride=vb?0x6e8:0x598;
                    if(old->second.size!=length) return std::unexpected(std::errc::message_size);
                    copy(2,126);
                    copy(length-48,48); // ADC/calibration tail copied by policy 2
                    for(size_t band=0;band<4;++band) {
                        const size_t base=0x80+band*stride;
                        copy(base,0x40);copy(base+0x88,0xa0);copy(base+0x168,0x12);
                        copy(base+0x1a2,0xb6);copy(base+0x258,2);
                        if(vb) {
                            copy(base+0x25a,0xb6);copy(base+0x310,2);
                            copy(base+0x33a,0x96);copy(base+0x3d0,0x96);
                        } else copy(base+0x282,0x96);
                    }
                    matched=true;continue;
                }
                if(rule.kind==NvItemKind::TdCalibration && old_version==3) {
                    if(old->second.size!=0x233c) return std::unexpected(std::errc::message_size);
                    // 0x27340: leave other new-template fields untouched.
                    copy(0x14,4);copy(0x18,0xe6);copy(0xfe,0xbae);copy(0xd28,0xa28);
                    matched=true;continue;
                }
                if(rule.kind==NvItemKind::TdCalibration && old_version==4) {
                    if(old->second.size!=0x2a0c) return std::unexpected(std::errc::message_size);
                    copy(0,0x2a0a); // audited handler retains the last two template bytes
                    matched=true;continue;
                }
                // DLL 0x27e14 / 0x281f4: current formats copy the whole item.
                const uint16_t full_copy=rule.kind==NvItemKind::GsmCalibration?0xff0c:5;
                if(old_version!=full_copy || new_version!=full_copy)
                    return std::unexpected(std::errc::not_supported);
            }
            std::copy_n(old_payload.begin()+old->second.offset,old->second.size,result.begin()+fresh->second.offset);
            matched=true;
        }
        if(!matched && !rule.allow_missing) return std::unexpected(std::errc::no_such_file_or_directory);
    }
    put(result,0,le(old_payload,0)+uint32_t{1});
    return result;
}
}

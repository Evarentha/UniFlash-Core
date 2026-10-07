/*
 * UniFlash-Core / PAC Layout Plan
 *
 * Geometry comparison and equal size region relocation planning.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#include <uniflash/session/pac_layout.h>
#include <algorithm>
#include <set>

namespace uniflash::session {
bool same_partition_geometry(const layout::GptLayout& a,const layout::GptLayout& b) {
    if(a.mbr || b.mbr || a.disk_bytes!=b.disk_bytes || a.header.sector_size!=b.header.sector_size ||
        a.partitions.size()!=b.partitions.size()) return false;
    return std::all_of(a.partitions.begin(),a.partitions.end(),[&](const auto& p) {
        return std::any_of(b.partitions.begin(),b.partitions.end(),[&](const auto& q) {
            return p.name==q.name && p.offset==q.offset && p.size==q.size;
        });
    });
}
std::expected<PacLayoutPlan,std::errc> prepare_pac_layout(const layout::GptLayout& original,
    const PacImage& requested,uint32_t strategy,std::span<const std::string> replaced) {
    if(strategy>3 || original.mbr || !original.header.sector_size)
        return std::unexpected(std::errc::invalid_argument);
    PacLayoutPlan result; result.expected=original;
    if(requested.partitions.empty()) {
        if(strategy==0) return std::unexpected(std::errc::bad_message);
        return result;
    }
    auto config=requested;
    if(config.nand || !config.legacy_gpt) return std::unexpected(std::errc::not_supported);
    config.disk_size=original.disk_bytes; config.sector_size=original.header.sector_size;
    auto table=PacParser::build_repartition_table(config);
    if(!table) return std::unexpected(table.error());
    if(strategy==2) return result;
    // v0 GPT generation is confirmed only for this sector/table geometry.
    if(original.header.sector_size!=512 || original.header.entry_count!=128 ||
        original.header.entry_size!=128 || original.header.first_usable!=34 ||
        original.disk_bytes/512<68 || original.header.last_usable!=original.disk_bytes/512-34)
        return std::unexpected(std::errc::not_supported);
    auto target=original; target.partitions.clear();
    uint64_t cursor=1048576, end=(original.header.last_usable+1)*512;
    for(const auto& p:config.partitions) {
        if(cursor>=end) return std::unexpected(std::errc::no_space_on_device);
        const bool remaining=p.size==UINT64_MAX || p.size==UINT32_MAX;
        const auto size=remaining?end-cursor:p.size;
        if(!size || size>end-cursor) return std::unexpected(std::errc::no_space_on_device);
        // The audited writer rejects fixed endpoints >= last_usable_lba;
        // its final size=0 sentinel is the only fill-to-end exception.
        if((remaining ? cursor/512 : (cursor+size)/512)>=original.header.last_usable)
            return std::unexpected(std::errc::no_space_on_device);
        target.partitions.push_back({p.name,cursor,size}); cursor+=size;
    }
    const bool same=same_partition_geometry(original,target);
    if(!same && strategy==1) return std::unexpected(std::errc::state_not_recoverable);
    if((strategy==1 || strategy==3) && same) return result;
    if(!same) {
        const std::set<std::string> overwritten(replaced.begin(),replaced.end());
        for(const auto& p:original.partitions) {
            if(overwritten.contains(p.name)) continue;
            const auto next=std::find_if(target.partitions.begin(),target.partitions.end(),[&](const auto& q){return p.name==q.name;});
            // No implicit deletion/truncation. Equal-sized regions can be
            // snapshotted before GPT changes and restored at their new names.
            if(next==target.partitions.end() || next->size!=p.size) return std::unexpected(std::errc::not_supported);
            if(next->offset!=p.offset) result.relocate.push_back(p);
        }
        // A newly created partition must have explicit replacement content.
        for(const auto& p:target.partitions) if(!overwritten.contains(p.name) &&
            std::none_of(original.partitions.begin(),original.partitions.end(),[&](const auto& q){return p.name==q.name;}))
            return std::unexpected(std::errc::not_supported);
    }
    result.expected=std::move(target); result.table=std::move(*table); result.changed=!same;
    return result;
}
}

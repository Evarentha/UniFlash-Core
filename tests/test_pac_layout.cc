#include <uniflash/session/pac_layout.h>
#include <uniflash/log.h>
using namespace uniflash;
int main() {
    constexpr uint64_t MiB=1048576;
    layout::GptLayout original;
    original.disk_bytes=16*MiB;
    original.header.sector_size=512;
    original.header.entry_size=128; original.header.entry_count=128;
    original.header.first_usable=34; original.header.last_usable=original.disk_bytes/512-34;
    const auto end=(original.header.last_usable+1)*512;
    original.partitions={{"nv",MiB,MiB},{"boot",2*MiB,MiB},{"system",3*MiB,end-3*MiB}};
    session::PacImage config; config.legacy_gpt=true;
    for(const auto& p:original.partitions) {
        session::PacPartition entry; entry.name=p.name; entry.size=p.name=="system"?UINT64_MAX:p.size;
        config.partitions.push_back(entry);
    }
    const std::string replaced[]{"boot","system"};
    auto always=session::prepare_pac_layout(original,config,0,replaced);
    if(!always || always->table.empty() || always->changed) return 1;
    for(uint32_t strategy:{1u,2u,3u}) {
        auto same=session::prepare_pac_layout(original,config,strategy,replaced);
        if(!same || !same->table.empty() || same->changed) return 1;
    }
    config.partitions[1].size=2*MiB;
    auto changed=session::prepare_pac_layout(original,config,3,replaced);
    if(!changed || !changed->changed || changed->table.empty() || changed->expected.partitions[2].offset!=4*MiB) return 1;
    if(session::prepare_pac_layout(original,config,1,replaced)) return 1;
    auto ignored=session::prepare_pac_layout(original,config,2,replaced);
    if(!ignored || !ignored->table.empty() || !session::same_partition_geometry(original,ignored->expected)) return 1;
    auto no_table=session::PacImage{};
    if(session::prepare_pac_layout(original,no_table,0,replaced)) return 1;
    if(!session::prepare_pac_layout(original,no_table,1,replaced)) return 1;
    const std::string boot_only[]{"boot"};
    if(session::prepare_pac_layout(original,config,3,boot_only)) return 1;
    config.partitions[0].size=2*MiB;
    if(session::prepare_pac_layout(original,config,0,replaced)) return 1;
    config.partitions[0].size=MiB;
    config.partitions.back().size=UINT32_MAX;
    auto sentinel=session::prepare_pac_layout(original,config,3,replaced);
    if(!sentinel || sentinel->expected.partitions.back().offset+sentinel->expected.partitions.back().size!=end) return 1;
    // Equal-sized unselected data can move after being frozen to disk.
    auto reordered=config;
    reordered.partitions.clear();
    for(const auto& name:{"boot","nv","system"}) {
        session::PacPartition p;p.name=name;p.size=p.name=="system"?UINT64_MAX:MiB;
        reordered.partitions.push_back(p);
    }
    auto moved=session::prepare_pac_layout(original,reordered,3,replaced);
    if(!moved || moved->relocate.size()!=1 || moved->relocate[0].name!="nv" || moved->relocate[0].offset!=MiB) return 1;
    uniflash::log_info("PAC strategies and preserved-region geometry checks passed");
}

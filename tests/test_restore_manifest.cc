/*
 * UniFlash-Core Test / Restore Manifest
 *
 * Covers strict manifest parsing and rejected inputs.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/session/restore_manifest.h>
#include "temp_directory.h"
#include <fstream>
#include <uniflash/log.h>

int main() {
    using namespace uniflash::session;
    TempDirectory root;
    const auto path=root.path/"manifest.json";
    const std::string good=R"({"format":"raw-partition-backup-v2","partition_scheme":"gpt",
"complete":true,"sector_size":512,"user_area_bytes_from_gpt":16777216,"limitation":"",
"partitions":[{"name":"miscdata","file":"miscdata.bin","source":"user_partition",
"status":"saved","expected_bytes":1048576,"actual_bytes":1048576,"offset_bytes":1048576}],
"total_read":1048576,"partitions_read":1})";
    const auto parse=[&](const std::string& text) {
        {std::ofstream out(path,std::ios::binary);out<<text;}
        return read_restore_manifest(path);
    };
    auto manifest=parse(good);
    if(!manifest || manifest->entries.size()!=1 || manifest->entries[0].offset!=1048576) return 1;
    const auto changed=[&](std::string_view from,std::string_view to) {
        auto text=good;const auto at=text.find(from);
        if(at==std::string::npos) return std::string{};
        text.replace(at,from.size(),to);return text;
    };
    for(const auto& bad:{changed("\"complete\":true","\"complete\":false"),
        changed("\"complete\":true","\"complete\":true,\"complete\":false"),
        changed("\"saved\"","\"pending\""),changed("\"actual_bytes\":1048576","\"actual_bytes\":512"),
        changed("miscdata.bin","../miscdata.bin"),changed("miscdata.bin","C:\\\\miscdata.bin"),
        changed("\"total_read\":1048576","\"total_read\":18446744073709551616"),
        changed("\"sector_size\":512","\"sector_size\":0512"),
        changed("\"sector_size\":512","\"sector_size\":512.0"),
        changed("\"limitation\":\"\"","\"limitation\":\"missing boot region\""),
        changed("miscdata.bin","file\\u0000.bin"),changed("miscdata.bin","file\\ud800.bin"),good+"garbage"})
        if(bad.empty() || parse(bad)) return 1;
    manifest=parse(changed("miscdata.bin","\\u955c\\u50cf.bin"));
    if(!manifest || manifest->entries[0].file!="镜像.bin") return 1;
    auto v3=changed("raw-partition-backup-v2","raw-partition-backup-v3");
    if(parse(v3)) return 1;
    v3.insert(1,"\"image_semantics\":\"physical-snapshot\",");
    if(parse(v3)) return 1;
    const std::string digest(64,'a');
    v3.insert(1,"\"primary_header_sha256\":\""+digest+"\",\"partition_entries_sha256\":\""+digest+"\",");
    v3.insert(v3.find("\"status\""),"\"sha256\":\""+digest+"\",");
    manifest=parse(v3);
    if(!manifest || manifest->entries[0].sha256!=digest) return 1;
    v3[v3.find(digest)]='G';
    if(parse(v3)) return 1;
    uniflash::log_info("Raw restore manifest completeness, paths and JSON checks passed");
}

/*
 * UniFlash-Core Test / Platform
 *
 * Covers filename encoding, UTF-8 paths and directory sealing.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/platform.h>
#include <uniflash/io/output.h>
#include <uniflash/io/partition_filename.h>
#include <uniflash/session/journal.h>
#include "temp_directory.h"

#include <fstream>
#include <uniflash/log.h>
#include <iterator>

int main() {
    using namespace uniflash;
    int failures=0;
    auto check=[&](bool ok,const char* message) {
        if(!ok) { uniflash::log_err(std::string("FAIL: ")+message); ++failures; }
    };
    TempDirectory root;
    check(io::partition_filename("boot") == "boot.bin", "readable image filename");
    check(io::partition_filename("userdata") == "userdata.bin", "userdata filename");
    check(io::partition_filename("../boot").find('/') == std::string::npos, "device name cannot escape output directory");
    check(io::partition_filename("CON").starts_with("%"), "Windows reserved name encoded");
    check(io::partition_filename("%CON") != io::partition_filename("CON"), "fallback encoding is unambiguous");
    std::string longest;
    for (unsigned i=0; i<36; ++i) longest += "镜";
    check(io::partition_filename(longest).size() <= 255, "longest GPT UTF-8 name remains within NAME_MAX");
    const std::string name="镜像 文件-中文-\xf0\x9f\x93\x81";
    auto directory=root.path/platform::path(name);
    std::filesystem::create_directory(directory);
    check(!platform::sync_directory_tree(directory/"missing"),"missing recovery directory cannot be sealed");
#ifndef _WIN32
    std::filesystem::create_directories(directory/"nested"/"recovery");
    check(bool(platform::sync_directory_tree(directory/"nested"/"recovery")),"nested recovery directories sealed through parents");
#endif
    check(platform::utf8_path(platform::path(name))==name,"UTF-8 filename roundtrip");
    std::vector<uint8_t> original(4096,0x7e);
    const auto destination = directory / "output.bin";
    auto output=io::AtomicOutput::open(destination);
    check(bool(output),"output in Unicode directory");
    if(output) {
        check(bool(output->write(original)) && bool(output->commit_result()), "Unicode output committed");
        auto repeated=output->commit_result();
        check(!repeated && repeated.error().state==io::CommitState::Durable && repeated.error().bytes==original.size(),
            "commit error retains already-durable state and byte count");
        const auto text=platform::utf8_path(destination);
        std::ifstream file(platform::path(text),std::ios::binary);
        std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(file),{}};
        check(bytes==original,"UTF-8 converted path opens exact binary contents");
    }
#ifdef _WIN32
    auto durability=platform::sync_directory_tree(directory);
    check(durability && *durability==platform::DirectoryDurability::FileCommitsOnly,"Windows reports directory durability without volume-admin access");
    check(bool(session::Journal::seal_directory(directory)) && std::filesystem::exists(directory/"durability.txt"),"weaker directory guarantee is recorded without admin access");
    check(platform::utf8(platform::wide(name))==name,"UTF-16 surrogate-pair roundtrip");
    bool rejected=false;
    try { (void)platform::wide(std::string("\xff")); }
    catch(const std::system_error&) { rejected=true; }
    check(rejected,"invalid UTF-8 is not silently changed");
    _wputenv_s(L"USERPROFILE", directory.c_str());
    check(platform::path(platform::history_path()).parent_path()==directory,"Windows profile history");
    _wputenv_s(L"USERPROFILE",L"relative\\profile");
    check(platform::history_path().empty(),"relative Windows profile disables history");
#else
    setenv("HOME",directory.c_str(),1);
    check(platform::path(platform::history_path()).parent_path()==directory,"Linux home history");
    setenv("HOME","relative/home",1);
    check(platform::history_path().empty(),"relative home disables history");
#endif
    if(failures) return 1;
    uniflash::log_info("Platform Unicode paths and output tests passed");
}

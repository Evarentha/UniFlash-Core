/*
 * UniFlash-Core Test / History
 *
 * Covers history merging, failed loads and symlinked parent paths.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#include <uniflash/cli/line_editor.h>
#include <uniflash/platform.h>
#include <uniflash/log.h>
#include "temp_directory.h"
#include <fstream>
#include <barrier>
#include <thread>

namespace {
#ifndef _WIN32
// POSIX resolves link/.. against the link target, not its lexical parent.
// Windows path normalization has different semantics for these components.
bool check_symlink_parent() {
    using namespace uniflash;
    TempDirectory root;
    const auto actual=root.path/"actual";
    std::filesystem::create_directories(actual/"child");
    std::filesystem::create_directory_symlink(actual/"child",root.path/"link");
    const auto direct=actual/"history";
    const auto alias=root.path/"link"/".."/"history";
    const auto decoy=root.path/"history";
    {std::ofstream out(direct);out<<"actual history\n";}
    {std::ofstream out(decoy);out<<"decoy history\n";}
    const auto direct_path=platform::utf8_path(direct);
    const auto alias_path=platform::utf8_path(alias);
    cli::LineEditor a,b,loaded;
    if(!a.load_history(alias_path) || !b.load_history(direct_path) ||
       a.history()!=std::vector<std::string>{"actual history"} || a.history()!=b.history())return false;

    // Aliased and direct sessions race through the same sidecar lock.
    a.add_history("alias addition");b.add_history("direct addition");
    std::barrier gate(3);
    bool a_ok=false,b_ok=false;
    std::thread ta([&]{gate.arrive_and_wait();a_ok=a.save_history(alias_path);});
    std::thread tb([&]{gate.arrive_and_wait();b_ok=b.save_history(direct_path);});
    gate.arrive_and_wait();ta.join();tb.join();
    if(!a_ok || !b_ok || !loaded.load_history(direct_path))return false;
    const auto records=loaded.history();
    if(records.size()!=3 || records[0]!="actual history" ||
       !((records[1]=="alias addition" && records[2]=="direct addition") ||
         (records[1]=="direct addition" && records[2]=="alias addition")))return false;
    if(!loaded.load_history(alias_path) || loaded.history()!=records)return false;
    // Identity comparison must accept another spelling of the same parent.
    a.add_history("same target");
    if(!a.save_history(direct_path) || !loaded.load_history(alias_path) ||
       loaded.history().back()!="same target")return false;
    if(!loaded.load_history(platform::utf8_path(decoy)) ||
       loaded.history()!=std::vector<std::string>{"decoy history"} ||
       std::filesystem::exists(root.path/"history.lock") ||
       !std::filesystem::exists(actual/"history.lock"))return false;

    // Resolve only the existing parent: a new history leaf must still work.
    const auto fresh_alias=platform::utf8_path(root.path/"link"/".."/"fresh");
    cli::LineEditor fresh;
    if(!fresh.load_history(fresh_alias))return false;
    fresh.add_history("first record");
    if(!fresh.save_history(fresh_alias) ||
       !loaded.load_history(platform::utf8_path(actual/"fresh")) ||
       loaded.history()!=std::vector<std::string>{"first record"} ||
       std::filesystem::exists(root.path/"fresh") ||
       std::filesystem::exists(root.path/"fresh.lock"))return false;
    return true;
}
#endif
}

int main() {
    using namespace uniflash;
#ifndef _WIN32
    if(!check_symlink_parent())return 1;
#endif
    TempDirectory root;const auto file=root.path/"history";
    {std::ofstream out(file,std::ios::binary);
        out<<std::string(3*1024*1024,'x')<<'\n';
        for(unsigned i=0;i<700;++i)out<<"command "<<i<<'\n';
        out<<"bad\x01line\n";
    }
    cli::LineEditor editor;
    if(!editor.load_history(platform::utf8_path(file)) || editor.history().size()!=500 ||
        editor.history().front()!="command 200" || editor.history().back()!="command 699")return 1;
    editor.add_history("中文命令");
    if(!editor.save_history(platform::utf8_path(file)))return 1;
    cli::LineEditor loaded;
    if(!loaded.load_history(platform::utf8_path(file)) || loaded.history()!=editor.history())return 1;
    if(loaded.save_history(platform::utf8_path(root.path/"missing"/"history")))return 1;

    // A stale, unchanged session must not rewrite another session's additions.
    cli::LineEditor stale, writer;
    const auto path=platform::utf8_path(file);
    if(!stale.load_history(path) || !writer.load_history(path))return 1;
    writer.add_history("other session");
    if(!writer.history_dirty() || !writer.save_history(path) || writer.history_dirty())return 1;
    const auto modified=std::filesystem::last_write_time(file);
    if(stale.history_dirty() || !stale.save_history(path) ||
       std::filesystem::last_write_time(file)!=modified)return 1;
    if(!loaded.load_history(path) || loaded.history().back()!="other session")return 1;

    // Real additions from stale snapshots must be merged, even at the limit.
    stale.add_history("stale session addition");
    if(!stale.save_history(path) || !loaded.load_history(path) || loaded.history().size()!=500 ||
       loaded.history()[498]!="other session" || loaded.history()[499]!="stale session addition")return 1;
    const auto merged=loaded.history();
    if(!stale.save_history(path) || !loaded.load_history(path) || loaded.history()!=merged)return 1;

    // Loading failure disables persistence, even after the path becomes valid.
    const auto failed_file=root.path/"failed-history";
    const auto failed_path=platform::utf8_path(failed_file);
    std::filesystem::create_directory(failed_file);
    cli::LineEditor failed;
    if(failed.load_history(failed_path))return 1;
    failed.add_history("must not overwrite");
    std::filesystem::remove(failed_file);
    {std::ofstream out(failed_file);out<<"preserved\n";}
    if(failed.save_history(failed_path) || !loaded.load_history(failed_path) ||
       loaded.history()!=std::vector<std::string>{"preserved"})return 1;

    // An absent file is a valid first-run history, but a clean exit creates none.
    const auto fresh_file=root.path/"fresh";
    const auto fresh_path=platform::utf8_path(fresh_file);
    cli::LineEditor fresh;
    if(!fresh.load_history(fresh_path) || !fresh.save_history(fresh_path) ||
       std::filesystem::exists(fresh_file) || std::filesystem::exists(fresh_file.string()+".lock"))return 1;
    fresh.add_history("first");
    if(!fresh.save_history(fresh_path))return 1;

    // Both writers start with the same snapshot and attempt the read/merge/
    // replace transaction concurrently. Separate lock handles must serialize.
    cli::LineEditor a,b;
    if(!a.load_history(fresh_path) || !b.load_history(fresh_path))return 1;
    a.add_history("from A");b.add_history("from B");
    std::barrier gate(3);
    bool a_ok=false,b_ok=false;
    std::thread ta([&]{gate.arrive_and_wait();a_ok=a.save_history(fresh_path);});
    std::thread tb([&]{gate.arrive_and_wait();b_ok=b.save_history(fresh_path);});
    gate.arrive_and_wait();ta.join();tb.join();
    if(!a_ok || !b_ok || !loaded.load_history(fresh_path))return 1;
    const auto& records=loaded.history();
    if(records.size()!=3 || records[0]!="first" ||
       !((records[1]=="from A" && records[2]=="from B") ||
         (records[1]=="from B" && records[2]=="from A")))return 1;

    // A failed merge read must not replace newly unreadable history; retry
    // after recovery keeps the pending addition exactly once.
    a.add_history("retry addition");
    std::filesystem::remove(fresh_file);
    std::filesystem::create_directory(fresh_file);
    if(a.save_history(fresh_path) || !a.history_dirty())return 1;
    std::filesystem::remove(fresh_file);
    {std::ofstream out(fresh_file);out<<"recovered\n";}
    if(!a.save_history(fresh_path) || !loaded.load_history(fresh_path) ||
       loaded.history()!=std::vector<std::string>{"recovered","retry addition"})return 1;
    log_info("Bounded history, dirty state and synchronized merge checks passed");
}

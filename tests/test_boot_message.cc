/*
 * UniFlash-Core Test / Boot Message
 *
 * Covers BCB target encoding and preserved metadata fields.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#include <uniflash/session/boot_message.h>

#include <uniflash/log.h>
#include <algorithm>

int main() {
    using namespace uniflash::session;
    int failures=0;
    auto check=[&](bool ok,const char* text) {
        if(!ok) { uniflash::log_err(std::string("FAIL: ")+text); ++failures; }
    };
    std::vector<uint8_t> original(4096,0xa5);
    const char* expected[]={"--show_text","--sideload","--sideload_auto_reboot","--rescue","--fastboot",
                           "--prompt_and_wipe_data\n--reason=Factory reset requested through UniFlash (erase userdata)."};
    for(size_t i=0;i<reboot_targets.size();++i) {
        const auto& target=reboot_targets[i];
        auto result=make_boot_message(original,target.target);
        check(result && result->size()==4096,"fixed block size");
        if(!result) continue;
        check(std::string(reinterpret_cast<const char*>(result->data()))=="boot-recovery","command field");
        check(std::string(reinterpret_cast<const char*>(result->data()+64))==
              "recovery\n"+std::string(expected[i])+"\n","exact target options, no stale arguments");
        check(target.hidden == (target.target == RebootTarget::RecoveryWipe), "only wipe routing target is hidden");
        check(std::all_of(result->begin()+32,result->begin()+64,[](auto b){return b==0;}),"status cleared");
        check(std::equal(original.begin()+832,original.end(),result->begin()+832),"metadata untouched");
        check(find_reboot_target(target.name)==&target,"target parser");
    }
    for(auto name:{"", "rec", "bootloader", "download", "--wipe_data", "fastboot"})
        check(!find_reboot_target(name),"unsupported targets rejected");
    check(!make_boot_message(std::vector<uint8_t>(4095),RebootTarget::Recovery),"short BCB rejected");
    check(!make_boot_message(original,static_cast<RebootTarget>(99)),"invalid enum rejected");

    if(failures) return 1;
    uniflash::log_info("BCB targets and field preservation passed");
}

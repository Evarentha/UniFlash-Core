/*
 * UniFlash-Core Test / Command Policy
 *
 * Covers command availability per stage and argument validation.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/cli/commands.h>

#include <array>
#include <uniflash/log.h>
#include <string_view>

namespace {

using namespace uniflash::cli;
using uniflash::device::Stage;

int failures = 0;

void check(bool condition, std::string_view message) {
    if (condition) return;
    uniflash::log_err("FAIL: "+std::string(message));
    ++failures;
}

// Expected eligibility comes from the CLI contract, not the policy masks.
// Columns: offline, bootrom, fdl1, fdl2, SPRD4 download stub.
void expect(std::string_view name, std::array<bool, 5> allowed) {
    const auto* command = find_command(name);
    check(command != nullptr, name);
    if (!command) return;
    for (size_t i = 0; i < allowed.size(); ++i) {
        if (command_allowed(*command, command_stages[i]) == allowed[i]) continue;
        uniflash::log_err("FAIL: "+std::string(name)+" at "+std::string(command_stage_name(command_stages[i])));
        ++failures;
    }
}

}  // namespace

int main() {
    for (auto name : {"help", "?", "bus", "connect", "quit", "info", "decrypt-image", "unpack-image"})
        expect(name, {true, true, true, true, true});

    expect("pc-mode", {true, false, false, false, false});
    check(!find_command("kick"), "old kick command is replaced by pc-mode");
    check(!find_command("profile"), "CLI does not require manual chip identity");
    expect("load-fdl1", {false, true, false, false, false});
    expect("load-fdl2", {false, false, true, false, true});
    expect("load-fdl", {false, true, true, false, true});
    expect("ddrtest", {false, false, true, false, false});

    for (auto name : {"download", "load-bin", "exec"})
        expect(name, {false, true, true, false, false});

    for (auto name : {"parts", "read", "write", "restore-raw", "erase", "dump",
                      "repartition", "firstmode",
                      "enable-write", "reboot", "poweroff"})
        expect(name, {false, false, false, true, false});

    check(command_stage(Stage::Offline, true) == CommandStage::Offline,
          "a disconnected session stays offline regardless of SPRD4 history");
    check(command_stage(Stage::BootRom, false) == CommandStage::BootRom,
          "ordinary bootrom is not an autodloader stub");
    check(command_stage(Stage::BootRom, true) == CommandStage::Sprd4,
          "SPRD4 stub is distinct from real bootrom");
    check(command_stage(Stage::Fdl1, false) == CommandStage::Fdl1,
          "FDL1 permits its own command set");
    check(command_stage(Stage::Fdl2, true) == CommandStage::Fdl2,
          "SPRD4 history does not restrict the real FDL2 stage");
    check(find_command("?") == find_command("help"), "help alias shares its policy");
    check(!find_command("mcptype"), "MCP is part of info, not a shell command");
    check(!find_command("not-a-command"), "unknown commands have no implicit policy");
    check(!find_command("flash"), "flash is removed, not retained as an alias");
    check(!find_command("datetime") && !find_command("set-debuginfo"), "firmware strings are not public commands");

    check(!find_command("endproc"), "internal liveness check is not a user command");
    check(command_stage(Stage::Memory, false) == CommandStage::Memory, "CRC dialect without identity stays BSL");
    for (auto name : {"help", "info", "quit", "load-fdl1", "load-fdl", "download", "exec"})
        check(command_allowed(*find_command(name), CommandStage::Memory), "memory protocol permits explicit RAM operations");
    for (auto name : {"write", "erase", "dump", "reboot", "ddrtest", "load-fdl2"})
        check(!command_allowed(*find_command(name), CommandStage::Memory), "unknown identity cannot issue stage-specific commands");

    for (size_t i = 0; i < commands.size(); ++i) {
        check(find_command(commands[i].name) == &commands[i],
              "help/completion entry is the dispatched command");
        for (size_t j = i + 1; j < commands.size(); ++j) {
            check(commands[i].id != commands[j].id, "command IDs are unique");
            check(commands[i].name != commands[j].name, "command names are unique");
        }
    }

    if (failures) return 1;
    uniflash::log_info("Command stage matrix passed");
    return 0;
}

/*
 * UniFlash-Core / Command Registry
 *
 * Command identifiers, stage gates and the single dispatch table.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef UNIFLASH_CLI_COMMANDS_H
#define UNIFLASH_CLI_COMMANDS_H

#include <uniflash/device/stage.h>

#include <array>
#include <cstdint>
#include <string_view>

namespace uniflash::cli {

enum class CommandId {
    Help, Bus, Connect, Quit, Info, DecryptImage, UnpackImage,
    LoadFdl1, LoadFdl2, LoadFdl, Download, LoadBin, Exec, DdrTest, PcMode,
    Parts, Read, Write, WriteRename, RestoreRaw, Erase, Dump, Repartition,
    FirstMode, EnableWrite, Reboot, PowerOff,
};

// SPRD4 initially reports BootRom, but its handlers only emulate RAM
// downloads. Treat that stub as a distinct command context. After entering
// real FDL2, the historical is_sprd4 flag must not restrict FDL2 commands.
enum class CommandStage : uint8_t {
    Offline = 1, BootRom = 2, Fdl1 = 4, Fdl2 = 8, Sprd4 = 16, Memory = 32,
};

using StageMask = uint8_t;

constexpr StageMask stage_mask(CommandStage stage) {
    return static_cast<StageMask>(stage);
}

inline constexpr std::array command_stages{
    CommandStage::Offline, CommandStage::BootRom, CommandStage::Fdl1,
    CommandStage::Fdl2, CommandStage::Sprd4, CommandStage::Memory,
};

constexpr CommandStage command_stage(device::Stage stage, bool is_sprd4) {
    switch (stage) {
    case device::Stage::Offline: return CommandStage::Offline;
    case device::Stage::BootRom:
        return is_sprd4 ? CommandStage::Sprd4 : CommandStage::BootRom;
    case device::Stage::Fdl1: return CommandStage::Fdl1;
    case device::Stage::Fdl2: return CommandStage::Fdl2;
    case device::Stage::Memory: return CommandStage::Memory;
    }
    return CommandStage::Offline;
}

constexpr std::string_view command_stage_name(CommandStage stage) {
    switch (stage) {
    case CommandStage::Offline: return "offline";
    case CommandStage::BootRom: return device::stage_display_name(device::Stage::BootRom);
    case CommandStage::Fdl1: return device::stage_display_name(device::Stage::Fdl1);
    case CommandStage::Fdl2: return device::stage_display_name(device::Stage::Fdl2);
    case CommandStage::Sprd4: return "SPRD4";
    case CommandStage::Memory: return "BSL";
    }
    return "unknown";
}

inline constexpr StageMask offline_stage = stage_mask(CommandStage::Offline);
inline constexpr StageMask bootrom_stage = stage_mask(CommandStage::BootRom);
inline constexpr StageMask fdl1_stage = stage_mask(CommandStage::Fdl1);
inline constexpr StageMask fdl2_stage = stage_mask(CommandStage::Fdl2);
inline constexpr StageMask sprd4_stage = stage_mask(CommandStage::Sprd4);
inline constexpr StageMask unidentified_memory_stage = stage_mask(CommandStage::Memory);
inline constexpr StageMask memory_stages = bootrom_stage | fdl1_stage | unidentified_memory_stage;
inline constexpr StageMask all_stages = offline_stage | memory_stages |
                                        fdl2_stage | sprd4_stage;

struct CommandSpec {
    CommandId id;
    std::string_view name;
    std::string_view arguments;
    StageMask stages;
    std::string_view description;
    bool hidden = false;
};

// Shared by dispatch, help and completion. Stage eligibility says nothing
// about firmware CONFIG_* capabilities: FDL2 gets to accept/refuse those.
inline constexpr auto commands = std::to_array<CommandSpec>({
    {CommandId::Help, "help", "", all_stages, "Show command reference"},
    {CommandId::DecryptImage, "decrypt-image", "<encrypted> <out> <key-file> <plaintext-sha256> [r27|sprd128|sprd256|sprd128-signed|sprd256-signed]", all_stages,
     "Offline AES-CBC; SPRD modes output payload only; verifies plaintext before commit"},
    {CommandId::UnpackImage, "unpack-image", "<image> <out> <sci1|sprd-sci1|sansa-view> <output-sha256>", all_stages,
     "Offline modem extraction or Sansa verification view; verifies output before commit"},
    {CommandId::Bus, "bus", "", all_stages, "List devices and link speed"},
    {CommandId::Connect, "connect", "[port]", all_stages, "Connect by USB path or Windows COM name"},
    {CommandId::Quit, "quit", "", all_stages, "Leave the shell"},
    {CommandId::Info, "info", "[diagnostic|miscdata]", all_stages,
     "Show device information; miscdata includes factory tests and BL record evidence"},
    {CommandId::LoadFdl1, "load-fdl1", "<f1> <addr>", bootrom_stage | unidentified_memory_stage,
      "Load and execute FDL1"},
    {CommandId::LoadFdl2, "load-fdl2", "[<f2> <addr>]", fdl1_stage | sprd4_stage,
      "Load FDL2"},
    {CommandId::LoadFdl, "load-fdl", "[<f1> <a1> <f2> <a2>]", bootrom_stage | fdl1_stage | sprd4_stage | unidentified_memory_stage,
      "Load the chain to FDL2"},
    {CommandId::Download, "download", "<bin> <addr>", memory_stages,
      "Download to RAM without executing"},
    {CommandId::LoadBin, "load-bin", "<bin> <addr> [entry]", memory_stages,
      "Download to RAM and execute"},
    {CommandId::Exec, "exec", "<addr>", memory_stages, "Execute a prior RAM download"},
    {CommandId::DdrTest, "ddrtest", "[sr <ms>]", fdl1_stage,
      "DDR verification or self-refresh test"},
    {CommandId::PcMode, "pc-mode", "<mode>", offline_stage,
     "PC-tool request (1..0x3f, freq=0): 0x02 auto-download (may erase SPL), "
     "0x15 autotest, 0x17 programkey (may program eFuse), others calibration"},
    {CommandId::Parts, "parts", "", fdl2_stage, "List partitions and export layout.xml"},
    {CommandId::Read, "read", "<part> [out] [size] or all [dir]", fdl2_stage, "read one partition or back up all raw partitions (alias: r)"},
    {CommandId::Write, "write", "<part> <img> or <dir> or <config.xml> or <package.pac> [host-config.xml]", fdl2_stage, "Write images or execute XML/PAC operations; PAC can load bundled FDLs from BootROM (alias: w)"},
    {CommandId::WriteRename, "write-rename", "<part> <img>", fdl2_stage,
      "Rebuild GPT with temporary name, write, restore layout"},
    {CommandId::RestoreRaw, "restore-raw", "<part> <snapshot> or <backup-dir>", fdl2_stage,
      "Restore exact GPT-partition bytes through a temporary alias; save originals and verify"},
    {CommandId::Erase, "erase", "<part>", fdl2_stage, "Erase a partition; userdata stores a next-boot Recovery wipe request without rebooting"},
    {CommandId::Dump, "dump", "[dir]", fdl2_stage, "alias for read all", true},
    {CommandId::Repartition, "repartition", "<rom.xml>", fdl2_stage, "Replace the complete partition layout"},
    {CommandId::FirstMode, "firstmode", "<value>", fdl2_stage, "Set boot-mode byte (0..255); firmware-defined"},
    {CommandId::EnableWrite, "enable-write", "", fdl2_stage, "Unlock firmware write protection"},
    {CommandId::Reboot, "reboot", "[target]", fdl2_stage,
     "Reboot normally or to a target listed below"},
    {CommandId::PowerOff, "poweroff", "", fdl2_stage,
     "Request power-off and exit; unplug cable to complete"},
});

constexpr const CommandSpec* find_command(std::string_view name) {
    if (name == "?") name = "help";
    else if (name == "w") name = "write";
    else if (name == "r") name = "read";
    else if (name == "e") name = "erase";
    for (const auto& command : commands)
        if (command.name == name) return &command;
    return nullptr;
}

constexpr bool command_allowed(const CommandSpec& command, CommandStage stage) {
    return (command.stages & stage_mask(stage)) != 0;
}

}  // namespace uniflash::cli

#endif

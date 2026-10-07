#ifndef UNIFLASH_DEVICE_STAGE_H
#define UNIFLASH_DEVICE_STAGE_H

namespace uniflash::device {

enum class Stage { Offline, BootRom, Fdl1, Fdl2, Memory };

constexpr const char* stage_display_name(Stage stage) {
    switch (stage) {
    case Stage::BootRom: return "BootROM";
    case Stage::Fdl1: return "FDL1";
    case Stage::Fdl2: return "FDL2";
    case Stage::Offline: return "offline";
    case Stage::Memory: return "BSL";
    }
    return "unknown";
}

}  // namespace uniflash::device

#endif

#pragma once
#include <cstdint>
namespace uniflash::device {
// Runtime announcement, distinct from user policy and offline loader facts.
struct SessionCapabilities {
    bool operator==(const SessionCapabilities&) const = default;
    bool valid=false;
    bool support_raw=false;
    bool disable_hdlc=false;
    uint32_t flush_kb=0;
    uint32_t storage=0;
};
using DaInfo=SessionCapabilities;
}

#pragma once
namespace uniflash::device {
enum class Capability { Unknown, Supported, Unsupported };
// Offline loader facts and runtime observations have distinct owners. An
// explicit runtime refusal overrides an earlier offline support declaration.
struct ObservedCapabilities {
    Capability flash_type_query=Capability::Unknown;
    Capability partition_query=Capability::Unknown;
    Capability user_area_read=Capability::Unknown;
};
}

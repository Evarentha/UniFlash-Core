#pragma once
#include <uniflash/session/flash_plan.h>
namespace uniflash::session {
// Explicit host product configuration, never loaded implicitly from a PAC.
std::expected<PacPrepareOptions,std::errc> read_pac_config(const std::filesystem::path&,
    std::string_view product,std::stop_token = {});
}

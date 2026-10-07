/*
 * UniFlash-Core / PAC Host Configuration
 *
 * Explicit host product configuration that is never read from a PAC.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once
#include <uniflash/session/flash_plan.h>
namespace uniflash::session {
// Explicit host product configuration, never loaded implicitly from a PAC.
std::expected<PacPrepareOptions,std::errc> read_pac_config(const std::filesystem::path&,
    std::string_view product,std::stop_token = {});
}

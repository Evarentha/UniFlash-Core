/*
 * UniFlash-Core / Authentication Types
 *
 * Responder and key callbacks for the R27 device authentication exchange.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <cstdint>
#include <expected>
#include <functional>
#include <span>
#include <stop_token>
#include <system_error>
#include <vector>
namespace uniflash::auth {
using Responder = std::function<std::expected<std::vector<uint8_t>,std::errc>(
    std::span<const uint8_t>,std::stop_token)>;
}

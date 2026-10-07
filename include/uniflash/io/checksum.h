/*
 * UniFlash-Core / CRC-32
 *
 * Chainable CRC-32 for sparse images and backup manifests.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <cstdint>
#include <span>
namespace uniflash::io {
uint32_t crc32_update(uint32_t crc, std::span<const uint8_t> data);
}

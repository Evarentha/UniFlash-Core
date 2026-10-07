/*
 * UniFlash-Core / PAC SecBinPack Table
 *
 * XOR table decoding with structure and CRC verification.
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
#include <vector>
#include <expected>
#include <system_error>
#include <stop_token>
namespace uniflash::session {
uint16_t pac_crc16(uint16_t,std::span<const uint8_t>);
// R27 SecBinPack9 table transform is byte XOR, not image AES. The stored
// FILE_INFO's fixed size supplies known plaintext; the stored CRC and every
// record's structure size are checked after decoding.
std::expected<std::vector<uint8_t>,std::errc> decode_pac_table(
    std::span<const uint8_t> encoded,uint16_t plaintext_crc,std::stop_token = {});
}

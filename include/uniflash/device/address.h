/*
 * UniFlash-Core / Address Arithmetic
 *
 * Address word order and erase size computation for loader addresses.
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
#include <system_error>
namespace uniflash::device {
enum class AddressWordOrder { Little, Big };
inline std::expected<uint32_t,std::errc> address_erase_size(uint32_t address,uint64_t size) {
    if(!size || size>UINT32_MAX)return std::unexpected(std::errc::invalid_argument);
    if(size==UINT32_MAX)return UINT32_MAX; // explicit whole-flash sentinel
    const auto padded=size+(size&1);
    if(padded>uint64_t(UINT32_MAX)+1-address)return std::unexpected(std::errc::value_too_large);
    return static_cast<uint32_t>(padded);
}
}

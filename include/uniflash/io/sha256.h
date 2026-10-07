/*
 * UniFlash-Core / SHA-256
 *
 * Incremental SHA-256 used for manifests and image digests.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once
#include <uniflash/io/stream.h>
#include <array>
#include <string>
#include <string_view>
namespace uniflash::io {
class Sha256 {
public:
    // Standard SHA-256 length encoding is modulo 2^64 bits. File helper below
    // rejects lengths beyond the standard byte range before reading.
    void update(std::span<const uint8_t>);
    std::string hex() const;
private:
    void block(std::span<const uint8_t,64>);
    std::array<uint32_t,8> state_{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    std::array<uint8_t,64> pending_{};
    uint64_t bytes_=0;
    size_t used_=0;
};
std::expected<std::string,std::errc> sha256(const Reader&,uint64_t,std::stop_token = {});
bool valid_sha256(std::string_view);
}

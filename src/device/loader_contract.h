/*
 * UniFlash-Core / Loader Contract
 *
 * Externally established loader facts that override automatic defaults.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <uniflash/device/profile.h>
#include <uniflash/io/sha256.h>
#include <span>
#include <array>
#include <bit>
#include <algorithm>

namespace uniflash::device::detail {
// Used only to match complete, offline-audited loader files, never to infer
// identity or trust. No binary-string/constant heuristic enables larger frames.
inline std::string loader_sha256(std::span<const uint8_t> bytes) {
    io::Sha256 hash;hash.update(bytes);return hash.hex();
}

struct RamLoaderContract {
    size_t size;
    std::string_view hash;
    size_t receive_capacity = 4096, wire_limit = 4095, payload_limit = 4090;
};
inline std::optional<RamLoaderContract> audited_fdl1(std::span<const uint8_t> image) {
    using Contract = RamLoaderContract;
    constexpr Contract contracts[]{
        {56376,"950578bcfd7b4bcf48aba227d2ee899e5f002f3dec75c2a9e00a66cd843f50a3"},
        {57204,"ae758f18aaddb025ccb673dd787e66a2e361d66bc0be102c5177c28c20214cdc"},
        {37268,"3ecaa1db4a6ffc760891509e755d54d37078c457393b5f1d04236a48d74d4172"},
    };
    if (std::none_of(std::begin(contracts),std::end(contracts),[&](auto c){return c.size==image.size();})) return std::nullopt;
    const auto digest=loader_sha256(image);
    for (const auto& contract : contracts) if(contract.size==image.size() && contract.hash==digest) return contract;
    return std::nullopt;
}
inline void apply_fdl2_contract(std::span<const uint8_t> image, DeviceProfile& profile) {
    // An unknown newly uploaded image must never inherit the previous file's
    // learned capabilities. These fields are evidence about a running binary.
    profile.flash_type_query=Capability::Unknown;
    profile.raw_recovery=RawRecoveryContract::Unknown;
    profile.partition_query=Capability::Unknown;
    profile.user_area_read=Capability::Unknown;
    profile.framed_write_u64=false;
    profile.nv_dialect=NvDialect::Unknown;
    profile.legacy_gpt_rebuild=false;
    profile.mirrors_signed_boot_images=false;
    profile.raw_partition_relocation=false;
    profile.bthd_alias_replay=false;
    profile.ufs_boot_roles=false;
    if (image.size()!=649364 && image.size()!=469860) return;
    const auto hash=loader_sha256(image);
    if (hash=="69dbd1e320af74171994e300ac9b38665a9d9ebf6908a2ec899f7ef3c2ebcbb8" ||
        hash=="0f789f0fe22fb80c89ce6c7481a304fc95b81adec82e7916e48067dca1699cd6") {
        profile.flash_type_query = Capability::Unsupported;
        profile.partition_query = Capability::Unsupported;
        profile.user_area_read = image.size()==469860?Capability::Unsupported:Capability::Supported;
        profile.framed_write_u64 = image.size()==649364;
        profile.nv_dialect = image.size()==649364 ? NvDialect::Signed7MiB : NvDialect::Unknown;
        profile.legacy_gpt_rebuild=image.size()==649364;
        profile.mirrors_signed_boot_images=image.size()==649364;
        profile.raw_partition_relocation=image.size()==649364;
        profile.bthd_alias_replay=image.size()==649364;
        profile.ufs_boot_roles=image.size()==649364;
    }
}
}

/*
 * UniFlash-Core / Packed Image Formats
 *
 * SCI1, signed SCI1 and verification view structures.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once
#include <uniflash/io/image.h>
#include <string_view>
#include <uniflash/io/commit.h>
namespace uniflash::session {
enum class PackedImageFormat { Sci1, SprdSignedSci1, SansaVerificationView };
struct SciModemRange { uint64_t offset=0,size=0; bool sha1_prefix=false; };
// Strict SCI1 directory, at most ten effective entries; bounds, nonoverlap,
// last marker and unique modem. Does not authenticate SHA1 prefix contents.
std::expected<SciModemRange,std::errc> parse_sci_modem(
    const io::Reader&,uint64_t size,std::stop_token = {});
// Explicit offline output: SCI modem payload, or Sansa's bounded verification
// view. Expected SHA256 covers the entire output. No automatic write routing
// or certificate/signature rewriting is implied by this transformation.
std::expected<uint64_t,io::OutputError> unpack_image(const io::Image&,PackedImageFormat,
    const std::filesystem::path& destination,std::string_view expected_sha256,
    std::stop_token = {},const io::PrepareObserver& = {});
}

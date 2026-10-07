/*
 * UniFlash-Core / Signed Image Payload
 *
 * LP64 signing trailer and content certificate validation.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once
#include <uniflash/io/stream.h>

namespace uniflash::session {
struct SprdSignedPayload { uint64_t offset=0, size=0; };
// LP64 SPRD 96-byte signing trailer and RSA2048 key/content certificate.
// Checks bounded ranges and hash_data against the selected payload, not RSA
// authenticity, rollback state or a device's trust decision.
std::expected<SprdSignedPayload,std::errc> validate_sprd_signed_payload(
    const io::Reader&,uint64_t file_size,uint32_t image_size,
    SprdSignedPayload expected,std::stop_token = {});
}

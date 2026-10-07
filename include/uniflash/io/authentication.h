/*
 * UniFlash-Core / R27 Authentication
 *
 * RSA2048 OAEP-SHA1 challenge response for the R27 scheme.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once
#include <uniflash/auth/types.h>
#include <filesystem>
namespace uniflash::io {
// R27 AuthenticationImpl: RSA2048 OAEP-SHA1 decrypt M1, SHA256 of the
// recovered message, raw PKCS1-v1.5 signature of that digest, nonce at +4.
// PKCS1 PEM key and exact 32-byte project-name field supplied externally.
std::expected<auth::Responder,std::errc> r27_authenticator(
    const std::filesystem::path& key,std::span<const uint8_t,32> project,std::stop_token = {});
}

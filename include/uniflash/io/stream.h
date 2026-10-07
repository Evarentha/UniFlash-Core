/*
 * UniFlash-Core / Byte Streams
 *
 * Reader and writer callbacks with bounded progress reporting.
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
#include <uniflash/io/observer.h>

namespace uniflash::io {
struct TransferProgress {
    uint64_t completed, total;
    double seconds;
};
using TransferObserver = Observer<TransferProgress>;
// Low-level I/O/codec APIs and Reader/Writer callbacks may throw allocation,
// filesystem or callback exceptions. Session transaction services translate
// these at their outer boundary; expected is not a noexcept promise.
// Calls on one device/plan are serialized and non-reentrant by contract.
// Exact random-access reads. An implementation must fail a short read, never
// silently fill the missing suffix. Offsets refer to expanded image bytes.
using Reader = std::function<std::expected<void, std::errc>(
    uint64_t, std::span<uint8_t>, std::stop_token)>;
using Writer = std::function<std::expected<void, std::errc>(
    std::span<const uint8_t>, std::stop_token)>;
}

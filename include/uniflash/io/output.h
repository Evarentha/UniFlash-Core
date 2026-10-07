/*
 * UniFlash-Core / Atomic Output File
 *
 * Temporary file creation, durable replacement and commit reporting.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once
#include <uniflash/io/stream.h>
#include <filesystem>
#include <memory>
#include <uniflash/io/commit.h>

namespace uniflash::io {
class AtomicOutput {
public:
    static std::expected<AtomicOutput, std::errc> open(const std::filesystem::path&);
    ~AtomicOutput();
    AtomicOutput(AtomicOutput&&) noexcept;
    AtomicOutput& operator=(AtomicOutput&&) noexcept;
    std::expected<void, std::errc> write(std::span<const uint8_t>, std::stop_token = {});
    std::expected<void, std::errc> commit();
    // Preferred API for services: a failed directory sync can occur after
    // replacement. The result retains that distinction and committed bytes.
    std::expected<void,OutputError> commit_result();
    uint64_t size() const;
    CommitState commit_state() const;
private:
    struct Impl;
    explicit AtomicOutput(std::unique_ptr<Impl>);
    std::unique_ptr<Impl> p_;
};
}

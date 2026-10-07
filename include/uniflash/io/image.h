/*
 * UniFlash-Core / Image Preparation
 *
 * Frozen image snapshots, sparse indexing and checksum verification.
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

namespace uniflash::io {

enum class PreparePhase { Snapshot, Index, Checksum };
struct PrepareProgress {
    PreparePhase phase;
    uint64_t completed;
    uint64_t total;
};
using PrepareObserver = Observer<PrepareProgress>;

// Prepared images retain a CoW/copy snapshot (Linux) or a private temporary
// copy made while denying ordinary WRITE/DELETE sharing (Windows). Sparse data stays encoded; its validated
// extent index is expanded by reader(), never materialized on disk.
class Image {
public:
    static std::expected<Image, std::errc> prepare(const std::filesystem::path&,
        uint64_t capacity, std::stop_token = {}, const PrepareObserver& = {});
    static std::expected<Image, std::errc> prepare_blob(const std::filesystem::path&,
        uint64_t capacity, std::stop_token = {}, const PrepareObserver& = {});
    uint64_t size() const;
    Reader reader() const;
    // Interpret a bounded region of an already frozen container as an image.
    // Retains the container snapshot; no extraction paths or extra file copies.
    std::expected<Image, std::errc> region(uint64_t offset, uint64_t length,
        uint64_t capacity, std::stop_token = {}, const PrepareObserver& = {}) const;
    std::expected<Image,std::errc> blob_region(uint64_t offset,uint64_t length) const;
private:
    static std::expected<Image,std::errc> freeze(const std::filesystem::path&,uint64_t,
        std::stop_token,const PrepareObserver&,bool);
    static std::expected<Image, std::errc> index(Reader, uint64_t,
        uint64_t, std::stop_token, const PrepareObserver&);
    struct Impl;
    explicit Image(std::shared_ptr<Impl> p) : p_(std::move(p)) {}
    std::shared_ptr<Impl> p_;
};

} // namespace uniflash::io

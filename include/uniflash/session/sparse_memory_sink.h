/*
 * UniFlash-Core / Sparse Memory Sink
 *
 * Collects decoded sparse extents in memory for layout checks.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNIFLASH_SESSION_SPARSE_MEMORY_SINK_H
#define UNIFLASH_SESSION_SPARSE_MEMORY_SINK_H

#include <uniflash/session/sparse.h>
#include <vector>
#include <cstring>
#include <uniflash/platform.h>

namespace uniflash::session {

class MemorySink : public SparseDecoder::Sink {
public:
    explicit MemorySink(std::vector<uint8_t>& out, uint64_t capacity)
        : out_(out), cap_(capacity) {}

    std::expected<void, std::errc>
    write_raw(uint64_t offset, std::span<const uint8_t> data) override {
        if (offset > cap_ || data.size() > cap_ - offset ||
            offset + data.size() > out_.max_size())
            return std::unexpected(std::errc::message_size);
        if (offset + data.size() > out_.size())
            out_.resize(static_cast<size_t>(offset + data.size()));
        std::memcpy(out_.data() + static_cast<size_t>(offset),
                    data.data(), data.size());
        return {};
    }

    std::expected<void, std::errc>
    write_fill(uint64_t offset, uint32_t block_count,
               uint32_t fill_value, uint32_t block_size) override {
        uint64_t total_bytes = static_cast<uint64_t>(block_count) * block_size;
        if (offset > cap_ || total_bytes > cap_ - offset ||
            offset + total_bytes > out_.max_size())
            return std::unexpected(std::errc::message_size);
        if (offset + total_bytes > out_.size())
            out_.resize(static_cast<size_t>(offset + total_bytes));

        size_t end = static_cast<size_t>(offset + total_bytes);
        size_t i = static_cast<size_t>(offset);
        fill_value = platform::little_endian(fill_value);
        for (; i + 4 <= end; i += 4)
            std::memcpy(out_.data() + i, &fill_value, 4);
        // Truncated tail carries the pattern prefix (sparse_img.c FILL).
        const uint8_t* pat = reinterpret_cast<const uint8_t*>(&fill_value);
        for (size_t k = 0; i < end; ++i, ++k)
            out_[i] = pat[k & 3];
        return {};
    }

    std::expected<void, std::errc>
    skip_dont_care(uint64_t offset, uint32_t block_count,
                   uint32_t block_size) override {
        uint64_t total_bytes = static_cast<uint64_t>(block_count) * block_size;
        if (offset > cap_ || total_bytes > cap_ - offset ||
            offset + total_bytes > out_.max_size())
            return std::unexpected(std::errc::message_size);
        size_t new_size = static_cast<size_t>(offset + total_bytes);
        if (new_size > out_.size())
            out_.resize(new_size);  // resize zero-fills the hole
        return {};
    }

private:
    std::vector<uint8_t>& out_;
    uint64_t cap_;
};

}

#endif

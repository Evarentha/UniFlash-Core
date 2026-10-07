#ifndef UNIFLASH_SESSION_SPARSE_H
#define UNIFLASH_SESSION_SPARSE_H

#include <span>
#include <system_error>
#include <expected>
#include <vector>
#include <cstdint>
#include <uniflash/io/checksum.h>
#include <uniflash/io/sparse_format.h>

namespace uniflash::session {

// Standard zlib CRC-32 (reflected poly 0xEDB88320, pre/post ~0) — identical
// to BSP sparse_crc32.c. Chainable: crc32_update(crc32_update(0,a),b) ==
// crc32_update(0, a||b).
using io::crc32_update;

using io::SparseHeader;
using io::SparseChunkHeader;
using io::SparseChunkType;
using enum io::SparseChunkType;

class SparseDecoder {
public:
    static bool is_sparse(std::span<const uint8_t> data);

    class Sink {
    public:
        virtual ~Sink() = default;
        virtual std::expected<void, std::errc>
        write_raw(uint64_t offset, std::span<const uint8_t> data) = 0;
        virtual std::expected<void, std::errc>
        write_fill(uint64_t offset, uint32_t block_count,
                   uint32_t fill_value, uint32_t block_size) = 0;
        virtual std::expected<void, std::errc>
        skip_dont_care(uint64_t offset, uint32_t block_count,
                       uint32_t block_size) = 0;
    };

    static std::expected<void, std::errc>
    decode(std::span<const uint8_t> data, Sink& sink);
};

std::expected<std::vector<uint8_t>, std::errc>
expand_sparse(const std::vector<uint8_t>& data);

}

#endif

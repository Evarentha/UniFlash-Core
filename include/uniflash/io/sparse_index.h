#pragma once
#include <uniflash/io/image.h>
#include <array>
#include <vector>
namespace uniflash::io {
struct SparseExtent {
    uint64_t start=0,length=0,source=0;
    uint16_t type=0;
    std::array<uint8_t,4> pattern{};
};
struct SparseIndex {
    bool sparse=false;
    uint64_t length=0;
    uint32_t block_size=0;
    std::vector<SparseExtent> extents;
};
// Single structural and declared-CRC validation engine. Completes before any
// sink is invoked. Reader must refer to stable bytes for the operation lifetime.
std::expected<SparseIndex,std::errc> index_sparse(const Reader&,uint64_t file_size,
    uint64_t capacity,std::stop_token = {},const PrepareObserver& = {});
}

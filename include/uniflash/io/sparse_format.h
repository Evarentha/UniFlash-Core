#pragma once
#include <cstdint>
namespace uniflash::io {
#pragma pack(push, 1)
struct SparseHeader {
    uint32_t magic;
    uint16_t major_version,minor_version,file_hdr_sz,chunk_hdr_sz;
    uint32_t blk_sz,total_blks,total_chunks,image_checksum;
};
enum SparseChunkType : uint16_t {
    CHUNK_TYPE_RAW=0xCAC1,CHUNK_TYPE_FILL=0xCAC2,
    CHUNK_TYPE_DONT_CARE=0xCAC3,CHUNK_TYPE_CRC32=0xCAC4,
};
struct SparseChunkHeader {
    uint16_t chunk_type,reserved1;
    uint32_t chunk_sz,total_sz;
};
#pragma pack(pop)
static_assert(sizeof(SparseHeader)==28);
static_assert(sizeof(SparseChunkHeader)==12);
}

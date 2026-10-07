#pragma once
#include <cstdint>
#include <span>
namespace uniflash::io {
uint32_t crc32_update(uint32_t crc, std::span<const uint8_t> data);
}

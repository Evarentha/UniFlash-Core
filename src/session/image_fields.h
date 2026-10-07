#pragma once
#include <cstdint>
#include <span>
#include <string>
namespace uniflash::session::image_fields {
inline uint64_t le(std::span<const uint8_t> bytes,size_t at,size_t count=4) {
    uint64_t value=0;
    for(size_t i=0;i<count;++i) value|=uint64_t(bytes[at+i])<<(8*i);
    return value;
}
inline void put(std::span<uint8_t> bytes,size_t at,uint32_t value) {
    for(size_t i=0;i<4;++i) bytes[at+i]=static_cast<uint8_t>(value>>(8*i));
}
inline bool range(uint64_t at,uint64_t length,uint64_t size) {
    return at<=size && length<=size-at;
}
inline std::string hex(std::span<const uint8_t> bytes) {
    constexpr char digits[]="0123456789abcdef";
    std::string result;result.reserve(bytes.size()*2);
    for(auto b:bytes) {result+=digits[b>>4];result+=digits[b&15];}
    return result;
}
}

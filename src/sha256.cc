#include <uniflash/io/sha256.h>
#include <algorithm>
#include <bit>
namespace uniflash::io {
void Sha256::block(std::span<const uint8_t,64> input) {
    constexpr uint32_t k[]{
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    std::array<uint32_t,64> w{};
    for(size_t i=0;i<16;++i) for(size_t j=0;j<4;++j) w[i]=(w[i]<<8)|input[4*i+j];
    for(size_t i=16;i<64;++i) {
        const auto x=w[i-15],y=w[i-2];
        w[i]=w[i-16]+(std::rotr(x,7)^std::rotr(x,18)^(x>>3))+w[i-7]+(std::rotr(y,17)^std::rotr(y,19)^(y>>10));
    }
    auto [a,b,c,d,e,f,g,h]=state_;
    for(size_t i=0;i<64;++i) {
        const auto t1=h+(std::rotr(e,6)^std::rotr(e,11)^std::rotr(e,25))+((e&f)^(~e&g))+k[i]+w[i];
        const auto t2=(std::rotr(a,2)^std::rotr(a,13)^std::rotr(a,22))+((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    const std::array<uint32_t,8> result{a,b,c,d,e,f,g,h};
    for(size_t i=0;i<8;++i) state_[i]+=result[i];
}
void Sha256::update(std::span<const uint8_t> data) {
    bytes_+=data.size();
    while(!data.empty()) {
        if(!used_ && data.size()>=64) {block(data.first<64>());data=data.subspan(64);continue;}
        const auto n=std::min(64-used_,data.size());
        std::copy_n(data.begin(),n,pending_.begin()+used_);used_+=n;data=data.subspan(n);
        if(used_==64) {block(pending_);used_=0;}
    }
}
std::string Sha256::hex() const {
    auto copy=*this;const uint64_t bits=bytes_*8;
    const uint8_t marker=0x80;copy.update(std::span(&marker,1));
    const uint8_t zero=0;
    while(copy.used_!=56) copy.update(std::span(&zero,1));
    std::array<uint8_t,8> size{};
    for(size_t i=0;i<8;++i) size[7-i]=static_cast<uint8_t>(bits>>(8*i));
    copy.update(size);
    constexpr char digits[]="0123456789abcdef";std::string result;result.reserve(64);
    for(auto word:copy.state_) for(int shift=28;shift>=0;shift-=4) result+=digits[(word>>shift)&15];
    return result;
}
std::expected<std::string,std::errc> sha256(const Reader& read,uint64_t size,std::stop_token stop) {
    if(!read || size>UINT64_MAX/8) return std::unexpected(std::errc::invalid_argument);
    if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    std::array<uint8_t,65536> buffer;Sha256 hash;
    for(uint64_t offset=0;offset<size;) {
        if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
        auto bytes=std::span(buffer).first(static_cast<size_t>(std::min<uint64_t>(buffer.size(),size-offset)));
        auto r=read(offset,bytes,stop);if(!r) return std::unexpected(r.error());hash.update(bytes);offset+=bytes.size();
    }
    return hash.hex();
}
bool valid_sha256(std::string_view value) {
    return value.size()==64 && std::all_of(value.begin(),value.end(),[](char c){return (c>='0' && c<='9') || (c>='a' && c<='f');});
}
}

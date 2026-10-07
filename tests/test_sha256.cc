#include <uniflash/io/sha256.h>
#include <algorithm>
#include <uniflash/log.h>
#include <vector>

int main() {
    using uniflash::io::Sha256;
    const auto bytes=[](std::string_view s){return std::span(reinterpret_cast<const uint8_t*>(s.data()),s.size());};
    Sha256 empty;
    if(empty.hex()!="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") return 1;
    Sha256 short_hash;short_hash.update(bytes("a"));short_hash.update(bytes("bc"));
    if(short_hash.hex()!="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") return 1;
    const auto snapshot=short_hash.hex();
    if(short_hash.hex()!=snapshot) return 1;
    short_hash.update(bytes("def"));
    if(short_hash.hex()!="bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721") return 1;
    constexpr std::string_view message="abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    for(size_t split=0;split<=message.size();++split) {
        Sha256 h;h.update(bytes(message.substr(0,split)));h.update(bytes(message.substr(split)));
        if(h.hex()!="248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") return 1;
    }
    const std::vector<uint8_t> a(1000,'a');Sha256 million;
    for(unsigned i=0;i<1000;++i) million.update(a);
    if(million.hex()!="cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") return 1;
    std::stop_source cancelled;cancelled.request_stop();
    auto result=uniflash::io::sha256([](auto,std::span<uint8_t> out,auto)->std::expected<void,std::errc>{
        std::fill(out.begin(),out.end(),'a');return {};
    },1000000,cancelled.get_token());
    if(result || result.error()!=std::errc::interrupted) return 1;
    uniflash::log_info("Streaming SHA-256 standard vectors and cancellation passed");
}

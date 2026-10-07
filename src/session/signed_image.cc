#include <uniflash/session/signed_image.h>
#include <uniflash/io/sha256.h>
#include "image_fields.h"
#include <algorithm>
#include <array>

namespace uniflash::session {
std::expected<SprdSignedPayload,std::errc> validate_sprd_signed_payload(
    const io::Reader& reader,uint64_t size,uint32_t image_size,
    SprdSignedPayload expected,std::stop_token stop) {
    using namespace image_fields;
    const uint64_t trailer=512+uint64_t(image_size);
    if(!reader || !image_size || !expected.size || expected.offset<512 ||
        !range(expected.offset,expected.size,trailer) || !range(trailer,96,size))
        return std::unexpected(std::errc::message_size);
    if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    std::array<uint8_t,96> header{};
    auto got=reader(trailer,header,stop);if(!got) return std::unexpected(got.error());
    // This producer zero-initializes magic/version and unused private/debug
    // regions. Other trailer dialects need their own parser.
    if(std::any_of(header.begin(),header.begin()+16,[](auto b){return b!=0;}) ||
        std::any_of(header.begin()+48,header.end(),[](auto b){return b!=0;}))
        return std::unexpected(std::errc::not_supported);
    const auto length=le(header,16,8),offset=le(header,24,8);
    const auto cert_size=le(header,32,8),cert_offset=le(header,40,8);
    // SPRD SCI signs an adjusted code range but retains payload_offset=512;
    // callers supply the independently parsed actual range.
    if(offset!=512 || length!=expected.size || cert_offset!=trailer+96 ||
        !range(cert_offset,cert_size,size) || cert_size!=size-cert_offset ||
        (cert_size!=596 && cert_size!=564)) return std::unexpected(std::errc::bad_message);
    std::array<uint8_t,596> cert{};
    got=reader(cert_offset,std::span(cert).first(static_cast<size_t>(cert_size)),stop);
    if(!got) return std::unexpected(got.error());
    const auto type=le(cert,0),exponent=le(cert,8);
    if((type!=0 && type!=1) || cert_size!=(type==1?596u:564u) || le(cert,4)!=2048 ||
        exponent<3 || !(exponent&1)) return std::unexpected(std::errc::bad_message);
    auto digest=io::sha256([&](uint64_t at,std::span<uint8_t> bytes,std::stop_token token) {
        return reader(expected.offset+at,bytes,token);
    },expected.size,stop);
    if(!digest) return std::unexpected(digest.error());
    if(*digest!=hex(std::span(cert).subspan(268,32))) return std::unexpected(std::errc::bad_message);
    return expected;
}
}

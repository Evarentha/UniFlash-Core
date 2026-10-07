#include <uniflash/session/boot_image.h>
#include <uniflash/session/pac_image_contract.h>
#include "temp_directory.h"
#include <fstream>
#include <vector>
#include <algorithm>
#include <array>
#include <uniflash/log.h>
int main() {
    using namespace uniflash;
    std::array<uint8_t,515> image{};
    image[0]=0x44;image[1]=0x48;image[2]=0x54;image[3]=0x42;image[4]=1;image[48]=3;
    image[512]='a';image[513]='b';image[514]='c';
    const io::Reader read=[&](uint64_t at,std::span<uint8_t> out,std::stop_token)->std::expected<void,std::errc> {
        if(at>image.size() || out.size()>image.size()-at) return std::unexpected(std::errc::message_size);
        std::copy_n(image.begin()+at,out.size(),out.begin());return {};
    };
    auto header=session::validate_boot_image(read,image.size());
    if(!header || header->declares_hash || header->payload_size!=3) return 1;
    constexpr std::array<uint8_t,32> digest{0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    std::copy(digest.begin(),digest.end(),image.begin()+8);
    header=session::validate_boot_image(read,image.size());
    if(!header || !header->declares_hash) return 1;
    image[512]^=1;if(session::validate_boot_image(read,image.size())) return 1;image[512]^=1;
    image[48]=4;if(session::validate_boot_image(read,image.size())) return 1;image[48]=3;
    image[56]=16;image[60]=0xff;image[61]=0xff;
    if(session::validate_boot_image(read,image.size())) return 1;
    image[56]=0;image[60]=0;image[61]=0;
    image[52]=1;if(session::validate_boot_image(read,image.size())) return 1;
    image[52]=0;
    TempDirectory root;const auto path=root.path/"signed.bin";
    std::vector<uint8_t> signed_image(image.begin(),image.end());signed_image.resize(515+96+564);
    const auto put=[&](size_t at,uint64_t value,size_t count=4) {
        for(size_t i=0;i<count;++i) signed_image[at+i]=static_cast<uint8_t>(value>>(8*i));
    };
    put(515+16,3,8);put(515+24,512,8);put(515+32,564,8);put(515+40,611,8);
    put(611+4,2048);put(611+8,65537);
    std::copy(digest.begin(),digest.end(),signed_image.begin()+611+268);
    const auto freeze=[&]() {
        {std::ofstream f(path,std::ios::binary);f.write(reinterpret_cast<const char*>(signed_image.data()),signed_image.size());}
        return io::Image::prepare_blob(path,4096);
    };
    auto source=freeze();if(!source) return 1;
    device::DeviceProfile profile;
    if(session::prepare_pac_image_contract("teecfg",*source,profile)) return 1;
    profile.mirrors_signed_boot_images=true;
    auto contract=session::prepare_pac_image_contract("teecfg",*source,profile);
    if(!contract || contract->verify_targets!=std::vector<std::string>{"teecfg","teecfg_bak"} ||
        contract->verify_size!=signed_image.size()) return 1;
    if(session::prepare_pac_image_contract("miscdata",*source,profile)) return 1;
    signed_image[611+268]^=1;auto damaged=freeze();
    if(!damaged || session::prepare_pac_image_contract("teecfg",*damaged,profile)) return 1;
    uniflash::log_info("Boot wrapper bounds, declared digest and packed-image rejection passed");
}

#include <uniflash/session/packed_image.h>
#include <uniflash/io/sha256.h>
#include "temp_directory.h"
#include <algorithm>
#include <fstream>
#include <uniflash/log.h>
using Bytes=std::vector<uint8_t>;
void put(Bytes& b,size_t at,uint64_t n,size_t width=4) {
    for(size_t i=0;i<width;++i) b[at+i]=static_cast<uint8_t>(n>>(8*i));
}
std::string digest(std::span<const uint8_t> b) {uniflash::io::Sha256 h;h.update(b);return h.hex();}
void save(const std::filesystem::path& p,const Bytes& b) {
    std::ofstream f(p,std::ios::binary);f.write(reinterpret_cast<const char*>(b.data()),b.size());
}
Bytes load(const std::filesystem::path& p) {std::ifstream f(p,std::ios::binary);return {std::istreambuf_iterator<char>(f),{}};}
int main() {
    using namespace uniflash;
    using session::PackedImageFormat;
    TempDirectory root;const auto input=root.path/"packed.bin",output=root.path/"out.bin";
    const Bytes modem{1,2,3,4,5,6,7,8};
    Bytes sci(132+modem.size());put(sci,0,0x31494353);put(sci,12,0x301);put(sci,16,132);put(sci,20,modem.size());
    std::copy(modem.begin(),modem.end(),sci.begin()+132);
    const auto apply=[&](const Bytes& b,PackedImageFormat format,std::string_view expected) {
        save(input,b);auto source=io::Image::prepare_blob(input,1024*1024);
        if(!source) return std::expected<uint64_t,io::OutputError>(std::unexpected(source.error()));
        return session::unpack_image(*source,format,output,expected);
    };
    if(!apply(sci,PackedImageFormat::Sci1,digest(modem)) || load(output)!=modem) return 1;
    auto corrupt=sci;put(corrupt,16,12);
    if(apply(corrupt,PackedImageFormat::Sci1,digest(modem)) || load(output)!=modem) return 1;
    corrupt=sci;put(corrupt,12,1); // missing terminal marker
    if(apply(corrupt,PackedImageFormat::Sci1,digest(modem))) return 1;
    corrupt=sci;put(corrupt,12,1);put(corrupt,24,0x101);put(corrupt,28,132);put(corrupt,32,8);
    if(apply(corrupt,PackedImageFormat::Sci1,digest(modem))) return 1; // duplicate modem
    auto prefixed=sci;prefixed.insert(prefixed.begin()+132,20,0xa5);put(prefixed,12,0x701);put(prefixed,20,28);
    if(!apply(prefixed,PackedImageFormat::Sci1,digest(modem)) || load(output)!=modem) return 1;
    // Signed SCI fixture: actual payload begins inside SCI, trailer retains 512.
    const size_t trailer=512+sci.size(),cert=trailer+96;
    Bytes signed_sci(cert+564);put(signed_sci,0,0x42544844);put(signed_sci,4,1);
    put(signed_sci,48,sci.size());put(signed_sci,52,1);put(signed_sci,56,modem.size());
    std::copy(sci.begin(),sci.end(),signed_sci.begin()+512);
    put(signed_sci,trailer+16,modem.size(),8);put(signed_sci,trailer+24,512,8);
    put(signed_sci,trailer+32,564,8);put(signed_sci,trailer+40,cert,8);
    put(signed_sci,cert+4,2048);put(signed_sci,cert+8,65537);
    const auto md=digest(modem);
    for(size_t i=0;i<32;++i) signed_sci[cert+268+i]=static_cast<uint8_t>(std::stoul(md.substr(i*2,2),nullptr,16));
    if(!apply(signed_sci,PackedImageFormat::SprdSignedSci1,md) || load(output)!=modem) return 1;
    corrupt=signed_sci;corrupt[512+132]^=1;
    if(apply(corrupt,PackedImageFormat::SprdSignedSci1,md) || load(output)!=modem) return 1;
    corrupt=signed_sci;put(corrupt,524,0x701);
    if(apply(corrupt,PackedImageFormat::SprdSignedSci1,md)) return 1;
    // Sansa loader-equivalent view, certificate uses the relocated coordinate
    // system. Stale original-image offsets must fail before output commit.
    Bytes sansa(512+256+1024);put(sansa,0,0x42544844);put(sansa,4,1);
    put(sansa,48,256);put(sansa,52,1);put(sansa,56,8);put(sansa,60,640);
    std::copy(modem.begin(),modem.end(),sansa.begin()+640);
    put(sansa,768+48,272,8);put(sansa,768+56,520+96,8);
    put(sansa,864,0xe291f358);put(sansa,864+8,4);put(sansa,864+12,2<<17);
    Bytes view(sansa.begin(),sansa.begin()+512);put(view,48,8);
    view.insert(view.end(),modem.begin(),modem.end());view.insert(view.end(),sansa.begin()+768,sansa.end());
    if(!apply(sansa,PackedImageFormat::SansaVerificationView,digest(view)) || load(output)!=view) return 1;
    corrupt=sansa;put(corrupt,768+56,768+96,8);
    if(apply(corrupt,PackedImageFormat::SansaVerificationView,digest(view)) || load(output)!=view) return 1;
    corrupt=sansa;put(corrupt,864+12,(2<<17)|0x10000);
    if(apply(corrupt,PackedImageFormat::SansaVerificationView,digest(view))) return 1;
    if(apply(sansa,PackedImageFormat::SansaVerificationView,std::string(64,'0')) || load(output)!=view) return 1;
    for(size_t field:{size_t(4),size_t(8),size_t(48),size_t(52),size_t(56),size_t(60)}) {
        corrupt=sansa;corrupt[field]^=1;
        if(apply(corrupt,PackedImageFormat::SansaVerificationView,digest(view)) || load(output)!=view) return 1;
    }
    save(input,sansa);auto frozen=io::Image::prepare_blob(input,1024*1024);
    if(!frozen) return 1;
    std::stop_source cancel;
    auto stopped=session::unpack_image(*frozen,PackedImageFormat::SansaVerificationView,output,digest(view),cancel.get_token(),
        [&](const io::PrepareProgress&){cancel.request_stop();});
    if(stopped || stopped.error()!=std::errc::interrupted || load(output)!=view) return 1;
    uniflash::log_info("Packed directory, signed payload and bounded Sansa view checks passed");
}

#include <uniflash/io/decrypt.h>
#include <uniflash/io/sha256.h>
#include "temp_directory.h"
#include <fstream>
#include <uniflash/log.h>
#include <vector>
#include <algorithm>

namespace {
std::vector<uint8_t> hex(std::string_view text) {
    const auto value=[](char c){return c<='9'?c-'0':c-'a'+10;};
    std::vector<uint8_t> bytes;
    for(size_t i=0;i<text.size();i+=2) bytes.push_back(static_cast<uint8_t>((value(text[i])<<4)|value(text[i+1])));
    return bytes;
}
void save(const std::filesystem::path& path,std::span<const uint8_t> bytes) {
    std::ofstream out(path,std::ios::binary);out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());
}
}
int main() {
    using namespace uniflash::io;
    TempDirectory root;
    // NIST SP800-38A F.2.5: AES-256-CBC with the R27 IV 000102...0f.
    auto key=hex("20000000603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    const auto ciphertext=hex("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d"
        "39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b");
    const auto plaintext=hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    Sha256 hash;hash.update(plaintext);
    const auto input=root.path/"encrypted.bin",output=root.path/"plaintext.bin";
    save(input,ciphertext);
    auto image=Image::prepare_blob(input,1024);
    if(!image) return 1;
    auto result=decrypt_r27_image(*image,key,output,hash.hex());
    if(!result || *result!=plaintext.size()) return 1;
    std::ifstream in(output,std::ios::binary);std::vector<uint8_t> actual{std::istreambuf_iterator<char>(in),{}};
    if(actual!=plaintext) return 1;
    in.close();
    key[4]^=1;
    if(decrypt_r27_image(*image,key,output,hash.hex())) return 1;
    auto retained=Image::prepare_blob(output,1024);std::vector<uint8_t> unchanged(plaintext.size());
    if(!retained || !retained->reader()(0,unchanged,{}) || unchanged!=plaintext) return 1;
    // Repeated NIST ciphertext spans cross the 1MiB processing boundary. Only
    // each repetition's first plaintext block changes with CBC chaining.
    std::vector<uint8_t> large_cipher,large_plain;
    for(unsigned repeat=0;repeat<16386;++repeat) {
        large_cipher.insert(large_cipher.end(),ciphertext.begin(),ciphertext.end());
        const auto start=large_plain.size();large_plain.insert(large_plain.end(),plaintext.begin(),plaintext.end());
        if(repeat) for(size_t i=0;i<16;++i) large_plain[start+i]^=static_cast<uint8_t>(i)^ciphertext[ciphertext.size()-16+i];
    }
    save(input,large_cipher);auto large=Image::prepare_blob(input,large_cipher.size());
    Sha256 large_hash;large_hash.update(large_plain);key[4]^=1;
    if(!large || !decrypt_r27_image(*large,key,output,large_hash.hex())) return 1;
    key[0]=16;
    if(decrypt_r27_image(*image,key,output,hash.hex())) return 1;
    const auto put=[](std::vector<uint8_t>& b,size_t at,uint64_t value,size_t width=4) {
        for(size_t i=0;i<width;++i) b[at+i]=static_cast<uint8_t>(value>>(8*i));
    };
    const auto bytes_of=[](const std::filesystem::path& p) {
        std::ifstream f(p,std::ios::binary);return std::vector<uint8_t>{std::istreambuf_iterator<char>(f),{}};
    };
    for(bool aes128:{false,true}) {
        const auto raw_key=aes128?hex("2b7e151628aed2a6abf7158809cf4f3c"):
            std::vector<uint8_t>(key.begin()+4,key.end());
        const auto cipher=aes128?hex("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
            "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"):ciphertext;
        std::vector<uint8_t> wrapped(512+cipher.size());
        put(wrapped,0,0x42544844);put(wrapped,4,1);put(wrapped,48,cipher.size());
        for(size_t i=0;i<16;++i) wrapped[60+i]=static_cast<uint8_t>(i);
        put(wrapped,68,0x0b0a0908^0x42544844);put(wrapped,72,0x0f0e0d0c^cipher.size());
        std::copy(cipher.begin(),cipher.end(),wrapped.begin()+512);
        save(input,wrapped);auto unsigned_image=Image::prepare_blob(input,4096);
        if(!unsigned_image || !decrypt_sprd_payload(*unsigned_image,raw_key,SprdCipherEnvelope::UnsignedPayload,output,hash.hex()) ||
            bytes_of(output)!=plaintext) return 1;
        if(decrypt_sprd_payload(*unsigned_image,raw_key,SprdCipherEnvelope::SignedPayload,output,hash.hex())) return 1;
        const size_t trailer=wrapped.size(),cert=trailer+96;
        wrapped.resize(cert+596);
        put(wrapped,trailer+16,cipher.size(),8);put(wrapped,trailer+24,512,8);
        put(wrapped,trailer+32,596,8);put(wrapped,trailer+40,cert,8);
        put(wrapped,cert,1);put(wrapped,cert+4,2048);put(wrapped,cert+8,65537);
        Sha256 ch;ch.update(cipher);auto digest=hex(ch.hex());
        std::copy(digest.begin(),digest.end(),wrapped.begin()+cert+268);
        save(input,wrapped);auto signed_image=Image::prepare_blob(input,4096);
        if(!signed_image || !decrypt_sprd_payload(*signed_image,raw_key,SprdCipherEnvelope::SignedPayload,output,hash.hex()) ||
            bytes_of(output)!=plaintext) return 1;
        if(decrypt_sprd_payload(*signed_image,raw_key,SprdCipherEnvelope::UnsignedPayload,output,hash.hex())) return 1;
        for(size_t field:{size_t(4),size_t(48),size_t(52),size_t(56),size_t(76),trailer+40}) {
            auto invalid=wrapped;invalid[field]^=1;save(input,invalid);
            auto bad=Image::prepare_blob(input,4096);
            if(!bad || decrypt_sprd_payload(*bad,raw_key,SprdCipherEnvelope::SignedPayload,output,hash.hex()) ||
                bytes_of(output)!=plaintext) return 1;
        }
        auto wrong_key=raw_key;wrong_key[0]^=1;
        if(decrypt_sprd_payload(*signed_image,wrong_key,SprdCipherEnvelope::SignedPayload,output,hash.hex()) ||
            bytes_of(output)!=plaintext) return 1;
        wrapped[cert+268]^=1;save(input,wrapped);auto broken=Image::prepare_blob(input,4096);
        if(!broken || decrypt_sprd_payload(*broken,raw_key,SprdCipherEnvelope::SignedPayload,output,hash.hex()) ||
            bytes_of(output)!=plaintext) return 1;
        std::stop_source cancelled;cancelled.request_stop();
        if(decrypt_sprd_payload(*signed_image,raw_key,SprdCipherEnvelope::SignedPayload,output,hash.hex(),cancelled.get_token())) return 1;
        // AES128 and AES256 both preserve CBC chaining across the 1MiB boundary.
        std::vector<uint8_t> blocks,expected_blocks;
        for(unsigned repeat=0;repeat<16386;++repeat) {
            blocks.insert(blocks.end(),cipher.begin(),cipher.end());
            const auto start=expected_blocks.size();expected_blocks.insert(expected_blocks.end(),plaintext.begin(),plaintext.end());
            if(repeat) for(size_t i=0;i<16;++i) expected_blocks[start+i]^=static_cast<uint8_t>(i)^cipher[cipher.size()-16+i];
        }
        wrapped.resize(512);put(wrapped,48,blocks.size());put(wrapped,72,0x0f0e0d0c^blocks.size());
        wrapped.insert(wrapped.end(),blocks.begin(),blocks.end());save(input,wrapped);
        auto chained=Image::prepare_blob(input,wrapped.size());Sha256 expected_hash;expected_hash.update(expected_blocks);
        if(!chained || !decrypt_sprd_payload(*chained,raw_key,SprdCipherEnvelope::UnsignedPayload,output,expected_hash.hex()) ||
            bytes_of(output)!=expected_blocks) return 1;
    }
    uniflash::log_info("R27 AES-CBC standard vector and failed-decrypt atomic output passed");
}

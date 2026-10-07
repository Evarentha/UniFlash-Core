/*
 * UniFlash-Core / Image Decryption
 *
 * AES payload extraction for the LP64 producer layout.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/io/decrypt.h>
#include <uniflash/io/output.h>
#include <uniflash/io/sha256.h>
#include <uniflash/session/signed_image.h>
#include "image_fields.h"
#include <algorithm>
#include <array>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <openssl/evp.h>
#endif

namespace uniflash::io {
namespace {
class AesCbc {
public:
    ~AesCbc() {
#ifdef _WIN32
        if(key_) BCryptDestroyKey(key_);
        if(algorithm_) BCryptCloseAlgorithmProvider(algorithm_,0);
        if(!object_.empty()) SecureZeroMemory(object_.data(),object_.size());
#else
        EVP_CIPHER_CTX_free(context_);
#endif
    }
    bool initialize(std::span<const uint8_t> key,std::span<const uint8_t,16> iv) {
        if(key.size()!=16 && key.size()!=32) return false;
        std::copy(iv.begin(),iv.end(),iv_.begin());
#ifdef _WIN32
        if(BCryptOpenAlgorithmProvider(&algorithm_,BCRYPT_AES_ALGORITHM,nullptr,0)<0) return false;
        if(BCryptSetProperty(algorithm_,BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),sizeof(BCRYPT_CHAIN_MODE_CBC),0)<0) return false;
        DWORD length=0,written=0;
        if(BCryptGetProperty(algorithm_,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&length),sizeof(length),&written,0)<0 ||
            written!=sizeof(length) || length>1024*1024) return false;
        object_.resize(length);
        return BCryptGenerateSymmetricKey(algorithm_,&key_,object_.data(),length,
            const_cast<PUCHAR>(key.data()),static_cast<ULONG>(key.size()),0)>=0;
#else
        context_=EVP_CIPHER_CTX_new();
        return context_ && EVP_DecryptInit_ex(context_,key.size()==16?EVP_aes_128_cbc():EVP_aes_256_cbc(),nullptr,key.data(),iv_.data())==1 &&
            EVP_CIPHER_CTX_set_padding(context_,0)==1;
#endif
    }
    bool update(std::span<uint8_t> encrypted,std::span<uint8_t> plain) {
#ifdef _WIN32
        ULONG produced=0;
        // BCrypt mutates the IV, but explicitly carry the last ciphertext block
        // to make inter-call chaining independent of provider implementation.
        std::array<uint8_t,16> next;
        std::copy(encrypted.end()-16,encrypted.end(),next.begin());
        const auto status=BCryptDecrypt(key_,encrypted.data(),static_cast<ULONG>(encrypted.size()),nullptr,
            iv_.data(),static_cast<ULONG>(iv_.size()),plain.data(),static_cast<ULONG>(plain.size()),&produced,0);
        iv_=next;
        return status>=0 && produced==encrypted.size();
#else
        int produced=0;
        return EVP_DecryptUpdate(context_,plain.data(),&produced,encrypted.data(),static_cast<int>(encrypted.size()))==1 &&
            produced==static_cast<int>(encrypted.size());
#endif
    }
    bool finish() {
#ifdef _WIN32
        return true;
#else
        std::array<uint8_t,16> tail{};int produced=0;
        return EVP_DecryptFinal_ex(context_,tail.data(),&produced)==1 && produced==0;
#endif
    }
private:
    std::array<uint8_t,16> iv_{};
#ifdef _WIN32
    BCRYPT_ALG_HANDLE algorithm_=nullptr;
    BCRYPT_KEY_HANDLE key_=nullptr;
    std::vector<uint8_t> object_;
#else
    EVP_CIPHER_CTX* context_=nullptr;
#endif
};
std::expected<uint64_t,OutputError> decrypt_region(const Image& encrypted,uint64_t offset,uint64_t length,
    AesCbc& cipher,const std::filesystem::path& destination,
    std::string_view expected,std::stop_token stop,const PrepareObserver& progress) {
    if(!length || length>UINT64_MAX/8 || length%16 ||
        !session::image_fields::range(offset,length,encrypted.size()) || !valid_sha256(expected))
        return std::unexpected(std::errc::invalid_argument);
    if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    const std::string expected_digest(expected);
    auto output=AtomicOutput::open(destination);
    if(!output) return std::unexpected(output.error());
    std::vector<uint8_t> input(1024*1024),plain(input.size());
    const auto reader=encrypted.reader();Sha256 hash;
    for(uint64_t at=0;at<length;) {
        const auto n=static_cast<size_t>(std::min<uint64_t>(input.size(),length-at));
        if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
        auto got=reader(offset+at,std::span(input).first(n),stop);if(!got) return std::unexpected(got.error());
        if(!cipher.update(std::span(input).first(n),std::span(plain).first(n))) return std::unexpected(std::errc::bad_message);
        hash.update(std::span(plain).first(n));
        auto written=output->write(std::span(plain).first(n),stop);if(!written) return std::unexpected(written.error());
        at+=n;if(progress) progress({PreparePhase::Checksum,at,length});
    }
    if(!cipher.finish() || hash.hex()!=expected_digest) return std::unexpected(std::errc::bad_message);
    if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    auto committed=output->commit_result();if(!committed) return std::unexpected(committed.error());
    return length;
}
}
std::expected<uint64_t,OutputError> decrypt_r27_image(const Image& encrypted,
    std::span<const uint8_t> descriptor,const std::filesystem::path& destination,
    std::string_view expected,std::stop_token stop,const PrepareObserver& progress) {
    if(descriptor.size()!=36 || descriptor[0]!=32 || descriptor[1] || descriptor[2] || descriptor[3])
        return std::unexpected(std::errc::invalid_argument);
    std::array<uint8_t,16> iv{};
    for(size_t i=0;i<iv.size();++i) iv[i]=static_cast<uint8_t>(i);
    AesCbc cipher;
    if(!cipher.initialize(descriptor.subspan(4),iv)) return std::unexpected(std::errc::io_error);
    return decrypt_region(encrypted,0,encrypted.size(),cipher,destination,expected,stop,progress);
}
std::expected<uint64_t,OutputError> decrypt_sprd_payload(const Image& encrypted,
    std::span<const uint8_t> key,SprdCipherEnvelope envelope,const std::filesystem::path& destination,
    std::string_view expected,std::stop_token stop,const PrepareObserver& progress) {
    using namespace session::image_fields;
    if((key.size()!=16 && key.size()!=32) || !valid_sha256(expected) ||
        (envelope!=SprdCipherEnvelope::UnsignedPayload && envelope!=SprdCipherEnvelope::SignedPayload))
        return std::unexpected(std::errc::invalid_argument);
    if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    const std::string expected_digest(expected);
    // Freeze before any reader/progress callback can mutate caller key data.
    std::array<uint8_t,32> frozen_key{};
    std::copy(key.begin(),key.end(),frozen_key.begin());
    struct Clear { std::array<uint8_t,32>& b; ~Clear(){volatile uint8_t* p=b.data();for(size_t i=0;i<b.size();++i) p[i]=0;} } clear{frozen_key};
    if(encrypted.size()<512) return std::unexpected(std::errc::message_size);
    std::array<uint8_t,512> header{};
    const auto reader=encrypted.reader();
    auto got=reader(0,header,stop);if(!got) return std::unexpected(got.error());
    if(le(header,0)!=0x42544844 || le(header,4)!=1 || le(header,52) || le(header,56))
        return std::unexpected(std::errc::not_supported);
    const auto length=static_cast<uint32_t>(le(header,48));
    if(!length || length%16 || !range(512,length,encrypted.size())) return std::unexpected(std::errc::message_size);
    // The audited secure-boot build starts with a zero payload hash and zero
    // reserved area except the 16-byte IV. Do not auto-detect other BTHD ABIs.
    if(std::any_of(header.begin()+8,header.begin()+40,[](auto b){return b!=0;}) ||
        std::any_of(header.begin()+76,header.end(),[](auto b){return b!=0;}))
        return std::unexpected(std::errc::not_supported);
    std::array<uint8_t,16> iv{};std::copy_n(header.begin()+60,16,iv.begin());
    put(iv,8,static_cast<uint32_t>(le(iv,8)^le(header,0)));
    put(iv,12,static_cast<uint32_t>(le(iv,12)^length));
    AesCbc cipher;
    if(!cipher.initialize(std::span(frozen_key).first(key.size()),iv)) return std::unexpected(std::errc::io_error);
    if(envelope==SprdCipherEnvelope::UnsignedPayload) {
        if(encrypted.size()!=512+uint64_t(length)) return std::unexpected(std::errc::message_size);
    } else {
        auto signed_payload=session::validate_sprd_signed_payload(reader,encrypted.size(),length,{512,length},stop);
        if(!signed_payload) return std::unexpected(signed_payload.error());
    }
    return decrypt_region(encrypted,512,length,cipher,destination,expected_digest,stop,progress);
}
}

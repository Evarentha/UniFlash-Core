/*
 * UniFlash-Core / R27 Authentication
 *
 * OpenSSL and BCrypt implementations of the R27 exchange.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#include <uniflash/io/authentication.h>
#include <uniflash/io/sha256.h>
#include <fstream>
#include <array>
#include <algorithm>
#include <mutex>
#include <memory>
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#endif
namespace uniflash::io {
namespace {
template<class B> void wipe(B& b) {volatile uint8_t* p=reinterpret_cast<volatile uint8_t*>(b.data());for(size_t i=0;i<b.size();++i)p[i]=0;}
struct Secret {std::vector<uint8_t> data;~Secret(){wipe(data);}};
struct Key {
    std::mutex mutex;
    std::array<uint8_t,32> project{};
#ifdef _WIN32
    BCRYPT_ALG_HANDLE algorithm=nullptr;BCRYPT_KEY_HANDLE key=nullptr;
    ~Key(){if(key)BCryptDestroyKey(key);if(algorithm)BCryptCloseAlgorithmProvider(algorithm,0);}
#else
    EVP_PKEY* key=nullptr;
    ~Key(){EVP_PKEY_free(key);}
#endif
};
#ifdef _WIN32
// Bounded DER PKCS1 reader; no platform-dependent native RSA structs on disk.
bool tlv(std::span<const uint8_t>& input,uint8_t tag,std::span<const uint8_t>& value) {
    if(input.size()<2 || input[0]!=tag)return false;
    size_t n=input[1],at=2;
    if(n&128) {
        const size_t bytes=n&127;if(!bytes || bytes>4 || input.size()<2+bytes || !input[2])return false;
        n=0;for(size_t i=0;i<bytes;++i)n=(n<<8)|input[at++];if(n<128)return false;
    }
    if(n>input.size()-at)return false;
    value=input.subspan(at,n);input=input.subspan(at+n);return true;
}
bool import_key(Key& out,std::span<const uint8_t> pem) {
    const std::string_view text(reinterpret_cast<const char*>(pem.data()),pem.size());
    constexpr std::string_view begin="-----BEGIN RSA PRIVATE KEY-----",end="-----END RSA PRIVATE KEY-----";
    const auto first=text.find(begin),last=text.find(end);
    if(first==std::string_view::npos || last==std::string_view::npos || last<first+begin.size())return false;
    Secret der;der.data.reserve(pem.size());uint32_t bits=0;unsigned count=0,padding=0,symbols=0;
    constexpr std::string_view alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for(char ch:text.substr(first+begin.size(),last-first-begin.size())) {
        if(ch==' '||ch=='\r'||ch=='\n'||ch=='\t')continue;
        ++symbols;
        if(ch=='='){if(++padding>2)return false;continue;}if(padding)return false;
        const auto v=alphabet.find(ch);if(v==std::string_view::npos)return false;
        bits=(bits<<6)|static_cast<uint32_t>(v);count+=6;
        if(count>=8){count-=8;der.data.push_back(static_cast<uint8_t>(bits>>count));}
    }
    if(symbols%4 || (padding==0 && count!=0) || (padding==1 && count!=2) ||
        (padding==2 && count!=4) || (count && (bits&((1u<<count)-1))))return false;
    std::span<const uint8_t> bytes=der.data,sequence;
    if(!tlv(bytes,0x30,sequence)||!bytes.empty())return false;
    std::array<std::span<const uint8_t>,9> integers;
    for(auto& value:integers) {
        if(!tlv(sequence,2,value)||value.empty()||(value[0]&128))return false;
        if(value.size()>1 && value[0]==0) {
            if(!(value[1]&128))return false;
            value=value.subspan(1);
        }
    }
    if(!sequence.empty()||integers[0].size()!=1||integers[0][0] || integers[1].size()!=256 ||
        !(integers[1][0]&128) || integers[2].size()>4)return false;
    BCRYPT_RSAKEY_BLOB header{BCRYPT_RSAFULLPRIVATE_MAGIC,2048,static_cast<ULONG>(integers[2].size()),256,128,128};
    Secret blob;blob.data.reserve(sizeof(header)+4+256+5*128+256);
    const auto* raw=reinterpret_cast<const uint8_t*>(&header);blob.data.assign(raw,raw+sizeof(header));
    const auto append=[&](size_t index,size_t length) {
        if(integers[index].size()>length)return false;
        blob.data.insert(blob.data.end(),length-integers[index].size(),0);
        blob.data.insert(blob.data.end(),integers[index].begin(),integers[index].end());return true;
    };
    if(!append(2,integers[2].size())||!append(1,256)||!append(4,128)||!append(5,128)||
        !append(6,128)||!append(7,128)||!append(8,128)||!append(3,256))return false;
    return BCryptOpenAlgorithmProvider(&out.algorithm,BCRYPT_RSA_ALGORITHM,nullptr,0)>=0 &&
        BCryptImportKeyPair(out.algorithm,nullptr,BCRYPT_RSAFULLPRIVATE_BLOB,&out.key,blob.data.data(),
            static_cast<ULONG>(blob.data.size()),0)>=0;
}
#endif
}
std::expected<auth::Responder,std::errc> r27_authenticator(const std::filesystem::path& path,
    std::span<const uint8_t,32> project,std::stop_token stop) {
    if(stop.stop_requested())return std::unexpected(std::errc::interrupted);
    std::ifstream file(path,std::ios::binary);if(!file)return std::unexpected(std::errc::no_such_file_or_directory);
    Secret pem;pem.data.resize(16385);file.read(reinterpret_cast<char*>(pem.data.data()),pem.data.size());
    const auto n=file.gcount();if(file.bad()||n<=0||n>16384)return std::unexpected(std::errc::message_size);
    pem.data.resize(static_cast<size_t>(n));auto key=std::make_shared<Key>();std::copy(project.begin(),project.end(),key->project.begin());
    const std::string_view text(reinterpret_cast<const char*>(pem.data.data()),pem.data.size());
    if(text.find("-----BEGIN RSA PRIVATE KEY-----")==std::string_view::npos)return std::unexpected(std::errc::not_supported);
#ifdef _WIN32
    if(!import_key(*key,pem.data))return std::unexpected(std::errc::bad_message);
#else
    BIO* bio=BIO_new_mem_buf(pem.data.data(),static_cast<int>(pem.data.size()));if(!bio)return std::unexpected(std::errc::not_enough_memory);
    key->key=PEM_read_bio_PrivateKey(bio,nullptr,[](char*,int,int,void*){return 0;},nullptr);BIO_free(bio);
    if(!key->key || !EVP_PKEY_is_a(key->key,"RSA") || EVP_PKEY_bits(key->key)!=2048)return std::unexpected(std::errc::bad_message);
#endif
    return auth::Responder([key](std::span<const uint8_t> m1,std::stop_token token)->std::expected<std::vector<uint8_t>,std::errc> {
        if(token.stop_requested())return std::unexpected(std::errc::interrupted);
        if(m1.size()!=290 || m1[288] || m1[289] || !std::equal(key->project.begin(),key->project.end(),m1.begin()+256))
            return std::unexpected(std::errc::bad_message);
        std::lock_guard lock(key->mutex);Secret plain;plain.data.resize(256);size_t length=256;
#ifdef _WIN32
        BCRYPT_OAEP_PADDING_INFO padding{BCRYPT_SHA1_ALGORITHM,nullptr,0};ULONG actual=0;
        if(BCryptDecrypt(key->key,const_cast<PUCHAR>(m1.data()),256,&padding,nullptr,0,plain.data.data(),256,&actual,BCRYPT_PAD_OAEP)<0)
            return std::unexpected(std::errc::bad_message);
        length=actual;
#else
        auto* ctx=EVP_PKEY_CTX_new(key->key,nullptr);if(!ctx)return std::unexpected(std::errc::not_enough_memory);
        const bool ok=EVP_PKEY_decrypt_init(ctx)>0 && EVP_PKEY_CTX_set_rsa_padding(ctx,RSA_PKCS1_OAEP_PADDING)>0 &&
            EVP_PKEY_CTX_set_rsa_oaep_md(ctx,EVP_sha1())>0 && EVP_PKEY_CTX_set_rsa_mgf1_md(ctx,EVP_sha1())>0 &&
            EVP_PKEY_decrypt(ctx,plain.data.data(),&length,m1.data(),256)>0;
        EVP_PKEY_CTX_free(ctx);if(!ok)return std::unexpected(std::errc::bad_message);
#endif
        if(length<36 || length>214)return std::unexpected(std::errc::bad_message);
        Sha256 hash;hash.update(std::span(plain.data).first(length));const auto hex=hash.hex();std::array<uint8_t,32> digest{};
        const auto digit=[](char c){return c<='9'?c-'0':c-'a'+10;};
        for(size_t i=0;i<32;++i)digest[i]=static_cast<uint8_t>(digit(hex[2*i])*16+digit(hex[2*i+1]));
        std::vector<uint8_t> response(288);
#ifdef _WIN32
        BCRYPT_PKCS1_PADDING_INFO info{nullptr};ULONG written=0;
        const bool signed_ok=BCryptSignHash(key->key,&info,digest.data(),32,response.data(),256,&written,BCRYPT_PAD_PKCS1)>=0 && written==256;
#else
        ctx=EVP_PKEY_CTX_new(key->key,nullptr);size_t written=256;
        const bool signed_ok=ctx && EVP_PKEY_sign_init(ctx)>0 && EVP_PKEY_CTX_set_rsa_padding(ctx,RSA_PKCS1_PADDING)>0 &&
            EVP_PKEY_sign(ctx,response.data(),&written,digest.data(),32)>0 && written==256;
        EVP_PKEY_CTX_free(ctx);
#endif
        wipe(digest);
        if(!signed_ok || token.stop_requested()) {wipe(response);return std::unexpected(token.stop_requested()?std::errc::interrupted:std::errc::bad_message);}
        std::copy_n(plain.data.begin()+4,32,response.begin()+256);return response;
    });
}
}

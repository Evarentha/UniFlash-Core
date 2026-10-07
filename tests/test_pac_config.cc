/*
 * UniFlash-Core Test / PAC Host Configuration
 *
 * Covers strict host configuration parsing and key handling.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/session/pac_config.h>
#include <uniflash/io/authentication.h>
#include <uniflash/io/sha256.h>
#include "temp_directory.h"
#include <fstream>
#include <array>
#include <algorithm>
#ifndef _WIN32
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#else
#include <windows.h>
#include <bcrypt.h>
#endif
int main() {
    using namespace uniflash;TempDirectory root;const auto path=root.path/"product.xml";
    const auto parse=[&](const std::string& text) {
        {std::ofstream out(path);out<<text;}
        return session::read_pac_config(path,"fixture");
    };
    auto config=parse("<PacHostConfig product=\"fixture\" address-word-order=\"big\" factory-timestamp=\"0x12345678\" write-efuse=\"1\">"
        "<NV target=\"nr_fixnv1\" logical-size=\"64\" protocol=\"r27-named\" device-order=\"little\" template-order=\"little\"/>"
        "<Vpac utf16le-hex=\"41000000\"/><SoftSim expected-eid-hex=\"00010203040506070809\"/></PacHostConfig>");
    if(!config || config->address_word_order!=device::AddressWordOrder::Big || config->factory_timestamp!=0x12345678 ||
        !config->factory_write_efuse || config->nv_representations.size()!=1 || config->nv_representations[0].logical_size!=64 || !config->nv_representations[0].r27_named_protocol ||
        config->vpac_utf16le!=std::vector<uint8_t>{0x41,0,0,0} || config->softsim_expected_eid.size()!=10)return 1;
    for(const auto* text:{"<PacHostConfig product=\"other\"/>","<PacHostConfig product=\"fixture\" typo=\"1\"/>",
        "<PacHostConfig product=\"fixture\"><NV target=\"a\" logical-size=\"9\"/></PacHostConfig>",
        "<PacHostConfig product=\"fixture\"><Vpac utf16le-hex=\"000041000000\"/></PacHostConfig>",
        "<PacHostConfig product=\"fixture\"><NV target=\"a\"/><NV target=\"a\"/></PacHostConfig>"})if(parse(text))return 1;
    if(!parse("\xef\xbb\xbf<?xml version=\"1.0\"?><PacHostConfig product=\"fixture\"/> <!--ok-->"))return 1;
    if(parse("<PacHostConfig product=\"fixture\"><!--\xff--></PacHostConfig>") ||
        parse("<PacHostConfig product=\"fixture\"/><PacHostConfig product=\"fixture\"/>"))return 1;
    std::array<uint8_t,32> project{};project[0]='P';
    const auto keypath=root.path/"key.pem";
    {std::ofstream out(keypath);out<<"-----BEGIN RSA PRIVATE KEY-----\nAA==\n-----END RSA PRIVATE KEY-----\n";}
    if(io::r27_authenticator(keypath,project))return 1;
#ifndef _WIN32
    // Executable fixture, compiled only: OAEP encryption and raw public-key
    // verification independently check the R27 responder's two RSA stages.
    EVP_PKEY_CTX* generation=EVP_PKEY_CTX_new_id(EVP_PKEY_RSA,nullptr);EVP_PKEY* key=nullptr;
    if(!generation || EVP_PKEY_keygen_init(generation)<=0 || EVP_PKEY_CTX_set_rsa_keygen_bits(generation,2048)<=0 ||
        EVP_PKEY_keygen(generation,&key)<=0)return 1;
    EVP_PKEY_CTX_free(generation);
    BIO* pem=BIO_new(BIO_s_mem());if(!pem || PEM_write_bio_PrivateKey_traditional(pem,key,nullptr,nullptr,0,nullptr,nullptr)!=1)return 1;
    char* encoded=nullptr;const auto length=BIO_get_mem_data(pem,&encoded);
    {std::ofstream out(keypath,std::ios::binary);out.write(encoded,length);}BIO_free(pem);
    auto responder=io::r27_authenticator(keypath,project);if(!responder)return 1;
    std::array<uint8_t,36> plain{};for(size_t i=0;i<plain.size();++i)plain[i]=static_cast<uint8_t>(i+1);
    std::vector<uint8_t> m1(290);size_t cipher_size=256;
    auto* ctx=EVP_PKEY_CTX_new(key,nullptr);
    if(!ctx || EVP_PKEY_encrypt_init(ctx)<=0 || EVP_PKEY_CTX_set_rsa_padding(ctx,RSA_PKCS1_OAEP_PADDING)<=0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx,EVP_sha1())<=0 || EVP_PKEY_CTX_set_rsa_mgf1_md(ctx,EVP_sha1())<=0 ||
        EVP_PKEY_encrypt(ctx,m1.data(),&cipher_size,plain.data(),plain.size())<=0 || cipher_size!=256)return 1;
    EVP_PKEY_CTX_free(ctx);std::copy(project.begin(),project.end(),m1.begin()+256);
    auto response=(*responder)(m1,{});if(!response || response->size()!=288 ||
        !std::equal(plain.begin()+4,plain.end(),response->begin()+256))return 1;
    std::array<uint8_t,32> digest{};unsigned digest_length=0;
    if(EVP_Digest(plain.data(),plain.size(),digest.data(),&digest_length,EVP_sha256(),nullptr)!=1)return 1;
    ctx=EVP_PKEY_CTX_new(key,nullptr);
    if(!ctx || EVP_PKEY_verify_init(ctx)<=0 || EVP_PKEY_CTX_set_rsa_padding(ctx,RSA_PKCS1_PADDING)<=0 ||
        EVP_PKEY_verify(ctx,response->data(),256,digest.data(),digest.size())!=1)return 1;
    EVP_PKEY_CTX_free(ctx);EVP_PKEY_free(key);
    m1[256]^=1;if((*responder)(m1,{}))return 1;
#else
    // Independent BCrypt producer/verification path exercises PEM/DER import,
    // OAEP decrypt, nonce extraction and raw PKCS1 signature on Windows.
    struct Rsa {
        BCRYPT_ALG_HANDLE alg=nullptr;BCRYPT_KEY_HANDLE key=nullptr;
        ~Rsa(){if(key)BCryptDestroyKey(key);if(alg)BCryptCloseAlgorithmProvider(alg,0);}
    } rsa;
    if(BCryptOpenAlgorithmProvider(&rsa.alg,BCRYPT_RSA_ALGORITHM,nullptr,0)<0 ||
        BCryptGenerateKeyPair(rsa.alg,&rsa.key,2048,0)<0 || BCryptFinalizeKeyPair(rsa.key,0)<0)return 1;
    using Bytes=std::vector<uint8_t>;ULONG count=0;
    if(BCryptExportKey(rsa.key,nullptr,BCRYPT_RSAFULLPRIVATE_BLOB,nullptr,0,&count,0)<0)return 1;
    Bytes blob(count);if(BCryptExportKey(rsa.key,nullptr,BCRYPT_RSAFULLPRIVATE_BLOB,blob.data(),count,&count,0)<0)return 1;
    const auto* header=reinterpret_cast<const BCRYPT_RSAKEY_BLOB*>(blob.data());
    const auto tlv=[](uint8_t tag,const Bytes& data) {
        Bytes out{tag};
        if(data.size()<128)out.push_back(static_cast<uint8_t>(data.size()));
        else if(data.size()<256){out.push_back(0x81);out.push_back(static_cast<uint8_t>(data.size()));}
        else {out.push_back(0x82);out.push_back(static_cast<uint8_t>(data.size()>>8));out.push_back(static_cast<uint8_t>(data.size()));}
        out.insert(out.end(),data.begin(),data.end());return out;
    };
    size_t at=sizeof(BCRYPT_RSAKEY_BLOB);
    const auto field=[&](size_t size) {Bytes out(blob.begin()+at,blob.begin()+at+size);at+=size;return out;};
    auto e=field(header->cbPublicExp),n=field(header->cbModulus),p=field(header->cbPrime1),q=field(header->cbPrime2);
    auto dp=field(header->cbPrime1),dq=field(header->cbPrime2),iq=field(header->cbPrime1),d=field(header->cbModulus);
    Bytes sequence;
    for(auto value:{Bytes{0},n,e,d,p,q,dp,dq,iq}) {
        while(value.size()>1 && !value.front())value.erase(value.begin());
        if(value.front()&128)value.insert(value.begin(),0);
        auto encoded=tlv(2,value);sequence.insert(sequence.end(),encoded.begin(),encoded.end());
    }
    const auto der=tlv(0x30,sequence);
    constexpr char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string pem="-----BEGIN RSA PRIVATE KEY-----\n";
    for(size_t i=0;i<der.size();i+=3) {
        const uint32_t bits=uint32_t(der[i])<<16 | (i+1<der.size()?uint32_t(der[i+1])<<8:0) | (i+2<der.size()?der[i+2]:0);
        pem+=alphabet[(bits>>18)&63];pem+=alphabet[(bits>>12)&63];
        pem+=i+1<der.size()?alphabet[(bits>>6)&63]:'=';pem+=i+2<der.size()?alphabet[bits&63]:'=';
    }
    pem+="\n-----END RSA PRIVATE KEY-----\n";
    {std::ofstream out(keypath,std::ios::binary);out<<pem;}
    auto responder=io::r27_authenticator(keypath,project);if(!responder)return 1;
    std::array<uint8_t,36> plain{};for(size_t i=0;i<plain.size();++i)plain[i]=static_cast<uint8_t>(i+1);
    Bytes m1(290);BCRYPT_OAEP_PADDING_INFO oaep{BCRYPT_SHA1_ALGORITHM,nullptr,0};
    if(BCryptEncrypt(rsa.key,plain.data(),plain.size(),&oaep,nullptr,0,m1.data(),256,&count,BCRYPT_PAD_OAEP)<0 || count!=256)return 1;
    std::copy(project.begin(),project.end(),m1.begin()+256);
    auto response=(*responder)(m1,{});if(!response || response->size()!=288 || !std::equal(plain.begin()+4,plain.end(),response->begin()+256))return 1;
    std::array<uint8_t,32> digest{};
    BCRYPT_ALG_HANDLE sha=nullptr;
    if(BCryptOpenAlgorithmProvider(&sha,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0)return 1;
    DWORD object_size=0,property_size=0;
    if(BCryptGetProperty(sha,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&object_size),sizeof(object_size),&property_size,0)<0)return 1;
    Bytes object(object_size);BCRYPT_HASH_HANDLE hash=nullptr;
    if(BCryptCreateHash(sha,&hash,object.data(),object.size(),nullptr,0,0)<0)return 1;
    const bool hashed=BCryptHashData(hash,plain.data(),plain.size(),0)>=0 && BCryptFinishHash(hash,digest.data(),digest.size(),0)>=0;
    BCryptDestroyHash(hash);BCryptCloseAlgorithmProvider(sha,0);if(!hashed)return 1;
    BCRYPT_PKCS1_PADDING_INFO pkcs{nullptr};
    if(BCryptVerifySignature(rsa.key,&pkcs,digest.data(),digest.size(),response->data(),256,BCRYPT_PAD_PKCS1)<0)return 1;
    m1[256]^=1;if((*responder)(m1,{}))return 1;
    m1[256]^=1;m1[0]^=1;if((*responder)(m1,{}))return 1;
#endif
}

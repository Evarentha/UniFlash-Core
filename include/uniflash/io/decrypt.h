#pragma once
#include <uniflash/io/image.h>
#include <string_view>
#include <uniflash/io/commit.h>
namespace uniflash::io {
enum class SprdCipherEnvelope { UnsignedPayload, SignedPayload };
// Explicit vendor LP64 producer: IV at header+60, AES128/256 selected by the
// raw key length, payload [512,512+mImgSize). Output is padded plaintext payload
// only; the ciphertext's certificate is never attached to the plaintext.
std::expected<uint64_t,OutputError> decrypt_sprd_payload(const Image& encrypted,
    std::span<const uint8_t> raw_key,SprdCipherEnvelope,
    const std::filesystem::path& destination,std::string_view expected_sha256,
    std::stop_token = {},const PrepareObserver& = {});
// R27 Codec.dll ALG_AES: key descriptor LE32(32)+key[32], IV 00..0f,
// AES-256-CBC, no padding. Expected plaintext digest must match before commit.
std::expected<uint64_t,OutputError> decrypt_r27_image(const Image& encrypted,
    std::span<const uint8_t> key_descriptor,const std::filesystem::path& destination,
    std::string_view expected_sha256,std::stop_token = {},const PrepareObserver& = {});
}

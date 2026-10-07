/*
 * UniFlash-Core Test / Checksum Frames
 *
 * Covers ADD checksum framing, escaping and reply classification.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#include <uniflash/protocol/bsl.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <uniflash/log.h>
#include <sstream>
#include <iterator>
#include <span>
#include <string>
#include <vector>

namespace {

using uniflash::protocol::BslCodec;
using uniflash::protocol::HDLC_ESCAPE;
using uniflash::protocol::HDLC_ESCAPE_MASK;
using uniflash::protocol::HDLC_FLAG;

int failures = 0;

void check(bool condition, const std::string& name) {
    if (!condition) {
        uniflash::log_err(std::string("FAIL: ")+name);
        ++failures;
    }
}

// Independent receiver oracle: BSP dl_crc.c/frm_chk consumes native LE
// words, including the trailer, and an odd final byte in the low position.
// A valid host command must give zero. Do not use the production checksum
// or decoder here: matching bugs in an encoder/decoder can round-trip.
uint16_t device_rx_residue(std::span<const uint8_t> packet) {
    uint32_t sum = 0;
    for (size_t i = 0; i < packet.size(); ++i)
        sum += static_cast<uint32_t>(packet[i]) << ((i & 1) * 8);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

std::vector<uint8_t> packet_body(std::span<const uint8_t> frame,
                                 bool escaped) {
    std::vector<uint8_t> body;
    for (size_t i = 1; i + 1 < frame.size(); ++i) {
        if (escaped && frame[i] == HDLC_ESCAPE) {
            if (i + 2 >= frame.size()) {
                check(false, "complete HDLC escape pair");
                return {};
            }
            body.push_back(frame[++i] ^ HDLC_ESCAPE_MASK);
        } else {
            body.push_back(frame[i]);
        }
    }
    return body;
}

void check_midst(size_t size) {
    std::vector<uint8_t> payload(size);
    for (size_t i = 0; i < size; ++i)
        payload[i] = static_cast<uint8_t>(i * 37 + 0x7d);

    for (bool escaped : {false, true}) {
        const std::string label = (escaped ? "escaped" : "raw") +
            std::string(" MIDST payload=") + std::to_string(size);
        auto encoded = escaped ? BslCodec::encode_midst_data_add(payload)
                               : BslCodec::encode_midst_data_raw(payload);
        check(encoded.has_value(), label + " encodes");
        if (!encoded) continue;
        check(encoded->front() == HDLC_FLAG && encoded->back() == HDLC_FLAG,
              label + " delimiters");
        if (!escaped)
            check(encoded->size() == size + 8, label + " has no padding");

        auto body = packet_body(*encoded, escaped);
        check(body.size() == size + 6, label + " body length");
        if (body.size() != size + 6) continue;
        check(body[0] == 0 && body[1] == 2 &&
                  ((static_cast<size_t>(body[2]) << 8) | body[3]) == size,
              label + " header length matches payload");
        check(std::equal(payload.begin(), payload.end(), body.begin() + 4),
              label + " payload unchanged");
        check(device_rx_residue(body) == 0,
              label + " passes the BSP whole-packet verifier");
        body.back() ^= 1;
        check(device_rx_residue(body) != 0,
              label + " corrupted trailer is rejected");
    }
}

}  // namespace

int main(int argc, char** argv) {
    // Known odd-length command. The old encoder emitted ed fc instead
    // of fc ed, which does not cancel the receiver's whole-packet sum.
    const std::array<uint8_t, 1> payload{0x12};
    const std::array<uint8_t, 5> odd_body{0x00, 0x02, 0x00, 0x01, 0x12};
    check(BslCodec::add_checksum(odd_body) == 0xedfc,
          "canonical body checksum retains its byte order");
    auto odd_command = BslCodec::encode_midst_data_raw(payload);
    const std::vector<uint8_t> expected_command{
        0x7e, 0x00, 0x02, 0x00, 0x01, 0x12, 0xfc, 0xed, 0x7e};
    check(odd_command && *odd_command == expected_command,
          "odd command trailer accounts for its alignment");

    // Same payload length as the reported DTB tail (102735 - 63488).
    // An all-zero fixture has a hand-computable header sum 0x994f + 2.
    auto tail = BslCodec::encode_midst_data_raw(std::vector<uint8_t>(39247));
    check(tail && tail->size() == 39255 &&
              (*tail)[39252] == 0xae && (*tail)[39253] == 0x66,
          "39247-byte tail uses the receiver-compatible trailer");

    // FDL_DataProcess generates replies differently: frm_chk(body),
    // EndianConv_16, then high/low bytes, even when the body is odd.
    // Do not apply the host-command parity correction to received replies.
    const std::vector<uint8_t> reply{
        0x7e, 0x00, 0x93, 0x00, 0x01, 0x12, 0xed, 0x6b, 0x7e};
    auto decoded = BslCodec::decode_hdlc(reply);
    check(decoded && decoded->first == 0x93 &&
              decoded->second == std::vector<uint8_t>{0x12},
          "odd-length BSP READ_FLASH reply still decodes");
    check(BslCodec::add_checksum(std::span(reply).subspan(1, 5)) == 0xed6b,
          "raw reply validator still matches the BSP reply checksum");
    auto bad_reply = reply;
    bad_reply[6] ^= 1;
    check(!BslCodec::decode_hdlc(bad_reply),
          "corrupted odd-length reply is rejected");

    for (size_t size : {0, 1, 2, 3, 5, 1017, 1018, 2043, 2044,
                       39246, 39247, 63488, 65529, 65530})
        check_midst(size);

    // Optional forensic check of a real image, without USB I/O.
    if (argc == 2) {
        std::ifstream file(argv[1], std::ios::binary);
        if (!file) {
            uniflash::log_err(std::string("cannot open image: ")+argv[1]);
            return 1;
        }
        const std::vector<uint8_t> image{
            std::istreambuf_iterator<char>{file},
            std::istreambuf_iterator<char>{}};
        const std::span<const uint8_t> data(image);
        for (size_t off = 0; off < data.size(); off += 63488) {
            const auto chunk = data.subspan(
                off, std::min<size_t>(63488, data.size() - off));
            auto encoded = BslCodec::encode_midst_data_raw(chunk);
            check(encoded.has_value(), "real image chunk encodes");
            if (!encoded) continue;
            const auto body = packet_body(*encoded, false);
            const auto residue = device_rx_residue(body);
            check(residue == 0, "real image chunk passes BSP verifier");
            std::ostringstream record;
            record << "offset=" << off << " payload=" << chunk.size()
                      << " wire=" << encoded->size() << " checksum=0x"
                      << std::hex
                      << ((static_cast<unsigned>(body[body.size() - 2]) << 8) |
                          body.back())
                      << " residue=0x" << residue;
            uniflash::log_info(record.str());
        }
    } else if (argc != 1) {
        uniflash::log_err("usage: test_add_checksum [image]");
        return 1;
    }

    if (failures) return 1;
    uniflash::log_info("ADD command parity and BSP reply regressions passed");
    return 0;
}

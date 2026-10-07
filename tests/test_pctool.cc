/*
 * UniFlash-Core Test / PC Tool Mode
 *
 * Covers mode parsing and confirmation frame decoding.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#include <uniflash/protocol/bsl.h>
#include <uniflash/protocol/pctool.h>

#include <uniflash/log.h>
#include <string>
#include <vector>

using namespace uniflash::protocol;

int main() {
    int failures = 0;
    const auto check = [&](bool ok, const char* name) {
        if (!ok) { uniflash::log_err(std::string("FAIL: ")+name); ++failures; }
    };
    for (const auto text : {"", "0", "0x00", "-1", "+2", "64", "0x42", "0x57",
                            "256", "0x102", "0x", "23junk", "2 ", " 2",
                            "999999999999999999999999999"})
        check(!parse_pc_mode(text), "invalid input rejected without truncation");
    for (unsigned mode = 1; mode <= 63; ++mode) {
        auto parsed = parse_pc_mode(std::to_string(mode));
        check(parsed && *parsed == mode, "decimal mode parses exactly");
        auto frame = BslCodec::encode_pctool_mode(static_cast<uint8_t>(mode));
        check(frame && frame->size() == 10 && (*frame)[0] == 0x7e &&
              (*frame)[5] == 8 && (*frame)[6] == 0 && (*frame)[7] == 0xfe &&
              (*frame)[8] == mode && (*frame)[9] == 0x7e,
              "wire mode matches BSP six-bit subtype");
        check(frame && (*frame)[1] == 0 && (*frame)[2] == 0 && (*frame)[3] == 0,
              "calibration frequency is explicitly zero");
    }
    check(parse_pc_mode("0x02") == PC_MODE_AUTO_DOWNLOAD, "hex auto-download");
    check(parse_pc_mode("0X15") == PC_MODE_AUTOTEST, "hex autotest");
    check(parse_pc_mode("23") == PC_MODE_PROGRAMKEY, "decimal programkey");
    check(!BslCodec::encode_pctool_mode(0), "encoder rejects zero");
    check(!BslCodec::encode_pctool_mode(0x42), "encoder rejects auto-download alias");
    check(!BslCodec::encode_pctool_mode(0x57), "encoder rejects programkey alias");

    // Literal BSP MSG_HEAD_T (8 bytes) + CNF {status, length=2}.
    const std::vector<uint8_t> cnf{0x7e, 0,0,0,0, 12,0, 0x62,0, 0,0, 2,0, 0x7e};
    auto decoded = decode_pctool_confirmation(cnf);
    check(decoded && decoded->sequence == 0 && decoded->status == 0,
          "valid program confirmation");
    auto exit_cnf = cnf;
    exit_cnf[1] = 1;
    exit_cnf[9] = 1;
    decoded = decode_pctool_confirmation(exit_cnf);
    check(decoded && decoded->sequence == 1 && decoded->status == 1,
          "exit sequence and failure status are preserved");
    const std::vector<uint8_t> escaped{0x7e, 0,0,0,0, 12,0, 0x62,0,
                                      0x7d,0x5e, 0x7d,0x5d, 2,0, 0x7e};
    decoded = decode_pctool_confirmation(escaped);
    check(decoded && decoded->status == 0x7d7e, "confirmation unescapes status bytes");
    for (size_t length = 0; length < cnf.size(); ++length)
        check(!decode_pctool_confirmation(std::span(cnf).first(length)),
              "truncated or empty confirmation rejected");
    for (size_t index : {size_t(0), size_t(5), size_t(6), size_t(7), size_t(8),
                         size_t(11), size_t(12), size_t(13)}) {
        auto malformed = cnf;
        malformed[index] ^= 1;
        check(!decode_pctool_confirmation(malformed), "malformed header or CNF rejected");
    }
    auto bad_escape = escaped;
    bad_escape[10] = 0x11;
    check(!decode_pctool_confirmation(bad_escape), "invalid escape rejected");
    auto merged = cnf;
    merged.insert(merged.end(), cnf.begin(), cnf.end());
    check(!decode_pctool_confirmation(merged), "decoder consumes one frame only");

    const std::vector<uint8_t> exit_request{0x7e, 1,0,0,0, 14,0, 0x62,0,
                                          0x0a,0, 6,0, 0xff,0xff, 0x7e};
    check(BslCodec::encode_pctool_programkey_exit(0xffff, 1) == exit_request,
          "exit uses a distinct sequence and requests power-down");
    if (failures) return 1;
    uniflash::log_info("PC-tool mode and confirmation tests passed");
}

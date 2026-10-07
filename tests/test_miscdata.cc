/*
 * UniFlash-Core Test / Miscdata
 *
 * Covers serial parsing and boot lock record classification.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#include <uniflash/session/miscdata.h>
#include <algorithm>
#include <uniflash/log.h>

int main() {
    using namespace uniflash::session;
    std::vector<uint8_t> bytes(512);
    const auto put = [&](size_t at, uint32_t value) {
        for (unsigned i=0;i<4;++i) bytes[at+i] = value >> (8*i);
    };
    for (uint32_t magic : {0x53503035u,0x53503039u}) {
        std::fill(bytes.begin(),bytes.end(),0);
        put(0,magic); put(52,3);
        bytes[4]='A'; bytes[28]='B';
        bytes[252]=4; bytes[254]=2;
        auto p=parse_miscdata(bytes);
        if (!p || p->sn1!="A" || p->sn2!="B" || p->stations.size()!=3 ||
            p->stations[0].result!=StationResult::Pass || p->stations[1].result!=StationResult::Fail ||
            p->stations[2].result!=StationResult::NotTested) return 1;
        put(52,16); if (parse_miscdata(bytes)) return 1;
    }
    std::fill(bytes.begin(),bytes.end(),0);
    put(0,0x53503135); put(132,2);
    std::fill(bytes.begin()+4,bytes.begin()+68,'S');
    put(484,1); put(488,2);
    auto p=parse_miscdata(bytes);
    if (!p || p->sn1.size()!=64 || !p->ambiguous_status ||
        p->stations[0].result!=StationResult::Unknown || p->stations[1].result!=StationResult::Unknown) return 1;
    if (parse_miscdata(std::span(bytes).first(490))) return 1;
    auto ilp32 = parse_miscdata(std::span(bytes).first(492));
    if (!ilp32 || ilp32->ambiguous_status || ilp32->stations[0].result != StationResult::NotTested) return 1;
    std::vector<uint8_t> lock(64);
    if (parse_boot_lock_record(lock) != BootLockRecord::Empty) return 1;
    const std::string marker = "VerifiedBoot-UNLOCK";
    std::copy(marker.begin(), marker.end(), lock.begin());
    if (parse_boot_lock_record(lock) != BootLockRecord::UnlockMarker) return 1;
    lock.back() = 1;
    if (parse_boot_lock_record(lock) != BootLockRecord::Opaque) return 1;
    put(132,21); if (parse_miscdata(bytes)) return 1;
    put(0,0); if (parse_miscdata(bytes).error()!=std::errc::not_supported) return 1;
    uniflash::log_info("Miscdata phase-check decoding passed");
}

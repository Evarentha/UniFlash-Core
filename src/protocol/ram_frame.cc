/*
 * UniFlash-Core / RAM Frames
 *
 * Start, midst and end frame encoding within wire limits.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#include <uniflash/protocol/ram_frame.h>
#include <array>

namespace uniflash::protocol {
std::expected<RamFrame, std::errc> encode_ram_midst(std::span<const uint8_t> data,
    BslCodec::Chk checksum, size_t payload_limit, size_t wire_limit,
    size_t packet_size, bool avoid_checksum_escapes) {
    const size_t maximum = std::min({data.size(), payload_limit, size_t(MAX_PAYLOAD_SIZE)});
    if (!maximum || wire_limit < 9 || packet_size < 2)
        return std::unexpected(std::errc::invalid_argument);
    const auto escaped = [](uint8_t b) { return b == HDLC_FLAG || b == HDLC_ESCAPE; };
    std::vector<size_t> lengths(maximum + 1, 0);
    // Header occupies 5..7 encoded bytes: opening flag + 00 02 + length.
    // Precompute bad payload boundaries for each possible header length so
    // rejecting many candidate lengths never repeatedly scans/hashes payload.
    std::array<size_t, 3> first_bad{maximum+1, maximum+1, maximum+1};
    for (size_t i=0; i<maximum; ++i) {
        if (escaped(data[i])) for (size_t h=5; h<=7; ++h)
            if ((h + lengths[i] + 1) % packet_size == 0)
                first_bad[h-5] = std::min(first_bad[h-5], i+1);
        lengths[i+1] = lengths[i] + (escaped(data[i]) ? 2 : 1);
    }
    for (size_t count=maximum; count; --count) {
        const size_t header = 5 + escaped(static_cast<uint8_t>(count >> 8)) +
            escaped(static_cast<uint8_t>(count));
        if (count >= first_bad[header-5] || header + lengths[count] + 3 > wire_limit) continue;
        const auto payload = data.first(count);
        if (avoid_checksum_escapes && BslCodec::chk_carries_escape(checksum, 2, payload)) continue;
        auto frame = BslCodec::encode_hdlc_chk(2, payload, checksum);
        if (!frame) return std::unexpected(frame.error());
        if (frame->size() > wire_limit) continue;
        bool safe = true;
        for (size_t boundary=packet_size-1; boundary+1<frame->size(); boundary+=packet_size)
            if ((*frame)[boundary] == HDLC_ESCAPE) { safe = false; break; }
        if (safe) return RamFrame{count, std::move(*frame)};
    }
    return std::unexpected(std::errc::protocol_error);
}
}

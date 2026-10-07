/*
 * UniFlash-Core / PAC Image Contract
 *
 * Mirrored boot targets, payload checks and loader policy limits.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/session/pac_image_contract.h>
#include <uniflash/session/boot_image.h>
#include <uniflash/session/signed_image.h>
#include <array>
#include <algorithm>
namespace uniflash::session {
bool mirrored_boot_target(std::string_view name) {
    return name=="splloader" || name=="uboot" || name=="trustos" || name=="teecfg" || name=="sml" || name=="vbmeta";
}
std::expected<PacImageContract,std::errc> prepare_pac_image_contract(
    const std::string& partition,const io::Image& image,const device::DeviceProfile& profile,std::stop_token stop) {
    std::array<uint8_t,4> magic{};
    if(image.size()>=magic.size()) {
        auto got=image.reader()(0,magic,stop);if(!got) return std::unexpected(got.error());
    }
    const bool wrapped=magic==std::array<uint8_t,4>{0x44,0x48,0x54,0x42};
    const bool mirrored=mirrored_boot_target(partition);
    if(partition=="miscdata" || (wrapped && !mirrored) || (mirrored && !profile.mirrors_signed_boot_images) ||
        (mirrored && partition!="vbmeta" && !wrapped)) return std::unexpected(std::errc::not_supported);
    if(wrapped) {
        auto header=validate_boot_image(image.reader(),image.size(),stop);
        if(!header) return std::unexpected(header.error());
        // The audited secure-boot package route expects SPRD key/content
        // certificates. Validate the stored hash as well as BTHD's optional hash
        // before a loader can enter its unrecoverable verification loop.
        auto signed_payload=validate_sprd_signed_payload(image.reader(),image.size(),header->payload_size,
            {512,header->payload_size},stop);
        if(!signed_payload) return std::unexpected(signed_payload.error());
    }
    PacImageContract result;result.verify_size=image.size();result.verify_targets={partition};
    if(partition=="splloader") result.verify_size=std::max<uint64_t>(result.verify_size,32768);
    if(mirrored) result.verify_targets.push_back(partition+"_bak");
    return result;
}
}

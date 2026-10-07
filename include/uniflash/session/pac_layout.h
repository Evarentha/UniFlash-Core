/*
 * UniFlash-Core / PAC Layout Plan
 *
 * Geometry comparison and relocation planning for repartitioning.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <uniflash/session/pac_parser.h>
#include <uniflash/layout/disk_layout.h>
#include <string>
#include <span>

namespace uniflash::session {
struct PacLayoutPlan {
    layout::GptLayout expected;
    std::vector<uint8_t> table;
    bool changed = false;
    std::vector<layout::GptPartition> relocate;
};
// Identifies equal-sized unselected regions requiring relocation. No implicit
// deletion/truncation. The execution service must snapshot all such sources
// and establish a byte-preserving write contract before changing the GPT.
std::expected<PacLayoutPlan,std::errc> prepare_pac_layout(const layout::GptLayout& original,
    const PacImage& requested,uint32_t strategy,std::span<const std::string> replaced);
bool same_partition_geometry(const layout::GptLayout&,const layout::GptLayout&);
}

/*
 * UniFlash-Core / Restore Manifest
 *
 * Strict bounded parser for raw partition backup manifests.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <cstdint>
#include <filesystem>
#include <expected>
#include <string>
#include <system_error>
#include <vector>

namespace uniflash::session {
struct RestoreEntry {
    std::string name, file, source;
    uint64_t size=0, offset=0;
    std::string sha256{};
};
struct RestoreManifest {
    uint64_t disk_bytes=0;
    uint32_t sector_size=0;
    std::string header_sha256, entries_sha256;
    std::vector<RestoreEntry> entries;
};
// Strict, bounded parser for committed raw-partition-backup-v1/v2/v3 manifests.
// Never infer completeness from the presence of files in a directory.
std::expected<RestoreManifest,std::errc> read_restore_manifest(const std::filesystem::path&);
}

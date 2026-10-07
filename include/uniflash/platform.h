/*
 * UniFlash-Core / Platform Abstraction
 *
 * Path, byte order, terminal and directory durability helpers.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef UNIFLASH_PLATFORM_H
#define UNIFLASH_PLATFORM_H

#include <bit>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <expected>

namespace uniflash::platform {

template<class T> constexpr T little_endian(T value) {
    if constexpr (std::endian::native == std::endian::little) return value;
    else return std::byteswap(value);
}

std::filesystem::path path(std::string_view utf8);
std::string utf8_path(const std::filesystem::path& path);
bool is_terminal(int fd);
bool supports_ansi(int fd);
void initialize_console();
std::string history_path();
// Linux persists directory entries up to the root. Windows reports the weaker
// file-commit-only guarantee explicitly, without requiring volume privileges.
enum class DirectoryDurability { Synced, FileCommitsOnly };
std::expected<DirectoryDurability,std::errc> sync_directory_tree(const std::filesystem::path&);

#ifdef _WIN32
std::wstring wide(std::string_view utf8);
std::string utf8(std::wstring_view wide);
std::errc windows_error(unsigned long code);
#endif

} // namespace uniflash::platform
#endif

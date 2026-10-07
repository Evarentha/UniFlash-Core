/*
 * UniFlash-Core / Platform Implementation
 *
 * Path conversion, directory durability and terminal control.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/platform.h>

#include <cstdlib>
#include <cerrno>
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#include <fcntl.h>
#endif

namespace uniflash::platform {
std::expected<DirectoryDurability,std::errc> sync_directory_tree(const std::filesystem::path& directory) {
    std::error_code ec;
    auto current=std::filesystem::canonical(directory,ec);
    if(ec)return std::unexpected(std::errc::io_error);
#ifdef _WIN32
    // File commits already use FlushFileBuffers + write-through replacement.
    // There is no unprivileged portable Windows directory-fsync equivalent.
    // Report the weaker guarantee instead of requiring volume-admin access or
    // claiming a volume flush happened. This works with writable UNC paths too.
    if(!std::filesystem::is_directory(current,ec) || ec)return std::unexpected(std::errc::not_a_directory);
    return DirectoryDurability::FileCommitsOnly;
#else
    for(;;) {
        const int fd=::open(current.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        if(fd<0)return std::unexpected(static_cast<std::errc>(errno));
        int result;do {result=fsync(fd);} while(result && errno==EINTR);
        const int error=errno;close(fd);
        if(result)return std::unexpected(static_cast<std::errc>(error));
        const auto parent=current.parent_path();if(parent==current)break;current=parent;
    }
#endif
    return DirectoryDurability::Synced;
}

std::filesystem::path path(std::string_view text) {
    return std::filesystem::u8path(text.begin(), text.end());
}

std::string utf8_path(const std::filesystem::path& value) {
    const auto text = value.u8string();
    return std::string(reinterpret_cast<const char*>(text.data()), text.size());
}

bool is_terminal(int fd) {
#ifdef _WIN32
    DWORD mode;
    return GetConsoleMode(reinterpret_cast<HANDLE>(_get_osfhandle(fd)), &mode) != 0;
#else
    return isatty(fd) != 0;
#endif
}

bool supports_ansi(int fd) {
#ifdef _WIN32
    DWORD mode;
    return GetConsoleMode(reinterpret_cast<HANDLE>(_get_osfhandle(fd)), &mode) &&
           (mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING);
#else
    return is_terminal(fd);
#endif
}

void initialize_console() {
#ifdef _WIN32
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
    for (DWORD id : {STD_OUTPUT_HANDLE, STD_ERROR_HANDLE}) {
        const HANDLE handle = GetStdHandle(id);
        DWORD mode;
        if (GetConsoleMode(handle, &mode))
            SetConsoleMode(handle, mode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
#endif
}

std::string history_path() {
    std::filesystem::path home;
#ifdef _WIN32
    if (const auto* value = _wgetenv(L"USERPROFILE")) home = value;
#else
    if (const auto* value = std::getenv("HOME")) home = path(value);
#endif
    // No shared /tmp history fallback. A missing/invalid home disables
    // persistence instead of writing into an unrelated directory.
    if (home.empty() || !home.is_absolute()) return {};
    for (const auto& part : home) if (part == "..") return {};
    return utf8_path(home / ".uniflash_history");
}

#ifdef _WIN32
std::wstring wide(std::string_view text) {
    if (text.empty()) return {};
    int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                                   static_cast<int>(text.size()), nullptr, 0);
    if (!size) throw std::system_error(GetLastError(), std::system_category());
    std::wstring out(size, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                        static_cast<int>(text.size()), out.data(), size);
    return out;
}

std::string utf8(std::wstring_view text) {
    if (text.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
                                   static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (!size) throw std::system_error(GetLastError(), std::system_category());
    std::string out(size, '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
                        static_cast<int>(text.size()), out.data(), size, nullptr, nullptr);
    return out;
}

std::errc windows_error(unsigned long code) {
    switch (code) {
    case ERROR_SUCCESS: return {};
    case ERROR_ACCESS_DENIED: return std::errc::permission_denied;
    case ERROR_SHARING_VIOLATION: case ERROR_BUSY: return std::errc::device_or_resource_busy;
    case ERROR_FILE_NOT_FOUND: case ERROR_PATH_NOT_FOUND: return std::errc::no_such_file_or_directory;
    case ERROR_DEVICE_NOT_CONNECTED:
    case ERROR_NO_SUCH_DEVICE: case ERROR_INVALID_HANDLE: case ERROR_DEV_NOT_EXIST:
        return std::errc::no_such_device;
    case ERROR_OPERATION_ABORTED: return std::errc::interrupted;
    case ERROR_TIMEOUT: case ERROR_SEM_TIMEOUT: return std::errc::timed_out;
    case ERROR_NOT_SUPPORTED: case ERROR_INVALID_FUNCTION: return std::errc::not_supported;
    case ERROR_INVALID_PARAMETER: return std::errc::invalid_argument;
    case ERROR_DISK_FULL: return std::errc::no_space_on_device;
    default: return std::errc::io_error;
    }
}
#endif

} // namespace uniflash::platform

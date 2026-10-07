/*
 * UniFlash-Core / Atomic Output File
 *
 * Temporary file creation, durable replacement and cleanup.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/io/output.h>
#include <uniflash/platform.h>
#include <algorithm>
#include <cerrno>
#include <utility>
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace uniflash::io {
#ifndef _WIN32
namespace {
int sync_file(int fd) {
    int result;
    do { result = fsync(fd); } while (result && errno == EINTR);
    return result;
}
}
#endif
struct AtomicOutput::Impl {
    std::filesystem::path destination, temporary, directory;
    uint64_t size = 0;
    bool committed = false;
    CommitState state = CommitState::NotCommitted;
    bool failed = false;
#ifdef _WIN32
    HANDLE file = INVALID_HANDLE_VALUE;
#else
    int file = -1;
#endif
    ~Impl() {
#ifdef _WIN32
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
        if (!committed && !temporary.empty()) DeleteFileW(temporary.c_str());
#else
        if (file >= 0) close(file);
        if (!committed && !temporary.empty()) unlink(temporary.c_str());
#endif
    }
};
AtomicOutput::AtomicOutput(std::unique_ptr<Impl> p) : p_(std::move(p)) {}
AtomicOutput::~AtomicOutput() = default;
AtomicOutput::AtomicOutput(AtomicOutput&&) noexcept = default;
AtomicOutput& AtomicOutput::operator=(AtomicOutput&&) noexcept = default;
uint64_t AtomicOutput::size() const { return p_->size; }
CommitState AtomicOutput::commit_state() const { return p_->state; }

std::expected<AtomicOutput, std::errc> AtomicOutput::open(const std::filesystem::path& destination) {
    auto p = std::make_unique<Impl>();
    // Resolve once before creating the temporary file: later chdir calls must
    // not redirect replacement, directory sync or cleanup. This does not pin
    // directory identity against renames or symlink/topology changes.
    std::error_code error;
    p->destination = std::filesystem::absolute(destination, error);
    if (error) {
        const auto condition = error.default_error_condition();
        return std::unexpected(condition.category() == std::generic_category()
            ? static_cast<std::errc>(condition.value()) : std::errc::io_error);
    }
    p->directory = p->destination.parent_path();
#ifdef _WIN32
    for (unsigned attempt = 0; attempt < 32; ++attempt) {
        unsigned char random[16];
        if (BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG))
            return std::unexpected(std::errc::io_error);
        constexpr wchar_t hex[] = L"0123456789abcdef";
        std::wstring name = L".uniflash-";
        for (auto c : random) { name += hex[c >> 4]; name += hex[c & 15]; }
        auto temporary = p->directory / name;
        p->file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                             FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (p->file != INVALID_HANDLE_VALUE) { p->temporary.swap(temporary); break; }
        if (GetLastError() != ERROR_FILE_EXISTS)
            return std::unexpected(platform::windows_error(GetLastError()));
    }
    if (p->file == INVALID_HANDLE_VALUE) return std::unexpected(std::errc::file_exists);
#else
    auto temporary = (p->directory / ".uniflash-XXXXXX").string();
    p->file = mkstemp(temporary.data());
    if (p->file < 0) return std::unexpected(static_cast<std::errc>(errno));
    // Path construction may allocate after mkstemp has created the file. Keep
    // its native name available for cleanup if ownership cannot be recorded.
    try { p->temporary = temporary; }
    catch (...) { unlink(temporary.c_str()); throw; }
    fcntl(p->file, F_SETFD, FD_CLOEXEC);
#endif
    return AtomicOutput(std::move(p));
}

std::expected<void, std::errc> AtomicOutput::write(std::span<const uint8_t> bytes, std::stop_token stop) {
    if (!p_ || p_->committed || p_->failed) return std::unexpected(std::errc::operation_not_permitted);
    struct Guard {
        bool& failed;
        bool complete = false;
        ~Guard() { if (!complete) failed = true; }
    } guard{p_->failed};
    size_t offset = 0;
    while (offset < bytes.size()) {
        if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
        const auto length = std::min<size_t>(bytes.size() - offset, 1u << 20);
#ifdef _WIN32
        DWORD written = 0;
        if (!WriteFile(p_->file, bytes.data() + offset, static_cast<DWORD>(length), &written, nullptr))
            return std::unexpected(platform::windows_error(GetLastError()));
#else
        const auto written = ::write(p_->file, bytes.data() + offset, length);
        if (written < 0 && errno == EINTR) continue;
        if (written < 0) return std::unexpected(static_cast<std::errc>(errno));
#endif
        if (!written) return std::unexpected(std::errc::io_error);
        offset += written;
        p_->size += written;
    }
    guard.complete = true;
    return {};
}

std::expected<void, std::errc> AtomicOutput::commit() {
    if (!p_ || p_->committed || p_->failed) return std::unexpected(std::errc::operation_not_permitted);
#ifdef _WIN32
    if (!FlushFileBuffers(p_->file)) return std::unexpected(platform::windows_error(GetLastError()));
    const auto file = std::exchange(p_->file, INVALID_HANDLE_VALUE);
    if (!CloseHandle(file)) return std::unexpected(platform::windows_error(GetLastError()));
    if (!MoveFileExW(p_->temporary.c_str(), p_->destination.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        return std::unexpected(platform::windows_error(GetLastError()));
#else
    if (sync_file(p_->file)) return std::unexpected(static_cast<std::errc>(errno));
    const auto file = std::exchange(p_->file, -1);
    if (close(file)) return std::unexpected(static_cast<std::errc>(errno));
    if (::rename(p_->temporary.c_str(), p_->destination.c_str()))
        return std::unexpected(static_cast<std::errc>(errno));
#endif
    p_->committed = true;
    p_->state = CommitState::Replaced;
#ifndef _WIN32
    const int directory = ::open(p_->directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) return std::unexpected(static_cast<std::errc>(errno));
    const int result = sync_file(directory);
    const int error = errno;
    close(directory);
    if (result) return std::unexpected(static_cast<std::errc>(error));
#endif
    p_->state = CommitState::Durable;
    return {};
}
std::expected<void,OutputError> AtomicOutput::commit_result() {
    if(!p_)return std::unexpected(OutputError{std::errc::operation_not_permitted});
    auto result=commit();
    if(!result)return std::unexpected(OutputError{result.error(),commit_state(),
        commit_state()==CommitState::NotCommitted?0:size()});
    return {};
}
}

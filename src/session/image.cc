/*
 * UniFlash-Core / Image Preparation
 *
 * Snapshot creation, sparse indexing and checksum verification.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#include <uniflash/io/image.h>
#include <uniflash/io/sparse_index.h>
#include <uniflash/io/sparse_format.h>
#include <uniflash/io/checksum.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <utility>
#include <uniflash/progress.h>
#ifdef _WIN32
#include <windows.h>
#include <uniflash/platform.h>
#include <fcntl.h>
#include <io.h>
#include <bcrypt.h>
#else
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace uniflash::io {
namespace {
struct CloseFile { void operator()(FILE* file) const { if (file) std::fclose(file); } };
using File = std::unique_ptr<FILE, CloseFile>;
bool seek(FILE* file, uint64_t offset) {
    if (offset > INT64_MAX) return false;
#ifdef _WIN32
    return _fseeki64(file, static_cast<int64_t>(offset), SEEK_SET) == 0;
#else
    return fseeko(file, static_cast<off_t>(offset), SEEK_SET) == 0;
#endif
}
bool read_at(FILE* file, uint64_t offset, std::span<uint8_t> bytes) {
    return seek(file, offset) && std::fread(bytes.data(), 1, bytes.size(), file) == bytes.size();
}
uint32_t word(const uint8_t* bytes, size_t width) {
    uint32_t value = 0;
    for (size_t i = 0; i < width; ++i) value |= uint32_t(bytes[i]) << (8 * i);
    return value;
}

// Combine standard IEEE CRC-32 values, not CRC32C. Matrix exponentiation
// advances the first CRC by exactly length bytes before appending the second.
uint32_t matrix_times(const std::array<uint32_t, 32>& matrix, uint32_t value) {
    uint32_t out = 0;
    for (size_t i = 0; value; ++i, value >>= 1) if (value & 1) out ^= matrix[i];
    return out;
}
std::array<uint32_t, 32> square(const std::array<uint32_t, 32>& matrix) {
    std::array<uint32_t, 32> out{};
    for (size_t i = 0; i < out.size(); ++i) out[i] = matrix_times(matrix, matrix[i]);
    return out;
}
uint32_t combine(uint32_t first, uint32_t second, uint64_t length) {
    if (!length) return first;
    std::array<uint32_t, 32> bit{};
    bit[0] = 0xedb88320;
    for (size_t i = 1; i < bit.size(); ++i) bit[i] = uint32_t{1} << (i - 1);
    auto bytes = square(square(square(bit)));
    while (length) {
        if (length & 1) first = matrix_times(bytes, first);
        length >>= 1;
        if (length) bytes = square(bytes);
    }
    return first ^ second;
}
uint32_t append_pattern(uint32_t crc, const std::array<uint8_t, 4>& pattern, uint64_t length) {
    // Sparse block sizes are multiples of four; no materialized zero/FILL scan.
    uint64_t count = length / 4, block_length = 4;
    uint32_t block_crc = crc32_update(0, pattern);
    while (count) {
        if (count & 1) crc = combine(crc, block_crc, block_length);
        count >>= 1;
        if (count) {
            block_crc = combine(block_crc, block_crc, block_length);
            block_length *= 2;
        }
    }
    return crc;
}

std::expected<File, std::errc> snapshot(const std::filesystem::path& path,
    uint64_t& size,uint64_t encoded_limit, std::stop_token stop, const PrepareObserver& progress) {
    if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    if (progress) progress({PreparePhase::Snapshot, 0, 0});
#ifdef _WIN32
    // Deny ordinary writers/deletion while copying into a private snapshot.
    // A pre-existing writable mapping can outlive its source handle, so the
    // sharing mode alone is not an immutable content snapshot.
    HANDLE handle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return std::unexpected(platform::windows_error(GetLastError()));
    LARGE_INTEGER length{};
    if (!GetFileSizeEx(handle, &length) || length.QuadPart <= 0) {
        CloseHandle(handle);
        return std::unexpected(std::errc::invalid_argument);
    }
    size = static_cast<uint64_t>(length.QuadPart);
    if(size>encoded_limit) {CloseHandle(handle);return std::unexpected(std::errc::file_too_large);}
    const int fd = _open_osfhandle(reinterpret_cast<intptr_t>(handle), _O_RDONLY | _O_BINARY);
    if (fd < 0) { CloseHandle(handle); return std::unexpected(static_cast<std::errc>(errno)); }
    FILE* source = _fdopen(fd, "rb");
    if (!source) { _close(fd); return std::unexpected(static_cast<std::errc>(errno)); }
    File original(source);
    std::error_code temp_error;
    const auto directory = std::filesystem::temp_directory_path(temp_error);
    if (temp_error) return std::unexpected(std::errc::io_error);
    HANDLE temporary = INVALID_HANDLE_VALUE;
    for (unsigned attempt = 0; attempt < 32; ++attempt) {
        unsigned char random[16];
        if (BCryptGenRandom(nullptr, random, sizeof random, BCRYPT_USE_SYSTEM_PREFERRED_RNG))
            return std::unexpected(std::errc::io_error);
        constexpr wchar_t digits[] = L"0123456789abcdef";
        std::wstring name = L"uniflash-image-";
        for (auto byte : random) { name += digits[byte >> 4]; name += digits[byte & 15]; }
        temporary = CreateFileW((directory / name).c_str(), GENERIC_READ | GENERIC_WRITE | DELETE,
            0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
        if (temporary != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_FILE_EXISTS) return std::unexpected(platform::windows_error(GetLastError()));
    }
    if (temporary == INVALID_HANDLE_VALUE) return std::unexpected(std::errc::file_exists);
    const int temporary_fd = _open_osfhandle(reinterpret_cast<intptr_t>(temporary), _O_RDWR | _O_BINARY);
    if (temporary_fd < 0) { CloseHandle(temporary); return std::unexpected(std::errc::io_error); }
    File copy(_fdopen(temporary_fd, "w+b"));
    if (!copy) { _close(temporary_fd); return std::unexpected(std::errc::io_error); }
    std::vector<uint8_t> buffer(1024 * 1024);
    for (uint64_t offset = 0; offset < size;) {
        if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
        const auto n = static_cast<size_t>(std::min<uint64_t>(buffer.size(), size - offset));
        if (std::fread(buffer.data(), 1, n, original.get()) != n ||
            std::fwrite(buffer.data(), 1, n, copy.get()) != n)
            return std::unexpected(std::errc::io_error);
        offset += n;
        if (progress) progress({PreparePhase::Snapshot, offset, size});
    }
    if (std::fflush(copy.get())) return std::unexpected(std::errc::io_error);
    // All validation and subsequent sends read this private copy. Concurrent
    // mapping writes cannot mutate the prepared bytes after validation.
    return copy;
#else
    // A FIFO without a writer must not block before the descriptor-level type
    // check. Linux ignores O_NONBLOCK for regular files; their snapshot path
    // (including symlinks to regular files) stays the same.
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return std::unexpected(static_cast<std::errc>(errno));
    File source(fdopen(fd, "rb"));
    if (!source) {
        const int error = errno;
        close(fd);
        return std::unexpected(static_cast<std::errc>(error));
    }
    struct stat before{};
    if (fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_size <= 0)
        return std::unexpected(std::errc::invalid_argument);
    size = static_cast<uint64_t>(before.st_size);
    if(size>encoded_limit)return std::unexpected(std::errc::file_too_large);
    if (progress) progress({PreparePhase::Snapshot, 0, size});
    // Try an anonymous same-filesystem file for CoW (Btrfs/XFS), then the
    // system temporary directory. Read-only source directories need not work.
    auto directory = path.parent_path();
    if (directory.empty()) directory = ".";
    int temporary = ::open(directory.c_str(), O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
    File copy(temporary >= 0 ? fdopen(temporary, "w+b") : nullptr);
    if (temporary >= 0 && !copy) close(temporary);
    const auto clone = [&](FILE* destination) {
        if (!destination) return false;
        WaitProgress waiting("snapshot - trying copy-on-write clone");
        return ioctl(fileno(destination), FICLONE, fd) == 0;
    };
    bool cloned = clone(copy.get());
    if (!cloned) {
        // Don't allocate a full fallback copy beside the source on a slow disk.
        copy.reset(std::tmpfile());
        if (!copy) return std::unexpected(static_cast<std::errc>(errno));
        fcntl(fileno(copy.get()), F_SETFD, FD_CLOEXEC);
        cloned = clone(copy.get());
    }
    if (!cloned) {
        std::vector<uint8_t> buffer(1024 * 1024);
        uint64_t offset = 0;
        while (offset < size) {
            if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
            const size_t n = static_cast<size_t>(std::min<uint64_t>(buffer.size(), size - offset));
            if (std::fread(buffer.data(), 1, n, source.get()) != n ||
                std::fwrite(buffer.data(), 1, n, copy.get()) != n)
                return std::unexpected(std::errc::io_error);
            offset += n;
            if (progress) progress({PreparePhase::Snapshot, offset, size});
        }
        if (std::fflush(copy.get())) return std::unexpected(std::errc::io_error);
    }
    struct stat after{}, copied{};
    if (fstat(fd, &after) || fstat(fileno(copy.get()), &copied))
        return std::unexpected(std::errc::io_error);
    // Detect ordinary concurrent source edits while making the fallback copy.
    if (before.st_size != after.st_size || before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec || before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
        before.st_ctim.tv_nsec != after.st_ctim.tv_nsec || copied.st_size != before.st_size)
        return std::unexpected(std::errc::state_not_recoverable);
    if (progress) progress({PreparePhase::Snapshot, size, size});
    return copy;
#endif
}
}

struct Image::Impl {
    using Extent=SparseExtent;
    Reader source;
    uint64_t length = 0;
    bool sparse = false;
    std::vector<Extent> extents;
    std::mutex mutex;
};

uint64_t Image::size() const { return p_->length; }
Reader Image::reader() const {
    return [p = p_](uint64_t offset, std::span<uint8_t> bytes, std::stop_token stop)
        -> std::expected<void, std::errc> {
        if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
        if (offset > p->length || bytes.size() > p->length - offset)
            return std::unexpected(std::errc::message_size);
        std::lock_guard lock(p->mutex);
        if (!p->sparse) {
            return p->source(offset, bytes, stop);
        }
        auto extent = std::upper_bound(p->extents.begin(), p->extents.end(), offset,
            [](uint64_t value, const Impl::Extent& e) { return value < e.start; });
        if (extent != p->extents.begin()) --extent;
        while (!bytes.empty()) {
            if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
            if (extent == p->extents.end() || offset < extent->start || offset - extent->start >= extent->length)
                return std::unexpected(std::errc::message_size);
            const uint64_t within = offset - extent->start;
            const size_t n = static_cast<size_t>(std::min<uint64_t>(bytes.size(), extent->length - within));
            if (extent->type == CHUNK_TYPE_RAW) {
                auto read = p->source(extent->source + within, bytes.first(n), stop);
                if (!read) return read;
            } else {
                // Seed the rotated pattern then double already initialized
                // bytes. Zero/FILL expansion uses bulk copies, not a modulo
                // operation for every logical byte.
                size_t filled = std::min<size_t>(4, n);
                for (size_t i = 0; i < filled; ++i) bytes[i] = extent->pattern[(within + i) % 4];
                while (filled < n) {
                    const size_t count = std::min(filled, n - filled);
                    std::memcpy(bytes.data() + filled, bytes.data(), count);
                    filled += count;
                }
            }
            bytes = bytes.subspan(n);
            offset += n;
            ++extent;
        }
        return {};
    };
}

std::expected<Image, std::errc> Image::prepare(const std::filesystem::path& path,
    uint64_t capacity, std::stop_token stop, const PrepareObserver& progress) {
    return freeze(path,capacity,stop,progress,true);
}
std::expected<Image,std::errc> Image::prepare_blob(const std::filesystem::path& path,
    uint64_t capacity,std::stop_token stop,const PrepareObserver& progress) {
    return freeze(path,capacity,stop,progress,false);
}
std::expected<Image,std::errc> Image::freeze(const std::filesystem::path& path,
    uint64_t capacity,std::stop_token stop,const PrepareObserver& progress,bool decode_sparse) {
    uint64_t file_size = 0;
    auto frozen = snapshot(path,file_size,decode_sparse?UINT64_MAX:capacity,stop,progress);
    if (!frozen) return std::unexpected(frozen.error());
    struct Source { File file; std::mutex mutex; };
    auto source = std::make_shared<Source>();
    source->file = std::move(*frozen);
    Reader reader=[source](uint64_t at, std::span<uint8_t> bytes, std::stop_token token)
        -> std::expected<void, std::errc> {
        if (token.stop_requested()) return std::unexpected(std::errc::interrupted);
        std::lock_guard lock(source->mutex);
        if (!read_at(source->file.get(), at, bytes)) return std::unexpected(std::errc::io_error);
        return {};
    };
    if(decode_sparse) return index(std::move(reader),file_size,capacity,stop,progress);
    auto p=std::make_shared<Impl>(); p->source=std::move(reader); p->length=file_size;
    return Image(std::move(p));
}
std::expected<Image,std::errc> Image::blob_region(uint64_t offset,uint64_t length) const {
    if(!length || offset>size() || length>size()-offset) return std::unexpected(std::errc::message_size);
    auto p=std::make_shared<Impl>(); p->length=length;
    p->source=[read=reader(),offset,length](uint64_t at,std::span<uint8_t> bytes,std::stop_token stop)->std::expected<void,std::errc> {
        if(at>length || bytes.size()>length-at) return std::unexpected(std::errc::message_size);
        return read(offset+at,bytes,stop);
    };
    return Image(std::move(p));
}

std::expected<Image, std::errc> Image::region(uint64_t offset, uint64_t length,
    uint64_t capacity, std::stop_token stop, const PrepareObserver& progress) const {
    if (!length || offset > size() || length > size() - offset)
        return std::unexpected(std::errc::message_size);
    return index([read = reader(), offset, length](uint64_t at, std::span<uint8_t> bytes, std::stop_token token)
        -> std::expected<void, std::errc> {
        if (at > length || bytes.size() > length - at) return std::unexpected(std::errc::message_size);
        return read(offset + at, bytes, token);
    }, length, capacity, stop, progress);
}

std::expected<Image, std::errc> Image::index(Reader source, uint64_t file_size,
    uint64_t capacity, std::stop_token stop, const PrepareObserver& progress) {
    auto indexed=index_sparse(source,file_size,capacity,stop,progress);
    if(!indexed)return std::unexpected(indexed.error());
    auto p = std::make_shared<Impl>();
    p->source = std::move(source);
    p->length=indexed->length;p->sparse=indexed->sparse;p->extents=std::move(indexed->extents);
    return Image(std::move(p));
}
std::expected<SparseIndex,std::errc> index_sparse(const Reader& read,uint64_t file_size,uint64_t capacity,
    std::stop_token stop,const PrepareObserver& progress) {
    if(!read)return std::unexpected(std::errc::invalid_argument);
    SparseIndex result;auto* p=&result;
    if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    std::array<uint8_t, 28> header{};
    const size_t initial = static_cast<size_t>(std::min<uint64_t>(header.size(), file_size));
    if (auto r = read(0, std::span(header).first(initial), stop); !r) return std::unexpected(r.error());
    p->sparse = initial >= 4 && word(header.data(), 4) == 0xed26ff3a;
    if (!p->sparse) {
        if (file_size > capacity) return std::unexpected(std::errc::file_too_large);
        p->length = file_size;
        return result; // No unused CRC pass over ordinary images.
    }
    const auto file_header = word(header.data() + 8, 2);
    const auto chunk_header = word(header.data() + 10, 2);
    const auto block_size = word(header.data() + 12, 4);
    p->block_size=block_size;
    const uint64_t total = uint64_t(word(header.data() + 16, 4)) * block_size;
    const auto chunks = word(header.data() + 20, 4);
    const auto expected_crc = word(header.data() + 24, 4);
    if (initial != 28 || word(header.data() + 4, 2) != 1 || file_header < 28 ||
        file_header > file_size || chunk_header < 12 || !block_size || block_size % 4 ||
        !total || total > capacity)
        return std::unexpected(std::errc::invalid_argument);
    struct Checkpoint { uint64_t offset; uint32_t crc; };
    std::vector<Checkpoint> checks;
    uint64_t cursor = file_header;
    if (progress) progress({PreparePhase::Index, 0, chunks});
    for (uint32_t i = 0; i < chunks; ++i) {
        if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
        std::array<uint8_t, 12> head;
        if (cursor > file_size || chunk_header > file_size - cursor)
            return std::unexpected(std::errc::message_size);
        auto got=read(cursor,head,stop);if(!got)return std::unexpected(got.error());
        const uint16_t type = static_cast<uint16_t>(word(head.data(), 2));
        const uint64_t bytes = uint64_t(word(head.data() + 4, 4)) * block_size;
        const uint64_t encoded = word(head.data() + 8, 4);
        if (bytes > total - p->length || encoded < chunk_header || encoded > file_size - cursor)
            return std::unexpected(std::errc::bad_message);
        const uint64_t source = cursor + chunk_header;
        uint64_t payload = 0;
        if (type == CHUNK_TYPE_RAW) payload = bytes;
        else if (type == CHUNK_TYPE_FILL || type == CHUNK_TYPE_CRC32) payload = 4;
        else if (type != CHUNK_TYPE_DONT_CARE) return std::unexpected(std::errc::not_supported);
        if (encoded != uint64_t(chunk_header) + payload) return std::unexpected(std::errc::bad_message);
        SparseExtent extent{p->length, bytes, source, type, {}};
        if (type == CHUNK_TYPE_CRC32 || type == CHUNK_TYPE_FILL) {
            if (auto r = read(source, extent.pattern, stop); !r) return std::unexpected(r.error());
        }
        if (type == CHUNK_TYPE_CRC32) {
            if (bytes) return std::unexpected(std::errc::bad_message);
            checks.push_back({p->length, word(extent.pattern.data(), 4)});
        } else if (bytes) {
            p->extents.push_back(extent);
            p->length += bytes;
        }
        cursor += encoded;
        if (progress) progress({PreparePhase::Index, uint64_t(i) + 1, chunks});
    }
    if (p->length != total || cursor != file_size) return std::unexpected(std::errc::bad_message);
    if (expected_crc) checks.push_back({total, expected_crc});
    // Only declared checksums require a payload scan, and only through the
    // last checkpoint. FILL/zero extents are combined in logarithmic time.
    if (!checks.empty()) {
        std::array<uint8_t, 65536> buffer;
        uint32_t crc = 0;
        size_t check = 0;
        uint64_t completed = 0;
        const auto end = checks.back().offset;
        const auto verify = [&]() {
            while (check < checks.size() && checks[check].offset == completed) {
                if (checks[check++].crc != crc) return false;
            }
            return true;
        };
        if (!verify()) return std::unexpected(std::errc::bad_message);
        if (progress) progress({PreparePhase::Checksum, 0, end});
        for (const auto& extent : p->extents) {
            if (completed == end) break;
            if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
            if (extent.type == CHUNK_TYPE_RAW) {
                for (uint64_t offset = 0; offset < extent.length;) {
                    if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
                    auto bytes = std::span(buffer).first(static_cast<size_t>(std::min<uint64_t>(buffer.size(), extent.length - offset)));
                    if (auto r = read(extent.source + offset, bytes, stop); !r) return std::unexpected(r.error());
                    crc = crc32_update(crc, bytes);
                    offset += bytes.size(); completed += bytes.size();
                    if (progress) progress({PreparePhase::Checksum, completed, end});
                }
            } else {
                crc = append_pattern(crc, extent.pattern, extent.length);
                completed += extent.length;
                if (progress) progress({PreparePhase::Checksum, completed, end});
            }
            if (!verify()) return std::unexpected(std::errc::bad_message);
        }
        if (check != checks.size()) return std::unexpected(std::errc::bad_message);
    }
    return result;
}
} // namespace uniflash::io

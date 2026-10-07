/*
 * UniFlash-Core / Interactive Line Editor
 *
 * Terminal raw mode, escape handling, completion and history persistence.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/cli/line_editor.h>
#include <uniflash/log.h>
#include <uniflash/cli/signal.h>
#include <uniflash/platform.h>
#include <uniflash/text.h>
#include <uniflash/io/output.h>
#include "windows_console.h"
#include "input.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fstream>
#include <atomic>
#include <system_error>
#include <thread>
#ifdef _WIN32
#include <windows.h>
#include <deque>
#else
#include <termios.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif
#include <iostream>

namespace uniflash::cli {

struct CommandInputEcho::Impl {
#ifdef _WIN32
    DWORD saved{};
    bool active = false;
    Impl() {
        const auto input = GetStdHandle(STD_INPUT_HANDLE);
        active = GetConsoleMode(input, &saved) &&
            SetConsoleMode(input, saved & ~ENABLE_ECHO_INPUT);
    }
    ~Impl() { if (active) SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), saved); }
#else
    tcflag_t echo{};
    bool active = false;
    Impl() {
        termios current{};
        if (tcgetattr(STDIN_FILENO, &current) != 0) return;
        echo = current.c_lflag & (ECHO | ECHONL);
        current.c_lflag &= ~(ECHO | ECHONL);
        active = tcsetattr(STDIN_FILENO, TCSANOW, &current) == 0;
    }
    ~Impl() {
        termios current{};
        if (active && tcgetattr(STDIN_FILENO, &current) == 0) {
            current.c_lflag = (current.c_lflag & ~(ECHO | ECHONL)) | echo;
            tcsetattr(STDIN_FILENO, TCSANOW, &current);
        }
    }
#endif
};
CommandInputEcho::CommandInputEcho(bool enabled) {
    if (enabled && platform::is_terminal(0)) impl_ = std::make_unique<Impl>();
}
CommandInputEcho::~CommandInputEcho() = default;

namespace {

using detail::InputStatus;

#ifdef _WIN32
struct RawMode {
    DWORD saved{};
    bool active = false;
    ~RawMode() { if(active) SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), saved); }
};
bool enable_raw(RawMode& rm) {
    const auto input=GetStdHandle(STD_INPUT_HANDLE);
    if(!platform::supports_ansi(1) || !GetConsoleMode(input,&rm.saved)) return false;
    if(!SetConsoleMode(input,(shell_input_mode(rm.saved) & ~(ENABLE_ECHO_INPUT|ENABLE_LINE_INPUT|
         ENABLE_PROCESSED_INPUT|ENABLE_QUICK_EDIT_MODE)) | ENABLE_EXTENDED_FLAGS)) return false;
    rm.active=true; return true;
}
InputStatus read_byte(char& out, int timeout_ms = -1) {
    static std::deque<char> pending;
    static wchar_t high=0;
    if (global_interrupted()) { pending.clear(); high = 0; return InputStatus::Interrupted; }
    while(pending.empty()) {
        if (global_interrupted()) { high = 0; return InputStatus::Interrupted; }
        const DWORD wait = WaitForSingleObject(GetStdHandle(STD_INPUT_HANDLE),
                                               timeout_ms < 0 ? 50 : timeout_ms);
        if (wait == WAIT_TIMEOUT) {
            if (timeout_ms >= 0) return InputStatus::Timeout;
            continue;
        }
        if (wait != WAIT_OBJECT_0)
            throw std::system_error(wait == WAIT_FAILED ? GetLastError() : ERROR_GEN_FAILURE,
                                    std::system_category(), "stdin console wait failed");
        INPUT_RECORD input{}; DWORD count=0;
        const bool ok = ReadConsoleInputW(GetStdHandle(STD_INPUT_HANDLE), &input, 1, &count) != 0;
        const auto status = detail::windows_read_status(ok, count, ok ? 0 : GetLastError(), global_interrupted());
        if (status != InputStatus::Byte) return status;
        if(input.EventType!=KEY_EVENT || !input.Event.KeyEvent.bKeyDown) continue;
        const auto& key=input.Event.KeyEvent;
        std::string bytes;
        switch(key.wVirtualKeyCode) {
        case VK_UP: bytes="\033[A"; break;
        case VK_DOWN: bytes="\033[B"; break;
        case VK_LEFT: bytes="\033[D"; break;
        case VK_RIGHT: bytes="\033[C"; break;
        case VK_HOME: bytes="\033[H"; break;
        case VK_END: bytes="\033[F"; break;
        case VK_DELETE: bytes="\033[3~"; break;
        case VK_ESCAPE: continue; // no incomplete escape sequence in editor
        default: {
            wchar_t c=key.uChar.UnicodeChar;
            if(c==0) continue;
            if(c>=0xd800 && c<=0xdbff) { high=c; continue; }
            if(c>=0xdc00 && c<=0xdfff) {
                if(!high) continue;
                wchar_t pair[]{high,c}; high=0; bytes=platform::utf8(std::wstring_view(pair,2));
            } else { high=0; bytes=platform::utf8(std::wstring_view(&c,1)); }
            break;
        }
        }
        for(WORD i=0;i<std::max<WORD>(1,key.wRepeatCount);++i)
            pending.insert(pending.end(),bytes.begin(),bytes.end());
    }
    out=pending.front(); pending.pop_front(); return InputStatus::Byte;
}
#else
struct RawMode {
    termios saved;
    bool active = false;
    ~RawMode() {
        if (active) tcsetattr(STDIN_FILENO, TCSANOW, &saved);
    }
};

bool enable_raw(RawMode& rm) {
    if (!platform::supports_ansi(1)) return false;
    if (tcgetattr(STDIN_FILENO, &rm.saved) != 0) return false;
    termios raw = rm.saved;
    raw.c_lflag &= ~(ECHO | ICANON);
    raw.c_iflag &= ~(IXON);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0) return false;
    rm.active = true;
    return true;
}
InputStatus read_byte(char& out, int timeout_ms = -1) {
    for (;;) {
        if (global_interrupted()) return InputStatus::Interrupted;
        pollfd input{STDIN_FILENO, POLLIN, 0};
        const int ready = poll(&input, 1, timeout_ms < 0 ? 50 : timeout_ms);
        if (ready < 0) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::generic_category(), "stdin poll failed");
        }
        if (global_interrupted()) return InputStatus::Interrupted;
        if (ready == 0) {
            if (timeout_ms >= 0) return InputStatus::Timeout;
            continue;
        }
        if (input.revents & POLLNVAL)
            throw std::system_error(EBADF, std::generic_category(), "stdin poll failed");
        const auto count = ::read(STDIN_FILENO, &out, 1);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0)
            throw std::system_error(errno, std::generic_category(), "stdin read failed");
        if (global_interrupted()) return InputStatus::Interrupted;
        if (count == 0 && (input.revents & POLLERR))
            throw std::system_error(EIO, std::generic_category(), "stdin poll reported an I/O error");
        return count ? InputStatus::Byte : InputStatus::Eof;
    }
}
#endif

size_t terminal_columns() {
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO info{};
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info))
        return std::max<size_t>(2, info.srWindow.Right - info.srWindow.Left + 1);
#else
    winsize size{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0 && size.ws_col)
        return std::max<size_t>(2, size.ws_col);
#endif
    return 80;
}

}  // namespace

// --- command-line tokenizing ----------------------------------------------


// --- UTF-8 helpers ---------------------------------------------------------

namespace {

bool is_continuation(char c) {
    return (static_cast<unsigned char>(c) & 0xC0) == 0x80;
}

// Length of the codepoint starting at pos (1 for stray continuation bytes).
size_t cp_len(const std::string& s, size_t pos) {
    if (pos >= s.size()) return 0;
    unsigned char b = static_cast<unsigned char>(s[pos]);
    if (b < 0x80 || is_continuation(b)) return 1;
    if ((b & 0xE0) == 0xC0) return 2;
    if ((b & 0xF0) == 0xE0) return 3;
    if ((b & 0xF8) == 0xF0) return 4;
    return 1;
}

}  // namespace

size_t utf8_prev_cp(const std::string& s, size_t pos) {
    if (pos == 0 || pos > s.size()) return 0;
    size_t p = pos - 1;
    // Walk back over continuation bytes (cap: a valid sequence is <= 4).
    for (size_t back = 0; back < 3 && p > 0 && is_continuation(s[p]);
         --p, ++back) {}
    return p;
}

size_t utf8_next_cp(const std::string& s, size_t pos) {
    if (pos >= s.size()) return s.size();
    size_t n = cp_len(s, pos);
    return std::min(pos + n, s.size());
}

int utf8_cp_width(const std::string& s, size_t pos) {
    if (pos >= s.size()) return 0;
    const auto cp = text::decode(s, pos);
    return cp.valid ? static_cast<int>(text::scalar_width(cp.value)) : 1;
}

size_t utf8_width(const std::string& s, size_t from, size_t to) {
    if (to > s.size()) to = s.size();
    size_t cols = 0;
    size_t i = from;
    while (i < to) {
        cols += static_cast<size_t>(utf8_cp_width(s, i));
        i = utf8_next_cp(s, i);
    }
    return cols;
}

// ---------------------------------------------------------------------------

LineEditor::Result LineEditor::read(const std::string& prompt,
                                      std::string& out,
                                      const Completer& completer) {
    out.clear();
    struct InputScope {
        InputScope() { set_input_active(true); }
        ~InputScope() { set_input_active(false); }
    } input_scope;
    const auto interrupted = [&]() {
        out.clear();
        return termination_requested() || force_exit_requested() ? Result::Eof : Result::Interrupted;
    };
    if (global_interrupted()) return interrupted();
    RawMode rm;
    if (!platform::is_terminal(0) || !enable_raw(rm)) {
        // Preserve canonical echo when output is redirected. POSIX reads are
        // polled so termination also wakes an idle pipe or canonical console.
        if (platform::is_terminal(0)) log_console(prompt);
        std::string line;
#ifdef _WIN32
        // Synchronous stdin handles (console, pipe, file) cannot use the COM
        // overlapped path. Isolate the read and cancel it from the owning thread.
        std::atomic<bool> done{false};
        std::atomic<HANDLE> read_thread{nullptr};
        InputStatus status = InputStatus::Eof;
        std::exception_ptr failure;
        std::thread reader([&] {
            try {
                HANDLE thread = nullptr;
                if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(),
                    &thread, THREAD_TERMINATE, FALSE, 0))
                    throw std::system_error(GetLastError(), std::system_category(), "stdin reader setup failed");
                read_thread.store(thread, std::memory_order_release);
                const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
                DWORD mode = 0;
                const bool console = GetConsoleMode(input, &mode) != 0;
                const auto read_one = [&](auto& c) {
                    if (global_interrupted()) return InputStatus::Interrupted;
                    DWORD count = 0;
                    const BOOL ok = console ? ReadConsoleW(input, &c, 1, &count, nullptr)
                                            : ReadFile(input, &c, 1, &count, nullptr);
                    return detail::windows_read_status(ok != 0, count, ok ? 0 : GetLastError(), global_interrupted());
                };
                if (console) {
                    std::wstring wide_line;
                    status = detail::read_line(wide_line, read_one);
                    line = platform::utf8(wide_line);
                } else status = detail::read_line(line, read_one);
            } catch (...) { failure = std::current_exception(); }
            done.store(true, std::memory_order_release);
        });
        while (!done.load(std::memory_order_acquire)) {
            if (global_interrupted()) {
                if (const auto thread = read_thread.load(std::memory_order_acquire)) CancelSynchronousIo(thread);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        reader.join();
        if (const auto thread = read_thread.load()) CloseHandle(thread);
        if (global_interrupted()) return interrupted();
        if (failure) std::rethrow_exception(failure);
        if (status == InputStatus::Interrupted) return interrupted();
        if (status == InputStatus::Eof) return Result::Eof;
#else
        const auto status = detail::read_line(line, [](char& c) { return read_byte(c); });
        if (status == InputStatus::Interrupted) return interrupted();
        if (status == InputStatus::Eof) return Result::Eof;
#endif
        if (global_interrupted()) return interrupted();
        if (!line.empty() && line.back() == '\r') line.pop_back();
        out = std::move(line);
        return Result::Ok;
    }

    std::string buf;
    size_t pos = 0;
    size_t hist_idx = history_.size();
    std::string saved_current;

    auto refresh = [&]() {
        // Keep one physical line, including a spare column to avoid the
        // terminal's pending-wrap state. Scroll by complete UTF-8 codepoints.
        const size_t available = terminal_columns() - 1;
        size_t prompt_end = 0, prompt_cols = 0;
        while (prompt_end < prompt.size()) {
            const size_t width = utf8_cp_width(prompt, prompt_end);
            if (prompt_cols + width + 1 >= available) break;
            prompt_cols += width;
            prompt_end = utf8_next_cp(prompt, prompt_end);
        }
        const size_t capacity = available - prompt_cols;
        size_t start = pos, left_cols = 0;
        while (start > 0) {
            const size_t previous = utf8_prev_cp(buf, start);
            const size_t width = utf8_cp_width(buf, previous);
            if (left_cols + width >= capacity) break;
            left_cols += width;
            start = previous;
        }
        size_t end = pos, cols = 0;
        while (end < buf.size()) {
            const size_t width = utf8_cp_width(buf, end);
            if (left_cols + cols + width > capacity) break;
            cols += width;
            end = utf8_next_cp(buf, end);
        }
        std::string display = "\r\033[K" + prompt.substr(0, prompt_end) + buf.substr(start, end - start);
        if (cols > 0) display += "\033[" + std::to_string(cols) + "D";
        log_console(display);
    };
    refresh();

    for (;;) {
        char c;
        const auto status = read_byte(c);
        if (status == InputStatus::Interrupted) {
            log_console("\r\033[K");
            return interrupted();
        }
        if (status == InputStatus::Eof) return Result::Eof;
        if (status == InputStatus::Timeout) continue;

        if (c == '\r' || c == '\n') {
            if (global_interrupted()) return interrupted();
            log_console("\n");
            out = buf;
            if (!buf.empty()) add_history(buf);
            return Result::Ok;
        }
        if (c == 3) {  // Ctrl+C
            interrupt_from_console();
            // Raw-console Ctrl+C uses the same exit latch as OS signals.
            log_console("\r\033[K");
            return interrupted();
        }
        if (c == 4) {  // Ctrl+D on empty line
            if (buf.empty()) {
                log_console("\n");
                return Result::Eof;
            }
            continue;
        }
        if (c == '\t') {
            if (completer) {
                auto cands = completer(buf, pos);
                if (cands.size() == 1) {
                    buf = cands[0];
                    pos = buf.size();
                } else if (cands.size() > 1) {
                    std::string add = cands[0];
                    for (auto& s : cands) {
                        size_t n = 0;
                        while (n < add.size() && n < s.size() &&
                               add[n] == s[n]) ++n;
                        add.resize(n);
                    }
                    if (add.size() > buf.size())
                        add = add.substr(buf.size());
                    else
                        add.clear();
                    if (!add.empty()) {
                        buf.insert(pos, add);
                        pos += add.size();
                    } else {
                        std::string choices = "\n";
                        for (auto& s : cands) {
                            if (choices.size() > 1) choices += ", ";
                            choices += s;
                        }
                        log_console(choices + "\n");
                    }
                }
                refresh();
            }
            continue;
        }
        if (c == 21) {  // Ctrl+U — kill line
            buf.clear();
            pos = 0;
            refresh();
            continue;
        }
        if (c == 23) {  // Ctrl+W — kill word (codepoints, space-separated)
            for (;;) {
                size_t p = utf8_prev_cp(buf, pos);
                if (p == pos || buf[p] != ' ') break;
                buf.erase(p, pos - p);
                pos = p;
            }
            for (;;) {
                size_t p = utf8_prev_cp(buf, pos);
                if (p == pos || buf[p] == ' ') break;
                buf.erase(p, pos - p);
                pos = p;
            }
            refresh();
            continue;
        }
        if (c == 127 || c == 8) {  // backspace — remove one codepoint
            size_t p = utf8_prev_cp(buf, pos);
            if (p < pos) {
                buf.erase(p, pos - p);
                pos = p;
            }
            refresh();
            continue;
        }
        if (c == 27) {  // escape sequence
            char seq[2];
            if (read_byte(seq[0], 50) != InputStatus::Byte) continue;
            if (seq[0] == '[' || seq[0] == 'O') {
                if (read_byte(seq[1], 50) != InputStatus::Byte) continue;
                switch (seq[1]) {
                    case 'A': {  // up — history prev
                        if (hist_idx > 0) {
                            if (hist_idx == history_.size())
                                saved_current = buf;
                            --hist_idx;
                            buf = history_[hist_idx];
                            pos = buf.size();
                        }
                        break;
                    }
                    case 'B': {  // down — history next
                        if (hist_idx < history_.size()) {
                            ++hist_idx;
                            buf = (hist_idx == history_.size())
                                      ? saved_current
                                      : history_[hist_idx];
                            pos = buf.size();
                        }
                        break;
                    }
                    case 'C':  // right — one codepoint
                        pos = utf8_next_cp(buf, pos);
                        break;
                    case 'D':  // left — one codepoint
                        pos = utf8_prev_cp(buf, pos);
                        break;
                    case 'H':  // home
                        pos = 0;
                        break;
                    case 'F':  // end
                        pos = buf.size();
                        break;
                    case '3': {  // delete — one codepoint
                        char z;
                        if (read_byte(z, 50) == InputStatus::Byte && z == '~') {
                            size_t n = utf8_next_cp(buf, pos);
                            if (n > pos) buf.erase(pos, n - pos);
                        }
                        break;
                    }
                    default:
                        break;
                }
            }
            refresh();
            continue;
        }
        if (c == 1) { pos = 0; refresh(); continue; }           // Ctrl+A
        if (c == 5) { pos = buf.size(); refresh(); continue; }  // Ctrl+E

        // Printable input: full UTF-8 byte stream (multibyte sequences
        // arrive byte by byte; navigation and rendering above treat them
        // as whole codepoints). Only C0 controls are filtered out here.
        if (static_cast<unsigned char>(c) >= 0x20 && c != 0x7f) {
            buf.insert(pos, 1, c);
            pos += 1;
            // Do not interleave ANSI redraws between the bytes of a UTF-8
            // codepoint (notably WriteFile-based Windows console output).
            const size_t beginning = utf8_prev_cp(buf, pos);
            if (pos - beginning >= cp_len(buf, beginning)) refresh();
        }
    }
}

namespace {

std::filesystem::path resolve_history_path(const std::string& path) {
    const auto absolute = std::filesystem::absolute(platform::path(path));
    // Resolve the existing parent through the filesystem: lexically folding
    // "link/.." could select a different directory. Parent aliases must also
    // share one stable lock path across atomic replacements of the leaf.
    // Keep the leaf itself, matching AtomicOutput's directory-entry replacement
    // semantics and allowing a missing history file on first use.
    return std::filesystem::canonical(absolute.parent_path()) / absolute.filename();
}

bool valid_history_line(const std::string& line) {
    if (line.empty() || line.size() > 4096) return false;
    for (size_t at = 0; at < line.size();) {
        const auto cp = text::decode(line, at);
        if (!cp.valid || cp.value < 32 || cp.value == 127) return false;
        at += cp.bytes;
    }
    return true;
}

void append_history(std::vector<std::string>& history, const std::string& line) {
    if (!history.empty() && history.back() == line) return;
    history.push_back(line);
    if (history.size() > 500) history.erase(history.begin());
}

// Lock a stable sidecar, not the history inode replaced by AtomicOutput.
// Leave the sidecar in place: unlinking it would split concurrent lock owners.
class HistoryLock {
public:
    explicit HistoryLock(std::filesystem::path path) {
        path += ".lock";
#ifdef _WIN32
        file_ = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file_ == INVALID_HANDLE_VALUE)
            throw std::system_error(GetLastError(), std::system_category(), "history lock open failed");
        OVERLAPPED offset{};
        if (!LockFileEx(file_, LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &offset)) {
            const auto error = GetLastError();
            CloseHandle(file_);
            throw std::system_error(error, std::system_category(), "history lock failed");
        }
#else
        file_ = ::open(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
        if (file_ < 0)
            throw std::system_error(errno, std::generic_category(), "history lock open failed");
        int result;
        do { result = flock(file_, LOCK_EX); } while (result < 0 && errno == EINTR);
        if (result < 0) {
            const auto error = errno;
            close(file_);
            throw std::system_error(error, std::generic_category(), "history lock failed");
        }
#endif
    }
    ~HistoryLock() {
#ifdef _WIN32
        OVERLAPPED offset{};
        UnlockFileEx(file_, 0, 1, 0, &offset);
        CloseHandle(file_);
#else
        flock(file_, LOCK_UN);
        close(file_);
#endif
    }
    HistoryLock(const HistoryLock&) = delete;
    HistoryLock& operator=(const HistoryLock&) = delete;
private:
#ifdef _WIN32
    HANDLE file_ = INVALID_HANDLE_VALUE;
#else
    int file_ = -1;
#endif
};

bool read_history(const std::filesystem::path& path, std::vector<std::string>& history) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        // A first-run missing file is an empty history; unreadable files and
        // dangling symlinks are failures, never permission to replace them.
        std::error_code error;
        const auto status = std::filesystem::symlink_status(path, error);
        return status.type() == std::filesystem::file_type::not_found &&
            (!error || error == std::errc::no_such_file_or_directory);
    }
    // Read at most the last 2 MiB; discard a partial first line. Bound each
    // record before allocating it, and keep only the last 500 valid commands.
    constexpr std::streamoff max_bytes=2*1024*1024;
    constexpr size_t max_line=4096;
    f.seekg(0,std::ios::end);const auto end=f.tellg();if(end<0)return false;
    const auto start=end>max_bytes?end-max_bytes:std::streampos(0);
    f.seekg(start);if(!f)return false;
    bool discard=start!=std::streampos(0);
    std::string line;char c;
    const auto accept=[&] {
        if(!line.empty() && line.back()=='\r')line.pop_back();
        if(!discard && valid_history_line(line))append_history(history,line);
        line.clear();discard=false;
    };
    while(f.get(c)) {
        if(c=='\n'){accept();continue;}
        if(!discard) {if(line.size()==max_line){line.clear();discard=true;}else line+=c;}
    }
    if(f.bad() || !f.eof())return false;
    accept();
    return true;
}

} // namespace

void LineEditor::add_history(const std::string& line) {
    if (!valid_history_line(line) || (!history_.empty() && history_.back() == line)) return;
    append_history(pending_history_, line);
    append_history(history_, line);
}

bool LineEditor::load_history(const std::string& path) try {
    history_loaded_ = false;
    if (path.empty()) return false;
    const auto resolved = resolve_history_path(path);
    std::vector<std::string> loaded;
    if (!read_history(resolved, loaded)) return false;
    history_path_ = resolved;
    history_ = std::move(loaded);
    pending_history_.clear();
    history_loaded_ = true;
    return true;
} catch (...) { return false; }

bool LineEditor::save_history(const std::string& path) try {
    if (!history_loaded_ || path.empty() ||
        resolve_history_path(path) != history_path_) return false;
    if (!history_dirty()) return true;
    HistoryLock lock(history_path_);
    std::vector<std::string> merged;
    if (!read_history(history_path_, merged)) return false;
    for (const auto& line : pending_history_) append_history(merged, line);
    auto file=io::AtomicOutput::open(history_path_);if(!file)return false;
    for (const auto& line : merged) {
        const auto record=line+"\n";
        if(!file->write(std::span(reinterpret_cast<const uint8_t*>(record.data()),record.size())))return false;
    }
    const auto committed = file->commit_result();
    // A directory-sync failure after replacement must not replay additions on
    // retry. Report the durability failure, but remember what is now on disk.
    if (committed || file->commit_state() != io::CommitState::NotCommitted) {
        history_ = std::move(merged);
        pending_history_.clear();
    }
    return bool(committed);
} catch(...) {return false;}

}

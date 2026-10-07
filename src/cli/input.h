#pragma once

#include <string>
#include <system_error>
#include <utility>
#ifdef _WIN32
#include <windows.h>
#endif

namespace uniflash::cli::detail {

// I/O errors are exceptions, never EOF or an escape-sequence timeout.
enum class InputStatus { Byte, Eof, Interrupted, Timeout };

#ifdef _WIN32
inline InputStatus windows_read_status(bool ok, unsigned long count,
                                       unsigned long error, bool interrupted) {
    if (interrupted) return InputStatus::Interrupted;
    if (!ok) {
        // Synchronous files and byte-mode pipes use different EOF indications.
        if (error == ERROR_BROKEN_PIPE || error == ERROR_HANDLE_EOF)
            return InputStatus::Eof;
        throw std::system_error(static_cast<int>(error), std::system_category(), "stdin read failed");
    }
    return count ? InputStatus::Byte : InputStatus::Eof;
}
#endif

// Publish a line only after newline or genuine EOF. In particular, a reader
// exception cannot leave a dispatchable prefix in the caller's output.
template<class Char, class Reader>
InputStatus read_line(std::basic_string<Char>& out, Reader&& reader) {
    out.clear();
    std::basic_string<Char> line;
    for (;;) {
        Char c{};
        const auto status = reader(c);
        if (status == InputStatus::Interrupted) return status;
        if (status == InputStatus::Timeout) continue;
        if (status == InputStatus::Eof && line.empty()) return status;
        if (status == InputStatus::Eof || c == Char('\n')) {
            out = std::move(line);
            return InputStatus::Byte;
        }
        line += c;
    }
}

}

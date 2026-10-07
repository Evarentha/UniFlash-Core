#ifndef UNIFLASH_CLI_LINE_EDITOR_H
#define UNIFLASH_CLI_LINE_EDITOR_H
#include <uniflash/cli/arguments.h>

#include <functional>
#include <filesystem>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace uniflash::cli {

// Suppress terminal-driver echo while commands render output. Preserve queued
// input and signal handling; restore terminal flags on every exit path.
class CommandInputEcho {
public:
    explicit CommandInputEcho(bool enabled);
    ~CommandInputEcho();
    CommandInputEcho(const CommandInputEcho&) = delete;
    CommandInputEcho& operator=(const CommandInputEcho&) = delete;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// --- command-line tokenizing -----------------------------------------------

// Read the next whitespace-delimited token from a command line. A token
// wrapped in '...' or "..." may contain spaces; the quotes are stripped.
// Returns false at end of input. Unterminated quotes are rejected.

// --- UTF-8 helpers (byte buffer, codepoint navigation, display width) ---

// Start byte of the codepoint BEFORE pos (pos itself is a start byte or
// end). Returns 0 when there is none. Stray continuation bytes count as
// their own one-byte units.
size_t utf8_prev_cp(const std::string& s, size_t pos);

// Start byte of the codepoint AFTER the one at pos (pos is a start byte).
// Returns s.size() at the end, or pos+1 for stray bytes.
size_t utf8_next_cp(const std::string& s, size_t pos);

// Terminal columns occupied by the codepoint starting at pos: 2 for common
// East Asian/emoji ranges, 0 for common combining marks/selectors, else 1.
int utf8_cp_width(const std::string& s, size_t pos);

// Sum of display columns for the byte range [from, to).
size_t utf8_width(const std::string& s, size_t from, size_t to);

// Minimal readline-style editor: history, arrows, Home/End, Delete,
// Ctrl+A/E/U, Tab completion, Ctrl+C abort. Uses termios on Linux and
// native console input events on Windows; no external line-editing library.
// UTF-8 aware: navigation moves whole codepoints, the cursor is positioned
// by display width (CJK counts two columns). Long input scrolls horizontally.
class LineEditor {
public:
    enum class Result { Ok, Eof, Interrupted };

    // Return candidate strings for the current input. Called on Tab.
    using Completer = std::function<std::vector<std::string>(
        const std::string& line, size_t cursor)>;

    // Clears out before reading and on interruption. SIGTERM returns Eof;
    // consult termination_requested() to distinguish it from normal EOF.
    // I/O failures throw std::system_error with out empty (no partial command).
    // Redirected stdout retains canonical input and receives no ANSI redraws.
    Result read(const std::string& prompt, std::string& out,
                const Completer& completer = {});

    void add_history(const std::string& line);
    const std::vector<std::string>& history() const { return history_; }

    bool load_history(const std::string& path);
    // Save only additions since the successful load/save, merging under a
    // cross-process lock. A failed load disables saving until a successful load.
    bool save_history(const std::string& path);
    bool history_dirty() const { return !pending_history_.empty(); }

private:
    std::vector<std::string> history_;
    std::vector<std::string> pending_history_;
    std::filesystem::path history_path_;
    bool history_loaded_ = false;
};

}

#endif

/*
 * UniFlash-Core / Diagnostic Output
 *
 * Single output authority for progress, informational, warning and error records.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef UNIFLASH_LOG_H
#define UNIFLASH_LOG_H

#include <functional>
#include <string>
#include <string_view>
#include <cstdint>
#include <span>
#include <vector>
#include <thread>

namespace uniflash {

// The single output authority for the whole tool.
//
// Style:  [*] info   -> stdout
//         [~] warn   -> stderr
//         [!] error  -> stderr
//         {module} diag -> stderr (module tags: {bsl}, {read}, {write},
//                          {rt}, {poll}, {da}, {usb})
//
// Brackets: [level] for user-facing messages, {module} for diagnostics.
//
// Timestamps: When UNIFLASH_TRACE=1, all messages prefixed with
//             [HH:MM:SS.mmm].
//
// Documents, prompts and terminal editing are emitted via log_document /
// log_console; progress uses the same lock and clearing lifecycle as messages.
//
// Library layers (device/transport/session) must route ALL user-visible
// output through here: a non-console client (uniflash-client)
// installs its own sink instead of the default console printer.

enum class LogLevel { Info, Warn, Error, Diag };

using LogSink = std::function<void(LogLevel, const std::string&)>;

// Install a client sink; nullptr restores the default console printer.
// Callbacks run outside the console lock and may replace the sink/reenter the
// logger. Concurrent callers may invoke the sink concurrently; the client owns
// synchronization of its callback state. An in-flight call retains its sink.
// Callback exceptions are isolated: logging must never unwind device I/O.
void set_log_sink(LogSink sink);

// Verbose telemetry ({rt} trip timings, {usb} open trace, TX/RX hex
// dumps) prints only when enabled. Default: the UNIFLASH_TRACE
// environment variable equals "1". Load-bearing failure context
// ({read}/{write}/{bsl}) is always-on diag and is NOT gated by this flag.
bool log_diag_trace_enabled();
// Summary-only performance diagnostics; no per-packet dumps.
bool log_performance_enabled();
void set_log_diag_trace(bool on);

// Progress-line coordination for transient status. Transfer callers clear on
// completion/failure; the command layer records success after final ACK/commit.
// The bar is UI chrome (not a log level): it is rendered only when
// stderr is a TTY (no ANSI/\r into pipes or logs) and is NOT delivered
// to a custom LogSink. Log lines emitted while a progress line is
// active clear it first and let the next render redraw it.
using ProgressOwner = std::thread::id;
void log_progress(const std::string& line, ProgressOwner owner = std::this_thread::get_id());
void log_finish_progress_line(ProgressOwner owner = std::this_thread::get_id());
void log_clear_progress_line(ProgressOwner owner = std::this_thread::get_id());
// Console documents/prompts share output serialization and progress clearing.
// Custom sinks receive documents as Info; raw terminal control stays console-only.
void log_document(std::string_view text);
void log_console(std::string_view text);

// Shared presentation rules: binary capacity units, seconds, and end-to-end
// throughput. Callers supply data, never prefixes or terminal controls.
std::string format_size(uint64_t bytes);
std::string format_duration(double seconds);
std::string format_transfer(uint64_t bytes, double seconds);
void log_status(LogLevel level, std::string_view action, std::string_view target,
                std::string_view detail = {});
void log_field(std::string_view name, std::string_view value);
enum class LogAlignment { Left, Right };
struct LogColumn {
    std::string heading;
    LogAlignment alignment = LogAlignment::Left;
};
using LogRow = std::vector<std::string>;
struct LogTableSection {
    std::string heading;
    std::vector<LogRow> rows;
};
// All sections share measured column widths. Cells are plain text, with control
// bytes escaped before measuring; rows must match the column count.
// Console emission is atomic across all rows; custom sinks get one multiline
// Info record from one retained sink snapshot (as for log_document).
void log_table(std::span<const LogColumn> columns, std::span<const LogTableSection> sections);
struct LogHelpEntry { std::string usage, description; };
struct LogHelpSection { std::string heading; std::vector<LogHelpEntry> entries; };
// Document-style command reference, including wrapping and continuation indent.
void log_help(std::span<const LogHelpSection> sections, std::string_view footer = {});
enum class ProgressUnit { Bytes, Items };
void log_transfer_progress(std::string_view label, uint64_t done, uint64_t total,
                           double seconds, ProgressUnit unit = ProgressUnit::Bytes);
void log_wait_progress(std::string_view label, double seconds, ProgressOwner owner = std::this_thread::get_id());

void log(LogLevel level, const std::string& msg);

inline void log_info(const std::string& msg) { log(LogLevel::Info, msg); }
inline void log_warn(const std::string& msg) { log(LogLevel::Warn, msg); }
inline void log_err(const std::string& msg)  { log(LogLevel::Error, msg); }
// The diagnostic tag is embedded in the message. Console records escape control
// bytes; custom sinks receive the original record without presentation prefixes.
inline void log_diag(const std::string& msg) { log(LogLevel::Diag, msg); }

}  // namespace uniflash

#endif  // UNIFLASH_LOG_H

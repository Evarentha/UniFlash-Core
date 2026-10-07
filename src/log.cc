/*
 * UniFlash-Core / Diagnostic Output
 *
 * Severity formatting, progress lines and diagnostic trace output.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/log.h>
#include <uniflash/platform.h>
#include <uniflash/text.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <mutex>
#include <memory>
#include <utility>
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <locale>
#include <sstream>
#include <limits>
#include <stdexcept>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/ioctl.h>
#include <unistd.h>
#endif

namespace uniflash {
namespace {

std::mutex g_log_mutex;
std::shared_ptr<const LogSink> g_sink;  // null = default console printer
// -1 = not initialized; a setter wins over concurrent lazy initialization.
std::atomic<int> g_trace{-1};
bool g_progress_active = false; // guarded by g_log_mutex
ProgressOwner g_progress_owner;

size_t progress_columns() {
    size_t columns = 80;
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO screen{};
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_ERROR_HANDLE), &screen))
        columns = static_cast<size_t>(screen.srWindow.Right - screen.srWindow.Left + 1);
#else
    winsize screen{};
    if (ioctl(STDERR_FILENO, TIOCGWINSZ, &screen) == 0 && screen.ws_col) columns = screen.ws_col;
#endif
    return std::max<size_t>(columns, 2);
}

std::string progress_text(std::string_view text, size_t columns = progress_columns()) {
    // Legacy callers may begin a progress string with CR. The logger owns it.
    if (text.starts_with('\r')) text.remove_prefix(1);
    auto out = uniflash::text::clip(uniflash::text::record(text), columns ? columns - 1 : 0);
    return out;
}

// Use the same UTF-8 column rules for fields, tables, help and progress.
size_t text_width(std::string_view text) {
    return uniflash::text::width(text);
}

std::string record_text(std::string_view message) {
    return text::record(message);
}

// Clear current line (for progress bar / diag output interleaving).
void clear_progress_line() {
    if (g_progress_active && platform::supports_ansi(2)) {
        std::fprintf(stderr, "\r\033[K");
        std::fflush(stderr);
    }
    g_progress_active = false;
}

// Format timestamp [HH:MM:SS.mmm] when UNIFLASH_TRACE=1.
std::string timestamp_prefix() {
    if (!log_diag_trace_enabled()) return "";
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char buf[32];
    std::snprintf(buf, sizeof buf, "[%02d:%02d:%02d.%03d] ",
                  tm.tm_hour, tm.tm_min, tm.tm_sec, (int)ms.count());
    return buf;
}

void console_sink(LogLevel level, const std::string& msg) {
    // Flush per line: stdout is block-buffered when piped, and the
    // warn/error/diag lines land on stderr — unflushed interleaving
    // would scramble the ordering in logs.
    const std::string ts = timestamp_prefix();
    FILE* output = level == LogLevel::Info ? stdout : stderr;
    const char* prefix = level == LogLevel::Info ? "[*] " : level == LogLevel::Warn ? "[~] " :
                         level == LogLevel::Error ? "[!] " : "";
    clear_progress_line();
    // Every record occupies one line, even when device text or a filename
    // contains newlines/control bytes. Only log_console emits terminal controls.
    const auto text = record_text(msg);
    std::fprintf(output, "%s%s%s\n", ts.c_str(), prefix, text.c_str());
    std::fflush(output);
}

}  // namespace

namespace {
std::string decimal(double value, int precision = 1) {
    std::ostringstream out;
    out.imbue(std::locale::classic());
    out << std::fixed << std::setprecision(precision) << value;
    return out.str();
}
}

std::string format_size(uint64_t bytes) {
    if (bytes < 1024) return std::to_string(bytes) + " B";
    constexpr const char* units[]{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"};
    double value = static_cast<double>(bytes) / 1024;
    size_t unit = 0;
    while (value >= 1024 && unit < 5) { value /= 1024; ++unit; }
    return decimal(value, 2) + " " + units[unit];
}

std::string format_duration(double seconds) {
    const double elapsed = std::isfinite(seconds) ? std::max(0.0, seconds) : 0.0;
    return elapsed >= 60.0 ? decimal(elapsed / 60.0, 2) + " min" : decimal(elapsed) + " s";
}

std::string format_transfer(uint64_t bytes, double seconds) {
    const double rate = std::isfinite(seconds) && seconds > 0 ? bytes / 1048576.0 / seconds : 0;
    return format_size(bytes) + " in " + format_duration(seconds) + " (" + decimal(rate, 2) + " MiB/s)";
}

void log_status(LogLevel level, std::string_view action, std::string_view target,
                std::string_view detail) {
    std::string text(action);
    if (!target.empty()) text += ": " + std::string(target);
    if (!detail.empty()) text += (target.empty() ? ": " : ", ") + std::string(detail);
    log(level, text);
}

void log_field(std::string_view name, std::string_view value) {
    const auto label = record_text(name);
    const auto width = text_width(label);
    log_info(label + std::string(width < 12 ? 12 - width : 1, ' ') + ": " + std::string(value));
}

void log_table(std::span<const LogColumn> columns, std::span<const LogTableSection> sections) {
    if (columns.empty()) return;
    std::vector<size_t> widths(columns.size());
    LogRow headings;
    for (size_t i = 0; i < columns.size(); ++i) {
        headings.push_back(record_text(columns[i].heading));
        widths[i] = text_width(headings.back());
    }
    // Prepare before emitting anything, including validating the whole table.
    auto prepared = std::vector<LogTableSection>(sections.begin(), sections.end());
    for (auto& section : prepared) {
        for (auto& row : section.rows) {
            if (row.size() != columns.size()) throw std::invalid_argument("log table column count mismatch");
            for (size_t i = 0; i < row.size(); ++i) {
                row[i] = record_text(row[i]);
                widths[i] = std::max(widths[i], text_width(row[i]));
            }
        }
    }
    std::vector<std::string> lines;
    const auto render = [&](const LogRow& row) {
        std::string line;
        for (size_t i = 0; i < row.size(); ++i) {
            if (i) line += "  ";
            const auto padding = widths[i] - text_width(row[i]);
            if (columns[i].alignment == LogAlignment::Right) line.append(padding, ' ');
            line += row[i];
            if (columns[i].alignment == LogAlignment::Left && i + 1 < row.size()) line.append(padding, ' ');
        }
        lines.push_back(std::move(line));
    };
    for (const auto& section : prepared) {
        if (!section.heading.empty()) lines.push_back(section.heading);
        render(headings);
        for (const auto& row : section.rows) render(row);
    }
    std::shared_ptr<const LogSink> sink;
    {
        std::lock_guard lock(g_log_mutex);
        sink = g_sink;
        if (!sink) {
            for (const auto& line : lines) console_sink(LogLevel::Info, line);
            return;
        }
    }
    std::string block;
    for (const auto& line : lines) { block += line; block += '\n'; }
    try { (*sink)(LogLevel::Info, block); } catch (...) {}
}

void log_help(std::span<const LogHelpSection> sections, std::string_view footer) {
    size_t description_column = 0;
    for (const auto& section : sections)
        for (const auto& entry : section.entries)
            description_column = std::max(description_column, text_width(record_text(entry.usage)) + 4);
    const size_t line_width = std::max<size_t>(40, progress_columns());
    description_column = std::min(description_column, std::min<size_t>(38, line_width / 2));
    std::ostringstream output;
    bool first = true;
    for (const auto& section : sections) {
        if (!first) output << '\n';
        first = false;
        output << record_text(section.heading) << '\n';
        for (const auto& entry : section.entries) {
            const auto usage = record_text(entry.usage);
            output << "  " << usage;
            if (text_width(usage) + 4 > description_column)
                output << '\n' << std::string(description_column, ' ');
            else
                output << std::string(description_column - text_width(usage) - 2, ' ');
            size_t column = description_column;
            std::istringstream words(record_text(entry.description));
            for (std::string word; words >> word;) {
                const auto width = text_width(word);
                if (column > description_column) {
                    if (column + 1 + width > line_width) {
                        output << '\n' << std::string(description_column, ' ');
                        column = description_column;
                    } else { output << ' '; ++column; }
                }
                output << word;
                column += width;
            }
            output << '\n';
        }
    }
    if (!footer.empty()) output << '\n' << record_text(footer) << '\n';
    log_document(output.str());
}

void log_wait_progress(std::string_view label, double seconds, ProgressOwner owner) {
    log_progress(std::string(label) + " (" + format_duration(seconds) + ")", owner);
}

void log_transfer_progress(std::string_view label, uint64_t done, uint64_t total,
                           double seconds, ProgressUnit unit) {
    if (!total) { log_wait_progress(label, seconds); return; }
    const double fraction = static_cast<double>(std::min(done, total)) / total;
    // Budget the actual rendered columns, including the logger's prefix and
    // a spare column. Preserve a useful bar before adding optional telemetry.
    const size_t columns = progress_columns();
    const size_t available = columns > 5 ? columns - 5 : 0;
    const auto percent = decimal(fraction * 100) + "%";
    const auto clean_label = record_text(label);
    const size_t preferred_bar = available >= 65 ? 24 : available >= 45 ? 16 : 8;
    const size_t reserved = preferred_bar + percent.size() + 4;
    const size_t label_budget = available > reserved ? available - reserved : 0;
    std::string heading = text::clip(clean_label, label_budget);
    if (heading.size() < clean_label.size() && label_budget >= 3)
        heading = text::clip(clean_label, label_budget - 3) + "...";
    const size_t fixed = text_width(heading) + percent.size() + 4; // spaces and brackets
    if (available < fixed + 4) {
        log_progress(percent + (heading.empty() ? "" : " " + heading));
        return;
    }
    std::string details;
    const auto append = [&](const std::string& value) {
        const std::string candidate = details + " " + value;
        if (fixed + preferred_bar + text_width(candidate) <= available) details = candidate;
    };
    append(unit == ProgressUnit::Bytes
        ? decimal(done / 1048576.0) + "/" + decimal(total / 1048576.0) + " MiB"
        : std::to_string(done) + "/" + std::to_string(total) + " chunks");
    if (unit == ProgressUnit::Bytes && std::isfinite(seconds) && seconds > 0)
        append(decimal(done / 1048576.0 / seconds, 2) + " MiB/s");
    if (done && std::isfinite(seconds) && seconds > 0 && done < total)
        append("ETA " + format_duration((total - done) * (seconds / done)));
    const size_t cells = std::min<size_t>(64, available - fixed - text_width(details));
    const size_t filled = static_cast<size_t>(fraction * cells);
    std::string bar(filled, '=');
    if (filled < cells) bar += '>';
    bar.append(cells - bar.size(), ' ');
    log_progress(heading + " [" + bar + "] " + percent + details);
}

void set_log_sink(LogSink sink) {
    auto replacement = sink ? std::make_shared<const LogSink>(std::move(sink)) : nullptr;
    {
        std::lock_guard<std::mutex> lk(g_log_mutex);
        clear_progress_line();
        g_sink.swap(replacement);
    }
    // Captured objects can themselves log during destruction.
}

bool log_diag_trace_enabled() {
    int value = g_trace.load(std::memory_order_acquire);
    if (value < 0) {
        const auto* environment = std::getenv("UNIFLASH_TRACE");
        const int from_env = environment && std::string_view(environment) == "1";
        if (g_trace.compare_exchange_strong(value, from_env)) value = from_env;
    }
    return value != 0;
}

bool log_performance_enabled() {
    const auto* value = std::getenv("UNIFLASH_PERF");
    return log_diag_trace_enabled() || (value && std::string_view(value) == "1");
}

void set_log_diag_trace(bool on) {
    g_trace.store(on, std::memory_order_release);
}

void log_progress(const std::string& line, ProgressOwner owner) {
    std::lock_guard<std::mutex> lk(g_log_mutex);
    if (!g_sink && !line.empty() && platform::supports_ansi(2)) {
        clear_progress_line();
        auto content = std::string_view(line);
        if (content.starts_with('\r')) content.remove_prefix(1);
        const auto display = progress_text("[*] " + std::string(content));
        std::fprintf(stderr, "%s", display.c_str());
        std::fflush(stderr);
        g_progress_active = true;
        g_progress_owner = owner;
    }
}

void log_finish_progress_line(ProgressOwner owner) {
    std::lock_guard<std::mutex> lk(g_log_mutex);
    if (g_progress_active && g_progress_owner != owner) return;
    if (g_progress_active && platform::supports_ansi(2)) {
        std::fputc('\n', stderr);
        std::fflush(stderr);
    }
    g_progress_active = false;
}

void log_clear_progress_line(ProgressOwner owner) {
    std::lock_guard<std::mutex> lk(g_log_mutex);
    if (g_progress_active && g_progress_owner != owner) return;
    clear_progress_line();
    std::fflush(stderr);
}

void log_document(std::string_view text) {
    std::shared_ptr<const LogSink> sink;
    {
        std::lock_guard<std::mutex> lock(g_log_mutex);
        sink = g_sink;
        if (!sink) {
            clear_progress_line();
            std::fwrite(text.data(), 1, text.size(), stdout);
            std::fflush(stdout);
            return;
        }
    }
    try { (*sink)(LogLevel::Info, std::string(text)); } catch (...) {}
}

void log_console(std::string_view text) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_sink) return;
    clear_progress_line();
    std::fwrite(text.data(), 1, text.size(), stdout);
    std::fflush(stdout);
}

void log(LogLevel level, const std::string& msg) {
    std::shared_ptr<const LogSink> sink;
    {
        std::lock_guard<std::mutex> lk(g_log_mutex);
        sink = g_sink;
        if (!sink) {
            console_sink(level, msg);
            return;
        }
    }
    try { (*sink)(level, msg); } catch (...) {}
}

}  // namespace uniflash

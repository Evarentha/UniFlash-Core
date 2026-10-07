/*
 * UniFlash-Core Test / Log Progress
 *
 * Covers progress line behaviour on a real pseudo terminal.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#include <uniflash/log.h>

#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <vector>
#include <unistd.h>
#include <thread>

// A real pseudo-terminal is needed: redirected-output tests do not enter
// the isatty branch that produced blank lines after small reads.
int main() {
    const int master = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (master < 0 || grantpt(master) || unlockpt(master)) return 1;
    const int terminal = open(ptsname(master), O_RDWR | O_NOCTTY);
    const int saved = dup(STDERR_FILENO);
    if (terminal < 0 || saved < 0 || dup2(terminal, STDERR_FILENO) < 0) return 1;
    close(terminal);

    int failures = 0;
    std::vector<std::string> failure_messages;
    const auto check = [&](bool ok, const char* name) {
        // Assertions must not write into the logger/PTY under observation.
        if (!ok) { failure_messages.push_back(std::string("FAIL: ")+name); ++failures; }
    };
    const auto output = [&]() {
        std::string result;
        char bytes[1024];
        for (;;) {
            const auto n = read(master, bytes, sizeof bytes);
            if (n > 0) result.append(bytes, static_cast<size_t>(n));
            else if (n < 0 && errno == EINTR) continue;
            else break;
        }
        return result;
    };
    using namespace uniflash;
    set_log_diag_trace(false);
    log_finish_progress_line();
    log_finish_progress_line();
    check(output().empty(), "no progress displayed: finish emits no blank line");

    log_diag("{test} small read complete");
    auto text = output();
    check(text.starts_with("{test}") && text.find('\033') == std::string::npos,
          "ordinary log does not clear an inactive terminal line");

    log_progress("\rprogress 100%");
    check(output() == "[*] progress 100%", "progress rendered through the unified prefix");
    log_finish_progress_line();
    text = output();
    check(text == "\r\n" || text == "\n", "finish terminates visible progress once");
    log_finish_progress_line();
    check(output().empty(), "repeated finish is silent");

    log_progress("\rprogress long line");
    output();
    log_progress("\rshort");
    check(output() == "\r\033[K[*] short", "shorter progress clears stale suffix");
    log_err("interrupted transfer");
    text = output();
    check(text.starts_with("\r\033[K[!]"), "error clears active progress");
    log_finish_progress_line();
    check(output().empty(), "finish after log-cleared progress is silent");

    log_progress("owner's progress");
    output();
    std::thread other([] { log_clear_progress_line(); log_finish_progress_line(); });
    other.join();
    check(output().empty(), "other transfer cannot clear this owner's progress");
    log_clear_progress_line();
    check(output() == "\r\033[K", "owner clears its own progress");

    int records = 0;
    set_log_sink([&](LogLevel, const std::string&) { ++records; });
    log_progress("\rhidden");
    log_finish_progress_line();
    log_diag("client record");
    check(output().empty() && records == 1, "custom sink has no console progress output");
    set_log_sink(nullptr);

    int pipefd[2];
    if (pipe(pipefd) != 0 || dup2(pipefd[1], STDERR_FILENO) < 0) return 1;
    close(pipefd[1]);
    log_progress("\rhidden in pipe");
    log_finish_progress_line();
    log_diag("plain");
    dup2(saved, STDERR_FILENO);
    close(saved);
    char bytes[128];
    const auto n = read(pipefd[0], bytes, sizeof bytes);
    check(n == 6 && std::string(bytes, static_cast<size_t>(n)) == "plain\n",
          "redirected logs contain neither progress nor stray newline");
    close(pipefd[0]);
    close(master);
    for(const auto& message:failure_messages)uniflash::log_err(message);
    if (failures) return 1;
    uniflash::log_info("Terminal progress lifecycle passed");
    return 0;
}

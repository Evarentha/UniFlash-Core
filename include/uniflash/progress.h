/*
 * UniFlash-Core / Console Progress
 *
 * Single-line progress rendering that never probes the device.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <uniflash/log.h>
#include <uniflash/platform.h>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <atomic>

namespace uniflash {
inline std::atomic<bool> console_wait_progress_enabled{false};
// UI only: never sends a device probe or invents a completion percentage.
// The worker is joined before the next stage can render a progress line.
class WaitProgress {
public:
    explicit WaitProgress(std::string label) {
        if (!console_wait_progress_enabled.load() || !platform::supports_ansi(2)) return;
        worker_ = std::jthread([this, label = std::move(label)](std::stop_token stop) {
            try {
            const auto start = std::chrono::steady_clock::now();
            std::unique_lock lock(mutex_);
            while (!condition_.wait_for(lock, stop, std::chrono::milliseconds(250), [] { return false; })) {
                if (stop.stop_requested()) break;
                const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
                if (elapsed < 1.0) continue;
                log_wait_progress(label, elapsed, owner_);
                rendered_ = true;
            }
            } catch (...) { /* Display failure must not terminate a transfer. */ }
        });
    }
    ~WaitProgress() {
        if (worker_.joinable()) { worker_.request_stop(); condition_.notify_all(); worker_.join(); }
        if (rendered_) log_clear_progress_line(owner_);
    }
    WaitProgress(const WaitProgress&) = delete;
    WaitProgress& operator=(const WaitProgress&) = delete;
private:
    ProgressOwner owner_ = std::this_thread::get_id();
    std::mutex mutex_;
    std::condition_variable_any condition_;
    std::jthread worker_;
    bool rendered_ = false; // read by owner only after worker is joined
};
}

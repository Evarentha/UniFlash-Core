/*
 * UniFlash-Core / Buffered Disk Writer
 *
 * Bounded producer and consumer queue that separates device reads from disk writes.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <uniflash/io/output.h>
#include <condition_variable>
#include <deque>
#include <vector>
#include <mutex>
#include <thread>
#include <algorithm>
#include <new>

namespace uniflash::io {
// One bounded producer/consumer queue, no device calls on the disk thread.
// finish() must succeed before checking AtomicOutput size or committing it.
// The referenced output must outlive this object. Destruction cancels and joins.
class BufferedOutput {
public:
    explicit BufferedOutput(AtomicOutput& output) : output_(output), worker_([this](std::stop_token stop) { run(stop); }) {}
    ~BufferedOutput() { worker_.request_stop(); condition_.notify_all(); worker_.join(); }
    BufferedOutput(const BufferedOutput&) = delete;
    BufferedOutput& operator=(const BufferedOutput&) = delete;
    std::expected<void, std::errc> write(std::span<const uint8_t> bytes, std::stop_token stop = {}) {
        std::unique_lock lock(mutex_);
        const auto cancelled = [&]() {
            if (error_ == std::errc{}) error_ = std::errc::interrupted;
            closing_ = true;
            worker_.request_stop();
            condition_.notify_all();
            return std::unexpected(error_);
        };
        if (stop.stop_requested()) return cancelled();
        if (error_ != std::errc{}) return std::unexpected(error_);
        if (closing_) return std::unexpected(std::errc::operation_not_permitted);
        try {
        while (!bytes.empty()) {
            const auto n = std::min<size_t>(bytes.size(), block_limit);
            condition_.wait(lock, stop, [&] { return error_ != std::errc{} || closing_ || pending_ + n <= capacity; });
            if (stop.stop_requested()) return cancelled();
            if (error_ != std::errc{}) return std::unexpected(error_);
            if (closing_) return std::unexpected(std::errc::operation_not_permitted);
            queue_.emplace_back(bytes.begin(), bytes.begin() + n);
            pending_ += n;
            accepted_ += n;
            bytes = bytes.subspan(n);
            condition_.notify_all();
        }
        } catch (...) {
            error_ = std::errc::not_enough_memory;
            closing_ = true;
            worker_.request_stop();
            condition_.notify_all();
            throw;
        }
        return {};
    }
    uint64_t accepted() const { return accepted_; } // producer only; not durable bytes
    std::expected<void, std::errc> finish(std::stop_token stop = {}) {
        std::unique_lock lock(mutex_);
        closing_ = true;
        condition_.notify_all();
        condition_.wait(lock, stop, [&] { return done_; });
        if (stop.stop_requested()) {
            if (error_ == std::errc{}) error_ = std::errc::interrupted;
            lock.unlock();
            worker_.request_stop();
            condition_.notify_all();
            return std::unexpected(std::errc::interrupted);
        }
        if (error_ != std::errc{}) return std::unexpected(error_);
        return {};
    }
private:
    static constexpr size_t capacity = 4 * 1024 * 1024, block_limit = 1024 * 1024;
    AtomicOutput& output_;
    std::mutex mutex_;
    std::condition_variable_any condition_;
    std::deque<std::vector<uint8_t>> queue_;
    size_t pending_ = 0; // includes the block currently being written
    uint64_t accepted_ = 0;
    std::errc error_{};
    bool closing_ = false, done_ = false;
    std::jthread worker_; // constructed after all shared state
    void run(std::stop_token stop) noexcept {
        try {
            for (;;) {
                std::unique_lock lock(mutex_);
                condition_.wait(lock, stop, [&] { return closing_ || !queue_.empty(); });
                if (stop.stop_requested() || (closing_ && queue_.empty())) break;
                auto bytes = std::move(queue_.front());
                queue_.pop_front();
                lock.unlock();
                auto written = output_.write(bytes, stop);
                lock.lock();
                pending_ -= bytes.size();
                if (!written) { if (error_ == std::errc{}) error_ = written.error(); break; }
                condition_.notify_all();
            }
        } catch (const std::bad_alloc&) {
            std::lock_guard lock(mutex_); error_ = std::errc::not_enough_memory;
        } catch (...) {
            std::lock_guard lock(mutex_); error_ = std::errc::io_error;
        }
        std::lock_guard lock(mutex_);
        if (stop.stop_requested() && error_ == std::errc{}) error_ = std::errc::interrupted;
        done_ = true;
        condition_.notify_all();
    }
};
}

#pragma once
#include <uniflash/session/operations.h>
#include <uniflash/log.h>
#include <uniflash/cli/signal.h>
#include <optional>
#include <chrono>
#include <cstdio>
#include <string>

namespace uniflash::cli {
class OperationDisplay {
public:
    explicit OperationDisplay(bool batch = false) : batch_(batch) {}
    ~OperationDisplay() { if (rendered_) log_clear_progress_line(); }
    session::ProgressObserver observer() {
        return [this](const session::OperationProgress& event) { update(event); };
    }
private:
    bool batch_ = false;
    std::string writing_;
    uint64_t write_start_bytes_ = 0;
    std::chrono::steady_clock::time_point write_started_;
    std::string label_;
    bool rendered_ = false;
    std::chrono::steady_clock::time_point started_, next_;
    void update(const session::OperationProgress& event) {
        using enum session::OperationStep;
        if (event.step == Erase && event.detail != "complete") {
            log_status(LogLevel::Info, "erase", event.target, "Ctrl+C disabled during erase");
        }
        const char* phase = event.step == Prepare ? "preparing" : event.step == Validate ? "checking" :
            event.step == Erase ? "erasing" : event.step == Write ? "writing" :
            event.step == Finish ? "finishing" : "reading";
        const auto now = std::chrono::steady_clock::now();
        if (event.step == Write && event.detail == "transfer") {
            if (now >= next_ || event.target_completed == event.target_total) {
                next_ = now + std::chrono::milliseconds(500);
                log_transfer_progress("write: " + std::string(event.target), event.target_completed,
                    event.target_total, event.transfer_seconds);
                rendered_ = true;
            }
            return;
        }
        if (batch_ && event.step == Write) {
            if (writing_ != event.target) {
                writing_ = event.target;
                write_start_bytes_ = event.completed;
                write_started_ = now;
            } else if (event.detail == "complete" && event.completed > write_start_bytes_) {
                log_status(LogLevel::Info, "written", event.target,
                    format_transfer(event.completed - write_start_bytes_,
                        std::chrono::duration<double>(now - write_started_).count()));
            }
        }
        if (batch_ && event.step == Erase && event.detail == "complete")
            log_status(LogLevel::Info, "erased", event.target);
        std::string label = std::string(phase) + (event.target.empty() ? "" : " " + std::string(event.target));
        if (!event.detail.empty()) label += ": " + std::string(event.detail);
        if (label != label_) {
            if (rendered_) log_clear_progress_line();
            rendered_ = false;
            label_ = std::move(label);
            started_ = now;
            next_ = now;
            if (log_diag_trace_enabled()) log_diag("{operation} " + label_);
        }
        if ((event.step != Prepare && !(event.step == Validate && event.detail == "physical readback")) ||
            (now < next_ && event.completed != event.total)) return;
        next_ = now + std::chrono::milliseconds(250);
        const double seconds = std::chrono::duration<double>(now - started_).count();
        if (seconds < 1.0) return;
        log_transfer_progress(label_, event.completed, event.total, seconds,
            event.detail == "sparse index" ? ProgressUnit::Items : ProgressUnit::Bytes);
        rendered_ = true;
    }
};
}

/*
 * UniFlash-Core / Interrupt Handling
 *
 * Stop token rotation, second-interrupt latching and termination requests.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef UNIFLASH_CLI_SIGNAL_H
#define UNIFLASH_CLI_SIGNAL_H

#include <stop_token>
#include <memory>

namespace uniflash::cli {

// Token of the current operation. Rotating acknowledges cancellation without
// clearing the second-interrupt latch; begin_command starts the next cycle.
std::stop_token current_stop_token();

// Replace the active stop_source with a fresh, non-stopped one.
void rotate_stop_source();
// Reset the double-interrupt latch only when accepting a new nonempty command.
void begin_command();
// Console input events (Windows raw mode) share the OS signal interrupt path.
void interrupt_from_console();

// True if the current token has been stopped (Ctrl+C during last command).
bool global_interrupted();

// Sticky process-exit request (SIGTERM / Windows console close). Unlike an
// interactive Ctrl+C, rotating the command token never clears this flag.
bool termination_requested();
// Input scope permits a second Ctrl+C to unwind terminal mode normally.
void set_input_active(bool active);
bool force_exit_requested();

// Discard Ctrl+C/Break during a non-interruptible erase. Suppressed events do
// not stop a token or arm the second-interrupt exit latch. Nestable; exceptions
// restore the previous behavior. SIGTERM/console close are not suppressed.
class IgnoreInterrupts {
public:
    IgnoreInterrupts();
    ~IgnoreInterrupts();
    IgnoreInterrupts(const IgnoreInterrupts&) = delete;
    IgnoreInterrupts& operator=(const IgnoreInterrupts&) = delete;
};
// Record cancellation but defer forced second-Ctrl+C exit until the owning
// transaction has restored its layout. Unlike IgnoreInterrupts, never drops it.
class DeferForcedExit {
public:
    DeferForcedExit();
    ~DeferForcedExit();
    DeferForcedExit(const DeferForcedExit&)=delete;
    DeferForcedExit& operator=(const DeferForcedExit&)=delete;
};

class SignalHandler {
public:
    SignalHandler();
    ~SignalHandler();
    SignalHandler(const SignalHandler&) = delete;
    SignalHandler& operator=(const SignalHandler&) = delete;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}

#endif

/*
 * UniFlash-Core Test / Erase Interruption
 *
 * Covers cancellation during erase and directory restore.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/cli/signal.h>
#include <stdexcept>

int main() {
    using namespace uniflash::cli;
    SignalHandler signals;
    const auto token = current_stop_token();
    {
        IgnoreInterrupts erase;
        interrupt_from_console();
        interrupt_from_console();
        if (global_interrupted() || token.stop_requested() || force_exit_requested()) return 1;
        {
            IgnoreInterrupts nested;
            interrupt_from_console();
        }
        interrupt_from_console();
        if (global_interrupted() || token.stop_requested()) return 1;
    }
    try {
        IgnoreInterrupts failed_erase;
        throw std::runtime_error("erase failed");
    } catch (const std::runtime_error&) {}
    // Must be the first accepted interrupt, not a force-exit left behind by
    // any of the ignored key presses. Also proves exception unwinding restores.
    interrupt_from_console();
    if (!global_interrupted() || force_exit_requested() || termination_requested()) return 1;
    rotate_stop_source();begin_command();
    {
        DeferForcedExit deferred;
        interrupt_from_console();interrupt_from_console();
        if(!global_interrupted() || force_exit_requested() || termination_requested())return 1;
    }
    return 0;
}

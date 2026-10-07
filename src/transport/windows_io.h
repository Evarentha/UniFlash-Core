/*
 * UniFlash-Core / Windows Overlapped I/O
 *
 * Named pipe overlapped transfer helper used by the Windows transport.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef UNIFLASH_WINDOWS_IO_H
#define UNIFLASH_WINDOWS_IO_H

#include <windows.h>
#include <uniflash/transport/usb.h>

namespace uniflash::transport {

// Overlapped byte I/O shared by the COM backend and the Windows pipe
// regression fixture. Never returns while the kernel still owns the buffer.
// Returns the byte count only for successful completion (including a race with
// cancellation). An aborted write may have delivered bytes: do not replay a
// complete protocol frame on error. timeout covers submission and the wait;
// cancellation drainage must finish even after that deadline for buffer safety.
std::expected<DWORD, std::errc> windows_transfer(
    HANDLE handle, uint8_t* data, DWORD length, bool writing,
    Timeout timeout, std::stop_token stop);

}
#endif

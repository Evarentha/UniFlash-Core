/*
 * UniFlash-Core / Device Error Mapping
 *
 * Builds operation errors from reply evidence and caught exceptions.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once
#include <uniflash/session/operation_result.h>
#include <uniflash/device/sprd_device.h>
namespace uniflash::session {
// Preserve reply evidence without making result consumers depend on a device.
inline OperationError device_operation_error(device::SprdDevice& device,OperationStep step,
    std::errc code,std::string target) {
    OperationError error{step,code,std::move(target)};
    error.exchange=device.last_exchange();
    error.cleanup_exchange=device.cleanup_exchange();
    error.session_synchronized=!device.link_dead() && !device.link_silent();
    return error;
}
inline OperationError device_exception_error(device::SprdDevice& device,OperationStep step) {
    auto result=exception_error(step);
    result.exchange=device.last_exchange();result.cleanup_exchange=device.cleanup_exchange();
    result.session_synchronized=!device.link_dead() && !device.link_silent();return result;
}
}

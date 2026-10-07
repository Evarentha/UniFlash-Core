/*
 * UniFlash-Core / Backup Failure Reporting
 *
 * Keeps the primary failure when the manifest commit also fails.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once
#include <uniflash/session/journal.h>

namespace uniflash::cli::detail {
// A failed manifest commit is secondary to the operation that stopped backup.
template<class Checkpoint>
session::OperationError record_backup_failure(session::OperationError primary, Checkpoint&& checkpoint) {
    auto saved = session::Journal::attempt(std::forward<Checkpoint>(checkpoint));
    if (!saved) session::attach_journal_failure(primary, saved.error());
    return primary;
}
}

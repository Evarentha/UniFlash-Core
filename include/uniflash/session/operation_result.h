/*
 * UniFlash-Core / Operation Result
 *
 * Step-tagged errors that retain reply evidence for diagnostics.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <uniflash/io/output.h>
#include <uniflash/protocol/evidence.h>
#include <string>
#include <string_view>
#include <functional>
#include <memory>
#include <new>
#include <stdexcept>

namespace uniflash::session {
enum class OperationStep { Prepare, Validate, Erase, Write, Read, Save, Finish };
struct OperationError {
    OperationStep step;
    std::errc code;
    std::string target;
    io::CommitState commit_state = io::CommitState::NotCommitted;
    uint64_t actual_bytes = 0;
    std::string detail{};
    std::optional<protocol::ExchangeEvidence> exchange{};
    bool session_synchronized = true;
    std::optional<protocol::ExchangeEvidence> initial_raw_failure{};
    std::optional<protocol::ExchangeEvidence> cleanup_exchange{};
    std::optional<io::OutputError> journal_failure{};
    std::shared_ptr<OperationError> cleanup_failure{};
};
// Called only from a catch handler. Allocation failure uses an empty target so
// translating it does not require constructing another diagnostic string.
inline OperationError exception_error(OperationStep step) {
    try {throw;}
    catch(const std::bad_alloc&) {return {step,std::errc::not_enough_memory,{}};}
    catch(const std::length_error&) {return {step,std::errc::value_too_large,{}};}
    catch(const std::system_error& e) {
        const auto code=e.code().default_error_condition();
        return {step,code.category()==std::generic_category()?static_cast<std::errc>(code.value()):std::errc::io_error,{}};
    }
    catch(...) {return {step,std::errc::io_error,{}};}
}
inline void attach_journal_failure(OperationError& primary,const OperationError& journal) {
    primary.journal_failure=io::OutputError{journal.code,journal.commit_state,journal.actual_bytes};
}
template<class T = void> using OperationResult = std::expected<T, OperationError>;
inline OperationResult<> commit_output(io::AtomicOutput& output,std::string target) {
    auto committed=output.commit_result();
    if(!committed)return std::unexpected(OperationError{OperationStep::Save,committed.error().code,
        std::move(target),committed.error().state,committed.error().bytes});
    return {};
}
struct OperationReport {
    uint64_t bytes = 0;
    size_t partitions = 0;
    double validate_seconds = 0, erase_seconds = 0, write_seconds = 0;
    double verify_seconds = 0;
    double open_seconds = 0, transfer_seconds = 0, sync_seconds = 0;
    double source_seconds = 0, encode_seconds = 0, send_seconds = 0, ack_seconds = 0;
    uint64_t slow_ack_count = 0;
    double slow_ack_seconds = 0, max_ack_seconds = 0;
    struct Attempt { std::string target; bool framed_restart; double raw_seconds;
        std::optional<protocol::ExchangeEvidence> raw_failure; };
    std::vector<Attempt> attempts;
};
struct OperationProgress {
    OperationStep step;
    std::string_view target;
    uint64_t completed;
    uint64_t total;
    std::string_view detail{};
    uint64_t target_completed = 0, target_total = 0;
    double transfer_seconds = 0;
};
using ProgressObserver = io::Observer<OperationProgress>;
// Control callbacks are separate from best-effort display observers.
using EraseScopeFactory = std::function<std::shared_ptr<void>()>;
}

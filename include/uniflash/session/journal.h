/*
 * UniFlash-Core / Recovery Journal
 *
 * Atomic persistence for recovery journals and bounded evidence.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once
#include <uniflash/session/operation_result.h>
#include <uniflash/platform.h>
#include <uniflash/log.h>

namespace uniflash::session {
// One atomic persistence path for recovery journals and bounded evidence.
// Domain-specific state text stays with the transaction that owns its meaning.
class Journal {
public:
    static OperationResult<> seal_directory(const std::filesystem::path& path) try {
        auto synced=platform::sync_directory_tree(path);
        if(!synced)return std::unexpected(OperationError{OperationStep::Save,synced.error(),
            "recovery directory durability: "+platform::utf8_path(path)});
        if(*synced==platform::DirectoryDurability::FileCommitsOnly) {
            auto recorded=write(path/"durability.txt",
                "Files flushed and replaced with write-through. Parent-directory power-loss durability is not confirmed on this platform.\n",
                "directory durability evidence");
            if(!recorded)return recorded;
            log_status(LogLevel::Warn,"recovery durability",platform::utf8_path(path),
                "files committed; parent-directory power-loss persistence unconfirmed");
        }
        return {};
    } catch(...) {return std::unexpected(exception_error(OperationStep::Save));}
    static OperationResult<> write(const std::filesystem::path& path,std::span<const uint8_t> bytes,
        std::string target,std::stop_token stop = {}) try {
        auto output=io::AtomicOutput::open(path);
        if(!output)return std::unexpected(OperationError{OperationStep::Save,output.error(),std::move(target)});
        auto saved=output->write(bytes,stop);
        if(!saved)return std::unexpected(OperationError{OperationStep::Save,saved.error(),std::move(target)});
        if(stop.stop_requested())return std::unexpected(OperationError{OperationStep::Save,std::errc::interrupted,std::move(target)});
        return commit_output(*output,std::move(target));
    } catch(...) {return std::unexpected(exception_error(OperationStep::Save));}
    static OperationResult<> write(const std::filesystem::path& path,std::string_view text,
        std::string target,std::stop_token stop = {}) {
        return write(path,std::span(reinterpret_cast<const uint8_t*>(text.data()),text.size()),std::move(target),stop);
    }
    // Includes caller-side path/text construction in the protected boundary.
    template<class F> static OperationResult<> attempt(F&& save) {
        try {return save();}catch(...) {return std::unexpected(exception_error(OperationStep::Save));}
    }
};
}

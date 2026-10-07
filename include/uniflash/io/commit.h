#pragma once
#include <system_error>
#include <cstdint>
namespace uniflash::io {
enum class CommitState { NotCommitted, Replaced, Durable };
struct OutputError {
    std::errc code;
    CommitState state=CommitState::NotCommitted;
    uint64_t bytes=0;
    OutputError(std::errc value):code(value) {}
    OutputError(std::errc value,CommitState commit,uint64_t size):code(value),state(commit),bytes(size) {}
    operator std::errc() const {return code;}
};
}

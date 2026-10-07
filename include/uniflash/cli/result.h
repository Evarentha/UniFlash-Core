#pragma once
#include <string>
#include <utility>

namespace uniflash::cli {
enum class CommandStatus { Success, Failed, Cancelled, Terminated };
struct CommandResult {
    CommandStatus status = CommandStatus::Success;
    std::string message;
    bool succeeded() const { return status == CommandStatus::Success; }
    int exit_code() const {
        switch (status) {
        case CommandStatus::Success: return 0;
        case CommandStatus::Failed: return 2;
        case CommandStatus::Cancelled: return 130;
        case CommandStatus::Terminated: return 143;
        }
        return 2;
    }
};
// Internal unwinding of a handler. Only the dispatcher translates and renders
// this value, so logging can never implicitly determine command success.
struct CommandFailure { std::string message; };
}

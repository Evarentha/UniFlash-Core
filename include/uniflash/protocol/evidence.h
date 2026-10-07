#pragma once
#include <uniflash/protocol/bsl.h>
#include <optional>
namespace uniflash::protocol {
enum class ExchangeOutcome { Unsent, AwaitingReply, ReplyReceived, Unknown };
struct ExchangeEvidence {
    std::optional<uint16_t> command;
    std::optional<BslResponse> response;
    size_t response_bytes = 0;
    ExchangeOutcome outcome = ExchangeOutcome::Unsent;
    std::errc transport_error{};
    bool bare_data=false;
    uint64_t offset=0,requested_bytes=0;
};
}

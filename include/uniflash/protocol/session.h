#pragma once

#include <uniflash/protocol/bsl.h>
#include <uniflash/protocol/evidence.h>
#include <uniflash/transport/transport.h>
#include <optional>

namespace uniflash::protocol {

// Owns framing, checksum phase, buffered replies and transaction validity.
// Discovery reads may time out; a request/reply timeout invalidates the session.
// Device command semantics and loader identities deliberately live above it.
class BslSession {
public:
    explicit BslSession(std::unique_ptr<transport::Transport> channel)
        : transport_(std::move(channel)) {}
    BslSession(BslSession&&) noexcept = default;
    BslSession& operator=(BslSession&&) noexcept = default;
    struct Reply {
        BslResponse cmd;
        std::vector<uint8_t> payload;
        std::optional<BslCodec::Chk> checksum;
    };
    std::expected<Reply, std::errc> send_recv(const std::vector<uint8_t>&,
        std::stop_token = {}, transport::Timeout = transport::DEFAULT_TIMEOUT);
    std::expected<Reply, std::errc> read_frame(std::stop_token, transport::Timeout);
    std::expected<void, std::errc> write_frame(std::span<const uint8_t>,
        std::stop_token, transport::Timeout);
    std::expected<Reply, std::errc> read_reply(std::stop_token, transport::Timeout);
    const ExchangeEvidence& last_exchange() const { return exchange_; }
    const std::optional<ExchangeEvidence>& cleanup_exchange() const {return cleanup_;}

protected:
    // State is private to the owning device; no shared/mutable external channel.
    transport::Channel transport_;
    std::vector<uint8_t> rx_buffer_;
    bool raw_tx_ = false;
    bool desynchronized_ = false;
    std::optional<BslCodec::Chk> rx_checksum_;
    ExchangeEvidence exchange_;
    std::optional<ExchangeEvidence> cleanup_;
    std::expected<void,std::errc> write_bare(std::span<const uint8_t>,uint64_t,std::stop_token,transport::Timeout);
};

} // namespace uniflash::protocol

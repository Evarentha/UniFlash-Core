#include <uniflash/protocol/session.h>
#include <algorithm>
#include <uniflash/log.h>
#include <cstdio>

namespace uniflash::protocol {

std::expected<void, std::errc> BslSession::write_frame(
    std::span<const uint8_t> frame, std::stop_token stop, transport::Timeout timeout) {
    if (desynchronized_) return std::unexpected(std::errc::state_not_recoverable);
    exchange_ = {};
    cleanup_.reset();
    if (frame.size() >= 3 && frame[0] == HDLC_FLAG)
        exchange_.command = uint16_t((uint16_t(frame[1]) << 8) | frame[2]);
    if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    std::expected<void, std::errc> result;
    try {
        result = raw_tx_ ? transport_.bulk_write_frame(frame, timeout, stop)
                         : transport_.bulk_write(frame, timeout, stop);
    } catch (...) {
        exchange_.outcome = ExchangeOutcome::Unknown;
        exchange_.transport_error = std::errc::io_error;
        desynchronized_ = true; throw;
    }
    if (!result && result.error() != std::errc::message_size) desynchronized_ = true;
    exchange_.outcome = result ? ExchangeOutcome::AwaitingReply :
        result.error() == std::errc::message_size ? ExchangeOutcome::Unsent : ExchangeOutcome::Unknown;
    if (!result) exchange_.transport_error = result.error();
    return result;
}

std::expected<void,std::errc> BslSession::write_bare(std::span<const uint8_t> bytes,uint64_t offset,
    std::stop_token stop,transport::Timeout timeout) {
    if(desynchronized_)return std::unexpected(std::errc::state_not_recoverable);
    exchange_={};cleanup_.reset();exchange_.bare_data=true;
    exchange_.offset=offset;exchange_.requested_bytes=bytes.size();
    if(stop.stop_requested())return std::unexpected(std::errc::interrupted);
    exchange_.outcome=ExchangeOutcome::Unknown;
    try {
        auto sent=transport_.bulk_write(bytes,timeout,stop);
        if(!sent) {exchange_.transport_error=sent.error();desynchronized_=true;return sent;}
    } catch(...) {exchange_.transport_error=std::errc::io_error;desynchronized_=true;throw;}
    exchange_.outcome=ExchangeOutcome::AwaitingReply;return {};
}

std::expected<BslSession::Reply, std::errc> BslSession::read_reply(
    std::stop_token stop, transport::Timeout timeout) {
    exchange_.response.reset();exchange_.response_bytes=0;exchange_.transport_error={};
    std::expected<Reply, std::errc> reply;
    try { reply = read_frame(stop, timeout); }
    catch (...) {
        exchange_.outcome = ExchangeOutcome::Unknown;
        exchange_.transport_error = std::errc::io_error;
        desynchronized_ = true; throw;
    }
    if (!reply) desynchronized_ = true;
    exchange_.outcome = reply ? ExchangeOutcome::ReplyReceived : ExchangeOutcome::Unknown;
    if (reply) { exchange_.response = reply->cmd; exchange_.response_bytes = reply->payload.size(); }
    else exchange_.transport_error = reply.error();
    return reply;
}

std::expected<BslSession::Reply, std::errc> BslSession::send_recv(
    const std::vector<uint8_t>& frame, std::stop_token stop, transport::Timeout timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    auto sent = write_frame(frame, stop, timeout);
    if (!sent) return std::unexpected(sent.error());
    auto reply = read_reply(stop, std::chrono::duration_cast<transport::Timeout>(
        deadline - std::chrono::steady_clock::now()));
    if (log_diag_trace_enabled()) {
        char text[192];
        const unsigned command = frame.size() > 2 ? frame[2] : 0;
        if (reply)
            std::snprintf(text, sizeof text, "{bsl} request=0x%02x reply=%s (0x%02x), payload=%zu B, buffered=%zu B",
                command, BslCodec::reply_name(static_cast<uint8_t>(reply->cmd)),
                static_cast<unsigned>(reply->cmd), reply->payload.size(), rx_buffer_.size());
        else
            std::snprintf(text, sizeof text, "{bsl} request=0x%02x failed: %s, buffered=%zu B",
                command, std::make_error_code(reply.error()).message().c_str(), rx_buffer_.size());
        log_diag(text);
    }
    return reply;
}

std::expected<BslSession::Reply, std::errc> BslSession::read_frame(
    std::stop_token stop, transport::Timeout timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
        const auto first = std::find(rx_buffer_.begin(), rx_buffer_.end(), HDLC_FLAG);
        rx_buffer_.erase(rx_buffer_.begin(), first);
        while (!rx_buffer_.empty()) {
            if (raw_tx_) {
                if (rx_buffer_.size() < 5) break;
                const auto* p = rx_buffer_.data();
                const uint16_t size = uint16_t((p[3] << 8) | p[4]);
                if (p[0] != HDLC_FLAG || p[1] != 0 || p[2] < 0x80 || size > MAX_PAYLOAD_SIZE) {
                    rx_buffer_.erase(rx_buffer_.begin());
                    continue;
                }
                const size_t length = size_t(size) + 8;
                if (rx_buffer_.size() < length) break;
                const uint16_t checksum = uint16_t((p[5 + size] << 8) | p[6 + size]);
                if (p[length - 1] != HDLC_FLAG ||
                    BslCodec::add_checksum(std::span(p + 1, size_t(size) + 4)) != checksum) {
                    rx_buffer_.erase(rx_buffer_.begin());
                    continue;
                }
                Reply reply{static_cast<BslResponse>((p[1] << 8) | p[2]),
                            std::vector<uint8_t>(p + 5, p + 5 + size), BslCodec::Chk::Add};
                rx_buffer_.erase(rx_buffer_.begin(), rx_buffer_.begin() + length);
                return reply;
            }
            const auto end = std::find(rx_buffer_.begin() + 1, rx_buffer_.end(), HDLC_FLAG);
            if (end == rx_buffer_.end()) break;
            const size_t length = size_t(end - rx_buffer_.begin()) + 1;
            auto decoded = BslCodec::decode_hdlc(std::span(rx_buffer_.data(), length), rx_checksum_);
            if (!decoded && length > 2 && log_diag_trace_enabled()) {
                char text[128];
                std::snprintf(text, sizeof text, "{bsl} discarded invalid HDLC frame: wire=%zu B, error=%s",
                    length, std::make_error_code(decoded.error()).message().c_str());
                log_diag(text);
            }
            auto checksum = rx_checksum_;
            if (decoded && !checksum) {
                checksum = BslCodec::decode_hdlc(std::span(rx_buffer_.data(), length), BslCodec::Chk::Crc16)
                    ? BslCodec::Chk::Crc16 : BslCodec::Chk::Add;
            }
            // Preserve the boundary flag: adjacent HDLC frames may share it.
            rx_buffer_.erase(rx_buffer_.begin(), end);
            if (decoded) return Reply{static_cast<BslResponse>(decoded->first), std::move(decoded->second), checksum};
        }
        constexpr size_t maximum = 2 * (MAX_PAYLOAD_SIZE + 6u) + 2;
        if (rx_buffer_.size() > maximum) {
            rx_buffer_.clear();
            return std::unexpected(std::errc::message_size);
        }
        if (std::chrono::steady_clock::now() >= deadline)
            return std::unexpected(std::errc::timed_out);
        auto remaining = std::chrono::duration_cast<transport::Timeout>(deadline - std::chrono::steady_clock::now());
        remaining = std::max(remaining, transport::Timeout(1));
        auto bytes = transport_.bulk_read(65536, remaining, stop);
        if (!bytes) {
            if (bytes.error() == std::errc::timed_out) continue;
            return std::unexpected(bytes.error());
        }
        rx_buffer_.insert(rx_buffer_.end(), bytes->begin(), bytes->end());
    }
}

} // namespace uniflash::protocol

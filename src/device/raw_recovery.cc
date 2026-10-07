#include <uniflash/device/sprd_device.h>
namespace uniflash::device {
std::expected<void,std::errc> SprdDevice::recover_raw_channel(bool end_already_sent,std::stop_token stop) {
    if(profile_.raw_recovery!=RawRecoveryContract::SingleBlockEndAckRestarts ||
        desynchronized_ || transport_.device_gone() || transport_.device_silent())
        return std::unexpected(std::errc::state_not_recoverable);
    // Keep the triggering write reply distinct from recovery queries/END.
    struct Preserve {
        protocol::ExchangeEvidence& active;std::optional<protocol::ExchangeEvidence>& cleanup;
        protocol::ExchangeEvidence failure;
        ~Preserve(){cleanup=active;active=failure;}
    } preserve{exchange_,cleanup_,exchange_};
    // The loader contract independently establishes reset-on-START semantics.
    // A single synchronous OUT block has fully completed. No next raw DMA
    // block exists. Never use this barrier for timeout/partial OUT failures.
    const auto barrier=[&](unsigned stale_acks)->std::expected<void,std::errc> {
        if(stop.stop_requested())return std::unexpected(std::errc::interrupted);
        auto query=encode_fdl2_command(protocol::BslCommand::CMD_READ_MCP_TYPE);
        if(!query)return std::unexpected(query.error());
        auto sent=write_frame(*query,{},std::chrono::seconds(3));if(!sent)return sent;
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(3);
        for(unsigned i=0;i<=stale_acks;++i) {
            auto remaining=std::chrono::duration_cast<transport::Timeout>(deadline-std::chrono::steady_clock::now());
            if(remaining.count()<=0)return std::unexpected(std::errc::timed_out);
            auto reply=read_reply(stop,remaining);if(!reply)return std::unexpected(reply.error());
            if(reply->cmd==protocol::BslResponse::REP_READ_MCP_TYPE && reply->payload.size()==12)return {};
            // Only the END already submitted by normal raw completion can
            // account for one queued response, positive or explicit refusal.
            if(!end_already_sent || i>=stale_acks || !reply->payload.empty() ||
                (reply->cmd!=protocol::BslResponse::REP_ACK && reply->cmd!=protocol::BslResponse::REP_OPERATION_FAILED &&
                 reply->cmd!=protocol::BslResponse::REP_DOWN_EARLY_END && reply->cmd!=protocol::BslResponse::REP_WRITE_ERROR))
                return std::unexpected(std::errc::protocol_error);
        }
        return std::unexpected(std::errc::protocol_error);
    };
    auto synchronized=barrier(end_already_sent?1:0);
    if(!synchronized)return synchronized;
    if(stop.stop_requested())return std::unexpected(std::errc::interrupted);
    auto end=encode_fdl2_command(protocol::BslCommand::CMD_END_DATA);
    if(!end)return std::unexpected(end.error());
    auto reply=send_recv(*end,{},std::chrono::seconds(60));
    if(!reply)return std::unexpected(reply.error());
    // A dispatch barrier alone cannot clean failed storage state. The explicit
    // contract requires successful END and reset-on-START, never a refused END.
    if(!reply->payload.empty() || reply->cmd!=protocol::BslResponse::REP_ACK)
        return std::unexpected(std::errc::protocol_error);
    synchronized=barrier(0);if(!synchronized)return synchronized;
    // read_frame retains a shared HDLC boundary; anything else is unexplained.
    for(auto b:rx_buffer_)if(b!=protocol::HDLC_FLAG)return std::unexpected(std::errc::protocol_error);
    return {};
}
}

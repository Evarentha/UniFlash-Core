#include <uniflash/device/sprd_device.h>
#include <uniflash/log.h>
#include <uniflash/progress.h>
#include <uniflash/layout/partition_table.h>
#include <uniflash/protocol/ram_frame.h>
#include "loader_contract.h"

#include <cctype>
#include <charconv>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iostream>
#include <thread>
#include <stdexcept>

namespace uniflash::device {

SprdDevice::SprdDevice(std::unique_ptr<transport::Transport> transport)
    : SprdDevice(std::move(transport), DeviceProfile{}) {}

SprdDevice::SprdDevice(std::unique_ptr<transport::Transport> transport, DeviceProfile profile)
    : BslSession(std::move(transport)), profile_(profile) {
    if (!profile_.valid()) throw std::invalid_argument("invalid device profile");
}

SprdDevice::~SprdDevice() = default;

std::expected<std::vector<uint8_t>, std::errc>
SprdDevice::encode_fdl2_command(protocol::BslCommand command,
                               std::span<const uint8_t> payload) const {
    const auto type = static_cast<uint8_t>(command);
    auto frame = raw_tx_ ? protocol::BslCodec::encode_raw_chk(type, payload, protocol::BslCodec::Chk::Add)
                         : protocol::BslCodec::encode_hdlc_chk(type, payload, protocol::BslCodec::Chk::Add);
    // Raw receivers require an intact transfer (and ZLP when necessary).
    // Validate controls before side effects such as write-unlock.
    if (frame && raw_tx_ && frame->size() > protocol::MAX_PKT_SIZE)
        return std::unexpected(std::errc::message_size);
    return frame;
}

// Throttle transfer telemetry; presentation belongs to the shared logger.
namespace {
bool valid_partition_name(const std::string& name) {
    return !name.empty() && name.size() <= 35 && std::all_of(name.begin(), name.end(),
        [](unsigned char c) { return c >= 0x20 && c < 0x7f; });
}
// A START accepted by the device must reach END successfully. Even a
// cancellation between packets otherwise leaves the peer mid-transfer.
struct TransferGuard {
    bool& desynchronized;
    bool complete = false;
    ~TransferGuard() {
        log_clear_progress_line();
        if (!complete) desynchronized = true;
    }
};

void report_progress(const std::string& what, uint64_t done, uint64_t total,
                     std::chrono::steady_clock::time_point t0,
                     std::chrono::steady_clock::time_point& next) {
    using namespace std::chrono;
    // Skip progress bar for sub-MB transfers (probes, small reads)
    if (total < 1024 * 1024) return;
    const auto now = steady_clock::now();
    if (done != 0 && done != total && now < next) return;
    next = now + milliseconds(500);
    const double sec = duration_cast<duration<double>>(now - t0).count();
    log_transfer_progress(what, done, total, sec);
}

// Printf-style diagnostics through the unified logger: verbatim stderr,
// the diagnostic tag ({stall}, {read}, ...) embedded in the message.
void log_diagf(const char* fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    uniflash::log_diag(buf);
}
}  // namespace

// RAM MIDST is a byte-stream append. Reframe before sending when an escape
// prefix lands at a USB packet boundary: UD710 ROM 0x3f44 clears escape
// state on receive refill, including escapes in the payload (not just CRC).
// Never retry a rejected MIDST: ROM CRC failure resets download bookkeeping.
std::expected<size_t, std::errc>
SprdDevice::send_midst(protocol::BslCodec::Chk phase,
                        std::span<const uint8_t> data,
                        std::stop_token stop) {
    const size_t wire_limit = info_.stage == Stage::Fdl1 ? profile_.fdl1_wire_limit : 1023;
    auto enc = protocol::encode_ram_midst(data, phase, data.size(), wire_limit,
        std::max<size_t>(64, transport_.out_maxpacket()), profile_.avoid_checksum_escapes);
    if (!enc) return std::unexpected(enc.error());
    auto result = send_recv(enc->wire, stop);
    if (!result) return std::unexpected(result.error());
    if (auto ok = expect_ack(result.value()); !ok)
        return std::unexpected(ok.error());
    return enc->payload_size;
}

// ---------------------------------------------------------------- handshake

std::expected<DeviceInfo, std::errc>
SprdDevice::handshake(std::stop_token stop) {
    invalidate_layout();
    if (desynchronized_) return std::unexpected(std::errc::state_not_recoverable);
    if (info_.stage != Stage::Offline)
        return std::unexpected(std::errc::operation_not_permitted);
    // The one-shot version is the identity, not disposable wake noise.
    // During discovery either checksum is legal; after identification
    // both directions use the receiver's actual protocol phase.
    rx_checksum_.reset();
    const uint8_t flag = protocol::HDLC_FLAG;
    auto wr = transport_.bulk_write(std::span(&flag, 1),
                                    std::chrono::milliseconds(500), stop);
    if (!wr) return std::unexpected(wr.error());
    auto version = read_frame(stop, std::chrono::seconds(2));
    if (!version) {
        if (version.error() != std::errc::timed_out || stop.stop_requested())
            return std::unexpected(stop.stop_requested() ? std::errc::interrupted : version.error());
        // ud710 USB ROM sends SPRD3 once (ROM offset 0x4724..0x477c),
        // then stays in the command loop at 0x47b4. A new host process
        // must send CONNECT instead of expecting another version banner.
        // CONNECT resets download bookkeeping, but does not write memory or
        // execute an image. A CRC16 ACK establishes only a memory dialect;
        // it cannot distinguish ROM from a CRC16 FDL1.
        if (log_diag_trace_enabled()) log_diag("{connect} no version banner; probing memory CONNECT");
        // Discovery still decodes ADD replies so an explicit FDL rejection
        // can be consumed without leaving a reply behind or mistaking it for
        // a ROM ACK. Classification below checks the verified checksum.
        rx_checksum_.reset();
        auto connect = protocol::BslCodec::encode_connect();
        if (!connect) return std::unexpected(connect.error());
        auto reply = send_recv(*connect, stop, std::chrono::seconds(2));
        if (!reply) return std::unexpected(reply.error());
        if (reply->checksum == protocol::BslCodec::Chk::Add) {
            if (reply->cmd == protocol::BslResponse::REP_INCOMPATIBLE_PART) {
                adopt_da_info(reply->payload);
                auto adopted = resync_fdl2(std::chrono::milliseconds(0), stop);
                if (!adopted) return std::unexpected(adopted.error());
                return info_;
            }
            if (reply->cmd != protocol::BslResponse::REP_VERIFY_ERROR && reply->cmd != protocol::BslResponse::REP_ACK)
                return std::unexpected(std::errc::protocol_error);
            rx_checksum_ = protocol::BslCodec::Chk::Add;
            auto connect_add = protocol::BslCodec::encode_connect_add();
            if (!connect_add) return std::unexpected(connect_add.error());
            auto confirmed = send_recv(*connect_add, stop);
            if (!confirmed) return std::unexpected(confirmed.error());
            if (confirmed->cmd != protocol::BslResponse::REP_ACK || !confirmed->payload.empty())
                return std::unexpected(std::errc::protocol_error);
            info_ = {};
            info_.stage = Stage::Fdl1;
            profile_.fdl1_checksum = LoaderChecksum::Add;
            return info_;
        }
        if (reply->cmd != protocol::BslResponse::REP_ACK || !reply->payload.empty()) {
            desynchronized_ = true;
            return std::unexpected(std::errc::protocol_error);
        }
        info_ = {};
        rx_checksum_ = protocol::BslCodec::Chk::Crc16;
        info_.stage = Stage::Memory;
        // No version was received: do not fabricate SPRD3 or a chip identity.
        return info_;
    }
    if (version->cmd == protocol::BslResponse::REP_INCOMPATIBLE_PART) {
        adopt_da_info(version->payload);
        rx_checksum_ = protocol::BslCodec::Chk::Add;
        info_.stage = Stage::Fdl2;
        if (auto raw = maybe_enable_raw_tx(stop); !raw)
            return std::unexpected(raw.error());
        return info_;
    }
    if (version->cmd != protocol::BslResponse::REP_VER)
        return std::unexpected(std::errc::protocol_error);
    DeviceInfo info;
    info.chip.version.assign(version->payload.begin(), version->payload.end());
    while (!info.chip.version.empty() && info.chip.version.back() == '\0')
        info.chip.version.pop_back();
    info.is_sprd4 = info.chip.version.starts_with("SPRD4") ||
                    info.chip.version.starts_with("AutoD");
    if (!info.is_sprd4 && info.chip.version.starts_with("Spreadtrum Boot")) {
        info.stage = Stage::Fdl1;
        rx_checksum_ = version->checksum;
        profile_.fdl1_checksum = *rx_checksum_ == protocol::BslCodec::Chk::Crc16
            ? LoaderChecksum::Crc16 : LoaderChecksum::Add;
    } else if (info.is_sprd4 || version->checksum == protocol::BslCodec::Chk::Crc16) {
        info.stage = info.is_sprd4 || info.chip.version.starts_with("SPRD3") ? Stage::BootRom : Stage::Memory;
        rx_checksum_ = protocol::BslCodec::Chk::Crc16;
    } else if (version->checksum == protocol::BslCodec::Chk::Add) {
        info.stage = Stage::Fdl1;
        rx_checksum_ = protocol::BslCodec::Chk::Add;
        profile_.fdl1_checksum = LoaderChecksum::Add;
    } else {
        info_ = std::move(info); // Retain unknown identity, never invent SPRD3.
        return std::unexpected(std::errc::not_supported);
    }
    auto enc = info.stage == Stage::Fdl1
        ? protocol::BslCodec::encode_hdlc_chk(0, {}, *rx_checksum_)
        : protocol::BslCodec::encode_connect();
    if (!enc) return std::unexpected(std::errc::invalid_argument);
    auto r = send_recv(enc.value(), stop, std::chrono::milliseconds(2000));
    if (!r) return std::unexpected(r.error());

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    for (;;) {
        if (r.value().cmd == protocol::BslResponse::REP_VER) {
            // A repeated version is not the CONNECT acknowledgement.
        } else if (r.value().cmd == protocol::BslResponse::REP_ACK && r->payload.empty()) {
            break;
        } else {
            return std::unexpected(std::errc::protocol_error);
        }
        if (std::chrono::steady_clock::now() > deadline) {
            desynchronized_ = true;
            return std::unexpected(std::errc::timed_out);
        }
        auto next = read_reply(stop, std::chrono::milliseconds(1000));
        if (!next) return std::unexpected(next.error());
        r = std::move(next);
    }

    info_ = std::move(info);
    // No mode narration here: the connection layer's summary line
    // ("device up: port=... mode=... stage=...") strictly supersedes it.
    return info_;
}

std::expected<void, std::errc>
SprdDevice::handshake_fdl1(std::stop_token stop) {
    invalidate_layout();
    if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    if (desynchronized_) return std::unexpected(std::errc::state_not_recoverable);
    if (info_.is_sprd4 || (info_.stage != Stage::Offline && info_.stage != Stage::Fdl1))
        return std::unexpected(std::errc::not_supported);
    TransferGuard transition{desynchronized_};
    // Discover the next loader's checksum from its version frame. The previous
    // ROM checksum and the host's SoC guesses do not define FDL1's build.
    rx_checksum_.reset();
    // This also adopts a freshly reopened handle, whose stage is Offline.
    // Establish the stage from the handshake rather than a caller setter.
    // fdl_main.c initializes USB, waits for 0x7e and emits a version.
    // Some builds retain the handle, others re-enumerate; physical disconnect
    // is handled by Connection on the same port. CONNECT uses the verified
    // version checksum, not a fixed SoC name. Do not clear endpoint halt or
    // reset USB state speculatively while waiting for the next loader.
    const uint8_t flag = protocol::HDLC_FLAG;
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::seconds(30);
    bool got_ver = false;
    bool connected_without_banner = false;
    while (std::chrono::steady_clock::now() < deadline) {
        if (stop.stop_requested())
            return std::unexpected(std::errc::interrupted);
        // During usb_init the OUT endpoint may NAK writes (the
        // controller is being reconfigured) — a write timeout is NOT
        // fatal, just part of the polling.
        auto wr = next_loader_version_ ? std::expected<void, std::errc>{} : transport_.bulk_write(
            std::span<const uint8_t>(&flag, 1),
            std::chrono::milliseconds(1000), stop);
        if (!wr && wr.error() != std::errc::timed_out)
            return std::unexpected(wr.error());
        auto r = next_loader_version_ ? std::expected<Reply, std::errc>(std::move(*next_loader_version_))
                                     : read_frame(stop, std::chrono::milliseconds(1000));
        next_loader_version_.reset();
        if (!r && r.error() != std::errc::timed_out)
            return std::unexpected(r.error());
        if (!r && wr && std::chrono::steady_clock::now() + std::chrono::milliseconds(1500) >= deadline) {
            // Expected FDL1 may already be in its command loop. CONNECT is
            // the only request here; never use a data write as a probe.
            auto connect = protocol::BslCodec::encode_connect_add();
            if (!connect) return std::unexpected(connect.error());
            r = send_recv(*connect, stop, std::chrono::seconds(2));
            if (!r) return std::unexpected(r.error());
            if (r->cmd == protocol::BslResponse::REP_VERIFY_ERROR &&
                r->checksum == protocol::BslCodec::Chk::Crc16) {
                // Only explicit rejection proves the first request ended.
                connect = protocol::BslCodec::encode_connect();
                if (!connect) return std::unexpected(connect.error());
                r = send_recv(*connect, stop, std::chrono::seconds(2));
                if (!r) return std::unexpected(r.error());
            }
            // A CRC16 ACK alone is indistinguishable from the old ROM still
            // running. Do not label it FDL1 without a loader version banner.
            if (r->cmd == protocol::BslResponse::REP_ACK && r->payload.empty() &&
                r->checksum == protocol::BslCodec::Chk::Add) {
                rx_checksum_ = r->checksum;
                profile_.fdl1_checksum = LoaderChecksum::Add;
                connected_without_banner = true;
                break;
            }
            if (r->cmd != protocol::BslResponse::REP_VER)
                return std::unexpected(std::errc::protocol_error);
        }
        // A delivered-but-unanswered poll vs a NAKed write are different
        // failure layers (device protocol dead vs endpoint disabled) —
        // the trace line makes the split visible per poll.
        if (uniflash::log_diag_trace_enabled())
            log_diagf("{poll} wr=%s rd=%s",
                      wr ? "ok" : "timeout",
                      r ? "frame" : "silent");
        if (r && r.value().cmd == protocol::BslResponse::REP_VER) {
            if (!r->checksum) return std::unexpected(std::errc::protocol_error);
            rx_checksum_ = r->checksum;
            profile_.fdl1_checksum = *r->checksum == protocol::BslCodec::Chk::Add
                ? LoaderChecksum::Add : LoaderChecksum::Crc16;
            info_.chip.version.assign(r->payload.begin(), r->payload.end());
            while (!info_.chip.version.empty() && info_.chip.version.back() == '\0')
                info_.chip.version.pop_back();
            got_ver = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    if (!got_ver && !connected_without_banner)
        return std::unexpected(std::errc::timed_out);

    if (!connected_without_banner) {
        auto enc = protocol::BslCodec::encode_hdlc_chk(0, {}, *rx_checksum_);
        if (!enc) return std::unexpected(enc.error());
        auto result = send_recv(enc.value(), stop);
        if (!result) return std::unexpected(result.error());
        auto sub = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (result.value().cmd == protocol::BslResponse::REP_VER) {
            if (std::chrono::steady_clock::now() > sub) {
                desynchronized_ = true;
                return std::unexpected(std::errc::timed_out);
            }
            auto next = read_reply(stop, std::chrono::milliseconds(1000));
            if (!next) return std::unexpected(next.error());
            result = std::move(next);
        }
        if (auto ok = expect_ack(result.value()); !ok)
            return std::unexpected(ok.error());
    }
    info_.stage = Stage::Fdl1;

    // KEEP_CHARGE (BSP set_chg_flag → chipram env): without it, u-boot's
    // sprdbat_init in download mode STOPS charging whenever the battery
    // sits above threshold — long flash sessions then run on battery
    // alone. Explicit command rejection is optional; a missing reply
    // cannot be ignored because a late ACK would poison the upload.
    if (profile_.keep_charge) if (auto chg = protocol::BslCodec::encode_hdlc_chk(
        static_cast<uint8_t>(protocol::BslCommand::CMD_OFF_CHG), {}, *rx_checksum_)) {
        auto reply = send_recv(*chg, stop, std::chrono::seconds(2));
        if (!reply) return std::unexpected(reply.error());
        if (!reply->payload.empty() || (reply->cmd != protocol::BslResponse::REP_ACK &&
            reply->cmd != protocol::BslResponse::REP_UNSUPPORTED_CMD &&
            reply->cmd != protocol::BslResponse::REP_INVALID_CMD &&
            reply->cmd != protocol::BslResponse::REP_UNKNOW_CMD))
            return std::unexpected(std::errc::protocol_error);
        if (log_diag_trace_enabled()) log_diag(reply->cmd == protocol::BslResponse::REP_ACK
            ? "{charge} KEEP_CHARGE acknowledged" : "{charge} KEEP_CHARGE unsupported");
    }
    transition.complete = true;
    return {};
}

// --------------------------------------------------------------- FDL upload

// Bare START/MIDST/END download — no EXEC. START/MIDST/END and EXEC are
// independent protocol commands; the CVE-2022-38694 flow needs them
// separate (park a payload in SRAM, execute it via a different address).
std::expected<void, std::errc>
SprdDevice::download_image(std::span<const uint8_t> image, uint32_t load_addr,
                            std::stop_token stop) {
    if (info_.stage == Stage::Fdl1)
        return download_image_add(image, load_addr, stop);
    if ((info_.stage != Stage::BootRom && info_.stage != Stage::Memory) || info_.is_sprd4)
        return std::unexpected(std::errc::not_supported);
    if (image.empty() || image.size() > UINT32_MAX ||
        image.size() > uint64_t(UINT32_MAX) + 1 - load_addr)
        return std::unexpected(std::errc::invalid_argument);
    // BSL does not advertise RAM receiver buffer size. Use a conservative
    // baseline rather than inferring the buffer layout from a SoC name.
    const size_t CHUNK = info_.stage == Stage::Memory
        ? std::min(profile_.bootrom_chunk, profile_.fdl1_receive_capacity - 6) : profile_.bootrom_chunk;

    auto start_enc = protocol::BslCodec::encode_start_data(
        load_addr, static_cast<uint32_t>(image.size()));
    if (!start_enc) return std::unexpected(std::errc::invalid_argument);
    auto result = send_recv(start_enc.value(), stop);
    if (!result) return std::unexpected(result.error());
    if (auto ok = expect_ack(result.value()); !ok)
        return std::unexpected(ok.error());
    TransferGuard transfer{desynchronized_};

    size_t off = 0;
    while (off < image.size()) {
        size_t chunk = std::min(CHUNK, image.size() - off);
        auto sent = send_midst(protocol::BslCodec::Chk::Crc16,
                               image.subspan(off, chunk), stop);
        if (!sent) return std::unexpected(sent.error());
        off += *sent;
    }

    auto end_enc = protocol::BslCodec::encode_end_data();
    if (!end_enc) return std::unexpected(std::errc::invalid_argument);
    result = send_recv(end_enc.value(), stop);
    if (!result) return std::unexpected(result.error());
    if (!result->payload.empty() || (result.value().cmd != protocol::BslResponse::REP_ACK &&
        result.value().cmd != protocol::BslResponse::REP_PHONE_SUCCEED))
        return std::unexpected(std::errc::protocol_error);
    transfer.complete = true;
    return {};
}

std::expected<void, std::errc>
SprdDevice::send_exec_raw(const std::vector<uint8_t>& exec_frame,
                           std::stop_token stop) {
    if (info_.is_sprd4 ||
        (info_.stage != Stage::BootRom && info_.stage != Stage::Memory && info_.stage != Stage::Fdl1))
        return std::unexpected(std::errc::not_supported);
    auto wr = write_frame(exec_frame, stop, std::chrono::milliseconds(500));
    if (!wr) return std::unexpected(wr.error());
    // An arbitrary binary has no known next command set. Retire this
    // session before receiving: exceptions must not expose the old stage.
    desynchronized_ = true;
    info_.stage = Stage::Offline;
    auto reply = read_reply(stop, std::chrono::milliseconds(800));
    if (reply) return expect_ack(*reply);
    if (reply.error() != std::errc::timed_out &&
        reply.error() != std::errc::no_such_device)
        return std::unexpected(reply.error());
    return {};
}

std::expected<void, std::errc>
SprdDevice::download_image_add(std::span<const uint8_t> image,
                                uint32_t load_addr, std::stop_token stop) {
    if (info_.stage != Stage::Fdl1 || info_.is_sprd4)
        return std::unexpected(std::errc::not_supported);
    if (image.empty() || image.size() > UINT32_MAX ||
        image.size() > uint64_t(UINT32_MAX) + 1 - load_addr)
        return std::unexpected(std::errc::invalid_argument);
    // Use the conservative baseline; known firmware buffer limits can be
    // supplied by library clients independently of chip identity.
    const size_t CHUNK = std::min(profile_.fdl1_chunk, profile_.fdl1_receive_capacity - 6);
    if (log_performance_enabled()) log_diag("{load} FDL1 receiver: payload<=" + std::to_string(CHUNK) +
        " B, encoded-frame<=" + std::to_string(profile_.fdl1_wire_limit) + " B");
    const auto checksum = profile_.fdl1_checksum == LoaderChecksum::Add
        ? protocol::BslCodec::Chk::Add : protocol::BslCodec::Chk::Crc16;

    auto start_enc = checksum == protocol::BslCodec::Chk::Add
        ? protocol::BslCodec::encode_start_data_add(load_addr, static_cast<uint32_t>(image.size()))
        : protocol::BslCodec::encode_start_data(load_addr, static_cast<uint32_t>(image.size()));
    if (!start_enc) return std::unexpected(std::errc::invalid_argument);
    auto result = send_recv(start_enc.value(), stop);
    if (!result) return std::unexpected(result.error());
    if (auto ok = expect_ack(result.value()); !ok)
        return std::unexpected(ok.error());
    TransferGuard transfer{desynchronized_};

    size_t off = 0;
    while (off < image.size()) {
        size_t chunk = std::min(CHUNK, image.size() - off);
        auto sent = send_midst(checksum,
                               image.subspan(off, chunk), stop);
        if (!sent) return std::unexpected(sent.error());
        off += *sent;
    }

    auto end_enc = protocol::BslCodec::encode_hdlc_chk(3, {}, checksum);
    if (!end_enc) return std::unexpected(std::errc::invalid_argument);
    result = send_recv(end_enc.value(), stop);
    if (!result) return std::unexpected(result.error());
    if (!result->payload.empty() || (result.value().cmd != protocol::BslResponse::REP_ACK &&
        result.value().cmd != protocol::BslResponse::REP_PHONE_SUCCEED))
        return std::unexpected(std::errc::protocol_error);
    transfer.complete = true;
    return {};
}

std::expected<void, std::errc>
SprdDevice::upload_binary(std::span<const uint8_t> image, uint32_t load_addr,
                          Stage after, std::stop_token stop) {
    // RAM download uses the current receiver's verified checksum.
    auto dl = after == Stage::Fdl2
        ? download_image_add(image, load_addr, stop)
        : download_image(image, load_addr, stop);
    if (!dl) return dl;
    std::expected<SprdDevice::Reply, std::errc> result;

    // The supplied ROMs' EXEC handlers use the START address, not a packet
    // address. Keep the established empty ROM EXEC. FDL1's existing addressed
    // form uses the current loader's verified checksum. Never try a second EXEC
    // encoding after silence: the first may already have transferred control.
    auto exec_enc = after == Stage::Fdl2
        ? (profile_.fdl1_checksum == LoaderChecksum::Add
            ? protocol::BslCodec::encode_exec_add(load_addr) : protocol::BslCodec::encode_exec(load_addr))
        : protocol::BslCodec::encode_exec_empty();
    if (!exec_enc) return std::unexpected(std::errc::invalid_argument);
    // A completed EXEC write may be followed by physical re-enumeration.
    // The caller must adopt the expected next stage before reporting success.
    const auto exec_timeout = transport::DEFAULT_TIMEOUT;
    auto sent = write_frame(*exec_enc, stop, exec_timeout);
    if (!sent) return std::unexpected(sent.error());
    TransferGuard transition{desynchronized_};
    // Only silence AFTER a delivered EXEC is expected. Do not swallow
    // write failures or consume the FDL2's one-shot DA_INFO unnoticed.
    // EXEC may ACK in the old dialect or immediately announce the new loader.
    // No failed/uncertain EXEC is resent. Silence only starts stage discovery.
    rx_checksum_.reset();
    result = read_frame(stop, std::chrono::milliseconds(500));
    if (!result) {
        const bool expected_silence =
            result.error() == std::errc::no_such_device ||
            result.error() == std::errc::timed_out;
        if (!expected_silence) {
            desynchronized_ = true;
            return std::unexpected(result.error());
        }
    } else if (after == Stage::Fdl2 &&
                result->cmd == protocol::BslResponse::REP_INCOMPATIBLE_PART) {
        adopt_da_info(result->payload);
    } else if (after == Stage::Fdl1 && result->cmd == protocol::BslResponse::REP_VER) {
        next_loader_version_ = std::move(*result);
    } else if (result->cmd != protocol::BslResponse::REP_ACK || !result->payload.empty()) {
        return std::unexpected(std::errc::protocol_error);
    }

    // EXEC delivery is not proof that the new loader is ready. Its
    // handshake/DA_INFO adoption is the only stage commit point.
    info_.stage = Stage::Offline;
    rx_checksum_ = after == Stage::Fdl1 && profile_.fdl1_checksum == LoaderChecksum::Crc16
        ? protocol::BslCodec::Chk::Crc16 : protocol::BslCodec::Chk::Add;
    transition.complete = true;
    return {};
}

std::expected<void, std::errc>
SprdDevice::upload_fdl1(std::span<const uint8_t> fdl1,
                         uint32_t load_addr,
                         std::stop_token stop) {
    if ((info_.stage != Stage::BootRom && info_.stage != Stage::Memory) || info_.is_sprd4)
        return std::unexpected(std::errc::not_supported);
    const auto audited = detail::audited_fdl1(fdl1);
    auto uploaded = upload_binary(fdl1, load_addr, Stage::Fdl1, stop);
    if (uploaded && audited && profile_.fdl1_receive_capacity == 0x300 &&
        profile_.fdl1_wire_limit == 1023 && profile_.fdl1_chunk == (4096 - DeviceProfile::frame_overhead) / 2) {
        // Applied only after upload/EXEC and only to unchanged automatic limits.
        // The caller carries this contract through physical re-enumeration;
        // the new loader must still pass its normal handshake.
        profile_.fdl1_receive_capacity = audited->receive_capacity;
        profile_.fdl1_wire_limit = audited->wire_limit;
        profile_.fdl1_chunk = audited->payload_limit;
        if (log_performance_enabled()) log_diag("{load} audited FDL1 image: receive=4096 B, wire<=4095 B");
    }
    return uploaded;
}

std::expected<void, std::errc>
SprdDevice::upload_fdl2(std::span<const uint8_t> fdl2,
                         uint32_t load_addr,
                         std::stop_token stop) {
    if (info_.stage != Stage::Fdl1 || info_.is_sprd4)
        return std::unexpected(std::errc::not_supported);
    auto result = upload_binary(fdl2, load_addr, Stage::Fdl2, stop);
    if (result) { detail::apply_fdl2_contract(fdl2, profile_);observed_={}; }
    return result;
}

// ----------------------------------------------------------- DA_INFO + misc

void SprdDevice::adopt_da_info(std::span<const uint8_t> payload) {
    fdl2_announced_ = true;
    // Forensic dump (once per fdl2 entry): the prebuilt fdl2's DA_INFO
    // is not guaranteed to match this BSP tree — observed on ud710: the
    // storage/flush TLVs parse as 0 on a device whose 0x0C reply says
    // eMMC, while disable_hdlc=1 matches the BSP. Only the raw bytes
    // distinguish "TLV absent" from "fixed-struct format mismatch".
    if (log_diag_trace_enabled()) {
        char buf[256];
        int n = std::snprintf(buf, sizeof buf, "{da} DA_INFO %zu B:",
                              payload.size());
        for (size_t i = 0; i < payload.size() && n + 3 < (int)sizeof buf;
             ++i)
            n += std::snprintf(buf + n, sizeof buf - n, " %02x",
                               payload[i]);
        uniflash::log_diag(buf);
    }
    info_.da = {};
    auto parsed = protocol::parse_da_info(payload);
    if (!parsed) return;
    info_.da.valid        = true;
    info_.da.disable_hdlc = parsed->disable_hdlc;
    info_.da.support_raw  = parsed->support_raw;
    info_.da.flush_kb     = parsed->flush_kb;
    info_.da.storage      = parsed->storage;
}

std::expected<void, std::errc>
SprdDevice::maybe_enable_raw_tx(std::stop_token stop) {
    if (raw_tx_) return {};
    if (!profile_.allow_disable_transcode || !transport_.supports_raw_frames()) {
        if (log_performance_enabled()) log_diag("{bsl} escaped TX: backend or policy requires framing");
        return {};
    }
    if (!info_.da.valid || !info_.da.disable_hdlc) {
        if (log_performance_enabled()) log_diag(info_.da.valid
            ? "{bsl} escaped TX: loader did not advertise disable-HDLC"
            : "{bsl} escaped TX: DA_INFO format not recognized or unavailable");
        return {};
    }
    auto enc = protocol::BslCodec::encode_disable_transcode();
    if (!enc) return std::unexpected(enc.error());
    auto r = send_recv(enc.value(), stop);
    if (!r) return std::unexpected(r.error());
    if (r.value().cmd == protocol::BslResponse::REP_ACK && r->payload.empty()) {
        raw_tx_ = true;
        if (log_performance_enabled()) log_diag("{bsl} raw TX enabled");
    } else if (r->payload.empty() && (r->cmd == protocol::BslResponse::REP_UNSUPPORTED_CMD ||
                r->cmd == protocol::BslResponse::REP_INVALID_CMD ||
                r->cmd == protocol::BslResponse::REP_UNKNOW_CMD)) {
        if (log_performance_enabled()) log_diag("{bsl} raw TX unavailable; using escaped frames");
    } else {
        desynchronized_ = true;
        return std::unexpected(std::errc::protocol_error);
    }
    return {};
}

std::expected<void, std::errc>
SprdDevice::expect_ack(const Reply& r) {
    if (r.cmd == protocol::BslResponse::REP_ACK && r.payload.empty()) return {};
    // Reuse the single-response rejection classifier. Unrelated replies and
    // malformed ACKs must not leave a delayed ACK for the next command.
    if (r.cmd == protocol::BslResponse::REP_ACK) desynchronized_ = true;
    else {
        using enum protocol::BslResponse;
        const bool completed_failure = r.payload.empty() &&
            (r.cmd == REP_WRITE_ERROR || r.cmd == REP_DOWN_SIZE_ERROR ||
             r.cmd == REP_DOWN_DEST_ERROR || r.cmd == REP_DOWN_EARLY_END);
        if (!completed_failure) (void)expect_query_reply(r, REP_ACK, "ACK");
    }
    // Retain the exact reply as always-on diagnostic context. The command
    // layer owns the single operation-failure record.
    char b[96];
    std::snprintf(b, sizeof b, "{bsl} device reply: %s (0x%02x)",
                  protocol::BslCodec::reply_name(
                      static_cast<uint8_t>(r.cmd)),
                  static_cast<unsigned>(
                      static_cast<uint8_t>(r.cmd)));
    uniflash::log_diag(b);
    return std::unexpected(std::errc::protocol_error);
}

std::expected<void, std::errc>
SprdDevice::expect_query_reply(const Reply& reply, protocol::BslResponse expected,
                             const char* query) {
    if (reply.cmd == expected) return {};
    const bool unsupported = reply.payload.empty() &&
        (reply.cmd == protocol::BslResponse::REP_UNSUPPORTED_CMD ||
         reply.cmd == protocol::BslResponse::REP_UNKNOW_CMD || reply.cmd == protocol::BslResponse::REP_INVALID_CMD);
    if (!unsupported || log_diag_trace_enabled())
        log_diagf("{query} %s expected 0x%02x, received %s (0x%02x), payload=%zu B",
        query, static_cast<unsigned>(expected),
        protocol::BslCodec::reply_name(static_cast<uint8_t>(reply.cmd)),
        static_cast<unsigned>(reply.cmd), reply.payload.size());
    // Single-response queries and RAM diagnostics use this classifier. These
    // empty negative replies terminate the request; they are not lost sync.
    if (reply.payload.empty()) {
        using enum protocol::BslResponse;
        switch (reply.cmd) {
        case REP_UNSUPPORTED_CMD: case REP_UNKNOW_CMD: case REP_INVALID_CMD:
            return std::unexpected(std::errc::not_supported);
        case REP_OPERATION_FAILED: case REP_VERIFY_ERROR: case REP_ERROR_CHECKSUM:
        case REP_CHECKSUM_DIFF: case REP_PHONE_NOT_ENOUGH_MEM:
        case REP_UNKNOWN_DEVICE: case REP_INVALID_DEVICE_SIZE:
        case REP_NOT_ENABLE_WRITE:
            return std::unexpected(std::errc::protocol_error);
        default: break;
        }
    }
    // An unrelated data frame or stray ACK cannot stand in for this reply.
    desynchronized_ = true;
    return std::unexpected(std::errc::protocol_error);
}

std::expected<void, std::errc>
SprdDevice::resync_fdl2(std::chrono::milliseconds boot_wait,
                           std::stop_token stop) {
    invalidate_layout();
    if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    if (desynchronized_) return std::unexpected(std::errc::state_not_recoverable);
    if (info_.stage != Stage::Offline && info_.stage != Stage::Fdl2)
        return std::unexpected(std::errc::not_supported);
    rx_checksum_ = protocol::BslCodec::Chk::Add;
    if (fdl2_announced_) {
        info_.stage = Stage::Fdl2;
        return maybe_enable_raw_tx(stop);
    }
    // Stage discovery is also used after reopening an existing FDL2
    // session. Ordinary FDL2 operations, unlike this probe, require FDL2.
    auto deadline = std::chrono::steady_clock::now() + boot_wait;
    while (std::chrono::steady_clock::now() < deadline) {
        if (stop.stop_requested())
            return std::unexpected(std::errc::interrupted);
        auto r = read_frame(stop, std::chrono::milliseconds(1000));
        if (!r) {
            if (r.error() == std::errc::timed_out) continue;
            return std::unexpected(r.error());
        }
        if (r.value().cmd == protocol::BslResponse::REP_INCOMPATIBLE_PART) {
            adopt_da_info(r.value().payload);
            info_.stage = Stage::Fdl2;
            return maybe_enable_raw_tx(stop);
        }
        // Some other frame — skip it and keep waiting for DA_INFO.
    }
    log_diag("{bsl} FDL2 announcement missing; framing is unknown");
    return std::unexpected(std::errc::not_supported);
}

std::expected<void, std::errc>
SprdDevice::sprd4_enter_fdl2(std::stop_token stop) {
    if (!info_.is_sprd4 || info_.stage != Stage::BootRom)
        return std::unexpected(std::errc::not_supported);

    auto exec_enc = protocol::BslCodec::encode_exec(0);
    if (!exec_enc) return std::unexpected(std::errc::invalid_argument);

    // EXEC #1: the stub ACKs and switches to its "FDL1 role", then blocks
    // inside adl_send_version until it sees a 0x7E.
    auto r1 = send_recv(exec_enc.value(), stop);
    if (!r1) return std::unexpected(r1.error());
    if (auto ok = expect_ack(r1.value()); !ok)
        return std::unexpected(ok.error());
    TransferGuard transition{desynchronized_};

    std::vector<uint8_t> flag{protocol::HDLC_FLAG};
    rx_checksum_ = protocol::BslCodec::Chk::Add;
    auto wr = write_frame(flag, stop, std::chrono::milliseconds(500));
    if (!wr) return std::unexpected(wr.error());
    auto ver = read_reply(stop, std::chrono::milliseconds(2000));
    if (!ver) return std::unexpected(ver.error());
    if (ver.value().cmd != protocol::BslResponse::REP_VER)
        return std::unexpected(std::errc::protocol_error);

    // EXEC #2 must be in the ADD form: EXEC #1 flipped act_as_romcode to
    // 0 inside autodloader_exec, and the packet layer validates frm_chk
    // from then on (u-boot dloader packet.c). The handler calls
    // do_download() with NO ACK — silence is the design, not an error —
    // and do_download reuses the SAME USB session (packet-pool re-init
    // only, no re-enumeration): keep the handle and resync on it.
    auto exec2 = protocol::BslCodec::encode_exec_add(0);
    if (!exec2) return std::unexpected(std::errc::invalid_argument);
    // No ACK is defined here. Let resync_fdl2 consume DA_INFO instead
    // of accidentally discarding it as an EXEC reply.
    auto r2 = write_frame(*exec2, stop, std::chrono::milliseconds(500));
    if (!r2)
        return std::unexpected(r2.error());
    info_.stage = Stage::Offline;
    transition.complete = true;
    return {};
}

std::expected<void, std::errc>
SprdDevice::enable_write_flash(std::stop_token stop) {
    if (info_.stage != Stage::Fdl2)
        return std::unexpected(std::errc::not_supported);
    auto enc = encode_fdl2_command(protocol::BslCommand::CMD_ENABLE_WRITE_FLASH);
    if (!enc) return std::unexpected(std::errc::invalid_argument);
    auto result = send_recv(enc.value(), stop);
    if (!result) return std::unexpected(result.error());
    if (result->cmd == protocol::BslResponse::REP_UNSUPPORTED_CMD)
        return std::unexpected(std::errc::not_supported);
    if (auto ok = expect_ack(result.value()); !ok)
        return std::unexpected(ok.error());
    return {};
}

std::expected<void, std::errc>
SprdDevice::set_first_mode(uint32_t mode, std::stop_token stop) {
    if (info_.stage != Stage::Fdl2)
        return std::unexpected(std::errc::not_supported);
    // Wire value is one byte. Mode meanings belong to the device firmware;
    // do not restrict them to one BSP's table or truncate the caller's value.
    if (mode > 0xff)
        return std::unexpected(std::errc::invalid_argument);
    const uint8_t payload = static_cast<uint8_t>(mode);
    auto enc = encode_fdl2_command(protocol::BslCommand::CMD_SET_FIRST_MODE,
                                  std::span(&payload, 1));
    if (!enc) return std::unexpected(std::errc::invalid_argument);
    auto result = send_recv(enc.value(), stop);
    if (!result) return std::unexpected(result.error());
    if (auto ok = expect_ack(result.value()); !ok)
        return std::unexpected(ok.error());
    return {};
}

std::expected<void, std::errc>
SprdDevice::set_debuginfo(const std::string& info, std::stop_token stop) {
    if (info_.stage != Stage::Fdl2)
        return std::unexpected(std::errc::not_supported);
    // The loader decides its string limits; retain the current frame bound.
    if (info.size() > protocol::MAX_PAYLOAD_SIZE || info.find('\0') != std::string::npos)
        return std::unexpected(std::errc::invalid_argument);
    auto enc = encode_fdl2_command(protocol::BslCommand::CMD_SET_DEBUGINFO,
        std::span<const uint8_t>{reinterpret_cast<const uint8_t*>(info.data()),
                                 info.size()});
    if (!enc) return std::unexpected(std::errc::invalid_argument);
    auto result = send_recv(enc.value(), stop);
    if (!result) return std::unexpected(result.error());
    if (auto ok = expect_ack(result.value()); !ok)
        return std::unexpected(ok.error());
    return {};
}

std::expected<McpInfo, std::errc>
SprdDevice::read_mcp_type(std::stop_token stop) {
    if (info_.stage != Stage::Fdl2)
        return std::unexpected(std::errc::not_supported);
    // Capability is firmware-dependent; DA storage alone is not a reliable
    // support matrix for prebuilt loaders. A timeout retires the session like
    // any other uncertain command, rather than consuming a later ACK as proof.
    auto enc = encode_fdl2_command(protocol::BslCommand::CMD_READ_MCP_TYPE);
    if (!enc) return std::unexpected(std::errc::invalid_argument);
    auto result = send_recv(enc.value(), stop);
    if (!result) return std::unexpected(result.error());
    if (auto accepted = expect_query_reply(*result, protocol::BslResponse::REP_READ_MCP_TYPE, "MCP"); !accepted)
        return std::unexpected(accepted.error());
    const auto& p = result.value().payload;
    // Three big-endian words on the wire: flag, pagesize, blocksize.
    if (p.size() < 12) return std::unexpected(std::errc::message_size);
    auto be32 = [&p](size_t o) {
        return (static_cast<uint32_t>(p[o]) << 24) |
               (static_cast<uint32_t>(p[o + 1]) << 16) |
               (static_cast<uint32_t>(p[o + 2]) << 8) |
               static_cast<uint32_t>(p[o + 3]);
    };
    McpInfo m;
    m.flag       = be32(0);
    m.page_size  = be32(4);
    m.block_size = be32(8);
    return m;
}

std::expected<std::pair<uint32_t, uint32_t>, std::errc>
SprdDevice::read_flash_type(std::stop_token stop) {
    if (info_.stage != Stage::Fdl2)
        return std::unexpected(std::errc::not_supported);
    if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    if (observed_.flash_type_query==Capability::Unsupported || profile_.flash_type_query==Capability::Unsupported) return std::unexpected(std::errc::not_supported);
    auto enc = encode_fdl2_command(protocol::BslCommand::CMD_READ_FLASH_TYPE);
    if (!enc) return std::unexpected(std::errc::invalid_argument);
    auto result = send_recv(enc.value(), stop);
    if (!result) return std::unexpected(result.error());
    if (auto accepted = expect_query_reply(*result, protocol::BslResponse::REP_READ_FLASH_TYPE, "FLASH_TYPE"); !accepted) {
        if (accepted.error() == std::errc::not_supported) observed_.flash_type_query=Capability::Unsupported;
        return std::unexpected(accepted.error());
    }
    const auto& p = result.value().payload;
    // BSP FLASH_TYPE: {mid=DDR MB, did=eMMC/UFS MB, eid, flag}, each
    // 4-byte word swapped on the wire (same convention as MCP_TYPE).
    // Measured on ud710: first word reads 0x1000 = 4096 MB DDR.
    if (p.size() < 4 || p.size() > 16 || p.size() % 4) return std::unexpected(std::errc::message_size);
    observed_.flash_type_query=Capability::Supported;
    auto word = [&](size_t i) {
        return (static_cast<uint32_t>(p[i]) << 24) |
               (static_cast<uint32_t>(p[i + 1]) << 16) |
               (static_cast<uint32_t>(p[i + 2]) << 8) |
               static_cast<uint32_t>(p[i + 3]);
    };
    info_.chip.ddr_mb = word(0);
    if (p.size() >= 8) info_.chip.emmc_mb = word(4);
    return std::make_pair(info_.chip.ddr_mb, info_.chip.emmc_mb);
}

std::expected<bool, std::errc>
SprdDevice::ddr_verify(std::stop_token stop) {
    // fdl_command.c ddr_verify_start: registered in the FDL1 only.
    if (info_.stage != Stage::Fdl1 || info_.is_sprd4)
        return std::unexpected(std::errc::not_supported);
    auto enc = protocol::BslCodec::encode_hdlc_chk(
        static_cast<uint8_t>(protocol::BslCommand::CMD_DDR_VERIFY), {},
        profile_.fdl1_checksum == LoaderChecksum::Add ? protocol::BslCodec::Chk::Add : protocol::BslCodec::Chk::Crc16);
    if (!enc) return std::unexpected(std::errc::invalid_argument);
    auto result = send_recv(enc.value(), stop);
    if (!result) return std::unexpected(result.error());
    if (!result->payload.empty()) {
        desynchronized_ = true;
        return std::unexpected(std::errc::message_size);
    }
    if (result.value().cmd == protocol::BslResponse::REP_DDR_VERIFY_FAIL)
        return false;
    auto accepted = expect_query_reply(*result, protocol::BslResponse::REP_ACK, "DDR verify");
    if (!accepted) return std::unexpected(accepted.error());
    return true;
}

std::expected<bool, std::errc>
SprdDevice::ddr_sr_test(uint32_t timeout_ms, std::stop_token stop) {
    if (info_.stage != Stage::Fdl1 || info_.is_sprd4)
        return std::unexpected(std::errc::not_supported);
    const uint8_t payload[]{static_cast<uint8_t>(timeout_ms), static_cast<uint8_t>(timeout_ms >> 8),
        static_cast<uint8_t>(timeout_ms >> 16), static_cast<uint8_t>(timeout_ms >> 24)};
    auto enc = protocol::BslCodec::encode_hdlc_chk(
        static_cast<uint8_t>(protocol::BslCommand::CMD_DDR_SR_TEST), payload,
        profile_.fdl1_checksum == LoaderChecksum::Add ? protocol::BslCodec::Chk::Add : protocol::BslCodec::Chk::Crc16);
    if (!enc) return std::unexpected(std::errc::invalid_argument);
    auto result = send_recv(enc.value(), stop,
        std::chrono::milliseconds(uint64_t(timeout_ms) + 5000));
    if (!result) return std::unexpected(result.error());
    if (!result->payload.empty()) {
        desynchronized_ = true;
        return std::unexpected(std::errc::message_size);
    }
    if (result.value().cmd == protocol::BslResponse::REP_DDR_TEST_FAIL)
        return false;
    auto accepted = expect_query_reply(*result, protocol::BslResponse::REP_ACK, "DDR self-refresh");
    if (!accepted) return std::unexpected(accepted.error());
    return true;
}

std::expected<void, std::errc>
SprdDevice::write_datetime(std::span<const uint8_t> datetime,
                           std::stop_token stop) {
    // dl_record_pacdatetime: common_raw_write(miscdata, size, 0, 0x81400).
    if (info_.stage != Stage::Fdl2)
        return std::unexpected(std::errc::not_supported);
    if (datetime.empty() || datetime.size() > protocol::MAX_PAYLOAD_SIZE)
        return std::unexpected(std::errc::invalid_argument);
    auto enc = encode_fdl2_command(protocol::BslCommand::CMD_WRITE_DATETIME, datetime);
    if (!enc) return std::unexpected(std::errc::invalid_argument);
    auto result = send_recv(enc.value(), stop);
    if (!result) return std::unexpected(result.error());
    if (auto ok = expect_ack(result.value()); !ok)
        return std::unexpected(ok.error());
    return {};
}

std::expected<uint8_t, std::errc>
SprdDevice::check_nv_type(std::stop_token stop) {
    // dl_cmd_check_NV_type: replies 0xB5 with the DRV_RF type as a
    // 4-byte LE payload (0xff = no RF part).
    if (info_.stage != Stage::Fdl2)
        return std::unexpected(std::errc::not_supported);
    auto enc = encode_fdl2_command(protocol::BslCommand::CMD_CHECK_NV_TYPE);
    if (!enc) return std::unexpected(std::errc::invalid_argument);
    auto result = send_recv(enc.value(), stop);
    if (!result) return std::unexpected(result.error());
    if (auto accepted = expect_query_reply(*result, protocol::BslResponse::REP_CHECK_NV_TYPE, "NV_TYPE"); !accepted)
        return std::unexpected(accepted.error());
    if (result.value().payload.size() != 4)
        return std::unexpected(std::errc::message_size);
    return result.value().payload.front();
}

std::expected<void, std::errc>
SprdDevice::end_process(std::stop_token stop) {
    // dl_cmd_end_process: a pure ACK — effectively a link ping.
    if (info_.stage != Stage::Fdl2)
        return std::unexpected(std::errc::not_supported);
    auto enc = encode_fdl2_command(protocol::BslCommand::CMD_END_PROCESS);
    if (!enc) return std::unexpected(std::errc::invalid_argument);
    auto result = send_recv(enc.value(), stop);
    if (!result) return std::unexpected(result.error());
    if (auto ok = expect_ack(result.value()); !ok)
        return std::unexpected(ok.error());
    return {};
}

std::expected<bool, std::errc>
SprdDevice::root_flag(std::stop_token stop) {
    if (info_.stage != Stage::Fdl2)
        return std::unexpected(std::errc::not_supported);
    auto enc = encode_fdl2_command(protocol::BslCommand::CMD_CHECK_ROOTFLAG);
    if (!enc) return std::unexpected(std::errc::invalid_argument);
    auto result = send_recv(enc.value(), stop);
    if (!result) return std::unexpected(result.error());
    // dl_cmd_check_rootflag: plain ACK = not rooted, 0xA7 = rooted;
    // anything else is a protocol failure, not silence.
    const bool rooted = result->cmd == protocol::BslResponse::REP_PHONE_ROOTFLAG;
    if (auto accepted = expect_query_reply(*result, rooted ? protocol::BslResponse::REP_PHONE_ROOTFLAG :
        protocol::BslResponse::REP_ACK, "ROOT_FLAG"); !accepted)
        return std::unexpected(accepted.error());
    if (!result->payload.empty()) return std::unexpected(std::errc::message_size);
    return rooted;
}

// ------------------------------------------------------------ partition ops

std::expected<void, std::errc>
SprdDevice::write_partition(const FlashPartition& part,
                              std::stop_token stop) {
    if (info_.stage != Stage::Fdl2)
        return std::unexpected(std::errc::not_supported);
    if (part.data.empty() || part.name.empty() || part.name.size() > 35 ||
        part.name.find('\0') != std::string::npos || part.offset != 0 ||
        (part.size != 0 && part.size != part.data.size()))
        return std::unexpected(std::errc::invalid_argument);
    const io::Reader source = [&part](uint64_t offset, std::span<uint8_t> bytes,
                                      std::stop_token token) -> std::expected<void, std::errc> {
        if (token.stop_requested()) return std::unexpected(std::errc::interrupted);
        if (offset > part.data.size() || bytes.size() > part.data.size() - offset)
            return std::unexpected(std::errc::message_size);
        std::copy_n(part.data.data() + offset, bytes.size(), bytes.data());
        return {};
    };
    return write_partition_stream(part.name, part.data.size(), source, stop);
}

std::expected<void, std::errc>
SprdDevice::write_partition_stream(const std::string& name, uint64_t size,
                                  const io::Reader& source, std::stop_token stop, const io::TransferObserver& progress) {
    // Never accidentally send a raw disk header through the NV payload route,
    // including when XML incorrectly labels an NV target as CODE2.
    if (nv_pair(name)) {
        write_timings_ = {};
        return std::unexpected(std::errc::not_supported);
    }
    return write_framed_stream(name, size, source, stop, progress);
}

std::expected<void,std::errc> SprdDevice::write_package_stream(const std::string& name,uint64_t size,
    const io::Reader& source,bool wide,std::stop_token stop,const io::TransferObserver& progress) {
    if(nv_pair(name)) return std::unexpected(std::errc::not_supported);
    return write_framed_stream(name,size,source,stop,progress,{},wide);
}
std::expected<void,std::errc> SprdDevice::send_ext_table(std::span<const uint8_t> table,std::stop_token stop) {
    if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    if(info_.stage!=Stage::Fdl2) return std::unexpected(std::errc::not_supported);
    if(table.empty() || table.size()>DeviceProfile::raw_payload_limit) return std::unexpected(std::errc::message_size);
    auto encoded=encode_fdl2_command(static_cast<protocol::BslCommand>(0x14),table);
    if(!encoded) return std::unexpected(encoded.error());
    invalidate_layout();
    auto result=send_recv(*encoded,stop,std::chrono::seconds(15));
    if(!result) return std::unexpected(result.error());
    return expect_ack(*result);
}
std::expected<void, std::errc> SprdDevice::write_nv(const std::string& primary,
    std::span<const uint8_t> payload, std::stop_token stop, const io::TransferObserver& progress) {
    if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    if(info_.stage!=Stage::Fdl2) return std::unexpected(std::errc::not_supported);
    const auto* pair = nv_pair(primary);
    if (!pair || pair->primary != primary || !nv_payload_size(profile_.nv_dialect) ||
        payload.size() != nv_payload_size(profile_.nv_dialect)) return std::unexpected(std::errc::not_supported);
    return write_logical_nv(primary,payload,stop,progress);
}
std::expected<void,std::errc> SprdDevice::write_logical_nv(const std::string& primary,
    std::span<const uint8_t> payload,std::stop_token stop,const io::TransferObserver& progress) {
    const auto* pair=nv_pair(primary);
    if(!pair || pair->primary!=primary || payload.empty() || payload.size()>16*1024*1024)
        return std::unexpected(std::errc::invalid_argument);
    // Copy before checksum: caller memory must not change between checksum and
    // the final MIDST, which can commit both NV copies before END_DATA.
    const std::vector<uint8_t> frozen(payload.begin(), payload.end());
    uint32_t sum = 0;
    for (auto byte : frozen) sum += byte;
    const io::Reader source = [&](uint64_t at, std::span<uint8_t> bytes, std::stop_token token)
        -> std::expected<void, std::errc> {
        if (token.stop_requested()) return std::unexpected(std::errc::interrupted);
        if (at > frozen.size() || bytes.size() > frozen.size() - at) return std::unexpected(std::errc::message_size);
        std::copy_n(frozen.begin() + at, bytes.size(), bytes.begin()); return {};
    };
    return write_framed_stream(primary, frozen.size(), source, stop, progress, sum);
}

std::expected<void, std::errc> SprdDevice::write_framed_stream(const std::string& name, uint64_t size,
    const io::Reader& source, std::stop_token stop, const io::TransferObserver& progress,
    std::optional<uint32_t> nv_checksum,bool package_wide,std::optional<uint32_t> address,AddressWordOrder order,size_t address_chunk,bool force_framed) {
    invalidate_layout();
    write_timings_ = {};
    const auto operation_start = std::chrono::steady_clock::now();
    if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    if (info_.stage != Stage::Fdl2) return std::unexpected(std::errc::not_supported);
    if (!source || !size || !valid_partition_name(name))
        return std::unexpected(std::errc::invalid_argument);
    if(address && (!address_chunk || address_chunk>(raw_tx_?profile_.raw_write_chunk:profile_.escaped_write_chunk)))
        return std::unexpected(std::errc::message_size);
    // Fast path: when FDL2 advertises raw-data support and the image is
    // >= one HDLC packet, use the whole-file raw channel (2MB chunks).
    // Otherwise fall back to the legacy 0x01/0x02/0x03 per-packet path.
    if (!force_framed && !address && !package_wide && !nv_checksum && profile_.allow_whole_file_raw && info_.da.valid && info_.da.support_raw && size >= protocol::MAX_PKT_SIZE) {
        if (log_diag_trace_enabled()) log_diag("{write} whole-file raw channel");
        return write_raw_stream(name, size, source, stop, progress);
    }
    // Factory-mirror write form (spd_dump verbose-2 trace: full 550MB
    // vendor write observed frame-by-frame): START in the BIT32 form
    // (name72 + size u32 LE, wire `7e 00 01 00 4c ...`), MIDST chunks of
    // 0xF800, strict one-ACK-per-frame alternation, END — and NO
    // pre-erase (zero 0x0a frames in the whole successful session; the
    // eMMC FTL handles erase-on-write internally). The FDL2 validates
    // every frame with frm_chk (ADD) — the partition-open START must be
    // in the ADD form.
    if (size > UINT32_MAX && !profile_.framed_write_u64 && !package_wide)
        return std::unexpected(std::errc::file_too_large);
    auto payload = (package_wide || size > UINT32_MAX)
        ? protocol::BslCodec::make_partition_payload(name, size)
        : protocol::BslCodec::make_partition_payload32(name, static_cast<uint32_t>(size));
    if (nv_checksum) for (unsigned shift=0; shift<32; shift+=8)
        payload.push_back(static_cast<uint8_t>(*nv_checksum >> shift));
    if(address) {
        if(size>UINT32_MAX || size>uint64_t(UINT32_MAX)+1-*address || (size&1) ||
            (order!=AddressWordOrder::Little && order!=AddressWordOrder::Big))
            return std::unexpected(std::errc::invalid_argument);
        payload.clear();
        for(uint32_t value:{*address,static_cast<uint32_t>(size)})
            for(unsigned i=0;i<4;++i) payload.push_back(static_cast<uint8_t>(value>>(order==AddressWordOrder::Little?i*8:(3-i)*8)));
    }
    auto start_enc = encode_fdl2_command(protocol::BslCommand::CMD_START_DATA, payload);
    if (!start_enc) return std::unexpected(start_enc.error());
    auto end_enc = encode_fdl2_command(protocol::BslCommand::CMD_END_DATA);
    if (!end_enc) return std::unexpected(end_enc.error());
    if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);

    // Wide first-contact window: the ACK is normally instant; 15s only
    // guards against device-side housekeeping right after the open.
    auto result = [&] {
        WaitProgress waiting("write: " + name + ", opening");
        // Once submitted, consume the entire reply before handling Ctrl+C.
        return send_recv(start_enc.value(), {}, std::chrono::seconds(15));
    }();
    if (!result) return std::unexpected(result.error());
    if (auto ok = expect_ack(result.value()); !ok)
        return std::unexpected(ok.error());
    TransferGuard transfer{desynchronized_};

    // Escaped frames need worst-case doubling room. Raw frames must
    // remain one intact transfer, including the final partial chunk.
    const size_t CHUNK = address?address_chunk:
        raw_tx_ ? profile_.raw_write_chunk : profile_.escaped_write_chunk;
    const bool measure = log_performance_enabled();
    if (measure) log_diag("{write} target=" + name + " mode=" +
        (raw_tx_ ? "raw-frame" : "escaped-frame") + " chunk=" + std::to_string(CHUNK) + " B");
    uint64_t off = 0;
    std::vector<uint8_t> buffer(CHUNK);
    const auto t0 = std::chrono::steady_clock::now();
    write_timings_.open_seconds = std::chrono::duration<double>(t0 - operation_start).count();
    auto next = t0 + std::chrono::milliseconds(500);
    const auto cancel_write = [&](std::errc cause = std::errc::interrupted) -> std::expected<void, std::errc> {
        const auto failure=exchange_;
        write_timings_.cancelled = cause == std::errc::interrupted;
        write_timings_.acknowledged_bytes = off;
        log_clear_progress_line();
        const auto closing = std::chrono::steady_clock::now();
        write_timings_.transfer_seconds = std::chrono::duration<double>(closing - t0).count();
        try {
            WaitProgress waiting("write: " + name + ", cancelling with END_DATA");
            auto closed = send_recv(*end_enc, {}, std::chrono::seconds(60));
            if (closed && closed->cmd == protocol::BslResponse::REP_ACK && closed->payload.empty()) {
                transfer.complete = true;
                write_timings_.cancel_end_acked = true;
            } else if (closed) {
                // A complete operation failure is a consumed END response,
                // not a lost frame. The synchronous framed handler has
                // returned to command dispatch; a new START can replace the
                // incomplete download state. Do not apply this to whole-file
                // raw, unsupported END, stray data or malformed replies.
                if (closed->payload.empty() &&
                    (closed->cmd == protocol::BslResponse::REP_OPERATION_FAILED ||
                     closed->cmd == protocol::BslResponse::REP_DOWN_EARLY_END ||
                     closed->cmd == protocol::BslResponse::REP_WRITE_ERROR)) {
                    transfer.complete = true;
                    write_timings_.cancel_end_rejected = true;
                }
                log_diagf("{write} cancellation END rejected: %s (0x%02x)",
                    protocol::BslCodec::reply_name(static_cast<uint8_t>(closed->cmd)),
                    static_cast<unsigned>(static_cast<uint8_t>(closed->cmd)));
            }
        } catch (...) {
            desynchronized_ = true;
        }
        cleanup_=exchange_;exchange_=failure;
        write_timings_.sync_seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - closing).count();
        // An early END ACK is not evidence that the intended image was written.
        return std::unexpected(cause);
    };
    if (progress) progress({0, size, 0});
    else report_progress("write: " + name, 0, size, t0, next);
    while (off < size) {
        if (stop.stop_requested()) return cancel_write();
        const size_t chunk = static_cast<size_t>(std::min<uint64_t>(CHUNK, size - off));
        auto bytes = std::span(buffer).first(chunk);
        const auto source_start = measure ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
        std::expected<void, std::errc> loaded;
        try { loaded = source(off, bytes, stop); }
        catch (...) { loaded = std::unexpected(std::errc::io_error); }
        if (measure) write_timings_.source_seconds += std::chrono::duration<double>(std::chrono::steady_clock::now() - source_start).count();
        if (!loaded) {
            return cancel_write(loaded.error());
        }
        if (stop.stop_requested()) return cancel_write();
        // Binary payload must match the device's parser mode: raw
        // (un-escaped) after 0x21 DISABLE_TRANSCODE, escaped otherwise.
        // START and END also follow the negotiated mode: binary size or
        // checksum bytes can require escaping even with ASCII names.
        const auto encode_start = measure ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
        auto midst_enc = encode_fdl2_command(protocol::BslCommand::CMD_MIDST_DATA,
            bytes);
        if (measure) write_timings_.encode_seconds += std::chrono::duration<double>(std::chrono::steady_clock::now() - encode_start).count();
        if (!midst_enc) return std::unexpected(midst_enc.error());
        if (stop.stop_requested()) return cancel_write();
        // Split into halves with distinct errors: "write stalled" =
        // the OUT endpoint dead (the device's rx race); "ack stalled"
        // = the device stopped replying (its flush/backstage wait).
        // 60s covers any legitimate buffer-boundary flush.
        const auto t_ws = std::chrono::steady_clock::now();
        // First-device-write latency is visible even before the first ACK.
        std::unique_ptr<WaitProgress> first_wait;
        if (off == 0) first_wait = std::make_unique<WaitProgress>("write: " + name + ", waiting for first ACK");
        auto wr = write_frame(*midst_enc, {}, std::chrono::seconds(60));
        if (measure) write_timings_.send_seconds += std::chrono::duration<double>(std::chrono::steady_clock::now() - t_ws).count();
        if (!wr) {
            if (wr.error() != std::errc::interrupted) log_diagf("{write} send failed after %lld ms "
                      "(chunk=%zu, done=%llu B): %s",
                      static_cast<long long>(
                          std::chrono::duration_cast<std::chrono::milliseconds>(
                              std::chrono::steady_clock::now() - t_ws).count()),
                       static_cast<size_t>(off / CHUNK),
                      static_cast<unsigned long long>(off),
                      std::strerror(static_cast<int>(wr.error())));
            return std::unexpected(wr.error());
        }
        const auto t_rs = std::chrono::steady_clock::now();
        result = read_reply({}, std::chrono::seconds(60));
        if (measure) {
            const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - t_rs).count();
            write_timings_.ack_seconds += elapsed;
            write_timings_.max_ack_seconds = std::max(write_timings_.max_ack_seconds, elapsed);
            if (elapsed >= 0.1) {
                ++write_timings_.slow_ack_count;
                write_timings_.slow_ack_seconds += elapsed;
                log_diag("{write} slow ACK: " + name + " offset=" + std::to_string(off + chunk) +
                    " B, wait=" + format_duration(elapsed));
            }
        }
        if (!result) {
            if (result.error() != std::errc::interrupted) log_diagf("{write} ACK failed after %lld ms "
                      "(chunk=%zu, done=%llu B): %s",
                      static_cast<long long>(
                          std::chrono::duration_cast<std::chrono::milliseconds>(
                              std::chrono::steady_clock::now() - t_rs).count()),
                       static_cast<size_t>(off / CHUNK),
                      static_cast<unsigned long long>(off),
                      std::strerror(static_cast<int>(result.error())));
            return std::unexpected(result.error());
        }
        if (auto ok = expect_ack(result.value()); !ok)
            return std::unexpected(ok.error());
        first_wait.reset();
        if (off == 0) next = std::chrono::steady_clock::now();
        off += chunk;
        write_timings_.acknowledged_bytes = off;
        if (stop.stop_requested()) return cancel_write();
        // Full speed — no host-side pacing: the device's speedup path
        // has built-in backpressure (a buffer-boundary frame blocks in
        // common_query_backstage until the other 2MB alter buffer
        // drains, throttling the ACK cadence to the eMMC rate). Speed
        // was never the killer; the exact-512-multiple transfer wedge
        // was (see bulk_write's ZLP invariant).
        if (progress) progress({off, size, std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count()});
        else report_progress("write: " + name, off, size, t0, next);
    }
    log_clear_progress_line();
    const auto sync_start = std::chrono::steady_clock::now();
    write_timings_.transfer_seconds = std::chrono::duration<double>(sync_start - t0).count();

    if (stop.stop_requested()) return cancel_write();
    result = [&] {
        WaitProgress waiting("write: " + name + ", waiting for final ACK");
        return send_recv(end_enc.value(), {}, std::chrono::seconds(60));
    }();
    if (stop.stop_requested()) write_timings_.cancelled = true;
    if (!result) return std::unexpected(result.error());
    if (stop.stop_requested() && result->payload.empty() &&
        (result->cmd == protocol::BslResponse::REP_OPERATION_FAILED ||
         result->cmd == protocol::BslResponse::REP_DOWN_EARLY_END ||
         result->cmd == protocol::BslResponse::REP_WRITE_ERROR)) {
        transfer.complete = true;
        write_timings_.cancel_end_rejected = true;
        return std::unexpected(std::errc::interrupted);
    }
    if (auto ok = expect_ack(result.value()); !ok)
        return std::unexpected(ok.error());
    if (!result->payload.empty()) return std::unexpected(std::errc::protocol_error);
    write_timings_.sync_seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - sync_start).count();
    transfer.complete = true;
    if (stop.stop_requested()) {
        write_timings_.cancelled = true;
        write_timings_.cancel_end_acked = true;
        return std::unexpected(std::errc::interrupted);
    }
    return {};
}

std::expected<void, std::errc>
SprdDevice::write_raw_stream(const std::string& name, uint64_t size,
                             const io::Reader& source, std::stop_token stop, const io::TransferObserver& progress) {
    invalidate_layout();
    write_timings_ = {};
    const auto operation_start = std::chrono::steady_clock::now();
    if (info_.stage != Stage::Fdl2)
        return std::unexpected(std::errc::not_supported);
    // FDL2 whole-file raw protocol (u-boot15 dloader dl_cmd_proc.c):
    //   0x28 WRITE_RAW_DATA_ENABLE (empty)      -> ACK
    //   0x01 START_DATA (partition name+size)   -> ACK; this opens the
    //       partition AND arms the raw buffers — prepare_buf_recv_raw_data
    //       is what sets g_bin_file_size, without it the 0x33 handler sees
    //       size 0 and rejects the transfer
    //   0x33 DLOAD_RAW_START2 (payload ignored) -> ACK (sent before any
    //       data is received)
    //   RAW_CHUNK_SIZE (2MB) bare USB bulk chunks; the device ACKs after
    //       EACH chunk (dload_whole_raw_file loop) — every ACK must be read
    //       or it poisons the next reply on this link.
    if (!size || !source || !valid_partition_name(name) || !info_.da.valid || !info_.da.support_raw)
        return std::unexpected(std::errc::invalid_argument);

    // Validate every control before enabling the raw channel. No padding
    // or USB-level splitting is legal in the unescaped frame mode.
    auto open_payload = protocol::BslCodec::make_partition_payload(
        name, size, 0, 0, false);
    auto open_enc = encode_fdl2_command(protocol::BslCommand::CMD_START_DATA, open_payload);
    if (!open_enc) return std::unexpected(open_enc.error());
    uint8_t size_be[8];
    for (size_t i = 0; i < 8; ++i)
        size_be[i] = static_cast<uint8_t>(size >> (56 - 8 * i));
    auto start_enc = encode_fdl2_command(protocol::BslCommand::CMD_DLOAD_RAW_START2, size_be);
    if (!start_enc) return std::unexpected(start_enc.error());
    auto end_enc = encode_fdl2_command(protocol::BslCommand::CMD_END_DATA);
    if (!end_enc) return std::unexpected(end_enc.error());
    auto enable_enc = encode_fdl2_command(protocol::BslCommand::CMD_WRITE_RAW_DATA_ENABLE);
    if (!enable_enc) return std::unexpected(std::errc::invalid_argument);
    auto opening = std::make_unique<WaitProgress>("write: " + name + ", opening raw channel");
    auto result = send_recv(enable_enc.value(), stop);
    if (!result) return std::unexpected(result.error());
    if (auto ok = expect_ack(result.value()); !ok)
        return std::unexpected(ok.error());
    TransferGuard transfer{desynchronized_};

    result = send_recv(open_enc.value(), stop);
    if (!result) return std::unexpected(result.error());
    if (auto ok = expect_ack(result.value()); !ok)
        return std::unexpected(ok.error());

    result = send_recv(start_enc.value(), stop);
    if (!result) return std::unexpected(result.error());
    if (auto ok = expect_ack(result.value()); !ok)
        return std::unexpected(ok.error());

    const auto t0 = std::chrono::steady_clock::now();
    opening.reset();
    write_timings_.open_seconds = std::chrono::duration<double>(t0 - operation_start).count();
    auto next = t0 + std::chrono::milliseconds(500);
    if (progress) progress({0, size, 0});
    else report_progress("write: " + name, 0, size, t0, next);
    std::vector<uint8_t> buffer(profile_.whole_file_chunk);
    bool recovery_source=false;
    const auto fallback=[&](const Reply& failure,bool end_sent,std::errc original)->std::expected<void,std::errc> {
        if(!profile_.allow_whole_file_recovery || profile_.raw_recovery!=RawRecoveryContract::SingleBlockEndAckRestarts ||
            !recovery_source || stop.stop_requested() ||
            !failure.payload.empty() || (failure.cmd!=protocol::BslResponse::REP_WRITE_ERROR &&
            failure.cmd!=protocol::BslResponse::REP_OPERATION_FAILED)) return std::unexpected(original);
        write_timings_.raw_failure=last_exchange();write_timings_.raw_recovery_attempted=true;
        const auto evidence=write_timings_.raw_failure;
        auto recovered=recover_raw_channel(end_sent,stop);
        if(!recovered)return std::unexpected(recovered.error());
        transfer.complete=true;
        if(stop.stop_requested())return std::unexpected(std::errc::interrupted);
        const double elapsed=std::chrono::duration<double>(std::chrono::steady_clock::now()-operation_start).count();
        log_status(LogLevel::Warn,"write",name,"raw error; channel synchronized, restarting once with framed data");
        // Retain the exact one-block bytes already sent. Never reread a mutable
        // caller source after the partial write, and never recurse into raw.
        const io::Reader frozen=[&](uint64_t at,std::span<uint8_t> out,std::stop_token token)->std::expected<void,std::errc> {
            if(token.stop_requested())return std::unexpected(std::errc::interrupted);
            if(at>size || out.size()>size-at)return std::unexpected(std::errc::message_size);
            std::copy_n(buffer.begin()+at,out.size(),out.begin());return {};
        };
        struct EvidenceGuard {
            WriteTimings& timings;std::optional<protocol::ExchangeEvidence> evidence;double seconds;
            ~EvidenceGuard(){timings.raw_failure=evidence;timings.raw_recovery_attempted=true;timings.raw_fallback=true;timings.raw_attempt_seconds=seconds;}
        } evidence_guard{write_timings_,evidence,elapsed};
        return write_framed_stream(name,size,frozen,stop,progress,{},false,{},AddressWordOrder::Little,0x800,true);
    };
    const bool measure = log_performance_enabled();
    if (measure) log_diag("{write} target=" + name + " mode=whole-file chunk=" +
        std::to_string(profile_.whole_file_chunk) + " B");
    for (uint64_t off = 0; off < size;) {
        const size_t n = static_cast<size_t>(std::min<uint64_t>(profile_.whole_file_chunk, size - off));
        if (stop.stop_requested()) {
            desynchronized_ = true; // Device is still expecting bare bytes.
            return std::unexpected(std::errc::interrupted);
        }
        auto bytes = std::span(buffer).first(n);
        const auto source_start = measure ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
        auto loaded = source(off, bytes, stop);
        if (measure) write_timings_.source_seconds += std::chrono::duration<double>(std::chrono::steady_clock::now() - source_start).count();
        if (!loaded) return std::unexpected(loaded.error());
        // Only single-block ordinary ext filesystem writes have a bounded,
        // repeatable stored-byte route here. Sparse, boot/NV/miscdata/userdata,
        // multiblock transfers and unknown storage remain non-replayable.
        recovery_source=off==0 && size<=buffer.size() && size>=1082 && size%512==0 &&
            info_.da.storage==0x102 &&
            (name=="system" || name=="vendor" || name=="product" || name=="cache") &&
            !(bytes[0]==0x44 && bytes[1]==0x48 && bytes[2]==0x54 && bytes[3]==0x42) &&
            !(bytes[0]==0x3a && bytes[1]==0xff && bytes[2]==0x26 && bytes[3]==0xed) &&
            bytes[1080]==0x53 && bytes[1081]==0xef;
        std::unique_ptr<WaitProgress> first_wait;
        if (off == 0) first_wait = std::make_unique<WaitProgress>("write: " + name + ", waiting for first ACK");
        const auto send_start = measure ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
        auto wr = write_bare(bytes,off,stop,std::chrono::seconds(30));
        if (measure) write_timings_.send_seconds += std::chrono::duration<double>(std::chrono::steady_clock::now() - send_start).count();
        if (!wr) {
            desynchronized_ = true;
            return std::unexpected(wr.error());
        }
        const auto ack_start = measure ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
        auto ack = read_reply(stop, std::chrono::seconds(30));
        if (measure) {
            const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - ack_start).count();
            write_timings_.ack_seconds += elapsed;
            write_timings_.max_ack_seconds = std::max(write_timings_.max_ack_seconds, elapsed);
            if (elapsed >= 0.1) {
                ++write_timings_.slow_ack_count;
                write_timings_.slow_ack_seconds += elapsed;
                log_diag("{write} slow ACK: " + name + " offset=" + std::to_string(off + n) +
                    " B, wait=" + format_duration(elapsed));
            }
        }
        if (!ack) return std::unexpected(ack.error());
        if (auto ok = expect_ack(*ack); !ok) {
            return fallback(*ack,false,ok.error());
        }
        first_wait.reset();
        if (off == 0) next = std::chrono::steady_clock::now();
        if (progress) progress({off + n, size, std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count()});
        else report_progress("write: " + name, off + n, size, t0, next);
        off += n;
    }
    // Chunk ACK means received, not persisted. END checks unsaved data,
    // syncs storage / closes UBI, and exposes a late raw-write error.
    const auto sync_start = std::chrono::steady_clock::now();
    write_timings_.transfer_seconds = std::chrono::duration<double>(sync_start - t0).count();
    result = [&] {
        WaitProgress waiting("write: " + name + ", waiting for final ACK");
        return send_recv(*end_enc, stop, std::chrono::seconds(60));
    }();
    if (!result) return std::unexpected(result.error());
    if (auto ok = expect_ack(*result); !ok) {
        // END may still produce another reply after the asynchronous
        // error just consumed. Never let that ACK enter a new command.
        return fallback(*result,true,ok.error());
    }
    log_clear_progress_line();
    write_timings_.sync_seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - sync_start).count();
    transfer.complete = true;
    return {};
}

std::expected<std::vector<uint8_t>, std::errc>
SprdDevice::read_partition(const std::string& name, uint64_t offset,
                             uint64_t size, std::stop_token stop) {
    std::vector<uint8_t> out;
    auto result = read_partition_stream(name, offset, size,
        [&out](std::span<const uint8_t> bytes, std::stop_token) -> std::expected<void, std::errc> {
            out.insert(out.end(), bytes.begin(), bytes.end());
            return {};
        }, stop);
    if (!result) return std::unexpected(result.error());
    return out;
}

std::expected<void, std::errc>
SprdDevice::read_partition_stream(const std::string& name, uint64_t offset,
    uint64_t size, const io::Writer& sink, std::stop_token stop) {
    return read_range(name, offset, size, sink, false, stop);
}

std::expected<void, std::errc>
SprdDevice::read_user_area(uint64_t offset, uint64_t size, const io::Writer& sink,
                          bool wide, std::stop_token stop, std::string_view progress_label) {
    return read_range("user_partition", offset, size, sink, wide, stop, progress_label);
}
std::expected<void,std::errc> SprdDevice::read_package_stream(const std::string& name,uint64_t offset,uint64_t size,
    const io::Writer& sink,bool wide,std::stop_token stop) {
    return read_range(name,offset,size,sink,wide,stop);
}

std::expected<void, std::errc>
SprdDevice::read_range(const std::string& name, uint64_t offset,
    uint64_t size, const io::Writer& sink, bool wide, std::stop_token stop,
    std::string_view progress_label) {
    if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    if (!sink) return std::unexpected(std::errc::invalid_argument);
    if (info_.stage != Stage::Fdl2)
        return std::unexpected(std::errc::not_supported);
    if (size > UINT64_MAX - offset ||
        (!wide && (offset > UINT32_MAX || size > UINT32_MAX - offset)))
        return std::unexpected(std::errc::file_too_large);
    if (!valid_partition_name(name))
        return std::unexpected(std::errc::invalid_argument);
    auto start_payload = wide
        ? protocol::BslCodec::make_partition_payload(name, offset + size, 0, 0, false)
        : protocol::BslCodec::make_partition_payload32(name, static_cast<uint32_t>(offset + size));
    auto start_enc = encode_fdl2_command(protocol::BslCommand::CMD_READ_FLASH_START, start_payload);
    if (!start_enc) return std::unexpected(start_enc.error());
    // Reads cancel at protocol boundaries, not in the middle of a USB frame.
    // A second Ctrl+C can still terminate a blocked operation immediately.
    auto result = send_recv(start_enc.value(), {});
    if (!result) {
        log_diagf("{read} START no reply: %s",
                  std::strerror(static_cast<int>(result.error())));
        return std::unexpected(result.error());
    }
    // A rejected START must surface here, not masquerade as a mid-read
    // failure one frame later.
    if (auto accepted=expect_query_reply(*result,protocol::BslResponse::REP_ACK,"READ START");!accepted) {
        log_diagf("{read} %s START rejected: %s (0x%02x)", name.c_str(),
                  protocol::BslCodec::reply_name(static_cast<uint8_t>(result->cmd)),
                  static_cast<unsigned>(static_cast<uint8_t>(result->cmd)));
        return std::unexpected(accepted.error());
    }
    if(auto accepted=expect_ack(*result);!accepted)return std::unexpected(accepted.error());

    TransferGuard transfer{desynchronized_};
    const auto close_read = [&](std::errc reason) -> std::expected<void, std::errc> {
        const auto failure=exchange_;
        try {
        log_clear_progress_line();
        auto end = encode_fdl2_command(protocol::BslCommand::CMD_READ_FLASH_END);
        if (end) {
            auto closed = send_recv(*end, {}, std::chrono::seconds(3));
            if (closed && expect_ack(*closed)) transfer.complete = true;
        }
        } catch (...) { desynchronized_ = true; }
        cleanup_=exchange_;exchange_=failure;
        return std::unexpected(reason);
    };
    uint64_t read = 0;
    const auto t0 = std::chrono::steady_clock::now();
    auto next = t0 + std::chrono::milliseconds(500);
    const std::string label = "read: " + std::string(progress_label.empty() ? std::string_view(name) : progress_label);
    // Per-request cap depends on the reply parser mode. ESCAPED replies
    // can double inside the device's send packet buffer: worst case
    // 2*(n+6) <= 65540 → n <= 32764 (32760 with margin) — a 64KB request
    // overflows on real data (~500 escape bytes per 64KB of ext4) and
    // the device emits garbage (measured: the read hangs). RAW replies
    // (FDL_DataProcess NONE_HDLC = verbatim memcpy) need no escape
    // room: n+8 <= 65540 → n <= 65532; 65024 = 127 blocks also stays
    // 512-aligned. Halving the round-trips halves the per-trip device
    // overhead (the read command path polls at coarse granularity —
    // the write's backstage path waits response-only, the read's does
    // not). spd_dump's largest observed request 0x8000, OEM 0x3000.
    const uint32_t kReadChunkEscaped = profile_.escaped_read_chunk;
    const uint32_t kReadChunkRaw = profile_.raw_read_chunk;
    const uint32_t chunk_cap = raw_tx_ ? kReadChunkRaw : kReadChunkEscaped;
    while (read < size) {
        if (stop.stop_requested()) return close_read(std::errc::interrupted);
        uint32_t chunk = static_cast<uint32_t>(
            std::min<uint64_t>(chunk_cap, size - read));
        // Binary payload (size+offset) must match the device's parser
        // mode: raw after 0x21, escaped otherwise. START/END carry
        // escape-free payloads and stay on the shared encoder.
        std::array<uint8_t, 12> payload{};
        for (size_t i = 0; i < 4; ++i) payload[i] = static_cast<uint8_t>(chunk >> (8 * i));
        for (size_t i = 0; i < (wide ? 8u : 4u); ++i)
            payload[4 + i] = static_cast<uint8_t>((offset + read) >> (8 * i));
        auto midst_enc = encode_fdl2_command(protocol::BslCommand::CMD_READ_FLASH_MIDST,
            std::span(payload).first(wide ? 12 : 8));
        if (!midst_enc) return std::unexpected(std::errc::invalid_argument);

        // Per-trip phase timing: splits the round-trip into the request
        // send (host) vs the reply wait (device eMMC read + reply send +
        // USB receive) — diagnoses which side owns the fixed overhead.
        const auto t_req = std::chrono::steady_clock::now();
        auto wr = write_frame(*midst_enc, {}, std::chrono::seconds(5));
        if (!wr) {
            log_diagf("{read} request send failed: chunk=%u off=%llu "
                      "done=%llu: %s",
                      chunk,
                      static_cast<unsigned long long>(offset + read),
                      static_cast<unsigned long long>(read),
                      std::strerror(static_cast<int>(wr.error())));
            return std::unexpected(wr.error());
        }
         const auto t_wait = std::chrono::steady_clock::now();

        auto reply = read_reply({}, std::chrono::seconds(30));
        const auto t_done = std::chrono::steady_clock::now();
        if (!reply) {
            log_diagf("{read} reply failed after %lld ms: chunk=%u "
                      "off=%llu done=%llu: %s",
                      static_cast<long long>(
                          std::chrono::duration_cast<std::chrono::milliseconds>(
                              t_done - t_wait).count()),
                      chunk,
                      static_cast<unsigned long long>(offset + read),
                      static_cast<unsigned long long>(read),
                      std::strerror(static_cast<int>(reply.error())));
            return std::unexpected(reply.error());
        }

        if (reply.value().cmd == protocol::BslResponse::REP_READ_FLASH) {
            if (reply->payload.empty() || reply->payload.size() > chunk) {
                desynchronized_ = true;
                return std::unexpected(std::errc::message_size);
            }
            if (stop.stop_requested()) return close_read(std::errc::interrupted);
            std::expected<void, std::errc> saved;
            try { saved = sink(reply->payload, stop); }
            catch (...) {
                (void)close_read(std::errc::io_error);
                throw;
            }
            if (!saved) return close_read(saved.error());
            read += reply.value().payload.size();
            // Round-trip phase split: req = host request send; reply =
            // device eMMC read + reply build/send + host receive.
            {
                const auto us = [](auto d) {
                    return static_cast<unsigned long long>(
                        std::chrono::duration_cast<
                            std::chrono::microseconds>(d).count());
                };
                const auto n_trip = read / chunk_cap;
                if ((n_trip < 10 || n_trip % 2000 == 0) &&
                    uniflash::log_diag_trace_enabled())
                    log_diagf("{rt} trip %llu: req=%lluuS reply=%lluuS",
                              static_cast<unsigned long long>(n_trip),
                              us(t_wait - t_req), us(t_done - t_wait));
            }
            report_progress(label, read, size, t0, next);
        } else {
            log_diagf("{read} midst reply=%s (0x%02x, expected "
                      "READ_FLASH): chunk=%u off=%llu payload=%zu",
                      protocol::BslCodec::reply_name(
                          static_cast<uint8_t>(reply.value().cmd)),
                      static_cast<unsigned>(
                          static_cast<uint8_t>(reply.value().cmd)),
                      chunk,
                      static_cast<unsigned long long>(offset + read),
                       reply.value().payload.size());
            // A complete negative response has consumed this MIDST. Close
            // the read transaction before considering another command.
            if (reply->payload.empty() &&
                (reply->cmd == protocol::BslResponse::REP_OPERATION_FAILED ||
                 reply->cmd == protocol::BslResponse::REP_UNSUPPORTED_CMD ||
                 reply->cmd == protocol::BslResponse::REP_INVALID_CMD ||
                 reply->cmd == protocol::BslResponse::REP_UNKNOW_CMD)) {
                const bool layout_probe = name == "user_partition" && !wide &&
                    offset == 0 && size == 512 && read == 0;
                auto closed = close_read(std::errc::protocol_error);
                // Only this exact initial probe may interpret explicit read
                // rejection as an unavailable raw-layout route, and only after
                // END ACK. Later I/O errors and corrupt GPT never fall back.
                if (layout_probe && transfer.complete)
                    return std::unexpected(std::errc::not_supported);
                return closed;
            }
            return std::unexpected(std::errc::protocol_error);
        }
    }

    log_clear_progress_line();
    auto end_enc = encode_fdl2_command(protocol::BslCommand::CMD_READ_FLASH_END);
    if (!end_enc) return std::unexpected(std::errc::invalid_argument);
    auto end_reply = send_recv(end_enc.value(), {});
    if (!end_reply) return std::unexpected(end_reply.error());
    if (auto ack = expect_ack(*end_reply); !ack) return std::unexpected(ack.error());
    transfer.complete = true;
    if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    return {};
}

std::expected<uint64_t, std::errc>
SprdDevice::probe_hw_part_size(const std::string& base_name,
                               std::stop_token stop) {
    // The _size endpoint returns a formatted text line, not binary data.
    // Request enough room for the complete line; a 4-byte request only
    // returns the literal prefix "size" and makes parsing impossible.
    constexpr uint64_t kSizeReplyCapacity = 128;
    auto data = read_partition(base_name + "_size", 0,
                               kSizeReplyCapacity, stop);
    if (!data) return std::unexpected(data.error());
    std::string_view text(reinterpret_cast<const char*>(data->data()), data->size());
    const auto nul = text.find('\0');
    if (nul != text.npos) text = text.substr(0, nul);
    const std::string prefix = "size:" + base_name + "_size: 0x";
    if (!text.starts_with(prefix)) return std::unexpected(std::errc::protocol_error);
    text.remove_prefix(prefix.size());
    uint64_t bytes = 0, blocks = 0;
    auto parsed = std::from_chars(text.data(), text.data() + text.size(), bytes, 16);
    if (parsed.ec != std::errc{} || !bytes) return std::unexpected(std::errc::protocol_error);
    text.remove_prefix(static_cast<size_t>(parsed.ptr - text.data()));
    constexpr std::string_view separator = " block number: 0x";
    if (!text.starts_with(separator)) return std::unexpected(std::errc::protocol_error);
    text.remove_prefix(separator.size());
    parsed = std::from_chars(text.data(), text.data() + text.size(), blocks, 16);
    if (parsed.ec != std::errc{} || bytes % 512 || blocks != bytes / 512)
        return std::unexpected(std::errc::protocol_error);
    text.remove_prefix(static_cast<size_t>(parsed.ptr - text.data()));
    if (!std::all_of(text.begin(), text.end(), [](unsigned char c) { return std::isspace(c); }))
        return std::unexpected(std::errc::protocol_error);
    return bytes;
}

std::expected<void, std::errc>
SprdDevice::erase_partition(const std::string& name, uint64_t size) {
    invalidate_layout();
    if (info_.stage != Stage::Fdl2)
        return std::unexpected(std::errc::not_supported);
    if (!valid_partition_name(name))
        return std::unexpected(std::errc::invalid_argument);
    auto payload = protocol::BslCodec::make_partition_payload(name, size);
    auto enc = encode_fdl2_command(protocol::BslCommand::CMD_ERASE_FLASH, payload);
    if (!enc) return std::unexpected(enc.error());
    // mmc_berase is a SYNCHRONOUS per-erase-group loop (sprd_mmc_r11.c):
    // a 576MB partition is hundreds of groups at real erase latency —
    // tens of seconds on eMMC. The 3s default would time out while the
    // device is still erasing and poison every following command.
    // Scale: 30s base + 1s per 4MB.
    // Zero means the whole partition, not an empty erase. Its unknown
    // capacity must receive the maximum operation window.
    const uint64_t mb = size == 0 ? 600 : (size >> 22) + ((size & ((4 << 20) - 1)) != 0);
    const auto erase_timeout = std::chrono::seconds(30) +
        std::chrono::seconds(std::min<uint64_t>(mb, 600));
    // Erase is non-cancellable. Wait for the final reply within its deadline.
    TransferGuard transaction{desynchronized_};
    const auto deadline = std::chrono::steady_clock::now() + erase_timeout;
    auto sent = write_frame(*enc, {}, std::chrono::seconds(5));
    if (!sent) return std::unexpected(sent.error());
    WaitProgress waiting("erase: " + name + ", waiting for device");
    auto result = read_reply({}, std::max(transport::Timeout(1),
        std::chrono::duration_cast<transport::Timeout>(deadline - std::chrono::steady_clock::now())));
    if (!result) return std::unexpected(result.error());
    if (!result->payload.empty()) {
        desynchronized_ = true;
        return std::unexpected(std::errc::protocol_error);
    }
    if (result->cmd != protocol::BslResponse::REP_ACK) {
        // Only definite failure replies may leave this transaction synchronized.
        // A stray version/data response cannot be used as an erase completion.
        switch (result->cmd) {
        case protocol::BslResponse::REP_OPERATION_FAILED:
        case protocol::BslResponse::REP_WRITE_ERROR:
        case protocol::BslResponse::REP_UNSUPPORTED_CMD:
        case protocol::BslResponse::REP_INVALID_CMD:
        case protocol::BslResponse::REP_UNKNOW_CMD:
        case protocol::BslResponse::REP_NOT_ENABLE_WRITE:
        case protocol::BslResponse::REP_DOWN_SIZE_ERROR:
        case protocol::BslResponse::REP_DOWN_DEST_ERROR:
            transaction.complete = true;
            break;
        default: desynchronized_ = true; break;
        }
        return expect_ack(*result);
    }
    transaction.complete = true;
    return {};
}

std::expected<layout::GptLayout, std::errc>
SprdDevice::read_disk_layout(std::stop_token stop) {
    if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    if (info_.stage != Stage::Fdl2) return std::unexpected(std::errc::not_supported);
    if (link_dead() || link_silent()) return std::unexpected(std::errc::state_not_recoverable);
    if (disk_layout_) return *disk_layout_;
    if (observed_.user_area_read==Capability::Unsupported || profile_.user_area_read==Capability::Unsupported || (info_.da.valid && info_.da.storage == 0x101))
        return std::unexpected(std::errc::not_supported);
    bool first = true;
    const io::Reader reader = [&](uint64_t offset, std::span<uint8_t> bytes, std::stop_token token)
        -> std::expected<void, std::errc> {
        size_t copied = 0;
        auto result = read_user_area(offset, bytes.size(), [&](auto chunk, auto) -> std::expected<void,std::errc> {
            if (chunk.size() > bytes.size()-copied) return std::unexpected(std::errc::message_size);
            std::copy(chunk.begin(), chunk.end(), bytes.begin()+copied);
            copied += chunk.size();
            return {};
        }, false, token);
        // A first, explicit START rejection is the only protocol fallback.
        if (!result && first && result.error() == std::errc::not_supported && !link_silent())
            observed_.user_area_read=Capability::Unsupported;
        first = false;
        if (!result) return result;
        if (copied != bytes.size()) return std::unexpected(std::errc::message_size);
        observed_.user_area_read=Capability::Supported;
        return {};
    };
    auto layout = layout::read_partition_layout(reader, stop, profile_.mbr_sector_size);
    if (!layout) return std::unexpected(layout.error());
    disk_layout_ = *layout;
    return layout;
}

std::expected<std::vector<PartitionInfo>, std::errc>
SprdDevice::list_partitions(std::stop_token stop, bool include_boot_sizes) {
    if (info_.stage != Stage::Fdl2)
        return std::unexpected(std::errc::not_supported);
    std::vector<PartitionInfo> parts;
    auto layout = read_disk_layout(stop);
    if (layout) {
        for (const auto& p : layout->partitions)
            parts.push_back({p.name, p.size, p.offset, false, layout->mbr, p.mbr_type});
    } else {
    if (layout.error() != std::errc::not_supported || link_dead() || link_silent() ||
        (observed_.user_area_read!=Capability::Unsupported && profile_.user_area_read!=Capability::Unsupported && !(info_.da.valid && info_.da.storage == 0x101)))
        return std::unexpected(layout.error());
    if (observed_.partition_query==Capability::Unsupported || profile_.partition_query==Capability::Unsupported) return std::unexpected(std::errc::not_supported);
    auto enc = encode_fdl2_command(protocol::BslCommand::CMD_CHECK_PARTITION);
    if (!enc) return std::unexpected(std::errc::invalid_argument);
    auto result = send_recv(enc.value(), stop);
    if (!result) return std::unexpected(result.error());

    if (auto accepted = expect_query_reply(*result, protocol::BslResponse::REP_READ_PARTITION, "PARTITIONS"); !accepted) {
        if (accepted.error() == std::errc::not_supported) {
            observed_.partition_query=Capability::Unsupported;
        }
        return std::unexpected(accepted.error());
    }

    auto entries = protocol::BslCodec::decode_partition_table(result.value().payload);
    if (!entries) return std::unexpected(std::errc::protocol_error);
    observed_.partition_query=Capability::Supported;

    for (const auto& e : entries.value()) {
        std::string name(reinterpret_cast<const char*>(e.name));
        if (name.empty()) break;
        PartitionInfo pi;
        pi.name = std::move(name);
        pi.size = static_cast<uint64_t>(e.size_kb) * 1024;
        pi.offset = 0;
        parts.push_back(std::move(pi));
    }
    }
    // The FDL2's CHECK_PARTITION walks only the USER_PART GPT
    // (get_partition_information -> USER_PART); splloader/splloader_bak
    // live on the eMMC BOOT hardware partitions (common_raw_read/write/
    // _erase all name-route them: BOOT_PART1/BOOT_PART2) and never
    // appear in the reply. Append them so write/erase/read work by name
    // — their sizes are card properties the protocol cannot report
    // (size 0, see cmd_read's size override).
    if (!info_.da.valid || (info_.da.storage != 0x102 &&
        !(info_.da.storage == 0x103 && profile_.ufs_boot_roles))) return parts;
    for (const char* hw : {"splloader", "splloader_bak"}) {
        bool listed = false;
        for (const auto& p : parts)
            if (p.name == hw) { listed = true; break; }
        if (!listed) {
            PartitionInfo pi;
            pi.name = hw;
            pi.size = 0;
            pi.offset = 0;
            pi.hw_boot = true;
            // Real capacity via the _size convention (ext_csd
            // BOOT_SIZE_MULT); stays 0 ("-") if the probe fails.
            if (include_boot_sizes) {
                if (auto sz = probe_hw_part_size(hw, stop)) pi.size = sz.value();
                else if (desynchronized_ || stop.stop_requested()) return std::unexpected(sz.error());
            }
            parts.push_back(std::move(pi));
        }
    }
    return parts;
}

std::expected<ChipInfo, std::errc>
SprdDevice::read_chip_info(std::stop_token stop, bool extended) {
    if (info_.stage != Stage::Fdl2)
        return std::unexpected(std::errc::not_supported);
    // READ_CHIP_TYPE (0x07) is commented out of the FDL2 registration
    // (cmd_download.c:188) — most builds reply BSL_UNSUPPORTED_CMD, so
    // only trust an actual REP_READ_CHIP_TYPE frame.
    auto chip_enc = encode_fdl2_command(protocol::BslCommand::CMD_READ_CHIP_TYPE);
    if (extended && chip_enc) {
        auto r = send_recv(chip_enc.value(), stop);
        if (!r) return std::unexpected(r.error());
        auto accepted = expect_query_reply(*r, protocol::BslResponse::REP_READ_CHIP_TYPE, "CHIP_TYPE");
        if (accepted) {
            if (r->payload.size() != 4) return std::unexpected(std::errc::message_size);
            info_.chip.chip_type = (uint32_t(r->payload[0]) << 24) |
                                   (uint32_t(r->payload[1]) << 16) |
                                   (uint32_t(r->payload[2]) << 8)  |
                                    uint32_t(r->payload[3]);
        } else if (accepted.error() != std::errc::not_supported) return std::unexpected(accepted.error());
    }

    // Identity/capacity only. Firmware flags and MCP are explicit diagnostic
    // queries, so the normal summary does not probe unrelated capabilities.
    auto uid_enc = encode_fdl2_command(protocol::BslCommand::CMD_READ_UID);
    if (uid_enc) {
        auto r = send_recv(uid_enc.value(), stop);
        if (!r) return std::unexpected(r.error());
        // UID encodings and lengths are firmware-specific. The frame decoder
        // already validates length/checksum and bounds allocation. A matching
        // reply is consumed even for empty or unfamiliar payloads; it does not
        // indicate transport desynchronization (some builds return 128 B).
        auto accepted = expect_query_reply(*r, protocol::BslResponse::REP_READ_CHIP_UID, "UID");
        if (accepted)
            info_.chip.chip_uid = r.value().payload;
        else if (accepted.error() != std::errc::not_supported) return std::unexpected(accepted.error());
    }

    if (extended) {
        auto ft = read_flash_type(stop);
        if (!ft && ft.error() != std::errc::not_supported)
            return std::unexpected(ft.error());
    }

    // Each successful query refreshes only the fields it actually obtained.
    // The caller and backup manifests see the same accumulated identity.
    return info_.chip;
}

std::expected<void, std::errc>
SprdDevice::repartition(std::span<const uint8_t> table_data,
                          std::stop_token stop, bool legacy_gpt,
                          uint32_t sector_size, std::optional<uint64_t> disk_size) {
    invalidate_layout();
    if (info_.stage != Stage::Fdl2)
        return std::unexpected(std::errc::not_supported);
    if (auto valid = layout::validate_partition_table(table_data, legacy_gpt, sector_size, disk_size); !valid)
        return std::unexpected(valid.error());
    const bool gpt = table_data.size() >= 16 && table_data[0] == 'p' && table_data[1] == 'a' &&
                      table_data[2] == 'r' && table_data[3] == ':';
    if (gpt || legacy_gpt) {
        const size_t header = gpt ? 16 : 0, cell = gpt ? 88 : 76;
        if ((table_data.size() - header) / cell > profile_.gpt_max_entries)
            return std::unexpected(std::errc::not_supported);
        for (size_t at = header; at < table_data.size(); at += cell) {
            size_t length = 0;
            while (length < 36 && table_data[at + 2 * length]) ++length;
            if (length > profile_.gpt_max_name) return std::unexpected(std::errc::not_supported);
        }
    }
    // v0 is also used by NAND; do not reinterpret an untyped legacy table.
    if (legacy_gpt && (gpt || !info_.da.valid ||
        (info_.da.storage != 0x102 && info_.da.storage != 0x103)))
        return std::unexpected(std::errc::not_supported);
    // Explicit layout selects the dialect when DA_INFO omits storage type.
    if (info_.da.valid && ((info_.da.storage == 0x101 && gpt) ||
        ((info_.da.storage == 0x102 || info_.da.storage == 0x103) && !gpt && !legacy_gpt)))
        return std::unexpected(std::errc::invalid_argument);
    auto enc = encode_fdl2_command(protocol::BslCommand::CMD_REPARTITION, table_data);
    if (!enc) return std::unexpected(enc.error());
    // Write permission is explicitly requested by the caller via enable-write.
    auto result = send_recv(enc.value(), stop, std::chrono::seconds(120));
    if (!result) return std::unexpected(result.error());
    if (result.value().cmd == protocol::BslResponse::REP_NOT_ENABLE_WRITE && result->payload.empty())
        return std::unexpected(std::errc::operation_not_permitted);
    if (auto ok = expect_ack(result.value()); !ok)
        return std::unexpected(ok.error());
    return {};
}

std::expected<void, std::errc>
SprdDevice::reset(std::stop_token stop) {
    invalidate_layout();
    // NORMAL_RESET is only issued to an adopted FDL2. Inspected ROM/FDL1
    // tables do not provide a safe universal reset handler.
    if (info_.stage != Stage::Fdl2)
        return std::unexpected(std::errc::not_supported);
    auto enc = encode_fdl2_command(protocol::BslCommand::CMD_NORMAL_RESET);
    if (!enc) return std::unexpected(std::errc::invalid_argument);
    auto r = send_recv(enc.value(), stop, std::chrono::seconds(5));
    if (!r) return std::unexpected(r.error());
    if (auto ok = expect_ack(r.value()); !ok)
        return std::unexpected(ok.error());
    session_ended_=true;info_.stage=Stage::Offline;desynchronized_=true;fdl2_announced_=false;
    return {};
}

std::expected<void, std::errc>
SprdDevice::power_down(std::stop_token stop) {
    invalidate_layout();
    // POWER_DOWN (dl_powerdown_device) exists only in the FDL2 dloader —
    // same stage rule and ADD checksum as NORMAL_RESET.
    if (info_.stage != Stage::Fdl2)
        return std::unexpected(std::errc::not_supported);
    auto enc = encode_fdl2_command(protocol::BslCommand::CMD_POWER_DOWN);
    if (!enc) return std::unexpected(std::errc::invalid_argument);
    auto r = send_recv(enc.value(), stop, std::chrono::seconds(5));
    if (!r) return std::unexpected(r.error());
    if (auto ok = expect_ack(r.value()); !ok)
        return std::unexpected(ok.error());
    session_ended_=true;info_.stage=Stage::Offline;desynchronized_=true;fdl2_announced_=false;
    return {};
}

} // namespace uniflash::device

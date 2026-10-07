/*
 * UniFlash-Core / Device Session
 *
 * Stage-aware BootROM and FDL session over the BSL download protocol.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef UNIFLASH_DEVICE_SPRD_H
#define UNIFLASH_DEVICE_SPRD_H

#include <uniflash/protocol/bsl.h>
#include <uniflash/protocol/session.h>
#include <uniflash/device/stage.h>
#include <uniflash/device/profile.h>
#include <uniflash/device/address.h>
#include <uniflash/io/stream.h>
#include <uniflash/layout/disk_layout.h>
#include <uniflash/auth/types.h>
#include <uniflash/device/capabilities.h>
#include <concepts>

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <stop_token>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace uniflash::device {
using AuthResponder = auth::Responder; // source-compatible public name

// DA_INFO capability frame (REP_INCOMPATIBLE_PART 0x96, magic 0x7477656e)
// sent by FDL2 right after the version frame. TLV entries.

struct ChipInfo {
    uint32_t chip_type    = 0;
    // dl_cmd_read_flashtype (0x0C) reply: 16 bytes = four big-endian
    // words of BSP FLASH_TYPE {mid=DDR MB, did=eMMC/UFS MB, eid, flag}
    // (dl_operate.c dl_get_flashtype; the words ride the wire swapped,
    // same convention as MCP_TYPE). It reports CAPACITIES, not a
    // storage-kind enum.
    uint32_t ddr_mb  = 0;
    uint32_t emmc_mb = 0;
    std::vector<uint8_t> chip_uid;
    std::string version;
};

// dl_cmd_read_mcptype reply: BSL_REP_READ_MCP_TYPE with 12 bytes = three
// big-endian words {flag, pagesize, blocksize} (dl_cmd_proc.c byte-swaps
// each 4-byte word of MCP_TYPE before sending).
struct McpInfo {
    uint32_t flag       = 0;
    uint32_t page_size  = 0;
    uint32_t block_size = 0;
};

struct PartitionInfo {
    std::string name;
    uint64_t    size = 0;
    uint64_t    offset = 0;
    // True for the synthesized eMMC BOOT1/BOOT2 hardware-partition
    // entries (splloader/splloader_bak): the FDL2's 0x2D reply walks
    // only the USER-partition GPT, so these never come from the wire —
    // list_partitions appends them for name-routed access, size left 0
    // (a card property the protocol cannot report).
    bool hw_boot = false;
    bool address_only = false;
    uint8_t mbr_type = 0;
    bool unverified = false; // Caller-supplied name when enumeration is unavailable.
};

struct DeviceInfo {
    ChipInfo chip;
    Stage    stage    = Stage::Offline;
    bool     is_sprd4 = false;  // SPRD4/AutoD version string, skips FDL1
    DaInfo   da;
};

struct FlashPartition {
    std::string name;
    uint64_t    offset = 0;
    uint64_t    size = 0;
    std::vector<uint8_t> data;
};

struct WriteTimings {
    bool raw_recovery_attempted = false, raw_fallback = false;
    double raw_attempt_seconds = 0;
    std::optional<protocol::ExchangeEvidence> raw_failure{};
    double open_seconds = 0;
    double transfer_seconds = 0;
    double sync_seconds = 0;
    double source_seconds = 0, encode_seconds = 0, send_seconds = 0, ack_seconds = 0;
    uint64_t slow_ack_count = 0;
    double slow_ack_seconds = 0, max_ack_seconds = 0;
    // Set only when this write actively handles cancellation. ACK confirms
    // closure, not rollback or a complete image.
    bool cancelled = false, cancel_end_acked = false, cancel_end_rejected = false;
    uint64_t acknowledged_bytes = 0;
};

class SprdDevice : private protocol::BslSession {
public:
    explicit SprdDevice(std::unique_ptr<transport::Transport> transport);
    SprdDevice(std::unique_ptr<transport::Transport> transport, DeviceProfile profile);
    template<class T> requires std::derived_from<T, transport::Transport>
    explicit SprdDevice(T&& transport)
        : SprdDevice(std::make_unique<T>(std::move(transport))) {}
    ~SprdDevice();

    SprdDevice(const SprdDevice&) = delete;
    SprdDevice& operator=(const SprdDevice&) = delete;
    SprdDevice(SprdDevice&&) noexcept = default;
    SprdDevice& operator=(SprdDevice&&) noexcept = default;

    std::expected<DeviceInfo, std::errc>
    handshake(std::stop_token stop = {});

    // FDL1 re-sync after bootrom EXEC (chipram fdl_main.c flow:
    // usb_init, then ONE 0x7E breaks the wait loop, then the version
    // frame, then the command loop): poll bare-0x7E, then CONNECT and
    // wait for the ACK — REP_VER frames are skipped until it arrives.
    std::expected<void, std::errc>
    handshake_fdl1(std::stop_token stop = {});

    // Send a bare EXEC_DATA frame (after a manual download_image), accepting
    // ACK or jump silence. Explicit errors propagate; the session is retired.
    // Used by load-bin for stub payloads (CVE-2022-38694 flow).
    std::expected<void, std::errc>
    send_exec_raw(const std::vector<uint8_t>& exec_frame,
                  std::stop_token stop = {});

    // Download WITHOUT executing: START/MIDST/END only. download_image
    // selects CRC16 at bootrom or delegates to the FDL1 ADD path; both
    // reject partition-mode FDL2 and the SPRD4 emulation stub.
    std::expected<void, std::errc>
    download_image(std::span<const uint8_t> image, uint32_t load_addr,
                   std::stop_token stop = {});
    std::expected<void, std::errc>
    download_image_add(std::span<const uint8_t> image, uint32_t load_addr,
                       std::stop_token stop = {});

    std::expected<void, std::errc>
    upload_fdl1(std::span<const uint8_t> fdl1,
                uint32_t load_addr,
                std::stop_token stop = {});

    std::expected<void, std::errc>
    upload_fdl2(std::span<const uint8_t> fdl2,
                uint32_t load_addr,
                std::stop_token stop = {});

    std::expected<void, std::errc>
    enable_write_flash(std::stop_token stop = {});
    // R27 SendExtTable: exact bounded table bytes, command 0x14, ACK required.
    std::expected<void,std::errc> send_ext_table(std::span<const uint8_t>,std::stop_token = {});
    // Explicit legacy storage addressing, never inferred from RAM addressing.
    std::expected<void,std::errc> write_address_stream(uint32_t,uint64_t,const io::Reader&,
        AddressWordOrder,std::stop_token = {},const io::TransferObserver& = {},size_t chunk = 0x800);
    std::expected<void,std::errc> read_address_stream(uint32_t,uint32_t,const io::Writer&,
        AddressWordOrder,std::stop_token = {});
    std::expected<void,std::errc> erase_address(uint32_t,uint32_t,AddressWordOrder);
    std::expected<void,std::errc> write_logical_nv(const std::string&,std::span<const uint8_t>,
        std::stop_token = {},const io::TransferObserver& = {});
    // R27 AUTH41: strict M1 structure, fresh responder result, no canned keys.
    std::expected<void,std::errc> authenticate(const AuthResponder&,std::stop_token = {});
    std::expected<void,std::errc> write_factory_timestamp(uint32_t unix_seconds,std::stop_token = {});
    std::expected<void,std::errc> write_factory_efuse(std::stop_token = {});
    std::expected<std::vector<uint8_t>,std::errc> read_vpac(std::stop_token = {});
    std::expected<void,std::errc> write_vpac(std::span<const uint8_t> utf16le,std::stop_token = {});
    std::expected<std::vector<uint8_t>,std::errc> read_softsim_identity(bool eid,std::stop_token = {});

    std::expected<void, std::errc>
    write_partition(const FlashPartition& part,
                    std::stop_token stop = {});

    std::expected<void, std::errc>
    write_partition_stream(const std::string& name, uint64_t size,
                            const io::Reader& source, std::stop_token stop = {}, const io::TransferObserver& progress = {});
    // Explicit package DownloadByIDEx dialect, even for a short file.
    std::expected<void,std::errc> write_package_stream(const std::string&,uint64_t,
        const io::Reader&,bool wide,std::stop_token = {},const io::TransferObserver& = {});
    std::expected<void, std::errc> write_nv(const std::string& primary,
        std::span<const uint8_t> payload, std::stop_token = {}, const io::TransferObserver& = {});
    std::expected<void, std::errc>
    read_partition_stream(const std::string& name, uint64_t offset, uint64_t size,
                           const io::Writer& sink, std::stop_token stop = {});
    std::expected<void,std::errc> read_package_stream(const std::string& name,uint64_t offset,uint64_t size,
        const io::Writer&,bool wide,std::stop_token = {});

    // Physical user-area access for GPT-backed raw backup. Wide addressing is
    // explicit: the backup service verifies the dialect before using high LBAs.
    std::expected<void, std::errc>
    read_user_area(uint64_t offset, uint64_t size, const io::Writer& sink,
                   bool wide, std::stop_token stop = {}, std::string_view progress_label = {});

    std::expected<std::vector<uint8_t>, std::errc>
    read_partition(const std::string& name, uint64_t offset,
                   uint64_t size, std::stop_token stop = {});

    std::expected<void, std::errc>
    erase_partition(const std::string& name, uint64_t size);

    std::expected<std::vector<PartitionInfo>, std::errc>
    list_partitions(std::stop_token stop = {}, bool include_boot_sizes = true);

    // Identity of the current connection/layout generation, not a timed cache.
    std::shared_ptr<const uint8_t> layout_token() const { return layout_token_; }
    std::shared_ptr<const uint8_t> connection_token() const { return connection_token_; }
    void invalidate_layout() { layout_token_ = std::make_shared<const uint8_t>(0); disk_layout_.reset(); }
    std::expected<layout::GptLayout, std::errc> read_disk_layout(std::stop_token stop = {});

    // Refresh UID; extended also queries chip type and capacities. Returns the
    // session cache, including version and previously known fields. Only valid
    // replies update their fields (including explicit zero/empty values);
    // skipped, unsupported or failed queries preserve them. Earlier successful
    // queries remain cached even if a later query fails. No root/NV/MCP or
    // partition queries.
    std::expected<ChipInfo, std::errc>
    read_chip_info(std::stop_token stop = {}, bool extended = true);

    std::expected<void, std::errc>
    repartition(std::span<const uint8_t> table_data,
                std::stop_token stop = {}, bool legacy_gpt = false,
                uint32_t sector_size = 512, std::optional<uint64_t> disk_size = {});

    std::expected<void, std::errc>
    reset(std::stop_token stop = {});

    std::expected<void, std::errc>
    power_down(std::stop_token stop = {});


    std::expected<void, std::errc>
    write_datetime(std::span<const uint8_t> dt,
                   std::stop_token stop = {});

    std::expected<void, std::errc>
    end_process(std::stop_token stop = {});

    // Capabilities retained from the announcement consumed during adoption.
    const DaInfo& da_info() const { return info_.da; }

    // CHECK_ROOTFLAG: firmware root flag; only after FDL2 adoption.
    std::expected<bool, std::errc>
    root_flag(std::stop_token stop = {});

    // FDL2-only commands (0x1B, 0x2A, 0x20, 0x19, 0x0D, 0x0C)
    std::expected<void, std::errc>
    set_first_mode(uint32_t mode, std::stop_token stop = {});

    // FDL2 BSL_CMD_SET_DEBUGINFO (0x25): writes a debug string into
    // miscdata at DEBUG_INFO_OFFSET (DL_CMD_PROC.H). Empty string enables
    // the default "enable" sentinel on the device side. Exclusive to fdl2.
    std::expected<void, std::errc>
    set_debuginfo(const std::string& info, std::stop_token stop = {});

    std::expected<McpInfo, std::errc>
    read_mcp_type(std::stop_token stop = {});

    // READ_FLASH_TYPE (0x0C) decoded: {ddr_mb, emmc_mb} from the BSP
    // FLASH_TYPE reply (capacities, not a storage-kind enum). Updates and returns
    // cached capacities; a short reply without eMMC/UFS capacity preserves it.
    std::expected<std::pair<uint32_t, uint32_t>, std::errc>
    read_flash_type(std::stop_token stop = {});

    // FDL1-stage memory diagnostics (fdl_command.c): ddr_test over the
    // 0x5F0000-0x8F0000 reserve region; SR test with a timeout (ms).
    // true = pass, false = the 0xB6/0xB7 fail reply.
    std::expected<bool, std::errc>
    ddr_verify(std::stop_token stop = {});
    std::expected<bool, std::errc>
    ddr_sr_test(uint32_t timeout_ms, std::stop_token stop = {});

    // FDL2 misc: query the RF/modem NV type.
    std::expected<uint8_t, std::errc>
    check_nv_type(std::stop_token stop = {});

    // True once the transport has seen LIBUSB_ERROR_NO_DEVICE — the
    // device is physically gone; the shell demotes to offline on this.
    bool link_dead() const { return transport_.device_gone(); }

    // An uncertain command reply permanently invalidates this session.
    // Successful USB writes cannot clear a late-ACK hazard.
    bool link_silent() const { return desynchronized_ || transport_.device_silent(); }

    // Boot-partition size via the BSP's hidden "_size" convention
    // (common_raw_read): a read whose partition name carries the
    // "_size" suffix answers with a formatted text line
    // ("size:<name>: 0x<bytes> block number: 0x<blocks>") instead of
    // flash data — get_img_partition_size routes splloader/splloader_bak
    // to the eMMC BOOT1/2 capacities (ext_csd BOOT_SIZE_MULT). The only
    // wire path to the boot hw partition sizes: 0x2D walks just the
    // USER-partition GPT.
    std::expected<uint64_t, std::errc>
    probe_hw_part_size(const std::string& base_name, std::stop_token stop = {});

    const DeviceInfo& info() const { return info_; }
    bool session_ended() const {return session_ended_;}
    const DeviceProfile& profile() const { return profile_; }
    const ObservedCapabilities& observed_capabilities() const { return observed_; }
    const WriteTimings& write_timings() const { return write_timings_; }
    const protocol::ExchangeEvidence& last_exchange() const { return BslSession::last_exchange(); }
    const std::optional<protocol::ExchangeEvidence>& cleanup_exchange() const {return BslSession::cleanup_exchange();}

    // True after DISABLE_TRANSCODE (0x21) was ACKed: the device's
    // receive parser is in raw/length mode and binary payloads (MIDST
    // image data) must go un-escaped.
    bool raw_tx() const { return raw_tx_; }

    // Wait for a fresh DA_INFO announcement and establish framing.
    // Call on a live link after upload_fdl2 /
    // sprd4_enter_fdl2, or right after reopening a re-enumerated device.
    std::expected<void, std::errc>
    resync_fdl2(std::chrono::milliseconds boot_wait = std::chrono::seconds(8),
                std::stop_token stop = {});

    // SPRD4 (autodloader): EXEC #1 switches the stub from "RomCode role" to
    // "FDL1 role" (ACK, then it blocks re-sending the version until a 0x7E
    // arrives); EXEC #2 enters the real do_download() which pushes DA_INFO
    // (autodloader_mode.c autodloader_exec). Follow with resync_fdl2,
    // possibly after a reopen if the bus re-enumerated.
    std::expected<void, std::errc>
    sprd4_enter_fdl2(std::stop_token stop = {});

private:
    std::expected<void, std::errc> write_framed_stream(const std::string&, uint64_t,
        const io::Reader&, std::stop_token, const io::TransferObserver&, std::optional<uint32_t> nv_checksum = {},bool package_wide = false,
        std::optional<uint32_t> address = {},AddressWordOrder = AddressWordOrder::Little,size_t address_chunk = 0x800,
        bool force_framed = false);
    std::expected<void, std::errc>
    read_range(const std::string&, uint64_t, uint64_t, const io::Writer&,
               bool wide, std::stop_token, std::string_view progress_label = {});
    std::expected<void, std::errc>
    write_raw_stream(const std::string& name, uint64_t size,
                      const io::Reader& source, std::stop_token stop, const io::TransferObserver& progress = {});
    std::expected<void,std::errc> recover_raw_channel(bool end_already_sent,std::stop_token);
    // Send the largest locally validated safe prefix and return ACKed length.
    // The caller advances by that length, avoiding tiny split remainders.
    std::expected<size_t, std::errc>
    send_midst(protocol::BslCodec::Chk phase,
               std::span<const uint8_t> data, std::stop_token stop);

    // Shared download engine: EXEC may ACK, announce the next stage or
    // disconnect; a missing reply alone is never proof of the next stage.
    // The new stage is committed only by its subsequent handshake/resync.
    std::expected<void, std::errc>
    upload_binary(std::span<const uint8_t> image, uint32_t load_addr,
                  Stage after, std::stop_token stop);

    void adopt_da_info(std::span<const uint8_t> payload);

    std::expected<std::vector<uint8_t>, std::errc>
    encode_fdl2_command(protocol::BslCommand command,
                        std::span<const uint8_t> payload = {}) const;

    // Explicit refusal preserves escaped mode; an uncertain exchange
    // invalidates the session because the device may already be raw.
    std::expected<void, std::errc> maybe_enable_raw_tx(std::stop_token stop);

    // Verify REP_ACK; retain other replies as always-on {bsl} diagnostics
    // and return protocol_error. The command layer renders operation failure.
    std::expected<void, std::errc> expect_ack(const Reply& r);
    std::expected<void, std::errc> expect_query_reply(const Reply&, protocol::BslResponse,
                                                    const char* query);

    DeviceInfo info_;
    bool session_ended_=false;
    DeviceProfile profile_;
    WriteTimings write_timings_;
    bool fdl2_announced_ = false;
    std::optional<layout::GptLayout> disk_layout_;
    ObservedCapabilities observed_;
    std::optional<Reply> next_loader_version_;
    std::shared_ptr<const uint8_t> layout_token_ = std::make_shared<const uint8_t>(0);
    std::shared_ptr<const uint8_t> connection_token_ = std::make_shared<const uint8_t>(0);
};

}

#endif

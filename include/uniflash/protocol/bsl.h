/*
 * UniFlash-Core / BSL Framing
 *
 * Frame constants, checksum phases and the BSL codec.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef UNIFLASH_PROTOCOL_BSL_H
#define UNIFLASH_PROTOCOL_BSL_H

#include <algorithm>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>
#include <string>
#include <system_error>
#include <expected>
#include <utility>

namespace uniflash::protocol {

constexpr uint16_t CRC16_POLY = 0x1021;
constexpr uint16_t CRC16_SEED = 0x0000;

constexpr uint8_t HDLC_FLAG        = 0x7E;
constexpr uint8_t HDLC_ESCAPE      = 0x7D;
constexpr uint8_t HDLC_ESCAPE_MASK = 0x20;

// BSP dl_cmd_proc.h: MAX_PARTITION_NAME_SIZE is 36 uint16 units on the
// wire (72 bytes, UTF-16LE). Keep the constant in *bytes* here.
constexpr uint8_t  MAX_PARTITION_NAME_SIZE = 72;
// The FDL2 packet layer's hard cap (u-boot15 packet.c Read(pdata,
// MAX_PKT_SIZE=0x10000) into packet_body): unescaped body+chk =
// payload+6 <= 65536 -> payload <= 65530. Per-receiver chunk constants
// (1018 bootrom / 2044 FDL1) stay tighter; this is the wire sanity bound.
constexpr uint16_t MAX_PAYLOAD_SIZE = 65530;
// FDL2 device MAX_PKT_SIZE (u-boot15/include/packet.h:21) = 0x10000 per
// HDLC data field. Our legacy constant was 4x smaller (0x4000); raise to
// match the device ceiling so reads/writes use fewer, larger round-trips.
constexpr uint32_t MAX_PKT_SIZE     = 0x10000;
// FDL2 raw-data receive buffer is RECV_PKT_SIZE=0x400000 (4MB), HALF_PKT_SIZE
// = 0x200000 (2MB) per raw bulk read (packet.h:25,27). We chunk raw writes
// at this 2MB granularity; the device double-buffers and self-flushes.
constexpr uint32_t RAW_CHUNK_SIZE   = 0x200000;

// Android sparse container (sparse_format.h — what the FDL2's
// write_sparse_img decodes). Wrapping a raw image in a minimal sparse
// container routes the FDL2 write through the regular per-chunk path
// (dl_download_midst detects SPARSE_HEADER_MAGIC -> IMG_WITH_SPARSE ->
// regular_download_process): the raw path for >2MB images instead fills
// a ~40MB alter buffer and flushes with ONE backstage MMC command of
// ~81920 blocks — over the 16-bit SDHCI block-count ceiling (65535) —
// a device-side hang at the first buffer boundary (measured: death at
// 41.7MB, every run).
inline constexpr uint32_t SPARSE_MAGIC = 0xed26ff3a;
inline constexpr uint32_t SPARSE_BLK_SZ = 4096;

// Wrap a raw image as a minimal sparse container (28-byte file header,
// 12-byte RAW chunk headers, 4MB chunks); returns the input unchanged
// if already sparse. Tail-padded to whole 4096-byte blocks.
std::vector<uint8_t> wrap_as_sparse(const uint8_t* data, size_t size);

// Split a partition payload into FDL2 raw-data chunks of RAW_CHUNK_SIZE.
// The last chunk is partial unless total is an exact multiple. total==0
// yields exactly one 0-size chunk so the device's terminating write fires.
template <typename F>
void for_each_raw_chunk(uint64_t total, F&& fn) {
    if (total == 0) { fn(0ull, 0ull); return; }
    uint64_t off = 0;
    while (off < total) {
        uint64_t n = std::min<uint64_t>(RAW_CHUNK_SIZE, total - off);
        fn(off, n);
        off += n;
    }
}

// FDL1 (bootrom) + FDL2 (U-Boot dloader) full command set,
// derived from bootrom_ums9621 reverse engineering and BSP
// u-boot15/include/dl_cmd_def.h
struct DaInfoTlv {
    bool     support_raw  = false;
    bool     disable_hdlc = false;
    uint32_t flush_kb     = 0;
    uint32_t storage      = 0;   // 0x101 nand, 0x102 emmc, 0x103 ufs
};

// Parse the DA_INFO frame body (magic 0x7477656e + TLV entries) that FDL2
// sends right after the version frame. Returns the capabilities, or nullopt
// if the magic is not present.
std::optional<DaInfoTlv> parse_da_info(std::span<const uint8_t> payload);

enum class BslCommand : uint8_t {
    CMD_CONNECT            = 0x00,
    CMD_START_DATA         = 0x01,
    CMD_MIDST_DATA         = 0x02,
    CMD_END_DATA           = 0x03,
    CMD_EXEC_DATA          = 0x04,
    CMD_NORMAL_RESET       = 0x05,
    // 0x08/0x09/0x31/0x32 are named for diagnostics but deliberately
    // unwrapped (registration evidence: fdl_main.c:75-83, cmd_download.c:
    // 178-221):
    //   0x06 READ_FLASH      - legacy address-based package reads, explicitly
    //                          configured word order; modern named reads use
    //                          the separate 0x10/0x11/0x12 transaction.
    //   0x08 LOOKUP_NVITEM   - defined in dl_cmd_def.h but registered in
    //                          NEITHER this BSP's FDL1 nor FDL2 (reply would
    //                          be BSL_UNSUPPORTED_CMD 0xFE); reply code 0x95
    //                          is named for diagnostics only.
    //   0x09 SET_BAUDRATE    - FDL1-only registration (set_baudrate); a UART
    //                          concept — meaningless on this USB-only tool.
    //   0x31 DLOAD_RAW_START - the per-packet raw variant; the raw write
    //                          path deliberately speaks 0x33 (whole-file)
    //                          instead (write_partition_stream capability routing).
    //   0x32 WRITE_FLUSH_DATA- explicit raw-chunk flush; unneeded by design,
    //                          the device double-buffers 2MB chunks and
    //                          self-flushes (bsl.h raw-channel notes).
    CMD_READ_FLASH         = 0x06,
    CMD_READ_CHIP_TYPE     = 0x07,
    CMD_LOOKUP_NVITEM      = 0x08,   // see above: unwrapped by design
    CMD_SET_BAUDRATE       = 0x09,   // see above: unwrapped by design
    CMD_ERASE_FLASH        = 0x0A,
    CMD_REPARTITION        = 0x0B,
    CMD_READ_FLASH_TYPE    = 0x0C,
    CMD_READ_MCP_TYPE      = 0x0D,
    CMD_READ_FLASH_START   = 0x10,
    CMD_READ_FLASH_MIDST   = 0x11,
    CMD_READ_FLASH_END     = 0x12,
    CMD_OFF_CHG            = 0x13,
    CMD_POWER_DOWN         = 0x17,
    CMD_CHECK_ROOTFLAG     = 0x19,
    CMD_READ_UID           = 0x1A,
    CMD_ENABLE_WRITE_FLASH = 0x1B,
    CMD_READ_REFINFO       = 0x20,
    CMD_DIS_HDLC           = 0x21,
    CMD_WRITE_DATETIME     = 0x22,
    CMD_CHECK_NV_TYPE      = 0x24,
    CMD_DDR_VERIFY         = 0x26,   // fdl_command.c: ddr_test on the
                                    // 0x5F0000-0x8F0000 reserve region
    CMD_DDR_SR_TEST        = 0x27,   // payload: u32 LE timeout ms
    CMD_SET_DEBUGINFO      = 0x25,
    CMD_WRITE_RAW_DATA_ENABLE = 0x28,
    CMD_SET_FIRST_MODE     = 0x2A,
    CMD_CHECK_PARTITION    = 0x2D,
    CMD_DLOAD_RAW_START    = 0x31,   // see above: unwrapped by design
    CMD_WRITE_FLUSH_DATA   = 0x32,   // see above: unwrapped by design
    CMD_DLOAD_RAW_START2   = 0x33,
    CMD_END_PROCESS        = 0x7F,
};

enum class BslResponse : uint8_t {
    REP_ACK                   = 0x80,
    REP_VER                   = 0x81,
    REP_INVALID_CMD           = 0x82,
    REP_UNKNOW_CMD            = 0x83,
    REP_OPERATION_FAILED      = 0x84,
    REP_NOT_SUPPORT_BAUDRATE  = 0x85,
    REP_DOWN_NOT_START        = 0x86,
    REP_DOWN_MULTI_START      = 0x87,
    REP_DOWN_EARLY_END        = 0x88,
    REP_DOWN_DEST_ERROR       = 0x89,
    REP_DOWN_SIZE_ERROR       = 0x8A,
    REP_VERIFY_ERROR          = 0x8B,
    REP_NOT_VERIFY            = 0x8C,
    REP_PHONE_NOT_ENOUGH_MEM  = 0x8D,
    REP_PHONE_WAIT_TIMEOUT    = 0x8E,
    REP_PHONE_SUCCEED         = 0x8F,
    REP_PHONE_VALID_BAUD      = 0x90,
    REP_PHONE_REPEAT_CONT     = 0x91,
    REP_PHONE_REPEAT_BREAK    = 0x92,
    REP_READ_FLASH            = 0x93,
    REP_READ_CHIP_TYPE        = 0x94,
    REP_LOOKUP_NVITEM         = 0x95,
    REP_INCOMPATIBLE_PART     = 0x96,
    REP_UNKNOWN_DEVICE        = 0x97,
    REP_INVALID_DEVICE_SIZE   = 0x98,
    REP_ILLEGAL_SDRAM         = 0x99,
    REP_WRONG_SDRAM_PARAMETER = 0x9A,
    REP_READ_MCP_TYPE         = 0x9B,
    REP_READ_FLASH_TYPE       = 0x9D,
    REP_ERROR_CHECKSUM        = 0xA0,
    REP_CHECKSUM_DIFF         = 0xA1,
    REP_WRITE_ERROR           = 0xA2,
    REP_PHONE_ROOTFLAG        = 0xA7,
    REP_READ_CHIP_UID         = 0xAB,
    REP_NOT_ENABLE_WRITE      = 0xAC,
    REP_READ_REFINFO          = 0xB1,
    REP_CHECK_NV_TYPE         = 0xB5,
    REP_DDR_VERIFY_FAIL       = 0xB6,
    REP_DDR_TEST_FAIL         = 0xB7,
    REP_READ_PARTITION        = 0xBA,
    REP_UNSUPPORTED_CMD       = 0xFE,
};

inline bool is_ack(uint8_t cmd) {
    return cmd == static_cast<uint8_t>(BslResponse::REP_ACK);
}


#pragma pack(push, 1)
struct BslHeader {
    uint16_t type;
    uint16_t size;
};

// FDL2 tool partition entry as sent by BSL_REP_READ_PARTITION (0xBA).
// Mirrors BSP tool_partition_t { char name[72]; u32 size; /*KB*/ }.
// name is UTF-16LE on the wire; size is little-endian KB.
struct ToolPartitionEntry {
    uint8_t  name[72];
    uint32_t size_kb;
};
#pragma pack(pop)
static_assert(sizeof(BslHeader) == 4 && sizeof(ToolPartitionEntry) == 76);

class BslCodec {
public:
    enum class Chk { Crc16, Add };
    static uint16_t compute_crc16(std::span<const uint8_t> data);

    static uint16_t be16v(uint16_t v) {
        return static_cast<uint16_t>(((v & 0x00FF) << 8) | ((v & 0xFF00) >> 8));
    }
    static uint32_t be32v(uint32_t v) {
        return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) |
               ((v & 0x00FF0000u) >> 8)  | ((v & 0xFF000000u) >> 24);
    }

    static std::expected<std::vector<uint8_t>, std::errc>
    encode_hdlc(uint8_t type, std::span<const uint8_t> payload);

    static std::expected<std::pair<uint8_t, std::vector<uint8_t>>, std::errc>
    decode_hdlc(std::span<const uint8_t> raw,
                std::optional<Chk> checksum = std::nullopt);

    // convenience encoders
    static std::expected<std::vector<uint8_t>, std::errc>
    encode(BslCommand cmd) {
        return encode_hdlc(static_cast<uint8_t>(cmd), {});
    }

    static std::expected<std::vector<uint8_t>, std::errc>
    encode_connect()          { return encode(BslCommand::CMD_CONNECT); }
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_end_data()         { return encode(BslCommand::CMD_END_DATA); }
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_normal_reset()     { return encode_hdlc_chk(static_cast<uint8_t>(BslCommand::CMD_NORMAL_RESET), {}, Chk::Add); }
    // The only receiver is the u-boot dloader (dl_enable_write_flash,
    // gated by CONFIG_PCTOOL_CHECK_WRITE_PROTECT builds) — ADD checksum,
    // never CRC16.
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_enable_write_flash() {
        return encode_hdlc_chk(
            static_cast<uint8_t>(BslCommand::CMD_ENABLE_WRITE_FLASH), {},
            Chk::Add);
    }
        static std::expected<std::vector<uint8_t>, std::errc>
    encode_end_process() {
        return encode_hdlc_chk(static_cast<uint8_t>(
            BslCommand::CMD_END_PROCESS), {}, Chk::Add);
    }
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_check_rootflag() {
        return encode_hdlc_chk(static_cast<uint8_t>(
            BslCommand::CMD_CHECK_ROOTFLAG), {}, Chk::Add);
    }
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_write_raw_data_enable() {
        return encode_hdlc_chk(static_cast<uint8_t>(
            BslCommand::CMD_WRITE_RAW_DATA_ENABLE), {}, Chk::Add);
    }
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_check_partition() {
        return encode_hdlc_chk(static_cast<uint8_t>(
            BslCommand::CMD_CHECK_PARTITION), {}, Chk::Add);
    }
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_read_chip_type() {
        return encode_hdlc_chk(static_cast<uint8_t>(
            BslCommand::CMD_READ_CHIP_TYPE), {}, Chk::Add);
    }
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_read_uid() {
        return encode_hdlc_chk(static_cast<uint8_t>(
            BslCommand::CMD_READ_UID), {}, Chk::Add);
    }
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_read_mcp_type() {
        return encode_hdlc_chk(static_cast<uint8_t>(
            BslCommand::CMD_READ_MCP_TYPE), {}, Chk::Add);
    }
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_read_flash_type() {
        return encode_hdlc_chk(static_cast<uint8_t>(
            BslCommand::CMD_READ_FLASH_TYPE), {}, Chk::Add);
    }
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_check_nv_type() {
        return encode_hdlc_chk(static_cast<uint8_t>(
            BslCommand::CMD_CHECK_NV_TYPE), {}, Chk::Add);
    }
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_read_flash_end() {
        return encode_hdlc_chk(static_cast<uint8_t>(
            BslCommand::CMD_READ_FLASH_END), {}, Chk::Add);
    }

    static std::expected<std::vector<uint8_t>, std::errc>
    encode_start_data(uint32_t addr, uint32_t size);

    static std::expected<std::vector<uint8_t>, std::errc>
    encode_midst_data(std::span<const uint8_t> data);

    static std::expected<std::vector<uint8_t>, std::errc>
    encode_exec(uint32_t entry_addr);
    // Empty EXEC for the inspected ROM dialects: jump target comes from START.
    // Not a claim that every loader ignores an addressed EXEC payload.
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_exec_empty();

    static std::expected<std::vector<uint8_t>, std::errc>
    encode_erase_flash(const std::string& partition_name, uint64_t size);

    static std::expected<std::vector<uint8_t>, std::errc>
    encode_read_flash_start(const std::string& partition_name, uint64_t size);

    static std::expected<std::vector<uint8_t>, std::errc>
    encode_read_flash_midst(uint32_t size, uint64_t offset);

    // Raw (un-escaped) twin for DISABLE_TRANSCODE sessions: the request
    // payload is binary (size+offset), so in raw parser mode it must
    // ride the wire verbatim.
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_read_flash_midst_raw(uint32_t size, uint64_t offset);

    static std::expected<std::vector<uint8_t>, std::errc>
    encode_repartition(std::span<const uint8_t> table_data);

    static std::expected<std::vector<uint8_t>, std::errc>
    encode_write_datetime(std::span<const uint8_t> datetime);

    static std::expected<std::vector<uint8_t>, std::errc>
    encode_set_debuginfo(std::span<const uint8_t> info);

    static std::expected<std::vector<uint8_t>, std::errc>
    encode_dload_whole_raw_start(uint64_t file_size);

    // FDL2 partition download payload:
    // name[72] (UTF-16LE, null-padded) + size(8B LE) + rev(8B LE) [+ checksum(4B LE)]
    static std::vector<uint8_t>
    make_partition_payload(const std::string& name, uint64_t size,
                           uint64_t rev = 0, uint32_t checksum = 0,
                           bool with_checksum = false);

    // BIT32 variant (0x4C = 76 bytes): name[72] + size[4] u32 LE — the
    // form the factory tool puts on the wire for FDL2 partition writes
    // (observed in its verbose trace: START `7e 00 01 00 4c` + name72 +
    // size u32). The device's _decode_packet_data takes the u32 branch
    // whenever body.size < 0x58 (BIT64_IDLEN_DATA_LENGTH).
    static std::vector<uint8_t>
    make_partition_payload32(const std::string& name, uint32_t size);

    static std::expected<std::vector<ToolPartitionEntry>, std::errc>
    decode_partition_table(std::span<const uint8_t> data);

    // ---- checksum mode ------------------------------------------------
    // bootrom frames use CRC16-CCITT; FDL1/FDL2 frames use the 16-bit
    // one's-complement word-sum checksum (chipram frm_chk), switched
    // right after EXEC. Outgoing ADD commands swap the checksum bytes
    // for odd-length bodies so frm_chk(body+trailer) gives zero. Device
    // replies retain the canonical high/low order even for odd bodies.

    // Canonical body checksum used by the device-reply validators.
    static uint16_t add_checksum(std::span<const uint8_t> body);

    // Name of any reply code (all 41 from dl_cmd_def.h) — failure
    // diagnostics; unmapped bytes return "unknown" (callers print the
    // raw byte alongside).
    static const char* reply_name(uint8_t code);

    // ud710 bootrom quirk (measured, e2e#9): a frame whose CHECKSUM
    // bytes are 0x7e/0x7d — escaped on the wire — is rejected with
    // BSL_REP_VERIFY_ERROR, while payload-position escapes pass. MIDST
    // is a pure byte-stream append on both receivers, so a dirty chunk
    // can be re-split into smaller frames to re-roll the checksum.
    static bool chk_carries_escape(Chk chk, uint16_t cmd,
                                   std::span<const uint8_t> payload);

    static std::expected<std::vector<uint8_t>, std::errc>
    encode_hdlc_chk(uint8_t type, std::span<const uint8_t> payload, Chk chk);

    // Un-escaped ("raw") frame form — the FDL2's DISABLE_TRANSCODE (0x21,
    // OEM Global.h name) mode: once the device switches, its receive
    // parser takes the wire bytes [1, count-2) verbatim (usb_get_packet's
    // hdlc_disabled branch), so payloads must NOT be 0x7e/0x7d-escaped.
    // ADD checksum verification remains enabled; 0x21 disables escaping,
    // not the checksum or the type/size header.
    // Byte-identical to the escaped form whenever the body carries no
    // escape-needing bytes, so small ASCII command frames are safe in
    // either mode. The factory tool downloads this way
    // (SupportUnTransCode=1): constant wire size and no per-frame
    // un-escape state machine burning device CPU.
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_raw_chk(uint8_t type, std::span<const uint8_t> payload, Chk chk);

    // KEEP_CHARGE for the FDL1 (BSP set_chg_flag): sets keep_charge=1 in
    // the chipram env — without it, u-boot's sprdbat_init in download
    // mode STOPS charging whenever the battery sits above threshold,
    // leaving long flash sessions to run on battery alone.
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_off_chg_add() {
        return encode_hdlc_chk(static_cast<uint8_t>(BslCommand::CMD_OFF_CHG),
                               {}, Chk::Add);
    }

    // FDL1-stage memory diagnostics (fdl_command.c): DDR_VERIFY runs
    // ddr_test over the 0x5F0000-0x8F0000 reserve; SR_TEST passes a
    // u32 LE timeout (ms). Both ACK on pass, 0xB6/0xB7 on fail.
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_ddr_verify() {
        return encode_hdlc_chk(
            static_cast<uint8_t>(BslCommand::CMD_DDR_VERIFY), {},
            Chk::Add);
    }
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_ddr_sr_test(uint32_t timeout_ms) {
        uint8_t t[4] = {
            static_cast<uint8_t>(timeout_ms),
            static_cast<uint8_t>(timeout_ms >> 8),
            static_cast<uint8_t>(timeout_ms >> 16),
            static_cast<uint8_t>(timeout_ms >> 24),
        };
        return encode_hdlc_chk(
            static_cast<uint8_t>(BslCommand::CMD_DDR_SR_TEST), t,
            Chk::Add);
    }

    static std::expected<std::vector<uint8_t>, std::errc>
    encode_normal_reset_add() {
        return encode_hdlc_chk(
            static_cast<uint8_t>(BslCommand::CMD_NORMAL_RESET), {}, Chk::Add);
    }

    // U-Boot PC-tool mode request (calibration_detect.c):
    //   7e | reserved(4)=0 | size(2,LE)=8 | 0xfe | mode | 7e
    // The inspected serial gadget answers this shape after the host sets
    // DTR (f_serial.c gser_setup: request 0x22, wValue low byte 1).
    // 0x02 requests auto-download (SPRD4 or erase-SPL/bootrom, depending
    // on the build). Echo acknowledges receipt, not completion.
    // Only 1..0x3f is supported here, with frequency fixed to zero.
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_pctool_mode(uint8_t mode);

    // PROGRAMKEY dialog frames (calibration_detect.h / check_pctool_cmd):
    // MSG_HEAD_T = {seq u32 LE=0, len u16 LE, type u8, subtype u8=0},
    // 0x7e-framed, NO BSL checksum (the raw diag protocol — parse the
    // reply with raw bulk reads, not read_frame).
    //
    // Program trigger (LEN_14): type 0x62 + TOOLS_DIAG_AP_CMD_T
    //   {cmd u16 LE = 0x09, length u16 LE = 4}.
    static std::vector<uint8_t> encode_pctool_programkey();

    // Exit (LEN_16): type 0x62 + TOOLS_DIAG_AP_EXIT_CMD_T
    //   {cmd 0x0a, length 6, para u16 LE}. para 0xffff = power down
    //   (the factory-standard end), 0xfffe = charge mode.
    // sequence is echoed in CNF: use a distinct value for the exit so
    // a delayed program confirmation cannot be mistaken for exit success.
    static std::vector<uint8_t> encode_pctool_programkey_exit(
        uint16_t para, uint32_t sequence = 0);

    static std::expected<std::vector<uint8_t>, std::errc>
    encode_connect_add() { return encode_hdlc_chk(
        static_cast<uint8_t>(BslCommand::CMD_CONNECT), {}, Chk::Add); }
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_start_data_add(uint32_t addr, uint32_t size);
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_midst_data_add(std::span<const uint8_t> data);
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_midst_data_raw(std::span<const uint8_t> data);
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_end_data_add();
    // BSL_CMD_DIS_HDLC (0x21; OEM Global.h: "DisableTransCode - use the
    // non-escape function"). Fixed 8-byte wire `7e 00 21 00 00 ff de 7e`
    // (empty payload, ADD checksum 0xFFDE) — never an escape byte in
    // sight, so the frame is byte-identical under both parser modes
    // (safe to re-send to a device already switched).
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_disable_transcode();
    static std::expected<std::vector<uint8_t>, std::errc>
    encode_exec_add(uint32_t entry_addr);

private:
    static uint16_t be16(uint16_t v) {
        return static_cast<uint16_t>(((v & 0x00FF) << 8) | ((v & 0xFF00) >> 8));
    }
    static uint64_t be64(uint64_t v);

};

// No universal SRAM/DDR window: addresses come from the selected loader's
// linker map. This helper only checks a window explicitly supplied by callers.
// True if [addr, addr+size) lies inside the window; false otherwise.
bool check_load_window(uint32_t addr, uint32_t size, uint32_t lo, uint32_t hi);


}

#endif

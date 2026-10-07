#include <uniflash/protocol/bsl.h>
#include <uniflash/log.h>
#include <uniflash/protocol/tests.h>
#include <uniflash/cli/line_editor.h>
#include <uniflash/session/sparse.h>
#include <uniflash/session/pac_parser.h>
#include <algorithm>
#include <cstring>
#include <uniflash/platform.h>
#include <iostream>
#include <string>
#include <vector>
#include <span>
#include <cstdlib>

namespace uniflash::protocol {

static void check(bool cond, const char* msg, const char* file, int line) {
    if (!cond) {
        log_err(std::string("FAIL ") + file + ":" + std::to_string(line) + " " + msg);
        std::exit(1);
    }
    log_info(std::string("PASS: ") + msg);
}
#define CHECK(cond, msg) uniflash::protocol::check(cond, msg, __FILE__, __LINE__)

void run_tests() {
    log_info("protocol/bsl tests");

    auto crc = BslCodec::compute_crc16(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>("123456789"), 9));
    log_info("CRC16 reference computed: " + std::to_string(crc));
    CHECK(crc == 0x31C3, "CRC16 reference value");

    {
        std::vector<uint8_t> payload{0x01, 0x02, 0x03, 0x7E, 0x7D, 0x04};
        auto enc = BslCodec::encode_hdlc(static_cast<uint8_t>(BslCommand::CMD_START_DATA), payload);
        CHECK(enc.has_value(), "encode_hdlc OK");
        CHECK(enc.value().front() == HDLC_FLAG, "frame starts with 0x7E");
        CHECK(enc.value().back() == HDLC_FLAG, "frame ends with 0x7E");
        bool has_esc = false;
        for (uint8_t b : enc.value())
            if (b == HDLC_ESCAPE) { has_esc = true; break; }
        CHECK(has_esc, "HDLC escapes 0x7E/0x7D bytes");

        auto dec = BslCodec::decode_hdlc(std::span<const uint8_t>(enc.value()));
        CHECK(dec.has_value(), "decode_hdlc OK");
        CHECK(dec.value().first == static_cast<uint8_t>(BslCommand::CMD_START_DATA), "roundtrip cmd");
        CHECK(dec.value().second == payload, "roundtrip payload");
    }

    // Hardware-evidence regression (ud710 e2e#7): the FDL1 version frame
    // carries the ADD checksum (aa e9), not CRC16 — the wire checksum
    // flips with the receiver at the EXEC boundary, and the FDL1 one-shot
    // version frame is the first ADD frame on the link.
    {
        const uint8_t fdl1_ver[] = {
            0x7e, 0x00, 0x81, 0x00, 0x22,
            'S','p','r','e','a','d','t','r','u','m',' ','B','o','o','t',' ',
            'B','l','o','c','k',' ','v','e','r','s','i','o','n',' ','1','.','1','\0',
            0xaa, 0xe9, 0x7e
        };
        auto dec = BslCodec::decode_hdlc(
            std::span<const uint8_t>(fdl1_ver, sizeof(fdl1_ver)));
        CHECK(dec.has_value(), "decode accepts ADD-checksum FDL1 version frame");
        CHECK(dec.value().first == 0x81, "FDL1 version cmd = REP_VER");
        CHECK(dec.value().second.size() == 34, "FDL1 version payload = 34 bytes");
    }

    // ud710 bootrom quirk (e2e#9 hardware evidence): the ONLY frame whose
    // CRC16 bytes contained 0x7e/0x7d was the ONLY frame the bootrom
    // rejected (0x8B) — checksum-position escapes fail, payload-position
    // escapes pass. Vectors: {0x1b} -> CRC 0x7d03, {0xcb} -> 0xb67e,
    // {0x00} -> 0xde59 (clean).
    {
        const uint8_t dirty_hi[] = {0x1b};
        const uint8_t dirty_lo[] = {0xcb};
        const uint8_t clean[]    = {0x00};
        const auto mid =
            static_cast<uint16_t>(BslCommand::CMD_MIDST_DATA);
        CHECK(BslCodec::chk_carries_escape(BslCodec::Chk::Crc16, mid,
              std::span<const uint8_t>(dirty_hi)),
              "dirty CRC (hi=0x7d) flagged");
        CHECK(BslCodec::chk_carries_escape(BslCodec::Chk::Crc16, mid,
              std::span<const uint8_t>(dirty_lo)),
              "dirty CRC (lo=0x7e) flagged");
        CHECK(!BslCodec::chk_carries_escape(BslCodec::Chk::Crc16, mid,
              std::span<const uint8_t>(clean)),
              "clean CRC not flagged");
        CHECK(!BslCodec::chk_carries_escape(BslCodec::Chk::Add, mid,
              std::span<const uint8_t>(clean)),
              "clean ADD not flagged");
    }

    // KEEP_CHARGE frame (BSP set_chg_flag / u-boot sprdbat_init gate):
    // ADD over body {00 13 00 00} — word sum 0x0013 → chk ~0x0013 = 0xffec.
    {
        auto enc = BslCodec::encode_off_chg_add();
        CHECK(enc.has_value(), "encode_off_chg_add OK");
        const uint8_t want[] = {0x7e, 0x00, 0x13, 0x00, 0x00,
                                0xff, 0xec, 0x7e};
        CHECK(enc.value() == std::vector<uint8_t>(want, want + sizeof(want)),
              "off_chg frame bytes (ADD chk 0xffec)");
        auto dec = BslCodec::decode_hdlc(std::span<const uint8_t>(enc.value()));
        CHECK(dec.has_value() && dec.value().first == 0x13,
              "off_chg roundtrip cmd");
    }

    // U-Boot PC-tool mode frame (calibration_detect.c COMMAND_T, parsed by
    // check_pctool_cmd: 0xfe at offset 7, mode at offset 8, &0x3f):
    // mode 0x02 requests auto-download; the build chooses SPRD4 or bootrom.
    {
        auto mode = BslCodec::encode_pctool_mode(0x02);
        const uint8_t want[] = {0x7e, 0, 0, 0, 0, 0x08, 0x00, 0xfe,
                                0x02, 0x7e};
        CHECK(mode && *mode == std::vector<uint8_t>(want, want + sizeof(want)),
              "pctool mode 2 frame bytes");
        auto calibration = BslCodec::encode_pctool_mode(0x01);
        CHECK(calibration && calibration->size() == 10 &&
              (*calibration)[7] == 0xfe && (*calibration)[8] == 0x01,
              "pctool request carries the calibration mode byte");
    }

    // PROGRAMKEY dialog frames (calibration_detect.h MSG_HEAD_T layout:
    // seq u32=0, len u16, type=0x62, sub=0; DIAG_AP cmd 0x09 / exit 0x0a
    // with LE u16s). No BSL checksum — the raw diag protocol.
    {
        auto prog = BslCodec::encode_pctool_programkey();
        const uint8_t want[] = {0x7e, 0, 0, 0, 0, 0x0c, 0x00, 0x62, 0x00,
                                0x09, 0x00, 0x04, 0x00, 0x7e};
        CHECK(prog.size() == 14 &&
              prog == std::vector<uint8_t>(want, want + sizeof(want)),
              "programkey trigger frame (LEN_14)");
        auto ext = BslCodec::encode_pctool_programkey_exit(0xffff);
        const uint8_t want2[] = {0x7e, 0, 0, 0, 0, 0x0e, 0x00, 0x62, 0x00,
                                 0x0a, 0x00, 0x06, 0x00, 0xff, 0xff, 0x7e};
        CHECK(ext.size() == 16 &&
              ext == std::vector<uint8_t>(want2, want2 + sizeof(want2)),
              "programkey exit frame (LEN_16, para 0xffff)");
        auto chg = BslCodec::encode_pctool_programkey_exit(0xfffe);
        CHECK(chg[13] == 0xfe && chg[14] == 0xff,
              "programkey exit para LE");
    }

    // ENABLE_WRITE_FLASH (0x1B): the u-boot dloader's software write
    // interlock — ADD form over body {00 1b 00 00}: word sum 0x001b ->
    // chk ~0x001b = 0xffe4.
    {
        auto enc = BslCodec::encode_enable_write_flash();
        CHECK(enc.has_value(), "encode_enable_write_flash OK");
        const uint8_t want[] = {0x7e, 0x00, 0x1b, 0x00, 0x00,
                                0xff, 0xe4, 0x7e};
        CHECK(enc.value() == std::vector<uint8_t>(want, want + sizeof(want)),
              "enable-write frame bytes (ADD chk 0xffe4)");
    }

    // The FDL2 encoder family must ALL use the ADD form (the u-boot
    // dloader validates frm_chk; the CRC16 convenience encoders were a
    // systemic ums9621-era error — the 8th audit sweep fixed 20 of them).
    // Vectors: empty-body commands' chk = ~type; DDR SR TEST carries a
    // u32 LE timeout (1000 ms -> body ...e8 03 00 00, sum 0xe82e ->
    // chk 0x17d1).
    {
        struct Vec { const char* name; std::vector<uint8_t> got;
                     std::vector<uint8_t> want; };
        std::vector<Vec> v;
        auto add = [&](const char* n,
                       std::expected<std::vector<uint8_t>, std::errc> e,
                       std::vector<uint8_t> w) {
            CHECK(e.has_value(), (std::string(n) + " OK").c_str());
            if (e) v.push_back({n, e.value(), std::move(w)});
        };
        add("check_partition", BslCodec::encode_check_partition(),
            {0x7e, 0x00, 0x2d, 0x00, 0x00, 0xff, 0xd2, 0x7e});
        add("ddr_verify", BslCodec::encode_ddr_verify(),
            {0x7e, 0x00, 0x26, 0x00, 0x00, 0xff, 0xd9, 0x7e});
        add("ddr_sr_test(1000)", BslCodec::encode_ddr_sr_test(1000),
            {0x7e, 0x00, 0x27, 0x00, 0x04, 0xe8, 0x03, 0x00, 0x00,
             0x17, 0xd1, 0x7e});
        add("end_process", BslCodec::encode_end_process(),
            {0x7e, 0x00, 0x7f, 0x00, 0x00, 0xff, 0x80, 0x7e});
        add("write_raw_data_enable",
            BslCodec::encode_write_raw_data_enable(),
            {0x7e, 0x00, 0x28, 0x00, 0x00, 0xff, 0xd7, 0x7e});
        add("check_nv_type", BslCodec::encode_check_nv_type(),
            {0x7e, 0x00, 0x24, 0x00, 0x00, 0xff, 0xdb, 0x7e});
        add("check_nv_type", BslCodec::encode_check_nv_type(),
            {0x7e, 0x00, 0x24, 0x00, 0x00, 0xff, 0xdb, 0x7e});
        for (auto& x : v)
            CHECK(x.got == x.want,
                  (std::string(x.name) + " ADD-form bytes").c_str());
    }

    // Sparse wrap: a raw image becomes a sparse container the FDL2's
    // write_sparse_img decodes (magic 0xed26ff3a, 28B header, 12B RAW
    // chunk headers, 4096B blocks); an already-sparse input passes
    // through unchanged.
    {
        const uint8_t raw[5000] = {};
        auto sp = wrap_as_sparse(raw, sizeof(raw));
        CHECK(sp.size() == 28 + 12 + 2 * 4096,
              "sparse container built (header+chunk+2 blocks)");
        CHECK((static_cast<uint32_t>(sp[0]) |
               (static_cast<uint32_t>(sp[1]) << 8) |
               (static_cast<uint32_t>(sp[2]) << 16) |
               (static_cast<uint32_t>(sp[3]) << 24)) == SPARSE_MAGIC,
              "sparse magic");
        // total_blks = ceil(5000/4096) = 2; chunk = 2 blocks; total_sz
        // = 12 + 8192; data intact at 28+12
        CHECK(sp[16] == 2, "total_blks = 2");
        CHECK(sp[20] == 1, "total_chunks = 1");
        CHECK(sp[28] == static_cast<uint8_t>(0xCAC1) &&
              sp[29] == static_cast<uint8_t>(0xCA),
              "chunk type RAW (0xCAC1 LE)");
        CHECK(sp.size() == 28 + 12 + 2 * 4096, "padded to whole blocks");
        CHECK(std::equal(raw, raw + 5000, sp.begin() + 40),
              "payload bytes intact");
        auto again = wrap_as_sparse(sp.data(), sp.size());
        CHECK(again == sp, "already-sparse passthrough");
    }

    {
        auto enc = BslCodec::encode_start_data(0x90000000, 0x1000);
        CHECK(enc.has_value(), "encode_start_data OK");
        auto dec = BslCodec::decode_hdlc(std::span<const uint8_t>(enc.value()));
        CHECK(dec.has_value(), "decode_start_data OK");
        CHECK(dec.value().first == static_cast<uint8_t>(BslCommand::CMD_START_DATA), "cmd = START_DATA");
        CHECK(dec.value().second.size() == 8, "payload = 8 bytes (addr+size)");
    }

    {
        auto enc = BslCodec::encode_connect();
        CHECK(enc.has_value(), "encode_connect OK");
        auto dec = BslCodec::decode_hdlc(std::span<const uint8_t>(enc.value()));
        CHECK(dec.has_value(), "decode_connect OK");
        CHECK(dec.value().first == static_cast<uint8_t>(BslCommand::CMD_CONNECT), "cmd = CONNECT");
        CHECK(dec.value().second.empty(), "CONNECT has no payload");
    }

    {
        auto enc = BslCodec::encode_exec(0x90000000);
        CHECK(enc.has_value(), "encode_exec OK");
        auto dec = BslCodec::decode_hdlc(std::span<const uint8_t>(enc.value()));
        CHECK(dec.has_value(), "decode_exec OK");
        CHECK(dec.value().first == static_cast<uint8_t>(BslCommand::CMD_EXEC_DATA), "cmd = EXEC_DATA");
    }

    {
        auto enc = BslCodec::encode_normal_reset();
        CHECK(enc.has_value(), "encode_normal_reset OK");
        auto dec = BslCodec::decode_hdlc(std::span<const uint8_t>(enc.value()));
        CHECK(dec.has_value(), "decode_normal_reset OK");
        CHECK(dec.value().first == static_cast<uint8_t>(BslCommand::CMD_NORMAL_RESET), "cmd = RESET");
    }

    {
        // The FDL2 wire form: ADD checksum (dl_cmd_reboot validates
        // with frm_chk). Frame: 7e 00 05 00 00 <chk> 7e; the ADD sum
        // over body (00 05 00 00) = 0x0005 -> chk 0xFFFA.
        auto enc = BslCodec::encode_normal_reset_add();
        CHECK(enc.has_value(), "encode_normal_reset_add OK");
        CHECK(enc.value().size() == 8, "reset_add frame = 8 bytes");
        CHECK(enc.value()[0] == 0x7e && enc.value()[1] == 0x00 &&
              enc.value()[2] == 0x05 && enc.value()[3] == 0x00 &&
              enc.value()[4] == 0x00 && enc.value()[7] == 0x7e,
              "reset_add header/footer correct");
        CHECK(enc.value()[5] == 0xff && enc.value()[6] == 0xfa,
              "reset_add ADD checksum = fffa");
    }

    {
        // POWER_DOWN (0x17) in the FDL2 ADD form (dl_powerdown_device
        // ACKs, then waits for charger unplug before dying). ADD sum
        // over (00 17 00 00) = 0x0017 -> chk 0xFFE8.
        auto enc = BslCodec::encode_hdlc_chk(
            static_cast<uint8_t>(BslCommand::CMD_POWER_DOWN), {},
            BslCodec::Chk::Add);
        CHECK(enc.has_value(), "encode_power_down OK");
        CHECK(enc.value().size() == 8, "power_down frame = 8 bytes");
        CHECK(enc.value()[0] == 0x7e && enc.value()[2] == 0x17 &&
              enc.value()[7] == 0x7e, "power_down header/footer correct");
        CHECK(enc.value()[5] == 0xff && enc.value()[6] == 0xe8,
              "power_down ADD checksum = ffe8");
    }

    {
        auto enc = BslCodec::encode_enable_write_flash();
        CHECK(enc.has_value(), "encode_enable_write_flash OK");
        auto dec = BslCodec::decode_hdlc(std::span<const uint8_t>(enc.value()));
        CHECK(dec.has_value(), "decode_enable_write_flash OK");
        CHECK(dec.value().first == static_cast<uint8_t>(BslCommand::CMD_ENABLE_WRITE_FLASH),
              "cmd = ENABLE_WRITE_FLASH");
    }

    {
        auto enc = BslCodec::encode_erase_flash("system", 0x100000);
        CHECK(enc.has_value(), "encode_erase_flash OK");
        auto dec = BslCodec::decode_hdlc(std::span<const uint8_t>(enc.value()));
        CHECK(dec.has_value(), "decode_erase_flash OK");
        CHECK(dec.value().first == static_cast<uint8_t>(BslCommand::CMD_ERASE_FLASH), "cmd = ERASE_FLASH");
        CHECK(dec.value().second.size() == 72 + 8 + 8,
              "erase payload = 72(name UTF-16LE)+8(size LE)+8(rev LE)");
    }

    {
        auto enc = BslCodec::encode_read_flash_start("boot", 0x40000);
        CHECK(enc.has_value(), "encode_read_flash_start OK");
        CHECK(enc.value().size() == 76 + 8,
              "read start = BIT32 (76B payload + 8 framing)");
        auto dec = BslCodec::decode_hdlc(std::span<const uint8_t>(enc.value()));
        CHECK(dec.has_value(), "decode_read_flash_start OK");
        CHECK(dec.value().first == static_cast<uint8_t>(BslCommand::CMD_READ_FLASH_START),
              "cmd = READ_FLASH_START");
    }

    {
        auto enc = BslCodec::encode_read_flash_midst(0x1000, 0x10000);
        CHECK(enc.has_value(), "encode_read_flash_midst OK");
        auto dec = BslCodec::decode_hdlc(std::span<const uint8_t>(enc.value()));
        CHECK(dec.has_value(), "decode_read_flash_midst OK");
        CHECK(dec.value().first == static_cast<uint8_t>(BslCommand::CMD_READ_FLASH_MIDST),
              "cmd = READ_FLASH_MIDST");
        // factory form: 8 bytes = {size u32 LE, offset u32 LE}
        CHECK(dec.value().second.size() == 8, "midst payload = 8 bytes");
        uint32_t v = 0;
        std::memcpy(&v, dec.value().second.data(), 4);
        CHECK(v == 0x1000, "midst size field u32 LE");
        std::memcpy(&v, dec.value().second.data() + 4, 4);
        CHECK(v == 0x10000, "midst offset field u32 LE");
    }

    {
        auto enc = BslCodec::encode_check_partition();
        CHECK(enc.has_value(), "encode_check_partition OK");
        auto dec = BslCodec::decode_hdlc(std::span<const uint8_t>(enc.value()));
        CHECK(dec.has_value(), "decode_check_partition OK");
        CHECK(dec.value().first == static_cast<uint8_t>(BslCommand::CMD_CHECK_PARTITION),
              "cmd = CHECK_PARTITION");
    }

    {
        auto enc = BslCodec::encode_read_chip_type();
        CHECK(enc.has_value(), "encode_read_chip_type OK");
        auto dec = BslCodec::decode_hdlc(std::span<const uint8_t>(enc.value()));
        CHECK(dec.has_value(), "decode_read_chip_type OK");
        CHECK(dec.value().first == static_cast<uint8_t>(BslCommand::CMD_READ_CHIP_TYPE),
              "cmd = READ_CHIP_TYPE");
    }

    {
        auto enc = BslCodec::encode_read_uid();
        CHECK(enc.has_value(), "encode_read_uid OK");
        auto dec = BslCodec::decode_hdlc(std::span<const uint8_t>(enc.value()));
        CHECK(dec.has_value(), "decode_read_uid OK");
        CHECK(dec.value().first == static_cast<uint8_t>(BslCommand::CMD_READ_UID), "cmd = READ_UID");
    }

    {
        auto enc = BslCodec::encode_end_process();
        CHECK(enc.has_value(), "encode_end_process OK");
        auto dec = BslCodec::decode_hdlc(std::span<const uint8_t>(enc.value()));
        CHECK(dec.has_value(), "decode_end_process OK");
        CHECK(dec.value().first == static_cast<uint8_t>(BslCommand::CMD_END_PROCESS), "cmd = END_PROCESS");
    }

    {
        auto enc = BslCodec::encode_write_raw_data_enable();
        CHECK(enc.has_value(), "encode_write_raw_data_enable OK");
        auto dec = BslCodec::decode_hdlc(std::span<const uint8_t>(enc.value()));
        CHECK(dec.has_value(), "decode_write_raw_data_enable OK");
        CHECK(dec.value().first == static_cast<uint8_t>(BslCommand::CMD_WRITE_RAW_DATA_ENABLE),
              "cmd = WRITE_RAW_DATA_ENABLE");
    }

    {
        auto enc = BslCodec::encode_dload_whole_raw_start(0x4000000);
        CHECK(enc.has_value(), "encode_dload_whole_raw_start OK");
        auto dec = BslCodec::decode_hdlc(std::span<const uint8_t>(enc.value()));
        CHECK(dec.has_value(), "decode_dload_whole_raw_start OK");
        CHECK(dec.value().first == static_cast<uint8_t>(BslCommand::CMD_DLOAD_RAW_START2),
              "cmd = DLOAD_RAW_START2 (whole-file 0x33)");
    }

    {
        auto enc = BslCodec::encode_normal_reset();
        CHECK(enc.has_value(), "encode_reboot OK");
        auto dec = BslCodec::decode_hdlc(std::span<const uint8_t>(enc.value()));
        CHECK(dec.has_value(), "decode_reboot OK");
        CHECK(dec.value().first == static_cast<uint8_t>(BslCommand::CMD_NORMAL_RESET), "cmd = REBOOT(normal_reset)");
    }

    {
        // Reply-code naming for failure diagnostics (dl_cmd_def.h set)
        CHECK(std::string(BslCodec::reply_name(0x80)) == "ACK",
              "reply_name 0x80 = ACK");
        CHECK(std::string(BslCodec::reply_name(0x8A)) == "DOWN_SIZE_ERROR",
              "reply_name 0x8A = DOWN_SIZE_ERROR");
        CHECK(std::string(BslCodec::reply_name(0x8B)) == "VERIFY_ERROR",
              "reply_name 0x8B = VERIFY_ERROR");
        CHECK(std::string(BslCodec::reply_name(0xFE)) == "UNSUPPORTED_CMD",
              "reply_name 0xFE = UNSUPPORTED_CMD");
        CHECK(std::string(BslCodec::reply_name(0x12)) == "unknown",
              "reply_name unmapped byte = unknown");
    }

    {
        auto enc = BslCodec::encode_off_chg_add();
        CHECK(enc.has_value(), "encode_off_chg_add OK");
        auto dec = BslCodec::decode_hdlc(std::span<const uint8_t>(enc.value()));
        CHECK(dec.has_value(), "decode_off_chg_add OK");
        CHECK(dec.value().first == static_cast<uint8_t>(BslCommand::CMD_OFF_CHG), "cmd = OFF_CHG");
    }

    {
        // 0x21 DISABLE_TRANSCODE: fixed escape-free 8-byte frame
        // (type 0x0021, empty payload, ADD chk 0xFFDE)
        auto enc = BslCodec::encode_disable_transcode();
        CHECK(enc.has_value(), "encode_disable_transcode OK");
        const uint8_t expect[8] = {0x7e, 0x00, 0x21, 0x00, 0x00,
                                   0xff, 0xde, 0x7e};
        CHECK(enc.value().size() == 8 &&
              0 == std::memcmp(enc.value().data(), expect, 8),
              "disable_transcode = 7e 00 21 00 00 ff de 7e");
    }

    {
        // raw MIDST: payload rides the wire verbatim (no 7d 5e/7d 5d)
        const uint8_t payload[] = {0x7e, 0x11, 0x7d, 0x22, 0x00};
        auto enc = BslCodec::encode_midst_data_raw(payload);
        CHECK(enc.has_value(), "encode_midst_data_raw OK");
        const auto& f = enc.value();
        CHECK(f.size() == sizeof(payload) + 8,
              "raw midst wire = payload + 8");
        CHECK(f[0] == 0x7e && f[1] == 0x00 && f[2] == 0x02 &&
              f[3] == 0x00 && f[4] == sizeof(payload),
              "raw midst header = 7e 00 02 00 <size>");
        CHECK(f[5] == 0x7e && f[7] == 0x7d,
              "raw payload bytes pass through verbatim");
        bool has_escape_pair = false;
        for (size_t i = 5; i + 1 < f.size() - 2; ++i)
            if (f[i] == 0x7d && (f[i + 1] == 0x5e || f[i + 1] == 0x5d))
                has_escape_pair = true;
        CHECK(!has_escape_pair, "no escape pairs anywhere in raw body");
    }

    {
        auto payload = BslCodec::make_partition_payload("system", 0x80000);
        CHECK(payload.size() == 72 + 8 + 8,
              "partition payload (no checksum) = 88 bytes");
        // UTF-16LE name: char at even offsets
        CHECK(payload[0] == 's' && payload[1] == 0 && payload[2] == 'y' &&
              payload[10] == 'm', "name field UTF-16LE correct");
        uint64_t sz = 0;
        std::memcpy(&sz, payload.data() + 72, 8);
        CHECK(sz == 0x80000, "size field little-endian correct");
    }

    {
        auto payload = BslCodec::make_partition_payload32("vendor", 0x22600000);
        CHECK(payload.size() == 72 + 4,
              "partition payload32 (BIT32) = 76 bytes");
        // UTF-16LE name: char at even offsets ("vendor": v@0 r@10)
        CHECK(payload[0] == 'v' && payload[1] == 0 && payload[10] == 'r',
              "payload32 name field UTF-16LE correct");
        uint32_t sz = 0;
        std::memcpy(&sz, payload.data() + 72, 4);
        CHECK(sz == 0x22600000, "payload32 size field u32 LE correct");
    }

    {
        std::vector<uint8_t> raw_table(sizeof(ToolPartitionEntry) * 2, 0);
        // Entry 0: name "test" as UTF-16LE, size 1024 KB LE
        const char* nm = "test";
        for (int j = 0; j < 4; ++j) raw_table[2*j] = (uint8_t)nm[j];
        uint32_t kb = platform::little_endian(uint32_t{1024});
        std::memcpy(raw_table.data() + 72, &kb, 4);
        auto dec = BslCodec::decode_partition_table(raw_table);
        CHECK(dec.has_value(), "decode_partition_table OK");
        CHECK(dec.value().size() == 2, "2 entries");
        CHECK(std::string(reinterpret_cast<const char*>(dec.value()[0].name))
                  .substr(0, 4) == "test",
              "decoded name UTF-16LE folded to ASCII");
        CHECK(dec.value()[0].size_kb == 1024, "decoded size LE correct");
    }

    {
        // Large payload encoding to test max size boundary
        std::vector<uint8_t> big(0x1000, 0xAA);
        auto enc = BslCodec::encode_midst_data(big);
        CHECK(enc.has_value(), "encode_midst_data 4KB");
        auto dec = BslCodec::decode_hdlc(std::span<const uint8_t>(enc.value()));
        CHECK(dec.has_value(), "decode_midst_data 4KB");
        CHECK(dec.value().second.size() == 0x1000, "roundtrip 4KB");
    }

    {
        // Test payload that contains 0x7E and 0x7D in every byte
        std::vector<uint8_t> tricky;
        for (int i = 0; i < 256; ++i) tricky.push_back((uint8_t)i);
        auto enc = BslCodec::encode_midst_data(tricky);
        CHECK(enc.has_value(), "encode 0-255 byte payload");
        auto dec = BslCodec::decode_hdlc(std::span<const uint8_t>(enc.value()));
        CHECK(dec.has_value(), "decode full byte range");
        CHECK(dec.value().second == tricky, "roundtrip 0-255 bytes exact");
    }

    {
        // Repartition table encoding
        std::vector<uint8_t> table;
        for (int i = 0; i < 32; ++i) table.push_back(i & 0xFF);
        auto enc = BslCodec::encode_repartition(table);
        CHECK(enc.has_value(), "encode_repartition OK");
        auto dec = BslCodec::decode_hdlc(std::span<const uint8_t>(enc.value()));
        CHECK(dec.has_value(), "decode_repartition OK");
        CHECK(dec.value().first == static_cast<uint8_t>(BslCommand::CMD_REPARTITION), "cmd = REPARTITION");
    }

    {
        // DA_INFO capability frame: magic 0x7477656e then TLV entries.
        // Build: magic + E_DISABLE_TRAN_CODE(0)=1 + E_SUPPORT_RAW_DATA(2)=2
        // + E_FLUSH_SIZE(3)=2048 + E_STORAGE_TYPE(6)=0x102 (emmc)
        std::vector<uint8_t> body;
        auto put16 = [&](uint16_t v) { body.push_back(v & 0xFF); body.push_back(v >> 8); };
        auto put32 = [&](uint32_t v) {
            body.push_back(v & 0xFF); body.push_back((v >> 8) & 0xFF);
            body.push_back((v >> 16) & 0xFF); body.push_back((v >> 24) & 0xFF);
        };
        put32(0x7477656e);  // magic
        put16(0); put16(4); put32(1);                 // disable_hdlc = 1
        put16(2); put16(1); body.push_back(2);         // support_raw = 2
        put16(3); put16(4); put32(2048);               // flush_kb = 2048
        put16(4); put16(4); put32(2);                  // RSA capability, not storage
        put16(6); put16(4); put32(0x102);              // storage = emmc
        auto da = parse_da_info(body);
        CHECK(da.has_value(), "parse_da_info OK");
        CHECK(da->disable_hdlc, "disable_hdlc parsed");
        CHECK(da->support_raw, "support_raw parsed");
        CHECK(da->flush_kb == 2048, "flush_kb parsed");
        CHECK(da->storage == 0x102, "storage = emmc");
        put16(3); put16(1);                            // truncated TLV invalidates capabilities
        CHECK(!parse_da_info(body), "truncated DA_INFO is rejected");
    }

    {
        // Wrong magic -> nullopt
        std::vector<uint8_t> bad{0xde, 0xad, 0xbe, 0xef};
        CHECK(!parse_da_info(bad).has_value(), "bad magic -> nullopt");
    }

    {
        // for_each_raw_chunk splits at RAW_CHUNK_SIZE (2MB) boundaries.
        auto sizes = [](uint64_t total) {
            std::vector<uint64_t> v;
            for_each_raw_chunk(total, [&](uint64_t, uint64_t n){ v.push_back(n); });
            return v;
        };
        auto one = std::vector<uint64_t>{0};
        CHECK(sizes(0) == one, "chunk total=0 -> [0]");
        auto two = std::vector<uint64_t>{1};
        CHECK(sizes(1) == two, "chunk total=1 -> [1]");
        auto three = std::vector<uint64_t>{0x1FFFFF};
        CHECK(sizes(0x1FFFFF) == three, "chunk <2MB single");
        auto four = std::vector<uint64_t>{RAW_CHUNK_SIZE};
        CHECK(sizes(RAW_CHUNK_SIZE) == four, "chunk ==2MB one");
        auto five = std::vector<uint64_t>{RAW_CHUNK_SIZE, 1};
        CHECK(sizes(RAW_CHUNK_SIZE + 1) == five, "chunk 2MB+1 -> [2MB,1]");
        auto six = std::vector<uint64_t>{RAW_CHUNK_SIZE, RAW_CHUNK_SIZE};
        CHECK(sizes(2ULL * RAW_CHUNK_SIZE) == six, "chunk 4MB -> [2MB,2MB]");
        auto seven = std::vector<uint64_t>{RAW_CHUNK_SIZE, RAW_CHUNK_SIZE, 0x100001};
        CHECK(sizes(0x500001) == seven, "chunk 0x500001 -> [2MB,2MB,0x100001]");
    }

    {
        // Arithmetic fixture only; these are not a device's default window.
        constexpr uint32_t FDL2_WIN_LO = 0x80000000u, FDL2_WIN_HI = 0xc0000000u;
        CHECK(check_load_window(FDL2_WIN_LO, 0, FDL2_WIN_LO, FDL2_WIN_HI),
              "FDL2 exact base in window");
        CHECK(!check_load_window(FDL2_WIN_LO - 1, 0, FDL2_WIN_LO, FDL2_WIN_HI),
              "FDL2 below base rejected");
        CHECK(!check_load_window(FDL2_WIN_HI, 0, FDL2_WIN_LO, FDL2_WIN_HI),
              "FDL2 at top excluded (half-open)");
        CHECK(check_load_window(FDL2_WIN_LO, 0x40000000, FDL2_WIN_LO, FDL2_WIN_HI),
              "FDL2 full 1GB in window");
        CHECK(!check_load_window(FDL2_WIN_LO, 0x40000001, FDL2_WIN_LO, FDL2_WIN_HI),
              "FDL2 1GB+1 overflow rejected");
    }

    {
        // BSL_CMD_SET_DEBUGINFO (0x25): payload is the raw debug string;
        // device accepts 0..31 bytes (dl_cmd_proc.c dl_cmd_set_debuginfo).
        std::vector<uint8_t> str{'e','n','a','b','l','e'};
        auto enc = BslCodec::encode_set_debuginfo(str);
        CHECK(enc.has_value(), "encode_set_debuginfo OK");
        auto dec = BslCodec::decode_hdlc(std::span<const uint8_t>(enc.value()));
        CHECK(dec.has_value(), "decode_set_debuginfo OK");
        CHECK(dec.value().first == static_cast<uint8_t>(BslCommand::CMD_SET_DEBUGINFO),
              "set_debuginfo roundtrip cmd 0x25");
        CHECK(dec.value().second == str, "set_debuginfo roundtrip payload");
        auto empty = BslCodec::encode_set_debuginfo({});
        CHECK(empty.has_value() && empty.value().size() >= 6,
              "encode_set_debuginfo empty payload OK");
    }

    {
        // Sparse (Android) image handling — ground truth: BSP
        // u-boot15/common/dloader/sparse_img.c + sparse_crc32.c.
        using uniflash::session::crc32_update;
        using uniflash::session::SparseChunkHeader;
        using uniflash::session::SparseHeader;
        using uniflash::session::CHUNK_TYPE_CRC32;
        using uniflash::session::CHUNK_TYPE_DONT_CARE;
        using uniflash::session::CHUNK_TYPE_FILL;
        using uniflash::session::CHUNK_TYPE_RAW;
        using uniflash::session::expand_sparse;

        const uint8_t check_vec[] = {'1','2','3','4','5','6','7','8','9'};
        CHECK(crc32_update(0, check_vec) == 0xCBF43926u,
              "crc32 zlib check vector");
        const uint8_t half1[] = {'1','2','3','4'};
        const uint8_t half2[] = {'5','6','7','8','9'};
        uint32_t chained = crc32_update(crc32_update(0, half1), half2);
        CHECK(chained == 0xCBF43926u, "crc32 chaining a||b");

        CHECK(sizeof(SparseChunkHeader) == 12, "sparse chunk header is 12B");

        auto put16 = [](std::vector<uint8_t>& v, uint16_t x) {
            v.push_back(static_cast<uint8_t>(x));
            v.push_back(static_cast<uint8_t>(x >> 8));
        };
        auto put32 = [](std::vector<uint8_t>& v, uint32_t x) {
            for (int i = 0; i < 4; ++i)
                v.push_back(static_cast<uint8_t>(x >> (8 * i)));
        };

        auto make_header = [&](uint32_t blk_sz, uint32_t total_blks,
                               uint32_t total_chunks) {
            std::vector<uint8_t> v;
            put32(v, 0xED26FF3Au);
            put16(v, 1); put16(v, 0);
            put16(v, 28); put16(v, 12);
            put32(v, blk_sz); put32(v, total_blks);
            put32(v, total_chunks); put32(v, 0);
            return v;
        };
        auto make_chunk = [&](uint16_t type, uint32_t chunk_sz,
                              uint32_t total_sz) {
            std::vector<uint8_t> v;
            put16(v, type); put16(v, 0);
            put32(v, chunk_sz); put32(v, total_sz);
            return v;
        };

        const uint8_t raw_data[] = {0xDE, 0xAD, 0xBE, 0xEF,
                                    0x10, 0x20, 0x30, 0x40};
        {
            std::vector<uint8_t> img = make_header(4, 2, 2);
            auto c1 = make_chunk(CHUNK_TYPE_RAW, 2, 12 + 8);
            img.insert(img.end(), c1.begin(), c1.end());
            img.insert(img.end(), raw_data, raw_data + 8);
            auto c2 = make_chunk(CHUNK_TYPE_CRC32, 0, 12 + 4);
            img.insert(img.end(), c2.begin(), c2.end());
            put32(img, crc32_update(0, raw_data));
            auto out = expand_sparse(img);
            CHECK(out.has_value(), "sparse RAW+CRC32 expands");
            CHECK(out.value().size() == 8 &&
                  std::equal(raw_data, raw_data + 8, out.value().begin()),
                  "sparse RAW data roundtrip");
        }
        {
            std::vector<uint8_t> img = make_header(4, 2, 2);
            auto c1 = make_chunk(CHUNK_TYPE_RAW, 2, 12 + 8);
            img.insert(img.end(), c1.begin(), c1.end());
            img.insert(img.end(), raw_data, raw_data + 8);
            auto c2 = make_chunk(CHUNK_TYPE_CRC32, 0, 12 + 4);
            img.insert(img.end(), c2.begin(), c2.end());
            put32(img, 0xDEADBEEFu);
            auto out = expand_sparse(img);
            CHECK(!out.has_value(), "sparse CRC32 mismatch rejected");
        }
        {
            // Android sparse block sizes are multiples of four bytes.
            std::vector<uint8_t> img = make_header(8, 1, 2);
            auto c1 = make_chunk(CHUNK_TYPE_FILL, 1, 12 + 4);
            img.insert(img.end(), c1.begin(), c1.end());
            put32(img, 0xDDCCBBAAu);
            auto c2 = make_chunk(CHUNK_TYPE_CRC32, 0, 12 + 4);
            img.insert(img.end(), c2.begin(), c2.end());
            const uint8_t pat[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB, 0xCC, 0xDD};
            put32(img, crc32_update(0, pat));
            auto out = expand_sparse(img);
            CHECK(out.has_value() && out.value().size() == 8,
                  "sparse FILL expands to 8B");
            if (out.has_value() && out.value().size() == 8)
                CHECK(std::equal(pat, pat + 8, out.value().begin()),
                      "sparse FILL repeats the little-endian pattern");
        }
        {
            // Malformed sparse must be an ERROR, not a silent passthrough.
            std::vector<uint8_t> img = make_header(4, 1, 1);
            auto c1 = make_chunk(CHUNK_TYPE_RAW, 2, 12 + 8);
            img.insert(img.end(), c1.begin(), c1.end());
            img.insert(img.end(), raw_data, raw_data + 4);  // short by 4
            auto out = expand_sparse(img);
            CHECK(!out.has_value(), "truncated sparse rejected");
        }
    }

    {
        // Repartition table — ground truth dl_cmd_proc.c
        // _parse_repartition_header: magic "par:" (0x3A726170 native LE),
        // version@4, unit@5, count@6, reserved@7, table_tag@8(LE32),
        // table_offset@12(LE16), table_size@14(LE16); v1 entry = name 72B
        // UTF-16LE + size LE u64 + gap LE u64 (dl_operate.c:311-406).
        using uniflash::session::PacImage;
        using uniflash::session::PacPartition;
        using uniflash::session::PacParser;

        PacImage img;
        PacPartition p1; p1.name = "boot";   p1.size = 0x10000;
        PacPartition p2; p2.name = "system"; p2.size = 0x100000;
        img.partitions = {p1, p2};

        auto t = PacParser::build_repartition_table(img);
        CHECK(t.has_value(), "repartition table builds");
        const auto& b = t.value();
        CHECK(b.size() == 16 + 2 * 88, "repartition table size 16+2*88");
        CHECK(b[0] == 0x70 && b[1] == 0x61 && b[2] == 0x72 && b[3] == 0x3A,
              "repartition magic is \"par:\" LE");
        CHECK(b[4] == 1, "repartition version 1");
        CHECK(b[5] == 3, "repartition unit 3 (bytes)");
        CHECK(b[6] == 1, "repartition table count 1");
        CHECK(b[12] == 16 && b[13] == 0, "repartition table_offset 16 LE");
        CHECK(b[14] == 176 && b[15] == 0, "repartition table_size 176 LE");
        CHECK(b[16] == 'b' && b[17] == 0 && b[18] == 'o' && b[19] == 0,
              "repartition name is UTF-16LE");
        auto le64at = [](const std::vector<uint8_t>& v, size_t o) {
            uint64_t x = 0;
            for (int i = 7; i >= 0; --i)
                x = (x << 8) | v[o + static_cast<size_t>(i)];
            return x;
        };
        CHECK(le64at(b, 16 + 72) == 0x10000, "repartition p1 size LE u64");
        CHECK(le64at(b, 16 + 88 + 72) == 0x100000,
              "repartition p2 size LE u64");
    }

    {
        // UTF-8 line editing: codepoint navigation + display width.
        using uniflash::cli::utf8_prev_cp;
        using uniflash::cli::utf8_next_cp;
        using uniflash::cli::utf8_cp_width;
        using uniflash::cli::utf8_width;

        const std::string zh = "\xE5\x88\x86\xE5\x8C\xBA";  // "分区" (2 cp)
        CHECK(zh.size() == 6, "分区 is 6 UTF-8 bytes");
        CHECK(utf8_prev_cp(zh, 6) == 3, "prev cp from end -> byte 3");
        CHECK(utf8_prev_cp(zh, 3) == 0, "prev cp -> byte 0");
        CHECK(utf8_prev_cp(zh, 0) == 0, "prev cp at 0 stays 0");
        CHECK(utf8_next_cp(zh, 0) == 3, "next cp 0 -> 3");
        CHECK(utf8_next_cp(zh, 3) == 6, "next cp 3 -> 6");
        CHECK(utf8_next_cp(zh, 6) == 6, "next cp at end stays");

        CHECK(utf8_cp_width(zh, 0) == 2, "分区 cp width 2");
        CHECK(utf8_cp_width(zh, 3) == 2, "区 cp width 2");
        CHECK(utf8_cp_width("a", 0) == 1, "ASCII width 1");
        CHECK(utf8_cp_width("\xEF\xBC\xA1", 0) == 2,
              "fullwidth A (U+FF21) width 2");  // "Ａ"
        CHECK(utf8_cp_width("\xC3\xA9", 0) == 1, "é width 1");

        CHECK(utf8_width(zh, 0, 6) == 4, "分区 total width 4");
        CHECK(utf8_width("a" + zh + "b", 0, 8) == 6, "a分区b width 6");
        // cursor rewind after 2nd cp: from mid-sequence pos it still sums
        // from the broken boundary as isolated continuation bytes (1 col).
        CHECK(utf8_width(zh, 4, 6) == 2,
              "mid-sequence tail counted as 2 isolated bytes");

        // Stray continuation byte: forward it is its own 1-column unit
        // (cp_len=1); backward, prev_cp walks over it to the lead byte.
        // (The old literal "a\x80b" was a GCC out-of-range escape that
        // silently truncated to 'a'+0x0b — no stray byte ever tested.)
        const std::string stray = "a\x80" "b";
        CHECK(utf8_prev_cp(stray, 2) == 0, "stray cc prev walks to lead");
        CHECK(utf8_next_cp(stray, 1) == 2, "stray cc next");
        CHECK(utf8_cp_width(stray, 1) == 1, "stray cc width 1");
    }

    {
        // Quoted command-line tokens: '...' / "..." may contain spaces,
        // quotes are stripped; bare tokens stop at whitespace.
        using uniflash::cli::next_token;
        std::istringstream ss("'/path/刷 机/fdl1.bin'  0x5500 "
                              "\"b c.bin\" plain");
        std::string t;
        CHECK(next_token(ss, t) && t == "/path/刷 机/fdl1.bin",
              "next_token single-quoted with space + CJK");
        CHECK(next_token(ss, t) && t == "0x5500",
              "next_token bare, skips extra spaces");
        CHECK(next_token(ss, t) && t == "b c.bin",
              "next_token double-quoted");
        CHECK(next_token(ss, t) && t == "plain", "next_token plain");
        CHECK(!next_token(ss, t), "next_token exhausted");

        std::istringstream u("'unterminated rest");
        bool rejected = false;
        try { (void)next_token(u, t); } catch (const std::invalid_argument&) { rejected = true; }
        CHECK(rejected, "next_token rejects unterminated quotes");

        std::istringstream e("   ");
        CHECK(!next_token(e, t), "next_token blank input");
    }

    log_info("All protocol tests passed");
}

}

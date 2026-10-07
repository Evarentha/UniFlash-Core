#include <uniflash/protocol/bsl.h>
#include <cstring>
#include <set>
#include <algorithm>
#include <stdexcept>
#include <uniflash/platform.h>

namespace uniflash::protocol {

uint64_t BslCodec::be64(uint64_t v) {
    return ((v & 0x00000000000000FFull) << 56) |
           ((v & 0x000000000000FF00ull) << 40) |
           ((v & 0x0000000000FF0000ull) << 24) |
           ((v & 0x00000000FF000000ull) << 8)  |
           ((v & 0x000000FF00000000ull) >> 8)  |
           ((v & 0x0000FF0000000000ull) >> 24) |
           ((v & 0x00FF000000000000ull) >> 40) |
           ((v & 0xFF00000000000000ull) >> 56);
}

uint16_t BslCodec::compute_crc16(std::span<const uint8_t> data) {
    uint16_t crc = CRC16_SEED;
    for (uint8_t byte : data) {
        crc = static_cast<uint16_t>(crc ^ (static_cast<uint16_t>(byte) << 8));
        for (int i = 0; i < 8; ++i) {
            if (crc & 0x8000)
                crc = static_cast<uint16_t>((crc << 1) ^ CRC16_POLY);
            else
                crc = static_cast<uint16_t>(crc << 1);
        }
    }
    return crc;
}

std::optional<DaInfoTlv>
parse_da_info(std::span<const uint8_t> payload) {
    if (payload.size() < 4) return std::nullopt;
    uint32_t magic = static_cast<uint32_t>(payload[0])      |
                     (static_cast<uint32_t>(payload[1]) << 8)  |
                     (static_cast<uint32_t>(payload[2]) << 16) |
                     (static_cast<uint32_t>(payload[3]) << 24);
    if (magic != 0x7477656e) {
        // cmd_download.c DA_INFO_T without CONFIG_SEND_STORAGE_TYPE:
        // version u32, disable-HDLC u32, old/raw/reserved bytes, flush u32,
        // then 60 reserved words. Version 2/4 are emitted by that producer.
        if (payload.size() != 256 || (magic != 2 && magic != 4)) return std::nullopt;
        const auto le32 = [&](size_t offset) {
            return uint32_t(payload[offset]) | (uint32_t(payload[offset+1]) << 8) |
                (uint32_t(payload[offset+2]) << 16) | (uint32_t(payload[offset+3]) << 24);
        };
        if (le32(4) > 1 || payload[8] > 1 || payload[9] > 2 || payload[10] || payload[11])
            return std::nullopt;
        DaInfoTlv da{};
        da.disable_hdlc = le32(4) != 0;
        da.support_raw = magic == 4 && payload[9] == 2;
        da.flush_kb = le32(12);
        // Reserved bytes are not a storage type in this layout.
        return da;
    }

    DaInfoTlv da{};
    size_t off = 4;
    std::set<uint16_t> seen;
    while (off + 4 <= payload.size()) {
        uint16_t type = static_cast<uint16_t>(payload[off] |
                                               (payload[off + 1] << 8));
        uint16_t len  = static_cast<uint16_t>(payload[off + 2] |
                                               (payload[off + 3] << 8));
        if (off + 4 + len > payload.size()) return std::nullopt;
        const uint8_t* v = payload.data() + off + 4;
        if((type==0 || type==2 || type==3 || type==6) && !seen.insert(type).second)return std::nullopt;
        switch (type) {
        case 0:
            if (len != 4 || v[0]>1 || v[1] || v[2] || v[3]) return std::nullopt;
            da.disable_hdlc = v[0] != 0;
            break;
        case 2:
            if (len != 1 || v[0]>2) return std::nullopt;
            // 2 denotes the whole-file raw channel; 1 is the older
            // per-packet protocol, which this client does not implement.
            da.support_raw = v[0] == 2;
            break;
        case 3:
            if (len != 4) return std::nullopt;
            {
                da.flush_kb = static_cast<uint32_t>(v[0])     |
                              (static_cast<uint32_t>(v[1]) << 8)  |
                              (static_cast<uint32_t>(v[2]) << 16) |
                              (static_cast<uint32_t>(v[3]) << 24);
            }
            break;
        case 6:  // E_STORAGE_TYPE; type 4 is E_RSA
            if (len != 4) return std::nullopt;
            {
                da.storage = static_cast<uint32_t>(v[0])     |
                             (static_cast<uint32_t>(v[1]) << 8)  |
                             (static_cast<uint32_t>(v[2]) << 16) |
                             (static_cast<uint32_t>(v[3]) << 24);
            }
            break;
        default: break;
        }
        off += 4 + len;
    }
    if (off != payload.size()) return std::nullopt;
    return da;
}

static std::vector<uint8_t> hdlc_encode_body(std::span<const uint8_t> body) {
    std::vector<uint8_t> out;
    out.reserve(body.size() * 2 + 16);
    for (uint8_t byte : body) {
        if (byte == HDLC_FLAG || byte == HDLC_ESCAPE) {
            out.push_back(HDLC_ESCAPE);
            out.push_back(static_cast<uint8_t>(byte ^ HDLC_ESCAPE_MASK));
        } else {
            out.push_back(byte);
        }
    }
    return out;
}

std::expected<std::vector<uint8_t>, std::errc>
BslCodec::encode_hdlc(uint8_t type, std::span<const uint8_t> payload) {
    if (payload.size() > MAX_PAYLOAD_SIZE)
        return std::unexpected(std::errc::message_size);

    BslHeader hdr{};
    hdr.type = be16(type);
    hdr.size = be16(static_cast<uint16_t>(payload.size()));

    std::vector<uint8_t> body;
    body.reserve(sizeof(hdr) + payload.size() + 2);
    const uint8_t* h = reinterpret_cast<const uint8_t*>(&hdr);
    body.insert(body.end(), h, h + sizeof(hdr));
    body.insert(body.end(), payload.begin(), payload.end());

    uint16_t crc = compute_crc16(body);
    body.push_back(static_cast<uint8_t>(crc >> 8));
    body.push_back(static_cast<uint8_t>(crc & 0xFF));

    std::vector<uint8_t> encoded = hdlc_encode_body(body);
    std::vector<uint8_t> frame;
    frame.reserve(encoded.size() + 2);
    frame.push_back(HDLC_FLAG);
    frame.insert(frame.end(), encoded.begin(), encoded.end());
    frame.push_back(HDLC_FLAG);
    return frame;
}

static std::expected<std::vector<uint8_t>, std::errc>
hdlc_decode_body(std::span<const uint8_t> data) {
    std::vector<uint8_t> out;
    out.reserve(data.size());
    size_t i = 0;
    while (i < data.size()) {
        if (data[i] == HDLC_ESCAPE) {
            if (i + 1 == data.size() ||
                (data[i + 1] != (HDLC_FLAG ^ HDLC_ESCAPE_MASK) &&
                 data[i + 1] != (HDLC_ESCAPE ^ HDLC_ESCAPE_MASK)))
                return std::unexpected(std::errc::illegal_byte_sequence);
            out.push_back(static_cast<uint8_t>(data[i + 1] ^ HDLC_ESCAPE_MASK));
            i += 2;
        } else if (data[i] == HDLC_FLAG) {
            return std::unexpected(std::errc::illegal_byte_sequence);
        } else {
            out.push_back(data[i]);
            ++i;
        }
    }
    return out;
}

std::expected<std::pair<uint8_t, std::vector<uint8_t>>, std::errc>
BslCodec::decode_hdlc(std::span<const uint8_t> raw, std::optional<Chk> checksum) {
    if (raw.size() < 6)
        return std::unexpected(std::errc::illegal_byte_sequence);
    if (raw.front() != HDLC_FLAG || raw.back() != HDLC_FLAG)
        return std::unexpected(std::errc::illegal_byte_sequence);

    auto decoded = hdlc_decode_body(
        std::span<const uint8_t>{raw.data() + 1, raw.size() - 2});
    if (!decoded) return std::unexpected(decoded.error());
    const auto& body = *decoded;

    if (body.size() < 6)
        return std::unexpected(std::errc::message_size);

    const size_t payload_size = (static_cast<size_t>(body[2]) << 8) | body[3];
    if (body[0] != 0 || payload_size > MAX_PAYLOAD_SIZE ||
        body.size() != payload_size + 6)
        return std::unexpected(std::errc::message_size);
    size_t data_size = body.size() - 4;
    uint16_t received_crc = static_cast<uint16_t>(
        (body[2 + data_size] << 8) | body[2 + data_size + 1]);

    const std::span<const uint8_t> checked{body.data(), body.size() - 2};
    const bool crc_ok = checksum != Chk::Add && received_crc == compute_crc16(checked);
    const bool add_ok = checksum != Chk::Crc16 && received_crc == add_checksum(checked);
    if (!crc_ok && !add_ok) return std::unexpected(std::errc::bad_message);

    uint8_t cmd = body[1];   // type is BE: [00, cmd]
    std::vector<uint8_t> payload(body.begin() + 4, body.end() - 2);
    return std::make_pair(cmd, std::move(payload));
}

uint16_t BslCodec::add_checksum(std::span<const uint8_t> body) {
    // Canonical big-endian word sum; an odd byte occupies the high half.
    // BSP FDL_DataProcess serializes this value in replies even when the
    // payload is odd. Host commands need a separate alignment adjustment
    // because the device verifies body+trailer with frm_chk as one buffer.
    uint32_t sum = 0;
    size_t i = 0;
    for (; i + 1 < body.size(); i += 2)
        sum += static_cast<uint32_t>(body[i]) << 8 |
               static_cast<uint32_t>(body[i + 1]);
    if (i < body.size())
        sum += static_cast<uint32_t>(body[i]) << 8;  // lone high byte
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += sum >> 16;
    return static_cast<uint16_t>(~sum & 0xFFFF);
}

static uint16_t command_checksum(BslCodec::Chk chk,
                                 std::span<const uint8_t> body) {
    if (chk == BslCodec::Chk::Crc16)
        return BslCodec::compute_crc16(body);
    const uint16_t checksum = BslCodec::add_checksum(body);
    // For odd bodies the first trailer byte pairs with the final payload
    // byte in frm_chk(body+trailer). Swap only outgoing ADD command bytes;
    // doing this in add_checksum would break odd-length device replies.
    if (body.size() & 1)
        return static_cast<uint16_t>((checksum >> 8) | (checksum << 8));
    return checksum;
}

bool BslCodec::chk_carries_escape(Chk chk, uint16_t cmd,
                                  std::span<const uint8_t> payload) {
    std::vector<uint8_t> body;
    body.reserve(payload.size() + 4);
    body.push_back(static_cast<uint8_t>(cmd >> 8));
    body.push_back(static_cast<uint8_t>(cmd & 0xFF));
    body.push_back(static_cast<uint8_t>(payload.size() >> 8));
    body.push_back(static_cast<uint8_t>(payload.size() & 0xFF));
    body.insert(body.end(), payload.begin(), payload.end());
    const uint16_t c = command_checksum(chk, body);
    return (c >> 8) == HDLC_ESCAPE || (c >> 8) == HDLC_FLAG ||
           (c & 0xFF) == HDLC_ESCAPE || (c & 0xFF) == HDLC_FLAG;
}

std::vector<uint8_t> BslCodec::encode_pctool_programkey() {
    // 7e | seq(4)=0 | len(2)=12 | type=0x62 | sub=0 | cmd(2)=09 | len(2)=4 | 7e
    return {HDLC_FLAG, 0, 0, 0, 0, 0x0c, 0x00, 0x62, 0x00,
            0x09, 0x00, 0x04, 0x00, HDLC_FLAG};
}

std::vector<uint8_t> BslCodec::encode_pctool_programkey_exit(uint16_t para,
                                                          uint32_t sequence) {
    // 7e | seq(4)=0 | len(2)=14 | type=0x62 | sub=0 | cmd(2)=0a |
    // len(2)=6 | para(2 LE) | 7e
    std::vector<uint8_t> body{
            static_cast<uint8_t>(sequence), static_cast<uint8_t>(sequence >> 8),
            static_cast<uint8_t>(sequence >> 16), static_cast<uint8_t>(sequence >> 24),
            0x0e, 0x00, 0x62, 0x00,
            0x0a, 0x00, 0x06, 0x00,
            static_cast<uint8_t>(para), static_cast<uint8_t>(para >> 8),
    };
    auto frame = hdlc_encode_body(body);
    frame.insert(frame.begin(), HDLC_FLAG);
    frame.push_back(HDLC_FLAG);
    return frame;
}

std::expected<std::vector<uint8_t>, std::errc>
BslCodec::encode_pctool_mode(uint8_t mode) {
    if (mode == 0 || mode > 0x3f)
        return std::unexpected(std::errc::invalid_argument);
    // COMMAND_T (calibration_detect.c send_caliberation_request):
    // {reserved:4 = 0, size:2 LE = CALIBERATE_STRING_LEN-2 = 8,
    //  cmd:1 = 0xfe, sub_cmd:1 = mode}, 0x7e-framed.
    return std::vector<uint8_t>{HDLC_FLAG, 0, 0, 0, 0, 0x08, 0x00, 0xfe, mode, HDLC_FLAG};
}

std::expected<std::vector<uint8_t>, std::errc>
BslCodec::encode_hdlc_chk(uint8_t type, std::span<const uint8_t> payload,
                           Chk chk) {
    if (payload.size() > MAX_PAYLOAD_SIZE)
        return std::unexpected(std::errc::message_size);

    BslHeader hdr{};
    hdr.type = be16(type);
    hdr.size = be16(static_cast<uint16_t>(payload.size()));

    std::vector<uint8_t> body;
    body.reserve(sizeof(hdr) + payload.size() + 2);
    const uint8_t* h = reinterpret_cast<const uint8_t*>(&hdr);
    body.insert(body.end(), h, h + sizeof(hdr));
    body.insert(body.end(), payload.begin(), payload.end());

    const uint16_t crc = command_checksum(chk, body);
    body.push_back(static_cast<uint8_t>(crc >> 8));
    body.push_back(static_cast<uint8_t>(crc & 0xFF));

    std::vector<uint8_t> encoded = hdlc_encode_body(body);
    std::vector<uint8_t> frame;
    frame.reserve(encoded.size() + 2);
    frame.push_back(HDLC_FLAG);
    frame.insert(frame.end(), encoded.begin(), encoded.end());
    frame.push_back(HDLC_FLAG);
    return frame;
}

std::expected<std::vector<uint8_t>, std::errc>
BslCodec::encode_raw_chk(uint8_t type, std::span<const uint8_t> payload,
                         Chk chk) {
    if (payload.size() > MAX_PAYLOAD_SIZE)
        return std::unexpected(std::errc::message_size);

    BslHeader hdr{};
    hdr.type = be16(type);
    hdr.size = be16(static_cast<uint16_t>(payload.size()));

    std::vector<uint8_t> body;
    body.reserve(sizeof(hdr) + payload.size() + 2);
    const uint8_t* h = reinterpret_cast<const uint8_t*>(&hdr);
    body.insert(body.end(), h, h + sizeof(hdr));
    body.insert(body.end(), payload.begin(), payload.end());

    const uint16_t crc = command_checksum(chk, body);
    body.push_back(static_cast<uint8_t>(crc >> 8));
    body.push_back(static_cast<uint8_t>(crc & 0xFF));

    // No hdlc_encode_body pass: the body rides the wire verbatim —
    // the DISABLE_TRANSCODE parser mode consumes it length-driven.
    std::vector<uint8_t> frame;
    frame.reserve(body.size() + 2);
    frame.push_back(HDLC_FLAG);
    frame.insert(frame.end(), body.begin(), body.end());
    frame.push_back(HDLC_FLAG);
    return frame;
}

std::expected<std::vector<uint8_t>, std::errc>
BslCodec::encode_start_data_add(uint32_t addr, uint32_t size) {
    uint8_t data[8] = {
        static_cast<uint8_t>(addr >> 24), static_cast<uint8_t>(addr >> 16),
        static_cast<uint8_t>(addr >> 8),  static_cast<uint8_t>(addr),
        static_cast<uint8_t>(size >> 24), static_cast<uint8_t>(size >> 16),
        static_cast<uint8_t>(size >> 8),  static_cast<uint8_t>(size),
    };
    return encode_hdlc_chk(static_cast<uint8_t>(BslCommand::CMD_START_DATA),
                           std::span<const uint8_t>{data, 8}, Chk::Add);
}

std::expected<std::vector<uint8_t>, std::errc>
BslCodec::encode_midst_data_add(std::span<const uint8_t> data) {
    return encode_hdlc_chk(static_cast<uint8_t>(BslCommand::CMD_MIDST_DATA),
                           data, Chk::Add);
}

std::expected<std::vector<uint8_t>, std::errc>
BslCodec::encode_end_data_add() {
    return encode_hdlc_chk(static_cast<uint8_t>(BslCommand::CMD_END_DATA),
                           {}, Chk::Add);
}

std::expected<std::vector<uint8_t>, std::errc>
BslCodec::encode_midst_data_raw(std::span<const uint8_t> data) {
    return encode_raw_chk(static_cast<uint8_t>(BslCommand::CMD_MIDST_DATA),
                          data, Chk::Add);
}

std::expected<std::vector<uint8_t>, std::errc>
BslCodec::encode_disable_transcode() {
    return encode_raw_chk(static_cast<uint8_t>(BslCommand::CMD_DIS_HDLC),
                          {}, Chk::Add);
}

std::expected<std::vector<uint8_t>, std::errc>
BslCodec::encode_exec_add(uint32_t entry_addr) {
    uint8_t data[4] = {
        static_cast<uint8_t>(entry_addr >> 24),
        static_cast<uint8_t>(entry_addr >> 16),
        static_cast<uint8_t>(entry_addr >> 8),
        static_cast<uint8_t>(entry_addr),
    };
    return encode_hdlc_chk(static_cast<uint8_t>(BslCommand::CMD_EXEC_DATA),
                           std::span<const uint8_t>{data, 4}, Chk::Add);
}

bool check_load_window(uint32_t addr, uint32_t size, uint32_t lo, uint32_t hi) {
    return addr >= lo && addr < hi && size <= hi - addr;
}

std::expected<std::vector<uint8_t>, std::errc>
BslCodec::encode_start_data(uint32_t addr, uint32_t size) {
    uint8_t data[8] = {
        static_cast<uint8_t>(addr >> 24), static_cast<uint8_t>(addr >> 16),
        static_cast<uint8_t>(addr >> 8),  static_cast<uint8_t>(addr),
        static_cast<uint8_t>(size >> 24), static_cast<uint8_t>(size >> 16),
        static_cast<uint8_t>(size >> 8),  static_cast<uint8_t>(size),
    };
    return encode_hdlc(static_cast<uint8_t>(BslCommand::CMD_START_DATA), data);
}

std::expected<std::vector<uint8_t>, std::errc>
BslCodec::encode_midst_data(std::span<const uint8_t> data) {
    return encode_hdlc(static_cast<uint8_t>(BslCommand::CMD_MIDST_DATA), data);
}

std::expected<std::vector<uint8_t>, std::errc>
BslCodec::encode_exec(uint32_t entry_addr) {
    uint8_t data[4] = {
        static_cast<uint8_t>(entry_addr >> 24),
        static_cast<uint8_t>(entry_addr >> 16),
        static_cast<uint8_t>(entry_addr >> 8),
        static_cast<uint8_t>(entry_addr),
    };
    return encode_hdlc(static_cast<uint8_t>(BslCommand::CMD_EXEC_DATA), data);
}

std::expected<std::vector<uint8_t>, std::errc>
BslCodec::encode_exec_empty() {
    return encode_hdlc(static_cast<uint8_t>(BslCommand::CMD_EXEC_DATA), {});
}

// FDL2 partition payload format (BSP dl_cmd_proc.h / _decode_packet_data):
//   name[72]  : 36 UTF-16LE chars (ascii char + 0x00), null-terminated
//   size[8]   : uint64 little-endian (device reads *(uint64_t*)(data+36))
//   rev[8]    : uint64 little-endian
//   [cs[4]]   : uint32 little-endian, only when with_checksum (payload > 0x58)
std::vector<uint8_t>
BslCodec::make_partition_payload(const std::string& name, uint64_t size,
                                 uint64_t rev, uint32_t checksum,
                                 bool with_checksum) {
    if (name.empty() || name.size() > 35 || !std::all_of(name.begin(), name.end(),
        [](unsigned char c) { return c >= 0x20 && c < 0x7f; }))
        throw std::invalid_argument("partition name must be 1..35 printable ASCII bytes");
    std::vector<uint8_t> out;
    out.reserve(72 + 8 + 8 + (with_checksum ? 4 : 0));

    // name: 36 UTF-16LE units = 72 bytes
    for (int i = 0; i < 36; ++i) {
        uint8_t c = (i < static_cast<int>(name.size()))
                        ? static_cast<uint8_t>(name[i]) : 0;
        out.push_back(c);
        out.push_back(0x00);
    }

    uint64_t size_le = platform::little_endian(size);
    uint64_t rev_le  = platform::little_endian(rev);
    const uint8_t* s = reinterpret_cast<const uint8_t*>(&size_le);
    const uint8_t* r = reinterpret_cast<const uint8_t*>(&rev_le);
    out.insert(out.end(), s, s + 8);
    out.insert(out.end(), r, r + 8);

    if (with_checksum) {
        uint32_t cs_le = platform::little_endian(checksum);
        const uint8_t* c = reinterpret_cast<const uint8_t*>(&cs_le);
        out.insert(out.end(), c, c + 4);
    }
    return out;
}

// BIT32 partition-open payload (0x4C = 76 bytes) — the form the factory
// tool puts on the wire for FDL2 writes (verbose-trace observation:
// START frame `7e 00 01 00 4c` + name72 + size u32 LE). The device's
// _decode_packet_data takes the u32 branch whenever body.size < 0x58.
std::vector<uint8_t>
BslCodec::make_partition_payload32(const std::string& name, uint32_t size) {
    if (name.empty() || name.size() > 35 || !std::all_of(name.begin(), name.end(),
        [](unsigned char c) { return c >= 0x20 && c < 0x7f; }))
        throw std::invalid_argument("partition name must be 1..35 printable ASCII bytes");
    std::vector<uint8_t> out;
    out.reserve(72 + 4);

    // name: 36 UTF-16LE units = 72 bytes
    for (int i = 0; i < 36; ++i) {
        uint8_t c = (i < static_cast<int>(name.size()))
                        ? static_cast<uint8_t>(name[i]) : 0;
        out.push_back(c);
        out.push_back(0x00);
    }

    uint32_t size_le = platform::little_endian(size);
    const auto* s = reinterpret_cast<const uint8_t*>(&size_le);
    out.insert(out.end(), s, s + 4);
    return out;
}

// Names for every reply code (dl_cmd_def.h numbering) — failure
// diagnostics; unmapped bytes render as "unknown" (callers print the
// raw byte alongside).
const char* BslCodec::reply_name(uint8_t code) {
    switch (static_cast<BslResponse>(code)) {
    case BslResponse::REP_ACK:                   return "ACK";
    case BslResponse::REP_VER:                   return "VER";
    case BslResponse::REP_INVALID_CMD:           return "INVALID_CMD";
    case BslResponse::REP_UNKNOW_CMD:            return "UNKNOW_CMD";
    case BslResponse::REP_OPERATION_FAILED:      return "OPERATION_FAILED";
    case BslResponse::REP_NOT_SUPPORT_BAUDRATE:  return "NOT_SUPPORT_BAUDRATE";
    case BslResponse::REP_DOWN_NOT_START:        return "DOWN_NOT_START";
    case BslResponse::REP_DOWN_MULTI_START:      return "DOWN_MULTI_START";
    case BslResponse::REP_DOWN_EARLY_END:        return "DOWN_EARLY_END";
    case BslResponse::REP_DOWN_DEST_ERROR:       return "DOWN_DEST_ERROR";
    case BslResponse::REP_DOWN_SIZE_ERROR:       return "DOWN_SIZE_ERROR";
    case BslResponse::REP_VERIFY_ERROR:          return "VERIFY_ERROR";
    case BslResponse::REP_NOT_VERIFY:            return "NOT_VERIFY";
    case BslResponse::REP_PHONE_NOT_ENOUGH_MEM:  return "NOT_ENOUGH_MEMORY";
    case BslResponse::REP_PHONE_WAIT_TIMEOUT:    return "WAIT_INPUT_TIMEOUT";
    case BslResponse::REP_PHONE_SUCCEED:         return "PHONE_SUCCEED";
    case BslResponse::REP_PHONE_VALID_BAUD:      return "VALID_BAUDRATE";
    case BslResponse::REP_PHONE_REPEAT_CONT:     return "REPEAT_CONTINUE";
    case BslResponse::REP_PHONE_REPEAT_BREAK:    return "REPEAT_BREAK";
    case BslResponse::REP_READ_FLASH:            return "READ_FLASH";
    case BslResponse::REP_READ_CHIP_TYPE:        return "READ_CHIP_TYPE";
    case BslResponse::REP_LOOKUP_NVITEM:         return "LOOKUP_NVITEM";
    case BslResponse::REP_INCOMPATIBLE_PART:     return "INCOMPATIBLE_PARTITION";
    case BslResponse::REP_UNKNOWN_DEVICE:        return "UNKNOWN_DEVICE";
    case BslResponse::REP_INVALID_DEVICE_SIZE:   return "INVALID_DEVICE_SIZE";
    case BslResponse::REP_ILLEGAL_SDRAM:         return "ILLEGAL_SDRAM";
    case BslResponse::REP_WRONG_SDRAM_PARAMETER: return "WRONG_SDRAM_PARAMETER";
    case BslResponse::REP_READ_MCP_TYPE:         return "READ_MCP_TYPE";
    case BslResponse::REP_READ_FLASH_TYPE:       return "READ_FLASH_TYPE";
    case BslResponse::REP_ERROR_CHECKSUM:        return "ERROR_CHECKSUM";
    case BslResponse::REP_CHECKSUM_DIFF:         return "CHECKSUM_DIFF";
    case BslResponse::REP_WRITE_ERROR:           return "WRITE_ERROR";
    case BslResponse::REP_PHONE_ROOTFLAG:        return "PHONE_ROOTFLAG";
    case BslResponse::REP_READ_CHIP_UID:         return "READ_CHIP_UID";
    case BslResponse::REP_NOT_ENABLE_WRITE:      return "NOT_ENABLE_WRITE_FLASH";
    case BslResponse::REP_READ_REFINFO:          return "READ_REFINFO";
    case BslResponse::REP_CHECK_NV_TYPE:         return "CHECK_NV_TYPE";
    case BslResponse::REP_DDR_VERIFY_FAIL:       return "DDR_VERIFY_FAIL";
    case BslResponse::REP_DDR_TEST_FAIL:         return "DDR_TEST_FAIL";
    case BslResponse::REP_READ_PARTITION:        return "READ_PARTITION";
    case BslResponse::REP_UNSUPPORTED_CMD:       return "UNSUPPORTED_CMD";
    }
    return "unknown";
}

std::expected<std::vector<uint8_t>, std::errc>
BslCodec::encode_erase_flash(const std::string& partition_name, uint64_t size) {
    auto payload = make_partition_payload(partition_name, size);
    return encode_hdlc_chk(static_cast<uint8_t>(BslCommand::CMD_ERASE_FLASH), payload, Chk::Add);
}

std::expected<std::vector<uint8_t>, std::errc>
BslCodec::encode_read_flash_start(const std::string& partition_name,
                                  uint64_t size) {
    // Factory form (spd trace): the READ START is BIT32 — same shape as
    // the write START (`7e 00 10 00 4c` + name72 + size u32 LE). The
    // device's u32 size field caps a single read session at 4GB.
    if (size > 0xFFFFFFFF)
        return std::unexpected(std::errc::file_too_large);
    auto payload = make_partition_payload32(
        partition_name, static_cast<uint32_t>(size));
    return encode_hdlc_chk(static_cast<uint8_t>(BslCommand::CMD_READ_FLASH_START), payload, Chk::Add);
}

std::expected<std::vector<uint8_t>, std::errc>
BslCodec::encode_read_flash_midst(uint32_t size, uint64_t offset) {
    // Factory form (spd trace: `7e 00 11 00 08 | size u32 LE | offset
    // u32 LE`) — the 8-byte payload takes the u32-offset branch of
    // dl_cmd_read_midst. The BSP also defines a 12-byte u64-offset
    // variant (BIT64_READ_MIDST_LENGTH), but the prebuilt fdl2 speaks
    // the 8-byte form. u32 offsets cap reads at 4GB into a partition.
    if (offset > 0xFFFFFFFF)
        return std::unexpected(std::errc::invalid_argument);
    uint8_t data[8];
    uint32_t size_le   = platform::little_endian(size);
    uint32_t offset_le = platform::little_endian(static_cast<uint32_t>(offset));
    memcpy(data, &size_le, 4);
    memcpy(data + 4, &offset_le, 4);
    return encode_hdlc_chk(static_cast<uint8_t>(BslCommand::CMD_READ_FLASH_MIDST),
                       std::span<const uint8_t>{data, sizeof(data)}, Chk::Add);
}

std::expected<std::vector<uint8_t>, std::errc>
BslCodec::encode_read_flash_midst_raw(uint32_t size, uint64_t offset) {
    if (offset > 0xFFFFFFFF)
        return std::unexpected(std::errc::invalid_argument);
    uint8_t data[8];
    uint32_t size_le   = platform::little_endian(size);
    uint32_t offset_le = platform::little_endian(static_cast<uint32_t>(offset));
    memcpy(data, &size_le, 4);
    memcpy(data + 4, &offset_le, 4);
    return encode_raw_chk(static_cast<uint8_t>(BslCommand::CMD_READ_FLASH_MIDST),
                       std::span<const uint8_t>{data, sizeof(data)}, Chk::Add);
}

std::expected<std::vector<uint8_t>, std::errc>
BslCodec::encode_repartition(std::span<const uint8_t> table_data) {
    return encode_hdlc_chk(static_cast<uint8_t>(BslCommand::CMD_REPARTITION), table_data, Chk::Add);
}

std::expected<std::vector<uint8_t>, std::errc>
BslCodec::encode_write_datetime(std::span<const uint8_t> datetime) {
    return encode_hdlc_chk(static_cast<uint8_t>(BslCommand::CMD_WRITE_DATETIME), datetime, Chk::Add);
}

std::expected<std::vector<uint8_t>, std::errc>
BslCodec::encode_set_debuginfo(std::span<const uint8_t> info) {
    return encode_hdlc_chk(static_cast<uint8_t>(BslCommand::CMD_SET_DEBUGINFO), info, Chk::Add);
}

std::expected<std::vector<uint8_t>, std::errc>
BslCodec::encode_dload_whole_raw_start(uint64_t file_size) {
    uint64_t size_be = be64(file_size);
    const uint8_t* b = reinterpret_cast<const uint8_t*>(&size_be);
    return encode_hdlc_chk(static_cast<uint8_t>(BslCommand::CMD_DLOAD_RAW_START2),
                       std::span<const uint8_t>{b, 8}, Chk::Add);
}

std::expected<std::vector<ToolPartitionEntry>, std::errc>
BslCodec::decode_partition_table(std::span<const uint8_t> data) {
    constexpr size_t kEntry = sizeof(ToolPartitionEntry);  // 76 bytes
    if (data.size() % kEntry != 0)
        return std::unexpected(std::errc::message_size);

    std::vector<ToolPartitionEntry> out;
    size_t count = data.size() / kEntry;
    out.reserve(count);
    std::set<std::string> names;
    bool ended = false;
    for (size_t i = 0; i < count; ++i) {
        ToolPartitionEntry e;
        memcpy(&e, data.data() + i * kEntry, kEntry);

        // name is UTF-16LE on the wire: copy before in-place fold.
        // MAX_PARTITION_NAME_SIZE (72) counts BYTES = 36 UTF-16 units;
        // the fold reads wire_name[2*j] so its bound is the UNIT count
        // (a j<72 loop reads wire_name[142] — a genuine stack OOB).
        uint8_t wire_name[72];
        memcpy(wire_name, e.name, 72);
        constexpr int kUnits = MAX_PARTITION_NAME_SIZE / 2;  // 36
        bool terminated = false;
        for (int j = 0; j < kUnits; ++j) {
            if (wire_name[2*j+1] || wire_name[2*j] >= 0x7f ||
                (wire_name[2*j] && wire_name[2*j] < 0x20) ||
                (terminated && wire_name[2*j]))
                return std::unexpected(std::errc::illegal_byte_sequence);
            if (!wire_name[2*j]) terminated = true;
            e.name[j] = wire_name[2 * j];
        }
        if (!terminated) return std::unexpected(std::errc::message_size);
        for (int j = kUnits; j < MAX_PARTITION_NAME_SIZE; ++j)
            e.name[j] = 0;

        e.size_kb = platform::little_endian(e.size_kb);
        const std::string name(reinterpret_cast<const char*>(e.name));
        if (name.empty()) ended = true;
        else if (ended || !names.insert(name).second)
            return std::unexpected(std::errc::bad_message);
        out.push_back(e);
    }
    return out;
}

// ------------------------------------------------------------ sparse wrap

std::vector<uint8_t> wrap_as_sparse(const uint8_t* data, size_t size) {
    if ((!data && size) || size > uint64_t(UINT32_MAX) * SPARSE_BLK_SZ)
        throw std::invalid_argument("sparse source exceeds format limits");
    // NB: the OR chain must be parenthesized — == binds tighter than |,
    // so the bare chain compared only the last term against SPARSE_MAGIC.
    const bool already_sparse =
        size >= 4 &&
        (static_cast<uint32_t>(data[0]) |
         (static_cast<uint32_t>(data[1]) << 8) |
         (static_cast<uint32_t>(data[2]) << 16) |
         (static_cast<uint32_t>(data[3]) << 24)) == SPARSE_MAGIC;
    if (already_sparse) return {data, data + size};

    // Blocks of the output image; pad the tail so every chunk's data is
    // a whole number of blocks (write_sparse_img writes chunk_sz * blk_sz).
    const uint64_t total_blks = size / SPARSE_BLK_SZ + (size % SPARSE_BLK_SZ != 0);
    constexpr uint32_t CHUNK_BLOCKS = 1024;            // 4 MB per chunk
    const uint32_t total_chunks = static_cast<uint32_t>(
        (total_blks + CHUNK_BLOCKS - 1) / CHUNK_BLOCKS);

    std::vector<uint8_t> out;
    out.reserve(size + 28 + 12ull * total_chunks + SPARSE_BLK_SZ);

    auto le16 = [](uint16_t v, uint8_t* p) {
        p[0] = static_cast<uint8_t>(v);
        p[1] = static_cast<uint8_t>(v >> 8);
    };
    auto le32 = [](uint32_t v, uint8_t* p) {
        p[0] = static_cast<uint8_t>(v);
        p[1] = static_cast<uint8_t>(v >> 8);
        p[2] = static_cast<uint8_t>(v >> 16);
        p[3] = static_cast<uint8_t>(v >> 24);
    };

    uint8_t hdr[28]{};
    le32(SPARSE_MAGIC, hdr + 0);
    le16(1, hdr + 4);                                  // major
    le16(0, hdr + 6);                                  // minor
    le16(28, hdr + 8);                                 // file_hdr_sz
    le16(12, hdr + 10);                                // chunk_hdr_sz
    le32(SPARSE_BLK_SZ, hdr + 12);
    le32(static_cast<uint32_t>(total_blks), hdr + 16);
    le32(total_chunks, hdr + 20);
    le32(0, hdr + 24);                                 // image_checksum
    out.insert(out.end(), hdr, hdr + 28);

    uint64_t blk = 0;
    while (blk < total_blks) {
        const uint32_t blocks =
            static_cast<uint32_t>(std::min<uint64_t>(CHUNK_BLOCKS,
                                                     total_blks - blk));
        const uint32_t data_sz = blocks * SPARSE_BLK_SZ;
        uint8_t ch[12];
        le16(0xCAC1, ch + 0);                          // CHUNK_TYPE_RAW
        le16(0, ch + 2);                               // reserved
        le32(blocks, ch + 4);
        le32(12 + data_sz, ch + 8);                    // total_sz
        out.insert(out.end(), ch, ch + 12);
        const uint64_t off = blk * SPARSE_BLK_SZ;
        const size_t have = size - std::min<uint64_t>(off, size);
        const size_t take = std::min<size_t>(have, data_sz);
        out.insert(out.end(), data + off, data + off + take);
        if (take < data_sz)                            // pad the tail
            out.insert(out.end(), data_sz - take, 0);
        blk += blocks;
    }
    return out;
}

}

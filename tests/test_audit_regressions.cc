/*
 * UniFlash-Core Test / Audit Regressions
 *
 * Covers sparse input size limits and manifest commit failure paths.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#include <uniflash/log.h>
#include <uniflash/text.h>
#include <uniflash/io/image.h>
#include <uniflash/io/output.h>
#include <uniflash/io/buffered_output.h>
#include <uniflash/session/operations.h>
#include <uniflash/session/pac_parser.h>
#include <uniflash/session/gpt.h>
#include <uniflash/session/sparse.h>
#include <uniflash/io/sparse_index.h>
#include <uniflash/protocol/bsl.h>
#include <uniflash/protocol/session.h>
#include "temp_directory.h"
#include "../src/cli/backup_failure.h"
#include <fstream>
#include <stdexcept>
#include <algorithm>

using namespace uniflash;
namespace {
class ThrowingTransport : public transport::Transport {
public:
    unsigned writes = 0;
    bool read_failure = false;
    std::expected<void, std::errc> bulk_write(std::span<const uint8_t>, transport::Timeout, std::stop_token) override {
        ++writes;
        if (!read_failure) throw std::runtime_error("send failure");
        return {};
    }
    std::expected<std::vector<uint8_t>, std::errc> bulk_read(size_t, transport::Timeout, std::stop_token) override {
        throw std::runtime_error("receive failure");
    }
    std::expected<void, std::errc> bulk_write_frame(std::span<const uint8_t> data, transport::Timeout t, std::stop_token s) override {
        return bulk_write(data, t, s);
    }
    bool supports_raw_frames() const override { return false; }
    uint16_t out_maxpacket() const override { return 64; }
    bool device_gone() const override { return false; }
    bool device_silent() const override { return false; }
};
}
int main() {
    int failures = 0;
    std::vector<std::string> failure_messages;
    const auto check = [&](bool ok, const char* label) {
        // Some assertions run inside a custom sink. Defer their diagnostics
        // until it is removed, rather than recursively invoking that sink.
        if (!ok) { ++failures; failure_messages.emplace_back(label); }
    };
    set_log_sink([](auto, const auto&) { throw std::runtime_error("log failure"); });
    log_info("callback exception must be isolated");
    log_document("document callback exception must be isolated");
    const LogColumn columns[]{{"name"}};
    const LogTableSection sections[]{{"section", {{"value"}}}};
    log_table(columns, sections);
    unsigned records = 0;
    set_log_sink([&](auto, const auto& block) {
        ++records;
        check(block.find("section") != std::string::npos && block.find("value") != std::string::npos,
              "table arrives as one complete record");
        set_log_sink(nullptr);
    });
    log_table(columns, sections);
    check(records == 1, "table uses a stable sink snapshot");
    check(text::width("分区A") == 5 && text::width("e\xcc\x81") == 1, "shared UTF-8 widths");
    check(text::record("\xff\n") == "\\xff\\n", "invalid UTF-8 and controls escaped");
    io::TransferObserver transfer_observer([](const auto&) { throw std::runtime_error("UI callback"); });
    transfer_observer({1, 2, 0.1});
    session::ProgressObserver progress_observer([](const auto&) { throw std::runtime_error("GUI callback"); });
    progress_observer({session::OperationStep::Finish, {}, 1, 1});
    io::PrepareObserver prepare_observer([](const auto&) { throw std::runtime_error("prepare callback"); });
    prepare_observer({io::PreparePhase::Snapshot, 0, 1});
    for (bool read_failure : {false, true}) {
        auto channel = std::make_unique<ThrowingTransport>();
        auto* raw = channel.get();
        raw->read_failure = read_failure;
        protocol::BslSession session(std::move(channel));
        try { (void)session.send_recv({0x7e}); } catch (const std::runtime_error&) {}
        const auto again = session.send_recv({0x7e});
        check(!again && again.error() == std::errc::state_not_recoverable && raw->writes == 1,
              "transport exception retires transaction before retry");
    }
    TempDirectory root;
    const auto image_path = root.path / "raw.bin";
    const std::vector<uint8_t> raw(5000, 0x42);
    { std::ofstream file(image_path, std::ios::binary); file.write(reinterpret_cast<const char*>(raw.data()), raw.size()); }
    auto wrapped = protocol::wrap_as_sparse(raw.data(), raw.size());
    check(wrapped[4] == 1 && wrapped[5] == 0 && wrapped[6] == 0 && wrapped[7] == 0, "sparse version bytes");
    auto expanded = session::expand_sparse(wrapped);
    check(expanded && expanded->size() == 8192 && std::equal(raw.begin(), raw.end(), expanded->begin()), "sparse wrapper roundtrip");
    {
        // A malformed trailing chunk must be rejected before any sink output;
        // the memory decoder and frozen-file path share this validation engine.
        struct Sink final:session::SparseDecoder::Sink {
            size_t calls=0;
            std::expected<void,std::errc> write_raw(uint64_t,std::span<const uint8_t>) override {++calls;return {};}
            std::expected<void,std::errc> write_fill(uint64_t,uint32_t,uint32_t,uint32_t) override {++calls;return {};}
            std::expected<void,std::errc> skip_dont_care(uint64_t,uint32_t,uint32_t) override {++calls;return {};}
        } sink;
        auto malformed=wrapped;malformed.push_back(0);
        check(!session::SparseDecoder::decode(malformed,sink) && sink.calls==0,"complete sparse preflight precedes sink effects");
        const io::Reader failed=[&](uint64_t offset,std::span<uint8_t> out,std::stop_token)->std::expected<void,std::errc> {
            if(offset)return std::unexpected(std::errc::interrupted);
            std::copy_n(wrapped.begin(),out.size(),out.begin());return {};
        };
        auto indexed=io::index_sparse(failed,wrapped.size(),UINT64_MAX);
        check(!indexed && indexed.error()==std::errc::interrupted,"sparse chunk reader preserves cancellation error");
    }
    const auto sparse_path = root.path / "sparse.bin";
    { std::ofstream file(sparse_path, std::ios::binary); file.write(reinterpret_cast<const char*>(wrapped.data()), wrapped.size()); }
    auto prepared = io::Image::prepare(sparse_path, 8192);
    std::vector<uint8_t> range(2000);
    check(prepared && prepared->reader()(4500, range, {}) &&
          std::all_of(range.begin(), range.begin()+500, [](auto c) { return c == 0x42; }) &&
          std::all_of(range.begin()+500, range.end(), [](auto c) { return c == 0; }), "indexed sparse cross-boundary read");
    // Mutating the original must not mutate validated/prepared contents.
    auto frozen = io::Image::prepare(image_path, 8192);
    { std::ofstream file(image_path, std::ios::binary | std::ios::trunc); file << "changed"; }
    std::vector<uint8_t> frozen_bytes(raw.size());
    check(frozen && frozen->reader()(0, frozen_bytes, {}) && frozen_bytes == raw, "prepared image owns immutable bytes");
    auto region = frozen->region(4000, 1000, 1000);
    std::vector<uint8_t> region_bytes(1000);
    check(region && region->reader()(0, region_bytes, {}) &&
        std::all_of(region_bytes.begin(), region_bytes.end(), [](auto b) { return b == 0x42; }),
        "container region retains frozen source after original mutation");
    check(!frozen->region(4999, 2, 2), "container region cannot escape source bounds");
    auto output = io::AtomicOutput::open(root.path / "saved.bin");
    check(output && output->commit_state() == io::CommitState::NotCommitted, "output initial state");
    if (output) {
        check(bool(output->write(raw)) && bool(output->commit()) &&
              output->commit_state() == io::CommitState::Durable, "durable atomic commit");
    }
    {
        auto file = io::AtomicOutput::open(root.path / "queued.bin");
        check(bool(file), "buffered output opens");
        if (file) {
            // Larger than the bounded queue: exercise producer backpressure,
            // byte order and finish-before-commit rather than just one block.
            std::vector<uint8_t> data(5 * 1024 * 1024 + 17);
            for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(i * 37);
            io::BufferedOutput buffered(*file);
            check(bool(buffered.write(data)) && buffered.accepted() == data.size(), "queue accepts exact bytes");
            check(bool(buffered.finish()) && file->size() == data.size(), "finish drains complete file");
            check(bool(file->commit()), "queue commits only after drain");
            std::ifstream saved(root.path / "queued.bin", std::ios::binary);
            std::vector<uint8_t> actual(data.size());
            saved.read(reinterpret_cast<char*>(actual.data()), actual.size());
            check(saved && actual == data, "queued output byte-for-byte order");
        }
    }
    {
        auto file = io::AtomicOutput::open(root.path / "failed-queue.bin");
        if (!file) return 1;
        // A rejected underlying write must reach finish, not become success.
        check(bool(file->commit()), "failure fixture commits empty output");
        io::BufferedOutput buffered(*file);
        (void)buffered.write(raw);
        auto drained = buffered.finish();
        check(!drained && drained.error() == std::errc::operation_not_permitted, "disk-thread error propagated");
    }
    {
        const auto destination = root.path / "cancelled-queue.bin";
        { std::ofstream saved(destination); saved << "original"; }
        {
            auto file = io::AtomicOutput::open(destination);
            if (!file) return 1;
            io::BufferedOutput buffered(*file);
            (void)buffered.write(raw);
            std::stop_source stop;
            stop.request_stop();
            auto drained = buffered.finish(stop.get_token());
            check(!drained && drained.error() == std::errc::interrupted, "cancelled drain rejected");
            check(!buffered.finish(), "cancelled finish stays failed with a fresh token");
        }
        std::ifstream saved(destination);
        std::string value; saved >> value;
        check(value == "original", "cancelled queue leaves old destination intact");
    }
    {
        auto file = io::AtomicOutput::open(root.path / "cancelled-write.bin");
        if (!file) return 1;
        io::BufferedOutput buffered(*file);
        (void)buffered.write(raw);
        std::stop_source stop; stop.request_stop();
        check(!buffered.write({}, stop.get_token()), "even empty cancelled write locks failure");
        check(!buffered.finish(), "write cancellation cannot become successful drain");
    }
    {
        auto file = io::AtomicOutput::open(root.path / "finished-queue.bin");
        if (!file) return 1;
        io::BufferedOutput buffered(*file);
        check(bool(buffered.finish()), "empty queue may finish");
        check(!buffered.write({}), "finished queue rejects even empty writes");
    }
    {
        // FILL with a nonzero pattern, read at a non-word-aligned offset.
        auto fill = wrapped;
        fill.resize(44);
        fill[28] = 0xc2; fill[29] = 0xca;
        fill[36] = 16; fill[37] = fill[38] = fill[39] = 0;
        fill[40] = 0x12; fill[41] = 0x34; fill[42] = 0x56; fill[43] = 0x78;
        const auto path = root.path / "fill.bin";
        { std::ofstream f(path, std::ios::binary); f.write(reinterpret_cast<const char*>(fill.data()), fill.size()); }
        auto image = io::Image::prepare(path, 8192);
        std::vector<uint8_t> data(4103);
        check(image && image->reader()(3, data, {}), "unaligned FILL read");
        bool matches = true;
        for (size_t i = 0; i < data.size(); ++i) matches &= data[i] == fill[40 + (i + 3) % 4];
        check(matches, "bulk FILL expansion preserves rotated pattern");
    }
    const auto xml_path = root.path / "rom.xml";
    const auto xml = [&](const std::string& value) {
        { std::ofstream file(xml_path, std::ios::binary); file << value; }
        return session::PacParser::parse_xml(xml_path);
    };
    auto parsed = xml("\xef\xbb\xbf<rom><partition name='boot' file='a&amp;b&#x2e;bin'/></rom>");
    check(parsed && parsed->partitions[0].file_path == "a&b.bin", "BOM and XML entities");
    check(!xml("<rom><partition name='boot' file='&unknown;'/></rom>"), "unknown entity rejected");
    for(const auto* invalid:{"<other><partition name='boot'/></other>",
        "<rom><partition name='boot' eraze='true'/></rom>","<rom><group><partition name='boot'/></group></rom>",
        "<rom><partition name='boot'><partition name='system'/></partition></rom>",
        "<rom typo='1'><partition name='boot'/></rom>"})check(!xml(invalid),"unknown layout schema rejected");
    {
        const std::vector<uint8_t> duplicate{0x6e,0x65,0x77,0x74,2,0,1,0,2,2,0,1,0,0};
        const std::vector<uint8_t> invalid_bool{0x6e,0x65,0x77,0x74,0,0,4,0,1,1,0,0};
        check(!protocol::parse_da_info(duplicate) && !protocol::parse_da_info(invalid_bool),"conflicting/invalid capability TLVs rejected");
    }
    std::string deep;
    for (unsigned i=0; i<65; ++i) deep += "<r>";
    for (unsigned i=0; i<65; ++i) deep += "</r>";
    check(!xml(deep), "XML nesting bounded");
    parsed = xml("<rom><partition name='boot' file='raw.bin' checksum='0'/></rom>");
    const device::PartitionInfo parts[]{{"boot", 8192}};
    {
        // Missing/unknown-capacity destinations must fail before opening an image.
        auto missing = session::Operations::prepare_write("absent", root.path / "missing.img", parts);
        check(!missing && missing.error().step == session::OperationStep::Validate &&
              missing.error().detail == "partition 'absent' not found",
              "missing partition is distinct from missing image");
        const device::PartitionInfo unknown[]{{"splloader", 0}};
        auto found = session::Operations::find_partition(unknown, "splloader");
        check(found && found->size == 0, "unknown capacity partition still exists for read/erase");
        auto unsized = session::Operations::prepare_write("splloader", root.path / "missing.img", unknown);
        check(!unsized && unsized.error().detail == "partition 'splloader' capacity unavailable",
              "unknown write capacity is distinct from absent partition");
    }
    auto plan = session::Operations::prepare_flash(xml_path, parts);
    check(parsed && parsed->partitions[0].has_checksum && !plan && plan.error().code == std::errc::not_supported,
          "declared zero checksum cannot silently disappear");
    {
        // A tiny FILL input expands to 4 GiB; no large file allocation needed.
        std::vector<uint8_t> sparse(44,0);
        const auto put=[&](size_t at,uint32_t value,size_t width=4) {
            for(size_t i=0;i<width;++i)sparse[at+i]=static_cast<uint8_t>(value>>(8*i));
        };
        put(0,0xed26ff3a);put(4,1,2);put(8,28,2);put(10,12,2);put(12,4096);
        put(16,1048576);put(20,1);put(28,0xcac2,2);put(32,1048576);put(36,16);
        {std::ofstream f(root.path/"large.sparse",std::ios::binary);f.write(reinterpret_cast<const char*>(sparse.data()),sparse.size());}
        const device::PartitionInfo large[]{{"target",8ull*1024*1024*1024}};
        for(const std::string size:{"4294967295","0","remaining","18446744073709551615",""}) {
            auto parsed_size=xml("<rom><partition name='target' file='large.sparse'"+
                (size.empty()?std::string{}:" size='"+size+"'")+"/></rom>");
            check(parsed_size && parsed_size->partitions[0].has_size==!size.empty() &&
                parsed_size->partitions[0].size_remaining==(size=="remaining"),"XML size syntax retained");
            auto prepared=session::Operations::prepare_flash(xml_path,large);
            check(bool(prepared)==(size!="4294967295" && size!="0"),"numeric XML capacity bound enforced");
        }
    }
    {
        session::OperationError original{session::OperationStep::Read,std::errc::protocol_error,"target"};
        original.exchange=protocol::ExchangeEvidence{};
        original.exchange->response=protocol::BslResponse::REP_OPERATION_FAILED;
        original.cleanup_exchange=protocol::ExchangeEvidence{};
        original.cleanup_exchange->response=protocol::BslResponse::REP_ACK;
        // A directory at the manifest destination forces atomic replacement failure.
        const auto destination=root.path/"manifest-directory";
        std::filesystem::create_directory(destination);
        auto failure=cli::detail::record_backup_failure(original,[&] {
            return session::Journal::write(destination,"incomplete","manifest");
        });
        check(failure.code==original.code && failure.target==original.target && failure.journal_failure &&
            failure.exchange->response==original.exchange->response &&
            failure.cleanup_exchange->response==original.cleanup_exchange->response,
            "backup retains read and cleanup evidence alongside manifest failure");
        auto exceptional=cli::detail::record_backup_failure(original,[]()->session::OperationResult<> {throw std::bad_alloc();});
        check(exceptional.code==original.code && exceptional.journal_failure &&
            exceptional.journal_failure->code==std::errc::not_enough_memory,"manifest exception remains secondary");
    }
    std::vector<uint8_t> wire(76, 0);
    wire[0] = 'a'; wire[72] = 1;
    check(bool(protocol::BslCodec::decode_partition_table(wire)), "ASCII partition accepted");
    wire[1] = 1;
    check(!protocol::BslCodec::decode_partition_table(wire), "UTF-16 low-byte alias rejected");
    wire[1] = 0;
    const auto duplicate = wire;
    wire.insert(wire.end(), duplicate.begin(), duplicate.end());
    check(!protocol::BslCodec::decode_partition_table(wire), "duplicate partition rejected");

    // Exercise the real GPT reader with CRC-protected bytes, not a fake layout.
    std::vector<uint8_t> disk(128 * 512, 0);
    const auto put = [&](size_t offset, uint64_t value, size_t length) {
        for (size_t i=0; i<length; ++i) disk[offset+i] = static_cast<uint8_t>(value >> (8*i));
    };
    const std::string magic = "EFI PART";
    std::copy(magic.begin(), magic.end(), disk.begin()+512);
    put(520, 0x10000, 4); put(524, 92, 4);
    put(536, 1, 8); put(544, 127, 8); put(552, 34, 8); put(560, 94, 8);
    disk[568] = 1;
    put(584, 2, 8); put(592, 1, 4); put(596, 128, 4);
    disk[1024] = 1; disk[1040] = 2;
    put(1056, 34, 8); put(1064, 35, 8); disk[1080] = 'a';
    put(600, session::crc32_update(0, std::span(disk).subspan(1024,128)), 4);
    put(528, session::crc32_update(0, std::span(disk).subspan(512,92)), 4);
    const io::Reader reader = [&](uint64_t offset, std::span<uint8_t> bytes, auto) -> std::expected<void,std::errc> {
        if (offset > disk.size() || bytes.size() > disk.size()-offset) return std::unexpected(std::errc::message_size);
        std::copy_n(disk.begin()+offset, bytes.size(), bytes.begin()); return {};
    };
    auto gpt = session::read_primary_gpt(reader);
    check(gpt && gpt->partitions.size() == 1 && gpt->partitions[0].offset == 34*512 &&
          gpt->partitions[0].size == 1024, "GPT derives exact physical range");
    if (gpt) {
        auto layout = *gpt;
        layout.partitions.insert(layout.partitions.begin(), {"later", 40*512, 3*512});
        auto exported = session::make_layout_xml(layout);
        check(bool(exported), "GPT layout exports as repartition XML");
        if (exported) {
            auto parsed_layout = xml(*exported);
            check(parsed_layout && parsed_layout->disk_size == disk.size() &&
                  parsed_layout->sector_size == 512 && parsed_layout->partitions.size() == 2 &&
                  parsed_layout->partitions[0].name == "a" &&
                  parsed_layout->partitions[0].flash_addr == 34*512 &&
                  parsed_layout->partitions[0].size == 1024 &&
                  parsed_layout->partitions[1].flash_addr == 40*512 &&
                  parsed_layout->partitions[1].size == 3*512 &&
                  session::PacParser::build_repartition_table(*parsed_layout),
                  "export roundtrip preserves exact geometry and gaps in physical order");
        }
        layout.partitions[0].size = (layout.header.last_usable + 1 - 40) * 512;
        exported = session::make_layout_xml(layout);
        check(bool(exported), "full-disk final partition exports without fixed-size boundary failure");
        if (exported) {
            auto full = xml(*exported);
            check(full && full->partitions.size() == 2 &&
                  full->partitions.back().size == UINT64_MAX &&
                  full->partitions.back().flash_addr == 40*512 &&
                  session::PacParser::build_repartition_table(*full),
                  "full-disk export roundtrip uses remaining and preserves start");
        }
        // One sector short must not be silently expanded by the exporter.
        layout.partitions[0].size -= 512;
        exported = session::make_layout_xml(layout);
        check(exported && exported->find("remaining") == std::string::npos,
              "fixed endpoint accepted without BSP boundary or silent expansion");
        layout.partitions[0].size = 3*512;
        layout.partitions[0].name = "name & \"quoted\"";
        exported = session::make_layout_xml(layout);
        if (exported) {
            auto decoded = xml(*exported);
            check(decoded && decoded->partitions.back().name == layout.partitions[0].name,
                  "printable partition names survive XML escaping");
        } else check(false, "printable partition name export");
    }
    auto detected = session::read_partition_layout(reader);
    check(detected && !detected->mbr && detected->partitions.size() == 1, "auto-detect GPT without protective MBR");
    disk[1080] ^= 1;
    check(!session::read_primary_gpt(reader), "GPT entry corruption rejected before backup");
    check(!session::read_partition_layout(reader), "corrupt GPT never falls back to MBR");
    std::fill(disk.begin(), disk.end(), 0);
    disk[510] = 0x55; disk[511] = 0xaa;
    const auto mbr_entry = [&](size_t sector, size_t slot, uint8_t type, uint32_t start, uint32_t count) {
        const size_t at = sector*512 + 446 + slot*16;
        disk[at+4] = type; put(at+8, start, 4); put(at+12, count, 4);
    };
    mbr_entry(0,0,0x83,8,4);
    mbr_entry(0,1,0x0f,16,80);
    disk[16*512+510] = 0x55; disk[16*512+511] = 0xaa;
    mbr_entry(16,0,0x83,1,8);
    mbr_entry(16,1,0x0f,16,64);
    disk[32*512+510] = 0x55; disk[32*512+511] = 0xaa;
    mbr_entry(32,0,0x07,1,8);
    check(!session::read_partition_layout(reader), "MBR needs an explicit logical-sector contract");
    detected = session::read_partition_layout(reader, {}, 512);
    check(detected && detected->mbr && detected->disk_bytes == 0 && detected->partitions.size() == 3 &&
          detected->partitions[1].offset == 17*512 && detected->partitions[2].offset == 33*512,
          "MBR primary and EBR-relative logical ranges, capacity remains unknown");
    if (detected) {
        auto exported = session::make_layout_xml(*detected);
        check(exported && exported->find("<region ") != std::string::npos &&
              exported->find("<partition ") == std::string::npos, "MBR labels never become named-write XML");
    }
    mbr_entry(32,1,0x0f,16,64);
    check(!session::read_partition_layout(reader, {}, 512), "cyclic EBR chain rejected");
    disk[450] = 0xee;
    check(!session::read_partition_layout(reader, {}, 512), "protective MBR without valid GPT rejected");
    set_log_sink(nullptr);
    for(const auto& message:failure_messages)log_err(message);
    return failures ? 1 : 0;
}

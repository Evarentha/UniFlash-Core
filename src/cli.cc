/*
 * UniFlash-Core / Command Line Interface
 *
 * Argument dispatch, interactive shell, script mode and the landing summary.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#include <uniflash/core.h>
#include "cli/operation_progress.h"
#include "cli/windows_console.h"
#include <uniflash/progress.h>
#include <uniflash/cli/result.h>
#include <uniflash/session/operations.h>
#include <uniflash/session/raw_backup.h>
#include <uniflash/session/backup_bundle.h>
#include <uniflash/session/nv_restore.h>
#include <uniflash/session/pac_archive.h>
#include <uniflash/session/pac_config.h>
#include <uniflash/session/miscdata.h>
#include <uniflash/session/rename_write.h>
#include <uniflash/session/raw_directory_restore.h>
#include <uniflash/io/decrypt.h>
#include <uniflash/io/sha256.h>
#include <uniflash/session/packed_image.h>
#include <uniflash/session/connection.h>
#include <uniflash/transport/usb.h>
#include <uniflash/platform.h>
#include <uniflash/log.h>
#include <uniflash/cli/commands.h>
#include <uniflash/cli/ping.h>
#include <uniflash/cli/signal.h>
#include <uniflash/cli/line_editor.h>
#include <uniflash/device/sprd_device.h>
#include <uniflash/device/chip_uid.h>
#include <uniflash/protocol/tests.h>
#include <uniflash/protocol/pctool.h>
#include <uniflash/session/pac_parser.h>
#include <uniflash/session/boot_message.h>
#include <uniflash/session/sparse.h>
#include "cli/safe_io.h"
#include "cli/backup_failure.h"

#include <chrono>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <map>
#include <limits>
#include <set>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#endif
#include <vector>

namespace fs = std::filesystem;


// Timing + throughput formatter for success messages
struct OpTimer {
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
    std::string format(uint64_t bytes) const {
        return uniflash::format_transfer(bytes, std::chrono::duration<double>(
            std::chrono::steady_clock::now() - start).count());
    }
};
namespace {

static void print_shell_commands();

using namespace uniflash;
using uniflash::cli::LineEditor;
using uniflash::cli::SignalHandler;
using uniflash::cli::next_token;
using uniflash::device::Stage;
using uniflash::device::DeviceInfo;
using uniflash::device::SprdDevice;
using uniflash::device::FlashPartition;
using uniflash::transport::UsbContext;
using uniflash::transport::UsbDevice;
using uniflash::transport::UsbTransport;

constexpr uint16_t SPRD_VID = 0x1782;

std::string history_path() {
    return platform::history_path();
}

// ----------------------------------------------------------------- output
// Thin wrappers over the unified logger (include/uniflash/log.h —
// the single output authority: style, stream discipline, client sink
// injection). Names kept so the 200+ call sites read naturally.

void info(const std::string& msg) { uniflash::log_info(msg); }
void warn(const std::string& msg) { uniflash::log_warn(msg); }

// Protocol diagnostics retain exact reply codes; the command still needs a
// self-contained failure reason when displayed without diagnostic records.
std::string err_detail(std::errc e) {
    if (e == std::errc::protocol_error) return ": unexpected device reply";
    if (e == std::errc::interrupted) return ": cancelled";
    return ": " + std::make_error_code(e).message();
}

std::string operation_error(std::string_view command, const session::OperationError& error) {
    auto message = std::string(command) + ": " +
        (error.detail.empty() ? error.target + err_detail(error.code) : error.detail);
    if (error.exchange && error.exchange->response) {
        message += "; device reply ";
        message += protocol::BslCodec::reply_name(static_cast<uint8_t>(*error.exchange->response));
    }
    if (!error.session_synchronized) message += "; connection retired, device outcome may be unknown";
    if(error.cleanup_failure)message+="; cleanup failed: "+error.cleanup_failure->target+err_detail(error.cleanup_failure->code);
    if(error.exchange && error.exchange->bare_data)message+="; raw block offset="+std::to_string(error.exchange->offset)+
        " bytes="+std::to_string(error.exchange->requested_bytes);
    if(error.cleanup_exchange && error.cleanup_exchange->response)message+="; cleanup reply "+
        std::string(protocol::BslCodec::reply_name(static_cast<uint8_t>(*error.cleanup_exchange->response)));
    if(error.journal_failure) {
        message+="; journal save failed: "+std::make_error_code(error.journal_failure->code).message();
        if(error.journal_failure->state==io::CommitState::Replaced)message+=" (replaced, durability unconfirmed)";
    }
    if(error.commit_state==io::CommitState::Replaced)message+="; output replaced, durability unconfirmed";
    if(error.initial_raw_failure && error.initial_raw_failure->response) {
        message+="; initial raw reply ";
        message+=protocol::BslCodec::reply_name(static_cast<uint8_t>(*error.initial_raw_failure->response));
    }
    return message;
}

std::expected<uint32_t, std::errc> parse_unsigned(std::string_view text) {
    int base = 10;
    if (text.starts_with("0x") || text.starts_with("0X")) {
        text.remove_prefix(2);
        base = 16;
    }
    if (text.empty()) return std::unexpected(std::errc::invalid_argument);
    uint32_t value;
    const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (ec != std::errc{} || end != text.data() + text.size())
        return std::unexpected(std::errc::invalid_argument);
    return value;
}

const char* stage_name(Stage s) {
    return device::stage_display_name(s);
}

std::string hex(uint64_t v) {
    std::ostringstream o;    o << std::hex << "0x" << v << std::dec;
    return o.str();
}

std::string storage_name(uint32_t s) {
    switch (s) {
    case 0x101: return "nand";
    case 0x102: return "eMMC";
    case 0x103: return "UFS";
    default:    return "unknown(" + hex(s) + ")";
    }
}

// ----------------------------------------------------------------- file

std::expected<std::vector<uint8_t>, std::errc>
read_file(const std::string& path) {
    std::ifstream f(platform::path(path), std::ios::binary | std::ios::ate);
    if (!f) return std::unexpected(std::errc::no_such_file_or_directory);
    const auto end = f.tellg();
    if (end < 0 || static_cast<uint64_t>(end) >
        static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max()) ||
        static_cast<uint64_t>(end) > std::numeric_limits<size_t>::max())
        return std::unexpected(std::errc::file_too_large);
    const auto sz = static_cast<size_t>(end);
    if (sz == 0) return std::unexpected(std::errc::invalid_argument);
    f.seekg(0);
    std::vector<uint8_t> buf(sz);
    if (!f.read(reinterpret_cast<char*>(buf.data()), sz))
        return std::unexpected(std::errc::io_error);
    return buf;
}

uint32_t load_address(const std::string& text, size_t size = 0) {
    const auto address = cli::detail::unsigned_number(text, UINT32_MAX);
    if (size > UINT32_MAX || size > uint64_t{UINT32_MAX} + 1 - address)
        throw std::invalid_argument("image exceeds 32-bit download address range");
    return static_cast<uint32_t>(address);
}

// ----------------------------------------------------------------- usb

std::vector<UsbDevice> scan_devices() {
    std::vector<uint16_t> vids{SPRD_VID};
    auto& ctx = UsbContext::instance();
    auto devs = ctx.find_devices(vids);
    if (!devs) throw std::system_error(std::make_error_code(devs.error()), "USB enumeration failed");
    return std::move(*devs);
}

// Poll bookkeeping may use an enumeration-local identity; reconnect matching
// must exclusively use a nonempty physical port_path.
std::string poll_key(const UsbDevice& device) {
    if (!device.port_path.empty()) return device.path_string();
#ifdef _WIN32
    return platform::utf8(device.device_path);
#else
    return std::to_string(reinterpret_cast<uintptr_t>(device.native.get()));
#endif
}

// Bus listing shared by the interactive `bus` command and the one-shot
// `bus` subcommand — one style, one speed annotation.
static void print_bus_nodes(const std::vector<UsbDevice>& devs) {
    for (size_t i = 0; i < devs.size(); ++i) {
        // FULL speed = the U-Boot PC-tool serial gadget (the pc-mode
        // window); HIGH = a dl_diag stage (bootrom / FDL1 / FDL2 / SPRD4).
        const char* speed =
            devs[i].speed == UsbDevice::Full ? "full"
            : devs[i].speed == UsbDevice::High ? "high"
            : devs[i].speed == UsbDevice::Super ? "super" : "unknown";
        log_status(LogLevel::Info, "device", std::to_string(i + 1),
             "VID=" + hex(devs[i].vid) + ", PID=" + hex(devs[i].pid) +
             ", USB port=" + devs[i].path_string() + ", speed=" + speed +
             (devs[i].port_name.empty() ? "" : ", " + devs[i].port_name));
    }
}

// The single command-table source: printed by BOTH the interactive
// `help` command and the --help flag (same source, zero drift).
static void print_help() {
    log_document(R"(UniFlash-Core - Unisoc/Spreadtrum device flasher

USAGE
  uniflash-core                             interactive shell
  uniflash-core "<command>" ["<command>"...]  script mode (run in order, exit)
  uniflash-core test | version              utilities (--version also supported)

EXAMPLES
  # Interactive (waits for device, auto-connects, then shell)
  uniflash-core

  # Script: explicit command sequence (ONE command language)
  uniflash-core "connect" \
                   "load-fdl fdl1.bin $FDL1_ADDR fdl2.bin $FDL2_ADDR" \
                    "write <partition> <image-file>" \
                   "reboot"

  # Utility: run protocol self-tests
  uniflash-core test

COMMANDS
)");
    print_shell_commands();
    log_document(R"(
NOTES
  - FDL load addresses come from your FDL build's linker script.
  - Options: --help/-h, --version. Script arguments use shell command syntax.
)");
}

static void print_shell_commands() {
    // Each command belongs to one purpose group; registry retains stage policy.
    using enum cli::CommandId;
    std::vector<LogHelpSection> document;
    const auto group = [&](std::string heading, std::initializer_list<cli::CommandId> ids,
                           bool show_stages = false) {
        auto& section = document.emplace_back(std::move(heading), std::vector<LogHelpEntry>{});
        for (auto id : ids) for (const auto& command : cli::commands) {
            if (command.id != id || command.hidden) continue;
            if (id == Info) {
                section.entries.push_back({"info", "Show device information"});
                section.entries.push_back({"info diagnostic", "Query firmware flags and MCP [FDL2]"});
                section.entries.push_back({"info miscdata", "Decode serials and factory tests [FDL2]"});
                continue;
            }
            if (id == Read) {
                section.entries.push_back({"read <part> [out] [size]", "Read a partition"});
                section.entries.push_back({"read all [dir]", "Back up all raw partitions"});
                continue;
            }
            if (id == Write) {
                section.entries.push_back({"write <part> <img>", "Write one image without pre-erase"});
                section.entries.push_back({"write <dir>", "Write images using layout.xml"});
                section.entries.push_back({"write <config.xml>", "Execute XML write/erase plan [FDL2]"});
                section.entries.push_back({"write <package.pac> [host-config.xml]", "BootROM: bundled FDLs; FDL2: reuse loader; no automatic info/parts"});
                continue;
            }
            std::string usage(command.name);
            if (!command.arguments.empty())
                usage += " " + std::string(command.arguments);
            std::string description(command.description);
            if (show_stages) {
                description += " [";
                bool first = true;
                for (auto stage : cli::command_stages) {
                    if (!cli::command_allowed(command, stage)) continue;
                    if (!first) description += '/';
                    description += cli::command_stage_name(stage);
                    first = false;
                }
                description += ']';
            }
            section.entries.push_back({std::move(usage), std::move(description)});
        }
    };
    group("Connection", {Bus, Connect, Info});
    group("Loaders", {LoadFdl, LoadFdl1, LoadFdl2}, true);
    group("Partitions (FDL2)", {Parts, Read, Write, WriteRename, RestoreRaw, Erase, Repartition});
    group("Boot and power (FDL2)", {Reboot, PowerOff, FirstMode});
    group("Advanced", {Download, LoadBin, Exec, DdrTest, PcMode}, true);
    group("Firmware settings (FDL2)", {EnableWrite});
    group("Shell", {Help, Quit});
    group("Offline images", {DecryptImage, UnpackImage});
    log_help(document, "Shortcuts: r = read, w = write, e = erase, ? = help");
    log_document("Arguments: <required>, [optional]. Read size is in bytes.\n"
        "SPRD4: load-fdl and load-fdl2 take no arguments. BSL: loader identity unavailable.\n"
        "Reboot targets: recovery, sideload, sideload-auto-reboot, rescue, fastbootd.\n"
        "Fastbootd requires compatible Recovery and dynamic partitions.");
}

std::expected<SprdDevice, std::errc>
open_and_handshake(const UsbDevice& raw, std::stop_token stop, device::DeviceProfile profile = {}) {
    return session::Connection::open(raw, stop, profile);
}

// After bootrom EXEC the device re-enumerates as FDL1. Re-sync the way
// the reference tools do it: a BSL_CMD_CONNECT frame and its ACK — the
// 0x7E-then-version handshake is a bootrom behavior FDL1 builds vary on.
std::expected<void, std::errc>
adopt_fdl1(SprdDevice& dev, std::stop_token stop) {
    return dev.handshake_fdl1(stop);
}
std::expected<void, std::errc> adopt_fdl2(SprdDevice& dev, std::stop_token stop) {
    return dev.resync_fdl2(std::chrono::seconds(20), stop);
}

std::expected<SprdDevice, std::errc>
wait_reopen(const std::vector<uint8_t>& port_path, std::stop_token stop,
            std::expected<void, std::errc> (*adopt)(SprdDevice&, std::stop_token),
             std::chrono::milliseconds timeout =
                std::chrono::milliseconds(60000), device::DeviceProfile profile = {}) {
    constexpr uint16_t vendors[]{0x1782};
    return session::Connection::reopen(vendors, port_path, adopt, timeout, stop, profile);
}

// ----------------------------------------------------------------- model

struct Slot {
    std::vector<uint8_t> port_path;
    std::optional<SprdDevice> dev;
    // Full entries (name + size), not bare names: `parts` numbers and
    // sizes them; the index is the entry position — the FDL2's 0x2D
    // reply (tool_partition_t {name[72], size_kb}) carries no explicit
    // index or offset fields (dl_cmd_proc.c dl_cmd_check_partition).
    std::vector<device::PartitionInfo> parts_cache;
    fs::path output_directory;

    Stage stage() const {
        if (!dev) return Stage::Offline;
        return dev->info().stage;
    }
};

// ----------------------------------------------------------------- repl

class Shell {
    friend int run_script(const std::vector<std::string>&, std::stop_token);
public:
    using Completer = LineEditor::Completer;
    Shell() {
        const auto path = history_path();
        if (!path.empty()) {
            history_path_ = platform::utf8_path(fs::absolute(platform::path(path)));
            history_loaded_ = editor_.load_history(history_path_);
        }
    }
    ~Shell() noexcept {
        try {
            if (history_loaded_ && editor_.history_dirty() &&
                !editor_.save_history(history_path_)) warn("history: save failed");
        } catch (...) { /* History persistence must not interrupt shutdown. */ }
    }

    int run(std::stop_token stop);
    void landing_summary(Stage prev, std::stop_token);

private:
    // Block until a device shows up, then handshake IMMEDIATELY — the
    // bootrom download window is short; the tool races it, not the human.
    bool wait_for_device(std::stop_token stop, int timeout_s);
    void refresh_parts(Slot& s, std::stop_token stop);
    const fs::path& session_directory();
    cli::CommandResult exec(const std::string& line, std::stop_token stop);
    void exec_checked(const std::string& line, std::stop_token stop, bool validate_only = false);

    void cmd_help();
    void cmd_ls();
    void cmd_connect(std::istringstream&, std::stop_token);
    void cmd_load_fdl1(std::istringstream&, std::stop_token);
    void cmd_load_fdl2(std::istringstream&, std::stop_token);
    void cmd_load_bin(std::istringstream&, std::stop_token);
    void cmd_download(std::istringstream&, std::stop_token);
    void cmd_exec(std::istringstream&, std::stop_token);
    void cmd_load_fdl(std::istringstream&, std::stop_token);
    void cmd_info(bool diagnostic, std::stop_token);
    void cmd_miscdata(std::stop_token);
    void cmd_parts(std::stop_token, bool export_layout = false);
    void cmd_read(std::istringstream&, std::stop_token);
    void cmd_write(std::istringstream&, std::stop_token);
    void cmd_write_rename(std::istringstream&, std::stop_token, bool physical = false);
    void cmd_erase(std::istringstream&, std::stop_token);
    void cmd_dump(std::istringstream&, std::stop_token);
    void cmd_firstmode(std::istringstream&, std::stop_token);
    void cmd_enable_write(std::stop_token);
    void cmd_repartition(std::istringstream&, std::stop_token);
    void cmd_reboot(std::istringstream&, std::stop_token, bool restart = true);
    void cmd_poweroff(std::stop_token);
    void cmd_pc_mode(std::istringstream&, std::stop_token);
    void cmd_ddrtest(std::istringstream&, std::stop_token);

    LineEditor editor_;
    std::string history_path_;
    bool history_loaded_ = false;
    Slot sess_;
    device::DeviceProfile profile_;
    std::expected<void, std::errc> finish_loader(Stage target, std::stop_token stop) {
        const auto adopt = target == Stage::Fdl1 ? adopt_fdl1 : adopt_fdl2;
        const auto active_profile = sess_.dev->profile();
        auto result = adopt(*sess_.dev, stop);
        if (result || stop.stop_requested() ||
            (result.error() != std::errc::no_such_device && !sess_.dev->link_dead())) return result;
        // Only a physical disconnect permits opening a new handle. Never
        // replay an upload or hide an uncertain END/EXEC on the old handle.
        sess_.dev.reset();
        sess_.parts_cache.clear();
        auto reopened = wait_reopen(sess_.port_path, stop, adopt, std::chrono::seconds(60), active_profile);
        if (!reopened) return std::unexpected(reopened.error());
        sess_.dev = std::move(*reopened);
        return {};
    }
    bool quitting_ = false;
    cli::CommandResult last_result_;
    std::string cancellation_detail_;
    void capture_write_cancellation() {
        const auto& timings = sess_.dev->write_timings();
        if (!timings.cancelled) return;
        cancellation_detail_ = timings.cancel_end_rejected
            ? "write cancelled; device rejected incomplete write; partition may be partially written"
            : timings.cancel_end_acked
            ? "write cancelled; END_DATA acknowledged; image completeness not confirmed"
            : "write cancelled; END_DATA unconfirmed; partition may be partially written";
    }
    std::chrono::steady_clock::time_point command_started_;
    void print_operation_timing(const session::OperationReport&, double prepare_seconds) const;
    std::string operation_summary(uint64_t bytes) const;

    [[noreturn]] void fail(const std::string& message) { throw cli::CommandFailure{message}; }

    [[noreturn]] void retire_connection(const std::string& message) {
        sess_.dev.reset();
        sess_.parts_cache.clear();
        fail(message);
    }

public:
    bool quitting() const { return quitting_; }
};

bool Shell::wait_for_device(std::stop_token stop, int timeout_s) {
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::seconds(timeout_s);
    auto last_note = std::chrono::steady_clock::time_point{};
    std::map<std::string, std::chrono::steady_clock::time_point> retry_after;
    info("connect: waiting for device");
    while (std::chrono::steady_clock::now() < deadline) {
        if (stop.stop_requested()) return false;
        auto devs = scan_devices();
        if (devs.size() > 1) fail("multiple matching interfaces found; only one device is supported");
        if (!devs.empty()) {
            for (size_t i = 0; i < devs.size(); ++i) {
                if (stop.stop_requested()) return false;
                auto& d = devs[i];
                const auto key = poll_key(d);
                if (std::chrono::steady_clock::now() < retry_after[key]) continue;
                auto opened = open_and_handshake(d, stop, profile_);
                if (opened) {
                    sess_.port_path = d.port_path;
                    sess_.dev = std::move(opened.value());
                    sess_.output_directory.clear();
                    log_status(LogLevel::Info, "connected", stage_name(sess_.stage()),
                        "port " + d.path_string() + (sess_.dev->info().chip.version.empty()
                            ? "" : ", handshake " + sess_.dev->info().chip.version));
                    return true;
                }
                auto now = std::chrono::steady_clock::now();
                retry_after[key] = now + std::chrono::seconds(2);
                if (now - last_note > std::chrono::seconds(2)) {
                    if (opened.error() == std::errc::permission_denied ||
                        opened.error() == std::errc::device_or_resource_busy)
                        warn("connect: " + d.path_string() + err_detail(opened.error()));
                    else if (log_diag_trace_enabled())
                        log_diag("{connect} " + d.path_string() + err_detail(opened.error()));
                    log_progress("connect: device present, waiting for handshake");
                    last_note = now;
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

void Shell::refresh_parts(Slot& s, std::stop_token stop) {
    s.parts_cache.clear();
    auto parts = s.dev
        ? s.dev->list_partitions(stop)
        : std::expected<std::vector<device::PartitionInfo>, std::errc>(
              std::unexpected(std::errc::not_connected));
    if (parts)
        for (auto& p : parts.value()) s.parts_cache.push_back(p);
    else if (parts.error() == std::errc::not_supported && !s.dev->link_dead() && !s.dev->link_silent() && !stop.stop_requested())
        warn("partition listing unavailable; explicit named operations remain available");
    else fail("cannot list partitions" + err_detail(parts.error()));
}

void Shell::cmd_help() {
    print_shell_commands();
}

void Shell::cmd_ls() {
    auto devs = scan_devices();
    if (devs.empty()) {
        info("bus: no devices found");
        return;
    }
    print_bus_nodes(devs);
}

void Shell::cmd_connect(std::istringstream& arguments, std::stop_token stop) {
    std::string selector, extra;
    next_token(arguments, selector); next_token(arguments, extra);
    if (!extra.empty()) fail("usage: connect [port]");
    auto devs = scan_devices();
    if (!selector.empty()) {
        auto found = std::find_if(devs.begin(), devs.end(), [&](const UsbDevice& dev) {
            if (dev.path_string() == selector) return true;
            std::string port = dev.port_name, requested = selector;
            std::transform(port.begin(), port.end(), port.begin(), [](unsigned char c) { return std::toupper(c); });
            std::transform(requested.begin(), requested.end(), requested.begin(), [](unsigned char c) { return std::toupper(c); });
            return !port.empty() && port == requested;
        });
        if (found == devs.end()) fail("connect: port not found: " + selector);
        UsbDevice selected = *found;
        devs = {std::move(selected)};
    }
    if (devs.size() > 1) fail("multiple matching interfaces found; only one device is supported");
    // A typo or failed enumeration cannot destroy a live loader session.
    // Keep the old device while opening a different physical target.
    if (sess_.dev) {
        if (selector.empty()) {
            log_status(LogLevel::Info, "connected", stage_name(sess_.stage()));
            return;
        }
        if (!sess_.port_path.empty() && devs.front().port_path == sess_.port_path) {
            log_status(LogLevel::Info, "connected", stage_name(sess_.stage()));
            return;
        }
    }
    if (devs.empty()) {
        // Nothing on the bus right now: fall back to waiting for one.
        if (!wait_for_device(stop, 120)) fail("device connection timeout or cancellation (120s)");
        return;
    }
    info("connect: opening device");
    std::errc last_error = std::errc::not_connected;
    for (const auto& d : devs) {
        if (stop.stop_requested()) fail("connect: cancelled");
        auto opened = open_and_handshake(d, stop, profile_);
        if (!opened) { last_error = opened.error(); continue; }
        sess_.port_path = d.port_path;
        sess_.dev = std::move(opened.value());
        sess_.output_directory.clear();
        sess_.parts_cache.clear();
        log_status(LogLevel::Info, "connected", stage_name(sess_.stage()),
            sess_.dev->info().chip.version.empty() ? "" : "handshake " + sess_.dev->info().chip.version);
        return;
    }
    fail("connect failed" + err_detail(last_error));
}

// Load FDL1 into bootrom SRAM. Requires the load address explicitly.
void Shell::cmd_load_fdl1(std::istringstream& ss, std::stop_token stop) {
    auto* s = &sess_;
    std::string file, astr;
    next_token(ss, file); next_token(ss, astr);
    if (file.empty() || astr.empty()) {
        fail("usage: load-fdl1 <fdl1.bin> <load_addr>");
    }
    auto f = read_file(file);
    if (!f) fail("cannot read " + file + err_detail(f.error()));
    uint32_t addr = load_address(astr, f->size());
    log_status(LogLevel::Info, "load", "FDL1", format_size(f->size()) + " at " + hex(addr));
    auto up = s->dev->upload_fdl1(*f, addr, stop);
    if (!up) {
        retire_connection("load failed" + err_detail(up.error()));
    }
    log_progress("load: FDL1, waiting for handshake");
    // Adopt in place, or reopen the same physical port after a disconnect.
    if (auto hs = finish_loader(Stage::Fdl1, stop)) {
        log_status(LogLevel::Info, "ready", stage_name(Stage::Fdl1));
    } else {
        retire_connection("FDL1 did not wake" + err_detail(hs.error()));
    }
}

// Load FDL2 into FDL1's DRAM window. Requires the load address explicitly.
void Shell::cmd_load_fdl2(std::istringstream& ss, std::stop_token stop) {
    auto* s = &sess_;
    // SPRD4 autodloader (adb reboot autodloader): u-boot IS the FDL2 —
    // no image upload happens, the double EXEC just switches it from
    // its RomCode-cosplay to the real do_download() handlers
    // (autodloader_mode.c autodloader_exec). The file/addr args are
    // not used on this path.
    if (s->dev->info().is_sprd4) {
        log_status(LogLevel::Info, "load", "FDL2", "SPRD4");
        auto enter = s->dev->sprd4_enter_fdl2(stop);
        if (!enter) {
            retire_connection("sprd4 transition failed" + err_detail(enter.error()));
        }
        auto rs = finish_loader(Stage::Fdl2, stop);
        if (!rs) {
            retire_connection("FDL2 did not come up" + err_detail(rs.error()));
        }
        return;
    }
    std::string file, astr;
    next_token(ss, file); next_token(ss, astr);
    if (file.empty() || astr.empty()) {
        fail("usage: load-fdl2 <fdl2.bin> <addr> (addr = FDL1 DRAM window)");
    }
    auto f = read_file(file);
    if (!f) fail("cannot read " + file + err_detail(f.error()));
    uint32_t addr = load_address(astr, f->size());
    log_status(LogLevel::Info, "load", "FDL2", format_size(f->size()) + " at " + hex(addr));
    auto up = s->dev->upload_fdl2(*f, addr, stop);
    if (!up) {
        retire_connection("load failed" + err_detail(up.error()));
    }
    log_progress("load: FDL2, waiting for DA_INFO");
    auto rs = finish_loader(Stage::Fdl2, stop);
    if (!rs) {
        retire_connection("FDL2 did not come up" + err_detail(rs.error()));
    }
}

// Generic binary loader: push ANY binary to the CURRENT stage and execute it.
// Works at bootrom / fdl1 — the address is always explicit.
void Shell::cmd_load_bin(std::istringstream& ss, std::stop_token stop) {
    auto* s = &sess_;
    if (s->port_path.empty()) fail("load-bin: physical identity unavailable for reconnect");
    std::string file, astr, estr;
    next_token(ss, file); next_token(ss, astr); next_token(ss, estr);
    if (file.empty() || astr.empty()) {
        fail("usage: load-bin <bin> <load_addr> [exec_addr]");
    }
    auto f = read_file(file);
    if (!f) fail("cannot read " + file + err_detail(f.error()));
    uint32_t addr = load_address(astr, f->size());
    uint32_t exec_addr = estr.empty()
        ? 0
        : load_address(estr);
    log_status(LogLevel::Info, "load", file, format_size(f->size()) + " at " + hex(addr));
    // A bare stub (no DHTB header) is NOT an "FDL image": send it through
    // download+EXEC instead of upload_fdl* — the bootrom's verify path is
    // tied to the FDL download flow, and EXEC on a plain address must not
    // drag the stub through START's image bookkeeping again.
    auto dl = s->dev->download_image(*f, addr, stop);
    if (!dl) {
        fail("download failed" + err_detail(dl.error()));
    }
    auto exec_enc = s->stage() == Stage::Fdl1 && s->dev->profile().fdl1_checksum == device::LoaderChecksum::Add
        ? protocol::BslCodec::encode_exec_add(estr.empty() ? addr : exec_addr)
        : protocol::BslCodec::encode_exec(estr.empty() ? addr : exec_addr);
    if (!exec_enc) fail("load-bin: exec encode failed" + err_detail(exec_enc.error()));
    auto wr = s->dev->send_exec_raw(exec_enc.value(), stop);
    if (!wr) {
        retire_connection("exec failed" + err_detail(wr.error()));
    }
    info("load: binary executed, waiting for reconnect");
    // Drop the dead link before waiting — same EBUSY cause as cmd_exec.
    s->dev.reset();
    // The pushed binary defines what answers next; an FDL1-shaped
    // payload answers the CONNECT handshake, so try that and report.
    if (auto again = wait_reopen(s->port_path, stop, adopt_fdl1, std::chrono::seconds(60), profile_)) {
        s->dev = std::move(again.value());
        log_status(LogLevel::Info, "ready", stage_name(s->stage()));
    } else {
        retire_connection("load-bin: device did not re-appear (or the binary is not FDL1-shaped)");
    }
}

// Download WITHOUT executing — START/MIDST/END only. Needed by the
// CVE-2022-38694 flow: park FDL1 at its SRAM address first, then execute
// a separate stub at another address that jumps there without verify.
void Shell::cmd_download(std::istringstream& ss, std::stop_token stop) {
    auto* s = &sess_;
    std::string file, astr;
    next_token(ss, file); next_token(ss, astr);
    if (file.empty() || astr.empty()) {
        fail("usage: download <bin> <addr> (no EXEC)");
    }
    auto f = read_file(file);
    if (!f) fail("cannot read " + file + err_detail(f.error()));
    uint32_t addr = load_address(astr, f->size());
    log_status(LogLevel::Info, "download", file, format_size(f->size()) + " at " + hex(addr));
    auto r = s->dev->download_image(*f, addr, stop);
    if (!r) {
        fail("download failed" + err_detail(r.error()));
    }
    log_status(LogLevel::Info, "downloaded", hex(addr), "not executed");
}

// Bare EXEC_DATA — no START/MIDST/END. Completes a manual sequence:
//   download <a> <addr1>; download <b> <addr2>; exec <addr2>
void Shell::cmd_exec(std::istringstream& ss, std::stop_token stop) {
    auto* s = &sess_;
    if (s->port_path.empty()) fail("exec: physical identity unavailable for reconnect");
    std::string astr;
    next_token(ss, astr);
    if (astr.empty()) {
        fail("usage: exec <addr> (bare EXEC_DATA, expects a prior download)");
    }
    uint32_t addr = load_address(astr);
    auto exec_enc = s->stage() == Stage::Fdl1 && s->dev->profile().fdl1_checksum == device::LoaderChecksum::Add
        ? protocol::BslCodec::encode_exec_add(addr)
        : protocol::BslCodec::encode_exec(addr);
    if (!exec_enc) fail("exec address encode failed" + err_detail(exec_enc.error()));
    log_status(LogLevel::Info, "exec", hex(addr));
    auto wr = s->dev->send_exec_raw(exec_enc.value(), stop);
    if (!wr) {
        retire_connection("exec failed" + err_detail(wr.error()));
    }
    log_progress("exec: waiting for reconnect");
    // Drop the dead link before waiting — a claimed interface on the
    // pre-reset node keeps the re-enumerated node busy (EBUSY).
    s->dev.reset();
    if (auto again = wait_reopen(s->port_path, stop, adopt_fdl1, std::chrono::seconds(60), profile_)) {
        s->dev = std::move(again.value());
        log_status(LogLevel::Info, "ready", stage_name(s->stage()));
    } else {
        retire_connection("exec: device did not re-appear");
    }
}

// One-shot: load FDL1 (into bootrom SRAM) then FDL2 (into FDL1 DRAM), reaching fdl2.
// Both addresses are explicit and paired with their file.
void Shell::cmd_load_fdl(std::istringstream& ss, std::stop_token stop) {
    auto* s = &sess_;
    // SPRD4 autodloader (adb reboot autodloader): NO binaries are needed —
    // u-boot itself runs the FDL2 download handlers once the double EXEC
    // flips it out of its RomCode cosplay (autodloader_mode.c). The whole
    // load-fdl sequence collapses to the sprd4 transition + resync.
    if (s->dev->info().is_sprd4) {
        cmd_load_fdl2(ss, stop);
        return;
    }
    std::string f1, a1, f2, a2;
    next_token(ss, f1); next_token(ss, a1);
    next_token(ss, f2); next_token(ss, a2);
    if (f1.empty() || a1.empty() || f2.empty() || a2.empty()) {
        fail("usage: load-fdl <fdl1.bin> <fdl1_addr> <fdl2.bin> <fdl2_addr>");
    }
    auto rf1 = read_file(f1);
    if (!rf1) fail("cannot read " + f1 + err_detail(rf1.error()));
    auto rf2 = read_file(f2);
    if (!rf2) fail("cannot read " + f2 + err_detail(rf2.error()));
    uint32_t addr1 = load_address(a1, rf1->size());
    uint32_t addr2 = load_address(a2, rf2->size());

    if (s->stage() == Stage::BootRom || s->stage() == Stage::Memory) {
        log_status(LogLevel::Info, "load", "FDL1", format_size(rf1->size()) + " at " + hex(addr1));
        auto up = s->dev->upload_fdl1(*rf1, addr1, stop);
        if (!up) {
            retire_connection("FDL1 load failed" + err_detail(up.error()));
        }
        log_progress("load: FDL1, waiting for handshake");
        // Same-handle poll (device does not re-enumerate).
        if (auto hs = finish_loader(Stage::Fdl1, stop)) {
            // The handshake confirmed the transition to FDL1.
        } else {
            retire_connection("FDL1 did not wake" + err_detail(hs.error()));
        }
    }
    if (!s->dev || s->stage() != Stage::Fdl1) {
        fail("load-fdl: expected FDL1 stage, got " + std::string(stage_name(s->stage())));
    }
    log_status(LogLevel::Info, "load", "FDL2", format_size(rf2->size()) + " at " + hex(addr2));
    auto up = s->dev->upload_fdl2(*rf2, addr2, stop);
    if (!up) {
        retire_connection("FDL2 load failed" + err_detail(up.error()));
    }
    log_progress("load: FDL2, waiting for DA_INFO");
    auto rs = finish_loader(Stage::Fdl2, stop);
    if (!rs) {
        retire_connection("FDL2 did not come up" + err_detail(rs.error()));
    }
}

void Shell::cmd_miscdata(std::stop_token stop) {
    if (sess_.stage() != Stage::Fdl2) fail("info miscdata: requires FDL2");
    auto parts = sess_.dev->list_partitions(stop, false);
    if (!parts) fail("info miscdata: cannot list partitions" + err_detail(parts.error()));
    auto part = session::Operations::find_partition(*parts, "miscdata");
    if (!part) fail(operation_error("info miscdata", part.error()));
    if (part->size < 512) fail("info miscdata: partition too small for header");
    if (part->size >= session::boot_lock_record_offset + 64) {
        auto record = sess_.dev->read_partition("miscdata", session::boot_lock_record_offset, 64, stop);
        if (!record) fail("info miscdata: boot lock record read failed" + err_detail(record.error()));
        using enum session::BootLockRecord;
        const auto kind = session::parse_boot_lock_record(*record);
        log_field("BL record", kind == UnlockMarker ? "VerifiedBoot-UNLOCK (plaintext marker)" :
            kind == LockMarker ? "VerifiedBoot-LOCK (plaintext marker)" :
            kind == Empty ? "empty" : "opaque (encrypted or unknown format)");
        // User-selected presence heuristic, independent of marker semantics.
        log_field("BL state", kind == Unavailable ? "unavailable" : kind == Empty ?
            "locked (empty record heuristic)" : "unlocked (non-empty record heuristic)");
    } else log_field("BL state", "unavailable (lock record outside partition)");
    auto bytes = sess_.dev->read_partition("miscdata", 0, 512, stop);
    if (!bytes) fail("info miscdata: read failed" + err_detail(bytes.error()));
    const auto serials = session::parse_miscdata_serials(*bytes);
    if (serials) {
        log_field("SN1", serials->first.empty() ? "unavailable" : serials->first);
        log_field("SN2", serials->second.empty() ? "unavailable" : serials->second);
    }
    auto parsed = session::parse_miscdata(*bytes);
    if (!parsed) {
        if (parsed.error() == std::errc::not_supported) fail("info miscdata: unrecognized phase-check magic");
        fail("info miscdata: invalid phase-check header" + err_detail(parsed.error()));
    }
    log_field("format", parsed->format);
    log_field("sign flag", hex(parsed->sign_flag));
    log_field("last failure", parsed->last_failure.empty() ? "none recorded" : parsed->last_failure);
    if (parsed->ambiguous_status) {
        warn("miscdata: SP15 status layout ambiguous (32/64-bit unsigned long)");
        log_field("32-bit masks", "tested=" + hex(parsed->tested_bits) + ", result=" + hex(parsed->result_bits));
        log_field("64-bit masks", "tested=" + hex(parsed->alternate_tested_bits) + ", result=" + hex(parsed->alternate_result_bits));
    }
    const LogColumn columns[]{{"#", LogAlignment::Right}, {"Station"}, {"Result"}};
    LogTableSection section;
    for (size_t i=0; i<parsed->stations.size(); ++i) {
        const auto& station = parsed->stations[i];
        using enum session::StationResult;
        const char* result = station.result == Pass ? "PASS" : station.result == Fail ? "FAIL" :
            station.result == NotTested ? "Not tested" : "Unknown";
        section.rows.push_back({std::to_string(i), station.name.empty() ? "unnamed" : station.name, result});
    }
    log_table(columns, std::span(&section,1));
    info("(" + std::to_string(parsed->stations.size()) + " stations total)");
}

void Shell::cmd_info(bool diagnostic, std::stop_token stop) {
    auto* s = &sess_;
    if (diagnostic) {
        if (s->stage() != Stage::Fdl2) fail("info diagnostic: requires FDL2");
        auto root = s->dev->root_flag(stop);
        if (!root) fail("info diagnostic: root flag query failed" + err_detail(root.error()));
        log_field("root flag", *root ? "set (firmware flag)" : "clear (firmware flag)");
        auto nv = s->dev->check_nv_type(stop);
        if (!nv) fail("info diagnostic: NV type query failed" + err_detail(nv.error()));
        log_field("NV type", *nv == 0xff ? "no RF part (0xff)" : hex(*nv));
        auto mcp = s->dev->read_mcp_type(stop);
        if (!mcp) {
            if (mcp.error() != std::errc::not_supported)
                fail("info diagnostic: MCP query failed" + err_detail(mcp.error()));
            log_field("MCP", "unavailable");
        } else {
            log_field("MCP flag", std::to_string(mcp->flag));
            log_field("MCP page", format_size(mcp->page_size));
            log_field("MCP block", format_size(mcp->block_size));
        }
        return;
    }
    if (!s->dev) {
        log_field("stage", "offline");
        return;
    }
    const auto& di = s->dev->info();

    log_field("stage", stage_name(s->stage()));
    if (!di.chip.version.empty())
        log_field(s->stage() == Stage::Fdl2 ? "handshake" : "loader", di.chip.version);
    if (s->stage() != Stage::Fdl2) return;
    auto layout = s->dev->read_disk_layout(stop);
    if (!layout && layout.error() != std::errc::not_supported)
        fail("info: partition layout read failed" + err_detail(layout.error()));
    auto ci = s->dev->read_chip_info(stop, false);
    if (!ci) fail("info: chip query failed" + err_detail(ci.error()));
    auto capacity = s->dev->read_flash_type(stop);
    if (!capacity && capacity.error() != std::errc::not_supported)
        fail("info: capacity query failed" + err_detail(capacity.error()));
    if (capacity) {
        ci->ddr_mb = capacity->first;
        ci->emmc_mb = capacity->second;
    }
    if (ci) {
        // 0x07 READ_CHIP_TYPE is commented out of the FDL2 registration
        // on most builds (cmd_download.c:188) — the device never
        // reports a chip_type there; only print what was actually
        // answered, not a misleading 0x0.
        if (ci->chip_type)
            log_field("chip type", hex(ci->chip_type));
        const auto uid = device::format_chip_uid(ci->chip_uid);
        log_field("chip UID", uid.empty() ? "unavailable" : uid);
        log_field("memory", ci->ddr_mb ? format_size(uint64_t(ci->ddr_mb) * 1048576) : "unavailable");
    }
    const auto& da = s->dev->da_info();
    const auto type = da.valid && da.storage ? storage_name(da.storage) : "unknown type";
    log_field("storage", type + std::string(", ") +
        (layout && layout->disk_bytes ? format_size(layout->disk_bytes) :
         ci->emmc_mb ? format_size(uint64_t(ci->emmc_mb) * 1048576) : "capacity unavailable"));
    std::string sn1, sn2;
    if (layout && !layout->mbr) {
        const auto part = std::find_if(layout->partitions.begin(), layout->partitions.end(),
            [](const auto& p) { return p.name == "miscdata"; });
        if (part != layout->partitions.end() && part->size >= 512) {
            auto bytes = s->dev->read_partition("miscdata", 0, 512, stop);
            if (!bytes) {
                if (stop.stop_requested() || s->dev->link_dead() || s->dev->link_silent())
                    fail("info: miscdata read failed" + err_detail(bytes.error()));
                if (log_diag_trace_enabled()) log_diag("{info} miscdata read failed" + err_detail(bytes.error()));
            } else {
                auto parsed = session::parse_miscdata_serials(*bytes);
                if (parsed) {
                    sn1 = std::move(parsed->first);
                    sn2 = std::move(parsed->second);
                } else if (log_diag_trace_enabled())
                    log_diag("{info} miscdata header not decoded" + err_detail(parsed.error()));
            }
        }
    }
    log_field("SN1", sn1.empty() ? "unavailable" : sn1);
    log_field("SN2", sn2.empty() ? "unavailable" : sn2);
    if (log_diag_trace_enabled() && da.valid) {
        log_diag("{da} raw-data capability: " + std::string(da.support_raw ? "yes" : "no"));
        log_diag("{da} disable-HDLC capability: " + std::string(da.disable_hdlc ? "yes" : "no"));
        log_diag("{bsl} active TX framing: " + std::string(s->dev->raw_tx() ? "raw" : "escaped"));
        if (da.flush_kb)
            log_diag("{da} flush: " + format_size(uint64_t(da.flush_kb) * 1024));
    }
}

void Shell::cmd_parts(std::stop_token stop, bool export_layout) {
    auto* s = &sess_;
    if (export_layout || s->parts_cache.empty()) refresh_parts(*s, stop);
    if (s->parts_cache.empty()) return;
    const bool show_type = std::any_of(s->parts_cache.begin(), s->parts_cache.end(),
        [](const auto& part) { return part.address_only; });
    std::vector<LogColumn> columns{
        {"#", LogAlignment::Right}, {"Name"},
        {"Size", LogAlignment::Right}, {"Bytes", LogAlignment::Right},
        {"Offset", LogAlignment::Right}};
    if (show_type) columns.push_back({"Type"});
    std::vector<LogTableSection> sections;
    // Group headers by source: the 0x2D reply walks only the GPT on
    // the eMMC USER hardware partition (BSP get_dev_hwpart USER_PART);
    // splloader/splloader_bak are synthesized rows for the eMMC BOOT1/2
    // hardware partitions, sized via the _size convention (ext_csd
    // BOOT_SIZE_MULT) — "-" only if that probe failed.
    std::optional<bool> cur_group;
    for (size_t i = 0; i < s->parts_cache.size(); ++i) {
        const auto& p = s->parts_cache[i];
        if (!cur_group || *cur_group != p.hw_boot) {
            sections.push_back({p.hw_boot ? (s->dev->da_info().storage==0x103 ? "UFS boot roles (firmware LU mapping)" : "eMMC boot hardware partitions") :
                p.address_only ? "MBR regions (labels are not firmware names)" : "device partitions", {}});
            cur_group = p.hw_boot;
        }
        const bool unknown = p.hw_boot && p.size == 0;
        LogRow row{std::to_string(i), p.name, unknown ? "unavailable" : format_size(p.size),
            unknown ? "-" : std::to_string(p.size), p.hw_boot || !p.offset ? "-" : std::to_string(p.offset)};
        if (show_type) row.push_back(p.address_only ? hex(p.mbr_type) : "-");
        sections.back().rows.push_back(std::move(row));
    }
    log_table(columns, sections);
    info("(" + std::to_string(s->parts_cache.size()) + " partitions total)");
    if (export_layout) {
        const auto destination = session_directory() / "layout.xml";
        auto layout = session::RawBackup::read_layout(*s->dev, stop);
        if (!layout && layout.error().code == std::errc::not_supported) {
            warn("parts: raw layout unavailable; XML export skipped");
            return;
        }
        if (!layout) fail(operation_error("parts: layout export", layout.error()));
        auto xml = session::make_layout_xml(*layout);
        if (!xml && xml.error() == std::errc::no_space_on_device)
            fail("parts: GPT partition endpoints exceed declared disk capacity");
        if (!xml) fail("parts: layout XML export failed" + err_detail(xml.error()));
        auto output = io::AtomicOutput::open(destination);
        if (!output) fail("parts: layout.xml" + err_detail(output.error()));
        auto written = output->write(std::span(reinterpret_cast<const uint8_t*>(xml->data()), xml->size()), stop);
        if (!written) fail("parts: layout.xml" + err_detail(written.error()));
        if (stop.stop_requested()) fail("parts: layout export cancelled");
        auto committed = output->commit();
        if (!committed) fail("parts: layout.xml" + err_detail(committed.error()) +
            (output->commit_state() == io::CommitState::Replaced ? "; output replaced, durability unconfirmed" : ""));
        log_status(LogLevel::Info, "output", platform::utf8_path(destination));
    }
}

void Shell::cmd_read(std::istringstream& ss, std::stop_token stop) {
    auto* s = &sess_;
    std::string part, out;
    next_token(ss, part);
    if (part == "all") { cmd_dump(ss, stop); return; }
    next_token(ss, out);
    std::string size_arg;
    next_token(ss, size_arg);   // optional size override (hw boot parts)
    if (part.empty()) fail("read: usage: read <part> [out] [size]");
    uint64_t size = 0;
    auto parts = s->dev->list_partitions(stop, false);
    if (!parts && (parts.error() != std::errc::not_supported || s->dev->link_dead() || s->dev->link_silent() || stop.stop_requested()))
        fail("read: cannot list partitions" + err_detail(parts.error()));
    bool hw_boot = false;
    if (parts) {
        auto partition = session::Operations::find_partition(*parts, part);
        if (!partition) fail(operation_error("read", partition.error()));
        size = partition->size;
        hw_boot = partition->hw_boot;
    } else {
        if (size_arg.empty()) fail("read: partition capacity unavailable; use read <part> <out> <size-bytes>");
        warn("read: enumeration unavailable; using explicit name and size");
    }
    if (size_arg.empty() && hw_boot && !size) {
        auto probed = s->dev->probe_hw_part_size(part, stop);
        if (probed) size = *probed;
        else if (s->dev->link_dead() || s->dev->link_silent() || stop.stop_requested())
            fail("read: " + part + err_detail(probed.error()));
    }
    if (!size_arg.empty()) {
        // An available table still validates the name; unavailable is not absent.
        size = cli::detail::unsigned_number(size_arg, UINT32_MAX);
    } else if (size == 0) {
        // listed but size unknown: the hw boot entries (splloader,
        // splloader_bak) — the FDL2 reports no BOOT1/BOOT2 size.
        fail("read: partition '" + part + "' capacity unavailable; use read <part> <out> <size-bytes>");
    }
    if (!size || size > UINT32_MAX) fail("read: invalid or unsupported partition size");
    if (out.empty()) out = platform::utf8_path(session_directory() /
        platform::path(cli::detail::partition_filename(part)));
    log_status(LogLevel::Info, "read", part, format_size(size));
    OpTimer tm;
    fs::path out_path = platform::path(out);
    if (fs::is_directory(out_path)) out_path /= platform::path(cli::detail::partition_filename(part));
    auto saved = session::Operations::backup(*s->dev, part, size, out_path, stop);
    if (!saved) {
        fail(operation_error("read", saved.error()));
    }
    log_status(LogLevel::Info, "saved", part, tm.format(*saved));
    log_status(LogLevel::Info, "output", platform::utf8_path(out_path));
}

void Shell::cmd_write(std::istringstream& ss, std::stop_token stop) {
    std::string part, file;
    next_token(ss, part); next_token(ss, file);
    if (part.empty()) fail("usage: write <part> <img> or write <dir|config.xml|package.pac>");
    auto* s = &sess_;
    auto input_extension=platform::utf8_path(platform::path(part).extension());
    for(auto& c:input_extension)if(c>='A'&&c<='Z')c+=32;
    const bool configured_pac=input_extension==".pac" && !file.empty();
    const bool batch = file.empty() || configured_pac;
    cli::OperationDisplay display(batch);
    const auto preparing = std::chrono::steady_clock::now();
    auto extension = platform::utf8_path(platform::path(part).extension());
    for (auto& c : extension) if (c >= 'A' && c <= 'Z') c += 32;
    if (!batch && device::nv_pair(part)) {
        auto prepared = session::NvRestore::prepare(*s->dev, part, platform::path(file), stop);
        if (!prepared) fail(operation_error("NV restore", prepared.error()));
        const auto root = session_directory();
        fs::path recovery;
        for (unsigned i=1; i<=10000; ++i) {
            auto candidate=root/("nv-restore-"+std::to_string(i));
            if (!fs::exists(candidate)) { recovery=std::move(candidate); break; }
        }
        if (recovery.empty()) fail("NV recovery directory unavailable");
        auto saved=session::NvRestore::save_recovery(*prepared,recovery);
        if (!saved) fail(operation_error("NV restore",saved.error()));
        log_status(LogLevel::Info,"NV recovery",platform::utf8_path(recovery));
        const auto began=std::chrono::steady_clock::now();
        auto restored=session::NvRestore::execute(*s->dev,*prepared,stop,[&](const io::TransferProgress& event) {
            log_transfer_progress("NV write: "+part,event.completed,event.total,
                std::chrono::duration<double>(std::chrono::steady_clock::now()-began).count());
        });
        if (!restored) fail(operation_error("NV restore",restored.error()));
        log_status(LogLevel::Info,"NV restored",part,"primary and backup physically verified");
        return;
    }
    std::optional<session::PacArchive> pac;
    session::PacPrepareOptions pac_options;
    if (batch && extension==".pac") {
        auto opened=session::PacArchive::open(platform::path(part),0,stop);
        if (!opened) fail("PAC preparation"+err_detail(opened.error()));
        pac.emplace(std::move(*opened));
        if(configured_pac) {
            auto options=session::read_pac_config(platform::path(file),pac->product(),stop);
            if(!options)fail("PAC host configuration"+err_detail(options.error()));
            pac_options=std::move(*options);
        }
        if (s->stage()!=Stage::Fdl2) s->output_directory.clear();
        const auto loader=[&](std::string_view type)->std::pair<std::vector<uint8_t>,uint32_t> {
            const auto found=std::find_if(pac->loaders().begin(),pac->loaders().end(),[&](const auto& l){return l.type==type;});
            if(found==pac->loaders().end()) fail("PAC missing loader "+std::string(type));
            auto bytes=pac->loader_bytes(*found,stop);
            if(!bytes) fail("PAC loader read"+err_detail(bytes.error()));
            return {std::move(*bytes),found->load_address};
        };
        // Freeze and check both loader byte ranges before the first EXEC.
        std::optional<std::pair<std::vector<uint8_t>,uint32_t>> f1,f2;
        if (s->stage()!=Stage::Fdl2 && !(s->dev && s->dev->info().is_sprd4)) {
            f2=loader("NAND_FDL");
            if(s->stage()!=Stage::Fdl1) f1=loader("FDL");
        }
        if(s->stage()!=Stage::Fdl2 && s->dev && s->dev->info().is_sprd4) {
            auto entered=s->dev->sprd4_enter_fdl2(stop);
            if(!entered) fail("PAC SPRD4 transition"+err_detail(entered.error()));
            auto ready=finish_loader(Stage::Fdl2,stop);
            if(!ready) fail("PAC FDL2 adoption"+err_detail(ready.error()));
        }
        if(f1) {
            auto sent=s->dev->upload_fdl1(f1->first,f1->second,stop);
            if(!sent) fail("PAC FDL1 upload"+err_detail(sent.error()));
            auto ready=finish_loader(Stage::Fdl1,stop);
            if(!ready) fail("PAC FDL1 adoption"+err_detail(ready.error()));
        }
        if(f2) {
            auto sent=s->dev->upload_fdl2(f2->first,f2->second,stop);
            if(!sent) fail("PAC FDL2 upload"+err_detail(sent.error()));
            auto ready=finish_loader(Stage::Fdl2,stop);
            if(!ready) fail("PAC FDL2 adoption"+err_detail(ready.error()));
        }
    }
    // Within a PAC transaction adoption flows directly into its plan. Do not
    // call landing_summary/info/parts between the FDL2 handshake and PAC work.
    auto plan = batch
        ? (extension == ".pac"
            ? session::Operations::prepare_pac_with_options(*s->dev, *pac, pac_options,stop, display.observer())
            : extension == ".xml"
                ? session::Operations::prepare_flash(*s->dev, platform::path(part), stop, display.observer())
                : session::Operations::prepare_directory(*s->dev, platform::path(part), stop, display.observer()))
        : session::Operations::prepare_write(*s->dev, part, platform::path(file), stop, display.observer());
    if (!plan) fail(operation_error("write", plan.error()));
    s->parts_cache.clear(); // plans may repartition or change loader name routes
    if(plan->requires_recovery()) {
        fs::path directory;
        for(unsigned i=1;i<=10000;++i) {
            auto candidate=session_directory()/((pac?"pac-":"directory-nv-")+std::to_string(i));
            if(!fs::exists(candidate)) {directory=std::move(candidate);break;}
        }
        if(directory.empty()) fail("write recovery directory unavailable");
        auto saved=session::Operations::save_recovery(*s->dev,*plan,directory,stop,display.observer());
        if(!saved) fail(operation_error("write recovery",saved.error()));
        log_status(LogLevel::Info,pac?"PAC recovery":"directory NV recovery",platform::utf8_path(directory));
    }
    const double prepared = std::chrono::duration<double>(std::chrono::steady_clock::now() - preparing).count();
    auto wr = session::Operations::execute(*s->dev, *plan, stop, display.observer(),
        [] { return std::make_shared<cli::IgnoreInterrupts>(); });
    if (!wr) {
        capture_write_cancellation();
        fail(operation_error("write", wr.error()));
    }
    const bool transactions=plan->requires_recovery();
    log_status(LogLevel::Info, transactions?"completed":"written", batch ? std::to_string(wr->partitions) + (transactions?" operations":" partitions") : part,
        operation_summary(wr->bytes));
    print_operation_timing(*wr, prepared);
    if(s->dev && s->dev->session_ended()) {s->dev.reset();s->parts_cache.clear();quitting_=true;}
}

void Shell::cmd_write_rename(std::istringstream& ss, std::stop_token stop, bool physical) {
    std::string part, file;
    next_token(ss, part); next_token(ss, file);
    const std::string command=physical?"restore-raw":"write-rename";
    if(physical && file.empty()) {
        auto plan=session::RawDirectoryRestore::prepare(*sess_.dev,platform::path(part),stop);
        if(!plan) fail(operation_error(command,plan.error()));
        fs::path recovery;
        for(unsigned i=1;i<=10000;++i) {
            auto candidate=session_directory()/("restore-directory-"+std::to_string(i));
            if(!fs::exists(candidate)) {recovery=std::move(candidate);break;}
        }
        if(recovery.empty()) fail("restore-raw: recovery directory unavailable");
        auto saved=session::RawDirectoryRestore::save_recovery(*sess_.dev,*plan,recovery,stop);
        if(!saved) fail(operation_error(command,saved.error()));
        log_status(LogLevel::Info,"recovery",platform::utf8_path(recovery));
        info("restore-raw: all originals saved; Ctrl+C stops after the current partition is restored; GPT GUIDs/attributes may change");
        cli::DeferForcedExit defer_exit;
        cli::OperationDisplay display(true);
        sess_.parts_cache.clear();
        auto result=session::RawDirectoryRestore::execute(*sess_.dev,*plan,stop,display.observer());
        sess_.parts_cache.clear();
        if(!result) fail(operation_error(command,result.error()));
        log_status(LogLevel::Info,"physically restored",std::to_string(plan->count())+" partitions",operation_summary(*result));
        return;
    }
    auto prepared = physical ? session::RenameWrite::prepare_raw(*sess_.dev,part,platform::path(file),stop)
        : session::RenameWrite::prepare(*sess_.dev, part, platform::path(file), stop);
    if (!prepared) fail(operation_error(command, prepared.error()));
    const auto root = session_directory();
    fs::path directory;
    for (unsigned i=1; i<=10000; ++i) {
        auto candidate = root / ((physical?"restore-raw-":"rename-write-") + std::to_string(i));
        std::error_code ec;
        if (fs::create_directory(candidate, ec)) { directory = std::move(candidate); break; }
        if (ec && ec != std::errc::file_exists) fail(command+": recovery directory: " + ec.message());
    }
    if (directory.empty()) fail(command+": cannot create recovery directory");
    auto saved = physical ? session::RenameWrite::save_raw_recovery(*sess_.dev,*prepared,directory,stop)
        : session::RenameWrite::save_recovery(*prepared, directory);
    if (!saved) fail(operation_error(command, saved.error()));
    log_status(LogLevel::Info, "recovery layout", platform::utf8_path(directory / "restore-layout.xml"));
    info(command+": rebuilds GPT metadata; original names and geometry will be restored, GUIDs/attributes may change");
    sess_.parts_cache.clear();
    // A second Ctrl+C must not terminate the process between rename and
    // restoration. Preparation remains cancellable; transaction is bounded by
    // transport timeouts and reports recovery inputs on any unconfirmed result.
    cli::IgnoreInterrupts ignore_interrupts;
    info(command+": Ctrl+C disabled during rename/write/restore");
    cli::CommandInputEcho command_echo(true);
    auto result = session::RenameWrite::execute(*sess_.dev, *prepared, stop);
    sess_.parts_cache.clear();
    if (!result) {
        warn("recovery layout: " + platform::utf8_path(directory / "restore-layout.xml"));
        fail(operation_error(command, result.error()));
    }
    log_status(LogLevel::Info, physical?"physically restored":"written", part, operation_summary(*result));
}

void Shell::print_operation_timing(const session::OperationReport& report, double prepare_seconds) const {
    if (!log_performance_enabled()) return;
    const double total = std::chrono::duration<double>(std::chrono::steady_clock::now() - command_started_).count();
    const double overhead = std::max(0.0, total - prepare_seconds - report.validate_seconds -
        report.erase_seconds - report.write_seconds - report.verify_seconds);
    char text[512];
    std::snprintf(text, sizeof text,
        "host=%.2f s, prepare=%.2f s, revalidate=%.2f s, erase=%.2f s, open=%.2f s, transfer=%.2f s, sync=%.2f s, verify=%.2f s, total=%.2f s",
        overhead, prepare_seconds, report.validate_seconds, report.erase_seconds, report.open_seconds,
        report.transfer_seconds, report.sync_seconds, report.verify_seconds, total);
    log_diag(std::string("{timing} ") + text);
    std::snprintf(text, sizeof text, "source=%.3f s, encode=%.3f s, send=%.3f s, ACK=%.3f s",
        report.source_seconds, report.encode_seconds, report.send_seconds, report.ack_seconds);
    log_diag(std::string("{timing} ") + text);
    std::snprintf(text, sizeof text, "speed: transfer=%.2f MiB/s end-to-end=%.2f MiB/s",
        report.transfer_seconds > 0 ? report.bytes / 1048576.0 / report.transfer_seconds : 0,
        total > 0 ? report.bytes / 1048576.0 / total : 0);
    log_diag(std::string("{timing} ") + text);
    std::snprintf(text, sizeof text, "ACK waits >=100 ms: count=%llu total=%.3f s max=%.3f s",
        static_cast<unsigned long long>(report.slow_ack_count), report.slow_ack_seconds, report.max_ack_seconds);
    log_diag(std::string("{timing} ") + text);
}

std::string Shell::operation_summary(uint64_t bytes) const {
    const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - command_started_).count();
    return format_transfer(bytes, elapsed);
}

void Shell::cmd_erase(std::istringstream& ss, std::stop_token stop) {
    auto* s = &sess_;
    std::string part;
    next_token(ss, part);
    if (part.empty()) fail("erase <part>");
    auto parts = s->dev->list_partitions(stop, false);
    if (!parts) {
        if (parts.error() != std::errc::not_supported || s->dev->link_dead() || s->dev->link_silent() || stop.stop_requested())
            fail("erase: cannot list partitions" + err_detail(parts.error()));
        warn("erase: enumeration unavailable; target will be checked by the loader");
    } else {
        auto partition = session::Operations::find_partition(*parts, part);
        if (!partition) fail(operation_error("erase", partition.error()));
    }
    if (stop.stop_requested()) fail("operation cancelled before erase");
    if (part == "userdata") {
        std::istringstream recovery("recovery-wipe");
        cmd_reboot(recovery, stop, false);
        return;
    }
    cli::IgnoreInterrupts ignore_interrupts;
    log_status(LogLevel::Info, "erase", part, "Ctrl+C disabled during erase");
    auto r = s->dev->erase_partition(part, 0);
    if (!r) {
        fail("erase: " + part + err_detail(r.error()) +
            (s->dev->link_dead() || s->dev->link_silent() ? "; erase result unknown" : ""));
    }
    log_status(LogLevel::Info, "erased", part);
}

void Shell::cmd_dump(std::istringstream& ss, std::stop_token stop) {
    auto* s = &sess_;
    std::string outdir;
    next_token(ss, outdir);
    if (outdir.empty()) outdir = platform::utf8_path(session_directory() / "dump");
    const auto directory = platform::path(outdir);
    fs::create_directories(directory);
    if (!fs::is_empty(directory)) fail("read all: output directory must be empty; use a new backup directory");
    info("read all: reading GPT layout");
    auto plan = [&] {
        WaitProgress waiting("reading and validating GPT");
        return session::RawBackup::discover(*s->dev, stop);
    }();
    if (!plan) fail(operation_error("read all", plan.error()));
    const auto* parts = &plan->entries();
    if (!plan->limitation().empty()) warn(plan->limitation());
    log_status(LogLevel::Info, "read all", std::to_string(parts->size()) + " partitions");
    log_status(LogLevel::Info, "output", platform::utf8_path(directory.lexically_normal()));
    OpTimer tm_dump;
    auto bundle = session::BackupBundle::create(directory, *plan,
        {std::string(stage_name(s->stage())), s->dev->info().chip.version, hex(s->dev->info().chip.chip_type)});
    if (!bundle) fail(operation_error("read all", bundle.error()));
    auto& records = bundle->records();
    uint64_t total_bytes = 0;
    size_t ok_count = 0;
    const auto manifest = [&](bool complete) {
        auto saved = bundle->checkpoint(*plan, complete);
        if (!saved) fail(operation_error("read all manifest", saved.error()));
    };
    for (size_t i = 0; i < parts->size(); ++i) {
        const auto& p = (*parts)[i];
        auto& record = records[i];
        const std::string item = std::to_string(i + 1) + "/" + std::to_string(parts->size()) + " " + p.name;
        if (record.status == "unavailable") {
            log_status(LogLevel::Warn, "unavailable", item, record.reason);
            continue;
        }
        log_progress("read all: " + item + " (" + format_size(p.size) + ")");
        OpTimer tm_part;
        std::optional<session::OperationError> failure;
        try {
            if (stop.stop_requested()) throw std::runtime_error("cancelled");
            auto saved = session::RawBackup::save(*s->dev, *plan, i,
                directory / platform::path(record.file), stop);
            if (!saved) {
                failure = saved.error();
                if (saved.error().commit_state == io::CommitState::Replaced) {
                    record.status = "durability_unconfirmed";
                    record.actual = saved.error().actual_bytes;
                }
                throw std::runtime_error(saved.error().target + err_detail(saved.error().code));
            }
            record.actual = *saved;
            record.status = "saved";
            ++ok_count;
            total_bytes += *saved;
            log_status(LogLevel::Info, "saved", item, tm_part.format(*saved));
        } catch (const std::exception& error) {
            if (!failure) failure = session::device_exception_error(*s->dev, session::OperationStep::Read);
            if (record.status != "durability_unconfirmed")
                record.status = stop.stop_requested() ? "cancelled" : "failed";
            record.reason = stop.stop_requested() ? "cancelled by user" : operation_error("read all", *failure);
            for (size_t j = i + 1; j < records.size(); ++j)
                if (records[j].status == "pending") records[j].status = "not_attempted";
            auto reported = cli::detail::record_backup_failure(std::move(*failure), [&] {
                return bundle->checkpoint(*plan, false);
            });
            if (reported.target.empty()) reported.target = error.what();
            fail(operation_error("read all", reported));
        }
        manifest(false);
    }
    if (stop.stop_requested()) fail("read all: cancelled");
    const bool complete = ok_count == parts->size() && plan->limitation().empty();
    manifest(complete);
    if (!complete) fail("read all incomplete: " + std::to_string(ok_count) + " partitions saved; see manifest.json for unavailable areas");
    log_status(LogLevel::Info, "read all complete", std::to_string(ok_count) + " partitions", tm_dump.format(total_bytes));
}

void Shell::cmd_firstmode(std::istringstream& ss, std::stop_token stop) {
    auto* s = &sess_;
    std::string arg, extra;
    next_token(ss, arg);
    next_token(ss, extra);
    auto mode = parse_unsigned(arg);
    if (!mode || *mode > 0xff || !extra.empty()) {
        fail("firstmode: expected a byte value (0..255)");
    }
    auto r = s->dev->set_first_mode(*mode, stop);
    if (!r) fail("firstmode failed" + err_detail(r.error()));
    log_status(LogLevel::Info, "firstmode written", hex(*mode));
}

void Shell::cmd_enable_write(std::stop_token stop) {
    auto* s = &sess_;
    auto r = s->dev->enable_write_flash(stop);
    if (!r) fail("enable-write failed" + err_detail(r.error()));
    info("enable-write: acknowledged");
}

void Shell::cmd_repartition(std::istringstream& ss, std::stop_token stop) {
    auto* s = &sess_;
    std::string xml, extra;
    next_token(ss, xml); next_token(ss, extra);
    if (xml.empty() || !extra.empty()) {
        fail("usage: repartition <rom.xml>");
    }
    auto img = session::PacParser::parse_xml(platform::path(xml));
    if (!img) fail("cannot parse " + xml + err_detail(img.error()));
    auto table = session::PacParser::build_repartition_table(*img);
    if (!table) fail("invalid repartition layout in " + xml + err_detail(table.error()));

    log_status(LogLevel::Info, "repartition", std::to_string(img->partitions.size()) + " entries");
    const LogColumn columns[]{{"Name"}, {"Size", LogAlignment::Right}, {"Bytes", LogAlignment::Right}};
    LogTableSection listing;
    for (const auto& p : img->partitions)
        listing.rows.push_back({p.name, format_size(p.size), std::to_string(p.size)});
    log_table(columns, std::span(&listing, 1));

    // A timeout may follow a partially written GPT. Never retain the old
    // cached layout across an attempted repartition, regardless of result.
    s->parts_cache.clear();
    auto r = s->dev->repartition(*table, stop, img->legacy_gpt, img->sector_size, img->disk_size);
    if (!r) {
        fail("repartition not confirmed" + err_detail(r.error()));
    }
    log_status(LogLevel::Info, "repartition acknowledged", img->nand ? "UBI volume table" : "GPT");
}

void Shell::cmd_reboot(std::istringstream& ss, std::stop_token stop, bool restart) {
    auto* s = &sess_;
    std::string target_name;
    next_token(ss, target_name);
    if (!target_name.empty()) {
        const auto* target = session::find_reboot_target(target_name);
        if (!target) fail("reboot: unknown target '" + target_name + "'");
        const bool wipe = target->target == session::RebootTarget::RecoveryWipe;
        if (wipe)
            info(restart?"erase: userdata, rebooting to Recovery for on-device data wipe confirmation":
                "erase: userdata, storing Recovery wipe request for the next boot");
        auto result = restart?session::reboot_to(*s->dev, target->target, stop):
            session::request_boot_target(*s->dev,target->target,stop);
        if (!result) {
            const auto& error = result.error();
            std::string action;
            using enum session::RebootStep;
            switch (error.step) {
            case FirstModeRead: action = "firstmode read failed"; break;
            case FirstModeConflict: action = "conflicting firstmode " + hex(error.first_mode); break;
            case MiscRead: action = "misc read failed"; break;
            case BuildMessage: action = "invalid misc BCB block"; break;
            case MiscWrite: action = "misc BCB write not confirmed"; break;
            case MiscVerify: action = "misc BCB readback verification failed"; break;
            case Reset: action = "reset not confirmed; verified BCB request remains stored"; break;
            }
            if (error.message_may_be_written())
                warn("BCB may affect the next boot");
            if (error.step == Reset || s->dev->link_dead() || s->dev->link_silent()) {
                s->dev.reset();
                s->parts_cache.clear();
            }
            fail((wipe ? std::string("erase userdata") : "reboot " + target_name) +
                 ": " + action + err_detail(error.reason));
        }
        if(restart)s->dev.reset();
        s->parts_cache.clear();
        if (wipe)
            info("Recovery wipe requested; confirm on the device.");
        else log_status(LogLevel::Info, "reboot requested", target_name);
        quitting_ = restart;
        return;
    }
    auto r = s->dev->reset(stop);
    s->dev.reset();
    s->parts_cache.clear();
    if (!r) fail("device reboot failed" + err_detail(r.error()));
    // The device leaves download mode by design (boots the normal
    // system) — it does NOT come back on its own, so waiting or an
    // offline prompt would only invite a dead `connect`. A successful
    // session-end operation exits the shell cleanly.
    info("reboot: requested");
    quitting_ = true;
}

void Shell::cmd_poweroff(std::stop_token stop) {
    auto* s = &sess_;
    auto r = s->dev->power_down(stop);
    if (r) {
        // dl_powerdown_device: ACK -> udelay(200) ->
        // while(charger_connected()); -> power_down. With the cable
        // still in, the device PARKS in that loop by design — the
        // power-off only completes when the cable is unplugged.
        s->dev.reset();
        s->parts_cache.clear();
        info("poweroff: requested, unplug cable to complete");
        quitting_ = true;
    } else {
        fail("device poweroff failed" + err_detail(r.error()));
    }
}

void Shell::cmd_pc_mode(std::istringstream& ss, std::stop_token stop) {
    auto* s = &sess_;
    const auto fail = [this](const std::string& message) { this->fail("pc-mode: " + message); };
    std::string m, extra;
    next_token(ss, m);
    next_token(ss, extra);
    if (m.empty() || !extra.empty()) {
        fail("usage: pc-mode <mode> (1..0x3f; frequency fixed to 0)");
    }
    auto parsed_mode = protocol::parse_pc_mode(m);
    if (!parsed_mode) {
        fail("invalid mode '" + m + "' (expected decimal or hexadecimal 1..0x3f)");
    }
    const uint8_t mode = *parsed_mode;
    const auto encoded = protocol::BslCodec::encode_pctool_mode(mode);
    if (!encoded) fail("encode failed" + err_detail(encoded.error()));
    const auto& frame = *encoded;

    // Single-device operation; the state-changing request is sent only once.
    log_status(LogLevel::Info, "pc-mode", "waiting for device");
    auto& ctx = transport::UsbContext::instance();
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(120);
    std::optional<transport::UsbTransport> gadget;
    std::vector<uint8_t> gadget_identity;
    std::map<std::string, std::chrono::steady_clock::time_point> retry_after;
    while (std::chrono::steady_clock::now() < deadline) {
        if (stop.stop_requested()) fail("interrupted");
        auto devs = scan_devices();
        if (devs.size() > 1)
            fail("multiple matching interfaces found; only one device is supported");
        bool unknown_identity = false;
        for (size_t i = 0; i < devs.size(); ++i) {
            auto& d = devs[i];
            if (!gadget) {
                if (mode == protocol::PC_MODE_AUTO_DOWNLOAD && d.port_path.empty()) {
                    unknown_identity = true;
                    continue;
                }
                const auto key = poll_key(d);
                if (std::chrono::steady_clock::now() < retry_after[key]) continue;
                auto opened = ctx.open_device(d, profile_.reset_usb_configuration, profile_.split_usb_packet);
                if (opened) {
                    gadget.emplace(std::move(opened.value()));
                    gadget_identity = d.port_path;
                } else retry_after[key] = std::chrono::steady_clock::now() + std::chrono::seconds(2);
            }
        }
        if (gadget) break;
        if (unknown_identity) {
            fail("physical identity unavailable; cannot safely reconnect after auto-download");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    if (!gadget) {
        fail("device did not become available within 120s");
    }

    // f_serial.c gser_setup: the gadget only reads after DTR opens the
    // port; echo means receipt, before any mode-specific action executes.
    if (auto dtr = gadget->serial_dtr(); !dtr) {
        fail("USB gadget DTR signal failed" + err_detail(dtr.error()));
    }
    // Do not resend a state-changing request: it may already have been
    // accepted, particularly if the device now awaits PROGRAM_KEY.
    if (auto sent = gadget->bulk_write(frame, std::chrono::seconds(1), stop); !sent) {
        fail("mode request write failed" + err_detail(sent.error()));
    }
    std::vector<uint8_t> echoed;
    const auto echo_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (echoed.size() < frame.size() && std::chrono::steady_clock::now() < echo_deadline) {
        const auto remaining = std::max(std::chrono::milliseconds(1),
            std::chrono::duration_cast<std::chrono::milliseconds>(
                echo_deadline - std::chrono::steady_clock::now()));
        auto part = gadget->bulk_read(64, remaining, stop);
        if (!part) {
            fail("mode request echo missing; outcome unknown" + err_detail(part.error()));
        }
        echoed.insert(echoed.end(), part->begin(), part->end());
    }
    if (echoed != frame) {
        fail("mode request echo mismatch; outcome unknown");
    }
    log_status(LogLevel::Info, "pc-mode request received", hex(mode));

    if (mode == protocol::PC_MODE_PROGRAMKEY) {
        // With CONFIG_SECURE_BOOT/CONFIG_SECBOOT disabled the BSP skips
        // both programming and its CNF and immediately waits for EXIT.
        // Even a success CNF only reports the backend's return value.
        info("PROGRAMKEY requested (firmware-dependent; may irreversibly program eFuse)");
        const auto prog = protocol::BslCodec::encode_pctool_programkey();
        if (auto w = gadget->bulk_write(prog,
                                        std::chrono::seconds(2), stop); !w) {
            fail("programkey write failed; outcome unknown" + err_detail(w.error()));
        }
        std::vector<uint8_t> pending;
        const auto confirmation = [&](uint32_t sequence, std::chrono::seconds timeout)
                -> std::expected<protocol::PcToolConfirmation, std::errc> {
            const auto until = std::chrono::steady_clock::now() + timeout;
            while (!stop.stop_requested()) {
                while (!pending.empty()) {
                    auto first = std::find(pending.begin(), pending.end(), uint8_t{0x7e});
                    pending.erase(pending.begin(), first);
                    if (pending.empty()) break;
                    auto last = std::find(pending.begin() + 1, pending.end(), uint8_t{0x7e});
                    if (last == pending.end()) {
                        if (pending.size() > 26)
                            return std::unexpected(std::errc::bad_message);
                        break;
                    }
                    const size_t length = static_cast<size_t>(last - pending.begin()) + 1;
                    auto reply = protocol::decode_pctool_confirmation(
                        std::span<const uint8_t>(pending.data(), length));
                    pending.erase(pending.begin(), pending.begin() + length);
                    if (!reply) return std::unexpected(reply.error());
                    if (reply->sequence == sequence) return reply;
                    // A late PROGRAM_KEY CNF is not an EXIT CNF.
                }
                const auto now = std::chrono::steady_clock::now();
                if (now >= until) return std::unexpected(std::errc::timed_out);
                auto bytes = gadget->bulk_read(64, std::max(std::chrono::milliseconds(1),
                    std::chrono::duration_cast<std::chrono::milliseconds>(until - now)), stop);
                if (!bytes) return std::unexpected(bytes.error());
                pending.insert(pending.end(), bytes->begin(), bytes->end());
            }
            return std::unexpected(std::errc::interrupted);
        };
        auto cnf = confirmation(0, std::chrono::seconds(20));
        std::string program_error;
        if (!cnf) {
            program_error = "PROGRAMKEY result unknown (confirmation absent or invalid)" + err_detail(cnf.error());
        } else if (cnf->status == 0) {
            info("PROGRAMKEY: firmware reported success; eFuse state not independently verified");
        } else {
            program_error = "PROGRAMKEY: firmware reported status " + hex(cnf->status) +
                            "; eFuse state unknown";
        }

        // Send EXIT even after an absent/failed CNF: the non-secure build
        // is already waiting for it. Sequence 1 distinguishes the reply
        // from a delayed sequence-0 program confirmation.
        const auto exit =
            protocol::BslCodec::encode_pctool_programkey_exit(0xffff, 1);
        auto sent = gadget->bulk_write(exit, std::chrono::seconds(2), stop);
        if (!sent) fail("programkey exit write failed" + err_detail(sent.error()));
        info("PROGRAMKEY exit request sent (0xffff: power-down)");
        auto exited = confirmation(1, std::chrono::seconds(2));
        if (!exited) {
            fail("programkey exit unconfirmed" + err_detail(exited.error()));
        } else if (exited->status != 0) {
            fail("programkey exit status " + hex(exited->status));
        } else {
            info("PROGRAMKEY exit acknowledged (power-down requested)");
        }
        if (!program_error.empty()) fail(program_error);
        return;
    }

    gadget.reset();

    if (mode != protocol::PC_MODE_AUTO_DOWNLOAD) {
        info(mode == protocol::PC_MODE_AUTOTEST
            ? "autotest requested (boot partition); boot completion not observed"
            : "calibration requested (mode " + hex(mode) +
              ", frequency 0); boot/recovery selection is firmware-dependent");
        return;
    }

    // CMD_AUTODLOADER_REBOOT may enter SPRD4 directly or erase both SPL
    // partitions and reset to bootrom (CONFIG_ERASE_SPL_AUTO_DOWNLOAD).
    info("pc-mode: auto-download requested, waiting for device");
    if (gadget_identity.empty()) fail("physical identity unavailable for reconnect");
    deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    retry_after.clear();
    while (std::chrono::steady_clock::now() < deadline) {
        if (stop.stop_requested()) fail("interrupted");
        auto devs = scan_devices();
        for (auto& d : devs) {
            if (d.port_path.empty() || d.port_path != gadget_identity) continue;
            const auto key = poll_key(d);
            if (std::chrono::steady_clock::now() < retry_after[key]) continue;
            std::optional<device::SprdDevice> taken;
            auto opened = open_and_handshake(d, stop, profile_);
            if (opened) taken.emplace(std::move(opened.value()));
            if (taken) {
                s->dev = std::move(taken.value());
                s->port_path = d.port_path;
                log_status(LogLevel::Info, "connected", stage_name(s->stage()),
                    s->dev->info().chip.version.empty() ? "" : "handshake " + s->dev->info().chip.version);
                return;
            }
            retry_after[key] = std::chrono::steady_clock::now() + std::chrono::seconds(2);
            // Handshake failed: not a responding download endpoint yet.
            // until the deadline.
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
    fail("no responding download device within 30s (BootROM or SPRD4)");
}
void Shell::cmd_ddrtest(std::istringstream& ss, std::stop_token stop) {
    auto* s = &sess_;
    std::string arg;
    next_token(ss, arg);
    if (arg.empty()) {
        auto r = s->dev->ddr_verify(stop);
        if (!r) fail("ddrtest failed" + err_detail(r.error()));
        if (!*r) fail("DDR verify FAIL (0xB6)");
        info("ddrtest: passed");
        return;
    }
    if (arg != "sr") fail("usage: ddrtest [sr <ms>]");
    uint32_t ms = 30000;
    std::string duration;
    if (next_token(ss, duration)) ms = load_address(duration);
    auto r = s->dev->ddr_sr_test(ms, stop);
    if (!r) fail("ddrtest sr failed" + err_detail(r.error()));
    if (!*r) fail("DDR SR test FAIL (0xB7)");
    info("ddrtest: self-refresh passed");
}

cli::CommandResult Shell::exec(const std::string& line, std::stop_token stop) {
    command_started_ = std::chrono::steady_clock::now();
    last_result_ = {};
    cancellation_detail_.clear();
    try {
        if (cli::termination_requested() || stop.stop_requested()) fail("operation cancelled");
        exec_checked(line, stop);
        if (sess_.dev && (sess_.dev->link_dead() || sess_.dev->link_silent()))
            fail("device stopped answering");
        if (cli::termination_requested() || stop.stop_requested()) fail("operation cancelled");
    } catch (const cli::CommandFailure& error) {
        last_result_ = {cli::CommandStatus::Failed, error.message};
    } catch (const std::exception& error) {
        last_result_ = {cli::CommandStatus::Failed, std::string("command failed: ") + error.what()};
    } catch (...) {
        last_result_ = {cli::CommandStatus::Failed, "command failed: unknown exception"};
    }
    if (cli::termination_requested()) last_result_.status = cli::CommandStatus::Terminated;
    else if (stop.stop_requested() || cli::global_interrupted()) last_result_.status = cli::CommandStatus::Cancelled;
    if (!last_result_.succeeded() && sess_.dev &&
        (sess_.dev->link_dead() || sess_.dev->link_silent() || sess_.stage() == Stage::Offline)) {
        sess_.dev.reset();
        sess_.parts_cache.clear();
    }
    log_clear_progress_line();
    if (last_result_.status == cli::CommandStatus::Cancelled) {
        warn((cancellation_detail_.empty() ? std::string("cancelled") : cancellation_detail_) +
            (sess_.dev ? "; " + std::string(stage_name(sess_.stage())) + " connection retained" : "; offline"));
    } else if (!last_result_.succeeded()) uniflash::log_err(last_result_.message);
    return last_result_;
}

void Shell::exec_checked(const std::string& line, std::stop_token stop, bool validate_only) {
    std::istringstream ss(line);
    std::string cmd;
    ss >> cmd;
    if (cmd.empty() || cmd[0] == '#') return;

    const auto* command = cli::find_command(cmd);
    if (!command) {
        fail("unknown command '" + cmd + "' (try 'help')");
    }
    const auto args = cli::detail::arguments(line);
    const auto count = args.size() - 1;
    using Id = cli::CommandId;
    size_t minimum = 0, maximum = 0;
    switch (command->id) {
    case Id::Info: case Id::Connect: case Id::Dump: case Id::Reboot: maximum = 1; break;
    case Id::LoadFdl1: case Id::Download: minimum = maximum = 2; break;
    case Id::LoadFdl2:
        minimum = maximum = sess_.dev && sess_.dev->info().is_sprd4 ? 0 : 2; break;
    case Id::LoadFdl:
        minimum = maximum = sess_.dev && sess_.dev->info().is_sprd4 ? 0 : 4; break;
    case Id::LoadBin: minimum = 2; maximum = 3; break;
    case Id::Exec: case Id::Erase: case Id::Repartition:
    case Id::FirstMode: minimum = maximum = 1; break;
    case Id::PcMode: minimum = maximum = 1; break;
    case Id::Read: minimum = 1; maximum = 3; break;
    case Id::Write: minimum = 1; maximum = 2; break;
    case Id::WriteRename: minimum = maximum = 2; break;
    case Id::RestoreRaw: minimum = 1; maximum = 2; break;
    case Id::DecryptImage: minimum = 4; maximum = 5; break;
    case Id::UnpackImage: minimum = maximum = 4; break;
    case Id::DdrTest: maximum = 2; break;
    default: break;
    }
    if (count < minimum || count > maximum) {
        fail("usage: " + std::string(command->name) + " " + std::string(command->arguments));
    }
    for (size_t i = 1; i < args.size(); ++i)
        if (args[i].empty()) fail("empty argument");
    const auto address = [&](size_t index) {
        (void)cli::detail::unsigned_number(args.at(index), UINT32_MAX);
    };
    switch (command->id) {
    case Id::DecryptImage:
        if(!io::valid_sha256(args[4])) fail("decrypt-image: expected a lowercase 64-digit plaintext SHA-256");
        if(count==5 && args[5]!="r27" && args[5]!="sprd128" && args[5]!="sprd256" &&
            args[5]!="sprd128-signed" && args[5]!="sprd256-signed") fail("decrypt-image: unknown explicit format");
        break;
    case Id::UnpackImage:
        if(!io::valid_sha256(args[4])) fail("unpack-image: expected a lowercase 64-digit output SHA-256");
        if(args[3]!="sci1" && args[3]!="sprd-sci1" && args[3]!="sansa-view") fail("unpack-image: unknown explicit format");
        break;
    case Id::Info:
        if (count && args[1] != "diagnostic" && args[1] != "miscdata") fail("usage: info [diagnostic|miscdata]");
        if (count && args[1] == "miscdata" && sess_.stage() != Stage::Fdl2)
            fail("info miscdata: requires FDL2");
        break;
    case Id::LoadFdl1: case Id::LoadFdl2: case Id::Download: case Id::LoadBin:
        if (count >= 2) address(2);
        if (count == 3) address(3);
        break;
    case Id::LoadFdl: if (count) { address(2); address(4); } break;
    case Id::Exec: address(1); break;
    case Id::Read:
        if (args[1] == "all" && count > 2) fail("usage: read all [dir]");
        if (count == 3 && cli::detail::unsigned_number(args[3], UINT32_MAX) == 0)
            throw std::invalid_argument("read size must be positive");
        break;
    case Id::DdrTest:
        if (count && args[1] != "sr") throw std::invalid_argument("expected ddrtest [sr [ms]]");
        if (count == 2) address(2);
        break;
    case Id::FirstMode: {
        (void)cli::detail::unsigned_number(args[1], 255);
        break;
    }
    default: break;
    }
    auto write_extension=count?platform::utf8_path(platform::path(args[1]).extension()):std::string{};
    for(auto& c:write_extension)if(c>='A'&&c<='Z')c+=32;
    if (command->id == Id::Read || (command->id == Id::Write && count == 2 && write_extension!=".pac") ||
        command->id == Id::WriteRename || (command->id == Id::RestoreRaw && count==2) || command->id == Id::Erase)
        if (!cli::detail::safe_partition_name(args[1]))
            throw std::invalid_argument("invalid partition name");
    // Feed the legacy token reader canonical whitespace/quotes so the strict
    // validation and dispatch consume exactly the same arguments.
    {
        std::string canonical;
        for (size_t i = 1; i < args.size(); ++i) {
            canonical += cli::quote_argument(args[i]); canonical += ' ';
        }
        ss.clear();
        ss.str(canonical);
    }
    // Reject malformed targets before any device I/O.
    // No target is allowed to fall back silently to a normal reset.
    if (command->id == cli::CommandId::Reboot) {
        if (count && !session::find_reboot_target(args[1])) {
            fail("reboot: expected no target or recovery/sideload/sideload-auto-reboot/rescue/fastbootd");
        }
    }
    const auto current = cli::command_stage(
        sess_.stage(), sess_.dev && sess_.dev->info().is_sprd4);
    auto package_extension = count>=1 ? platform::utf8_path(platform::path(args[1]).extension()) : std::string{};
    for (auto& c : package_extension) if(c>='A' && c<='Z') c+=32;
    const bool pac_command = command->id==Id::Write && package_extension==".pac";
    const bool pac_load = pac_command &&
        sess_.dev && (sess_.stage()==Stage::BootRom || sess_.stage()==Stage::Memory || sess_.stage()==Stage::Fdl1);
    if (!cli::command_allowed(*command, current) && !pac_load) {
        fail(cmd + ": unavailable at " +
            std::string(cli::command_stage_name(current)));
    }

    if (cli::termination_requested() || stop.stop_requested()) {
        fail("operation cancelled");
    }
    if (validate_only) return;
    if (command->id == Id::Write)
        log_status(LogLevel::Info, "write", args[1]);

    const auto previous_stage = sess_.stage();
    // Gate every entry point before file access or USB I/O. Capability
    // differences within FDL2 are handled by the device reply, not here.
    using cli::CommandId;
    switch (command->id) {
    case CommandId::Help: cmd_help(); break;
    case CommandId::DecryptImage: {
        const std::string format=count==5?args[5]:"r27";
        const bool r27=format=="r27";
        const size_t key_size=r27?36:format.starts_with("sprd128")?16:32;
        const auto input=platform::path(args[1]),output=platform::path(args[2]),key_path=platform::path(args[3]);
        std::error_code ec;
        if(fs::exists(output,ec)) {
            if(ec) fail("decrypt-image: output path: "+ec.message());
            if(fs::equivalent(input,output) || fs::equivalent(key_path,output)) fail("decrypt-image: output must differ from input and key file");
        } else if(ec) fail("decrypt-image: output path: "+ec.message());
        auto source=io::Image::prepare_blob(input,UINT64_MAX,stop);
        if(!source) fail("decrypt-image: source"+err_detail(source.error()));
        std::array<uint8_t,36> descriptor{};
        struct ClearKey {
            std::array<uint8_t,36>& bytes;
            ~ClearKey() { volatile uint8_t* p=bytes.data();for(size_t i=0;i<bytes.size();++i) p[i]=0; }
        } clear_key{descriptor};
        // Read this small key once into memory, not through the image snapshot
        // layer, which can create an unnecessary private temporary disk copy.
        std::ifstream key_file(key_path,std::ios::binary);
        if(!key_file.read(reinterpret_cast<char*>(descriptor.data()),key_size) ||
            key_file.peek()!=std::char_traits<char>::eof() || key_file.bad())
            fail(r27?"decrypt-image: key file must be LE32(32) followed by 32 key bytes":
                "decrypt-image: expected exactly "+std::to_string(key_size)+" raw key bytes for "+format);
        key_file.close();
        cli::OperationDisplay display;
        const auto observer=display.observer();
        const io::PrepareObserver progress=[&](const io::PrepareProgress& event) {
            observer({session::OperationStep::Prepare,"decrypt-image",event.completed,event.total,"decrypt/hash"});
        };
        auto result=r27?io::decrypt_r27_image(*source,descriptor,output,args[4],stop,progress):
            io::decrypt_sprd_payload(*source,std::span(descriptor).first(key_size),
                format.ends_with("-signed")?io::SprdCipherEnvelope::SignedPayload:io::SprdCipherEnvelope::UnsignedPayload,
                output,args[4],stop,progress);
        // Never write key material to history, logs or diagnostics.
        if(!result) fail("decrypt-image: decryption/digest/commit failed"+err_detail(result.error().code)+
            (result.error().state==io::CommitState::Replaced?"; output replaced, durability unconfirmed":""));
        log_status(LogLevel::Info,"decrypted",platform::utf8_path(output),format_size(*result));
        break;
    }
    case CommandId::UnpackImage: {
        const auto input=platform::path(args[1]),output=platform::path(args[2]);
        std::error_code ec;
        const bool exists=fs::exists(output,ec);
        if(ec) fail("unpack-image: output path: "+ec.message());
        if(exists && fs::equivalent(input,output)) fail("unpack-image: output must differ from input");
        auto source=io::Image::prepare_blob(input,UINT64_MAX,stop);
        if(!source) fail("unpack-image: source"+err_detail(source.error()));
        const auto format=args[3]=="sci1"?session::PackedImageFormat::Sci1:
            args[3]=="sprd-sci1"?session::PackedImageFormat::SprdSignedSci1:session::PackedImageFormat::SansaVerificationView;
        cli::OperationDisplay display;const auto observer=display.observer();
        auto result=session::unpack_image(*source,format,output,args[4],stop,[&](const io::PrepareProgress& event) {
            observer({session::OperationStep::Prepare,"unpack-image",event.completed,event.total,"unpack/hash"});
        });
        if(!result) fail("unpack-image: structure/digest/commit failed"+err_detail(result.error().code)+
            (result.error().state==io::CommitState::Replaced?"; output replaced, durability unconfirmed":""));
        log_status(LogLevel::Info,args[3]=="sansa-view"?"verification view saved":"modem payload extracted",
            platform::utf8_path(output),format_size(*result));
        break;
    }
    case CommandId::Bus: cmd_ls(); break;
    case CommandId::Connect: cmd_connect(ss, stop); break;
    case CommandId::Quit: quitting_ = true; break;
    case CommandId::Info:
        if (count && args[1] == "miscdata") cmd_miscdata(stop);
        else cmd_info(count != 0, stop);
        break;
    case CommandId::LoadFdl1: cmd_load_fdl1(ss, stop); break;
    case CommandId::LoadFdl2: cmd_load_fdl2(ss, stop); break;
    case CommandId::LoadFdl: cmd_load_fdl(ss, stop); break;
    case CommandId::Download: cmd_download(ss, stop); break;
    case CommandId::LoadBin: cmd_load_bin(ss, stop); break;
    case CommandId::Exec: cmd_exec(ss, stop); break;
    case CommandId::DdrTest: cmd_ddrtest(ss, stop); break;
    case CommandId::PcMode: cmd_pc_mode(ss, stop); break;
    case CommandId::Parts: cmd_parts(stop, true); break;
    case CommandId::Read: cmd_read(ss, stop); break;
    case CommandId::Write: cmd_write(ss, stop); break;
    case CommandId::WriteRename: cmd_write_rename(ss, stop); break;
    case CommandId::RestoreRaw: cmd_write_rename(ss, stop, true); break;
    case CommandId::Erase: cmd_erase(ss, stop); break;
    case CommandId::Dump: cmd_dump(ss, stop); break;
    case CommandId::Repartition: cmd_repartition(ss, stop); break;
    case CommandId::FirstMode: cmd_firstmode(ss, stop); break;
    case CommandId::EnableWrite: cmd_enable_write(stop); break;
    case CommandId::Reboot: cmd_reboot(ss, stop); break;
    case CommandId::PowerOff: cmd_poweroff(stop); break;
    }
    // PAC owns its loader adoption and recovery directory. Optional discovery
    // and presentation must not add info/parts requests after this transaction.
    if (!pac_command && command->id!=Id::DecryptImage && command->id!=Id::UnpackImage) landing_summary(previous_stage, stop);
}

static std::vector<std::string>
shell_completer(const std::vector<std::string>&,
                const Slot& sess,
                 const std::string& line, size_t cursor) {
    std::vector<std::string> out;
    if (cursor != line.size()) return out;
    size_t pos = line.find(' ');
    if (pos == std::string::npos) {
        for (const auto& command : cli::commands)
            if (!command.hidden && command.name.starts_with(line)) out.emplace_back(command.name);
        return out;
    }
    std::string head = line.substr(0, pos);
    std::string tail = line.substr(pos + 1);
    const auto* selected = cli::find_command(head);
    if (head == "info") {
        for (std::string_view option : {"diagnostic", "miscdata"})
            if (option.starts_with(tail)) out.push_back("info " + std::string(option));
        return out;
    }
    if (head == "reboot" && tail.find(' ') == std::string::npos) {
        for (const auto& target : session::reboot_targets)
            if (!target.hidden && target.name.starts_with(tail)) out.push_back("reboot " + std::string(target.name));
        return out;
    }
    if (selected && (selected->id == cli::CommandId::Read || selected->id == cli::CommandId::Write ||
        selected->id == cli::CommandId::WriteRename ||
        selected->id == cli::CommandId::RestoreRaw ||
        selected->id == cli::CommandId::Erase) &&
        tail.find(' ') == std::string::npos && !sess.parts_cache.empty()) {
        for (const auto& p : sess.parts_cache)
            if (p.name.rfind(tail, 0) == 0) out.push_back(head + " " +
                (p.name.find_first_of(" \t\"'\\") == std::string::npos ? p.name : cli::quote_argument(p.name)));
    }
    if (selected && selected->id == cli::CommandId::Read && std::string_view("all").starts_with(tail))
        out.push_back(head + " all");
    return out;
}


const fs::path& Shell::session_directory() {
    if (!sess_.output_directory.empty()) return sess_.output_directory;
    if (sess_.stage() != Stage::Fdl2) fail("session: FDL2 connection required");
    const auto now = std::chrono::system_clock::now();
    const auto seconds = std::chrono::floor<std::chrono::seconds>(now);
    const auto time = std::chrono::system_clock::to_time_t(seconds);
    std::tm local{};
#ifdef _WIN32
    if (localtime_s(&local, &time) != 0) fail("session: cannot determine local time");
#else
    if (!localtime_r(&time, &local)) fail("session: cannot determine local time");
#endif
    char stamp[32];
    if (!std::strftime(stamp, sizeof stamp, "%Y%m%d-%H%M%S", &local))
        fail("session: cannot format timestamp");
    char milliseconds[8];
    std::snprintf(milliseconds, sizeof milliseconds, "-%03d",
        static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(now - seconds).count()));
    const std::string name = std::string(stamp) + milliseconds;
    std::error_code ec;
    const auto root = fs::current_path(ec) / "sessions";
    if (ec) fail("session: current directory unavailable: " + ec.message());
    fs::create_directories(root, ec);
    if (ec) fail("session: cannot create " + platform::utf8_path(root) + ": " + ec.message());
    for (unsigned suffix = 0; suffix < 10000; ++suffix) {
        const auto directory = root / platform::path(name + (suffix ? "-" + std::to_string(suffix) : ""));
        if (fs::create_directory(directory, ec)) {
            sess_.output_directory = directory;
            log_status(LogLevel::Info, "session", platform::utf8_path(directory));
            return sess_.output_directory;
        }
        if (ec && ec != std::errc::file_exists)
            fail("session: cannot create " + platform::utf8_path(directory) + ": " + ec.message());
    }
    fail("session: cannot allocate a unique directory");
}

void Shell::landing_summary(Stage prev, std::stop_token stop) {
    // The common execution path covers interactive, piped and argv modes.
    if (!sess_.dev || sess_.stage() != Stage::Fdl2 ||
        (prev == Stage::Fdl2 && !sess_.output_directory.empty()))
        return;
    if (prev != Stage::Fdl2) sess_.output_directory.clear();
    log_status(LogLevel::Info, "ready", stage_name(sess_.stage()));
    try {
        session_directory();
        if (stop.stop_requested()) return;
        cmd_info(false, stop);
        if (stop.stop_requested()) return;
        cmd_parts(stop, true);
    } catch (const cli::CommandFailure& error) {
        warn("FDL2 ready; automatic summary incomplete: " + error.message);
    } catch (const std::exception& error) {
        warn("FDL2 ready; automatic summary incomplete: " + std::string(error.what()));
    }
}

int Shell::run(std::stop_token stop) {
    const bool interactive = platform::is_terminal(0);
    if (cli::termination_requested()) return 143;
    if (stop.stop_requested() && !interactive) return 130;
    if (interactive) {
        info("UniFlash-Core " + std::string(VERSION) + " (" + std::string(BUILD_ID) + ")");
        info("Type 'help' for commands. Tab completes input.");
        info("Ctrl+C cancels; press again before a new command to exit.");
    }
    // The default wait-and-connect is an INTERACTIVE behavior; piped
    // stdin is scripting — drop straight into the command loop (commands
    // like 'connect' still wait on demand). An interrupted or timed-out
    // wait drops to the offline prompt instead of killing the shell —
    // 'connect' retries on demand, 'quit' leaves.
    if (interactive && !sess_.dev) {
        try { (void)wait_for_device(stop, 120); }
        catch (const cli::CommandFailure& error) { log_err(error.message); }
        if (cli::termination_requested()) return 143;
        if (cli::global_interrupted()) cli::rotate_stop_source();
        if (!sess_.dev)
            log_status(LogLevel::Warn, "connect", "no device connected");
        try { landing_summary(Stage::Offline, cli::current_stop_token()); }
        catch (const cli::CommandFailure& error) { uniflash::log_err(error.message); }
        if (cli::termination_requested()) return 143;
    }

    auto completer = [this](const std::string& line, size_t cur) {
        return shell_completer(editor_.history(), sess_, line, cur);
    };

    for (;;) {
        if (cli::termination_requested()) return 143;
        if (!interactive && cli::current_stop_token().stop_requested()) return 130;
        // Honest prompt: once the transport has seen the device
        // physically disappear (LIBUSB_ERROR_NO_DEVICE), demote the
        // session immediately — a stale `fdl2>` after an unplugged
        // cable only invites confusion. The same for the ACK-silent
        // wedge (timeout with the device still on the bus): per the
        // write-death invariant it never recovers without a power
        // cycle, so every later command would just time out again.
        if (sess_.dev && sess_.dev->link_dead()) {
            sess_.dev.reset();
            sess_.parts_cache.clear();
            warn("device disconnected; offline");
        } else if (sess_.dev && sess_.dev->link_silent()) {
            sess_.dev.reset();
            sess_.parts_cache.clear();
            warn("device stopped answering; offline");
        }
        std::string prompt = "uniflash-core> ";
        if (sess_.dev)
            prompt = std::string(stage_name(sess_.stage())) + "> ";
        else
            prompt = "offline> ";

        std::string line;
        auto rc = editor_.read(prompt, line, completer);
        if (cli::termination_requested()) return 143;
        if (rc == LineEditor::Result::Eof) {
            if (cli::global_interrupted()) return 130;
            break;
        }
        if (rc == LineEditor::Result::Interrupted) {
            if (!interactive) return 130;
            warn("input cancelled; Ctrl+C again to exit");
            cli::rotate_stop_source();
            continue;
        }
        if (cli::global_interrupted()) {
            if (!interactive) return 130;
            cli::rotate_stop_source();
            continue; // a cancelled input must never become the next command
        }
        if (line.find_first_not_of(" \t\r\n") != std::string::npos) cli::begin_command();
        // An accepted interactive Enter is an explicit liveness request,
        // including an empty line. Piped/argv execution has no such probe.
        std::istringstream command_input(line);
        std::string command_name;
        command_input >> command_name;
        const auto* entered = cli::find_command(command_name);
        const bool local = entered && (entered->id == cli::CommandId::Quit || entered->id == cli::CommandId::Help ||
            entered->id == cli::CommandId::Bus || entered->id == cli::CommandId::Connect ||
            entered->id == cli::CommandId::DecryptImage || entered->id == cli::CommandId::UnpackImage);
        const bool ping_candidate = command_name.empty() || (entered && !local);
        if (interactive && entered && !local) {
            try { exec_checked(line, cli::current_stop_token(), true); }
            catch (...) {
                // Render through the normal result boundary; repeated
                // validation fails before dispatch and therefore before I/O.
                (void)exec(line, cli::current_stop_token());
                if (cli::global_interrupted()) cli::rotate_stop_source();
                continue;
            }
        }
        if (interactive && ping_candidate && sess_.dev && sess_.stage() == Stage::Fdl2) {
            const auto ping = cli::ping_fdl2(sess_.dev, sess_.parts_cache,
                                            cli::current_stop_token());
            if (cli::termination_requested()) return 143;
            if (!ping) {
                uniflash::log_err("connection check failed" + err_detail(ping.error()) +
                                    (sess_.dev ? " - input cancelled" : " - offline"));
                if (cli::global_interrupted()) cli::rotate_stop_source();
                continue; // Never execute the submitted command after failure.
            }
        }
        const auto result = exec(line, cli::current_stop_token());
        if (cli::termination_requested()) return 143;
        if (!interactive && !result.succeeded()) return result.exit_code();
        if (quitting_) break;
        if (cli::global_interrupted())
            cli::rotate_stop_source();
    }
    if (interactive) info("session closed");
    return cli::termination_requested() ? 143 : 0;
}


static void run_version() {
    log_document(std::string(PROJECT) + " " + std::string(VERSION) + "\n");
}

static int run_protocol_test() {
    protocol::run_tests();
    return 0;
}

static int run_shell(std::stop_token stop) {
    Shell shell;
    return shell.run(stop);
}

int run_script(const std::vector<std::string>& lines, std::stop_token stop) {
    Shell shell;
    for (const auto& line : lines) {
        if (cli::termination_requested()) return 143;
        if (stop.stop_requested()) return 130;
        if (line.empty() || line[0] == '#') continue;
        log_document("> " + line + "\n");
        const auto result = shell.exec(line, stop);
        if (cli::termination_requested()) return 143;
        if (stop.stop_requested()) return 130;
        if (!result.succeeded()) return result.exit_code();
        if (shell.quitting()) break;
    }
    return cli::termination_requested() ? 143 : stop.stop_requested() ? 130 : 0;
}



}  // namespace

int main(int argc, char** argv) try {
    platform::initialize_console();
#ifdef _WIN32
    cli::ConsoleInputMode console_input_mode;
#endif
    console_wait_progress_enabled.store(true);
    cli::SignalHandler sig_handler;
#ifdef _WIN32
    // MSVC's narrow argv uses the ANSI codepage. Convert the actual wide
    // command line once, keeping all internal text and paths UTF-8.
    int wide_count = 0;
    auto wide_args = CommandLineToArgvW(GetCommandLineW(), &wide_count);
    if (!wide_args) return 1;
    std::vector<std::string> utf8_args;
    for (int i=0;i<wide_count;++i) utf8_args.push_back(platform::utf8(wide_args[i]));
    LocalFree(wide_args);
    std::vector<char*> pointers;
    for (auto& arg : utf8_args) pointers.push_back(arg.data());
    argc = wide_count;
    argv = pointers.data();
#endif
    
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (argc == 2 && (arg == "--help" || arg == "-h")) {
            print_help();
            return 0;
        }
        args.push_back(arg);
    }
    
    if (args.size() == 1) {
        if (args[0] == "version")
            return (run_version(), 0);
        if (args[0] == "--version")
            return (run_version(), 0);
        if (args[0] == "test" || args[0] == "protocol-test")
            return run_protocol_test();
    }
    
    if (!args.empty())
        return run_script(args, cli::current_stop_token());
    
    return run_shell(cli::current_stop_token());
} catch (const std::exception& error) {
    uniflash::log_err(std::string("fatal: ") + error.what());
    return 2;
} catch (...) {
    uniflash::log_err("fatal: unknown exception");
    return 2;
}

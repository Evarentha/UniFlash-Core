#include <uniflash/io/image.h>
#include <uniflash/io/output.h>
#include <uniflash/log.h>
#include "temp_directory.h"
#include <array>
#include <cerrno>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#ifndef _WIN32
#include <csignal>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {
namespace fs = std::filesystem;
using uniflash::io::AtomicOutput;
using uniflash::io::Image;

void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
void save(const fs::path& path, const std::string& bytes) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file << bytes;
    file.close();
    require(bool(file), "fixture write failed");
}
std::string load(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    require(bool(file), "fixture read failed");
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}
struct RestoreCwd {
    fs::path saved = fs::current_path();
    ~RestoreCwd() { std::error_code ignored; fs::current_path(saved, ignored); }
};
fs::path temporary_name(const fs::path& directory) {
    fs::path found;
    for (const auto& entry : fs::directory_iterator(directory)) {
        if (entry.path().filename().string().starts_with(".uniflash-")) {
            require(found.empty(), "multiple temporary files left behind");
            found = entry.path().filename();
        }
    }
    return found;
}

void output_boundaries(const fs::path& root, const fs::path& relative) {
    const auto a = root / "a", b = root / "b";
    const auto parent_a = a / relative.parent_path();
    const auto parent_b = b / relative.parent_path();
    fs::create_directories(parent_a);
    fs::create_directories(parent_b);
    save(a / relative, "original");
    save(b / relative, "other destination");
    RestoreCwd cwd;
    const std::array<uint8_t, 3> bytes{'n', 'e', 'w'};
    fs::path name;
    fs::current_path(a);
    {
        auto output = AtomicOutput::open(relative);
        require(bool(output), "relative output open");
        name = temporary_name(parent_a);
        require(!name.empty(), "temporary created beside original destination");
        save(parent_b / name, "other temporary");
        fs::current_path(b);
        require(bool(output->write(bytes)), "write after cwd change");
        require(bool(output->commit()), "commit after cwd change");
        require(output->commit_state() == uniflash::io::CommitState::Durable,
                "commit durability state");
    }
    require(load(a / relative) == "new", "original directory receives commit");
    require(load(b / relative) == "other destination", "other destination preserved");
    require(load(parent_b / name) == "other temporary", "other temporary preserved at commit");
    require(temporary_name(parent_a).empty(), "commit leaves no original temporary");
    fs::remove(parent_b / name);

    // Exercise stack unwinding while cwd points at another matching directory.
    struct Unwind {};
    fs::current_path(a);
    try {
        auto output = AtomicOutput::open(relative);
        require(bool(output), "uncommitted output open");
        name = temporary_name(parent_a);
        require(!name.empty(), "uncommitted temporary exists");
        save(parent_b / name, "other temporary");
        fs::current_path(b);
        require(bool(output->write(bytes)), "uncommitted output write");
        throw Unwind{};
    } catch (const Unwind&) {}
    require(temporary_name(parent_a).empty(), "unwind removes original temporary");
    require(load(a / relative) == "new", "unwind preserves original destination");
    require(load(b / relative) == "other destination", "unwind preserves other destination");
    require(load(parent_b / name) == "other temporary", "unwind preserves other temporary");
    fs::remove(parent_b / name);

    // Replacement fails after closing the file; destruction still owns its name.
    fs::remove(a / relative);
    fs::create_directory(a / relative);
    fs::current_path(a);
    {
        auto output = AtomicOutput::open(relative);
        require(bool(output), "failed commit output open");
        name = temporary_name(parent_a);
        require(!name.empty(), "failed commit temporary exists");
        save(parent_b / name, "other temporary");
        fs::current_path(b);
        require(!output->commit(), "directory destination rejects replacement");
        require(output->commit_state() == uniflash::io::CommitState::NotCommitted,
                "failed replacement state");
    }
    require(temporary_name(parent_a).empty(), "failed commit cleans original temporary");
    require(fs::is_directory(a / relative), "failed commit preserves destination directory");
    require(load(b / relative) == "other destination", "failed commit preserves other destination");
    require(load(parent_b / name) == "other temporary", "failed commit preserves other temporary");
    fs::remove(parent_b / name);
}

void snapshot_boundaries(const fs::path& root) {
    const auto regular = root / "image.bin";
    save(regular, "snapshot");
    auto image = Image::prepare(regular, 8);
    auto blob = Image::prepare_blob(regular, 8);
    require(image && blob, "regular image and blob prepare");
#ifndef _WIN32
    const auto link = root / "image-link.bin";
    fs::create_symlink(regular.filename(), link);
    auto linked = Image::prepare(link, 8);
    require(bool(linked), "symlink to regular file prepare");
#endif
    save(regular, "modified");
    std::array<uint8_t, 8> bytes{};
    const auto unchanged = [&](const Image& prepared) {
        return prepared.size() == bytes.size() && prepared.reader()(0, bytes, {}) &&
            std::string(bytes.begin(), bytes.end()) == "snapshot";
    };
    require(unchanged(*image) && unchanged(*blob), "ordinary snapshots survive source edit");
#ifndef _WIN32
    require(unchanged(*linked), "symlink snapshot survives source edit");
#endif
    std::stop_source stop;
    stop.request_stop();
    auto cancelled = Image::prepare(regular, 8, stop.get_token());
    require(!cancelled && cancelled.error() == std::errc::interrupted, "cancelled regular snapshot");
}

#ifndef _WIN32
void fifo_boundaries(const fs::path& root) {
    const auto fifo = root / "input.fifo";
    require(mkfifo(fifo.c_str(), 0600) == 0, "FIFO fixture creation");
    // A regressed blocking open must fail this test rather than hang the suite.
    const pid_t child = fork();
    require(child >= 0, "FIFO test fork");
    if (child == 0) {
        std::signal(SIGALRM, SIG_DFL);
        alarm(5);
        const auto image = Image::prepare(fifo, 1024);
        const auto blob = Image::prepare_blob(fifo, 1024);
        std::stop_source stop;
        stop.request_stop();
        const auto cancelled = Image::prepare(fifo, 1024, stop.get_token());
        _exit(!image && image.error() == std::errc::invalid_argument &&
              !blob && blob.error() == std::errc::invalid_argument &&
              !cancelled && cancelled.error() == std::errc::interrupted ? 0 : 1);
    }
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    require(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "FIFO without writer must reject before deadline; pre-cancellation must return");
}
#endif
}

int main() {
    try {
        TempDirectory temporary;
        const auto root = fs::absolute(temporary.path);
#ifndef _WIN32
        fifo_boundaries(root);
#endif
        output_boundaries(root / "bare", "result.bin");
        output_boundaries(root / "nested", "sub/result.bin");
        snapshot_boundaries(root);
    } catch (const std::exception& error) {
        uniflash::log_err(error.what());
        return 1;
    }
}

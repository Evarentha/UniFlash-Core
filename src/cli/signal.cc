#include <uniflash/cli/signal.h>

#include <atomic>
#include <cerrno>
#include <csignal>
#include <mutex>
#include <system_error>
#include <thread>
#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace uniflash::cli {
namespace {

std::mutex g_mutex;
std::stop_source g_stop_source;
static_assert(std::atomic<int>::is_always_lock_free);
// One atomic state prevents acknowledgement/new-command races from erasing
// a concurrently arriving interrupt: 0=armed, 1=pending, 2=acknowledged.
std::atomic<int> g_interrupt{0};
std::atomic<int> g_terminate{0};
std::atomic<int> g_input_active{0};
std::atomic<int> g_exit{0};
std::atomic<int> g_ignore_interrupts{0};
std::atomic<int> g_defer_forced_exit{0};

// Only ordinary threads call this: request_stop may invoke client callbacks.
void cancel_current_command() {
    auto source = [] {
        std::lock_guard lock(g_mutex);
        if (g_interrupt.load() != 1 && !g_terminate.load() && !g_exit.load())
            return std::stop_source(std::nostopstate);
        return g_stop_source;
    }();
    source.request_stop();
}

#ifdef _WIN32
BOOL WINAPI console_control(DWORD event) {
    if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT &&
        event != CTRL_CLOSE_EVENT) return FALSE;
    if (event != CTRL_CLOSE_EVENT && g_ignore_interrupts.load() != 0) return TRUE;
    if (event == CTRL_CLOSE_EVENT) g_terminate.store(1);
    else if (g_interrupt.exchange(1) != 0 && !g_defer_forced_exit.load()) {
        if (g_input_active.load()) g_exit.store(1);
        else ExitProcess(130);
    }
    cancel_current_command();
    return TRUE;
}
#else
std::atomic<int> g_signal_write_fd{-1};
std::atomic<int> g_handlers_active{0};
std::atomic<int> g_restore_echoctl{0};

extern "C" void handle_signal(int signal) {
    const int saved_errno = errno;
    if (signal == SIGINT && g_ignore_interrupts.load() != 0) {
        errno = saved_errno;
        return;
    }
    g_handlers_active.fetch_add(1);
    if (signal == SIGTERM) g_terminate.store(1, std::memory_order_relaxed);
    else if (g_interrupt.exchange(1) != 0 && !g_defer_forced_exit.load()) {
        if (g_input_active.load()) g_exit.store(1);
        else {
            // tcgetattr/tcsetattr are POSIX async-signal-safe. No C++ cleanup
            // or logger is invoked from this forced-exit path.
#ifdef ECHOCTL
            termios current{};
            if (g_restore_echoctl.load() && tcgetattr(STDIN_FILENO, &current) == 0) {
                current.c_lflag |= ECHOCTL;
                tcsetattr(STDIN_FILENO, TCSANOW, &current);
            }
#endif
            _exit(130);
        }
    }
    const int fd = g_signal_write_fd.load();
    if (fd >= 0) {
        const char byte = 1;
        // Nonblocking: a full pipe already guarantees the worker will wake.
        while (write(fd, &byte, 1) < 0 && errno == EINTR) {}
    }
    g_handlers_active.fetch_sub(1);
    errno = saved_errno;
}
#endif

} // namespace

struct SignalHandler::Impl {
#ifdef _WIN32
    bool installed = false;
    ~Impl() { if (installed) SetConsoleCtrlHandler(console_control, FALSE); }
#else
    int pipefd[2]{-1, -1};
    struct sigaction previous_int{}, previous_term{};
    bool installed_int = false, installed_term = false;
    std::atomic<bool> shutdown{false};
    std::thread worker;
    bool changed_echoctl = false;

    ~Impl() {
        // Restore only our flag, not the line editor's other terminal modes.
#ifdef ECHOCTL
        if (changed_echoctl) {
            termios current{};
            if (tcgetattr(STDIN_FILENO, &current) == 0) {
                current.c_lflag |= ECHOCTL;
                tcsetattr(STDIN_FILENO, TCSANOW, &current);
            }
        }
        g_restore_echoctl.store(0);
#endif
        // The worker inherits a blocked signal mask. The owning main thread
        // restores the old dispositions before dismantling its wakeup pipe.
        if (installed_int) sigaction(SIGINT, &previous_int, nullptr);
        if (installed_term) sigaction(SIGTERM, &previous_term, nullptr);
        g_signal_write_fd.store(-1);
        // Also cover a handler already running on another application thread:
        // after this drain, no handler can retain a soon-to-be-reused pipe fd.
        while (g_handlers_active.load() != 0) std::this_thread::yield();
        shutdown.store(true);
        if (worker.joinable()) {
            const char byte = 0;
            while (write(pipefd[1], &byte, 1) < 0 && errno == EINTR) {}
            worker.join();
        }
        for (int fd : pipefd) if (fd >= 0) close(fd);
    }
#endif
};

std::stop_token current_stop_token() {
    std::lock_guard lock(g_mutex);
    return g_stop_source.get_token();
}

void rotate_stop_source() {
    std::lock_guard lock(g_mutex);
    if (g_terminate.load()) return;
    g_stop_source = std::stop_source{};
    // Acknowledging cancellation must not disarm the second-Ctrl+C exit.
    // Only accepting a subsequent nonempty command starts a new interrupt cycle.
    int pending = 1;
    g_interrupt.compare_exchange_strong(pending, 2);
}

void begin_command() {
    int acknowledged = 2;
    g_interrupt.compare_exchange_strong(acknowledged, 0);
}

void interrupt_from_console() {
#ifdef _WIN32
    console_control(CTRL_C_EVENT);
#else
    raise(SIGINT);
#endif
}

bool global_interrupted() {
    return g_interrupt.load() == 1 || termination_requested();
}

bool termination_requested() { return g_terminate.load() != 0; }
void set_input_active(bool active) { g_input_active.store(active); }
bool force_exit_requested() { return g_exit.load() != 0; }

IgnoreInterrupts::IgnoreInterrupts() { g_ignore_interrupts.fetch_add(1); }
IgnoreInterrupts::~IgnoreInterrupts() { g_ignore_interrupts.fetch_sub(1); }
DeferForcedExit::DeferForcedExit(){g_defer_forced_exit.fetch_add(1);}
DeferForcedExit::~DeferForcedExit(){g_defer_forced_exit.fetch_sub(1);}

SignalHandler::SignalHandler() {
    auto impl = std::make_unique<Impl>();
#ifdef _WIN32
    if (!SetConsoleCtrlHandler(console_control, TRUE))
        throw std::system_error(GetLastError(), std::system_category());
    impl->installed = true;
#else
    // Kernel-echoed '^C' can land in the middle of a progress redraw. The
    // dispatcher renders cancellation once through the logger instead.
#ifdef ECHOCTL
    termios console{};
    if (tcgetattr(STDIN_FILENO, &console) == 0 && (console.c_lflag & ECHOCTL)) {
        console.c_lflag &= ~ECHOCTL;
        impl->changed_echoctl = tcsetattr(STDIN_FILENO, TCSANOW, &console) == 0;
        g_restore_echoctl.store(impl->changed_echoctl);
    }
#endif
    if (pipe(impl->pipefd) != 0)
        throw std::system_error(errno, std::generic_category());
    for (int fd : impl->pipefd) {
        const int flags = fcntl(fd, F_GETFL);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
            fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
            throw std::system_error(errno, std::generic_category());
    }

    sigset_t blocked, previous_mask;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGINT);
    sigaddset(&blocked, SIGTERM);
    int error = pthread_sigmask(SIG_BLOCK, &blocked, &previous_mask);
    if (error) throw std::system_error(error, std::generic_category());
    try {
        impl->worker = std::thread([state = impl.get()] {
            pollfd input{state->pipefd[0], POLLIN, 0};
            while (!state->shutdown.load()) {
                const int ready = poll(&input, 1, -1);
                if (ready < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                char bytes[64];
                while (read(input.fd, bytes, sizeof bytes) > 0) {}
                if (!state->shutdown.load()) cancel_current_command();
            }
        });
        g_signal_write_fd.store(impl->pipefd[1]);
        struct sigaction action{};
        action.sa_handler = handle_signal;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGINT, &action, &impl->previous_int) != 0)
            throw std::system_error(errno, std::generic_category());
        impl->installed_int = true;
        if (sigaction(SIGTERM, &action, &impl->previous_term) != 0)
            throw std::system_error(errno, std::generic_category());
        impl->installed_term = true;
    } catch (...) {
        impl.reset();
        pthread_sigmask(SIG_SETMASK, &previous_mask, nullptr);
        throw;
    }
    pthread_sigmask(SIG_SETMASK, &previous_mask, nullptr);
#endif
    impl_ = std::move(impl);
}

SignalHandler::~SignalHandler() = default;

} // namespace uniflash::cli

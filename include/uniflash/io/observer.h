#pragma once
#include <functional>
#include <utility>
#include <type_traits>
#include <cstddef>

namespace uniflash::io {
// Notifications are not data operations. A presentation callback must not
// unwind an acknowledged write, or turn an already committed file into failure.
template<class Event> class Observer {
public:
    Observer() = default;
    Observer(std::nullptr_t) {}
    template<class F> requires (!std::is_same_v<std::remove_cvref_t<F>, Observer>)
    Observer(F&& callback) : callback_(std::forward<F>(callback)) {}
    explicit operator bool() const noexcept { return bool(callback_); }
    void operator()(const Event& event) const noexcept {
        try { if (callback_) callback_(event); } catch (...) {}
    }
private:
    std::function<void(const Event&)> callback_;
};
}

/*
 * UniFlash-Core / Transport Interface
 *
 * Byte channel contract with framing, timeout and cancellation guarantees.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <stop_token>
#include <system_error>
#include <vector>

namespace uniflash::transport {

using Timeout = std::chrono::milliseconds;
inline constexpr Timeout DEFAULT_TIMEOUT{3000};

// A byte channel and its framing guarantees, independent of enumeration and
// platform driver types. Calls on a channel are serialized by its owner.
class Transport {
public:
    // Payload logging is suppressed by the owner for sensitive exchanges.
    // Derived transports must honor this flag in their trace implementation.
    bool sensitive() const noexcept {return sensitive_;}
    void set_sensitive(bool value) noexcept {sensitive_=value;}
    virtual ~Transport() = default;
    virtual std::expected<void, std::errc> bulk_write(
        std::span<const uint8_t>, Timeout, std::stop_token) = 0;
    virtual std::expected<std::vector<uint8_t>, std::errc> bulk_read(
        size_t, Timeout, std::stop_token) = 0;
    virtual bool supports_raw_frames() const = 0;
    virtual uint16_t out_maxpacket() const = 0;
    virtual std::expected<void, std::errc> bulk_write_frame(
        std::span<const uint8_t>, Timeout, std::stop_token) = 0;
    virtual bool device_gone() const = 0;
    virtual bool device_silent() const = 0;
private:
    bool sensitive_=false;
};

// Move-only owner used by protocol sessions. Keeping the forwarding surface
// here makes an injected fake use the exact same path as a production driver.
class Channel {
public:
    bool sensitive() const noexcept {return transport_ && transport_->sensitive();}
    void set_sensitive(bool value) noexcept {if(transport_)transport_->set_sensitive(value);}
    explicit Channel(std::unique_ptr<Transport> transport) : transport_(std::move(transport)) {}
    Channel(Channel&&) noexcept = default;
    Channel& operator=(Channel&&) noexcept = default;
    std::expected<void, std::errc> bulk_write(std::span<const uint8_t> data,
        Timeout timeout = DEFAULT_TIMEOUT, std::stop_token stop = {}) {
        if (!transport_) return std::unexpected(std::errc::not_connected);
        return transport_->bulk_write(data, timeout, stop);
    }
    std::expected<std::vector<uint8_t>, std::errc> bulk_read(size_t size,
        Timeout timeout = DEFAULT_TIMEOUT, std::stop_token stop = {}) {
        if (!transport_) return std::unexpected(std::errc::not_connected);
        return transport_->bulk_read(size, timeout, stop);
    }
    std::expected<void, std::errc> bulk_write_frame(std::span<const uint8_t> data,
        Timeout timeout = DEFAULT_TIMEOUT, std::stop_token stop = {}) {
        if (!transport_) return std::unexpected(std::errc::not_connected);
        return transport_->bulk_write_frame(data, timeout, stop);
    }
    bool supports_raw_frames() const { return transport_ && transport_->supports_raw_frames(); }
    uint16_t out_maxpacket() const { return transport_ ? transport_->out_maxpacket() : 0; }
    bool device_gone() const { return !transport_ || transport_->device_gone(); }
    bool device_silent() const { return !transport_ || transport_->device_silent(); }
private:
    std::unique_ptr<Transport> transport_;
};

} // namespace uniflash::transport

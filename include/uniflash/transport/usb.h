/*
 * UniFlash-Core / USB Transport
 *
 * Shared libusb context, enumeration records and transports.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef UNIFLASH_TRANSPORT_USB_H
#define UNIFLASH_TRANSPORT_USB_H

#include <uniflash/transport/transport.h>

#ifndef _WIN32
#include <libusb.h>
#include <mutex>
#endif

#include <atomic>
#include <chrono>
#include <expected>
#include <memory>
#include <span>
#include <stop_token>
#include <system_error>
#include <vector>
#include <string>

namespace uniflash::transport {


struct UsbDevice {
#ifndef _WIN32
    std::shared_ptr<libusb_device> native;
#else
    std::wstring device_path;
#endif
    uint16_t vid = 0;
    uint16_t pid = 0;
    // Link speed only; it does not identify the device's protocol or stage.
    enum Speed { Unknown, Full, High, Super };
    Speed speed = Unknown;
    std::string port_name; // COM name on Windows; empty on Linux
    // Physical location on the bus (stable across USB re-enumeration).
    // Empty when topology cannot be established; never a COM-name fallback.
    std::vector<uint8_t> port_path;

#ifndef _WIN32
    // Set by find_devices(); open_device validates its binding to native before
    // any libusb I/O. Copies retain both owners. Manually assembled or modified
    // native/context pairs are not accepted; external handles use adopt().
    std::shared_ptr<libusb_context> context_owner;
#endif

    std::string path_string() const;
};

class UsbTransport final : public Transport {
    friend class UsbContext;
public:
    // Calls on one transport (including move/destruction) require caller
    // serialization. Distinct transports may transfer concurrently on a context.
    UsbTransport();
    ~UsbTransport() override;

    UsbTransport(const UsbTransport&) = delete;
    UsbTransport& operator=(const UsbTransport&) = delete;
    UsbTransport(UsbTransport&&) noexcept;
    UsbTransport& operator=(UsbTransport&&) noexcept;

    // Take ownership of an already-claimed handle with known endpoints.
    // out_maxpacket: the OUT bulk endpoint's wMaxPacketSize — bulk_write
    // splits exact-multiple transfers to dodge the device-side
    // no-short-packet wedge (see bulk_write's ZLP invariant).
#ifndef _WIN32
    // context must be the handle's context and outlive this transport;
    // nullptr denotes libusb's default context. DTR defaults to interface_number;
    // pass the already-claimed CDC control interface explicitly for a separate
    // control function; ownership includes releasing both claimed interfaces.
    // The supplied handle must not already be owned by this transport.
    void adopt(libusb_device_handle* h, uint8_t ep_in, uint8_t ep_out,
                uint16_t out_maxpacket = 512, int interface_number = 0,
                libusb_context* context = nullptr, int control_interface_number = -1);
#endif

    std::expected<void, std::errc>
    bulk_write(std::span<const uint8_t> data,
               Timeout timeout = DEFAULT_TIMEOUT,
               std::stop_token stop = {}) override;

    uint16_t out_maxpacket() const override { return p_ ? p_->out_maxpacket : 0; }

    bool supports_raw_frames() const override {
#ifdef _WIN32
        return false;
#else
        return true;
#endif
    }

    // One complete raw BSL frame in ONE submission: no stream splitting,
    // padding or retry of a partial frame. Empty frames are invalid; lengths
    // exceeding 64 KiB fail with message_size BEFORE any bytes are sent.
    // libusb appends a ZLP for maxpacket multiples (ADD_ZERO_PACKET). If the
    // backend cannot honor that flag, its error is returned without fallback.
    // A partial submission is an error even when
    // some bytes reached the device. Callers must split payloads before encoding.
    // Windows COM cannot guarantee USB boundaries and returns not_supported;
    // callers must use supports_raw_frames() before negotiating raw framing.
    // Windows out_maxpacket() is speed-derived, not an endpoint descriptor.
    std::expected<void, std::errc>
    bulk_write_frame(std::span<const uint8_t> frame,
                     Timeout timeout = DEFAULT_TIMEOUT,
                     std::stop_token stop = {}) override;

    std::expected<std::vector<uint8_t>, std::errc>
    bulk_read(size_t max_len,
              Timeout timeout = DEFAULT_TIMEOUT,
              std::stop_token stop = {}) override;

    // CDC-style SET_CONTROL_LINE_STATE (DTR): the u-boot serial gadget's
    // gser_setup (f_serial.c) opens its port when wValue low byte == 1 —
    // mandatory before the gadget reads the PC-tool mode request
    // (calibration_detect.c cali_usb_enum waits for the port to open).
    std::expected<void, std::errc> serial_dtr();

    // True once libusb has reported LIBUSB_ERROR_NO_DEVICE on any
    // transfer — the device is physically gone (unplugged / bus
    // reset); every later call would fail. Lets the shell demote its
    // session to offline instead of showing a stale stage prompt.
    bool device_gone() const override {
        return p_ && p_->gone.load();
    }

    // True once a transfer timed out with nothing delivered and no
    // later transfer succeeded — the device is on the bus but not
    // answering (ACK-silent wedge). Per the write-death invariant a
    // wedged FDL2 never recovers without a power cycle, so the shell
    // demotes the session on this just like device_gone(). Any
    // successful transfer clears it (expected-silence paths such as
    // the FDL2 exec no-ACK or the resync DA_INFO poll self-correct
    // when the next exchange succeeds).
    bool device_silent() const override {
        return p_ && p_->silent;
    }

private:
    static constexpr int kBulkTransferSize = 64 * 1024;

    struct Impl {
        ~Impl();
#ifndef _WIN32
        libusb_device_handle* handle = nullptr;
        std::shared_ptr<libusb_context> context_owner;
        libusb_context* context = nullptr;
        // Calls on this transport are serialized; reuse only after callback
        // drainage. Separate directions keep future duplex ownership explicit.
        libusb_transfer* tx_transfer = nullptr;
        libusb_transfer* rx_transfer = nullptr;
        int interface_number = 0;
        int control_interface_number = 0;
        bool claimed = false;
        bool detached = false;
        bool control_claimed = false;
        bool control_detached = false;
#else
        void* handle = nullptr; // owned Windows HANDLE, hidden from protocol headers
#endif
        uint8_t ep_in  = 0x81;
        uint8_t ep_out = 0x01;
        uint16_t out_maxpacket = 512;
        std::atomic<bool> gone{false};
        // Command-thread access only (transfers are synchronous); no
        // signal handler ever touches the transport.
        bool silent = false;
        bool split_packet = false;
    };
    std::unique_ptr<Impl> p_;
};

// Shared libusb context: enumeration records and transports retain ownership
// so devices/handles can safely outlive the singleton's own reference.
class UsbContext {
public:
    static UsbContext& instance();

    // Enumeration records own their native references, including skipped
    // candidates. They may be retained across a scan without manual unref.
    std::expected<std::vector<UsbDevice>, std::errc>
    find_devices(std::span<const uint16_t> vids);

    // Linux accepts only intact enumeration records from find_devices(). A
    // non-null native without matching provenance fails with invalid_argument.
    std::expected<UsbTransport, std::errc>
    open_device(const UsbDevice& dev, bool reset_configuration = false, bool split_packet = false);

private:
    UsbContext() = default;
    ~UsbContext();

#ifndef _WIN32
    std::mutex context_mutex_;
    std::shared_ptr<libusb_context> ctx_;
    std::expected<std::shared_ptr<libusb_context>, std::errc> context();
#endif
};

}

#endif

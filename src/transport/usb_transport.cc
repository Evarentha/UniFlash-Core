/*
 * UniFlash-Core / USB Transport
 *
 * libusb enumeration, bulk transfers, cancellation and event handling.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#include <uniflash/log.h>
#include <uniflash/transport/usb.h>

#include <algorithm>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <thread>

namespace uniflash::transport {

namespace {

// The deleter binds the public native reference to its enumerating context.
// A context pointer alone cannot prove which event loop owns a libusb device.
struct EnumeratedDevice {
    std::shared_ptr<libusb_context> context;
    libusb_device* device;
    void operator()(libusb_device* value) const { libusb_unref_device(value); }
};

std::errc libusb_to_errc(int err) {
    switch (err) {
        case LIBUSB_SUCCESS:            return std::errc{};
        case LIBUSB_ERROR_IO:           return std::errc::io_error;
        case LIBUSB_ERROR_INVALID_PARAM:return std::errc::invalid_argument;
        case LIBUSB_ERROR_ACCESS:       return std::errc::permission_denied;
        case LIBUSB_ERROR_NO_DEVICE:    return std::errc::no_such_device;
        case LIBUSB_ERROR_NOT_FOUND:    return std::errc::no_such_file_or_directory;
        case LIBUSB_ERROR_BUSY:         return std::errc::device_or_resource_busy;
        case LIBUSB_ERROR_TIMEOUT:      return std::errc::timed_out;
        case LIBUSB_ERROR_OVERFLOW:     return std::errc::result_out_of_range;
        case LIBUSB_ERROR_PIPE:         return std::errc::broken_pipe;
        case LIBUSB_ERROR_INTERRUPTED:  return std::errc::interrupted;
        case LIBUSB_ERROR_NO_MEM:       return std::errc::not_enough_memory;
        case LIBUSB_ERROR_NOT_SUPPORTED:return std::errc::not_supported;
        default:                        return std::errc::io_error;
    }
}

using Clock = std::chrono::steady_clock;

struct TransferResult {
    int transferred = 0;
    std::errc error{};
};

struct Completion {
    std::atomic<bool> done{false};
    TransferResult result;
};

void LIBUSB_CALL transfer_complete(libusb_transfer* transfer) {
    auto& completion = *static_cast<Completion*>(transfer->user_data);
    completion.result.transferred = transfer->actual_length;
    switch (transfer->status) {
    case LIBUSB_TRANSFER_COMPLETED: break;
    case LIBUSB_TRANSFER_TIMED_OUT: completion.result.error = std::errc::timed_out; break;
    case LIBUSB_TRANSFER_CANCELLED: completion.result.error = std::errc::interrupted; break;
    case LIBUSB_TRANSFER_NO_DEVICE: completion.result.error = std::errc::no_such_device; break;
    case LIBUSB_TRANSFER_STALL: completion.result.error = std::errc::broken_pipe; break;
    case LIBUSB_TRANSFER_OVERFLOW: completion.result.error = std::errc::result_out_of_range; break;
    default: completion.result.error = std::errc::io_error; break;
    }
    completion.done.store(true, std::memory_order_release);
}

TransferResult transfer_bytes(libusb_transfer*& cached, libusb_context* context, libusb_device_handle* handle,
                              uint8_t endpoint, uint8_t* data, int length,
                              Clock::time_point deadline, std::stop_token stop,
                              bool raw_frame = false) {
    if (stop.stop_requested()) return {0, std::errc::interrupted};
    if (Clock::now() >= deadline) return {0, std::errc::timed_out};
    if (!cached) cached = libusb_alloc_transfer(0);
    auto* transfer = cached;
    if (!transfer) return {0, std::errc::not_enough_memory};
    Completion completion;
    // The host deadline covers submission, event handling and all stream chunks.
    // timeout=0 is intentional here: this asynchronous request is cancelled below.
    transfer->flags = 0; // A previous raw frame may have enabled ZLP.
    libusb_fill_bulk_transfer(transfer, handle, endpoint, data, length,
                             transfer_complete, &completion, 0);
    // Preserve the entire raw frame as one transfer; the Linux backend appends
    // a ZLP only for packet-size multiples. Unsupported backends must fail the
    // submission, never retry without the flag or split a raw frame's data.
    if (raw_frame) transfer->flags |= LIBUSB_TRANSFER_ADD_ZERO_PACKET;
    const int submitted = libusb_submit_transfer(transfer);
    if (submitted != LIBUSB_SUCCESS) {
        transfer->user_data = nullptr;
        transfer->buffer = nullptr;
        return {0, libusb_to_errc(submitted)};
    }
    std::errc cancellation{};
    // Multiple transports share a context. Serialize our event pumps, never hold
    // this mutex while waiting for another thread's completion, and publish
    // callback results with release/acquire (callbacks may run on ANY pump).
    // libusb's event API also arbitrates with external event handlers.
    static std::mutex events_mutex;
    while (!completion.done.load(std::memory_order_acquire)) {
        if (cancellation == std::errc{} &&
            (stop.stop_requested() || Clock::now() >= deadline)) {
            cancellation = stop.stop_requested() ? std::errc::interrupted : std::errc::timed_out;
            libusb_cancel_transfer(transfer);
        }
        std::unique_lock lock(events_mutex, std::try_to_lock);
        if (!lock.owns_lock()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        if (completion.done.load(std::memory_order_acquire)) break;
        timeval wait{0, 10000};
        const int rc = libusb_handle_events_timeout_completed(context, &wait, nullptr);
        if (rc != LIBUSB_SUCCESS && rc != LIBUSB_ERROR_INTERRUPTED && cancellation == std::errc{}) {
            cancellation = libusb_to_errc(rc);
            libusb_cancel_transfer(transfer);
        }
        // Even an event-loop error cannot justify releasing a live transfer:
        // drain cancellation to its callback before freeing transfer or buffer.
    }
    // done is published inside the callback. Join the event-handler critical
    // section as well, so even an external pump has returned from the callback
    // before its user_data, transfer and context references can be destroyed.
    libusb_lock_events(context);
    libusb_unlock_events(context);
    auto result = completion.result;
    transfer->user_data = nullptr;
    transfer->buffer = nullptr;
    if (cancellation != std::errc{}) result.error = cancellation;
    return result;
}

}

// ---------------------------------------------------------------- transport

UsbTransport::UsbTransport() : p_(std::make_unique<Impl>()) {}
UsbTransport::Impl::~Impl() {
    if (tx_transfer) libusb_free_transfer(tx_transfer);
    if (rx_transfer) libusb_free_transfer(rx_transfer);
    if (handle) {
        if (claimed) libusb_release_interface(handle, interface_number);
        if (control_claimed) libusb_release_interface(handle, control_interface_number);
        if (detached) libusb_attach_kernel_driver(handle, interface_number);
        if (control_detached) libusb_attach_kernel_driver(handle, control_interface_number);
        libusb_close(handle);
    }
}
UsbTransport::~UsbTransport() = default;

UsbTransport::UsbTransport(UsbTransport&&) noexcept = default;
UsbTransport& UsbTransport::operator=(UsbTransport&& other) noexcept {
    if (this != &other) {
        UsbTransport old(std::move(*this));
        Transport::operator=(std::move(other));
        p_ = std::move(other.p_);
    }
    return *this;
}

void UsbTransport::adopt(libusb_device_handle* h, uint8_t ep_in, uint8_t ep_out,
                         uint16_t out_maxpacket, int interface_number,
                         libusb_context* context, int control_interface_number) {
    auto owned = std::make_unique<Impl>();
    owned->handle = h;
    owned->ep_in = ep_in;
    owned->ep_out = ep_out;
    owned->out_maxpacket = out_maxpacket > 1 ? out_maxpacket : 512;
    owned->interface_number = interface_number;
    owned->control_interface_number = control_interface_number < 0 ? interface_number : control_interface_number;
    owned->claimed = true;
    owned->control_claimed = owned->control_interface_number != interface_number;
    owned->context = context;
    p_ = std::move(owned);
}

static void hex_dump(const char* tag, const uint8_t* data, size_t len) {
    if (!uniflash::log_diag_trace_enabled()) return;
    // One line: tag + up to 64 bytes + elision — built as a string so
    // the whole dump lands on the sink as a single Diag record.
    char buf[256];
    int n = std::snprintf(buf, sizeof buf, "{usb} %s (%zu B):", tag, len);
    for (size_t i = 0; i < len && i < 64 && n + 4 < (int)sizeof buf; ++i)
        n += std::snprintf(buf + n, sizeof buf - n, " %02x", data[i]);
    if (len > 64)
        std::snprintf(buf + n, sizeof buf - n, " ...(%zu more)", len - 64);
    uniflash::log_diag(buf);
}

std::expected<void, std::errc>
UsbTransport::bulk_write(std::span<const uint8_t> data, Timeout timeout,
                         std::stop_token stop) {
    if (!p_ || !p_->handle)
        return std::unexpected(std::errc::no_such_device);

    const auto deadline = Clock::now() + timeout;
    size_t sent = 0;
    while (sent < data.size()) {
        if (stop.stop_requested())
            return std::unexpected(std::errc::interrupted);

        size_t len = std::min<size_t>(data.size() - sent,
                                      static_cast<size_t>(kBulkTransferSize));
        // Stream-only workaround (escaped frames / whole bare payloads).
        // Raw BSL frames must instead use bulk_write_frame's single transfer.
        // A bulk-OUT transfer whose length is an exact
        // multiple of wMaxPacketSize ends on a FULL packet — no short
        // packet; these stream transfers do not request ADD_ZERO_PACKET.
        // The SPRD receive path (dwc3 DMA armed for a full 64KB
        // buffer, no ZLP handling on OUT) then never completes the
        // transfer device-side: XFER_CMPL never fires and the FDL's
        // event loop (usb3_handler's do-while(1)) wedges forever — no
        // error, no reply, power-cycle only. Our writes died
        // deterministically at exactly the first frame whose escaped
        // wire length hit a 512 multiple (chunk 192 with 63488-byte
        // chunks, chunk 1051 with 61440 — both predicted by a
        // congruence scan of the image, both confirmed on hardware);
        // the factory tool ships the same workaround (its config:
        // "SupportZroPkg: segment USB packet to avoid Zero-Length-
        // Packet problem"). Split any exact-multiple transfer: send
        // n-1 now, the loop's next pass delivers the final byte — both
        // parts then end on short packets and the device DMA completes.
        if (p_->split_packet && len % p_->out_maxpacket == 0) len -= 1;
        auto result = transfer_bytes(p_->tx_transfer, p_->context, p_->handle, p_->ep_out,
            const_cast<uint8_t*>(data.data() + sent), static_cast<int>(len), deadline, stop);
        const int transferred = result.transferred;
        // log only delivered bytes — a silently NAKed write (stale
        // endpoint state) must not masquerade as a sent frame in traces
        if (transferred > 0 && !sensitive())
            hex_dump("TX", data.data() + sent,
                     static_cast<size_t>(transferred));

        if (result.error == std::errc::no_such_device) p_->gone.store(true);
        if (result.error != std::errc{} || transferred == 0) {
            const auto error = result.error == std::errc{} ? std::errc::io_error : result.error;
            p_->silent = error == std::errc::timed_out;
            return std::unexpected(error);
        }
        sent += static_cast<size_t>(transferred);
    }
    p_->silent = false;
    return {};
}

std::expected<void, std::errc>
UsbTransport::bulk_write_frame(std::span<const uint8_t> frame, Timeout timeout,
                               std::stop_token stop) {
    if (!p_ || !p_->handle) return std::unexpected(std::errc::no_such_device);
    if (frame.empty()) return std::unexpected(std::errc::invalid_argument);
    if (frame.size() > size_t(kBulkTransferSize))
        return std::unexpected(std::errc::message_size);
    auto result = transfer_bytes(p_->tx_transfer, p_->context, p_->handle, p_->ep_out,
        const_cast<uint8_t*>(frame.data()), static_cast<int>(frame.size()), Clock::now() + timeout, stop, true);
    if (result.transferred > 0 && !sensitive()) hex_dump("TX", frame.data(), static_cast<size_t>(result.transferred));
    if (result.error == std::errc::no_such_device) p_->gone = true;
    p_->silent = result.error == std::errc::timed_out;
    if (result.error != std::errc{}) return std::unexpected(result.error);
    if (static_cast<size_t>(result.transferred) != frame.size())
        return std::unexpected(std::errc::io_error);
    return {};
}

std::expected<std::vector<uint8_t>, std::errc>
UsbTransport::bulk_read(size_t max_len, Timeout timeout, std::stop_token stop) {
    if (!p_ || !p_->handle)
        return std::unexpected(std::errc::no_such_device);
    if (stop.stop_requested())
        return std::unexpected(std::errc::interrupted);

    if (!max_len) return std::unexpected(std::errc::invalid_argument);
    const auto deadline = Clock::now() + timeout;
    std::vector<uint8_t> buf(std::min(max_len, size_t(kBulkTransferSize)));
    auto result = transfer_bytes(p_->rx_transfer, p_->context, p_->handle, p_->ep_in, buf.data(),
                                 static_cast<int>(buf.size()), deadline, stop);
    const int transferred = result.transferred;
    if (result.error != std::errc{} && result.error != std::errc::timed_out) {
        if (result.error == std::errc::no_such_device) p_->gone.store(true);
        return std::unexpected(result.error);
    }
    if (transferred <= 0) {
        // Deadline miss with nothing delivered: the device is on the
        // bus but sent nothing — mark it silent (any later successful
        // transfer clears this, so poll-loop misses self-correct).
        p_->silent = true;
        return std::unexpected(std::errc::timed_out);
    }

    buf.resize(static_cast<size_t>(transferred));
    if(!sensitive())hex_dump("RX", buf.data(), buf.size());
    p_->silent = false;
    return buf;
}

std::expected<void, std::errc> UsbTransport::serial_dtr() {
    if (!p_ || !p_->handle)
        return std::unexpected(std::errc::no_such_device);
    // f_serial.c gser_setup: class request 0x22, wValue low byte 1 ->
    // usb_port_open = true; the gadget then reads the PC-tool mode request.
    // wLength 0 -> a plain zero-length status stage.
    int rc = libusb_control_transfer(p_->handle, 0x21, 0x22, 0x0001,
                                     static_cast<uint16_t>(p_->control_interface_number),
                                     nullptr, 0, 1000);
    if (rc < 0)
        return std::unexpected(libusb_to_errc(rc));
    return {};
}

// ----------------------------------------------------------------- context

UsbContext::~UsbContext() = default;

UsbContext& UsbContext::instance() {
    static UsbContext ctx;
    return ctx;
}

std::expected<std::shared_ptr<libusb_context>, std::errc> UsbContext::context() {
    std::lock_guard lock(context_mutex_);
    if (!ctx_) {
        libusb_context* context = nullptr;
        const int rc = libusb_init(&context);
        if (rc != LIBUSB_SUCCESS) return std::unexpected(libusb_to_errc(rc));
        ctx_ = std::shared_ptr<libusb_context>(context, libusb_exit);
    }
    return ctx_;
}

std::expected<std::vector<UsbDevice>, std::errc>
UsbContext::find_devices(std::span<const uint16_t> vids) {
    auto owner = context();
    if (!owner) return std::unexpected(owner.error());
    libusb_device** list = nullptr;
    ssize_t cnt = libusb_get_device_list(owner->get(), &list);
    if (cnt < 0)
        return std::unexpected(libusb_to_errc(static_cast<int>(cnt)));

    const auto free_list = [](libusb_device** devices) { libusb_free_device_list(devices, 1); };
    std::unique_ptr<libusb_device*, decltype(free_list)> owned_list(list, free_list);
    std::vector<UsbDevice> out;
    for (ssize_t i = 0; i < cnt; ++i) {
        libusb_device_descriptor desc{};
        if (libusb_get_device_descriptor(list[i], &desc) != LIBUSB_SUCCESS)
            continue;
        for (uint16_t vid : vids) {
            if (desc.idVendor == vid) {
                // Keep the device alive after free_device_list.
                libusb_ref_device(list[i]);
                UsbDevice d;
                d.context_owner = *owner;
                d.native = std::shared_ptr<libusb_device>(list[i], EnumeratedDevice{*owner, list[i]});
                d.vid = desc.idVendor;
                d.pid = desc.idProduct;
                switch (libusb_get_device_speed(list[i])) {
                case LIBUSB_SPEED_FULL: d.speed = UsbDevice::Full; break;
                case LIBUSB_SPEED_HIGH: d.speed = UsbDevice::High; break;
                case LIBUSB_SPEED_SUPER: case LIBUSB_SPEED_SUPER_PLUS:
                    d.speed = UsbDevice::Super; break;
                default: break;
                }
                uint8_t path[8];
                int n = libusb_get_port_numbers(list[i], path, sizeof(path));
                if (n > 0) {
                    d.port_path.push_back(libusb_get_bus_number(list[i]));
                    d.port_path.insert(d.port_path.end(), path, path + n);
                }
                out.push_back(std::move(d));
                break;
            }
        }
    }
    return out;
}

std::string UsbDevice::path_string() const {
    std::string s;
    for (size_t i = 0; i < port_path.size(); ++i) {
        if (i) s += '.';
        s += std::to_string(port_path[i]);
    }
    return s;
}

std::expected<UsbTransport, std::errc>
UsbContext::open_device(const UsbDevice& device, bool reset_configuration, bool split_packet) {
    auto* dev = device.native.get();
    if (!dev) return std::unexpected(std::errc::no_such_device);
    const auto* source = std::get_deleter<EnumeratedDevice>(device.native);
    const auto& owner = device.context_owner;
    if (!source || source->device != dev || !owner || source->context.get() != owner.get() ||
        source->context.owner_before(owner) || owner.owner_before(source->context))
        return std::unexpected(std::errc::invalid_argument);
    UsbTransport t;
    t.p_->split_packet = split_packet;
    t.p_->context_owner = owner;
    t.p_->context = owner.get();
    int rc = libusb_open(dev, &t.p_->handle);
    if (rc != LIBUSB_SUCCESS) return std::unexpected(libusb_to_errc(rc));
    if (!t.p_->handle) return std::unexpected(std::errc::io_error);
    auto* h = t.p_->handle;

    libusb_config_descriptor* descriptor = nullptr;
    rc = libusb_get_active_config_descriptor(dev, &descriptor);
    if (rc == LIBUSB_ERROR_NOT_FOUND)
        rc = libusb_get_config_descriptor(dev, 0, &descriptor);
    if (rc != LIBUSB_SUCCESS) return std::unexpected(libusb_to_errc(rc));
    std::unique_ptr<libusb_config_descriptor, decltype(&libusb_free_config_descriptor)>
        cfg(descriptor, libusb_free_config_descriptor);

    struct Pair {
        const libusb_interface_descriptor* alt = nullptr;
        uint8_t in = 0, out = 0;
        uint16_t maxpacket = 0;
    } selected;
    for (int i = 0; i < cfg->bNumInterfaces; ++i) {
        Pair candidate;
        for (int j = 0; j < cfg->interface[i].num_altsetting; ++j) {
            const auto& alt = cfg->interface[i].altsetting[j];
            Pair pair{&alt};
            int inputs = 0, outputs = 0;
            for (int k = 0; k < alt.bNumEndpoints; ++k) {
                const auto& ep = alt.endpoint[k];
                if ((ep.bmAttributes & 0x03) != LIBUSB_TRANSFER_TYPE_BULK) continue;
                if (ep.bEndpointAddress & LIBUSB_ENDPOINT_IN) {
                    pair.in = ep.bEndpointAddress;
                    ++inputs;
                } else {
                    pair.out = ep.bEndpointAddress;
                    pair.maxpacket = ep.wMaxPacketSize & 0x7ff;
                    ++outputs;
                }
            }
            if (inputs != 1 || outputs != 1 || pair.maxpacket <= 1) continue;
            // Prefer the reset default alternate setting, otherwise the lowest
            // usable alternate setting. Never combine endpoints across settings.
            if (!candidate.alt || alt.bAlternateSetting < candidate.alt->bAlternateSetting)
                candidate = pair;
        }
        if (!candidate.alt) continue;
        // VID alone cannot identify which of several serial functions speaks BSL.
        // Refuse ambiguity rather than silently talking to the last bulk pair.
        if (selected.alt) return std::unexpected(std::errc::not_supported);
        selected = candidate;
    }
    if (!selected.alt) return std::unexpected(std::errc::not_supported);
    t.p_->interface_number = selected.alt->bInterfaceNumber;
    t.p_->control_interface_number = t.p_->interface_number;
    t.p_->ep_in = selected.in;
    t.p_->ep_out = selected.out;
    t.p_->out_maxpacket = selected.maxpacket;

    // CDC ACM has a separate control interface. Its Union functional descriptor
    // names the data slave; vendor/gser interfaces without a Union use themselves.
    int control = -1;
    for (int i = 0; i < cfg->bNumInterfaces; ++i) {
        for (int j = 0; j < cfg->interface[i].num_altsetting; ++j) {
            const auto& alt = cfg->interface[i].altsetting[j];
            if (alt.bInterfaceClass != LIBUSB_CLASS_COMM || alt.bAlternateSetting != 0) continue;
            for (int offset = 0; offset + 2 <= alt.extra_length;) {
                const auto* extra = alt.extra + offset;
                const int length = extra[0];
                if (length < 2 || length > alt.extra_length - offset) break;
                if (length >= 5 && extra[1] == 0x24 && extra[2] == 0x06 &&
                    extra[3] == alt.bInterfaceNumber) {
                    for (int k = 4; k < length; ++k) {
                        if (extra[k] != t.p_->interface_number) continue;
                        if (control >= 0 && control != alt.bInterfaceNumber)
                            return std::unexpected(std::errc::not_supported);
                        control = alt.bInterfaceNumber;
                    }
                }
                offset += length;
            }
        }
    }
    if (control >= 0) t.p_->control_interface_number = control;
    const bool separate_control = t.p_->control_interface_number != t.p_->interface_number;
    const auto detach = [&](int interface_number, bool& detached) -> std::expected<void, std::errc> {
        int active = libusb_kernel_driver_active(h, interface_number);
        if (active == LIBUSB_ERROR_NOT_SUPPORTED || active == 0) return {};
        if (active < 0) return std::unexpected(libusb_to_errc(active));
        int result = libusb_detach_kernel_driver(h, interface_number);
        if (result != LIBUSB_SUCCESS) return std::unexpected(libusb_to_errc(result));
        detached = true;
        return {};
    };
    if (auto result = detach(t.p_->interface_number, t.p_->detached); !result) return std::unexpected(result.error());
    if (separate_control) {
        if (auto result = detach(control, t.p_->control_detached); !result) return std::unexpected(result.error());
    }
    // Preserve active configuration by default. Reapplying it resets endpoint
    // state and is an explicit firmware quirk, not a universal open operation.
    int active_configuration = 0;
    rc = libusb_get_configuration(h, &active_configuration);
    if (rc != LIBUSB_SUCCESS) return std::unexpected(libusb_to_errc(rc));
    const bool configured = reset_configuration || active_configuration != cfg->bConfigurationValue;
    if (configured) {
        rc = libusb_set_configuration(h, cfg->bConfigurationValue);
        if (rc != LIBUSB_SUCCESS) return std::unexpected(libusb_to_errc(rc));
    }
    rc = libusb_claim_interface(h, t.p_->interface_number);
    if (rc != LIBUSB_SUCCESS) return std::unexpected(libusb_to_errc(rc));
    t.p_->claimed = true;
    if (separate_control) {
        rc = libusb_claim_interface(h, control);
        if (rc != LIBUSB_SUCCESS) return std::unexpected(libusb_to_errc(rc));
        t.p_->control_claimed = true;
    }
    uint8_t active_alt = 0;
    size_t alternatives = 0;
    for (int i = 0; i < cfg->bNumInterfaces; ++i)
        for (int j = 0; j < cfg->interface[i].num_altsetting; ++j)
            if (cfg->interface[i].altsetting[j].bInterfaceNumber == t.p_->interface_number) ++alternatives;
    if (!configured) {
        // With only one descriptor there is no alternate to discover. Minimal
        // ROMs can ignore GET_INTERFACE rather than STALL it; do not introduce
        // an unsupported control request before the first BSL byte.
        if (alternatives == 1) {
            active_alt = selected.alt->bAlternateSetting;
        } else {
        rc = libusb_control_transfer(h, 0x81, LIBUSB_REQUEST_GET_INTERFACE, 0,
            static_cast<uint16_t>(t.p_->interface_number), &active_alt, 1, 1000);
        if (rc != 1) {
            log_diag("{usb} cannot determine active alternate setting: " +
                std::string(rc < 0 ? libusb_error_name(rc) : "short GET_INTERFACE reply"));
            return std::unexpected(rc < 0 ? libusb_to_errc(rc) : std::errc::protocol_error);
        }
        }
    }
    if (active_alt != selected.alt->bAlternateSetting) {
        rc = libusb_set_interface_alt_setting(h, t.p_->interface_number, selected.alt->bAlternateSetting);
        if (rc != LIBUSB_SUCCESS) return std::unexpected(libusb_to_errc(rc));
    }
    return t;
}

}

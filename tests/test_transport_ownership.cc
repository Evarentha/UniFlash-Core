/*
 * UniFlash-Core Test / Transport Ownership
 *
 * Covers enumeration provenance, event context use and sensitive flag moves.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */

#include <uniflash/transport/usb.h>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <type_traits>
#include <utility>

using namespace uniflash::transport;

#ifndef _WIN32
// Link-time libusb doubles. No physical devices or real contexts are used.
// Open is initially denied to distinguish provenance rejection from I/O, then
// enabled to check the event context and cancellation drainage with fake handles.
struct libusb_context { int marker = 0; };
struct libusb_device { libusb_context* context = nullptr; int references = 0; };
struct libusb_device_handle { libusb_device* device; };
namespace {
libusb_device devices[2];
int opens = 0;
int initializations = 0;
bool wrong_context = false;
bool allow_open = false;
bool freed_live_transfer = false;
int cancellations = 0;
int completions = 0;
int closes = 0;
libusb_transfer* pending = nullptr;
std::stop_source* stop_on_submit = nullptr;
}
extern "C" {
int LIBUSB_CALL libusb_init(libusb_context** context) {
    ++initializations;
    *context = new libusb_context;
    for (auto& device : devices) device.context = *context;
    return LIBUSB_SUCCESS;
}
void LIBUSB_CALL libusb_exit(libusb_context* context) { delete context; }
ssize_t LIBUSB_CALL libusb_get_device_list(libusb_context* context, libusb_device*** list) {
    wrong_context |= context != devices[0].context;
    *list = new libusb_device*[3]{&devices[0], &devices[1], nullptr};
    for (auto& device : devices) ++device.references;
    return 2;
}
void LIBUSB_CALL libusb_free_device_list(libusb_device** list, int unref) {
    if (unref) for (size_t i = 0; list[i]; ++i) --list[i]->references;
    delete[] list;
}
libusb_device* LIBUSB_CALL libusb_ref_device(libusb_device* device) {
    ++device->references;
    return device;
}
void LIBUSB_CALL libusb_unref_device(libusb_device* device) { --device->references; }
int LIBUSB_CALL libusb_get_device_descriptor(libusb_device*, libusb_device_descriptor* descriptor) {
    *descriptor = {};
    descriptor->idVendor = 0x1782;
    return LIBUSB_SUCCESS;
}
int LIBUSB_CALL libusb_get_device_speed(libusb_device*) { return LIBUSB_SPEED_HIGH; }
int LIBUSB_CALL libusb_get_port_numbers(libusb_device*, uint8_t* path, int length) {
    if (length < 1) return LIBUSB_ERROR_OVERFLOW;
    path[0] = 1;
    return 1;
}
uint8_t LIBUSB_CALL libusb_get_bus_number(libusb_device*) { return 1; }
int LIBUSB_CALL libusb_open(libusb_device* device, libusb_device_handle** handle) {
    ++opens;
    wrong_context |= device->context != devices[0].context;
    *handle = nullptr;
    if (!allow_open) return LIBUSB_ERROR_ACCESS;
    *handle = new libusb_device_handle{libusb_ref_device(device)};
    return LIBUSB_SUCCESS;
}
void LIBUSB_CALL libusb_close(libusb_device_handle* handle) {
    ++closes;
    libusb_unref_device(handle->device);
    delete handle;
}
int LIBUSB_CALL libusb_get_active_config_descriptor(libusb_device*, libusb_config_descriptor** config) {
    static const auto endpoints = [] {
        std::array<libusb_endpoint_descriptor, 2> value{};
        value[0].bEndpointAddress = 0x81;
        value[1].bEndpointAddress = 0x01;
        for (auto& endpoint : value) {
            endpoint.bmAttributes = LIBUSB_TRANSFER_TYPE_BULK;
            endpoint.wMaxPacketSize = 512;
        }
        return value;
    }();
    static const auto alt = [] {
        libusb_interface_descriptor value{};
        value.bNumEndpoints = 2;
        value.endpoint = endpoints.data();
        return value;
    }();
    static const libusb_interface interface{&alt, 1};
    static auto descriptor = [] {
        libusb_config_descriptor value{};
        value.bNumInterfaces = 1;
        value.bConfigurationValue = 1;
        value.interface = &interface;
        return value;
    }();
    *config = &descriptor;
    return LIBUSB_SUCCESS;
}
void LIBUSB_CALL libusb_free_config_descriptor(libusb_config_descriptor*) {}
int LIBUSB_CALL libusb_kernel_driver_active(libusb_device_handle*, int) { return 0; }
int LIBUSB_CALL libusb_get_configuration(libusb_device_handle*, int* value) {
    *value = 1;
    return LIBUSB_SUCCESS;
}
int LIBUSB_CALL libusb_claim_interface(libusb_device_handle*, int) { return LIBUSB_SUCCESS; }
int LIBUSB_CALL libusb_release_interface(libusb_device_handle*, int) { return LIBUSB_SUCCESS; }
libusb_transfer* LIBUSB_CALL libusb_alloc_transfer(int) {
    return static_cast<libusb_transfer*>(std::calloc(1, sizeof(libusb_transfer)));
}
void LIBUSB_CALL libusb_free_transfer(libusb_transfer* transfer) {
    freed_live_transfer |= pending == transfer;
    std::free(transfer);
}
int LIBUSB_CALL libusb_submit_transfer(libusb_transfer* transfer) {
    pending = transfer;
    transfer->status = LIBUSB_TRANSFER_COMPLETED;
    if (stop_on_submit) stop_on_submit->request_stop();
    return LIBUSB_SUCCESS;
}
int LIBUSB_CALL libusb_cancel_transfer(libusb_transfer* transfer) {
    ++cancellations;
    transfer->status = LIBUSB_TRANSFER_CANCELLED;
    return LIBUSB_SUCCESS;
}
int LIBUSB_CALL libusb_handle_events_timeout_completed(libusb_context* context, timeval*, int*) {
    if (pending) {
        auto* transfer = std::exchange(pending, nullptr);
        wrong_context |= context != transfer->dev_handle->device->context;
        transfer->actual_length = transfer->status == LIBUSB_TRANSFER_COMPLETED ? transfer->length : 0;
        ++completions;
        transfer->callback(transfer);
    }
    return LIBUSB_SUCCESS;
}
void LIBUSB_CALL libusb_lock_events(libusb_context* context) { wrong_context |= context != devices[0].context; }
void LIBUSB_CALL libusb_unlock_events(libusb_context* context) { wrong_context |= context != devices[0].context; }
}
#endif

int main() {
    int failures = 0;
    const auto check = [&](bool ok, const char* message) {
        if (!ok) { std::fprintf(stderr, "FAIL: %s\n", message); ++failures; }
    };
    static_assert(std::is_nothrow_move_assignable_v<UsbTransport>);
    static_assert(std::is_nothrow_move_constructible_v<UsbTransport>);
    static_assert(std::is_aggregate_v<UsbDevice>);

    // Use real transports without handles: the confidentiality state belongs
    // to the channel, and its move contract does not require any device I/O.
    for (bool sensitive : {false, true}) {
        UsbTransport source, destination;
        source.set_sensitive(sensitive);
        destination.set_sensitive(!sensitive);
        auto& assigned = (destination = std::move(source));
        check(&assigned == &destination && destination.sensitive() == sensitive,
            "move assignment transfers sensitive in both directions");
        check(destination.out_maxpacket() != 0 && source.out_maxpacket() == 0,
            "move assignment transfers the implementation owner");
        auto* self = &destination;
        destination = std::move(*self);
        check(destination.sensitive() == sensitive && destination.out_maxpacket() != 0,
            "self move preserves state and implementation owner");
        UsbTransport constructed(std::move(destination));
        check(constructed.sensitive() == sensitive && destination.out_maxpacket() == 0,
            "move construction agrees with assignment");
        destination = std::move(constructed);
        check(destination.sensitive() == sensitive && destination.out_maxpacket() != 0,
            "moved-from transport can receive ownership again");
    }

#ifndef _WIN32
    auto& context = UsbContext::instance();
    const auto rejected = [&](const UsbDevice& device, std::errc error) {
        const int before = opens;
        auto result = context.open_device(device);
        check(!result && result.error() == error && opens == before,
            "invalid provenance is rejected before libusb_open");
    };
    rejected(UsbDevice{}, std::errc::no_such_device);
    UsbDevice external;
    external.native = std::shared_ptr<libusb_device>(&devices[0], [](auto*) {});
    rejected(external, std::errc::invalid_argument);
    check(initializations == 0, "invalid candidate does not initialize a context");

    const uint16_t vendors[]{0x1782};
    auto found = context.find_devices(vendors);
    check(found && found->size() == 2, "mock enumeration returns owned records");
    if (found && found->size() == 2) {
        UsbDevice original = found->front();
        check(original.context_owner && original.context_owner.get() == devices[0].context,
            "enumeration publishes the actual context owner");
        auto copied = original;
        found->clear();
        check(devices[0].references == 1 && devices[1].references == 0,
            "record copies retain one native reference after list release");
        auto moved = std::move(copied);
        const int before = opens;
        auto result = context.open_device(moved);
        check(!result && result.error() == std::errc::permission_denied && opens == before + 1,
            "copied and moved enumeration record reaches the mocked open");

        auto changed = original;
        changed.context_owner.reset();
        rejected(changed, std::errc::invalid_argument);
        changed.context_owner = std::make_shared<libusb_context>();
        rejected(changed, std::errc::invalid_argument);
        changed.context_owner = std::shared_ptr<libusb_context>(original.context_owner.get(), [](auto*) {});
        rejected(changed, std::errc::invalid_argument);
        changed = original;
        changed.native = external.native;
        rejected(changed, std::errc::invalid_argument);
        // An alias keeps the genuine control block/deleter but changes the
        // device pointer. Context equality alone must not authorize it.
        changed.native = std::shared_ptr<libusb_device>(original.native, &devices[1]);
        rejected(changed, std::errc::invalid_argument);
        external.context_owner = original.context_owner;
        rejected(external, std::errc::invalid_argument);

        allow_open = true;
        auto opened = context.open_device(original);
        check(bool(opened), "genuine record opens with mock descriptors");
        if (opened) {
            const uint8_t bytes[]{0x12, 0x34};
            original = {};
            moved = {};
            changed = {};
            external = {};
            check(devices[0].references == 1, "open handle outlives all enumeration records");
            check(bool(opened->bulk_write(bytes)), "transfer completes on the recorded context");
            std::stop_source stop;
            stop_on_submit = &stop;
            auto cancelled = opened->bulk_write(bytes, DEFAULT_TIMEOUT, stop.get_token());
            stop_on_submit = nullptr;
            check(!cancelled && cancelled.error() == std::errc::interrupted &&
                cancellations == 1 && completions == 2 && !pending,
                "cancellation drains its callback on the recorded context");
        }
    }
    check(devices[0].references == 0 && devices[1].references == 0,
        "enumeration native references are balanced");
    check(!wrong_context && initializations == 1, "one correct mock enumeration context");
    check(closes == 1 && !freed_live_transfer, "transport closes after transfer drainage");
#endif
    return failures ? 1 : 0;
}

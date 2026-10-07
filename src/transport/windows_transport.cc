#include <uniflash/transport/usb.h>
#include <uniflash/platform.h>
#include <uniflash/log.h>
#include "windows_io.h"

#include <windows.h>
#include <winioctl.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <initguid.h>
#include <devguid.h>
#include <devpkey.h>
#include <usbiodef.h>
#include <usbioctl.h>
#include <algorithm>
#include <array>
#include <cwctype>
#include <cwchar>
#include <cstdio>
#include <set>

namespace uniflash::transport {
namespace {

struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE handle) : value(handle) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
struct DeviceSet {
    HDEVINFO value;
    explicit DeviceSet(HDEVINFO set) : value(set) {}
    DeviceSet(const DeviceSet&) = delete;
    DeviceSet& operator=(const DeviceSet&) = delete;
    ~DeviceSet() { if (value != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(value); }
};

std::wstring property(HDEVINFO set, SP_DEVINFO_DATA& dev, DWORD key) {
    DWORD bytes = 0, type = 0;
    SetupDiGetDeviceRegistryPropertyW(set, &dev, key, &type, nullptr, 0, &bytes);
    if (!bytes) return {};
    std::vector<wchar_t> value(bytes / sizeof(wchar_t) + 2, 0);
    if (!SetupDiGetDeviceRegistryPropertyW(set, &dev, key, &type,
        reinterpret_cast<BYTE*>(value.data()), bytes, nullptr)) return {};
    // Hardware IDs are a MULTI_SZ; the first is the most specific ID.
    return value.data();
}

std::wstring driver_key(DEVINST instance) {
    ULONG type = 0, bytes = 0;
    CM_Get_DevNode_Registry_PropertyW(instance, CM_DRP_DRIVER, &type, nullptr, &bytes, 0);
    if (!bytes) return {};
    std::vector<wchar_t> text(bytes/sizeof(wchar_t)+1,0);
    if (CM_Get_DevNode_Registry_PropertyW(instance, CM_DRP_DRIVER, &type,
        text.data(), &bytes, 0) != CR_SUCCESS) return {};
    std::wstring key(text.data());
    std::transform(key.begin(),key.end(),key.begin(),[](wchar_t c){return std::towupper(c);});
    return key;
}

void stable_location(DEVINST instance, UsbDevice& result) {
    DEVPROPTYPE type = 0;
    ULONG bytes = 0;
    if (CM_Get_DevNode_PropertyW(instance, &DEVPKEY_Device_LocationPaths,
        &type, nullptr, &bytes, 0) != CR_BUFFER_SMALL || !bytes) return;
    std::vector<wchar_t> paths(bytes / sizeof(wchar_t) + 2, 0);
    if (CM_Get_DevNode_PropertyW(instance, &DEVPKEY_Device_LocationPaths,
        &type, reinterpret_cast<BYTE*>(paths.data()), &bytes, 0) != CR_SUCCESS ||
        type != DEVPROP_TYPE_STRING_LIST) return;
    // The physical USB device ancestor (not its MI_xx function) has a path
    // rooted in host-controller topology, independent of VID/PID/COM number.
    // Canonicalize the MULTI_SZ selection so property ordering cannot change it.
    std::wstring chosen;
    for (const wchar_t* path = paths.data(); *path; path += std::wcslen(path) + 1) {
        std::wstring value(path);
        std::transform(value.begin(), value.end(), value.begin(), [](wchar_t c) { return std::towupper(c); });
        if (value.find(L"USBROOT(") == value.npos || value.find(L"#USB(") == value.npos) continue;
        if (chosen.empty() || value < chosen) chosen = std::move(value);
    }
    if (!chosen.empty()) {
        const auto utf8 = platform::utf8(chosen);
        result.port_path.assign(utf8.begin(), utf8.end());
    }
}

// A COM driver does not expose USB speed. Match its USB ancestor's driver
// key against hub connection records. Speed is telemetry, not a protocol or
// loader identity. Physical identity comes independently
// from the physical USB ancestor's LocationPaths, even if hub access fails.
void usb_location(DEVINST instance, UsbDevice& result) {
    std::set<std::wstring> keys;
    bool found_usb = false;
    for (unsigned depth=0; depth<32; ++depth) {
        wchar_t id[MAX_DEVICE_ID_LEN]{};
        if (CM_Get_Device_IDW(instance,id,MAX_DEVICE_ID_LEN,0)==CR_SUCCESS) {
            std::wstring identity(id);
            std::transform(identity.begin(),identity.end(),identity.begin(),
                           [](wchar_t c){return std::towupper(c);});
            if (identity.starts_with(L"USB\\VID_") && identity.find(L"&MI_")==identity.npos) {
                stable_location(instance, result);
                auto key = driver_key(instance);
                if (!key.empty()) keys.insert(std::move(key));
                found_usb = true;
                break;
            }
        }
        DEVINST parent;
        if (CM_Get_Parent(&parent, instance, 0) != CR_SUCCESS) break;
        instance=parent;
    }
    // Never match a hub/controller ancestor's own key and report its speed.
    if (!found_usb || keys.empty()) return;
    DeviceSet hubs{SetupDiGetClassDevsW(&GUID_DEVINTERFACE_USB_HUB, nullptr, nullptr,
                                       DIGCF_PRESENT | DIGCF_DEVICEINTERFACE)};
    if (hubs.value == INVALID_HANDLE_VALUE) return;
    for (DWORD index=0;;++index) {
        SP_DEVICE_INTERFACE_DATA iface{};
        iface.cbSize=sizeof(iface);
        if (!SetupDiEnumDeviceInterfaces(hubs.value,nullptr,&GUID_DEVINTERFACE_USB_HUB,index,&iface)) break;
        DWORD bytes=0;
        SetupDiGetDeviceInterfaceDetailW(hubs.value,&iface,nullptr,0,&bytes,nullptr);
        std::vector<BYTE> buffer(bytes);
        auto* detail=reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(buffer.data());
        if (bytes<sizeof(*detail)) continue;
        detail->cbSize=sizeof(*detail);
        if (!SetupDiGetDeviceInterfaceDetailW(hubs.value,&iface,detail,bytes,nullptr,nullptr)) continue;
        Handle hub{CreateFileW(detail->DevicePath,GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,
                               nullptr,OPEN_EXISTING,0,nullptr)};
        if (hub.value==INVALID_HANDLE_VALUE) continue;
        USB_NODE_INFORMATION info{};
        info.NodeType=UsbHub;
        DWORD returned=0;
        if (!DeviceIoControl(hub.value,IOCTL_USB_GET_NODE_INFORMATION,&info,sizeof(info),
                              &info,sizeof(info),&returned,nullptr)) continue;
        for (ULONG port=1;port<=info.u.HubInformation.HubDescriptor.bNumberOfPorts;++port) {
            USB_NODE_CONNECTION_DRIVERKEY_NAME header{};
            header.ConnectionIndex=port;
            if (!DeviceIoControl(hub.value,IOCTL_USB_GET_NODE_CONNECTION_DRIVERKEY_NAME,
                &header,sizeof(header),&header,sizeof(header),&returned,nullptr) ||
                header.ActualLength<sizeof(header)) continue;
            std::vector<BYTE> key_bytes(header.ActualLength+sizeof(wchar_t),0);
            auto* key=reinterpret_cast<USB_NODE_CONNECTION_DRIVERKEY_NAME*>(key_bytes.data());
            key->ConnectionIndex=port;
            if (!DeviceIoControl(hub.value,IOCTL_USB_GET_NODE_CONNECTION_DRIVERKEY_NAME,
                key,header.ActualLength,key,header.ActualLength,&returned,nullptr)) continue;
            std::wstring candidate(key->DriverKeyName);
            std::transform(candidate.begin(),candidate.end(),candidate.begin(),
                           [](wchar_t c){return std::towupper(c);});
            if (!keys.contains(candidate)) continue;
            USB_NODE_CONNECTION_INFORMATION_EX connection{};
            connection.ConnectionIndex=port;
            if (DeviceIoControl(hub.value,IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX,
                &connection,sizeof(connection),&connection,sizeof(connection),&returned,nullptr) &&
                connection.ConnectionStatus==DeviceConnected) {
                result.speed = connection.Speed==1 ? UsbDevice::Full :
                               connection.Speed==2 ? UsbDevice::High :
                               connection.Speed>=3 ? UsbDevice::Super : UsbDevice::Unknown;
            }
            return;
        }
    }
}

void trace(const char* tag, std::span<const uint8_t> bytes) {
    if (!log_diag_trace_enabled()) return;
    std::string text="{usb} "+std::string(tag)+" ("+std::to_string(bytes.size())+" B):";
    char hex[4];
    for(size_t i=0;i<std::min<size_t>(64,bytes.size());++i) {
        std::snprintf(hex,sizeof(hex)," %02x",bytes[i]); text+=hex;
    }
    if(bytes.size()>64) text+=" ...("+std::to_string(bytes.size()-64)+" more)";
    log_diag(text);
}

} // namespace

std::expected<DWORD,std::errc> windows_transfer(HANDLE handle, uint8_t* data, DWORD length,
                                       bool writing, Timeout timeout, std::stop_token stop) {
    if (stop.stop_requested()) return std::unexpected(std::errc::interrupted);
    if (timeout.count() <= 0) return std::unexpected(std::errc::timed_out);
    const auto deadline=std::chrono::steady_clock::now()+timeout;
    Handle event{CreateEventW(nullptr,TRUE,FALSE,nullptr)};
    if (!event.value) return std::unexpected(platform::windows_error(GetLastError()));
    OVERLAPPED operation{};
    operation.hEvent=event.value;
    DWORD done=0;
    const BOOL ok=writing ? WriteFile(handle,data,length,&done,&operation)
                          : ReadFile(handle,data,length,&done,&operation);
    if (ok) return done;
    if (GetLastError()!=ERROR_IO_PENDING)
        return std::unexpected(platform::windows_error(GetLastError()));
    for (;;) {
        const auto now=std::chrono::steady_clock::now();
        if(stop.stop_requested() || now>=deadline) {
            CancelIoEx(handle,&operation);
            // OVERLAPPED and buffer must outlive cancellation completion.
            const BOOL completed=GetOverlappedResult(handle,&operation,&done,TRUE);
            const DWORD error=completed?ERROR_SUCCESS:GetLastError();
            // Cancellation can race normal completion. Only successful results
            // have a usable byte count; failure must not turn a partial write
            // into a successful frame or hide a physical disconnect.
            if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
            if(completed && done) return done;
            if(!completed && error!=ERROR_OPERATION_ABORTED)
                return std::unexpected(platform::windows_error(error));
            return std::unexpected(stop.stop_requested()?std::errc::interrupted:std::errc::timed_out);
        }
        const auto left=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-now).count();
        const DWORD wait=WaitForSingleObject(event.value,static_cast<DWORD>(std::clamp<int64_t>(left,1,50)));
        if(wait==WAIT_TIMEOUT) continue;
        if(wait!=WAIT_OBJECT_0) {
            const auto error=platform::windows_error(GetLastError());
            CancelIoEx(handle,&operation);
            GetOverlappedResult(handle,&operation,&done,TRUE);
            return std::unexpected(error);
        }
        if(!GetOverlappedResult(handle,&operation,&done,FALSE))
            return std::unexpected(platform::windows_error(GetLastError()));
        return done;
    }
}

UsbTransport::UsbTransport() : p_(std::make_unique<Impl>()) {}
UsbTransport::Impl::~Impl() {
    if(handle) { CancelIoEx(handle,nullptr); CloseHandle(handle); }
}
UsbTransport::~UsbTransport() = default;
UsbTransport::UsbTransport(UsbTransport&&) noexcept = default;
UsbTransport& UsbTransport::operator=(UsbTransport&& other) noexcept {
    if(this!=&other) {
        UsbTransport old(std::move(*this));
        Transport::operator=(std::move(other));
        p_=std::move(other.p_);
    }
    return *this;
}

std::expected<void,std::errc> UsbTransport::bulk_write(std::span<const uint8_t> bytes,
                                                      Timeout timeout,std::stop_token stop) {
    if(!p_ || !p_->handle) return std::unexpected(std::errc::no_such_device);
    const auto deadline=std::chrono::steady_clock::now()+timeout;
    size_t sent=0;
    while(sent<bytes.size()) {
        if(stop.stop_requested()) return std::unexpected(std::errc::interrupted);
        auto left=std::chrono::duration_cast<Timeout>(deadline-std::chrono::steady_clock::now());
        if(left.count()<=0) { p_->silent=true; return std::unexpected(std::errc::timed_out); }
        size_t length=std::min<size_t>(65536,bytes.size()-sent);
        // Preserve stream splitting, but COM may coalesce/split these writes:
        // this cannot establish USB packet boundaries (raw frames are disabled).
        if(p_->split_packet && length%p_->out_maxpacket==0) --length;
        auto result=windows_transfer(p_->handle,const_cast<uint8_t*>(bytes.data()+sent),
                             static_cast<DWORD>(length),true,left,stop);
        if(!result || *result==0) {
            auto error=result?std::errc::timed_out:result.error();
            if(error==std::errc::no_such_device) p_->gone=true;
            p_->silent=error==std::errc::timed_out;
            return std::unexpected(error);
        }
        if(!sensitive())trace("TX",bytes.subspan(sent,*result));
        sent+=*result;
    }
    p_->silent=false; return {};
}

std::expected<void,std::errc> UsbTransport::bulk_write_frame(std::span<const uint8_t>,
    Timeout, std::stop_token) {
    // A COM driver may split/coalesce WriteFile requests and provides no ZLP
    // control. The device layer must retain escaped framing on this backend.
    return std::unexpected(std::errc::not_supported);
}

std::expected<std::vector<uint8_t>,std::errc> UsbTransport::bulk_read(size_t max_len,
    Timeout timeout,std::stop_token stop) {
    if(!p_ || !p_->handle) return std::unexpected(std::errc::no_such_device);
    if(max_len==0) return std::unexpected(std::errc::invalid_argument);
    std::vector<uint8_t> bytes(std::min<size_t>(65536,max_len));
    auto result=windows_transfer(p_->handle,bytes.data(),static_cast<DWORD>(bytes.size()),false,timeout,stop);
    if(!result || *result==0) {
        auto error=result?std::errc::timed_out:result.error();
        if(error==std::errc::no_such_device) p_->gone=true;
        p_->silent=error==std::errc::timed_out;
        return std::unexpected(error);
    }
    bytes.resize(*result); if(!sensitive())trace("RX",bytes); p_->silent=false; return bytes;
}

std::expected<void,std::errc> UsbTransport::serial_dtr() {
    if(!p_ || !p_->handle) return std::unexpected(std::errc::no_such_device);
    if(!EscapeCommFunction(p_->handle,SETDTR))
        return std::unexpected(platform::windows_error(GetLastError()));
    return {};
}

UsbContext::~UsbContext() = default;
UsbContext& UsbContext::instance() { static UsbContext context; return context; }

std::expected<std::vector<UsbDevice>,std::errc>
UsbContext::find_devices(std::span<const uint16_t> vids) {
    // Vendor serial interfaces can be in Ports or Modem setup classes.
    DeviceSet set{SetupDiGetClassDevsW(nullptr,nullptr,nullptr,DIGCF_PRESENT|DIGCF_ALLCLASSES)};
    if(set.value==INVALID_HANDLE_VALUE) return std::unexpected(platform::windows_error(GetLastError()));
    std::vector<UsbDevice> out;
    for(DWORD index=0;;++index) {
        SP_DEVINFO_DATA dev{};
        dev.cbSize=sizeof(dev);
        if(!SetupDiEnumDeviceInfo(set.value,index,&dev)) {
            const auto error=GetLastError();
            if(error==ERROR_NO_MORE_ITEMS) break;
            return std::unexpected(platform::windows_error(error));
        }
        if (!IsEqualGUID(dev.ClassGuid,GUID_DEVCLASS_PORTS) &&
            !IsEqualGUID(dev.ClassGuid,GUID_DEVCLASS_MODEM)) continue;
        auto id=property(set.value,dev,SPDRP_HARDWAREID);
        std::transform(id.begin(),id.end(),id.begin(),[](wchar_t c){return std::towupper(c);});
        const auto vid_at=id.find(L"VID_"),pid_at=id.find(L"PID_");
        if(vid_at==id.npos || pid_at==id.npos) continue;
        unsigned vid=0,pid=0;
        if(swscanf(id.c_str()+vid_at,L"VID_%4x",&vid)!=1 ||
           swscanf(id.c_str()+pid_at,L"PID_%4x",&pid)!=1 ||
           std::find(vids.begin(),vids.end(),vid)==vids.end()) continue;
        HKEY key=SetupDiOpenDevRegKey(set.value,&dev,DICS_FLAG_GLOBAL,0,DIREG_DEV,KEY_QUERY_VALUE);
        if(key==INVALID_HANDLE_VALUE) continue;
        wchar_t port[257]{}; DWORD size=sizeof(port)-sizeof(wchar_t),type=0;
        const auto rc=RegQueryValueExW(key,L"PortName",nullptr,&type,reinterpret_cast<BYTE*>(port),&size);
        RegCloseKey(key);
        if(rc!=ERROR_SUCCESS || type!=REG_SZ) continue;
        const std::wstring_view port_text(port);
        if(!port_text.starts_with(L"COM") || port_text.size()==3 ||
           !std::all_of(port_text.begin()+3,port_text.end(),[](wchar_t c){return c>=L'0' && c<=L'9';})) continue;
        UsbDevice item;
        item.vid=static_cast<uint16_t>(vid); item.pid=static_cast<uint16_t>(pid);
        item.port_name=platform::utf8(port);
        item.device_path=L"\\\\.\\"+std::wstring(port);
        usb_location(dev.DevInst,item);
        out.push_back(std::move(item));
    }
    return out;
}

std::string UsbDevice::path_string() const {
    return port_path.empty() ? port_name : std::string(port_path.begin(),port_path.end());
}

std::expected<UsbTransport,std::errc> UsbContext::open_device(const UsbDevice& dev, bool reset_configuration, bool split_packet) {
    (void)reset_configuration; // COM does not expose SET_CONFIGURATION.
    Handle file{CreateFileW(dev.device_path.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,
                            OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr)};
    if(file.value==INVALID_HANDLE_VALUE) {
        const auto error=GetLastError();
        return std::unexpected(error==ERROR_FILE_NOT_FOUND || error==ERROR_PATH_NOT_FOUND
            ? std::errc::no_such_device : platform::windows_error(error));
    }
    DCB dcb{}; dcb.DCBlength=sizeof(dcb);
    if(!GetCommState(file.value,&dcb)) return std::unexpected(platform::windows_error(GetLastError()));
    dcb.BaudRate=115200; dcb.ByteSize=8; dcb.Parity=NOPARITY; dcb.StopBits=ONESTOPBIT;
    dcb.fBinary=TRUE; dcb.fParity=FALSE; dcb.fOutxCtsFlow=FALSE; dcb.fOutxDsrFlow=FALSE;
    dcb.fDtrControl=DTR_CONTROL_DISABLE; dcb.fRtsControl=RTS_CONTROL_DISABLE;
    dcb.fOutX=FALSE; dcb.fInX=FALSE; dcb.fNull=FALSE; dcb.fAbortOnError=FALSE;
    dcb.fDsrSensitivity=FALSE; dcb.fErrorChar=FALSE; dcb.fTXContinueOnXoff=TRUE;
    if(!SetCommState(file.value,&dcb)) return std::unexpected(platform::windows_error(GetLastError()));
    // Return buffered bytes immediately, otherwise wait for the first
    // byte; our overlapped deadline and CancelIoEx enforce call timeouts.
    COMMTIMEOUTS timeouts{MAXDWORD,MAXDWORD,MAXDWORD-1,0,0};
    if(!SetCommTimeouts(file.value,&timeouts)) return std::unexpected(platform::windows_error(GetLastError()));
    UsbTransport result;
    result.p_->split_packet = split_packet;
    result.p_->handle=file.value;
    // COM exposes no endpoint descriptor. Unknown uses the conservative full-
    // speed boundary for stream splitting instead of assuming 512.
    // SuperSpeed bulk uses 1024, but this remains a speed-derived estimate.
    result.p_->out_maxpacket=dev.speed==UsbDevice::Super?1024:
                            dev.speed==UsbDevice::High?512:64;
    file.value=INVALID_HANDLE_VALUE;
    if(log_diag_trace_enabled()) log_diag("{usb} opened native COM " + dev.port_name);
    return result;
}

} // namespace uniflash::transport

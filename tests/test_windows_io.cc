/*
 * UniFlash-Core Test / Windows Overlapped I/O
 *
 * Covers the named pipe connection race, timeout and cancellation.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#include "../src/transport/windows_io.h"
#include <array>
#include <future>
#include <uniflash/log.h>

int main() {
    using namespace uniflash::transport;
    using namespace std::chrono_literals;
    const auto name=L"\\\\.\\pipe\\uniflash-io-"+std::to_wstring(GetCurrentProcessId());
    HANDLE server=CreateNamedPipeW(name.c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|
        FILE_FLAG_FIRST_PIPE_INSTANCE,PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT,1,4096,4096,0,nullptr);
    if(server==INVALID_HANDLE_VALUE) return 1;
    HANDLE client=CreateFileW(name.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,
                               FILE_FLAG_OVERLAPPED,nullptr);
    if(client==INVALID_HANDLE_VALUE) { CloseHandle(server); return 1; }
    // A client may connect before ConnectNamedPipe; ERROR_PIPE_CONNECTED
    // is the documented successful race outcome.
    OVERLAPPED connect{}; connect.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    BOOL connected=ConnectNamedPipe(server,&connect);
    DWORD error=connected?ERROR_SUCCESS:GetLastError();
    if(error!=ERROR_SUCCESS && error!=ERROR_PIPE_CONNECTED) {
        CancelIoEx(server,&connect); DWORD done=0;
        GetOverlappedResult(server,&connect,&done,TRUE);
        CloseHandle(connect.hEvent); CloseHandle(client); CloseHandle(server); return 1;
    }
    CloseHandle(connect.hEvent);
    int failures=0;
    auto check=[&](bool ok,const char* text) { if(!ok) { uniflash::log_err(text); ++failures; } };
    std::array<uint8_t,32> buffer{};
    auto result=windows_transfer(server,buffer.data(),buffer.size(),false,5ms,{});
    check(!result && result.error()==std::errc::timed_out,"pending read times out and drains cancellation");

    std::stop_source source;
    auto pending=std::async(std::launch::async,[&] {
        return windows_transfer(server,buffer.data(),buffer.size(),false,10s,source.get_token());
    });
    source.request_stop();
    check(pending.wait_for(2s)==std::future_status::ready,"cancelled read returns promptly");
    auto cancelled=pending.get();
    check(!cancelled && cancelled.error()==std::errc::interrupted,"cancel returns interrupted");

    std::array<uint8_t,3> data{0x7e,0x7d,0xff};
    auto sent=windows_transfer(client,data.data(),data.size(),true,1s,{});
    check(sent && *sent==3,"write exact bytes");
    result=windows_transfer(server,buffer.data(),buffer.size(),false,1s,{});
    check(result && *result==3 && std::equal(data.begin(),data.end(),buffer.begin()),
          "partial read succeeds after previous cancellations without stale operation");
    CloseHandle(client);
    result=windows_transfer(server,buffer.data(),buffer.size(),false,1s,{});
    check(!result,"disconnected peer returns an error");
    CloseHandle(server);
    return failures?1:0;
}

/*
 * UniFlash-Core Test / CLI Input
 *
 * Covers input statuses, injected I/O errors and interruption.
 *
 * Authors:
 * worryzu <worryzu@gmail.com> @LinearTeam
 *
 * Copyright (C) 2026 Evarentha
 * SPDX-License-Identifier: Apache-2.0
 */
#include "../src/cli/input.h"
#include <uniflash/cli/line_editor.h>
#include <uniflash/cli/signal.h>
#include <cerrno>
#include <string>
#include <system_error>
#ifndef _WIN32
#include <unistd.h>
#endif

namespace {
using uniflash::cli::detail::InputStatus;
using uniflash::cli::detail::read_line;

// Fault injection into the same line accumulator used by both OS backends.
bool check_terminal_event(const std::string& prefix, InputStatus terminal, bool fail) {
    std::string out="old output";
    size_t at=0;
    bool dispatched=false;
    try {
        const auto result=read_line(out,[&](char& c) {
            if(at<prefix.size()) {c=prefix[at++];return InputStatus::Byte;}
            if(fail)throw std::system_error(EIO,std::generic_category(),"injected stdin read failure");
            return terminal;
        });
        dispatched=result==InputStatus::Byte;
        if(fail)return false;
        if(terminal==InputStatus::Interrupted)return !dispatched && out.empty();
        return dispatched==!prefix.empty() && out==prefix;
    } catch(const std::system_error& error) {
        return fail && !dispatched && out.empty() && error.code().value()==EIO;
    }
}

// Exercise OS EOF/error handling through the actual LineEditor API. No shell
// commands, device transports, or external executables are involved.
bool check_native_input() {
    using uniflash::cli::LineEditor;
    LineEditor editor;
    std::string line;
#ifdef _WIN32
    const auto saved=GetStdHandle(STD_INPUT_HANDLE);
    struct Restore { HANDLE saved; ~Restore(){SetStdHandle(STD_INPUT_HANDLE,saved);} } restore{saved};
    HANDLE reader=nullptr,writer=nullptr;
    if(!CreatePipe(&reader,&writer,nullptr,0))return false;
    struct Close {HANDLE handle;~Close(){CloseHandle(handle);}} close_reader{reader};
    DWORD count=0;
    const bool written=WriteFile(writer,"reboot",6,&count,nullptr)!=0;
    CloseHandle(writer);
    if(!written || count!=6 || !SetStdHandle(STD_INPUT_HANDLE,reader))return false;
#else
    const auto saved=dup(STDIN_FILENO);
    if(saved<0)return false;
    struct Restore {int saved;~Restore(){dup2(saved,STDIN_FILENO);close(saved);}} restore{saved};
    int pipe_fd[2];
    if(pipe(pipe_fd)!=0)return false;
    const auto count=write(pipe_fd[1],"reboot",6);
    close(pipe_fd[1]);
    const auto replaced=dup2(pipe_fd[0],STDIN_FILENO);
    close(pipe_fd[0]);
    if(count!=6 || replaced<0)return false;
#endif
    if(editor.read("",line)!=LineEditor::Result::Ok || line!="reboot")return false;
    if(editor.read("",line)!=LineEditor::Result::Eof || !line.empty())return false;
#ifdef _WIN32
    if(!SetStdHandle(STD_INPUT_HANDLE,INVALID_HANDLE_VALUE))return false;
#else
    close(STDIN_FILENO);
#endif
    line="must be cleared";
    try { (void)editor.read("",line);return false; }
    catch(const std::system_error& error) {
#ifdef _WIN32
        if(error.code().value()!=ERROR_INVALID_HANDLE)return false;
#else
        if(error.code().value()!=EBADF)return false;
#endif
        if(!line.empty())return false;
    }
    uniflash::cli::interrupt_from_console();
    const auto result=editor.read("",line);
    uniflash::cli::rotate_stop_source();
    return result==LineEditor::Result::Interrupted && line.empty();
}
}

int main() {
    uniflash::cli::SignalHandler signal_handler;
    for(const std::string prefix:{"","reboot"}) {
        if(!check_terminal_event(prefix,InputStatus::Eof,true) ||
           !check_terminal_event(prefix,InputStatus::Eof,false) ||
           !check_terminal_event(prefix,InputStatus::Interrupted,false))return 1;
    }
    std::string out;
    unsigned step=0;
    if(read_line(out,[&](char& c){
        if(step++==0)return InputStatus::Timeout;
        c='\n';return InputStatus::Byte;
    })!=InputStatus::Byte || !out.empty())return 1;
#ifdef _WIN32
    using uniflash::cli::detail::windows_read_status;
    for(const DWORD error:{ERROR_BROKEN_PIPE,ERROR_HANDLE_EOF})
        if(windows_read_status(false,0,error,false)!=InputStatus::Eof)return 1;
    if(windows_read_status(true,0,0,false)!=InputStatus::Eof ||
       windows_read_status(false,0,ERROR_OPERATION_ABORTED,true)!=InputStatus::Interrupted)return 1;
    for(const DWORD code:{ERROR_ACCESS_DENIED,ERROR_INVALID_HANDLE,ERROR_OPERATION_ABORTED,ERROR_NO_DATA}) {
        try {(void)windows_read_status(false,0,code,false);return 1;}
        catch(const std::system_error& error){if(error.code().value()!=static_cast<int>(code))return 1;}
    }
#endif
    return check_native_input()?0:1;
}

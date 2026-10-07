#pragma once
#ifdef _WIN32
#include <windows.h>

namespace uniflash::cli {
// This is a line-oriented shell, not a mouse-driven terminal application.
// Let conhost/Windows Terminal own wheel scrolling, including during commands.
// ReadConsoleInputW consumes KEY_EVENT records, not VT input escape sequences.
inline constexpr DWORD shell_input_mode(DWORD mode) {
    return mode & ~(ENABLE_MOUSE_INPUT | ENABLE_VIRTUAL_TERMINAL_INPUT);
}
class ConsoleInputMode {
public:
    ConsoleInputMode():input_(GetStdHandle(STD_INPUT_HANDLE)) {
        active_=GetConsoleMode(input_,&saved_) && SetConsoleMode(input_,shell_input_mode(saved_));
    }
    ~ConsoleInputMode(){if(active_)SetConsoleMode(input_,saved_);}
    ConsoleInputMode(const ConsoleInputMode&)=delete;
    ConsoleInputMode& operator=(const ConsoleInputMode&)=delete;
private:
    HANDLE input_;
    DWORD saved_=0;
    bool active_=false;
};
static_assert(!(shell_input_mode(ENABLE_MOUSE_INPUT | ENABLE_VIRTUAL_TERMINAL_INPUT) &
    (ENABLE_MOUSE_INPUT | ENABLE_VIRTUAL_TERMINAL_INPUT)));
static_assert(shell_input_mode(ENABLE_PROCESSED_INPUT | ENABLE_QUICK_EDIT_MODE)==
    (ENABLE_PROCESSED_INPUT | ENABLE_QUICK_EDIT_MODE));
}
#endif

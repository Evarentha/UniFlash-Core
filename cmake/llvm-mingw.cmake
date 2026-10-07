#
# UniFlash-Core Cross Toolchain
#
# Configures a Windows x64 build from an extracted LLVM-MinGW release.
#
# Authors:
# worryzu <worryzu@gmail.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: Apache-2.0

# cmake -S . -B build-win -G Ninja -DCMAKE_TOOLCHAIN_FILE=cmake/llvm-mingw.cmake
# Set LLVM_MINGW_ROOT in the environment to an extracted LLVM-MinGW release.
set(CMAKE_SYSTEM_NAME Windows)
if(NOT DEFINED ENV{LLVM_MINGW_ROOT})
    message(FATAL_ERROR "Set LLVM_MINGW_ROOT to the LLVM-MinGW toolchain directory")
endif()
set(CMAKE_CXX_COMPILER "$ENV{LLVM_MINGW_ROOT}/bin/x86_64-w64-mingw32-clang++")
set(CMAKE_RC_COMPILER "$ENV{LLVM_MINGW_ROOT}/bin/x86_64-w64-mingw32-windres")

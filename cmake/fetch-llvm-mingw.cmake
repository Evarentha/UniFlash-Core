#
# UniFlash-Core Toolchain Fetch
#
# Downloads and verifies the pinned LLVM-MinGW release.
#
# Authors:
# worryzu <worryzu@gmail.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: Apache-2.0
# cmake -P cmake/fetch-llvm-mingw.cmake
# Pin both origin and content. No compiler or target executable is run here.
set(version 20260922)
set(name "llvm-mingw-${version}-ucrt-ubuntu-22.04-x86_64")
if(NOT DEFINED TOOLCHAIN_CACHE)
    set(TOOLCHAIN_CACHE "$ENV{HOME}/.cache/uniflash/toolchains")
endif()
file(MAKE_DIRECTORY "${TOOLCHAIN_CACHE}")
file(DOWNLOAD
    "https://github.com/mstorsjo/llvm-mingw/releases/download/${version}/${name}.tar.xz"
    "${TOOLCHAIN_CACHE}/${name}.tar.xz"
    EXPECTED_HASH SHA256=bb7bb7654b33d5aa8712acb837c963b2e0c56352560c76105270a3268c665c21
    TLS_VERIFY ON STATUS download_status)
list(GET download_status 0 error)
if(error)
    message(FATAL_ERROR "LLVM-MinGW download failed: ${download_status}")
endif()
file(ARCHIVE_EXTRACT INPUT "${TOOLCHAIN_CACHE}/${name}.tar.xz" DESTINATION "${TOOLCHAIN_CACHE}")
message(STATUS "LLVM_MINGW_ROOT=${TOOLCHAIN_CACHE}/${name}")

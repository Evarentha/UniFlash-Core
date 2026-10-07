#
# UniFlash-Core Test / CLI Stages
#
# Runs the CLI against staged loader files in a temporary home directory.
#
# Authors:
# worryzu <worryzu@gmail.com> @LinearTeam
#
# Copyright (C) 2026 Evarentha
# SPDX-License-Identifier: Apache-2.0

if(NOT DEFINED BIN OR NOT DEFINED TEST_ROOT)
    message(FATAL_ERROR "BIN and TEST_ROOT are required")
endif()

string(RANDOM LENGTH 12 ALPHABET 0123456789abcdef run_id)
set(home "${TEST_ROOT}/cli-stages-${run_id}")
file(MAKE_DIRECTORY "${home}")
set(ENV{USERPROFILE} "${home}")

# Each rejected command must stop an argv script before the following help
# command runs. A nonexistent image additionally verifies rejection occurs
# before the handler attempts file access. No test connects to USB.
foreach(line IN ITEMS "write dtbo missing.bin" "write-rename boot missing.bin" "restore-raw miscdata missing.bin" "read dtbo" "erase dtbo" "erase userdata" "reboot recovery-wipe"
        "dump" "read all" "read all output" "restore-raw backup-dir" "write images" "write missing.xml" "write missing.XML" "write missing.PAC" "write missing.pac" "write missing.PAC config.xml" "repartition missing.xml" "parts"
        "firstmode 0" "enable-write"
        "reboot" "reboot recovery" "reboot sideload"
        "reboot sideload-auto-reboot" "reboot rescue" "reboot fastbootd" "poweroff" "ddrtest"
        "load-fdl1 missing.bin 0x100" "load-fdl2 missing.bin 0x100"
        "load-fdl missing.bin 0x100 missing.bin 0x200"
        "download missing.bin 0x100" "load-bin missing.bin 0x100" "exec 0x100")
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env "HOME=${home}" --unset=UNIFLASH_TRACE
            "${BIN}" "${line}" "help"
        RESULT_VARIABLE status OUTPUT_VARIABLE out ERROR_VARIABLE err
        TIMEOUT 5)
    string(REGEX MATCH "^[^ ]+" command "${line}")
    if(NOT status EQUAL 2 OR
       NOT err STREQUAL "[!] ${command}: unavailable at offline\n" OR
       NOT out STREQUAL "> ${line}\n")
        message(FATAL_ERROR "stage rejection failed: ${line}; status=${status}\n${out}\n${err}")
    endif()
endforeach()

# Removed commands must not be accepted as aliases or reach file/device I/O.
foreach(line IN ITEMS "flash missing.pac" "datetime test" "set-debuginfo enable")
string(REGEX MATCH "^[^ ]+" command "${line}")
execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "HOME=${home}" --unset=UNIFLASH_TRACE
        "${BIN}" "${line}" "help"
    RESULT_VARIABLE status OUTPUT_VARIABLE out ERROR_VARIABLE err TIMEOUT 5)
if(NOT status EQUAL 2 OR NOT err STREQUAL "[!] unknown command '${command}' (try 'help')\n" OR
    NOT out STREQUAL "> ${line}\n")
    message(FATAL_ERROR "removed command was not rejected: ${line}; ${status}\n${out}\n${err}")
endif()
endforeach()

# Invalid PC-tool inputs must fail before opening a USB device or waiting
# for the boot window. No valid pc-mode action is run by this test.
foreach(line IN ITEMS "pc-mode" "pc-mode 0" "pc-mode -1" "pc-mode 0x42"
        "pc-mode 0x57" "pc-mode 256" "pc-mode 0x102" "pc-mode 2junk"
        "pc-mode 2 extra" "pc-mode 9999999999999999999999" "kick 2"
        "reboot typo" "reboot recovery extra" "reboot \"\"" "decrypt-image a b c invalid" "decrypt-image a b c"
        "unpack-image a b sci1 invalid" "unpack-image a b" 
        "decrypt-image a b c 0000000000000000000000000000000000000000000000000000000000000000 unknown"
        "unpack-image a b unknown 0000000000000000000000000000000000000000000000000000000000000000")
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env "HOME=${home}" --unset=UNIFLASH_TRACE
            "${BIN}" "${line}" "help"
        RESULT_VARIABLE status OUTPUT_VARIABLE out ERROR_VARIABLE err TIMEOUT 5)
    if(NOT status EQUAL 2 OR NOT out STREQUAL "> ${line}\n" OR NOT err MATCHES "\\[!\\]")
        message(FATAL_ERROR "invalid PC-tool input was not rejected: ${line}; ${status}\n${out}\n${err}")
    endif()
endforeach()

execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "HOME=${home}" --unset=UNIFLASH_TRACE
        "${BIN}" "info" "quit"
    RESULT_VARIABLE status OUTPUT_VARIABLE out ERROR_VARIABLE err TIMEOUT 5)
if(NOT status EQUAL 0 OR NOT err STREQUAL "" OR NOT out MATCHES "stage +: offline")
    message(FATAL_ERROR "offline info failed: ${status}\n${out}\n${err}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "HOME=${home}" --unset=UNIFLASH_TRACE
        "${BIN}" "help" "quit"
    RESULT_VARIABLE status OUTPUT_VARIABLE out ERROR_VARIABLE err TIMEOUT 5)
if(NOT status EQUAL 0 OR NOT err STREQUAL "")
    message(FATAL_ERROR "universal commands failed: ${status}\n${err}")
endif()
if(out MATCHES "recovery-wipe")
    message(FATAL_ERROR "internal recovery wipe target leaked into help")
endif()
if(out MATCHES "datetime|set-debuginfo")
    message(FATAL_ERROR "removed firmware commands leaked into help")
endif()
if(out MATCHES "dump ")
    message(FATAL_ERROR "hidden dump alias leaked into help")
endif()
if(out MATCHES "flash <" OR
    NOT out MATCHES "write <config.xml> +" OR
    NOT out MATCHES "write <package.pac> +" OR
    NOT out MATCHES "FDL1/SPRD4" OR
    NOT out MATCHES "\nConnection\n" OR
    NOT out MATCHES "\nLoaders\n" OR
    NOT out MATCHES "\nPartitions \\(FDL2\\)\n" OR
    NOT out MATCHES "read all \\[dir\\]" OR
    NOT out MATCHES "write <dir>" OR
    NOT out MATCHES "Shortcuts: r = read, w = write, e = erase")
    message(FATAL_ERROR "help is missing command stage metadata\n${out}")
endif()

# A piped session is a script: stop immediately on a rejected command.
file(WRITE "${home}/commands.txt" "reboot\nhelp\nquit\n")
execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env "HOME=${home}" --unset=UNIFLASH_TRACE "${BIN}"
    INPUT_FILE "${home}/commands.txt"
    RESULT_VARIABLE status OUTPUT_VARIABLE out ERROR_VARIABLE err TIMEOUT 5)
if(NOT status EQUAL 2 OR NOT err STREQUAL "[!] reboot: unavailable at offline\n" OR
   out MATCHES "help +command reference")
    message(FATAL_ERROR "piped rejection failed: ${status}\n${out}\n${err}")
endif()

file(REMOVE_RECURSE "${home}")
message(STATUS "CLI stage checks passed")

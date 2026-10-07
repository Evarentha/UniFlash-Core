cmake_minimum_required(VERSION 3.28)
project(UniFlash-Core VERSION 1.0.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)
find_package(Threads REQUIRED)

# Identify the exact configured source snapshot in diagnostic logs. CMake
# reconfigures when any source/header changes; no Git checkout is required.
file(GLOB_RECURSE UNIFLASH_ID_INPUTS CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cc" "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")
list(SORT UNIFLASH_ID_INPUTS)
list(APPEND UNIFLASH_ID_INPUTS "${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists.txt"
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.h.in")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${UNIFLASH_ID_INPUTS})
set(UNIFLASH_SOURCE_DIGEST "")
foreach(input IN LISTS UNIFLASH_ID_INPUTS)
    file(SHA256 "${input}" digest)
    string(APPEND UNIFLASH_SOURCE_DIGEST "${digest}")
endforeach()
string(SHA256 UNIFLASH_BUILD_ID "${UNIFLASH_SOURCE_DIGEST}")
string(SUBSTRING "${UNIFLASH_BUILD_ID}" 0 16 UNIFLASH_BUILD_ID)
configure_file(cmake/version.h.in generated/uniflash/version.h @ONLY)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /utf-8 /permissive-)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Wno-deprecated-declarations)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT WIN32)
        add_compile_options(-g -O0 -fsanitize=address -fsanitize=undefined)
        add_link_options(-fsanitize=address -fsanitize=undefined)
    endif()
endif()

if(WIN32)
    add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0602)
    if(MINGW)
        # LLVM-MinGW otherwise requires libc++.dll/libunwind.dll beside
        # every executable. Native Windows DLL imports remain dynamic.
        add_link_options(-static)
    endif()
endif()

add_library(uniflash_core STATIC
    src/platform.cc
    src/checksum.cc
    src/sha256.cc
    src/log.cc
    src/protocol/bsl.cc
    src/protocol/session.cc
    src/protocol/pctool.cc
    src/protocol/ram_frame.cc
)
add_library(UniFlash::Core ALIAS uniflash_core)
set_target_properties(uniflash_core PROPERTIES EXPORT_NAME Core)
target_compile_features(uniflash_core PUBLIC cxx_std_23)
target_link_libraries(uniflash_core PUBLIC Threads::Threads)
if(NOT WIN32 AND CMAKE_BUILD_TYPE STREQUAL "Debug" AND
   CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_link_options(uniflash_core INTERFACE -fsanitize=address -fsanitize=undefined)
endif()

if(WIN32)
    target_sources(uniflash_core PRIVATE src/transport/windows_transport.cc)
    target_link_libraries(uniflash_core PUBLIC setupapi cfgmgr32 advapi32 bcrypt)
else()
    find_package(PkgConfig REQUIRED)
    find_package(OpenSSL REQUIRED COMPONENTS Crypto)
    pkg_check_modules(LIBUSB REQUIRED IMPORTED_TARGET libusb-1.0)
    target_sources(uniflash_core PRIVATE src/transport/usb_transport.cc)
    target_link_libraries(uniflash_core PUBLIC PkgConfig::LIBUSB)
    target_link_libraries(uniflash_core PRIVATE OpenSSL::Crypto)
endif()
target_sources(uniflash_core PRIVATE
    src/device/sprd_device.cc
    src/device/package_commands.cc
    src/device/raw_recovery.cc
    src/session/pac_parser.cc
    src/session/pac_archive.cc
    src/session/pac_table.cc
    src/session/pac_layout.cc
    src/layout/partition_table.cc
    src/session/boot_message.cc
    src/session/boot_image.cc
    src/session/signed_image.cc
    src/session/packed_image.cc
    src/session/raw_image_contract.cc
    src/session/readback.cc
    src/session/pac_image_contract.cc
    src/session/sparse.cc
    src/session/image.cc
    src/session/decrypt.cc
    src/session/output.cc
    src/session/operations.cc
    src/session/pac_execution.cc
    src/session/pac_config.cc
    src/session/authentication.cc
    src/session/connection.cc
    src/layout/disk_layout.cc
    src/session/miscdata.cc
    src/session/nv_image.cc
    src/session/nv_restore.cc
    src/session/physical_access.cc
    src/session/rename_write.cc
    src/session/raw_backup.cc
    src/session/backup_bundle.cc
    src/session/restore_manifest.cc
    src/session/raw_directory_restore.cc
)

target_include_directories(uniflash_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

add_executable(uniflash-core
    src/cli.cc
    src/cli/signal.cc
    src/cli/line_editor.cc
    # The CLI exposes a built-in protocol-test command even without CTest.
    src/protocol/test_bsl.cc
)
target_link_libraries(uniflash-core PRIVATE uniflash_core)
if(WIN32)
    target_link_libraries(uniflash-core PRIVATE shell32)
endif()

if(BUILD_TESTING)
add_executable(test_transport_ownership tests/test_transport_ownership.cc)
target_link_libraries(test_transport_ownership PRIVATE uniflash_core)
add_test(NAME transport-ownership COMMAND test_transport_ownership)
add_executable(test_file_boundaries tests/test_file_boundaries.cc)
target_link_libraries(test_file_boundaries PRIVATE uniflash_core)
add_test(NAME file-boundaries COMMAND test_file_boundaries)
add_executable(test_cli_input tests/test_cli_input.cc src/cli/line_editor.cc src/cli/signal.cc)
target_link_libraries(test_cli_input PRIVATE uniflash_core)
add_test(NAME cli-input COMMAND test_cli_input)
add_executable(test_history tests/test_history.cc src/cli/line_editor.cc src/cli/signal.cc)
target_link_libraries(test_history PRIVATE uniflash_core)
add_test(NAME history COMMAND test_history)
add_executable(test_whole_file_policy tests/test_whole_file_policy.cc)
target_link_libraries(test_whole_file_policy PRIVATE uniflash_core)
add_test(NAME whole-file-policy COMMAND test_whole_file_policy)
add_executable(test_pac_config tests/test_pac_config.cc)
target_link_libraries(test_pac_config PRIVATE uniflash_core)
if(NOT WIN32)
    target_link_libraries(test_pac_config PRIVATE OpenSSL::Crypto)
endif()
add_test(NAME pac-config COMMAND test_pac_config)
add_executable(test_package_commands tests/test_package_commands.cc)
target_link_libraries(test_package_commands PRIVATE uniflash_core)
add_test(NAME package-commands COMMAND test_package_commands)
add_executable(test_pac_execution tests/test_pac_execution.cc)
target_link_libraries(test_pac_execution PRIVATE uniflash_core)
add_test(NAME pac-execution COMMAND test_pac_execution)
add_executable(test_boot_image tests/test_boot_image.cc)
target_link_libraries(test_boot_image PRIVATE uniflash_core)
add_test(NAME boot-image COMMAND test_boot_image)
add_executable(test_decrypt tests/test_decrypt.cc)
target_link_libraries(test_decrypt PRIVATE uniflash_core)
add_test(NAME decrypt COMMAND test_decrypt)
add_executable(test_sha256 tests/test_sha256.cc)
target_link_libraries(test_sha256 PRIVATE uniflash_core)
add_test(NAME sha256 COMMAND test_sha256)
add_executable(test_restore_manifest tests/test_restore_manifest.cc)
target_link_libraries(test_restore_manifest PRIVATE uniflash_core)
add_test(NAME restore-manifest COMMAND test_restore_manifest)
add_executable(test_pac_relocation tests/test_pac_relocation.cc)
target_link_libraries(test_pac_relocation PRIVATE uniflash_core)
add_test(NAME pac-relocation COMMAND test_pac_relocation)
add_executable(test_nv_restore tests/test_nv_restore.cc)
target_link_libraries(test_nv_restore PRIVATE uniflash_core)
add_test(NAME nv-restore COMMAND test_nv_restore)
add_executable(test_pac_layout tests/test_pac_layout.cc)
target_link_libraries(test_pac_layout PRIVATE uniflash_core)
add_test(NAME pac-layout COMMAND test_pac_layout)
add_executable(test_nv_image tests/test_nv_image.cc)
target_link_libraries(test_nv_image PRIVATE uniflash_core)
add_test(NAME nv-image COMMAND test_nv_image)
add_executable(test_pac_archive tests/test_pac_archive.cc)
target_link_libraries(test_pac_archive PRIVATE uniflash_core)
add_test(NAME pac-archive COMMAND test_pac_archive)
add_executable(test_ram_frame tests/test_ram_frame.cc)
target_link_libraries(test_ram_frame PRIVATE uniflash_core)
add_test(NAME ram-frame COMMAND test_ram_frame)
add_executable(test_rename_write tests/test_rename_write.cc)
target_link_libraries(test_rename_write PRIVATE uniflash_core)
add_test(NAME rename-write COMMAND test_rename_write)
add_executable(test_miscdata tests/test_miscdata.cc)
target_link_libraries(test_miscdata PRIVATE uniflash_core)
add_test(NAME miscdata COMMAND test_miscdata)
add_executable(test_erase_interrupt tests/test_erase_interrupt.cc src/cli/signal.cc)
target_link_libraries(test_erase_interrupt PRIVATE uniflash_core)
add_test(NAME erase-interrupt COMMAND test_erase_interrupt)
add_executable(test_bootrom_reconnect tests/test_bootrom_reconnect.cc)
target_link_libraries(test_bootrom_reconnect PRIVATE uniflash_core)
add_test(NAME bootrom-reconnect COMMAND test_bootrom_reconnect)
add_executable(test_audit_regressions tests/test_audit_regressions.cc)
target_link_libraries(test_audit_regressions PRIVATE uniflash_core)
add_test(NAME audit-regressions COMMAND test_audit_regressions)
add_test(NAME protocol-test COMMAND uniflash-core protocol-test)

add_executable(test_add_checksum tests/test_add_checksum.cc)
target_link_libraries(test_add_checksum PRIVATE uniflash_core)
add_test(NAME add-checksum-test COMMAND test_add_checksum)

add_executable(test_pctool tests/test_pctool.cc)
target_link_libraries(test_pctool PRIVATE uniflash_core)
add_test(NAME pctool-test COMMAND test_pctool)

if(NOT WIN32)
    add_executable(test_log_progress tests/test_log_progress.cc)
    target_link_libraries(test_log_progress PRIVATE uniflash_core)
    add_test(NAME log-progress-test COMMAND test_log_progress)
endif()

add_executable(test_packed_image tests/test_packed_image.cc)
target_link_libraries(test_packed_image PRIVATE uniflash_core)
add_test(NAME packed-image COMMAND test_packed_image)
add_executable(test_command_policy tests/test_command_policy.cc)
target_link_libraries(test_command_policy PRIVATE uniflash_core)
add_test(NAME command-policy-test COMMAND test_command_policy)
add_test(NAME cli-stage-test COMMAND ${CMAKE_COMMAND}
    "-DBIN=$<TARGET_FILE:uniflash-core>"
    "-DTEST_ROOT=${CMAKE_CURRENT_BINARY_DIR}"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_cli_stages.cmake")

add_executable(test_fdl2_commands tests/test_fdl2_commands.cc)
target_link_libraries(test_fdl2_commands PRIVATE uniflash_core)
add_test(NAME fdl2-commands-test COMMAND test_fdl2_commands)
add_executable(test_boot_message tests/test_boot_message.cc)
target_link_libraries(test_boot_message PRIVATE uniflash_core)
add_test(NAME boot-message-test COMMAND test_boot_message)
add_executable(test_repartition tests/test_repartition.cc)
target_link_libraries(test_repartition PRIVATE uniflash_core)
add_test(NAME repartition-test COMMAND test_repartition)
add_executable(test_device_stages tests/test_device_stages.cc)
target_link_libraries(test_device_stages PRIVATE uniflash_core)
add_test(NAME device-stage-test COMMAND test_device_stages)
add_executable(test_platform tests/test_platform.cc)
target_link_libraries(test_platform PRIVATE uniflash_core)
add_test(NAME platform-test COMMAND test_platform)
if(WIN32)
    add_executable(test_windows_io tests/test_windows_io.cc)
    target_link_libraries(test_windows_io PRIVATE uniflash_core)
    add_test(NAME windows-io-test COMMAND test_windows_io)
endif()
endif()

install(TARGETS uniflash-core
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(TARGETS uniflash_core EXPORT UniFlashCoreTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    PATTERN "cli" EXCLUDE
    PATTERN "tests.h" EXCLUDE)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/generated/uniflash/version.h"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/uniflash")
set(UNIFLASH_CONFIG_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/UniFlashCore")
configure_package_config_file(cmake/UniFlashCoreConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/UniFlashCoreConfig.cmake"
    INSTALL_DESTINATION "${UNIFLASH_CONFIG_INSTALL_DIR}")
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/UniFlashCoreConfigVersion.cmake"
    VERSION ${PROJECT_VERSION} COMPATIBILITY ExactVersion)
install(EXPORT UniFlashCoreTargets NAMESPACE UniFlash::
    DESTINATION "${UNIFLASH_CONFIG_INSTALL_DIR}")
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/UniFlashCoreConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/UniFlashCoreConfigVersion.cmake"
    DESTINATION "${UNIFLASH_CONFIG_INSTALL_DIR}")

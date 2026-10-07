<!--
UniFlash-Core User Guide

Introduction, build instructions, usage workflow and the main commands.

Authors:
worryzu <worryzu@gmail.com> @LinearTeam

Copyright (C) 2026 Evarentha
SPDX-License-Identifier: Apache-2.0
-->

# UniFlash-Core

**English** | [简体中文](README.zh-CN.md)

UniFlash-Core is a command-line flashing tool for Unisoc / Spreadtrum devices, providing FDL loading, partition I/O, PAC flashing, storage backups, and physical restoration. The executable is `uniflash-core` (`uniflash-core.exe` on Windows). This repository also provides a C++ core library for integration with other clients.

The program communicates through the BootROM / FDL download protocol. A typical session connects to BootROM, loads FDL1 and FDL2, then performs storage operations in FDL2. Linux uses libusb; Windows uses native COM ports.

Backups include partition images, layout information, and SHA-256 manifests. Writes accept individual images, XML plans, image directories, and PAC packages. Dedicated NV operations restore primary/backup data or merge items according to PAC configuration; physical restoration uses temporary GPT aliases. Offline commands decrypt images, extract SCI1 payloads, and generate Sansa verification views.

This guide describes version 1.0.0, tagged `v1.0.0`.

## Building

### Requirements

| Component | Requirement |
|---|---|
| Build system | CMake 3.28 or later |
| Compiler and standard library | C++23 support, including `std::expected` |
| Linux dependencies | pkg-config, libusb-1.0, and OpenSSL Crypto development packages |
| Windows environment | Visual Studio C++ developer environment or LLVM-MinGW; cryptographic operations use system BCrypt |

Run the following commands from the project root. Use a new build directory when changing compilers or generators.

Recorded build environments use CMake 4.4.4 with Linux GCC 16.2.1 or Windows x64 LLVM-MinGW 20260922 / Clang 23.1.2.

### Linux

Install dependencies on Debian/Ubuntu:

```sh
sudo apt install build-essential cmake pkg-config libusb-1.0-0-dev libssl-dev
```

Configure and build:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build build --parallel 4
```

Outputs are `build/uniflash-core` and `build/libuniflash_core.a`. Select a compiler with `-DCMAKE_CXX_COMPILER=/path/to/compiler`. The current user needs permission to access the USB device.

Distribution package versions vary. Check `cmake --version` and `c++ --version` before configuring; upgrade CMake if it is older than 3.28. If `<expected>` or `std::expected` is unavailable, select a compiler **and standard library** with C++23 support. USB permission failures are covered under [troubleshooting](#troubleshooting).

### Windows

From a Visual Studio C++ developer environment:

```powershell
cmake -S . -B build-msvc -A x64 -DBUILD_TESTING=OFF
cmake --build build-msvc --config Release --parallel 4
```

Outputs are in `build-msvc\Release\`, including `uniflash-core.exe` and `uniflash_core.lib`. Install the Unisoc download serial driver and identify the device's COM port in Device Manager.

### Cross-compiling Windows x64 on Linux

Install Ninja, then use the included LLVM-MinGW configuration:

```sh
cmake -P cmake/fetch-llvm-mingw.cmake
export LLVM_MINGW_ROOT="$HOME/.cache/uniflash/toolchains/llvm-mingw-20260922-ucrt-ubuntu-22.04-x86_64"
cmake -S . -B build-win -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/llvm-mingw.cmake \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build build-win --parallel 4
```

For an existing toolchain, omit the download step and set its installation path. The download script pins the version and SHA-256. Outputs are `build-win/uniflash-core.exe` and `build-win/libuniflash_core.a`, with the C++ runtime linked statically.

### Installation and library integration

```sh
cmake --install build --prefix /path/to/install
```

Add `--config Release` when installing a Visual Studio build. Installation includes the CLI, static library, public headers, the Apache-2.0 license text, and CMake package configuration. Clients use:

```cmake
find_package(UniFlashCore CONFIG REQUIRED)
target_link_libraries(your_client PRIVATE UniFlash::Core)
```

Set `CMAKE_PREFIX_PATH` to the installation directory when configuring the client. The header prefix and namespace are both `uniflash`. Linux clients need OpenSSL and libusb discoverable by CMake/pkg-config.

### Building and running tests

The release commands above disable test targets. To enable them in the same Linux build directory:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --parallel 4
ctest --test-dir build --output-on-failure
```

For a native Visual Studio build:

```powershell
cmake -S . -B build-msvc -A x64 -DBUILD_TESTING=ON
cmake --build build-msvc --config Release --parallel 4
ctest --test-dir build-msvc -C Release --output-on-failure
```

`BUILD_TESTING` defaults to `ON` when omitted in a new build directory. `cmake --build` compiles the program, core library, and tests; `ctest` runs the tests. Cross-compiled Windows tests must run in a Windows-compatible execution environment. Linux GNU/Clang single-configuration Debug builds enable AddressSanitizer and UndefinedBehaviorSanitizer; configure those in a separate directory such as `build-debug`.

## Usage workflow

Enter command examples marked `text` inside UniFlash-Core; run `sh` and `powershell` blocks in the operating system's terminal. XML blocks show file contents. `<…>` denotes an argument to replace and `[…]` an optional argument. Quote paths containing spaces.

| Task | Sequence |
|---|---|
| Flash a PAC directly | Connect → `write <package.pac>` → follow the package's completion action |
| Back up before flashing | Connect → load separate FDL files → `read all` → write the PAC or images → reboot |
| Read or write individual images | Connect → load FDLs → read/write → reboot or quit |

Obtain loader files and their load addresses from the matching firmware package or build configuration. Partition names come from the device's `parts` output. File paths may contain Unicode; relative paths are resolved from UniFlash-Core's working directory at startup, except image paths inside XML, which are relative to that XML file.

### 1. Connect the device

Start the program:

```sh
./build/uniflash-core
```

On Windows:

```powershell
.\build-msvc\Release\uniflash-core.exe
```

Interactive startup without arguments waits up to 120 seconds and attempts a handshake. Put the device into download mode and connect it. Press Ctrl+C during the wait to return to the offline prompt and select a port manually:

```text
bus
connect <port>
```

On Windows, use a COM name listed by `bus`, such as `COM5`; on Linux, use a listed USB physical path. `connect <port>` requires the port to be present. Plain `connect` selects an available device or waits up to 120 seconds if none is present. Connect one device at a time and ensure the port is not in use by another process.

| Prompt | State |
|---|---|
| `offline>` | Not connected |
| `BootROM>` | Connected to the chip's download entry |
| `BSL>` | Communication established; loader identity not yet determined |
| `FDL1>` | First-stage loader ready |
| `FDL2>` | Partition operations available |

During loader transitions, the program handles USB re-enumeration and reconnection using physical port identity.

### 2. Load FDLs or flash a PAC

#### Separate loader files

Prepare FDL1, FDL2, and their load addresses:

```text
load-fdl <FDL1-file> <FDL1-address> <FDL2-file> <FDL2-address>
```

Addresses accept decimal or `0x` hexadecimal notation. Ordinary `load-fdl` requires all four arguments. From FDL1, you can instead use `load-fdl2 <file> <address>`. A recognized SPRD4 built-in download environment uses `load-fdl` without arguments.

After ordinary loading into FDL2, the CLI creates a session directory and runs `info` and `parts`, exporting `layout.xml` when the physical layout is readable. This also applies to scripts and connections to devices already in FDL2. Loading only FDL1 does not trigger these queries. An automatic query or export failure produces a warning; it does not by itself fail the loading command while the connection remains usable.

#### PAC package

Load and flash the product's PAC file in one command:

```text
write <package.pac>
```

From BootROM, the package supplies FDL1, FDL2, and their addresses. From FDL1, only FDL2 is loaded; an existing FDL2 is reused. Package execution proceeds without the automatic `info` and `parts` used by ordinary loading. To back up first, enter FDL2 using separate loader files.

Before loader upload, the program validates the archive's headers, file ranges, and CRCs and parses any host configuration. It completes image and operation checks in FDL2, saves package-requested backups and execution records, applies the repartition policy, and executes the selected XML operations, including erases, reads, and terminal reset or power-off actions. Supported PAC versions are BP_R1.0.0 and BP_R2.0.0, with a subset of R27 operations; unsupported selected operations fail preparation.

When the package supplies a partition table, its policy selects `0` to always repartition, `1` to stop on mismatch, `2` to ignore differences, or `3` to repartition on mismatch. Policies `1` and `3` compare GPT partition names, offsets, and sizes. Repartitioning does not automatically relocate existing partition contents.

Use `write <package.pac> <host-config.xml>` for additional NV, authentication, and factory parameters. See the [product configuration reference](docs/COMMANDS.md#pac-product-configuration-fields).

### 3. Query and back up

Run `info` to view device information again or `parts` to refresh partitions and the layout export. If enumeration works but physical-layout reading is unsupported, `parts` reports `XML export skipped`; other layout-read errors fail the command.

In the partition table, `Size` is human-readable; `Bytes` and `Offset` are byte counts. `-` denotes an unavailable or inapplicable offset. `Type` appears only when MBR regions are present and contains the MBR type code. MBR labels describe physical regions, not firmware partition names; use `read all` for those regions.

#### Read one partition

Use `read <partition> [output-path] [bytes]`. By default, the program queries the length, reads from the beginning, and generates a filename from the partition name. Ordinary named reads accept 1 through 4,294,967,295 bytes (4 GiB − 1 byte); use `read all` to back up larger physical partitions.

| Usage | Output and range |
|---|---|
| `read <partition>` | Save to `sessions/<timestamp>/<partition>.bin` |
| `read <partition> <output-file>` | Save to the specified file |
| `read <partition> <existing-directory>` | Generate a partition filename inside the directory |
| `read <partition> <output-file> <bytes>` | Read the specified length from the start of the partition |

The second argument is always the output path; the third is the length. Supply a path when specifying a length. Relative paths use the startup working directory. Existing directories are treated as directories; nonexistent paths are treated as filenames. A successful commit replaces an existing output file. Use different filenames to retain multiple results.

Explicit lengths accept decimal or `0x` hexadecimal notation and override the queried length. When capacity queries are unavailable, specify both output and length. Named reads of special partitions such as NV may return data processed by the FDL.

For example, read the first 4096 bytes to an explicit file:

```text
read <partition> "output.bin" 4096
```

Omitting `"output.bin"` would make `4096` the filename. Default filenames use `<partition>.bin` for portable names; reserved or unusual names are encoded into a portable filename. The program prints the actual output path.

#### Back up physical partitions

Use either form:

```text
read all
read all <backup-directory>
```

These are alternative forms: the first saves to `sessions/<timestamp>/dump/`, and the second uses the specified directory. A missing directory is created; an existing directory must be empty. Use a new empty directory for another backup.

GPT backup directories contain `manifest.json`, `layout.xml`, `gpt-primary-header.bin`, `gpt-entries.bin`, and partition images. The manifest records sources, offsets, expected and actual lengths, SHA-256 digests, statuses, and failure reasons. `complete: true` means all planned entries were saved with no recorded coverage limitation.

Reads extending beyond the 32-bit address range first verify the FDL's 64-bit addressing against the backup GPT. Hardware BOOT areas are backed up separately where supported. MBR and UFS backups retain coverage limitations and therefore report incomplete even if all planned images are saved. `read all` does not support NAND, arbitrary UFS LUs, or RPMB.

An incomplete backup retains saved files and records failed, unavailable, or unattempted entries in the manifest; the command reports failure. A complete backup describes read coverage, not restoration support. Complete eMMC backups include hardware BOOT entries, which whole-directory `restore-raw` currently rejects. Eligible GPT partition images can be restored individually with `restore-raw <partition> <snapshot>`. See [physical restoration](docs/COMMANDS.md#layout-and-physical-restoration).

### 4. Write images

#### Write one partition

In FDL2, write a partition with:

```text
write <partition> <image-file>
```

Single-partition writes do not pre-erase. The host expands standalone Android sparse images on demand; sparse files in a PAC retain their encoding for the FDL to expand. Ordinary writes complete upon the FDL's final acknowledgement.

#### Write a directory or XML plan

For batch images, list files and targets in `layout.xml`. Replace `PARTITION_NAME` below with the target partition name:

```text
images/
  layout.xml
  image.bin
```

```xml
<rom>
  <partition name="PARTITION_NAME" file="image.bin"/>
</rom>
```

| Entry point | Behavior |
|---|---|
| `write <image-directory>` | Write files listed in `layout.xml`, ignoring erase flags; omitted `file` uses the partition's `.bin` filename |
| `write <config.xml>` | Execute XML writes and explicit erases; relative file paths use the XML directory |

For the directory shown above, enter `write images`, or execute its XML directly with `write images/layout.xml`.

In directory mode, the program selects files from the XML list and starts writing after all files have been prepared. Files must resolve within the directory. Missing files, duplicate partition names, unknown fields, and external links are rejected. Preparation creates frozen snapshots and requires temporary disk space.

Ordinary XML uses a `rom` root and direct `partition` children. `size` can set an additional byte-capacity limit; changing partition sizes in a write plan does not repartition the device. For XML and directory writes, input file sizes before sparse expansion are limited by default to 64 GiB per file and 256 GiB per batch; expanded image sizes are checked separately against capacity limits. See [XML and directory plans](docs/COMMANDS.md#xml-and-directory-plans) for fields, erase-only entries, and examples.

#### Transfer and verification

Eligible named writes use whole-file raw when the FDL advertises mode 2; other writes use framed transfers. Windows COM uses escaped BSL frames and can also use the whole-file data channel. If the FDL requires write permission, run `enable-write` explicitly.

Writes to NV primary partitions use a dedicated flow: validate input containing a physical header, save current primary/backup headers and effective data, update both copies, and read back their physical contents for verification. If a directory supplies both copies, their payloads must agree and the pair executes once at the primary entry's position. This regenerates NV headers and updates effective data. Direct XML rejects NV image writes; use a single-partition or directory write. PAC NV merging copies selected old items into a new template according to product rules. Input requirements are in [NV writing](docs/COMMANDS.md#nv-writing).

| Operation | Completion evidence |
|---|---|
| Ordinary image/XML/directory write | FDL final acknowledgement |
| Dedicated physical-header NV write | Physical primary/backup header and effective-payload comparison |
| Standard PAC | Selected command acknowledgements and package-requested checks such as `CHECK_NV` |
| `restore-raw` | Physical byte comparison and restored GPT names/geometry; directory restoration also performs final aggregate readback |

Physical backup directories use `restore-raw`, not ordinary `write`. Directory restoration requires a complete manifest, matching eMMC/GPT geometry, and corresponding alias-write support. For version 3 manifests, it also checks image and GPT digests. Directory restoration currently rejects hardware BOOT entries. GPT GUIDs, types, and attributes may be regenerated. See the [additional command reference](docs/COMMANDS.md) for parameters and checks.

### 5. End the session

```text
reboot
```

`reboot` requests restart and exits. `quit` only exits the program. `poweroff` requests shutdown and exits; some firmware requires unplugging USB. See [boot targets](docs/COMMANDS.md#boot-targets) for targeted reboots.

`erase userdata` is a special operation: it writes and verifies a Recovery wipe request in `misc`, then returns to the shell, **without clearing data immediately or rebooting automatically**. Run plain `reboot` or reboot manually afterwards, then confirm on the device. Subsequent writes to `misc` or other boot requests can affect it. Explicit userdata erases selected by PAC/XML still execute as planned.

### Cancellation

| Operation | Ctrl+C behavior |
|---|---|
| Connection wait or file preparation | Cancel; interactive mode returns to the shell, scripts stop |
| Ordinary named read | Attempt to close the read after the current complete request/reply |
| Ordinary framed write | Attempt END cleanup at a protocol boundary; written data remains |
| Whole-file raw transfer | Cancellation during raw reception may retire the session |
| Direct erase, PAC repartition, or an individual GPT alias transaction | CLI interrupts are suppressed until completion or failure |
| Directory physical restore | Restore the GPT after the active partition's transaction, then stop without starting the next partition; final readback is cancellable |

`erase userdata` stages a boot request and remains cancellable; a request already written may affect the next boot. Outside protected transactions, repeated Ctrl+C can force exit. An uncertain write, repartition, or EXEC stops the operation. Cancellation and failure do not undo completed writes.

### Output files and execution records

Default outputs are under `sessions/<timestamp>/`. Commands on the same connection share the directory, and the program prints actual paths:

| Path | Contents |
|---|---|
| `layout.xml` | Physical layout exported on ordinary FDL2 entry or by `parts` |
| `<partition>.bin` | Named read with no output path specified |
| `dump/` | `read all` with no directory specified |
| `pac-N/` | PAC plan, package-requested backups, and execution records |
| `nv-restore-N/`, `directory-nv-N/` | Original NV primary/backup headers, effective data, and records |
| `restore-directory-N/`, `restore-raw-N/` | Physical recovery material and records |
| `rename-write-N/` | GPT recovery material for `write-rename` |

Each flow generates applicable state files such as `execution.txt` and `last-operation.txt`. Outputs use temporary files and atomic replacement. A replacement-with-unconfirmed-durability error means new contents may already be committed. Linux synchronizes relevant directories. Windows flushes files and uses write-through replacement, recording parent-directory power-loss persistence information in recovery material's `durability.txt`.

### Script execution

Each process argument is one complete command:

```sh
./build/uniflash-core "connect" "write firmware.pac" "quit"
```

Commands can also be read line by line from standard input. Device operations in non-interactive mode require explicit `connect`; use `"connect COM5"` on Windows when that port is already present. A failed command stops later execution. A PAC reset or power-off also ends the sequence.

For paths containing spaces, preserve the inner path quotes as part of the command argument:

```sh
./build/uniflash-core 'connect' 'write "firmware files/package.pac"' 'quit'
```

For PowerShell, a line-based script avoids nested native-argument quoting:

```powershell
@'
connect COM5
write "firmware files/package.pac"
quit
'@ | .\build-msvc\Release\uniflash-core.exe
```

Alternatively, save one UniFlash-Core command per line in a UTF-8 file **without BOM**, such as `commands.txt`, then run:

```sh
./build/uniflash-core < commands.txt
```

Blank lines and lines whose first non-whitespace character is `#` are ignored. Variables such as `$FDL1_ADDR` in the example below are expanded by the system shell; UniFlash-Core does not expand variables in `commands.txt`.

When piping non-ASCII paths from PowerShell, set `$OutputEncoding` to UTF-8 without BOM before the pipeline:

```powershell
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
```

A Linux shell sequence to load, back up, and then flash:

```sh
./build/uniflash-core "connect" \
  "load-fdl fdl1.bin $FDL1_ADDR fdl2.bin $FDL2_ADDR" \
  "read all backup" \
  "write firmware.pac" \
  "reboot"
```

Set `FDL1_ADDR` and `FDL2_ADDR` to the actual addresses and prepare the listed files before execution. Script exit codes are `0` for success, `2` for command failure, `130` for cancellation, and `143` for termination. In interactive mode, a failed command returns to the prompt; a later normal exit returns `0`.

### Troubleshooting

| Message or symptom | Check |
|---|---|
| No device in `bus` | Download mode, USB connection, and download serial driver |
| `permission denied` | USB access and output-path write permissions |
| `device or resource busy` | Another process using the device or COM port |
| `unavailable at ...` | Whether the current stage permits the command |
| Missing FDL2 announcement or failed reconnection | FDL files, load addresses, and physical port identity |
| Unknown capacity | Provide an output path and byte count for `read` |
| `automatic summary incomplete` | Automatic query or export failed; inspect separately with `info` and `parts` |
| Unsupported PAC/NV operation | Operation type, format, and product configuration reported in the error |
| Timeout or lost synchronization | Preserve records, establish device state, and reconnect in download mode |

On Linux, use your distribution's udev configuration to grant the current user access to the device; reconnect USB after changing permissions. On Windows, confirm the download interface is present in Device Manager and that its COM port matches `bus`. For build failures, first check CMake/compiler versions and whether the listed development packages are installed.

Use `UNIFLASH_PERF=1` for performance statistics and `UNIFLASH_TRACE=1` for detailed communication logs:

```sh
UNIFLASH_PERF=1 ./build/uniflash-core
```

```powershell
$env:UNIFLASH_PERF = "1"
.\build-msvc\Release\uniflash-core.exe
```

`[*]`, `[~]`, and `[!]` denote information, warnings, and errors. Traces may contain transferred data; AUTH41 payload hex dumps are suppressed. Interactive history is saved in `.uniflash_history` in the user's home directory.

## Main commands

| Command | Description |
|---|---|
| `help` | Display help and applicable stages |
| `bus` | List devices and ports |
| `connect [port]` | Connect to a device |
| `info` | Display device and connection information |
| `load-fdl <FDL1-file> <FDL1-address> <FDL2-file> <FDL2-address>` | Load to FDL2 and automatically display info and parts; omit arguments for SPRD4 |
| `parts` | Refresh partitions and export XML when the physical layout is readable |
| `read <partition> [output-path] [bytes]` | Read a partition; default output is the session directory |
| `read all [backup-directory]` | Back up physical partitions; default output is the session directory's `dump/` |
| `write <partition> <image-file>` | Write a single partition |
| `write <image-directory>` / `write <config.xml>` | Execute directory or XML batch writes |
| `write <package.pac> [host-config.xml]` | Execute a PAC plan |
| `erase <partition>` | Erase a partition; userdata only stages a Recovery wipe request |
| `reboot [target]` | Reboot and exit |
| `poweroff` | Request shutdown and exit |
| `quit` | Exit the program |

Aliases: `r` = `read`, `w` = `write`, `e` = `erase`, `?` = `help`.

Full arguments for separate loader stages, RAM operations, diagnostics, physical restoration, repartitioning, factory modes, and offline image processing are in [docs/COMMANDS.md](docs/COMMANDS.md).

## License

Apache-2.0, Copyright (C) 2026 Evarentha. See [LICENSE](LICENSE).

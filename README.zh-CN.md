<!--
UniFlash-Core User Guide (Simplified Chinese)

Chinese introduction, build instructions, usage workflow and the main commands.

Authors:
worryzu <worryzu@gmail.com> @LinearTeam

Copyright (C) 2026 Evarentha
SPDX-License-Identifier: Apache-2.0
-->

# UniFlash-Core

[English](README.md) | **简体中文**

UniFlash-Core 是面向紫光展锐（Unisoc / Spreadtrum）设备的命令行刷机工具，提供 FDL 加载、分区读写、PAC 刷写、存储备份及物理恢复功能。可执行文件名为 `uniflash-core`，Windows 下为 `uniflash-core.exe`。本仓库同时提供 C++ 核心库，供其他客户端集成。

程序通过 BootROM / FDL 下载协议与设备通信。常规流程为连接 BootROM、加载 FDL1 和 FDL2，然后在 FDL2 阶段执行存储操作。Linux 使用 libusb，Windows 使用原生 COM 接口。

备份包含分区镜像、布局信息和 SHA-256 清单。写入支持独立镜像、XML 计划、镜像目录和 PAC 固件包。NV 专用操作可恢复主备数据，或按 PAC 配置合并条目；物理恢复通过临时 GPT 别名完成。离线命令提供镜像解密、SCI1 载荷提取和 Sansa 验签视图生成。

本文档对应 1.0.0 版本，标记为 `v1.0.0`。

## 构建方法

### 环境要求

| 项目 | 要求 |
|---|---|
| 构建系统 | CMake 3.28 或更高版本 |
| 编译器与标准库 | 支持 C++23，包括 `std::expected` |
| Linux 依赖 | pkg-config、libusb-1.0、OpenSSL Crypto 开发包 |
| Windows 环境 | Visual Studio C++ 开发环境，或 LLVM-MinGW；加密功能使用系统 BCrypt |

在项目根目录执行下列构建命令。更换编译器或生成器时应使用新的构建目录。

已有构建记录使用 CMake 4.4.4，编译器为 Linux GCC 16.2.1 或 Windows x64 LLVM-MinGW 20260922 / Clang 23.1.2。

### Linux

Debian/Ubuntu 依赖安装：

```sh
sudo apt install build-essential cmake pkg-config libusb-1.0-0-dev libssl-dev
```

配置并编译：

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build build --parallel 4
```

产物为 `build/uniflash-core` 和 `build/libuniflash_core.a`。可通过 `-DCMAKE_CXX_COMPILER=/path/to/compiler` 选择编译器。运行时，当前用户需要具有设备的 USB 访问权限。

不同发行版的软件包版本不同。配置前通过 `cmake --version`、`c++ --version` 检查版本；CMake 低于 3.28 时先升级。如果缺少 `<expected>` 或 `std::expected`，应选择同时具备 C++23 支持的**编译器和标准库**。USB 权限问题见[问题排查](#问题排查)。

### Windows

在 Visual Studio C++ 开发环境中执行：

```powershell
cmake -S . -B build-msvc -A x64 -DBUILD_TESTING=OFF
cmake --build build-msvc --config Release --parallel 4
```

产物位于 `build-msvc\Release\`，包括 `uniflash-core.exe` 和 `uniflash_core.lib`。安装展锐下载串口驱动后，在设备管理器中确认设备的 COM 端口。

### Linux 交叉编译 Windows x64

安装 Ninja 后，使用仓库提供的 LLVM-MinGW 工具链配置：

```sh
cmake -P cmake/fetch-llvm-mingw.cmake
export LLVM_MINGW_ROOT="$HOME/.cache/uniflash/toolchains/llvm-mingw-20260922-ucrt-ubuntu-22.04-x86_64"
cmake -S . -B build-win -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=cmake/llvm-mingw.cmake \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build build-win --parallel 4
```

已有工具链时，可省略下载步骤并设置其安装路径。下载脚本固定版本和 SHA-256。产物为 `build-win/uniflash-core.exe` 及 `build-win/libuniflash_core.a`，C++ 运行库静态链接。

### 安装与库集成

```sh
cmake --install build --prefix /path/to/install
```

Visual Studio 构建安装时添加 `--config Release`。安装内容包含命令行程序、静态库、公共头文件、Apache-2.0 许可证文本和 CMake 包配置。客户端使用：

```cmake
find_package(UniFlashCore CONFIG REQUIRED)
target_link_libraries(your_client PRIVATE UniFlash::Core)
```

配置客户端时，通过 `CMAKE_PREFIX_PATH` 指定安装目录。头文件前缀和命名空间均为 `uniflash`；Linux 客户端需要可由 CMake/pkg-config 查找的 OpenSSL 和 libusb。

### 构建与运行测试

前面的发布构建命令关闭了测试目标。在同一 Linux 构建目录中启用测试：

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --parallel 4
ctest --test-dir build --output-on-failure
```

Windows 原生 Visual Studio 构建：

```powershell
cmake -S . -B build-msvc -A x64 -DBUILD_TESTING=ON
cmake --build build-msvc --config Release --parallel 4
ctest --test-dir build-msvc -C Release --output-on-failure
```

新建构建目录时，省略 `BUILD_TESTING` 的默认值为 `ON`。`cmake --build` 编译程序、核心库和测试；`ctest` 运行测试。交叉编译出的 Windows 测试需要在兼容 Windows 的执行环境运行。Linux GNU/Clang 单配置生成器的 Debug 构建启用 AddressSanitizer 和 UndefinedBehaviorSanitizer，可使用 `build-debug` 等独立目录配置。

## 使用流程

标为 `text` 的命令示例在 UniFlash-Core 内输入，`sh`、`powershell` 代码块在系统终端执行，XML 代码块表示文件内容。`<…>` 表示需要替换的参数，`[…]` 表示可选参数；路径含空格时加引号。

| 任务 | 操作顺序 |
|---|---|
| 直接刷写 PAC | 连接 → `write <package.pac>` → 按包定义完成操作 |
| 先备份再刷写 | 连接 → 加载独立 FDL → `read all` → 写入 PAC 或镜像 → 重启 |
| 读取或写入独立镜像 | 连接 → 加载 FDL → 读写 → 重启或退出 |

FDL 文件及加载地址从对应固件包或构建配置中取得，分区名以设备的 `parts` 输出为准。文件路径支持 Unicode；相对路径以 UniFlash-Core 启动时的工作目录为基准，XML 内的镜像相对路径则以 XML 所在目录为基准。

### 1. 连接设备

启动程序：

```sh
./build/uniflash-core
```

Windows 对应命令：

```powershell
.\build-msvc\Release\uniflash-core.exe
```

无参数交互启动会等待设备最多 120 秒并尝试握手。将设备置于下载模式后接入电脑。等待期间按 Ctrl+C 可返回离线提示符，再手动选择端口：

```text
bus
connect <端口>
```

Windows 使用 `bus` 列出的 COM 名称，例如 `COM5`；Linux 使用列出的 USB 物理路径。`connect <端口>` 要求端口已经出现；无参数 `connect` 选择当前设备，无设备时最多等待 120 秒。一次连接一台设备，端口需处于未被其他程序占用的状态。

| 提示符 | 当前状态 |
|---|---|
| `offline>` | 尚未连接 |
| `BootROM>` | 已连接芯片下载入口 |
| `BSL>` | 通信已建立，加载器身份尚未确定 |
| `FDL1>` | 第一阶段加载器已就绪 |
| `FDL2>` | 可执行分区操作 |

加载器切换时，程序按物理端口身份处理 USB 重新枚举和重连。

### 2. 加载 FDL 或刷写 PAC

#### 独立 FDL 文件

准备 FDL1、FDL2 及对应加载地址：

```text
load-fdl <FDL1文件> <FDL1地址> <FDL2文件> <FDL2地址>
```

地址使用十进制或 `0x` 十六进制。普通 `load-fdl` 需要全部四个参数；已处于 FDL1 时，也可单独执行 `load-fdl2 <文件> <地址>`。识别为 SPRD4 内置下载环境时，使用无参数 `load-fdl`。

普通加载进入 FDL2 后，CLI 自动创建会话目录，执行 `info` 和 `parts`，并在物理布局可读时导出 `layout.xml`。脚本执行及连接已处于 FDL2 的设备时也会执行这些操作；仅加载 FDL1 不触发这组查询。自动查询或导出失败会显示警告；连接仍可用时，这类错误本身不会使加载命令失败。

#### PAC 固件包

使用一条命令加载并刷写对应产品的 PAC 文件：

```text
write <package.pac>
```

从 BootROM 开始时使用包内 FDL1、FDL2 和地址；从 FDL1 开始时只加载 FDL2；已在 FDL2 时复用当前加载器。进入 FDL2 后直接执行 PAC 计划，不插入普通加载流程的自动 `info`、`parts`。需要先备份时，应先用独立 FDL 进入 FDL2。

程序在上传加载器前校验固件包的包头、文件范围和 CRC，并解析附带的主机配置。进入 FDL2 后完成镜像与操作检查，保存包要求的备份和执行记录，应用重分区策略，再按 XML 顺序执行选中操作，包括擦除、读取及末项重启或关机。支持的 PAC 版本为 BP_R1.0.0、BP_R2.0.0，支持部分 R27 操作；不支持的选中操作会在准备阶段报错。

包内提供分区表时，由包指定策略：`0` 始终重分区，`1` 布局不一致则停止，`2` 忽略差异，`3` 不一致时重分区。策略 `1`、`3` 按 GPT 分区名称、偏移和大小比较布局。重分区不会自动迁移已有分区内容。

附带主机产品配置时使用 `write <package.pac> <host-config.xml>`。配置用于 NV、认证和工厂操作参数，详见[产品配置参考](docs/COMMANDS.md#pac-product-configuration-fields)。

### 3. 查询与备份

手动执行 `info` 可再次查看设备信息，`parts` 可刷新分区列表及布局导出。若列表可查询但不支持物理布局读取，`parts` 会提示 `XML export skipped`；其他布局读取错误会使命令失败。

分区表中的 `Size` 为可读容量，`Bytes` 和 `Offset` 均以字节计。偏移显示 `-` 表示未知或不适用。仅当列表包含 MBR 区域时显示 `Type`，其值为 MBR 类型码。MBR 标签表示物理区域，不是固件分区名；这类区域使用 `read all` 备份。

#### 读取单个分区

完整语法为 `read <分区名> [输出路径] [字节数]`。默认查询分区长度，从起始位置读取，并按分区名保存文件。普通命名读取的长度范围为 1 至 4,294,967,295 字节（4 GiB − 1 字节）；更大的物理分区使用 `read all` 备份。

| 用法 | 输出及范围 |
|---|---|
| `read <分区名>` | 保存为 `sessions/<时间戳>/<分区名>.bin` |
| `read <分区名> <输出文件>` | 保存到指定文件 |
| `read <分区名> <已有目录>` | 在目录内生成分区文件名 |
| `read <分区名> <输出文件> <字节数>` | 从分区起始位置读取指定长度 |

第二个参数始终是输出路径，第三个参数才是长度，不能省略路径直接填写长度。相对路径以启动时的工作目录为基准；已有目录按目录处理，不存在的路径按文件名处理。同名输出在提交成功后替换，保留多次结果时应指定不同文件名。

指定长度接受十进制或 `0x` 十六进制，并覆盖自动查询的长度。容量查询不可用时，需要明确提供输出和长度。NV 等特殊分区的命名读取结果可能经过 FDL 处理。

例如，将起始 4096 字节读取到指定文件：

```text
read <分区名> "output.bin" 4096
```

省略 `"output.bin"` 时，`4096` 会被当作文件名。默认输出对可移植名称使用 `<分区名>.bin`；保留名称或特殊字符名称会编码为可移植文件名。程序会打印实际输出路径。

#### 备份物理分区

任选以下一种形式：

```text
read all
read all <备份目录>
```

两种写法分别表示默认保存到 `sessions/<时间戳>/dump/` 和保存到指定目录。目标目录不存在时创建，已存在时必须为空。再次备份应使用新的空目录。

GPT 备份目录包含 `manifest.json`、`layout.xml`、`gpt-primary-header.bin`、`gpt-entries.bin` 和各分区镜像。清单记录来源、偏移、预期和实际长度、SHA-256、状态及失败原因；`complete: true` 表示计划中的项目全部保存且没有已记录的范围限制。

读取范围超出 32 位地址范围时，先通过备份 GPT 验证 FDL 的 64 位寻址。硬件 BOOT 区在固件支持时单独备份。MBR 和 UFS 备份带有范围限制，即使全部计划镜像已保存，也会报告不完整。`read all` 不支持 NAND、任意 UFS LU 或 RPMB。

备份不完整时，已保存文件会保留，manifest 记录失败、不可用或未尝试的项目，命令返回失败。完整备份描述的是读取覆盖情况，不代表支持整包恢复。完整 eMMC 备份包含硬件 BOOT 项目，目前不能执行整目录 `restore-raw`。符合条件的 GPT 分区镜像可通过 `restore-raw <分区名> <快照文件>` 逐个恢复。详见[物理恢复](docs/COMMANDS.md#layout-and-physical-restoration)。

### 4. 写入镜像

#### 写入单个分区

进入 FDL2 后，写入指定分区：

```text
write <分区名> <镜像文件>
```

单分区写入不预先擦除。普通 Android sparse 镜像由主机按需展开；PAC 内的 sparse 文件保留原始编码，由 FDL 展开。普通写入以 FDL 最终应答作为完成标志。

#### 写入目录或 XML 计划

批量镜像目录使用 `layout.xml` 列出文件和目标。以下 `PARTITION_NAME` 为待替换的分区名：

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

| 入口 | 执行方式 |
|---|---|
| `write <镜像目录>` | 按目录内 `layout.xml` 写文件，忽略擦除标记；省略 `file` 时使用分区名对应的 `.bin` 文件 |
| `write <配置.xml>` | 按 XML 执行写入及显式擦除；相对文件路径以 XML 所在目录为基准 |

上述目录使用 `write images`，或通过 `write images/layout.xml` 直接执行其中的 XML。

目录模式下，程序按 XML 列表选择文件，全部准备完成后开始写入。文件须位于目录内，缺文件、重复分区名、未知字段或目录外链接会报错。镜像准备会建立冻结快照，需要相应临时磁盘空间。

普通 XML 使用 `rom` 根和直接 `partition` 子项。`size` 可设置额外的字节容量上限；修改写入计划中的分区大小不会执行重分区。XML 和目录写入默认限制 sparse 展开前的输入文件大小：单文件 64 GiB、整批 256 GiB；展开后的镜像大小另行按容量上限检查。字段、仅擦除条目及示例见 [XML 与目录计划](docs/COMMANDS.md#xml-and-directory-plans)。

#### 传输与完成校验

命名写入在满足条件且 FDL 宣告 whole-file raw mode 2 时使用裸数据通道，其他写入使用逐帧传输。Windows COM 使用转义 BSL 帧，也可使用上述 whole-file 数据通道。FDL 要求写入许可时，需显式执行 `enable-write`。

NV 主分区通过专用流程写入：校验包含物理头的输入，保存当前主备头及有效数据，更新两份数据后读回物理内容进行校验。目录同时提供主备文件时，有效载荷须一致，每对在主条目位置执行一次；该流程重建 NV 头并更新有效数据。直接 XML 不支持 NV 镜像写入，应使用单分区或目录入口。PAC NV 合并按产品规则将指定旧条目合入新模板。输入要求见 [NV 写入](docs/COMMANDS.md#nv-writing)。

| 操作 | 完成依据 |
|---|---|
| 普通镜像、XML、目录写入 | FDL 最终应答 |
| 带物理头的专用 NV 写入 | 物理读回主备头及有效载荷并比较 |
| 标准 PAC | 选中命令的应答及包要求的检查，例如 `CHECK_NV` |
| `restore-raw` | 物理字节比较及 GPT 名称、几何恢复；整目录另执行最终聚合读回 |

物理备份目录使用 `restore-raw`，不能交给普通 `write`。目录恢复要求完整 manifest、匹配的 eMMC/GPT 布局及相应别名写入支持。对于版本 3 的 manifest，还会核对镜像和 GPT 摘要。当前不接受包含硬件 BOOT 区的整目录恢复；GPT GUID、类型及属性可能重新生成。参数和检查步骤见[其他命令参考](docs/COMMANDS.md)。

### 5. 结束操作

```text
reboot
```

`reboot` 请求设备重启并退出；`quit` 仅退出程序；`poweroff` 请求关机并退出，部分固件需拔掉 USB 才完成。带目标的重启方式见[启动目标](docs/COMMANDS.md#boot-targets)。

`erase userdata` 是特殊操作：写入并读回验证 `misc` 中的 Recovery 清除请求，然后返回命令行，**不立即清除数据，也不自动重启**。另行执行普通 `reboot` 或手动重启后，在设备端确认清除。后续写入 `misc` 或其他启动请求会影响该请求；PAC/XML 的显式 userdata 擦除仍按计划执行。

### 取消操作

| 操作 | Ctrl+C 行为 |
|---|---|
| 等待连接、准备文件 | 取消；交互模式返回命令行，脚本停止 |
| 普通命名读取 | 当前完整请求/回复结束后尝试关闭读取 |
| 普通帧式写入 | 在协议边界尝试 END 收尾，已写数据保留 |
| whole-file raw 传输 | 裸数据接收阶段取消可能使会话失效 |
| 直接擦除、PAC 重分区、单次 GPT 别名事务 | CLI 屏蔽中断，等待完成或返回错误 |
| 整目录物理恢复 | 当前分区事务恢复 GPT 后停止，不再开始下一分区；最终读回可取消 |

`erase userdata` 写入启动请求，仍可取消；已经写入的请求可能影响下次启动。除受保护事务外，连续 Ctrl+C 可强制退出。写入、重分区或 EXEC 结果不确定时停止操作；取消和失败不会撤销已经完成的写入。

### 输出文件与执行记录

默认输出放在 `sessions/<时间戳>/`。同一连接使用同一会话目录，程序会打印实际路径：

| 路径 | 内容 |
|---|---|
| `layout.xml` | 普通流程进入 FDL2 或执行 `parts` 时导出的物理布局 |
| `<分区名>.bin` | 未指定输出路径的命名读取结果 |
| `dump/` | 未指定目录的 `read all` 结果 |
| `pac-N/` | PAC 计划、包要求的备份和执行记录 |
| `nv-restore-N/`、`directory-nv-N/` | NV 原始主备头、有效数据及记录 |
| `restore-directory-N/`、`restore-raw-N/` | 物理恢复材料及记录 |
| `rename-write-N/` | `write-rename` 的 GPT 恢复材料 |

各流程按需生成 `execution.txt`、`last-operation.txt` 等状态文件。输出采用临时文件和原子替换；“已替换但持久化未确认”表示新内容可能已经提交。Linux 同步相关目录；Windows 刷新文件并使用 write-through 替换，父目录掉电持久性说明写入恢复材料的 `durability.txt`。

### 脚本执行

每个进程参数是一条完整命令：

```sh
./build/uniflash-core "connect" "write firmware.pac" "quit"
```

也可从标准输入逐行读取命令。非交互模式的设备操作需要显式 `connect`；Windows 端口已经出现时可使用 `"connect COM5"`。命令失败后停止后续执行，PAC 自身重启或关机也会结束命令序列。

路径含空格时，需要将路径引号保留在完整命令参数中：

```sh
./build/uniflash-core 'connect' 'write "firmware files/package.pac"' 'quit'
```

PowerShell 可使用逐行脚本，避免原生程序参数中的嵌套引号问题：

```powershell
@'
connect COM5
write "firmware files/package.pac"
quit
'@ | .\build-msvc\Release\uniflash-core.exe
```

也可在**无 BOM 的 UTF-8** 文件（例如 `commands.txt`）中每行写一条 UniFlash-Core 命令，再执行：

```sh
./build/uniflash-core < commands.txt
```

空行及首个非空白字符为 `#` 的行会被忽略。下例的 `$FDL1_ADDR` 等变量由系统 shell 展开；UniFlash-Core 不会展开 `commands.txt` 中的变量。

通过 PowerShell 管道传入非 ASCII 路径时，在执行管道前将 `$OutputEncoding` 设为无 BOM 的 UTF-8：

```powershell
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
```

先加载、备份，再刷写的 Linux shell 示例：

```sh
./build/uniflash-core "connect" \
  "load-fdl fdl1.bin $FDL1_ADDR fdl2.bin $FDL2_ADDR" \
  "read all backup" \
  "write firmware.pac" \
  "reboot"
```

执行前将 `FDL1_ADDR`、`FDL2_ADDR` 设置为实际地址，并准备示例中的文件。脚本退出码为：`0` 成功，`2` 命令失败，`130` 取消，`143` 终止。交互模式的命令失败后返回提示符，随后正常退出仍返回 `0`。

### 问题排查

| 提示或现象 | 检查内容 |
|---|---|
| `bus` 无设备 | 下载模式、USB 连接及下载串口驱动 |
| `permission denied` | USB 访问权限、输出路径写权限 |
| `device or resource busy` | 设备或 COM 端口是否被其他进程占用 |
| `unavailable at ...` | 当前阶段是否符合命令要求 |
| FDL2 宣告缺失、重连失败 | FDL 文件、加载地址和物理端口身份 |
| 容量未知 | 为 `read` 提供输出路径和字节数 |
| `automatic summary incomplete` | 自动信息查询或导出未完成，可单独执行 `info`、`parts` 检查 |
| PAC/NV 操作不受支持 | 错误中列出的操作类型、格式和产品配置 |
| 超时或失步 | 保存记录，确认设备状态并重新建立下载连接 |

Linux 使用发行版的 udev 配置为当前用户授予设备访问权限，修改后重新连接 USB。Windows 在设备管理器中确认下载接口存在，且 COM 端口与 `bus` 输出相符。构建失败时，先检查 CMake、编译器版本和所列开发包是否已安装。

性能统计使用 `UNIFLASH_PERF=1`，详细通信日志使用 `UNIFLASH_TRACE=1`：

```sh
UNIFLASH_PERF=1 ./build/uniflash-core
```

```powershell
$env:UNIFLASH_PERF = "1"
.\build-msvc\Release\uniflash-core.exe
```

`[*]`、`[~]`、`[!]` 分别表示信息、警告和错误。trace 可能包含传输数据，AUTH41 载荷的十六进制输出会被抑制。交互历史保存于用户目录的 `.uniflash_history`。

## 主要命令

| 命令 | 说明 |
|---|---|
| `help` | 显示帮助和适用阶段 |
| `bus` | 列出设备和端口 |
| `connect [端口]` | 连接设备 |
| `info` | 显示设备和连接信息 |
| `load-fdl <FDL1文件> <FDL1地址> <FDL2文件> <FDL2地址>` | 加载至 FDL2，随后自动显示 info、parts；SPRD4 使用无参数形式 |
| `parts` | 刷新分区列表，并在物理布局可读时导出 XML |
| `read <分区名> [输出路径] [字节数]` | 读取分区；默认保存到会话目录 |
| `read all [备份目录]` | 物理分区备份；默认保存到会话目录的 `dump/` |
| `write <分区名> <镜像文件>` | 单分区写入 |
| `write <镜像目录>` / `write <配置.xml>` | 目录或 XML 批量写入 |
| `write <package.pac> [host-config.xml]` | 执行 PAC 计划 |
| `erase <分区名>` | 擦除分区；userdata 仅暂存 Recovery 清除请求 |
| `reboot [目标]` | 重启并退出 |
| `poweroff` | 请求关机并退出 |
| `quit` | 退出程序 |

简写：`r` = `read`，`w` = `write`，`e` = `erase`，`?` = `help`。

分阶段加载、RAM 操作、诊断、物理恢复、重分区、工厂模式及离线镜像处理的完整参数见 [docs/COMMANDS.md](docs/COMMANDS.md)（英文）。

## 许可证

本项目以 Apache-2.0 许可发布，Copyright (C) 2026 Evarentha，完整文本见 [LICENSE](LICENSE)。

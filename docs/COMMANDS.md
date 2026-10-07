# Additional Command Reference

Command details for UniFlash-Core 1.0.0. `<…>` denotes a required argument; `[…]` denotes an optional argument. Addresses accept decimal or `0x` hexadecimal notation.

Enter command examples marked `text` inside UniFlash-Core. XML blocks are file contents. Replace uppercase XML placeholders with the actual product or partition parameters. Numeric sizes are in bytes unless another unit is stated; KiB, MiB, and GiB denote powers of 1024.

## Separate loader stages and RAM operations

| Command | Stage | Description |
|---|---|---|
| `load-fdl1 <file> <address>` | BootROM / BSL | Download and execute FDL1, then confirm its handshake |
| `load-fdl2 <file> <address>` | FDL1 | Download FDL2 and establish communication, then automatically display info and parts |
| `load-fdl2` | SPRD4 | Enter the built-in FDL2 environment without loader files |
| `download <file> <address>` | BootROM / BSL / FDL1 | Download to RAM without execution |
| `load-bin <file> <load-address> [entry-address]` | BootROM / BSL / FDL1 | Download and execute, then attempt an FDL1 handshake; the entry defaults to the load address |
| `exec <address>` | BootROM / BSL / FDL1 | Execute a previously downloaded RAM payload, then attempt an FDL1 handshake |
| `ddrtest` | FDL1 | Run DDR verification |
| `ddrtest sr [milliseconds]` | FDL1 | Run a DDR self-refresh test; default 30000 ms |

Files, addresses, and entry points must match the device and payload.

RAM addresses are unsigned 32-bit values (`0`–`0xffffffff`). Input must be nonempty, at most 4 GiB − 1 byte, and fit within the 32-bit address space from its load address. The entry argument is sent in EXEC; the receiver determines how it interprets that field. DDR self-refresh accepts `0`–`4294967295` milliseconds; zero is passed through to the firmware.

To pause at FDL1 for a DDR check before entering FDL2:

```text
load-fdl1 <FDL1-file> <FDL1-address>
ddrtest
load-fdl2 <FDL2-file> <FDL2-address>
```

To run only the self-refresh check from FDL1, use `ddrtest sr` for the default duration or `ddrtest sr 5000` for 5 seconds. A firmware FAIL reply is reported as a failed command.

Ordinary `load-fdl`, `load-fdl2`, and connections to devices already in FDL2 create a CLI session directory and run `info` and `parts`, exporting `layout.xml` when the physical layout is readable. This applies to interactive and script execution. Automatic query or export failures produce warnings rather than failing the loading command while the connection remains usable. Loading only FDL1 does not trigger the summary; PAC commands proceed directly to their package plan. Core device-loading API calls do not include the CLI's display or export.

## Diagnostics

- `info diagnostic`: query additional firmware flags, MCP information, and other diagnostics in FDL2.
- `info miscdata`: read and decode factory tests, serial numbers, and Bootloader lock records in FDL2, displaying plaintext markers, blank records, or unknown data according to their contents.

`BL state` uses a record-presence heuristic over the 64 bytes at `miscdata + 0x2000`: all `0x00` or all `0xFF` means locked; any other content means unlocked, including a plaintext LOCK marker. An unavailable record is reported as unavailable. The output labels this heuristic; it is not the TrustOS verification result.

FDL2 entry automatically calls ordinary `info`, not `info diagnostic` or `info miscdata`. Invoke these extended queries explicitly.

`BL record` describes the stored bytes; `BL state` shows the rule above. `info diagnostic` reports the separate root flag, NV/RF type, and MCP information. These fields are independent of the record-presence rule. Factory station results are decoded from the stored tested/result masks; ambiguous SP15 32/64-bit layouts can produce `Unknown`.

## XML and directory plans

These entry points run in FDL2:

```text
write <image-directory>
write <config.xml>
```

A directory must contain `layout.xml`; only listed partitions are selected. Direct XML executes entries in order and honors explicit erase flags. Both prepare all selected image files before starting writes.

### Fields and defaults

The root is `rom`, with direct `partition` children and unique partition names. Unknown attributes or nested operations are rejected. Named-operation partition names are 1–35 printable ASCII bytes; file paths support Unicode.

| Partition field | Write behavior |
|---|---|
| `name` | Required target name |
| `file` | Image path; relative to the XML directory |
| `size` | Additional capacity limit on the expanded image, in bytes; must be positive for image writes. Omitted or `remaining` uses device-capacity checks |
| `erase` | `true`, `false`, `1`, or `0`; default false. Direct XML erases before writing when true; directory mode ignores this field |
| `address`, `gap` | Used by repartitioning; ordinary writes still start at partition offset zero |
| `checksum` | Rejected by ordinary write planning because its algorithm is unspecified; image-format checksums are checked separately |

For direct XML, an entry with `erase="true"` and no `file` performs only an erase; an entry with neither a file nor an active erase is skipped. Directory mode instead supplies the partition-derived `.bin` filename when `file` is omitted, so every listed entry must have an image. Directory paths must be relative, contain no `..` components, and resolve inside the directory, including through symbolic links or Windows junctions. Direct XML also accepts absolute image paths and paths outside its directory.

Root attributes accepted by the shared parser are `name`, `version`, `storage`, `sector_size`, `disk_size`, `repartition_format`, and `image_semantics`. Layout attributes do not turn `write` into repartitioning. Ordinary write entry points reject `image_semantics="physical-snapshot"` and any input directory containing `manifest.json`, including direct XML in that directory.

XML text is limited to 8 MiB and accepts a UTF-8 BOM. Input file sizes before sparse expansion are limited by default to 64 GiB per file and 256 GiB per batch; expanded image sizes are checked separately against capacity limits. Core directory clients can override the input file size limits through `DirectoryPrepareOptions`.

### Write and erase example

Save the following as `config.xml`, replace the three target placeholders, and place the two images beside it:

```xml
<rom>
  <partition name="PARTITION_A" file="image-a.bin"/>
  <partition name="PARTITION_B" file="image-b.bin" erase="true"/>
  <partition name="PARTITION_C" erase="true"/>
</rom>
```

```text
write config.xml
```

This writes the first image, erases then writes the second target, and erases the third target. An explicit userdata erase inside XML follows this erase plan; the CLI command `erase userdata` stages a Recovery request instead. Direct XML rejects image writes to recognized NV primary/backup names; use the dedicated single-partition or directory workflow below.

## NV writing

Write an NV snapshot through its primary name:

```text
write <NV-primary-partition> <NV-snapshot-file>
```

Input must contain a valid 512-byte physical header and match the established NV format and length. The tool saves the current primary/backup headers and effective payloads, sends the payload to the primary name for the FDL to update both copies, and verifies physical readback. Headers are regenerated; unused partition tails are not restored.

`write <image-directory>` can include these NV files. A primary entry is required. If both copies are supplied, their effective payloads must agree; each pair runs once at the primary entry's position. A standalone write to the backup name is rejected. PAC named NV merging uses `NV_COMM`; an unknown loader NV dialect requires an explicit `protocol="r27-named"` product declaration, described below.

Dedicated snapshot restoration requires a recognized NV primary/backup pair, an established loader NV dialect, and physical GPT reads for backup and verification. Input is at most 16 MiB and must include the entire effective payload after the 512-byte header. A named NV read may return header-stripped or loader-processed data, so its output is not automatically valid snapshot input.

A mixed directory can use this `layout.xml`; replace all target names:

```xml
<rom>
  <partition name="PARTITION_NAME" file="image.bin"/>
  <partition name="NV_PRIMARY" file="nv-primary.bin"/>
  <partition name="NV_BACKUP" file="nv-backup.bin"/>
</rom>
```

The backup entry is optional. Snapshot restoration replaces the effective NV payload; PAC template merging preserves calibration items according to the package's NV rules.

## PAC product configuration fields

Select a configuration with `write <package.pac> <host-config.xml>`. The file is limited to 64 KiB and accepts a UTF-8 BOM. Unknown elements or attributes, duplicate entries, and mismatched product names are rejected. Configuration is read before uploading FDLs; requirements for selected operations are checked further during plan compilation.

| Location | Field | Meaning |
|---|---|---|
| `PacHostConfig` root | `product` | Required; exact PAC product name |
| Root | `address-word-order` | Address-operation parameter byte order: `little` or `big` |
| Root | `factory-timestamp` | Factory timestamp as 32-bit Unix seconds |
| Root | `write-efuse` | `0` or `1`; a selected WriteEfuse operation requires an explicit `1` |
| `NV` | `target` | Primary partition name of a selected NV_COMM operation |
| `NV` | `logical-size` | NV logical data length, an even number from 8 B to 16 MiB |
| `NV` | `protocol` | Currently accepts `r27-named`, declaring the established checksum-bearing named NV protocol |
| `NV` | `device-order`, `template-order` | `little`, `big-items`, `reversed-words`, or `little-index-big-items` |
| `Auth41` | `key`, `project-hex` | Product private key file and device project field encoded as 64 hexadecimal digits |
| `Vpac` | `utf16le-hex` | Hex-encoded UTF-16LE bytes including the terminating NUL |
| `SoftSim` | `expected-eid-hex` | Expected 10-byte EID encoded as 20 hexadecimal digits |

Replace `PRODUCT_NAME`, `NV_PRIMARY`, and `LOGICAL_SIZE` with product parameters:

```xml
<PacHostConfig product="PRODUCT_NAME">
  <NV target="NV_PRIMARY" logical-size="LOGICAL_SIZE"
      protocol="r27-named" device-order="little" template-order="little"/>
</PacHostConfig>
```

AUTH41 resolves `key` relative to the configuration directory and accepts an unencrypted PKCS1 RSA2048 PEM private key. `project-hex` corresponds to the 32-byte project field in M1.

### Product configuration defaults

`product` is mandatory. Other requirements depend on the selected package operations:

- `address-word-order` has no default; selected address-based operations require `little` or `big`.
- `factory-timestamp` has no default; selected `MiscDataCode`/`MiscDataCode2` operations require it. Values are `0`–`4294967295` Unix seconds.
- `write-efuse` defaults to `0`. Setting it to `1` permits a selected `WriteEfuse` operation; it does not add an operation to the package.
- NV byte orders default to `little`. Logical length uses configured `logical-size`, then a nonzero package `Block/Size`, then the established loader NV length. It is not inferred from physical partition capacity.
- Each NV `target` must be unique and match a selected `NV_COMM` operation. `reversed-words` additionally requires logical and template lengths divisible by four.
- `Vpac`, `SoftSim`, and `Auth41` may each appear once. VPAC is 4–512 bytes including a terminal UTF-16LE NUL, with no embedded NUL; SoftSIM EID is exactly 10 bytes.
- Numeric configuration fields accept decimal or lowercase `0x` hexadecimal notation. Hex byte strings have no `0x` prefix or separators.

NV representation values describe payload data independently of address-parameter word order:

| Value | Representation |
|---|---|
| `little` | Little-endian NV item headers |
| `big-items` | Big-endian item headers in the supported flat layout |
| `reversed-words` | Reverse bytes within each four-byte word before parsing, and reverse output back |
| `little-index-big-items` | Little-endian outer INDX container with big-endian per-core item headers |

The representation must match the actual input. Cross-representation merging is checked against implemented item rules; setting an order does not convert arbitrary calibration structures.

For AUTH41, replace `PRODUCT_NAME` with the product name and `PROJECT_HEX` with 64 hexadecimal digits:

```xml
<PacHostConfig product="PRODUCT_NAME">
  <Auth41 key="keys/rsa2048.pem" project-hex="PROJECT_HEX"/>
</PacHostConfig>
```

Invoke it with `write firmware.pac product.xml` after saving it as `product.xml`. The key is supplied as a separate file. AUTH41 checks the project field, processes the challenge, and sends one response; payload hex dumps are suppressed in trace output.

NV merge preparation checks data representation and calibration structure versions. Standard PAC `NV_COMM` uses logical data returned by the FDL. The Core API's physical NV merge flow reads both copies independently and rejects a merge when both are valid but disagree; this flow is not selected by the CLI host configuration.

Address-based `NV`/`NV_NAND` uses package `Block/Base` and `Block/Size` plus the configured address word order; its implemented item representation is little-endian. `CHECK_NV`/`CHECK_NV2` requires a preceding prepared NV result at the same address/name with matching length, and compares all bytes except the first four counter bytes. `WriteVpac` uses the configured value, `ReadVpac` saves the reply, and `Soft_SIM` saves the flash UID before writing and checks the EID afterwards. Factory timestamps are sent after the corresponding image write.

## Layout and physical restoration

The following commands run in FDL2.

| Command | Description |
|---|---|
| `repartition <rom.xml>` | Replace the entire partition layout according to XML |
| `write-rename <partition> <image>` | Temporarily change a GPT partition name, write, then restore the original names and geometry |
| `restore-raw <partition> <snapshot>` | Save the current complete partition, write a physical snapshot through a temporary alias, and verify readback |
| `restore-raw <backup-directory>` | Validate all inputs against a complete manifest, save original data, restore each partition, and verify the final aggregate state |

Physical restoration requires matching eMMC/GPT geometry and the corresponding alias-write support. Directory restore handles USER partitions; hardware BOOT entries, missing files, or unsupported formats reject the batch. GPT GUIDs, types, and attributes may be regenerated.

Complete eMMC bundles produced by `read all` include hardware BOOT entries and therefore cannot be restored as a whole through this command. Eligible GPT partition images can be passed individually to `restore-raw <partition> <snapshot>`.

On Ctrl+C during directory restore, the active alias transaction restores the GPT, then the operation stops without starting the next partition. Completed writes are not automatically rolled back on failure.

### Checks before restoration

Single-partition `restore-raw` requires a raw byte snapshot exactly as long as the physical target partition. Android sparse is rejected, and BTHD data is checked against the corresponding alias-write rules.

Directory restore reads a `raw-partition-backup-v1/v2/v3` manifest. The backup must be complete, without recorded coverage limitations, and file lengths, sources, and partition coverage must agree. For version 3 manifests, restoration also verifies image and GPT evidence SHA-256 digests. The current alias backend requires eMMC with 512-byte sectors and a 128-entry GPT, with disk capacity and partition layout matching the backup.

Directory restoration validates and freezes all sources before checking device geometry and saving current device data. Single-partition preparation first reads the target geometry to establish the required snapshot length. Original contents are checked again before submission to detect changes since preparation. Recovery data is saved in a new directory outside the source backup; allow disk space for frozen inputs, original partition backups, and frozen copies of those backups.

The alias table must round-trip through the loader's legacy GPT format: contiguous layout starting at 1 MiB, fixed sizes in whole MiB, and names within the receiver's limits (at most 30 characters on this path). Preparation reports any mismatch before submitting a temporary GPT. Restoring the old GPT restores names and geometry, not partition contents that have already been overwritten.

### Execute and inspect a restore

For an individual physical snapshot:

```text
restore-raw <partition> <snapshot-file>
```

For a complete, supported USER-partition backup bundle:

```text
restore-raw <backup-directory>
```

The directory must include `manifest.json`, `gpt-primary-header.bin`, `gpt-entries.bin`, and every image named by the manifest. Names, offsets, lengths, sector size, and disk capacity must agree with the device. Version 1 and 2 manifests lack the mandatory image hashes of version 3; matching lengths alone cannot detect changes made after backup if file sizes remain unchanged.

The CLI prints a new recovery directory before execution:

| File or directory | Purpose |
|---|---|
| `before-partition.bin` | Original complete target bytes for a single physical restore |
| `original-gpt-header.bin`, `original-gpt-entries.bin` | Original primary GPT evidence |
| `original-backup-gpt-header.bin`, `original-backup-gpt-entries.bin` | Backup GPT evidence for physical restoration |
| `restore-layout.xml`, `restore-table.bin` | Original names/geometry represented in the loader's recovery dialect |
| `execution.txt` | Individual physical transaction state |
| `plan.txt`, `directory-execution.txt`, numbered subdirectories | Directory order, overall state, and each partition's recovery material |
| `durability.txt` | Windows file-commit versus parent-directory persistence information |

For an uncertain failure, inspect these records and the reported original/cleanup errors before choosing the next operation. `restore-layout.xml` describes a layout-only recovery; it does not restore overwritten image bytes. `write-rename` saves GPT recovery inputs and checks restored names/geometry, whereas `restore-raw` additionally saves original partition bytes and verifies their replacement physically.

### Repartition XML

`repartition` and `write <config.xml>` share the base XML structure but perform different operations. The root `storage` field accepts `gpt`, `emmc`, `ufs`, or `nand`; omission uses GPT. `sector_size` defaults to 512 and accepts powers of two from 512 to 4096. Optional `disk_size` must be a positive, sector-aligned byte count.

GPT defaults to v1 table encoding. Set `repartition_format="legacy-gpt"` to explicitly select the legacy format. `address` specifies an absolute start and `gap` a relative gap; v1 entries cannot specify both. Legacy GPT does not support arbitrary gaps. `size="remaining"` is permitted only for the last entry. NAND uses the legacy MiB-unit table and does not accept `address` or `gap`.

Repartitioning does not write images named by `file` attributes or automatically relocate existing contents. It replaces the complete layout and requires a complete target partition list.

The XML unit is **bytes**, including when the tool converts it to a legacy MiB-unit wire table. Fixed v1 GPT sizes and gaps must be sector-aligned; fixed legacy GPT/NAND sizes must be whole MiB. For v1 GPT, omitted first address/gap starts at 1 MiB and later omitted gaps are zero. Legacy GPT starts at 1 MiB and requires contiguous entries. Default GPT receiver limits are 128 entries and 30-character names, subject to the loaded firmware's contract.

Structure example for a two-partition target layout; replace the names and sizes with the complete intended layout. Here 1048576 is a 1 MiB starting offset and 16777216 is a 16 MiB example size:

```xml
<rom storage="gpt" sector_size="512" repartition_format="v1">
  <partition name="PARTITION_A" address="1048576" size="16777216"/>
  <partition name="PARTITION_B" size="remaining"/>
</rom>
```

Save the actual layout as `target-layout.xml`, then execute:

```text
repartition target-layout.xml
parts
```

The first command reports the FDL acknowledgement; `parts` then refreshes the layout and exports the readable result.

## Boot targets

Use `reboot <target>` in FDL2:

| Target | Request |
|---|---|
| `recovery` | Enter Recovery |
| `sideload` | Enter Recovery's ADB sideload mode |
| `sideload-auto-reboot` | Enter sideload and let Recovery reboot automatically afterwards |
| `rescue` | Enter Recovery rescue mode |
| `fastbootd` | Enter userspace fastbootd provided by Recovery |
| `recovery-wipe` | Write a wipe-confirmation request and reboot immediately; hidden from normal help |

A targeted reboot checks for a conflicting firmware firstmode setting when its location is known, then writes and verifies the 4096-byte BCB block before sending reset. It preserves bytes from offset `0x340` onward. Success confirms the reset acknowledgement; the bootloader and Recovery determine whether the target is reached. `fastbootd` requires compatible Recovery and dynamic partitions. `erase userdata` only writes and verifies the wipe request, retaining the current connection.

## Firmware and factory modes

| Command | Stage | Description |
|---|---|---|
| `enable-write` | FDL2 | Request firmware write permission for the current download session; invoked explicitly |
| `firstmode <value>` | FDL2 | Set a firmware-defined boot-mode byte, 0–255 |
| `pc-mode <mode>` | Offline | Request a PC-tool mode, 1–0x3f; no port argument is accepted |

`pc-mode 0x02` requests auto-download and may erase SPL on some firmware. `0x15` requests autotest. `0x17` enters the programkey flow and may involve eFuse programming. Use the firmware's PC-tool mode definitions for other values.

`enable-write` requests permission for FDL storage operations; it does not unlock the Bootloader. Select `firstmode` values from the product's boot-mode definition. `pc-mode` waits up to 120 seconds for an interface, uses frequency zero, and requests the mode once; auto-download then waits up to 30 seconds for the same physical device to reconnect. Run this offline command from a separate invocation, such as `uniflash-core "pc-mode 0x02"`, to avoid the interactive startup handshake.

For `pc-mode 0x17`, the CLI sends PROGRAM_KEY, waits for the firmware result, then sends an EXIT request with the power-down value `0xffff`. A success reply does not independently verify the eFuse state.

## Offline image processing

```text
decrypt-image <encrypted> <out> <key-file> <plaintext-sha256> [format]
unpack-image <image> <out> <format> <output-sha256>
```

Neither command requires a device. The SHA-256 argument is the expected output digest as 64 lowercase hexadecimal digits. Output is committed only after verification.

Inputs are frozen before processing. The output parent directory must already exist. The output must differ from the input and, for decryption, from the key file. A successful commit replaces an existing output; validation failure before commit leaves it intact. Temporary storage is needed for the input snapshot and output. Use a separately established expected **output** digest; the input file's digest is not a substitute. Keys are binary files, not textual hexadecimal strings.

| Decryption format | Key and output |
|---|---|
| `r27` (default) | A 36-byte key file: LE32(32) followed by a 32-byte key; AES-256-CBC, retaining original alignment padding |
| `sprd128` / `sprd256` | A raw 16 / 32-byte key; processes supported SPRD containers and outputs the plaintext payload only |
| `sprd128-signed` / `sprd256-signed` | As above, with additional checks on the corresponding signature trailer structure and digest |

### Decryption input requirements

- **`r27`:** nonempty ciphertext with a length divisible by 16. The key file begins with bytes `20 00 00 00` followed by the 32-byte key. AES-256-CBC uses the format's fixed IV bytes `00` through `0f`; output retains alignment padding.
- **`sprd128` / `sprd256`:** a 512-byte BTHD version-1 header followed by the declared encrypted payload. The payload length must be positive and divisible by 16, and the unsigned file ends immediately after it. The supported header has packed and firmware-size fields zero, a zero payload-hash field, a 16-byte IV field at offset 60, and zero bytes from offset 76 onward. The tool applies the format-specific IV adjustment.
- **Signed SPRD forms:** the same encrypted payload envelope plus the supported 96-byte SPRD trailer and 564/596-byte content/key certificate structure. Container ranges and the stored payload digest are checked before decryption. These structure/digest checks do not perform device-trusted RSA signature verification.

Supply the format explicitly when using SPRD input:

```text
decrypt-image "encrypted.bin" "plaintext.bin" "key.bin" <plaintext-sha256> sprd256
```

### Unpacking input and output

| Format | Input requirements | Output |
|---|---|---|
| `sci1` | Valid SCI1 directory with a unique modem entry, at most 10 entries, bounded nonoverlapping regions, and an end marker | Modem bytes; the optional 20-byte SHA-1 prefix is removed |
| `sprd-sci1` | Packed BTHD v1, supported SPRD signature trailer, modem discoverable within the first seven SCI1 entries, no SHA-1 modem prefix, matching firmware length | Modem payload only |
| `sansa-view` | Packed BTHD v1 with a valid runtime subrange and supported 1024-byte Sansa tail; resulting view at most 20 MiB | 512-byte adjusted header + runtime payload + original 1024-byte tail |

`sansa-view` reproduces the buffer presented to the loader's verifier; it does not re-sign the image or report signature acceptance. Encrypted content certificates and unsupported trailer layouts are rejected. The requested format is always explicit:

```text
unpack-image "packed.bin" "modem.bin" sci1 <output-sha256>
```

## Startup options, aliases, and logging

Run the following commands in the system terminal. Each startup selector must be the sole process argument; inside the UniFlash-Core shell, use `help` for command help.

- `uniflash-core --help` or `uniflash-core -h`: display help.
- `uniflash-core --version` or `uniflash-core version`: display the version.
- `uniflash-core protocol-test` or `uniflash-core test`: run the built-in protocol tests.

Inside UniFlash-Core, `dump [directory]` is a compatibility alias for `read all [directory]`, hidden from normal help. Short aliases are `r` = `read`, `w` = `write`, `e` = `erase`, and `?` = `help`.

Set `UNIFLASH_PERF=1` for performance timing or `UNIFLASH_TRACE=1` for detailed communication logs. Traces may include transferred data; AUTH41 payload hex dumps are suppressed.

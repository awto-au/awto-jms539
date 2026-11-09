# awto-jms539

Research into an ORICO **6648SUSJ3-BK** four-bay USB-SATA dock, as identified
by its owner, reporting JMicron USB ID `152d:0539`. A
[2012 teardown](https://news.mydrivers.com/1/218/218034.htm) found JMS539 and
JMB321 chips in one 6648SUSJ3 sample; it does not establish this dock's board
revision or firmware compatibility.

## Status

- The bridge reports product `5392` and firmware **31.00.40.06** through the
  vendor SCSI version command `E0 F4 E7`.
- **Repeatable flash-read captures have been obtained, but the physical flash
  capacity and a recovery procedure are unverified.** No update was
  intentionally performed. A `jms578flash` extraction attempt did not finish.
  The earlier Wine probe did not press Update; its log did not record explicit
  raw SCSI traffic, but does not conclusively rule out device commands.
- A later targeted, data-in-only probe of the updater's `DF ... FA` flash-read
  command returned no data and timed out. Linux reset the dock. A subsequent
  standard SCSI readiness check also timed out and triggered another dock
  reset. After a power cycle, both disks re-enumerated and the kernel read their
  capacities; the 1 TB volume was automatically mounted.
- Subsequent testing with the dock's disks unmounted produced matching reads
  of the first 64 KiB and of the first 128 KiB of the bridge's flash-read
  address space. The second 64 KiB is identical to the first: this could
  indicate address wrapping or duplicate contents, not a confirmed chip
  capacity. The 1 TB volume was remounted after a successful readiness check.
  No erase or write CDB was sent in these later tests.
- ORICO's JMS539B version 40.16 package lists 3549/3559 and 9548/9558 models;
  it does not list 6648SUSJ3-BK. Its image contains identifier `5391` at
  offset `0xbff4`, while the dock's version response contains `5392`. The
  significance of this difference is unknown.
- A [third-party listing](https://www.usbdev.ru/files/jmicron/jms539firmware/)
  provides an image named `JMS539_B_31.00.40.06.BIN`. All 49,408 bytes match
  the beginning of the dock's repeatable capture, including `5391` at
  `0xbff4`. The image is shorter than the 64 KiB capture.
- The attempted SPI probe returned `7f9d207f`. An earlier identification as
  `Pm25LD020` with 256 KiB capacity was a guess, not a finding; its proposed
  flash configuration has been disabled. The updater's table maps
  `7f 9d 20` to 64 KiB, but that is not independent confirmation of the
  installed chip or its write commands.

## Windows updater investigation

The supplied updater is a 32-bit Windows C++Builder application with no PE
debug directory or COFF symbol table. It retains form and event RTTI; the
Ghidra script in `ghidra/scripts/RecoverUpdaterRtti.java` recovers 31 control
fields and 12 event-handler names into the local project.

Static analysis of this updater found:

- Refresh enumerates candidate USB storage and SBP2 devices and sends the
  vendor CDB `FF 04 4A 4D 55` to candidates before identifying their JMicron
  chip. Its effects on other devices are unknown. The Update handler uses the
  currently selected device entry, but startup/refresh is not confined to it.
  In both downloaded images, that CDB sets a mode flag and appears to restrict
  the commands accepted afterward. The dock rejected both that command and
  the corresponding `FF 04 4A 4D AA` exit command as invalid fields in the
  CDB; a mode change was not confirmed.
- Startup/refresh also calls a JMS539 check that can automatically repair
  flash: when detected capacity is at least 128 KiB and exactly one of two
  64 KiB firmware copies passes its validity check, it writes the valid copy
  over the other. The Wine trace does not establish whether this path ran.
- On the same JMS539 path, the flash routine writes the image at offset
  `0x0000` and, when detected capacity is at least 128 KiB, writes and
  verifies a second copy at `0x10000`. With smaller detected flash, it writes
  only one copy.
- In one update configuration, that routine first reads 4 KiB from offset
  `0xC000` and overlays it on the image in memory. The write length depends
  on the input image; blindly writing a padded image would not necessarily
  preserve the dock's existing configuration.
- The updater chooses write flags and chunk boundaries using its detected
  flash type and geometry. The actual erase scope on this dock is unverified;
  limiting requested write addresses to the first 64 KiB does not by itself
  establish that higher addresses would be preserved.
- A copy is valid when bytes `0xBFF0..0xBFF3` are `55 AA AA 55`, bytes
  `0xBFF4..0xBFF7` hold the chip identifier (`5391` here), and the
  big-endian word at `0xBFFE` matches a CRC-16 (polynomial `0x1021`, initial
  value 0). The CRC processes bytes `0x0000..0xBFFB` as little-endian 32-bit
  words, most significant nibble first. Both 64 KiB halves of the 128 KiB
  capture and the downloaded 31.00.40.06 image pass this check (`F929`).
- The updater's dual-copy logic does not establish that the boot ROM falls
  back to the copy at `0x10000`. No public source was found that documents
  boot-ROM fallback or a USB command that selects a copy.
  If the flash is physically 64 KiB, the identical second half in the capture
  is address wrap-around rather than a backup copy.
- The JMS539 HDD-firmware branch can issue SCSI `WRITE(16)` commands to an
  area near the end of the selected disk. This branch is reachable through the
  `JMS539 HDD FW` option or a detected flash-type condition; its exact use on
  this dock has not been established.
- The JMS539 backup path polls a status bit using `FF 04 12` before each
  `DF 10 ... FA` read, in chunks of up to 8 KiB. The later dock capture used
  this sequence with 4 KiB reads and a two-byte status transfer.
- In the JMS539 image-check path, `FUN_00413ab0` checks only the first three
  characters of the chip identifier. Passing that check would not establish
  that a `5391` image is compatible with a dock reporting `5392`.
- A previous Wine startup probe exposed host drives through automatic mappings.
  Do not assume that running the updater under Wine isolates other disks.

These are static-analysis findings, not a tested update procedure. No update
should be attempted until the image, target selection and write path are
verified.

## Design documentation and SDK

The [two-page JMS539 datasheet](https://www.datasheethub.com/uploads/2023/07/jms539-datasheet.pdf)
describes an 8051 core and lists a design kit containing a datasheet, design
guide and evaluation board. It does not document the flash protocol or
identify a firmware SDK or compiler. No verified public JMS539 SDK or design
guide has been found; the datasheet does not establish whether an SDK exists
or is currently available.

A [third-party listing](https://www.usbdev.ru/files/jmicron/jms539datasheet/)
advertises a separate v0.5.4 datasheet, but its download returned HTTP 500
when checked, so its contents have not been verified. JMicron's
[contact form](https://www.jmicron.com/contact) offers a technical-support
option for requesting the design guide, SDK and programming documentation.
ORICO should be asked separately for firmware and recovery instructions
specific to 6648SUSJ3-BK.

## Linux tooling

[BertoldVdb/jms578flash](https://github.com/BertoldVdb/jms578flash) targets
JMS578, not this bridge. Its SPI polling loop has no timeout, and its firmware
layout is chip-specific. Both `-flash` and `-dumprom` can erase flash when
`-unsafe` is enabled; neither is a safe backup command.

Upstream [issue #12](https://github.com/BertoldVdb/jms578flash/issues/12)
reports the same `7f9d207f` response on a different dock with a chip marked
`Pm25LQ512`, but provides no working fix. This does not identify the flash in
this dock. The open flash-support PRs and examined forks add other IDs; none
establishes JMS539 support for this ID.

[projectgus/jms567ctl](https://github.com/projectgus/jms567ctl) and its
derivative [xx25/jms567settings](https://github.com/xx25/jms567settings)
use the same `DF 10 ... FA` layout to read JMS567 flash in 4 KiB chunks.
They were not used for the successful capture and do not establish general
JMS539 support.

[One report](https://wiki.archlinux.org/title/User:Boscowitch/Sharkoon_5-Bay_RAID_Box)
recommends USB 2.0 for updating a different JMS539 enclosure. That is not a
verified fix for this dock; a failed read can reset the whole dock and
interrupt mounted volumes.

The Python entry point is `scripts/dev.py`; run
`python3 scripts/dev.py describe` for machine-readable commands or
`python3 scripts/dev.py --help` for help. Output is logged to
`tmp/logs/dev.log`.

`sudo python3 scripts/dev.py version /dev/sgN` sends only the version command
to the explicitly supplied SCSI generic node. Verify the node and its USB
parent before use; names such as `/dev/sg2` can change after reconnecting.
The command requires `sg_raw` and rejects short or invalid version responses.

`python3 scripts/dev.py plan IMAGE --backup CAPTURE` reconstructs a single
first-region write attempt **offline**, assuming updater flash type 1. It
checks the image and capture trailers and CRCs, overlays the capture's
configuration as the updater does when NVRAM preservation is selected, and
reports the resulting lengths, hashes and CDBs. Use `--use-image-config`
instead of `--backup` to model the alternative. `--mode` selects the initial
mode 2 or retry modes 1 and 3; mode 3 is used by the updater's erase-only path
and may erase the whole flash. The plan does not include status polling,
readback or reset commands. For a `0xC100`-byte image, only the first `0x100`
bytes of the overlaid configuration are included in the updater's comparison,
followed by `0x100` zero-filled transfer bytes.

This is not a flash implementation or a safe hardware procedure. Flash
identity, physical erase scope and data-out behavior are unverified, and
the addresses in a plan do not prove that other flash regions are preserved.
The actual updater can retry with mode 3 and write a second region. Run the
offline checks with `python3 scripts/dev.py test`. The Ghidra script
`ghidra/scripts/TraceUpdaterWritePlan.java` independently emulates the
updater's chunk and CDB construction without executing its SCSI transport.

## JMS567 settings tool review

The complete source and comments of
[xx25/jms567settings](https://github.com/xx25/jms567settings/tree/5ec8935c36132e586c80b39372d438903d307fe1)
were reviewed at commit `5ec8935c36132e586c80b39372d438903d307fe1`. It targets
the JMS567 family containing `##VER:0103`; neither local JMS539 image contains
that marker. Its behavior must not be treated as a JMS539 programming or
recovery procedure.

Key paths: [read](https://github.com/xx25/jms567settings/blob/5ec8935c36132e586c80b39372d438903d307fe1/jms_settings.py#L140),
[erase](https://github.com/xx25/jms567settings/blob/5ec8935c36132e586c80b39372d438903d307fe1/jms_settings.py#L151),
[write safety wrapper](https://github.com/xx25/jms567settings/blob/5ec8935c36132e586c80b39372d438903d307fe1/jms_settings.py#L303),
and [command handlers](https://github.com/xx25/jms567settings/blob/5ec8935c36132e586c80b39372d438903d307fe1/jms_settings.py#L395).

| Commands | What the source does |
|---|---|
| `info` | Reads the chip and interprets UAS and a two-byte spin-down field even if the family marker is absent. Those field meanings are not established for this JMS539. |
| `dump`, `verify` | Read a hard-coded 64 KiB in 4 KiB chunks, without the updater's status polling or a per-chunk length check. |
| `restore`, `set-uas`, `set-spindown` | Issue `DF 02` erase, then rewrite 64 KiB, reset and read back; they do not merely write the changed configuration bytes. The source describes `DF 02` as a whole-chip erase on JMS567; its extent on JMS539 is unverified. |

Other important limitations in that revision:

- The family test is a substring search, not an exact version, flash-geometry
  or CRC check. The new image must be 64 KiB, but the current read is not
  length-checked before being saved as the backup. A short read containing
  the marker, or `--force`, can therefore lead to an incomplete backup. The
  setting commands can report "already set" before checking the family.
- A short `dump` is written and reported successfully. `verify` exits with
  an error on unequal lengths, but counts only differing bytes in the
  overlapping prefix; it can report zero differences for an empty read.
- After resetting, the tool reopens the same device path without establishing
  that it is the same USB device. It ignores the write wrapper's failure
  return, so a family-check refusal or failed post-write verification can
  still result in exit status zero.
- The printed recovery command puts the global `--force` option after the
  `restore` subcommand, which its parser rejects. Its claims of ROM fallback
  and universal reversibility are not verified for this dock.
- The chip-info comment calls the version bytes BCD. The saved dock response
  ends `1f 00 28 06`, which is not valid BCD; interpreting the individual
  bytes as decimal gives the reported `31.00.40.06`.

The reviewed
[py3_sg revision](https://github.com/tvladyslav/py3_sg/blob/524492b11a6218841cc2d4fe8246bbf1e5674392/py3_sg.c)
uses ordinary indirect I/O and returns `dxfer_len - resid` bytes for reads;
its write wrapper does not check the residual. If the earlier full-residual
behavior recurs with that helper, the tool could receive empty flash data,
but this has not been tested against the dock. An offline simulation using
synthetic files and a stub SCSI module reproduced an empty successful dump, a
zero-byte forced backup and a 4 KiB backup accepted without `--force` when the
marker was present. It also reproduced successful exits after family refusal
and simulated readback failure. No SCSI commands were sent.

## Configuration decoding

`python3 scripts/dev.py config IMAGE [OTHER_IMAGE]` decodes the first 256 bytes
at `0xC000` and, with two files, reports every differing byte in that range.
It accepts regular files only and sends no device commands. It checks the
firmware marker and CRC before decoding; **that CRC does not cover the
configuration block**, so it does not verify the settings. The JSON includes
the raw block, descriptor errors, flags, candidate timer values, and how much
of the updater's 4 KiB overlay is available in each file.

[xx25/jms567settings](https://github.com/xx25/jms567settings) describes a
similar layout at `0xC000` for JMS567, while
[9500/ds500u3-jms567-uas](https://github.com/9500/ds500u3-jms567-uas)
independently documents related fields. The former restricts writes to a
verified `##VER:0103` firmware family; neither local JMS539 image contains
that marker. Its write operations and other chips' feature-bit definitions
must not be assumed safe or applicable to this dock.

The local 40.06 capture and 40.16 image have the same decoded identity:

| Offset | Stored field |
|---|---|
| `0xC000`–`0xC003` | Little-endian USB VID:PID `152d:0539` |
| `0xC00C`, `0xC030` | Packed ASCII USB strings `JMicron` and `USB to ATA/ATAPI Bridge` |
| `0xC054` | Empty serial descriptor; the live all-zero USB serial is not explained |
| `0xC0C8`, `0xC0D0` | Candidate SCSI inquiry strings `JMicron` and `Generic` |
| `0xC0E0`, `0xC0F0`, `0xC0FE` | Markers `HD`, `BC`, `JM` |
| `0xC0E7`, `0xC0F2`, `0xC0F3` | Raw flags `00`, `18`, `01`; most meanings remain unverified |

Static analysis provides stronger evidence for the changed bytes. The 40.06
loader sets up a read from `0xC000` into XDATA `0x3800`, checks the markers,
and tests bit 3 of `0xC0F2`. When set, its code at CPU `0x4A79` sets up a
four-byte copy from `0xC0F4` into a working countdown, labeled
`Auto Spin Down Timer` in the firmware. The countdown code subtracts across
all four bytes. The 40.16 code at `0x4B25` has a corresponding path.

| Field | 40.06 capture | 40.16 image |
|---|---|---|
| `0xC0F2` bit 3 | Set | Set |
| `0xC0F4`–`0xC0F7` | `2d 00 01 2c` = `754975020` big-endian | `00 00 07 08` = `1800` big-endian |
| `0xC0F8` | `00` | `2d` = `45` |

For comparison, the JMS567 tool interprets only `0xC0F6`–`0xC0F7` as a
big-endian timeout in seconds, giving 300 and 1800. **That is not a verified
five-minute timeout on this JMS539:** 40.06's high bytes are nonzero and the
static code appears to use all four. The unit, ROM helper behavior and actual
live spin-down timing remain unverified. In 40.06, `0xC0F4` is also copied
separately to another working byte; 40.16 instead reads `0xC0F8` and labels
that value `Temp boundary`, with a minimum of 45. Its units and effect are
not confirmed.

If the updater preserves the capture's configuration while installing 40.16,
the new code would receive the capture's `2d 00 01 2c` timer bytes, not the
candidate image's `00 00 07 08`. The resulting live behavior has not been
tested.

The 40.06 capture has zeros at `0xC100`–`0xCFFF`; the 40.16 image ends at
`0xC100`, so its bytes beyond the decoded block cannot be compared. The
capture and flash geometry remain provisional. Do not edit or flash either
configuration based on these interpretations.

## Flash-read capture

The dock returned `00 00` to a two-byte `FF 04 12` status read. Each subsequent
4 KiB `DF 10 ... FA` read returned SCSI status good, but Linux reported a
4,096-byte residual. `sg_raw` therefore emitted no data despite its successful
exit status. An `SG_FLAG_MMAP_IO` diagnostic exposed the underlying buffer:
two complete passes, initialized with different byte patterns, produced
identical data at every offset. The cause of the residual is unconfirmed.

The local, Git-ignored captures are:

| Address range | Passes | Size per file | SHA-256 per file |
| --- | --- | --- | --- |
| `0x00000`–`0x0ffff` | `firmware/device/jms539-6648susj3-64k-pass{1,2}.bin` | 65,536 bytes | `91ce1af69badce5d775c0b44e5ddd2f1a014680af2817a6b26f66a889007f799` |
| `0x00000`–`0x1ffff` | `firmware/device/jms539-6648susj3-128k-pass{1,2}.bin` | 131,072 bytes | `decc0e979955115d5240360a1b57f894129fa82c0c4d3eece25fd75c0295161f` |

The first 64 KiB agrees across both capture sizes; the 128 KiB capture consists
of two identical 64 KiB halves. This is a repeatable read of the address
space, not proof of the physical flash size or a tested restore procedure.
The local script `analysis/initial/sg_residual_probe.py` is specific to the
then-current USB port, device number and SCSI nodes; it must not be blindly
rerun after a reconnect. Read tests can reset the whole dock, so unmount all
its volumes before testing.

## Installed 40.06 vs ORICO 40.16

The first 49,408 bytes of the dock capture are byte-identical to the
downloaded `JMS539_B_31.00.40.06.BIN`. That image was compared with ORICO's
`JMS539B_PM_v40.16.BIN` (SHA-256
`58783dfa4cd214a2b3590612ad15001d13aa38146f72f0c9cb9f779904b3b8f4`):

| | 40.06 (installed) | 40.16 (ORICO) |
|---|---|---|
| File size | 49,408 | 49,408 |
| Code end | ~`0x82C9` | ~`0x8C5C` (+2.4 KiB) |
| Trailer | `55AAAA55 "5391"`, CRC `F929` | `55AAAA55 "5391"`, CRC `D414` |
| CRC check | pass | pass |

- Both images target the same `5391` chip ID and use the same header layout.
  The interrupt and jump vectors at `0x30–0x6F` differ only because code moved.
- After alignment, about 29 KiB of code is identical. Changes are spread
  across about 36 larger insertions and deletions, so 40.16 is a substantive
  revision, not just a configuration change.
- The apparent 256-byte configuration area at `0xC000` contains the USB
  identifiers and strings. Four bytes differ at `0xC0F4` and
  `0xC0F6`–`0xC0F8`; see Configuration decoding above.
- Debug strings added in 40.16 point to SATA bring-up and port-handling work:
  `SATA_SET_UDMAMODE`, `software reset`, `sata port off`,
  `id scan port`, `read_sector_count_signature`, `idle hdd-`,
  `Temp boundary`, `compliance=` and `Timeout...`. No 40.06 feature string is
  missing from 40.16.
- The configuration change does not explain the dock's `5392` product ID.

## Offline 8051 image map and ABI evidence

Offsets in this table are file/flash-read offsets, not 8051 code addresses.
The installed capture has not been proven to span the physical flash.

| File offsets | 40.06 capture / image | 40.16 image |
|---|---|---|
| `0x0000` to last nonzero byte | Through `0x82C9` | Through `0x8C5C` |
| Following bytes through `0xBFEF` | Zero-filled | Zero-filled |
| `0xBFF0`–`0xBFFF` | Marker, `5391`, metadata and CRC `F929` | Marker, `5391`, metadata and CRC `D414` |
| `0xC000`–`0xC0FF` | Configuration | Configuration |
| `0xC100`–`0xFFFF` | Zero-filled in the 64 KiB capture | Not present in the file |

The nonzero body includes code, embedded data and strings; their boundaries
are not fully classified. The CRC covers `0x0000`–`0xBFFB`, including most
of the trailer, but not the configuration. The identical 128 KiB capture
halves do not distinguish a second physical copy from address wrapping.

The datasheet identifies an 8051 core. For the supplied code, a `0x4000`
relocation is supported by the stub at file offset `0x0000`, which calls
CPU address `0x4200`, and coherent target code at file offset `0x0200`.
The existing D52 listings use this relocation. The low-address stubs are
not yet classified as reset/interrupt vectors or a ROM API table, and calls
below CPU `0x4000` reach code not supplied in these images.

In the timer path, 40.06 sets registers `R6:R7=0x38F4`, `R4:R5=0x3218`
and `R3=4` before calling unavailable code at `0x2B50`; a four-byte copy
is a supported interpretation, not a fully measured compiler ABI. It then
passes a four-byte value and the constant `0xB4` to another unavailable
helper. The corresponding 40.16 sequence uses `0x3C` instead. Conditional
branch targets land just after four bytes following the call to `0x1BF0`, so
those bytes appear to be inline data; the helper's predicate, effects and
timing units remain unverified. Do not let a linear disassembler interpret
those bytes as confirmed instructions.

Static command-path tracing locates `E0 F4 E7` and `DF` recognition near CPU
`0x8F30` and `0x8F3E` in 40.06, and `0x9804` and `0x9816` in 40.16.
On one conditional path, bytes `FF 04 4A 4D 55` at XDATA `0x300F..0x3013`
set bit `0x21.5`, and `FF 04 4A 4D AA` clears it. That bit gates checks for
`FF 04`, `E0 F4 E7` and `DF`. This is static code evidence, not proof that
the path is active on the dock; the live tests of the exit command returned
invalid-field errors.

The candidate command dispatcher loads the first command byte and calls the
unavailable helper at `0x1C2D`. The following bytes have the structure of a
sorted inline table of two-byte targets and one-byte opcodes, ending in
`00 00` and a default target. Its `DF` entries and the corresponding paths
are:

| | 40.06 | 40.16 |
|---|---|---|
| Dispatcher | `0x75A4` | `0x7CAE` |
| Apparent inline table, including default | `0x75AB..0x7620` | `0x7CB5..0x7D24` |
| `DF` target in table | `0x7683` | `0x7D84` |
| `FB` check | `0x76CB` | `0x7DD9` |
| Non-`FB` call to unavailable `0x1488` | `0x77D2` | `0x7EE0` |

The `DF` path examines XDATA `0x301A`, consistent with CDB byte 11. For
`FB`, it copies the apparent length and address fields into XDATA
`0x3181..0x3182` and `0x317E..0x3180`; then one branch on the low nibble of
byte 1 calls `0x3334`, `0x330F`, `0x3720` or `0x3251` for values 1, 2, 3 or
7 respectively. The 40.06 and 40.16 branch instruction bytes are identical.
Those helper bodies are outside the supplied slice. An `FA` byte takes the
non-`FB` path into `0x1488`, whose body is also unavailable. Consequently,
the exact read/write implementation, erase scope, status semantics and
boot-copy selection remain unresolved.

An offline comparison with the available Keil `C51S.LIB`, `C51C.LIB` and
`C51L.LIB` used relocation-masked signatures: 155 non-short C-library
function signatures produced no exact or heuristic near match in either
supplied code slice; 19 were too short for reliable identification. The reused
parser excludes `?C?` runtime helpers from that pass. A separate scan of 624
helper segments across those libraries found 576 absent, 45 too short and three
multiple matches in each image. The three are the same low-complexity
signature, 11 zero bytes followed by `RET`, occurring in stub padding at CPU
`0x4125` and `0x4165`; they do not establish a library match. Masked matching
passed a synthetic positive control. `python3 scripts/keil_helpers.py --help`
describes the helper scan, which uses the parser and matcher in
`../awto-ddc/scripts`; its signatures and results are kept under ignored
`analysis/initial/`.

A local SDCC 4.6.4 probe, compiled for both small and large models, passed the
first of three arguments in `DPTR` and the others through static parameter
slots, unlike the register setup above. Neither test identifies the firmware
compiler: runtime code may be in the unavailable lower-address region, and a
ROM helper may use a custom ABI. The SDCC probe is also under
`analysis/initial/`.

No verified JMS539 SDK, library match, compiler family or exact compiler
version is available yet. Do not transfer Realtek-specific Keil helper names
or assume that a missing match disproves Keil or SDCC.

### Relocated initialization checks

The 40.06 function at CPU `0xB0CE` writes `5A C3 69 E1` to XDATA addresses
`0x4C00..0x4C03`. The function at `0xB0E1` compares those four bytes and
returns carry clear only if they all match. The startup path at `0x4200`
checks them first and calls the writer when the comparison fails. The
corresponding 40.16 functions at `0xBA40` and `0xBA53` are byte-identical.
The purpose and persistence of that XDATA range are not established.

### Memory writes and register candidates

The decoded write inventory and XDATA-read inventory are tracked for both
images:

- [40.06 write sites](re/jms539/memory_write_sites_40.06.tsv),
  [XDATA reads](re/jms539/memory_xdata_read_sites_40.06.tsv), and
  [address summary](re/jms539/memory_address_summary_40.06.tsv)
- [40.16 write sites](re/jms539/memory_write_sites_40.16.tsv),
  [XDATA reads](re/jms539/memory_xdata_read_sites_40.16.tsv), and
  [address summary](re/jms539/memory_address_summary_40.16.tsv)
- [Curated observations and related-chip hypotheses](re/jms539/memory_findings.tsv)

The write inventory distinguishes direct internal RAM (`0x00..0x7F`), direct
SFRs (`0x80..0xFF`), bit-addressed locations, register banks, indirect internal
RAM and XDATA. Register-bank selection, indirect pointers and stack addresses
are retained as `?` where runtime state is unknown. A call has one
`stack_push_2` site representing two pushed bytes. The inventory also records
implicit DPTR and stack-pointer updates, but does not enumerate implicit
accumulator, B or PSW effects, interrupt-hardware writes or reads outside
XDATA. XDATA is a separate address space and may contain RAM or device
registers; the range alone does not establish which.

| Version | Decoded instructions | Write effects | XDATA stores (unknown target) | XDATA loads (unknown target) |
|---|---:|---:|---:|---:|
| 40.06 | 9,380 | 7,613 | 993 (34) | 903 (12) |
| 40.16 | 11,808 | 9,406 | 1,282 (54) | 1,080 (17) |

These are static sites in the current Ghidra listing, not execution counts
or coverage of undisassembled bytes and unavailable ROM. `encoded` addresses
come from an instruction; `local_straight_line` and `ghidra_inferred`
addresses are candidates, not verified runtime values. Conflicting or multiple
inferences remain `?` with alternatives. Constant and read/modify/write
patterns are local observations, not proof of device behavior.

The public [Synopsys DW8051 datasheet](https://www.keil.com/dd/docs/datashts/synopsys/dw8051_ds.pdf)
describes dual pointers and configurable peripherals but does not identify
JMS539's core or supply its register map. No direct `INC 0x86` selector
pattern occurs in the supplied slices; this does not exclude other sequences
or missing ROM. SFR `0xA8.7` is cleared and set around a command path, matching
the standard 8051 interrupt-enable convention; this is a JMS539 candidate,
not a confirmed register map. The 40.16 listing also writes SFR `0xE8` near
`0xA8` changes, but its function is unknown. A
[JMS539-specific teardown](https://syscall.eu/blog/2018/03/12/aigo_part1/)
confirms an 8051 and shows a boot-time firmware capture but does not publish
a register map; no JMS539-specific map was found in the public sources checked.

The [JMS567 analysis](https://github.com/9500/ds500u3-jms567-uas/blob/743529e7a29febf501cc187b96f3691905ed3245/docs/firmware-analysis.md)
uses XDATA `0x7043.0` to launch a command; both JMS539 images write `1` to
`0x7043` in several paths. The
[JMS578 SPI implementation](https://github.com/BertoldVdb/jms578flash/blob/30a91997f7d3a96b128041dbfa046c8536095887/jmshal/spi.go)
identifies `0x716D` as a DMA transfer limit; the JMS539 `DF FB` path writes
`FF` there before copying apparent length bytes to `0x7166..0x7167`. These
are useful cross-chip hypotheses, not confirmed JMS539 register semantics.
The related JMS578 SPI addresses `0x7140`, `0x7141`, `0x714C` and `0x7150`
have no fixed references in the current decoded listings.

### Cross-chip pattern sweep

[`scripts/cross_chip_patterns.py`](scripts/cross_chip_patterns.py) searches
whole images, not only Ghidra-decoded code, for the `MOV DPTR,#addr` idioms
used by the public JMS567/JMS578 tools. It writes
[`re/jms539/cross_chip_signatures.tsv`](re/jms539/cross_chip_signatures.tsv)
(counts, plus how many hits start a decoded instruction) and
[`re/jms539/cross_chip_signature_hits.tsv`](re/jms539/cross_chip_signature_hits.tsv).
The comparison images were the
[ds500u3 JMS567 build](https://github.com/9500/ds500u3-jms567-uas/blob/743529e7a29febf501cc187b96f3691905ed3245/firmware/DS500U3-JMS567-125.2.0.3-v3-uas-ncq.bin)
and the [jms578flash test image](https://github.com/BertoldVdb/jms578flash/blob/30a91997f7d3a96b128041dbfa046c8536095887/image/test/image_flash.bin);
these are not stored here. Byte matches suggest shared idioms but do not prove
the same register semantics on JMS539.

Observed results:

- **JMS567-style NVS loader.** 40.06 `0x4971` (40.16 has the same sequence)
  stores a 24-bit address `0x00C000` in XDATA `0x317E..0x3180`, stores
  `0x3800` in `0x7160..0x7161` and calls `0x329F` with `EA` cleared. It then
  checks `JM` at XDATA `0x38FE..0x38FF` and copies buffer offsets `0x00..0x03`,
  `0x06..0x08` and a 32-byte string at `0x0C`. This matches the
  [JMS567 layout](https://github.com/xx25/jms567settings/blob/5ec8935c36132e586c80b39372d438903d307fe1/jms_settings.py#L63-L71):
  VID, PID, config block, iManufacturer and `JM` at `+0xFE`. The JMS567 loader
  uses buffer `0x3B00` instead. This is static evidence of a flash-`0xC000`
  configuration read on JMS539.
- **`0x716x` DMA-style block, not the JMS578 PIO FIFO.** Neither JMS539 image
  contains `MOV DPTR` to `0x7140`, `0x7142`, `0x7148`, `0x714C` or `0x7150`.
  This conclusion covers the whole image, not just decoded code. The JMS567
  image uses `0x7140` eight times and `0x714C` seven times. JMS539 instead
  programs `0x7160..0x7161` (buffer), `0x7165`, `0x7166..0x7167` (length),
  `0x7168` (`0x41` when byte `0x315F` is `0xAF`, otherwise `0x42`), `0x7169`
  (the `0x315F` byte) and `0x716D`. `0xAF` is the AAI-program opcode on some
  older SST SPI flashes; that link is a guess.
  The jms578flash PIO SPI routine should therefore not be assumed to work on
  JMS539. In the NVS loader, `0x3181/0x3182 = 00/01` feed `0x7166/0x7167`
  while 256 bytes appear to be consumed. Either the length is counted in
  pages, or the high/low labels on `0x7166/0x7167` are reversed.
- **`0x7020..0x7026` + `0x7026.0` start/busy.** JMS539 writes a six-byte
  descriptor at `0x7020..0x7025`, sets `0x7026=1` and polls bit 0 until it
  clears. One 40.06 path at `0x9476` bounds the wait with a countdown at
  `0x7084`; the other, at `0xA05D`, has no timeout. JMS578 `spi_tx.asm` and
  the JMS567 image use the same registers.
- **`0x7078` timer idiom.** 40.16 `0xC24E` clears `0x7078` and re-reads it
  against `0x46`, matching the JMS578 `reset.asm` "reset slow timer, wait"
  pattern.
- **`0x7054`** is updated with read-modify-write operations (`AND EF/DF/7F`,
  `OR 07`, `=FF`). JMS578 `dumprom.asm` writes `0xE1` there to switch on an
  LED, so this is a GPIO/LED-register candidate.
- **Absent from JMS539:** `0x703B` (JMS567 SATA port select), `0x708C`
  (JMS578 code-map), `0x7800`, and the `0x78E1..0x791E` command-state block.
- **Coverage gap.** Of 47 JMS539 signature hits per image, 23 (40.06) and 19
  (40.16) are in bytes Ghidra did not decode. For example, 40.06 has eight
  `0x7078` references at `0xB81F..0xB8F0` and eleven of fifteen `0x7026`
  references outside decoded code. The memory-write inventory therefore
  undercounts MMIO use.
- **Inline data after `LCALL 0x1BF0`.** 40.06 has 11 call sites and 40.16 has
  12. Each is followed by four constant bytes, including ASCII `JM0P`, `JmmM`
  and `DEFA`. Only one site per image is protected as data. Ghidra decoded the
  inline bytes as code at 6 sites in 40.06 and 9 in 40.16. One resulting
  bogus inventory row is 40.06 `0x49A0 INC @R0`.

Regenerate with:

```bash
E=analysis/initial/ghidra-8051-research2/exports
F=analysis/initial/jms539-31.00.40.06
python3 -B scripts/cross_chip_patterns.py \
  --image 40.06=$F/v40_06_code.bin@0x4000 --image 40.16=$F/v40_16_code.bin@0x4000 \
  --instructions 40.06=$E/40.06/instructions.tsv \
  --instructions 40.16=$E/40.16/instructions.tsv \
  --image jms567_ds500u3=DS500U3-JMS567-125.2.0.3-v3-uas-ncq.bin@0 \
  --image jms578_test_flash=image_flash.bin@0 \
  --counts re/jms539/cross_chip_signatures.tsv \
  --hits re/jms539/cross_chip_signature_hits.tsv
```

### Ghidra findings and sibling comparison

The durable, image-hash-bound findings are in
[`re/jms539/ghidra_names_40.06.tsv`](re/jms539/ghidra_names_40.06.tsv) and
[`re/jms539/ghidra_names_40.16.tsv`](re/jms539/ghidra_names_40.16.tsv).
Add each finding to the appropriate TSV with its CPU address, name, type,
evidence, status and confidence. Only `[fw]`/`high` rows are applied to the
project; lower-confidence rows remain candidates. Currently each version has
nine applied findings and seven candidates. Confirmed function rows must
point to existing Ghidra function entries; unrelated names and comments are
not overwritten.

The ignored `analysis/initial/ghidra-8051-research2/` workspace contains the
saved projects and regenerated exports. The pipeline requires the existing
`v40_06_code.bin`, `v40_16_code.bin` 48 KiB slices and matching `.d52`
listings in `analysis/initial/jms539-31.00.40.06/`. These are generated from
the first `0xC000` bytes of the respective images; D52's `-b -d -x4000`
options produce the relocated listings. The firmware and generated
disassembly remain Git-ignored.

With `GHIDRA_HOME` pointing at a Ghidra installation, use:

```bash
# Create new projects only in an empty, dedicated workspace.
python3 scripts/ghidra_8051.py import --version both --workspace analysis/initial/ghidra-8051-new

# Apply current TSV findings and regenerate existing curated projects.
python3 scripts/ghidra_8051.py regen --version both --workspace analysis/initial/ghidra-8051-research2

# Regenerate the tracked memory inventories from the current exports.
python3 scripts/memory_writes.py --workspace analysis/initial/ghidra-8051-research2 --output re/jms539

# Produce a non-applying Ghidra Version Tracking report and a separate byte diff.
python3 scripts/ghidra_8051.py vt --workspace analysis/initial/ghidra-8051-research2
python3 scripts/ghidra_8051.py compare --workspace analysis/initial/ghidra-8051-research2
```

`import` refuses to overwrite a project; `regen` saves the applied findings
and stages exports before publication. A project property tracks managed
annotations: removing, downgrading or renaming an applied row makes `regen`
stop rather than leave a stale annotation. Restore the row or import into a
new workspace with the revised TSV. Newly confirmed rows and edits to their
evidence comments can be applied by regeneration. Two consecutive
regenerations produced byte-identical exports.

The exports include findings, instructions, functions, data, calls,
references, decompilation and a manifest. Current coverage is:

| Version | Instructions | Functions | Calls | Defined data units |
|---|---:|---:|---:|---:|
| 40.06 | 9,380 | 220 | 591 | 340 |
| 40.16 | 11,808 | 246 | 744 | 347 |

These are analysis results, not complete code coverage. Ghidra reports
decompilation completion for each defined function, but also warns about
unmapped ROM targets and control-flow warnings in both versions; the resulting
C can be partial. Three apparent tables following `LCALL 0x1C2D` per version
and the four bytes following each `LCALL 0x1BF0` are preserved as data rather
than disassembled as code:

| Table | 40.06 | 40.16 |
|---|---|---|
| Main dispatch | `0x75AB..0x7620` (38 entries) | `0x7CB5..0x7D24` (36 entries) |
| Secondary | `0x8FE6..0x9010` (13 entries) | `0x98BE..0x98E8` (13 entries) |
| Tertiary | `0xA5BE..0xA609` (24 entries) | `0xAF23..0xAF6E` (24 entries) |

The tracked
[`vt_function_matches_40.06_40.16.tsv`](re/jms539/vt_function_matches_40.06_40.16.tsv)
records the current Ghidra Version Tracking candidates: 28 exact-byte
matches and 107 instruction matches, for 109 distinct
function pairs. The minimum size is 10 bytes. Instruction matches are not
necessarily byte-identical: the `0x4200` pair differs in eight bytes. No
matches or names were applied automatically. A fresh report is written under
the workspace's `comparison/` directory; review it before updating the tracked
snapshot. The separate same-offset comparison found 14,571 matching and
34,581 differing positions across the 49,152-byte slices; that is not Version
Tracking.

## Physical read options

A [JMS539 teardown](https://syscall.eu/blog/2018/03/12/aigo_part1/) captured
48 KiB of firmware by monitoring SPI traffic at boot on a different device.
That technique captures what the bridge reads, not necessarily every byte of
flash. Reading the complete flash with an external programmer is another
possibility, but requires identifying this dock's chip, voltage and pinout
and preventing power conflicts with the dock. Neither method has been tested
on this unit.

## Local research files

The Ghidra project, updater, firmware image, generated disassembly and logs
are kept locally in this directory but excluded from the public repository:
their redistribution rights have not been established.
The third-party archive `JMS539_B_31.00.40.06.rar` is in the repository root;
it and the device captures are also Git-ignored.

The analyzed updater's SHA-256 is
`c816bb55326f2643dc04d4961f5e090973701c53c509190266bca5fe66db7e2a`.
The original ORICO archive's SHA-256 is
`45f3aea7cb5ad52ad8a1e507cbd51431f229ac4e113a9796f193ea72b42bc791`.
The third-party 40.06 archive's SHA-256 is
`f7c87e8261329bbb2985655469f60c23289f806dd457ad6e6c34a0beddb96171`;
its 49,408-byte image hashes to
`63f75ce11d34bd3dc6378e5ffd03b5f19ce816184af8bbf3ed85f2fb3fd5de14`.

To reapply the RTTI annotations to the matching executable in an existing
Ghidra project:

```bash
analyzeHeadless ghidra updater -process FwUpdateTool_v1_17_12.exe -noanalysis -scriptPath ghidra/scripts -postScript RecoverUpdaterRtti.java
```

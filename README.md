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
  significance of this difference is unknown. The archive was downloaded
  over HTTP after HTTPS certificate verification failed, and its authenticity
  has not been independently verified. Do not assume it is suitable for this
  dock.
- A [third-party listing](https://www.usbdev.ru/files/jmicron/jms539firmware/)
  provides an image named `JMS539_B_31.00.40.06.BIN`. All 49,408 bytes match
  the beginning of the dock's repeatable capture, including `5391` at
  `0xbff4`. The archive's authenticity is unverified, and the image alone is
  not a complete flash backup or a verified update package.
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

`tools/read_version.sh /dev/sgN` sends only the version command to the
explicitly supplied SCSI generic node. Verify the node and its USB parent
before use; names such as `/dev/sg2` can change after reconnecting.

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
`45f3aea7cb5ad52ad8a1e507cbd51431f229ac4e113a9796f193ea72b42bc791`;
this identifies the downloaded file, not its authenticity.
The third-party 40.06 archive's SHA-256 is
`f7c87e8261329bbb2985655469f60c23289f806dd457ad6e6c34a0beddb96171`;
its 49,408-byte image hashes to
`63f75ce11d34bd3dc6378e5ffd03b5f19ce816184af8bbf3ed85f2fb3fd5de14`.
These hashes identify the local files, not their authenticity or suitability.

To reapply the RTTI annotations to the matching executable in an existing
Ghidra project:

```bash
analyzeHeadless ghidra updater -process FwUpdateTool_v1_17_12.exe \
  -noanalysis -scriptPath ghidra/scripts -postScript RecoverUpdaterRtti.java
```

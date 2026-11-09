# awto-jms539

Research into a four-bay ORICO USB-SATA dock reporting JMicron USB ID
`152d:0539`. The exact dock model and update compatibility are not confirmed.

## Status

- The bridge reports product `5392` and firmware **31.00.40.06** through the
  vendor SCSI version command `E0 F4 E7`.
- **No firmware backup has been completed or update intentionally performed.**
  A `jms578flash` extraction attempt did not finish. The earlier Wine probe did
  not press Update; its log did not record explicit raw SCSI traffic, but does
  not conclusively rule out device commands.
- A later targeted, data-in-only probe of the updater's `DF ... FA` flash-read
  command returned no data and timed out. Linux reset the dock. A subsequent
  standard SCSI readiness check also timed out and triggered another dock
  reset. After a power cycle, both disks re-enumerated and the kernel read their
  capacities; the 1 TB volume was automatically mounted. No further firmware
  commands were sent.
- ORICO's JMS539B version 40.16 package lists 3549/3559 and 9548/9558 models;
  it does not list 6648. The archive was downloaded over HTTP after HTTPS
  certificate verification failed, and its authenticity has not been
  independently verified. Do not assume it is suitable for this dock.
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
  In the downloaded 40.16 firmware, that CDB sets a mode flag and appears to
  restrict the commands accepted afterward; the behavior of the installed
  40.06 firmware is not established by that disassembly.
- Startup/refresh also calls a JMS539 check that can automatically repair
  flash: when detected capacity is at least 128 KiB and exactly one of two
  64 KiB firmware copies passes its validity check, it writes the valid copy
  over the other. The Wine trace does not establish whether this path ran.
- The JMS539 HDD-firmware branch can issue SCSI `WRITE(16)` commands to an
  area near the end of the selected disk. This branch is reachable through the
  `JMS539 HDD FW` option or a detected flash-type condition; its exact use on
  this dock has not been established.
- A previous Wine startup probe exposed host drives through automatic mappings.
  Do not assume that running the updater under Wine isolates other disks.

These are static-analysis findings, not a tested update procedure. No update
should be attempted until the image, target selection and write path are
verified.

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

`tools/read_version.sh /dev/sgN` sends only the version command to the
explicitly supplied SCSI generic node. Verify the node and its USB parent
before use; names such as `/dev/sg2` can change after reconnecting.

## Local research files

The Ghidra project, updater, firmware image, generated disassembly and logs
are kept locally in this directory but excluded from the public repository:
their redistribution rights have not been established.

The analyzed updater's SHA-256 is
`c816bb55326f2643dc04d4961f5e090973701c53c509190266bca5fe66db7e2a`.
The original ORICO archive's SHA-256 is
`45f3aea7cb5ad52ad8a1e507cbd51431f229ac4e113a9796f193ea72b42bc791`;
this identifies the downloaded file, not its authenticity.

To reapply the RTTI annotations to the matching executable in an existing
Ghidra project:

```bash
analyzeHeadless ghidra updater -process FwUpdateTool_v1_17_12.exe \
  -noanalysis -scriptPath ghidra/scripts -postScript RecoverUpdaterRtti.java
```

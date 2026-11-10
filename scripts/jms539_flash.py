#!/usr/bin/env python3
"""Linux flasher for the JMS539 bridge in the ORICO 6648SUSJ3 dock.

Usage:
    sudo python3 scripts/jms539_flash.py check   /dev/sgN IMAGE [--config device|image]
    sudo python3 scripts/jms539_flash.py write   /dev/sgN IMAGE --confirm TOKEN [--config ...]
    sudo python3 scripts/jms539_flash.py restore /dev/sgN BACKUP --confirm TOKEN

`check` is read-only: it verifies the dock, reads the version and flash type
(`FF 04 23 04`; JEDEC `9F` via `FF 04 20/21` only if the type is 0), captures and
saves a fresh 64 KiB backup, stages the payload and prints the confirmation
token. `write` repeats every check, then writes, reads back, retries once and
resets the dock. `restore` writes a saved 64 KiB backup and does not require
the current flash contents to be valid.

The sequence follows the decompiled vendor updater (FwUpdateTool 1.17.12):
`FF 04 12` busy poll before every command, `DF <mode> ... FB` writes with mode
2 (32 KiB block erase) and a mode 1 (4 KiB sector erase) retry, `DF 10 ... FA`
readback and `FF 04 26 4A 4D` reset. Mode 3 (whole-chip erase) is never sent.
Unlike the updater, the whole 64 KiB is written so that bytes after the image
keep their current contents.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import mmap
import os
import re
import signal
import stat
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dev  # noqa: E402

USB_ID = ("152d", "0539")
FLASH_SIZE = 0x10000
READ_CHUNK = 0x1000
POLL_CDB = bytes.fromhex("ff 04 12 00 00 00 00 00 00 00 00 00")
RESET_CDB = bytes.fromhex("ff 04 26 4a 4d 00 00 00 00 00 00 00")
FLASH_TYPE_CDB = bytes.fromhex("ff 04 23 04 00 00 00 00 00 00 00 00")
SPI_JEDEC_CDB = bytes.fromhex("ff 04 20 01 01 9f 00 00 00 00 00 00")
SPI_RESULT_CDB = bytes.fromhex("ff 04 21 00 00 00 00 00 04 00 00 00")
# Updater tables at 0x4882ac/0x4882d8: type 1 (JEDEC 7F 9D) = 32 KiB block, 4 KiB sector.
SUPPORTED_FLASH_TYPE = 1
VERSION_CDB = bytes.fromhex("".join(dev.VERSION_CDB))
POLL_INTERVAL = 0.01
POLL_LIMIT = 501
READ_TIMEOUT_MS = 10_000
WRITE_TIMEOUT_MS = 50_000
WRITE_MODES = (2, 1)
SENTINELS = (0xA5, 0x5A)

SG_IO = 0x2285
SG_DXFER_NONE = -1
SG_DXFER_TO_DEV = -2
SG_DXFER_FROM_DEV = -3
SG_FLAG_MMAP_IO = 4


class DockError(RuntimeError):
    pass


class VerifyError(DockError):
    pass


def read_cdb(offset: int, length: int) -> bytes:
    return bytes(
        (0xDF, 0x10, 0, length >> 8, length & 0xFF, 0, 0, 0,
         offset >> 16, (offset >> 8) & 0xFF, offset & 0xFF, 0xFA)
    )


def confirm_token(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()[:12]


class SgIoHeader(ctypes.Structure):
    _fields_ = [
        ("interface_id", ctypes.c_int),
        ("dxfer_direction", ctypes.c_int),
        ("cmd_len", ctypes.c_ubyte),
        ("mx_sb_len", ctypes.c_ubyte),
        ("iovec_count", ctypes.c_ushort),
        ("dxfer_len", ctypes.c_uint),
        ("dxferp", ctypes.c_void_p),
        ("cmdp", ctypes.c_void_p),
        ("sbp", ctypes.c_void_p),
        ("timeout", ctypes.c_uint),
        ("flags", ctypes.c_uint),
        ("pack_id", ctypes.c_int),
        ("usr_ptr", ctypes.c_void_p),
        ("status", ctypes.c_ubyte),
        ("masked_status", ctypes.c_ubyte),
        ("msg_status", ctypes.c_ubyte),
        ("sb_len_wr", ctypes.c_ubyte),
        ("host_status", ctypes.c_ushort),
        ("driver_status", ctypes.c_ushort),
        ("resid", ctypes.c_int),
        ("duration", ctypes.c_uint),
        ("info", ctypes.c_uint),
    ]


class SgTransport:
    """SG_IO with an mmap buffer; Linux reports full residuals on this
    bridge's reads although the data arrives, so data-in uses a sentinel
    prefill and callers compare repeated reads."""

    def __init__(self, path: str) -> None:
        self.fd = os.open(path, os.O_RDWR | os.O_EXCL | os.O_CLOEXEC)
        try:
            self.buffer = mmap.mmap(
                self.fd, dev.MAX_CHUNK, flags=mmap.MAP_SHARED,
                prot=mmap.PROT_READ | mmap.PROT_WRITE,
            )
        except OSError:
            os.close(self.fd)
            raise
        self.libc = ctypes.CDLL(None, use_errno=True)

    def close(self) -> None:
        self.buffer.close()
        os.close(self.fd)

    def _io(self, cdb: bytes, direction: int, length: int, timeout_ms: int) -> int:
        command = (ctypes.c_ubyte * len(cdb)).from_buffer_copy(cdb)
        sense = (ctypes.c_ubyte * 32)()
        header = SgIoHeader(
            interface_id=ord("S"), dxfer_direction=direction, cmd_len=len(cdb),
            mx_sb_len=len(sense), dxfer_len=length, cmdp=ctypes.addressof(command),
            sbp=ctypes.addressof(sense), timeout=timeout_ms,
            flags=SG_FLAG_MMAP_IO if length else 0,
        )
        if self.libc.ioctl(self.fd, SG_IO, ctypes.byref(header)) < 0:
            error = ctypes.get_errno()
            raise OSError(error, f"SG_IO {cdb.hex(' ')}: {os.strerror(error)}")
        if header.status or header.host_status or header.driver_status or header.info & 1:
            raise DockError(
                f"SCSI error for {cdb.hex(' ')}: status={header.status:#x} "
                f"host={header.host_status:#x} driver={header.driver_status:#x} "
                f"sense={bytes(sense[: header.sb_len_wr]).hex()}"
            )
        if not 0 <= header.resid <= length:
            raise DockError(f"invalid residual {header.resid} for {cdb.hex(' ')}")
        return header.resid

    def data_in(self, cdb: bytes, length: int, timeout_ms: int, sentinel: int) -> tuple[bytes, int]:
        self.buffer[:length] = bytes([sentinel]) * length
        resid = self._io(cdb, SG_DXFER_FROM_DEV, length, timeout_ms)
        return bytes(self.buffer[:length]), resid

    def data_out(self, cdb: bytes, data: bytes, timeout_ms: int) -> int:
        self.buffer[: len(data)] = data
        return self._io(cdb, SG_DXFER_TO_DEV, len(data), timeout_ms)

    def no_data(self, cdb: bytes, timeout_ms: int) -> None:
        self._io(cdb, SG_DXFER_NONE, 0, timeout_ms)


@dataclass(frozen=True)
class Dock:
    sg: str
    usb_path: Path
    busnum: str
    devnum: str
    blocks: tuple[str, ...]


def _read(path: Path) -> str:
    return path.read_text().strip()


def find_dock(sg_path: str, sys_root: Path = Path("/sys"), proc_root: Path = Path("/proc")) -> Dock:
    name = Path(sg_path).name
    if not re.fullmatch(r"sg\d+", name):
        raise DockError(f"{sg_path} is not a /dev/sgN node")
    link = sys_root / "class" / "scsi_generic" / name / "device"
    if not link.exists():
        raise DockError(f"{name} has no sysfs device")
    node = link.resolve()
    usb_path = next((p for p in node.parents if (p / "idVendor").is_file()), None)
    if usb_path is None:
        raise DockError(f"{name} is not attached through USB")
    found = (_read(usb_path / "idVendor"), _read(usb_path / "idProduct"))
    if found != USB_ID:
        raise DockError(f"{name} belongs to USB {':'.join(found)}, not {':'.join(USB_ID)}")

    docks = {
        entry.resolve()
        for entry in (sys_root / "bus" / "usb" / "devices").iterdir()
        if (entry / "idVendor").is_file()
        and (_read(entry / "idVendor"), _read(entry / "idProduct")) == USB_ID
    }
    if docks != {usb_path}:
        raise DockError(f"expected exactly one {':'.join(USB_ID)} device, found {len(docks)}")

    blocks, dev_ids = [], {}
    for disk in sorted((sys_root / "class" / "block").iterdir()):
        device = disk / "device"
        if not device.exists() or usb_path not in device.resolve().parents:
            continue
        for entry in [disk, *sorted(disk.glob(f"{disk.name}*"))]:
            if entry != disk and not (entry / "partition").is_file():
                continue
            blocks.append(entry.name)
            dev_ids[_read(entry / "dev")] = entry.name
            holders = entry / "holders"
            if holders.is_dir() and any(holders.iterdir()):
                raise DockError(f"{entry.name} is held by {sorted(h.name for h in holders.iterdir())}")

    for line in (proc_root / "self" / "mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) > 4 and fields[2] in dev_ids:
            raise DockError(f"{dev_ids[fields[2]]} is mounted on {fields[4]}")
    swaps = proc_root / "swaps"
    if swaps.is_file():
        for line in swaps.read_text().splitlines()[1:]:
            if line.split() and Path(line.split()[0]).name in blocks:
                raise DockError(f"{line.split()[0]} is in use as swap")

    return Dock(name, usb_path, _read(usb_path / "busnum"), _read(usb_path / "devnum"), tuple(blocks))


def make_guard(dock: Dock) -> Callable[[], None]:
    def guard() -> None:
        try:
            current = (_read(dock.usb_path / "idVendor"), _read(dock.usb_path / "idProduct"),
                       _read(dock.usb_path / "devnum"))
        except OSError as exc:
            raise DockError("the dock disappeared from USB") from exc
        if current != (*USB_ID, dock.devnum):
            raise DockError("the dock re-enumerated; stop and reconnect before retrying")
    return guard


class Flasher:
    def __init__(self, transport, guard: Callable[[], None] = lambda: None,
                 log: Callable[[str], None] = print, sleep: Callable[[float], None] = time.sleep) -> None:
        self.transport = transport
        self.guard = guard
        self.log = log
        self.sleep = sleep

    def wait_ready(self) -> None:
        for _ in range(POLL_LIMIT):
            self.guard()
            status, resid = self.transport.data_in(POLL_CDB, 2, READ_TIMEOUT_MS, 0xA5)
            if resid:
                raise DockError(f"incomplete busy status: residual {resid}")
            if not status[0] & 1:
                return
            self.sleep(POLL_INTERVAL)
        raise DockError("the dock stayed busy for 5 seconds")

    def version(self) -> dict[str, str]:
        self.guard()
        data, resid = self.transport.data_in(VERSION_CDB, 16, READ_TIMEOUT_MS, 0)
        if resid:
            raise DockError(f"incomplete version response: residual {resid}")
        return dev.parse_version(data)

    def _stable_in(self, cdb: bytes, length: int) -> bytes:
        results = []
        for sentinel in SENTINELS:
            self.wait_ready()
            data, _ = self.transport.data_in(cdb, length, READ_TIMEOUT_MS, sentinel)
            results.append(data)
        if results[0] != results[1]:
            raise DockError(f"{cdb[:4].hex(' ')} returned no stable data")
        return results[0]

    def flash_type(self) -> dict:
        """Mirror the updater's identification: FF 04 23, then JEDEC 9F only for type 0."""
        kind = self._stable_in(FLASH_TYPE_CDB, 4)[0]
        info = {"flash_type": kind, "jedec": None}
        if kind == 0:
            self.wait_ready()
            self.transport.no_data(SPI_JEDEC_CDB, READ_TIMEOUT_MS)
            jedec = self._stable_in(SPI_RESULT_CDB, 4)
            info["jedec"] = jedec.hex()
            if jedec[:2] == b"\x7f\x9d":
                info["flash_type"] = SUPPORTED_FLASH_TYPE
        if info["flash_type"] != SUPPORTED_FLASH_TYPE:
            raise DockError(f"flash type {info} is not type 1 (7F 9D); erase geometry would differ")
        return info

    def read(self, length: int, sentinel: int) -> bytes:
        chunks = []
        for offset in range(0, length, READ_CHUNK):
            self.wait_ready()
            data, _ = self.transport.data_in(read_cdb(offset, READ_CHUNK), READ_CHUNK,
                                             READ_TIMEOUT_MS, sentinel)
            chunks.append(data)
        return b"".join(chunks)

    def write(self, payload: bytes, mode: int) -> list[int]:
        if mode not in WRITE_MODES:
            raise ValueError(f"write mode {mode} is not allowed")
        residuals = []
        for chunk in dev.write_chunks(len(payload), mode):
            self.wait_ready()
            data = payload[chunk.offset : chunk.offset + chunk.length]
            residuals.append(self.transport.data_out(chunk.cdb(), data, WRITE_TIMEOUT_MS))
        self.wait_ready()
        return residuals

    def reset(self) -> None:
        self.wait_ready()
        try:
            self.transport.no_data(RESET_CDB, READ_TIMEOUT_MS)
        except (OSError, DockError) as exc:
            self.log(f"Reset command ended with an error, as expected if the dock rebooted: {exc}")


def capture(flasher: Flasher, require_valid: bool = True) -> bytes:
    """Read 128 KiB twice with different prefills and return the first 64 KiB."""
    passes = [flasher.read(2 * FLASH_SIZE, sentinel) for sentinel in SENTINELS]
    if passes[0] != passes[1]:
        raise DockError("two flash reads differ; the read path is not trustworthy")
    data = passes[0]
    if data[:FLASH_SIZE] != data[FLASH_SIZE:]:
        raise DockError(
            "the 128 KiB read does not mirror; the flash may be larger than 64 KiB "
            "or hold a second copy, which this flasher does not handle"
        )
    if require_valid:
        dev.validate_image(data[:FLASH_SIZE], "device flash")
    return data[:FLASH_SIZE]


def stage_payload(image: bytes, device: bytes, config: str) -> bytes:
    if not dev.CRC_OFFSET + 2 <= len(image) <= FLASH_SIZE:
        raise ValueError(f"image is {len(image)} bytes; expected 0xC000..0x10000")
    if len(device) != FLASH_SIZE:
        raise ValueError("device capture must be 64 KiB")
    dev.validate_image(image, "image")
    staged = bytearray(device)
    staged[: dev.CONFIG_OFFSET] = image[: dev.CONFIG_OFFSET]
    if config == "image":
        staged[dev.CONFIG_OFFSET : len(image)] = image[dev.CONFIG_OFFSET :]
    elif config != "device":
        raise ValueError("config must be 'device' or 'image'")
    dev.validate_image(bytes(staged), "staged payload")
    return bytes(staged)


def flash(flasher: Flasher, payload: bytes, modes: tuple[int, ...] = WRITE_MODES) -> dict:
    if len(payload) != FLASH_SIZE:
        raise ValueError("payload must be 64 KiB")
    attempts = []
    for attempt, mode in enumerate(modes):
        flasher.log(f"Writing 64 KiB with mode {mode} (attempt {attempt + 1})")
        residuals = flasher.write(payload, mode)
        readback = flasher.read(FLASH_SIZE, SENTINELS[attempt % 2])
        mismatches = [i for i in range(FLASH_SIZE) if readback[i] != payload[i]]
        attempts.append({"mode": mode, "write_residuals": sorted(set(residuals)),
                         "mismatched_bytes": len(mismatches),
                         "first_mismatch": f"0x{mismatches[0]:05x}" if mismatches else None})
        if not mismatches:
            flasher.log(f"Readback matches all 64 KiB after mode {mode}")
            return {"verified": True, "attempts": attempts}
        flasher.log(f"Readback differs in {len(mismatches)} bytes from 0x{mismatches[0]:05x}")
    raise VerifyError(
        "readback still differs after all allowed modes; the dock is NOT reset. "
        "Keep it powered and run `restore` with the saved backup. Details: "
        + json.dumps(attempts)
    )


def save_backup(root: Path, data: bytes, firmware: str) -> Path:
    directory = root / "firmware" / "device"
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = directory / f"jms539-backup-{firmware}-{stamp}.bin"
    with path.open("xb") as handle:
        handle.write(data)
    return path


def busy_services(proc_root: Path = Path("/proc")) -> list[str]:
    found = set()
    for comm in proc_root.glob("[0-9]*/comm"):
        try:
            name = comm.read_text().strip()
        except OSError:
            continue
        if name in ("smartd", "udisksd", "hdparm", "smartctl"):
            found.add(name)
    return sorted(found)


class Session:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.log_path = root / "tmp" / "logs" / "jms539_flash.log"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, message: str) -> None:
        stamp = datetime.now().astimezone().isoformat(timespec="milliseconds")
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"{stamp} {message}\n")
        print(message, file=sys.stderr, flush=True)


def prepare(session: Session, args, flasher: Flasher, dock: Dock) -> tuple[bytes, dict]:
    version = flasher.version()
    session.log(f"Dock {dock.sg} at USB {dock.busnum}-{dock.devnum}, firmware {version['firmware']}, "
                f"disks {', '.join(dock.blocks) or 'none'}")
    flash_info = flasher.flash_type()
    session.log(f"Flash identification: {flash_info}")
    for name in busy_services():
        session.log(f"WARNING: {name} is running and may send commands to the dock disks")
    session.log("Capturing 2 x 128 KiB of flash")
    restoring = args.command == "restore"
    current = capture(flasher, require_valid=not restoring)
    backup = save_backup(session.root, current, version["firmware"])
    session.log(f"Saved backup {backup} sha256 {hashlib.sha256(current).hexdigest()}")
    image = dev.read_regular_file(args.image)
    if restoring:
        if len(image) != FLASH_SIZE:
            raise ValueError("restore needs a complete 64 KiB backup")
        dev.validate_image(image, "backup")
        payload = image
    else:
        payload = stage_payload(image, current, args.config)
    changed = [i for i in range(FLASH_SIZE) if payload[i] != current[i]]
    report = {
        "device": dock.sg,
        "usb": f"{dock.busnum}-{dock.devnum}",
        "firmware": version["firmware"],
        "flash": flash_info,
        "backup": str(backup),
        "image": str(args.image),
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "config_source": "backup" if restoring else args.config,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "payload_crc": f"{dev.checksum(payload):04x}",
        "changed_bytes": len(changed),
        "changed_range": [f"0x{changed[0]:05x}", f"0x{changed[-1]:05x}"] if changed else None,
        "configuration_changed": any(dev.CONFIG_OFFSET <= i < dev.CONFIG_OFFSET + dev.CONFIG_SIZE for i in changed),
        "write_modes": list(WRITE_MODES),
        "chunks": [chunk.cdb().hex(" ") for chunk in dev.write_chunks(FLASH_SIZE, WRITE_MODES[0])],
        "confirm": confirm_token(payload),
    }
    return payload, report


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (("check", "read-only identity, backup and plan"),
                            ("write", "flash IMAGE, verify and reset"),
                            ("restore", "write a saved 64 KiB backup")):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("device", help="explicit /dev/sgN of the dock")
        command.add_argument("image", type=Path)
        if name != "restore":
            command.add_argument("--config", choices=("device", "image"), default="device",
                                 help="settings block 0xC000 source (default: keep the device's)")
        if name != "check":
            command.add_argument("--confirm", required=True, help="token printed by check")
            command.add_argument("--no-reset", action="store_true", help="skip the final dock reset")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    session = Session(dev.repo_root())
    try:
        if os.geteuid() != 0:
            raise DockError("run as root (sudo) to access the SCSI generic node")
        if not stat.S_ISCHR(os.stat(args.device).st_mode):
            raise DockError(f"{args.device} is not a character device")
        dock = find_dock(args.device)
        guard = make_guard(dock)
        transport = SgTransport(f"/dev/{dock.sg}")
        try:
            flasher = Flasher(transport, guard, session.log)
            payload, report = prepare(session, args, flasher, dock)
            print(json.dumps(report, indent=2), flush=True)
            if args.command == "check":
                session.log(f"Read-only check complete. To flash, rerun with: write ... --confirm {report['confirm']}")
                return 0
            if args.confirm != report["confirm"]:
                raise DockError(f"confirmation token {args.confirm} does not match {report['confirm']}; nothing written")
            find_dock(args.device)
            previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
            try:
                session.log("Writing flash; signals are ignored until verification ends")
                result = flash(flasher, payload)
                session.log(json.dumps(result))
                if args.no_reset:
                    session.log("Verified. Reset skipped; power-cycle the dock to load the new firmware")
                else:
                    flasher.reset()
                    session.log("Verified and reset. Wait for re-enumeration, then read the version")
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)
            return 0
        finally:
            transport.close()
    except (OSError, ValueError, DockError) as exc:
        session.log(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

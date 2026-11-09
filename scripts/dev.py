#!/usr/bin/env python3
"""JMS539 research CLI: read the version or inspect an offline write plan.

Usage:
    python3 scripts/dev.py describe
    sudo python3 scripts/dev.py version /dev/sgN
    python3 scripts/dev.py plan IMAGE --backup CAPTURE
    python3 scripts/dev.py test

The plan command does not communicate with a device or write firmware.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import unittest
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

PROJECT = "awto-jms539"
COMMANDS = {
    "describe": "Describe commands as JSON",
    "doctor": "Check the Python interpreter and sg_raw",
    "version": "Read the version from an explicitly selected SCSI generic device",
    "plan": "Reconstruct an updater write attempt without accessing hardware",
    "test": "Run the offline test suite",
    "gate": "Run the pre-commit checks",
}
REGION_SIZE = 0x10000
CRC_END = 0xBFFC
CRC_OFFSET = 0xBFFE
MARKER_OFFSET = 0xBFF0
CONFIG_OFFSET = 0xC000
CONFIG_SIZE = 0x1000
MAX_CHUNK = 0x2000
VERSION_CDB = ("e0", "f4", "e7", "00", "00", "00")


def repo_root() -> Path:
    override = os.environ.get("AWTO_JMS539_REPO")
    if override:
        root = Path(override).expanduser().resolve()
        if not root.is_dir():
            raise ValueError(f"AWTO_JMS539_REPO is not a directory: {root}")
        return root
    script_dir = Path(__file__).resolve().parent
    try:
        result = subprocess.run(
            ["git", "-C", str(script_dir), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            timeout=0.25,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return script_dir.parent
    if result.returncode == 0 and result.stdout.strip():
        return Path(result.stdout.strip()).resolve()
    return script_dir.parent


class Reporter:
    def __init__(self, root: Path) -> None:
        self.path = root / "tmp" / "logs" / "dev.log"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _record(self, message: str, level: str, console: bool) -> None:
        lines = []
        for part in message.splitlines() or [""]:
            stamp = datetime.now().astimezone().isoformat(timespec="milliseconds")
            lines.append(f"{stamp}  {level:<5} [dev.py] {part}")
        with self.path.open("a", encoding="utf-8") as log:
            log.write("\n".join(lines) + "\n")
        if console:
            print("\n".join(lines), file=sys.stderr, flush=True)

    def log(self, message: str, level: str = "INFO") -> None:
        self._record(message, level, True)

    def output(self, message: str) -> None:
        self._record(message, "INFO", False)
        print(message, flush=True)


class TestLog:
    def __init__(self, reporter: Reporter) -> None:
        self.reporter = reporter
        self.pending = ""

    def write(self, text: str) -> None:
        self.pending += text
        while "\n" in self.pending:
            line, self.pending = self.pending.split("\n", 1)
            self.reporter.log(line)

    def flush(self) -> None:
        pass


def parse_version(response: bytes) -> dict[str, str]:
    if len(response) != 16:
        raise ValueError(
            f"version response is {len(response)} bytes, expected 16; "
            "a successful sg_raw exit does not prove that data was returned"
        )
    if response[:2] != b"\xf4\xe7":
        raise ValueError(f"unexpected version response signature: {response[:2].hex()}")
    return {
        "raw": response.hex(),
        "vid": response[2:4].hex(),
        "pid": response[4:6].hex(),
        "firmware": ".".join(f"{component:02d}" for component in response[12:16]),
    }


def read_version(device: str) -> dict[str, str]:
    command = [
        "sg_raw",
        "--binary",
        "--request=16",
        "--timeout=20",
        device,
        *VERSION_CDB,
    ]
    try:
        result = subprocess.run(command, capture_output=True, timeout=25, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "sg_raw exceeded its 25-second version-read deadline; "
            "check whether the dock reset"
        ) from exc
    if result.returncode:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"sg_raw failed with exit {result.returncode}: {detail}")
    return parse_version(result.stdout)


def checksum(image: bytes | bytearray) -> int:
    if len(image) < CRC_END:
        raise ValueError("image is too short for the firmware checksum")
    crc = 0
    for offset in range(0, CRC_END, 4):
        word = int.from_bytes(image[offset : offset + 4], "little")
        for shift in range(28, -1, -4):
            nibble = ((word >> shift) ^ (crc >> 12)) & 0xF
            crc = ((crc << 4) ^ (nibble << 12) ^ (nibble << 5) ^ nibble) & 0xFFFF
    return crc


def validate_image(image: bytes, label: str) -> int:
    if len(image) < CRC_OFFSET + 2:
        raise ValueError(f"{label} is too short to contain the JMS539 trailer")
    if image[MARKER_OFFSET : MARKER_OFFSET + 4] != b"\x55\xaa\xaa\x55":
        raise ValueError(f"{label} has an invalid firmware marker")
    if image[MARKER_OFFSET + 4 : MARKER_OFFSET + 7] != b"539":
        raise ValueError(f"{label} does not contain a JMS539 identifier")
    stored = int.from_bytes(image[CRC_OFFSET : CRC_OFFSET + 2], "big")
    calculated = checksum(image)
    if stored != calculated:
        raise ValueError(
            f"{label} checksum mismatch: stored {stored:04x}, calculated {calculated:04x}"
        )
    return calculated


def prepare_payload(image: bytes, backup: bytes | None) -> tuple[bytes, int]:
    if len(image) > REGION_SIZE:
        raise ValueError("image is larger than the first 64 KiB region")
    validate_image(image, "image")
    if backup is not None:
        if len(backup) not in (REGION_SIZE, 2 * REGION_SIZE):
            raise ValueError("capture must be exactly 64 KiB or 128 KiB")
        validate_image(backup, "capture")

    compare_length = (len(image) + 0xFF) & ~0xFF
    transfer_length = (compare_length + 0x1FF) & ~0x1FF
    staged = bytearray(REGION_SIZE)
    staged[: len(image)] = image
    if backup is not None:
        staged[CONFIG_OFFSET : CONFIG_OFFSET + CONFIG_SIZE] = backup[
            CONFIG_OFFSET : CONFIG_OFFSET + CONFIG_SIZE
        ]
    crc = checksum(staged)
    staged[CRC_OFFSET : CRC_OFFSET + 2] = crc.to_bytes(2, "big")
    payload = bytes(staged[:compare_length]) + bytes(transfer_length - compare_length)
    return payload, compare_length


@dataclass(frozen=True)
class WriteChunk:
    offset: int
    length: int
    flag: int

    def cdb(self) -> bytes:
        return bytes(
            (
                0xDF,
                self.flag & 0x87,
                0,
                self.length >> 8,
                self.length & 0xFF,
                0,
                0,
                0,
                self.offset >> 16,
                (self.offset >> 8) & 0xFF,
                self.offset & 0xFF,
                0xFB,
            )
        )


def write_chunks(transfer_length: int, mode: int) -> list[WriteChunk]:
    if transfer_length <= 0 or transfer_length > REGION_SIZE or transfer_length % 0x200:
        raise ValueError("transfer length must be 512-byte aligned and at most 64 KiB")
    if mode not in (1, 2, 3):
        raise ValueError("supported offline modes are 1, 2 and 3")

    boundary = {1: 0x1000, 2: 0x8000}.get(mode)
    chunks = []
    offset = 0
    while offset < transfer_length:
        length = min(MAX_CHUNK, transfer_length - offset)
        if offset == 0:
            length = min(length, 0x1000)
        if boundary is None:
            flag = mode if offset == 0 else 0
        else:
            flag = mode if offset % boundary == 0 else 0
            length = min(length, boundary - offset % boundary)
        chunks.append(WriteChunk(offset, length, flag))
        offset += length
    return chunks


def build_plan(image: bytes, backup: bytes | None, mode: int) -> dict:
    payload, compare_length = prepare_payload(image, backup)
    chunks = write_chunks(len(payload), mode)
    warnings = [
        "Offline reconstruction only: no device commands are sent.",
        "Flash type 1 is assumed, not detected; erase scope is unverified.",
        "Only write CDBs are modeled; status polling, readback and reset are not included.",
        "The original updater can retry with mode 3 and write another region; this plan does neither.",
    ]
    if mode == 3:
        warnings.append(
            "Mode 3 is used by the updater's erase-only path and may erase the whole flash."
        )
    overlay_bytes = max(0, min(CONFIG_SIZE, compare_length - CONFIG_OFFSET))
    return {
        "warnings": warnings,
        "assumed_flash_type": 1,
        "mode": mode,
        "image_bytes": len(image),
        "image_sha256": hashlib.sha256(image).hexdigest(),
        "image_crc": f"{int.from_bytes(image[CRC_OFFSET : CRC_OFFSET + 2], 'big'):04x}",
        "configuration_source": "capture" if backup is not None else "image",
        "capture_sha256": hashlib.sha256(backup).hexdigest()
        if backup is not None
        else None,
        "configuration_bytes_in_comparison": overlay_bytes,
        "compared_bytes": compare_length,
        "transfer_bytes": len(payload),
        "zero_padding_bytes": len(payload) - compare_length,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "chunks": [
            {
                "offset": f"0x{chunk.offset:04x}",
                "length": chunk.length,
                "flag": f"0x{chunk.flag:02x}",
                "cdb": chunk.cdb().hex(" "),
            }
            for chunk in chunks
        ],
    }


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("describe", "doctor", "test", "gate"):
        subparsers.add_parser(name, help=COMMANDS[name])
    version = subparsers.add_parser("version", help=COMMANDS["version"])
    version.add_argument(
        "device", help="explicit /dev/sgN device; verify its USB parent first"
    )
    plan = subparsers.add_parser("plan", help=COMMANDS["plan"])
    plan.add_argument("image", type=Path, help="candidate firmware image")
    config = plan.add_mutually_exclusive_group(required=True)
    config.add_argument(
        "--backup", type=Path, help="preserve configuration from this capture"
    )
    config.add_argument(
        "--use-image-config", action="store_true", help="use configuration in image"
    )
    plan.add_argument("--mode", type=int, choices=(1, 2, 3), default=2)
    return parser


def run_tests(root: Path, reporter: Reporter) -> int:
    sys.dont_write_bytecode = True
    suite = unittest.defaultTestLoader.discover(
        str(root / "tests"), pattern="test_*.py"
    )
    result = unittest.TextTestRunner(stream=TestLog(reporter), verbosity=2).run(suite)
    if result.testsRun == 0:
        reporter.log("No tests were discovered", "ERROR")
        return 1
    return 0 if result.wasSuccessful() else 1


def main(argv: list[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    reporter = None
    try:
        root = repo_root()
        reporter = Reporter(root)
        if args.command == "describe":
            reporter.output(
                json.dumps(
                    {
                        "project": PROJECT,
                        "entrypoint": "scripts/dev.py",
                        "log": "tmp/logs/dev.log",
                        "commands": {
                            name: {"summary": summary}
                            for name, summary in COMMANDS.items()
                        },
                    },
                    indent=2,
                )
            )
            return 0
        if args.command == "doctor":
            reporter.log(f"Python {sys.version.split()[0]}")
            sg_raw = shutil.which("sg_raw")
            if not sg_raw:
                reporter.log(
                    "sg_raw is missing; the version command cannot run", "ERROR"
                )
                return 1
            reporter.log(f"sg_raw: {sg_raw}")
            return 0
        if args.command == "version":
            reporter.log(
                f"Reading version from {args.device}; verify the device's USB parent first"
            )
            version = read_version(args.device)
            reporter.output(
                f"raw:     {version['raw']}\n"
                f"VID:PID: {version['vid']}:{version['pid']}\n"
                f"FW:      {version['firmware']}"
            )
            return 0
        if args.command == "plan":
            image = args.image.read_bytes()
            backup = args.backup.read_bytes() if args.backup else None
            reporter.output(json.dumps(build_plan(image, backup, args.mode), indent=2))
            return 0
        return run_tests(root, reporter)
    except (OSError, ValueError, RuntimeError) as exc:
        if reporter is not None:
            try:
                reporter.log(str(exc), "ERROR")
            except OSError as log_error:
                print(
                    f"ERROR: {exc}; could not write log: {log_error}", file=sys.stderr
                )
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

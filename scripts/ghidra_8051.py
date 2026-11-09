#!/usr/bin/env python3
"""Offline Ghidra import, regeneration, and exact comparison for JMS539 8051 slices."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Callable
from itertools import pairwise
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
INPUT_DIR = ROOT / "analysis" / "initial" / "jms539-31.00.40.06"
ANALYSIS_ROOT = ROOT / "analysis" / "initial"
DEFAULT_WORKSPACE = ANALYSIS_ROOT / "ghidra-8051"
SCRIPT_DIR = ROOT / "ghidra" / "scripts"
FINDINGS_DIR = ROOT / "re" / "jms539"

BASE_ADDRESS = 0x4000
IMAGE_LENGTH = 0xC000
LANGUAGE_ID = "8051:BE:16:default"
COMPILER_SPEC_ID = "default"
VERSIONS = {
    "40.06": ("v40_06_code.bin", "v40_06_code.d52"),
    "40.16": ("v40_16_code.bin", "v40_16_code.d52"),
}
SLOT_STARTS = tuple(range(0x4000, 0x41F1, 0x10))
POST_CALL_SEQUENCE_CASES = {
    "40.06": (0x4AA9, bytes.fromhex("12 1B F0 00 00 00 B4")),
    "40.16": (0x4B55, bytes.fromhex("12 1B F0 00 00 00 3C")),
}
DISPATCH_CASES = {
    "40.06": (0x75A4, 0x75AB, 0x7620, 0x7611, 0x7683, 0x784B),
    "40.16": (0x7CAE, 0x7CB5, 0x7D24, 0x7D15, 0x7D84, 0x7F59),
}
EXTRA_SWITCH_CASES = {
    "40.06": ((0x8FE3, 0x8FE6, 0x9010, 0x931E), (0xA5BB, 0xA5BE, 0xA609, 0xA66B)),
    "40.16": ((0x98BB, 0x98BE, 0x98E8, 0x9BFB), (0xAF20, 0xAF23, 0xAF6E, 0xAFD0)),
}
GHIDRA_EXPORTS = (
    "program.tsv",
    "findings.tsv",
    "instructions.tsv",
    "data.tsv",
    "functions.tsv",
    "calls.tsv",
    "references.tsv",
    "decompilation.c",
    "summary.tsv",
)


class PipelineError(RuntimeError):
    """A local input, Ghidra, or export validation error."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def version_values(selection: str) -> list[str]:
    return list(VERSIONS) if selection == "both" else [selection]


def input_paths(version: str) -> tuple[Path, Path]:
    binary_name, listing_name = VERSIONS[version]
    return INPUT_DIR / binary_name, INPUT_DIR / listing_name


def findings_path(version: str) -> Path:
    return FINDINGS_DIR / f"ghidra_names_{version}.tsv"


def read_verified_findings(
    version: str, expected_image_sha256: str
) -> tuple[Path, bytes]:
    path = findings_path(version)
    if not path.is_file():
        raise PipelineError(f"Missing findings TSV: {path}")
    contents = path.read_bytes()
    try:
        contents.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PipelineError(f"{path.name}: findings TSV is not UTF-8") from error
    hashes = re.findall(rb"^# image_sha256=([0-9a-f]{64})\r?$", contents, re.MULTILINE)
    if hashes != [expected_image_sha256.encode("ascii")]:
        raise PipelineError(
            f"{path.name}: image SHA-256 does not match the input slice"
        )
    return path, contents


def read_verified_input(version: str) -> tuple[bytes, Path, Path]:
    binary_path, listing_path = input_paths(version)
    if not binary_path.is_file():
        raise PipelineError(f"Missing firmware slice: {binary_path}")
    if not listing_path.is_file():
        raise PipelineError(f"Missing D52 listing: {listing_path}")

    image = binary_path.read_bytes()
    if len(image) != IMAGE_LENGTH:
        raise PipelineError(
            f"{binary_path.name}: expected {IMAGE_LENGTH:#x} bytes, got {len(image):#x}"
        )

    listing = listing_path.read_text(encoding="utf-8", errors="replace")
    evidence_patterns = (
        r"^\s*org\s+4000h\s*$",
        r";\s*4000\s+12\s+42\s+00(?:\s|$)",
        r";\s*4200\s+d2\s+58(?:\s|$)",
    )
    for pattern in evidence_patterns:
        if re.search(pattern, listing, re.IGNORECASE | re.MULTILINE) is None:
            raise PipelineError(
                f"{listing_path.name}: expected D52 mapping evidence is absent "
                f"(pattern {pattern!r})"
            )

    # D52's CPU 0x4000 LCALL 0x4200 is 12 42 00 at file offset 0.
    # CPU 0x4200 is therefore file offset 0x0200, where D52 shows D2 58.
    if image[:3] != bytes((0x12, 0x42, 0x00)):
        raise PipelineError(f"{binary_path.name}: offset 0 does not match LCALL 0x4200")
    if image[0x200:0x202] != bytes((0xD2, 0x58)):
        raise PipelineError(
            f"{binary_path.name}: offset 0x200 does not match D52 bytes at CPU 0x4200"
        )
    callsite, observed_bytes = POST_CALL_SEQUENCE_CASES[version]
    sequence_offset = callsite - BASE_ADDRESS
    if image[sequence_offset : sequence_offset + len(observed_bytes)] != observed_bytes:
        raise PipelineError(
            f"{binary_path.name}: expected observed post-call sequence at "
            f"CPU 0x{callsite:04X}"
        )

    dispatcher, table_start, table_end, df_entry, df_target, default = DISPATCH_CASES[
        version
    ]
    checks = (
        (dispatcher, bytes.fromhex("90 30 0F E0 12 1C 2D")),
        (df_entry, df_target.to_bytes(2, "big") + b"\xdf"),
        (table_end - 3, b"\x00\x00" + default.to_bytes(2, "big")),
        (df_target, bytes.fromhex("90 30 1A E0 B4 FF")),
    )
    for address, expected in checks:
        offset = address - BASE_ADDRESS
        if image[offset : offset + len(expected)] != expected:
            raise PipelineError(
                f"{binary_path.name}: expected command-table evidence at CPU {address:#06x}"
            )
    table_length = table_end - 3 - table_start
    table = image[table_start - BASE_ADDRESS : table_end - 3 - BASE_ADDRESS]
    if table_length % 3 or len(table) != table_length:
        raise PipelineError(
            f"{binary_path.name}: invalid apparent command-table length"
        )
    keys = [table[offset + 2] for offset in range(0, len(table), 3)]
    targets = [
        int.from_bytes(table[offset : offset + 2], "big")
        for offset in range(0, len(table), 3)
    ]
    if any(left >= right for left, right in pairwise(keys)) or any(
        target < BASE_ADDRESS or table_start <= target <= table_end
        for target in targets
    ):
        raise PipelineError(
            f"{binary_path.name}: invalid apparent command-table entries"
        )
    for call, start, end, default_target in EXTRA_SWITCH_CASES[version]:
        if (
            start != call + 3
            or image[call - BASE_ADDRESS : start - BASE_ADDRESS] != b"\x12\x1c\x2d"
            or (end - 3 - start) % 3
            or image[end - 3 - BASE_ADDRESS : end + 1 - BASE_ADDRESS]
            != b"\x00\x00" + default_target.to_bytes(2, "big")
        ):
            raise PipelineError(
                f"{binary_path.name}: invalid apparent switch table at CPU {start:#06x}"
            )
        table = image[start - BASE_ADDRESS : end - 3 - BASE_ADDRESS]
        keys = [table[offset + 2] for offset in range(0, len(table), 3)]
        targets = [
            int.from_bytes(table[offset : offset + 2], "big")
            for offset in range(0, len(table), 3)
        ]
        if (
            not keys
            or any(left >= right for left, right in pairwise(keys))
            or any(
                target < BASE_ADDRESS or start <= target <= end for target in targets
            )
        ):
            raise PipelineError(
                f"{binary_path.name}: invalid apparent switch entries at CPU {start:#06x}"
            )

    return image, binary_path, listing_path


def project_name(version: str) -> str:
    return f"JMS539_40_{version.split('.', 1)[1]}"


def resolve_workspace(requested: str | Path | None) -> Path:
    allowed_root = ANALYSIS_ROOT.resolve()
    candidate = DEFAULT_WORKSPACE if requested is None else Path(requested).expanduser()
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    candidate = candidate.resolve()
    try:
        candidate.relative_to(allowed_root)
    except ValueError as error:
        raise PipelineError(
            f"Workspace must be confined under {allowed_root}: {candidate}"
        ) from error
    if candidate == allowed_root:
        raise PipelineError(
            f"Workspace must be a dedicated subdirectory under {allowed_root}"
        )
    try:
        candidate.relative_to(INPUT_DIR.resolve())
    except ValueError:
        pass
    else:
        raise PipelineError(
            f"Workspace must not be inside the firmware input directory: {candidate}"
        )
    return candidate


def project_directory(workspace: Path) -> Path:
    return workspace / "projects"


def project_artifacts(workspace: Path, version: str) -> tuple[Path, Path]:
    name = project_name(version)
    directory = project_directory(workspace)
    return directory / f"{name}.gpr", directory / f"{name}.rep"


def require_project_absent(workspace: Path, version: str) -> None:
    artifacts = project_artifacts(workspace, version)
    existing = [path for path in artifacts if path.exists() or path.is_symlink()]
    if existing:
        paths = ", ".join(str(path) for path in existing)
        raise PipelineError(
            f"Refusing to overwrite existing Ghidra project for {version}: {paths}. "
            "Use regen or select a new --workspace."
        )


def require_project_present(workspace: Path, version: str) -> Path:
    project_file, project_repository = project_artifacts(workspace, version)
    if not project_file.is_file() or not project_repository.is_dir():
        raise PipelineError(
            f"No complete saved Ghidra project for {version}: expected both "
            f"{project_file} and {project_repository}; run import in a new workspace first"
        )
    return project_file


def resolve_headless(explicit: str | None) -> str:
    candidate = explicit or os.environ.get("GHIDRA_ANALYZE_HEADLESS")
    if candidate:
        path = Path(candidate).expanduser()
        if not path.is_file():
            raise PipelineError(f"analyzeHeadless is not a file: {path}")
        return str(path.resolve())

    ghidra_home = os.environ.get("GHIDRA_HOME")
    if ghidra_home:
        path = Path(ghidra_home).expanduser() / "support" / "analyzeHeadless"
        if path.is_file():
            return str(path.resolve())

    discovered = shutil.which("analyzeHeadless")
    if discovered:
        return str(Path(discovered).resolve())
    raise PipelineError(
        "Ghidra is unavailable: set GHIDRA_ANALYZE_HEADLESS or GHIDRA_HOME, "
        "or put analyzeHeadless on PATH. This pipeline does not install dependencies."
    )


def ghidra_environment(workspace: Path) -> dict[str, str]:
    """Keep Ghidra's user settings and cache below the ignored work directory."""
    home = workspace / "user-home"
    xdg_config = workspace / "xdg-config"
    xdg_cache = workspace / "xdg-cache"
    xdg_data = workspace / "xdg-data"
    for directory in (home, xdg_config, xdg_cache, xdg_data):
        directory.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(xdg_config)
    env["XDG_CACHE_HOME"] = str(xdg_cache)
    env["XDG_DATA_HOME"] = str(xdg_data)
    # The installed Ghidra launcher forwards this variable to the JVM.
    user_home_option = f"-Duser.home={home}"
    headless_options = env.get("GHIDRA_HEADLESS_JAVA_OPTIONS", "").strip()
    if user_home_option not in headless_options.split():
        env["GHIDRA_HEADLESS_JAVA_OPTIONS"] = (
            f"{headless_options} {user_home_option}".strip()
        )
    return env


def run_headless(command: list[str], headless: str, workspace: Path) -> None:
    full_command = [headless, *command]
    print("$ " + shlex.join(full_command), flush=True)
    result = subprocess.run(
        full_command,
        cwd=ROOT,
        env=ghidra_environment(workspace),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        check=False,
    )
    if result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
    if result.returncode != 0:
        raise PipelineError(f"analyzeHeadless exited with status {result.returncode}")
    if re.search(
        r"ERROR REPORT SCRIPT ERROR|Exception occurred while running script",
        result.stdout,
        re.IGNORECASE,
    ):
        raise PipelineError(
            "Ghidra reported a script error; staged exports were discarded"
        )


def export_path(version: str, workspace: Path) -> Path:
    return workspace / "exports" / version


def export_script_arguments(
    version: str, expected_sha256: str, output_directory: Path
) -> list[str]:
    return [
        "-postScript",
        "ExportJms5398051.java",
        version,
        expected_sha256,
        str(output_directory),
    ]


def findings_script_arguments(
    version: str, expected_image_sha256: str, expected_findings_sha256: str, stage: Path
) -> list[str]:
    return [
        "-postScript",
        "ApplyJms539Findings.java",
        version,
        expected_image_sha256,
        str(findings_path(version)),
        expected_findings_sha256,
        str(stage),
    ]


def make_manifest(
    version: str, mapped_image_sha256: str, expected_findings_sha256: str
) -> dict[str, Any]:
    image, binary_path, listing_path = read_verified_input(version)
    findings, findings_contents = read_verified_findings(version, sha256(image))
    if sha256(image) != mapped_image_sha256:
        raise PipelineError(f"{version}: input image changed during export")
    if sha256(findings_contents) != expected_findings_sha256:
        raise PipelineError(f"{version}: findings TSV changed during export")
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "firmware_version": version,
        "input": {
            "binary": binary_path.relative_to(ROOT).as_posix(),
            "size_bytes": len(image),
            "sha256": sha256(image),
            "d52_listing": listing_path.relative_to(ROOT).as_posix(),
        },
        "address_map": {
            "file_offset_start": "0x0000",
            "file_offset_end_exclusive": f"0x{IMAGE_LENGTH:04X}",
            "cpu_address_start": f"0x{BASE_ADDRESS:04X}",
            "cpu_address_end_inclusive": "0xFFFF",
            "rule": "cpu_address = 0x4000 + file_offset",
            "evidence": [
                "The matching D52 listing declares org 4000h.",
                "At file offset 0, bytes 12 42 00 decode as LCALL 0x4200.",
                "At file offset 0x0200, bytes D2 58 match the D52 instruction at CPU 0x4200.",
            ],
        },
        "ghidra": {
            "processor_language_id": LANGUAGE_ID,
            "compiler_spec_id": COMPILER_SPEC_ID,
            "analysis_seed": {
                "address": "0x4000",
                "count": len(SLOT_STARTS),
                "addresses": [f"0x{address:04X}" for address in SLOT_STARTS],
                "status": (
                    "Provisional analysis seeds at observed 16-byte slot starts; "
                    "not asserted interrupt vectors or semantic names."
                ),
                "basis": (
                    "The D52 listings and both binaries show observed code at these "
                    "slot starts; seeds only encourage analysis of more real paths."
                ),
            },
            "command_path_seeds": {
                "dispatcher": f"0x{DISPATCH_CASES[version][0]:04X}",
                "df_target": f"0x{DISPATCH_CASES[version][4]:04X}",
                "status": "Provisional seeds; no ROM helper behavior is assumed.",
            },
            "switch_table_seeds": {
                "status": (
                    "Targets of three apparent inline tables are disassembled provisionally; "
                    "their dispatch semantics are not established."
                ),
                "additional_tables": [
                    {
                        "call": f"0x{call:04X}",
                        "start": f"0x{start:04X}",
                        "end_inclusive": f"0x{end:04X}",
                        "default_target": f"0x{default_target:04X}",
                    }
                    for call, start, end, default_target in EXTRA_SWITCH_CASES[version]
                ],
            },
            "findings": {
                "path": findings.relative_to(ROOT).as_posix(),
                "sha256": expected_findings_sha256,
                "policy": "Apply [fw] high rows; retain [guess] rows in TSV only.",
            },
            "rom_and_abi_limits": [
                "Only CPU 0x4000..0xFFFF is supplied; CPU 0x0000..0x3FFF is not mapped.",
                "A reference to ROM helper 0x1BF0 remains unresolved; no ROM bytes or behavior are assumed.",
                "Any low-address 8051 register/data spaces in Ghidra are uninitialized processor spaces, not ROM or a JMS539-specific SFR map.",
                "D52-derived MOV DPTR,#0x7xxx entries are disassembled provisionally when not already covered; these are candidate instruction starts, not semantic or function labels.",
                "The seeded code has an unresolved transfer to CODE:0x362A; decompiler output that reaches it may be partial.",
                "No Keil ABI inference, Keil-specific return repair, or hardware-register labels are applied; names are limited to directly observed behavior.",
            ],
        },
    }
    manifest["ghidra"]["mapped_image_sha256_verified"] = mapped_image_sha256
    manifest["ghidra"]["mapped_image_bytes_verified"] = IMAGE_LENGTH

    _, table_start, table_end, df_entry, df_target, default = DISPATCH_CASES[version]
    manifest["apparent_command_table"] = {
        "start": f"0x{table_start:04X}",
        "end_inclusive": f"0x{table_end:04X}",
        "df_entry": f"0x{df_entry:04X}",
        "df_target": f"0x{df_target:04X}",
        "default_target": f"0x{default:04X}",
        "status": "Sorted target/opcode table inferred from bytes; ROM 0x1C2D unavailable.",
        "handling": "Preserved as data before disassembly; DF target seeded provisionally.",
    }

    manifest["unresolved_control_flow"] = [
        {
            "source": "0x4238",
            "target": "0x362A",
            "bytes": "02 36 2A",
            "status": "Ghidra decodes LJMP; target is outside the supplied code slice",
        }
    ]
    callsite, observed_bytes = POST_CALL_SEQUENCE_CASES[version]
    payload_start = callsite + 3
    manifest["post_call_sequence"] = {
        "callsite": f"0x{callsite:04X}",
        "call_bytes": "12 1B F0",
        "target": "0x1BF0",
        "nop_start": f"0x{payload_start:04X}",
        "nop_bytes": "00 00 00",
        "following_instruction_byte": f"{observed_bytes[6]:02X}",
        "status": "D52 decodes three NOPs and an instruction after the unmapped call",
        "handling": "Three NOPs are decoded as code; no ROM helper behavior or return semantics are inferred.",
        "source": "D52 listing checked against exact local image bytes.",
    }
    manifest["unresolved_control_flow"].append(
        {
            "source": f"0x{callsite:04X}",
            "target": "0x1BF0",
            "bytes": "12 1B F0",
            "status": (
                f"Observed LCALL at 0x{callsite:04X}; target is outside the supplied slice"
            ),
        }
    )
    return manifest


def write_manifest(
    version: str,
    directory: Path,
    mapped_image_sha256: str,
    expected_findings_sha256: str,
) -> None:
    manifest = make_manifest(version, mapped_image_sha256, expected_findings_sha256)
    path = directory / "manifest.json"
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def build_import_command(
    version: str,
    workspace: Path,
    expected_sha256: str,
    expected_findings_sha256: str,
    stage: Path,
) -> list[str]:
    binary_path, _ = input_paths(version)
    command = [
        str(project_directory(workspace)),
        project_name(version),
        "-import",
        str(binary_path),
        "-loader",
        "BinaryLoader",
        "-loader-baseAddr",
        f"0x{BASE_ADDRESS:X}",
        "-processor",
        LANGUAGE_ID,
        "-cspec",
        COMPILER_SPEC_ID,
        "-analysisTimeoutPerFile",
        "300",
        "-max-cpu",
        "1",
        "-scriptPath",
        str(SCRIPT_DIR),
        "-preScript",
        "SeedJms5398051.java",
        version,
        str(input_paths(version)[1]),
    ]
    command.extend(
        findings_script_arguments(
            version, expected_sha256, expected_findings_sha256, stage
        )
    )
    command.extend(export_script_arguments(version, expected_sha256, stage))
    return command


def build_regen_command(
    version: str,
    workspace: Path,
    expected_sha256: str,
    expected_findings_sha256: str,
    stage: Path,
) -> list[str]:
    binary_path, _ = input_paths(version)
    command = [
        str(project_directory(workspace)),
        project_name(version),
        "-process",
        binary_path.name,
        "-noanalysis",
        "-max-cpu",
        "1",
        "-scriptPath",
        str(SCRIPT_DIR),
        "-postScript",
        "RecoverUndecodedJms5398051.java",
        version,
        str(input_paths(version)[1]),
    ]
    command.extend(
        findings_script_arguments(
            version, expected_sha256, expected_findings_sha256, stage
        )
    )
    command.extend(export_script_arguments(version, expected_sha256, stage))
    return command


def read_key_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    with path.open("r", encoding="utf-8") as source:
        for line in source:
            row = line.rstrip("\r\n")
            if not row:
                break
            key, separator, value = row.partition("\t")
            if separator and key != "key":
                values[key] = value
    return values


def require_tsv_columns(path: Path, expected: set[str]) -> None:
    with path.open("r", encoding="utf-8") as source:
        header = source.readline().rstrip("\r\n").split("\t")
    missing = expected.difference(header)
    if missing:
        raise PipelineError(
            f"{path.name} is missing required columns: {', '.join(sorted(missing))}"
        )


def tsv_row_count(path: Path) -> int:
    with path.open("r", encoding="utf-8") as source:
        next(source, None)
        return sum(1 for line in source if line.strip())


def validate_ghidra_exports(
    version: str, directory: Path, expected_sha256: str
) -> None:
    missing = [
        name
        for name in GHIDRA_EXPORTS
        if not (directory / name).is_file() or (directory / name).stat().st_size == 0
    ]
    if missing:
        raise PipelineError(
            f"Ghidra export for {version} is incomplete or empty; "
            f"missing/empty: {', '.join(missing)}"
        )

    summary = read_key_values(directory / "summary.tsv")
    if summary.get("firmware_version") != version:
        raise PipelineError(f"summary.tsv firmware version does not match {version}")
    if summary.get("language_id") != LANGUAGE_ID:
        raise PipelineError("summary.tsv has an unexpected processor language")
    if summary.get("compiler_spec_id") != COMPILER_SPEC_ID:
        raise PipelineError("summary.tsv has an unexpected compiler spec")
    if summary.get("image_range") != "0x4000..0xFFFF":
        raise PipelineError("summary.tsv has an unexpected mapped image range")

    expected_hash = expected_sha256.lower()
    if summary.get("mapped_image_sha256", "").lower() != expected_hash:
        raise PipelineError(
            "Ghidra mapped-image SHA-256 mismatch: expected "
            f"{expected_hash}, got {summary.get('mapped_image_sha256', '<missing>')}"
        )
    if summary.get("mapped_image_bytes_verified") != str(IMAGE_LENGTH):
        raise PipelineError(
            f"Ghidra did not report verifying all {IMAGE_LENGTH:#x} mapped image bytes"
        )
    try:
        instruction_count = int(summary["instruction_count"])
        function_count = int(summary["function_count"])
    except (KeyError, ValueError) as error:
        raise PipelineError(
            "summary.tsv has invalid instruction/function counts"
        ) from error
    if instruction_count <= 0 or function_count <= 0:
        raise PipelineError("Ghidra export contains no instructions or functions")

    program = read_key_values(directory / "program.tsv")
    if program.get("processor_language") != LANGUAGE_ID:
        raise PipelineError("program.tsv has an unexpected processor language")
    if program.get("compiler_spec") != COMPILER_SPEC_ID:
        raise PipelineError("program.tsv has an unexpected compiler spec")
    if program.get("expected_cpu_range") != "0x4000..0xFFFF":
        raise PipelineError("program.tsv has an unexpected mapped image range")
    if program.get("mapped_image_sha256") != expected_hash:
        raise PipelineError("program.tsv mapped-image SHA-256 does not match the input")
    if program.get("mapped_image_bytes_verified") != str(IMAGE_LENGTH):
        raise PipelineError("program.tsv does not confirm the full mapped byte count")

    require_tsv_columns(
        directory / "instructions.tsv",
        {
            "address",
            "containing_function_entry",
            "bytes",
            "mnemonic",
            "operands",
            "user_label",
            "plate_comment",
        },
    )
    require_tsv_columns(
        directory / "functions.tsv",
        {
            "entry",
            "name",
            "body_start",
            "body_end",
            "body_ranges",
            "name_status",
            "comment",
        },
    )
    if tsv_row_count(directory / "instructions.tsv") != instruction_count:
        raise PipelineError("instructions.tsv row count does not match summary.tsv")
    if tsv_row_count(directory / "functions.tsv") != function_count:
        raise PipelineError("functions.tsv row count does not match summary.tsv")


def validate_exports(
    version: str, directory: Path, expected_sha256: str, expected_findings_sha256: str
) -> None:
    required = (*GHIDRA_EXPORTS, "manifest.json")
    missing = [
        name
        for name in required
        if not (directory / name).is_file() or (directory / name).stat().st_size == 0
    ]
    if missing:
        raise PipelineError(
            f"Ghidra export for {version} is incomplete or empty; "
            f"missing: {', '.join(missing)}"
        )
    try:
        manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as error:
        raise PipelineError(f"Invalid manifest for {version}: {error}") from error
    input_hash = manifest.get("input", {}).get("sha256")
    mapped_hash = manifest.get("ghidra", {}).get("mapped_image_sha256_verified")
    if input_hash != expected_sha256 or mapped_hash != expected_sha256:
        raise PipelineError(
            f"Manifest SHA-256 values do not match the verified {version} input"
        )
    if (
        manifest.get("ghidra", {}).get("findings", {}).get("sha256")
        != expected_findings_sha256
    ):
        raise PipelineError(
            f"Manifest findings SHA-256 does not match the {version} TSV"
        )


def validate_findings_export(
    version: str, directory: Path, image_sha256: str, expected_findings_sha256: str
) -> None:
    _, contents = read_verified_findings(version, image_sha256)
    if sha256(contents) != expected_findings_sha256:
        raise PipelineError(f"{version}: findings TSV changed during export")
    expected = ["address\tname\ttype\tcomment\tstatus\tconfidence\tapplication"]
    for line in contents.decode("utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 6 or not re.fullmatch(r"CODE:[0-9a-fA-F]{4}", fields[0]):
            raise PipelineError(f"{version}: invalid findings TSV row")
        fields[0] = fields[0].upper()
        application = "applied" if fields[4:] == ["[fw]", "high"] else "candidate"
        expected.append("\t".join((*fields, application)))
    actual = (directory / "findings.tsv").read_text(encoding="utf-8").splitlines()
    if actual != expected:
        raise PipelineError(f"{version}: exported findings do not match the source TSV")


def remove_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    elif path.exists() or path.is_symlink():
        path.unlink()


def publish_staged_directory(stage: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    backup: Path | None = None
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink() or not destination.is_dir():
            raise PipelineError(
                f"Refusing to replace non-directory export: {destination}"
            )
        allowed_names = {*GHIDRA_EXPORTS, "manifest.json"}
        unexpected = [
            item
            for item in destination.iterdir()
            if item.name not in allowed_names or item.is_symlink() or not item.is_file()
        ]
        if unexpected:
            raise PipelineError(
                f"Refusing to replace export directory containing unexpected files: {unexpected}"
            )
        backup = destination.parent / (f".{destination.name}.backup-{uuid.uuid4().hex}")
        os.replace(destination, backup)
    try:
        os.replace(stage, destination)
    except OSError:
        if backup is not None and (backup.exists() or backup.is_symlink()):
            os.replace(backup, destination)
        raise
    if backup is not None:
        remove_path(backup)


def run_staged_export(
    version: str,
    expected_sha256: str,
    expected_findings_sha256: str,
    workspace: Path,
    headless: str,
    command_builder: Callable[[Path], list[str]],
    after_run: Callable[[], None] | None = None,
) -> Path:
    export_root = workspace / "exports"
    export_root.mkdir(parents=True, exist_ok=True)
    destination = export_path(version, workspace)
    with tempfile.TemporaryDirectory(
        prefix=f".stage-{version.replace('.', '-')}-", dir=export_root
    ) as stage_name:
        stage = Path(stage_name)
        command = command_builder(stage)
        run_headless(command, headless, workspace)
        if after_run is not None:
            after_run()
        validate_ghidra_exports(version, stage, expected_sha256)
        validate_findings_export(
            version, stage, expected_sha256, expected_findings_sha256
        )
        write_manifest(version, stage, expected_sha256, expected_findings_sha256)
        validate_exports(version, stage, expected_sha256, expected_findings_sha256)
        publish_staged_directory(stage, destination)
    return destination


def import_version(version: str, headless: str, workspace: Path) -> None:
    require_project_absent(workspace, version)
    image, _, _ = read_verified_input(version)
    project_directory(workspace).mkdir(parents=True, exist_ok=True)
    expected_sha256 = sha256(image)
    _, findings = read_verified_findings(version, expected_sha256)
    findings_sha256 = sha256(findings)

    def verify_imported_project() -> None:
        require_project_present(workspace, version)

    output = run_staged_export(
        version,
        expected_sha256,
        findings_sha256,
        workspace,
        headless,
        lambda stage: build_import_command(
            version, workspace, expected_sha256, findings_sha256, stage
        ),
        verify_imported_project,
    )
    print(
        f"Imported {version}: {len(image)} bytes at CPU 0x4000..0xFFFF; "
        f"exports in {output.relative_to(ROOT)}"
    )


def regen_version(version: str, headless: str, workspace: Path) -> None:
    image, _, _ = read_verified_input(version)
    project_file = require_project_present(workspace, version)
    expected_sha256 = sha256(image)
    _, findings = read_verified_findings(version, expected_sha256)
    findings_sha256 = sha256(findings)
    output = run_staged_export(
        version,
        expected_sha256,
        findings_sha256,
        workspace,
        headless,
        lambda stage: build_regen_command(
            version, workspace, expected_sha256, findings_sha256, stage
        ),
    )
    print(
        f"Regenerated {version} exports from {project_file.name} into "
        f"{output.relative_to(ROOT)}"
    )


def changed_runs(left: bytes, right: bytes) -> list[dict[str, int | str]]:
    runs: list[dict[str, int | str]] = []
    start: int | None = None
    for offset, (left_byte, right_byte) in enumerate(zip(left, right)):
        if left_byte != right_byte and start is None:
            start = offset
        elif left_byte == right_byte and start is not None:
            runs.append(make_run(start, offset))
            start = None
    if start is not None:
        runs.append(make_run(start, len(left)))
    return runs


def make_run(start: int, end_exclusive: int) -> dict[str, int | str]:
    return {
        "file_offset_start": f"0x{start:04X}",
        "file_offset_end_exclusive": f"0x{end_exclusive:04X}",
        "cpu_address_start": f"0x{BASE_ADDRESS + start:04X}",
        "cpu_address_end_inclusive": f"0x{BASE_ADDRESS + end_exclusive - 1:04X}",
        "length_bytes": end_exclusive - start,
    }


def compare_siblings(workspace: Path) -> None:
    left, left_path, _ = read_verified_input("40.06")
    right, right_path, _ = read_verified_input("40.16")
    if len(left) != len(right):
        raise PipelineError(
            f"Cannot compare unequal slice lengths: {len(left)} vs {len(right)}"
        )

    difference_count = sum(a != b for a, b in zip(left, right))
    runs = changed_runs(left, right)
    output = workspace / "comparison"
    output.mkdir(parents=True, exist_ok=True)
    diff_path = output / "sibling-byte-diff.tsv"
    with diff_path.open("w", encoding="utf-8", newline="\n") as diff:
        diff.write(
            "# Exact byte comparison; no instruction or semantic normalization.\n"
        )
        diff.write("cpu_address\tfile_offset\t40.06\t40.16\n")
        for offset, (left_byte, right_byte) in enumerate(zip(left, right)):
            if left_byte != right_byte:
                diff.write(
                    f"0x{BASE_ADDRESS + offset:04X}\t0x{offset:04X}\t"
                    f"0x{left_byte:02X}\t0x{right_byte:02X}\n"
                )

    report = {
        "comparison": "exact byte-for-byte, same file offset and CPU address",
        "range": {
            "cpu_start": f"0x{BASE_ADDRESS:04X}",
            "cpu_end_inclusive": "0xFFFF",
            "length_bytes_each": len(left),
        },
        "40.06": {
            "binary": left_path.relative_to(ROOT).as_posix(),
            "sha256": sha256(left),
        },
        "40.16": {
            "binary": right_path.relative_to(ROOT).as_posix(),
            "sha256": sha256(right),
        },
        "matching_byte_positions": len(left) - difference_count,
        "differing_byte_positions": difference_count,
        "different_percent": round(100.0 * difference_count / len(left), 6),
        "different_contiguous_runs": runs,
        "diff_tsv": diff_path.relative_to(ROOT).as_posix(),
    }
    report_path = output / "sibling-comparison.json"
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        f"Exact sibling comparison: {len(left) - difference_count} matching and "
        f"{difference_count} differing byte positions across {len(runs)} changed runs "
        f"({len(left)} bytes total)."
    )
    print(f"Diff: {diff_path.relative_to(ROOT)}")


def compare_functions(workspace: Path, headless: str) -> None:
    hashes: dict[str, str] = {}
    for version in VERSIONS:
        image, _, _ = read_verified_input(version)
        image_hash = sha256(image)
        _, findings = read_verified_findings(version, image_hash)
        findings_hash = sha256(findings)
        require_project_present(workspace, version)
        exports = export_path(version, workspace)
        validate_ghidra_exports(version, exports, image_hash)
        validate_exports(version, exports, image_hash, findings_hash)
        validate_findings_export(version, exports, image_hash, findings_hash)
        hashes[version] = image_hash

    output = workspace / "comparison"
    output.mkdir(parents=True, exist_ok=True)
    destination = output / "vt-exact-functions.tsv"
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink() or not destination.is_file():
            raise PipelineError(
                f"Refusing to replace non-file VT report: {destination}"
            )
        with destination.open(encoding="utf-8") as existing:
            if (
                existing.readline().strip()
                != "# Candidate matches only; no names or markup were applied."
            ):
                raise PipelineError(
                    f"Refusing to replace an unknown VT report: {destination}"
                )

    with tempfile.TemporaryDirectory(prefix=".vt-stage-", dir=output) as stage_name:
        staged = Path(stage_name) / "vt-exact-functions.tsv"
        command = [
            str(project_directory(workspace)),
            project_name("40.06"),
            "-process",
            input_paths("40.06")[0].name,
            "-readOnly",
            "-noanalysis",
            "-max-cpu",
            "1",
            "-scriptPath",
            str(SCRIPT_DIR),
            "-postScript",
            "CompareJms539Functions.java",
            str(project_directory(workspace)),
            project_name("40.16"),
            input_paths("40.16")[0].name,
            hashes["40.06"],
            hashes["40.16"],
            str(staged),
        ]
        run_headless(command, headless, workspace)
        if not staged.is_file():
            raise PipelineError("Ghidra did not create the staged VT report")
        lines = staged.read_text(encoding="utf-8").splitlines()
        if (
            len(lines) < 5
            or lines[0] != "# Candidate matches only; no names or markup were applied."
            or not lines[1].endswith(hashes["40.06"])
            or not lines[2].endswith(hashes["40.16"])
        ):
            raise PipelineError("Ghidra VT report has missing or incorrect provenance")
        reader = csv.DictReader(lines[4:], delimiter="\t")
        columns = [
            "correlator",
            "source",
            "destination",
            "source_name",
            "destination_name",
            "source_length",
            "destination_length",
            "similarity",
            "confidence",
        ]
        if reader.fieldnames != columns:
            raise PipelineError("Ghidra VT report has an unexpected schema")
        counts = {
            "Exact Function Bytes Match": 0,
            "Exact Function Instructions Match": 0,
        }
        seen: set[tuple[str, str, str]] = set()
        for row in reader:
            try:
                correlation = row["correlator"]
                source = int(row["source"], 16)
                target = int(row["destination"], 16)
                source_length = int(row["source_length"])
                target_length = int(row["destination_length"])
                similarity = float(row["similarity"])
                confidence = float(row["confidence"])
            except (TypeError, ValueError, KeyError) as error:
                raise PipelineError(
                    "Ghidra VT report has an invalid match row"
                ) from error
            key = correlation, row["source"], row["destination"]
            if (
                correlation not in counts
                or not BASE_ADDRESS <= source <= 0xFFFF
                or not BASE_ADDRESS <= target <= 0xFFFF
                or source_length <= 0
                or target_length <= 0
                or similarity != 1.0
                or not math.isfinite(confidence)
                or confidence < 0
                or not row["source_name"]
                or not row["destination_name"]
                or set(row) != set(columns)
                or key in seen
            ):
                raise PipelineError("Ghidra VT report has an invalid match row")
            seen.add(key)
            counts[correlation] += 1
        os.replace(staged, destination)
    print(
        "Ghidra Version Tracking candidates: "
        f"{counts['Exact Function Bytes Match']} byte matches, "
        f"{counts['Exact Function Instructions Match']} instruction matches; "
        "no names or markup applied."
    )
    print(f"Report: {destination.relative_to(ROOT)}")


def add_version_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--version",
        choices=("40.06", "40.16", "both"),
        default="both",
        help="firmware slice to process (default: both)",
    )
    parser.add_argument(
        "--analyze-headless",
        help="path to Ghidra analyzeHeadless (or set GHIDRA_ANALYZE_HEADLESS)",
    )
    parser.add_argument(
        "--workspace",
        help=(
            "dedicated output workspace under analysis/initial "
            f"(default: {DEFAULT_WORKSPACE.relative_to(ROOT)})"
        ),
    )


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Offline Ghidra 8051 import/export pipeline for the local JMS539 code slices. "
            "No network, device, USB, or firmware-write operations are performed."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("import", "regen"):
        subparser = subparsers.add_parser(
            name,
            help=(
                "import and analyze the raw slices"
                if name == "import"
                else "recover D52-correlated XDATA code and re-export saved projects"
            ),
        )
        add_version_argument(subparser)
    subparsers.add_parser(
        "compare",
        help="write an exact byte-for-byte 40.06 versus 40.16 comparison",
    ).add_argument(
        "--workspace",
        help=(
            "dedicated output workspace under analysis/initial "
            f"(default: {DEFAULT_WORKSPACE.relative_to(ROOT)})"
        ),
    )
    vt = subparsers.add_parser(
        "vt",
        help="run non-applying Ghidra exact-function Version Tracking",
    )
    vt.add_argument(
        "--analyze-headless",
        help="path to Ghidra analyzeHeadless (or set GHIDRA_ANALYZE_HEADLESS)",
    )
    vt.add_argument(
        "--workspace",
        help=(
            "dedicated output workspace under analysis/initial "
            f"(default: {DEFAULT_WORKSPACE.relative_to(ROOT)})"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    try:
        workspace = resolve_workspace(args.workspace)
        if args.command == "compare":
            compare_siblings(workspace)
            return 0
        if args.command == "vt":
            compare_functions(workspace, resolve_headless(args.analyze_headless))
            return 0

        versions = version_values(args.version)
        if args.command == "import":
            for version in versions:
                require_project_absent(workspace, version)
        else:
            for version in versions:
                require_project_present(workspace, version)
        headless = resolve_headless(args.analyze_headless)
        if args.command == "import":
            for version in versions:
                import_version(version, headless, workspace)
        else:
            for version in versions:
                regen_version(version, headless, workspace)
        if args.version == "both":
            compare_siblings(workspace)
        return 0
    except (OSError, PipelineError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Inventory decoded JMS539 8051 memory writes and XDATA reads offline.

The report includes unresolved targets and does not assume that XDATA is RAM
or a peripheral register. It covers the instructions in the saved Ghidra
exports, not undisassembled code or the unavailable ROM. It includes implicit
DPTR and stack-pointer updates, but not implicit accumulator/B/PSW effects or
interrupt hardware writes.
"""

from __future__ import annotations

import argparse
import csv
import io
import os
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

import ghidra_8051 as pipeline

DIRECT_WRITES = {
    0x05,
    0x15,
    0x42,
    0x43,
    0x52,
    0x53,
    0x62,
    0x63,
    0x75,
    0x86,
    0x87,
    0xC5,
    0xD0,
    0xD5,
    0xF5,
    *range(0x88, 0x90),
}
BIT_WRITES = {0x10, 0x92, 0xB2, 0xC2, 0xD2}
INDIRECT_WRITES = {
    0x06,
    0x07,
    0x16,
    0x17,
    0x76,
    0x77,
    0xA6,
    0xA7,
    0xC6,
    0xC7,
    0xD6,
    0xD7,
    0xF6,
    0xF7,
}
REGISTER_WRITES = (
    *range(0x08, 0x10),
    *range(0x18, 0x20),
    *range(0x78, 0x80),
    *range(0xA8, 0xB0),
    *range(0xC8, 0xD0),
    *range(0xD8, 0xE0),
    *range(0xF8, 0x100),
)
FLOW_ENDS = {
    "ACALL",
    "LCALL",
    "AJMP",
    "LJMP",
    "SJMP",
    "JMP",
    "RET",
    "RETI",
    "JBC",
    "JB",
    "JNB",
    "JC",
    "JNC",
    "JZ",
    "JNZ",
    "CJNE",
    "DJNZ",
}
CORE_SFRS = {0x81: "SP", 0x82: "DPL", 0x83: "DPH", 0xD0: "PSW", 0xE0: "ACC", 0xF0: "B"}
MAGIC = "# JMS539 decoded memory-write inventory"
SITE_COLUMNS = (
    "pc",
    "function",
    "mnemonic",
    "space",
    "target",
    "bit",
    "access",
    "candidate_targets",
    "value_or_pattern",
    "resolution",
)
ADDRESS_COLUMNS = (
    "space",
    "target",
    "classification",
    "resolution",
    "candidate_name",
    "candidate_status",
    "candidate_confidence",
    "write_sites",
    "xdata_read_sites",
)


@dataclass(frozen=True)
class Instruction:
    address: int
    data: bytes
    mnemonic: str
    function: str = ""


def direct_destination(data: bytes) -> int | None:
    if data[0] == 0x85:
        return data[2]
    return data[1] if data[0] in DIRECT_WRITES else None


def writes_accumulator(opcode: int) -> bool:
    return (
        opcode
        in {
            0x03,
            0x04,
            0x13,
            0x14,
            0x23,
            0x33,
            0x74,
            0x83,
            0x84,
            0x93,
            0xA4,
            0xC4,
            0xC5,
            0xC6,
            0xC7,
            0xD4,
            0xD6,
            0xD7,
            0xE0,
            0xE2,
            0xE3,
            0xE4,
            0xE5,
            0xE6,
            0xE7,
            0xF4,
        }
        or 0x24 <= opcode <= 0x2F
        or 0x34 <= opcode <= 0x3F
        or 0x44 <= opcode <= 0x4F
        or 0x54 <= opcode <= 0x5F
        or 0x64 <= opcode <= 0x6F
        or 0x94 <= opcode <= 0x9F
        or 0xC8 <= opcode <= 0xCF
        or 0xE8 <= opcode <= 0xEF
    )


def target_text(address: int, width: int = 2) -> str:
    return f"0x{address:0{width}X}"


def audit(
    instructions: list[Instruction],
    incoming: set[int],
    xdata_references: dict[int, set[int]],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    writes: list[dict[str, str]] = []
    reads: list[dict[str, str]] = []
    dptr: int | None = None
    accumulator: tuple[str, int, str] | None = None
    previous_end: int | None = None
    previous_function: str | None = None

    for instruction in instructions:
        pc = instruction.address
        data = instruction.data
        opcode = data[0]
        if (
            pc != previous_end
            or pc in incoming
            or instruction.function != previous_function
        ):
            dptr = None
            accumulator = None

        def add(
            space: str,
            target: str,
            access: str,
            resolution: str,
            bit: str = "",
            candidates: str = "",
            pattern: str = "",
            direction: str = "write",
            context: Instruction = instruction,
        ) -> None:
            (reads if direction == "read" else writes).append(
                {
                    "pc": target_text(context.address, 4),
                    "function": context.function,
                    "mnemonic": context.mnemonic,
                    "space": space,
                    "target": target,
                    "bit": bit,
                    "access": access,
                    "resolution": resolution,
                    "candidate_targets": candidates,
                    "value_or_pattern": pattern,
                }
            )

        destination = direct_destination(data)
        if destination is not None:
            space = "IRAM" if destination < 0x80 else "SFR"
            add(space, target_text(destination), "direct_byte", "encoded")
        if opcode in BIT_WRITES:
            encoded = data[1]
            space = "IRAM" if encoded < 0x80 else "SFR"
            address = 0x20 + (encoded >> 3) if encoded < 0x80 else encoded & 0xF8
            access = "conditional_bit_clear" if opcode == 0x10 else "bit"
            add(space, target_text(address), access, "encoded", bit=str(encoded & 7))
        if opcode in INDIRECT_WRITES:
            add("IRAM", "?", f"indirect_R{opcode & 1}", "unresolved")
        if opcode in REGISTER_WRITES:
            register = opcode & 7
            possible = ",".join(target_text(register + 8 * bank) for bank in range(4))
            add(
                "IRAM",
                "?",
                f"register_R{register}",
                "bank_unresolved",
                candidates=possible,
            )
        if opcode in {0x90, 0xA3}:
            add("SFR", "0x82", "implicit_DPTR_low", "8051_core")
            add("SFR", "0x83", "implicit_DPTR_high", "8051_core")

        is_call = opcode == 0x12 or opcode & 0x1F == 0x11
        if is_call or opcode == 0xC0:
            add(
                "IRAM", "?", "stack_push_2" if is_call else "stack_push_1", "unresolved"
            )
        if is_call or opcode in {0xC0, 0xD0, 0x22, 0x32}:
            add("SFR", "0x81", "implicit_stack_pointer", "8051_core")

        if opcode == 0x90:
            dptr = int.from_bytes(data[1:3], "big")
        elif opcode == 0xA3 and dptr is not None:
            dptr = (dptr + 1) & 0xFFFF
        elif destination in {0x82, 0x83, 0x86}:
            dptr = None

        if opcode == 0x74:
            accumulator = ("constant", data[1], "")
        elif opcode == 0xE4:
            accumulator = ("constant", 0, "")
        elif opcode == 0xE0:
            accumulator = ("xdata", dptr, "") if dptr is not None else None
        elif opcode in {0x44, 0x54, 0x64} and accumulator is not None:
            kind, value, pattern = accumulator
            operation = {0x44: "or", 0x54: "and", 0x64: "xor"}[opcode]
            if kind == "constant":
                value = {
                    0x44: value | data[1],
                    0x54: value & data[1],
                    0x64: value ^ data[1],
                }[opcode]
            else:
                pattern += f"{operation}_{data[1]:02X};"
            accumulator = (kind, value, pattern)
        elif (
            opcode in {0x04, 0x14, 0xF4}
            and accumulator
            and accumulator[0] == "constant"
        ):
            value = accumulator[1]
            value = {0x04: value + 1, 0x14: value - 1, 0xF4: value ^ 0xFF}[
                opcode
            ] & 0xFF
            accumulator = ("constant", value, "")
        elif writes_accumulator(opcode):
            accumulator = None

        if opcode in {0xE0, 0xE2, 0xE3, 0xF0, 0xF2, 0xF3}:
            is_write = opcode in {0xF0, 0xF2, 0xF3}
            refs = xdata_references.get(pc, set())
            local = dptr if opcode in {0xE0, 0xF0} else None
            possible = set(refs)
            if local is not None:
                possible.add(local)
            if local is not None and refs and refs != {local}:
                target, resolution = "?", "conflicting_inferences"
            elif local is not None:
                target, resolution = target_text(local, 4), "local_straight_line"
            elif len(refs) == 1:
                target, resolution = target_text(next(iter(refs)), 4), "ghidra_inferred"
            else:
                target = "?"
                resolution = "multiple_inferences" if refs else "unresolved"
            pattern = ""
            if is_write and accumulator and accumulator[0] == "constant":
                pattern = f"constant_{accumulator[1]:02X}"
            elif (
                is_write
                and accumulator
                and accumulator[0] == "xdata"
                and local == accumulator[1]
                and accumulator[2]
            ):
                pattern = "read_modify_write_" + accumulator[2].rstrip(";")
            add(
                "XDATA",
                target,
                "MOVX_DPTR" if opcode in {0xE0, 0xF0} else f"MOVX_R{opcode & 1}",
                resolution,
                candidates=",".join(
                    target_text(value, 4) for value in sorted(possible)
                ),
                pattern=pattern,
                direction="write" if is_write else "read",
            )

        if destination == 0xE0 or (
            opcode in BIT_WRITES and data[1] >= 0xE0 and data[1] < 0xE8
        ):
            accumulator = None
        if instruction.mnemonic.upper() in FLOW_ENDS:
            dptr = None
            accumulator = None
        previous_end = pc + len(data)
        previous_function = instruction.function
    return writes, reads


def read_analysis(
    version: str, workspace: Path
) -> tuple[bytes, list[Instruction], set[int], dict[int, set[int]]]:
    image, _, _ = pipeline.read_verified_input(version)
    image_hash = pipeline.sha256(image)
    _, findings = pipeline.read_verified_findings(version, image_hash)
    findings_hash = pipeline.sha256(findings)
    exports = pipeline.export_path(version, workspace)
    pipeline.validate_ghidra_exports(version, exports, image_hash)
    pipeline.validate_exports(version, exports, image_hash, findings_hash)
    pipeline.validate_findings_export(version, exports, image_hash, findings_hash)
    pipeline.require_tsv_columns(
        exports / "references.tsv",
        {"from_address", "to_address", "to_space", "reference_type"},
    )
    instructions = []
    with (exports / "instructions.tsv").open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            address = int(row["address"], 16)
            data = bytes.fromhex(row["bytes"])
            offset = address - pipeline.BASE_ADDRESS
            if not data or offset < 0 or image[offset : offset + len(data)] != data:
                raise pipeline.PipelineError(
                    f"{version}: invalid instruction bytes at {address:#x}"
                )
            if instructions and address < instructions[-1].address + len(
                instructions[-1].data
            ):
                raise pipeline.PipelineError(
                    f"{version}: overlapping or unsorted instructions"
                )
            instructions.append(
                Instruction(
                    address, data, row["mnemonic"], row["containing_function_entry"]
                )
            )
    incoming: set[int] = set()
    references: dict[int, set[int]] = defaultdict(set)
    with (exports / "references.tsv").open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            kind = row["reference_type"]
            if row["to_space"] == "CODE" and ("JUMP" in kind or "CALL" in kind):
                incoming.add(int(row["to_address"], 16))
            if row["to_space"] == "EXTMEM" and kind in {"READ", "WRITE", "READ_WRITE"}:
                references[int(row["from_address"], 16)].add(int(row["to_address"], 16))
    return image, instructions, incoming, references


def classification(space: str, target: str) -> str:
    if target == "?":
        return "unresolved"
    if space == "IRAM":
        return "internal_ram"
    if space == "SFR":
        return CORE_SFRS.get(int(target, 16), "sfr_unclassified")
    return "xdata_ram_or_register_unknown"


def read_memory_findings() -> dict[tuple[str, str], tuple[str, str, str]]:
    path = pipeline.FINDINGS_DIR / "memory_findings.tsv"
    findings: dict[tuple[str, str], tuple[str, str, str]] = {}
    with path.open(encoding="utf-8", newline="") as stream:
        rows = csv.reader(
            (line for line in stream if not line.startswith("#")), delimiter="\t"
        )
        for row in rows:
            if len(row) != 8 or row[0] not in {"SFR", "XDATA"}:
                raise pipeline.PipelineError(f"Invalid memory finding in {path}")
            try:
                address = int(row[1], 16)
            except ValueError as error:
                raise pipeline.PipelineError(
                    f"Invalid memory address in {path}"
                ) from error
            width = 2 if row[0] == "SFR" else 4
            if not 0 <= address <= (0xFF if row[0] == "SFR" else 0xFFFF):
                raise pipeline.PipelineError(f"Out-of-range memory address in {path}")
            key = row[0], target_text(address, width)
            if (
                key in findings
                or row[3] not in {"[fw]", "[guess]"}
                or row[4] not in {"high", "med", "low"}
            ):
                raise pipeline.PipelineError(
                    f"Duplicate or invalid memory finding in {path}: {key}"
                )
            findings[key] = row[2], row[3], row[4]
    return findings


def tsv_text(
    version: str, image_hash: str, columns: tuple[str, ...], rows: list[dict[str, str]]
) -> str:
    output = io.StringIO(newline="")
    output.write(MAGIC + "\n")
    output.write(f"# firmware={version}; image_sha256={image_hash}\n")
    output.write(
        "# Decoded sites only; unknown targets and inferred addresses are not confirmed.\n"
    )
    writer = csv.DictWriter(
        output, fieldnames=columns, delimiter="\t", lineterminator="\n"
    )
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def publish(path: Path, contents: str) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise pipeline.PipelineError(f"Refusing to replace non-file output: {path}")
    if path.exists():
        with path.open(encoding="utf-8") as existing:
            if existing.readline().rstrip("\n") != MAGIC:
                raise pipeline.PipelineError(
                    f"Refusing to replace unknown output: {path}"
                )
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="\n", dir=path.parent, delete=False
    ) as temporary:
        name = temporary.name
        try:
            temporary.write(contents)
            temporary.flush()
            os.replace(name, path)
        finally:
            if os.path.exists(name):
                os.unlink(name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", choices=("40.06", "40.16", "both"), default="both")
    parser.add_argument("--workspace", required=True, help="existing Ghidra workspace")
    parser.add_argument("--output", help="output directory inside this repository")
    args = parser.parse_args(argv)
    try:
        workspace = pipeline.resolve_workspace(args.workspace)
        output = Path(args.output) if args.output else workspace / "memory-writes"
        if not output.is_absolute():
            output = pipeline.ROOT / output
        output = output.resolve()
        if output == pipeline.ROOT or not output.is_relative_to(pipeline.ROOT):
            raise pipeline.PipelineError(
                "Output must be in a subdirectory of this repository"
            )

        findings = read_memory_findings()
        for version in pipeline.version_values(args.version):
            image, instructions, incoming, references = read_analysis(
                version, workspace
            )
            rows, reads = audit(instructions, incoming, references)
            counts = Counter(
                (row["space"], row["target"], row["resolution"]) for row in rows
            )
            read_counts = Counter(
                (row["space"], row["target"], row["resolution"]) for row in reads
            )
            addresses = []
            for space, target, resolution in sorted(counts.keys() | read_counts.keys()):
                key = space, target, resolution
                name, status, confidence = findings.get((space, target), ("", "", ""))
                addresses.append(
                    {
                        "space": space,
                        "target": target,
                        "classification": classification(space, target),
                        "resolution": resolution,
                        "write_sites": str(counts[key]),
                        "xdata_read_sites": str(read_counts[key]),
                        "candidate_name": name,
                        "candidate_status": status,
                        "candidate_confidence": confidence,
                    }
                )
            image_hash = pipeline.sha256(image)
            publish(
                output / f"memory_write_sites_{version}.tsv",
                tsv_text(version, image_hash, SITE_COLUMNS, rows),
            )
            publish(
                output / f"memory_xdata_read_sites_{version}.tsv",
                tsv_text(version, image_hash, SITE_COLUMNS, reads),
            )
            publish(
                output / f"memory_address_summary_{version}.tsv",
                tsv_text(version, image_hash, ADDRESS_COLUMNS, addresses),
            )
            xdata = [row for row in rows if row["space"] == "XDATA"]
            print(
                f"{version}: {len(instructions)} decoded instructions, {len(rows)} write effects, "
                f"{len(xdata)} XDATA stores ({sum(row['target'] == '?' for row in xdata)} unresolved), "
                f"{len(reads)} XDATA loads ({sum(row['target'] == '?' for row in reads)} unresolved)"
            )
        print(f"Reports: {output.relative_to(pipeline.ROOT)}")
        return 0
    except (OSError, ValueError, pipeline.PipelineError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

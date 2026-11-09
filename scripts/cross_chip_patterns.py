#!/usr/bin/env python3
"""Scan 8051 images for register idioms used by public JMS567/JMS578 tools.

A hit means the byte sequence occurs; it is not proof of identical register
semantics on JMS539. When a Ghidra instructions.tsv export is given, each hit
is classified as the start of a decoded instruction, inside one, or undecoded.

Usage:
  python3 scripts/cross_chip_patterns.py \
      --image 40.06=analysis/initial/jms539-31.00.40.06/v40_06_code.bin@0x4000 \
      --instructions 40.06=analysis/initial/ghidra-8051-research2/exports/40.06/instructions.tsv \
      --image jms567=/path/to/DS500U3-JMS567-125.2.0.3-v3-uas-ncq.bin@0 \
      --counts counts.tsv --hits hits.tsv
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import re
import sys
from pathlib import Path

# (name, byte pattern, public source of the related-chip usage)
SIGNATURES = [
    ("xdata_7020_descriptor", "90 70 20", "jms578flash spi_tx.asm"),
    ("xdata_7026_set_1", "90 70 26 74 01 F0", "jms578flash spi_tx.asm"),
    ("xdata_7026_poll_bit0", "90 70 26 E0 (20|30) E0", "related start/busy idiom"),
    ("xdata_703B_store", "90 70 3B", "ds500u3 firmware-analysis.md"),
    ("xdata_7043_set_1", "90 70 43 74 01 F0", "ds500u3 firmware-analysis.md"),
    ("xdata_7054_access", "90 70 54", "jms578flash dumprom.asm (LED)"),
    ("xdata_7078_access", "90 70 78", "jms578flash reset.asm (timer)"),
    ("xdata_708C_access", "90 70 8C", "jms578flash firmware.go (code map)"),
    ("xdata_7140_access", "90 71 40", "jms578flash spi.go / spi_rx.asm"),
    ("xdata_7142_access", "90 71 42", "jms578flash spi_rx.asm / spi_tx.asm"),
    ("xdata_7148_access", "90 71 48", "jms578flash spi_rx.asm / spi_tx.asm"),
    ("xdata_714C_access", "90 71 4C", "jms578flash spi.go"),
    ("xdata_7150_access", "90 71 50", "jms578flash spi.go"),
    ("xdata_7160_store", "90 71 60 F0", "jms578flash spi_rx.asm"),
    ("xdata_7161_store", "90 71 61 F0", "jms578flash spi_rx.asm"),
    ("xdata_7166_store", "90 71 66 F0", "jms578flash spi_rx.asm / spi_tx.asm"),
    ("xdata_7167_store", "90 71 67 F0", "jms578flash spi_rx.asm / spi_tx.asm"),
    ("xdata_7168_access", "90 71 68", "none (JMS539-only neighbour)"),
    ("xdata_7169_access", "90 71 69", "none (JMS539-only neighbour)"),
    ("xdata_716D_set_FF", "90 71 6D 74 FF F0", "jms578flash spi.go"),
    ("xdata_7800_access", "90 78 00", "jms578flash reset.asm"),
    (
        "nvs_JM_signature_check",
        "E0 64 4A 60 .. .. .. .. A3 E0 64 4D",
        "ds500u3 NVS loader",
    ),
    ("ea_off_lcall_ea_on", "C2 AF 00 12 .. .. D2 AF", "none (JMS539 idiom)"),
]


def compile_pattern(text: str) -> re.Pattern[bytes]:
    """Hex tokens, `..` for any byte, `(AA|BB)` for alternatives."""
    parts = []
    for token in text.split():
        if token == "..":
            parts.append(b".")
        elif token.startswith("(") and token.endswith(")"):
            options = [re.escape(bytes.fromhex(x)) for x in token[1:-1].split("|")]
            parts.append(b"(?:" + b"|".join(options) + b")")
        else:
            parts.append(re.escape(bytes.fromhex(token)))
    return re.compile(b"".join(parts), re.DOTALL)


def load_instruction_starts(path: Path) -> dict[int, int]:
    """Map every byte covered by a decoded instruction to its start address."""
    covered = {}
    with path.open(newline="") as handle:
        for row in csv.DictReader(handle, delimiter="\t"):
            start = int(row["address"], 16)
            for offset in range(len(row["bytes"].split())):
                covered[start + offset] = start
    return covered


def classify(address: int, covered: dict[int, int] | None) -> str:
    if covered is None:
        return "no_listing"
    if covered.get(address) == address:
        return "decoded"
    return "inside_instruction" if address in covered else "undecoded"


def scan(image: bytes, base: int, covered: dict[int, int] | None):
    for name, text, _ in SIGNATURES:
        for match in compile_pattern(text).finditer(image):
            address = base + match.start()
            yield (
                name,
                address,
                match.group().hex(" ").upper(),
                classify(address, covered),
            )


def parse_labelled(value: str) -> tuple[str, str]:
    label, sep, rest = value.partition("=")
    if not sep or not label or not rest:
        raise argparse.ArgumentTypeError(f"expected LABEL=VALUE, got {value!r}")
    return label, rest


def parse_image(value: str) -> tuple[str, Path, int]:
    label, rest = parse_labelled(value)
    path, _, base = rest.rpartition("@") if "@" in rest else (rest, "", "0")
    return label, Path(path), int(base, 0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--image",
        action="append",
        type=parse_image,
        required=True,
        help="LABEL=PATH[@BASE]; BASE is the CPU address of byte 0",
    )
    parser.add_argument(
        "--instructions",
        action="append",
        type=parse_labelled,
        default=[],
        help="LABEL=Ghidra instructions.tsv for coverage classification",
    )
    parser.add_argument("--counts", type=Path, required=True)
    parser.add_argument("--hits", type=Path, required=True)
    args = parser.parse_args(argv)

    listings = {
        label: load_instruction_starts(Path(p)) for label, p in args.instructions
    }
    unknown = set(listings) - {label for label, _, _ in args.image}
    if unknown:
        parser.error(f"--instructions labels without --image: {sorted(unknown)}")

    labels = [label for label, _, _ in args.image]
    counts = {name: dict.fromkeys(labels, 0) for name, _, _ in SIGNATURES}
    decoded = {name: dict.fromkeys(labels, 0) for name, _, _ in SIGNATURES}
    hit_rows = []
    headers = []
    for label, path, base in args.image:
        image = path.read_bytes()
        headers.append(
            f"# {label}: sha256={hashlib.sha256(image).hexdigest()} base=0x{base:04X}"
        )
        for name, address, raw, status in scan(image, base, listings.get(label)):
            counts[name][label] += 1
            decoded[name][label] += status == "decoded"
            hit_rows.append((label, name, f"0x{address:04X}", raw, status))

    with args.counts.open("w", newline="") as handle:
        handle.write(
            "# Byte-pattern hits; related-chip semantics are not assumed for JMS539.\n"
        )
        handle.write("\n".join(headers) + "\n")
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        columns = []
        for label in labels:
            columns += [label] + ([f"{label}_decoded"] if label in listings else [])
        writer.writerow(["signature", "pattern", *columns, "related_source"])
        for name, text, source in SIGNATURES:
            values = []
            for label in labels:
                values.append(counts[name][label])
                if label in listings:
                    values.append(decoded[name][label])
            writer.writerow([name, text, *values, source])

    with args.hits.open("w", newline="") as handle:
        handle.write("\n".join(headers) + "\n")
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(["image", "signature", "address", "bytes", "ghidra_coverage"])
        writer.writerows(hit_rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())

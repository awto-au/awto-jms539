#!/usr/bin/env python3
"""Compare Keil OMF-51 helper segments with offline JMS539 code images.

Requires the OMF parser and matcher in ../awto-ddc/scripts. All inputs are
regular files; the output contains library-derived bytes and belongs under
the ignored analysis/initial/ directory.

Usage:
    python3 scripts/keil_helpers.py --help
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from dev import read_regular_file

ROOT = Path(__file__).resolve().parents[1]


def helper_signatures(modules: list[Any]) -> list[dict[str, Any]]:
    signatures = []
    for module in modules:
        if not module.name.startswith("?C?"):
            continue
        if module.unresolved_fixups:
            raise ValueError(f"{module.name} has unresolved fixups")
        for segment in module.segs.values():
            if segment.b2 != 0:
                continue
            entries = [
                {"name": name, "offset": offset}
                for name, seg_id, offset, _kind in module.publics
                if seg_id == segment.sid and name.startswith("?C?")
            ]
            if not entries:
                continue
            if (
                segment.data is None
                or segment.known is None
                or len(segment.data) != segment.size
                or len(segment.known) != segment.size
                or any(not 0 <= entry["offset"] < segment.size for entry in entries)
            ):
                raise ValueError(f"invalid code segment {module.name}/{segment.name}")
            mask = bytes(
                0 if index in segment.reloc or not segment.known[index] else 0xFF
                for index in range(segment.size)
            )
            signatures.append(
                {
                    "name": module.name,
                    "segment": segment.name,
                    "entries": entries,
                    "size": segment.size,
                    "fixed_bytes": mask.count(0xFF),
                    "distinct_fixed_bytes": len(
                        {value for value, fixed in zip(segment.data, mask) if fixed}
                    ),
                    "hex": bytes(segment.data).hex(),
                    "mask": mask.hex(),
                }
            )
    return signatures


def validate_output(output: Path, inputs: list[Path], allowed: Path) -> None:
    if not output.resolve().is_relative_to(allowed.resolve()):
        raise ValueError(f"output must be under {allowed}")
    if output.exists() and not output.is_file():
        raise ValueError(f"output is not a regular file: {output}")
    for path in inputs:
        if output.resolve() == path.resolve() or (
            output.exists() and path.exists() and output.samefile(path)
        ):
            raise ValueError(f"output would overwrite input: {path}")


def classify_siblings(matches: list[dict[str, Any]]) -> None:
    exact_at: dict[int, set[str]] = {}
    for match in matches:
        if match["class"] == "EXACT":
            exact_at.setdefault(match["file_offsets"][0], set()).add(match["helper"])
    for match in matches:
        if match["class"] not in ("NEAR", "ABSENT") or match["score"] < 0.5:
            continue
        names = exact_at.get(match["best_offset"], set())
        if names and match["helper"] not in names:
            match["class"] = "SIBLING"
            match["sibling_helpers"] = sorted(names)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, action="append", required=True)
    parser.add_argument("--image", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--code-base", type=lambda value: int(value, 0), default=0x4000)
    parser.add_argument("--tools", type=Path, default=ROOT.parent / "awto-ddc/scripts")
    args = parser.parse_args()

    try:
        if not 0 <= args.code_base < 0x10000:
            raise ValueError("code base must fit the 8051 address space")
        if (
            not (args.tools / "omf51_lib.py").is_file()
            or not (args.tools / "rtk_libsig.py").is_file()
        ):
            raise ValueError(f"OMF parser and matcher not found in {args.tools}")
        validate_output(
            args.output, args.library + args.image, ROOT / "analysis" / "initial"
        )
        os.environ.setdefault("AWTO_DDC_REPO", str(ROOT))
        sys.path.insert(0, str(args.tools.resolve()))
        omf = importlib.import_module("omf51_lib")
        matcher = importlib.import_module("rtk_libsig")

        libraries = []
        for path in args.library:
            contents = read_regular_file(path)
            signatures = helper_signatures(omf.parse_lib(path))
            if not signatures:
                raise ValueError(f"no helper signatures found in {path}")
            libraries.append(
                {
                    "path": str(path),
                    "sha256": hashlib.sha256(contents).hexdigest(),
                    "signatures": signatures,
                }
            )

        images = []
        for path in args.image:
            contents = read_regular_file(path)
            if not contents or args.code_base + len(contents) > 0x10000:
                raise ValueError(f"image does not fit the 8051 code space: {path}")
            matches = []
            for library in libraries:
                for signature in library["signatures"]:
                    kind, hits, score, best = matcher.classify(signature, {0: contents})
                    matches.append(
                        {
                            "library": library["path"],
                            "helper": signature["name"],
                            "entries": signature["entries"],
                            "fixed_bytes": signature["fixed_bytes"],
                            "distinct_fixed_bytes": signature["distinct_fixed_bytes"],
                            "class": kind,
                            "score": score,
                            "hit_count": len(hits),
                            "file_offsets": [offset for _bank, offset in hits[:4]],
                            "best_offset": best[1] if best else None,
                        }
                    )
            classify_siblings(matches)
            images.append(
                {
                    "path": str(path),
                    "sha256": hashlib.sha256(contents).hexdigest(),
                    "code_base": args.code_base,
                    "matches": matches,
                }
            )
            print(f"{path}: {dict(Counter(match['class'] for match in matches))}")

        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps({"libraries": libraries, "images": images}, indent=2) + "\n",
            encoding="utf-8",
        )
        print(
            f"Saved candidates and signatures to {args.output}; no names were applied."
        )
        return 0
    except (ImportError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

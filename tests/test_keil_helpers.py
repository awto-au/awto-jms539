"""Offline tests for extracting masked Keil helper signatures."""

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import keil_helpers


class HelperSignatureTests(unittest.TestCase):
    def test_includes_whole_code_segment_and_masks_fixups(self) -> None:
        segment = SimpleNamespace(
            sid=1,
            name="?C?LIB_CODE",
            b2=0,
            size=5,
            data=bytearray(b"\x12\x34\x56\x78\x22"),
            known=bytearray(b"\x01\x01\x01\x00\x01"),
            reloc={1, 2},
        )
        module = SimpleNamespace(
            name="?C?COPY",
            unresolved_fixups=0,
            segs={1: segment},
            publics=[("?C?COPY", 1, 2, 0)],
        )

        signatures = keil_helpers.helper_signatures([module])

        self.assertEqual(len(signatures), 1)
        self.assertEqual(signatures[0]["hex"], "1234567822")
        self.assertEqual(signatures[0]["mask"], "ff000000ff")
        self.assertEqual(signatures[0]["entries"], [{"name": "?C?COPY", "offset": 2}])

    def test_rejects_unresolved_fixups(self) -> None:
        module = SimpleNamespace(name="?C?COPY", unresolved_fixups=1, segs={})
        with self.assertRaisesRegex(ValueError, "unresolved fixups"):
            keil_helpers.helper_signatures([module])

    def test_sibling_candidate_does_not_override_an_exact_match(self) -> None:
        matches = [
            {"class": "EXACT", "helper": "A", "file_offsets": [100]},
            {"class": "NEAR", "helper": "B", "best_offset": 100, "score": 0.95},
        ]
        keil_helpers.classify_siblings(matches)
        self.assertEqual(matches[0]["class"], "EXACT")
        self.assertEqual(matches[1]["class"], "SIBLING")
        self.assertEqual(matches[1]["sibling_helpers"], ["A"])

    def test_output_must_not_overwrite_an_input_or_leave_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "library.lib"
            source.write_bytes(b"fixture")
            with self.assertRaisesRegex(ValueError, "overwrite"):
                keil_helpers.validate_output(source, [source], root)
            with self.assertRaisesRegex(ValueError, "must be under"):
                keil_helpers.validate_output(
                    root.parent / "outside.json", [source], root
                )


if __name__ == "__main__":
    unittest.main()

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import cross_chip_patterns as ccp


class CrossChipPatternTests(unittest.TestCase):
    def test_wildcards_and_alternatives(self):
        pattern = ccp.compile_pattern("90 70 26 E0 (20|30) E0 ..")
        self.assertTrue(pattern.fullmatch(bytes.fromhex("907026E020E00A")))
        self.assertTrue(pattern.fullmatch(bytes.fromhex("907026E030E00A")))
        self.assertIsNone(pattern.fullmatch(bytes.fromhex("907026E040E00A")))

    def test_hits_are_classified_against_decoded_listing(self):
        image = bytes.fromhex("907054 00 907054")
        covered = {0x4000: 0x4000, 0x4001: 0x4000, 0x4002: 0x4000, 0x4005: 0x4003}
        hits = [
            h for h in ccp.scan(image, 0x4000, covered) if h[0] == "xdata_7054_access"
        ]
        self.assertEqual(
            [(address, status) for _, address, _, status in hits],
            [(0x4000, "decoded"), (0x4004, "undecoded")],
        )
        self.assertEqual(ccp.classify(0x4005, covered), "inside_instruction")
        self.assertEqual(ccp.classify(0x4000, None), "no_listing")


if __name__ == "__main__":
    unittest.main()

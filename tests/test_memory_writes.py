import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import memory_writes


def instruction(address: int, code: str, mnemonic: str):
    return memory_writes.Instruction(address, bytes.fromhex(code), mnemonic)


class MemoryWriteAuditTests(unittest.TestCase):
    def test_direct_and_bit_writes_use_the_correct_address_spaces(self):
        instructions = [
            instruction(0x4000, "75 20 12", "MOV"),
            instruction(0x4003, "85 21 E8", "MOV"),
            instruction(0x4006, "D2 58", "SETB"),
            instruction(0x4008, "C2 AF", "CLR"),
        ]
        rows, _ = memory_writes.audit(instructions, set(), {})
        self.assertEqual(
            [(r["space"], r["target"], r["bit"]) for r in rows],
            [
                ("IRAM", "0x20", ""),
                ("SFR", "0xE8", ""),
                ("IRAM", "0x2B", "0"),
                ("SFR", "0xA8", "7"),
            ],
        )

    def test_dptr_increment_and_calls_preserve_unknown_targets(self):
        instructions = [
            instruction(0x4000, "90 12 34", "MOV"),
            instruction(0x4003, "74 AA", "MOV"),
            instruction(0x4005, "F0", "MOVX"),
            instruction(0x4006, "A3", "INC"),
            instruction(0x4007, "F0", "MOVX"),
            instruction(0x4008, "12 00 04", "LCALL"),
            instruction(0x400B, "F0", "MOVX"),
        ]
        rows, _ = memory_writes.audit(instructions, set(), {0x4005: {0x1234}})
        xdata = [r for r in rows if r["space"] == "XDATA"]
        self.assertEqual([r["target"] for r in xdata], ["0x1234", "0x1235", "?"])
        self.assertEqual(xdata[0]["value_or_pattern"], "constant_AA")
        self.assertEqual(xdata[-1]["resolution"], "unresolved")
        self.assertTrue(
            any(r["access"] == "stack_push_2" and r["target"] == "?" for r in rows)
        )

    def test_conflicting_references_and_branch_entries_are_not_asserted(self):
        instructions = [
            instruction(0x4000, "90 12 34", "MOV"),
            instruction(0x4003, "F0", "MOVX"),
            instruction(0x4004, "F0", "MOVX"),
        ]
        rows, _ = memory_writes.audit(instructions, {0x4004}, {0x4003: {0x5678}})
        xdata = [r for r in rows if r["space"] == "XDATA"]
        self.assertEqual(xdata[0]["resolution"], "conflicting_inferences")
        self.assertEqual(xdata[0]["target"], "?")
        self.assertEqual(xdata[0]["candidate_targets"], "0x1234,0x5678")
        self.assertEqual(xdata[1]["resolution"], "unresolved")

    def test_read_modify_write_pattern_requires_same_known_address(self):
        instructions = [
            instruction(0x4000, "90 70 43", "MOV"),
            instruction(0x4003, "E0", "MOVX"),
            instruction(0x4004, "44 01", "ORL"),
            instruction(0x4006, "F0", "MOVX"),
        ]
        rows, reads = memory_writes.audit(instructions, set(), {})
        store = next(row for row in rows if row["space"] == "XDATA")
        self.assertEqual(store["target"], "0x7043")
        self.assertEqual(store["value_or_pattern"], "read_modify_write_or_01")
        self.assertEqual([row["target"] for row in reads], ["0x7043"])

    def test_indirect_and_banked_register_addresses_remain_unresolved(self):
        instructions = [
            instruction(0x4000, "F6", "MOV"),
            instruction(0x4001, "79 01", "MOV"),
            instruction(0x4003, "F2", "MOVX"),
        ]
        rows, _ = memory_writes.audit(instructions, set(), {})
        self.assertEqual(rows[0]["access"], "indirect_R0")
        self.assertEqual(rows[0]["target"], "?")
        self.assertEqual(rows[1]["candidate_targets"], "0x01,0x09,0x11,0x19")
        self.assertEqual(rows[2]["space"], "XDATA")
        self.assertEqual(rows[2]["resolution"], "unresolved")

    def test_explicit_accumulator_writes_invalidate_known_value(self):
        instructions = [
            instruction(0x4000, "90 70 43", "MOV"),
            instruction(0x4003, "74 AA", "MOV"),
            instruction(0x4005, "D2 E0", "SETB"),
            instruction(0x4007, "F0", "MOVX"),
            instruction(0x4008, "74 BB", "MOV"),
            instruction(0x400A, "75 E0 12", "MOV"),
            instruction(0x400D, "F0", "MOVX"),
        ]
        rows, _ = memory_writes.audit(instructions, set(), {})
        stores = [row for row in rows if row["space"] == "XDATA"]
        self.assertEqual([row["value_or_pattern"] for row in stores], ["", ""])

    def test_xdata_findings_do_not_hide_unknown_hardware_classification(self):
        findings = memory_writes.read_memory_findings()
        self.assertEqual(findings[("XDATA", "0x7043")][1], "[guess]")
        self.assertEqual(
            memory_writes.classification("XDATA", "0x7043"),
            "xdata_ram_or_register_unknown",
        )

    def test_xdata_reads_include_unknown_and_conflicting_targets(self):
        instructions = [
            instruction(0x4000, "90 12 34", "MOV"),
            instruction(0x4003, "E0", "MOVX"),
            instruction(0x4004, "12 00 04", "LCALL"),
            instruction(0x4007, "E2", "MOVX"),
        ]
        _, reads = memory_writes.audit(instructions, set(), {0x4003: {0x5678}})
        self.assertEqual(reads[0]["resolution"], "conflicting_inferences")
        self.assertEqual(reads[0]["candidate_targets"], "0x1234,0x5678")
        self.assertEqual(reads[1]["target"], "?")
        self.assertEqual(reads[1]["access"], "MOVX_R0")

    def test_function_boundaries_do_not_inherit_register_state(self):
        instructions = [
            memory_writes.Instruction(
                0x4000, bytes.fromhex("90 12 34"), "MOV", "0x4000"
            ),
            memory_writes.Instruction(0x4003, bytes.fromhex("F0"), "MOVX", "0x4003"),
        ]
        writes, _ = memory_writes.audit(instructions, set(), {})
        store = next(row for row in writes if row["space"] == "XDATA")
        self.assertEqual(store["resolution"], "unresolved")


if __name__ == "__main__":
    unittest.main()

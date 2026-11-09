"""Offline tests for the JMS539 version reader and updater write plan."""

from __future__ import annotations

import binascii
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import dev


def image_fixture(size: int = 0xC100) -> bytes:
    image = bytearray((index * 37 + 11) & 0xFF for index in range(size))
    image[0xBFF0:0xBFF8] = b"\x55\xaa\xaa\x555391"
    reversed_words = b"".join(
        image[offset : offset + 4][::-1] for offset in range(0, 0xBFFC, 4)
    )
    image[0xBFFE:0xC000] = binascii.crc_hqx(reversed_words, 0).to_bytes(2, "big")
    return bytes(image)


class VersionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.response = bytes.fromhex("f4e7152d05390000353339321f002806")

    def test_version_reader_sends_only_the_expected_read_cdb(self) -> None:
        with mock.patch.object(
            dev.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, self.response, b""),
        ) as run:
            result = dev.read_version("/dev/sg2")
        self.assertEqual(result["raw"], self.response.hex())
        self.assertEqual((result["vid"], result["pid"]), ("152d", "0539"))
        self.assertEqual(result["firmware"], "31.00.40.06")
        command = run.call_args.args[0]
        self.assertEqual(command[-7:], ["/dev/sg2", "e0", "f4", "e7", "00", "00", "00"])
        self.assertIn("--request=16", command)

    def test_rejects_empty_or_unexpected_responses(self) -> None:
        with self.assertRaisesRegex(ValueError, "expected 16"):
            dev.parse_version(b"")
        with self.assertRaisesRegex(ValueError, "signature"):
            dev.parse_version(b"\x00\x00" + self.response[2:])

    def test_surfaces_sg_raw_failure(self) -> None:
        failed = subprocess.CompletedProcess([], 5, b"", b"device not ready")
        with (
            mock.patch.object(dev.subprocess, "run", return_value=failed),
            self.assertRaisesRegex(RuntimeError, "exit 5: device not ready"),
        ):
            dev.read_version("/dev/sg2")

    def test_surfaces_version_read_timeout(self) -> None:
        timeout = subprocess.TimeoutExpired("sg_raw", 25)
        with (
            mock.patch.object(dev.subprocess, "run", side_effect=timeout),
            self.assertRaisesRegex(RuntimeError, "25-second"),
        ):
            dev.read_version("/dev/sg2")


class PayloadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.image = image_fixture()
        self.backup = image_fixture(0x10000)

    def test_crc_matches_independent_crc16_implementation(self) -> None:
        self.assertEqual(
            dev.checksum(self.image), int.from_bytes(self.image[0xBFFE:0xC000], "big")
        )

    def test_preservation_and_uncompared_zero_padding_match_updater(self) -> None:
        backup = bytearray(self.backup)
        backup[0xC000:0xD000] = b"\xa5" * 0x1000
        payload, compared = dev.prepare_payload(self.image, bytes(backup))
        self.assertEqual(compared, 0xC100)
        self.assertEqual(len(payload), 0xC200)
        self.assertEqual(payload[0xC000:0xC100], b"\xa5" * 0x100)
        self.assertEqual(payload[0xC100:0xC200], bytes(0x100))

    def test_rounding_preserves_only_the_256_byte_aligned_extent(self) -> None:
        image = image_fixture(0xC101)
        backup = bytearray(self.backup)
        backup[0xC000:0xD000] = b"\x5a" * 0x1000
        payload, compared = dev.prepare_payload(image, bytes(backup))
        self.assertEqual(compared, 0xC200)
        self.assertEqual(len(payload), 0xC200)
        self.assertEqual(payload[0xC000:0xC200], b"\x5a" * 0x200)

    def test_image_configuration_option_does_not_overlay_capture(self) -> None:
        payload, compared = dev.prepare_payload(self.image, None)
        self.assertEqual(payload[:compared], self.image)

    def test_rejects_invalid_image_and_capture(self) -> None:
        corrupted = bytearray(self.image)
        corrupted[10] ^= 1
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            dev.prepare_payload(bytes(corrupted), self.backup)
        with self.assertRaisesRegex(ValueError, "exactly 64 KiB or 128 KiB"):
            dev.prepare_payload(self.image, self.backup[:-1])
        with self.assertRaisesRegex(ValueError, "larger than"):
            dev.prepare_payload(self.backup + b"x", None)


class WritePlanTests(unittest.TestCase):
    def test_mode_two_matches_the_emulated_updater(self) -> None:
        expected = [
            (0x0000, 0x1000, 2, "df 02 00 10 00 00 00 00 00 00 00 fb"),
            (0x1000, 0x2000, 0, "df 00 00 20 00 00 00 00 00 10 00 fb"),
            (0x3000, 0x2000, 0, "df 00 00 20 00 00 00 00 00 30 00 fb"),
            (0x5000, 0x2000, 0, "df 00 00 20 00 00 00 00 00 50 00 fb"),
            (0x7000, 0x1000, 0, "df 00 00 10 00 00 00 00 00 70 00 fb"),
            (0x8000, 0x2000, 2, "df 02 00 20 00 00 00 00 00 80 00 fb"),
            (0xA000, 0x2000, 0, "df 00 00 20 00 00 00 00 00 a0 00 fb"),
            (0xC000, 0x0200, 0, "df 00 00 02 00 00 00 00 00 c0 00 fb"),
        ]
        actual = [
            (c.offset, c.length, c.flag, c.cdb().hex(" "))
            for c in dev.write_chunks(0xC200, 2)
        ]
        self.assertEqual(actual, expected)

    def test_retry_modes_and_region_limits(self) -> None:
        mode_one = dev.write_chunks(0xC200, 1)
        self.assertEqual([c.offset for c in mode_one], list(range(0, 0xD000, 0x1000)))
        self.assertTrue(all(c.flag == 1 for c in mode_one))
        self.assertEqual(mode_one[-1].length, 0x200)
        mode_three = dev.write_chunks(0xC200, 3)
        self.assertEqual([c.flag for c in mode_three], [3, 0, 0, 0, 0, 0, 0])
        for mode in (1, 2, 3):
            chunks = dev.write_chunks(0x10000, mode)
            self.assertEqual(chunks[-1].offset + chunks[-1].length, 0x10000)
        with self.assertRaises(ValueError):
            dev.write_chunks(0x10200, 2)

    def test_plan_warns_that_mode_three_may_erase_entire_flash(self) -> None:
        plan = dev.build_plan(image_fixture(), image_fixture(0x10000), 3)
        self.assertTrue(any("whole flash" in warning for warning in plan["warnings"]))
        self.assertEqual(plan["configuration_bytes_in_comparison"], 0x100)
        self.assertEqual(plan["zero_padding_bytes"], 0x100)


class CliTests(unittest.TestCase):
    def test_describe_is_json_and_does_not_claim_a_flash_command(self) -> None:
        result = subprocess.run(
            [sys.executable, "-B", str(ROOT / "scripts" / "dev.py"), "describe"],
            capture_output=True,
            text=True,
            check=True,
        )
        description = json.loads(result.stdout)
        self.assertEqual(description["project"], "awto-jms539")
        self.assertTrue(
            {"version", "plan", "test", "gate"} <= description["commands"].keys()
        )
        self.assertNotIn("flash", description["commands"])

    def test_version_cli_with_fake_sg_raw(self) -> None:
        scratch = ROOT / "tmp"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            fake = Path(directory) / "sg_raw"
            fake.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                'sys.stdout.buffer.write(bytes.fromhex("f4e7152d05390000353339321f002806"))\n',
                encoding="utf-8",
            )
            fake.chmod(0o755)
            env = dict(os.environ)
            env["PATH"] = f"{directory}{os.pathsep}{env.get('PATH', '')}"
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(ROOT / "scripts" / "dev.py"),
                    "version",
                    "/dev/sg2",
                ],
                capture_output=True,
                text=True,
                env=env,
                check=True,
            )
        self.assertEqual(
            result.stdout.splitlines(),
            [
                "raw:     f4e7152d05390000353339321f002806",
                "VID:PID: 152d:0539",
                "FW:      31.00.40.06",
            ],
        )


if __name__ == "__main__":
    unittest.main()

"""Offline tests for the JMS539 flasher using an emulated dock."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import dev
import jms539_flash as jf
from test_dev import configuration_fixture, image_fixture


class FakeDock:
    """64 KiB NOR flash that mirrors at 0x10000; flags 1/2 erase a 4/32 KiB
    unit before programming unless chip_erase_flag selects a whole-chip erase."""

    def __init__(self, flash: bytes, chip_erase_flag: int | None = None, stuck: bool = False,
                 busy_polls: int = 0, flash_type: int = 1, jedec: bytes = b"\x7f\x9d\x20\x7f") -> None:
        self.flash = bytearray(flash)
        self.chip_erase_flag = chip_erase_flag
        self.stuck = stuck
        self.busy_polls = busy_polls
        self.type = flash_type
        self.jedec = jedec
        self.commands: list[bytes] = []

    def data_in(self, cdb: bytes, length: int, timeout_ms: int, sentinel: int):
        self.commands.append(cdb)
        if cdb == jf.POLL_CDB:
            if self.busy_polls:
                self.busy_polls -= 1
                return b"\x01\x00", 0
            return b"\x00\x00", 0
        if cdb == jf.VERSION_CDB:
            return bytes.fromhex("f4e7152d0539000000000000") + bytes((31, 0, 40, 6)), 0
        if cdb == jf.FLASH_TYPE_CDB:
            return bytes((self.type, 0, 0, 0)), 0
        if cdb == jf.SPI_RESULT_CDB:
            return self.jedec, 0
        assert cdb[0] == 0xDF and cdb[11] == 0xFA and cdb[1] == 0x10
        offset = int.from_bytes(cdb[8:11], "big") % jf.FLASH_SIZE
        return bytes(self.flash[offset : offset + length]), length

    def data_out(self, cdb: bytes, data: bytes, timeout_ms: int) -> int:
        self.commands.append(cdb)
        assert cdb[0] == 0xDF and cdb[11] == 0xFB
        flag = cdb[1]
        assert flag != 3, "mode 3 must never be sent"
        offset = int.from_bytes(cdb[8:11], "big")
        assert int.from_bytes(cdb[3:5], "big") == len(data)
        if flag and flag == self.chip_erase_flag:
            self.flash[:] = b"\xff" * jf.FLASH_SIZE
        elif flag in (1, 2):
            unit = 0x1000 if flag == 1 else 0x8000
            start = offset - offset % unit
            self.flash[start : start + unit] = b"\xff" * unit
        if not self.stuck:
            for index, value in enumerate(data):
                self.flash[offset + index] &= value
        return len(data)

    def no_data(self, cdb: bytes, timeout_ms: int) -> None:
        self.commands.append(cdb)


def device_fixture() -> bytes:
    flash = bytearray(jf.FLASH_SIZE)
    flash[:0xC100] = configuration_fixture()
    return bytes(flash)


def candidate_fixture() -> bytes:
    image = bytearray(image_fixture())
    image[0xC000:0xC100] = b"\x11" * 0x100
    return bytes(image)


def flasher_for(dock: FakeDock) -> jf.Flasher:
    return jf.Flasher(dock, log=lambda _: None, sleep=lambda _: None)


class StagingTests(unittest.TestCase):
    def test_keeps_device_settings_and_tail_by_default(self) -> None:
        device = bytearray(device_fixture())
        device[0xF000] = 0x42
        payload = jf.stage_payload(candidate_fixture(), bytes(device), "device")
        self.assertEqual(payload[:0xC000], candidate_fixture()[:0xC000])
        self.assertEqual(payload[0xC000:], bytes(device[0xC000:]))

    def test_image_config_replaces_only_the_image_extent(self) -> None:
        payload = jf.stage_payload(candidate_fixture(), device_fixture(), "image")
        self.assertEqual(payload[0xC000:0xC100], b"\x11" * 0x100)
        self.assertEqual(payload[0xC100:], device_fixture()[0xC100:])

    def test_rejects_corrupt_image(self) -> None:
        image = bytearray(candidate_fixture())
        image[0x100] ^= 1
        with self.assertRaisesRegex(ValueError, "checksum"):
            jf.stage_payload(bytes(image), device_fixture(), "device")


class FlashTests(unittest.TestCase):
    def test_mode_two_sequence_polls_before_every_write_and_verifies(self) -> None:
        dock = FakeDock(device_fixture(), busy_polls=3)
        payload = jf.stage_payload(candidate_fixture(), device_fixture(), "device")
        result = jf.flash(flasher_for(dock), payload)
        self.assertTrue(result["verified"])
        self.assertEqual(len(result["attempts"]), 1)
        self.assertEqual(bytes(dock.flash), payload)
        writes = [c for c in dock.commands if c[11] == 0xFB]
        expected = [chunk.cdb() for chunk in dev.write_chunks(jf.FLASH_SIZE, 2)]
        self.assertEqual(writes, expected)
        for index, command in enumerate(dock.commands):
            if command[0] == 0xDF:
                self.assertEqual(dock.commands[index - 1], jf.POLL_CDB)

    def test_chip_erase_semantics_are_recovered_by_mode_one_retry(self) -> None:
        dock = FakeDock(device_fixture(), chip_erase_flag=2)
        payload = jf.stage_payload(candidate_fixture(), device_fixture(), "device")
        result = jf.flash(flasher_for(dock), payload)
        self.assertEqual([a["mode"] for a in result["attempts"]], [2, 1])
        self.assertGreater(result["attempts"][0]["mismatched_bytes"], 0)
        self.assertEqual(bytes(dock.flash), payload)

    def test_persistent_mismatch_raises_without_reset_or_mode_three(self) -> None:
        dock = FakeDock(device_fixture(), stuck=True)
        payload = jf.stage_payload(candidate_fixture(), device_fixture(), "device")
        with self.assertRaisesRegex(jf.VerifyError, "NOT reset"):
            jf.flash(flasher_for(dock), payload)
        self.assertNotIn(jf.RESET_CDB, dock.commands)

    def test_busy_timeout_aborts_before_any_write(self) -> None:
        dock = FakeDock(device_fixture(), busy_polls=10_000)
        with self.assertRaisesRegex(jf.DockError, "busy"):
            flasher_for(dock).write(bytes(jf.FLASH_SIZE), 2)
        self.assertFalse([c for c in dock.commands if c[0] == 0xDF])

    def test_refuses_mode_three(self) -> None:
        with self.assertRaises(ValueError):
            flasher_for(FakeDock(device_fixture())).write(bytes(jf.FLASH_SIZE), 3)


class IdentificationTests(unittest.TestCase):
    def test_type_one_still_reads_the_jedec_id_for_capacity(self) -> None:
        dock = FakeDock(device_fixture())
        self.assertEqual(flasher_for(dock).flash_type(),
                         {"flash_type": 1, "type_response": "01000000", "jedec": "7f9d207f"})
        self.assertIn(jf.SPI_JEDEC_CDB, dock.commands)

    def test_larger_type_one_parts_are_refused(self) -> None:
        for capacity in (0x21, 0x22):
            with self.assertRaisesRegex(jf.DockError, "64 KiB"):
                flasher_for(FakeDock(device_fixture(), jedec=bytes((0x7F, 0x9D, capacity, 0x7F)))).flash_type()

    def test_nonzero_type_response_tail_is_refused(self) -> None:
        class Tail(FakeDock):
            def data_in(self, cdb, length, timeout_ms, sentinel):
                if cdb == jf.FLASH_TYPE_CDB:
                    return bytes((1, 0, 0, 7)), 0
                return super().data_in(cdb, length, timeout_ms, sentinel)
        with self.assertRaisesRegex(jf.DockError, "unexpected flash type response"):
            flasher_for(Tail(device_fixture())).flash_type()

    def test_type_zero_falls_back_to_jedec_like_the_updater(self) -> None:
        dock = FakeDock(device_fixture(), flash_type=0)
        self.assertEqual(flasher_for(dock).flash_type()["jedec"], "7f9d207f")
        with self.assertRaisesRegex(jf.DockError, "not type 1"):
            flasher_for(FakeDock(device_fixture(), flash_type=0, jedec=b"\xc2\x20\x10\x00")).flash_type()

    def test_other_flash_types_are_refused(self) -> None:
        with self.assertRaisesRegex(jf.DockError, "not type 1"):
            flasher_for(FakeDock(device_fixture(), flash_type=5)).flash_type()


class CaptureTests(unittest.TestCase):
    def test_capture_requires_mirrored_valid_flash(self) -> None:
        self.assertEqual(jf.capture(flasher_for(FakeDock(device_fixture()))), device_fixture())

        class Unmirrored(FakeDock):
            def data_in(self, cdb, length, timeout_ms, sentinel):
                data, resid = super().data_in(cdb, length, timeout_ms, sentinel)
                if cdb[0] == 0xDF and cdb[8]:
                    data = b"\x00" * length
                return data, resid

        with self.assertRaisesRegex(jf.DockError, "mirror"):
            jf.capture(flasher_for(Unmirrored(device_fixture())))

    def test_reads_that_return_the_sentinel_are_rejected(self) -> None:
        class Silent(FakeDock):
            def data_in(self, cdb, length, timeout_ms, sentinel):
                data, resid = super().data_in(cdb, length, timeout_ms, sentinel)
                return (bytes([sentinel]) * length if cdb[0] == 0xDF else data), resid

        with self.assertRaisesRegex(jf.DockError, "differ"):
            jf.capture(flasher_for(Silent(device_fixture())))


class SysfsTests(unittest.TestCase):
    def build(self, root: Path, mounted: bool = False) -> None:
        usb = root / "sys/devices/usb2/2-6"
        scsi = usb / "2-6:1.0/host8/target8:0:0/8:0:0:0"
        scsi.mkdir(parents=True)
        for name, value in (("idVendor", "152d"), ("idProduct", "0539"), ("busnum", "2"), ("devnum", "7")):
            (usb / name).write_text(value + "\n")
        for parent, link, target in (
            ("sys/class/scsi_generic/sg2", "device", scsi),
            ("sys/bus/usb/devices", "2-6", usb),
            ("sys/class/block/sdc", "device", scsi),
        ):
            (root / parent).mkdir(parents=True, exist_ok=True)
            (root / parent / link).symlink_to(target)
        (root / "sys/class/block/sdc/dev").write_text("8:32\n")
        part = root / "sys/class/block/sdc/sdc1"
        part.mkdir()
        (part / "partition").write_text("1\n")
        (part / "dev").write_text("8:33\n")
        (root / "proc/self").mkdir(parents=True)
        mount = "36 1 8:33 / /mnt/x rw - ext4 /dev/sdc1 rw\n" if mounted else ""
        (root / "proc/self/mountinfo").write_text("1 0 0:1 / / rw - ext4 /dev/root rw\n" + mount)

    def test_finds_dock_and_refuses_mounted_partition(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.build(root)
            dock = jf.find_dock("/dev/sg2", root / "sys", root / "proc")
            self.assertEqual((dock.busnum, dock.devnum, dock.blocks), ("2", "7", ("sdc", "sdc1")))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.build(root, mounted=True)
            with self.assertRaisesRegex(jf.DockError, "sdc1 is mounted"):
                jf.find_dock("/dev/sg2", root / "sys", root / "proc")


if __name__ == "__main__":
    unittest.main()

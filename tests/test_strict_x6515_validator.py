#!/usr/bin/env python3
from __future__ import annotations

import gzip
import hashlib
import contextlib
import io
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import strict_x6515_validator as v  # noqa: E402
import validate_x6515_firmware as firmware_audit  # noqa: E402


def cpio_record(name: str, content: bytes, mode: int = 0o100755, crc: bool = False) -> bytes:
    name_bytes = name.encode() + b"\0"
    fields = [1, mode, 0, 0, 1, 0, len(content), 0, 0, 0, 0, len(name_bytes),
              (sum(content) & 0xFFFFFFFF) if crc else 0]
    magic = b"070702" if crc else b"070701"
    out = bytearray(magic + b"".join(f"{field:08x}".encode() for field in fields))
    out.extend(name_bytes)
    out.extend(b"\0" * ((-len(out)) % 4))
    out.extend(content)
    out.extend(b"\0" * ((-len(out)) % 4))
    return bytes(out)


def make_cpio(records: list[tuple[str, bytes, int]], crc: bool = False) -> bytes:
    out = b"".join(cpio_record(name, data, mode, crc) for name, data, mode in records)
    out += cpio_record("TRAILER!!!", b"", 0, crc)
    return out


def make_fdt_container() -> bytes:
    prefix = b"X" * 64
    structure = (
        struct.pack(">I", 1) + b"\0" * 4 +  # FDT_BEGIN_NODE, empty root name
        struct.pack(">III", 3, 4, 0) + b"\xd0\x0d\xfe\xed" +  # FDT_PROP value includes magic bytes
        struct.pack(">II", 2, 9)  # FDT_END_NODE, FDT_END
    )
    strings = b"compatible\0\0"
    header = struct.pack(">10I", 0xD00DFEED, 100, 56, 88, 40, 17, 16, 0, len(strings), len(structure))
    return prefix + header + (b"\0" * 16) + structure + strings


def make_boot_image(kernel: bytes = b"kernel-data", ramdisk: bytes | None = None,
                    dtb: bytes | None = None, file_padding: int = 0) -> bytes:
    if ramdisk is None:
        raw = make_cpio([("init", b"init", 0o100755)])
        ramdisk = gzip.compress(raw, mtime=0)
    if dtb is None:
        dtb = make_fdt_container()
    page = 2048
    header = bytearray(page)
    header[:8] = b"ANDROID!"
    struct.pack_into("<II", header, 8, len(kernel), 0x40080000)
    struct.pack_into("<II", header, 16, len(ramdisk), 0x51B00000)
    struct.pack_into("<II", header, 24, 0, 0)
    struct.pack_into("<I", header, 32, 0x47880000)
    struct.pack_into("<I", header, 36, page)
    struct.pack_into("<I", header, 40, 2)
    struct.pack_into("<I", header, 1632, 0)
    struct.pack_into("<Q", header, 1636, 0)
    struct.pack_into("<I", header, 1644, 1660)
    struct.pack_into("<I", header, 1648, len(dtb))
    struct.pack_into("<Q", header, 1652, 0x47880000)
    out = bytearray(header)
    out.extend(kernel)
    out.extend(b"\0" * ((-len(out)) % page))
    out.extend(ramdisk)
    out.extend(b"\0" * ((-len(out)) % page))
    out.extend(dtb)
    if file_padding:
        out.extend(b"\0" * file_padding)
    return bytes(out)


class BootHeaderTests(unittest.TestCase):
    def test_valid_v2_boot_image(self):
        parsed = v.parse_android_v2(make_boot_image())
        self.assertEqual(parsed.header_version, 2)
        self.assertEqual(parsed.page_size, 2048)
        self.assertEqual(parsed.kernel_addr, 0x40080000)
        self.assertEqual(parsed.ramdisk_addr, 0x51B00000)
        self.assertEqual(parsed.dtb_addr, 0x47880000)
        self.assertEqual(parsed.dtb_size, len(make_fdt_container()))

    def test_rejects_bad_magic(self):
        with self.assertRaisesRegex(v.ValidationError, "header"):
            v.parse_android_v2(b"NOTANDROID" + bytes(4096))

    def test_rejects_truncated_header(self):
        with self.assertRaisesRegex(v.ValidationError, "header"):
            v.parse_android_v2(b"ANDROID!" + bytes(100))

    def test_rejects_wrong_version(self):
        data = bytearray(make_boot_image())
        struct.pack_into("<I", data, 40, 1)
        with self.assertRaisesRegex(v.ValidationError, "version"):
            v.parse_android_v2(bytes(data))

    def test_rejects_bad_page_size(self):
        data = bytearray(make_boot_image())
        struct.pack_into("<I", data, 36, 4096)
        with self.assertRaisesRegex(v.ValidationError, "page size"):
            v.parse_android_v2(bytes(data))

    def test_rejects_header_size_larger_than_header_page(self):
        data = bytearray(make_boot_image())
        struct.pack_into("<I", data, 1644, 4096)
        with self.assertRaisesRegex(v.ValidationError, "header_size"):
            v.parse_android_v2(bytes(data))

    def test_rejects_noncanonical_v2_header_size(self):
        data = bytearray(make_boot_image())
        struct.pack_into("<I", data, 1644, 1664)
        with self.assertRaisesRegex(v.ValidationError, "canonical header_size"):
            v.parse_android_v2(bytes(data))

    def test_rejects_second_stage_component(self):
        data = bytearray(make_boot_image())
        struct.pack_into("<I", data, 24, 1)
        with self.assertRaisesRegex(v.ValidationError, "second-stage"):
            v.parse_android_v2(bytes(data))

    def test_rejects_nonzero_recovery_dtbo_with_zero_offset(self):
        data = bytearray(make_boot_image())
        struct.pack_into("<I", data, 1632, 1)
        struct.pack_into("<Q", data, 1636, 0)
        with self.assertRaisesRegex(v.ValidationError, "offset is zero"):
            v.parse_android_v2(bytes(data))

    def test_rejects_out_of_bounds_kernel(self):
        data = bytearray(make_boot_image())
        struct.pack_into("<I", data, 8, 10_000_000)
        with self.assertRaisesRegex(v.ValidationError, "exceeds image size"):
            v.parse_android_v2(bytes(data))

    def test_rejects_missing_dtb(self):
        data = bytearray(make_boot_image())
        struct.pack_into("<I", data, 1648, 0)
        with self.assertRaisesRegex(v.ValidationError, "DTB"):
            v.parse_android_v2(bytes(data))

    def test_rejects_recovery_dtbo_overlap(self):
        data = bytearray(make_boot_image())
        struct.pack_into("<I", data, 1632, 10)
        struct.pack_into("<Q", data, 1636, 2048)
        with self.assertRaisesRegex(v.ValidationError, "recovery_dtbo"):
            v.parse_android_v2(bytes(data))

    def test_rejects_image_over_partition_limit(self):
        data = bytearray(make_boot_image())
        data.extend(b"\0" * (v.BOOT_PARTITION_LIMIT - len(data) + 1))
        with self.assertRaisesRegex(v.ValidationError, "exceeds 32 MiB"):
            v.parse_android_v2(bytes(data))

    def test_accepts_partition_padding_under_limit(self):
        parsed = v.parse_android_v2(make_boot_image(file_padding=1024))
        self.assertGreater(parsed.file_size, parsed.dtb_offset + parsed.dtb_size)


class CpioAndDtbTests(unittest.TestCase):
    def test_accepts_newc_and_crc_archives(self):
        regular = make_cpio([("init", b"abc", 0o100755)])
        crc = make_cpio([("system/bin/adbd", b"def", 0o100755)], crc=True)
        entries = v.parse_newc(regular + crc)
        self.assertEqual(entries["init"].data, b"abc")
        self.assertEqual(entries["system/bin/adbd"].data, b"def")

    def test_rejects_path_traversal(self):
        data = make_cpio([("../escape", b"bad", 0o100644)])
        with self.assertRaisesRegex(v.ValidationError, "unsafe"):
            v.parse_newc(data)

    def test_rejects_absolute_path(self):
        data = make_cpio([("/escape", b"bad", 0o100644)])
        with self.assertRaisesRegex(v.ValidationError, "unsafe"):
            v.parse_newc(data)

    def test_rejects_truncated_cpio(self):
        with self.assertRaises(v.ValidationError):
            v.parse_newc(b"070701" + b"0" * 30)

    def test_rejects_conflicting_duplicate_paths(self):
        data = make_cpio([("init", b"one", 0o100755)]) + make_cpio([("init", b"two", 0o100755)])
        with self.assertRaisesRegex(v.ValidationError, "duplicate"):
            v.parse_newc(data)

    def test_rejects_bad_crc(self):
        data = bytearray(make_cpio([("init", b"abc", 0o100755)], crc=True))
        # The newc checksum field starts at byte 102 within the header.
        data[102:110] = b"00000000"
        with self.assertRaisesRegex(v.ValidationError, "CRC"):
            v.parse_newc(bytes(data))

    def test_rejects_nonzero_newc_check_field(self):
        data = bytearray(make_cpio([("init", b"abc", 0o100755)]))
        data[102:110] = b"00000001"
        with self.assertRaisesRegex(v.ValidationError, "check field must be zero"):
            v.parse_newc(bytes(data))

    def test_accepts_expected_fdt_container(self):
        v._validate_wrapped_fdt(make_fdt_container())

    def test_rejects_wrong_fdt_location(self):
        with self.assertRaisesRegex(v.ValidationError, "offset 64"):
            v._validate_wrapped_fdt(b"\xd0\x0d\xfe\xed" + bytes(64))

    def test_rejects_overlapping_fdt_blocks(self):
        data = bytearray(make_fdt_container())
        struct.pack_into(">I", data, 64 + 12, 84)
        with self.assertRaisesRegex(v.ValidationError, "overlaps"):
            v._validate_wrapped_fdt(bytes(data))

    def test_rejects_invalid_fdt_structure_token(self):
        data = bytearray(make_fdt_container())
        struct.pack_into(">I", data, 64 + 56 + 28, 3)
        with self.assertRaisesRegex(v.ValidationError, "FDT_PROP"):
            v._validate_wrapped_fdt(bytes(data))

    def test_rejects_gzip_bomb_over_limit(self):
        packed = gzip.compress(b"A" * (2 * 1024 * 1024), mtime=0)
        with self.assertRaisesRegex(v.ValidationError, "safety limit"):
            v.decompress_gzip_bounded(packed, 1024 * 1024)


class FullImageValidationTests(unittest.TestCase):
    def _candidate_image(self, include_mtk: bool = True) -> bytes:
        records = [
            ("init", b"recovery-init", 0o100755),
            ("init.recovery.mt6761.rc", (ROOT / "recovery/root/init.recovery.mt6761.rc").read_bytes(), 0o100644),
            ("system/etc/init/mtk-plpath-utils.rc", (ROOT / "recovery/root/mtk-plpath-utils.rc").read_bytes(), 0o100644),
            ("system/bin/adbd", b"adbd-test", 0o100755),
        ]
        if include_mtk:
            records.append(("system/bin/mtk_plpath_utils", b"mtk-path-test", 0o100755))
        ramdisk = gzip.compress(make_cpio(records), mtime=0)
        kernel = (ROOT / "prebuilt/kernel").read_bytes()
        dtb = (ROOT / "prebuilt/dtb.img").read_bytes()
        return make_boot_image(kernel=kernel, ramdisk=ramdisk, dtb=dtb)

    def test_valid_candidate_image_and_ramdisk_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "boot.img"
            image.write_bytes(self._candidate_image())
            passes, errors = v.validate_image(image, ROOT)
            self.assertEqual(errors, [], "image validation errors: " + " | ".join(errors))
            self.assertEqual(len(passes), 2)

    def test_candidate_missing_mtk_service_binary_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "boot.img"
            image.write_bytes(self._candidate_image(include_mtk=False))
            _, errors = v.validate_image(image, ROOT)
            self.assertTrue(any("system/bin/mtk_plpath_utils" in error for error in errors))


class LegacyFirmwareHeaderTests(unittest.TestCase):
    def test_rejects_64bit_recovery_dtbo_offset_without_truncating(self):
        data = bytearray(8192)
        data[:8] = b"ANDROID!"
        struct.pack_into("<II", data, 8, 1, 0x40080000)
        struct.pack_into("<II", data, 16, 1, 0x51B00000)
        struct.pack_into("<II", data, 24, 0, 0)
        struct.pack_into("<I", data, 32, 0x47880000)
        struct.pack_into("<I", data, 36, 2048)
        struct.pack_into("<I", data, 40, 2)
        struct.pack_into("<I", data, 1632, 1)
        struct.pack_into("<Q", data, 1636, 0x100001800)
        struct.pack_into("<I", data, 1644, 1660)
        struct.pack_into("<I", data, 1648, 0)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "boot.img"
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "recovery_dtbo"):
                firmware_audit.parse_boot_image(path)


class MakeAndFstabTests(unittest.TestCase):
    def test_make_continuation_and_operator_are_preserved(self):
        parsed = v.parse_make_assignments("A := one\nB += two \\\n three\n")
        self.assertEqual(parsed["A"][0][1], "one")
        self.assertEqual(parsed["B"][0][0], "+=")
        self.assertEqual(parsed["B"][0][1], "two three")

    def test_make_comment_in_quotes_is_preserved(self):
        parsed = v.parse_make_assignments('VALUE := "x#y" # actual comment\n')
        self.assertEqual(parsed["VALUE"][0][1], '"x#y"')

    def test_make_scalar_duplicate_fails(self):
        parsed = v.parse_make_assignments("A := one\nA := one\n")
        errors: list[str] = []
        v._scalar(parsed, "A", "one", errors)
        self.assertTrue(any("expected one assignment" in item for item in errors))

    def test_fstab_flags_are_parsed_and_duplicates_rejected(self):
        row = v.parse_fstab("/data f2fs /dev/block/by-name/userdata flags=display=data;formattable;quota\n")[0]
        self.assertIn("formattable", row["flags"])
        with self.assertRaisesRegex(v.ValidationError, "duplicate mount flags"):
            v.parse_fstab("/data f2fs userdata flags=quota;quota\n")

    def test_current_device_tree_source_checks(self):
        passes, errors, blockers = v.validate_tree(ROOT)
        self.assertEqual(errors, [], "source-tree hard failures: " + " | ".join(errors))
        self.assertTrue(passes)
        self.assertTrue(blockers, "known unverified release areas must be surfaced")

    def test_missing_product_makefile_fails_without_crashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "tree"
            tree.mkdir()
            for child in ROOT.iterdir():
                if child.name in {".git", "__pycache__"}:
                    continue
                (tree / child.name).symlink_to(child, target_is_directory=child.is_dir())
            (tree / "device.mk").unlink()
            _, errors, _ = v.validate_tree(tree)
            self.assertTrue(any("product makefiles cannot be read" in error for error in errors))

    def test_release_cli_missing_inputs_fails_closed(self):
        args = ["strict_x6515_validator.py", "--mode", "release", "--device-tree", str(ROOT)]
        with patch.object(sys, "argv", args), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(v.main(), 1)


class DeviceReportTests(unittest.TestCase):
    def _make_report(self, root: Path, image: Path, stock: Path) -> Path:
        evidence = {}
        for name in v.REQUIRED_DEVICE_TESTS:
            proof = root / (name + ".log")
            proof.write_text("PASS " + name + "\n")
            evidence[name] = {
                "status": "PASS",
                "evidence": [{"test_id": name, "path": proof.name,
                              "sha256": hashlib.sha256(proof.read_bytes()).hexdigest()}],
            }
        payload = {
            "schema_version": 1,
            "device": {"model": "Infinix X6515", "board": "mt6761",
                       "fingerprint": v.EXPECTED_STOCK_FINGERPRINT},
            "stock_firmware": {"boot_sha256": hashlib.sha256(stock.read_bytes()).hexdigest()},
            "image_sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
            "started_at": "2026-10-20T10:00:00Z",
            "completed_at": "2026-10-20T11:00:00+00:00",
            "tests": evidence,
        }
        (root / "boot.img").write_bytes(stock.read_bytes())
        report = root / "device-report.json"
        report.write_text(json.dumps(payload))
        return report

    def test_accepts_complete_report_with_hashed_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image, stock = root / "candidate.img", root / "stock.img"
            image.write_bytes(b"candidate")
            stock.write_bytes(b"stock")
            report = self._make_report(root, image, stock)
            self.assertEqual(v.validate_device_report(report, image, root), [])

    def test_rejects_feature_not_passed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image, stock = root / "candidate.img", root / "stock.img"
            image.write_bytes(b"candidate")
            stock.write_bytes(b"stock")
            report = self._make_report(root, image, stock)
            payload = json.loads(report.read_text())
            payload["tests"]["fbe_keymaster_tee"]["status"] = "BLOCKED"
            report.write_text(json.dumps(payload))
            errors = v.validate_device_report(report, image, root)
            self.assertTrue(any("fbe_keymaster_tee" in error for error in errors))

    def test_rejects_wrong_image_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image, stock = root / "candidate.img", root / "stock.img"
            image.write_bytes(b"candidate")
            stock.write_bytes(b"stock")
            report = self._make_report(root, image, stock)
            payload = json.loads(report.read_text())
            payload["image_sha256"] = "0" * 64
            report.write_text(json.dumps(payload))
            self.assertTrue(any("image_sha256" in error for error in v.validate_device_report(report, image, root)))

    def test_rejects_traversal_evidence_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image, stock = root / "candidate.img", root / "stock.img"
            image.write_bytes(b"candidate")
            stock.write_bytes(b"stock")
            report = self._make_report(root, image, stock)
            payload = json.loads(report.read_text())
            payload["tests"]["boot_and_recovery_startup"]["evidence"][0]["path"] = "../outside.log"
            report.write_text(json.dumps(payload))
            self.assertTrue(any("safe relative path" in error for error in v.validate_device_report(report, image, root)))

    def test_rejects_corrupted_evidence_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image, stock = root / "candidate.img", root / "stock.img"
            image.write_bytes(b"candidate")
            stock.write_bytes(b"stock")
            report = self._make_report(root, image, stock)
            payload = json.loads(report.read_text())
            payload["tests"]["usb_adb_mtp_otg"]["evidence"][0]["sha256"] = "f" * 64
            report.write_text(json.dumps(payload))
            self.assertTrue(any("SHA-256 mismatch" in error for error in v.validate_device_report(report, image, root)))

    def test_rejects_non_object_top_level_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = root / "report.json"
            report.write_text("[]")
            self.assertTrue(any("top-level value" in error for error in v.validate_device_report(report, root / "missing.img", root)))

    def test_rejects_wrong_nested_json_types_without_crashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image, stock = root / "candidate.img", root / "boot.img"
            image.write_bytes(b"candidate")
            stock.write_bytes(b"stock")
            report = root / "report.json"
            report.write_text(json.dumps({
                "schema_version": 1, "device": [], "stock_firmware": [],
                "image_sha256": "0" * 64, "tests": [],
                "started_at": "bad", "completed_at": "bad"
            }))
            errors = v.validate_device_report(report, image, root)
            self.assertTrue(any("device must be a JSON object" in error for error in errors))
            self.assertTrue(any("tests must be a JSON object" in error for error in errors))

    def test_rejects_reused_evidence_across_features(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image, stock = root / "candidate.img", root / "stock.img"
            image.write_bytes(b"candidate")
            stock.write_bytes(b"stock")
            report = self._make_report(root, image, stock)
            payload = json.loads(report.read_text())
            payload["tests"]["display_touch_brightness"]["evidence"] = payload["tests"]["boot_and_recovery_startup"]["evidence"]
            report.write_text(json.dumps(payload))
            errors = v.validate_device_report(report, image, root)
            self.assertTrue(any("reused by tests" in error for error in errors))

    def test_rejects_evidence_misattributed_to_another_feature(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image, stock = root / "candidate.img", root / "stock.img"
            image.write_bytes(b"candidate")
            stock.write_bytes(b"stock")
            report = self._make_report(root, image, stock)
            payload = json.loads(report.read_text())
            payload["tests"]["usb_adb_mtp_otg"]["evidence"][0]["test_id"] = "fbe_keymaster_tee"
            report.write_text(json.dumps(payload))
            errors = v.validate_device_report(report, image, root)
            self.assertTrue(any("test_id must equal" in error for error in errors))

    def test_rejects_completed_timestamp_before_started(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image, stock = root / "candidate.img", root / "stock.img"
            image.write_bytes(b"candidate")
            stock.write_bytes(b"stock")
            report = self._make_report(root, image, stock)
            payload = json.loads(report.read_text())
            payload["completed_at"] = "2026-10-20T09:00:00Z"
            report.write_text(json.dumps(payload))
            errors = v.validate_device_report(report, image, root)
            self.assertTrue(any("must not precede" in error for error in errors))


if __name__ == "__main__":
    unittest.main(verbosity=2)

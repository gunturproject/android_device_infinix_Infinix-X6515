#!/usr/bin/env python3
"""Strict, read-only X6515 OrangeFox candidate and release validation.

Candidate validation checks source configuration and built-image structure. Release
certification additionally requires intact stock firmware evidence and a hashed,
feature-complete report from the exact physical device. Passing static checks is
never represented as proof of hardware compatibility.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import posixpath
import re
import shlex
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

BOOT_PARTITION_LIMIT = 33_554_432
EXPECTED_LOADS = {
    "kernel_addr": 0x40080000,
    "ramdisk_addr": 0x51B00000,
    "tags_addr": 0x47880000,
    "dtb_addr": 0x47880000,
}
EXPECTED_STOCK_FINGERPRINT = (
    "Infinix/X6515-OP/Infinix-X6515:12/SP1A.210812.016/241204V944:user/release-keys"
)
EXPECTED_HASHES = {
    "prebuilt/kernel": "541bed276dd57d97ab249bc25e123b595f4c8d78a17ac2fa816802a7b565689e",
    "prebuilt/dtb.img": "be65cfd3bbe139701b6377ebaa5a71f960e710e911ab247c76b8df56db447b01",
}
EXPECTED_KERNEL_RAW_SIZE = 27_885_568
MAX_RAMDISK_RAW_SIZE = 256 * 1024 * 1024
REQUIRED_DEVICE_TESTS = (
    "boot_and_recovery_startup",
    "display_touch_brightness",
    "usb_adb_mtp_otg",
    "storage_and_dynamic_partitions",
    "fbe_keymaster_tee",
    "backup_restore_sideload",
    "slots_avb_and_reboot",
    "ui_performance_and_locales",
    "init_services_and_logs",
    "crash_free_stress",
)


class ValidationError(ValueError):
    """Raised when an input is structurally invalid or fails a hard check."""


@dataclass(frozen=True)
class CpioEntry:
    path: str
    mode: int
    data: bytes


@dataclass(frozen=True)
class BootImage:
    file_size: int
    page_size: int
    header_version: int
    header_size: int
    kernel_size: int
    kernel_addr: int
    tags_addr: int
    kernel_offset: int
    ramdisk_size: int
    ramdisk_addr: int
    ramdisk_offset: int
    second_size: int
    second_offset: int
    recovery_dtbo_size: int
    recovery_dtbo_offset: int
    dtb_size: int
    dtb_addr: int
    dtb_offset: int


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def align(value: int, page: int) -> int:
    return (value + page - 1) // page * page


def parse_android_v2(data: bytes) -> BootImage:
    """Parse Android boot header v2 and prove each declared component is in-bounds."""
    if len(data) < 1660 or data[:8] != b"ANDROID!":
        raise ValidationError("boot image lacks a complete Android v2 header")
    if len(data) > BOOT_PARTITION_LIMIT:
        raise ValidationError(f"image size {len(data)} exceeds 32 MiB boot partition")
    kernel_size, kernel_addr = struct.unpack_from("<II", data, 8)
    ramdisk_size, ramdisk_addr = struct.unpack_from("<II", data, 16)
    second_size = struct.unpack_from("<I", data, 24)[0]
    second_addr = struct.unpack_from("<I", data, 28)[0]
    tags_addr = struct.unpack_from("<I", data, 32)[0]
    page_size = struct.unpack_from("<I", data, 36)[0]
    header_version = struct.unpack_from("<I", data, 40)[0]
    recovery_dtbo_size = struct.unpack_from("<I", data, 1632)[0]
    recovery_dtbo_offset = struct.unpack_from("<Q", data, 1636)[0]
    header_size = struct.unpack_from("<I", data, 1644)[0]
    dtb_size = struct.unpack_from("<I", data, 1648)[0]
    dtb_addr = struct.unpack_from("<Q", data, 1652)[0]
    if page_size != 2048:
        raise ValidationError(f"unexpected page size {page_size}; X6515 requires 2048")
    if header_version != 2:
        raise ValidationError(f"unexpected boot header version {header_version}; X6515 requires v2")
    if header_size != 1660:
        raise ValidationError(f"X6515 header v2 requires canonical header_size 1660, got {header_size}")
    if second_size != 0 or second_addr != 0:
        raise ValidationError("X6515 recovery-as-boot contract does not allow a second-stage component")
    if not kernel_size or not ramdisk_size or not dtb_size:
        raise ValidationError("kernel, ramdisk, and DTB must all be non-empty")
    kernel_off = page_size
    ramdisk_off = align(kernel_off + kernel_size, page_size)
    second_off = align(ramdisk_off + ramdisk_size, page_size)
    second_end = second_off + second_size
    rec_off = 0
    if recovery_dtbo_size:
        if recovery_dtbo_offset == 0:
            raise ValidationError("recovery_dtbo_size is non-zero but recovery_dtbo_offset is zero")
        rec_off = recovery_dtbo_offset
        if rec_off % page_size or rec_off < align(second_end, page_size):
            raise ValidationError("recovery_dtbo offset is unaligned or overlaps preceding components")
        dtb_off = align(rec_off + recovery_dtbo_size, page_size)
    else:
        if recovery_dtbo_offset:
            raise ValidationError("recovery_dtbo_offset is non-zero while recovery_dtbo_size is zero")
        dtb_off = align(second_end, page_size)
    extents = [("kernel", kernel_off, kernel_size), ("ramdisk", ramdisk_off, ramdisk_size),
               ("second", second_off, second_size), ("recovery_dtbo", rec_off, recovery_dtbo_size),
               ("dtb", dtb_off, dtb_size)]
    occupied = sorted((start, start + size, name) for name, start, size in extents if size)
    previous_end = page_size
    previous_name = "header"
    for start, end, name in occupied:
        if start < previous_end:
            raise ValidationError(f"{name} overlaps {previous_name}")
        if end > len(data):
            raise ValidationError(f"{name} range [{start}, {end}) exceeds image size {len(data)}")
        previous_end, previous_name = end, name
    return BootImage(
        file_size=len(data), page_size=page_size, header_version=header_version,
        header_size=header_size, kernel_size=kernel_size, kernel_addr=kernel_addr,
        tags_addr=tags_addr, kernel_offset=kernel_off, ramdisk_size=ramdisk_size, ramdisk_addr=ramdisk_addr,
        ramdisk_offset=ramdisk_off, second_size=second_size, second_offset=second_off,
        recovery_dtbo_size=recovery_dtbo_size, recovery_dtbo_offset=rec_off,
        dtb_size=dtb_size, dtb_addr=dtb_addr, dtb_offset=dtb_off,
    )


def parse_newc(data: bytes, *, max_entries: int = 100_000) -> dict[str, CpioEntry]:
    """Parse concatenated newc/crc cpio archives with bounds and path checks."""
    pos = 0
    entries: dict[str, CpioEntry] = {}
    archive_count = 0
    entry_count = 0
    saw_trailer = False
    while pos < len(data):
        while pos < len(data) and data[pos] == 0:
            pos += 1
        if pos == len(data):
            break
        archive_count += 1
        if data[pos:pos + 6] not in (b"070701", b"070702"):
            raise ValidationError(f"unsupported cpio magic at offset {pos}")
        saw_trailer = False
        while True:
            if pos + 110 > len(data) or data[pos:pos + 6] not in (b"070701", b"070702"):
                raise ValidationError(f"truncated or malformed newc header at offset {pos}")
            magic = data[pos:pos + 6]
            try:
                fields = [int(data[pos + 6 + i * 8:pos + 14 + i * 8], 16) for i in range(13)]
            except ValueError as exc:
                raise ValidationError(f"non-hex newc header field at offset {pos}") from exc
            mode, file_size, name_size, expected_check = fields[1], fields[6], fields[11], fields[12]
            if name_size < 1 or name_size > 1024 * 1024:
                raise ValidationError(f"invalid cpio name length {name_size}")
            pos += 110
            name_end = pos + name_size
            if name_end > len(data):
                raise ValidationError("cpio filename exceeds ramdisk bounds")
            name_bytes = data[pos:name_end]
            if name_bytes[-1:] != b"\0" or b"\0" in name_bytes[:-1]:
                raise ValidationError("cpio filename is not a single NUL-terminated path")
            raw_name = name_bytes[:-1].decode("utf-8", "surrogateescape")
            pos = align(name_end, 4)
            content_end = pos + file_size
            if content_end > len(data):
                raise ValidationError(f"cpio payload for {raw_name!r} exceeds ramdisk bounds")
            content = data[pos:content_end]
            pos = align(content_end, 4)
            entry_count += 1
            if entry_count > max_entries:
                raise ValidationError(f"cpio exceeds {max_entries} entries")
            if magic == b"070702" and (sum(content) & 0xFFFFFFFF) != expected_check:
                raise ValidationError(f"cpio CRC mismatch for {raw_name!r}")
            if magic == b"070701" and expected_check != 0:
                raise ValidationError(f"070701 cpio check field must be zero for {raw_name!r}")
            if raw_name == "TRAILER!!!":
                if file_size:
                    raise ValidationError("cpio TRAILER!!! must have an empty payload")
                saw_trailer = True
                break
            if raw_name.startswith("/") or any(part == ".." for part in raw_name.split("/")):
                raise ValidationError(f"unsafe absolute/traversal cpio path {raw_name!r}")
            clean = posixpath.normpath(raw_name)
            if clean in ("", "."):
                clean = "."
            if clean in entries:
                prior = entries[clean]
                if prior.mode != mode or prior.data != content:
                    raise ValidationError(f"conflicting duplicate cpio path {clean!r}")
            else:
                entries[clean] = CpioEntry(clean, mode, content)
        if not saw_trailer:
            raise ValidationError("cpio archive has no TRAILER!!!")
    if archive_count == 0:
        raise ValidationError("ramdisk contains no cpio archive")
    return entries


def decompress_gzip_bounded(data: bytes, limit: int = MAX_RAMDISK_RAW_SIZE) -> bytes:
    try:
        stream = gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb")
        chunks: list[bytes] = []
        size = 0
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            if size > limit:
                raise ValidationError(f"gzip payload expands beyond safety limit {limit}")
            chunks.append(block)
        return b"".join(chunks)
    except (OSError, EOFError) as exc:
        raise ValidationError(f"invalid or truncated gzip payload: {exc}") from exc


def parse_make_assignments(text: str) -> dict[str, list[tuple[str, str, int]]]:
    """Parse simple Make assignments while preserving operators and line numbers."""
    logical: list[tuple[int, str]] = []
    pending = ""
    start_line = 0
    for line_no, line in enumerate(text.splitlines(), 1):
        if not pending:
            start_line = line_no
        line = line.rstrip()
        if line.endswith("\\"):
            pending += line[:-1].rstrip() + " "
            continue
        logical.append((start_line, pending + line.lstrip()))
        pending = ""
    if pending:
        raise ValidationError("unterminated Make continuation at end of file")
    result: dict[str, list[tuple[str, str, int]]] = {}
    for line_no, line in logical:
        quoted = None
        cut = len(line)
        for i, ch in enumerate(line):
            if ch in ('"', "'"):
                quoted = None if quoted == ch else (ch if quoted is None else quoted)
            elif ch == "#" and quoted is None:
                cut = i
                break
        line = line[:cut].strip()
        match = re.match(r"^([A-Za-z0-9_]+)\s*(\+=|\?=|:=|=)\s*(.*?)\s*$", line)
        if match:
            key, op, value = match.groups()
            result.setdefault(key, []).append((op, value.strip(), line_no))
    return result


def _scalar(assignments: dict[str, list[tuple[str, str, int]]], key: str, expected: str,
            errors: list[str]) -> None:
    found = assignments.get(key, [])
    if len(found) != 1:
        errors.append(f"{key}: expected one assignment, found {len(found)}")
        return
    op, value, line = found[0]
    if op == "+=":
        errors.append(f"{key}: scalar uses += at line {line}")
    value = value.strip().strip('"').strip("'")
    if value != expected:
        errors.append(f"{key}: expected {expected!r}, got {value!r} (line {line})")


def parse_fstab(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split(None, 3)
        if len(fields) != 4:
            raise ValidationError(f"recovery.fstab line {line_no}: expected 4 fields")
        mount, fs_type, source, flag_field = fields
        if not flag_field.startswith("flags="):
            raise ValidationError(f"recovery.fstab line {line_no}: expected flags= field")
        flags = [value for value in flag_field[6:].split(";") if value]
        if len(flags) != len(set(flags)):
            raise ValidationError(f"recovery.fstab line {line_no}: duplicate mount flags")
        rows.append({"line": line_no, "mount": mount, "fs": fs_type, "source": source,
                     "flags": set(flags), "raw": line})
    return rows


def _check(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def validate_tree(tree: Path) -> tuple[list[str], list[str], list[str]]:
    """Return (passes, errors, release blockers) for source-only validation."""
    passes: list[str] = []
    errors: list[str] = []
    blockers: list[str] = []
    board_path = tree / "BoardConfig.mk"
    try:
        board_text = board_path.read_text(errors="strict")
        board = parse_make_assignments(board_text)
    except (OSError, UnicodeError, ValidationError) as exc:
        return passes, [f"cannot parse BoardConfig.mk: {exc}"], blockers

    expected = {
        "BOARD_BOOTIMG_HEADER_VERSION": "2",
        "BOARD_KERNEL_BASE": "0x40078000",
        "BOARD_KERNEL_OFFSET": "0x00008000",
        "BOARD_KERNEL_PAGESIZE": "2048",
        "BOARD_RAMDISK_OFFSET": "0x11a88000",
        "BOARD_KERNEL_TAGS_OFFSET": "0x07808000",
        "BOARD_DTB_OFFSET": "0x07808000",
        "BOARD_BOOTIMAGE_PARTITION_SIZE": str(BOOT_PARTITION_LIMIT),
        "BOARD_SUPER_PARTITION_SIZE": "6723633152",
        "BOARD_INFINIX_DYNAMIC_PARTITIONS_SIZE": "6719438848",
        "BOARD_USES_RECOVERY_AS_BOOT": "true",
        "TARGET_BOARD_PLATFORM": "mt6761",
        "TARGET_ARCH": "arm64",
        "TARGET_CPU_ABI": "arm64-v8a",
        "TARGET_SCREEN_DENSITY": "320",
        "TARGET_RECOVERY_PIXEL_FORMAT": "RGBX_8888",
        "BOARD_USERDATAIMAGE_FILE_SYSTEM_TYPE": "f2fs",
        "BOARD_AVB_ENABLE": "true",
        "TW_INCLUDE_CRYPTO": "true",
        "TW_INCLUDE_FBE_METADATA_DECRYPT": "true",
        "TW_THEME": "portrait_hdpi",
        "TW_BRIGHTNESS_PATH": "/sys/class/leds/lcd-backlight/brightness",
        "TW_MAX_BRIGHTNESS": "255",
        "TW_EXTRA_LANGUAGES": "false",
        "TARGET_FORCE_PREBUILT_KERNEL": "true",
    }
    for key, value in expected.items():
        _scalar(board, key, value, errors)
    if not errors:
        passes.append("BoardConfig scalar assignments are unique and match reviewed X6515 contract")

    mkboot_args = " ".join(value for _, value, _ in board.get("BOARD_MKBOOTIMG_ARGS", []))
    for flag, value in (
        ("--header_version", "$(BOARD_BOOTIMG_HEADER_VERSION)"),
        ("--kernel_offset", "$(BOARD_KERNEL_OFFSET)"),
        ("--ramdisk_offset", "$(BOARD_RAMDISK_OFFSET)"),
        ("--tags_offset", "$(BOARD_KERNEL_TAGS_OFFSET)"),
        ("--dtb_offset", "$(BOARD_DTB_OFFSET)"),
    ):
        count = len(re.findall(rf"(?<!\S){re.escape(flag)}\s+{re.escape(value)}(?=\s|$)", mkboot_args))
        _check(count == 1, f"BOARD_MKBOOTIMG_ARGS must pass {flag} {value} exactly once (found {count})", errors)
    if "$(TARGET_PREBUILT_DTB)" not in mkboot_args:
        errors.append("BOARD_MKBOOTIMG_ARGS does not pass the reviewed prebuilt DTB")

    for forbidden in ("BOARD_RECOVERYIMAGE_PARTITION_SIZE", "ALLOW_MISSING_DEPENDENCIES"):
        if forbidden in board:
            errors.append(f"forbidden weakening/conflicting BoardConfig setting: {forbidden}")
    ota = " ".join(value for _, value, _ in board.get("AB_OTA_PARTITIONS", []))
    ota_parts = set(re.findall(r"[A-Za-z0-9_]+", ota))
    expected_ota = {"vbmeta_vendor", "product", "boot", "vendor", "system", "system_ext", "vbmeta_system"}
    _check(ota_parts == expected_ota, f"AB_OTA_PARTITIONS differs from reviewed set: {sorted(ota_parts)}", errors)

    for rel, digest in EXPECTED_HASHES.items():
        path = tree / rel
        if not path.is_file():
            errors.append(f"required firmware-derived prebuilt is missing: {rel}")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        _check(actual == digest, f"{rel} SHA-256 mismatch: {actual}", errors)
        if rel.endswith("kernel"):
            try:
                raw = decompress_gzip_bounded(path.read_bytes(), 64 * 1024 * 1024)
                _check(len(raw) == EXPECTED_KERNEL_RAW_SIZE,
                       f"kernel expands to {len(raw)} bytes; expected {EXPECTED_KERNEL_RAW_SIZE}", errors)
            except ValidationError as exc:
                errors.append(f"prebuilt kernel gzip validation failed: {exc}")
        else:
            try:
                _validate_wrapped_fdt(path.read_bytes())
            except ValidationError as exc:
                errors.append(f"prebuilt DTB validation failed: {exc}")
    if not any(rel in e for e in errors for rel in EXPECTED_HASHES):
        passes.append("pinned kernel/DTB hashes, kernel gzip stream, and FDT container validate")

    fstab_path = tree / "recovery.fstab"
    try:
        rows = parse_fstab(fstab_path.read_text(errors="strict"))
    except (OSError, UnicodeError, ValidationError) as exc:
        rows = []
        errors.append(f"recovery.fstab invalid: {exc}")
    by_mount: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_mount.setdefault(row["mount"], []).append(row)
    for mount, copies in by_mount.items():
        if mount == "auto":
            _check(len(copies) == 2 and len({row["source"] for row in copies}) == 2,
                   "auto mount rows must be the two distinct external-device patterns", errors)
        else:
            _check(len(copies) == 1, f"duplicate fstab mountpoint {mount}", errors)
    required = {
        "/system": ("ext4", "system", {"logical", "slotselect"}),
        "/system_ext": ("ext4", "system_ext", {"logical", "slotselect"}),
        "/vendor": ("ext4", "vendor", {"logical", "slotselect"}),
        "/product": ("ext4", "product", {"logical", "slotselect"}),
        "/metadata": ("ext4", "/dev/block/by-name/md_udc", set()),
        "/data": ("f2fs", "/dev/block/by-name/userdata", {
            "formattable", "inlinecrypt", "quota", "fscompress",
            "fileencryption=aes-256-xts:aes-256-cts:v2",
            "keydirectory=/metadata/vold/metadata_encryption",
        }),
        "/boot": ("emmc", "/dev/block/by-name/boot", {"slotselect"}),
        "/vbmeta_vendor": ("emmc", "/dev/block/by-name/vbmeta_vendor", {"slotselect"}),
        "/vbmeta_system": ("emmc", "/dev/block/by-name/vbmeta_system", {"slotselect"}),
    }
    for mount, (fs_type, source, flags) in required.items():
        matches = by_mount.get(mount, [])
        _check(len(matches) == 1, f"required fstab mount {mount} missing/duplicated", errors)
        if len(matches) == 1:
            row = matches[0]
            _check(row["fs"] == fs_type, f"{mount} filesystem expected {fs_type}, got {row['fs']}", errors)
            _check(row["source"] == source, f"{mount} source expected {source}, got {row['source']}", errors)
            _check(flags.issubset(row["flags"]), f"{mount} missing flags {sorted(flags - row['flags'])}", errors)
    for row in rows:
        if "formattable" in row["flags"] and row["mount"] != "/data":
            errors.append(f"formattable is unsafe on non-userdata mount {row['mount']}")
    if "/recovery" in by_mount or "/recovery_a" in by_mount or "/recovery_b" in by_mount:
        errors.append("separate recovery partition is declared despite recovery-as-boot layout")
    if not errors:
        passes.append("fstab fields, critical block paths, F2FS/FBE flags, logical slots, and format scope validate")

    product_path = tree / "twrp_Infinix_X6515.mk"
    device_path = tree / "device.mk"
    products_path = tree / "AndroidProducts.mk"
    product_text = device_text = products_text = ""
    product: dict[str, list[tuple[str, str, int]]] = {}
    device: dict[str, list[tuple[str, str, int]]] = {}
    try:
        product_text = product_path.read_text(errors="strict")
        product = parse_make_assignments(product_text)
        device_text = device_path.read_text(errors="strict")
        device = parse_make_assignments(device_text)
        products_text = products_path.read_text(errors="strict")
    except (OSError, UnicodeError, ValidationError) as exc:
        product, device, products_text = {}, {}, ""
        errors.append(f"product makefiles cannot be read: {exc}")
    for key, value in {
        "PRODUCT_DEVICE": "Infinix-X6515", "PRODUCT_NAME": "twrp_Infinix_X6515",
        "PRODUCT_BRAND": "Infinix", "PRODUCT_MODEL": "Infinix X6515",
        "PRODUCT_MANUFACTURER": "INFINIX", "BUILD_FINGERPRINT": EXPECTED_STOCK_FINGERPRINT,
    }.items():
        _scalar(product, key, value, errors)
    _check("vendor/twrp/config/common.mk" in product_text, "product does not inherit common TWRP/OrangeFox config", errors)
    _check("$(LOCAL_DIR)/twrp_Infinix_X6515.mk" in products_text, "AndroidProducts.mk omits device product", errors)
    _check("COMMON_LUNCH_CHOICES := twrp_Infinix_X6515-eng" in products_text, "expected eng lunch target missing", errors)
    packages = " ".join(value for _, value, _ in device.get("PRODUCT_PACKAGES", []))
    for package in ("android.hardware.boot@1.0-impl.recovery", "bootctrl.mt6761.recovery", "update_engine_sideload"):
        _check(package in packages, f"required recovery package missing: {package}", errors)
    if not any("product" in e or "package" in e or "AndroidProducts" in e for e in errors):
        passes.append("product identity, stock fingerprint, lunch target, and recovery packages validate")

    root = tree / "recovery/root"
    init_rc = root / "init.recovery.mt6761.rc"
    mtk_rc = root / "mtk-plpath-utils.rc"
    if not init_rc.is_file() or not mtk_rc.is_file():
        errors.append("required MT6761 recovery init rc file is missing")
    else:
        init_text = init_rc.read_text(errors="strict")
        mtk_text = mtk_rc.read_text(errors="strict")
        for text, marker, label in (
            (init_text, "setprop sys.usb.configfs 1", "configfs USB setup"),
            (init_text, "/system/bin/mtk_plpath_utils", "MTK path utility execution"),
            (mtk_text, "service mtk.plpath.utils.link /system/bin/mtk_plpath_utils", "MTK path utility service"),
            (mtk_text, "oneshot", "oneshot service policy"),
            (mtk_text, "disabled", "disabled service policy"),
        ):
            _check(marker in text, f"init rc lacks {label}", errors)
        if not (tree / "proprietary-files.txt").is_file():
            blockers.append("proprietary-files.txt/blobs absent; MTK helper and Keymaster/TEE are not source-verified")
        if not any("init rc" in e for e in errors):
            passes.append("MT6761 init rc includes USB setup and the declared MTK path service")

    if "PRODUCT_STATIC_BOOT_CONTROL_HAL" in device_text:
        errors.append("obsolete PRODUCT_STATIC_BOOT_CONTROL_HAL is present")
    if not (tree / "proprietary-files.txt").is_file():
        if "proprietary-files.txt/blobs absent; MTK helper and Keymaster/TEE are not source-verified" not in blockers:
            blockers.append("proprietary-files.txt absent; vendor crypto/TEE integration is unverified")
    return passes, errors, blockers


def _validate_wrapped_fdt(data: bytes) -> None:
    magic = b"\xd0\x0d\xfe\xed"
    off = 64
    if len(data) < off + 40 or data[off:off + 4] != magic:
        raise ValidationError("expected an FDT header at wrapper offset 64")
    vals = struct.unpack_from(">10I", data, off)
    total, struct_off, strings_off, reserve_off, version, last_comp, _boot_cpu, strings_size, struct_size = vals[1:]
    if total < 40 or off + total != len(data):
        raise ValidationError(f"FDT totalsize {total} does not exactly fit wrapper ({len(data) - off} bytes)")
    if version < 16 or last_comp > version:
        raise ValidationError("FDT version compatibility fields are invalid")
    if struct_off < 40 or struct_off % 4 or struct_size < 4 or struct_off + struct_size > total:
        raise ValidationError("FDT structure block is outside totalsize")
    if strings_off < 40 or strings_off % 4 or strings_off + strings_size > total:
        raise ValidationError("FDT strings block is outside totalsize")
    if reserve_off < 40 or reserve_off % 8 or reserve_off + 16 > total:
        raise ValidationError("FDT reserve map is outside totalsize")
    cursor = off + reserve_off
    limit = off + total
    reserve_end = None
    while cursor + 16 <= limit:
        address, size = struct.unpack_from(">QQ", data, cursor)
        cursor += 16
        if address == 0 and size == 0:
            reserve_end = cursor - off
            break
        if address + size > 0xFFFFFFFFFFFFFFFF:
            raise ValidationError("FDT reserve-map address range overflows uint64")
    if reserve_end is None:
        raise ValidationError("FDT reserve map lacks a terminator")
    blocks = [(0, 40, "header"), (reserve_off, reserve_end, "reserve map"),
              (struct_off, struct_off + struct_size, "structure block")]
    if strings_size:
        blocks.append((strings_off, strings_off + strings_size, "strings block"))
    blocks.sort()
    for previous, current in zip(blocks, blocks[1:]):
        if current[0] < previous[1]:
            raise ValidationError(f"FDT {current[2]} overlaps {previous[2]}")

    struct_start = off + struct_off
    struct_end = struct_start + struct_size
    strings_start = off + strings_off
    strings_end = strings_start + strings_size
    cursor = struct_start
    depth = 0
    saw_root = False
    saw_end = False
    while cursor < struct_end:
        if cursor + 4 > struct_end:
            raise ValidationError("truncated FDT structure token")
        token = struct.unpack_from(">I", data, cursor)[0]
        cursor += 4
        if token == 1:  # FDT_BEGIN_NODE
            name_end = data.find(b"\0", cursor, struct_end)
            if name_end < 0:
                raise ValidationError("unterminated FDT node name")
            name = data[cursor:name_end]
            if depth == 0 and (saw_root or name != b""):
                raise ValidationError("FDT root node is missing, duplicated, or named")
            saw_root = True
            cursor = struct_start + align(name_end + 1 - struct_start, 4)
            depth += 1
        elif token == 2:  # FDT_END_NODE
            if depth == 0:
                raise ValidationError("unbalanced FDT_END_NODE")
            depth -= 1
        elif token == 3:  # FDT_PROP
            if depth == 0 or cursor + 8 > struct_end:
                raise ValidationError("FDT_PROP is outside a node or truncated")
            value_size, name_offset = struct.unpack_from(">II", data, cursor)
            cursor += 8
            value_end = cursor + value_size
            if value_end > struct_end:
                raise ValidationError("FDT property value exceeds structure block")
            if name_offset >= strings_size:
                raise ValidationError("FDT property name offset exceeds strings block")
            prop_name_start = strings_start + name_offset
            if data.find(b"\0", prop_name_start, strings_end) < 0:
                raise ValidationError("FDT property name is not NUL-terminated")
            cursor = struct_start + align(value_end - struct_start, 4)
        elif token == 4:  # FDT_NOP
            continue
        elif token == 9:  # FDT_END
            if not saw_root or depth != 0:
                raise ValidationError("FDT_END encountered before the root node closed")
            if cursor != struct_end:
                raise ValidationError("bytes remain after FDT_END in the structure block")
            saw_end = True
            break
        else:
            raise ValidationError(f"unknown FDT structure token {token:#x}")
    if not saw_end:
        raise ValidationError("FDT structure block lacks FDT_END")


def _entry_by_suffix(entries: dict[str, CpioEntry], suffix: str) -> list[CpioEntry]:
    return [entry for name, entry in entries.items() if name == suffix or name.endswith("/" + suffix)]


def validate_image(image_path: Path, tree: Path) -> tuple[list[str], list[str]]:
    passes: list[str] = []
    errors: list[str] = []
    try:
        image = image_path.read_bytes()
        boot = parse_android_v2(image)
    except (OSError, ValidationError, struct.error) as exc:
        return passes, [f"boot image structural validation failed: {exc}"]
    for key, expected in EXPECTED_LOADS.items():
        actual = getattr(boot, key)
        if actual != expected:
            errors.append(f"{key}={actual:#x}; expected {expected:#x}")
    components = {
        "prebuilt/kernel": image[boot.kernel_offset:boot.kernel_offset + boot.kernel_size],
        "prebuilt/dtb.img": image[boot.dtb_offset:boot.dtb_offset + boot.dtb_size],
    }
    for rel, component in components.items():
        prebuilt_path = tree / rel
        if not prebuilt_path.is_file():
            errors.append(f"missing reference component {rel}")
            continue
        try:
            expected = prebuilt_path.read_bytes()
        except OSError as exc:
            errors.append(f"cannot read reference component {rel}: {exc}")
            continue
        if component != expected:
            errors.append(f"built image {rel} differs byte-for-byte from reviewed stock-derived prebuilt")
    if not errors:
        passes.append("v2 header, 32 MiB ceiling, non-overlapping ranges, stock load addresses, kernel and DTB byte identity validate")

    ramdisk = image[boot.ramdisk_offset:boot.ramdisk_offset + boot.ramdisk_size]
    try:
        raw = decompress_gzip_bounded(ramdisk)
        entries = parse_newc(raw)
    except ValidationError as exc:
        return passes, errors + [f"ramdisk gzip/newc validation failed: {exc}"]
    expected_sources = {
        "init.recovery.mt6761.rc": tree / "recovery/root/init.recovery.mt6761.rc",
        "mtk-plpath-utils.rc": tree / "recovery/root/mtk-plpath-utils.rc",
    }
    for suffix, source_path in expected_sources.items():
        found = _entry_by_suffix(entries, suffix)
        if len(found) != 1:
            errors.append(f"ramdisk must contain exactly one {suffix}; found {len(found)}")
        elif source_path.is_file() and found[0].data != source_path.read_bytes():
            errors.append(f"ramdisk {suffix} differs from the reviewed source file")
    for path in ("init", "system/bin/adbd", "system/bin/mtk_plpath_utils"):
        entry = entries.get(path)
        if entry is None:
            errors.append(f"required executable missing from ramdisk: {path}")
        elif (entry.mode & 0o170000) != 0o100000 or not (entry.mode & 0o111):
            errors.append(f"ramdisk path is not an executable regular file: {path}")
    if not errors:
        passes.append(f"gzip/newc ramdisk validates ({len(entries)} entries); init, adbd and MTK service binary are present")
    return passes, errors


def validate_firmware(firmware_dir: Path, tree: Path) -> list[str]:
    errors: list[str] = []
    boot = firmware_dir / "boot.img"
    scatter = firmware_dir / "MT6761_Android_scatter.txt"
    if not boot.is_file() or not scatter.is_file():
        errors.append("strict firmware audit requires boot.img and MT6761_Android_scatter.txt")
        return errors
    avbtool = shutil.which("avbtool")
    avbtool_source = None
    if not avbtool and os.environ.get("ANDROID_BUILD_TOP"):
        candidate = Path(os.environ["ANDROID_BUILD_TOP"]) / "external/avb/avbtool.py"
        if candidate.is_file():
            avbtool_source = candidate
    avb_command = ([avbtool] if avbtool else
                   [sys.executable, str(avbtool_source)] if avbtool_source else None)
    if avb_command is None:
        errors.append("avbtool is required to verify AVB metadata; add it to PATH or set ANDROID_BUILD_TOP")
    for name in ("vbmeta.img", "vbmeta_system.img", "vbmeta_vendor.img"):
        path = firmware_dir / name
        if not path.is_file():
            errors.append(f"missing or invalid AVB image: {name}")
            continue
        try:
            if path.read_bytes()[:4] != b"AVB0":
                errors.append(f"missing or invalid AVB image: {name}")
            elif avb_command is not None:
                result = subprocess.run(avb_command + ["verify_image", "--image", str(path)],
                                        capture_output=True, text=True, timeout=120)
                if result.returncode != 0:
                    detail = (result.stdout + result.stderr).strip()[-500:]
                    errors.append(f"avbtool verify_image failed for {name}: {detail or f'exit {result.returncode}'}")
                else:
                    print(f"AVB image verified: {name}")
        except OSError as exc:
            errors.append(f"cannot read AVB image {name}: {exc}")
        except subprocess.TimeoutExpired:
            errors.append(f"avbtool timed out while verifying {name}")
    super_path = firmware_dir / "super.img"
    if not super_path.is_file():
        errors.append("intact super.img is required for strict logical-partition validation")
    elif not shutil.which("lpdump"):
        errors.append("lpdump is not installed; cannot validate dynamic-partition metadata")
    else:
        try:
            result = subprocess.run(["lpdump", str(super_path)], capture_output=True, text=True, timeout=120)
            if result.returncode != 0 or not result.stdout.strip():
                errors.append("lpdump could not parse super.img: " + (result.stderr.strip()[:300] or f"exit {result.returncode}"))
            else:
                out = result.stdout.lower()
                for token in ("metadata version:", "group name:", "partition name:"):
                    if token not in out:
                        errors.append(f"lpdump output lacks expected dynamic-partition marker {token!r}")
                partition_names = {name.lower() for name in re.findall(
                    r"^\s*Partition Name:\s*([A-Za-z0-9_]+)\s*$", result.stdout, re.IGNORECASE | re.MULTILINE
                )}
                for base in ("system", "system_ext", "vendor", "product"):
                    if not any(name == base or name.startswith(base + "_") for name in partition_names):
                        errors.append(f"lpdump has no logical partition for required fstab mount {base}")
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"lpdump execution failed: {exc}")
    manifest = tree / "proprietary-files.txt"
    try:
        has_manifest_entries = manifest.is_file() and any(
            line.strip() and not line.lstrip().startswith("#")
            for line in manifest.read_text(errors="strict").splitlines()
        )
    except (OSError, UnicodeError):
        has_manifest_entries = False
    if not has_manifest_entries:
        errors.append("non-empty proprietary-files.txt is required to package firmware-matched vendor/crypto dependencies")
    validator = tree / "tools/validate_x6515_firmware.py"
    if not validator.is_file():
        errors.append("tools/validate_x6515_firmware.py is required for strict release firmware auditing")
    else:
        try:
            result = subprocess.run([sys.executable, str(validator), "--firmware-dir", str(firmware_dir),
                                     "--device-tree", str(tree)], capture_output=True, text=True, timeout=180)
            if result.returncode != 0:
                errors.append("existing stock-firmware audit did not return clean (warnings are not release-pass): "
                              + (result.stdout + result.stderr)[-1200:].strip())
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"stock-firmware audit could not complete: {exc}")
    return errors


def validate_device_report(report_path: Path, image_path: Path, firmware_dir: Path) -> list[str]:
    errors: list[str] = []
    try:
        report = json.loads(report_path.read_text(errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [f"device test report cannot be read as JSON: {exc}"]
    if not isinstance(report, dict):
        return ["device test report top-level value must be a JSON object"]
    if report.get("schema_version") != 1:
        errors.append("device report schema_version must be 1")
    device = report.get("device", {})
    if not isinstance(device, dict):
        errors.append("device report device must be a JSON object")
        device = {}
    for key, expected in (("model", "Infinix X6515"), ("board", "mt6761"),
                          ("fingerprint", EXPECTED_STOCK_FINGERPRINT)):
        if device.get(key) != expected:
            errors.append(f"device.{key} must equal {expected!r}")
    try:
        actual_image_sha = hashlib.sha256(image_path.read_bytes()).hexdigest()
    except OSError as exc:
        actual_image_sha = None
        errors.append(f"candidate boot.img cannot be read: {exc}")
    if report.get("image_sha256") != actual_image_sha:
        errors.append("device report image_sha256 does not match the candidate boot.img")
    stock = report.get("stock_firmware", {})
    if not isinstance(stock, dict):
        errors.append("device report stock_firmware must be a JSON object")
        stock = {}
    stock_boot = firmware_dir / "boot.img"
    if not stock_boot.is_file():
        errors.append("stock firmware boot.img missing while checking report identity")
    else:
        try:
            stock_digest = hashlib.sha256(stock_boot.read_bytes()).hexdigest()
            if stock.get("boot_sha256") != stock_digest:
                errors.append("device report stock_firmware.boot_sha256 does not match supplied stock boot.img")
        except OSError as exc:
            errors.append(f"stock firmware boot.img cannot be read: {exc}")
    tests = report.get("tests", {})
    if not isinstance(tests, dict):
        errors.append("device report tests must be a JSON object")
        tests = {}
    base = report_path.parent.resolve()
    evidence_owners: dict[Path, str] = {}
    for name in REQUIRED_DEVICE_TESTS:
        item = tests.get(name)
        if not isinstance(item, dict) or item.get("status") != "PASS":
            errors.append(f"device feature test {name} is missing or not PASS")
            continue
        evidence = item.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            errors.append(f"device feature test {name} has no hashed evidence")
            continue
        for index, proof in enumerate(evidence):
            if not isinstance(proof, dict) or not isinstance(proof.get("path"), str):
                errors.append(f"{name} evidence[{index}] must contain a relative path and sha256")
                continue
            if proof.get("test_id") != name:
                errors.append(f"{name} evidence[{index}] test_id must equal {name!r}")
            rel = Path(proof["path"])
            if rel.is_absolute() or ".." in rel.parts:
                errors.append(f"{name} evidence[{index}] path is not a safe relative path")
                continue
            proof_path = (base / rel).resolve()
            try:
                proof_path.relative_to(base)
            except ValueError:
                errors.append(f"{name} evidence[{index}] escapes report directory")
                continue
            owner = evidence_owners.get(proof_path)
            if owner is not None:
                errors.append(f"evidence file {rel} is reused by tests {owner} and {name}")
            else:
                evidence_owners[proof_path] = name
            if not proof_path.is_file():
                errors.append(f"{name} evidence file missing: {rel}")
                continue
            try:
                digest = hashlib.sha256(proof_path.read_bytes()).hexdigest()
                if proof.get("sha256") != digest:
                    errors.append(f"{name} evidence SHA-256 mismatch: {rel}")
            except OSError as exc:
                errors.append(f"{name} evidence cannot be read {rel}: {exc}")
    timestamps: dict[str, datetime] = {}
    for key in ("started_at", "completed_at"):
        value = report.get(key)
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else None
            if parsed is None or parsed.tzinfo is None:
                raise ValueError("timezone required")
            timestamps[key] = parsed
        except ValueError:
            errors.append(f"device report {key} must be an ISO-8601 timestamp with timezone")
    if len(timestamps) == 2 and timestamps["completed_at"] < timestamps["started_at"]:
        errors.append("device report completed_at must not precede started_at")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("tree", "image", "release"), required=True)
    parser.add_argument("--device-tree", type=Path, required=True)
    parser.add_argument("--image", type=Path)
    parser.add_argument("--firmware-dir", type=Path)
    parser.add_argument("--device-report", type=Path)
    args = parser.parse_args()
    tree = args.device_tree.resolve()
    passes, errors, blockers = validate_tree(tree)
    if args.mode != "release":
        blockers.append("full firmware and physical-device evidence not supplied; candidate checks do not certify runtime features")
    if args.mode in ("image", "release"):
        if not args.image:
            errors.append(f"--image is required in {args.mode} mode")
        else:
            image_passes, image_errors = validate_image(args.image.resolve(), tree)
            passes.extend(image_passes)
            errors.extend(image_errors)
    if args.mode == "release":
        if not args.firmware_dir:
            errors.append("--firmware-dir is required for the release evidence gate")
        else:
            fw = args.firmware_dir.resolve()
            errors.extend(validate_firmware(fw, tree))
            if args.image and args.device_report:
                errors.extend(validate_device_report(args.device_report.resolve(), args.image.resolve(), fw))
            else:
                errors.append("--device-report and --image are required for the full release evidence gate")
    print(f"X6515 STRICT VALIDATION — mode={args.mode}")
    for item in passes:
        print("PASS: " + item)
    for item in blockers:
        print("BLOCKED: " + item)
    for item in errors:
        print("FAIL: " + item)
    if errors:
        print(f"\nRESULT: FAIL ({len(errors)} hard failure(s), {len(blockers)} release blocker(s))")
        return 1
    if args.mode == "release" and blockers:
        print(f"\nRESULT: RELEASE EVIDENCE INCOMPLETE ({len(blockers)} blocker(s))")
        return 1
    if args.mode == "release":
        print("\nRESULT: RELEASE EVIDENCE GATE PASS — static, firmware, and required report checks passed; manually review evidence provenance before any compatibility claim")
    else:
        print(f"\nRESULT: CANDIDATE CHECKS PASS; NOT DEVICE-CERTIFIED ({len(blockers)} release blocker(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())

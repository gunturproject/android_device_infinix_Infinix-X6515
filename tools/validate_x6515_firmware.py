#!/usr/bin/env python3
"""Read-only static audit of an X6515 stock firmware directory and device tree.

This tool never writes to a device or modifies firmware files. A successful
static audit is not proof of boot, touchscreen, USB, storage, encryption, or
AVB compatibility on physical hardware.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def align(value: int, page: int) -> int:
    return (value + page - 1) // page * page


def read_vars(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.is_file():
        return out
    for line in path.read_text(errors="replace").splitlines():
        match = re.match(r"^\s*([A-Z0-9_]+)\s*:?=\s*([^#]+?)\s*(?:#.*)?$", line)
        if match:
            out[match.group(1)] = match.group(2).strip().strip('"')
    return out


def parse_scatter(path: Path) -> dict[str, dict[str, str]]:
    text = path.read_text(errors="replace")
    result: dict[str, dict[str, str]] = {}
    for block in re.split(r"(?=\s*partition_index\s*:)", text):
        name = re.search(r"(?m)^\s*partition_name\s*:\s*(\S+)", block)
        if not name:
            continue
        values = {}
        for key in ("partition_size", "file_name", "is_download", "region", "linear_start_addr"):
            m = re.search(rf"(?m)^\s*{re.escape(key)}\s*:\s*(\S+)", block)
            if m:
                values[key] = m.group(1)
        result[name.group(1)] = values
    return result


def parse_boot_image(path: Path) -> dict[str, int | str]:
    data = path.read_bytes()
    if len(data) < 1660 or data[:8] != b"ANDROID!":
        raise ValueError("boot.img tidak memiliki magic Android atau header v2 lengkap")
    kernel_size, kernel_addr = struct.unpack_from("<II", data, 8)
    ramdisk_size, ramdisk_addr = struct.unpack_from("<II", data, 16)
    second_size, _second_addr = struct.unpack_from("<II", data, 24)
    tags_addr = struct.unpack_from("<I", data, 32)[0]
    page_size = struct.unpack_from("<I", data, 36)[0]
    header_version = struct.unpack_from("<I", data, 40)[0]
    recovery_dtbo_size = struct.unpack_from("<I", data, 1632)[0]
    recovery_dtbo_offset = struct.unpack_from("<Q", data, 1636)[0]
    header_size = struct.unpack_from("<I", data, 1644)[0]
    dtb_size = struct.unpack_from("<I", data, 1648)[0]
    dtb_addr = struct.unpack_from("<Q", data, 1652)[0]
    if page_size <= 0 or page_size > 65536 or page_size & (page_size - 1):
        raise ValueError(f"page size tidak valid: {page_size}")
    kernel_off = page_size
    ramdisk_off = align(kernel_off + kernel_size, page_size)
    second_off = align(ramdisk_off + ramdisk_size, page_size)
    if recovery_dtbo_size:
        recovery_off = recovery_dtbo_offset or align(second_off + second_size, page_size)
        if recovery_off < second_off or recovery_off + recovery_dtbo_size > len(data):
            raise ValueError("rentang recovery_dtbo di luar ukuran boot image")
        dtb_off = align(recovery_off + recovery_dtbo_size, page_size)
    else:
        recovery_off = 0
        dtb_off = align(second_off + second_size, page_size)
    extents = {
        "kernel": (kernel_off, kernel_size),
        "ramdisk": (ramdisk_off, ramdisk_size),
        "second": (second_off, second_size),
        "dtb": (dtb_off, dtb_size),
    }
    for label, (offset, size) in extents.items():
        if size and (offset < page_size or offset + size > len(data)):
            raise ValueError(f"{label} berada di luar ukuran boot image: offset={offset}, size={size}")
    return {
        "file_size": len(data), "page_size": page_size,
        "header_version": header_version, "header_size": header_size,
        "kernel_size": kernel_size, "kernel_addr": kernel_addr,
        "tags_addr": tags_addr,
        "kernel_offset": kernel_off, "ramdisk_size": ramdisk_size,
        "ramdisk_addr": ramdisk_addr, "ramdisk_offset": ramdisk_off,
        "second_size": second_size, "recovery_dtbo_size": recovery_dtbo_size,
        "recovery_dtbo_offset": recovery_off, "dtb_size": dtb_size,
        "dtb_addr": dtb_addr, "dtb_offset": dtb_off,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firmware-dir", required=True, type=Path,
                        help="Direktori image hasil ekstraksi firmware stok")
    parser.add_argument("--device-tree", required=True, type=Path,
                        help="Root repository device tree X6515")
    args = parser.parse_args()
    fw = args.firmware_dir.resolve()
    tree = args.device_tree.resolve()
    errors: list[str] = []
    warnings: list[str] = []
    facts: list[str] = []

    def require(condition: bool, message: str) -> None:
        (facts if condition else errors).append(("PASS: " if condition else "FAIL: ") + message)

    def warn(message: str) -> None:
        warnings.append("WARN: " + message)

    boot_path = fw / "boot.img"
    scatter_path = fw / "MT6761_Android_scatter.txt"
    if not boot_path.is_file() or not scatter_path.is_file():
        print("FAIL: butuh boot.img dan MT6761_Android_scatter.txt di firmware-dir")
        return 1
    try:
        boot = parse_boot_image(boot_path)
    except (OSError, ValueError, struct.error) as exc:
        print(f"FAIL: tidak dapat membaca header boot image: {exc}")
        return 1
    scatter = parse_scatter(scatter_path)
    board = read_vars(tree / "BoardConfig.mk")
    facts.append(f"INFO: boot.img {boot['file_size']} byte; header v{boot['header_version']}; page {boot['page_size']}")
    facts.append(f"INFO: kernel={boot['kernel_size']} byte at {boot['kernel_addr']:#x}; ramdisk={boot['ramdisk_size']} byte at {boot['ramdisk_addr']:#x}; dtb={boot['dtb_size']} byte at {boot['dtb_addr']:#x}")

    require(boot["header_version"] == 2, f"header version stok adalah v{boot['header_version']}, tree mengharapkan v2")
    require(boot["page_size"] == 2048, f"page size stok adalah {boot['page_size']}, tree mengharapkan 2048")
    require(boot["header_size"] >= 1660, f"header_size boot image v2 adalah {boot['header_size']}")
    require(len(boot_path.read_bytes()) == 33554432, "ukuran boot.img stok sama dengan partisi boot 32 MiB")

    kernel_path = tree / "prebuilt/kernel"
    dtb_path = tree / "prebuilt/dtb.img"
    data = boot_path.read_bytes()
    for label, path, offset_key, size_key in (
        ("kernel", kernel_path, "kernel_offset", "kernel_size"),
        ("DTB", dtb_path, "dtb_offset", "dtb_size"),
    ):
        if not path.is_file():
            require(False, f"prebuilt {label} tidak ada di tree")
            continue
        component = data[int(boot[offset_key]):int(boot[offset_key]) + int(boot[size_key])]
        prebuilt = path.read_bytes()
        require(sha256(component) == sha256(prebuilt),
                f"prebuilt {label} identik byte-per-byte dengan komponen boot.img stok (SHA-256 {sha256(prebuilt)})")

    base_s = board.get("BOARD_KERNEL_BASE", "")
    if base_s:
        base = int(base_s, 0)
        facts.append(f"INFO: BOARD_KERNEL_BASE={base:#x}; audit memeriksa base+offset terhadap alamat absolut header stok")
        for config_key, header_key, expected in (
            ("BOARD_KERNEL_OFFSET", "kernel_addr", int(boot["kernel_addr"]) - base),
            ("BOARD_RAMDISK_OFFSET", "ramdisk_addr", int(boot["ramdisk_addr"]) - base),
            ("BOARD_KERNEL_TAGS_OFFSET", "tags_addr", int(boot["tags_addr"]) - base),
            ("BOARD_DTB_OFFSET", "dtb_addr", int(boot["dtb_addr"]) - base),
        ):
            actual_s = board.get(config_key)
            if actual_s is None:
                require(False, f"{config_key} belum dideklarasikan; header stok memerlukan {expected:#x}")
            else:
                actual = int(actual_s, 0)
                require(actual == expected, f"{config_key}={actual:#x} cocok dengan header stok ({expected:#x})")
    else:
        require(False, "BOARD_KERNEL_BASE belum dideklarasikan")

    require(board.get("BOARD_BOOTIMG_HEADER_VERSION") == "2", "BoardConfig menetapkan boot header v2")
    require(board.get("BOARD_KERNEL_PAGESIZE") == "2048", "BoardConfig menetapkan page size 2048")
    require(board.get("BOARD_BOOTIMAGE_PARTITION_SIZE") == "33554432", "BoardConfig membatasi boot image ke 32 MiB")
    require(board.get("BOARD_USES_RECOVERY_AS_BOOT", "").lower() == "true", "tree menargetkan recovery-as-boot")
    require(board.get("TARGET_BOARD_PLATFORM") == "mt6761", "BoardConfig menargetkan SoC MT6761")
    board_text = (tree / "BoardConfig.mk").read_text(errors="replace")
    for argument, config_key in (
        ("--kernel_offset $(BOARD_KERNEL_OFFSET)", "BOARD_KERNEL_OFFSET"),
        ("--ramdisk_offset $(BOARD_RAMDISK_OFFSET)", "BOARD_RAMDISK_OFFSET"),
        ("--tags_offset $(BOARD_KERNEL_TAGS_OFFSET)", "BOARD_KERNEL_TAGS_OFFSET"),
        ("--dtb_offset $(BOARD_DTB_OFFSET)", "BOARD_DTB_OFFSET"),
    ):
        require(argument in board_text, f"mkbootimg menerima {config_key} secara eksplisit")

    for name in ("boot_a", "boot_b"):
        p = scatter.get(name)
        if not p:
            require(False, f"scatter tidak memiliki {name}")
            continue
        try:
            size = int(p["partition_size"], 0)
            require(size == int(boot["file_size"]), f"{name} berukuran {size} byte, sama dengan image {boot['file_size']} byte")
        except (KeyError, ValueError):
            require(False, f"ukuran {name} tidak dapat dibaca dari scatter")
    require("recovery" not in scatter and "recovery_a" not in scatter and "recovery_b" not in scatter,
            "scatter tidak mendeklarasikan partisi recovery terpisah")
    for name in ("vendor_boot_a", "vendor_boot_b"):
        p = scatter.get(name)
        if p:
            if p.get("file_name", "NONE").upper() == "NONE":
                warn(f"scatter menyediakan {name} tetapi firmware package tidak menyertakan image; jangan menganggap partisi kosong/terpakai tanpa dump perangkat")
            else:
                warn(f"scatter menyebut image {name}={p.get('file_name')}; validasi layout vendor_boot terpisah sebelum memilih target image")
    if "super" not in scatter:
        warn("scatter tidak mempunyai entri super; logical partition layout belum dapat dibuktikan")
    else:
        try:
            facts.append(f"INFO: kapasitas fisik super menurut scatter: {int(scatter['super']['partition_size'], 0)} byte")
        except (KeyError, ValueError):
            warn("ukuran super pada scatter tidak dapat diparse")

    avb_files = ("vbmeta.img", "vbmeta_system.img", "vbmeta_vendor.img")
    for name in avb_files:
        path = fw / name
        if path.is_file():
            require(path.read_bytes()[:4] == b"AVB0", f"{name} mempunyai magic AVB0")
        else:
            warn(f"{name} tidak ada pada firmware-dir; AVB chain tidak lengkap untuk audit ini")
    super_path = fw / "super.img"
    if not super_path.is_file():
        warn("super.img tidak tersedia di firmware-dir; kapasitas saja tidak membuktikan metadata/group/extents logical partitions")
    elif shutil.which("lpdump"):
        try:
            result = subprocess.run(["lpdump", str(super_path)], text=True, capture_output=True, timeout=60)
            if result.returncode == 0 and result.stdout.strip():
                facts.append("PASS: lpdump dapat membaca metadata super.img")
            else:
                errors.append("FAIL: lpdump gagal membaca metadata super.img: " + (result.stderr.strip()[:300] or f"exit {result.returncode}"))
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"FAIL: lpdump gagal dijalankan: {exc}")
    else:
        warn("lpdump tidak terpasang; metadata dynamic-partition super.img belum divalidasi")

    fstab_path = tree / "recovery.fstab"
    fstab = fstab_path.read_text(errors="replace") if fstab_path.is_file() else ""
    require(bool(re.search(r"(?m)^/data\s+f2fs\s+/dev/block/by-name/userdata\b", fstab)), "recovery.fstab memetakan /data ke userdata sebagai F2FS")
    require("fileencryption=aes-256-xts:aes-256-cts:v2" in fstab and "keydirectory=/metadata/vold/metadata_encryption" in fstab,
            "recovery.fstab memuat parameter file-based encryption stok")
    require(bool(re.search(r"(?m)^/metadata\s+ext4\s+/dev/block/by-name/md_udc\b", fstab)), "recovery.fstab memetakan /metadata ke md_udc")
    for mount in ("system", "system_ext", "vendor", "product"):
        require(bool(re.search(rf"(?m)^/{mount}\s+ext4\s+{mount}\s+flags=[^\n]*logical[^\n]*slotselect", fstab)), f"recovery.fstab mendefinisikan logical slotselect untuk /{mount}")
    if not (tree / "proprietary-files.txt").is_file():
        warn("proprietary-files.txt tidak ada; vendor/Keymaster/TEE tidak dapat diekstrak dari tree ini, sehingga dekripsi /data belum tervalidasi")
    installed_vendor = fw / "installed-files-vendor.txt"
    if installed_vendor.is_file() and re.search(r"keymaster|keystore|trustonic", installed_vendor.read_text(errors="replace"), re.I):
        warn("manifest stock menyebut komponen Keymaster/Keystore; cocokkan versi dan library/service vendor, jangan menetapkan versi hanya dari flag fstab")

    print("X6515 FIRMWARE STATIC AUDIT — READ ONLY")
    for line in facts + warnings + errors:
        print(line)
    print("\nKesimpulan: " + ("GAGAL — ada mismatch statis." if errors else "STATIC CHECKS LULUS; kompatibilitas perangkat belum dibuktikan."))
    if warnings:
        print(f"Peringatan: {len(warnings)}. Audit dynamic super, vendor blobs, Keymaster, dan runtime masih belum lengkap.")
    if errors:
        return 1
    return 2 if warnings else 0


if __name__ == "__main__":
    sys.exit(main())

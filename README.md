# OrangeFox 12.1 device tree — Infinix X6515 / H6127

This tree targets the Infinix X6515 stock firmware identified by the supplied `boot.img`: Android 12, build description `vnd_x6515_h6127-user 12 SP1A.210812.016 764070 release-keys`, fingerprint `Infinix/X6515-OP/Infinix-X6515:12/SP1A.210812.016/241204V944:user/release-keys`, incremental `241204V944`, security patch `2024-12-05`.

## Verified static alignment

The stock `boot.img` is a 32 MiB Android boot image with header v2 and 2048-byte pages. The device-tree kernel and DTB prebuilts match the corresponding byte ranges extracted from that image (SHA-256 checked by the builder). AOSP Android 12 `unpack_bootimg.py` reports the stock absolute load addresses as kernel `0x40080000`, ramdisk `0x51b00000`, tags `0x47880000`, and DTB `0x0000000047880000`. With the tree's configured base `0x40078000`, the corresponding offsets are kernel `0x00008000`, ramdisk `0x11a88000`, tags `0x07808000`, and DTB `0x07808000`. Tags and DTB are separate header fields even though their addresses match on this firmware. `dtb_addr` is 64-bit in header v2. `BOARD_MKBOOTIMG_ARGS` explicitly passes the kernel, ramdisk, tags, and DTB offsets; an AOSP Android 12 `mkbootimg.py` reconstruction with these values produced the same absolute load addresses as the stock header. CI checks those absolute addresses after the OrangeFox build. The header stores absolute addresses, so it does not by itself prove a unique `BOARD_KERNEL_BASE`/offset decomposition; the audit verifies that the configured base plus each offset reproduces the stock addresses. The board config must keep the boot-image limit at exactly 33,554,432 bytes.

Offset method: inspect a known-good stock boot image with AOSP `unpack_bootimg.py --format mkbootimg`; when the original base is unknown, AOSP prints `--base 0` and represents the absolute load addresses as offsets. Alternatively, retain a base from a known-good device-specific configuration and calculate each offset as `load_address - base`. Do not assume universal ramdisk, tags, or DTB offsets. The XDA discussion explains the base/offset relationship and shows why default assumptions fail when a device uses non-standard offsets. The decisive check is that a repacked image's absolute load addresses match stock, not that the offsets merely look familiar.

The scatter file allocates `boot_a` and `boot_b` at 32 MiB, a shared physical `super` partition at `0x190c28000` bytes, and A/B `dtbo`, `vbmeta`, and `vendor_boot` entries. The supplied package does not include `vendor_boot_a`/`vendor_boot_b` image payloads (`file_name: NONE`), so their runtime contents and purpose are not inferred here. This tree builds only the recovery-as-boot `boot.img`; it does not rebuild vendor_boot.

The stock recovery fstab uses F2FS for `/data`, `inlinecrypt`, `fileencryption=aes-256-xts:aes-256-cts:v2`, `/metadata/vold/metadata_encryption`, and `/dev/block/by-name/md_udc` for `/metadata`. The recovery fstab mirrors those key data/metadata mappings and declares the dynamic system partitions as logical and slot-selectable.

## Firmware audit before building

Run the read-only standard-library checker against a clean, fully extracted stock firmware directory:

```sh
python3 tools/validate_x6515_firmware.py \
  --firmware-dir /path/to/clean/X6515/firmware \
  --device-tree .
```

The checker compares the boot header, stock partition sizes, kernel/DTB bytes, board offsets (including the separate DTB offset), AVB image magic, and key fstab entries. It warns if `super.img`, vendor_boot payloads, or proprietary blobs are unavailable. Exit status 2 means static checks passed but warnings remain; it does **not** mean recovery was tested on a phone.

`BOARD_SUPER_PARTITION_SIZE` reflects the physical capacity reported by scatter only. Logical partition group sizes and extents must be verified with an intact `super.img` using `lpdump`; scatter capacity alone is not proof of `/system`, `/vendor`, `/product`, or `/data` behavior. `super_empty.img` is not a substitute for the production super image.

## Strict validation gates

Run `python3 -m unittest discover -s tests -v` for parser and regression tests. `python3 tools/strict_x6515_validator.py --mode tree --device-tree .` checks the reviewed source configuration; add `--mode image --image /path/to/boot.img` to inspect a built candidate's header, component ranges, pinned kernel/DTB, gzip/newc ramdisk, init files, and required executables. Candidate checks are not runtime certification.

The fail-closed release command, feature test matrix, safe evidence requirements, and report schema are in [`docs/STRICT-VALIDATION.md`](docs/STRICT-VALIDATION.md) and [`docs/device-test-report.schema.json`](docs/device-test-report.schema.json). Release mode additionally requires intact extracted firmware, `super.img`/`lpdump`, a non-empty audited proprietary manifest, and a fully passing hash-linked physical-device report. Missing evidence or a single non-PASS feature fails certification; no “100% compatible” claim is made from static checks alone.

## Proprietary components and encryption

This tree currently has no audited `proprietary-files.txt` and no packaged vendor/Keymaster/TEE blobs. `extract-files.sh` therefore fails early with an explanatory error rather than producing an apparently successful empty vendor tree. The fstab crypto flags and `TW_INCLUDE_CRYPTO`/`TW_INCLUDE_FBE_METADATA_DECRYPT` options are configuration only. FBE decryption is **not verified** until matching firmware blobs/services are supplied and tested on the exact XOS build. Do not claim encrypted `/data` support from a successful compile or matching fstab alone.

## Build and size policy

Use the OrangeFox `fox_12.1` manifest for this Android 12 target. The CI workflow enables `FOX_AB_DEVICE=1` from the A/B scatter layout, and `FOX_VANILLA_BUILD=1` plus `OF_DISABLE_MIUI_SPECIFIC_FEATURES=1` for this non-Xiaomi device. The standard build is the default. `FOX_DRASTIC_SIZE_REDUCTION=1` is experimental and removes many OrangeFox extras; the builder exposes it only as an explicit fallback if a standard image exceeds the fixed 32 MiB boot partition. Test every feature again when using that mode. Do not use LZMA ramdisk compression unless the exact stock kernel has been proven to support it; the checked stock kernel uses GZIP initramfs support.

The recovery theme is `portrait_hdpi`, screen density is 320, and extra languages are disabled to conserve image space. These are conservative build settings, not a guarantee of smooth UI; rendering, touch latency, brightness, and USB behavior require physical-device testing.

## Required device tests before any permanent flash

A successful compile and static audit prove neither bootability nor hardware compatibility. On the exact X6515/H6127 firmware, validate first boot, display/touch/brightness, USB/ADB/MTP/OTG, active-slot handling, boot and reboot paths, logical partition mounts, `/data` mount and format, encrypted-data decryption, backup/restore, sideload, and AVB/vbmeta behavior. Keep a tested stock restore path and verify the final image checksum and size. Do not flash an image permanently until those checks pass.

## References

- [Android boot image header specification](https://source.android.com/docs/core/architecture/bootloader/boot-image-header)
- [Android DTB image configuration](https://source.android.com/docs/core/architecture/bootloader/dtb-images)
- [AOSP Android 12 mkbootimg.py](https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/android12-release/mkbootimg.py), [unpack_bootimg.py](https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/android12-release/unpack_bootimg.py), and [AOSP Android 12 boot-image build rule](https://android.googlesource.com/platform/build/+/refs/heads/android12-release/core/Makefile)
- [XDA: Get Base Address from boot.img](https://xdaforums.com/t/how-to-get-base-address-from-boot-img.3036396/)
- [OrangeFox build guide](https://wiki.orangefox.tech/dev/building) and [build variables](https://wiki.orangefox.tech/dev/build_vars)

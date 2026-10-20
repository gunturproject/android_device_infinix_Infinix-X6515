# Android device tree for Infinix Infinix X6515 (Infinix-X6515)

```
#
# Copyright (C) 2026 The Android Open Source Project
# Copyright (C) 2026 SebaUbuntu's TWRP device tree generator
#
# SPDX-License-Identifier: Apache-2.0
#
```


## Recovery notes for stock XOS Android 12

This tree was audited against the uploaded X6515 stock `boot.img` ramdisk. The image reports fingerprint `Infinix/X6515-OP/Infinix-X6515:12/SP1A.210812.016/241204V944:user/release-keys` and its stock recovery fstab specifies F2FS for `/data`, `inlinecrypt`, `fileencryption=aes-256-xts:aes-256-cts:v2`, and `keydirectory=/metadata/vold/metadata_encryption`. The device-tree `/data` fstab entry and crypto build option are aligned to those values. This is configuration-level alignment only: it does not prove OrangeFox can decrypt this firmware. Verify decryption on the target device with the exact XOS build, and verify keymaster/vendor dependencies, formatting, backup/restore, and reboot paths before flashing.


The supplied `Download2.tar` scatter declares `super` size `0x190c28000` (6,723,633,152 bytes), while the original generated tree used 9,126,805,504 bytes. `BoardConfig.mk` now uses the stock SUPER capacity and a dynamic group 4 MiB smaller (preserving 4 MiB headroom, consistent with the original tree margin), rather than the oversized generated constants. The scatter shows A/B `boot`, `vendor_boot`, `dtbo`, and `vbmeta` families, plus a shared `super` and `userdata`. `vbmeta`, `vbmeta_system`, and `vbmeta_vendor` are AVB0 images with flags 0 and rollback index 2 in the supplied files. These values were inspected only; no bootloader, TEE, key, or verified-boot firmware images were modified or substituted.


The Android product/lunch identifier is `omni_Infinix_X6515` (underscore), while the device directory and `PRODUCT_DEVICE` remain `Infinix-X6515`. The hyphen in the former product target made Android 12.1 parse `X6515` as a build variant and reject it.

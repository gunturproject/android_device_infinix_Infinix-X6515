# Device tree OrangeFox 12.1 for Infinix X6515

## Firmware target

This tree is aligned to the user-supplied Infinix X6515 XOS stock boot image. The ramdisk reports model `Infinix X6515`, Android 12, fingerprint `Infinix/X6515-OP/Infinix-X6515:12/SP1A.210812.016/241204V944:user/release-keys`, build description `vnd_x6515_h6127-user 12 SP1A.210812.016 764070 release-keys`, build incremental `241204V944`, and security patch `2024-12-05`.

`prebuilt/kernel` and `prebuilt/dtb.img` are the kernel and DTB components extracted from that stock `boot.img`. The build workflow checks their SHA-256 values so a different prebuilt cannot silently replace them. Kernel base, page size, ramdisk offset, tags offset, and boot header version are set from the supplied stock boot image. The stock kernel advertises GZIP initramfs support; LZMA/LZ4 ramdisk compression is intentionally not enabled.

## Storage and partitions

The stock recovery fstab declares `/data` as F2FS with `inlinecrypt`, `fileencryption=aes-256-xts:aes-256-cts:v2`, and `keydirectory=/metadata/vold/metadata_encryption`. The recovery fstab retains those values and exposes `formattable` as in stock; BoardConfig also selects F2FS for userdata, and the build enables crypto plus FBE metadata-decrypt support. `/metadata` uses `/dev/block/by-name/md_udc`, matching the stock fstab. Scatter data places `boot_a` and `boot_b` at `0x2000000` bytes each, declares a shared `super` of `0x190c28000`, and confirms A/B boot, vendor_boot, dtbo, and vbmeta partitions. The recovery is built as recovery-as-boot in `boot.img`; the 32 MiB boot size is a hard limit and is not increased.

## Verification limits

This is configuration alignment, not proof that OrangeFox boots or can decrypt the exact XOS installation. The full firmware archive inventory includes `super.img` and a vendor manifest listing Trustonic Keymaster 4.1, but the actual vendor partition and its init/service dependencies are not yet extracted or packaged in this tree. Enabling FBE code and matching fstab alone does not provide the device-specific Keymaster/TEE services; runtime decryption remains unverified. Physical-device testing is still required for first boot, touch/display, USB/ADB/MTP, mount and format behavior, decryption, backup/restore, flashing, and reboot/slot handling. Do not flash an image unless it is verified to fit the stock boot partition and you have a tested stock restore path.

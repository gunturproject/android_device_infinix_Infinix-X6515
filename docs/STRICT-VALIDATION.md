# Validasi ketat OrangeFox untuk Infinix X6515

## Tujuan dan batas klaim

Suite ini memisahkan **validasi kandidat build** dari **sertifikasi release**. Tes statis tidak dapat membuktikan bahwa recovery benar-benar boot, layar sentuh berfungsi, `/data` terdekripsi, atau operasi flash aman. Karena itu, keluaran mode `tree`/`image` selalu menyatakan bahwa image **belum device-certified**. Mode `release` bersifat fail-closed: satu mismatch, firmware yang tidak lengkap, bukti fitur yang hilang, atau status selain `PASS` akan menghasilkan exit code nonzero.

Semua pemeriksaan di CI bersifat read-only terhadap perangkat; CI tidak melakukan flashing. Jangan menganggap artefak kandidat aman untuk diflash hanya karena kompilasi atau pemeriksaan statis lulus.

## Cakupan otomatis

`tools/strict_x6515_validator.py` memeriksa:

- Penetapan scalar BoardConfig yang kritis harus tunggal dan cocok dengan kontrak X6515 yang ditinjau: recovery-as-boot, boot header v2, page size, alamat load, batas partisi boot 32 MiB, platform MT6761, AVB, F2FS, UI/backlight, serta opsi recovery crypto. Argumen `mkbootimg` untuk kernel, ramdisk, tags, dan DTB harus diteruskan tepat satu kali.
- Hash kernel dan DTB prebuilt harus cocok dengan hash yang ditinjau; kernel harus lulus dekompresi gzip dan ukuran hasilnya cocok; DTB MediaTek harus memiliki wrapper/FDT valid.
- `recovery.fstab` harus dapat diparse penuh. Mount kritis, device path, filesystem, slot/logical flags, FBE/metadata flags, dan batas `formattable` diperiksa; duplikasi mountpoint tidak diabaikan (kecuali dua pola `auto` eksternal yang memang berbeda).
- Product identity/fingerprint, lunch target, paket boot-control/sideload, serta file init MT6761 dan deklarasi layanan MTK diperiksa.
- Boot image hasil build harus ber-header Android v2, berada di bawah 32 MiB, memiliki rentang kernel/ramdisk/DTB yang utuh dan tidak tumpang tindih, alamat load sama dengan header stok, serta kernel dan DTB identik byte-per-byte dengan prebuilt yang ditinjau.
- Ramdisk harus berupa gzip valid yang mengembang di bawah batas keselamatan 256 MiB, berisi cpio `newc`/`crc` valid, tanpa path traversal/duplikasi konflik, dan memuat `init`, `adbd`, init rc perangkat, serta binary MTK yang dipanggil oleh rc.
- Mode `release` mensyaratkan firmware stok utuh, semua image AVB, `super.img` yang dapat dibaca `lpdump`, manifest proprietary yang tidak kosong, audit firmware tanpa warning, serta laporan uji perangkat dengan SHA-256 image/firmware/bukti yang cocok.

Tes unit menggunakan fixture sintetis dan sengaja merusak header, rentang, checksum, path cpio, konfigurasi Make/fstab, status fitur, dan hash bukti untuk memastikan kesalahan ditolak.

## Menjalankan tes

Dari root repository device tree:

```bash
python3 -m unittest discover -s tests -v
python3 tools/strict_x6515_validator.py --mode tree --device-tree .
python3 tools/strict_x6515_validator.py --mode image --device-tree . --image /path/to/boot.img
```

Full release gate dijalankan hanya setelah firmware serta bukti fisik tersedia:

```bash
python3 tools/strict_x6515_validator.py \
  --mode release \
  --device-tree . \
  --image /path/to/candidate/boot.img \
  --firmware-dir /path/to/extracted-stock-firmware \
  --device-report /path/to/report/device-report.json
```

Direktori report harus berisi file bukti yang dirujuk dengan path relatif. SHA-256 setiap file diverifikasi. Jangan masukkan nomor seri/IMEI, data pengguna, kunci, atau informasi sensitif ke report/log; sanitasi bukti sebelum menyimpannya.

Mode release membutuhkan `lpdump` dan `avbtool` pada `PATH`; untuk sumber AOSP, `avbtool.py` juga dicari di `$ANDROID_BUILD_TOP/external/avb/avbtool.py`. Gate memeriksa metadata AVB dengan `avbtool verify_image` dan partisi logical menggunakan `lpdump`. Verifikasi AVB tersebut tidak menetapkan trust root vendor secara out-of-band; maintainer tetap harus membandingkan public key/fingerprint penandatangan dengan sumber firmware tepercaya. Demikian pula, output lpdump dan ukuran group/extent harus ditinjau terhadap firmware produksi sebelum menyimpulkan seluruh layout storage benar.

## Cakupan uji perangkat wajib

Setiap butir di bawah harus dikerjakan pada **Infinix X6515** dengan firmware yang fingerprint dan hash boot-nya sama dengan laporan. Tiap status harus `PASS` dan disertai satu atau lebih file bukti ber-hash. Jika belum bisa dikerjakan dengan aman, gunakan `BLOCKED`/`NOT_RUN`; jangan menebak hasil dari konfigurasi.

1. `boot_and_recovery_startup` — masuk recovery, startup tanpa panic/reboot loop, reboot ke system dan recovery.
2. `display_touch_brightness` — seluruh area sentuh, tombol, slider brightness minimum/tengah/maksimum, orientasi serta kestabilan UI.
3. `usb_adb_mtp_otg` — ADB dari host, transfer MTP, USB/OTG storage dan reconnect; catat `dmesg`/log yang relevan.
4. `storage_and_dynamic_partitions` — mount system, system_ext, vendor, product, metadata, userdata, media eksternal; validasi layout `super` dengan `lpdump`; uji baca/tulis hanya pada data uji.
5. `fbe_keymaster_tee` — dekripsi `/data` yang memang terenkripsi pada firmware sasaran, akses berkas uji setelah unlock, dan log Keymaster/TEE. Jangan format userdata untuk mengatasi kegagalan.
6. `backup_restore_sideload` — backup lalu restore data uji, ADB sideload paket uji non-destruktif, dan verifikasi hasil. Hindari partisi penting.
7. `slots_avb_and_reboot` — identifikasi slot aktif, reboot ke system/bootloader/recovery, cek log AVB; jangan menulis `vbmeta` atau mengganti slot secara spekulatif.
8. `ui_performance_and_locales` — kelancaran animasi/input, penggunaan memori, tema, bahasa dan kestabilan setelah beberapa siklus UI.
9. `init_services_and_logs` — periksa layanan init yang dipakai, USB/ADB, path block MTK, SELinux denials, `dmesg`/logcat dan tidak ada layanan yang gagal berulang.
10. `crash_free_stress` — beberapa siklus cold boot/reboot, mount/unmount dan operasi recovery aman; periksa panic, watchdog, hang, atau crash.

Uji format/flash yang destruktif hanya boleh dilakukan pada perangkat uji dengan backup dan jalur pemulihan yang sudah diverifikasi. Uji itu bukan prasyarat untuk menandai fitur lain sebagai lulus; bila tidak aman, catat `BLOCKED`.

## Laporan perangkat

Gunakan skema `device-test-report.schema.json`. Semua kategori wajib hadir. Setiap file bukti harus mencantumkan `test_id` yang sama dengan kategori, memakai path berbeda dari kategori lain, dan memiliki SHA-256 yang cocok. Status selain `PASS`, report untuk hash image yang berbeda, bukti yang hilang/berubah, path yang keluar dari folder report, atau waktu selesai sebelum waktu mulai akan menggagalkan gate. Bukti yang dapat dipakai antara lain log ADB yang disanitasi, output `lpdump`, foto/video layar uji tanpa data pribadi, serta hash artefak yang diuji.

Penting: SHA-256 hanya mengikat isi file yang diperiksa; ia **tidak membuktikan** bahwa file benar-benar direkam dari handset atau bahwa report tidak direkayasa. Hasil mode `release` adalah kelulusan pemeriksaan evidence yang diserahkan, bukan attestasi independen atau jaminan “100% kompatibel”. Maintainer harus meninjau asal bukti secara manual sebelum membuat klaim kompatibilitas atau memublikasikan image.

## Blocker tree saat ini

Tree yang ada belum membawa `proprietary-files.txt`/blob vendor yang membuktikan binary path MTK dan Keymaster/TEE. Firmware `super` serta hasil uji pada handset juga tidak disimpan di repository. Maka tree atau image kandidat dapat lulus pemeriksaan kandidat, tetapi tidak boleh dilabeli “100% kompatibel” sebelum blocker tersebut diselesaikan dan semua tes perangkat benar-benar lulus.

#!/usr/bin/env bash
#
# Copyright (C) 2016 The CyanogenMod Project
# Copyright (C) 2017-2020 The LineageOS Project
#
# SPDX-License-Identifier: Apache-2.0
#

set -eo pipefail

DEVICE=Infinix-X6515
VENDOR=infinix

MY_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ANDROID_ROOT="${MY_DIR}/../../.."
PROPRIETARY_FILES="${MY_DIR}/proprietary-files.txt"
HELPER="${ANDROID_ROOT}/tools/extract-utils/extract_utils.sh"

CLEAN_VENDOR=true
KANG=
SECTION=
SRC=

usage() {
    cat <<'EOF'
Usage: ./extract-files.sh [OPTIONS] [ADB_DEVICE_OR_FIRMWARE_DIR]

Options:
  -n, --no-cleanup       Keep the existing vendor directory.
  -k, --kang             Allow extracting from a device with locally changed blobs.
  -s, --section SECTION Extract only one named section.
  -h, --help             Show this help.

This device tree does not yet contain a verified proprietary-files.txt. Add a
blob list audited against the exact X6515 firmware before attempting extraction.
EOF
}

while (($#)); do
    case "$1" in
        -n|--no-cleanup)
            CLEAN_VENDOR=false
            ;;
        -k|--kang)
            KANG=--kang
            ;;
        -s|--section)
            if (($# < 2)) || [[ -z "$2" || "$2" == -* ]]; then
                echo "ERROR: $1 requires a section name." >&2
                exit 2
            fi
            SECTION="$2"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -* )
            echo "ERROR: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            if [[ -n "$SRC" ]]; then
                echo "ERROR: only one ADB device or firmware source may be specified." >&2
                exit 2
            fi
            SRC="$1"
            ;;
    esac
    shift
done

if [[ -z "$SRC" ]]; then
    SRC=adb
fi

if [[ ! -s "$PROPRIETARY_FILES" ]] || ! grep -Eq '^[[:space:]]*[^#[:space:]]' "$PROPRIETARY_FILES"; then
    echo "ERROR: $PROPRIETARY_FILES is missing or has no blob entries." >&2
    echo "This tree cannot claim vendor/Keymaster/TEE support or FBE decryption until a blob list is audited against the exact X6515 firmware." >&2
    exit 2
fi

if [[ ! -f "$HELPER" ]]; then
    echo "ERROR: extract-utils helper not found at $HELPER" >&2
    exit 1
fi

# Load extract_utils and initialize the vendor directory.
# shellcheck source=/dev/null
source "$HELPER"
setup_vendor "$DEVICE" "$VENDOR" "$ANDROID_ROOT" false "$CLEAN_VENDOR"
EXTRACT_ARGS=()
if [[ -n "$KANG" ]]; then
    EXTRACT_ARGS+=("$KANG")
fi
if [[ -n "$SECTION" ]]; then
    EXTRACT_ARGS+=(--section "$SECTION")
fi
extract "$PROPRIETARY_FILES" "$SRC" "${EXTRACT_ARGS[@]}"
"${MY_DIR}/setup-makefiles.sh"

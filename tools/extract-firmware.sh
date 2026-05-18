#!/usr/bin/env bash
# Recursive embedded-Linux firmware extractor.
# Usage: extract-firmware.sh INPUT_FILE OUTPUT_DIR
#
# Cracks open the firmware payload formats observed across Eaton's network /
# PDU / gateway lines so the OT NSRL baseline can hash individual filesystem
# files (binaries, libs, configs) instead of opaque firmware blobs:
#
#   tar      -> .tar archives (Eaton Network-M2/M3 ship as tar containing
#               rootfs.ubifs.xz + u-boot.img + upgrade scripts)
#   xz/gzip  -> rootfs compression
#   UBIFS    -> the Linux flash filesystem inside rootfs (Network-M2 family)
#   squashfs -> common embedded Linux rootfs (RAUC .raucb bundles are
#               squashfs containers used in Network-M3 family)
#   cpio     -> initramfs payloads
#   FAT      -> Eaton Network-M3 / Industrial-Gateway-M3 use a FAT16 .data_img
#               wrapper around the RAUC bundles. Extracted via 7-Zip.
#   FIT      -> u-boot Flat Image Tree, contains kernel + initramfs + DTB as
#               subimages. Extracted via dumpimage (u-boot-tools).
#
# Bounded to depth 6. Returns 0 on completion (even if input wasn't a
# recognized container) so the caller can blindly point it at every
# firmware artifact without special-casing.
#
# Invoked from PowerShell via:
#   wsl --user root -d Ubuntu -- bash /mnt/c/.../tools/extract-firmware.sh ARGS

set -u

INPUT="${1:-}"
OUTDIR="${2:-}"
MAX_DEPTH=${MAX_DEPTH:-6}

if [ -z "$INPUT" ] || [ -z "$OUTDIR" ]; then
    echo "Usage: $0 INPUT_FILE OUTPUT_DIR" >&2
    exit 2
fi

extract_one() {
    local input="$1"
    local outdir="$2"
    local depth="$3"

    [ "$depth" -ge "$MAX_DEPTH" ] && return 0
    [ ! -f "$input" ] && return 0

    local ft
    ft=$(file -b "$input" 2>/dev/null)

    local out=""
    case "$ft" in
        *"tar archive"*)
            out="$outdir/tar"
            mkdir -p "$out"
            tar -xf "$input" -C "$out" 2>/dev/null || { rm -rf "$out"; return 0; }
            ;;
        "XZ compressed"*)
            out="$outdir/xz"
            mkdir -p "$out"
            local base; base=$(basename "$input" .xz)
            if ! xz -dk -c "$input" > "$out/$base" 2>/dev/null; then
                rm -rf "$out"; return 0
            fi
            ;;
        "gzip compressed"*)
            out="$outdir/gz"
            mkdir -p "$out"
            local base; base=$(basename "$input" .gz)
            if ! gunzip -c "$input" > "$out/$base" 2>/dev/null; then
                rm -rf "$out"; return 0
            fi
            ;;
        "Squashfs filesystem"*)
            # mkdir parent first -- unsquashfs's -d won't create intermediates,
            # so it silently fails when $outdir is a yet-uncreated -d sibling
            # from a parent recursion (e.g. raucb inside FAT inside tar).
            mkdir -p "$outdir"
            out="$outdir/squashfs"
            rm -rf "$out"
            unsquashfs -no-progress -d "$out" "$input" >/dev/null 2>&1 || { rm -rf "$out"; return 0; }
            ;;
        "UBIfs image"*)
            out="$outdir/ubifs"
            mkdir -p "$outdir"
            # ubireader_extract_files writes to its current directory; cd in.
            local parent; parent="$outdir"; local name="ubifs"
            (cd "$parent" && ubireader_extract_files -k -o "$name" "$input") >/dev/null 2>&1 || { rm -rf "$out"; return 0; }
            ;;
        "ASCII cpio archive"*|*"cpio archive"*)
            out="$outdir/cpio"
            mkdir -p "$out"
            (cd "$out" && cpio -idu --quiet < "$input") 2>/dev/null || { rm -rf "$out"; return 0; }
            ;;
        *"DOS/MBR boot sector"*)
            # FAT12/16/32 volume. 7z handles all variants. Reports non-zero
            # exit on volumes without a real MBR (Eaton's .data_img has none)
            # but still extracts cleanly -- so we check post-hoc for content.
            out="$outdir/fat"
            mkdir -p "$out"
            7z x -y "-o$out" "$input" >/dev/null 2>&1 || true
            if [ -z "$(ls -A "$out" 2>/dev/null)" ]; then
                rm -rf "$out"; return 0
            fi
            ;;
        "Device Tree Blob"*)
            # FIT image (subimages: kernel/initramfs/dtb) vs plain DTB.
            # Probe with dumpimage on subimage 0 -- succeeds only on FIT.
            out="$outdir/fit"
            mkdir -p "$out"
            if ! dumpimage -T flat_dt -p 0 -o "$out/sub-0" "$input" >/dev/null 2>&1; then
                rm -rf "$out"; return 0
            fi
            local i=1
            while dumpimage -T flat_dt -p "$i" -o "$out/sub-$i" "$input" >/dev/null 2>&1; do
                i=$((i + 1))
            done
            ;;
        *)
            return 0
            ;;
    esac

    if [ -d "$out" ]; then
        find "$out" -type f 2>/dev/null | while IFS= read -r f; do
            extract_one "$f" "${f}-d" $((depth + 1))
        done
    fi
}

extract_one "$INPUT" "$OUTDIR" 0

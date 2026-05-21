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

# Make extracted output readable from PowerShell on /mnt/c. Squashfs / UBIFS
# / cpio preserve the original Linux ACLs (often 0600 or 0640 on /etc/clish/*
# style configs), which NTFS translates to "Access denied" for the
# Windows-side user that later runs 5b's file uploads. chmod a+rX = files
# readable, dirs readable+traversable.
make_readable() {
    chmod -R a+rX "$1" 2>/dev/null || true
}

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
            # unsquashfs returns non-zero when device nodes / fifos / sockets
            # can't be created on NTFS (/mnt/c) but still extracts every regular
            # file/dir/symlink. Check post-hoc for content rather than trusting
            # exit code, otherwise we'd throw away ~1900 real files to avoid a
            # ~700-node /dev tree we can't represent on Windows anyway.
            unsquashfs -no-progress -d "$out" "$input" >/dev/null 2>&1
            if [ -z "$(ls -A "$out" 2>/dev/null)" ]; then
                rm -rf "$out"; return 0
            fi
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
        *"Zip archive"*)
            # Proper ZIP handler (7z handles all variants). Without this,
            # ZIPs would fall into the binwalk-fallback case below and get
            # carved as slices, which then re-trigger binwalk on themselves
            # because each slice contains the same downstream signatures.
            out="$outdir/zip"
            mkdir -p "$out"
            7z x -y "-o$out" "$input" >/dev/null 2>&1 || true
            if [ -z "$(ls -A "$out" 2>/dev/null)" ]; then
                rm -rf "$out"; return 0
            fi
            ;;
        *"ext2 filesystem"*|*"ext3 filesystem"*|*"ext4 filesystem"*)
            # 7z handles ext2/3/4 read-only extraction natively (no kernel
            # mount, no fuseext2 dependency). Vertiv IntelliSlot Unity's
            # binwalk extraction yields a 96MB ext2 rootfs we'd otherwise
            # leave as an opaque blob; this handler pulls thousands of
            # files out of it.
            out="$outdir/ext"
            mkdir -p "$out"
            7z x -y "-o$out" "$input" >/dev/null 2>&1 || true
            if [ -z "$(ls -A "$out" 2>/dev/null)" ]; then
                rm -rf "$out"; return 0
            fi
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
            # Don't re-binwalk anything that came out of a previous binwalk
            # carve -- binwalk's ZIP/gzip extractor produces partial slices
            # that contain the rest of the original file, so re-scanning
            # them re-discovers the same downstream signatures and the
            # cascade explodes (PDU G3 went 1 -> 308 rows with only 8
            # unique hashes before this guard was added).
            case "$input" in
                */_*.extracted/*) return 0 ;;
            esac

            # USHA-format ESP32 firmware (Eaton BestLink Adapter / ConnectUPS /
            # ConnectUPS-Web-SNMP-Card). 'file' calls them "data", and
            # binwalk -e returns 0 carves because the embedded HTML/GIF
            # resources are stored inline (no compression container).
            # Hand off to the Python slicer that carves between binwalk's
            # signature offsets. The slicer is also called as a SECOND PASS
            # after binwalk -e below for inline HTML/SWF in firmware images
            # that DO yield container carves (APC NMC3 .bin).
            local slicer
            slicer="$(dirname "$(readlink -f "$0")")/slice-firmware-webui.py"
            local magic
            magic=$(head -c 4 "$input" 2>/dev/null)
            if [ "$magic" = "USHA" ]; then
                out="$outdir/usha-webui"
                mkdir -p "$out"
                if [ -f "$slicer" ]; then
                    python3 "$slicer" "$input" "$out" >/dev/null 2>&1 || true
                fi
                if [ -z "$(ls -A "$out" 2>/dev/null)" ]; then
                    rm -rf "$out"; return 0
                fi
                make_readable "$out"
                return 0  # don't recurse into carved web assets
            fi

            # Fallback: try binwalk's signature-based auto-extract for any
            # unrecognized format >=1MB. Picks up things like Eaton PDU G3
            # firmware (STM32 image with zipped SNMP MIBs + gzipped web-UI
            # assets embedded at fixed offsets) where no container handler
            # applies but signature-scanning finds extractable payloads.
            # Smaller files are skipped -- binwalk on tiny binaries tends
            # to produce false-positive carves with no real content.
            local sz
            sz=$(stat -c%s "$input" 2>/dev/null || echo 0)
            if [ "$sz" -lt 1048576 ]; then return 0; fi
            if ! command -v binwalk >/dev/null 2>&1; then return 0; fi
            local stage
            stage="$outdir/binwalk"
            mkdir -p "$stage"
            (cd "$stage" && binwalk -e --run-as=root --depth=2 "$input" >/dev/null 2>&1) || true
            local bwOut
            bwOut="$stage/_$(basename "$input").extracted"
            # Second pass: also carve inline HTML/GIF/PNG/JPEG/SWF that
            # binwalk -e identified by signature but had no extractor for.
            # APC NMC3 firmware shows this pattern -- binwalk extracts the
            # gzipped fonts but skips the inline HTML pages + Flash SWF + GIFs.
            if [ -f "$slicer" ]; then
                local sliceOut="$outdir/inline-webui"
                mkdir -p "$sliceOut"
                python3 "$slicer" "$input" "$sliceOut" >/dev/null 2>&1 || true
                if [ -z "$(ls -A "$sliceOut" 2>/dev/null)" ]; then
                    rm -rf "$sliceOut"
                else
                    make_readable "$sliceOut"
                fi
            fi
            if [ -d "$bwOut" ] && [ -n "$(ls -A "$bwOut" 2>/dev/null)" ]; then
                out="$bwOut"
            else
                rm -rf "$stage"
                return 0
            fi
            ;;
    esac

    if [ -d "$out" ]; then
        make_readable "$out"
        find "$out" -type f 2>/dev/null | while IFS= read -r f; do
            extract_one "$f" "${f}-d" $((depth + 1))
        done
    fi
}

extract_one "$INPUT" "$OUTDIR" 0

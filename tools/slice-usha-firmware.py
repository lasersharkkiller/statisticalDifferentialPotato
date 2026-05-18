#!/usr/bin/env python3
"""
Carve embedded web-UI files (HTML / GIF / PNG / JPEG) from Eaton USHA-format
firmware -- the ESP32-style images shipped on the BestLink Adapter,
ConnectUPS, ConnectUPS-Web-SNMP-Card, and X-Slot-Modbus network cards.

USHA firmware stores its embedded web UI inline (not in a compressed
container), so binwalk identifies the resource signatures but can't auto-
carve them with `binwalk -e`. This script:

  1. Verifies "USHA" magic at offset 0 of the input.
  2. Runs binwalk in signature-only mode to get every {HTML, GIF, PNG, JPEG}
     header / footer offset.
  3. For each resource header, slices from that offset to the next signature
     start and trims the result at the resource's natural end marker
     (</html>, GIF terminator 0x3B, PNG IEND, JPEG EOI).
  4. Looks for a likely filename near the start of the carve (printable
     ASCII string ending in .html/.htm/.gif/.png/.jpg/.css/.js). Falls back
     to a synthesized name like html-0001C00.html when none is found.
  5. Writes each carve to OUTPUT_DIR.

Invoked from tools/extract-firmware.sh's fallback path when the input
file's first 4 bytes are "USHA".

Usage:
  slice-usha-firmware.py INPUT_FILE OUTPUT_DIR
"""

import os
import re
import subprocess
import sys


# Filename pattern used to label carves: printable ASCII ending in a known
# web-asset extension. Tolerates path-style names but strips slashes.
FILENAME_RE = re.compile(
    rb'[A-Za-z0-9._/\\-]{3,40}\.(?:html?|css|js|gif|png|jpe?g|ico|txt)'
)

# Resource handlers: binwalk description prefix -> (extension, end-marker
# byte sequence). end-marker is searched from the end of the slice and
# everything past it is trimmed; None means use the next signature offset.
HANDLERS = [
    ('HTML document header', 'html', (b'</html>', b'</HTML>')),
    ('GIF image data',       'gif',  (b'\x3B',)),     # GIF terminator
    ('PNG image',            'png',  (b'IEND\xae\x42\x60\x82',)),
    ('JPEG image',           'jpg',  (b'\xFF\xD9',)),  # EOI
]


def parse_binwalk(path):
    """Returns list of (offset, description) tuples in ascending offset order."""
    try:
        out = subprocess.run(
            ['binwalk', '--run-as=root', path],
            capture_output=True, text=True, check=False,
        ).stdout
    except FileNotFoundError:
        print('binwalk not found in PATH', file=sys.stderr)
        return []
    sigs = []
    for line in out.splitlines():
        m = re.match(r'^\s*(\d+)\s+0x[0-9A-Fa-f]+\s+(.+)$', line)
        if m:
            sigs.append((int(m.group(1)), m.group(2).strip()))
    sigs.sort(key=lambda t: t[0])
    return sigs


def detect_filename(data, offset, search_radius=512):
    """Hunt for a plausible filename string within +/- search_radius of offset."""
    start = max(0, offset - search_radius)
    end = min(len(data), offset + search_radius)
    matches = FILENAME_RE.findall(data[start:end])
    if not matches:
        return None
    # Prefer matches BEFORE the data start (filename usually precedes content
    # in flat file tables); fall back to any match.
    for m in matches:
        s = m.decode('ascii', 'ignore')
        # Skip 'plain' artifacts like ".js" or extension-only matches
        if len(s) >= 5 and s[0] not in '.':
            return s.replace('\\', '_').replace('/', '_')
    return None


def safe_filename(name, used):
    """Sanitize and de-duplicate. Returns a name that's safe on NTFS."""
    name = re.sub(r'[<>:"|?*\x00-\x1f]', '_', name)
    name = name.strip('. ') or 'unnamed'
    if name not in used:
        return name
    # de-duplicate with numeric suffix preserving extension
    base, _, ext = name.rpartition('.')
    if not base:
        base, ext = name, ''
    n = 2
    while True:
        candidate = f'{base}_{n}.{ext}' if ext else f'{base}_{n}'
        if candidate not in used:
            return candidate
        n += 1


def carve(data, signatures, out_dir):
    """For each known resource signature, carve out the region into a file."""
    os.makedirs(out_dir, exist_ok=True)
    used_names = set()
    count = 0

    for i, (offset, desc) in enumerate(signatures):
        for sig_prefix, ext, end_markers in HANDLERS:
            if not desc.startswith(sig_prefix):
                continue
            # Slice from this signature to the next one (or EOF)
            next_offset = signatures[i + 1][0] if i + 1 < len(signatures) else len(data)
            region = data[offset:next_offset]
            # Trim at end marker if found
            best_end = len(region)
            for marker in end_markers:
                pos = region.rfind(marker)
                if pos >= 0:
                    best_end = min(best_end, pos + len(marker))
            carved = region[:best_end]
            if len(carved) < 16:
                # Too short to be meaningful
                break
            # Pick a name
            fname = detect_filename(data, offset)
            if not fname:
                fname = f'{ext}-{offset:08x}.{ext}'
            else:
                # If the detected filename doesn't already end with the right
                # extension, leave it as-is -- the firmware's own label wins.
                pass
            fname = safe_filename(fname, used_names)
            used_names.add(fname)
            with open(os.path.join(out_dir, fname), 'wb') as f:
                f.write(carved)
            count += 1
            break  # don't try other handlers for the same signature
    return count


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    input_path, out_dir = sys.argv[1], sys.argv[2]
    with open(input_path, 'rb') as f:
        data = f.read()
    if len(data) < 4 or data[:4] != b'USHA':
        # Not USHA-format: let the caller decide what to do
        sys.exit(1)
    sigs = parse_binwalk(input_path)
    if not sigs:
        sys.exit(1)
    count = carve(data, sigs, out_dir)
    print(f'Carved {count} files from {os.path.basename(input_path)}')
    sys.exit(0 if count > 0 else 1)


if __name__ == '__main__':
    main()

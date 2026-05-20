#!/usr/bin/env python3
"""
Carve embedded web-UI resources (HTML / GIF / PNG / JPEG / SWF) from any
firmware image where binwalk identifies the signatures but no standard
container handler applies.

Two production cases:

  * Eaton USHA (ESP32) -- BestLink Adapter, ConnectUPS, ConnectUPS-Web-
    SNMP-Card. Flat .bin with inline HTML pages and GIF icons; binwalk -e
    returns 0 carves because there is no compression container.

  * APC NMC3 -- the apc_hw21_su_*.bin AOS+APP image is Renesas RZ/N1 MCU
    code, not Linux, but ships the device's web UI inline. binwalk -e
    handles the gzipped fonts + the inner ZIPs, but skips HTML, GIF, and
    SWF chunks the same way.

Algorithm:

  1. Run binwalk in signature-only mode to get every {HTML, GIF, PNG,
     JPEG, SWF} header offset.
  2. For each header, slice from the offset to the next signature start
     (or EOF) and trim the result at the resource's natural end marker:
       - HTML: </html> / </HTML>
       - GIF:  0x3B terminator
       - PNG:  IEND + CRC32 (\xAE\x42\x60\x82)
       - JPEG: 0xFFD9 EOI marker
       - SWF:  no reliable end marker; cap at next signature
  3. Look for a likely filename string within +/-512 bytes of the carve
     header (printable ASCII ending in .html/.htm/.gif/.png/.jpg/...);
     fall back to a synthesized {ext}-{offset:08x}.{ext} name.
  4. Write each carve to OUTPUT_DIR, de-duplicating filenames.

Exit codes:
  0 = at least one resource carved
  1 = no resources found / binwalk missing / input too small

Invoked from tools/extract-firmware.sh both as the USHA fast-path (when
the first 4 bytes are "USHA") and as a post-binwalk fallback for any
firmware where binwalk -e produced output but inline web resources may
remain. The two callers are idempotent because the destination dir
gets the same content either way.

Usage:
  slice-firmware-webui.py INPUT_FILE OUTPUT_DIR
"""

import os
import re
import subprocess
import sys


# Filename pattern used to label carves: printable ASCII ending in a known
# web-asset extension. Tolerates path-style names but strips slashes.
FILENAME_RE = re.compile(
    rb'[A-Za-z0-9._/\\-]{3,40}\.(?:html?|css|js|gif|png|jpe?g|ico|swf|txt|xml|svg|woff|eot|ttf)'
)

# Resource handlers: binwalk description prefix -> (extension, end-marker
# byte sequence). end-marker is searched from the end of the slice and
# everything past it is trimmed; empty tuple means use the next signature
# offset as-is (no end-marker trim).
HANDLERS = [
    ('HTML document header',  'html', (b'</html>', b'</HTML>')),
    ('GIF image data',        'gif',  (b'\x3B',)),                # GIF terminator
    ('PNG image',             'png',  (b'IEND\xae\x42\x60\x82',)),
    ('JPEG image',            'jpg',  (b'\xFF\xD9',)),            # EOI
    ('Adobe Flash SWF',       'swf',  ()),                        # no reliable end marker
    ('Uncompressed Adobe',    'swf',  ()),                        # "Uncompressed Adobe Flash SWF file"
    ('PEM certificate',       'pem',  (b'-----END CERTIFICATE-----',
                                       b'-----END RSA PRIVATE KEY-----',
                                       b'-----END PRIVATE KEY-----',
                                       b'-----END PUBLIC KEY-----',
                                       b'-----END CERTIFICATE REQUEST-----',
                                       b'-----END DH PARAMETERS-----')),
    ('XML document',          'xml',  ()),                        # no fixed end marker; rely on next-sig boundary
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
        # Skip extension-only artifacts (e.g. ".js")
        if len(s) >= 5 and s[0] not in '.':
            return s.replace('\\', '_').replace('/', '_')
    return None


def safe_filename(name, used):
    """Sanitize and de-duplicate. Returns a name that's safe on NTFS."""
    name = re.sub(r'[<>:"|?*\x00-\x1f]', '_', name)
    name = name.strip('. ') or 'unnamed'
    if name not in used:
        return name
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
            next_offset = signatures[i + 1][0] if i + 1 < len(signatures) else len(data)
            region = data[offset:next_offset]
            best_end = len(region)
            for marker in end_markers:
                pos = region.rfind(marker)
                if pos >= 0:
                    best_end = min(best_end, pos + len(marker))
            carved = region[:best_end]
            if len(carved) < 16:
                break
            fname = detect_filename(data, offset)
            if not fname:
                fname = f'{ext}-{offset:08x}.{ext}'
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
    try:
        with open(input_path, 'rb') as f:
            data = f.read()
    except OSError as e:
        print(f'cannot read {input_path}: {e}', file=sys.stderr)
        sys.exit(1)
    if len(data) < 64:
        sys.exit(1)
    sigs = parse_binwalk(input_path)
    if not sigs:
        sys.exit(1)
    count = carve(data, sigs, out_dir)
    print(f'Carved {count} files from {os.path.basename(input_path)}')
    sys.exit(0 if count > 0 else 1)


if __name__ == '__main__':
    main()

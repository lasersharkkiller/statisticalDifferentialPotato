#!/usr/bin/env python3
"""
Re-categorize VT baseline JSON files: move ELF files out of unsignedWin -> unsignedLinux,
and PE files out of unsignedLinux -> unsignedWin. Covers both VirusTotal-main and
VirusTotal-behaviors roots. Checks ALL subfolders.
"""

import json
import os
import shutil

ROOTS = [
    r'D:\Loaded-Potato\output-baseline\VirusTotal-main',
    r'D:\Loaded-Potato\output-baseline\VirusTotal-behaviors',
]

ELF_TYPE_TAGS = {'elf', 'elf64', 'elf32', 'macho', 'macho64', 'macho32'}
PE_TYPE_TAGS  = {'peexe', 'pedll', 'pemsi', 'peexe64', 'pedll64', 'msi', 'nsis', 'pe'}


def is_elf(attrs: dict) -> bool:
    tt = (attrs.get('type_tag') or '').lower()
    if tt in ELF_TYPE_TAGS:
        return True
    if 'elf_info' in attrs:
        return True
    magic = (attrs.get('magic') or '').lower()
    if magic.startswith('elf '):
        return True
    tags = [t.lower() for t in (attrs.get('tags') or [])]
    if 'elf' in tags:
        return True
    return False


def is_pe(attrs: dict) -> bool:
    tt = (attrs.get('type_tag') or '').lower()
    if tt in PE_TYPE_TAGS:
        return True
    if 'pe_info' in attrs:
        return True
    magic = (attrs.get('magic') or '').lower()
    if magic.startswith('pe32') or 'ms windows' in magic or 'microsoft' in magic:
        return True
    tags = [t.lower() for t in (attrs.get('tags') or [])]
    if 'peexe' in tags or 'pedll' in tags:
        return True
    return False


def get_attrs(path: str) -> dict:
    with open(path, 'rb') as fh:
        raw = fh.read()
    try:
        data = json.loads(raw.decode('utf-8'))
    except UnicodeDecodeError:
        data = json.loads(raw.decode('latin-1'))
    # Handle double-encoded JSON (file content is a JSON string containing JSON)
    if isinstance(data, str):
        data = json.loads(data)
    if not isinstance(data, dict):
        return {}
    inner = data.get('data') or {}
    if isinstance(inner, list):
        inner = inner[0] if inner else {}
    return (inner or {}).get('attributes') or {}


def process_root(root: str):
    subfolders = [d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))]
    linux_dir = os.path.join(root, 'unsignedLinux')
    win_dir   = os.path.join(root, 'unsignedWin')

    moved_to_linux = 0
    moved_to_win   = 0
    errors         = 0
    skipped_other  = []  # ELF/PE mismatches in non-unsigned folders (report only)

    for subfolder in subfolders:
        src_dir = os.path.join(root, subfolder)
        # Skip placeholder/unnamed files: must be at least 32 chars before .json and contain non-zero chars
        files   = [f for f in os.listdir(src_dir)
                   if f.endswith('.json') and len(f) > 33 and f.replace('0','').replace('.json','') != '']
        print(f'  [{subfolder}] {len(files)} files ...')

        for fname in files:
            fpath = os.path.join(src_dir, fname)
            try:
                attrs = get_attrs(fpath)
            except Exception as e:
                print(f'    ERROR reading {fname}: {e}')
                errors += 1
                continue

            file_is_elf = is_elf(attrs)
            file_is_pe  = is_pe(attrs)

            if subfolder == 'unsignedWin' and file_is_elf:
                dst = os.path.join(linux_dir, fname)
                shutil.move(fpath, dst)
                moved_to_linux += 1

            elif subfolder == 'unsignedLinux' and file_is_pe:
                dst = os.path.join(win_dir, fname)
                shutil.move(fpath, dst)
                moved_to_win += 1

            elif subfolder not in ('unsignedWin', 'unsignedLinux'):
                # Just note unexpected ELF/PE placements in other folders
                if file_is_elf and subfolder in ('drivers', 'SignedVerified'):
                    skipped_other.append((subfolder, fname, 'ELF in Windows-only folder'))
                elif file_is_pe and subfolder == 'unsignedLinux':
                    pass  # already handled above

    return moved_to_linux, moved_to_win, errors, skipped_other


def main():
    total_to_linux = 0
    total_to_win   = 0
    total_errors   = 0

    for root in ROOTS:
        root_name = os.path.basename(root)
        print(f'\n=== {root_name} ===')
        tl, tw, te, other = process_root(root)
        total_to_linux += tl
        total_to_win   += tw
        total_errors   += te
        print(f'  -> Moved to unsignedLinux: {tl}')
        print(f'  -> Moved to unsignedWin:   {tw}')
        print(f'  -> Errors:                 {te}')
        if other:
            print(f'  -> Noteworthy (not moved): {len(other)}')
            for subfolder, fname, reason in other[:10]:
                print(f'       {subfolder}/{fname[:16]}... : {reason}')

    print(f'\n=== TOTALS ===')
    print(f'Moved to unsignedLinux : {total_to_linux}')
    print(f'Moved to unsignedWin   : {total_to_win}')
    print(f'Errors                 : {total_errors}')


if __name__ == '__main__':
    main()

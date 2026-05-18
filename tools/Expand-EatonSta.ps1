<#
.SYNOPSIS
Unpack an Eaton .sta firmware file into its constituent memory-segment
blocks and the vendor-provided manifest.json.

.DESCRIPTION
Eaton ships UPS firmware as a proprietary .sta container. Structure:

  Offset 0:  4-byte big-endian uint  manifest_compressed_size  (mcsize)
  Offset 4:  4-byte big-endian uint  manifest_uncompressed_size (musize)
  Offset 8:  zlib stream of mcsize bytes containing a Python-dict-style
             manifest listing each block's name, uncompressed size, and
             compressed size, e.g.
                ({'block-1.bin':{size:N,csize:M}, 'manifest.json':...})
  Offset 8 + mcsize:
             concatenated zlib streams, one per block, in manifest order

Newer Eaton .sta files are wrapped in a Windows PE self-extractor: the
zlib payload (same layout as above) is appended as an overlay after the
last PE section. This script auto-detects the MZ header, walks the PE
section table to find the end of the last section, and treats data from
that offset onward as the .sta payload.

Each block-N.bin is a flat memory segment that gets flashed at a specific
address on the UPS's microcontroller (the address ranges are listed in
manifest.json, which is itself one of the blocks). manifest.json also
contains vendor-attested SHA1 hashes for each block - useful as an
independent verification of the extraction.

For higher-level UPS or PLC firmware that ships filesystem images instead
of flat MCU memory, you would not use this tool - this is specifically for
Eaton .sta files.

.PARAMETER StaPath
Path to the .sta firmware file.

.PARAMETER OutputDir
Where to write the extracted blocks. Defaults to a 'sta-unpacked'
subfolder beside the .sta file.

.PARAMETER Force
Overwrite any existing files in OutputDir without prompting.

.PARAMETER Quiet
Suppress per-block progress output. Final summary still prints.

.EXAMPLE
.\tools\Expand-EatonSta.ps1 -StaPath 'C:\githubProjects\firmware-staging\Eaton\9PX 5-11K-UPS\extracted\eaton_9px_lvhv11_e0_v02.24.0048_tl00.sta'

.EXAMPLE
.\tools\Expand-EatonSta.ps1 `
    -StaPath 'firmware.sta' `
    -OutputDir 'C:\out' `
    -Force
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$StaPath,

    [string]$OutputDir,

    [switch]$Force,

    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $StaPath -PathType Leaf)) {
    Write-Error ".sta file not found: $StaPath"
    return
}

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path (Split-Path -Path $StaPath -Parent) 'sta-unpacked'
}
if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
} elseif ($Force) {
    Get-ChildItem -LiteralPath $OutputDir -Force | Remove-Item -Recurse -Force
}

$data = [System.IO.File]::ReadAllBytes($StaPath)
if ($data.Length -lt 16) {
    Write-Error ".sta file too small to contain valid header (got $($data.Length) bytes)"
    return
}

# 8-byte big-endian header: manifest_compressed_size, manifest_uncompressed_size
function Read-BEUInt32 {
    param([byte[]]$Bytes, [int]$Offset)
    return ([uint32]$Bytes[$Offset]       -shl 24) -bor
           ([uint32]$Bytes[$Offset + 1]   -shl 16) -bor
           ([uint32]$Bytes[$Offset + 2]   -shl 8 ) -bor
            [uint32]$Bytes[$Offset + 3]
}

# PE structure is little-endian; helpers used only for PE-wrapper detection.
function Read-LEUInt16 {
    param([byte[]]$Bytes, [int]$Offset)
    return ([uint16]$Bytes[$Offset + 1] -shl 8) -bor [uint16]$Bytes[$Offset]
}

function Read-LEUInt32 {
    param([byte[]]$Bytes, [int]$Offset)
    return ([uint32]$Bytes[$Offset + 3] -shl 24) -bor
           ([uint32]$Bytes[$Offset + 2] -shl 16) -bor
           ([uint32]$Bytes[$Offset + 1] -shl 8 ) -bor
            [uint32]$Bytes[$Offset]
}

# Detect a PE self-extractor wrapper and return the offset where the real
# .sta payload begins (i.e., end of the last PE section). Returns 0 when
# the file is a plain old/new-format .sta without a PE wrapper.
function Get-StaPayloadOffset {
    param([byte[]]$Bytes)
    if ($Bytes.Length -lt 64)                       { return 0 }
    if ($Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x5A)  { return 0 }   # not MZ
    $peOffset = [int](Read-LEUInt32 -Bytes $Bytes -Offset 60)       # e_lfanew
    if ($peOffset -lt 0 -or ($peOffset + 24) -gt $Bytes.Length)    { return 0 }
    if ($Bytes[$peOffset]     -ne 0x50 -or                          # 'P'
        $Bytes[$peOffset + 1] -ne 0x45 -or                          # 'E'
        $Bytes[$peOffset + 2] -ne 0x00 -or
        $Bytes[$peOffset + 3] -ne 0x00) { return 0 }
    # IMAGE_FILE_HEADER starts at $peOffset + 4
    $numberOfSections     = [int](Read-LEUInt16 -Bytes $Bytes -Offset ($peOffset + 6))
    $sizeOfOptionalHeader = [int](Read-LEUInt16 -Bytes $Bytes -Offset ($peOffset + 20))
    # Section headers (40 bytes each) sit just after IMAGE_OPTIONAL_HEADER
    $sectionHeadersStart = $peOffset + 24 + $sizeOfOptionalHeader
    $endOfSections = 0
    for ($i = 0; $i -lt $numberOfSections; $i++) {
        $sh = $sectionHeadersStart + ($i * 40)
        if (($sh + 40) -gt $Bytes.Length) { break }
        $sizeOfRawData    = [int](Read-LEUInt32 -Bytes $Bytes -Offset ($sh + 16))
        $pointerToRawData = [int](Read-LEUInt32 -Bytes $Bytes -Offset ($sh + 20))
        $sectionEnd = $pointerToRawData + $sizeOfRawData
        if ($sectionEnd -gt $endOfSections) { $endOfSections = $sectionEnd }
    }
    if ($endOfSections -le 0 -or $endOfSections -ge $Bytes.Length) { return 0 }
    return $endOfSections
}

$staStart = [int](Get-StaPayloadOffset -Bytes $data)

$mcsize = Read-BEUInt32 -Bytes $data -Offset $staStart
$musize = Read-BEUInt32 -Bytes $data -Offset ($staStart + 4)

if ($mcsize -le 0 -or $mcsize -gt ($data.Length - $staStart - 8)) {
    Write-Error ("Manifest size {0} is implausible for a {1}-byte .sta file (payload offset {2}) - header format may differ from expected" -f $mcsize, $data.Length, $staStart)
    return
}

if (-not $Quiet) {
    Write-Host "Source:    $StaPath"
    Write-Host "Output:    $OutputDir"
    Write-Host "Total size: $($data.Length) bytes"
    if ($staStart -gt 0) {
        Write-Host ("PE wrapper: .sta overlay at 0x{0:X} ({0} bytes of PE shell skipped)" -f $staStart)
    }
    Write-Host ("Manifest:  csize={0}, usize={1}" -f $mcsize, $musize)
}

# Decompress manifest (first zlib stream, exactly mcsize bytes after the 8-byte header)
$manifestText = $null
$ms  = [System.IO.MemoryStream]::new($data, ($staStart + 8), $mcsize)
$zls = [System.IO.Compression.ZLibStream]::new($ms, [System.IO.Compression.CompressionMode]::Decompress, $false)
$out = [System.IO.MemoryStream]::new()
try {
    $zls.CopyTo($out)
    $manifestText = [System.Text.Encoding]::ASCII.GetString($out.ToArray())
}
catch {
    Write-Error "Failed to decompress manifest: $($_.Exception.Message)"
    return
}
finally {
    $zls.Dispose(); $ms.Dispose(); $out.Dispose()
}

# Manifest can be in three observed shapes:
#   Old (Python-dict-ish, flat names): ({'block-1.bin':{size:N,csize:M}, ...})
#   New (JSON):                        {"block-1.bin":{"size":N,"csize":M}, ...}
#   PE-wrapper (path names + extras):  ({'./path/to/f.bin':{size:N,csize:M,time:T,module:"M"}, ...})
# Single regex handles all three: name and field names may be in single OR
# double quotes (or unquoted in the old shape), and entries may have extra
# trailing fields after csize -- terminated by '}' or ',' either works.
$blocks = New-Object System.Collections.Generic.List[object]
foreach ($m in [regex]::Matches($manifestText, '["'']([^"'']+)["'']\s*:\s*\{\s*["'']?size["'']?\s*:\s*(\d+)\s*,\s*["'']?csize["'']?\s*:\s*(\d+)\s*[\},]')) {
    $blocks.Add([pscustomobject]@{
        Name  = $m.Groups[1].Value
        Size  = [int64]$m.Groups[2].Value
        Csize = [int64]$m.Groups[3].Value
    })
}

if ($blocks.Count -eq 0) {
    Write-Error "No blocks parsed from manifest. Manifest text was: $manifestText"
    return
}

if (-not $Quiet) { Write-Host ("Parsed {0} blocks from manifest" -f $blocks.Count) }

# Walk and decompress each block in order
$cursor    = $staStart + 8 + $mcsize
$extracted = New-Object System.Collections.Generic.List[object]
$failed    = 0

foreach ($b in $blocks) {
    if (($cursor + $b.Csize) -gt $data.Length) {
        Write-Host ("  [FAIL] {0}: csize={1} extends past file end (cursor={2}, file={3})" -f $b.Name, $b.Csize, $cursor, $data.Length) -ForegroundColor Red
        $failed++
        $cursor += $b.Csize
        continue
    }
    $bms  = [System.IO.MemoryStream]::new($data, $cursor, $b.Csize)
    $bzls = [System.IO.Compression.ZLibStream]::new($bms, [System.IO.Compression.CompressionMode]::Decompress, $false)
    $bout = [System.IO.MemoryStream]::new()
    try {
        $bzls.CopyTo($bout)
        $bytes = $bout.ToArray()
        # PE-wrapper manifests use path-style names (e.g., './tmp/.../f0.bin');
        # normalize the separator and create parent dirs before writing.
        $relName = $b.Name -replace '^\./','' -replace '/','\'
        $dest    = Join-Path $OutputDir $relName
        $destDir = Split-Path -Path $dest -Parent
        if ($destDir -and -not (Test-Path -LiteralPath $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }
        [System.IO.File]::WriteAllBytes($dest, $bytes)
        $extracted.Add([pscustomobject]@{
            Name           = $b.Name
            Path           = $dest
            CompressedSize = $b.Csize
            ExtractedSize  = $bytes.Length
            ExpectedSize   = $b.Size
            ZlibOffset     = $cursor
        })
        if (-not $Quiet) {
            $mark = if ($bytes.Length -eq $b.Size) { 'OK  ' } else { 'WARN' }
            Write-Host ("  [{0}] {1,-15} {2,7} -> {3,7} bytes  (manifest expected {4})" -f $mark, $b.Name, $b.Csize, $bytes.Length, $b.Size)
        }
    }
    catch {
        Write-Host ("  [FAIL] {0}: {1}" -f $b.Name, $_.Exception.Message) -ForegroundColor Red
        $failed++
    }
    finally {
        $bzls.Dispose(); $bms.Dispose(); $bout.Dispose()
    }
    $cursor += $b.Csize
}

# Optional auto-verification against the vendor hashes in manifest.json.
# Older Eaton manifests carry a 'sha1' field per block; newer ones (5PX G2,
# 9PX Lithium-Ion) switched to 'sha256'. Pick whichever the manifest uses.
$mfPath = Join-Path $OutputDir 'manifest.json'
if (Test-Path -LiteralPath $mfPath) {
    try {
        $mf = Get-Content -LiteralPath $mfPath -Raw | ConvertFrom-Json
        if ($mf.binaryBlocks) {
            if (-not $Quiet) {
                Write-Host ""
                Write-Host "=== Vendor hash verification (manifest.json) ==="
            }
            $ok = 0; $bad = 0
            foreach ($prop in $mf.binaryBlocks.PSObject.Properties) {
                $entry  = $prop.Value
                $fp     = Join-Path $OutputDir $entry.file
                if (-not (Test-Path -LiteralPath $fp)) { continue }
                $vendor = $null; $alg = $null
                if ($entry.PSObject.Properties.Name -contains 'sha256' -and $entry.sha256) {
                    $vendor = $entry.sha256; $alg = 'SHA256'
                } elseif ($entry.PSObject.Properties.Name -contains 'sha1' -and $entry.sha1) {
                    $vendor = $entry.sha1; $alg = 'SHA1'
                }
                if (-not $vendor) { continue }
                $ours  = (Get-FileHash -LiteralPath $fp -Algorithm $alg).Hash.ToLowerInvariant()
                $match = ($ours -ieq $vendor)
                if ($match) { $ok++ } else { $bad++ }
                if (-not $Quiet) {
                    $color = if ($match) { 'Green' } else { 'Red' }
                    Write-Host ("  {0,-8} {1,-6} {2,-15} ours={3} vendor={4}" -f ($(if ($match) { 'OK' } else { 'MISMATCH' })), $alg, $entry.file, $ours, $vendor.ToLowerInvariant()) -ForegroundColor $color
                }
            }
            if (-not $Quiet) { Write-Host ("Result: {0} matched, {1} mismatched" -f $ok, $bad) }
            if ($bad -gt 0) {
                Write-Warning ("{0} block(s) failed vendor hash verification" -f $bad)
            }
        }
    }
    catch {
        Write-Warning ("Could not parse manifest.json for verification: {0}" -f $_.Exception.Message)
    }
}

if (-not $Quiet) {
    Write-Host ""
    Write-Host "[DONE]"
    Write-Host ("  Blocks listed in manifest: {0}" -f $blocks.Count)
    Write-Host ("  Successfully extracted:    {0}" -f $extracted.Count)
    if ($failed -gt 0) {
        Write-Host ("  Failed:                    {0}" -f $failed) -ForegroundColor Red
    }
    Write-Host ("  Trailing bytes in .sta:    {0}" -f ($data.Length - $cursor))
    Write-Host ""
    Write-Host "Next step: build the catalog from the unpacked tree, e.g."
    Write-Host "  .\tools\Build-OsCatalog.ps1 -OsName 'Eaton 9PX UPS X-YkVA vN.N.NNNN' -SourceDir '$OutputDir'"
}

# Pipeline-friendly output
return $extracted

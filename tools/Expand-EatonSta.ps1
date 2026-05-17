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
    $OutputDir = Join-Path (Split-Path -LiteralPath $StaPath -Parent) 'sta-unpacked'
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

$mcsize = Read-BEUInt32 -Bytes $data -Offset 0
$musize = Read-BEUInt32 -Bytes $data -Offset 4

if ($mcsize -le 0 -or $mcsize -gt ($data.Length - 8)) {
    Write-Error ("Manifest size {0} is implausible for a {1}-byte .sta file - header format may differ from expected" -f $mcsize, $data.Length)
    return
}

if (-not $Quiet) {
    Write-Host "Source:    $StaPath"
    Write-Host "Output:    $OutputDir"
    Write-Host "Total size: $($data.Length) bytes"
    Write-Host ("Manifest:  csize={0}, usize={1}" -f $mcsize, $musize)
}

# Decompress manifest (first zlib stream, exactly mcsize bytes after the 8-byte header)
$manifestText = $null
$ms  = [System.IO.MemoryStream]::new($data, 8, $mcsize)
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

if (-not $manifestText.StartsWith('(')) {
    Write-Warning ("Manifest text doesn't start with '(' as expected - .sta format may differ. First 80 chars: {0}" -f $manifestText.Substring(0, [Math]::Min(80, $manifestText.Length)))
}

# Parse Python-dict-ish entries: 'name': {size: N, csize: M}
$blocks = New-Object System.Collections.Generic.List[object]
foreach ($m in [regex]::Matches($manifestText, "'([^']+)':\s*\{\s*size:\s*(\d+),\s*csize:\s*(\d+)\s*\}")) {
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
$cursor    = 8 + $mcsize
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
        $dest  = Join-Path $OutputDir $b.Name
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

# Optional auto-verification against vendor SHA1s in manifest.json
$mfPath = Join-Path $OutputDir 'manifest.json'
if (Test-Path -LiteralPath $mfPath) {
    try {
        $mf = Get-Content -LiteralPath $mfPath -Raw | ConvertFrom-Json
        if ($mf.binaryBlocks) {
            if (-not $Quiet) {
                Write-Host ""
                Write-Host "=== Vendor SHA1 verification (manifest.json) ==="
            }
            $ok = 0; $bad = 0
            foreach ($prop in $mf.binaryBlocks.PSObject.Properties) {
                $entry  = $prop.Value
                $fp     = Join-Path $OutputDir $entry.file
                if (-not (Test-Path -LiteralPath $fp)) { continue }
                $ourSha1 = (Get-FileHash -LiteralPath $fp -Algorithm SHA1).Hash.ToLowerInvariant()
                $match   = ($ourSha1 -ieq $entry.sha1)
                if ($match) { $ok++ } else { $bad++ }
                if (-not $Quiet) {
                    $color = if ($match) { 'Green' } else { 'Red' }
                    Write-Host ("  {0,-8} {1,-15} ours={2} vendor={3}" -f ($(if ($match) { 'OK' } else { 'MISMATCH' })), $entry.file, $ourSha1, $entry.sha1) -ForegroundColor $color
                }
            }
            if (-not $Quiet) { Write-Host ("Result: {0} matched, {1} mismatched" -f $ok, $bad) }
            if ($bad -gt 0) {
                Write-Warning ("{0} block(s) failed vendor SHA1 verification" -f $bad)
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

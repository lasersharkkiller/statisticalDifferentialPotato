<#
.SYNOPSIS
Build an NSRL-format CSV (Hash,FileName,OsName) for an extracted firmware tree.

.DESCRIPTION
Walks every file under -SourceDir recursively, computes SHA256, and writes
one row per file to -OutputCsv. The OsName column is set to the value of
-OsName for every row.

The output CSV is the same shape as NSRL/nsrl_reduced.csv, so any number
of these per-product catalogs can later be merged together (or fed
individually to Get-VTBaseline) without further transformation.

.PARAMETER OsName
The exact string that goes in the OsName column. Becomes the menu label
once you integrate. Use a versioned name so different firmware versions
stay distinct, e.g. 'Schneider Modicon M580 v4.20'.

.PARAMETER SourceDir
Root of the already-extracted firmware (e.g. binwalk output).

.PARAMETER OutputCsv
Destination CSV path. Defaults to:
  <repo-parent>\firmware-staging\<sanitized-OsName>.csv
which resolves to C:\githubProjects\firmware-staging\... when this repo
lives at C:\githubProjects\statisticalDifferentialPotato.

.PARAMETER Append
If set, appends to an existing CSV. Otherwise overwrites.

.PARAMETER ExcludeExtensions
Skip files matching these extensions (e.g. '.log', '.tmp'). Default: none.

.PARAMETER MinSizeBytes
Skip files smaller than this. Default: 1 (skips only zero-byte files).

.EXAMPLE
.\tools\Build-OsCatalog.ps1 `
    -OsName 'Eaton 9PX UPS v4.0' `
    -SourceDir 'C:\githubProjects\firmware-staging\Eaton\9PX-UPS-v4.0\extracted'

.EXAMPLE
.\tools\Build-OsCatalog.ps1 `
    -OsName 'Schneider Modicon M580 v4.20' `
    -SourceDir 'D:\firmware\m580\extracted' `
    -OutputCsv 'C:\githubProjects\firmware-staging\Schneider\m580-v420.csv' `
    -ExcludeExtensions '.log','.tmp'
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$OsName,

    [Parameter(Mandatory=$true)]
    [string]$SourceDir,

    [string]$OutputCsv,

    [switch]$Append,

    [string[]]$ExcludeExtensions = @(),

    [int]$MinSizeBytes = 1
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $SourceDir -PathType Container)) {
    Write-Error "SourceDir not found or not a directory: $SourceDir"
    return
}

if ([string]::IsNullOrWhiteSpace($OutputCsv)) {
    # Default staging root sits one level above this repo so firmware blobs
    # (large, sometimes license-restricted) don't end up inside the repo
    # working tree at all. e.g. C:\githubProjects\firmware-staging\
    $stagingRoot = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'firmware-staging'
    $slug = $OsName -replace '[\\/:*?"<>|]', '_' -replace '\s+', '-'
    $OutputCsv = Join-Path $stagingRoot "$slug.csv"
}

$outDir = Split-Path $OutputCsv -Parent
if ($outDir -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

if (-not $Append -and (Test-Path $OutputCsv)) {
    Remove-Item $OutputCsv -Force
}

if (-not (Test-Path $OutputCsv)) {
    # Header row matches NSRL/nsrl_reduced.csv exactly so existing readers
    # don't need adjustment.
    'Hash,FileName,OsName' | Set-Content -Path $OutputCsv -Encoding UTF8
}

$excludeSet = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
foreach ($e in $ExcludeExtensions) { [void]$excludeSet.Add($e.TrimStart('.').ToLowerInvariant()) }

Write-Host "OsName:    $OsName"
Write-Host "SourceDir: $SourceDir"
Write-Host "OutputCsv: $OutputCsv"
Write-Host ""

$total      = 0
$emitted    = 0
$skippedTny = 0
$skippedExt = 0
$failed     = 0
$batch      = New-Object System.Collections.Generic.List[string]
$batchSize  = 500

Get-ChildItem -LiteralPath $SourceDir -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
    $total++
    if ($_.Length -lt $MinSizeBytes) { $skippedTny++; return }
    $ext = $_.Extension.TrimStart('.').ToLowerInvariant()
    if ($ext -and $excludeSet.Contains($ext)) { $skippedExt++; return }
    try {
        $h = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        # Escape commas / quotes in filename so CSV stays valid.
        $name = $_.Name
        if ($name -match '[,"\r\n]') {
            $name = '"' + ($name -replace '"', '""') + '"'
        }
        $osQuoted = $OsName
        if ($osQuoted -match '[,"\r\n]') {
            $osQuoted = '"' + ($osQuoted -replace '"', '""') + '"'
        }
        [void]$batch.Add("$h,$name,$osQuoted")
        $emitted++
        if ($batch.Count -ge $batchSize) {
            Add-Content -Path $OutputCsv -Value $batch -Encoding UTF8
            $batch.Clear()
        }
        if ($emitted % 1000 -eq 0) {
            Write-Host "  Processed $emitted files..." -ForegroundColor DarkGray
        }
    } catch {
        $failed++
        Write-Host "  [WARN] Hash failed for $($_.FullName): $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

if ($batch.Count -gt 0) {
    Add-Content -Path $OutputCsv -Value $batch -Encoding UTF8
}

Write-Host ""
Write-Host "[DONE]"
Write-Host ("  Files scanned:           {0}" -f $total)
Write-Host ("  Rows written:            {0}" -f $emitted)
Write-Host ("  Skipped (too small):     {0}" -f $skippedTny)
Write-Host ("  Skipped (excluded ext):  {0}" -f $skippedExt)
Write-Host ("  Failed to hash:          {0}" -f $failed)
Write-Host ""
Write-Host "Output: $OutputCsv"

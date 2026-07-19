#Requires -Version 5.1
<#
.SYNOPSIS
    One-shot remediation of *_Master_Intel.csv rows where IOCType="Hash"
    is generic / algorithm-agnostic. Re-tags by IOCValue length:
        32 hex chars  -> MD5
        40 hex chars  -> SHA1
        64 hex chars  -> SHA256
        96 hex chars  -> splits into two rows: SHA256 (first 64) + MD5 (last 32)
    Any value that doesn't match those shapes is left as-is and logged
    to the anomaly report.

.DESCRIPTION
    Cybersixgill (and a handful of other community feeds) return
    ioc_type="Hash" without specifying the algorithm. The harvester
    (purpleTeaming\aptIocs.psm1) historically passed that label through
    verbatim. Downstream consumers - 1a -> 7 (Get-AptHashRecords), the
    fidelity index builder, the differential analysis modules, the
    agentic dashboards - all switch on IOCType and silently drop the
    "Hash" rows. Across the corpus this means roughly 38% of all
    accumulated hash IOCs (45,739 of 121,736 total hash rows as of the
    initial scope assessment) are sitting in the CSVs but contributing
    nothing to baselines, differentials, or detection-rule generation.

    This script is the one-shot correction. ConvertTo-HashIocType in
    aptIocs.psm1 has been patched to do the same classification at
    ingest time, so no future runs of 1b will re-create the problem.

.PARAMETER AptRoot
    Root folder to walk. Defaults to ..\apt relative to this script.

.PARAMETER Apply
    Write changes back to disk. Without this flag the script runs as a
    dry-run, prints projected counts + anomaly list, and exits.

.EXAMPLE
    .\tools\Repair-MasterIntelHashTypes.ps1
    Dry-run: scans + prints summary, no files touched.

.EXAMPLE
    .\tools\Repair-MasterIntelHashTypes.ps1 -Apply
    Writes back changes; original files are replaced atomically via
    a .tmp + Move-Item.
#>
[CmdletBinding()]
param(
    [string]$AptRoot = (Join-Path $PSScriptRoot '..\apt'),
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $AptRoot)) {
    Write-Error "Apt root not found: $AptRoot"
    return
}

$files = @(Get-ChildItem -LiteralPath $AptRoot -Filter '*_Master_Intel.csv' -Recurse -File)
Write-Host ("Found {0} *_Master_Intel.csv files under {1}" -f $files.Count, (Resolve-Path $AptRoot)) -ForegroundColor Cyan
if (-not $Apply) {
    Write-Host "Mode: DRY-RUN (no files will be modified - re-run with -Apply to write)" -ForegroundColor Yellow
} else {
    Write-Host "Mode: APPLY (files will be rewritten in place)" -ForegroundColor Green
}
Write-Host ""

$filesScanned   = 0
$filesModified  = 0
$rowsScanned    = 0
$rowsRetaggedMd5    = 0
$rowsRetaggedSha1   = 0
$rowsRetaggedSha256 = 0
$rowsSplit          = 0
$rowsUnchanged      = 0
$anomalies          = [System.Collections.Generic.List[string]]::new()

foreach ($file in $files) {
    $filesScanned++

    try {
        $rows = @(Import-Csv -LiteralPath $file.FullName)
    } catch {
        $anomalies.Add("CANNOT_PARSE: $($file.FullName) - $($_.Exception.Message)")
        continue
    }

    $newRows = [System.Collections.Generic.List[object]]::new()
    $changed = $false

    foreach ($row in $rows) {
        $rowsScanned++

        $type = if ($row.PSObject.Properties['IOCType']) { ($row.IOCType + '').Trim() } else { '' }

        if ($type -ne 'Hash') {
            $newRows.Add($row)
            $rowsUnchanged++
            continue
        }

        $value = if ($row.PSObject.Properties['IOCValue']) { ($row.IOCValue + '').Trim() } else { '' }

        if ($value -match '^[0-9a-fA-F]{32}$') {
            $row.IOCType = 'MD5'
            $newRows.Add($row)
            $rowsRetaggedMd5++
            $changed = $true
        }
        elseif ($value -match '^[0-9a-fA-F]{40}$') {
            $row.IOCType = 'SHA1'
            $newRows.Add($row)
            $rowsRetaggedSha1++
            $changed = $true
        }
        elseif ($value -match '^[0-9a-fA-F]{64}$') {
            $row.IOCType = 'SHA256'
            $newRows.Add($row)
            $rowsRetaggedSha256++
            $changed = $true
        }
        elseif ($value -match '^[0-9a-fA-F]{96}$') {
            $sha = $value.Substring(0,64)
            $md5 = $value.Substring(64,32)
            $splitNote = if ($row.PSObject.Properties['Context'] -and $row.Context) {
                "$($row.Context) (split from SHA256+MD5 concat)"
            } else { '(split from SHA256+MD5 concat)' }
            $newRows.Add([PSCustomObject]@{
                Date     = $row.Date
                Source   = $row.Source
                Actor    = $row.Actor
                IOCType  = 'SHA256'
                IOCValue = $sha
                Context  = $splitNote
                Link     = $row.Link
            })
            $newRows.Add([PSCustomObject]@{
                Date     = $row.Date
                Source   = $row.Source
                Actor    = $row.Actor
                IOCType  = 'MD5'
                IOCValue = $md5
                Context  = $splitNote
                Link     = $row.Link
            })
            $rowsSplit++
            $changed = $true
        }
        else {
            # Doesn't match any known hash shape - log and leave untouched.
            $preview = if ($value.Length -gt 40) { $value.Substring(0,40) + '...' } else { $value }
            $anomalies.Add(("ANOMALOUS_HASH_VALUE: {0} (len={1}): {2}" -f $file.Name, $value.Length, $preview))
            $newRows.Add($row)
            $rowsUnchanged++
        }
    }

    if ($changed) {
        $filesModified++
        if ($Apply) {
            $tmp = "$($file.FullName).tmp"
            try {
                # Match harvester encoding ($Sync-/Export-Csv -Encoding UTF8) for consistency.
                $newRows | Export-Csv -LiteralPath $tmp -NoTypeInformation -Encoding UTF8
                Move-Item -LiteralPath $tmp -Destination $file.FullName -Force
            } catch {
                $anomalies.Add("WRITE_FAIL: $($file.FullName) - $($_.Exception.Message)")
                if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
            }
        }
    }
}

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host ("Files scanned:           {0,7}" -f $filesScanned)
Write-Host ("Files modified:          {0,7}" -f $filesModified)
Write-Host ("Rows scanned:            {0,7}" -f $rowsScanned)
Write-Host ("Rows re-tagged MD5:      {0,7}" -f $rowsRetaggedMd5)
Write-Host ("Rows re-tagged SHA1:     {0,7}" -f $rowsRetaggedSha1)
Write-Host ("Rows re-tagged SHA256:   {0,7}" -f $rowsRetaggedSha256)
Write-Host ("Rows split (SHA256+MD5): {0,7}  ({1} resulting new rows)" -f $rowsSplit, ($rowsSplit * 2))
Write-Host ("Rows unchanged:          {0,7}" -f $rowsUnchanged)

if ($anomalies.Count -gt 0) {
    Write-Host ""
    Write-Host ("Anomalies ({0}):" -f $anomalies.Count) -ForegroundColor Yellow
    $anomalies | Select-Object -First 20 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkYellow }
    if ($anomalies.Count -gt 20) {
        Write-Host ("  ... and {0} more (suppressed)" -f ($anomalies.Count - 20)) -ForegroundColor DarkYellow
    }
}

if (-not $Apply) {
    Write-Host ""
    Write-Host "DRY RUN. Re-run with -Apply to write changes." -ForegroundColor Cyan
}

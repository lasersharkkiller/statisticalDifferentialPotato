<#
.SYNOPSIS
    Polls pending VT analyses with N workers in parallel, pulling main +
    behaviour reports.

.DESCRIPTION
    This is the long pole of the pipeline, not submission. Measured serially:
    14,175 analyses in 347.6 min = ~41/min. At the projected ~300k submissions
    that is ~123 hours, so it dominates the total run time.

    Each worker polls its own slice of the pending tracker. Workers never touch
    the shared MissingHashes.csv - they emit MissingHashesRemove.sync<N>.csv and
    this script applies every deregistration once, which avoids the
    last-writer-wins clobbering that per-worker rewrites would cause.

    Suffixes are .sync<N> so they cannot collide with the submit orchestrator's
    .part<N> files.

.PARAMETER Workers
    Parallel workers. 6 is roughly 6% of the 10,000/min enterprise cap when the
    submit orchestrator is not also running.
#>
[CmdletBinding()]
param(
    [int]$Workers    = 6,
    [int]$MinDelayMs = 12,
    [string]$Repo    = (Split-Path $PSScriptRoot -Parent),
    [string]$LogDir  = $(Join-Path ([System.IO.Path]::GetTempPath()) 'ot-sync-parallel'),
    [switch]$WhatIfPlan
)

$ErrorActionPreference = 'Stop'
Set-Location $Repo
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

$pendingMain = Join-Path $Repo 'output\PendingVTSubmissions.csv'
$missingMain = Join-Path $Repo 'output\MissingHashes.csv'

Write-Host ""
Write-Host "=== Parallel VT analysis sync: $Workers workers, ${MinDelayMs}ms spacing each ===" -ForegroundColor Cyan

if (-not (Test-Path $pendingMain)) { Write-Host "  no pending tracker - nothing to sync." -ForegroundColor Green; return }
$rows = @(Import-Csv $pendingMain)
Write-Host ("  pending analyses: {0:N0}" -f $rows.Count)
if ($rows.Count -eq 0) { Write-Host "  nothing to sync." -ForegroundColor Green; return }

# Round-robin the rows so every worker gets a mix of old and new analyses
# (older ones are more likely to be complete, so this balances the work).
$shards = @{}
for ($i = 0; $i -lt $Workers; $i++) { $shards[$i] = [System.Collections.Generic.List[object]]::new() }
for ($i = 0; $i -lt $rows.Count; $i++) { $shards[$i % $Workers].Add($rows[$i]) }
foreach ($k in ($shards.Keys | Sort-Object)) {
    Write-Host ("  worker {0}: {1,7:N0} analyses" -f ($k + 1), $shards[$k].Count)
}
if ($WhatIfPlan) { Write-Host "  -WhatIfPlan: stopping before launch." -ForegroundColor Yellow; return }

# Write the shards, then move the main tracker aside so nothing double-polls it.
foreach ($k in ($shards.Keys | Sort-Object)) {
    if ($shards[$k].Count -eq 0) { continue }
    $shards[$k] | Export-Csv -LiteralPath (Join-Path $Repo ("output\PendingVTSubmissions.sync{0}.csv" -f ($k + 1))) -NoTypeInformation
}
$stash = Join-Path $Repo ('output\PendingVTSubmissions.presync.csv')
Move-Item -LiteralPath $pendingMain -Destination $stash -Force
Write-Host "  main tracker stashed -> $(Split-Path $stash -Leaf)" -ForegroundColor DarkGray

$workerScript = Join-Path $LogDir 'syncworker.ps1'
@'
param([string]$Repo, [string]$Suffix, [int]$MinDelayMs)
$ErrorActionPreference = 'Continue'
Set-Location $Repo
Import-Module (Join-Path $Repo 'baseline\OtBaseline.psm1') -Force
Sync-VTPendingSubmissions -Enterprise -EnterpriseMinDelayMs $MinDelayMs -TrackerSuffix $Suffix
'@ | Set-Content -LiteralPath $workerScript -Encoding UTF8

$procs = @()
foreach ($k in ($shards.Keys | Sort-Object)) {
    if ($shards[$k].Count -eq 0) { continue }
    $suffix = ".sync{0}" -f ($k + 1)
    $log    = Join-Path $LogDir ("syncworker{0}.log" -f ($k + 1))
    $procs += Start-Process -FilePath 'pwsh' -PassThru -WindowStyle Hidden `
        -ArgumentList @('-NoProfile', '-File', $workerScript, '-Repo', $Repo, '-Suffix', $suffix, '-MinDelayMs', $MinDelayMs) `
        -RedirectStandardOutput $log -RedirectStandardError ($log -replace '\.log$', '.err')
    Write-Host ("  launched sync worker {0} (pid {1})" -f ($k + 1), $procs[-1].Id)
}

Write-Host ""
Write-Host "  waiting for $($procs.Count) workers..." -ForegroundColor DarkCyan
$t0 = Get-Date
$procs | Wait-Process
Write-Host ("  all sync workers finished in {0:N1} min" -f ((Get-Date) - $t0).TotalMinutes) -ForegroundColor Green

# ------------------------------------------------------------------ merge ---
Write-Host ""
Write-Host "  merging..." -ForegroundColor Cyan

# 1. Whatever is still pending across all shards becomes the new main tracker.
$stillParts = @(Get-ChildItem (Join-Path $Repo 'output\PendingVTSubmissions.sync*.csv') -ErrorAction SilentlyContinue)
$still = @(foreach ($p in $stillParts) { Import-Csv $p.FullName })
if ($still.Count -gt 0) {
    $still | Export-Csv -LiteralPath $pendingMain -NoTypeInformation
    Write-Host ("    still pending: {0:N0} -> {1}" -f $still.Count, (Split-Path $pendingMain -Leaf))
} else {
    Write-Host "    nothing still pending; tracker cleared."
}
$stillParts | Remove-Item -Force

# 2. Apply every worker's deregistrations to MissingHashes exactly once.
$remParts = @(Get-ChildItem (Join-Path $Repo 'output\MissingHashesRemove.sync*.csv') -ErrorAction SilentlyContinue)
$confirmed = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($p in $remParts) { Import-Csv $p.FullName | ForEach-Object { if ($_.Hash) { [void]$confirmed.Add($_.Hash) } } }
Write-Host ("    confirmed now-in-VT: {0:N0}" -f $confirmed.Count)
if ($confirmed.Count -gt 0 -and (Test-Path $missingMain)) {
    $before = @(Import-Csv $missingMain)
    $after  = @($before | Where-Object { -not $confirmed.Contains($_.Hash) })
    if ($after.Count -gt 0) {
        $after | Export-Csv -LiteralPath $missingMain -NoTypeInformation
    } else {
        'Hash,DateChecked' | Set-Content -LiteralPath $missingMain
    }
    Write-Host ("    MissingHashes: {0:N0} -> {1:N0}" -f $before.Count, $after.Count)
}
$remParts | Remove-Item -Force
Remove-Item -LiteralPath $stash -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "  worker logs: $LogDir" -ForegroundColor DarkCyan
Write-Host ""

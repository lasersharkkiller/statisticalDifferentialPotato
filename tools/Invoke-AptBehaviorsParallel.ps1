<#
.SYNOPSIS
    Pulls VT main + behaviour reports for malware/APT hashes that do not have one
    yet, with N workers in parallel.

.DESCRIPTION
    This is the MALICIOUS side of the differential - the M counts. The goodware
    side (OT firmware, NSRL) is handled by Invoke-OtQueryParallel.ps1 /
    Invoke-OtSyncParallel.ps1.

    baseline\AptMasterIntelVT.psm1 was free-tier only: 15,000 ms spacing per key
    and 499 requests/key/day, which cannot move ~24k hashes (~48k calls) in any
    reasonable time. It now has an -Enterprise path; those free-tier constants are
    deliberately untouched.

    SHARDING. Get-AptMasterIntelVTAll walks <AptRoot>\APTs and
    <AptRoot>\Malware Families for *_Master_Intel.csv, and derives the output
    directory from each CSV's filename
    (apt-master-intel\<Bucket>\<Actor>\<Hash>.json). So each worker gets a
    synthetic AptRoot mirroring that layout, holding only its slice of the work -
    the same virtual-catalog trick used for the OT submit stage. One globally
    de-duplicated work list means a hash is fetched once, not once per actor that
    references it.

    Workers write MissingHashes.apt<N>.csv and this script merges them, because
    Export-Csv -Append is not safe across processes and a per-worker rewrite of
    the shared tracker would clobber the other workers' 404s.

.PARAMETER Workers
    Parallel workers. Measured sibling stages: ~400 items/min at 8-10 workers,
    roughly 4% of the 10,000/min enterprise cap.

.EXAMPLE
    .\tools\Invoke-AptBehaviorsParallel.ps1 -Workers 8
#>
[CmdletBinding()]
param(
    [int]$Workers      = 8,
    [int]$MinDelayMs   = 12,
    [string]$Repo      = (Split-Path $PSScriptRoot -Parent),
    [string]$LogDir    = $(Join-Path ([System.IO.Path]::GetTempPath()) 'apt-behav-parallel'),
    [int]$Limit        = 0,
    [switch]$WhatIfPlan
)

$ErrorActionPreference = 'Stop'
Set-Location $Repo
if (Test-Path $LogDir) { Get-ChildItem $LogDir -Recurse -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

function New-HS { $h = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase); Write-Output $h -NoEnumerate }

Write-Host ""
Write-Host "=== Parallel APT/malware behaviour pull: $Workers workers, ${MinDelayMs}ms each ===" -ForegroundColor Cyan

# ------------------------------------------------- what we already have / lack ---
$have = New-HS
foreach ($b in @('apt-master-intel', 'malicious')) {
    $root = Join-Path $Repo "output-baseline\VirusTotal-behaviors\$b"
    if (-not (Test-Path $root)) { continue }
    foreach ($f in [System.IO.Directory]::EnumerateFiles($root, '*.json', 'AllDirectories')) {
        [void]$have.Add([System.IO.Path]::GetFileNameWithoutExtension($f))
    }
}
$known404 = New-HS
$mh = Join-Path $Repo 'output\MissingHashes.csv'
if (Test-Path $mh) { Import-Csv $mh | ForEach-Object { if ($_.Hash) { [void]$known404.Add($_.Hash) } } }
Write-Host ("  behaviour reports held: {0:N0} | known-404 hashes: {1:N0}" -f $have.Count, $known404.Count)

# --------------------------------------- globally de-duplicated work list ---
Write-Host "  building work list from the master intel corpus..."
$sources = @(
    @{ Bucket = 'APTs';             Glob = 'apt\APTs\*\*\*_Master_Intel.csv' },
    @{ Bucket = 'Malware Families'; Glob = 'apt\Malware Families\*\*_Master_Intel.csv' }
)
$claimed = New-HS
$work    = @{}     # "<bucket>|<actor>" -> List[hash]
$total   = 0
$skipHave = 0; $skip404 = 0

foreach ($src in $sources) {
    foreach ($csv in @(Get-ChildItem (Join-Path $Repo $src.Glob) -ErrorAction SilentlyContinue)) {
        if ($Limit -gt 0 -and $total -ge $Limit) { break }
        $actor = $csv.BaseName -replace '_Master_Intel$', ''
        foreach ($r in @(Import-Csv $csv.FullName)) {
            if ($Limit -gt 0 -and $total -ge $Limit) { break }
            $t = ("" + $r.IOCType).Trim()
            if ($t -notin @('SHA256', 'MD5', 'SHA1')) { continue }
            $h = ("" + $r.IOCValue).Trim()
            if (-not $h) { continue }
            if ($have.Contains($h))     { $skipHave++; continue }
            if ($known404.Contains($h)) { $skip404++;  continue }
            if (-not $claimed.Add($h))  { continue }
            $key = "$($src.Bucket)|$actor"
            if (-not $work.ContainsKey($key)) { $work[$key] = [System.Collections.Generic.List[string]]::new() }
            $work[$key].Add($h)
            $total++
        }
    }
}
Write-Host ("  already have: {0:N0} | known-404 skipped: {1:N0}" -f $skipHave, $skip404)
Write-Host ("  TO PULL: {0:N0} distinct hashes across {1:N0} actors" -f $total, $work.Count) -ForegroundColor Green
if (-not $total) { Write-Host "  nothing to pull." -ForegroundColor Green; return }

# ------------------------------------------------------------------ shard ---
# Round-robin within each actor so workers share large actors evenly. Two workers
# writing into the same actor output directory is safe: filenames are hashes.
$plan = @{}
for ($i = 1; $i -le $Workers; $i++) { $plan[$i] = @{} }
foreach ($key in $work.Keys) {
    $items = $work[$key]
    for ($j = 0; $j -lt $items.Count; $j++) {
        $w = ($j % $Workers) + 1
        if (-not $plan[$w].ContainsKey($key)) { $plan[$w][$key] = [System.Collections.Generic.List[string]]::new() }
        $plan[$w][$key].Add($items[$j])
    }
}
Write-Host ""
foreach ($w in ($plan.Keys | Sort-Object)) {
    $n = ($plan[$w].Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    Write-Host ("  worker {0}: {1,7:N0} hashes across {2,4} actors" -f $w, $n, $plan[$w].Count)
}
Write-Host ""
if ($WhatIfPlan) { Write-Host "  -WhatIfPlan: stopping before launch." -ForegroundColor Yellow; return }

# Materialise one synthetic AptRoot per worker.
foreach ($w in ($plan.Keys | Sort-Object)) {
    foreach ($key in $plan[$w].Keys) {
        $bucket, $actor = $key -split '\|', 2
        $dir = Join-Path $LogDir ("shard{0}\{1}\{2}" -f $w, $bucket, $actor)
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        # IOCType MUST be 'Hash', not 'SHA256'. Get-AptHashRecords validates the
        # value length against the declared type and silently drops mismatches, so
        # labelling a 32-char MD5 as SHA256 discards it - that lost 2,563 MD5/SHA1
        # hashes on the first run. 'Hash' accepts all three lengths, which is what
        # VT's /files/{hash} endpoint does anyway.
        @($plan[$w][$key] | ForEach-Object {
            [pscustomobject]@{ Date = ''; Source = 'shard'; Actor = $actor; IOCType = 'Hash'
                               IOCValue = $_; Context = ''; Link = '' }
        }) | Export-Csv -LiteralPath (Join-Path $dir "$actor`_Master_Intel.csv") -NoTypeInformation
    }
}

$workerScript = Join-Path $LogDir 'aptworker.ps1'
@'
param([string]$Repo, [string]$AptRoot, [string]$Suffix, [int]$MinDelayMs)
$ErrorActionPreference = 'Continue'
Set-Location $Repo
Import-Module (Join-Path $Repo 'baseline\VTBaseline.psm1')        -Force
Import-Module (Join-Path $Repo 'baseline\AptMasterIntelVT.psm1')  -Force
Get-AptMasterIntelVTAll -AptRoot $AptRoot -Enterprise -EnterpriseMinDelayMs $MinDelayMs -TrackerSuffix $Suffix
'@ | Set-Content -LiteralPath $workerScript -Encoding UTF8

$procs = @()
foreach ($w in ($plan.Keys | Sort-Object)) {
    if ($plan[$w].Count -eq 0) { continue }
    $shardRoot = Join-Path $LogDir ("shard{0}" -f $w)
    $log       = Join-Path $LogDir ("worker{0}.log" -f $w)
    $procs += Start-Process -FilePath 'pwsh' -PassThru -WindowStyle Hidden `
        -ArgumentList @('-NoProfile', '-File', $workerScript, '-Repo', $Repo,
                        '-AptRoot', $shardRoot, '-Suffix', (".apt{0}" -f $w), '-MinDelayMs', $MinDelayMs) `
        -RedirectStandardOutput $log -RedirectStandardError ($log -replace '\.log$', '.err')
    Write-Host ("  launched worker {0} (pid {1})" -f $w, $procs[-1].Id)
}

Write-Host ""
Write-Host "  waiting for $($procs.Count) workers..." -ForegroundColor DarkCyan
$t0 = Get-Date
$procs | Wait-Process
$mins = ((Get-Date) - $t0).TotalMinutes
Write-Host ("  all workers finished in {0:N1} min" -f $mins) -ForegroundColor Green

# ------------------------------------------------------------------ merge ---
Write-Host ""
Write-Host "  merging 404 trackers..." -ForegroundColor Cyan
$parts = @(Get-ChildItem (Join-Path $Repo 'output\MissingHashes.apt*.csv') -ErrorAction SilentlyContinue)
if ($parts.Count -gt 0) {
    $new      = @(foreach ($p in $parts) { Import-Csv $p.FullName })
    $existing = @(if (Test-Path $mh) { Import-Csv $mh })
    $seen = New-HS
    $keep = @(foreach ($r in @($existing + $new)) { if ($r.Hash -and $seen.Add($r.Hash)) { $r } })
    $keep | Export-Csv -LiteralPath $mh -NoTypeInformation
    Write-Host ("    MissingHashes: {0:N0} + {1:N0} new 404s -> {2:N0}" -f $existing.Count, $new.Count, $keep.Count)
    $parts | Remove-Item -Force
}

$ok = 0; $m404 = 0; $err = 0
foreach ($l in @(Get-ChildItem (Join-Path $LogDir 'worker*.log'))) {
    $t = Get-Content $l.FullName -Raw
    # [OK] fires once for the main report and once for behaviours, so halve it
    # rather than reporting double the real count.
    $ok   += [math]::Floor(([regex]::Matches($t, '\[OK\]')).Count / 2)
    $m404 += ([regex]::Matches($t, '\[404\]')).Count
    $err  += ([regex]::Matches($t, '\[ERROR\]')).Count
}
Write-Host ""
Write-Host ("  pulled ~{0:N0} hashes (main+behaviours), new 404s {1:N0}, errors {2:N0}" -f $ok, $m404, $err) -ForegroundColor Green
Write-Host ("  rate: ~{0:N0} hashes/min" -f ($ok / [math]::Max(0.1, $mins)))
Write-Host "  worker logs: $LogDir" -ForegroundColor DarkCyan
Write-Host ""

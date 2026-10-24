<#
.SYNOPSIS
    Queries VT for every cataloged OT hash not yet asked about, with N workers.

.DESCRIPTION
    This is the first stage of the pipeline and, after the submit and sync stages
    were parallelised, the largest remaining one: 613,012 cataloged hashes have
    never been sent to VT, 571,433 of them Siemens.

    For each hash VT either has a report (pulled to
    output-baseline\VirusTotal-main\OT\<Vendor>) or answers 404, which appends the
    hash to the missing tracker so the submit stage can pick it up.

    Sharded exactly like the submit orchestrator: one globally de-duplicated work
    list split across workers, materialised as per-worker virtual catalogs in the
    normal Hash,FileName,OsName,FullPath format. Workers append 404s to
    MissingHashes.q<N>.csv - never the shared tracker, since Export-Csv -Append
    is not safe across processes - and this script merges them at the end.

.PARAMETER Workers
    Parallel workers. Lookups are cheaper than uploads, so this can run higher
    than the submit stage; 10 is ~10% of the 10,000/min enterprise cap.

.PARAMETER Vendors
    Restrict to these vendors. Useful for calibrating the 404 rate on a sample
    before committing to a full sweep.

.PARAMETER Limit
    Stop after this many hashes (per run, across all workers). 0 = no limit.

.EXAMPLE
    # Calibrate the Siemens 404 rate on 3,000 hashes before the full sweep
    .\tools\Invoke-OtQueryParallel.ps1 -Vendors Siemens -Limit 3000 -Workers 6

.EXAMPLE
    .\tools\Invoke-OtQueryParallel.ps1 -Workers 10
#>
[CmdletBinding()]
param(
    [int]$Workers      = 10,
    [int]$MinDelayMs   = 12,
    [string[]]$Vendors,
    [int]$Limit        = 0,
    [string]$Repo      = (Split-Path $PSScriptRoot -Parent),
    [string]$Staging   = 'C:\githubProjects\firmware-staging',
    [string]$LogDir    = $(Join-Path ([System.IO.Path]::GetTempPath()) 'ot-query-parallel'),
    [switch]$WhatIfPlan
)

$ErrorActionPreference = 'Stop'
Set-Location $Repo
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
# Clear BOTH shards and worker logs. The end-of-run tallies grep every
# worker*.log in $LogDir, so logs left by a previous run get counted again:
# a 162-hash run once reported "in VT -273, 404 435 (268.5%)" because it was
# still reading the prior sweep's logs. The merge counts were right; only the
# summary lied, which is worse - it looks like data.
Get-ChildItem (Join-Path $LogDir 'shard*.csv')  -ErrorAction SilentlyContinue | Remove-Item -Force
Get-ChildItem (Join-Path $LogDir 'worker*.log') -ErrorAction SilentlyContinue | Remove-Item -Force

function New-HS { $h = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase); Write-Output $h -NoEnumerate }

Write-Host ""
Write-Host "=== Parallel OT VT query: $Workers workers, ${MinDelayMs}ms spacing each ===" -ForegroundColor Cyan

# --------------------------------------------------- what have we asked about ---
$asked = New-HS
$mainRoot = Join-Path $Repo 'output-baseline\VirusTotal-main\OT'
if (Test-Path $mainRoot) {
    foreach ($f in [System.IO.Directory]::EnumerateFiles($mainRoot, '*.json', 'AllDirectories')) {
        [void]$asked.Add([System.IO.Path]::GetFileNameWithoutExtension($f))
    }
}
$inVtCount = $asked.Count
foreach ($g in @('output\MissingHashes.csv', 'output\MissingHashes.q*.csv',
                 'output\PendingVTSubmissions*.csv', 'output\metrics\VTSubmissionLedger*.csv')) {
    foreach ($f in @(Get-ChildItem (Join-Path $Repo $g) -ErrorAction SilentlyContinue)) {
        Import-Csv $f.FullName | ForEach-Object { if ($_.Hash) { [void]$asked.Add($_.Hash) } }
    }
}
Write-Host ("  already asked about: {0:N0}  (of which in VT: {1:N0})" -f $asked.Count, $inVtCount)

# ----------------------------------------- globally de-duplicated work list ---
Write-Host "  building work list across all catalogs..."
$catalogs = @(Get-ChildItem (Join-Path $Staging '*\*\*\catalog.csv') -ErrorAction SilentlyContinue)
if ($Vendors) {
    $catalogs = @($catalogs | Where-Object { $Vendors -contains $_.FullName.Split([char]92)[3] })
    Write-Host ("  restricted to vendors: {0}  ({1} catalogs)" -f ($Vendors -join ', '), $catalogs.Count)
}
$claimed  = New-HS
$byVendor = @{}
$taken    = 0

foreach ($c in $catalogs) {
    if ($Limit -gt 0 -and $taken -ge $Limit) { break }
    $vendor = $c.FullName.Split([char]92)[3]
    foreach ($line in [System.IO.File]::ReadLines($c.FullName)) {
        if ($Limit -gt 0 -and $taken -ge $Limit) { break }
        $i = $line.IndexOf(',')
        if ($i -lt 32) { continue }
        # Catalogs are Export-Csv output, so every field is quoted. Strip them:
        # an unstripped 66-char hash matches nothing in $asked (whose keys are
        # 64-char report filenames), and the path regex never matches a quoted
        # field - together that silently yields an empty work list.
        $h = $line.Substring(0, $i).Trim([char]34)
        if ($asked.Contains($h) -or $claimed.Contains($h)) { continue }
        $m = [regex]::Match($line, ',"?([A-Za-z]:\\)')
        if (-not $m.Success) { continue }
        $fp = $line.Substring($m.Index + 1).Trim([char]34)
        [void]$claimed.Add($h)
        $taken++
        if (-not $byVendor.ContainsKey($vendor)) { $byVendor[$vendor] = [System.Collections.Generic.List[object]]::new() }
        $byVendor[$vendor].Add([pscustomobject]@{
            Hash = $h; FileName = [System.IO.Path]::GetFileName($fp); OsName = $vendor; FullPath = $fp
        })
    }
}
$total = ($byVendor.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
Write-Host ("  unqueried hashes to look up: {0:N0}" -f $total)
foreach ($v in ($byVendor.Keys | Sort-Object)) { Write-Host ("     {0,-16} {1,8:N0}" -f $v, $byVendor[$v].Count) }
if (-not $total) { Write-Host "  nothing to query." -ForegroundColor Green; return }

# ------------------------------------------------------------------ shard ---
$plan = @{}
for ($i = 1; $i -le $Workers; $i++) { $plan[$i] = [System.Collections.Generic.List[object]]::new() }
foreach ($v in ($byVendor.Keys | Sort-Object)) {
    $items = $byVendor[$v]
    for ($j = 0; $j -lt $items.Count; $j++) {
        $plan[(($j % $Workers) + 1)].Add([pscustomobject]@{ Vendor = $v; Row = $items[$j] })
    }
}
Write-Host ""
foreach ($w in ($plan.Keys | Sort-Object)) { Write-Host ("  worker {0}: {1,8:N0} hashes" -f $w, $plan[$w].Count) }
Write-Host ""
if ($WhatIfPlan) { Write-Host "  -WhatIfPlan: stopping before launch." -ForegroundColor Yellow; return }

$jobs = @{}
foreach ($w in ($plan.Keys | Sort-Object)) {
    $jobs[$w] = [System.Collections.Generic.List[object]]::new()
    foreach ($grp in ($plan[$w] | Group-Object Vendor)) {
        $shard = Join-Path $LogDir ("shard{0}_{1}.csv" -f $w, ($grp.Name -replace '[^A-Za-z0-9]', '_'))
        @($grp.Group | ForEach-Object { $_.Row }) | Export-Csv -LiteralPath $shard -NoTypeInformation
        $jobs[$w].Add([pscustomobject]@{ Path = $shard; Vendor = $grp.Name; Count = $grp.Count })
    }
}

$workerScript = Join-Path $LogDir 'queryworker.ps1'
@'
param([string]$Repo, [string]$Suffix, [int]$MinDelayMs, [string]$JobFile)
$ErrorActionPreference = 'Continue'
Set-Location $Repo
Import-Module (Join-Path $Repo 'baseline\OtBaseline.psm1') -Force
$jobs = Import-Csv $JobFile
Write-Host "worker $Suffix : $($jobs.Count) shards"
foreach ($j in $jobs) {
    Write-Host ("  shard {0} ({1} hashes)" -f $j.Vendor, $j.Count) -ForegroundColor Cyan
    try {
        Get-OtBaseline -CatalogCsv $j.Path -Vendor $j.Vendor -Category 'sharded' -Product 'sharded' `
                       -Enterprise -EnterpriseMinDelayMs $MinDelayMs -TrackerSuffix $Suffix
    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
}
Write-Host "worker $Suffix : done"
'@ | Set-Content -LiteralPath $workerScript -Encoding UTF8

$procs = @()
foreach ($w in ($jobs.Keys | Sort-Object)) {
    if ($jobs[$w].Count -eq 0) { continue }
    $jobFile = Join-Path $LogDir ("jobs{0}.csv" -f $w)
    $jobs[$w] | Export-Csv -LiteralPath $jobFile -NoTypeInformation
    $log = Join-Path $LogDir ("worker{0}.log" -f $w)
    $procs += Start-Process -FilePath 'pwsh' -PassThru -WindowStyle Hidden `
        -ArgumentList @('-NoProfile', '-File', $workerScript, '-Repo', $Repo,
                        '-Suffix', (".q{0}" -f $w), '-MinDelayMs', $MinDelayMs, '-JobFile', $jobFile) `
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
$mhMain  = Join-Path $Repo 'output\MissingHashes.csv'
$qParts  = @(Get-ChildItem (Join-Path $Repo 'output\MissingHashes.q*.csv') -ErrorAction SilentlyContinue)
if ($qParts.Count -gt 0) {
    $new      = @(foreach ($p in $qParts) { Import-Csv $p.FullName })
    $existing = @(if (Test-Path $mhMain) { Import-Csv $mhMain })
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $keep = @(foreach ($r in @($existing + $new)) { if ($r.Hash -and $seen.Add($r.Hash)) { $r } })
    $keep | Export-Csv -LiteralPath $mhMain -NoTypeInformation
    Write-Host ("    MissingHashes: {0:N0} existing + {1:N0} new 404s -> {2:N0}" -f $existing.Count, $new.Count, $keep.Count)
    $qParts | Remove-Item -Force
}

# Count ONLY unambiguous per-hash markers. Do not count [OK]/[CACHED]: those
# fire more than once per hash (main report and behaviour report each log one),
# which previously reported 906,222 "queried" out of a 608,837-hash plan and a
# correspondingly meaningless 404 percentage. The planned total is authoritative.
$missed = 0; $err = 0
foreach ($l in @(Get-ChildItem (Join-Path $LogDir 'worker*.log'))) {
    $t = Get-Content $l.FullName -Raw
    $missed += ([regex]::Matches($t, '\[404\] not in VT')).Count
    $err    += ([regex]::Matches($t, '\[ERROR\]')).Count
}
$tot   = $total
$found = $tot - $missed - $err
Write-Host ""
Write-Host ("  queried {0:N0} (planned): in VT {1:N0}, 404 {2:N0} ({3:N1}%), errors {4:N0}" -f $tot, $found, $missed, $(if($tot){100.0*$missed/$tot}else{0}), $err) -ForegroundColor Green
Write-Host ("  rate: {0:N0} hashes/min" -f ($tot / [math]::Max(0.1, $mins)))
Write-Host "  worker logs: $LogDir" -ForegroundColor DarkCyan
Write-Host "  Next: tools\Invoke-OtSubmitParallel.ps1 for the new 404s." -ForegroundColor DarkCyan
Write-Host ""

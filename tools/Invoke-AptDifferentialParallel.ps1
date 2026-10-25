<#
.SYNOPSIS
    Reruns every APT/malware-family statistical differential across N workers,
    now that ELF import extraction actually works.

.DESCRIPTION
    `targetedMalwareDifferentialAnalysis.psm1` read `elf_info.imported_symbols`,
    a field that does not exist in VT's schema (the real one is
    `elf_info.import_list`). The ELF bucket was therefore always empty, so
    **no run ever produced TargetedElfDifferentialAnalysis.json** - confirmed
    across all 92 actor folders, 0 of which have one. Every existing APT
    differential is Windows-only by accident, with ELF samples' imports
    silently dropped. Fixed 2026-10-23; this reruns the corpus.

    WHY THE STORE PATHS MATTER - this is the whole reason the rerun is viable.
    `Get-TargetedMalwareAnalysis` resolves each input hash by checking, in order:
    the Global_Hash_Resolution cache, then `<MaliciousStoragePath>\<hash>.json`,
    then **the VT API**. Its default MaliciousStoragePath is
    `output-baseline\VirusTotal-main\malicious`, but APT reports live under
    `output-baseline\VirusTotal-main\apt-master-intel\{APTs|Malware Families}\<Actor>\`.
    Called with defaults it finds nothing locally and falls through to the API -
    and the differential has NO enterprise-key path, so it resolves on the free
    keys at their calibrated ~15s spacing. Measured on APT30: 26% of its 566
    hashes resolve locally against the wrong store, so 419 would hit the API at
    ~14s each = 1.7 hours for ONE actor; extrapolated over 101,595 corpus rows
    that is several hundred hours.

    Pointed at the correct per-actor store, APT30 resolves **566/566 = 100%
    locally, zero API calls**. 90 of 92 actors map to a store by folder name;
    the 2 that do not (Team313, Storm-0501) hold 0 and 1 hashes respectively.

.PARAMETER Workers
    Each worker loads the full known-good baseline (NSRL + localBaseline =
    ~45,061 JSONs) independently, because the analyser reloads it per call.
    That is the memory constraint, not CPU - keep this modest.

.EXAMPLE
    .\tools\Invoke-AptDifferentialParallel.ps1 -WhatIfPlan
    .\tools\Invoke-AptDifferentialParallel.ps1 -Workers 6
#>
[CmdletBinding()]
param(
    [int]$Workers       = 6,
    [int]$MinDetections = 5,
    [string]$Repo       = (Split-Path $PSScriptRoot -Parent),
    [string]$LogDir     = $(Join-Path ([System.IO.Path]::GetTempPath()) 'apt-diff-parallel'),
    [switch]$OnlyMissingElf,
    [switch]$WhatIfPlan
)

$ErrorActionPreference = 'Stop'
Set-Location $Repo
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
Get-ChildItem (Join-Path $LogDir 'job*.csv')    -ErrorAction SilentlyContinue | Remove-Item -Force
Get-ChildItem (Join-Path $LogDir 'aptworker*.log') -ErrorAction SilentlyContinue | Remove-Item -Force

$mainRoot = Join-Path $Repo 'output-baseline\VirusTotal-main\apt-master-intel'
$behRoot  = Join-Path $Repo 'output-baseline\VirusTotal-behaviors\apt-master-intel'

Write-Host ''
Write-Host "=== APT differential rerun: $Workers workers ===" -ForegroundColor Cyan

# ------------------------------------------------- map actor -> store ---
$stores = @{}
foreach ($grp in @('APTs', 'Malware Families')) {
    foreach ($d in (Get-ChildItem (Join-Path $mainRoot $grp) -Directory -ErrorAction SilentlyContinue)) {
        $stores[$d.Name] = @{ Main = $d.FullName; Beh = (Join-Path (Join-Path $behRoot $grp) $d.Name) }
    }
}
Write-Host ("  report stores: {0}" -f $stores.Count)

$jobs = [System.Collections.Generic.List[object]]::new()
$unmapped = [System.Collections.Generic.List[string]]::new()
foreach ($c in (Get-ChildItem (Join-Path $Repo 'apt\APTs') -Recurse -Filter '*_Master_Intel.csv' -ErrorAction SilentlyContinue)) {
    $actor = Split-Path $c.DirectoryName -Leaf
    if (-not $stores.ContainsKey($actor)) { $unmapped.Add($actor); continue }
    if ($OnlyMissingElf -and (Test-Path (Join-Path $c.DirectoryName 'TargetedElfDifferentialAnalysis.json'))) { continue }
    $rows = 0
    try { $rows = @(Import-Csv $c.FullName).Count } catch {}
    if ($rows -lt 1) { continue }     # nothing to analyse
    $jobs.Add([pscustomobject]@{
        Actor = $actor; Csv = $c.FullName; Rows = $rows
        Main  = $stores[$actor].Main;  Beh = $stores[$actor].Beh
    })
}

Write-Host ("  actors to run : {0}" -f $jobs.Count)
if ($unmapped.Count) { Write-Host ("  unmapped (no report store, skipped): {0}" -f ($unmapped -join ', ')) -ForegroundColor DarkYellow }
if (-not $jobs.Count) { Write-Host '  nothing to do.' -ForegroundColor Yellow; return }

# Largest actors first so one 5,000-hash actor does not become the tail of the run.
$sorted = @($jobs | Sort-Object Rows -Descending)
$plan = @{}
for ($i = 1; $i -le $Workers; $i++) { $plan[$i] = [System.Collections.Generic.List[object]]::new() }
for ($j = 0; $j -lt $sorted.Count; $j++) { $plan[(($j % $Workers) + 1)].Add($sorted[$j]) }

Write-Host ''
foreach ($w in ($plan.Keys | Sort-Object)) {
    $tot = ($plan[$w] | Measure-Object -Property Rows -Sum).Sum
    Write-Host ("  worker {0}: {1,3} actors, {2,7:N0} rows" -f $w, $plan[$w].Count, $tot)
}
Write-Host ''
if ($WhatIfPlan) { Write-Host '  -WhatIfPlan: stopping before launch.' -ForegroundColor Yellow; return }

$workerScript = Join-Path $LogDir 'aptworker.ps1'
@'
param([string]$Repo, [string]$JobFile, [int]$MinDetections)
$ErrorActionPreference = 'Continue'
Set-Location $Repo
Import-Module (Join-Path $Repo 'baseline\VTBaseline.psm1') -Force
Import-Module (Join-Path $Repo 'baseline\targetedMalwareDifferentialAnalysis.psm1') -Force
foreach ($j in (Import-Csv $JobFile)) {
    Write-Host ("=== {0} ({1} rows) ===" -f $j.Actor, $j.Rows)
    $t0 = Get-Date
    try {
        # The store paths are the point: without them this resolves via the VT
        # API on free keys at ~15s per hash.
        Get-TargetedMalwareAnalysis -CsvPath $j.Csv `
            -MaliciousStoragePath $j.Main `
            -BehaviorsStoragePath $j.Beh `
            -MinDetections $MinDetections
        $elf = Join-Path (Split-Path $j.Csv -Parent) 'TargetedElfDifferentialAnalysis.json'
        Write-Host ("  [DONE] {0} in {1:N1} min (ELF file: {2})" -f $j.Actor, ((Get-Date)-$t0).TotalMinutes, (Test-Path $elf))
    } catch {
        Write-Host ("  [FAIL] {0}: {1}" -f $j.Actor, $_.Exception.Message)
    }
}
Write-Host 'WORKER-DONE'
'@ | Set-Content -LiteralPath $workerScript -Encoding UTF8

$procs = @()
foreach ($w in ($plan.Keys | Sort-Object)) {
    if (-not $plan[$w].Count) { continue }
    $jf = Join-Path $LogDir ("job{0}.csv" -f $w)
    $plan[$w] | Select-Object Actor, Csv, Rows, Main, Beh | Export-Csv -LiteralPath $jf -NoTypeInformation
    $log = Join-Path $LogDir ("aptworker{0}.log" -f $w)
    $procs += Start-Process -FilePath 'pwsh' -PassThru -WindowStyle Hidden `
        -ArgumentList @('-NoProfile','-File',$workerScript,'-Repo',$Repo,'-JobFile',$jf,'-MinDetections',$MinDetections) `
        -RedirectStandardOutput $log -RedirectStandardError ($log -replace '\.log$','.err')
    Write-Host ("  launched worker {0} (pid {1})" -f $w, $procs[-1].Id)
}

Write-Host ''
Write-Host ("  waiting for {0} workers..." -f $procs.Count) -ForegroundColor DarkCyan
$t0 = Get-Date
$procs | Wait-Process
$mins = ((Get-Date) - $t0).TotalMinutes

$done = 0; $fail = 0; $withElf = 0
foreach ($l in @(Get-ChildItem (Join-Path $LogDir 'aptworker*.log') -ErrorAction SilentlyContinue)) {
    $t = Get-Content $l.FullName -Raw
    $done += ([regex]::Matches($t, '\[DONE\]')).Count
    $fail += ([regex]::Matches($t, '\[FAIL\]')).Count
    $withElf += ([regex]::Matches($t, 'ELF file: True')).Count
}
Write-Host ''
Write-Host ("  completed {0}, failed {1}, in {2:N1} min" -f $done, $fail, $mins) -ForegroundColor Green
Write-Host ("  actors that now have an ELF differential: {0}" -f $withElf) -ForegroundColor Green
Write-Host "  worker logs: $LogDir" -ForegroundColor DarkCyan
Write-Host ''

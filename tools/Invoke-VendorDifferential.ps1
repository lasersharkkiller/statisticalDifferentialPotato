<#
.SYNOPSIS
    Runs a per-vendor statistical differential: each OT firmware vendor's own
    corpus as the known-good baseline, against the malicious/APT corpus.

.DESCRIPTION
    The corpus-wide baseline is ~86% Siemens, so a global differential
    effectively asks "is this unlike Siemens?". Scoping the baseline to one
    vendor asks the useful question instead: **for an Axis device, which
    malicious capabilities are anomalous against Axis-normal?** That output is
    per-vendor detection content and drops into the vendor's threat brief and
    into PB-11's firmware-drift workflow.

    This is a wrapper, not new analysis: `Get-TargetedMalwareAnalysis` already
    accepts -BaselinePaths / -BaselineBehavePaths, so each vendor run just
    repoints the baseline and gives the run its own output directory (the
    function writes its 13 Targeted*DifferentialAnalysis.json files next to
    the input CSV).

.PARAMETER MinBehaviorsWithData
    Vendors below this many behaviour reports that actually carry data are
    skipped. MEASURED 2026-10-23 across the OT corpus - the limiting resource
    is not hash count, it is behavioural yield, and the two are barely related:

      Tridium   53,093 main -> 12,740 behaviours with data (24.0%)
      Eaton     49,637      ->  6,120 (12.3%)
      Siemens  568,230      ->  3,787 ( 0.67%)   <- 10x the corpus, 1/3 the data
      Mercury        1      ->      0            <- cannot support any statistic

    Six vendors (Inductive, JCI, Schneider, AutomatedLogic, Galaxy, Mercury)
    have under 100. Generating a differential for those produces a file that
    looks authoritative and is arithmetic on noise, so they are skipped by
    default and reported as skipped rather than silently emitted.

.PARAMETER MaxBaselineFiles
    Guard against the Siemens problem. The baseline loader reads every JSON
    with ConvertFrom-Json; at 568,230 files that is impractical in PowerShell.
    Above this count the vendor is reported as needing a sampled run rather
    than being attempted, because a half-finished baseline would silently
    understate rarity (an item absent only because its file was never read
    scores as maximally rare - a false signal, not a missing one).

.EXAMPLE
    .\tools\Invoke-VendorDifferential.ps1 -Vendors Axis -WhatIfPlan
    .\tools\Invoke-VendorDifferential.ps1 -Vendors Axis,Echelon
#>
[CmdletBinding()]
param(
    [string[]]$Vendors,
    [int]$MinBehaviorsWithData = 100,
    [int]$MaxBaselineFiles     = 120000,
    [int]$MinDetections        = 5,
    # Take the ~707 MD5/SHA1 targets that are not yet in the resolution cache.
    # Each costs one free-key API call at ~15s spacing, so this adds hours.
    [switch]$IncludeUnresolvedHashes,
    [string]$Repo              = (Split-Path $PSScriptRoot -Parent),
    [string]$OutRoot           = 'output\vendor-differential',
    # Route the differential's VT calls (hash resolution + behaviour_summary)
    # through VT_Enterprise_Key instead of the free VT_API_Key_1/2. The per-vendor
    # behaviour fetches are what consume the personal/free VT licence; -Enterprise
    # moves them onto the enterprise quota. Default OFF = unchanged free path.
    [switch]$Enterprise,
    [string]$EnterpriseSecretName = 'VT_Enterprise_Key',
    [int]$EnterpriseMinDelayMs    = 50,
    [switch]$WhatIfPlan
)

$ErrorActionPreference = 'Stop'
Set-Location $Repo
Import-Module (Join-Path $Repo 'baseline\targetedMalwareDifferentialAnalysis.psm1') -Force

$mainRoot = 'output-baseline\VirusTotal-main\OT'
$behRoot  = 'output-baseline\VirusTotal-behaviors\OT'
$malMain  = 'output-baseline\VirusTotal-main\malicious'

Write-Host ''
Write-Host '=== Per-vendor statistical differential ===' -ForegroundColor Cyan
Write-Host '  baseline = one vendor''s firmware   target = malicious corpus' -ForegroundColor DarkGray

if (-not (Test-Path $malMain)) { throw "Malicious corpus not found: $malMain" }
$malCount = @([System.IO.Directory]::EnumerateFiles($malMain, '*.json', 'AllDirectories')).Count
Write-Host ("  malicious target corpus: {0:N0} samples" -f $malCount)

# ------------------------------------------------- assess each vendor ---
$cands = @(Get-ChildItem $mainRoot -Directory -ErrorAction SilentlyContinue | Sort-Object Name)
if ($Vendors) { $cands = @($cands | Where-Object { $Vendors -contains $_.Name }) }
if (-not $cands) { Write-Host '  no matching vendors.' -ForegroundColor Yellow; return }

$plan = [System.Collections.Generic.List[object]]::new()
foreach ($v in $cands) {
    $bp = Join-Path $behRoot $v.Name
    $mainN = @([System.IO.Directory]::EnumerateFiles($v.FullName, '*.json', 'AllDirectories')).Count
    $behWithData = 0
    if (Test-Path $bp) {
        # >900 B is a validated proxy for "carries behaviour content" - checked
        # against parsed content on a 400-file sample: 99.1% precision, 98.3% recall.
        foreach ($f in [System.IO.Directory]::EnumerateFiles($bp, '*.json', 'AllDirectories')) {
            if ((Get-Item -LiteralPath $f).Length -gt 900) { $behWithData++ }
        }
    }
    $reason = ''
    if ($behWithData -lt $MinBehaviorsWithData) {
        $reason = "SKIP - only $behWithData behaviour reports with data (need $MinBehaviorsWithData)"
    } elseif ($mainN -gt $MaxBaselineFiles) {
        $reason = "DEFER - $('{0:N0}' -f $mainN) baseline files exceeds $('{0:N0}' -f $MaxBaselineFiles); needs a sampled run"
    }
    # Classify this vendor's baseline platform from a sample of its reports, so
    # the target set can be matched to it. OT baselines are overwhelmingly ELF +
    # config/text; almost none are Windows PE, which is precisely why an
    # unmatched target set produced rarity 100.0 across the board.
    $plat = 'Mixed'
    if ([string]::IsNullOrEmpty($reason)) {
        $files = @([System.IO.Directory]::EnumerateFiles($v.FullName, '*.json', 'AllDirectories'))
        $samp  = @($files | Get-Random -Count ([Math]::Min(400, $files.Count)) -ErrorAction SilentlyContinue)
        $win = 0; $elf = 0; $seen = 0; $withImports = 0
        foreach ($f in $samp) {
            try {
                $a = (Get-Content $f -Raw | ConvertFrom-Json).data.attributes
                $t = $a.type_description
                if (-not $t) { continue }
                $seen++
                if     ($t -match 'Win32|Win64|DOS|MSI|\.NET|Windows') { $win++ }
                elseif ($t -match 'ELF|Linux')                          { $elf++ }
                # A static import differential needs native import tables. Java
                # bytecode, configs and archives have none, whatever their count.
                if ($a.elf_info.import_list -or $a.pe_info.import_list) { $withImports++ }
            } catch {}
        }
        if ($seen -gt 0) {
            $wp = $win / $seen; $ep = $elf / $seen; $ip = $withImports / $seen
            # Gate on IMPORT COVERAGE, not file count. Inductive-Automation has a
            # 13,166-file baseline and 116 behaviour reports with data, so it passed
            # every other check - but it is 94% Java Bytecode with 0% native import
            # tables, so its differential came back with ONE distinct rarity value
            # across 1,186 rows: non-discriminating, i.e. useless. Ignition is a Java
            # platform; there are no native imports to be rare against.
            if ($ip -lt 0.05) {
                $reason = "SKIP - only $([int]($ip*100))% of baseline carries native import tables (Java/config corpus); static differential cannot discriminate"
            }
            # Require a MEANINGFUL fraction before claiming a platform. Without the
            # floor, a single stray ELF file in a 400-sample set classified an entire
            # Java vendor as ELF.
            $plat = if ($wp -ge 0.25 -and $ep -ge 0.10) { 'Mixed' }
                    elseif ($wp -ge 0.05 -and $wp -gt $ep) { 'Windows' }
                    elseif ($ep -ge 0.05)                  { 'ELF' }
                    else                                   { 'Mixed' }
        }
    }
    $plan.Add([pscustomobject]@{
        Vendor = $v.Name; MainFiles = $mainN; BehWithData = $behWithData
        Platform = $plat
        Runnable = [string]::IsNullOrEmpty($reason); Reason = $reason
    })
}

Write-Host ''
Write-Host ('{0,-24} {1,10} {2,12} {3,9}  {4}' -f 'VENDOR','BASELINE','BEHAV+DATA','PLATFORM','STATUS')
foreach ($p in $plan) {
    $status = if ($p.Runnable) { 'run' } else { $p.Reason }
    $colour = if ($p.Runnable) { 'Green' } else { 'DarkYellow' }
    Write-Host ('{0,-24} {1,10:N0} {2,12:N0} {3,9}  {4}' -f $p.Vendor, $p.MainFiles, $p.BehWithData, $p.Platform, $status) -ForegroundColor $colour
}

$runnable = @($plan | Where-Object Runnable)
Write-Host ''
Write-Host ("  runnable: {0} of {1} vendors" -f $runnable.Count, $plan.Count)

# ------------------------------------------------- build target list ---
# Build ONCE and reuse for every vendor: the target set does not vary by vendor,
# only the baseline does.
#
# Why this is filtered rather than "every file in the malicious corpus": the
# corpus is named by whatever hash the source supplied - 17,312 SHA256, 1,313
# MD5, 806 SHA1. The analyser resolves a non-SHA256 input to its canonical
# SHA256 *through the VT API*, and it has no enterprise-key path - it uses the
# free keys at their calibrated ~15s spacing. A naive target list therefore
# spends hours in [Rate Limit] cooldowns before any analysis starts, which is
# exactly what a first attempt did. Measured 2026-10-23:
#   SHA256-named                      17,312  (99.5% already have cached behaviours)
#   MD5/SHA1 already in the resolution cache  1,412  -> free, no API call
#   MD5/SHA1 not yet resolved                   707  -> ~15s each, EXCLUDED
# Excluding those 707 drops 3.6% of targets and removes ~2.5h of serial API
# waiting. Pass -IncludeUnresolvedHashes to take them anyway.
$resolved = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$resPath = 'output\Global_Hash_Resolution.csv'
if (Test-Path $resPath) {
    Import-Csv $resPath | ForEach-Object { if ($_.Input_Hash) { [void]$resolved.Add($_.Input_Hash) } }
}

# --- PLATFORM MATCHING -------------------------------------------------
# The first run of this tool produced a tautology: 100.0% of 17,613 Axis rows
# scored rarity 100.0. Cause - OT vendor baselines are ELF + config/text, while
# the malicious corpus is 57.6% Windows PE. Every Windows API is trivially
# absent from Linux firmware, so "rare" meant "different operating system",
# which is not a finding.
#
# Validated fix (Axis ELF vs malicious ELF, 150 samples each): 28.5% of
# malicious symbols are SHARED with Axis firmware (memmove, strstr, openlog)
# and correctly score low, while 71.5% are malicious-only (gethostbyname,
# putenv, ttyname) and score high. That is a real distribution.
#
# Corpus platform split (output\malicious-platform.csv): Windows 11,129,
# Other 4,693, Script 2,050, ELF 1,462.
$platMap = @{}
$platPath = 'output\malicious-platform.csv'
if (Test-Path $platPath) {
    Import-Csv $platPath | ForEach-Object { if ($_.Hash) { $platMap[$_.Hash] = $_.Platform } }
} else {
    Write-Host "  [WARN] $platPath missing - target set will NOT be platform-matched, which produced a tautology last time." -ForegroundColor Red
}

$script:AllTargets = foreach ($f in [System.IO.Directory]::EnumerateFiles($malMain, '*.json', 'AllDirectories')) {
    $n = [System.IO.Path]::GetFileNameWithoutExtension($f)
    if (-not $n) { continue }
    if ($n.Length -ne 64 -and -not $resolved.Contains($n) -and -not $IncludeUnresolvedHashes) { continue }
    [pscustomobject]@{
        IOCType  = 'Hash'   # must read as Hash - the loader drops unrecognised types silently
        IOCValue = $n
        Date     = (Get-Item -LiteralPath $f).LastWriteTime.ToString('yyyy-MM-dd')
        Platform = $(if ($platMap.ContainsKey($n)) { $platMap[$n] } else { 'Other' })
    }
}
Write-Host ("  resolvable targets: {0:N0}" -f @($script:AllTargets).Count)
@($script:AllTargets) | Group-Object Platform | Sort-Object Count -Descending | ForEach-Object {
    Write-Host ("     {0,-10} {1,7:N0}" -f $_.Name, $_.Count) }

if ($WhatIfPlan) { Write-Host '  -WhatIfPlan: stopping before analysis.' -ForegroundColor Yellow; return }
if (-not $runnable) { return }

# --------------------------------------------------------------- run ---
foreach ($p in $runnable) {
    $outDir = Join-Path $OutRoot $p.Vendor
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

    # Target CSV. IOCType must read as 'Hash' - the loader matches the TYPE column
    # against SHA256|MD5|SHA1|Hash and silently drops rows whose type it cannot
    # recognise, so a wrong header here yields an empty, successful-looking run.
    # Platform-match this vendor's target set to its own baseline. Script and
    # Other are always included: scripts are OS-portable, and Other covers the
    # configs/XML/archives that make up the bulk of every OT baseline.
    $keepPlatforms = switch ($p.Platform) {
        'Windows' { @('Windows','Script','Other') }
        'ELF'     { @('ELF','Script','Other') }
        default   { @('ELF','Windows','Script','Other') }
    }
    $rows = @($script:AllTargets | Where-Object { $keepPlatforms -contains $_.Platform } |
              Select-Object IOCType, IOCValue, Date)
    $csv = Join-Path $outDir 'malicious-targets.csv'
    $rows | Export-Csv -LiteralPath $csv -NoTypeInformation
    Write-Host ("  target set: {0:N0} ({1}-matched: {2})" -f $rows.Count, $p.Platform, ($keepPlatforms -join '+'))

    Write-Host ''
    Write-Host ("--- {0}: baseline {1:N0} files, {2:N0} behaviours with data ---" -f $p.Vendor, $p.MainFiles, $p.BehWithData) -ForegroundColor Cyan
    $t0 = Get-Date
    try {
        Get-TargetedMalwareAnalysis -CsvPath $csv `
            -BaselinePaths       @((Join-Path $mainRoot $p.Vendor)) `
            -BaselineBehavePaths @((Join-Path $behRoot  $p.Vendor)) `
            -MinDetections $MinDetections `
            -Enterprise:$Enterprise -EnterpriseSecretName $EnterpriseSecretName -EnterpriseMinDelayMs $EnterpriseMinDelayMs
        $produced = @(Get-ChildItem $outDir -Filter 'Targeted*DifferentialAnalysis.json' -ErrorAction SilentlyContinue)
        Write-Host ("  [OK] {0} differential files in {1:N1} min -> {2}" -f $produced.Count, ((Get-Date)-$t0).TotalMinutes, $outDir) -ForegroundColor Green
    } catch {
        Write-Host ("  [FAIL] {0}: {1}" -f $p.Vendor, $_.Exception.Message) -ForegroundColor Red
    }
}

Write-Host ''
Write-Host '  Next: fold the per-vendor tables into docs\<vendor>-firmware-threat-brief.md' -ForegroundColor DarkCyan
Write-Host ''

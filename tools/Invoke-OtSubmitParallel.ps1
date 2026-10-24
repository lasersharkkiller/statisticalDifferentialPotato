<#
.SYNOPSIS
    Runs Submit-OtFilesNotInVT across all OT catalogs with N workers in parallel.

.DESCRIPTION
    Submissions are latency-bound, not quota-bound. Measured: a single serial
    worker managed ~49 files/min; six workers reached 385 files/min (7.9x) at
    only ~4% of the 10,000/min enterprise cap, so concurrency is the right lever.

    SHARDING BY DISTINCT HASH. The first version of this script split work by
    *catalog*, which wasted 43% of a run: the same content hash legitimately
    appears in many vendors' firmware, so different workers submitted the same
    file concurrently (21,738 submissions collapsed to 12,769 distinct, and 546
    of them came back HTTP 409 Conflict because VT already had that exact upload
    in flight). This version builds one globally de-duplicated work list, then
    shards it, so a hash is submitted at most once per run.

    Work is written out as per-worker "virtual catalogs" in the normal catalog
    format (Hash,FileName,OsName,FullPath), so Submit-OtFilesNotInVT needs no
    knowledge of sharding. Shards are grouped by vendor because $Vendor decides
    where main/behaviour reports are cached
    (output-baseline\VirusTotal-main\OT\<Vendor>).

    Each worker owns its tracker files via -TrackerSuffix (Export-Csv -Append is
    not safe across processes); the parts are merged back when the run finishes.

.PARAMETER Workers
    Parallel workers. 6 measured ~385 files/min at ~4% of the enterprise cap.

.PARAMETER MaxFileSizeBytes
    Skip anything larger; mirrors Submit-OtFilesNotInVT's own 650MB ceiling so
    the plan does not count files VT will refuse.

.EXAMPLE
    .\tools\Invoke-OtSubmitParallel.ps1 -Workers 10
#>
[CmdletBinding()]
param(
    [int]$Workers              = 6,
    [int]$MinDelayMs           = 12,
    [int64]$MaxFileSizeBytes   = 650MB,
    # Submit only files whose first bytes mark them as a PE or ELF image.
    # MEASURED 2026-10-02 over 308,840 freshly-submitted OT files: overall yield
    # of real behaviour data was 3.0%, but it is entirely file-type bound --
    #   Win32 DLL  88.9% real (5,487 of 6,175)
    #   ELF        31.2% real (2,359 of 7,560)
    #   HTML        0.0% real (0 of 192,800)  <- 62% of everything we sent
    #   PNG/XML/JSON/SVG/CSV/ZLIB/bytecode ~0%
    # PE+ELF were 4.4% of submissions yet produced 86% of all real data, so this
    # filter cuts ~22x the upload volume for ~14% loss of yield. VT only reports
    # type_description after a lookup, so detect locally from magic bytes.
    #
    # Scripts are included as well: they are wanted for analysis, and the measured
    # yield supports it -- Powershell and Shell script came back 100% real, DOS
    # batch 67%, Python 23%. They are also tiny, so they cost almost no bandwidth.
    [switch]$ExecutableOnly,
    # Set -IncludeScripts:$false for strictly PE/ELF binaries.
    [bool]$IncludeScripts = $true,
    [string]$Repo              = (Split-Path $PSScriptRoot -Parent),
    [string]$Staging           = 'C:\githubProjects\firmware-staging',
    [string]$LogDir            = $(Join-Path ([System.IO.Path]::GetTempPath()) 'ot-submit-parallel'),
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

# Script extensions worth analysing. Interpreted content VT does run, plus
# anything an analyst would want to read even if VT never detonates it.
$script:ScriptExtensions = @(
    '.ps1', '.psm1', '.psd1', '.bat', '.cmd', '.vbs', '.vbe', '.wsf', '.wsh', '.hta',
    '.js', '.jse', '.sh', '.bash', '.zsh', '.ksh', '.csh', '.py', '.pyw', '.pl', '.pm',
    '.rb', '.lua', '.php', '.awk', '.tcl', '.r', '.sql', '.reg', '.inf', '.scr'
)

function Test-IsSubmittableForAnalysis {
    # PE ("MZ") or ELF ("ELF") by magic bytes, plus - when -IncludeScripts -
    # scripts by extension or by shebang. Magic bytes are checked rather than
    # extensions for binaries because OT firmware routinely ships unextensioned
    # ELF objects.
    param([string]$Path, [bool]$AllowScripts = $true)
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        try {
            $b = [byte[]]::new(4)
            $read = $fs.Read($b, 0, 4)
        } finally { $fs.Dispose() }
        if ($read -ge 2 -and $b[0] -eq 0x4D -and $b[1] -eq 0x5A) { return $true }    # MZ
        if ($read -ge 4 -and $b[0] -eq 0x7F -and $b[1] -eq 0x45 -and $b[2] -eq 0x4C -and $b[3] -eq 0x46) { return $true }  # ELF
        if (-not $AllowScripts) { return $false }
        if ($script:ScriptExtensions -contains [System.IO.Path]::GetExtension($Path).ToLowerInvariant()) { return $true }
        if ($read -ge 2 -and $b[0] -eq 0x23 -and $b[1] -eq 0x21) { return $true }    # #! shebang
        return $false
    } catch { return $false }
}

Write-Host ""
Write-Host "=== Parallel OT submission: $Workers workers, ${MinDelayMs}ms spacing each ===" -ForegroundColor Cyan

# ------------------------------------------------------- what still needs it ---
$missing = New-HS
$mh = Join-Path $Repo 'output\MissingHashes.csv'
if (Test-Path $mh) { Import-Csv $mh | ForEach-Object { if ($_.Hash) { [void]$missing.Add($_.Hash) } } }

$already = New-HS
foreach ($g in @('output\PendingVTSubmissions*.csv', 'output\metrics\VTSubmissionLedger*.csv')) {
    foreach ($f in @(Get-ChildItem (Join-Path $Repo $g) -ErrorAction SilentlyContinue)) {
        Import-Csv $f.FullName | ForEach-Object { if ($_.Hash) { [void]$already.Add($_.Hash) } }
    }
}
$inVt = New-HS
$mainRoot = Join-Path $Repo 'output-baseline\VirusTotal-main\OT'
if (Test-Path $mainRoot) {
    foreach ($f in [System.IO.Directory]::EnumerateFiles($mainRoot, '*.json', 'AllDirectories')) {
        [void]$inVt.Add([System.IO.Path]::GetFileNameWithoutExtension($f))
    }
}
Write-Host ("  MissingHashes {0:N0} | already submitted/pending {1:N0} | already in VT {2:N0}" -f $missing.Count, $already.Count, $inVt.Count)

# -------------------------------------- one globally de-duplicated work list ---
Write-Host "  building de-duplicated work list across all catalogs..."
$catalogs = @(Get-ChildItem (Join-Path $Staging '*\*\*\catalog.csv') -ErrorAction SilentlyContinue)
$claimed  = New-HS
$byVendor = @{}
$oversize = 0
$noFile   = 0
$notExe   = 0
$symlink  = 0

foreach ($c in $catalogs) {
    $vendor = $c.FullName.Split([char]92)[3]
    foreach ($line in [System.IO.File]::ReadLines($c.FullName)) {
        $i = $line.IndexOf(',')
        if ($i -lt 32) { continue }
        # Catalogs come from two generations: the older ones are unquoted, the
        # ones built with Export-Csv quote every field. Trim so both parse - an
        # unstripped 66-char hash matches nothing in $missing and the path regex
        # never matches a quoted field, which silently skipped whole vendors.
        $h = $line.Substring(0, $i).Trim([char]34)
        if (-not $missing.Contains($h)) { continue }
        if ($already.Contains($h) -or $inVt.Contains($h)) { continue }
        if ($claimed.Contains($h)) { continue }           # another catalog owns it

        $m = [regex]::Match($line, ',"?([A-Za-z]:\\)')
        if (-not $m.Success) { continue }
        $fp = $line.Substring($m.Index + 1).Trim([char]34)
        try {
            $fi = [System.IO.FileInfo]::new($fp)
            if (-not $fi.Exists -or $fi.Length -eq 0) { $noFile++; continue }
            # Extracted Linux rootfs images carry symlinks that Windows materialises
            # as reparse points whose targets do not resolve. FileInfo.Exists is TRUE
            # for them and Length is non-zero, so they pass every other check, then
            # fail at upload with Win32 1920 "cannot be accessed by the system" -
            # which the log reported as "access denied". They have no content to
            # submit, so drop them here instead of burning an upload slot.
            # Measured 2026-10-22: 1,449 of a 6,250-file plan (23%) were these.
            # Only skip a reparse point we actually cannot read - some resolve fine,
            # and a blanket skip would silently drop real content.
            if ($fi.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                $readable = $false
                try { $probe = [System.IO.File]::Open($fp, 'Open', 'Read', 'Read'); $probe.Close(); $readable = $true } catch { }
                if (-not $readable) { $symlink++; [void]$claimed.Add($h); continue }
            }
            if ($fi.Length -gt $MaxFileSizeBytes) { $oversize++; [void]$claimed.Add($h); continue }
            if ($ExecutableOnly -and -not (Test-IsSubmittableForAnalysis -Path $fp -AllowScripts $IncludeScripts)) {
                $notExe++; [void]$claimed.Add($h); continue
            }
        } catch { $noFile++; continue }

        [void]$claimed.Add($h)
        if (-not $byVendor.ContainsKey($vendor)) { $byVendor[$vendor] = [System.Collections.Generic.List[object]]::new() }
        # Rebuild a catalog-format row; FileName/OsName are display-only downstream.
        $byVendor[$vendor].Add([pscustomobject]@{
            Hash = $h; FileName = [System.IO.Path]::GetFileName($fp); OsName = $vendor; FullPath = $fp
        })
    }
}
$total = ($byVendor.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
Write-Host ("  distinct submittable: {0:N0}   (skipped: {1:N0} oversize, {2:N0} unreadable{3})" -f `
    $total, $oversize, $noFile, $(if ($ExecutableOnly) { ", $('{0:N0}' -f $notExe) non-PE/ELF" } else { '' }))
if ($symlink) { Write-Host ("  skipped {0:N0} unreadable symlinks (dangling reparse points in extracted rootfs)" -f $symlink) -ForegroundColor DarkYellow }
if ($ExecutableOnly) {
    Write-Host ("  -ExecutableOnly: PE/ELF{0} (measured 86% of real-behaviour yield from 4.4% of the volume)" -f `
        $(if ($IncludeScripts) { ' + scripts' } else { ' only, scripts excluded' })) -ForegroundColor DarkCyan
}
foreach ($v in ($byVendor.Keys | Sort-Object)) { Write-Host ("     {0,-16} {1,7:N0}" -f $v, $byVendor[$v].Count) }
if (-not $total) { Write-Host "  nothing to submit." -ForegroundColor Green; return }

# ------------------------------------------- shard each vendor across workers ---
$plan = @{}
for ($i = 1; $i -le $Workers; $i++) { $plan[$i] = [System.Collections.Generic.List[object]]::new() }
foreach ($v in ($byVendor.Keys | Sort-Object)) {
    $items = $byVendor[$v]
    for ($j = 0; $j -lt $items.Count; $j++) {
        $w = ($j % $Workers) + 1
        $plan[$w].Add([pscustomobject]@{ Vendor = $v; Row = $items[$j] })
    }
}
Write-Host ""
foreach ($w in ($plan.Keys | Sort-Object)) { Write-Host ("  worker {0}: {1,7:N0} files" -f $w, $plan[$w].Count) }
Write-Host ""
if ($WhatIfPlan) { Write-Host "  -WhatIfPlan: stopping before launch." -ForegroundColor Yellow; return }

# Materialise each worker's shards as one virtual catalog per vendor.
$jobs = @{}
foreach ($w in ($plan.Keys | Sort-Object)) {
    $jobs[$w] = [System.Collections.Generic.List[object]]::new()
    foreach ($grp in ($plan[$w] | Group-Object Vendor)) {
        $shard = Join-Path $LogDir ("shard{0}_{1}.csv" -f $w, ($grp.Name -replace '[^A-Za-z0-9]', '_'))
        @($grp.Group | ForEach-Object { $_.Row }) | Export-Csv -LiteralPath $shard -NoTypeInformation
        $jobs[$w].Add([pscustomobject]@{ Path = $shard; Vendor = $grp.Name; Count = $grp.Count })
    }
}

$workerScript = Join-Path $LogDir 'worker.ps1'
@'
param([string]$Repo, [string]$Suffix, [int]$MinDelayMs, [string]$JobFile)
$ErrorActionPreference = 'Continue'
Set-Location $Repo
Import-Module (Join-Path $Repo 'baseline\OtBaseline.psm1') -Force
$jobs = Import-Csv $JobFile
Write-Host "worker $Suffix : $($jobs.Count) shards"
foreach ($j in $jobs) {
    Write-Host ("  shard {0} ({1} files)" -f $j.Vendor, $j.Count) -ForegroundColor Cyan
    try {
        Submit-OtFilesNotInVT -CatalogCsv $j.Path -Vendor $j.Vendor -Category 'sharded' -Product 'sharded' `
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
                        '-Suffix', (".part{0}" -f $w), '-MinDelayMs', $MinDelayMs, '-JobFile', $jobFile) `
        -RedirectStandardOutput $log -RedirectStandardError ($log -replace '\.log$', '.err')
    Write-Host ("  launched worker {0} (pid {1})" -f $w, $procs[-1].Id)
}

Write-Host ""
Write-Host "  waiting for $($procs.Count) workers..." -ForegroundColor DarkCyan
$t0 = Get-Date
$procs | Wait-Process
$mins = ((Get-Date) - $t0).TotalMinutes
Write-Host ("  all workers finished in {0:N1} min" -f $mins) -ForegroundColor Green

# ------------------------------------------------------------------- merge ---
Write-Host ""
Write-Host "  merging worker trackers..." -ForegroundColor Cyan
function Merge-Parts($mainPath, $globPattern) {
    $parts = @(Get-ChildItem $globPattern -ErrorAction SilentlyContinue)
    if ($parts.Count -eq 0) { return }
    $rows = @(foreach ($p in $parts) { Import-Csv $p.FullName })
    if ($rows.Count -eq 0) { $parts | Remove-Item -Force; return }
    $existing = @(if (Test-Path $mainPath) { Import-Csv $mainPath })
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $keep = @(foreach ($r in @($existing + $rows)) { if ($r.Hash -and $seen.Add($r.Hash)) { $r } })
    $keep | Export-Csv -LiteralPath $mainPath -NoTypeInformation
    Write-Host ("    {0}: {1:N0} existing + {2:N0} new -> {3:N0} rows" -f (Split-Path $mainPath -Leaf), $existing.Count, $rows.Count, $keep.Count)
    $parts | Remove-Item -Force
}
Merge-Parts (Join-Path $Repo 'output\PendingVTSubmissions.csv')       (Join-Path $Repo 'output\PendingVTSubmissions.part*.csv')
Merge-Parts (Join-Path $Repo 'output\metrics\VTSubmissionLedger.csv') (Join-Path $Repo 'output\metrics\VTSubmissionLedger.part*.csv')

$ok = 0; $err = 0
foreach ($l in @(Get-ChildItem (Join-Path $LogDir 'worker*.log'))) {
    $t = Get-Content $l.FullName -Raw
    $ok  += ([regex]::Matches($t, '\[OK\] analysis_id=')).Count
    $err += ([regex]::Matches($t, '\[ERROR\]')).Count
}
Write-Host ""
Write-Host ("  submitted {0:N0}, errors {1:N0}, {2:N0} files/min" -f $ok, $err, ($ok / [math]::Max(0.1, $mins))) -ForegroundColor Green
Write-Host "  worker logs: $LogDir" -ForegroundColor DarkCyan
Write-Host "  Next: tools\Invoke-OtSyncParallel.ps1 to pull main + behaviours." -ForegroundColor DarkCyan
Write-Host ""

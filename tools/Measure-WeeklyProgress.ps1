<#
.SYNOPSIS
    Weekly progress metrics for the VT-baseline / differential-analysis pipeline.

.DESCRIPTION
    Snapshots how much of our firmware corpus VirusTotal knew about before we
    started versus now, how many files we have contributed to VT's baseline, and
    how much behavioural (top-of-pyramid) data that has unlocked.

    One row is written per ISO week to output\metrics\weekly-progress.csv
    (re-running inside the same week replaces that week's row), so the series
    accumulates into a trend. A markdown report is rendered alongside it.

    Attribution of "files we added to VT" comes from
    output\metrics\VTSubmissionLedger.csv, which Submit-OtFilesNotInVT appends to
    at submit time. Rows carry a Provenance column:
      ledger-exact          - recorded by the submitter, authoritative
      inferred-sole-source  - back-filled for pre-ledger weeks, where VT reports
                              unique_sources=1 and first_submission_date falls in
                              a week that was >=95% sole-source (i.e. only we
                              could have introduced those files)

.PARAMETER NoCache
    Force a full re-parse of every behaviour report instead of using the
    incremental cache. The first run is always a full parse.

.EXAMPLE
    .\tools\Measure-WeeklyProgress.ps1
#>
[CmdletBinding()]
param(
    [string]$Repo            = (Split-Path $PSScriptRoot -Parent),
    [string]$FirmwareStaging = 'C:\githubProjects\firmware-staging',
    [switch]$NoCache,
    [switch]$Quiet,
    # Mirrors Submit-OtFilesNotInVT -MaxFileSizeBytes (650MB).
    [int64]$MaxSubmitBytes = 650MB
)

$ErrorActionPreference = 'Stop'
Set-Location $Repo

$metricsDir = Join-Path $Repo 'output\metrics'
if (-not (Test-Path $metricsDir)) { New-Item -ItemType Directory -Path $metricsDir -Force | Out-Null }

$seriesCsv  = Join-Path $metricsDir 'weekly-progress.csv'
$reportMd   = Join-Path $metricsDir 'weekly-progress-report.md'
$behavCache = Join-Path $metricsDir '_behaviour-cache.csv'
$univCache  = Join-Path $metricsDir '_universe-cache.json'
$ledgerCsv  = Join-Path $metricsDir 'VTSubmissionLedger.csv'

$BT      = [char]96   # literal backtick, for markdown code spans
$nowUtc  = [DateTime]::UtcNow
$weekIso = '{0}-W{1:D2}' -f [System.Globalization.ISOWeek]::GetYear($nowUtc), [System.Globalization.ISOWeek]::GetWeekOfYear($nowUtc)

function Say($m, $c = 'Gray') { if (-not $Quiet) { Write-Host $m -ForegroundColor $c } }
function New-HashSet {
    # -NoEnumerate is required: PowerShell unrolls enumerable return values, and
    # an empty HashSet enumerates to nothing, so a bare return yields $null.
    $hs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    Write-Output $hs -NoEnumerate
}

Say ""
Say "=== Weekly progress snapshot: $weekIso ($($nowUtc.ToString('yyyy-MM-dd HH:mm')) UTC) ===" Cyan

# ------------------------------------------------------------- trackers ---
Say "  [1/6] loading trackers..."
$ledger       = @(if (Test-Path $ledgerCsv) { Import-Csv $ledgerCsv })
$ledgerHashes = New-HashSet
$ledgerWeek   = @{}
$ledgerBytes  = 0L
$ledgerBytesWeek = 0L
$submittedThisWeek = 0
foreach ($r in $ledger) {
    if (-not $r.Hash) { continue }
    [void]$ledgerHashes.Add($r.Hash)
    $w = $r.WeekISO
    if ($w) { $ledgerWeek[$w] = [int]$ledgerWeek[$w] + 1 }
    $sz = 0L
    [void][long]::TryParse(("" + $r.SizeBytes), [ref]$sz)
    $ledgerBytes += $sz
    if ($w -eq $weekIso) { $submittedThisWeek++; $ledgerBytesWeek += $sz }
}

$missing = New-HashSet
$mhPath  = Join-Path $Repo 'output\MissingHashes.csv'
if (Test-Path $mhPath) {
    Import-Csv $mhPath | ForEach-Object { if ($_.Hash) { [void]$missing.Add($_.Hash) } }
}

$pendingCount  = 0
$pendingHashes = New-HashSet
$pPath = Join-Path $Repo 'output\PendingVTSubmissions.csv'
if (Test-Path $pPath) {
    $pRows = @(Import-Csv $pPath)
    $pendingCount = $pRows.Count
    foreach ($r in $pRows) { if ($r.Hash) { [void]$pendingHashes.Add($r.Hash) } }
}

# --------------------------------------------------- VT main reports ---
Say "  [2/6] indexing VT main reports..."
$mainOt   = New-HashSet
$mainNsrl = New-HashSet
foreach ($b in @(@{ n = 'OT'; s = $mainOt }, @{ n = 'NSRL'; s = $mainNsrl })) {
    $root = Join-Path $Repo "output-baseline\VirusTotal-main\$($b.n)"
    if (-not (Test-Path $root)) { continue }
    foreach ($f in [System.IO.Directory]::EnumerateFiles($root, '*.json', 'AllDirectories')) {
        [void]$b.s.Add([System.IO.Path]::GetFileNameWithoutExtension($f))
    }
}

# ------------------------------------------- cataloged firmware universe ---
Say "  [3/6] counting distinct hashes across OT catalogs..."
$catalogs = @(Get-ChildItem (Join-Path $FirmwareStaging '*\*\*\catalog.csv') -ErrorAction SilentlyContinue)
$sigText = ($catalogs | Sort-Object FullName |
            ForEach-Object { "$($_.FullName)|$($_.Length)|$($_.LastWriteTimeUtc.Ticks)" }) -join "`n"
$sigHash = [BitConverter]::ToString(
    [System.Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($sigText))
).Replace('-', '')

# The universe hash SET is cached alongside the count. Without the set, the
# "queried" figure (which legitimately contains APT and NSRL hashes too) was
# being divided by the OT-only catalog total and reported 105.75% of universe.
$univSetCache = Join-Path $metricsDir '_universe-hashes.txt'
$universe = $null
$univSet  = $null
if ((Test-Path $univCache) -and (Test-Path $univSetCache) -and -not $NoCache) {
    try {
        $uc = Get-Content $univCache -Raw | ConvertFrom-Json
        if ($uc.Signature -eq $sigHash) {
            $universe = [int]$uc.DistinctHashes
            $univSet  = New-HashSet
            foreach ($line in [System.IO.File]::ReadLines($univSetCache)) { if ($line) { [void]$univSet.Add($line) } }
            Say "        (cached: $universe)" DarkGray
        }
    } catch { $universe = $null; $univSet = $null }
}
if ($null -eq $universe) {
    $univSet = New-HashSet
    foreach ($c in $catalogs) {
        Import-Csv $c.FullName | ForEach-Object { if ($_.Hash) { [void]$univSet.Add($_.Hash) } }
    }
    $universe = $univSet.Count
    [System.IO.File]::WriteAllLines($univSetCache, [string[]]$univSet)
    [pscustomobject]@{ Signature = $sigHash; DistinctHashes = $universe; Catalogs = $catalogs.Count } |
        ConvertTo-Json | Set-Content $univCache -Encoding UTF8
}

# --------------------------------------------- behaviour report corpus ---
Say "  [4/6] scanning behaviour reports (incremental)..."
$cache = @{}
if ((Test-Path $behavCache) -and -not $NoCache) {
    Import-Csv $behavCache | ForEach-Object { $cache[$_.Path] = $_ }
    Say "        cache entries: $($cache.Count)" DarkGray
}

# start of the current ISO week (Monday), for "added this week" counting
$weekStart = $nowUtc.Date
while ($weekStart.DayOfWeek -ne [DayOfWeek]::Monday) { $weekStart = $weekStart.AddDays(-1) }

$stats = @{}
foreach ($n in @('OT', 'NSRL')) { $stats[$n] = @{ total = 0; real = 0 } }
$behavOtHashes = New-HashSet   # hashes with an OT behaviour report pulled
$mitre = New-HashSet
$sigma = New-HashSet
$mbc   = New-HashSet
$highSev = 0
$realThisWeek = 0
$parsed = 0
$fresh = [System.Collections.Generic.List[object]]::new()

foreach ($branch in @('OT', 'NSRL')) {
    $root = Join-Path $Repo "output-baseline\VirusTotal-behaviors\$branch"
    if (-not (Test-Path $root)) { continue }
    foreach ($f in [System.IO.Directory]::EnumerateFiles($root, '*.json', 'AllDirectories')) {
        $fi = [System.IO.FileInfo]::new($f)
        $stats[$branch].total++
        if ($branch -eq 'OT') { [void]$behavOtHashes.Add([System.IO.Path]::GetFileNameWithoutExtension($f)) }

        $hit = $cache[$f]
        if ($hit -and $hit.Ticks -eq "$($fi.LastWriteTimeUtc.Ticks)" -and $hit.Length -eq "$($fi.Length)") {
            $isReal = ($hit.IsReal -eq 'True')
            $mIds = $hit.Mitre; $sIds = $hit.Sigma; $bIds = $hit.Mbc; $hs = [int]$hit.HighSev
        } else {
            $parsed++
            $isReal = $false; $mIds = ''; $sIds = ''; $bIds = ''; $hs = 0
            try {
                $raw = [System.IO.File]::ReadAllText($f)
                # cheap stub test first - most OT reports are {"data": null}
                if ($raw -notmatch '"data"\s*:\s*null') {
                    $d = $raw | ConvertFrom-Json
                    $a = $d.data
                    if ($a -and $a.PSObject.Properties['attributes'] -and $a.attributes) { $a = $a.attributes }
                    if ($a) {
                        $pop = @($a.PSObject.Properties | Where-Object {
                            $null -ne $_.Value -and "$($_.Value)" -ne '' -and
                            -not ($_.Value -is [array] -and $_.Value.Count -eq 0)
                        })
                        if ($pop.Count -gt 0) {
                            $isReal = $true
                            $mIds = (@($a.mitre_attack_techniques | ForEach-Object { $_.id } | Where-Object { $_ }) | Select-Object -Unique) -join ';'
                            $sIds = (@($a.signature_matches        | ForEach-Object { $_.id } | Where-Object { $_ }) | Select-Object -Unique) -join ';'
                            $bIds = (@($a.mbc                      | ForEach-Object { $_.id } | Where-Object { $_ }) | Select-Object -Unique) -join ';'
                            $hs   = @($a.mitre_attack_techniques | Where-Object { "$($_.severity)" -match 'HIGH|CRITICAL' }).Count
                        }
                    }
                }
            } catch { }
            $fresh.Add([pscustomobject]@{
                Path = $f; Ticks = $fi.LastWriteTimeUtc.Ticks; Length = $fi.Length
                IsReal = $isReal; Mitre = $mIds; Sigma = $sIds; Mbc = $bIds; HighSev = $hs
            })
        }

        if ($isReal) {
            $stats[$branch].real++
            $highSev += $hs
            if ($fi.LastWriteTimeUtc -ge $weekStart) { $realThisWeek++ }
            if ($mIds) { foreach ($x in $mIds.Split(';')) { if ($x) { [void]$mitre.Add($x) } } }
            if ($sIds) { foreach ($x in $sIds.Split(';')) { if ($x) { [void]$sigma.Add($x) } } }
            if ($bIds) { foreach ($x in $bIds.Split(';')) { if ($x) { [void]$mbc.Add($x) } } }
        }
    }
}
Say "        parsed this run: $parsed (remainder from cache)" DarkGray

# rewrite the cache: still-valid entries plus freshly parsed ones
$freshPaths = New-HashSet
foreach ($r in $fresh) { [void]$freshPaths.Add($r.Path) }
$keep = @($cache.Values | Where-Object { -not $freshPaths.Contains($_.Path) })
@(@($keep) + @($fresh)) |
    Select-Object Path, Ticks, Length, IsReal, Mitre, Sigma, Mbc, HighSev |
    Export-Csv -Path $behavCache -NoTypeInformation

# ------------------------------------------------------ coverage maths ---
Say "  [5/6] computing coverage..."
# Queried = every OT/firmware hash we have ever asked VT about.
$queried = New-HashSet
foreach ($h in $mainOt)  { [void]$queried.Add($h) }
foreach ($h in $missing) { [void]$queried.Add($h) }
foreach ($r in $ledger)  { if ($r.Branch -eq 'OT' -and $r.Hash) { [void]$queried.Add($r.Hash) } }

$addedByUs = 0
foreach ($h in $ledgerHashes) { if ($mainOt.Contains($h)) { $addedByUs++ } }
$preExisting = 0
foreach ($h in $mainOt) { if (-not $ledgerHashes.Contains($h)) { $preExisting++ } }
$stillMissing = 0
foreach ($h in $missing) { if (-not $mainOt.Contains($h)) { $stillMissing++ } }

# Keep only hashes that are genuinely part of the cataloged OT corpus; $missing
# and $ledger also carry APT and NSRL hashes, which do not belong in an
# OT-coverage denominator.
if ($univSet -and $univSet.Count -gt 0) {
    $queriedOt = New-HashSet
    foreach ($h in $queried) { if ($univSet.Contains($h)) { [void]$queriedOt.Add($h) } }
    Say ("        queried set narrowed to cataloged OT hashes: {0:N0} -> {1:N0}" -f $queried.Count, $queriedOt.Count) DarkGray
    $queried = $queriedOt
}
$q = [math]::Max(1, $queried.Count)
$covBefore = 100.0 * $preExisting / $q
$covNow    = 100.0 * ($preExisting + $addedByUs) / $q

# Everything that has ever come back 404 from VT. Union, not a sum: a submitted
# hash stays in MissingHashes until the sync confirms VT has it, so adding the
# pending/ledger counts to $missing would double-count the overlap.
$everMissing = New-HashSet
foreach ($h in $missing)       { [void]$everMissing.Add($h) }
foreach ($h in $ledgerHashes)  { [void]$everMissing.Add($h) }
foreach ($h in $pendingHashes) { [void]$everMissing.Add($h) }
$notInVtEver = $everMissing.Count

# Behaviour-pull coverage must be a set intersection, not a ratio of file counts:
# the behaviour tree can hold reports whose main report is absent, which produced
# a nonsensical >100% figure.
$behavForInVt = 0
foreach ($h in $behavOtHashes) { if ($mainOt.Contains($h)) { $behavForInVt++ } }
$behavOrphans = $behavOtHashes.Count - $behavForInVt

# Remaining submit backlog: a hash VT still does not have, whose file we can
# actually find on disk, that is not already submitted or in flight. Catalog rows
# are Hash,FileName,OsName,FullPath - unquoted, FullPath last and always starting
# with a drive letter, so we locate it by the ",<drive>:\" marker rather than
# splitting on commas (FileName/OsName may contain them).
Say "        computing submit backlog..."
$backlogSeen = New-HashSet
$backlog = 0
$backlogBytes = 0L
$backlogOversize = 0
foreach ($c in $catalogs) {
    foreach ($line in [System.IO.File]::ReadLines($c.FullName)) {
        $ci = $line.IndexOf(',')
        if ($ci -lt 32) { continue }                       # header or malformed
        $h = $line.Substring(0, $ci)
        if (-not $missing.Contains($h)) { continue }       # VT already has it
        if ($mainOt.Contains($h)) { continue }             # already pulled
        if ($pendingHashes.Contains($h)) { continue }      # in flight
        if ($ledgerHashes.Contains($h)) { continue }       # already submitted
        if (-not $backlogSeen.Add($h)) { continue }        # distinct hashes only
        $m = [regex]::Match($line, ',([A-Za-z]:\\)')
        if (-not $m.Success) { continue }
        $fp = $line.Substring($m.Index + 1)
        try {
            $fi2 = [System.IO.FileInfo]::new($fp)
            if (-not $fi2.Exists -or $fi2.Length -eq 0) { continue }
            # Match Submit-OtFilesNotInVT's ceiling, so the backlog is what can
            # actually be submitted rather than a number inflated by a handful of
            # multi-GB images VT will refuse.
            if ($fi2.Length -gt $MaxSubmitBytes) { $backlogOversize++; continue }
            $backlog++
            $backlogBytes += $fi2.Length
        } catch { }
    }
}

$fidDims = 0
$fidEntries = 0
$manifest = @(
    (Join-Path $Repo 'output-baseline\fidelity-manifest.json'),
    (Join-Path $Repo 'output\fidelity-manifest.json')
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($manifest) {
    try {
        $fm = Get-Content $manifest -Raw | ConvertFrom-Json
        if ($fm.dimension_meta) {
            $props = @($fm.dimension_meta.PSObject.Properties)
            $fidDims = $props.Count
            $sum = ($props | ForEach-Object { [int]$_.Value.entry_count } | Measure-Object -Sum).Sum
            if ($sum) { $fidEntries = [int]$sum }
        }
    } catch { }
}

$row = [pscustomobject]@{
    WeekISO                 = $weekIso
    SnapshotUtc             = $nowUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
    UniverseDistinctHashes  = $universe
    QueriedDistinct         = $queried.Count
    QueriedPctOfUniverse    = [math]::Round(100.0 * $queried.Count / [math]::Max(1, $universe), 2)
    PreExistingInVT         = $preExisting
    NotInVtEver             = $notInVtEver
    AddedByUs               = $addedByUs
    StillMissing            = $stillMissing
    PendingOutstanding      = $pendingCount
    SubmitBacklog           = $backlog
    SubmitBacklogGb         = [math]::Round($backlogBytes / 1GB, 3)
    SubmitBacklogOversize   = $backlogOversize
    OtInVt                  = $mainOt.Count
    BehavPulled             = $behavForInVt
    BehavPullCoveragePct    = [math]::Round(100.0 * $behavForInVt / [math]::Max(1, $mainOt.Count), 2)
    BehavOrphans            = $behavOrphans
    VtCoverageBeforePct     = [math]::Round($covBefore, 2)
    VtCoverageNowPct        = [math]::Round($covNow, 2)
    VtCoverageDeltaPct      = [math]::Round($covNow - $covBefore, 2)
    SubmittedCumulative     = $ledgerHashes.Count
    SubmittedThisWeek       = $submittedThisWeek
    SubmittedGbCumulative   = [math]::Round($ledgerBytes / 1GB, 3)
    SubmittedGbThisWeek     = [math]::Round($ledgerBytesWeek / 1GB, 3)
    OtBehavTotal            = $stats['OT'].total
    OtBehavReal             = $stats['OT'].real
    OtBehavRealPct          = [math]::Round(100.0 * $stats['OT'].real / [math]::Max(1, $stats['OT'].total), 2)
    NsrlBehavTotal          = $stats['NSRL'].total
    NsrlBehavReal           = $stats['NSRL'].real
    NsrlBehavRealPct        = [math]::Round(100.0 * $stats['NSRL'].real / [math]::Max(1, $stats['NSRL'].total), 2)
    RealBehavAddedThisWeek  = $realThisWeek
    DistinctMitreTechniques = $mitre.Count
    DistinctSigmaRules      = $sigma.Count
    DistinctMbcBehaviours   = $mbc.Count
    HighSevTechniqueHits    = $highSev
    FidelityDimensions      = $fidDims
    FidelityEntries         = $fidEntries
}

# -------------------------------------------------- upsert the series ---
Say "  [6/6] writing series + report..."
$series = @(if (Test-Path $seriesCsv) { Import-Csv $seriesCsv })
$series = @(@($series | Where-Object { $_.WeekISO -ne $weekIso }) + @($row)) | Sort-Object WeekISO
$series | Export-Csv -Path $seriesCsv -NoTypeInformation

# ----------------------------------------------------------- markdown ---
function Get-Delta($cur, $prev, $fmt = 'N0') {
    if ($null -eq $prev -or "$prev" -eq '') { return '' }
    $d = [double]$cur - [double]$prev
    if ([math]::Abs($d) -lt 0.005) { return '--' }
    $sign = if ($d -gt 0) { '+' } else { '-' }
    "$sign$([math]::Abs($d).ToString($fmt))"
}
function Add-MetricRows($sb, $defs, $cur, $prv) {
    foreach ($m in $defs) {
        $v = $cur.($m[1])
        $p = if ($prv) { $prv.($m[1]) } else { $null }
        [void]$sb.AppendLine("| $($m[0]) | $(([double]$v).ToString($m[2])) | $(Get-Delta $v $p $m[2]) |")
    }
}

$prev = if (@($series).Count -ge 2) { @($series)[-2] } else { $null }
$md = [System.Text.StringBuilder]::new()

[void]$md.AppendLine('# Weekly progress - VT baseline & differential analysis')
[void]$md.AppendLine('')
$hdr = "**Week $weekIso** | snapshot $($nowUtc.ToString('yyyy-MM-dd HH:mm')) UTC | "
$hdr += if ($prev) { "previous: $($prev.WeekISO)" } else { 'first snapshot' }
[void]$md.AppendLine($hdr)
[void]$md.AppendLine('')

[void]$md.AppendLine('## 1. Submitting files VirusTotal did not have')
[void]$md.AppendLine('')
[void]$md.AppendLine('Every file that comes back 404 is one VT has never seen. Submitting it is what')
[void]$md.AppendLine('makes a behaviour report possible at all, and extends VT''s own baseline.')
[void]$md.AppendLine('')
[void]$md.AppendLine('| Metric | Value | vs prev |')
[void]$md.AppendLine('|---|---:|---:|')
Add-MetricRows $md @(
    @('Distinct hashes cataloged (universe)', 'UniverseDistinctHashes', 'N0'),
    @('Queried against VT',                   'QueriedDistinct',        'N0'),
    @('Not in VT when queried (404)',         'NotInVtEver',            'N0'),
    @('**Submitted by us, cumulative**',      'SubmittedCumulative',    'N0'),
    @('Submitted this week',                  'SubmittedThisWeek',      'N0'),
    @('GB submitted, cumulative',             'SubmittedGbCumulative',  'N3'),
    @('Confirmed added to VT',                'AddedByUs',              'N0'),
    @('Awaiting analysis',                    'PendingOutstanding',     'N0'),
    @('**Still to submit (backlog)**',        'SubmitBacklog',          'N0'),
    @('Backlog GB',                           'SubmitBacklogGb',        'N3'),
    @('Too large for VT (excluded)',          'SubmitBacklogOversize',  'N0')
) $row $prev
[void]$md.AppendLine('')
if ($ledgerWeek.Count) {
    [void]$md.AppendLine('<details><summary>Submissions by week</summary>')
    [void]$md.AppendLine('')
    [void]$md.AppendLine('| Week | Files |')
    [void]$md.AppendLine('|---|---:|')
    foreach ($k in ($ledgerWeek.Keys | Sort-Object)) {
        [void]$md.AppendLine("| $k | $(([int]$ledgerWeek[$k]).ToString('N0')) |")
    }
    [void]$md.AppendLine('')
    [void]$md.AppendLine('</details>')
    [void]$md.AppendLine('')
}

[void]$md.AppendLine('## 2. Pulling behaviour reports for the files VirusTotal does have')
[void]$md.AppendLine('')
[void]$md.AppendLine('A behaviour report only exists if VT actually detonated the file. Reports that come')
[void]$md.AppendLine("back as ${BT}{`"data`": null}${BT} stubs are counted separately, because only the real ones")
[void]$md.AppendLine("turn ${BT}G=0${BT} (never observed) into genuine known-good evidence.")
[void]$md.AppendLine('')
[void]$md.AppendLine('| Metric | Value | vs prev |')
[void]$md.AppendLine('|---|---:|---:|')
Add-MetricRows $md @(
    @('OT files VT has (main reports pulled)', 'OtInVt',                 'N0'),
    @('Behaviour reports pulled',              'BehavPulled',            'N0'),
    @('Behaviour pull coverage %',             'BehavPullCoveragePct',   'N2'),
    @('**With real behaviour data**',          'OtBehavReal',            'N0'),
    @('Real as % of pulled',                   'OtBehavRealPct',         'N2'),
    @('**Real reports added this week**',      'RealBehavAddedThisWeek', 'N0'),
    @('NSRL behaviour reports pulled',         'NsrlBehavTotal',         'N0'),
    @('NSRL with real behaviour data',         'NsrlBehavReal',          'N0'),
    @('NSRL % real',                           'NsrlBehavRealPct',       'N2')
) $row $prev
[void]$md.AppendLine('')

[void]$md.AppendLine('## 3. Pyramid-of-pain yield (distinct TTPs observed)')
[void]$md.AppendLine('')
[void]$md.AppendLine('| Metric | Value | vs prev |')
[void]$md.AppendLine('|---|---:|---:|')
Add-MetricRows $md @(
    @('Distinct MITRE ATT&CK techniques', 'DistinctMitreTechniques', 'N0'),
    @('Distinct VT signature rules',      'DistinctSigmaRules',      'N0'),
    @('Distinct MBC behaviours',          'DistinctMbcBehaviours',   'N0'),
    @('High/critical technique hits',     'HighSevTechniqueHits',    'N0'),
    @('Fidelity index dimensions',        'FidelityDimensions',      'N0'),
    @('Fidelity index entries',           'FidelityEntries',         'N0')
) $row $prev
[void]$md.AppendLine('')

if (@($series).Count -ge 2) {
    [void]$md.AppendLine('## Trend')
    [void]$md.AppendLine('')
    [void]$md.AppendLine('| Week | Submitted (cum.) | Backlog | Behav. pulled | Real behav. | MITRE techniques |')
    [void]$md.AppendLine('|---|---:|---:|---:|---:|---:|')
    foreach ($s in @($series)) {
        [void]$md.AppendLine("| $($s.WeekISO) | $(([double]$s.SubmittedCumulative).ToString('N0')) | $(([double]$s.SubmitBacklog).ToString('N0')) | $(([double]$s.BehavPulled).ToString('N0')) | $(([double]$s.OtBehavReal).ToString('N0')) | $(([double]$s.DistinctMitreTechniques).ToString('N0')) |")
    }
    [void]$md.AppendLine('')
}

[void]$md.AppendLine('---')
[void]$md.AppendLine('')
[void]$md.AppendLine("*Series: ${BT}output\metrics\weekly-progress.csv${BT}. Submissions are recorded at submit")
[void]$md.AppendLine("time in ${BT}output\metrics\VTSubmissionLedger.csv${BT}. Regenerate with menu option 3b.*")

$md.ToString() | Set-Content $reportMd -Encoding UTF8

# ------------------------------------------------------------ console ---
Say ''
Say '  1. Submitting files VT did not have' Cyan
Say ("    queried against VT        : {0,10:N0}  ({1}% of {2:N0} cataloged)" -f $queried.Count, $row.QueriedPctOfUniverse, $universe)
Say ("    not in VT when queried    : {0,10:N0}" -f $notInVtEver)
Say ("    submitted by us           : {0,10:N0}  ({1} GB; {2:N0} this week)" -f $ledgerHashes.Count, $row.SubmittedGbCumulative, $submittedThisWeek) Green
Say ("    confirmed added to VT     : {0,10:N0}" -f $addedByUs) Green
Say ("    awaiting analysis         : {0,10:N0}" -f $pendingCount)
Say ("    STILL TO SUBMIT           : {0,10:N0}  ({1} GB)" -f $backlog, $row.SubmitBacklogGb) Yellow
if ($backlogOversize -gt 0) {
    Say ("    (too large for VT         : {0,10:N0}  over {1:N0}MB)" -f $backlogOversize, ($MaxSubmitBytes / 1MB)) DarkYellow
}
Say ''
Say '  2. Behaviour reports for files VT does have' Cyan
Say ("    OT files VT has           : {0,10:N0}" -f $mainOt.Count)
Say ("    behaviour reports pulled  : {0,10:N0}  ({1}% of those)" -f $behavForInVt, $row.BehavPullCoveragePct)
if ($behavOrphans -gt 0) {
    Say ("    (orphan behav. reports    : {0,10:N0}  no main report on disk)" -f $behavOrphans) DarkYellow
}
Say ("    with REAL behaviour data  : {0,10:N0}  ({1}% of pulled)" -f $stats['OT'].real, $row.OtBehavRealPct) Green
Say ("    real added this week      : {0,10:N0}" -f $realThisWeek) Green
Say ("    NSRL real behaviours      : {0,10:N0} / {1:N0}  ({2}%)" -f $stats['NSRL'].real, $stats['NSRL'].total, $row.NsrlBehavRealPct)
Say ''
Say '  3. TTP yield' Cyan
Say ("    distinct MITRE techniques : {0,10:N0}" -f $mitre.Count)
Say ("    distinct signature rules  : {0,10:N0}" -f $sigma.Count)
Say ''
Say "  series : $seriesCsv" DarkCyan
Say "  report : $reportMd" DarkCyan
Say ''

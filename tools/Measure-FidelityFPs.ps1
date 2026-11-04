#Requires -Version 6.0
<#
.SYNOPSIS
    Re-measure the known-FP set against a fidelity-index.json to check whether
    Fixes 1-5 (case-sensitivity, Score100 consumer, NSRL common-software corpus,
    Alt-A Bayesian prior) have actually cleared the observed false positives.

.NOTES
    Requires PowerShell 6.0+ for `ConvertFrom-Json -AsHashtable`. Windows
    PowerShell 5.1 does not support that flag; run under pwsh (Core / 7+).

.DESCRIPTION
    Loads the fidelity-index.json (default: elasticPotato/output-baseline/
    fidelity-index.json), looks up each FP by both the raw and lowercased key,
    and prints M / G / S / Score100 / Score100_AltA / U / R / L for each.

    Classes:
      UNIQUE-FP  (G=0 today): expected to clear once NSRL common-software
                              corpus adds Firefox/NSS/UCRT hashes.
      RARE-FP    (LOLBins):   expected to survive corpus fix; killed by
                              Score100 read + Confidence gate, or by Alt-A
                              prior once process-baseline is populated.

    Snapshot support: -SaveSnapshot dumps current results to
    tools\fidelity-fps-snapshot.json alongside the script. -PriorRunJson loads
    a previous snapshot and prints DELTA (which FPs cleared since last run).

.PARAMETER FidelityIndexPath
    Path to fidelity-index.json. Default: c:\githubProjects\elasticPotato\
    output-baseline\fidelity-index.json.

.PARAMETER ExtraFPs
    Additional artifact strings to report on beyond the built-in FP list.

.PARAMETER PriorRunJson
    Path to a prior snapshot JSON to compute delta against.

.PARAMETER SaveSnapshot
    Save results to tools\fidelity-fps-snapshot.json next to this script.

.EXAMPLE
    .\tools\Measure-FidelityFPs.ps1
    Baseline reading; no snapshot saved.

.EXAMPLE
    .\tools\Measure-FidelityFPs.ps1 -SaveSnapshot
    Baseline reading, saves snapshot. Run again after rebuild to diff.

.EXAMPLE
    .\tools\Measure-FidelityFPs.ps1 -PriorRunJson tools\fidelity-fps-snapshot.json
    Compare against the saved snapshot; print CLEARED / STILL_FP / NEW deltas.
#>
[CmdletBinding()]
param(
    [string]$FidelityIndexPath = 'c:\githubProjects\elasticPotato\output-baseline\fidelity-index.json',
    [string[]]$ExtraFPs = @(),
    [string]$PriorRunJson,
    [switch]$SaveSnapshot,
    # The flat fidelity-index.json collapses 'dim|value' to bare 'value' and on
    # cross-dimension collision keeps the highest-RiskScore entry (see the
    # comment at Build-VTFidelityIndex.psm1 ~L1238). So an artifact that exists
    # in several dimensions -- csc.exe is in process, file and
    # command-execution -- is reported from WHICHEVER dimension won the
    # tie-break in that build. When the ordering shifts between builds the
    # reported M/G change wholesale with no underlying change to the feature,
    # which makes flat-index deltas order-dependent. -PerDimension additionally
    # loads every fidelity-<dim>.json named in the manifest and reports the
    # artifact's entry in each dimension, so a comparison is reproducible.
    [switch]$PerDimension
)

$ErrorActionPreference = 'Stop'

# ---------- FP catalog ---------------------------------------------------------
# Extracted from user 2026-07-22 screenshot + researcher notes.
$Catalog = @(
    [pscustomobject]@{ Class = 'UNIQUE-FP'; Artifact = 'private_browsing.exe' }
    [pscustomobject]@{ Class = 'UNIQUE-FP'; Artifact = 'plugin-container.exe' }
    [pscustomobject]@{ Class = 'UNIQUE-FP'; Artifact = 'libEGL.dll' }
    [pscustomobject]@{ Class = 'UNIQUE-FP'; Artifact = 'softokn3.dll' }
    [pscustomobject]@{ Class = 'UNIQUE-FP'; Artifact = 'nss3.dll' }
    [pscustomobject]@{ Class = 'UNIQUE-FP'; Artifact = 'taskhostw.exe' }
    [pscustomobject]@{ Class = 'UNIQUE-FP'; Artifact = 'setup.exe' }
    [pscustomobject]@{ Class = 'UNIQUE-FP'; Artifact = 'api-ms-win-crt-multibyte-l1-1-0.dll' }
    [pscustomobject]@{ Class = 'UNIQUE-FP'; Artifact = 'crashreporter.exe' }
    [pscustomobject]@{ Class = 'UNIQUE-FP'; Artifact = 'freebl3.dll' }
    [pscustomobject]@{ Class = 'RARE-FP';   Artifact = 'csc.exe' }
    [pscustomobject]@{ Class = 'RARE-FP';   Artifact = 'cvtres.exe' }
    [pscustomobject]@{ Class = 'RARE-FP';   Artifact = 'regsvr32.exe' }
    [pscustomobject]@{ Class = 'RARE-FP';   Artifact = 'netstat.exe' }
    [pscustomobject]@{ Class = 'RARE-FP';   Artifact = 'find.exe' }
)
foreach ($e in $ExtraFPs) {
    if ($e) { $Catalog += [pscustomobject]@{ Class = 'EXTRA'; Artifact = $e } }
}

# ---------- Load index ---------------------------------------------------------
if (-not (Test-Path -LiteralPath $FidelityIndexPath)) {
    Write-Error "Fidelity index not found: $FidelityIndexPath"
    return
}

Write-Host "Loading fidelity index (this can take a few seconds for 37MB)..." -ForegroundColor DarkCyan
$idxRaw = Get-Content -LiteralPath $FidelityIndexPath -Raw -Encoding UTF8
$idx    = $idxRaw | ConvertFrom-Json -AsHashtable
Write-Host ("  {0:N0} entries loaded from {1}" -f $idx.Count, $FidelityIndexPath) -ForegroundColor DarkGray

# Per-dimension indices, loaded from the dims named in the manifest beside the
# flat index. Needed because the flat shim is dimension-lossy (see -PerDimension).
$dimIdx = [ordered]@{}
if ($PerDimension) {
    $baseDir      = Split-Path -Parent (Resolve-Path -LiteralPath $FidelityIndexPath)
    $manifestPath = Join-Path $baseDir 'fidelity-manifest.json'
    $dimNames = @()
    if (Test-Path -LiteralPath $manifestPath) {
        try {
            $mf = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json -AsHashtable
            if ($mf.dimension_meta) { $dimNames = @($mf.dimension_meta.Keys) }
        } catch { Write-Warning "Manifest unreadable: $manifestPath" }
    }
    if (-not $dimNames -or $dimNames.Count -eq 0) {
        $dimNames = @(Get-ChildItem -LiteralPath $baseDir -Filter 'fidelity-*.json' -ErrorAction SilentlyContinue |
                      Where-Object { $_.Name -notmatch 'manifest|^fidelity-index' } |
                      ForEach-Object { $_.BaseName -replace '^fidelity-','' })
        Write-Warning "No dimension_meta in manifest; falling back to $($dimNames.Count) fidelity-*.json files on disk."
    }
    foreach ($d in ($dimNames | Sort-Object)) {
        $f = Join-Path $baseDir ("fidelity-{0}.json" -f $d)
        if (-not (Test-Path -LiteralPath $f)) { continue }
        try { $dimIdx[$d] = (Get-Content -LiteralPath $f -Raw | ConvertFrom-Json -AsHashtable) } catch { continue }
    }
    Write-Host ("  {0} per-dimension indices loaded" -f $dimIdx.Count) -ForegroundColor DarkGray
}
Write-Host ""

# ---------- Prior snapshot (optional) -----------------------------------------
$prior = $null
if ($PriorRunJson) {
    if (Test-Path -LiteralPath $PriorRunJson) {
        try {
            $prior = Get-Content -LiteralPath $PriorRunJson -Raw | ConvertFrom-Json -AsHashtable
        } catch {
            Write-Warning "Prior snapshot unreadable: $PriorRunJson - continuing without delta."
        }
    } else {
        Write-Warning "Prior snapshot not found: $PriorRunJson - continuing without delta."
    }
}

# ---------- Look up each FP ---------------------------------------------------
$results = [System.Collections.Generic.List[object]]::new()
foreach ($cat in $Catalog) {
    $a = $cat.Artifact
    $e = $null
    # ConvertFrom-Json -AsHashtable in PowerShell 7+ returns a CASE-SENSITIVE
    # OrderedHashtable (unlike a plain @{} which is case-insensitive). The
    # builder writes lowercase for process/file/module/registry/service/
    # scheduled-task/dns/vt-tag; also try the raw form for cert/mitre/mutex
    # dims that preserve case at write time.
    if     ($idx.ContainsKey($a.ToLowerInvariant()))  { $e = $idx[$a.ToLowerInvariant()] }
    elseif ($idx.ContainsKey($a))                     { $e = $idx[$a] }

    $obj = [ordered]@{
        Artifact       = $a
        Class          = $cat.Class
        Found          = ($null -ne $e)
        M              = if ($e) { [int]$e.M } else { $null }
        G              = if ($e) { [int]$e.G } else { $null }
        # M/G are per-sample document frequency as of 2026-09-26. M_obs/G_obs are
        # the raw occurrence counts M/G used to carry, kept so a pre-fix snapshot
        # can be compared against a post-fix one without misreading the delta.
        M_obs          = if ($e -and $e.ContainsKey('M_obs')) { [int]$e.M_obs } else { $null }
        G_obs          = if ($e -and $e.ContainsKey('G_obs')) { [int]$e.G_obs } else { $null }
        Phase2         = if ($e -and $e.ContainsKey('Phase2')) { [bool]$e.Phase2 } else { $null }
        # Which dimension the flat shim actually resolved to. Without this a
        # delta between two builds cannot be told apart from the tie-break
        # picking a different dimension.
        Dimension      = if ($e -and $e.ContainsKey('Dimension')) { "$($e.Dimension)" } else { $null }
        PerDim         = @()
        S              = if ($e) { $e.S } else { $null }
        Score100       = if ($e -and $e.ContainsKey('Score100')) { [int]$e.Score100 } else { $null }
        Score100_AltA  = if ($e -and $e.ContainsKey('Score100_AltA')) { [int]$e.Score100_AltA } else { $null }
        AltAPrior_PB   = if ($e -and $e.ContainsKey('AltAPrior_PB')) { [int]$e.AltAPrior_PB } else { $null }
        U              = if ($e) { [bool]$e.U } else { $null }
        R              = if ($e) { [bool]$e.R } else { $null }
        LegitParents   = @()
    }
    # Coerce L into a name list regardless of shape. Historical fidelity-
    # index.json entries encode L as:
    #   * empty OrderedHashtable `{}`  (most common; no legit parents)
    #   * string array `["nvm.exe", ...]`
    #   * hashtable of name -> count `{"nvm.exe":5, ...}`
    # ConvertFrom-Json -AsHashtable deserializes {} as an empty
    # OrderedHashtable, so `if ($e.L)` alone is truthy and would print the
    # type name if we don't check .Count / shape.
    if ($e -and $e.L) {
        $L = $e.L
        $names = @()
        if ($L -is [System.Collections.IDictionary]) {
            if ($L.Count -gt 0) { $names = @($L.Keys) }
        } elseif ($L -is [System.Collections.IEnumerable] -and $L -isnot [string]) {
            $names = @($L | Where-Object { $_ -and ($_ -isnot [System.Collections.IDictionary]) })
        }
        $obj['LegitParents'] = @($names | Select-Object -First 3)
    }
    # Status derived from the flags. Use Score100_AltA when present, else Score100, else S.
    if (-not $e) {
        $obj['Status'] = 'NOT_IN_INDEX'
    } elseif ($e.U -eq $true) {
        $obj['Status'] = 'STILL_FP_UNIQUE'
    } elseif ($e.R -eq $true) {
        $obj['Status'] = 'STILL_FP_RARE'
    } else {
        $obj['Status'] = 'CLEARED'
    }
    # Per-dimension breakdown: the dimension-correct view the flat shim cannot
    # give. Each row is one dimension that genuinely contains this artifact.
    if ($PerDimension -and $dimIdx.Count -gt 0) {
        $rows = [System.Collections.Generic.List[object]]::new()
        foreach ($d in $dimIdx.Keys) {
            $di = $dimIdx[$d]
            $de = $null
            if     ($di.ContainsKey($a.ToLowerInvariant())) { $de = $di[$a.ToLowerInvariant()] }
            elseif ($di.ContainsKey($a))                    { $de = $di[$a] }
            if ($null -eq $de) { continue }
            $rows.Add([pscustomobject]@{
                Dim      = $d
                M        = [int]$de.M
                G        = [int]$de.G
                M_obs    = if ($de.ContainsKey('M_obs')) { [int]$de.M_obs } else { $null }
                G_obs    = if ($de.ContainsKey('G_obs')) { [int]$de.G_obs } else { $null }
                Score100 = if ($de.ContainsKey('Score100')) { [int]$de.Score100 } else { $null }
                VP       = if ($de.ContainsKey('VerdictPoints')) { [int]$de.VerdictPoints } else { $null }
                Phase2   = if ($de.ContainsKey('Phase2')) { [bool]$de.Phase2 } else { $null }
            })
        }
        $obj.PerDim = @($rows)
    }
    $results.Add([pscustomobject]$obj)
}

# ---------- Print --------------------------------------------------------------
$statusColor = @{
    'CLEARED'         = 'Green'
    'STILL_FP_UNIQUE' = 'Red'
    'STILL_FP_RARE'   = 'Yellow'
    'NOT_IN_INDEX'    = 'DarkGray'
}

Write-Host ("{0,-42} {1,-10} {2,4} {3,4} {4,5} {5,5} {6,-15} {7}" -f `
    'Artifact','Class','M','G','S','S100','Status','LegitParents') -ForegroundColor Cyan
Write-Host ('-' * 130) -ForegroundColor DarkGray

foreach ($r in $results) {
    $legit = ($r.LegitParents -join ',')
    if ($legit.Length -gt 50) { $legit = $legit.Substring(0, 47) + '...' }
    # Pre-compute each field. Using inline `if`-as-expression inside a multi-
    # line -f arg list confuses the PS 5.1 parser at runtime (it tries to
    # execute `if` as a cmdlet). Assigning first via if works cleanly.
    # Render as "df/obs" when the occurrence counts are present and differ, so a
    # feature inflated by one chatty sample is visible at a glance.
    $mStr = if ($null -ne $r.M) {
        if ($null -ne $r.M_obs -and $r.M_obs -ne $r.M) { "$($r.M)/$($r.M_obs)" } else { "$($r.M)" }
    } else { '-' }
    $gStr = if ($null -ne $r.G) {
        if ($null -ne $r.G_obs -and $r.G_obs -ne $r.G) { "$($r.G)/$($r.G_obs)" } else { "$($r.G)" }
    } else { '-' }
    $sStr = if ($null -ne $r.S) { "$([int]$r.S)" } else { '-' }
    $s100Str = if ($null -ne $r.Score100) {
        "$($r.Score100)"
    } elseif ($null -ne $r.Score100_AltA) {
        "$($r.Score100_AltA)*"
    } else { '-' }
    $p2Str = if ($r.Phase2) { 'P2 ' } else { '' }
    $line = "{0,-42} {1,-10} {2,9} {3,9} {4,5} {5,5} {6,-15} {7}{8}" -f `
        $r.Artifact, $r.Class, $mStr, $gStr, $sStr, $s100Str, $r.Status, $p2Str, $legit
    Write-Host $line -ForegroundColor $statusColor[$r.Status]
    # Dimension-correct rows. Multiple rows here means the flat-index numbers
    # above are one arbitrary pick among them.
    if ($PerDimension -and $r.PerDim -and @($r.PerDim).Count -gt 0) {
        foreach ($pd in @($r.PerDim)) {
            $mo = if ($null -ne $pd.M_obs) { "/$($pd.M_obs)" } else { '' }
            $go = if ($null -ne $pd.G_obs) { "/$($pd.G_obs)" } else { '' }
            $p2 = if ($pd.Phase2) { ' PHASE2' } else { '' }
            Write-Host ("      - {0,-18} M={1}{2} G={3}{4} S100={5} VP={6}{7}" -f `
                $pd.Dim, $pd.M, $mo, $pd.G, $go, $pd.Score100, $pd.VP, $p2) -ForegroundColor DarkGray
        }
        if (@($r.PerDim).Count -gt 1) {
            Write-Host ("      ! present in {0} dimensions - flat-index row above is one arbitrary pick" -f @($r.PerDim).Count) -ForegroundColor DarkYellow
        }
    }
}

# ---------- Summary ------------------------------------------------------------
$cleared     = @($results | Where-Object { $_.Status -eq 'CLEARED' }).Count
$stillUnique = @($results | Where-Object { $_.Status -eq 'STILL_FP_UNIQUE' }).Count
$stillRare   = @($results | Where-Object { $_.Status -eq 'STILL_FP_RARE' }).Count
$notInIdx    = @($results | Where-Object { $_.Status -eq 'NOT_IN_INDEX' }).Count
$total       = $results.Count

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host ("CLEARED         : {0} / {1}" -f $cleared,     $total) -ForegroundColor Green
Write-Host ("STILL_FP_UNIQUE : {0}" -f $stillUnique)         -ForegroundColor Red
Write-Host ("STILL_FP_RARE   : {0}" -f $stillRare)           -ForegroundColor Yellow
Write-Host ("NOT_IN_INDEX    : {0}" -f $notInIdx)            -ForegroundColor DarkGray

# ---------- Delta vs prior snapshot -------------------------------------------
if ($prior) {
    Write-Host ""
    Write-Host "=== Delta vs prior snapshot ===" -ForegroundColor Cyan
    $priorByArt = @{}
    foreach ($p in $prior.results) { $priorByArt[$p.Artifact] = $p }
    $deltas = 0
    foreach ($r in $results) {
        $pr = $priorByArt[$r.Artifact]
        if (-not $pr) { continue }
        if ($pr.Status -ne $r.Status) {
            $deltas++
            $arrow = if ($r.Status -eq 'CLEARED') { '>>>' } else { '!!!' }
            Write-Host ("  {0} {1,-42} {2} -> {3}" -f $arrow, $r.Artifact, $pr.Status, $r.Status) `
                -ForegroundColor $statusColor[$r.Status]
        }
    }
    if ($deltas -eq 0) { Write-Host "  (no status changes)" -ForegroundColor DarkGray }
}

# ---------- Save snapshot -----------------------------------------------------
if ($SaveSnapshot) {
    $snapPath = Join-Path $PSScriptRoot 'fidelity-fps-snapshot.json'
    $snap = [pscustomobject]@{
        Timestamp = (Get-Date).ToString('o')
        Source    = $FidelityIndexPath
        Summary   = [pscustomobject]@{
            Cleared         = $cleared
            StillFPUnique   = $stillUnique
            StillFPRare     = $stillRare
            NotInIndex      = $notInIdx
            Total           = $total
        }
        results   = $results
    }
    $snap | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $snapPath -Encoding UTF8
    Write-Host ""
    Write-Host ("Snapshot saved: {0}" -f $snapPath) -ForegroundColor DarkGreen
}

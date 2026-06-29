function Build-OTGlobalThreatDashboard {
    <#
    .SYNOPSIS
        Builds a single-page OT Global Threat Dashboard summarizing baseline
        coverage + verdict distribution + MITRE ATT&CK ICS overlap with the
        cataloged malware corpus, organized by Purdue Model layer.

    .DESCRIPTION
        Cross-cuts every dataset under output-baseline/VirusTotal-main and
        VirusTotal-behaviors and emits an interactive HTML dashboard
        (Bootstrap 5 + Chart.js) with the following panels:

          - Hero KPIs: total baseline hashes, % cached, total verdicts
          - Per-Purdue-layer stacked bar (Clean / Suspicious / Unknown /
            Malicious counts)
          - Per-dataset cards (hash counts, verdict pie, Purdue layer tag,
            primary use case from the per-vendor brief)
          - VT coverage burndown (cached vs remaining per dataset)
          - MITRE ATT&CK ICS overlap heatmap: techniques observed in
            baseline only (GREEN), in both baseline + malware corpus
            (YELLOW = ambiguity), or malware-corpus-only (RED = clean
            detection signal)
          - IOC anchor density: per-vendor count of patched-good firmware
            baselines (e.g., Maple cMT EasyWeb security patches that fix
            ICSA-21-082-01)
          - Top 20 most-common MITRE techniques in OT baselines
          - Top 20 most-common parent processes across L3 datasets
            (informational baseline that the Capability Matrix will drill
            into)

        Dataset-to-Purdue-layer mapping is driven from the per-vendor
        threat briefs (docs/<vendor>-firmware-threat-brief.md). Datasets
        that genuinely span multiple layers are tagged with their primary
        layer plus a secondary list.

        Malware corpus comparison source:
          apt/Malware Families/<Family>/TargetedMitreDifferentialAnalysis.json
          apt/APTs/<APT>/TargetedMitreDifferentialAnalysis.json

    .PARAMETER BaselineRoot
        Root of the offline VT baseline. Default: output-baseline.

    .PARAMETER AptRoot
        Root of the APT / malware family folder tree.
        Default: apt (with subfolders APTs/ and Malware Families/).

    .PARAMETER OutputPath
        Path of the output HTML file.
        Default: output-baseline/visualizations/ot-global-threat-dashboard.html.

    .PARAMETER CatalogRoot
        firmware-staging root, used to compute total catalog hash counts
        per vendor (cached + remaining = total catalog). Default:
        ../../firmware-staging.

    .PARAMETER Force
        Regenerate even if existing HTML is newer than every input.

    .EXAMPLE
        Import-Module .\agentic\Build-OTGlobalThreatDashboard.psm1
        Build-OTGlobalThreatDashboard

    .EXAMPLE
        Build-OTGlobalThreatDashboard -Force
    #>
    [CmdletBinding()]
    param(
        [string] $BaselineRoot = 'output-baseline',
        [string] $AptRoot      = 'apt',
        [string] $OutputPath   = 'output-baseline/visualizations/ot-global-threat-dashboard.html',
        [string] $CatalogRoot  = '../../firmware-staging',
        [switch] $Force
    )

    # ----- Path resolution ---------------------------------------------------
    if (-not [System.IO.Path]::IsPathRooted($BaselineRoot)) {
        $BaselineRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\$BaselineRoot"))
    }
    if (-not [System.IO.Path]::IsPathRooted($AptRoot)) {
        $AptRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\$AptRoot"))
    }
    if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
        $OutputPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\$OutputPath"))
    }
    if (-not [System.IO.Path]::IsPathRooted($CatalogRoot)) {
        $CatalogRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot $CatalogRoot))
    }

    $mainRoot = Join-Path $BaselineRoot 'VirusTotal-main'
    $behRoot  = Join-Path $BaselineRoot 'VirusTotal-behaviors'
    $outDir   = Split-Path $OutputPath -Parent

    if (-not (Test-Path $mainRoot)) { Write-Error "VT-main root not found: $mainRoot"; return }
    if (-not (Test-Path $behRoot))  { Write-Error "VT-behaviors root not found: $behRoot"; return }
    if (-not (Test-Path $outDir))   { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }

    Write-Host "`n[Build-OTGlobalThreatDashboard] BaselineRoot = $BaselineRoot" -ForegroundColor DarkCyan
    Write-Host "[Build-OTGlobalThreatDashboard] OutputPath   = $OutputPath" -ForegroundColor DarkCyan

    # ----- Dataset -> Purdue-layer mapping (from per-vendor briefs) ----------
    # Primary layer per dataset, with secondary if the vendor genuinely
    # spans multiple layers (per the briefs in docs/).
    $purdueMap = @{
        'NSRL/Windows-11'           = @{ Primary='L4'; Secondary=@('L3','L3.5'); Note='Admin workstations + EWS hosts' }
        'NSRL/Windows-Server-2025'  = @{ Primary='L3'; Secondary=@();             Note='SCADA / Historian / EWS server tier' }
        'NSRL/Ubuntu-24.04'         = @{ Primary='L3'; Secondary=@();             Note='Linux SCADA control center (Ignition, etc.)' }
        'NSRL/Debian-13'            = @{ Primary='L3'; Secondary=@();             Note='Linux server tier (limited corpus)' }
        'OT/Eaton'                  = @{ Primary='L3.5'; Secondary=@('PowerInfra'); Note='NMCs (L3.5) + bare-metal UPS MCUs (PowerInfra)' }
        'OT/APC'                    = @{ Primary='L3.5'; Secondary=@('L3','PowerInfra'); Note='NMCs (L3.5) + PowerChute (L3) + Smart-UPS MCU (PowerInfra)' }
        'OT/Vertiv'                 = @{ Primary='L3.5'; Secondary=@('PowerInfra'); Note='Avocent ACS + IntelliSlot (L3.5) + Liebert MCU (PowerInfra)' }
        'OT/SEL'                    = @{ Primary='L3'; Secondary=@('L1');         Note='Industrial PCs + engineering SW (L3) + relays/RTAC (L1, pending)' }
        'OT/Siemens'                = @{ Primary='L3'; Secondary=@('L1','L3.5'); Note='TIA Portal + WinCC (L3) + S7 PLCs (L1) + SCALANCE (L3.5)' }
        'OT/Inductive-Automation'   = @{ Primary='L3'; Secondary=@();             Note='Ignition Gateway (water-utility SCADA reference)' }
        'OT/Maple-Systems'          = @{ Primary='L2'; Secondary=@('L3');         Note='cMT HMI panels (L2) + EBPro/MAPware design tools (L3)' }
        'OT/Red-Lion'               = @{ Primary='L2'; Secondary=@('L1','L3');   Note='Graphite HMI (L2) + Sixnet RTU (L1) + Crimson (L3)' }
    }

    $layerColors = @{
        'L1'         = '#dc2626'  # red — controllers (lowest, highest consequence)
        'L2'         = '#ea580c'  # orange — area supervisory
        'L3'         = '#ca8a04'  # amber — site operations
        'L3.5'       = '#2563eb'  # blue — IT/OT boundary
        'L4'         = '#7c3aed'  # purple — corporate IT
        'PowerInfra' = '#0d9488'  # teal — power infrastructure cross-cut
        'Safety'     = '#dc2626'  # red — safety systems (parallel to L1)
    }

    # ----- Walk datasets, gather VT-main + verdict + behavior MITRE -----------
    $datasetStats  = @()  # array of pscustomobject per dataset
    $allMitreBase  = @{}  # MITRE technique ID -> count across all OT/NSRL baselines
    $allParentsL3  = @{}  # parent process -> count across L3-tagged datasets
    $allVerdicts   = @{ Clean=0; Suspicious=0; Malicious=0; Unknown=0 }

    foreach ($bucket in @('NSRL','OT')) {
        $bucketRoot = Join-Path $mainRoot $bucket
        if (-not (Test-Path $bucketRoot)) { continue }
        foreach ($dsDir in (Get-ChildItem -LiteralPath $bucketRoot -Directory -ErrorAction SilentlyContinue)) {
            $slug = "$bucket/$($dsDir.Name)"
            # -Recurse: NSRL nests one level deeper than OT
            # (<OsName>/<SignerCategory>/<hash>.json — categories are
            # SignedVerified / unsignedWin / unsignedLinux / unverified /
            # drivers per the Build-VTFidelityIndex convention).
            $mainFiles = @(Get-ChildItem -LiteralPath $dsDir.FullName -Filter '*.json' -File -Recurse -ErrorAction SilentlyContinue)
            if ($mainFiles.Count -eq 0) { continue }

            $behDsDir = Join-Path (Join-Path $behRoot $bucket) $dsDir.Name
            $behFiles = if (Test-Path $behDsDir) {
                @(Get-ChildItem -LiteralPath $behDsDir -Filter '*.json' -File -Recurse -ErrorAction SilentlyContinue)
            } else { @() }

            Write-Host ("  walking $slug : $($mainFiles.Count) main / $($behFiles.Count) behaviors") -ForegroundColor DarkGray

            $clean=0; $susp=0; $mal=0; $unk=0
            $mitreInDs = New-Object System.Collections.Generic.HashSet[string]
            $isL3 = $purdueMap.ContainsKey($slug) -and ($purdueMap[$slug].Primary -eq 'L3' -or $purdueMap[$slug].Secondary -contains 'L3')

            # Verdict + signer pass over VT-main
            foreach ($f in $mainFiles) {
                try {
                    $j = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    $attrs = if ($j.data -is [System.Object[]]) { $j.data[0].attributes } else { $j.data.attributes }
                    if ($null -eq $attrs) { $unk++; continue }
                    $mc = 0
                    if ($attrs.last_analysis_stats -and $attrs.last_analysis_stats.malicious) {
                        $mc = [int]$attrs.last_analysis_stats.malicious
                    }
                    if     ($mc -ge 5) { $mal++ }
                    elseif ($mc -ge 1) { $susp++ }
                    elseif ($null -ne $attrs.last_analysis_stats) { $clean++ }
                    else { $unk++ }
                } catch { $unk++ }
            }

            # MITRE + parent-process pass over VT-behaviors
            foreach ($f in $behFiles) {
                try {
                    if ($f.Length -gt 50MB) { continue }
                    $j = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    $d = if ($j.data -is [System.Object[]]) { $j.data[0] } else { $j.data }
                    if ($null -eq $d) { continue }
                    if ($d.mitre_attack_techniques) {
                        foreach ($t in $d.mitre_attack_techniques) {
                            if ($t.id) {
                                [void]$mitreInDs.Add([string]$t.id)
                                $allMitreBase[[string]$t.id] = ($allMitreBase[[string]$t.id] | ForEach-Object { if ($_) { $_ } else { 0 } }) + 1
                            }
                        }
                    }
                    if ($isL3 -and $d.processes_tree) {
                        foreach ($p in $d.processes_tree) {
                            if ($p.name) {
                                $allParentsL3[[string]$p.name] = ($allParentsL3[[string]$p.name] | ForEach-Object { if ($_) { $_ } else { 0 } }) + 1
                            }
                        }
                    }
                } catch { }
            }

            $allVerdicts.Clean      += $clean
            $allVerdicts.Suspicious += $susp
            $allVerdicts.Malicious  += $mal
            $allVerdicts.Unknown    += $unk

            # Catalog total for this dataset (OT: from firmware-staging; NSRL: from nsrl_reduced.csv)
            $catalogTotal = 0
            if ($bucket -eq 'OT') {
                $vendorDir = Join-Path $CatalogRoot $dsDir.Name
                if (Test-Path $vendorDir) {
                    $catFiles = Get-ChildItem -LiteralPath $vendorDir -Filter 'catalog.csv' -Recurse -ErrorAction SilentlyContinue
                    $uniq = New-Object System.Collections.Generic.HashSet[string]
                    foreach ($c in $catFiles) {
                        try {
                            Import-Csv -LiteralPath $c.FullName | ForEach-Object {
                                if ($_.Hash) { [void]$uniq.Add($_.Hash.ToLowerInvariant()) }
                            }
                        } catch { }
                    }
                    $catalogTotal = $uniq.Count
                }
            } else {
                # NSRL: count rows in nsrl_reduced.csv whose OsName matches
                $nsrlCsv = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\NSRL\nsrl_reduced.csv'))
                if (Test-Path $nsrlCsv) {
                    # Best-effort substring match on dataset slug
                    $needle = $dsDir.Name -replace '-',' ' -replace '_',' '
                    $count = 0
                    Import-Csv -LiteralPath $nsrlCsv | ForEach-Object {
                        if ($_.OsName -and $_.OsName -like "*$needle*") { $count++ }
                    }
                    $catalogTotal = $count
                }
            }

            $purdue = if ($purdueMap.ContainsKey($slug)) { $purdueMap[$slug] } else { @{ Primary='L?'; Secondary=@(); Note='' } }
            $datasetStats += [pscustomobject]@{
                Bucket         = $bucket
                Dataset        = $dsDir.Name
                Slug           = $slug
                Cached         = $mainFiles.Count
                BehCached      = $behFiles.Count
                CatalogTotal   = $catalogTotal
                Remaining      = [Math]::Max(0, $catalogTotal - $mainFiles.Count)
                Clean          = $clean
                Suspicious     = $susp
                Malicious      = $mal
                Unknown        = $unk
                MitreTechIds   = @($mitreInDs)
                PurduePrimary  = $purdue.Primary
                PurdueSecondary= $purdue.Secondary
                PurdueNote     = $purdue.Note
            }
        }
    }

    # ----- Walk apt/ for malware-corpus MITRE comparison ---------------------
    Write-Host "`n  walking apt/ for malware-corpus MITRE ..." -ForegroundColor DarkGray
    $aptMitreCorpus = @{}   # techniqueId -> count of malware/APT folders that observe it
    $aptFamilyCount = 0
    foreach ($subdir in @('Malware Families','APTs')) {
        $rootSub = Join-Path $AptRoot $subdir
        if (-not (Test-Path $rootSub)) { continue }
        foreach ($famDir in (Get-ChildItem -LiteralPath $rootSub -Directory -ErrorAction SilentlyContinue)) {
            $mitreJson = Join-Path $famDir.FullName 'TargetedMitreDifferentialAnalysis.json'
            if (-not (Test-Path $mitreJson)) { continue }
            $aptFamilyCount++
            try {
                $rows = Get-Content -LiteralPath $mitreJson -Raw | ConvertFrom-Json
                foreach ($r in $rows) {
                    if ($r.Item_Name) {
                        # Malware corpus stores Item_Name as "T1016: get socket status" —
                        # the T-code is the prefix, the rest is a free-form sandbox-detector
                        # signature description. Extract just the T-code so this matches
                        # the baseline format (which is just "T1016").
                        $raw = [string]$r.Item_Name
                        $techId = if ($raw -match '^(T\d+(?:\.\d+)?)') { $matches[1] } else { $raw }
                        $aptMitreCorpus[$techId] = ($aptMitreCorpus[$techId] | ForEach-Object { if ($_) { $_ } else { 0 } }) + 1
                    }
                }
            } catch { }
        }
    }
    Write-Host ("  apt/ walked: {0} families/APTs, {1} unique MITRE techniques in malware corpus" -f $aptFamilyCount, $aptMitreCorpus.Count) -ForegroundColor DarkGray

    # ----- Aggregate per-Purdue-layer counts ---------------------------------
    $layerAggregate = @{}
    foreach ($ds in $datasetStats) {
        $layer = $ds.PurduePrimary
        if (-not $layerAggregate.ContainsKey($layer)) {
            $layerAggregate[$layer] = @{ Clean=0; Suspicious=0; Malicious=0; Unknown=0; HashCount=0; DatasetCount=0 }
        }
        $layerAggregate[$layer].Clean       += $ds.Clean
        $layerAggregate[$layer].Suspicious  += $ds.Suspicious
        $layerAggregate[$layer].Malicious   += $ds.Malicious
        $layerAggregate[$layer].Unknown     += $ds.Unknown
        $layerAggregate[$layer].HashCount   += $ds.Cached
        $layerAggregate[$layer].DatasetCount++
    }

    # ----- MITRE overlap categorization --------------------------------------
    $mitreBaseSet    = New-Object System.Collections.Generic.HashSet[string]
    foreach ($k in $allMitreBase.Keys) { [void]$mitreBaseSet.Add($k) }
    $mitreMalSet     = New-Object System.Collections.Generic.HashSet[string]
    foreach ($k in $aptMitreCorpus.Keys) { [void]$mitreMalSet.Add($k) }

    $mitreOnlyBase   = $mitreBaseSet | Where-Object { -not $mitreMalSet.Contains($_) }
    $mitreBoth       = $mitreBaseSet | Where-Object { $mitreMalSet.Contains($_) }
    $mitreOnlyMal    = $mitreMalSet  | Where-Object { -not $mitreBaseSet.Contains($_) }

    # ----- Build JSON payload for the HTML ----------------------------------
    $payload = [ordered]@{
        generatedAt    = (Get-Date).ToString('s')
        totals         = [ordered]@{
            datasets         = $datasetStats.Count
            cachedHashes     = ($datasetStats | Measure-Object -Property Cached -Sum).Sum
            behHashes        = ($datasetStats | Measure-Object -Property BehCached -Sum).Sum
            catalogHashes    = ($datasetStats | Measure-Object -Property CatalogTotal -Sum).Sum
            remainingHashes  = ($datasetStats | Measure-Object -Property Remaining -Sum).Sum
            verdicts         = $allVerdicts
            aptFamilies      = $aptFamilyCount
            uniqueMitreBase  = $mitreBaseSet.Count
            uniqueMitreMal   = $mitreMalSet.Count
        }
        layers         = $layerAggregate
        layerColors    = $layerColors
        datasets       = $datasetStats | ForEach-Object {
            [ordered]@{
                slug           = $_.Slug
                bucket         = $_.Bucket
                dataset        = $_.Dataset
                cached         = $_.Cached
                behCached      = $_.BehCached
                catalogTotal   = $_.CatalogTotal
                remaining      = $_.Remaining
                clean          = $_.Clean
                suspicious     = $_.Suspicious
                malicious      = $_.Malicious
                unknown        = $_.Unknown
                purduePrimary  = $_.PurduePrimary
                purdueSecondary= $_.PurdueSecondary
                purdueNote     = $_.PurdueNote
                mitreTechCount = $_.MitreTechIds.Count
            }
        }
        mitre          = [ordered]@{
            onlyBaseline = @($mitreOnlyBase | Sort-Object)
            both         = @($mitreBoth | Sort-Object)
            onlyMalware  = @($mitreOnlyMal | Sort-Object)
            topBaseline  = ($allMitreBase.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 20 |
                              ForEach-Object { @{ id=$_.Key; count=$_.Value } })
            topMalware   = ($aptMitreCorpus.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 20 |
                              ForEach-Object { @{ id=$_.Key; count=$_.Value } })
        }
        topParentsL3   = ($allParentsL3.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 20 |
                          ForEach-Object { @{ name=$_.Key; count=$_.Value } })
    }

    $payloadJson = $payload | ConvertTo-Json -Depth 10 -Compress

    # ----- Render HTML -------------------------------------------------------
    $html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<title>OT Global Threat Dashboard</title>
<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css' rel='stylesheet'>
<style>
  body { background:#f8f9fa; font-family:'Segoe UI',system-ui,sans-serif; padding:24px; }
  .kpi { background:#fff; border-radius:8px; padding:20px; box-shadow:0 1px 3px rgba(0,0,0,.06); text-align:center; }
  .kpi-value { font-size:2rem; font-weight:600; color:#1f2937; }
  .kpi-label { color:#6b7280; font-size:.85rem; text-transform:uppercase; letter-spacing:.5px; margin-top:4px; }
  .panel { background:#fff; border-radius:8px; padding:20px; box-shadow:0 1px 3px rgba(0,0,0,.06); margin-bottom:20px; }
  .panel h2 { font-size:1.15rem; font-weight:600; color:#1f2937; margin-bottom:6px; }
  .panel-sub { color:#6b7280; font-size:.85rem; margin-bottom:16px; }
  .layer-pill { display:inline-block; padding:2px 8px; border-radius:4px; color:#fff; font-size:.75rem; font-weight:600; margin-right:4px; }
  .ds-card { background:#fff; border-radius:8px; padding:14px; box-shadow:0 1px 3px rgba(0,0,0,.06); height:100%; }
  .ds-card h3 { font-size:1rem; font-weight:600; margin-bottom:4px; color:#1f2937; }
  .ds-card .ds-meta { color:#6b7280; font-size:.78rem; }
  .ds-card .ds-stats { font-size:.85rem; color:#374151; margin-top:8px; }
  .verdict-clean { color:#15803d; font-weight:600; }
  .verdict-susp  { color:#b45309; font-weight:600; }
  .verdict-mal   { color:#b91c1c; font-weight:600; }
  .verdict-unk   { color:#1e40af; font-weight:600; }
  .breadcrumb-bar { background:#e5e7eb; padding:8px 16px; border-radius:6px; font-size:.85rem; color:#374151; margin-bottom:16px; }
  .mitre-chip { display:inline-block; padding:3px 7px; margin:2px; border-radius:3px; font-size:.72rem; font-family:'Consolas','Monaco',monospace; }
  .mitre-base { background:#dcfce7; color:#15803d; border:1px solid #86efac; }
  .mitre-both { background:#fef3c7; color:#92400e; border:1px solid #fcd34d; }
  .mitre-mal  { background:#fee2e2; color:#991b1b; border:1px solid #fca5a5; }
  details summary { cursor:pointer; padding:4px 0; font-weight:600; color:#374151; }
  small.muted { color:#6b7280; }
</style>
</head>
<body>

<div class='breadcrumb-bar'>OT Global Threat Dashboard &nbsp; · &nbsp; generated <span id='gen-date'></span> &nbsp; · &nbsp; cross-vendor baseline coverage</div>

<!-- Hero KPIs -->
<div class='row g-3 mb-4'>
  <div class='col-md-2 col-6'><div class='kpi'><div class='kpi-value' id='kpi-datasets'>0</div><div class='kpi-label'>Datasets</div></div></div>
  <div class='col-md-2 col-6'><div class='kpi'><div class='kpi-value' id='kpi-cached'>0</div><div class='kpi-label'>Cached (VT)</div></div></div>
  <div class='col-md-2 col-6'><div class='kpi'><div class='kpi-value' id='kpi-catalog'>0</div><div class='kpi-label'>Catalog Total</div></div></div>
  <div class='col-md-2 col-6'><div class='kpi'><div class='kpi-value' id='kpi-remaining'>0</div><div class='kpi-label'>Remaining</div></div></div>
  <div class='col-md-2 col-6'><div class='kpi'><div class='kpi-value' id='kpi-mitre-base'>0</div><div class='kpi-label'>MITRE Techniques (baseline)</div></div></div>
  <div class='col-md-2 col-6'><div class='kpi'><div class='kpi-value' id='kpi-apt'>0</div><div class='kpi-label'>Malware/APT corpus</div></div></div>
</div>

<!-- Two-column charts -->
<div class='row g-3 mb-4'>
  <div class='col-md-6'>
    <div class='panel'>
      <h2>Per-Purdue-layer verdict distribution</h2>
      <div class='panel-sub'>Stacked bar: cached binaries per Purdue layer, broken out by verdict (Clean / Suspicious / Unknown / Malicious). Tall green = good coverage of the layer with confidently-clean references.</div>
      <canvas id='chart-purdue' height='220'></canvas>
    </div>
  </div>
  <div class='col-md-6'>
    <div class='panel'>
      <h2>VT coverage burndown (per dataset)</h2>
      <div class='panel-sub'>Cached vs Remaining hashes. Hover for the exact split. Bars sorted by Remaining (descending) — the next-priority pulls are at the top.</div>
      <canvas id='chart-burndown' height='220'></canvas>
    </div>
  </div>
</div>

<!-- MITRE overlap -->
<div class='panel'>
  <h2>MITRE ATT&amp;CK ICS overlap: baseline ∩ malware corpus</h2>
  <div class='panel-sub'>Green = technique observed ONLY in known-good baseline (clean detection signal — if you see this in live telemetry from a non-baselined binary, that's a strong anomaly). Yellow = observed in BOTH (ambiguity zone — needs context to interpret). Red = observed ONLY in cataloged malware/APT corpus (high-confidence malware indicator).</div>
  <div class='row mb-2'>
    <div class='col-md-4'><div class='text-center'><div style='font-size:1.5rem;font-weight:600;color:#15803d'><span id='mitre-base-only'>0</span></div><div class='text-muted small'>baseline-only</div></div></div>
    <div class='col-md-4'><div class='text-center'><div style='font-size:1.5rem;font-weight:600;color:#92400e'><span id='mitre-both'>0</span></div><div class='text-muted small'>both (ambiguity zone)</div></div></div>
    <div class='col-md-4'><div class='text-center'><div style='font-size:1.5rem;font-weight:600;color:#991b1b'><span id='mitre-mal-only'>0</span></div><div class='text-muted small'>malware-only</div></div></div>
  </div>
  <details><summary>Show technique IDs (click)</summary>
    <div class='mt-2'>
      <strong style='color:#15803d'>Baseline-only (clean detection signal)</strong><br><div id='mitre-list-base'></div>
      <hr>
      <strong style='color:#92400e'>Both (ambiguity zone — context-dependent)</strong><br><div id='mitre-list-both'></div>
      <hr>
      <strong style='color:#991b1b'>Malware-only (high-confidence indicator)</strong><br><div id='mitre-list-mal'></div>
    </div>
  </details>
</div>

<!-- Top MITRE in baseline -->
<div class='row g-3 mb-4'>
  <div class='col-md-6'>
    <div class='panel'>
      <h2>Top 20 MITRE techniques in OT/NSRL baseline</h2>
      <div class='panel-sub'>Most-frequently-observed MITRE ATT&amp;CK ICS techniques across all known-good binaries. These are the "normal envelope" techniques that legitimate OT software triggers in VT sandbox.</div>
      <canvas id='chart-mitre-top-base' height='320'></canvas>
    </div>
  </div>
  <div class='col-md-6'>
    <div class='panel'>
      <h2>Top 20 MITRE techniques in malware corpus</h2>
      <div class='panel-sub'>Most-frequently-observed techniques across cataloged malware families + APTs. Cross-reference with the baseline panel left — overlapping techniques are the "valid-cred abuse" risk surface.</div>
      <canvas id='chart-mitre-top-mal' height='320'></canvas>
    </div>
  </div>
</div>

<!-- Per-dataset cards -->
<div class='panel'>
  <h2>Per-dataset baseline coverage</h2>
  <div class='panel-sub'>One card per dataset. Verdict counts + cached/remaining + Purdue layer tag from the per-vendor brief.</div>
  <div class='row g-3' id='ds-grid'></div>
</div>

<!-- Top parents L3 -->
<div class='panel'>
  <h2>Top 20 parent processes across L3 baselines</h2>
  <div class='panel-sub'>What launches binaries at the L3 Site Operations tier. This is the legitimate parent-process envelope — the Capability Matrix (next visualization) will drill into per-binary expected parents.</div>
  <canvas id='chart-parents' height='320'></canvas>
</div>

<script src='https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js'></script>
<script>
const DATA = $payloadJson;

document.getElementById('gen-date').textContent = DATA.generatedAt.replace('T',' ').substring(0,16);
document.getElementById('kpi-datasets').textContent = DATA.totals.datasets.toLocaleString();
document.getElementById('kpi-cached').textContent = DATA.totals.cachedHashes.toLocaleString();
document.getElementById('kpi-catalog').textContent = DATA.totals.catalogHashes.toLocaleString();
document.getElementById('kpi-remaining').textContent = DATA.totals.remainingHashes.toLocaleString();
document.getElementById('kpi-mitre-base').textContent = DATA.totals.uniqueMitreBase.toLocaleString();
document.getElementById('kpi-apt').textContent = DATA.totals.aptFamilies.toLocaleString();

// MITRE overlap counts
document.getElementById('mitre-base-only').textContent = DATA.mitre.onlyBaseline.length.toLocaleString();
document.getElementById('mitre-both').textContent = DATA.mitre.both.length.toLocaleString();
document.getElementById('mitre-mal-only').textContent = DATA.mitre.onlyMalware.length.toLocaleString();

function chipList(ids, cls) {
  return ids.map(id => '<span class="mitre-chip mitre-' + cls + '">' + id + '</span>').join('');
}
document.getElementById('mitre-list-base').innerHTML = chipList(DATA.mitre.onlyBaseline, 'base');
document.getElementById('mitre-list-both').innerHTML = chipList(DATA.mitre.both, 'both');
document.getElementById('mitre-list-mal').innerHTML  = chipList(DATA.mitre.onlyMalware, 'mal');

// Per-Purdue-layer stacked bar
const layerOrder = ['L1','L2','L3','L3.5','L4','PowerInfra','L?'];
const layerLabels = layerOrder.filter(l => DATA.layers[l]);
new Chart(document.getElementById('chart-purdue'), {
  type: 'bar',
  data: {
    labels: layerLabels,
    datasets: [
      { label:'Clean',      data: layerLabels.map(l => DATA.layers[l].Clean),      backgroundColor:'#86efac' },
      { label:'Suspicious', data: layerLabels.map(l => DATA.layers[l].Suspicious), backgroundColor:'#fcd34d' },
      { label:'Unknown',    data: layerLabels.map(l => DATA.layers[l].Unknown),    backgroundColor:'#c7d2fe' },
      { label:'Malicious',  data: layerLabels.map(l => DATA.layers[l].Malicious),  backgroundColor:'#fca5a5' }
    ]
  },
  options: { responsive:true, scales:{ x:{ stacked:true }, y:{ stacked:true } } }
});

// Burndown bar (sorted by remaining desc)
const sortedDs = DATA.datasets.slice().sort((a,b)=>b.remaining-a.remaining);
new Chart(document.getElementById('chart-burndown'), {
  type: 'bar',
  data: {
    labels: sortedDs.map(d => d.slug),
    datasets: [
      { label:'Cached',    data: sortedDs.map(d => d.cached),    backgroundColor:'#86efac' },
      { label:'Remaining', data: sortedDs.map(d => d.remaining), backgroundColor:'#cbd5e1' }
    ]
  },
  options: { responsive:true, indexAxis:'y', scales:{ x:{ stacked:true }, y:{ stacked:true } } }
});

// Top MITRE bars
new Chart(document.getElementById('chart-mitre-top-base'), {
  type: 'bar',
  data: {
    labels: DATA.mitre.topBaseline.map(t => t.id),
    datasets: [{ label:'Observations in baseline', data: DATA.mitre.topBaseline.map(t => t.count), backgroundColor:'#86efac' }]
  },
  options: { responsive:true, indexAxis:'y' }
});
new Chart(document.getElementById('chart-mitre-top-mal'), {
  type: 'bar',
  data: {
    labels: DATA.mitre.topMalware.map(t => t.id),
    datasets: [{ label:'Families observing technique', data: DATA.mitre.topMalware.map(t => t.count), backgroundColor:'#fca5a5' }]
  },
  options: { responsive:true, indexAxis:'y' }
});

// Top parents L3 bar
new Chart(document.getElementById('chart-parents'), {
  type: 'bar',
  data: {
    labels: DATA.topParentsL3.map(p => p.name),
    datasets: [{ label:'Observations across L3 baselines', data: DATA.topParentsL3.map(p => p.count), backgroundColor:'#c7d2fe' }]
  },
  options: { responsive:true, indexAxis:'y' }
});

// Per-dataset cards
const grid = document.getElementById('ds-grid');
DATA.datasets.sort((a,b)=>b.cached-a.cached).forEach(d => {
  const layerColor = DATA.layerColors[d.purduePrimary] || '#6b7280';
  const secondaryPills = (d.purdueSecondary || []).map(l =>
    '<span class="layer-pill" style="background:'+(DATA.layerColors[l]||'#9ca3af')+'">'+l+'</span>').join('');
  const card =
    '<div class="col-md-4 col-lg-3">' +
      '<div class="ds-card">' +
        '<h3>' + d.slug + '</h3>' +
        '<div class="ds-meta">' +
          '<span class="layer-pill" style="background:'+layerColor+'">'+d.purduePrimary+'</span>' +
          secondaryPills + '</div>' +
        '<div class="ds-meta mt-1" style="font-style:italic">' + (d.purdueNote||'') + '</div>' +
        '<div class="ds-stats">' +
          '<div>Cached: <b>' + d.cached.toLocaleString() + '</b> · Catalog: <b>' + d.catalogTotal.toLocaleString() + '</b></div>' +
          '<div>Remaining: <b>' + d.remaining.toLocaleString() + '</b> · Behaviors: <b>' + d.behCached.toLocaleString() + '</b></div>' +
          '<div class="mt-1">' +
            '<span class="verdict-clean">' + d.clean.toLocaleString() + '</span> clean &nbsp; ' +
            '<span class="verdict-susp">' + d.suspicious.toLocaleString() + '</span> susp &nbsp; ' +
            '<span class="verdict-mal">' + d.malicious.toLocaleString() + '</span> mal &nbsp; ' +
            '<span class="verdict-unk">' + d.unknown.toLocaleString() + '</span> unk' +
          '</div>' +
        '</div>' +
      '</div>' +
    '</div>';
  grid.insertAdjacentHTML('beforeend', card);
});
</script>
</body>
</html>
"@

    Set-Content -LiteralPath $OutputPath -Value $html -Encoding UTF8
    Write-Host ("`n[Build-OTGlobalThreatDashboard] Wrote {0:N0} bytes -> {1}" -f (Get-Item $OutputPath).Length, $OutputPath) -ForegroundColor Green
    Write-Host "[Build-OTGlobalThreatDashboard] Open in browser: file:///$($OutputPath -replace '\\','/')" -ForegroundColor Cyan
}

Export-ModuleMember -Function Build-OTGlobalThreatDashboard

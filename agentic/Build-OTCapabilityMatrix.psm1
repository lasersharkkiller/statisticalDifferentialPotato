function Build-OTCapabilityMatrix {
    <#
    .SYNOPSIS
        Builds the OT Capability Matrix — per-binary x MITRE-technique matrix
        with malware-corpus overlay. The inverse-differential workhorse.

    .DESCRIPTION
        For each binary in the OT/NSRL baseline, shows which MITRE ATT&CK
        techniques it triggers in VT sandbox, color-coded by whether the
        same technique appears in the cataloged malware corpus:

          GREEN  = baseline-only (clean detection signal — seeing this
                   technique in live telemetry from a non-baselined process
                   would be a strong anomaly)
          YELLOW = baseline AND malware corpus (ambiguity zone — the
                   technique alone is not diagnostic; need behavioral context)
          RED    = malware-corpus-only (high-confidence indicator — should
                   never appear in known-good baseline telemetry)

        The matrix is filterable by Purdue layer, vendor, and technique
        category. Clicking a cell drills into:
          - the specific binaries (hash + filename) that triggered the
            technique in this dataset
          - the malware families that triggered it (when in the overlap or
            malware-only set)

        Data sources:
          output-baseline/VirusTotal-behaviors/{NSRL,OT}/<ds>/**/*.json
            (mitre_attack_techniques[].id per binary)
          apt/{Malware Families,APTs}/<family>/TargetedMitreDifferentialAnalysis.json
            (Item_Name = "T1059: signature description" -> extract T-code)
          firmware-staging/<vendor>/**/catalog.csv
            (hash -> filename / OsName join)
          NSRL/nsrl_reduced.csv
            (hash -> OsName for NSRL datasets)

    .PARAMETER BaselineRoot
        Root of the offline VT baseline. Default: output-baseline.

    .PARAMETER AptRoot
        Root of the APT / malware family folder tree. Default: apt.

    .PARAMETER OutputPath
        Path of the output HTML file.
        Default: output-baseline/visualizations/ot-capability-matrix.html.

    .PARAMETER CatalogRoot
        firmware-staging root. Default: ../../firmware-staging.

    .PARAMETER MinBinariesPerRow
        Minimum number of baselined binaries an OS/vendor must have to
        get its own row in the matrix. Default: 5 (filters out very
        sparse datasets so the matrix stays readable).

    .PARAMETER Force
        Regenerate even if output is newer than inputs.

    .EXAMPLE
        Import-Module .\agentic\Build-OTCapabilityMatrix.psm1
        Build-OTCapabilityMatrix
    #>
    [CmdletBinding()]
    param(
        [string] $BaselineRoot = 'output-baseline',
        [string] $AptRoot      = 'apt',
        [string] $OutputPath   = 'output-baseline/visualizations/ot-capability-matrix.html',
        [string] $CatalogRoot  = '../../firmware-staging',
        [int]    $MinBinariesPerRow = 5,
        [switch] $Force
    )

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

    $behRoot = Join-Path $BaselineRoot 'VirusTotal-behaviors'
    $outDir  = Split-Path $OutputPath -Parent
    if (-not (Test-Path $behRoot)) { Write-Error "VT-behaviors root not found: $behRoot"; return }
    if (-not (Test-Path $outDir))  { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }

    Write-Host "`n[Build-OTCapabilityMatrix] BaselineRoot = $BaselineRoot" -ForegroundColor DarkCyan
    Write-Host "[Build-OTCapabilityMatrix] OutputPath   = $OutputPath" -ForegroundColor DarkCyan

    $purdueMap = @{
        'NSRL/Windows-11'           = @{ Primary='L4';   Note='Admin workstations + EWS hosts' }
        'NSRL/Windows-Server-2025'  = @{ Primary='L3';   Note='SCADA / Historian / EWS server tier' }
        'NSRL/Ubuntu-24.04'         = @{ Primary='L3';   Note='Linux SCADA control center' }
        'NSRL/Debian-13'            = @{ Primary='L3';   Note='Linux server tier (limited corpus)' }
        'OT/Eaton'                  = @{ Primary='L3.5'; Note='NMCs + bare-metal UPS MCUs' }
        'OT/APC'                    = @{ Primary='L3.5'; Note='NMCs + PowerChute + Smart-UPS MCU' }
        'OT/Vertiv'                 = @{ Primary='L3.5'; Note='Avocent ACS + IntelliSlot + Liebert MCU' }
        'OT/SEL'                    = @{ Primary='L3';   Note='Industrial PCs + engineering SW' }
        'OT/Siemens'                = @{ Primary='L3';   Note='TIA Portal + WinCC + SIMATIC PLCs' }
        'OT/Inductive-Automation'   = @{ Primary='L3';   Note='Ignition Gateway' }
        'OT/Maple-Systems'          = @{ Primary='L2';   Note='cMT HMI panels + design tools' }
        'OT/Red-Lion'               = @{ Primary='L2';   Note='Graphite HMI + Sixnet RTU + Crimson' }
    }
    $layerColors = @{
        'L1' = '#dc2626'; 'L2' = '#ea580c'; 'L3' = '#ca8a04'; 'L3.5' = '#2563eb';
        'L4' = '#7c3aed'; 'PowerInfra' = '#0d9488'; 'L?' = '#6b7280'
    }

    # ----- Walk baseline behaviors, per dataset, build matrix cells ----------
    # matrixCells[dataset][techId] = @{ count = N; hashes = [list of 'hash|filename'] }
    $matrixCells = @{}
    $datasetMeta = @{}    # slug -> @{ binaryCount; purdue }

    foreach ($bucket in @('NSRL','OT')) {
        $bucketRoot = Join-Path $behRoot $bucket
        if (-not (Test-Path $bucketRoot)) { continue }
        foreach ($dsDir in (Get-ChildItem -LiteralPath $bucketRoot -Directory -ErrorAction SilentlyContinue)) {
            $slug = "$bucket/$($dsDir.Name)"
            $behFiles = @(Get-ChildItem -LiteralPath $dsDir.FullName -Filter '*.json' -File -Recurse -ErrorAction SilentlyContinue)
            if ($behFiles.Count -lt $MinBinariesPerRow) {
                Write-Host ("  skip {0} (only {1} behaviors)" -f $slug, $behFiles.Count) -ForegroundColor DarkGray
                continue
            }
            Write-Host ("  walking {0} : {1} behaviors" -f $slug, $behFiles.Count) -ForegroundColor DarkGray

            $matrixCells[$slug] = @{}
            $datasetMeta[$slug] = @{
                binaryCount = $behFiles.Count
                purdue      = if ($purdueMap.ContainsKey($slug)) { $purdueMap[$slug] } else { @{ Primary='L?'; Note='' } }
            }

            $i = 0
            foreach ($f in $behFiles) {
                $i++
                if ($i % 2000 -eq 0) { Write-Host "    processed $i / $($behFiles.Count)..." -ForegroundColor DarkGray }
                try {
                    if ($f.Length -gt 50MB) { continue }
                    $j = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    $d = if ($j.data -is [System.Object[]]) { $j.data[0] } else { $j.data }
                    if (-not $d -or -not $d.mitre_attack_techniques) { continue }
                    $hash = [System.IO.Path]::GetFileNameWithoutExtension($f.Name).ToLowerInvariant()
                    foreach ($t in $d.mitre_attack_techniques) {
                        if (-not $t.id) { continue }
                        $tid = [string]$t.id
                        if (-not $matrixCells[$slug].ContainsKey($tid)) {
                            $matrixCells[$slug][$tid] = [pscustomobject]@{ count = 0; hashes = New-Object System.Collections.Generic.HashSet[string] }
                        }
                        $matrixCells[$slug][$tid].count++
                        [void]$matrixCells[$slug][$tid].hashes.Add($hash)
                    }
                } catch { }
            }
        }
    }

    # ----- Build filename lookup (hash -> filename) for drill-down -----------
    Write-Host "`n  building hash->filename lookup ..." -ForegroundColor DarkGray
    $hashToFile = @{}
    # OT vendors: walk all firmware-staging catalog.csvs
    if (Test-Path $CatalogRoot) {
        $catFiles = @(Get-ChildItem -LiteralPath $CatalogRoot -Filter 'catalog.csv' -Recurse -ErrorAction SilentlyContinue)
        foreach ($cf in $catFiles) {
            try {
                Import-Csv -LiteralPath $cf.FullName | ForEach-Object {
                    if ($_.Hash -and -not $hashToFile.ContainsKey($_.Hash.ToLowerInvariant())) {
                        $fn = if ($_.FileName) { $_.FileName } else { '(unnamed)' }
                        $hashToFile[$_.Hash.ToLowerInvariant()] = $fn
                    }
                }
            } catch { }
        }
    }
    # NSRL: load nsrl_reduced.csv
    $nsrlCsv = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\NSRL\nsrl_reduced.csv'))
    if (Test-Path $nsrlCsv) {
        try {
            Import-Csv -LiteralPath $nsrlCsv | ForEach-Object {
                if ($_.Hash -and -not $hashToFile.ContainsKey($_.Hash.ToLowerInvariant())) {
                    $fn = if ($_.FileName) { $_.FileName } else { '(unnamed)' }
                    $hashToFile[$_.Hash.ToLowerInvariant()] = $fn
                }
            }
        } catch { }
    }
    Write-Host ("  hash->filename lookup: {0:N0} entries" -f $hashToFile.Count) -ForegroundColor DarkGray

    # ----- Walk malware corpus MITRE -----------------------------------------
    Write-Host "`n  walking apt/ for malware-corpus MITRE ..." -ForegroundColor DarkGray
    $malwareByTech = @{}  # techId -> [list of "family|count"]
    $aptFamilyCount = 0
    foreach ($subdir in @('Malware Families','APTs')) {
        $rootSub = Join-Path $AptRoot $subdir
        if (-not (Test-Path $rootSub)) { continue }
        foreach ($famDir in (Get-ChildItem -LiteralPath $rootSub -Directory -ErrorAction SilentlyContinue)) {
            $mitreJson = Join-Path $famDir.FullName 'TargetedMitreDifferentialAnalysis.json'
            if (-not (Test-Path $mitreJson)) { continue }
            $aptFamilyCount++
            $famName = $famDir.Name
            try {
                $rows = Get-Content -LiteralPath $mitreJson -Raw | ConvertFrom-Json
                $perFamily = @{}
                foreach ($r in $rows) {
                    if (-not $r.Item_Name) { continue }
                    $raw = [string]$r.Item_Name
                    $tid = if ($raw -match '^(T\d+(?:\.\d+)?)') { $matches[1] } else { $raw }
                    $cnt = if ($r.Malicious_Count) { [int]$r.Malicious_Count } else { 1 }
                    $perFamily[$tid] = ($perFamily[$tid] | ForEach-Object { if ($_) { $_ } else { 0 } }) + $cnt
                }
                foreach ($tid in $perFamily.Keys) {
                    if (-not $malwareByTech.ContainsKey($tid)) {
                        $malwareByTech[$tid] = New-Object System.Collections.Generic.List[object]
                    }
                    $malwareByTech[$tid].Add(@{ family = $famName; count = $perFamily[$tid] })
                }
            } catch { }
        }
    }
    Write-Host ("  apt/ walked: {0} families/APTs, {1} unique T-codes" -f $aptFamilyCount, $malwareByTech.Count) -ForegroundColor DarkGray

    # ----- Build column list (union of all techniques across baseline + malware)
    $allTechs = New-Object System.Collections.Generic.HashSet[string]
    foreach ($ds in $matrixCells.Keys) {
        foreach ($t in $matrixCells[$ds].Keys) { [void]$allTechs.Add($t) }
    }
    foreach ($t in $malwareByTech.Keys) { [void]$allTechs.Add($t) }
    $colsSorted = @($allTechs) | Sort-Object

    # ----- Build payload -----------------------------------------------------
    $datasets = @()
    foreach ($slug in ($matrixCells.Keys | Sort-Object)) {
        $meta = $datasetMeta[$slug]
        $cells = @{}
        foreach ($tid in $colsSorted) {
            if ($matrixCells[$slug].ContainsKey($tid)) {
                $c = $matrixCells[$slug][$tid]
                $cells[$tid] = [ordered]@{
                    count    = $c.count
                    inBase   = $true
                    inMal    = $malwareByTech.ContainsKey($tid)
                    hashes   = @($c.hashes) | Select-Object -First 30  # cap drill-down list
                    hashOver = ($c.hashes.Count -gt 30)
                }
            } elseif ($malwareByTech.ContainsKey($tid)) {
                $cells[$tid] = [ordered]@{
                    count  = 0
                    inBase = $false
                    inMal  = $true
                }
            }
        }
        $datasets += [ordered]@{
            slug          = $slug
            binaryCount   = $meta.binaryCount
            purduePrimary = $meta.purdue.Primary
            purdueNote    = $meta.purdue.Note
            cells         = $cells
        }
    }

    $techMeta = @{}
    foreach ($tid in $colsSorted) {
        $techMeta[$tid] = [ordered]@{
            inAnyBase = ($datasets | Where-Object { $_.cells[$tid] -and $_.cells[$tid].inBase } | Measure-Object | Select-Object -ExpandProperty Count) -gt 0
            inMal     = $malwareByTech.ContainsKey($tid)
            malFamilies = if ($malwareByTech.ContainsKey($tid)) {
                @($malwareByTech[$tid]) | Sort-Object { $_.count } -Descending | Select-Object -First 15 |
                  ForEach-Object { @{ family = $_.family; count = $_.count } }
            } else { @() }
        }
    }

    # Build hash->filename for ONLY the hashes referenced (keep payload manageable)
    $hashLookup = @{}
    foreach ($ds in $datasets) {
        foreach ($tid in $ds.cells.Keys) {
            $cell = $ds.cells[$tid]
            if ($cell.hashes) {
                foreach ($h in $cell.hashes) {
                    if ($hashToFile.ContainsKey($h)) { $hashLookup[$h] = $hashToFile[$h] }
                }
            }
        }
    }

    $payload = [ordered]@{
        generatedAt = (Get-Date).ToString('s')
        cols        = $colsSorted
        datasets    = $datasets
        techMeta    = $techMeta
        hashLookup  = $hashLookup
        layerColors = $layerColors
        totals      = [ordered]@{
            datasets     = $datasets.Count
            techniques   = $colsSorted.Count
            malFamilies  = $aptFamilyCount
            baselineOnly = ($colsSorted | Where-Object { $techMeta[$_].inAnyBase -and -not $techMeta[$_].inMal }).Count
            both         = ($colsSorted | Where-Object { $techMeta[$_].inAnyBase -and $techMeta[$_].inMal }).Count
            malwareOnly  = ($colsSorted | Where-Object { -not $techMeta[$_].inAnyBase -and $techMeta[$_].inMal }).Count
        }
    }

    $payloadJson = $payload | ConvertTo-Json -Depth 10 -Compress

    # ----- Render HTML -------------------------------------------------------
    $html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<title>OT Capability Matrix</title>
<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css' rel='stylesheet'>
<style>
  body { background:#f8f9fa; font-family:'Segoe UI',system-ui,sans-serif; padding:20px; }
  .breadcrumb-bar { background:#e5e7eb; padding:8px 16px; border-radius:6px; font-size:.85rem; color:#374151; margin-bottom:16px; }
  .panel { background:#fff; border-radius:8px; padding:18px; box-shadow:0 1px 3px rgba(0,0,0,.06); margin-bottom:18px; }
  .panel h2 { font-size:1.1rem; font-weight:600; color:#1f2937; margin-bottom:6px; }
  .panel-sub { color:#6b7280; font-size:.85rem; margin-bottom:14px; }
  .legend { display:flex; gap:14px; flex-wrap:wrap; font-size:.85rem; align-items:center; margin-bottom:10px; }
  .legend-swatch { display:inline-block; width:18px; height:18px; border-radius:3px; vertical-align:middle; margin-right:5px; border:1px solid #d1d5db; }
  .matrix-wrap { overflow:auto; max-height:75vh; border:1px solid #e5e7eb; border-radius:6px; }
  table.matrix { border-collapse:separate; border-spacing:0; font-size:.7rem; }
  table.matrix th, table.matrix td { padding:3px 5px; text-align:center; border-right:1px solid #f1f5f9; border-bottom:1px solid #f1f5f9; }
  table.matrix thead th { position:sticky; top:0; background:#f9fafb; z-index:2; font-weight:600; min-width:55px; max-width:55px; transform:rotate(-30deg); transform-origin:bottom left; height:90px; font-family:'Consolas','Monaco',monospace; }
  table.matrix thead th:first-child { transform:none; height:auto; min-width:240px; max-width:240px; text-align:left; padding-left:10px; }
  table.matrix tbody td:first-child { position:sticky; left:0; background:#fff; text-align:left; font-weight:600; min-width:240px; padding-left:10px; border-right:2px solid #d1d5db; z-index:1; }
  table.matrix tbody tr:hover td { background:#fffbeb; }
  .cell-green { background:#86efac; cursor:pointer; }
  .cell-yellow { background:#fcd34d; cursor:pointer; }
  .cell-red { background:#fca5a5; cursor:default; }
  .cell-empty { background:#fff; }
  .layer-pill { display:inline-block; padding:1px 7px; border-radius:4px; color:#fff; font-size:.68rem; font-weight:600; margin-right:4px; }
  .filter-bar { display:flex; gap:10px; align-items:center; margin-bottom:12px; flex-wrap:wrap; }
  .filter-bar select, .filter-bar input { font-size:.85rem; padding:4px 8px; border:1px solid #d1d5db; border-radius:4px; }
  .modal-content { font-size:.9rem; }
  .chip-hash { display:inline-block; padding:2px 7px; margin:2px; border-radius:3px; background:#e0e7ff; color:#3730a3; border:1px solid #c7d2fe; font-family:'Consolas','Monaco',monospace; font-size:.72rem; }
  .chip-fam { display:inline-block; padding:2px 7px; margin:2px; border-radius:3px; background:#fee2e2; color:#991b1b; border:1px solid #fca5a5; font-size:.72rem; }
</style>
</head>
<body>

<div class='breadcrumb-bar'>OT Capability Matrix &nbsp; · &nbsp; per-binary MITRE ATT&CK × baseline ∩ malware corpus &nbsp; · &nbsp; generated <span id='gen'></span></div>

<div class='panel'>
  <h2>OT Capability Matrix</h2>
  <div class='panel-sub'>
    Rows = baselined OT/NSRL datasets (organized by Purdue layer). Columns = MITRE ATT&amp;CK techniques observed in baseline OR cataloged malware corpus. <strong>Click any cell</strong> for drill-down to the contributing binaries + malware families.
  </div>
  <div class='legend'>
    <div><span class='legend-swatch' style='background:#86efac'></span>baseline-only (clean detection signal — observing in live = strong anomaly)</div>
    <div><span class='legend-swatch' style='background:#fcd34d'></span>both (ambiguity zone — needs behavioral context)</div>
    <div><span class='legend-swatch' style='background:#fca5a5'></span>malware-only (high-confidence indicator)</div>
    <div><span class='legend-swatch' style='background:#fff;border-color:#d1d5db'></span>not observed</div>
  </div>
  <div class='filter-bar'>
    <label>Purdue layer:
      <select id='filter-layer'>
        <option value=''>All</option>
        <option value='L1'>L1</option>
        <option value='L2'>L2</option>
        <option value='L3'>L3</option>
        <option value='L3.5'>L3.5</option>
        <option value='L4'>L4</option>
      </select>
    </label>
    <label>Technique class:
      <select id='filter-class'>
        <option value=''>All</option>
        <option value='base-only'>baseline-only (green)</option>
        <option value='both'>both (yellow)</option>
        <option value='mal-only'>malware-only (red)</option>
      </select>
    </label>
    <label>Filter T-code:
      <input type='text' id='filter-tcode' placeholder='e.g. T1059'>
    </label>
    <div class='ms-auto text-muted small'>
      Totals: <strong id='t-base'>?</strong> baseline-only · <strong id='t-both'>?</strong> both · <strong id='t-mal'>?</strong> malware-only · <strong id='t-fams'>?</strong> malware/APT families
    </div>
  </div>
  <div class='matrix-wrap'><table class='matrix' id='matrix'></table></div>
</div>

<!-- Drill-down modal -->
<div class='modal fade' id='drillModal' tabindex='-1'>
  <div class='modal-dialog modal-lg modal-dialog-scrollable'>
    <div class='modal-content'>
      <div class='modal-header'>
        <h5 class='modal-title' id='drillTitle'>Cell drill-down</h5>
        <button type='button' class='btn-close' data-bs-dismiss='modal'></button>
      </div>
      <div class='modal-body' id='drillBody'></div>
    </div>
  </div>
</div>

<script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js'></script>
<script>
const DATA = $payloadJson;

document.getElementById('gen').textContent = DATA.generatedAt.replace('T',' ').substring(0,16);
document.getElementById('t-base').textContent = DATA.totals.baselineOnly;
document.getElementById('t-both').textContent = DATA.totals.both;
document.getElementById('t-mal').textContent = DATA.totals.malwareOnly;
document.getElementById('t-fams').textContent = DATA.totals.malFamilies;

function cellClass(ds, tid) {
  const cell = ds.cells[tid];
  if (!cell) return 'cell-empty';
  if (cell.inBase && cell.inMal) return 'cell-yellow';
  if (cell.inBase) return 'cell-green';
  if (cell.inMal)  return 'cell-red';
  return 'cell-empty';
}
function cellLabel(ds, tid) {
  const cell = ds.cells[tid];
  if (!cell || !cell.inBase) return '';
  return cell.count;
}

function renderMatrix(filterLayer, filterClass, filterTcode) {
  const cols = DATA.cols.filter(t => {
    const tm = DATA.techMeta[t];
    if (filterTcode && !t.toLowerCase().includes(filterTcode.toLowerCase())) return false;
    if (filterClass === 'base-only' && (!tm.inAnyBase || tm.inMal)) return false;
    if (filterClass === 'both'      && !(tm.inAnyBase && tm.inMal)) return false;
    if (filterClass === 'mal-only'  && (tm.inAnyBase || !tm.inMal)) return false;
    return true;
  });
  const rows = DATA.datasets.filter(d => !filterLayer || d.purduePrimary === filterLayer);

  let html = '<thead><tr><th>Dataset (binaries)</th>';
  cols.forEach(t => { html += '<th title="' + t + '">' + t + '</th>'; });
  html += '</tr></thead><tbody>';

  rows.forEach(d => {
    const color = DATA.layerColors[d.purduePrimary] || '#6b7280';
    html += '<tr><td>' +
      '<span class="layer-pill" style="background:' + color + '">' + d.purduePrimary + '</span>' +
      d.slug + ' <small class="text-muted">(' + d.binaryCount.toLocaleString() + ')</small>' +
      '<div class="text-muted small">' + (d.purdueNote||'') + '</div>' +
      '</td>';
    cols.forEach(t => {
      const klass = cellClass(d, t);
      const label = cellLabel(d, t);
      const click = (klass === 'cell-green' || klass === 'cell-yellow' || klass === 'cell-red')
        ? ' onclick="drillCell(\'' + d.slug + '\',\'' + t + '\')"'
        : '';
      html += '<td class="' + klass + '"' + click + '>' + label + '</td>';
    });
    html += '</tr>';
  });
  html += '</tbody>';
  document.getElementById('matrix').innerHTML = html;
}

function drillCell(slug, tid) {
  const ds = DATA.datasets.find(x => x.slug === slug);
  const cell = ds.cells[tid];
  const tm = DATA.techMeta[tid];
  let body = '<p><strong>Dataset:</strong> ' + slug + '<br><strong>Technique:</strong> <code>' + tid + '</code> ' +
             '(<a href="https://attack.mitre.org/techniques/' + tid.replace('.', '/') + '/" target="_blank">attack.mitre.org</a>)</p>';

  if (cell && cell.inBase) {
    body += '<h6>Baseline binaries that triggered this technique (' + cell.count + ' total, showing first ' + cell.hashes.length + (cell.hashOver?', more truncated':'') + ')</h6>';
    cell.hashes.forEach(h => {
      const fn = DATA.hashLookup[h] || '(unknown)';
      body += '<div class="chip-hash" title="' + h + '">' + h.substring(0,12) + '… &nbsp;<small>' + fn + '</small></div>';
    });
    body += '<hr>';
  }
  if (tm.inMal) {
    body += '<h6>Malware/APT families also observing this technique (' + tm.malFamilies.length + ' shown)</h6>';
    tm.malFamilies.forEach(f => {
      body += '<div class="chip-fam">' + f.family + ' <small>(' + f.count + ')</small></div>';
    });
  }
  if (cell && cell.inBase && tm.inMal) {
    body += '<hr><div class="alert alert-warning small">' +
      '<strong>Ambiguity zone:</strong> this technique is observed in BOTH the legitimate baseline AND in cataloged malware. ' +
      'A live observation needs behavioral context (parent process, command line, network destination) to disambiguate ' +
      'normal use from abuse. Use the Behavioral Fingerprint Table for the parent binary as the comparison envelope.' +
      '</div>';
  }

  document.getElementById('drillTitle').textContent = slug + '  ×  ' + tid;
  document.getElementById('drillBody').innerHTML = body;
  new bootstrap.Modal(document.getElementById('drillModal')).show();
}

document.getElementById('filter-layer').onchange =
document.getElementById('filter-class').onchange =
document.getElementById('filter-tcode').oninput = () => {
  renderMatrix(
    document.getElementById('filter-layer').value,
    document.getElementById('filter-class').value,
    document.getElementById('filter-tcode').value.trim()
  );
};

renderMatrix('', '', '');
</script>
</body>
</html>
"@

    Set-Content -LiteralPath $OutputPath -Value $html -Encoding UTF8
    Write-Host ("`n[Build-OTCapabilityMatrix] Wrote {0:N0} bytes -> {1}" -f (Get-Item $OutputPath).Length, $OutputPath) -ForegroundColor Green
    Write-Host "[Build-OTCapabilityMatrix] Totals: $($payload.totals.baselineOnly) baseline-only / $($payload.totals.both) both / $($payload.totals.malwareOnly) malware-only / $($payload.totals.techniques) total techniques" -ForegroundColor DarkCyan
    Write-Host "[Build-OTCapabilityMatrix] Open in browser: file:///$($OutputPath -replace '\\','/')" -ForegroundColor Cyan
}

Export-ModuleMember -Function Build-OTCapabilityMatrix

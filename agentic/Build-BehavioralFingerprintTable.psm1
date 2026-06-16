function Build-BehavioralFingerprintTable {
    <#
    .SYNOPSIS
        Builds per-dataset known-good behavioral fingerprint reports for analyst
        lookup ("what does this known-good hash NORMALLY do").

    .DESCRIPTION
        Inverse-differential complement to the malware / APT analysis pipeline.
        For every dataset folder under output-baseline/VirusTotal-behaviors/NSRL/
        and /OT/ this builds:

          <OutputRoot>/<Dataset>/Master_Intel.csv      (one row per hash)
          <OutputRoot>/<Dataset>/behaviors_index.json  (machine-readable)
          <OutputRoot>/<Dataset>/Detailed_Report.html  (DataTables UI)
          <OutputRoot>/index.html                       (dataset selector)

        Join sources (Hash -> FileName / OsName / FullPath):
          - OT/<Vendor>/      : union of every catalog.csv under
                                <CatalogRoot>/<Vendor>/**.
          - NSRL/<OsName>/    : NSRL/nsrl_reduced.csv filtered to the OsName slug.

        Hashes with behaviors data but no catalog row are kept (FileName /
        FullPath set to "(unknown)") so the fingerprint is not lost.

        Behavior-JSON fields read (top-level $json.data.*, NOT .attributes):
          processes_created, processes_tree, processes_terminated,
          command_executions, files_opened, files_written, files_dropped,
          files_deleted, registry_keys_set, registry_keys_opened,
          registry_keys_deleted, dns_lookups, ip_traffic,
          memory_pattern_domains, memory_pattern_urls, modules_loaded,
          mutexes_created, services_started, mitre_attack_techniques,
          signature_matches, tags.

        Main-JSON fields read (when present alongside the behaviors JSON):
          type_description, meaningful_name, magic, size,
          first_submission_date, last_analysis_stats,
          signature_info.signers, signature_info.verified,
          sigma_analysis_results, crowdsourced_yara_results, tags.

    .PARAMETER DatasetFilter
        Optional list of "<bucket>/<dataset>" slugs to restrict the run, e.g.
        @('OT/APC','NSRL/Windows-11'). Empty (default) means every dataset.

    .PARAMETER BaselineRoot
        Root of the offline VT baseline. Default: output-baseline.

    .PARAMETER OutputRoot
        Where the per-dataset reports are written.
        Default: output-baseline/behavioral-fingerprints.

    .PARAMETER CatalogRoot
        firmware-staging root, used to discover per-vendor catalog.csv files.
        Default: ../../firmware-staging (relative to this module, which lands
        at the sibling-of-repo firmware-staging tree).

    .PARAMETER WhatIfMode
        Dry-run; counts inputs and prints the per-dataset plan but writes no
        outputs.

    .PARAMETER Force
        Regenerate even if existing output files are newer than every input.

    .EXAMPLE
        Import-Module .\agentic\Build-BehavioralFingerprintTable.psm1
        Build-BehavioralFingerprintTable

    .EXAMPLE
        Build-BehavioralFingerprintTable -DatasetFilter @('OT/APC') -Force
    #>
    [CmdletBinding()]
    param(
        [string[]] $DatasetFilter = @(),
        [string]   $BaselineRoot  = 'output-baseline',
        [string]   $OutputRoot    = 'output-baseline/behavioral-fingerprints',
        [string]   $CatalogRoot   = '../../firmware-staging',
        [switch]   $WhatIfMode,
        [switch]   $Force
    )

    # ----- Path resolution ---------------------------------------------------
    if (-not [System.IO.Path]::IsPathRooted($BaselineRoot)) {
        $BaselineRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\$BaselineRoot"))
    }
    if (-not [System.IO.Path]::IsPathRooted($OutputRoot)) {
        $OutputRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\$OutputRoot"))
    }
    if (-not [System.IO.Path]::IsPathRooted($CatalogRoot)) {
        $CatalogRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot $CatalogRoot))
    }

    $behRoot  = Join-Path $BaselineRoot 'VirusTotal-behaviors'
    $mainRoot = Join-Path $BaselineRoot 'VirusTotal-main'
    $nsrlCsv  = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\NSRL\nsrl_reduced.csv'))

    if (-not (Test-Path $behRoot)) {
        Write-Error "Behavior root not found: $behRoot"
        return
    }

    Write-Host "`n[Build-BehavioralFingerprintTable] BaselineRoot = $BaselineRoot" -ForegroundColor DarkCyan
    Write-Host "[Build-BehavioralFingerprintTable] OutputRoot   = $OutputRoot"   -ForegroundColor DarkCyan
    Write-Host "[Build-BehavioralFingerprintTable] CatalogRoot  = $CatalogRoot"  -ForegroundColor DarkCyan
    Write-Host "[Build-BehavioralFingerprintTable] NSRL CSV     = $nsrlCsv"      -ForegroundColor DarkCyan

    $globalStart = Get-Date

    # ----- Dataset discovery -------------------------------------------------
    $datasets = Get-DatasetCandidate -BehaviorRoot $behRoot -Filter $DatasetFilter

    if (-not $datasets -or $datasets.Count -eq 0) {
        Write-Warning "No datasets matched."
        return
    }

    Write-Host ("[Build-BehavioralFingerprintTable] {0} dataset(s) queued" -f $datasets.Count) -ForegroundColor Cyan

    # ----- NSRL catalog (lazy-loaded once for all NSRL datasets) -------------
    $nsrlCatalog = $null

    # ----- Per-dataset summary (used by index.html) --------------------------
    $datasetSummaries = New-Object System.Collections.Generic.List[psobject]

    foreach ($ds in $datasets) {
        $bucket   = $ds.Bucket           # e.g. 'OT' or 'NSRL'
        $datasetN = $ds.Name             # e.g. 'APC' or 'Windows-11'
        $dsRoot   = $ds.Path             # behavior root for the dataset
        $dsSlug   = "$bucket/$datasetN"

        Write-Host ""
        Write-Host "===== Dataset: $dsSlug =====" -ForegroundColor Yellow
        $tStart = Get-Date

        # ----- Behavior JSON enumeration -------------------------------------
        $behaviorFiles = @(Get-ChildItem -Path $dsRoot -Filter *.json -Recurse -File -ErrorAction SilentlyContinue)
        if ($behaviorFiles.Count -eq 0) {
            Write-Host "  (no behavior json under $dsRoot - skipping)" -ForegroundColor DarkGray
            continue
        }

        Write-Host ("  behavior files : {0}" -f $behaviorFiles.Count)

        # ----- Idempotency check ---------------------------------------------
        $dsOutDir = Join-Path $OutputRoot $dsSlug
        $outCsv   = Join-Path $dsOutDir 'Master_Intel.csv'
        $outJson  = Join-Path $dsOutDir 'behaviors_index.json'
        $outHtml  = Join-Path $dsOutDir 'Detailed_Report.html'

        if (-not $Force -and -not $WhatIfMode) {
            if ((Test-IsOutputFresh -Outputs @($outCsv, $outJson, $outHtml) -Inputs $behaviorFiles)) {
                Write-Host "  (output is fresh - skipping; use -Force to override)" -ForegroundColor DarkGray
                $datasetSummaries.Add([pscustomobject]@{
                    Bucket          = $bucket
                    Name            = $datasetN
                    Slug            = $dsSlug
                    HashCount       = $behaviorFiles.Count
                    WithBehaviors   = $null
                    MalformedJson   = 0
                    ReportPath      = (Resolve-RelPath -From $OutputRoot -To $outHtml)
                    Cached          = $true
                })
                continue
            }
        }

        # ----- Catalog join --------------------------------------------------
        $catalog = $null
        switch ($bucket) {
            'OT' {
                $catalog = Get-VendorCatalog -CatalogRoot $CatalogRoot -Vendor $datasetN
            }
            'NSRL' {
                if (-not $nsrlCatalog) {
                    $nsrlCatalog = Get-NsrlCatalog -NsrlCsvPath $nsrlCsv
                }
                $catalog = Get-NsrlDatasetSlice -Catalog $nsrlCatalog -DatasetSlug $datasetN
            }
            default {
                $catalog = @{}
            }
        }
        Write-Host ("  catalog rows   : {0}" -f $catalog.Count)

        if ($WhatIfMode) {
            Write-Host "  (WhatIfMode - skipping write)" -ForegroundColor DarkGray
            continue
        }

        # ----- Per-hash processing -------------------------------------------
        $records       = New-Object System.Collections.Generic.List[psobject]
        $malformed     = 0
        $oversize      = 0
        $withBehaviors = 0

        # rollups for the dataset summary header
        $rollParents = @{}
        $rollMods    = @{}
        $rollMitre   = @{}

        $i = 0
        foreach ($bf in $behaviorFiles) {
            $i++
            if (($i % 1000) -eq 0) {
                Write-Host ("  ...{0}/{1}" -f $i, $behaviorFiles.Count) -ForegroundColor DarkGray
            }

            if ($bf.Length -gt 50MB) {
                Write-Warning ("  oversize behavior file skipped ({0:N0} bytes): {1}" -f $bf.Length, $bf.Name)
                $oversize++
                continue
            }

            $hash = [System.IO.Path]::GetFileNameWithoutExtension($bf.Name).ToLowerInvariant()
            if ($hash.Length -ne 64) { continue }

            $behAttr = $null
            try {
                $rawJson = [System.IO.File]::ReadAllText($bf.FullName)
                if (-not $rawJson -or $rawJson.Length -lt 12) { continue }
                $parsed = $rawJson | ConvertFrom-Json -ErrorAction Stop
                $behAttr = Get-BehaviorAttributes -Parsed $parsed
            } catch {
                $malformed++
                continue
            }

            # Main JSON (best-effort - may be absent)
            $mainAttr = $null
            $mainPath = Resolve-MainJsonPath -BehFilePath $bf.FullName -BehRoot $behRoot -MainRoot $mainRoot
            if ($mainPath -and (Test-Path $mainPath)) {
                try {
                    $mraw = [System.IO.File]::ReadAllText($mainPath)
                    if ($mraw -and $mraw.Length -gt 12) {
                        $mparsed = $mraw | ConvertFrom-Json -ErrorAction Stop
                        if ($mparsed.data -and $mparsed.data.attributes) {
                            $mainAttr = $mparsed.data.attributes
                        }
                    }
                } catch {
                    # tolerated; main JSON is non-essential
                }
            }

            $cat = $catalog[$hash]

            $rec = New-FingerprintRecord `
                -Hash $hash `
                -BehAttr $behAttr `
                -MainAttr $mainAttr `
                -CatalogRow $cat

            if ($rec.HasBehaviors) { $withBehaviors++ }

            # Update dataset rollups (top-N display in HTML header)
            foreach ($p in $rec.ParentProcessesList) { Add-Counter -Table $rollParents -Key $p }
            foreach ($m in $rec.ModulesLoadedList)   { Add-Counter -Table $rollMods    -Key $m }
            foreach ($t in $rec.MitreList)           { Add-Counter -Table $rollMitre   -Key $t }

            $records.Add($rec)
        }

        Write-Host ("  records        : {0}  (with-behaviors {1}, malformed {2}, oversize {3})" -f `
            $records.Count, $withBehaviors, $malformed, $oversize)

        # ----- Write outputs --------------------------------------------------
        if (-not (Test-Path $dsOutDir)) {
            New-Item -ItemType Directory -Path $dsOutDir -Force | Out-Null
        }

        Write-MasterIntelCsv -Records $records -Path $outCsv
        Write-BehaviorsIndexJson -Records $records -Path $outJson -Bucket $bucket -Dataset $datasetN
        Write-DetailedReportHtml `
            -Records $records `
            -Path $outHtml `
            -Bucket $bucket `
            -Dataset $datasetN `
            -TopParents (Get-TopN -Table $rollParents -N 10) `
            -TopModules (Get-TopN -Table $rollMods    -N 10) `
            -TopMitre   (Get-TopN -Table $rollMitre   -N 10) `
            -HashCount $records.Count `
            -WithBehaviors $withBehaviors `
            -Malformed $malformed `
            -Oversize $oversize

        $datasetSummaries.Add([pscustomobject]@{
            Bucket          = $bucket
            Name            = $datasetN
            Slug            = $dsSlug
            HashCount       = $records.Count
            WithBehaviors   = $withBehaviors
            MalformedJson   = $malformed
            ReportPath      = (Resolve-RelPath -From $OutputRoot -To $outHtml)
            Cached          = $false
        })

        $tEnd = Get-Date
        Write-Host ("  done in {0:N1}s" -f ($tEnd - $tStart).TotalSeconds) -ForegroundColor Green
    }

    # ----- Top-level dataset selector ----------------------------------------
    if (-not $WhatIfMode -and $datasetSummaries.Count -gt 0) {
        if (-not (Test-Path $OutputRoot)) { New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null }
        Write-IndexHtml -Summaries $datasetSummaries -Path (Join-Path $OutputRoot 'index.html')
    }

    $globalEnd = Get-Date
    Write-Host ("`n[Build-BehavioralFingerprintTable] Finished in {0:N1}s" -f ($globalEnd - $globalStart).TotalSeconds) -ForegroundColor Green
}


# =========================================================================
# Private helpers
# =========================================================================

function Get-DatasetCandidate {
    param(
        [Parameter(Mandatory)] [string]   $BehaviorRoot,
        [Parameter()]          [string[]] $Filter = @()
    )
    $result = New-Object System.Collections.Generic.List[psobject]
    # NOTE: see New-StringSet for why we ,return the list at the bottom of this function.
    foreach ($bucket in @('NSRL','OT')) {
        $bucketRoot = Join-Path $BehaviorRoot $bucket
        if (-not (Test-Path $bucketRoot)) { continue }
        $children = Get-ChildItem -Path $bucketRoot -Directory -ErrorAction SilentlyContinue
        foreach ($c in $children) {
            $slug = "$bucket/$($c.Name)"
            if ($Filter.Count -gt 0 -and ($Filter -notcontains $slug)) { continue }
            # Cheap existence check that short-circuits on first match (avoids
            # walking 30k+ NSRL files when we only need to know "is there >=1").
            $hasJson = $false
            try {
                $enum = [System.IO.Directory]::EnumerateFiles(
                    $c.FullName, '*.json',
                    [System.IO.SearchOption]::AllDirectories)
                foreach ($e in $enum) { $hasJson = $true; break }
            } catch {
                $hasJson = $false
            }
            if (-not $hasJson) { continue }
            $result.Add([pscustomobject]@{
                Bucket = $bucket
                Name   = $c.Name
                Path   = $c.FullName
            })
        }
    }
    return ,$result
}

function Get-BehaviorAttributes {
    param([Parameter(Mandatory)] $Parsed)
    if (-not $Parsed) { return $null }
    $d = $Parsed.data
    if (-not $d) { return $null }
    if ($d -is [System.Array]) {
        if ($d.Count -eq 0) { return $null }
        return $d[0]
    }
    return $d
}

function Resolve-MainJsonPath {
    param(
        [Parameter(Mandatory)] [string] $BehFilePath,
        [Parameter(Mandatory)] [string] $BehRoot,
        [Parameter(Mandatory)] [string] $MainRoot
    )
    if (-not $BehFilePath.StartsWith($BehRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $null
    }
    $rel = $BehFilePath.Substring($BehRoot.Length).TrimStart('\','/')
    return (Join-Path $MainRoot $rel)
}

function Get-VendorCatalog {
    param(
        [Parameter(Mandatory)] [string] $CatalogRoot,
        [Parameter(Mandatory)] [string] $Vendor
    )
    $table = @{}
    $vendorRoot = Join-Path $CatalogRoot $Vendor
    if (-not (Test-Path $vendorRoot)) { return $table }
    $catalogs = @(Get-ChildItem -Path $vendorRoot -Filter catalog.csv -Recurse -File -ErrorAction SilentlyContinue)
    foreach ($cat in $catalogs) {
        try {
            $rows = Import-Csv -Path $cat.FullName -ErrorAction Stop
        } catch {
            Write-Warning ("  catalog parse failed: {0} ({1})" -f $cat.FullName, $_.Exception.Message)
            continue
        }
        foreach ($r in $rows) {
            if (-not $r.Hash) { continue }
            $k = ([string]$r.Hash).ToLowerInvariant().Trim()
            if ($k.Length -ne 64) { continue }
            if ($table.ContainsKey($k)) { continue }   # first-wins de-dupe
            $table[$k] = [pscustomobject]@{
                FileName = "$($r.FileName)"
                OsName   = "$($r.OsName)"
                FullPath = "$($r.FullPath)"
            }
        }
    }
    return $table
}

function Get-NsrlCatalog {
    param([Parameter(Mandatory)] [string] $NsrlCsvPath)
    if (-not (Test-Path $NsrlCsvPath)) {
        Write-Warning "NSRL catalog missing: $NsrlCsvPath"
        return @{}
    }
    $rows = Import-Csv -Path $NsrlCsvPath -ErrorAction Stop
    # group by normalized OsName slug so the per-dataset slice is O(1)
    $grouped = @{}
    foreach ($r in $rows) {
        if (-not $r.Hash) { continue }
        $slug = ConvertTo-OsSlug -OsName $r.OsName
        if (-not $slug) { continue }
        if (-not $grouped.ContainsKey($slug)) { $grouped[$slug] = New-Object System.Collections.Generic.List[psobject] }
        $grouped[$slug].Add($r)
    }
    return $grouped
}

function ConvertTo-OsSlug {
    param([string] $OsName)
    if ([string]::IsNullOrWhiteSpace($OsName)) { return $null }
    $s = $OsName.Trim()
    # Strip noise that doesn't appear in folder slugs
    $s = $s -replace '(?i)\s+LTS\b',''
    $s = $s -replace '(?i)\s+Version\s+\w+',''
    $s = $s -replace '(?i)\s+X64\b',''
    $s = $s -replace '(?i)\s+X86\b',''
    $s = $s.Trim() -replace '\s+','-'
    return $s
}

function Get-NsrlDatasetSlice {
    param(
        [Parameter(Mandatory)] $Catalog,
        [Parameter(Mandatory)] [string] $DatasetSlug
    )
    $table = @{}
    if (-not $Catalog) { return $table }
    if (-not $Catalog.ContainsKey($DatasetSlug)) { return $table }
    foreach ($r in $Catalog[$DatasetSlug]) {
        $k = ([string]$r.Hash).ToLowerInvariant().Trim()
        if ($k.Length -ne 64) { continue }
        if ($table.ContainsKey($k)) { continue }
        $table[$k] = [pscustomobject]@{
            FileName = "$($r.FileName)"
            OsName   = "$($r.OsName)"
            FullPath = ""   # NSRL CSV has no FullPath column
        }
    }
    return $table
}

function New-FingerprintRecord {
    param(
        [Parameter(Mandatory)] [string] $Hash,
                               $BehAttr,
                               $MainAttr,
                               $CatalogRow
    )

    # multi-value accumulators (HashSet, not @() -- O(1) Add)
    $parents   = New-StringSet
    $children  = New-StringSet
    $cmdlines  = New-StringSet
    $fOpened   = New-StringSet
    $fWritten  = New-StringSet
    $fDropped  = New-StringSet
    $rkSet     = New-StringSet
    $rkOpen    = New-StringSet
    $rkDel     = New-StringSet
    $dns       = New-StringSet
    $ipTraffic = New-StringSet
    $http      = New-StringSet
    $modules   = New-StringSet
    $mutexes   = New-StringSet
    $services  = New-StringSet
    $schedTask = New-StringSet
    $mitre     = New-StringSet
    $sigmaTags = New-StringSet
    $yaraTags  = New-StringSet

    $hasBeh = $false
    if ($BehAttr -and ($BehAttr.PSObject.Properties.Count -gt 0)) {
        $hasBeh = $true

        # processes_tree gives parent->child relationships; descend the tree
        # iteratively so we capture grandchildren too (VT trees can be deep).
        if ($BehAttr.processes_tree) {
            foreach ($p in @($BehAttr.processes_tree)) {
                if ($p -and $p.name) { Add-NormalizedToSet -Set $parents -Value $p.name }
                if ($p -and $p.children) {
                    $stack = New-Object System.Collections.Generic.Stack[object]
                    foreach ($c in @($p.children)) { $stack.Push($c) }
                    while ($stack.Count -gt 0) {
                        $node = $stack.Pop()
                        if ($node.name) { Add-NormalizedToSet -Set $children -Value $node.name }
                        if ($node.children) {
                            foreach ($gc in @($node.children)) { $stack.Push($gc) }
                        }
                    }
                }
            }
        }
        if ($BehAttr.processes_created) {
            foreach ($v in @($BehAttr.processes_created)) { Add-NormalizedToSet -Set $children -Value $v }
        }
        if ($BehAttr.command_executions) {
            foreach ($v in @($BehAttr.command_executions)) { Add-NormalizedToSet -Set $cmdlines -Value $v }
        }

        if ($BehAttr.files_opened) {
            foreach ($v in @($BehAttr.files_opened))  { Add-NormalizedToSet -Set $fOpened  -Value $v }
        }
        if ($BehAttr.files_written) {
            foreach ($v in @($BehAttr.files_written)) { Add-NormalizedToSet -Set $fWritten -Value $v }
        }
        if ($BehAttr.files_dropped) {
            foreach ($v in @($BehAttr.files_dropped)) {
                $path = if ($v.path) { $v.path } else { $v }
                Add-NormalizedToSet -Set $fDropped -Value $path
            }
        }

        if ($BehAttr.registry_keys_set) {
            foreach ($v in @($BehAttr.registry_keys_set)) {
                # registry_keys_set elements are objects {key, value}; others may be plain strings
                $rk = if ($v.key) { if ($v.value) { "$($v.key)=$($v.value)" } else { "$($v.key)" } } else { $v }
                Add-NormalizedToSet -Set $rkSet  -Value $rk
            }
        }
        if ($BehAttr.registry_keys_opened) {
            foreach ($v in @($BehAttr.registry_keys_opened)) {
                $rk = if ($v.key) { "$($v.key)" } else { $v }
                Add-NormalizedToSet -Set $rkOpen -Value $rk
            }
        }
        if ($BehAttr.registry_keys_deleted) {
            foreach ($v in @($BehAttr.registry_keys_deleted)) {
                $rk = if ($v.key) { "$($v.key)" } else { $v }
                Add-NormalizedToSet -Set $rkDel  -Value $rk
            }
        }

        if ($BehAttr.dns_lookups) {
            foreach ($v in @($BehAttr.dns_lookups)) {
                $dnsHost = if ($v.hostname) { $v.hostname } else { $v }
                Add-NormalizedToSet -Set $dns -Value $dnsHost
            }
        }
        if ($BehAttr.ip_traffic) {
            foreach ($v in @($BehAttr.ip_traffic)) {
                $ip   = "$($v.destination_ip)"
                $port = "$($v.destination_port)"
                $prot = "$($v.transport_layer_protocol)"
                if ($ip) { Add-NormalizedToSet -Set $ipTraffic -Value ("{0}:{1}/{2}" -f $ip, $port, $prot) }
            }
        }
        if ($BehAttr.memory_pattern_urls) {
            foreach ($v in @($BehAttr.memory_pattern_urls)) { Add-NormalizedToSet -Set $http -Value $v }
        }
        if ($BehAttr.memory_pattern_domains) {
            foreach ($v in @($BehAttr.memory_pattern_domains)) { Add-NormalizedToSet -Set $http -Value $v }
        }

        if ($BehAttr.modules_loaded) {
            foreach ($v in @($BehAttr.modules_loaded)) { Add-NormalizedToSet -Set $modules -Value $v }
        }
        if ($BehAttr.mutexes_created) {
            foreach ($v in @($BehAttr.mutexes_created)) { Add-NormalizedToSet -Set $mutexes -Value $v }
        }
        if ($BehAttr.services_started) {
            foreach ($v in @($BehAttr.services_started)) { Add-NormalizedToSet -Set $services -Value $v }
        }
        if ($BehAttr.PSObject.Properties['services_created']) {
            foreach ($v in @($BehAttr.services_created)) { Add-NormalizedToSet -Set $services -Value $v }
        }

        if ($BehAttr.mitre_attack_techniques) {
            foreach ($t in @($BehAttr.mitre_attack_techniques)) {
                if ($t.id) { Add-NormalizedToSet -Set $mitre -Value $t.id }
            }
        }

        if ($BehAttr.tags) {
            foreach ($v in @($BehAttr.tags)) { Add-NormalizedToSet -Set $sigmaTags -Value $v }
        }
    }

    # Main-JSON Sigma / Yara enrichments
    $signer         = ''
    $signerVerified = ''
    $typeDesc       = ''
    $magic          = ''
    $size           = 0
    $firstSeen      = ''
    $vtMal          = $null
    $vtEng          = $null
    $verdict        = 'Unknown'

    if ($MainAttr) {
        if ($MainAttr.signature_info) {
            $sig = $MainAttr.signature_info
            if ($sig.signers)  { $signer = "$($sig.signers)" }
            if ($sig.verified) { $signerVerified = "$($sig.verified)" }
        }
        if ($MainAttr.type_description) { $typeDesc = "$($MainAttr.type_description)" }
        if ($MainAttr.magic)            { $magic    = "$($MainAttr.magic)" }
        if ($MainAttr.size)             { $size     = [int64]$MainAttr.size }
        if ($MainAttr.first_submission_date) {
            $firstSeen = (Get-Date '1970-01-01').AddSeconds([int64]$MainAttr.first_submission_date).ToString('yyyy-MM-dd')
        }
        if ($MainAttr.last_analysis_stats) {
            $lst = $MainAttr.last_analysis_stats
            $vtMal = [int]$lst.malicious
            $vtEng = [int]$lst.malicious + [int]$lst.suspicious + [int]$lst.undetected + [int]$lst.harmless + [int]$lst.timeout
            if ($vtMal -ge 5)      { $verdict = 'Malicious'  }
            elseif ($vtMal -ge 1)  { $verdict = 'Suspicious' }
            elseif ($vtEng -gt 0)  { $verdict = 'Clean'      }
        }
        if ($MainAttr.sigma_analysis_results) {
            foreach ($s in @($MainAttr.sigma_analysis_results)) {
                if ($s.rule_title) { Add-NormalizedToSet -Set $sigmaTags -Value $s.rule_title }
            }
        }
        if ($MainAttr.crowdsourced_yara_results) {
            foreach ($y in @($MainAttr.crowdsourced_yara_results)) {
                if ($y.rule_name) { Add-NormalizedToSet -Set $yaraTags -Value $y.rule_name }
            }
        }
    }

    $fileName = if ($CatalogRow -and $CatalogRow.FileName) { "$($CatalogRow.FileName)" } else { '(unknown)' }
    $osName   = if ($CatalogRow -and $CatalogRow.OsName)   { "$($CatalogRow.OsName)"   } else { '(unknown)' }
    $fullPath = if ($CatalogRow -and $CatalogRow.FullPath) { "$($CatalogRow.FullPath)" } else { '(unknown)' }
    if (-not $fullPath) { $fullPath = '(unknown)' }

    return [pscustomobject]@{
        Hash                  = $Hash
        FileName              = $fileName
        OsName                = $osName
        FullPath              = $fullPath
        FileSize              = $size
        FirstSeen             = $firstSeen
        Signer                = $signer
        SignerVerified        = $signerVerified
        TypeDescription       = $typeDesc
        MagicSignature        = $magic
        VT_TotalDetections    = $vtMal
        VT_TotalEngines       = $vtEng
        Verdict               = $verdict
        HasBehaviors          = $hasBeh

        # *List members are the in-memory HashSets used both for CSV truncation
        # and dataset-wide rollups. *Csv members are the ';'-joined truncated
        # strings written to Master_Intel.csv.
        ParentProcessesList   = $parents
        ChildProcessesList    = $children
        CmdLineExamplesList   = $cmdlines
        FilesOpenedList       = $fOpened
        FilesWrittenList      = $fWritten
        FilesDroppedList      = $fDropped
        RegistryKeysSetList   = $rkSet
        RegistryKeysOpenedList= $rkOpen
        RegistryKeysDeletedList=$rkDel
        DnsLookupsList        = $dns
        IpTrafficList         = $ipTraffic
        HttpDestinationsList  = $http
        ModulesLoadedList     = $modules
        MutexesCreatedList    = $mutexes
        ServicesCreatedList   = $services
        ScheduledTasksList    = $schedTask
        MitreList             = $mitre
        SigmaTagsList         = $sigmaTags
        YaraTagsList          = $yaraTags
    }
}

function New-StringSet {
    # Comma-prefix prevents PowerShell from enumerating the empty HashSet
    # (which would emit nothing and leave the caller with $null).
    return ,([System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase))
}

function Add-NormalizedToSet {
    param(
        [Parameter(Mandatory)] $Set,
                               $Value
    )
    if ($null -eq $Value) { return }
    $s = "$Value".Trim()
    if ([string]::IsNullOrWhiteSpace($s)) { return }
    if ($s.Length -gt 512) { $s = $s.Substring(0,512) + '...' }
    [void]$Set.Add($s)
}

function Add-Counter {
    param(
        [Parameter(Mandatory)] [hashtable] $Table,
        [Parameter(Mandatory)] [string]    $Key
    )
    if ([string]::IsNullOrWhiteSpace($Key)) { return }
    if (-not $Table.ContainsKey($Key)) { $Table[$Key] = 0 }
    $Table[$Key] = [int]$Table[$Key] + 1
}

function Get-TopN {
    param(
        [Parameter(Mandatory)] [hashtable] $Table,
        [int] $N = 10
    )
    $arr = @($Table.GetEnumerator() |
        Sort-Object -Property Value -Descending |
        Select-Object -First $N |
        ForEach-Object { [pscustomobject]@{ Name = $_.Key; Count = $_.Value } })
    return ,$arr
}

function Format-CapList {
    param(
        [Parameter(Mandatory)] $Set,
        [int] $Cap = 20
    )
    if ($null -eq $Set -or $Set.Count -eq 0) { return '' }
    $arr = @($Set)
    if ($arr.Count -le $Cap) { return ($arr -join ';') }
    $head = $arr | Select-Object -First $Cap
    $extra = $arr.Count - $Cap
    return (($head -join ';') + ";(+$extra more)")
}

function Test-IsOutputFresh {
    param(
        [Parameter(Mandatory)] [string[]] $Outputs,
        [Parameter(Mandatory)]            $Inputs
    )
    foreach ($o in $Outputs) {
        if (-not (Test-Path $o)) { return $false }
    }
    $oldest = ($Outputs | ForEach-Object { (Get-Item $_).LastWriteTimeUtc } | Sort-Object | Select-Object -First 1)
    foreach ($f in $Inputs) {
        if ($f.LastWriteTimeUtc -gt $oldest) { return $false }
    }
    return $true
}

function Resolve-RelPath {
    param(
        [Parameter(Mandatory)] [string] $From,
        [Parameter(Mandatory)] [string] $To
    )
    try {
        $u1 = New-Object System.Uri(($From.TrimEnd('\','/') + '\'))
        $u2 = New-Object System.Uri($To)
        # MakeRelativeUri returns forward slashes (HTML-safe) and URL-encodes
        # spaces as %20; that's exactly what href="" wants.
        return $u1.MakeRelativeUri($u2).ToString()
    } catch {
        return $To
    }
}

# =========================================================================
# Writers
# =========================================================================

function Write-MasterIntelCsv {
    param(
        [Parameter(Mandatory)] $Records,
        [Parameter(Mandatory)] [string] $Path
    )
    $rows = foreach ($r in $Records) {
        [pscustomobject][ordered]@{
            Hash                  = $r.Hash
            FileName              = $r.FileName
            OsName                = $r.OsName
            FullPath              = $r.FullPath
            FileSize              = $r.FileSize
            FirstSeen             = $r.FirstSeen
            Signer                = $r.Signer
            SignerVerified        = $r.SignerVerified
            TypeDescription       = $r.TypeDescription
            MagicSignature        = $r.MagicSignature
            VT_TotalDetections    = $r.VT_TotalDetections
            VT_TotalEngines       = $r.VT_TotalEngines
            ParentProcesses       = (Format-CapList -Set $r.ParentProcessesList)
            ChildProcesses        = (Format-CapList -Set $r.ChildProcessesList)
            CmdLineExamples       = (Format-CapList -Set $r.CmdLineExamplesList)
            FilesOpened           = (Format-CapList -Set $r.FilesOpenedList)
            FilesWritten          = (Format-CapList -Set $r.FilesWrittenList)
            FilesDropped          = (Format-CapList -Set $r.FilesDroppedList)
            RegistryKeysSet       = (Format-CapList -Set $r.RegistryKeysSetList)
            RegistryKeysOpened    = (Format-CapList -Set $r.RegistryKeysOpenedList)
            RegistryKeysDeleted   = (Format-CapList -Set $r.RegistryKeysDeletedList)
            DnsLookups            = (Format-CapList -Set $r.DnsLookupsList)
            IpTraffic             = (Format-CapList -Set $r.IpTrafficList)
            HttpDestinations      = (Format-CapList -Set $r.HttpDestinationsList)
            ModulesLoaded         = (Format-CapList -Set $r.ModulesLoadedList)
            MutexesCreated        = (Format-CapList -Set $r.MutexesCreatedList)
            ServicesCreated       = (Format-CapList -Set $r.ServicesCreatedList)
            ScheduledTasks        = (Format-CapList -Set $r.ScheduledTasksList)
            MitreAttackTechniques = (Format-CapList -Set $r.MitreList)
            SigmaTags             = (Format-CapList -Set $r.SigmaTagsList)
            YaraTags              = (Format-CapList -Set $r.YaraTagsList)
        }
    }
    $rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

function Write-BehaviorsIndexJson {
    param(
        [Parameter(Mandatory)] $Records,
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Bucket,
        [Parameter(Mandatory)] [string] $Dataset
    )
    $payload = [ordered]@{
        bucket  = $Bucket
        dataset = $Dataset
        built   = (Get-Date).ToString('s')
        schema  = 'behavioral-fingerprint-v1'
        records = @(
            foreach ($r in $Records) {
                [ordered]@{
                    hash                    = $r.Hash
                    file_name               = $r.FileName
                    os_name                 = $r.OsName
                    full_path               = $r.FullPath
                    file_size               = $r.FileSize
                    first_seen              = $r.FirstSeen
                    signer                  = $r.Signer
                    signer_verified         = $r.SignerVerified
                    type_description        = $r.TypeDescription
                    magic                   = $r.MagicSignature
                    vt_detections           = $r.VT_TotalDetections
                    vt_engines              = $r.VT_TotalEngines
                    verdict                 = $r.Verdict
                    has_behaviors           = $r.HasBehaviors
                    parent_processes        = @($r.ParentProcessesList)
                    child_processes         = @($r.ChildProcessesList)
                    command_executions      = @($r.CmdLineExamplesList)
                    files_opened            = @($r.FilesOpenedList)
                    files_written           = @($r.FilesWrittenList)
                    files_dropped           = @($r.FilesDroppedList)
                    registry_keys_set       = @($r.RegistryKeysSetList)
                    registry_keys_opened    = @($r.RegistryKeysOpenedList)
                    registry_keys_deleted   = @($r.RegistryKeysDeletedList)
                    dns_lookups             = @($r.DnsLookupsList)
                    ip_traffic              = @($r.IpTrafficList)
                    http_destinations       = @($r.HttpDestinationsList)
                    modules_loaded          = @($r.ModulesLoadedList)
                    mutexes_created         = @($r.MutexesCreatedList)
                    services_created        = @($r.ServicesCreatedList)
                    scheduled_tasks         = @($r.ScheduledTasksList)
                    mitre_attack_techniques = @($r.MitreList)
                    sigma_tags              = @($r.SigmaTagsList)
                    yara_tags               = @($r.YaraTagsList)
                }
            }
        )
    }
    $json = $payload | ConvertTo-Json -Depth 8 -Compress
    [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
}

function ConvertTo-SafeHtml {
    param([string] $Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Value)
}

function Write-DetailedReportHtml {
    param(
        [Parameter(Mandatory)] $Records,
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Bucket,
        [Parameter(Mandatory)] [string] $Dataset,
        [Parameter(Mandatory)] $TopParents,
        [Parameter(Mandatory)] $TopModules,
        [Parameter(Mandatory)] $TopMitre,
        [Parameter(Mandatory)] [int] $HashCount,
        [Parameter(Mandatory)] [int] $WithBehaviors,
        [Parameter(Mandatory)] [int] $Malformed,
        [Parameter(Mandatory)] [int] $Oversize
    )

    # Build the inline JSON payload that DataTables will consume.
    $payload = @(
        foreach ($r in $Records) {
            [ordered]@{
                hash      = $r.Hash
                file      = $r.FileName
                os        = $r.OsName
                signer    = $r.Signer
                verdict   = $r.Verdict
                det       = $r.VT_TotalDetections
                eng       = $r.VT_TotalEngines
                size      = $r.FileSize
                first     = $r.FirstSeen
                type      = $r.TypeDescription
                magic     = $r.MagicSignature
                path      = $r.FullPath
                parents   = @($r.ParentProcessesList)
                children  = @($r.ChildProcessesList)
                cmds      = @($r.CmdLineExamplesList)
                f_open    = @($r.FilesOpenedList)
                f_write   = @($r.FilesWrittenList)
                f_drop    = @($r.FilesDroppedList)
                rk_set    = @($r.RegistryKeysSetList)
                rk_open   = @($r.RegistryKeysOpenedList)
                rk_del    = @($r.RegistryKeysDeletedList)
                dns       = @($r.DnsLookupsList)
                ip        = @($r.IpTrafficList)
                http      = @($r.HttpDestinationsList)
                modules   = @($r.ModulesLoadedList)
                mutex     = @($r.MutexesCreatedList)
                svc       = @($r.ServicesCreatedList)
                sched     = @($r.ScheduledTasksList)
                mitre     = @($r.MitreList)
                sigma     = @($r.SigmaTagsList)
                yara      = @($r.YaraTagsList)
            }
        }
    )
    $payloadJson = ($payload | ConvertTo-Json -Depth 8 -Compress)
    $payloadB64  = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadJson))

    # Top-N rollup HTML (rendered server-side; small)
    function _RollupItems($items) {
        if (-not $items -or $items.Count -eq 0) { return '<li class="list-group-item text-muted">(none)</li>' }
        ($items | ForEach-Object {
            "<li class='list-group-item d-flex justify-content-between align-items-center'><span>$(ConvertTo-SafeHtml $_.Name)</span><span class='badge bg-secondary rounded-pill'>$($_.Count)</span></li>"
        }) -join ''
    }
    $rollParentsHtml = _RollupItems $TopParents
    $rollModsHtml    = _RollupItems $TopModules
    $rollMitreHtml   = _RollupItems $TopMitre

    $title = "Behavioral Fingerprint - $Bucket / $Dataset"

    # Breadcrumb depth: file lives at <OutputRoot>/<Bucket>/<Dataset>/Detailed_Report.html
    # so the index.html dataset selector is 2 levels up.
    $bucketEnc  = ConvertTo-SafeHtml $Bucket
    $datasetEnc = ConvertTo-SafeHtml $Dataset

    $html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<title>$title</title>
<link href='https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css' rel='stylesheet'>
<link href='https://cdn.datatables.net/2.1.8/css/dataTables.bootstrap5.min.css' rel='stylesheet'>
<style>
  body { background:#f8f9fa; font-family:'Segoe UI',system-ui,sans-serif; padding:20px; }
  .breadcrumb { background:#e9ecef; padding:10px 15px; border-radius:5px; margin-bottom:20px; }
  .score-high { color:#dc3545; font-weight:bold; }
  .score-med  { color:#fd7e14; font-weight:bold; }
  .score-low  { color:#198754; }
  .source-badge { font-size:.75rem; padding:2px 6px; border-radius:4px; background:#e2e8f0; color:#475569; border:1px solid #cbd5e1; }
  .filter-bar { background:white; padding:15px; border-radius:5px; margin-bottom:20px; box-shadow:0 1px 3px rgba(0,0,0,.1); }
  .summary-card { background:white; padding:15px; border-radius:5px; box-shadow:0 1px 3px rgba(0,0,0,.1); margin-bottom:20px; }
  .hash-cell { font-family: 'Consolas','Monaco',monospace; font-size:.85rem; }
  .chip { display:inline-block; padding:2px 6px; margin:2px; background:#eef2ff; color:#3730a3; border:1px solid #c7d2fe; border-radius:4px; font-size:.78rem; word-break:break-all; }
  .chip-mitre { background:#fee2e2; color:#991b1b; border-color:#fca5a5; }
  .chip-cmd { background:#fef3c7; color:#92400e; border-color:#fcd34d; font-family:'Consolas','Monaco',monospace; }
  .verdict-clean      { background:#dcfce7; color:#166534; padding:2px 6px; border-radius:4px; font-size:.78rem; }
  .verdict-suspicious { background:#fef3c7; color:#92400e; padding:2px 6px; border-radius:4px; font-size:.78rem; }
  .verdict-malicious  { background:#fee2e2; color:#991b1b; padding:2px 6px; border-radius:4px; font-size:.78rem; }
  .verdict-unknown    { background:#e5e7eb; color:#374151; padding:2px 6px; border-radius:4px; font-size:.78rem; }
  details > summary { cursor:pointer; font-weight:600; color:#1e40af; padding:4px 0; }
  .col-section { margin-bottom:8px; }
  .col-section .col-title { font-weight:600; color:#475569; font-size:.85rem; margin-right:6px; }
  table.dataTable td { vertical-align: middle; }
</style>
</head>
<body>
<nav aria-label='breadcrumb'>
  <ol class='breadcrumb'>
    <li class='breadcrumb-item'><a href='../../index.html'>Behavioral Fingerprints</a></li>
    <li class='breadcrumb-item'>$bucketEnc</li>
    <li class='breadcrumb-item active'>$datasetEnc</li>
  </ol>
</nav>

<div class='d-flex justify-content-between align-items-center mb-3'>
  <h2>$bucketEnc / $datasetEnc <span class='badge bg-secondary'>Behavioral Fingerprint</span></h2>
  <span class='text-muted small'>Built $(Get-Date -Format 's')</span>
</div>

<div class='row'>
  <div class='col-md-3'>
    <div class='summary-card'>
      <h6 class='text-muted'>Hashes</h6>
      <div class='h3'>$HashCount</div>
      <div class='small text-muted'>$WithBehaviors with behavior data</div>
      <div class='small text-muted'>$Malformed malformed json, $Oversize oversize</div>
    </div>
  </div>
  <div class='col-md-3'>
    <div class='summary-card'>
      <h6 class='text-muted'>Top Parent Processes</h6>
      <ul class='list-group list-group-flush'>$rollParentsHtml</ul>
    </div>
  </div>
  <div class='col-md-3'>
    <div class='summary-card'>
      <h6 class='text-muted'>Top Modules Loaded</h6>
      <ul class='list-group list-group-flush'>$rollModsHtml</ul>
    </div>
  </div>
  <div class='col-md-3'>
    <div class='summary-card'>
      <h6 class='text-muted'>Top MITRE Techniques</h6>
      <ul class='list-group list-group-flush'>$rollMitreHtml</ul>
    </div>
  </div>
</div>

<div class='filter-bar'>
  <div class='form-check form-check-inline'>
    <input class='form-check-input col-toggle' type='checkbox' id='col-type'    data-col='8'><label class='form-check-label' for='col-type'>Type</label>
  </div>
  <div class='form-check form-check-inline'>
    <input class='form-check-input col-toggle' type='checkbox' id='col-size'    data-col='9'><label class='form-check-label' for='col-size'>Size</label>
  </div>
  <div class='form-check form-check-inline'>
    <input class='form-check-input col-toggle' type='checkbox' id='col-first'   data-col='10'><label class='form-check-label' for='col-first'>First Seen</label>
  </div>
  <div class='form-check form-check-inline'>
    <input class='form-check-input col-toggle' type='checkbox' id='col-path'    data-col='11'><label class='form-check-label' for='col-path'>Path</label>
  </div>
  <span class='text-muted small ms-3'>Click any row to expand the full behavior detail.</span>
</div>

<table id='fp-table' class='table table-striped table-hover' style='width:100%'>
  <thead>
    <tr>
      <th></th>
      <th>Hash</th>
      <th>File Name</th>
      <th>OS Name</th>
      <th>Signer</th>
      <th>Verdict</th>
      <th>Detections</th>
      <th>Engines</th>
      <th>Type</th>
      <th>Size</th>
      <th>First Seen</th>
      <th>Path</th>
    </tr>
  </thead>
</table>

<textarea id='data_store' style='display:none'>$payloadB64</textarea>

<script src='https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js'></script>
<script src='https://code.jquery.com/jquery-3.7.1.min.js'></script>
<script src='https://cdn.datatables.net/2.1.8/js/dataTables.min.js'></script>
<script src='https://cdn.datatables.net/2.1.8/js/dataTables.bootstrap5.min.js'></script>
<script>
(function(){
  function decodePayload(){
    try {
      var b64 = document.getElementById('data_store').value.trim();
      var raw = atob(b64);
      var bytes = new Uint8Array(raw.length);
      for (var i=0;i<raw.length;i++){ bytes[i] = raw.charCodeAt(i); }
      var json = new TextDecoder('utf-8').decode(bytes);
      return JSON.parse(json);
    } catch(e){ console.error('payload decode failed', e); return []; }
  }
  function esc(s){ if (s===null||s===undefined) return ''; return String(s).replace(/[&<>"']/g, function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];}); }
  function chips(arr, klass){
    if (!arr || !arr.length) return '<span class="text-muted">(none)</span>';
    return arr.map(function(v){ return '<span class="chip '+(klass||'')+'">'+esc(v)+'</span>'; }).join('');
  }
  function verdictBadge(v){
    var cls = 'verdict-unknown';
    if (v==='Clean')      cls='verdict-clean';
    if (v==='Suspicious') cls='verdict-suspicious';
    if (v==='Malicious')  cls='verdict-malicious';
    return '<span class="'+cls+'">'+esc(v)+'</span>';
  }
  function hashCell(h){
    return '<span class="hash-cell" title="'+esc(h)+'">'+esc(h.substring(0,12))+'...</span>';
  }
  function detailHtml(r){
    var sections = [
      ['Parent Processes',   chips(r.parents, '')],
      ['Child Processes',    chips(r.children, '')],
      ['Command Executions', chips(r.cmds, 'chip-cmd')],
      ['MITRE Techniques',   chips(r.mitre, 'chip-mitre')],
      ['Modules Loaded',     chips(r.modules, '')],
      ['Mutexes Created',    chips(r.mutex, '')],
      ['Services Created',   chips(r.svc, '')],
      ['Scheduled Tasks',    chips(r.sched, '')],
      ['Files Opened',       chips(r.f_open, '')],
      ['Files Written',      chips(r.f_write, '')],
      ['Files Dropped',      chips(r.f_drop, '')],
      ['Registry Set',       chips(r.rk_set, '')],
      ['Registry Opened',    chips(r.rk_open, '')],
      ['Registry Deleted',   chips(r.rk_del, '')],
      ['DNS Lookups',        chips(r.dns, '')],
      ['IP Traffic',         chips(r.ip, '')],
      ['HTTP Destinations',  chips(r.http, '')],
      ['Sigma Tags',         chips(r.sigma, '')],
      ['Yara Tags',          chips(r.yara, '')]
    ];
    var open = ['Parent Processes','Child Processes','Command Executions','MITRE Techniques'];
    var out = '<div class="p-3">';
    sections.forEach(function(s){
      var isOpen = open.indexOf(s[0]) >= 0;
      out += '<details'+(isOpen?' open':'')+'><summary>'+s[0]+'</summary><div class="col-section">'+s[1]+'</div></details>';
    });
    out += '</div>';
    return out;
  }
  var data = decodePayload();
  var rows = data.map(function(r){ return [
    '<span class="dt-control">+</span>',
    hashCell(r.hash),
    esc(r.file),
    esc(r.os),
    esc(r.signer),
    verdictBadge(r.verdict),
    (r.det===null||r.det===undefined) ? '' : r.det,
    (r.eng===null||r.eng===undefined) ? '' : r.eng,
    esc(r.type),
    r.size || '',
    esc(r.first),
    esc(r.path)
  ]; });
  var table = new DataTable('#fp-table', {
    data: rows,
    columns: [
      { className:'dt-control', orderable:false, defaultContent:'+' },
      { title:'Hash' }, { title:'File Name' }, { title:'OS Name' },
      { title:'Signer' }, { title:'Verdict' },
      { title:'Detections' }, { title:'Engines' },
      { title:'Type', visible:false },
      { title:'Size', visible:false },
      { title:'First Seen', visible:false },
      { title:'Path', visible:false }
    ],
    pageLength: 25,
    order: [[5,'asc'],[2,'asc']]
  });
  // Expand-on-click
  document.querySelector('#fp-table tbody').addEventListener('click', function(ev){
    var tr = ev.target.closest('tr');
    if (!tr) return;
    var row = table.row(tr);
    if (!row.data()) return;
    var idx = row.index();
    if (row.child.isShown()) { row.child.hide(); }
    else { row.child(detailHtml(data[idx])).show(); }
  });
  // Column toggles
  document.querySelectorAll('.col-toggle').forEach(function(cb){
    cb.addEventListener('change', function(){
      var col = table.column(parseInt(cb.dataset.col,10));
      col.visible(cb.checked);
    });
  });
})();
</script>
</body>
</html>
"@

    [System.IO.File]::WriteAllText($Path, $html, [System.Text.UTF8Encoding]::new($false))
}

function Write-IndexHtml {
    param(
        [Parameter(Mandatory)] $Summaries,
        [Parameter(Mandatory)] [string] $Path
    )
    $rows = ($Summaries | Sort-Object Bucket, Name | ForEach-Object {
        $linkRel = "$($_.Bucket)/$($_.Name)/Detailed_Report.html"
        $with = if ($null -eq $_.WithBehaviors) { '?' } else { "$($_.WithBehaviors)" }
        "<tr><td>$(ConvertTo-SafeHtml $_.Bucket)</td><td><a href='$(ConvertTo-SafeHtml $linkRel)'>$(ConvertTo-SafeHtml $_.Name)</a></td><td class='text-end'>$($_.HashCount)</td><td class='text-end'>$with</td><td class='text-end'>$($_.MalformedJson)</td></tr>"
    }) -join "`n"

    $html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<title>Behavioral Fingerprint Index</title>
<link href='https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css' rel='stylesheet'>
<style>
  body { background:#f8f9fa; font-family:'Segoe UI',system-ui,sans-serif; padding:20px; }
  .breadcrumb { background:#e9ecef; padding:10px 15px; border-radius:5px; margin-bottom:20px; }
  table { background:white; border-radius:5px; box-shadow:0 1px 3px rgba(0,0,0,.1); }
</style>
</head>
<body>
<nav aria-label='breadcrumb'>
  <ol class='breadcrumb'>
    <li class='breadcrumb-item'><a href='../../output/Global_Threat_Dashboard.html'>Dashboard</a></li>
    <li class='breadcrumb-item active'>Behavioral Fingerprints</li>
  </ol>
</nav>
<h2>Behavioral Fingerprint Index <span class='badge bg-secondary'>Known-Good Reference</span></h2>
<p class='text-muted'>Built $(Get-Date -Format 's'). Inverse-differential view: "what does this known-good hash NORMALLY do" - use it to spot anomalies in live telemetry.</p>
<table class='table table-striped table-hover'>
  <thead>
    <tr><th>Bucket</th><th>Dataset</th><th class='text-end'>Hashes</th><th class='text-end'>With Behaviors</th><th class='text-end'>Malformed</th></tr>
  </thead>
  <tbody>
$rows
  </tbody>
</table>
</body>
</html>
"@

    [System.IO.File]::WriteAllText($Path, $html, [System.Text.UTF8Encoding]::new($false))
}

Export-ModuleMember -Function Build-BehavioralFingerprintTable

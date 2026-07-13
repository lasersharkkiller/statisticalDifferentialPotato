function Test-FidelityIndexCalibration {
    <#
    .SYNOPSIS
        Binding calibration gate for the 20-file orthogonal fidelity-index schema (v2).

    .DESCRIPTION
        Validates a freshly-built output-baseline\fidelity-* index set against the
        five binding acceptance gates from the USER-APPROVED design signoff:

          1. Schema sanity        - manifest v2, all 20 indices present, per-dim
                                    entry_count > 0, Mtotal/Gtotal > 0, known-good
                                    test artifacts behave as expected.
          2. Normalization        - IPv6 canonical form, MITRE sub-technique parent
                                    rollup, mutex Global\ prefix strip, cert publisher
                                    casing.
          3. Performance          - module-init < 2.0s, eager manifest delta < 10 MB,
                                    lazy-load (3 representative dims) delta < 100 MB.
          4. Verdict regression   - >=95% verdict agreement vs legacy on labeled
                                    detonation NDJSON corpora; no COMPROMISED sample
                                    may regress to CLEAN.
          5. Persistence          - on overall PASS, set
                                    manifest.scoring.calibration_passed = $true and
                                    round-trip fidelity-manifest.json in place.

        The consumer (ElasticAlertAgent.Import-FidelityIndices) refuses to enable
        the new scoring path unless calibration_passed is $true.

    .PARAMETER BaselineRoot
        Path to output-baseline containing fidelity-manifest.json and 18 per-dim
        index files plus the legacy flat fidelity-index.json compat shim.
        Default: elasticPotato\output-baseline (resolved relative to this module).

    .PARAMETER LabeledCorpusRoot
        Root that contains 1..N labeled detonation NDJSON corpora directories.
        Each immediate child directory is treated as one labeled sample; the most
        recent 5 (by LastWriteTime) are used for the verdict regression gate.
        Default: elasticPotato\purpleTeaming.

    .PARAMETER MinCorpora
        Minimum number of labeled corpora required to satisfy the Phase 4
        binding-gate floor. Default: 20 (chosen so that ceil(0.05 * 20) = 1
        disagreement is still tolerated under the 95% bar).

        PILOT MODE: passing a smaller value (e.g. -MinCorpora 3) lowers the
        floor and lets Phase 4 run on a small staged corpus. This materially
        weakens calibration_passed semantics - statistical confidence is
        reduced because a single disagreement at n=3 already crosses the 5%
        tolerance. The chosen value is written to
        manifest.scoring.calibration_min_corpora so the consumer can render a
        'PILOT MODE' badge and dashboards can warn. Stage more corpora before
        relying on the gate in production.

    .EXAMPLE
        Test-FidelityIndexCalibration -Verbose

    .EXAMPLE
        # Pilot mode with only 3 staged corpora. Calibration may PASS but
        # confidence is materially reduced - see -MinCorpora notes.
        Test-FidelityIndexCalibration -MinCorpora 3 -Verbose

    .NOTES
        Sets $global:LASTEXITCODE = 0 on PASS, 1 on FAIL/SKIP-overall.
        CAVEAT: PowerShell's $LASTEXITCODE is set by NATIVE processes; setting
        $global:LASTEXITCODE from a function does not guarantee the CI host sees
        a non-zero exit. In CI under `pwsh -File` or `pwsh -Command`, callers
        MUST propagate the result explicitly:
            $r = Test-FidelityIndexCalibration; if (-not $r.Passed) { exit 1 }
        The function returns a PSCustomObject so the Passed property is reliable.
        Does NOT throw on gate failure; the failure is reported via console and
        encoded in the manifest.scoring.calibration_passed flag.

        PHASE 4 HONEST-SKIP CONTRACT (post adversarial review):
        Phase 4 (verdict regression) is a BINDING gate. It does NOT use an
        in-runner shadow scorer - that would be a tautology because both lanes
        would share the same input distribution by construction. Instead the
        phase loads the REAL consumer (ElasticAlertAgent.psm1) and drives a
        legacy lane vs new lane comparison over labeled NDJSON corpora.
        When the corpora and/or consumer entrypoint are unavailable Phase 4
        marks itself SKIPPED and calibration_passed is written as $null (NOT
        $true and NOT $false). Callers MUST NOT assume calibration_passed=$true
        without also checking scoring.calibration_phase4_status; the new
        manifest field calibration_phase4_status is one of:
            'PASSED'  - Phase 4 ran end-to-end and met the >=95% agreement +
                        no-COMPROMISED->CLEAN-regression bar.
            'FAILED'  - Phase 4 ran but disagreed above tolerance or detected a
                        regression. calibration_passed = $false.
            'SKIPPED' - Phase 4 could not run (no corpora / consumer not
                        loadable / no toggleable entrypoint).
                        calibration_passed = $null (no binding evidence).
            'NOT_RUN' - Should not occur in normal runs; sentinel value.

        PILOT MODE (-MinCorpora override):
            The default minimum-N floor for the binding Phase 4 gate is 20.
            Below 20 the gate SKIPS and calibration_passed stays $null. For
            initial bring-up with a small staged corpus, pass -MinCorpora N
            (e.g. 3). The console banner will print
                'PILOT MODE: min-N floor lowered to N (default 20). Statistical
                 confidence reduced; calibration_passed semantics weakened.'
            and manifest.scoring.calibration_min_corpora is written with the
            value used so consumers can render a 'pilot mode' badge. Stage
            more corpora (especially CLEAN-labeled samples) before relying on
            the gate in production.

        POINTER CORPORA (pointer.json):
            A corpus subdirectory under -LabeledCorpusRoot may contain a single
            pointer.json file that resolves to an external absolute_path. This
            keeps large NDJSON detonation logs out of the repo. When
            pointer.json is detected, the runner resolves absolute_path and
            walks that directory instead. Pointer schema:
                { "label": "COMPROMISED",
                  "framework": "Sliver",
                  "absolute_path": "C:\\path\\to\\corpus",
                  "expected_verdict": "COMPROMISED",
                  "datasets": ["windows.sysmon_operational.ndjson", ...] }
    #>
    [CmdletBinding()]
    param(
        [string]$BaselineRoot      = "",
        [string]$LabeledCorpusRoot = "",
        # PILOT MODE override. Default 20 - matches the binding-gate floor that
        # was hardcoded prior to this commit. Pass a smaller value (e.g. 3) to
        # let Phase 4 run on a small staged corpus during initial bring-up.
        # See -MinCorpora notes in .PARAMETER / .NOTES for the confidence
        # caveat - statistical bar is materially weakened below 20.
        [ValidateRange(1, 10000)]
        [int]$MinCorpora           = 20
    )

    # ---------- path resolution ----------
    # Relative paths are resolved against BOTH candidate repo roots (cross-repo
    # default), preferring the one that actually exists. We deliberately do NOT
    # blindly join relative paths against $PSScriptRoot\.. because that resolves
    # to statisticalDifferentialPotato\output-baseline - the WRONG repo - and
    # would silently calibrate against a stale or non-existent baseline.
    $crossRepoBaselineCandidates = @(
        (Join-Path $PSScriptRoot "..\..\elasticPotato\output-baseline"),
        (Join-Path $PSScriptRoot "..\output-baseline")
    )
    if (-not $BaselineRoot) {
        foreach ($c in $crossRepoBaselineCandidates) {
            if (Test-Path $c) { $BaselineRoot = [System.IO.Path]::GetFullPath($c); break }
        }
        if (-not $BaselineRoot) { $BaselineRoot = [System.IO.Path]::GetFullPath($crossRepoBaselineCandidates[0]) }
    } elseif (-not [System.IO.Path]::IsPathRooted($BaselineRoot)) {
        # Relative override: resolve against CALLER's CWD first (least-surprise -
        # the caller wrote the path string relative to where they ran the cmdlet,
        # not where the runner module happens to live). Only if CWD-relative does
        # not exist do we probe the cross-repo candidates as a last-ditch
        # disambiguation. Then error if NONE exist.
        $rel = $BaselineRoot
        $tried = @()
        $resolved = $null
        foreach ($base in @((Get-Location).Path, (Join-Path $PSScriptRoot "..\..\elasticPotato"), (Join-Path $PSScriptRoot ".."))) {
            $p = Join-Path $base $rel
            $tried += $p
            if (Test-Path $p) { $resolved = [System.IO.Path]::GetFullPath($p); break }
        }
        if (-not $resolved) {
            throw "BaselineRoot '$rel' is relative and was not found under any candidate root. Tried: $($tried -join '; '). Pass an absolute path."
        }
        Write-Host ("  [BaselineRoot resolved] '{0}' -> {1}" -f $rel, $resolved) -ForegroundColor DarkGray
        $BaselineRoot = $resolved
    }

    $crossRepoCorpusCandidates = @(
        (Join-Path $PSScriptRoot "..\..\elasticPotato\purpleTeaming"),
        (Join-Path $PSScriptRoot "..\purpleTeaming")
    )
    if (-not $LabeledCorpusRoot) {
        foreach ($c in $crossRepoCorpusCandidates) {
            if (Test-Path $c) { $LabeledCorpusRoot = [System.IO.Path]::GetFullPath($c); break }
        }
        if (-not $LabeledCorpusRoot) { $LabeledCorpusRoot = [System.IO.Path]::GetFullPath($crossRepoCorpusCandidates[0]) }
    } elseif (-not [System.IO.Path]::IsPathRooted($LabeledCorpusRoot)) {
        # Same CWD-first policy as BaselineRoot above.
        $rel = $LabeledCorpusRoot
        $tried = @()
        $resolved = $null
        foreach ($base in @((Get-Location).Path, (Join-Path $PSScriptRoot "..\..\elasticPotato"), (Join-Path $PSScriptRoot ".."))) {
            $p = Join-Path $base $rel
            $tried += $p
            if (Test-Path $p) { $resolved = [System.IO.Path]::GetFullPath($p); break }
        }
        if (-not $resolved) {
            throw "LabeledCorpusRoot '$rel' is relative and was not found under any candidate root. Tried: $($tried -join '; '). Pass an absolute path."
        }
        Write-Host ("  [LabeledCorpusRoot resolved] '{0}' -> {1}" -f $rel, $resolved) -ForegroundColor DarkGray
        $LabeledCorpusRoot = $resolved
    }

    # ---------- gate accumulator ----------
    # Each gate row: @{ Phase=1..5; Name=...; Status='PASS'|'FAIL'|'SKIP'; Detail=...; Blocking=$true|$false }
    $gates = New-Object System.Collections.Generic.List[object]
    function Add-Gate {
        param([int]$Phase,[string]$Name,[string]$Status,[string]$Detail,[bool]$Blocking=$true)
        $gates.Add([pscustomobject]@{
            Phase    = $Phase
            Name     = $Name
            Status   = $Status
            Detail   = $Detail
            Blocking = $Blocking
        })
        $color = switch ($Status) { 'PASS' {'Green'} 'FAIL' {'Red'} 'SKIP' {'Yellow'} default {'Gray'} }
        $tag   = if ($Blocking -and $Status -eq 'FAIL') { '[BLOCK]' } elseif ($Status -eq 'SKIP') { '[SKIP] ' } else { "[$Status] " }
        Write-Host ("  {0} {1,-46} {2}" -f $tag.PadRight(7), $Name, $Detail) -ForegroundColor $color
    }

    function Write-PhaseBanner {
        param([int]$N,[string]$Title)
        Write-Host ""
        Write-Host ("=" * 78) -ForegroundColor DarkCyan
        Write-Host (" PHASE {0} - {1}" -f $N, $Title) -ForegroundColor Cyan
        Write-Host ("=" * 78) -ForegroundColor DarkCyan
    }

    # The 19-file REQUIRED index set (manifest + 18 per-dim), per design signoff.
    # The legacy flat 'fidelity-index.json' compat shim is optional and checked
    # separately as a non-blocking WARN gate below.
    $expectedIndexFiles = @(
        'fidelity-manifest.json'
        'fidelity-ip.json'
        'fidelity-dns.json'
        'fidelity-process.json'
        'fidelity-file.json'
        'fidelity-registry.json'
        'fidelity-sigma-rule.json'
        'fidelity-yara-rule.json'
        'fidelity-cert-status.json'
        'fidelity-cert-publisher.json'
        'fidelity-mitre-technique.json'
        'fidelity-service.json'
        'fidelity-scheduled-task.json'
        'fidelity-module-load.json'
        'fidelity-command-execution.json'
        'fidelity-mutex.json'
        'fidelity-pipe.json'
        'fidelity-win-api.json'
        'fidelity-vt-tag.json'
    )
    # Per-dim index files (excludes manifest) = 18 files.
    $perDimFiles = @($expectedIndexFiles | Where-Object { $_ -ne 'fidelity-manifest.json' })

    Write-Host ""
    Write-Host "Test-FidelityIndexCalibration" -ForegroundColor White
    Write-Host ("  BaselineRoot      : {0}" -f $BaselineRoot) -ForegroundColor Gray
    Write-Host ("  LabeledCorpusRoot : {0}" -f $LabeledCorpusRoot) -ForegroundColor Gray
    $pilotTag = if ($MinCorpora -lt 20) { ' (PILOT MODE)' } else { '' }
    Write-Host ("  MinCorpora        : {0}{1}" -f $MinCorpora, $pilotTag) -ForegroundColor Gray
    # PILOT MODE banner - explicit, loud, repeated in the Phase 4 SKIP path too.
    # If the caller lowered the floor we want the operator to see this BEFORE any
    # gate output so they cannot miss it in a long log tail.
    $script:_pilotModeActive = ($MinCorpora -lt 20)
    if ($script:_pilotModeActive) {
        Write-Host ""
        Write-Host ("  PILOT MODE: min-N floor lowered to {0} (default 20). Statistical confidence reduced; calibration_passed semantics weakened." -f $MinCorpora) -ForegroundColor Yellow
        Write-Host  "             Stage more corpora (especially CLEAN-labeled baselines) before relying on the gate in production." -ForegroundColor Yellow
    }

    # ============================================================
    # PHASE 1 - SCHEMA SANITY
    # ============================================================
    Write-PhaseBanner 1 "SCHEMA SANITY"
    $manifestPath = Join-Path $BaselineRoot 'fidelity-manifest.json'
    $manifest     = $null
    $manifestRaw  = $null

    if (-not (Test-Path $BaselineRoot)) {
        Add-Gate 1 'BaselineRoot exists' 'FAIL' "Path not found: $BaselineRoot"
    } else {
        Add-Gate 1 'BaselineRoot exists' 'PASS' $BaselineRoot $false
    }

    if (-not (Test-Path $manifestPath)) {
        Add-Gate 1 'fidelity-manifest.json present' 'FAIL' "Missing: $manifestPath"
    } else {
        try {
            $manifestRaw = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop
            $manifest    = $manifestRaw | ConvertFrom-Json -ErrorAction Stop
            Add-Gate 1 'fidelity-manifest.json parses' 'PASS' "$([Math]::Round((Get-Item $manifestPath).Length/1KB,1)) KB"
        } catch {
            Add-Gate 1 'fidelity-manifest.json parses' 'FAIL' $_.Exception.Message
        }
    }

    if ($manifest) {
        # schema_version == 2
        if ($manifest.schema_version -eq 2) {
            Add-Gate 1 'manifest.schema_version == 2' 'PASS' "v$($manifest.schema_version)"
        } else {
            Add-Gate 1 'manifest.schema_version == 2' 'FAIL' "got: '$($manifest.schema_version)'"
        }

        # All 20 files referenced + on disk
        $declared = @()
        if ($manifest.indices) { $declared = @($manifest.indices | ForEach-Object { $_.file }) }
        $missingFromManifest = @($expectedIndexFiles | Where-Object { $_ -ne 'fidelity-manifest.json' -and $_ -notin $declared })
        if ($missingFromManifest.Count -eq 0) {
            Add-Gate 1 'manifest declares all 18 per-dim indices' 'PASS' "$($declared.Count) entries"
        } else {
            Add-Gate 1 'manifest declares all 18 per-dim indices' 'FAIL' "missing: $($missingFromManifest -join ', ')"
        }

        $missingOnDisk = @()
        foreach ($f in $expectedIndexFiles) {
            $p = Join-Path $BaselineRoot $f
            if (-not (Test-Path $p)) { $missingOnDisk += $f }
        }
        if ($missingOnDisk.Count -eq 0) {
            Add-Gate 1 'all 19 required index files on disk' 'PASS' "$($expectedIndexFiles.Count) files"
        } else {
            Add-Gate 1 'all 19 required index files on disk' 'FAIL' "missing: $($missingOnDisk -join ', ')"
        }

        # Non-blocking compat-shim gate: fidelity-index.json is the legacy flat
        # union emitted by the builder for older consumers. Its absence is NOT a
        # calibration failure - report as PASS if present, SKIP if absent, and
        # mark the gate non-blocking so it never contributes to failure counts.
        $shimPath = Join-Path $BaselineRoot 'fidelity-index.json'
        if (Test-Path $shimPath) {
            Add-Gate 1 'fidelity-index.json compat shim present' 'PASS' '(optional flat union)' $false
        } else {
            Add-Gate 1 'fidelity-index.json compat shim present' 'SKIP' 'shim not emitted (optional)' $false
        }

        # Per-dim entry_count > 0. Some dims (pipe, scheduled-task) may legitimately
        # have zero entries on a small corpus - the builder still emits an empty
        # file + manifest indices[] entry so consumers don't fail-open silently.
        # Treat zero-entry as non-blocking WARN, not blocking FAIL.
        $emptyDims = @()
        if ($manifest.indices) {
            foreach ($entry in $manifest.indices) {
                $ec = [int]($entry.entry_count)
                if ($ec -le 0) {
                    $fname = if ($entry.file) { $entry.file } elseif ($entry.filename) { $entry.filename } else { "$($entry.dimension)" }
                    $emptyDims += $fname
                }
            }
        }
        if ($emptyDims.Count -eq 0 -and $manifest.indices) {
            Add-Gate 1 'all dims entry_count > 0' 'PASS' "$($manifest.indices.Count) dims non-empty"
        } else {
            Add-Gate 1 'all dims entry_count > 0' 'FAIL' "empty: $($emptyDims -join ', ') [corpus-content; non-blocking]" $false
        }

        # Mtotal / Gtotal > 0. Builder exposes these under both 'corpus' (preferred)
        # and 'totals' (compat with earlier drafts). Read whichever is present.
        $mTot = 0; $gTot = 0
        if ($manifest.corpus) {
            $mTot = [int]$manifest.corpus.Mtotal
            $gTot = [int]$manifest.corpus.Gtotal
        } elseif ($manifest.totals) {
            $mTot = [int]$manifest.totals.Mtotal
            $gTot = [int]$manifest.totals.Gtotal
        }
        if ($mTot -gt 0 -and $gTot -gt 0) {
            Add-Gate 1 'corpus Mtotal & Gtotal > 0' 'PASS' "M=$mTot G=$gTot"
        } else {
            Add-Gate 1 'corpus Mtotal & Gtotal > 0' 'FAIL' "M=$mTot G=$gTot"
        }
    }

    # Known-good test artifacts - load per-dim files as needed.
    $loadIndex = {
        param($file)
        $p = Join-Path $BaselineRoot $file
        if (-not (Test-Path $p)) { return $null }
        try {
            return (Get-Content -LiteralPath $p -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
        } catch { return $null }
    }
    # Helper: locate an entry by key in a per-dim index file.
    # CONTRACT: builder emits PSCustomObject-keyed-by-value (a JSON object where
    # property names are canonical-key values). This helper looks up via that
    # contract and DOES NOT fall back to array-of-objects scans, so any future
    # schema migration that changes the layout will trigger an immediate
    # detectable failure here rather than silently passing.
    $findEntry = {
        param($idx,$key)
        if ($null -eq $idx) { return $null }
        $kLower = $key.ToString().ToLowerInvariant()
        # Prefer direct property lookup (case-insensitive)
        try {
            $direct = $idx.$key
            if ($null -ne $direct) { return $direct }
        } catch {}
        foreach ($prop in $idx.PSObject.Properties) {
            if ($prop.Name.ToLowerInvariant() -eq $kLower) { return $prop.Value }
        }
        return $null
    }
    $getNum = {
        param($obj,[string[]]$names)
        if ($null -eq $obj) { return $null }
        foreach ($n in $names) {
            $p = $obj.PSObject.Properties[$n]
            if ($p) { return [double]$p.Value }
        }
        return $null
    }

    # ----- STRUCTURAL per-dim entry schema validation (binding) -----
    # The 5 hardcoded probes below assert CORPUS CONTENT (e.g. 'is 8.8.8.8 in the
    # IP index, is powershell.exe in the process index'). On a fresh build where
    # the VT corpus has not been ingested, or on a Linux-only corpus where
    # powershell.exe does not appear, those probes would legitimately fail and
    # the runner would confuse 'corpus not ingested' with 'schema is invalid'.
    # Instead we split:
    #   - STRUCTURE (this block, BINDING): each per-dim index loads as JSON and
    #     a sample entry exposes the documented v2 value_schema fields. These
    #     are 100% schema-driven and have no corpus-content dependency.
    #   - CORPUS HEALTH (next block, NON-BINDING informational): the 5 legacy
    #     hardcoded probes, surfaced via $script:_corpusHealthStatus and a
    #     console warning - NEVER contributing to PASS/FAIL.
    $script:_corpusHealthStatus = [pscustomobject]@{
        Probed   = 0
        Passed   = 0
        Failed   = 0
        Skipped  = 0
        Details  = New-Object System.Collections.Generic.List[string]
    }
    $valueSchemaFields = @('M','G','RiskScore','Confidence','PMI','Score100','Dimension')
    if ($manifest) {
        $structuralFailures = New-Object System.Collections.Generic.List[string]
        $structuralChecked  = 0
        foreach ($f in $perDimFiles) {
            $idx = & $loadIndex $f
            if ($null -eq $idx) {
                # File-missing is handled by the 'all 20 index files on disk' gate
                # above. Don't double-count here.
                continue
            }
            $sampleEntries = @()
            try {
                $sampleEntries = @($idx.PSObject.Properties | Select-Object -First 2 | ForEach-Object { $_.Value })
            } catch {}
            if ($sampleEntries.Count -eq 0) {
                # Empty per-dim file is OK (handled by entry_count gate); structurally
                # there is nothing to check here.
                continue
            }
            foreach ($entry in $sampleEntries) {
                $structuralChecked++
                $missing = @()
                foreach ($fld in $valueSchemaFields) {
                    $hasField = $false
                    try { $hasField = ($null -ne $entry.PSObject.Properties[$fld]) } catch {}
                    if (-not $hasField) { $missing += $fld }
                }
                if ($missing.Count -gt 0) {
                    $structuralFailures.Add("${f}: missing field(s) [$($missing -join ', ')]")
                }
            }
        }
        if ($structuralChecked -eq 0) {
            Add-Gate 1 'per-dim entries match v2 value_schema' 'SKIP' 'no per-dim sample entries available' $false
        } elseif ($structuralFailures.Count -eq 0) {
            Add-Gate 1 'per-dim entries match v2 value_schema' 'PASS' "$structuralChecked sample entries OK"
        } else {
            $head = ($structuralFailures | Select-Object -First 3) -join '; '
            Add-Gate 1 'per-dim entries match v2 value_schema' 'FAIL' "checked=$structuralChecked failures=$($structuralFailures.Count) e.g. $head"
        }
    }

    # ----- CORPUS HEALTH (informational, NON-BINDING) -----
    # These 5 probes assert corpus content, not schema. They are EXCLUDED from
    # the gate accumulator entirely - they emit a console warning and populate
    # $script:_corpusHealthStatus so dashboards can surface a 'corpus health'
    # badge separately from the binding 'schema sanity' verdict.
    if ($manifest) {
        $idxIP        = & $loadIndex 'fidelity-ip.json'
        $idxCertStat  = & $loadIndex 'fidelity-cert-status.json'
        $idxMitre     = & $loadIndex 'fidelity-mitre-technique.json'
        $idxProc      = & $loadIndex 'fidelity-process.json'

        $probeRows = @(
            @{ Name = 'IP 8.8.8.8 G > 0'; Eval = {
                $e = & $findEntry $idxIP '8.8.8.8'
                $g = if ($e) { & $getNum $e @('G','GoodCount','goodCount','good') } else { $null }
                @{ Ok = ($e -and $g -gt 0); Detail = "entry=$([bool]$e) G=$g" }
            }},
            @{ Name = 'SignedVerified G > M'; Eval = {
                $eS = & $findEntry $idxCertStat 'SignedVerified'
                $gS = if ($eS) { & $getNum $eS @('G','GoodCount','goodCount','good') } else { $null }
                $mS = if ($eS) { & $getNum $eS @('M','MalCount','malCount','mal','malicious') } else { $null }
                @{ Ok = ($eS -and $gS -gt $mS); Detail = "entry=$([bool]$eS) G=$gS M=$mS" }
            }},
            @{ Name = 'SelfSigned M > G'; Eval = {
                $eSS = & $findEntry $idxCertStat 'SelfSigned'
                $gSS = if ($eSS) { & $getNum $eSS @('G','GoodCount','goodCount','good') } else { $null }
                $mSS = if ($eSS) { & $getNum $eSS @('M','MalCount','malCount','mal','malicious') } else { $null }
                @{ Ok = ($eSS -and $mSS -gt $gSS); Detail = "entry=$([bool]$eSS) M=$mSS G=$gSS" }
            }},
            @{ Name = 'MITRE T1055 RiskScore > 0.5'; Eval = {
                $eT = & $findEntry $idxMitre 'T1055'
                $rs = if ($eT) { & $getNum $eT @('RiskScore','riskScore','risk') } else { $null }
                @{ Ok = ($eT -and $rs -gt 0.5); Detail = ("entry={0} RiskScore={1}" -f [bool]$eT, $rs) }
            }},
            @{ Name = 'process powershell.exe G > 0'; Eval = {
                $eP = & $findEntry $idxProc 'powershell.exe'
                $gP = if ($eP) { & $getNum $eP @('G','GoodCount','goodCount','good') } else { $null }
                @{ Ok = ($eP -and $gP -gt 0); Detail = "entry=$([bool]$eP) G=$gP" }
            }}
        )
        foreach ($row in $probeRows) {
            $script:_corpusHealthStatus.Probed++
            $r = & $row.Eval
            if ($r.Ok) {
                $script:_corpusHealthStatus.Passed++
                Write-Host ("  [CORPUS-HEALTH ok]   {0,-40} {1}" -f $row.Name, $r.Detail) -ForegroundColor DarkGreen
            } else {
                $script:_corpusHealthStatus.Failed++
                $msg = "{0}: {1}" -f $row.Name, $r.Detail
                $script:_corpusHealthStatus.Details.Add($msg)
                Write-Host ("  [CORPUS-HEALTH warn] {0,-40} {1}" -f $row.Name, $r.Detail) -ForegroundColor DarkYellow
            }
        }
        if ($script:_corpusHealthStatus.Failed -gt 0) {
            Write-Warning ("Corpus-health probes: {0}/{1} probes failed. This is INFORMATIONAL (does not affect calibration_passed) - typically means VT corpus not fully ingested or Linux-only corpus. Investigate ingestion if unexpected." -f $script:_corpusHealthStatus.Failed, $script:_corpusHealthStatus.Probed)
        }
    }

    # ============================================================
    # PHASE 2 - NORMALIZATION ROUND-TRIPS
    # ============================================================
    Write-PhaseBanner 2 "NORMALIZATION ROUND-TRIPS"

    # 2a IPv6 canonical form: parse + re-emit ToString() must collapse zeros per RFC 5952.
    # Uses a NON-canonical uncompressed input so IPAddress.Parse().ToString() is not an
    # identity transform - avoids the prior tautology where '2001:db8::1' -> '2001:db8::1'
    # trivially matched.
    try {
        $nonCanonical = '2001:0db8:0:0:0:0:0:1'
        $expected     = '2001:db8::1'
        $ipObj        = [System.Net.IPAddress]::Parse($nonCanonical)
        $canonical    = $ipObj.ToString()
        if ($canonical -eq $expected -and $canonical -ne $nonCanonical) {
            Add-Gate 2 'IPv6 canonical via IPAddress.Parse' 'PASS' "'$nonCanonical' -> '$canonical'"
        } else {
            Add-Gate 2 'IPv6 canonical via IPAddress.Parse' 'FAIL' "expected '$expected' got '$canonical' from '$nonCanonical'"
        }
    } catch {
        Add-Gate 2 'IPv6 canonical via IPAddress.Parse' 'FAIL' $_.Exception.Message
    }

    # 2b MITRE sub-technique parent rollup: 'T1055.012' -> lookup on 'T1055'.
    $mitreNorm = {
        param($s)
        if ($s -match '^(T\d{4})(\.\d{3})?$') { return $Matches[1] } else { return $s }
    }
    $rolled = & $mitreNorm 'T1055.012'
    if ($rolled -eq 'T1055') {
        Add-Gate 2 'MITRE sub-technique parent rollup' 'PASS' "T1055.012 -> $rolled"
    } else {
        Add-Gate 2 'MITRE sub-technique parent rollup' 'FAIL' "got: $rolled"
    }
    if ($manifest) {
        $eT = & $findEntry (& $loadIndex 'fidelity-mitre-technique.json') $rolled
        if ($eT) {
            Add-Gate 2 'MITRE rolled-up key looks up' 'PASS' "T1055 entry present"
        } else {
            Add-Gate 2 'MITRE rolled-up key looks up' 'FAIL' "no entry for T1055"
        }
    }

    # 2c Mutex Global\ prefix strip.
    $mtxNorm = {
        param($s)
        $t = "$s"
        if ($t -match '^(?i)Global\\(.+)$') { return $Matches[1] }
        if ($t -match '^(?i)Local\\(.+)$')  { return $Matches[1] }
        return $t
    }
    $mNorm = & $mtxNorm 'Global\TestMutex'
    if ($mNorm -eq 'TestMutex') {
        Add-Gate 2 'mutex Global\ prefix strip' 'PASS' "Global\TestMutex -> $mNorm"
    } else {
        Add-Gate 2 'mutex Global\ prefix strip' 'FAIL' "got: $mNorm"
    }

    # 2d Cert publisher casing collision.
    $pubNorm = {
        param($s)
        $t = "$s"
        $t = $t.ToLowerInvariant()
        $t = [System.Text.RegularExpressions.Regex]::Replace($t, '\s+', ' ')
        $t = $t.Trim().TrimEnd('.', ',', ';', ':')
        return $t
    }
    $a = & $pubNorm 'Microsoft Corporation'
    $b = & $pubNorm 'microsoft corporation'
    $c = & $pubNorm '  Microsoft   Corporation.  '
    if ($a -eq $b -and $a -eq $c) {
        Add-Gate 2 'cert publisher casing collapses' 'PASS' "all -> '$a'"
    } else {
        Add-Gate 2 'cert publisher casing collapses' 'FAIL' "a='$a' b='$b' c='$c'"
    }

    # ============================================================
    # PHASE 3 - PERFORMANCE GATES
    # ============================================================
    Write-PhaseBanner 3 "PERFORMANCE GATES"

    # 3a Module-init: manifest-only read. Two attempts to avoid first-touch cache skew.
    $initMs = $null
    if (Test-Path $manifestPath) {
        # warm fs cache once (untimed)
        try { [void](Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop) } catch {}
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $tmp = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        } catch {}
        $sw.Stop()
        $initMs = $sw.ElapsedMilliseconds
        if ($initMs -lt 2000) {
            Add-Gate 3 'module-init < 2.0s (manifest read)' 'PASS' "${initMs} ms"
        } else {
            Add-Gate 3 'module-init < 2.0s (manifest read)' 'FAIL' "${initMs} ms"
        }
    } else {
        Add-Gate 3 'module-init < 2.0s (manifest read)' 'FAIL' 'no manifest to time'
    }

    # 3b Eager memory delta (manifest only).
    [void][GC]::Collect(); [void][GC]::WaitForPendingFinalizers(); [void][GC]::Collect()
    $memBefore = [GC]::GetTotalMemory($true)
    $eagerObj  = $null
    if (Test-Path $manifestPath) {
        try { $eagerObj = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop } catch {}
    }
    $memAfterEager = [GC]::GetTotalMemory($false)
    $eagerDeltaMB  = [Math]::Round((($memAfterEager - $memBefore) / 1MB), 2)
    if ($null -ne $eagerObj -and $eagerDeltaMB -lt 10) {
        Add-Gate 3 'eager delta < 10 MB (manifest only)' 'PASS' "${eagerDeltaMB} MB"
    } elseif ($null -eq $eagerObj) {
        Add-Gate 3 'eager delta < 10 MB (manifest only)' 'FAIL' 'manifest did not load'
    } else {
        Add-Gate 3 'eager delta < 10 MB (manifest only)' 'FAIL' "${eagerDeltaMB} MB"
    }

    # 3c Lazy-load probe: 3 representative dims (ip, dns, process). Models real
    #    consumer behavior - Import-FidelityIndices in ElasticAlertAgent.psm1 is
    #    lazy per dim; it never eager-loads all 18 files at once. The previous
    #    full-warm gate double-counted the manifest (loaded again above) and
    #    inflated JSON ~26x via ConvertFrom-Json PSCustomObject hydration, which
    #    modeled no real state. Threshold: < 100 MB delta across 3 representative
    #    dims (~30 MB/dim upper bound after PSCustomObject inflation).
    $lazyDims = @('fidelity-ip.json', 'fidelity-dns.json', 'fidelity-process.json')
    [void][GC]::Collect(); [void][GC]::WaitForPendingFinalizers(); [void][GC]::Collect()
    $memBeforeLazy = [GC]::GetTotalMemory($true)
    $lazyObjs      = @{}
    $lazyMissing   = @()
    foreach ($f in $lazyDims) {
        $p = Join-Path $BaselineRoot $f
        if (Test-Path $p) {
            try {
                $lazyObjs[$f] = Get-Content -LiteralPath $p -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            } catch {
                $lazyMissing += $f
            }
        } else {
            $lazyMissing += $f
        }
    }
    $memAfterLazy = [GC]::GetTotalMemory($false)
    $lazyDeltaMB  = [Math]::Round((($memAfterLazy - $memBeforeLazy) / 1MB), 2)
    $loadedLazy   = $lazyObjs.Count
    if ($lazyMissing.Count -gt 0) {
        Add-Gate 3 'lazy-load delta < 100 MB (3 dims)' 'FAIL' "missing dims: $($lazyMissing -join ', ')"
    } elseif ($loadedLazy -eq $lazyDims.Count -and $lazyDeltaMB -lt 100) {
        Add-Gate 3 'lazy-load delta < 100 MB (3 dims)' 'PASS' "${lazyDeltaMB} MB across $loadedLazy dims (ip/dns/process)"
    } else {
        Add-Gate 3 'lazy-load delta < 100 MB (3 dims)' 'FAIL' "${lazyDeltaMB} MB across $loadedLazy dims"
    }
    # Release refs so they don't pollute downstream measurements.
    $lazyObjs = $null
    [void][GC]::Collect()

    # ============================================================
    # PHASE 4 - VERDICT REGRESSION (legacy vs new on labeled corpora)
    # ============================================================
    Write-PhaseBanner 4 "VERDICT REGRESSION"

    # PHASE 4 BINDING-GATE CONTRACT (post adversarial-review hardening):
    #   The 95% verdict-agreement gate is a BINDING calibration gate (user
    #   confirmation #3 in design signoff). To be honest, this phase requires
    #   THREE things to be present simultaneously:
    #     (a) at least 5 labeled NDJSON corpora under -LabeledCorpusRoot
    #     (b) the real consumer ElasticAlertAgent.psm1 must be Import-Module'able
    #     (c) the consumer must expose a callable scoring entrypoint that we
    #         can drive twice (legacy lane vs new lane) over the same input
    #   If ANY of those is missing this phase is marked SKIPPED (not PASS, not
    #   FAIL) and $script:_phase4_status = 'SKIPPED'. In that state Phase 5
    #   leaves calibration_passed at its prior value or $null - it does NOT
    #   write $true. This is the only way to keep the gate BINDING: a tautology
    #   (in-runner re-implementation of both lanes) is explicitly NOT acceptable
    #   because both lanes would share the same input distribution by construction
    #   and a 100% match would prove nothing about real-consumer behavior.
    #   See adversarial review for full rationale.

    $script:_phase4_status   = 'NOT_RUN'   # one of NOT_RUN | SKIPPED | PASSED | FAILED
    $script:_phase4_reason   = ''
    $script:_phase4_agreepct = $null
    $script:_phase4_n        = 0

    # (1) Discover labeled corpora
    #
    # A corpus subdirectory under -LabeledCorpusRoot may be materialized in
    # either of two ways:
    #   (a) INLINE - the subdirectory contains the NDJSON datasets directly.
    #       This is the historical layout and is still walked as-is.
    #   (b) POINTER - the subdirectory contains a single 'pointer.json' file
    #       that resolves to an external absolute_path. This keeps large
    #       detonation logs out of the calibration_samples repo. When a
    #       pointer is detected we resolve absolute_path and walk THAT
    #       directory instead, taking the label / expected_verdict from the
    #       pointer (falling back to the subdir-name heuristic only if the
    #       pointer omits an explicit label).
    $corpora = @()
    if (Test-Path $LabeledCorpusRoot) {
        $candidates = @(Get-ChildItem -LiteralPath $LabeledCorpusRoot -Directory -ErrorAction SilentlyContinue |
                       Sort-Object LastWriteTime -Descending)
        foreach ($d in $candidates) {
            $walkDir       = $d.FullName
            $pointerLabel  = $null
            $pointerFramework = $null
            $pointerPath   = Join-Path $d.FullName 'pointer.json'
            if (Test-Path -LiteralPath $pointerPath) {
                try {
                    $ptr = Get-Content -LiteralPath $pointerPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    if ($ptr.absolute_path) {
                        if (Test-Path -LiteralPath $ptr.absolute_path) {
                            $walkDir = [string]$ptr.absolute_path
                            if ($ptr.label)            { $pointerLabel     = [string]$ptr.label }
                            elseif ($ptr.expected_verdict) { $pointerLabel = [string]$ptr.expected_verdict }
                            if ($ptr.framework)        { $pointerFramework = [string]$ptr.framework }
                            Write-Host ("    [pointer] {0} -> {1}" -f $d.Name, $walkDir) -ForegroundColor DarkGray
                        } else {
                            Write-Warning ("pointer.json absolute_path not found, skipping corpus '{0}': {1}" -f $d.Name, $ptr.absolute_path)
                            continue
                        }
                    } else {
                        Write-Warning ("pointer.json in '{0}' has no absolute_path field; skipping." -f $d.Name)
                        continue
                    }
                } catch {
                    Write-Warning ("pointer.json in '{0}' failed to parse, skipping: {1}" -f $d.Name, $_.Exception.Message)
                    continue
                }
            }
            $ndjson = @(Get-ChildItem -LiteralPath $walkDir -File -Recurse -ErrorAction SilentlyContinue -Filter '*.ndjson')
            if ($ndjson.Count -eq 0) {
                $ndjson = @(Get-ChildItem -LiteralPath $walkDir -File -Recurse -ErrorAction SilentlyContinue -Filter '*.json' |
                            Where-Object { $_.Name -ne 'pointer.json' })
            }
            if ($ndjson.Count -gt 0) {
                $label =
                    if ($pointerLabel) { $pointerLabel.ToUpperInvariant() }
                    elseif ($d.Name -match '(?i)clean|baseline|benign') { 'CLEAN' }
                    else { 'COMPROMISED' }
                $corpora += [pscustomobject]@{
                    Name      = if ($pointerFramework) { "$($d.Name) ($pointerFramework)" } else { $d.Name }
                    Path      = $walkDir
                    EventFile = $ndjson[0].FullName
                    Label     = $label
                }
            }
        }
    }

    # (2) Discover the consumer module
    $consumerPath = Join-Path $PSScriptRoot "..\..\elasticPotato\agentic\ElasticAlertAgent.psm1"
    $consumerResolved = $null
    if (Test-Path $consumerPath) {
        try { $consumerResolved = (Resolve-Path -LiteralPath $consumerPath -ErrorAction Stop).Path } catch {}
    }

    # (3) Try to load the consumer and probe for a callable scoring entrypoint
    $consumerLoaded   = $false
    $consumerEntryFn  = $null     # the cmdlet that scores a labeled corpus end-to-end
    $consumerToggleOk = $false    # whether the entrypoint exposes a legacy/new toggle
    $consumerLoadErr  = $null
    if ($consumerResolved) {
        try {
            Import-Module $consumerResolved -Force -ErrorAction Stop -WarningAction SilentlyContinue
            $consumerLoaded = $true
        } catch {
            $consumerLoadErr = $_.Exception.Message
        }
    }
    if ($consumerLoaded) {
        # We need a function we can call twice (legacy lane, new lane) over the
        # SAME detonation-log directory and read back a deterministic verdict.
        # The consumer exposes:
        #   - -DetonationLogsDir <dir>       : offline-mode input
        #   - -UseLegacyFidelity             : forces $script:_fidUseNewScoring = $false
        #                                      immediately after Import-FidelityIndices,
        #                                      overriding manifest.scoring.calibration_passed
        #   - -ReturnVerdict                 : suppresses interactive banners and
        #                                      returns the structured PSCustomObject
        # Both switches are additive - existing callers (menu 3a/3b) that omit
        # them see identical pre-refactor behavior.
        $candidateFn = Get-Command -Name 'Invoke-ElasticAlertAgentAnalysis' -ErrorAction SilentlyContinue
        if ($candidateFn) {
            $params = $candidateFn.Parameters
            # Walk canonical parameter names + aliases. The consumer exposes
            # -ReturnVerdict as an [Alias('ReturnVerdict')] on the canonical
            # -SuppressVerdictBanner; ContainsKey only matches canonical keys,
            # so alias-only checks would report a false negative.
            $hasParamOrAlias = {
                param($paramMap, [string[]]$candidates)
                foreach ($c in $candidates) {
                    if ($paramMap.ContainsKey($c)) { return $true }
                    foreach ($p in $paramMap.Values) {
                        if ($p.Aliases -contains $c) { return $true }
                    }
                }
                return $false
            }
            $hasDetonationDir = & $hasParamOrAlias $params @('DetonationLogsDir')
            $hasLegacyToggle  = & $hasParamOrAlias $params @('UseLegacyFidelity','ForceLegacyScoring')
            $hasReturnVerdict = & $hasParamOrAlias $params @('SuppressVerdictBanner','ReturnVerdict','ScoreOnlyReturnVerdict','NonInteractive')
            if ($hasDetonationDir -and $hasLegacyToggle -and $hasReturnVerdict) {
                $consumerEntryFn  = $candidateFn
                $consumerToggleOk = $true
            }
        }
    }

    # (4) Decide PASS / SKIP / FAIL
    # Minimum-N floor for the 95% verdict-agreement gate: with n<20 a single
    # disagreement crosses the 5% bar (e.g. n=5 -> 1 disagreement = 80% =
    # instant FAIL). The 20-corpus floor was chosen so that ceil(0.05 * 20) = 1
    # disagreement is still tolerated; below 20 we cannot distinguish noise
    # from a real regression, so we treat the gate as SKIPPED (same state as
    # 'no corpora at all') and leave calibration_passed = $null.
    #
    # PILOT MODE: $MinCorpora is a runtime override (default 20) that lets
    # the operator lower this floor for initial bring-up on a small staged
    # corpus. The pilot-mode banner is printed at startup; the chosen value
    # is recorded in manifest.scoring.calibration_min_corpora so the
    # consumer can render a 'PILOT MODE' badge.
    $minCorporaForBinding = $MinCorpora
    $skipReasons = New-Object System.Collections.Generic.List[string]
    if ($corpora.Count -eq 0) {
        $skipReasons.Add("no NDJSON/JSON corpora under $LabeledCorpusRoot")
    } elseif ($corpora.Count -lt $minCorporaForBinding) {
        $skipReasons.Add("only $($corpora.Count) corpora found; need >= $minCorporaForBinding for binding gate (minimum-N floor)")
    }
    if (-not $consumerResolved) {
        $skipReasons.Add("consumer module not found at $consumerPath")
    } elseif (-not $consumerLoaded) {
        $skipReasons.Add("Import-Module $consumerResolved failed: $consumerLoadErr")
    } elseif (-not $consumerEntryFn) {
        $skipReasons.Add("consumer does not expose a callable scoring entrypoint (need Invoke-ElasticAlertAgentAnalysis with -DetonationLogsDir, a legacy-fidelity toggle, and a non-interactive verdict-return mode)")
    }

    if ($skipReasons.Count -gt 0) {
        $reason = $skipReasons -join '; '
        $script:_phase4_status = 'SKIPPED'
        $script:_phase4_reason = $reason
        Write-Warning ("Phase 4 verdict-regression skipped: {0}. calibration_passed will not be set to true until Phase 4 can run with real corpora and a loadable consumer." -f $reason)
        $consumerDetail =
            if      ($consumerLoaded -and -not $consumerEntryFn) { 'loaded but no toggleable entrypoint' }
            elseif  ($consumerLoaded)                            { 'loaded' }
            elseif  ($consumerResolved)                          { "load failed: $consumerLoadErr" }
            else                                                 { 'module not found' }
        Add-Gate 4 ("labeled corpora available (>={0})" -f $minCorporaForBinding) 'SKIP' ("corpora found: {0}" -f $corpora.Count) $false
        Add-Gate 4 'real consumer loadable + toggleable' 'SKIP' $consumerDetail $false
        Add-Gate 4 'verdict agreement >= 95% (binding)'  'SKIP' "skipped: $reason" $false
        Add-Gate 4 'no COMPROMISED -> CLEAN regression'  'SKIP' "skipped: $reason" $false
    } else {
        # All preconditions met - run the REAL consumer twice per corpus.
        Add-Gate 4 ("labeled corpora available (>={0})" -f $minCorporaForBinding) 'PASS' "$($corpora.Count) corpora" $false
        Add-Gate 4 'real consumer loadable + toggleable' 'PASS' "$($consumerEntryFn.Name) exposes -DetonationLogsDir + legacy toggle + verdict-return" $false

        # Offline-mode verdicts are drawn from this set. Any other value indicates
        # a schema drift (e.g. AlertContext-mode return leaking in) and the row
        # is treated as an error-skip with a diagnostic message.
        $validOfflineVerdicts = @('COMPROMISED','SUSPICIOUS','CLEAN')

        $agree       = 0
        $disagree    = 0
        $skippedRows = 0
        $regressions = 0
        $rows        = New-Object System.Collections.Generic.List[object]
        foreach ($c in $corpora) {
            $legacyVerdict = $null
            $newVerdict    = $null
            $rowErr        = $null
            try {
                # Legacy lane: force $script:_fidUseNewScoring = $false regardless
                # of manifest state via -UseLegacyFidelity. -ReturnVerdict suppresses
                # console banners and returns the structured PSCustomObject.
                # 6>$null 4>$null suppresses any residual Write-Host/Write-Information
                # leakage during comparison so only Add-Gate lines print.
                $legacyResult = & $consumerEntryFn `
                    -DetonationLogsDir $c.Path `
                    -UseLegacyFidelity `
                    -ReturnVerdict `
                    -ErrorAction Stop 6>$null 4>$null
                $legacyVerdict = if ($legacyResult -and $legacyResult.Verdict) { [string]$legacyResult.Verdict } else { [string]$legacyResult }

                # New lane: default fidelity path (manifest-driven).
                $newResult = & $consumerEntryFn `
                    -DetonationLogsDir $c.Path `
                    -ReturnVerdict `
                    -ErrorAction Stop 6>$null 4>$null
                $newVerdict = if ($newResult -and $newResult.Verdict) { [string]$newResult.Verdict } else { [string]$newResult }
            } catch {
                $rowErr = $_.Exception.Message
            }

            # Defensive shape check: both lanes must return one of the three
            # offline-mode verdicts. Anything else is a schema drift bug -
            # error-skip with a clear diagnostic instead of silently agreeing.
            if (-not $rowErr) {
                if ($legacyVerdict -and ($legacyVerdict.ToUpperInvariant() -notin $validOfflineVerdicts)) {
                    $rowErr = "legacy verdict '$legacyVerdict' not in offline set [$($validOfflineVerdicts -join ', ')]"
                } elseif ($newVerdict -and ($newVerdict.ToUpperInvariant() -notin $validOfflineVerdicts)) {
                    $rowErr = "new verdict '$newVerdict' not in offline set [$($validOfflineVerdicts -join ', ')]"
                }
            }

            if ($rowErr -or -not $legacyVerdict -or -not $newVerdict) {
                $skippedRows++
                $rows.Add([pscustomobject]@{
                    Sample     = $c.Name
                    Label      = $c.Label
                    LegacyV    = if ($legacyVerdict) { $legacyVerdict } else { 'ERROR' }
                    NewV       = if ($newVerdict)    { $newVerdict }    else { 'ERROR' }
                    Agree      = $false
                    Regression = $false
                    Error      = $rowErr
                })
                continue
            }

            # Case-insensitive verdict comparison per plan.
            $sameVerdict  = ($legacyVerdict.ToUpperInvariant() -eq $newVerdict.ToUpperInvariant())
            if ($sameVerdict) { $agree++ } else { $disagree++ }
            $isRegression = ($legacyVerdict.ToUpperInvariant() -eq 'COMPROMISED' -and $newVerdict.ToUpperInvariant() -eq 'CLEAN')
            if ($isRegression) { $regressions++ }
            $rows.Add([pscustomobject]@{
                Sample     = $c.Name
                Label      = $c.Label
                LegacyV    = $legacyVerdict
                NewV       = $newVerdict
                Agree      = $sameVerdict
                Regression = $isRegression
                Error      = $null
            })
        }
        foreach ($r in $rows) {
            $col = if ($r.Regression) {'Red'} elseif ($r.Agree) {'Green'} else {'Yellow'}
            Write-Host ("    {0,-32} label={1,-12} legacy={2,-12} new={3,-12} agree={4}" `
                -f $r.Sample, $r.Label, $r.LegacyV, $r.NewV, $r.Agree) -ForegroundColor $col
        }
        $eligible = $agree + $disagree
        $pct = if ($eligible -gt 0) { [Math]::Round(100.0 * $agree / $eligible, 1) } else { 0.0 }
        $skipNote = if ($skippedRows -gt 0) { " ($skippedRows error-skipped)" } else { "" }
        $script:_phase4_agreepct = $pct
        $script:_phase4_n        = $eligible

        $agreementOk  = ($eligible -ge $minCorporaForBinding) -and ($pct -ge 95)
        $regressionOk = ($regressions -eq 0)

        if ($eligible -lt $minCorporaForBinding) {
            $script:_phase4_status = 'SKIPPED'
            $script:_phase4_reason = "eligible=$eligible < min=$minCorporaForBinding after error-skip"
            Add-Gate 4 'verdict agreement >= 95% (binding)' 'SKIP' "n=$eligible < min=$minCorporaForBinding; pct=$pct%$skipNote" $false
            Add-Gate 4 'no COMPROMISED -> CLEAN regression' 'SKIP' "n=$eligible < min=$minCorporaForBinding$skipNote" $false
        } else {
            if ($agreementOk) {
                Add-Gate 4 'verdict agreement >= 95% (binding)' 'PASS' "$pct% ($agree/$eligible)$skipNote"
            } else {
                Add-Gate 4 'verdict agreement >= 95% (binding)' 'FAIL' "$pct% ($agree/$eligible)$skipNote"
            }
            if ($regressionOk) {
                Add-Gate 4 'no COMPROMISED -> CLEAN regression' 'PASS' "0 regressions over $eligible eligible$skipNote"
            } else {
                # List the regressing corpus names so operators can drill in without
                # trawling the per-row output.
                $regressionNames = @($rows | Where-Object { $_.Regression } | ForEach-Object { $_.Sample })
                Add-Gate 4 'no COMPROMISED -> CLEAN regression' 'FAIL' "$regressions regression(s) over $eligible eligible$skipNote [$($regressionNames -join '; ')]"
            }
            if ($agreementOk -and $regressionOk) {
                $script:_phase4_status = 'PASSED'
            } else {
                $script:_phase4_status = 'FAILED'
                $script:_phase4_reason = "agreement=$pct% n=$eligible regressions=$regressions"
            }
        }
    }

    # ============================================================
    # PHASE 5 - PERSISTENCE (round-trip manifest)
    # ============================================================
    Write-PhaseBanner 5 "PERSISTENCE"

    # calibration_passed contract (post adversarial-review hardening):
    #   $true   : EVERY phase 1-4 reached PASS on all blocking gates AND Phase 4
    #             ran end-to-end (status = PASSED). Only state in which the
    #             consumer enables the new scoring path.
    #   $false  : at least one blocking gate FAILED, OR Phase 4 ran and disagreed
    #             above the 5% tolerance OR detected a COMPROMISED->CLEAN
    #             regression (status = FAILED).
    #   $null   : Phase 4 was SKIPPED (no labeled corpora and/or no loadable
    #             consumer entrypoint). NO BINDING EVIDENCE either way - the
    #             consumer treats $null the same as $false (does not enable new
    #             scoring) but tooling can render an honest 'NOT YET CALIBRATED'
    #             badge instead of a 'CALIBRATION FAILED' badge.
    # The scoring.calibration_phase4_status field records the underlying P4
    # status so the consumer / dashboards can distinguish the three cases.
    $phase4Status = if ($script:_phase4_status) { [string]$script:_phase4_status } else { 'NOT_RUN' }
    $blockingFails = @($gates | Where-Object { $_.Blocking -and $_.Status -ne 'PASS' })
    $allBlockingOk = ($blockingFails.Count -eq 0)
    $calibrationPassedValue = switch ($phase4Status) {
        'PASSED'  { $allBlockingOk }                                # true iff no other blocking fails
        'FAILED'  { $false }                                        # P4 ran and disagreed
        'SKIPPED' { $null }                                         # no binding evidence
        default   { $null }                                         # NOT_RUN -> treat as no evidence
    }
    # $passOverall drives the console banner + exit code. It is $true ONLY when
    # we are willing to write calibration_passed=$true. SKIPPED P4 -> not passed.
    $passOverall = ($calibrationPassedValue -eq $true)

    if ($manifest -and (Test-Path $manifestPath)) {
        try {
            # Ensure manifest.scoring exists, then set calibration_passed.
            if (-not $manifest.PSObject.Properties['scoring']) {
                Add-Member -InputObject $manifest -MemberType NoteProperty -Name 'scoring' `
                    -Value ([pscustomobject]@{}) -Force
            }
            if (-not $manifest.scoring.PSObject.Properties['calibration_passed']) {
                Add-Member -InputObject $manifest.scoring -MemberType NoteProperty -Name 'calibration_passed' `
                    -Value $calibrationPassedValue -Force
            } else {
                $manifest.scoring.calibration_passed = $calibrationPassedValue
            }
            # Phase 4 status - PASSED | FAILED | SKIPPED | NOT_RUN. Always present.
            if (-not $manifest.scoring.PSObject.Properties['calibration_phase4_status']) {
                Add-Member -InputObject $manifest.scoring -MemberType NoteProperty -Name 'calibration_phase4_status' `
                    -Value $phase4Status -Force
            } else {
                $manifest.scoring.calibration_phase4_status = $phase4Status
            }
            # Forensic context for why P4 SKIPPED / FAILED (empty string when PASSED).
            if (-not $manifest.scoring.PSObject.Properties['calibration_phase4_reason']) {
                Add-Member -InputObject $manifest.scoring -MemberType NoteProperty -Name 'calibration_phase4_reason' `
                    -Value ([string]$script:_phase4_reason) -Force
            } else {
                $manifest.scoring.calibration_phase4_reason = [string]$script:_phase4_reason
            }
            # PILOT MODE breadcrumb: record the minimum-N floor that was in effect
            # for THIS run so consumers / dashboards can render a 'PILOT MODE'
            # badge when the value is below the default 20. We deliberately write
            # the value on EVERY run (including non-pilot runs) so the field is
            # always present and the consumer never has to disambiguate
            # 'unset = default' from 'unset = old runner without the override'.
            if (-not $manifest.scoring.PSObject.Properties['calibration_min_corpora']) {
                Add-Member -InputObject $manifest.scoring -MemberType NoteProperty -Name 'calibration_min_corpora' `
                    -Value $MinCorpora -Force
            } else {
                $manifest.scoring.calibration_min_corpora = $MinCorpora
            }
            # Also record a timestamp + gate summary for forensics.
            $summary = [pscustomobject]@{
                timestamp_utc = (Get-Date).ToUniversalTime().ToString('o')
                gates_total   = $gates.Count
                gates_passed  = @($gates | Where-Object { $_.Status -eq 'PASS' }).Count
                gates_failed  = @($gates | Where-Object { $_.Status -eq 'FAIL' }).Count
                gates_skipped = @($gates | Where-Object { $_.Status -eq 'SKIP' }).Count
                phase4_status = $phase4Status
                phase4_agreement_pct = $script:_phase4_agreepct
                phase4_n            = $script:_phase4_n
            }
            if (-not $manifest.scoring.PSObject.Properties['calibration_last_run']) {
                Add-Member -InputObject $manifest.scoring -MemberType NoteProperty -Name 'calibration_last_run' `
                    -Value $summary -Force
            } else {
                $manifest.scoring.calibration_last_run = $summary
            }

            $json = $manifest | ConvertTo-Json -Depth 20 -Compress
            # Round-trip equivalence guard: re-parse the JSON we're about to
            # write and confirm we did NOT accidentally lose any top-level
            # field via ConvertTo-Json type coercion (e.g. DateTime -> string).
            $verify = $json | ConvertFrom-Json -ErrorAction Stop
            $missingFields = @()
            foreach ($p in $manifest.PSObject.Properties) {
                if (-not $verify.PSObject.Properties[$p.Name]) {
                    $missingFields += $p.Name
                }
            }
            if ($missingFields.Count -gt 0) {
                throw "Round-trip lost top-level fields: $($missingFields -join ', ')"
            }
            Set-Content -LiteralPath $manifestPath -Value $json -Encoding UTF8 -NoNewline
            $passedDisplay = if ($null -eq $calibrationPassedValue) { 'null (P4 SKIPPED)' } else { [string]$calibrationPassedValue }
            Add-Gate 5 'manifest round-trip + calibration_passed set' 'PASS' `
                ("calibration_passed = {0}, phase4_status = {1}" -f $passedDisplay, $phase4Status) $false
        } catch {
            Add-Gate 5 'manifest round-trip + calibration_passed set' 'FAIL' $_.Exception.Message
            $passOverall = $false
        }
    } else {
        Add-Gate 5 'manifest round-trip + calibration_passed set' 'FAIL' 'no manifest to update'
        $passOverall = $false
    }

    # ============================================================
    # FINAL SUMMARY
    # ============================================================
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
    $failedBlocking = @($gates | Where-Object { $_.Blocking -and $_.Status -ne 'PASS' })
    $phase4StatusOut = if ($script:_phase4_status) { [string]$script:_phase4_status } else { 'NOT_RUN' }
    if ($passOverall -and $failedBlocking.Count -eq 0) {
        Write-Host (" CALIBRATION PASSED (calibration_passed=true; phase4_status={0})" -f $phase4StatusOut) -ForegroundColor Green
        $global:LASTEXITCODE = 0
    } elseif ($phase4StatusOut -eq 'SKIPPED' -and $failedBlocking.Count -eq 0) {
        # No blocking failures but Phase 4 could not run => honest SKIP overall.
        # Per the binding-gate contract this is NOT a pass; calibration_passed
        # is written as $null and the consumer will NOT enable new scoring.
        Write-Host (" CALIBRATION NOT BINDING (phase4_status=SKIPPED, calibration_passed=null)") -ForegroundColor Yellow
        Write-Host ("   reason: {0}" -f $script:_phase4_reason) -ForegroundColor Yellow
        Write-Host  "   NOTE: callers must NOT treat this as PASSED. The consumer will not enable the new scoring path until Phase 4 runs end-to-end on real corpora with the real consumer." -ForegroundColor Yellow
        $global:LASTEXITCODE = 1
    } else {
        Write-Host (" CALIBRATION FAILED ({0} blocking gate(s); phase4_status={1})" -f $failedBlocking.Count, $phase4StatusOut) -ForegroundColor Red
        foreach ($f in $failedBlocking) {
            Write-Host ("   - P{0} {1}: {2}" -f $f.Phase, $f.Name, $f.Detail) -ForegroundColor Red
        }
        $global:LASTEXITCODE = 1
    }
    Write-Host ("=" * 78) -ForegroundColor DarkCyan

    return [pscustomobject]@{
        Passed                  = $passOverall
        CalibrationPassedValue  = $calibrationPassedValue  # $true | $false | $null
        Phase4Status            = $phase4StatusOut         # PASSED | FAILED | SKIPPED | NOT_RUN
        Phase4Reason            = [string]$script:_phase4_reason
        Phase4AgreementPct      = $script:_phase4_agreepct
        Phase4N                 = $script:_phase4_n
        MinCorpora              = $MinCorpora              # binding-gate floor used this run (PILOT MODE if < 20)
        PilotMode               = [bool]$script:_pilotModeActive
        BaselineRoot            = $BaselineRoot
        ManifestPath            = $manifestPath
        Gates                   = $gates
        BlockingFailed          = $failedBlocking.Count
        GatesPassed             = @($gates | Where-Object { $_.Status -eq 'PASS' }).Count
        GatesFailed             = @($gates | Where-Object { $_.Status -eq 'FAIL' }).Count
        GatesSkipped            = @($gates | Where-Object { $_.Status -eq 'SKIP' }).Count
    }
}

Export-ModuleMember -Function Test-FidelityIndexCalibration

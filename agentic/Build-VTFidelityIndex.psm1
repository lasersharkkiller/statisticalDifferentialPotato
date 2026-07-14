function Build-VTFidelityIndex {
    <#
    .SYNOPSIS
        Builds the redesigned per-dimension fidelity index (Option B / orthogonal indices)
        plus the legacy flat fidelity-index.json compat shim and process-baseline.json.

    .DESCRIPTION
        Schema v2 emits:
          - fidelity-manifest.json   (NEW, eager-only, < 10 KB)
          - fidelity-<dim>.json      (one per dimension, lazy-loadable)
          - fidelity-index.json      (PRESERVED filename, flat union for backward-compat
                                      consumers without manifest support)
          - process-baseline.json    (unchanged pipeline)

        Phase 1 - VT Behavior Baseline:
          Reads EVERY behavior JSON file across all VT baseline categories
          (malicious, SignedVerified, unsignedWin, unsignedLinux, unverified, drivers)
          and routes typed indicators through Update-Index with explicit Dimension.

        Phase 2 - APT Differential Merge:
          Merges all Targeted*DifferentialAnalysis.json files.
          Merge rule: LOWEST GoodCount wins, HIGHEST MalCount wins. Dimension is
          inferred from the row context.

        Scoring (per entry in every per-dim index):
          3-axis Bayesian, corpus-normalized:
            RiskScore  = 1 - I_{0.5}(M+1, G_eff+1)  where G_eff = G * (Mtotal/Gtotal)
            PMI        = tanh( (log2((M+0.5)/(Mtotal+1)) - log2((G+0.5)/(Gtotal+1))) / 3 )
            Confidence = min(1, log10(M+G+1) / log10(p95_total[dim]+1))
            Score100   = round(RiskScore * 100, AwayFromZero)
            U          = (Score100 >= 95 AND Confidence >= 0.4)
            R          = (Score100 in [85,95) AND Confidence >= 0.4)
            VerdictPts = min(cap, round( ((RiskScore-0.5)*40 + max(0,PMI)*20) * Confidence ));
                         zero when (M+G) < 5 (minimum-evidence gate)

    .PARAMETER BaselineRoot
        Root of the offline VT baseline. Default: output-baseline.

    .PARAMETER AptRoot
        Root of the APT differential analysis folder tree. Default: apt\APTs.
        Set to "" to skip the APT merge phase.

    .PARAMETER MaxLegitNames
        Max number of legitimate product names stored per indicator. Default: 5.

    .PARAMETER SkipPhase2
        When set, the APT differential merge is skipped (useful for unit tests).

    .EXAMPLE
        Build-VTFidelityIndex
        Build-VTFidelityIndex -BaselineRoot "D:\MyBaseline" -SkipPhase2
    #>
    param(
        [string]$BaselineRoot  = "output-baseline",
        [string]$AptRoot       = "apt\APTs",
        [int]   $MaxLegitNames = 5,
        [switch]$SkipPhase2
    )

    if (-not [System.IO.Path]::IsPathRooted($BaselineRoot)) {
        $BaselineRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\$BaselineRoot"))
    }
    if ($AptRoot -and -not [System.IO.Path]::IsPathRooted($AptRoot)) {
        $AptRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\$AptRoot"))
    }
    $behRoot  = Join-Path $BaselineRoot "VirusTotal-behaviors"
    $mainRoot = Join-Path $BaselineRoot "VirusTotal-main"
    $outFile  = Join-Path $BaselineRoot "fidelity-index.json"

    if (-not (Test-Path $behRoot)) {
        Write-Error "Behavior root not found: $behRoot"
        return
    }

    Write-Host "`n[Build-VTFidelityIndex] Building schema-v2 fidelity index from $behRoot" -ForegroundColor DarkCyan
    $startTime = Get-Date

    # -----------------------------------------------------------------------
    # FLAT hashtables keyed by '$Dimension|$Value' composite strings.
    # PS5.1 nested-hashtable corruption forbids nested @{} writes from inside
    # nested functions; pipe-separated composite keys are the existing workaround.
    # -----------------------------------------------------------------------
    $script:_vtfi_mal   = @{}   # 'dim|value' -> int malicious count
    $script:_vtfi_good  = @{}   # 'dim|value' -> int goodware  count
    $script:_vtfi_legit = @{}   # 'dim|value' -> List[string] legit names
    $script:_vtfi_dims  = [System.Collections.Generic.HashSet[string]]::new(
                              [System.StringComparer]::OrdinalIgnoreCase)
    $script:_vtfi_keys  = [System.Collections.Generic.HashSet[string]]::new(
                              [System.StringComparer]::OrdinalIgnoreCase)

    # Process-baseline pipeline (UNCHANGED)
    $script:_vtfi_procG       = @{}
    $script:_vtfi_procM       = @{}
    $script:_vtfi_procSigners = @{}
    $script:_vtfi_procDirs    = @{}
    $script:_vtfi_maxLN       = $MaxLegitNames

    # Sandbox-artifact scrubber state (process-baseline D field).
    $script:_vtfi_scrubDropped = 0                 # total sandbox-artifact paths rejected
    $script:_vtfi_scrubProcs   = @{}               # process-name -> drop count (for distinct-M metric)
    # Compile the sandbox-artifact rejection regex ONCE per build. Kept in exact lockstep with the runtime
    # consumer filter in elasticPotato\agentic\ElasticAlertAgent.psm1 ($sandboxOnlyTokens + $sandboxRx,
    # located inside the process-baseline masquerade check; grep for $sandboxOnlyTokens if the location has
    # drifted). Any pattern change here MUST be mirrored there and vice versa.
    # Patterns per spec:
    #   ^%[a-z]+%                                                     - ANY VT/sandbox env-macro token
    #                                                                   (%samplepath%, %tempfile%, %datafile%,
    #                                                                    %userprofile%, %localappdata%, %appdata%,
    #                                                                    %public%, %homepath%, %allusersprofile%,
    #                                                                    %windir%, ...) - never a real install dir
    #   ^c:\users\(user|admin|administrator|analyst|sandbox|malware)\ - known sandbox VM usernames.
    #     NOTE: 'administrator' is a real interactive user on Windows Server workloads, so this arm will
    #     scrub legitimate paths like c:\users\administrator\downloads\foo on Server. Trade-off accepted
    #     because the VT corpus is sandbox-heavy and administrator observations are almost entirely
    #     detonation-VM noise. Operators on Server-heavy corpora who want to preserve those paths would
    #     need to fork this regex (no -SandboxUsernames parameter today).
    #   ^c:\users\[^\]+\desktop($|\)                                  - ANY user's Desktop = sample staging
    #   ^c:\users\[^\]+\appdata\local\temp($|\)                       - ANY user's local Temp = sandbox scratch
    # IgnoreCase is set so the regex itself owns case-insensitivity. Callers still lowercase $dir/$kd for
    # OTHER reasons (stored D-list normalization, non-regex string comparisons downstream) - do NOT remove
    # those .ToLower() calls just because the regex tolerates mixed case.
    $script:_vtfi_sandboxArtifactRx = [regex]::new(
        '^%[a-z]+%|^c:\\users\\(user|admin|administrator|analyst|sandbox|malware)\\|^c:\\users\\[^\\]+\\desktop($|\\)|^c:\\users\\[^\\]+\\appdata\\local\\temp($|\\)',
        ([System.Text.RegularExpressions.RegexOptions]::Compiled -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    )

    # Corpus-wide M / G totals (incremented once per processed file)
    $script:_vtfi_Mtotal = 0
    $script:_vtfi_Gtotal = 0
    $script:_vtfi_GoodwareSubcorpora = @{}  # cat -> file count

    # -------------------------------------------------------------------------
    # Test-IsSandboxArtifactPath: returns $true if $Path is a VT sandbox
    # detonation-VM artifact that must not enter the process-baseline D field.
    # Preserves REAL user paths like c:\users\bob\downloads (only rejects the
    # sandbox-username set and generic Desktop/AppData\Local\Temp patterns).
    # Case-insensitive (regex owns it) - caller does not need to lowercase.
    # Paired with runtime filter in elasticPotato\agentic\ElasticAlertAgent.psm1
    # ($sandboxOnlyTokens + $sandboxRx - grep for the symbol names, not a line number).
    # -------------------------------------------------------------------------
    function Test-IsSandboxArtifactPath {
        param([string]$Path)
        if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
        return $script:_vtfi_sandboxArtifactRx.IsMatch($Path)
    }

    function Update-ProcBaseline {
        param([string]$Name, [string]$FullPath, [bool]$IsMalicious, [string]$Signer)
        if (-not $Name -or $Name.Length -lt 2) { return }
        if ($IsMalicious) {
            $script:_vtfi_procM[$Name] = [int]($script:_vtfi_procM[$Name]) + 1
        } else {
            $script:_vtfi_procG[$Name] = [int]($script:_vtfi_procG[$Name]) + 1
            if ($FullPath -and $FullPath -match '\\') {
                $dir = [System.IO.Path]::GetDirectoryName($FullPath).ToLower().TrimEnd('\')
                # Reject VT sandbox-VM artifact paths BEFORE the length gate: e.g. bare '%samplepath%'
                # (len 12) would otherwise slip past. The goodware count above stands (the process WAS
                # seen in goodware) - only the untrusted directory string is dropped. Signer branch is
                # also skipped: a sandbox-only observation should not seed Signers from this call.
                # HOT PATH: called ~once per processes_created entry across ~500k behavior JSONs. Skip
                # the Test-IsSandboxArtifactPath wrapper (function-call overhead ~10-50us per call
                # x millions of calls) and hit the compiled regex directly. Test-IsSandboxArtifactPath
                # remains available for tests and external callers.
                if ($dir -and $script:_vtfi_sandboxArtifactRx.IsMatch($dir)) {
                    $script:_vtfi_scrubDropped++
                    $script:_vtfi_scrubProcs[$Name] = [int]($script:_vtfi_scrubProcs[$Name]) + 1
                    return
                }
                if ($dir -and $dir.Length -gt 2) {
                    $existing = $script:_vtfi_procDirs[$Name]
                    $parts = if ($existing) { $existing -split '\|' } else { @() }
                    if ($parts.Count -lt 10 -and $dir -notin $parts) {
                        $script:_vtfi_procDirs[$Name] = ($parts + $dir) -join '|'
                    }
                }
            }
            if ($Signer) {
                $existing = $script:_vtfi_procSigners[$Name]
                $parts = if ($existing) { $existing -split '\|' } else { @() }
                if ($parts.Count -lt 5 -and $Signer -notin $parts) {
                    $script:_vtfi_procSigners[$Name] = ($parts + $Signer) -join '|'
                }
            }
        }
    }

    # -----------------------------------------------------------------------
    # Update-Index: routes a (Value, Dimension) into the per-dim flat hashtables.
    # Composite key is "$Dimension|$Value" - keeps everything in single-level @{}
    # to dodge PS5.1's nested-hash corruption bug.
    # -----------------------------------------------------------------------
    function Update-Index {
        param(
            [string]$Value,
            [string]$Dimension,
            [bool]  $IsMalicious,
            [string]$LegitName
        )
        if ([string]::IsNullOrWhiteSpace($Value)) { return }
        if ([string]::IsNullOrWhiteSpace($Dimension)) { return }
        $v = $Value.Trim()
        if ($v.Length -lt 3) { return }
        $k = "$Dimension|$v"
        [void]$script:_vtfi_keys.Add($k)
        [void]$script:_vtfi_dims.Add($Dimension)
        if ($IsMalicious) {
            $script:_vtfi_mal[$k] = [int]($script:_vtfi_mal[$k]) + 1
        } else {
            $script:_vtfi_good[$k] = [int]($script:_vtfi_good[$k]) + 1
            if ($LegitName) {
                if (-not $script:_vtfi_legit.ContainsKey($k)) {
                    $script:_vtfi_legit[$k] = [System.Collections.Generic.List[string]]::new()
                }
                $ln = $script:_vtfi_legit[$k]
                if ($ln.Count -lt $script:_vtfi_maxLN -and -not $ln.Contains($LegitName)) {
                    [void]$ln.Add($LegitName)
                }
            }
        }
    }

    # -----------------------------------------------------------------------
    # Cert-status classifier (per signoff decision tree).
    # Input: $attr.signature_info from VT-main JSON (may be $null).
    # Output: one of SignedVerified | SelfSigned | Unsigned | SignedExpired |
    #         SignedRevoked | InvalidSignature | CatalogSigned
    # Samples without main JSON contribute Unsigned.
    # -----------------------------------------------------------------------
    function Get-CertStatus {
        param($SignatureInfo)
        if (-not $SignatureInfo) { return "Unsigned" }
        $verified = "$($SignatureInfo.verified)"
        $sigs     = $SignatureInfo.signers
        $subj     = "$($SignatureInfo.subject)"
        $issuer   = "$($SignatureInfo.issuer)"
        if ($verified -match '(?i)revoked') { return "SignedRevoked" }
        if ($verified -match '(?i)expired') { return "SignedExpired" }
        if ($verified -match '(?i)invalid|bad|tampered|broken') { return "InvalidSignature" }
        if ($verified -match '(?i)catalog') { return "CatalogSigned" }
        if ($verified -match '(?i)signed|valid|trusted') {
            if ($subj -and $issuer -and ($subj.Trim() -eq $issuer.Trim())) { return "SelfSigned" }
            return "SignedVerified"
        }
        if (-not $verified -and -not $sigs -and -not $subj) { return "Unsigned" }
        if ($subj -and $issuer -and ($subj.Trim() -eq $issuer.Trim())) { return "SelfSigned" }
        if ($subj -or $sigs) { return "SignedVerified" }
        return "Unsigned"
    }

    function Get-CertPublisher {
        param($SignatureInfo)
        if (-not $SignatureInfo) { return "" }
        $name = ""
        if ($SignatureInfo.signers) {
            $first = @($SignatureInfo.signers)[0]
            if ($first) {
                if ($first.PSObject -and $first.PSObject.Properties['name']) {
                    $name = "$($first.name)"
                } else {
                    $name = "$first"
                }
            }
        }
        if (-not $name -and $SignatureInfo.subject) {
            # Subject is a DN string like 'CN=Microsoft Corporation, O=Microsoft, C=US'.
            # Extracting just the CN= component avoids fragmenting the same publisher
            # across many keys when DN attribute order varies between samples.
            $sub = "$($SignatureInfo.subject)"
            if ($sub -match '(?i)CN\s*=\s*([^,]+)') { $name = $Matches[1] }
            else { $name = $sub }
        }
        if (-not $name) { return "" }
        $name = $name.ToLowerInvariant().TrimEnd(',', '.', ';', ' ').Trim()
        $name = ($name -replace '\s+', ' ')
        return $name
    }

    # -----------------------------------------------------------------------
    # Get-CommandLineTokens: shared tokenizer used by builder + consumer.
    # Extracts a small set of canonical risk tokens from a command line:
    #   - encoded-payload markers : -enc, -encodedcommand, fromBase64String
    #   - download verbs           : iwr, invoke-webrequest, downloadstring,
    #                                 invoke-restmethod, certutil-urlcache,
    #                                 bitsadmin-transfer, curl, wget
    #   - LOLBin flags             : iex, /c, /k, -nop, -noprofile, -windowstyle hidden,
    #                                 -executionpolicy bypass, regsvr32, rundll32,
    #                                 mshta, wmic, schtasks
    # Returns: distinct lower-cased token strings.
    # NOTE: copy/paste this function into the consumer module to keep tokenizer
    # output identical across builder and runtime sides.
    # -----------------------------------------------------------------------
    function Get-CommandLineTokens {
        param([string]$CommandLine)
        if ([string]::IsNullOrWhiteSpace($CommandLine)) { return @() }
        $cl = $CommandLine.ToLowerInvariant()
        $tokens = [System.Collections.Generic.HashSet[string]]::new()
        # encoded-payload markers
        if ($cl -match '\s-e(nc(odedcommand)?)?\b') { [void]$tokens.Add('cmd:enc') }
        if ($cl -match 'frombase64string')          { [void]$tokens.Add('cmd:b64decode') }
        # download verbs
        if ($cl -match '\b(iwr|invoke-webrequest)\b') { [void]$tokens.Add('cmd:dl:iwr') }
        if ($cl -match 'downloadstring|downloadfile|downloaddata') { [void]$tokens.Add('cmd:dl:net') }
        if ($cl -match '\binvoke-restmethod\b')       { [void]$tokens.Add('cmd:dl:irm') }
        if ($cl -match 'certutil.*(-urlcache|-decode|-decodehex)') { [void]$tokens.Add('cmd:lolbin:certutil-dl') }
        if ($cl -match 'bitsadmin.*/transfer')        { [void]$tokens.Add('cmd:lolbin:bitsadmin-dl') }
        if ($cl -match '\b(curl|wget)\.exe\b|\bcurl\s|\bwget\s') { [void]$tokens.Add('cmd:dl:curl') }
        # LOLBin & evasion flags
        if ($cl -match '\biex\b|invoke-expression') { [void]$tokens.Add('cmd:iex') }
        if ($cl -match '\s/c\b')                    { [void]$tokens.Add('cmd:cmd-c') }
        if ($cl -match '\s/k\b')                    { [void]$tokens.Add('cmd:cmd-k') }
        if ($cl -match '\s-nop\b|\s-noprofile\b')   { [void]$tokens.Add('cmd:ps-noprofile') }
        if ($cl -match '-w(indowstyle)?\s+hidden')  { [void]$tokens.Add('cmd:ps-hidden') }
        if ($cl -match '-ex(ecutionpolicy)?\s+bypass|-ep\s+bypass') { [void]$tokens.Add('cmd:ps-bypass') }
        if ($cl -match '\bregsvr32\.exe\b.*\/i:')  { [void]$tokens.Add('cmd:lolbin:regsvr32-scrobj') }
        if ($cl -match '\brundll32\.exe\b')        { [void]$tokens.Add('cmd:lolbin:rundll32') }
        if ($cl -match '\bmshta\.exe\b')           { [void]$tokens.Add('cmd:lolbin:mshta') }
        if ($cl -match '\bwmic\.exe\b.*process.*call.*create') { [void]$tokens.Add('cmd:lolbin:wmic-spawn') }
        if ($cl -match '\bschtasks\.exe\b.*/create') { [void]$tokens.Add('cmd:lolbin:schtasks-create') }
        return @($tokens)
    }

    # -----------------------------------------------------------------------
    # Bayesian scorer (3-axis, corpus-normalized).
    # Uses Lanczos lgamma + continued-fraction regularized incomplete beta.
    # -----------------------------------------------------------------------
    function Get-LogGamma {
        param([double]$x)
        # Lanczos approximation (g=7, n=9)
        $g = 7.0
        $c = @(
             0.99999999999980993,
           676.5203681218851,
         -1259.1392167224028,
           771.32342877765313,
          -176.61502916214059,
            12.507343278686905,
            -0.13857109526572012,
             9.9843695780195716e-6,
             1.5056327351493116e-7
        )
        if ($x -lt 0.5) {
            # reflection: lgamma(1-x) = log(pi / (sin(pi*x))) - lgamma(x)
            $pi = [Math]::PI
            return [Math]::Log($pi / [Math]::Sin($pi * $x)) - (Get-LogGamma -x (1.0 - $x))
        }
        $x = $x - 1.0
        $a = $c[0]
        $t = $x + $g + 0.5
        for ($i = 1; $i -lt 9; $i++) { $a += $c[$i] / ($x + $i) }
        return 0.5 * [Math]::Log(2.0 * [Math]::PI) + ($x + 0.5) * [Math]::Log($t) - $t + [Math]::Log($a)
    }

    function Get-BetaContinuedFraction {
        param([double]$a, [double]$b, [double]$x)
        # Lentz's method
        $maxIter = 200
        $eps     = 3.0e-7
        $fpmin   = 1.0e-30
        $qab = $a + $b
        $qap = $a + 1.0
        $qam = $a - 1.0
        $c = 1.0
        $d = 1.0 - $qab * $x / $qap
        if ([Math]::Abs($d) -lt $fpmin) { $d = $fpmin }
        $d = 1.0 / $d
        $h = $d
        for ($m = 1; $m -le $maxIter; $m++) {
            $m2 = 2 * $m
            $aa = $m * ($b - $m) * $x / (($qam + $m2) * ($a + $m2))
            $d = 1.0 + $aa * $d
            if ([Math]::Abs($d) -lt $fpmin) { $d = $fpmin }
            $c = 1.0 + $aa / $c
            if ([Math]::Abs($c) -lt $fpmin) { $c = $fpmin }
            $d = 1.0 / $d
            $h *= $d * $c
            $aa = -($a + $m) * ($qab + $m) * $x / (($a + $m2) * ($qap + $m2))
            $d = 1.0 + $aa * $d
            if ([Math]::Abs($d) -lt $fpmin) { $d = $fpmin }
            $c = 1.0 + $aa / $c
            if ([Math]::Abs($c) -lt $fpmin) { $c = $fpmin }
            $d = 1.0 / $d
            $del = $d * $c
            $h *= $del
            if ([Math]::Abs($del - 1.0) -lt $eps) { break }
        }
        return $h
    }

    function Get-RegularizedIncompleteBeta {
        param([double]$a, [double]$b, [double]$x)
        # Exact-arithmetic shortcuts
        if ($x -le 0.0) { return 0.0 }
        if ($x -ge 1.0) { return 1.0 }
        if ([Math]::Abs($a - $b) -lt 1e-12 -and [Math]::Abs($x - 0.5) -lt 1e-12) { return 0.5 }
        # Large-imbalance shortcuts (avoid CF when result is essentially 0 or 1).
        # I_x(a,b) is the Beta(a,b) CDF at x. At x=0.5:
        #   alpha >> beta  -> mass concentrated near p=1 -> CDF(0.5) ~= 0
        #   beta  >> alpha -> mass concentrated near p=0 -> CDF(0.5) ~= 1
        # (Earlier versions had these reversed; that silently zeroed every
        #  high-M / low-G entry's RiskScore. Verified by full evaluation:
        #  I_{0.5}(201, 50) = 2.44e-23  ~= 0;   I_{0.5}(50, 201) ~= 1.)
        if ($a -gt 200.0 -and $b -lt 0.5 * $a) { return 0.0 }
        if ($b -gt 200.0 -and $a -lt 0.5 * $b) { return 1.0 }
        $lbeta = (Get-LogGamma -x $a) + (Get-LogGamma -x $b) - (Get-LogGamma -x ($a + $b))
        $expArg = -$lbeta + $a * [Math]::Log($x) + $b * [Math]::Log(1.0 - $x)
        # Underflow guard: exp(-700) ~= 1e-304, below this the result rounds to 0 either way
        if ($expArg -lt -700.0) {
            # bt underflows. Decide which limit applies by which side of the mode x sits.
            # If x < mode, CDF is essentially 0; if x > mode, CDF is essentially 1.
            $mode = ($a + 1.0) / ($a + $b + 2.0)
            return $(if ($x -lt $mode) { 0.0 } else { 1.0 })
        }
        $bt = [Math]::Exp($expArg)
        if ($x -lt (($a + 1.0) / ($a + $b + 2.0))) {
            return $bt * (Get-BetaContinuedFraction -a $a -b $b -x $x) / $a
        } else {
            return 1.0 - $bt * (Get-BetaContinuedFraction -a $b -b $a -x (1.0 - $x)) / $b
        }
    }

    function Get-ArtifactScores {
        # $L is intentionally unused: L is display-only per v2 scoring signoff.
        param(
            [int]   $M,
            [int]   $G,
            [int]   $L,
            [int]   $Mtotal,
            [int]   $Gtotal,
            [double]$P95Total
        )
        # corpus normalization: G_eff brings goodware count onto the malware scale
        $g_eff = if ($Gtotal -gt 0) { [double]$G * ([double]$Mtotal / [double]$Gtotal) } else { [double]$G }
        $alpha = [double]$M + 1.0
        $beta  = $g_eff + 1.0
        $I = Get-RegularizedIncompleteBeta -a $alpha -b $beta -x 0.5
        $risk = 1.0 - $I
        if ($risk -lt 0.0) { $risk = 0.0 } elseif ($risk -gt 1.0) { $risk = 1.0 }

        $pmiRaw = [Math]::Log((($M + 0.5) / ($Mtotal + 1)), 2) - [Math]::Log((($G + 0.5) / ($Gtotal + 1)), 2)
        $pmi = [Math]::Tanh($pmiRaw / 3.0)

        $denom = [Math]::Log10($P95Total + 1)
        if ($denom -le 0.0) { $denom = 1.0 }
        $conf = [Math]::Log10($M + $G + 1) / $denom
        if ($conf -gt 1.0) { $conf = 1.0 } elseif ($conf -lt 0.0) { $conf = 0.0 }

        $score100 = [Math]::Round($risk * 100.0, [MidpointRounding]::AwayFromZero)
        $U = ($score100 -ge 95) -and ($conf -ge 0.4)
        $R = ($score100 -ge 85) -and ($score100 -lt 95) -and ($conf -ge 0.4)

        return [PSCustomObject]@{
            RiskScore  = [Math]::Round($risk, 6)
            PMI        = [Math]::Round($pmi, 6)
            Confidence = [Math]::Round($conf, 6)
            Score100   = [int]$score100
            U          = $U
            R          = $R
        }
    }

    # Documented per-dim verdict caps (all idf_calibrated:false in manifest)
    $script:_vtfi_maxVP = @{
        'ip'                = 15
        'dns'               = 15
        'process'           = 20
        'file'              = 15
        'registry'          = 20
        'sigma-rule'        = 25
        'yara-rule'         = 25
        'cert-status'       = 30
        'cert-publisher'    = 25
        'mitre-technique'   = 25
        'service'           = 25
        'scheduled-task'    = 25
        'module-load'       = 15
        'command-execution' = 20
        'mutex'             = 30
        'pipe'              = 10
        'win-api'           = 30
        'vt-tag'            = 15
    }

    # Manifest usage tag per dim
    $script:_vtfi_usage = @{
        'ip'                = 'detection'
        'dns'               = 'detection'
        'process'           = 'detection'
        'file'              = 'detection'
        'registry'          = 'detection'
        'sigma-rule'        = 'detection'
        'yara-rule'         = 'detection'
        'cert-status'       = 'detection'
        'cert-publisher'    = 'detection'
        'mitre-technique'   = 'detection'
        'service'           = 'detection'
        'scheduled-task'    = 'detection'
        'module-load'       = 'detection'
        'command-execution' = 'detection'
        'mutex'             = 'enrichment'
        'pipe'              = 'enrichment'
        'win-api'           = 'enrichment'
        'vt-tag'            = 'enrichment'
    }

    # Disk layout on VirusTotal-behaviors/:
    #   malicious/          = flat, ~19629 files today, MALICIOUS
    #   NSRL/<OS>/          = per-OS subfolders (Debian-13, Ubuntu-24.04,
    #                         Windows-11, etc.), GOODWARE
    #   OT/<vendor>/        = per-OT-vendor subfolders, GOODWARE
    #   localBaseline/<bucket>/ = drivers/, SignedVerified/, unsignedWin/,
    #                             unsignedLinux/, unverified/ subfolders,
    #                             GOODWARE - the legacy sub-bucket names
    #                             lived here all along
    #   apt-master-intel/<Country>/<Actor>/ or /Malware Families/<Family>/
    #                         = per-actor and per-family subfolders,
    #                           GOODWARE by design (represents observed
    #                           APT infrastructure - the 'known-shape'
    #                           side of the differential math per the
    #                           corpus-normalization design)
    #
    # Both goodware and malicious buckets NEED -Recurse now that the
    # sub-bucket organization is nested, not flat. Previous flat globs
    # returned 0 files silently and skipped the whole goodware side.
    $malCats  = @("malicious")
    $goodCats = @("NSRL","OT","localBaseline","apt-master-intel")
    $allCats  = $malCats + $goodCats

    $totalFiles = 0; $totalProcessed = 0

    foreach ($cat in $allCats) {
        $catPath = Join-Path $behRoot $cat
        if (-not (Test-Path $catPath)) {
            $isGoodCat = -not ($malCats -contains $cat)
            $color = if ($isGoodCat) { 'Yellow' } else { 'DarkGray' }
            Write-Host "  [skip] $cat (not found at $catPath)" -ForegroundColor $color
            if ($isGoodCat) {
                Write-Warning "Goodware category '$cat' missing under $behRoot -- process-baseline will be starved for this bucket."
            }
            continue
        }
        $files = Get-ChildItem $catPath -Filter "*.json" -Recurse -ErrorAction SilentlyContinue
        $totalFiles += $files.Count
        $isMalicious = $malCats -contains $cat
        $processed = 0

        Write-Host "  Processing $cat ($($files.Count) files)..." -ForegroundColor DarkGray

        foreach ($f in $files) {
            $processed++; $totalProcessed++
            # Corpus totals: 1 file = 1 increment, regardless of which dims fire
            if ($isMalicious) { $script:_vtfi_Mtotal++ }
            else {
                $script:_vtfi_Gtotal++
                $script:_vtfi_GoodwareSubcorpora[$cat] = [int]($script:_vtfi_GoodwareSubcorpora[$cat]) + 1
            }
            if ($processed % 1000 -eq 0) {
                $elapsed = (Get-Date) - $startTime
                Write-Host "    ${cat}: $processed / $($files.Count) ($([Math]::Round($elapsed.TotalSeconds))s elapsed, dim-entries: $($script:_vtfi_keys.Count))" -ForegroundColor DarkGray
            }

            try {
                $raw = Get-Content $f.FullName -Raw
                $j = $raw | ConvertFrom-Json
                $d = $j.data

                $legitName   = ""
                $legitSigner = ""
                $certStatus  = $null
                $certPub     = $null
                $vtTags      = @()

                # Try main JSON for either category (for cert/tag info)
                $mainPath = Join-Path $mainRoot "$cat\$($f.BaseName).json"
                $attr     = $null
                if (Test-Path $mainPath) {
                    try {
                        $mj = Get-Content $mainPath -Raw | ConvertFrom-Json
                        $attr = $mj.data.attributes
                    } catch { $attr = $null }
                }

                if ($attr) {
                    if ($attr.signature_info) {
                        $certStatus = Get-CertStatus -SignatureInfo $attr.signature_info
                        $certPub    = Get-CertPublisher -SignatureInfo $attr.signature_info
                        if ($attr.signature_info.subject) { $legitSigner = "$($attr.signature_info.subject)" }
                    }
                    if (-not $legitSigner -and $attr.code_signing_results) {
                        $vr = $attr.code_signing_results |
                              Where-Object { $_.result -eq "valid" -or $_.result -eq "signed" } |
                              Select-Object -First 1
                        if ($vr -and $vr.subject) { $legitSigner = "$($vr.subject)" }
                    }
                    if ($attr.meaningful_name)            { $legitName = "$($attr.meaningful_name)" }
                    elseif ($attr.names -and $attr.names.Count -gt 0) { $legitName = "$($attr.names[0])" }

                    # cert-status / cert-publisher dims (every sample with main JSON)
                    if (-not $certStatus) { $certStatus = "Unsigned" }
                    Update-Index -Value $certStatus -Dimension "cert-status" -IsMalicious $isMalicious -LegitName $legitName
                    if ($certPub) {
                        Update-Index -Value $certPub -Dimension "cert-publisher" -IsMalicious $isMalicious -LegitName $legitName
                    }

                    # vt-tag (enrichment-only)
                    if ($attr.tags) {
                        $attr.tags | ForEach-Object {
                            if ($_ -and "$_".Length -ge 3) {
                                Update-Index -Value "$_" -Dimension "vt-tag" -IsMalicious $isMalicious -LegitName $legitName
                            }
                        }
                    }
                    if ($attr.popular_threat_classification -and $attr.popular_threat_classification.popular_threat_name) {
                        $attr.popular_threat_classification.popular_threat_name | ForEach-Object {
                            $ptn = if ($_.value) { "$($_.value)" } else { "$_" }
                            if ($ptn -and $ptn.Length -ge 3) {
                                Update-Index -Value $ptn -Dimension "vt-tag" -IsMalicious $isMalicious -LegitName $legitName
                            }
                        }
                    }

                    # sigma/yara rules contribute only when sample is malicious
                    # (matches signoff intent: rules with high hit-rate on malicious corpus = high fidelity)
                    if ($isMalicious -and $attr.sigma_analysis_results) {
                        $attr.sigma_analysis_results | ForEach-Object {
                            if ($_.rule_title) { Update-Index -Value $_.rule_title -Dimension "sigma-rule" -IsMalicious $true -LegitName "" }
                        }
                    }
                    if ($isMalicious -and $attr.crowdsourced_yara_results) {
                        $attr.crowdsourced_yara_results | ForEach-Object {
                            if ($_.rule_name) { Update-Index -Value $_.rule_name -Dimension "yara-rule" -IsMalicious $true -LegitName "" }
                        }
                    }

                    # Register sample's own filename as a known-good process (preserve legacy behavior)
                    if (-not $isMalicious -and $legitName) {
                        $pn = [System.IO.Path]::GetFileName($legitName).ToLower()
                        if ($pn -and $pn.Length -gt 2) {
                            Update-ProcBaseline -Name $pn -FullPath $legitName -IsMalicious $false -Signer $legitSigner
                        }
                    }
                } else {
                    # No main JSON -> contribute Unsigned cert-status
                    Update-Index -Value "Unsigned" -Dimension "cert-status" -IsMalicious $isMalicious -LegitName ""
                }

                # ----- network -----
                if ($d.ip_traffic) {
                    $d.ip_traffic | ForEach-Object {
                        if ($_.destination_ip) {
                            Update-Index -Value $_.destination_ip -Dimension "ip" -IsMalicious $isMalicious -LegitName $legitName
                        }
                    }
                }
                if ($d.dns_lookups) {
                    $d.dns_lookups | ForEach-Object {
                        if ($_.hostname) {
                            Update-Index -Value $_.hostname -Dimension "dns" -IsMalicious $isMalicious -LegitName $legitName
                        }
                    }
                }

                # ----- processes -----
                if ($d.processes_created) {
                    $d.processes_created | ForEach-Object {
                        $raw = "$_".Trim().Trim('"')
                        # VT processes_created is often the full command line, not a bare exe path.
                        # Feeding "C:\Windows\System32\svchost.exe -k netsvcs" whole to GetFileName
                        # yields 'svchost.exe -k netsvcs' as a bogus process name, and GetDirectoryName
                        # produces garbage residue that pollutes the D-list. Extract the executable
                        # token first: leading quoted "path" wins; otherwise the first whitespace-
                        # delimited token. Fallback to $raw if neither pattern matches.
                        $exe = if ($raw -match '^"([^"]+)"') { $Matches[1] }
                               elseif ($raw -match '^(\S+)')  { $Matches[1] }
                               else { $raw }
                        $pn = [System.IO.Path]::GetFileName($exe)
                        if ($pn) {
                            $pnl = $pn.ToLower()
                            Update-Index        -Value $pnl -Dimension "process" -IsMalicious $isMalicious -LegitName $legitName
                            Update-ProcBaseline -Name  $pnl -FullPath $exe -IsMalicious $isMalicious -Signer $legitSigner
                        }
                    }
                }

                # ----- files written -----
                if ($d.files_written) {
                    $d.files_written | ForEach-Object {
                        $fn = [System.IO.Path]::GetFileName($_)
                        if ($fn -and $fn -notmatch '^\.' -and $fn.Length -gt 3) {
                            Update-Index -Value $fn.ToLower() -Dimension "file" -IsMalicious $isMalicious -LegitName $legitName
                        }
                    }
                }

                # ----- registry keys (persistence-style only) -----
                if ($d.registry_keys_set) {
                    $d.registry_keys_set | Where-Object { $_ -match "Run|RunOnce|Services|Winlogon|AppInit|Shell|Policies" } |
                        ForEach-Object {
                            $leaf = ($_ -split '\\')[-1]
                            if ($leaf -and $leaf.Length -gt 2) {
                                Update-Index -Value $leaf.ToLower() -Dimension "registry" -IsMalicious $isMalicious -LegitName $legitName
                            }
                        }
                }

                # ----- mutex (enrichment-only this PR but we still build the dim) -----
                if ($d.mutexes_created) {
                    $d.mutexes_created | Where-Object { $_ -and $_.Length -gt 4 -and $_ -notmatch '^[\w]{1,4}$' } |
                        ForEach-Object {
                            Update-Index -Value $_ -Dimension "mutex" -IsMalicious $isMalicious -LegitName $legitName
                        }
                }

                # ----- MITRE techniques (Phase-1: strip .NNN sub-technique) -----
                if ($d.mitre_attack_techniques) {
                    $d.mitre_attack_techniques | ForEach-Object {
                        $tid = "$($_.id)" -replace '\.\d+$',''
                        if ($tid -match '^T\d{4}') {
                            Update-Index -Value $tid -Dimension "mitre-technique" -IsMalicious $isMalicious -LegitName $legitName
                        }
                    }
                }

                # ----- highlighted API calls (enrichment, feature-flagged on consumer) -----
                if ($d.calls_highlighted) {
                    $d.calls_highlighted | Where-Object { $_ -and $_.Length -gt 3 } | ForEach-Object {
                        Update-Index -Value $_ -Dimension "win-api" -IsMalicious $isMalicious -LegitName $legitName
                    }
                }

                # ----- modules loaded -----
                if ($d.modules_loaded) {
                    $d.modules_loaded | ForEach-Object {
                        $dll = [System.IO.Path]::GetFileName("$_").ToLower()
                        if ($dll -match '\.dll$' -and $dll.Length -gt 4) {
                            Update-Index -Value $dll -Dimension "module-load" -IsMalicious $isMalicious -LegitName $legitName
                        }
                    }
                }

                # ----- processes injected (alias to process dim - same key space) -----
                if ($d.processes_injected) {
                    $d.processes_injected | ForEach-Object {
                        $pn = [System.IO.Path]::GetFileName("$_").ToLower()
                        if ($pn -and $pn.Length -gt 3) {
                            Update-Index -Value $pn -Dimension "process" -IsMalicious $isMalicious -LegitName $legitName
                        }
                    }
                }

                # ----- behavior_summary side-channels -----
                $bs = $d.behavior_summary
                if (-not $bs -and $d.PSObject -and $d.PSObject.Properties['summary']) { $bs = $d.summary }
                if ($bs) {
                    # service
                    foreach ($svcProp in @('services_created','services_opened')) {
                        if ($bs.PSObject.Properties[$svcProp] -and $bs.$svcProp) {
                            $bs.$svcProp | ForEach-Object {
                                $svc = if ($_.name) { "$($_.name)" } else { "$_" }
                                if ($svc -and $svc.Length -gt 2) {
                                    Update-Index -Value $svc.ToLower() -Dimension "service" -IsMalicious $isMalicious -LegitName $legitName
                                }
                            }
                        }
                    }
                    # scheduled-task
                    if ($bs.PSObject.Properties['scheduled_tasks'] -and $bs.scheduled_tasks) {
                        $bs.scheduled_tasks | ForEach-Object {
                            $st = if ($_.name) { "$($_.name)" } elseif ($_.task_name) { "$($_.task_name)" } else { "$_" }
                            if ($st -and $st.Length -gt 2) {
                                Update-Index -Value $st.ToLower() -Dimension "scheduled-task" -IsMalicious $isMalicious -LegitName $legitName
                            }
                        }
                    }
                    # pipe
                    if ($bs.PSObject.Properties['ipc'] -and $bs.ipc -and $bs.ipc.PSObject.Properties['pipes_created']) {
                        $bs.ipc.pipes_created | ForEach-Object {
                            $pp = "$_"
                            if ($pp -and $pp.Length -gt 2) {
                                Update-Index -Value $pp -Dimension "pipe" -IsMalicious $isMalicious -LegitName $legitName
                            }
                        }
                    }
                    # command-execution (tokenized)
                    if ($bs.PSObject.Properties['command_executions'] -and $bs.command_executions) {
                        $bs.command_executions | ForEach-Object {
                            $cl = "$_"
                            $toks = Get-CommandLineTokens -CommandLine $cl
                            foreach ($t in $toks) {
                                Update-Index -Value $t -Dimension "command-execution" -IsMalicious $isMalicious -LegitName $legitName
                            }
                        }
                    }
                }

                # High-severity behavior signatures (legacy fold-in -> mitre-technique-adjacent;
                # keep them in win-api dim for now to preserve enrichment value w/o new dim).
                # Note: the win-api dim therefore holds TWO disjoint token namespaces -
                # raw API names ('CreateRemoteThread') and 'sig:<signature_name>' tokens
                # ('sig:Code Injection'). They share a key namespace but never collide
                # because the 'sig:' prefix is reserved. Consumers/dashboards that want
                # only raw APIs should filter on keys NOT starting with 'sig:'. Both
                # contribute zero verdict points by default (dimension_gates disables
                # win-api verdict_points; see manifest).
                if ($d.signatures) {
                    $d.signatures | Where-Object { $_.severity -ge 7 } | ForEach-Object {
                        if ($_.name) {
                            Update-Index -Value "sig:$($_.name)" -Dimension "win-api" -IsMalicious $isMalicious -LegitName $legitName
                        }
                    }
                }

            } catch { <# skip malformed files #> }
        }

        Write-Host "    $cat complete: $processed files, dim-entries now $($script:_vtfi_keys.Count)" -ForegroundColor DarkGray
    }

    # -----------------------------------------------------------------------
    # Phase 2: APT differential merge (lowest GoodCount wins; highest MalCount wins).
    # -----------------------------------------------------------------------
    if (-not $SkipPhase2 -and $AptRoot -and (Test-Path $AptRoot)) {
        Write-Host "`n  [Phase 2] Merging APT differential analysis from $AptRoot ..." -ForegroundColor DarkCyan
        $aptFiles = Get-ChildItem $AptRoot -Recurse -Filter "Targeted*DifferentialAnalysis.json" -ErrorAction SilentlyContinue
        Write-Host "    Found $($aptFiles.Count) APT differential files" -ForegroundColor DarkGray

        $aptUpdated = 0; $aptAdded = 0
        foreach ($af in $aptFiles) {
            try {
                $entries = Get-Content $af.FullName -Raw | ConvertFrom-Json
                # Infer default dimension from filename for rows that don't self-identify
                $fnLower = $af.Name.ToLower()
                # File-dim must be matched BEFORE the generic process catch-all, else
                # any 'TargetedFiles*DifferentialAnalysis.json' is silently mis-routed
                # to the 'process' dim.
                $defaultDim = if ($fnLower -match 'ip')        { 'ip' }
                              elseif ($fnLower -match 'dns|domain|host') { 'dns' }
                              elseif ($fnLower -match 'mutex') { 'mutex' }
                              elseif ($fnLower -match 'sigma') { 'sigma-rule' }
                              elseif ($fnLower -match 'yara')  { 'yara-rule' }
                              elseif ($fnLower -match 'mitre|ttp|technique') { 'mitre-technique' }
                              elseif ($fnLower -match 'registry') { 'registry' }
                              elseif ($fnLower -match 'service')  { 'service' }
                              elseif ($fnLower -match 'task|schedule') { 'scheduled-task' }
                              elseif ($fnLower -match 'cmd|command') { 'command-execution' }
                              elseif ($fnLower -match 'module|dll')  { 'module-load' }
                              elseif ($fnLower -match 'pipe')  { 'pipe' }
                              elseif ($fnLower -match 'cert')  { 'cert-publisher' }
                              elseif ($fnLower -match 'tag')   { 'vt-tag' }
                              elseif ($fnLower -match 'files?\b|written|writes?\b|dropped') { 'file' }
                              elseif ($fnLower -match 'process|exec|binary') { 'process' }
                              else  { 'process' }

                foreach ($entry in $entries) {
                    $rawKey = if ($entry.Item_Name) { "$($entry.Item_Name)".Trim() } else { $null }
                    if (-not $rawKey -or $rawKey.Length -lt 3) { continue }

                    # Per-row dim override if entry exposes a Type/Dimension hint
                    $dim = $defaultDim
                    if ($entry.PSObject.Properties['Item_Type']) {
                        $itype = "$($entry.Item_Type)".ToLower()
                        switch -Regex ($itype) {
                            '^ip'           { $dim = 'ip' }
                            'dns|domain|host' { $dim = 'dns' }
                            'mutex'         { $dim = 'mutex' }
                            'sigma'         { $dim = 'sigma-rule' }
                            'yara'          { $dim = 'yara-rule' }
                            '^t\d{4}|mitre|technique' { $dim = 'mitre-technique' }
                            'registry|reg'  { $dim = 'registry' }
                            'service'       { $dim = 'service' }
                            'task|sched'    { $dim = 'scheduled-task' }
                            'cmd|command'   { $dim = 'command-execution' }
                            'module|\.dll'  { $dim = 'module-load' }
                            'pipe'          { $dim = 'pipe' }
                            'cert'          { $dim = 'cert-publisher' }
                            'tag'           { $dim = 'vt-tag' }
                            'process|file|binary|exe' { $dim = 'process' }
                        }
                    }

                    # Normalize key (MITRE: strip sub-technique even at Phase-2)
                    $key = $rawKey
                    if ($dim -eq 'mitre-technique') { $key = $key -replace '\.\d+$','' }

                    $compKey = "$dim|$key"
                    # Distinguish missing field (default to 1) from explicit zero (keep zero).
                    $mc = if ($null -ne $entry.Malicious_Count) { [int]$entry.Malicious_Count } else { 1 }
                    $gc = if ($null -ne $entry.Baseline_Count)  { [int]$entry.Baseline_Count }  else { 0 }

                    if ($script:_vtfi_keys.Contains($compKey)) {
                        # "Lowest G wins" overwrite guarded so a Baseline_Count=0 APT row
                        # cannot clobber a legitimate goodware count for a ubiquitous
                        # process (e.g. chrome.exe phase-1 G=500 must not be overwritten
                        # by a phase-2 'this APT used chrome.exe' row with G=0). We only
                        # allow the overwrite when the new G is itself > 0 AND clearly
                        # smaller than the existing G (less than half), or when no
                        # phase-1 evidence exists yet (existing G == 0).
                        $existingG = [int]($script:_vtfi_good[$compKey])
                        $allowOverwrite = $false
                        if ($existingG -eq 0) { $allowOverwrite = ($gc -ge 0) }
                        elseif ($gc -gt 0 -and $gc -lt ($existingG * 0.5)) { $allowOverwrite = $true }
                        if ($allowOverwrite -and $gc -lt $existingG) {
                            $script:_vtfi_good[$compKey] = $gc
                            $aptUpdated++
                        }
                        if ($mc -gt [int]($script:_vtfi_mal[$compKey])) { $script:_vtfi_mal[$compKey] = $mc }
                    } else {
                        $script:_vtfi_mal[$compKey]  = $mc
                        $script:_vtfi_good[$compKey] = $gc
                        [void]$script:_vtfi_keys.Add($compKey)
                        [void]$script:_vtfi_dims.Add($dim)
                        $aptAdded++
                    }
                }
            } catch { <# skip malformed #> }
        }
        Write-Host "    APT merge complete: $aptUpdated updated (lower G), $aptAdded added" -ForegroundColor DarkGray
    } elseif ($SkipPhase2) {
        Write-Host "`n  [Phase 2] -SkipPhase2 set; APT merge skipped" -ForegroundColor DarkYellow
    } elseif ($AptRoot) {
        Write-Host "`n  [Phase 2] APT root not found at $AptRoot - skipping" -ForegroundColor DarkYellow
    }

    # -----------------------------------------------------------------------
    # Per-dim aggregates: median_total and p95_total over each dim's (M+G) values.
    # -----------------------------------------------------------------------
    Write-Host "`n  Computing per-dim aggregates..." -ForegroundColor DarkCyan
    $script:_vtfi_dimMeta = @{}
    $dimBuckets = @{}
    foreach ($k in $script:_vtfi_keys) {
        $sep = $k.IndexOf('|')
        if ($sep -lt 0) { continue }
        $dim = $k.Substring(0, $sep)
        $tot = [int]($script:_vtfi_mal[$k]) + [int]($script:_vtfi_good[$k])
        if (-not $dimBuckets.ContainsKey($dim)) {
            $dimBuckets[$dim] = [System.Collections.Generic.List[int]]::new()
        }
        [void]$dimBuckets[$dim].Add($tot)
    }
    foreach ($dim in $dimBuckets.Keys) {
        $arr = $dimBuckets[$dim].ToArray() | Sort-Object
        $n = $arr.Count
        if ($n -eq 0) { continue }
        # True median: average of two middle values when N is even, so dashboards
        # that consume median_total see a strict median rather than the lower-mid value.
        $median = if ($n % 2 -eq 0) {
            [int]([Math]::Round((($arr[$n/2 - 1] + $arr[$n/2]) / 2.0), [MidpointRounding]::AwayFromZero))
        } else {
            $arr[[Math]::Floor($n / 2)]
        }
        $p95idx = [Math]::Min($n - 1, [Math]::Floor($n * 0.95))
        $p95    = $arr[$p95idx]
        if ($p95 -lt 1) { $p95 = 1 }
        $script:_vtfi_dimMeta[$dim] = [PSCustomObject]@{
            EntryCount   = $n
            MedianTotal  = [int]$median
            P95Total     = [int]$p95
        }
    }

    # -----------------------------------------------------------------------
    # Score every entry: per-dim files + flat compat union.
    # -----------------------------------------------------------------------
    Write-Host "`n  Scoring $($script:_vtfi_keys.Count) entries across $($script:_vtfi_dims.Count) dimensions ..." -ForegroundColor DarkCyan

    $perDim = @{}       # dim -> @{ value -> entry-object }
    $flatOut = @{}      # 'dim|value' OR legacy bare key -> entry-object (compat)
    $uniqueCount = 0; $rareCount = 0
    $Mtotal = [int]$script:_vtfi_Mtotal
    $Gtotal = [int]$script:_vtfi_Gtotal

    foreach ($k in $script:_vtfi_keys) {
        $sep = $k.IndexOf('|')
        if ($sep -lt 0) { continue }
        $dim = $k.Substring(0, $sep)
        $val = $k.Substring($sep + 1)
        $mc  = [int]($script:_vtfi_mal[$k])
        $gc  = [int]($script:_vtfi_good[$k])
        if ($mc -eq 0 -and $gc -eq 0) { continue }
        $legit = if ($script:_vtfi_legit.ContainsKey($k)) { @($script:_vtfi_legit[$k]) } else { @() }

        $p95 = if ($script:_vtfi_dimMeta.ContainsKey($dim)) { [double]$script:_vtfi_dimMeta[$dim].P95Total } else { 1.0 }
        $scores = Get-ArtifactScores -M $mc -G $gc -L $legit.Count -Mtotal $Mtotal -Gtotal $Gtotal -P95Total $p95

        # Preserve legacy S (bit-identical to legacy formula)
        $legacyS = if   ($gc -eq 0)  { 100.0 }
                   elseif ($gc -le 3) {  95.0 }
                   else { [Math]::Max(30.0, 95.0 - ([Math]::Log($gc + 1, 2) * 15.0)) }
        $legacyS = [Math]::Round($legacyS, 1)

        if ($scores.U) { $uniqueCount++ }
        if ($scores.R) { $rareCount++ }

        # Preliminary verdict points (consumer may override per dim flag)
        $cap = if ($script:_vtfi_maxVP.ContainsKey($dim)) { [int]$script:_vtfi_maxVP[$dim] } else { 15 }
        $vp = 0
        if (($mc + $gc) -ge 5) {
            $vpRaw = (($scores.RiskScore - 0.5) * 40.0 + [Math]::Max(0.0, $scores.PMI) * 20.0) * $scores.Confidence
            $vp = [int][Math]::Round($vpRaw, [MidpointRounding]::AwayFromZero)
            if ($vp -lt 0)    { $vp = 0 }
            if ($vp -gt $cap) { $vp = $cap }
        }

        $entry = [PSCustomObject]@{
            M             = $mc
            G             = $gc
            S             = $legacyS
            U             = $scores.U
            R             = $scores.R
            L             = $legit
            RiskScore     = $scores.RiskScore
            Confidence    = $scores.Confidence
            PMI           = $scores.PMI
            Score100      = $scores.Score100
            Dimension     = $dim
            VerdictPoints = $vp
        }

        if (-not $perDim.ContainsKey($dim)) { $perDim[$dim] = @{} }
        $perDim[$dim][$val] = $entry

        # Compat shim: legacy flat file used bare value keys (no dim prefix).
        # On cross-dim collision (e.g. 'svchost.exe' appears in process, file, and
        # module-load dims), prefer the highest-RiskScore entry so we never
        # silently downgrade a high-fidelity detection. Consumer is encouraged
        # to migrate to the manifest-based loader to get the dim-correct entry.
        if ($flatOut.ContainsKey($val)) {
            $existing = $flatOut[$val]
            if ([double]$entry.RiskScore -gt [double]$existing.RiskScore) {
                $flatOut[$val] = $entry
            }
        } else {
            $flatOut[$val] = $entry
        }
    }

    $elapsed = (Get-Date) - $startTime

    # -----------------------------------------------------------------------
    # WRITE PHASE
    # -----------------------------------------------------------------------
    Write-Host "`n  Writing per-dimension index files ..." -ForegroundColor DarkCyan
    $indicesMeta = @()
    $blockingZero = @()
    # Iterate over the union of (all known dims from $script:_vtfi_maxVP) AND
    # $perDim.Keys. Dims with zero entries still get a file written (empty {}),
    # still appear in indices[], and still trigger the $blockingZero warning -
    # the consumer can therefore distinguish 'dim absent / build regression'
    # from 'dim present but no entries on this corpus'.
    $allKnownDims = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($d in $script:_vtfi_maxVP.Keys) { [void]$allKnownDims.Add($d) }
    foreach ($d in $perDim.Keys)             { [void]$allKnownDims.Add($d) }
    foreach ($dim in (@($allKnownDims) | Sort-Object)) {
        $fname = "fidelity-$dim.json"
        $fpath = Join-Path $BaselineRoot $fname
        $bucket = if ($perDim.ContainsKey($dim)) { $perDim[$dim] } else { @{} }
        ([PSCustomObject]$bucket) | ConvertTo-Json -Depth 20 -Compress | Set-Content -Path $fpath -Encoding UTF8
        $entryCount = $bucket.Keys.Count
        if ($entryCount -eq 0) { $blockingZero += $dim }
        $median = if ($script:_vtfi_dimMeta.ContainsKey($dim)) { [int]$script:_vtfi_dimMeta[$dim].MedianTotal } else { 0 }
        $p95v   = if ($script:_vtfi_dimMeta.ContainsKey($dim)) { [int]$script:_vtfi_dimMeta[$dim].P95Total } else { 1 }
        $cap    = if ($script:_vtfi_maxVP.ContainsKey($dim))   { [int]$script:_vtfi_maxVP[$dim] } else { 15 }
        $usage  = if ($script:_vtfi_usage.ContainsKey($dim))   { $script:_vtfi_usage[$dim] } else { 'detection' }
        $indicesMeta += [PSCustomObject]@{
            dimension          = $dim
            filename           = $fname
            file               = $fname   # also expose as 'file' so consumer/calibration probes can locate via either key
            entry_count        = $entryCount
            usage              = $usage
            median_total       = $median
            p95_total          = $p95v
            max_verdict_points = $cap
            idf_calibrated     = $false
        }
        Write-Host ("    {0,-22} {1,7} entries  (median={2}, p95={3}, cap={4}, {5})" -f $dim, $entryCount, $median, $p95v, $cap, $usage) -ForegroundColor DarkGray
    }

    # Manifest. calibration_passed contract (post adversarial review):
    #   $null            = no binding evidence yet (fresh build, or prior
    #                      calibration was phase4_status=SKIPPED, or build
    #                      signature changed and we cleared the stale flag).
    #   $false           = calibration ran end-to-end and at least one gate
    #                      FAILED. New scoring path remains DISABLED.
    #   $true            = calibration runner verified all gates AND Phase 4
    #                      ran with phase4_status='PASSED'. Only state in
    #                      which the consumer enables the new scoring path.
    # build_signature ties calibration to a specific corpus snapshot. It is a
    # SHA-256 over (Mtotal, Gtotal, per-dim entry counts sorted by dim name)
    # so two builds that produce the same corpus statistics produce the same
    # signature even if file timestamps differ. When the signature is stable
    # the builder preserves the prior calibration verdict; when it changes
    # the builder clears calibration_passed back to $null + phase4_status
    # back to 'NOT_RUN' so downstream consumers see an explicit "needs
    # re-calibration" signal rather than a silently-stale PASS.
    $dimSigParts = @($script:_vtfi_dimMeta.Keys | Sort-Object | ForEach-Object {
        $ec = if ($script:_vtfi_dimMeta[$_].PSObject.Properties['EntryCount']) {
                  [int]$script:_vtfi_dimMeta[$_].EntryCount
              } else { 0 }
        "$_=$ec"
    })
    $sigInput = "Mtotal:$Mtotal,Gtotal:$Gtotal," + ($dimSigParts -join ',')
    $sha256   = [System.Security.Cryptography.SHA256]::Create()
    try {
        $sigBytes = [System.Text.Encoding]::UTF8.GetBytes($sigInput)
        $sigHash  = $sha256.ComputeHash($sigBytes)
        $buildSignature = ($sigHash | ForEach-Object { $_.ToString('x2') }) -join ''
    } finally {
        $sha256.Dispose()
    }
    $manifestPath = Join-Path $BaselineRoot "fidelity-manifest.json"

    # Dimension meta table (dim -> { max_verdict_points, usage }) so the
    # consumer can index by dim name without scanning the indices[] array.
    $dimensionMeta = @{}
    foreach ($im in $indicesMeta) {
        $dimensionMeta[$im.dimension] = [PSCustomObject]@{
            max_verdict_points = $im.max_verdict_points
            usage              = $im.usage
            entry_count        = $im.entry_count
            median_total       = $im.median_total
            p95_total          = $im.p95_total
        }
    }
    $manifest = [PSCustomObject]@{
        schema_version         = 2
        generated_utc          = (Get-Date).ToUniversalTime().ToString("o")
        build_signature        = $buildSignature
        totals                 = [PSCustomObject]@{
            Mtotal              = $Mtotal
            Gtotal              = $Gtotal
            FilesProcessed      = $totalProcessed
            GoodwareSubcorpora  = [PSCustomObject]$script:_vtfi_GoodwareSubcorpora
        }
        # Also expose under 'corpus' for downstream tooling that asks for either.
        corpus                 = [PSCustomObject]@{
            Mtotal              = $Mtotal
            Gtotal              = $Gtotal
            FilesProcessed      = $totalProcessed
            GoodwareSubcorpora  = [PSCustomObject]$script:_vtfi_GoodwareSubcorpora
        }
        indices                = $indicesMeta
        dimension_meta         = [PSCustomObject]$dimensionMeta
        scoring                = [PSCustomObject]@{
            formula                = 'corpus_normalized_beta_binomial_v2'
            prior_alpha            = 1.0
            prior_beta             = 1.0
            l_weight               = 0.0
            confidence_norm_basis  = 'per_dimension_p95'
            canonicalization       = [PSCustomObject]@{
                cert_publisher = 'lowercase + collapse whitespace + trim trailing , . ; space; CN= extracted from DN subject fallback'
                cert_status    = 'TitleCase enum: SignedVerified|SelfSigned|Unsigned|SignedExpired|SignedRevoked|InvalidSignature|CatalogSigned'
                mitre          = 'parent T-code only; .NNN sub-technique stripped at insert in both phase 1 and phase 2'
                ip             = 'System.Net.IPAddress.Parse then ToString (canonical IPv6)'
                process_file_module = 'GetFileName(path).ToLower()'
                dns            = 'lowercase + trim trailing .'
            }
            dimension_gates        = [PSCustomObject]@{
                'behavior.win_api_call' = [PSCustomObject]@{
                    verdict_points_enabled = $false
                    reason                 = 'no host extractor; enrichment-only'
                }
            }
            # Contract: this field is [bool] OR $null. $null means "no binding
            # evidence" (initial state or post-corpus-drift). Builder NEVER
            # writes $true. Only the calibration runner writes $true, and
            # only after Phase 4 runs end-to-end with phase4_status='PASSED'.
            calibration_passed         = $null
            calibration_last_run       = $null
            calibration_phase4_status  = 'NOT_RUN'
            calibration_phase4_reason  = ''
            calibration_run_utc        = $null
            calibration_failed_reason  = $null
            calibration_notes          = ''
        }
        legacy_compat_flat_file = $true
    }

    # Read-then-merge calibration result: preserve prior calibration verdict
    # across rebuilds IFF build_signature is unchanged. On corpus drift, clear
    # calibration_passed back to $null and reset phase4_status to NOT_RUN so
    # callers see an explicit "needs re-calibration" signal. Always write the
    # NEW build_signature regardless.
    if (Test-Path $manifestPath) {
        try {
            $prior = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $priorSig = $null
            if ($prior.PSObject.Properties['build_signature']) { $priorSig = [string]$prior.build_signature }
            elseif ($prior.scoring -and $prior.scoring.PSObject.Properties['build_signature']) { $priorSig = [string]$prior.scoring.build_signature }
            if ($priorSig -eq $buildSignature -and $prior.scoring) {
                # Signature stable -> preserve calibration verdict + companions.
                $priorScoring = $prior.scoring
                $copyIf = {
                    param($name)
                    if ($priorScoring.PSObject.Properties[$name]) {
                        $manifest.scoring.$name = $priorScoring.$name
                    }
                }
                & $copyIf 'calibration_passed'
                & $copyIf 'calibration_last_run'
                & $copyIf 'calibration_phase4_status'
                & $copyIf 'calibration_phase4_reason'
                & $copyIf 'calibration_run_utc'
                & $copyIf 'calibration_failed_reason'
                & $copyIf 'calibration_notes'
                $priorPassedDisplay = if ($null -eq $priorScoring.calibration_passed) { 'null' } else { [string]$priorScoring.calibration_passed }
                Write-Host ("    [Build] Existing manifest matches new build_signature; preserving calibration result: calibration_passed=$priorPassedDisplay") -ForegroundColor DarkGray
            } else {
                # Signature changed or no prior scoring section -> clear stale verdict.
                $manifest.scoring.calibration_passed        = $null
                $manifest.scoring.calibration_phase4_status = 'NOT_RUN'
                if ($priorSig -and $prior.scoring -and $prior.scoring.calibration_passed -eq $true) {
                    $manifest.scoring.calibration_failed_reason = "build_signature changed since prior calibration ('$priorSig' -> '$buildSignature')"
                }
                Write-Host "    [Build] No matching prior calibration for this build; calibration_passed cleared. Run Test-FidelityIndexCalibration." -ForegroundColor Yellow
            }
        } catch {
            # Prior manifest unparseable -> treat as never-calibrated.
            Write-Host "    [Build] Prior manifest unparseable; treating as never-calibrated. Run Test-FidelityIndexCalibration." -ForegroundColor Yellow
        }
    } else {
        Write-Host "    [Build] No prior manifest at $manifestPath; calibration_passed remains null until Test-FidelityIndexCalibration runs." -ForegroundColor DarkGray
    }
    # ALWAYS write the freshly-computed build_signature into scoring so consumers
    # have a single canonical location to read it. (We also keep the top-level
    # build_signature for back-compat with older readers.)
    if (-not $manifest.scoring.PSObject.Properties['build_signature']) {
        Add-Member -InputObject $manifest.scoring -MemberType NoteProperty -Name 'build_signature' -Value $buildSignature -Force
    } else {
        $manifest.scoring.build_signature = $buildSignature
    }

    $manifest | ConvertTo-Json -Depth 20 -Compress | Set-Content -Path $manifestPath -Encoding UTF8
    Write-Host "    fidelity-manifest.json written ($([Math]::Round((Get-Item $manifestPath).Length / 1KB, 1)) KB)" -ForegroundColor Green

    # Flat compat shim (PRESERVED filename)
    ([PSCustomObject]$flatOut) | ConvertTo-Json -Depth 20 -Compress | Set-Content -Path $outFile -Encoding UTF8
    Write-Host "    fidelity-index.json (compat shim) written ($([Math]::Round((Get-Item $outFile).Length / 1MB, 2)) MB)" -ForegroundColor Green

    # Process baseline emit. Fail-loud sentinel: if procG is empty but the
    # walker DID see goodware (Gtotal > 0), that is a contradiction we must
    # surface rather than silently overwrite process-baseline.json with '{}'.
    # Prior incident (2026-07-13 18:03 build): Gtotal=132675 but on-disk
    # process-baseline.json was 4 bytes '{}'. Root cause never conclusively
    # identified; the guard below turns any future recurrence into a hard
    # abort with enough diagnostic state to root-cause it (procG.Count,
    # procM.Count, Gtotal, Mtotal). Existing tracked baseline is preserved.
    $procOutFile = Join-Path $BaselineRoot "process-baseline.json"
    $procGCount = $script:_vtfi_procG.Count
    $procMCount = $script:_vtfi_procM.Count
    Write-Host "`n  Building process baseline from $procGCount known-good process names..." -ForegroundColor DarkCyan
    if ($procGCount -eq 0 -and $Gtotal -gt 0) {
        Write-Warning ("process-baseline emit aborted: _vtfi_procG.Count=0 but Gtotal=$Gtotal " +
                       "(walker processed goodware but registered zero goodware process names). " +
                       "State: procM.Count=$procMCount, Mtotal=$Mtotal, scrubDropped=$($script:_vtfi_scrubDropped). " +
                       "Preserving existing $procOutFile on disk instead of overwriting with '{}'.")
        throw "process-baseline emit invariant violated: procG empty despite Gtotal>0. Refusing to overwrite $procOutFile."
    }
    $procOut = @{}
    foreach ($pn in $script:_vtfi_procG.Keys) {
        $gVal = [int]($script:_vtfi_procG[$pn])
        if ($gVal -eq 0) { continue }
        $signers = @($script:_vtfi_procSigners[$pn] -split '\|' | Where-Object { $_ })
        $dirs    = @($script:_vtfi_procDirs[$pn]    -split '\|' | Where-Object { $_ })
        $procOut[$pn] = [PSCustomObject]@{
            G = $gVal
            M = [int]($script:_vtfi_procM[$pn])
            S = $signers
            D = $dirs
        }
    }
    ([PSCustomObject]$procOut) | ConvertTo-Json -Depth 4 -Compress | Set-Content -Path $procOutFile -Encoding UTF8
    Write-Host "    process-baseline.json written ($([Math]::Round((Get-Item $procOutFile).Length / 1MB, 2)) MB, $($procOut.Count) entries)" -ForegroundColor Green
    Write-Host "    [Scrub] Dropped $($script:_vtfi_scrubDropped) sandbox-artifact paths across $($script:_vtfi_scrubProcs.Count) distinct process names during build" -ForegroundColor DarkYellow

    # -----------------------------------------------------------------------
    # Final report
    # -----------------------------------------------------------------------
    Write-Host "`n  Build complete:" -ForegroundColor Green
    Write-Host "    Files processed              : $totalProcessed"
    Write-Host "    Corpus Mtotal (malicious)    : $Mtotal"
    Write-Host "    Corpus Gtotal (goodware)     : $Gtotal"
    Write-Host "    Goodware subcorpora          :"
    foreach ($sc in $script:_vtfi_GoodwareSubcorpora.Keys) {
        Write-Host "      - $sc = $($script:_vtfi_GoodwareSubcorpora[$sc])"
    }
    Write-Host "    Total dim entries scored     : $($script:_vtfi_keys.Count)"
    Write-Host "    Unique-to-malware (U)        : $uniqueCount"
    Write-Host "    Rare              (R)        : $rareCount"
    Write-Host "    Build time                   : $([Math]::Round($elapsed.TotalMinutes, 1)) minutes"

    if ($blockingZero.Count -gt 0) {
        Write-Warning "BLOCKING: dimensions with zero entries: $($blockingZero -join ', ')"
    }

    # Clean up module-scope working variables
    $script:_vtfi_mal = $null; $script:_vtfi_good = $null; $script:_vtfi_legit = $null
    $script:_vtfi_keys = $null; $script:_vtfi_dims = $null
    $script:_vtfi_procG = $null; $script:_vtfi_procM = $null
    $script:_vtfi_procSigners = $null; $script:_vtfi_procDirs = $null
    $script:_vtfi_maxLN = $null
    $script:_vtfi_scrubDropped = $null; $script:_vtfi_scrubProcs = $null
    $script:_vtfi_sandboxArtifactRx = $null
    $script:_vtfi_Mtotal = $null; $script:_vtfi_Gtotal = $null
    $script:_vtfi_GoodwareSubcorpora = $null
    $script:_vtfi_dimMeta = $null
    $script:_vtfi_maxVP = $null; $script:_vtfi_usage = $null

    return [PSCustomObject]@{
        SchemaVersion  = 2
        ManifestPath   = $manifestPath
        FlatIndexPath  = $outFile
        Entries        = $flatOut.Count
        Dimensions     = $indicesMeta.Count
        UniqueCount    = $uniqueCount
        RareCount      = $rareCount
        FilesScanned   = $totalProcessed
        Mtotal         = $Mtotal
        Gtotal         = $Gtotal
        BuildSeconds   = [Math]::Round($elapsed.TotalSeconds)
        BlockingZeroDims = $blockingZero
    }
}

# ---------------------------------------------------------------------------
# Invoke-ProcessBaselineScrub
#
# One-shot retroactive cleanup for a process-baseline.json that was built
# BEFORE the sandbox-artifact scrub landed. Reads the JSON, filters the
# D-list of every process entry through the same regex that Build-VTFidelityIndex
# now applies at build time, then writes the file back in-place. Runs in
# seconds vs. a ~10-minute full rebuild.
#
# Use this when:
#   - You upgraded elasticPotato\agentic\ElasticAlertAgent.psm1 but do NOT want
#     to re-run Build-VTFidelityIndex right now, AND
#   - You want stale baseline D-lists cleaned up so downstream masquerade checks
#     see a scrubbed picture instead of relying on the runtime defense-in-depth
#     filter alone.
#
# The regex is duplicated from Build-VTFidelityIndex's $script:_vtfi_sandboxArtifactRx
# so this helper is self-contained. If you change one, change both (see the
# "MUST be mirrored" contract on the builder regex).
# ---------------------------------------------------------------------------
function Invoke-ProcessBaselineScrub {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Error "process-baseline.json not found at: $Path"
        return
    }
    $rx = [regex]::new(
        '^%[a-z]+%|^c:\\users\\(user|admin|administrator|analyst|sandbox|malware)\\|^c:\\users\\[^\\]+\\desktop($|\\)|^c:\\users\\[^\\]+\\appdata\\local\\temp($|\\)',
        ([System.Text.RegularExpressions.RegexOptions]::Compiled -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    )
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $obj = $raw | ConvertFrom-Json
    $totalDropped = 0
    $procsTouched = 0
    $out = [ordered]@{}
    foreach ($prop in $obj.PSObject.Properties) {
        $entry = $prop.Value
        $before = @($entry.D)
        $after = @($before | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $rx.IsMatch(([string]$_).ToLower()) })
        $dropped = $before.Count - $after.Count
        if ($dropped -gt 0) {
            $totalDropped += $dropped
            $procsTouched++
        }
        $out[$prop.Name] = [PSCustomObject]@{
            G = $entry.G
            M = $entry.M
            S = @($entry.S)
            D = $after
        }
    }
    ([PSCustomObject]$out) | ConvertTo-Json -Depth 4 -Compress | Set-Content -LiteralPath $Path -Encoding UTF8
    Write-Host "[Scrub] Rewrote $Path : dropped $totalDropped sandbox-artifact paths across $procsTouched process entries" -ForegroundColor Green
}

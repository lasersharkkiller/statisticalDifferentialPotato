#Requirements
#Install-Module -Scope CurrentUser Microsoft.PowerShell.SecretManagement, Microsoft.Powershell.SecretStore -Force
#Register-SecretVault -Name LocalSecrets -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
#VirusTotal API (multiple keys spread the rate limit)
#Set-Secret -Name 'VT_API_Key_1' -Secret '<your-vt-key-1>'
#Set-Secret -Name 'VT_API_Key_2' -Secret '<your-vt-key-2>'
#Optional - Intezer
#Set-Secret -Name 'Intezer_API_Key' -Secret '<your-intezer-key>'


# Group 1: Build Process Baseline (was Group 15 in Loaded-Potato)
Import-Module -Name ".\baseline\VTBaseline.psm1"
Import-Module -Name ".\baseline\AptMasterIntelVT.psm1"
Import-Module -Name ".\baseline\OtBaseline.psm1"
Import-Module -Name ".\agentic\Build-VTFidelityIndex.psm1"
Import-Module -Name ".\agentic\Build-BehavioralFingerprintTable.psm1"
Import-Module -Name ".\purpleTeaming\GetVTDetectionsFromList.psm1"
Import-Module -Name ".\baseline\OrganizeBaselines.psm1"
Import-Module -Name ".\purpleTeaming\GetDedupHashesToSha256.psm1"
Import-Module -Name ".\purpleTeaming\GetRemoveMalwareBazaarEntries.psm1"
Import-Module -Name ".\purpleTeaming\aptIocs.psm1"

# Group 2: Static/Dynamic Differentials (was Group 16 in Loaded-Potato)
Import-Module -Name ".\baseline\maliciousDifferential.psm1"
Import-Module -Name ".\baseline\maliciousApiDllDifferential.psm1"
Import-Module -Name ".\baseline\targetedMalwareDifferentialAnalysis.psm1"
Import-Module -Name ".\baseline\specifiedMaliciousApiDllDifferential.psm1"

# Group 3: Reports (was 20b in Loaded-Potato)
Import-Module -Name ".\reports\createApiMatrix.psm1"
Import-Module -Name ".\reports\createArtOfWarMitreMatrix.psm1"

# Connectivity check
try {
    $ping = Test-Connection -ComputerName "8.8.8.8" -Count 1 -Quiet
    if (-not $ping) { Write-Host "Unable to reach 8.8.8.8 - network connectivity may be limited" }
} catch {
    Write-Host "Unable to reach 8.8.8.8 - network connectivity may be limited"
}

Write-Host "statisticalDifferentialPotato - VT baseline + statistical differential analysis"
Write-Host "Choose which function you would like to use:"
Write-Host ""

# -- GROUP 1: Build Process Baseline ------------------------------------------
Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkCyan
Write-Host "  $([char]27)[4m|                  NextGen NSRL                  |$([char]27)[24m" -ForegroundColor DarkCyan
Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkCyan
Write-Host "1a) Baseline Procs with VirusTotal  (submenu: per-OS continue, APT pulls, local/malicious)" -ForegroundColor DarkCyan
Write-Host "1b) Harvest IOCs per Threat Actor / Malware Family  (VT Intel + ThreatFox + MalwareBazaar + URLhaus + OTX + Cybersixgill)" -ForegroundColor DarkCyan
Write-Host "     -> Populates apt\APTs\<Country>\<Actor>\<Actor>_Master_Intel.csv from threat-intel feeds" -ForegroundColor DarkGray
Write-Host "     -> Run BEFORE 1a's 'Pull VT Metadata for ...' submenu options" -ForegroundColor DarkGray
Write-Host "1d) Build VT Fidelity Index  (fidelity-index.json + process-baseline.json)" -ForegroundColor DarkCyan
Write-Host "     -> Run after pulling new VT samples or updating APT differential files" -ForegroundColor DarkGray
Write-Host "1e) Pull VT YARA + Sigma Detections for a List of Hashes" -ForegroundColor DarkCyan
Write-Host "1f) Organize Local Baselines (move + dedupe across categories)" -ForegroundColor DarkCyan
Write-Host "1g) Dedup IOC List by SHA256 (normalize MD5/SHA1 -> SHA256 via VT)" -ForegroundColor DarkCyan
Write-Host "1h) Filter MalwareBazaar Hashes from IOC List" -ForegroundColor DarkCyan
Write-Host "1i) Build Behavioral Fingerprint Tables  (per-dataset known-good 'what is normal' reference)" -ForegroundColor DarkCyan
Write-Host "     -> Inverse-differential complement to the malware/APT Detailed_Report.html" -ForegroundColor DarkGray
Write-Host "     -> Generates Master_Intel.csv + Detailed_Report.html + behaviors_index.json per dataset" -ForegroundColor DarkGray
Write-Host ""

# -- GROUP 2: Static/Dynamic Differentials ------------------------------------
Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkCyan
Write-Host "  $([char]27)[4m|             Static/Dynamic Analysis            |$([char]27)[24m" -ForegroundColor DarkCyan
Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkCyan
Write-Host "2a) Malicious API / DLL Differentials Statistical Analysis Against Baseline" -ForegroundColor DarkCyan
Write-Host "2b) Specified API / DLL Differentials Statistical Analysis Against Baseline" -ForegroundColor DarkCyan
Write-Host ""

# -- GROUP 3: Reports ---------------------------------------------------------
Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor Gray
Write-Host "  $([char]27)[4m|                  Report Creation               |$([char]27)[24m" -ForegroundColor Gray
Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor Gray
Write-Host "3a) Iterate through APT Analyses and Create API Matrix" -ForegroundColor Gray
Write-Host ""

# -- GROUP 4: Firmware Extraction (NextGen NSRL Building) ---------------------
Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkYellow
Write-Host "  $([char]27)[4m|     Firmware Extraction (NextGen NSRL)        |$([char]27)[24m" -ForegroundColor DarkYellow
Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkYellow
Write-Host "4a) Eaton: Extract firmware bundles + build NSRL catalogs (submenu: pick one or ALL)" -ForegroundColor DarkYellow
Write-Host "4b) APC (Schneider): Extract firmware bundles + build NSRL catalogs (submenu: pick one or ALL)" -ForegroundColor DarkYellow
Write-Host "4c) Vertiv (Liebert/Avocent): Extract firmware bundles + build NSRL catalogs (submenu: pick one or ALL)" -ForegroundColor DarkYellow
Write-Host "4d) SEL (Schweitzer Engineering Laboratories): Extract firmware bundles + build NSRL catalogs (submenu: pick one or ALL)" -ForegroundColor DarkYellow
Write-Host "4e) Honeywell (Niagara / Experion / ControlEdge / HC900): Extract firmware bundles + build NSRL catalogs" -ForegroundColor DarkYellow
Write-Host "4f) Schneider Electric (Modicon / EcoStruxure / Magelis / Altivar): Extract firmware bundles + build NSRL catalogs" -ForegroundColor DarkYellow
Write-Host "4g) Rockwell (ControlLogix / CompactLogix / FactoryTalk / Studio 5000): Extract firmware bundles + build NSRL catalogs" -ForegroundColor DarkYellow
Write-Host "4h) Siemens (SIMATIC / SCALANCE / SINAMICS / RUGGEDCOM / TIA Portal): Extract firmware bundles + build NSRL catalogs" -ForegroundColor DarkYellow
Write-Host ""

# -- GROUP 5: OT Firmware Baselining ------------------------------------------
Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor Magenta
Write-Host "  $([char]27)[4m|        OT Firmware Baselining                  |$([char]27)[24m" -ForegroundColor Magenta
Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor Magenta
Write-Host "5a) OT: Baseline firmware catalogs (pull VT metadata) -- all vendors (Eaton + APC + Vertiv + ...)" -ForegroundColor Magenta
Write-Host "5b) OT: Submit 404'd firmware files to VT (opt-in upload) -- all vendors" -ForegroundColor Magenta
Write-Host "5z) Poll pending VT submissions (downloads metadata once VT analysis completes)" -ForegroundColor Magenta
Write-Host ""


$functionChoice = (Read-Host "Please enter an option").Trim().ToLowerInvariant()

# -- GROUP 1: Build Process Baseline ------------------------------------------
if ($functionChoice -eq "1a") {
    # Build OS list dynamically from NSRL CSV
    $nsrlCsvPath = "NSRL\nsrl_reduced.csv"
    $osList = @()
    if (Test-Path $nsrlCsvPath) {
        $osList = Import-Csv $nsrlCsvPath |
                  Where-Object { $_.OsName } |
                  Select-Object -ExpandProperty OsName |
                  Sort-Object -Unique
    } else {
        Write-Host "[WARN] $nsrlCsvPath not found - per-OS continue options unavailable." -ForegroundColor Yellow
    }

    # Toggleable per-run setting. Default OFF (i.e. INCLUDE behaviors for
    # SignedVerified samples) so the differential-analysis pipeline gets a
    # populated goodware-side G-count on the process / module / dll dims.
    # Default flipped 2026-07-23 to prevent the taskhostw/nss3/plugin-container
    # false-positive class. Toggle back on with `t` for a quota-constrained run.
    $skipSignedBeh = $false

    $subOptions = New-Object System.Collections.Generic.List[object]
    $i = 1
    foreach ($os in $osList) {
        $subOptions.Add([pscustomobject]@{ Num = $i; Label = "Continue $os"; Action = 'NSRLOs'; OsName = $os })
        $i++
    }
    $subOptions.Add([pscustomobject]@{ Num = $i; Label = "Continue ALL NSRL OSes"; Action = 'NSRLAll' }); $i++
    $subOptions.Add([pscustomobject]@{ Num = $i; Label = "Pull VT Metadata for ALL Master Intel Hashes"; Action = 'MasterIntelAll' }); $i++
    $subOptions.Add([pscustomobject]@{ Num = $i; Label = "Pull VT Metadata for Specific APT / Malware Family"; Action = 'MasterIntelByActor' }); $i++
    $subOptions.Add([pscustomobject]@{ Num = $i; Label = "Continue Local Baseline (procs + drivers)"; Action = 'LocalBaseline' }); $i++
    $subOptions.Add([pscustomobject]@{ Num = $i; Label = "Continue Malicious Baseline"; Action = 'Malicious' })

    $picked = $null
    while (-not $picked) {
        Write-Host ""
        Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkCyan
        Write-Host "  $([char]27)[4m|        1a) Baseline Procs with VirusTotal     |$([char]27)[24m" -ForegroundColor DarkCyan
        Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkCyan
        $stateLabel = if ($skipSignedBeh) { 'SKIP (saves quota; goodware behaviors starved)' } else { 'INCLUDE (default - full differential coverage)' }
        Write-Host ("  SignedVerified behaviors fetch: {0}" -f $stateLabel) -ForegroundColor DarkGray
        Write-Host ""
        foreach ($opt in $subOptions) {
            Write-Host ("  {0,2}) {1}" -f $opt.Num, $opt.Label) -ForegroundColor DarkCyan
        }
        Write-Host ("   t) Toggle SignedVerified behaviors fetch") -ForegroundColor DarkCyan
        Write-Host ""
        $subChoice = (Read-Host "Please enter a 1a sub-option").Trim()

        if ($subChoice -ieq 't') {
            $skipSignedBeh = -not $skipSignedBeh
            continue
        }

        $picked = $subOptions | Where-Object { $_.Num.ToString() -eq $subChoice } | Select-Object -First 1
        if (-not $picked) {
            Write-Host "Unknown sub-option: $subChoice" -ForegroundColor Red
            break
        }
    }

    if ($picked) {
        switch ($picked.Action) {
            'NSRLOs'             { Get-VTBaseline -Mode NSRLOs -OsFilter $picked.OsName -SkipBehaviorsForSignedVerified $skipSignedBeh }
            'NSRLAll'            { Get-VTBaseline -Mode NSRL                            -SkipBehaviorsForSignedVerified $skipSignedBeh }
            'MasterIntelAll'     { Get-AptMasterIntelVTAll }
            'MasterIntelByActor' { Get-AptMasterIntelVTByActor }
            'LocalBaseline'      { Get-VTBaseline -Mode LocalBaseline                   -SkipBehaviorsForSignedVerified $skipSignedBeh }
            'Malicious'          { Get-VTBaseline -Mode Malicious                       -SkipBehaviorsForSignedVerified $skipSignedBeh }
        }
    }
}
elseif ($functionChoice -eq "1b") {
    Write-Host ""
    Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkCyan
    Write-Host "  $([char]27)[4m|        1b) Harvest IOCs per Threat Actor      |$([char]27)[24m" -ForegroundColor DarkCyan
    Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkCyan
    Write-Host "   1) Harvest ALL actors + malware families in MasterConfig" -ForegroundColor DarkCyan
    Write-Host "   2) Harvest a SPECIFIC actor or malware family (prompted)"  -ForegroundColor DarkCyan
    Write-Host ""
    $bChoice = (Read-Host "Please enter a 1b sub-option").Trim()
    if ($bChoice -eq "1") {
        Get-ThreatActorIOCs
    } elseif ($bChoice -eq "2") {
        $actor = (Read-Host "Enter the actor/family Name (must match MasterConfig.Name exactly, e.g. UNC5792)").Trim()
        if ($actor) {
            Get-ThreatActorIOCs -SpecificActor $actor
        } else {
            Write-Host "[WARN] No actor entered - aborting 1b." -ForegroundColor Yellow
        }
    } else {
        Write-Host "[WARN] Unrecognized 1b sub-option - aborting." -ForegroundColor Yellow
    }
}
elseif ($functionChoice -eq "1d") {
    Build-VTFidelityIndex
}
elseif ($functionChoice -eq "1e") {
    $inputPath = Read-Host -Prompt "Path to hash list (TXT or CSV)"
    Get-VTDetectionsFromList -InputPath $inputPath
}
elseif ($functionChoice -eq "1f") {
    Move-OrganizeBaselines
}
elseif ($functionChoice -eq "1g") {
    Get-DedupHashesToSha256
}
elseif ($functionChoice -eq "1h") {
    Get-RemoveMalwareBazaarEntries
}
elseif ($functionChoice -eq "1i") {
    Build-BehavioralFingerprintTable
}

# -- GROUP 2: Static/Dynamic Differentials ------------------------------------
elseif ($functionChoice -eq "2a") {
    Get-MaliciousDifferentialAnalysis
}
elseif ($functionChoice -eq "2b") {
    Get-TargetedMalwareAnalysis
}

# -- GROUP 3: Reports ---------------------------------------------------------
elseif ($functionChoice -eq "3a") {
    New-ApiMatrixDashboard
}

# -- GROUP 4: Firmware Extraction (NextGen NSRL Building) ---------------------
elseif ($functionChoice -eq "4a") {
    # Auto-discover firmware ZIPs in firmware-staging\Eaton\**\raw\*.zip
    $stagingRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'firmware-staging\Eaton'
    $zipFiles = @()
    if (Test-Path $stagingRoot) {
        $zipFiles = @(Get-ChildItem -Path $stagingRoot -Recurse -File -Filter '*.zip' -ErrorAction SilentlyContinue |
                      Where-Object { $_.DirectoryName -match '[\\/]raw([\\/]|$)' } |
                      Sort-Object FullName)
    }
    if ($zipFiles.Count -eq 0) {
        Write-Host "[WARN] No firmware ZIPs found under $stagingRoot\**\raw\ - drop firmware ZIPs there first." -ForegroundColor Yellow
    } else {
        Write-Host ""
        Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkYellow
        Write-Host "  $([char]27)[4m|      4a) Eaton: Extract + build catalog       |$([char]27)[24m" -ForegroundColor DarkYellow
        Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkYellow
        for ($i = 0; $i -lt $zipFiles.Count; $i++) {
            # path: .../firmware-staging/Eaton/<Cat>/<Product>/raw/<zip>
            $rawDir   = $zipFiles[$i].DirectoryName
            $product  = Split-Path -Parent $rawDir | Split-Path -Leaf
            $category = Split-Path -Parent (Split-Path -Parent $rawDir) | Split-Path -Leaf
            Write-Host ("  {0,2}) {1}/{2}" -f ($i + 1), $category, $product) -ForegroundColor DarkYellow
        }
        Write-Host ("  {0,2}) ALL Eaton firmware ZIPs" -f ($zipFiles.Count + 1)) -ForegroundColor DarkYellow
        Write-Host ""
        $sub = (Read-Host "Please enter a 4a sub-option").Trim()

        $picks = @()
        if ($sub -eq ($zipFiles.Count + 1).ToString() -or $sub -ieq 'all') {
            $picks = $zipFiles
        } elseif ($sub -match '^\d+$' -and [int]$sub -ge 1 -and [int]$sub -le $zipFiles.Count) {
            $picks = @($zipFiles[[int]$sub - 1])
        } else {
            Write-Host "Unknown sub-option: $sub" -ForegroundColor Red
        }

        foreach ($zip in $picks) {
            $rawDir     = $zip.DirectoryName
            $productDir = Split-Path -Parent $rawDir
            $product    = Split-Path -Leaf $productDir
            $category   = Split-Path -Leaf (Split-Path -Parent $productDir)

            Write-Host ""
            Write-Host ("=== {0}/{1} ===" -f $category, $product) -ForegroundColor Cyan
            Write-Host ""
            Write-Host ">>> Step 1/2: Extracting firmware bundle" -ForegroundColor DarkYellow
            try {
                & "$PSScriptRoot\tools\Expand-EatonFirmware.ps1" -ZipPath $zip.FullName -Force
            } catch {
                Write-Host "[ERROR] Extraction failed: $($_.Exception.Message)" -ForegroundColor Red
                continue
            }

            # Build OsName from product folder name; try to enrich with a
            # version from any .sta in the extract.
            $extractedDir = Join-Path $productDir 'extracted'
            $verHint = ''
            $staFile = Get-ChildItem -LiteralPath $extractedDir -Recurse -File -Filter '*.sta' -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($staFile) {
                $vMatch = [regex]::Match($staFile.BaseName, 'v\d+[._]\d+[._]\d+')
                if ($vMatch.Success) {
                    $verHint = ' ' + ($vMatch.Value -replace '_', '.')
                }
            }
            $osName = "Eaton $product$verHint"

            Write-Host ""
            Write-Host ">>> Step 2/2: Building NSRL catalog (OsName='$osName')" -ForegroundColor DarkYellow
            $catalogPath = Join-Path $productDir 'catalog.csv'
            & "$PSScriptRoot\tools\Build-OsCatalog.ps1" -OsName $osName -SourceDir $extractedDir -OutputCsv $catalogPath
        }
    }
}
elseif ($functionChoice -eq "4b") {
    # Same flow as 4a but rooted at firmware-staging\APC. Expand-EatonFirmware
    # is vendor-agnostic (its Step 3 .sta handler just no-ops for non-Eaton);
    # version-hint regex is tuned for APC's apc_hw05_aos_704.bin / apcfwapp_v3.4.0.8.nmc3
    # naming instead of Eaton's vNN.NN.NNNN.
    $stagingRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'firmware-staging\APC'
    $zipFiles = @()
    if (Test-Path $stagingRoot) {
        $zipFiles = @(Get-ChildItem -Path $stagingRoot -Recurse -File -Filter '*.zip' -ErrorAction SilentlyContinue |
                      Where-Object { $_.DirectoryName -match '[\\/]raw([\\/]|$)' } |
                      Sort-Object FullName)
    }
    if ($zipFiles.Count -eq 0) {
        Write-Host "[WARN] No firmware ZIPs found under $stagingRoot\**\raw\ - drop firmware ZIPs there first." -ForegroundColor Yellow
        Write-Host "       Download URLs are listed in $stagingRoot\README.md" -ForegroundColor DarkGray
    } else {
        Write-Host ""
        Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkYellow
        Write-Host "  $([char]27)[4m|       4b) APC: Extract + build catalog        |$([char]27)[24m" -ForegroundColor DarkYellow
        Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkYellow
        for ($i = 0; $i -lt $zipFiles.Count; $i++) {
            $rawDir   = $zipFiles[$i].DirectoryName
            $product  = Split-Path -Parent $rawDir | Split-Path -Leaf
            $category = Split-Path -Parent (Split-Path -Parent $rawDir) | Split-Path -Leaf
            Write-Host ("  {0,2}) {1}/{2}" -f ($i + 1), $category, $product) -ForegroundColor DarkYellow
        }
        Write-Host ("  {0,2}) ALL APC firmware ZIPs" -f ($zipFiles.Count + 1)) -ForegroundColor DarkYellow
        Write-Host ""
        $sub = (Read-Host "Please enter a 4b sub-option").Trim()

        $picks = @()
        if ($sub -eq ($zipFiles.Count + 1).ToString() -or $sub -ieq 'all') {
            $picks = $zipFiles
        } elseif ($sub -match '^\d+$' -and [int]$sub -ge 1 -and [int]$sub -le $zipFiles.Count) {
            $picks = @($zipFiles[[int]$sub - 1])
        } else {
            Write-Host "Unknown sub-option: $sub" -ForegroundColor Red
        }

        foreach ($zip in $picks) {
            $rawDir     = $zip.DirectoryName
            $productDir = Split-Path -Parent $rawDir
            $product    = Split-Path -Leaf $productDir
            $category   = Split-Path -Leaf (Split-Path -Parent $productDir)

            Write-Host ""
            Write-Host ("=== {0}/{1} ===" -f $category, $product) -ForegroundColor Cyan
            Write-Host ""
            Write-Host ">>> Step 1/2: Extracting firmware bundle" -ForegroundColor DarkYellow
            try {
                & "$PSScriptRoot\tools\Expand-EatonFirmware.ps1" -ZipPath $zip.FullName -Force
            } catch {
                Write-Host "[ERROR] Extraction failed: $($_.Exception.Message)" -ForegroundColor Red
                continue
            }

            # Version hint for APC: apc_hw05_aos_704.bin -> v7.0.4
            #                       apcfwapp_v3.4.0.8.nmc3 -> v3.4.0.8
            #                       apc_hw05_rpdu2g_633.bin -> v6.3.3
            $extractedDir = Join-Path $productDir 'extracted'
            $verHint = ''
            $hintFile = @(Get-ChildItem -LiteralPath $extractedDir -Recurse -File -Include '*.bin','*.nmc3' -ErrorAction SilentlyContinue) | Select-Object -First 1
            if ($hintFile) {
                # First try _v3.4.0.8 / _v7.0.4 dotted style
                $vMatch = [regex]::Match($hintFile.BaseName, '_v(\d+\.\d+\.\d+(?:\.\d+)?)')
                if (-not $vMatch.Success) {
                    # Then try _704 / _633 compact style at end of basename
                    $vMatch = [regex]::Match($hintFile.BaseName, '_(\d{3,4})$')
                    if ($vMatch.Success) {
                        $compact = $vMatch.Groups[1].Value
                        # 704 -> 7.0.4; 633 -> 6.3.3; 4006 -> 4.0.0.6 (4 chars)
                        $dotted = ($compact.ToCharArray() | ForEach-Object { $_ }) -join '.'
                        $verHint = " v$dotted"
                    }
                } else {
                    $verHint = ' v' + $vMatch.Groups[1].Value
                }
            }
            $osName = "APC $product$verHint"

            Write-Host ""
            Write-Host ">>> Step 2/2: Building NSRL catalog (OsName='$osName')" -ForegroundColor DarkYellow
            $catalogPath = Join-Path $productDir 'catalog.csv'
            & "$PSScriptRoot\tools\Build-OsCatalog.ps1" -OsName $osName -SourceDir $extractedDir -OutputCsv $catalogPath
        }
    }
}
elseif ($functionChoice -eq "4c") {
    # Vertiv (Liebert / Avocent / Geist / NetSure). Same flow as 4a/4b.
    # Version-hint regex matches Vertiv firmware naming conventions:
    #   intelliSlot_unity_v8.4.1.0.bin        -> v8.4.1.0
    #   ACS8000-v2.28.4-firmware.tar           -> v2.28.4
    #   GXT5-3.7.0.upd                          -> v3.7.0
    #   liebert_psi5_2_1_0_4.bin                -> v2.1.0.4 (underscore variant)
    $stagingRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'firmware-staging\Vertiv'
    # Vertiv ships some firmware as raw .bin/.tar/.iso without a ZIP wrapper
    # (e.g. IntelliSlot Unity vertiv-is-unity_*.bin). Discover both.
    $vertivExts = '.zip','.bin','.tar','.iso','.img','.iwo','.upd','.uup'
    $zipFiles = @()
    if (Test-Path $stagingRoot) {
        $zipFiles = @(Get-ChildItem -Path $stagingRoot -Recurse -File -ErrorAction SilentlyContinue |
                      Where-Object {
                          ($_.DirectoryName -match '[\\/]raw([\\/]|$)') -and
                          ($_.Extension.ToLowerInvariant() -in $vertivExts)
                      } |
                      Sort-Object FullName)
    }
    if ($zipFiles.Count -eq 0) {
        Write-Host "[WARN] No firmware ZIPs found under $stagingRoot\**\raw\ - drop firmware ZIPs there first." -ForegroundColor Yellow
        Write-Host "       Download URLs are listed in $stagingRoot\README.md" -ForegroundColor DarkGray
    } else {
        Write-Host ""
        Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkYellow
        Write-Host "  $([char]27)[4m|       4c) Vertiv: Extract + build catalog     |$([char]27)[24m" -ForegroundColor DarkYellow
        Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkYellow
        for ($i = 0; $i -lt $zipFiles.Count; $i++) {
            $rawDir   = $zipFiles[$i].DirectoryName
            $product  = Split-Path -Parent $rawDir | Split-Path -Leaf
            $category = Split-Path -Parent (Split-Path -Parent $rawDir) | Split-Path -Leaf
            Write-Host ("  {0,2}) {1}/{2}" -f ($i + 1), $category, $product) -ForegroundColor DarkYellow
        }
        Write-Host ("  {0,2}) ALL Vertiv firmware ZIPs" -f ($zipFiles.Count + 1)) -ForegroundColor DarkYellow
        Write-Host ""
        $sub = (Read-Host "Please enter a 4c sub-option").Trim()

        $picks = @()
        if ($sub -eq ($zipFiles.Count + 1).ToString() -or $sub -ieq 'all') {
            $picks = $zipFiles
        } elseif ($sub -match '^\d+$' -and [int]$sub -ge 1 -and [int]$sub -le $zipFiles.Count) {
            $picks = @($zipFiles[[int]$sub - 1])
        } else {
            Write-Host "Unknown sub-option: $sub" -ForegroundColor Red
        }

        foreach ($zip in $picks) {
            $rawDir     = $zip.DirectoryName
            $productDir = Split-Path -Parent $rawDir
            $product    = Split-Path -Leaf $productDir
            $category   = Split-Path -Leaf (Split-Path -Parent $productDir)

            Write-Host ""
            Write-Host ("=== {0}/{1} ===" -f $category, $product) -ForegroundColor Cyan
            Write-Host ""
            Write-Host ">>> Step 1/2: Extracting firmware bundle" -ForegroundColor DarkYellow
            try {
                & "$PSScriptRoot\tools\Expand-EatonFirmware.ps1" -ZipPath $zip.FullName -Force
            } catch {
                Write-Host "[ERROR] Extraction failed: $($_.Exception.Message)" -ForegroundColor Red
                continue
            }

            # Version hint for Vertiv: try dotted vN.N.N first, then underscore-style
            $extractedDir = Join-Path $productDir 'extracted'
            $verHint = ''
            $hintFile = @(Get-ChildItem -LiteralPath $extractedDir -Recurse -File -Include '*.bin','*.upd','*.uup','*.iwo','*.tar','*.iso','*.img' -ErrorAction SilentlyContinue) | Select-Object -First 1
            if ($hintFile) {
                $vMatch = [regex]::Match($hintFile.BaseName, '[_-]v?(\d+\.\d+\.\d+(?:\.\d+)?)')
                if (-not $vMatch.Success) {
                    $vMatch = [regex]::Match($hintFile.BaseName, '_(\d+_\d+_\d+_\d+)$')
                    if ($vMatch.Success) {
                        $verHint = ' v' + ($vMatch.Groups[1].Value -replace '_','.')
                    }
                } else {
                    $verHint = ' v' + $vMatch.Groups[1].Value
                }
            }
            $osName = "Vertiv $product$verHint"

            Write-Host ""
            Write-Host ">>> Step 2/2: Building NSRL catalog (OsName='$osName')" -ForegroundColor DarkYellow
            $catalogPath = Join-Path $productDir 'catalog.csv'
            & "$PSScriptRoot\tools\Build-OsCatalog.ps1" -OsName $osName -SourceDir $extractedDir -OutputCsv $catalogPath
        }
    }
}
elseif ($functionChoice -eq "4d") {
    # SEL (Schweitzer Engineering Laboratories). Same flow as 4a/4b/4c.
    # Version-hint regex matches SEL's naming conventions:
    #   acSELerator_QuickSet_v7.1.4.0.exe       -> v7.1.4.0
    #   sel-3355-os-bundle-2.1.3.tar             -> v2.1.3
    #   acselerator_rtac_v3.16.0.exe             -> v3.16.0
    # Accepts raw .bin/.tar/.iso/.up3/.upd/.s19/.hex/.cid alongside .zip in raw/.
    $stagingRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'firmware-staging\SEL'
    $selExts = '.zip','.bin','.tar','.iso','.img','.up3','.upd','.s19','.hex','.cid','.exe'
    $zipFiles = @()
    if (Test-Path $stagingRoot) {
        $zipFiles = @(Get-ChildItem -Path $stagingRoot -Recurse -File -ErrorAction SilentlyContinue |
                      Where-Object {
                          ($_.DirectoryName -match '[\\/]raw([\\/]|$)') -and
                          ($_.Extension.ToLowerInvariant() -in $selExts)
                      } |
                      Sort-Object FullName)
    }
    if ($zipFiles.Count -eq 0) {
        Write-Host "[WARN] No firmware files found under $stagingRoot\**\raw\ - drop firmware ZIPs / installers / raw .bin there first." -ForegroundColor Yellow
        Write-Host "       Download URLs are listed in $stagingRoot\README.md" -ForegroundColor DarkGray
        Write-Host "       Note: most SEL relay firmware needs a mySchweitzer login; the public portal at" -ForegroundColor DarkGray
        Write-Host "       https://selinc.com/software/downloads/ has industrial-PC OS + admin tools." -ForegroundColor DarkGray
    } else {
        Write-Host ""
        Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkYellow
        Write-Host "  $([char]27)[4m|        4d) SEL: Extract + build catalog       |$([char]27)[24m" -ForegroundColor DarkYellow
        Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkYellow
        for ($i = 0; $i -lt $zipFiles.Count; $i++) {
            $rawDir   = $zipFiles[$i].DirectoryName
            $product  = Split-Path -Parent $rawDir | Split-Path -Leaf
            $category = Split-Path -Parent (Split-Path -Parent $rawDir) | Split-Path -Leaf
            Write-Host ("  {0,2}) {1}/{2}" -f ($i + 1), $category, $product) -ForegroundColor DarkYellow
        }
        Write-Host ("  {0,2}) ALL SEL firmware files" -f ($zipFiles.Count + 1)) -ForegroundColor DarkYellow
        Write-Host ""
        $sub = (Read-Host "Please enter a 4d sub-option").Trim()

        $picks = @()
        if ($sub -eq ($zipFiles.Count + 1).ToString() -or $sub -ieq 'all') {
            $picks = $zipFiles
        } elseif ($sub -match '^\d+$' -and [int]$sub -ge 1 -and [int]$sub -le $zipFiles.Count) {
            $picks = @($zipFiles[[int]$sub - 1])
        } else {
            Write-Host "Unknown sub-option: $sub" -ForegroundColor Red
        }

        foreach ($zip in $picks) {
            $rawDir     = $zip.DirectoryName
            $productDir = Split-Path -Parent $rawDir
            $product    = Split-Path -Leaf $productDir
            $category   = Split-Path -Leaf (Split-Path -Parent $productDir)

            Write-Host ""
            Write-Host ("=== {0}/{1} ===" -f $category, $product) -ForegroundColor Cyan
            Write-Host ""
            Write-Host ">>> Step 1/2: Extracting firmware bundle" -ForegroundColor DarkYellow
            try {
                & "$PSScriptRoot\tools\Expand-EatonFirmware.ps1" -ZipPath $zip.FullName -Force
            } catch {
                Write-Host "[ERROR] Extraction failed: $($_.Exception.Message)" -ForegroundColor Red
                continue
            }

            # Version hint for SEL: dotted vN.N.N(.N) anywhere in any .exe/.bin/.tar
            $extractedDir = Join-Path $productDir 'extracted'
            $verHint = ''
            $hintFile = @(Get-ChildItem -LiteralPath $extractedDir -Recurse -File -Include '*.exe','*.bin','*.tar','*.up3','*.upd','*.iso','*.img' -ErrorAction SilentlyContinue) | Select-Object -First 1
            if ($hintFile) {
                $vMatch = [regex]::Match($hintFile.BaseName, '[_-]v?(\d+\.\d+\.\d+(?:\.\d+)?)')
                if ($vMatch.Success) {
                    $verHint = ' v' + $vMatch.Groups[1].Value
                }
            }
            $osName = "SEL $product$verHint"

            Write-Host ""
            Write-Host ">>> Step 2/2: Building NSRL catalog (OsName='$osName')" -ForegroundColor DarkYellow
            $catalogPath = Join-Path $productDir 'catalog.csv'
            & "$PSScriptRoot\tools\Build-OsCatalog.ps1" -OsName $osName -SourceDir $extractedDir -OutputCsv $catalogPath
        }
    }
}
elseif ($functionChoice -in @("4e","4f","4g","4h")) {
    # 4e/4f/4g/4h: Honeywell / Schneider / Rockwell / Siemens.
    # Same flow as 4a/4b/4c/4d -- factored into one block since the
    # vendor-specific bits are just the staging-root path, the extension
    # allowlist, and a one-line OsName prefix. The extraction + catalog
    # build calls Expand-EatonFirmware.ps1 (vendor-neutral despite its
    # name) and Build-OsCatalog.ps1 unchanged.
    $vendorMap = @{
        '4e' = @{
            Name  = 'Honeywell'
            Dir   = 'Honeywell'
            Exts  = '.zip','.exe','.dist','.par','.cck','.dpe','.tar','.iso','.img'
            Note  = 'Honeywell Process Solutions / Niagara firmware needs partner login.'
        }
        '4f' = @{
            Name  = 'Schneider'
            Dir   = 'Schneider'
            Exts  = '.zip','.exe','.fwm','.cck','.eds','.lds','.tar','.iso','.img','.bin'
            Note  = 'Schneider gates downloads via secureidentity.schneider-electric.com (same wall as APC).'
        }
        '4g' = @{
            Name  = 'Rockwell'
            Dir   = 'Rockwell'
            Exts  = '.zip','.exe','.dmk','.nvs','.acd','.L5K','.L5X','.tar','.iso','.img','.bin'
            Note  = 'Rockwell PCDC requires a free MyRockwell account for firmware downloads.'
        }
        '4h' = @{
            Name  = 'Siemens'
            Dir   = 'Siemens'
            Exts  = '.zip','.exe','.upd','.zap','.s7p','.fwl','.fwu','.tar','.iso','.img','.bin'
            Note  = 'Siemens Industry Online Support requires a free PIA account.'
        }
    }
    $cfg = $vendorMap[$functionChoice]
    $stagingRoot = Join-Path (Split-Path $PSScriptRoot -Parent) "firmware-staging\$($cfg.Dir)"
    $vendorExts = $cfg.Exts
    $zipFiles = @()
    if (Test-Path $stagingRoot) {
        $zipFiles = @(Get-ChildItem -Path $stagingRoot -Recurse -File -ErrorAction SilentlyContinue |
                      Where-Object {
                          ($_.DirectoryName -match '[\\/]raw([\\/]|$)') -and
                          ($_.Extension.ToLowerInvariant() -in $vendorExts)
                      } |
                      Sort-Object FullName)
    }
    if ($zipFiles.Count -eq 0) {
        Write-Host "[WARN] No firmware files found under $stagingRoot\**\raw\ - drop firmware files there first." -ForegroundColor Yellow
        Write-Host "       Download URLs are listed in $stagingRoot\README.md" -ForegroundColor DarkGray
        Write-Host "       Note: $($cfg.Note)" -ForegroundColor DarkGray
    } else {
        Write-Host ""
        Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkYellow
        Write-Host ("  $([char]27)[4m|     {0}) {1}: Extract + build catalog     |$([char]27)[24m" -f $functionChoice, $cfg.Name) -ForegroundColor DarkYellow
        Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkYellow
        for ($i = 0; $i -lt $zipFiles.Count; $i++) {
            $rawDir   = $zipFiles[$i].DirectoryName
            $product  = Split-Path -Parent $rawDir | Split-Path -Leaf
            $category = Split-Path -Parent (Split-Path -Parent $rawDir) | Split-Path -Leaf
            Write-Host ("  {0,2}) {1}/{2}" -f ($i + 1), $category, $product) -ForegroundColor DarkYellow
        }
        Write-Host ("  {0,2}) ALL $($cfg.Name) firmware files" -f ($zipFiles.Count + 1)) -ForegroundColor DarkYellow
        Write-Host ""
        $sub = (Read-Host "Please enter a $functionChoice sub-option").Trim()

        $picks = @()
        if ($sub -eq ($zipFiles.Count + 1).ToString() -or $sub -ieq 'all') {
            $picks = $zipFiles
        } elseif ($sub -match '^\d+$' -and [int]$sub -ge 1 -and [int]$sub -le $zipFiles.Count) {
            $picks = @($zipFiles[[int]$sub - 1])
        } else {
            Write-Host "Unknown sub-option: $sub" -ForegroundColor Red
        }

        foreach ($zip in $picks) {
            $rawDir     = $zip.DirectoryName
            $productDir = Split-Path -Parent $rawDir
            $product    = Split-Path -Leaf $productDir
            $category   = Split-Path -Leaf (Split-Path -Parent $productDir)

            Write-Host ""
            Write-Host ("=== {0}/{1} ===" -f $category, $product) -ForegroundColor Cyan
            Write-Host ""
            Write-Host ">>> Step 1/2: Extracting firmware bundle" -ForegroundColor DarkYellow
            try {
                & "$PSScriptRoot\tools\Expand-EatonFirmware.ps1" -ZipPath $zip.FullName -Force
            } catch {
                Write-Host "[ERROR] Extraction failed: $($_.Exception.Message)" -ForegroundColor Red
                continue
            }

            # Dotted-version regex covers Honeywell / Schneider / Rockwell / Siemens
            # firmware naming uniformly (e.g. tia_portal_v19.0.exe, m580_2.10.exe,
            # PowerFlex755_v32.001.exe, niagara_4.11.exe).
            $extractedDir = Join-Path $productDir 'extracted'
            $verHint = ''
            $hintFile = @(Get-ChildItem -LiteralPath $extractedDir -Recurse -File -Include '*.exe','*.bin','*.tar','*.upd','*.iso','*.img','*.dmk','*.fwm','*.dist','*.par','*.zap' -ErrorAction SilentlyContinue) | Select-Object -First 1
            if ($hintFile) {
                $vMatch = [regex]::Match($hintFile.BaseName, '[_-]v?(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)')
                if ($vMatch.Success) {
                    $verHint = ' v' + $vMatch.Groups[1].Value
                }
            }
            $osName = "$($cfg.Name) $product$verHint"

            Write-Host ""
            Write-Host ">>> Step 2/2: Building NSRL catalog (OsName='$osName')" -ForegroundColor DarkYellow
            $catalogPath = Join-Path $productDir 'catalog.csv'
            & "$PSScriptRoot\tools\Build-OsCatalog.ps1" -OsName $osName -SourceDir $extractedDir -OutputCsv $catalogPath
        }
    }
}

# -- GROUP 5: OT Firmware Baselining ------------------------------------------
elseif ($functionChoice -eq "5a" -or $functionChoice -eq "5b") {
    # Auto-discover per-product catalogs under firmware-staging\<Vendor>\.
    # Vendor-neutral: any first-level directory under firmware-staging\
    # is treated as a vendor, and catalog.csv files anywhere beneath it
    # are processed. Get-OtBaseline / Submit-OtFilesNotInVT already
    # derive Vendor/Category/Product from the catalog's path, so each
    # row stays cleanly partitioned in output-baseline/<main|behaviors>/OT/<Vendor>/.
    $stagingRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'firmware-staging'
    $catalogs = @()
    if (Test-Path $stagingRoot) {
        $catalogs = @(Get-ChildItem -Path $stagingRoot -Recurse -Filter 'catalog.csv' -File -ErrorAction SilentlyContinue |
                      Sort-Object FullName)
    }
    if ($catalogs.Count -eq 0) {
        Write-Host "[WARN] No catalog.csv files found under $stagingRoot - run option 4a / 4b / 4c first." -ForegroundColor Yellow
    } else {
        $verb = if ($functionChoice -eq "5a") { 'Baseline' } else { "Submit 404'd files for" }
        # Group catalogs by vendor for clearer display
        $byVendor = @{}
        foreach ($c in $catalogs) {
            $parts   = $c.FullName -split '[\\/]'
            $idx     = [array]::IndexOf($parts, 'firmware-staging')
            $vendor  = if ($idx -ge 0 -and $parts.Count -gt $idx + 1) { $parts[$idx + 1] } else { '?' }
            if (-not $byVendor.ContainsKey($vendor)) { $byVendor[$vendor] = @() }
            $byVendor[$vendor] += $c
        }
        Write-Host ""
        Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor Magenta
        Write-Host ("  $([char]27)[4m|        {0} {1}     |$([char]27)[24m" -f $functionChoice.ToUpperInvariant(), $verb) -ForegroundColor Magenta
        Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor Magenta
        $i = 0
        $vendorCount = 0
        foreach ($vendor in $byVendor.Keys | Sort-Object) {
            $vendorCount++
            Write-Host ("  --- {0} ({1} catalog(s)) ---" -f $vendor, $byVendor[$vendor].Count) -ForegroundColor DarkMagenta
            foreach ($c in $byVendor[$vendor]) {
                $i++
                $product  = Split-Path -Parent $c.FullName | Split-Path -Leaf
                $category = Split-Path -Parent $c.FullName | Split-Path -Parent | Split-Path -Leaf
                Write-Host ("  {0,3}) {1} {2}/{3}" -f $i, $verb, $category, $product) -ForegroundColor Magenta
            }
        }
        $allOpt = $catalogs.Count + 1
        Write-Host ("  {0,3}) {1} ALL OT catalogs across all {2} vendor(s)" -f $allOpt, $verb, $vendorCount) -ForegroundColor Magenta
        # Per-vendor "all" options
        $vendorList = @($byVendor.Keys | Sort-Object)
        for ($v = 0; $v -lt $vendorList.Count; $v++) {
            $vName = $vendorList[$v]
            $optNum = $allOpt + $v + 1
            Write-Host ("  {0,3}) {1} ALL {2} catalogs only" -f $optNum, $verb, $vName) -ForegroundColor Magenta
        }
        Write-Host ""
        $sub = (Read-Host "Please enter a sub-option").Trim()

        $picks = @()
        if ($sub -eq $allOpt.ToString() -or $sub -ieq 'all') {
            $picks = $catalogs
        } elseif ($sub -match '^\d+$' -and [int]$sub -ge 1 -and [int]$sub -le $catalogs.Count) {
            $picks = @($catalogs[[int]$sub - 1])
        } elseif ($sub -match '^\d+$' -and [int]$sub -gt $allOpt -and [int]$sub -le ($allOpt + $vendorList.Count)) {
            $vIdx = [int]$sub - $allOpt - 1
            $picks = $byVendor[$vendorList[$vIdx]]
        } else {
            Write-Host "Unknown sub-option: $sub" -ForegroundColor Red
        }

        foreach ($cat in $picks) {
            if ($functionChoice -eq "5a") {
                Get-OtBaseline -CatalogCsv $cat.FullName
            } else {
                Submit-OtFilesNotInVT -CatalogCsv $cat.FullName
            }
        }
    }
}
elseif ($functionChoice -eq "5z") {
    Sync-VTPendingSubmissions
}

else {
    Write-Host "Unknown option: $functionChoice" -ForegroundColor Red
}

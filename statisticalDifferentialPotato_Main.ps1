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
Import-Module -Name ".\agentic\Build-VTFidelityIndex.psm1"
Import-Module -Name ".\purpleTeaming\GetVTDetectionsFromList.psm1"
Import-Module -Name ".\baseline\OrganizeBaselines.psm1"
Import-Module -Name ".\purpleTeaming\GetDedupHashesToSha256.psm1"
Import-Module -Name ".\purpleTeaming\GetRemoveMalwareBazaarEntries.psm1"

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
Write-Host "1d) Build VT Fidelity Index  (fidelity-index.json + process-baseline.json)" -ForegroundColor DarkCyan
Write-Host "     -> Run after pulling new VT samples or updating APT differential files" -ForegroundColor DarkGray
Write-Host "1e) Pull VT YARA + Sigma Detections for a List of Hashes" -ForegroundColor DarkCyan
Write-Host "1f) Organize Local Baselines (move + dedupe across categories)" -ForegroundColor DarkCyan
Write-Host "1g) Dedup IOC List by SHA256 (normalize MD5/SHA1 -> SHA256 via VT)" -ForegroundColor DarkCyan
Write-Host "1h) Filter MalwareBazaar Hashes from IOC List" -ForegroundColor DarkCyan
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

    Write-Host ""
    Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkCyan
    Write-Host "  $([char]27)[4m|        1a) Baseline Procs with VirusTotal     |$([char]27)[24m" -ForegroundColor DarkCyan
    Write-Host "  $([char]27)[4m+----------------------------------------------+$([char]27)[24m" -ForegroundColor DarkCyan

    $subOptions = New-Object System.Collections.Generic.List[object]
    $i = 1
    foreach ($os in $osList) {
        $subOptions.Add([pscustomobject]@{ Num = $i; Label = "Continue $os"; Action = 'NSRLOs'; OsName = $os })
        Write-Host ("  {0,2}) Continue {1}" -f $i, $os) -ForegroundColor DarkCyan
        $i++
    }
    $subOptions.Add([pscustomobject]@{ Num = $i; Label = "Continue ALL NSRL OSes"; Action = 'NSRLAll' })
    Write-Host ("  {0,2}) Continue ALL NSRL OSes" -f $i) -ForegroundColor DarkCyan; $i++

    $subOptions.Add([pscustomobject]@{ Num = $i; Label = "Pull VT Metadata for ALL Master Intel Hashes"; Action = 'MasterIntelAll' })
    Write-Host ("  {0,2}) Pull VT Metadata for ALL Master Intel Hashes" -f $i) -ForegroundColor DarkCyan; $i++

    $subOptions.Add([pscustomobject]@{ Num = $i; Label = "Pull VT Metadata for Specific APT / Malware Family"; Action = 'MasterIntelByActor' })
    Write-Host ("  {0,2}) Pull VT Metadata for Specific APT / Malware Family" -f $i) -ForegroundColor DarkCyan; $i++

    $subOptions.Add([pscustomobject]@{ Num = $i; Label = "Continue Local Baseline (procs + drivers)"; Action = 'LocalBaseline' })
    Write-Host ("  {0,2}) Continue Local Baseline (procs + drivers)" -f $i) -ForegroundColor DarkCyan; $i++

    $subOptions.Add([pscustomobject]@{ Num = $i; Label = "Continue Malicious Baseline"; Action = 'Malicious' })
    Write-Host ("  {0,2}) Continue Malicious Baseline" -f $i) -ForegroundColor DarkCyan

    Write-Host ""
    $subChoice = (Read-Host "Please enter a 1a sub-option").Trim()
    $picked = $subOptions | Where-Object { $_.Num.ToString() -eq $subChoice } | Select-Object -First 1

    if (-not $picked) {
        Write-Host "Unknown sub-option: $subChoice" -ForegroundColor Red
    } else {
        switch ($picked.Action) {
            'NSRLOs'             { Get-VTBaseline -Mode NSRLOs -OsFilter $picked.OsName }
            'NSRLAll'            { Get-VTBaseline -Mode NSRL }
            'MasterIntelAll'     { Get-AptMasterIntelVTAll }
            'MasterIntelByActor' { Get-AptMasterIntelVTByActor }
            'LocalBaseline'      { Get-VTBaseline -Mode LocalBaseline }
            'Malicious'          { Get-VTBaseline -Mode Malicious }
        }
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

else {
    Write-Host "Unknown option: $functionChoice" -ForegroundColor Red
}

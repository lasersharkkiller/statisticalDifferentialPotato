#Requires -Version 5.1
<#
.SYNOPSIS
    Install a common-software package (winget), hash every binary in its
    install directory, and append the results to NSRL\nsrl_common_software.csv.

.DESCRIPTION
    Fills the known baseline-coverage gap that causes legitimate Firefox / NSS
    / VCRedist / etc. artifacts to score UNIQUE-TO-MALWARE (S=100, U=true) in
    the fidelity index. Each hash written here is picked up by VTBaseline.psm1
    (which now enumerates every CSV under NSRL\) and routed as goodware.

    Workflow:
      1) Optionally runs `winget install --id <PackageId>` (interactive confirm).
      2) Walks the install directory, computes SHA-256 for every .exe/.dll/.sys/.ocx.
      3) Appends {Hash, FileName, OsName} rows to NSRL\nsrl_common_software.csv,
         deduplicating against what's already there.
      4) Prints a summary and next-steps reminder.

    NEXT STEPS (out of scope for this script - user runs these):
      Import-Module .\baseline\VTBaseline.psm1
      Get-VTBaseline -Mode NSRL -OsFilter 'Windows 11' -SkipBehaviorsForSignedVerified:$false
      Import-Module .\agentic\Build-VTFidelityIndex.psm1
      Build-VTFidelityIndex

.PARAMETER PackageId
    winget package ID. Presets known:
      Mozilla.Firefox.ESR, Mozilla.Thunderbird, Google.Chrome,
      Microsoft.VCRedist.2015+.x64, Microsoft.VCRedist.2015+.x86,
      Microsoft.DotNet.SDK.9, Microsoft.VisualStudio.2022.BuildTools,
      Notepad++.Notepad++, VideoLAN.VLC, 7zip.7zip, PuTTY.PuTTY,
      WinSCP.WinSCP, Git.Git

.PARAMETER InstallPath
    Override the install directory to hash. If omitted, uses a preset for
    known package IDs, or fails with a message asking the user to supply it.

.PARAMETER SkipInstall
    Skip the `winget install` step. Use when the package is already installed
    or when hashing an existing install (e.g. VCRedist post-install).

.PARAMETER OsName
    OsName value written to the CSV. Default: 'Windows 11'. Must match a value
    handled by Get-NSRLOsSlug in VTBaseline.psm1.

.PARAMETER CsvPath
    Destination CSV. Default: NSRL\nsrl_common_software.csv relative to repo root.

.PARAMETER Force
    Skip the interactive winget-install confirmation prompt.

.EXAMPLE
    .\tools\Import-CommonSoftwareCorpus.ps1 -PackageId Mozilla.Firefox.ESR
    Prompts for winget install, then hashes C:\Program Files\Mozilla Firefox.

.EXAMPLE
    .\tools\Import-CommonSoftwareCorpus.ps1 -PackageId Microsoft.VCRedist.2015+.x64 -SkipInstall
    Skips install (VCRedist has no persistent install-dir); hashes both
    C:\Windows\System32\api-ms-* and C:\Windows\System32\vcruntime*.

.EXAMPLE
    .\tools\Import-CommonSoftwareCorpus.ps1 -PackageId 'Custom.LOBApp' -InstallPath 'D:\Apps\Foo'
    Hash-only mode; ignores winget, just walks D:\Apps\Foo.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PackageId,
    [string]$InstallPath,
    [switch]$SkipInstall,
    [string]$OsName = 'Windows 11',
    [string]$CsvPath,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# ---------- Preset resolution --------------------------------------------------
$Presets = @{
    'Mozilla.Firefox.ESR'                   = @('C:\Program Files\Mozilla Firefox')
    'Mozilla.Thunderbird'                   = @('C:\Program Files\Mozilla Thunderbird')
    'Google.Chrome'                         = @('C:\Program Files\Google\Chrome\Application')
    # VCRedist is a redistributable — it drops files into System32/SysWOW64.
    # No persistent install dir; hash the delivered surface.
    'Microsoft.VCRedist.2015+.x64'          = @('C:\Windows\System32\api-ms-*', 'C:\Windows\System32\vcruntime*', 'C:\Windows\System32\msvcp*')
    'Microsoft.VCRedist.2015+.x86'          = @('C:\Windows\SysWOW64\api-ms-*', 'C:\Windows\SysWOW64\vcruntime*', 'C:\Windows\SysWOW64\msvcp*')
    'Microsoft.DotNet.SDK.9'                = @('C:\Program Files\dotnet')
    'Microsoft.VisualStudio.2022.BuildTools' = @('C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools')
    'Notepad++.Notepad++'                   = @('C:\Program Files\Notepad++')
    'VideoLAN.VLC'                          = @('C:\Program Files\VideoLAN\VLC')
    '7zip.7zip'                             = @('C:\Program Files\7-Zip')
    'PuTTY.PuTTY'                           = @('C:\Program Files\PuTTY')
    'WinSCP.WinSCP'                         = @('C:\Program Files (x86)\WinSCP')
    'Git.Git'                               = @('C:\Program Files\Git')
}

# Resolve destination CSV relative to repo root (../NSRL from this script's dir)
if (-not $CsvPath) {
    $CsvPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'NSRL\nsrl_common_software.csv'
}
if (-not (Test-Path -LiteralPath $CsvPath)) {
    Write-Host "Creating CSV: $CsvPath" -ForegroundColor DarkCyan
    'Hash,FileName,OsName' | Set-Content -LiteralPath $CsvPath -Encoding UTF8
}

# Resolve install paths
$scanPaths = @()
if ($InstallPath) {
    $scanPaths = @($InstallPath)
} elseif ($Presets.ContainsKey($PackageId)) {
    $scanPaths = $Presets[$PackageId]
} else {
    Write-Error "Unknown PackageId '$PackageId' and no -InstallPath given. Add a preset or pass -InstallPath."
    return
}

# ---------- Interactive install confirmation -----------------------------------
if (-not $SkipInstall) {
    Write-Host ""
    Write-Host "About to run:" -ForegroundColor Yellow
    Write-Host "  winget install --id $PackageId --silent --accept-package-agreements --accept-source-agreements" -ForegroundColor Cyan
    Write-Host ""
    if (-not $Force) {
        $confirm = Read-Host 'Proceed? (y/N)'
        if ($confirm -notmatch '^[yY]') {
            Write-Host "Aborted by user. Use -SkipInstall to hash an existing install." -ForegroundColor Yellow
            return
        }
    }
    Write-Host "Running winget install..." -ForegroundColor DarkCyan
    $wingetArgs = @('install', '--id', $PackageId, '--silent', '--accept-package-agreements', '--accept-source-agreements')
    & winget @wingetArgs
    if ($LASTEXITCODE -ne 0) {
        # Exit code 0 = success; -1978335189 = already installed (also OK for our purposes)
        if ($LASTEXITCODE -eq -1978335189) {
            Write-Host "Already installed (winget exit -1978335189). Continuing to hash step." -ForegroundColor DarkGray
        } else {
            Write-Warning "winget install returned exit code $LASTEXITCODE. Continuing to hash step anyway."
        }
    }
}

# ---------- Hash walk ----------------------------------------------------------
Write-Host ""
Write-Host "Hashing binaries under:" -ForegroundColor DarkCyan
foreach ($p in $scanPaths) { Write-Host "  $p" -ForegroundColor DarkGray }

# Load existing CSV into a lookup so we don't append dupes.
$existing = @{}
try {
    Import-Csv -LiteralPath $CsvPath | ForEach-Object {
        if ($_.Hash) { $existing[$_.Hash.ToLowerInvariant()] = $true }
    }
} catch {
    Write-Warning "Could not read $CsvPath for dedup - proceeding without dedup."
}

$rows        = [System.Collections.Generic.List[object]]::new()
$scannedFiles = 0
$dupes        = 0
foreach ($p in $scanPaths) {
    # Support both directory paths and wildcard file patterns (VCRedist uses wildcards)
    if ($p -match '[\*\?]') {
        $files = @(Get-ChildItem -Path $p -File -ErrorAction SilentlyContinue)
    } elseif (Test-Path -LiteralPath $p) {
        $files = @(Get-ChildItem -LiteralPath $p -Recurse -File -Include '*.exe','*.dll','*.sys','*.ocx' -ErrorAction SilentlyContinue)
    } else {
        Write-Warning "Path not found: $p (skipping)"
        continue
    }
    foreach ($f in $files) {
        $scannedFiles++
        try {
            $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
            if ($existing.ContainsKey($hash)) { $dupes++; continue }
            $existing[$hash] = $true
            $rows.Add([PSCustomObject]@{
                Hash     = $hash
                FileName = $f.Name
                OsName   = $OsName
            })
        } catch {
            Write-Warning "Hash failed for $($f.FullName): $($_.Exception.Message)"
        }
    }
}

# ---------- Append -------------------------------------------------------------
if ($rows.Count -gt 0) {
    # Append rows without rewriting existing content. Use manual concat to
    # preserve the file's existing header + rows.
    $lines = foreach ($r in $rows) {
        # CSV-safe filename: quote if it contains a comma / quote.
        $fn = $r.FileName
        if ($fn -match '[",]') { $fn = '"' + ($fn -replace '"','""') + '"' }
        $os = $r.OsName
        if ($os -match '[",]') { $os = '"' + ($os -replace '"','""') + '"' }
        "$($r.Hash),$fn,$os"
    }
    Add-Content -LiteralPath $CsvPath -Value $lines -Encoding UTF8
}

# ---------- Summary ------------------------------------------------------------
Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host ("Package         : {0}" -f $PackageId)
Write-Host ("OsName          : {0}" -f $OsName)
Write-Host ("Files scanned   : {0,6}" -f $scannedFiles)
Write-Host ("Duplicates      : {0,6}" -f $dupes)
Write-Host ("New rows added  : {0,6}" -f $rows.Count)
Write-Host ("Destination CSV : {0}" -f $CsvPath)
Write-Host ""

if ($rows.Count -gt 0) {
    Write-Host "Next steps to actually seed the goodware baseline with these hashes:" -ForegroundColor Yellow
    Write-Host "  1. Import-Module .\baseline\VTBaseline.psm1"
    Write-Host "  2. Get-VTBaseline -Mode NSRL -OsFilter '$OsName' -SkipBehaviorsForSignedVerified:`$false"
    Write-Host "     (behaviors for signed-verified files are SKIPPED by default - flip to `$false or"
    Write-Host "      the pilot is a no-op for the process/module/dll dims we actually need to fix)"
    Write-Host "  3. Import-Module .\agentic\Build-VTFidelityIndex.psm1"
    Write-Host "  4. Build-VTFidelityIndex   # ~10-15 min; emits Score100 + calibration_passed clears"
    Write-Host "  5. .\tools\Measure-FidelityFPs.ps1   # confirm FP-kill delta"
} else {
    Write-Host "No new hashes added - CSV was already up to date for this package." -ForegroundColor DarkGray
}

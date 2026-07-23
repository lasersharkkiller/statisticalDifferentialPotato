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
      Get-VTBaseline -Mode NSRL -OsFilter 'Windows 11'
      Import-Module .\agentic\Build-VTFidelityIndex.psm1
      Build-VTFidelityIndex

    NOTE: as of 2026-07-23 SkipBehaviorsForSignedVerified defaults to $false
    (INCLUDE behaviors). Pass -SkipBehaviorsForSignedVerified:$true only if
    you need to opt out for a quota-constrained run.

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
    OsName value written to the CSV. If omitted, auto-detected by matching the
    running OS against distinct OsName values in NSRL\nsrl_reduced.csv (e.g.
    'Windows 11 Version 25H2 X64' on a Win 11 host, 'Ubuntu 24.04 LTS' on
    Noble). Warns (does not block) if you pass an OsName not present in the
    NSRL corpus.

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
    # OsName written to the CSV. If omitted, auto-detected from the running
    # OS + matched against distinct OsName values in NSRL\nsrl_reduced.csv.
    # Must match exactly what nsrl_reduced.csv uses so Get-VTBaseline -OsFilter
    # can route the new rows through the same per-OS bucket as the NIST base.
    [string]$OsName,
    [string]$CsvPath,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# ---------- OsName auto-detect helper -----------------------------------------
function Resolve-DefaultOsName {
    <#
    .SYNOPSIS
        Read NSRL\nsrl_reduced.csv, detect the running OS, return the matching
        OsName value (exact string as written in the NSRL corpus).
    .DESCRIPTION
        NSRL OsName strings are precise ('Windows 11 Version 25H2 X64',
        'Windows Server 2025', 'Ubuntu 24.04 LTS', 'Debian 13'). A user
        passing a shorter form like 'Windows 11' would fail the -OsFilter
        match in Get-VTBaseline. This helper picks the closest match by:
          1. Enumerate distinct OsName values in nsrl_reduced.csv.
          2. Detect current OS via Win32_OperatingSystem (Windows) or
             /etc/os-release (Linux).
          3. Score each OsName against the detected product string; return
             the top-scoring match, or $null if nothing matches confidently.
        Returns $null on any failure - caller must fall back to explicit
        -OsName or fail cleanly.
    .PARAMETER RepoRoot
        Repo root (contains NSRL\ subfolder).
    #>
    [OutputType([string])]
    param([string]$RepoRoot)

    $csv = Join-Path $RepoRoot 'NSRL\nsrl_reduced.csv'
    if (-not (Test-Path -LiteralPath $csv)) { return $null }

    $osNames = @()
    try {
        $osNames = @(Import-Csv -LiteralPath $csv |
                     Where-Object { $_.OsName } |
                     Select-Object -ExpandProperty OsName |
                     Sort-Object -Unique)
    } catch { return $null }
    if ($osNames.Count -eq 0) { return $null }

    # Detect current-OS caption. Windows path first (most common). PS 6+
    # cross-platform Linux fallback via /etc/os-release. macOS is unsupported
    # (no macOS OsName in NSRL corpus).
    $productCaption = $null
    if ($env:OS -eq 'Windows_NT' -or ($PSVersionTable.Platform -in @($null,'Win32NT'))) {
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $productCaption = "$($os.Caption)"
        } catch {
            # Registry fallback. NOTE: HKLM ProductName has a decade-old bug
            # where Windows 11 still reads "Windows 10 Pro" through at least
            # build 26200. If CurrentBuild >= 22000 we synthesize a Windows 11
            # caption from EditionID; if CurrentBuild >= 10240 we synthesize
            # a Windows 10 caption; otherwise fall back to raw ProductName.
            try {
                $reg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
                $build = 0
                if ($reg.PSObject.Properties['CurrentBuild']) {
                    [int]::TryParse("$($reg.CurrentBuild)", [ref]$build) | Out-Null
                }
                $edition = if ($reg.PSObject.Properties['EditionID']) { "$($reg.EditionID)" } else { '' }
                if ($build -ge 22000) {
                    $productCaption = "Microsoft Windows 11 $edition".Trim()
                } elseif ($build -ge 10240) {
                    $productCaption = "Microsoft Windows 10 $edition".Trim()
                } else {
                    $productCaption = "$($reg.ProductName)"
                }
            } catch { return $null }
        }
    } elseif (Test-Path '/etc/os-release') {
        $osrel = Get-Content '/etc/os-release' -Raw -ErrorAction SilentlyContinue
        if ($osrel -match '(?m)^PRETTY_NAME="?([^"\r\n]+)') { $productCaption = $Matches[1] }
        elseif ($osrel -match '(?m)^NAME="?([^"\r\n]+)') { $productCaption = $Matches[1] }
    }

    if (-not $productCaption) { return $null }

    # Match by family + version. Score each NSRL OsName by which family it
    # matches; break ties by preferring the version-specific entry over a
    # generic one (e.g. 'Windows 11 Version 25H2 X64' beats 'Windows 11').
    $family = switch -Regex ($productCaption) {
        'Windows Server 2025'   { 'Windows Server 2025';   break }
        'Windows Server 2022'   { 'Windows Server 2022';   break }
        'Windows Server 2019'   { 'Windows Server 2019';   break }
        'Windows 11'            { 'Windows 11';            break }
        'Windows 10'            { 'Windows 10';            break }
        'Ubuntu 24\.\d+'        { 'Ubuntu 24';             break }
        'Ubuntu 22\.\d+'        { 'Ubuntu 22';             break }
        '^Debian.*13'           { 'Debian 13';             break }
        '^Debian.*12'           { 'Debian 12';             break }
        default                 { $null }
    }
    if (-not $family) { return $null }

    $osMatches = @($osNames | Where-Object { $_ -match [regex]::Escape($family) })
    if ($osMatches.Count -eq 0) { return $null }
    if ($osMatches.Count -eq 1) { return $osMatches[0] }
    # Prefer the LONGEST matching string as the most-specific version variant
    # (e.g. 'Windows 11 Version 25H2 X64' > 'Windows 11').
    return ($osMatches | Sort-Object Length -Descending | Select-Object -First 1)
}

# ---------- Resolve OsName ----------------------------------------------------
# Locate the script directory. $PSScriptRoot is unset when the file is
# dot-sourced from a REPL or executed via Invoke-Expression; fall back to
# $PSCommandPath's parent, then hard-fail with an actionable message rather
# than letting Split-Path throw a confusing 'null Path' error.
$scriptDir = if ($PSScriptRoot) {
    $PSScriptRoot
} elseif ($PSCommandPath) {
    Split-Path -Parent $PSCommandPath
} else {
    $null
}
if (-not $scriptDir) {
    throw "Cannot locate the script directory. Run this file as a .ps1 script (not dot-sourced from a REPL or Invoke-Expression'd)."
}
$RepoRoot = Split-Path -Parent $scriptDir

if (-not $OsName) {
    $OsName = Resolve-DefaultOsName -RepoRoot $RepoRoot
    if ($OsName) {
        Write-Host ("  [auto] Detected OsName: {0}" -f $OsName) -ForegroundColor DarkGreen
    } else {
        # Collect diagnostic context so the operator can see WHY auto-detect
        # failed (unrecognized caption vs. no NSRL entry vs. CIM/registry
        # both threw). Cheap - re-runs detection just to grab the caption.
        $diag = @{ caption = '(unavailable)'; nsrlOsList = '(unreadable)' }
        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $diag.caption = "$($os.Caption)"
        } catch { }
        try {
            $diag.nsrlOsList = (Import-Csv (Join-Path $RepoRoot 'NSRL\nsrl_reduced.csv') |
                                Where-Object OsName |
                                Select-Object -ExpandProperty OsName |
                                Sort-Object -Unique) -join [Environment]::NewLine
        } catch { }
        Write-Error @"
Could not auto-detect OsName. Pass -OsName '<value>' explicitly.
  Detected running OS caption : $($diag.caption)
Distinct OsName values in NSRL\nsrl_reduced.csv:
$($diag.nsrlOsList)
"@
        return
    }
} else {
    # Validate that the user-supplied OsName matches an entry in the NSRL
    # corpus. A typo (e.g. 'Windows 11' vs 'Windows 11 Version 25H2 X64')
    # would silently misroute later - fail fast here with the available list.
    $csvPathForCheck = Join-Path $RepoRoot 'NSRL\nsrl_reduced.csv'
    if (Test-Path -LiteralPath $csvPathForCheck) {
        try {
            $knownOs = @(Import-Csv -LiteralPath $csvPathForCheck |
                         Where-Object { $_.OsName } |
                         Select-Object -ExpandProperty OsName |
                         Sort-Object -Unique)
            if ($knownOs.Count -gt 0 -and -not ($knownOs -contains $OsName)) {
                Write-Warning @"
OsName '$OsName' is NOT present in NSRL\nsrl_reduced.csv. Get-VTBaseline -OsFilter
will not route these rows through any existing per-OS bucket. Known values:
  $($knownOs -join "`n  ")
Proceeding anyway (assume this is intentional). Ctrl+C to abort.
"@
            }
        } catch {
            # Non-fatal: if the corpus check fails we still let the user proceed.
        }
    }
}

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
    $CsvPath = Join-Path $RepoRoot 'NSRL\nsrl_common_software.csv'
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
    Write-Host "  2. Get-VTBaseline -Mode NSRL -OsFilter '$OsName'"
    Write-Host "     (behaviors for signed-verified files are INCLUDED by default as of 2026-07-23;"
    Write-Host "      pass -SkipBehaviorsForSignedVerified:`$true only for a quota-constrained run)"
    Write-Host "  3. Import-Module .\agentic\Build-VTFidelityIndex.psm1"
    Write-Host "  4. Build-VTFidelityIndex   # ~10-15 min; emits Score100 + calibration_passed clears"
    Write-Host "  5. .\tools\Measure-FidelityFPs.ps1   # confirm FP-kill delta"
} else {
    Write-Host "No new hashes added - CSV was already up to date for this package." -ForegroundColor DarkGray
}

<#
.SYNOPSIS
Smart unpacker for an Eaton firmware ZIP. Handles every Eaton firmware
pattern observed in the UPS/PDU/Network lines:

  Pattern A — Outer ZIP -> .sta multi-block container + setUPS.exe + PDF
              (most modern Eaton UPS lines: 5SC, 5P, 5PX, 5PX G2, 9PX,
              9SX, 9PX variants)
              -> delegates each .sta to Expand-EatonSta.ps1

  Pattern B — Outer ZIP -> nested ZIP -> Motorola S-record or other flat
              firmware + flasher.exe (9130 Powerware-era; 5P 2U-Rackmount;
              5P Standard-Depth-Rack)
              -> recursively expands nested ZIPs

  Pattern C — Outer ZIP -> single large installer .exe (9PXM)
              -> tries 7-Zip extraction if installed; falls back to
              "leave .exe as-is and warn"

  Pattern D — Outer ZIP -> flat .bin files + flasher.exe + PDF
              (Ferrups FX)
              -> nothing additional needed; flat files already present

  Pattern E — Outer ZIP -> multiple module-specific subfolders, each
              with its own firmware (9170+: Charger, Interface,
              Power modules)
              -> recursive walk handles this naturally

  Pattern F — Outer ZIP -> multiple flasher .exe files (each IS the
              firmware payload for a different component; Blade-UPS)
              -> nothing additional needed; flashers stay as artifacts

After all applicable inner expansions, the entire extracted tree is
ready for Build-OsCatalog.ps1 to walk and hash.

.PARAMETER ZipPath
Path to the outer Eaton firmware ZIP file (typically in <product>/raw/).

.PARAMETER OutputDir
Where to write extracted contents. Defaults to <ZipPath's grand-parent>/extracted/,
i.e. firmware-staging/Eaton/<Cat>/<Product>/extracted/

.PARAMETER Force
Clear OutputDir before extracting. Recommended for re-runs to avoid
mixing old + new extractions.

.PARAMETER Quiet
Suppress per-step progress output.

.EXAMPLE
.\tools\Expand-EatonFirmware.ps1 -ZipPath 'C:\githubProjects\firmware-staging\Eaton\UPS\9PX 5-11K-UPS\raw\eaton-9px-5-11k-ups-firmware.zip' -Force
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ZipPath,

    [string]$OutputDir,

    [switch]$Force,

    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ZipPath -PathType Leaf)) {
    Write-Error "ZIP file not found: $ZipPath"
    return
}

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    # Default: <ZipPath's grand-parent>/extracted/
    # e.g. .../<product>/raw/firmware.zip -> .../<product>/extracted/
    $rawDir     = Split-Path -Path $ZipPath -Parent
    $productDir = Split-Path -Path $rawDir  -Parent
    $OutputDir  = Join-Path $productDir 'extracted'
}

if ($Force -and (Test-Path -LiteralPath $OutputDir)) {
    Remove-Item -LiteralPath $OutputDir -Recurse -Force
}
if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

if (-not $Quiet) {
    Write-Host "ZipPath:   $ZipPath"
    Write-Host "OutputDir: $OutputDir"
    Write-Host ""
}

# --- Step 1: outer ZIP ---
if (-not $Quiet) { Write-Host "Step 1: extract outer ZIP" -ForegroundColor DarkCyan }
try {
    Expand-Archive -LiteralPath $ZipPath -DestinationPath $OutputDir -Force
} catch {
    Write-Error "Outer ZIP extraction failed: $($_.Exception.Message)"
    return
}
if (-not $Quiet) { Write-Host "  done" -ForegroundColor Green }

# --- Step 2: recursively expand any nested ZIPs (Pattern B) ---
function Expand-NestedZipsRecursive {
    param([string]$Root, [int]$Depth, [int]$MaxDepth)
    if ($Depth -ge $MaxDepth) { return }
    $nestedZips = Get-ChildItem -LiteralPath $Root -Recurse -File -Filter '*.zip' -ErrorAction SilentlyContinue
    foreach ($nz in $nestedZips) {
        # Don't re-process zips inside already-unpacked subdirs from prior runs
        if ($nz.DirectoryName -match '-unpacked($|[\\/])' -or
            $nz.DirectoryName -match 'sta-unpacked($|[\\/])') { continue }
        $destName = $nz.BaseName + '-unpacked'
        $dest     = Join-Path $nz.DirectoryName $destName
        if (Test-Path -LiteralPath $dest) { continue }
        try {
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            Expand-Archive -LiteralPath $nz.FullName -DestinationPath $dest -Force
            if (-not $script:eatonFwQuiet) {
                Write-Host ("  Expanded nested {0} -> {1}/" -f $nz.Name, $destName) -ForegroundColor DarkGray
            }
            Expand-NestedZipsRecursive -Root $dest -Depth ($Depth + 1) -MaxDepth $MaxDepth
        } catch {
            Write-Host ("  [WARN] Could not expand nested {0}: {1}" -f $nz.Name, $_.Exception.Message) -ForegroundColor Yellow
        }
    }
}

$script:eatonFwQuiet = $Quiet
if (-not $Quiet) { Write-Host ""; Write-Host "Step 2: expand any nested ZIPs (recursion depth <=3)" -ForegroundColor DarkCyan }
Expand-NestedZipsRecursive -Root $OutputDir -Depth 0 -MaxDepth 3

# --- Step 3: unpack any .sta files via Expand-EatonSta (Pattern A) ---
$staFiles = Get-ChildItem -LiteralPath $OutputDir -Recurse -File -Filter '*.sta' -ErrorAction SilentlyContinue
if (-not $Quiet) {
    Write-Host ""
    Write-Host ("Step 3: unpack {0} .sta file(s)" -f $staFiles.Count) -ForegroundColor DarkCyan
}
foreach ($sta in $staFiles) {
    $staUnpackDir = Join-Path $sta.DirectoryName 'sta-unpacked'
    if (Test-Path -LiteralPath $staUnpackDir) { continue }
    try {
        if (-not $Quiet) { Write-Host ("  {0} -> sta-unpacked/" -f $sta.Name) -ForegroundColor DarkGray }
        $staArgs = @{ StaPath = $sta.FullName; OutputDir = $staUnpackDir }
        if ($Quiet) { $staArgs['Quiet'] = $true }
        & "$PSScriptRoot\Expand-EatonSta.ps1" @staArgs | Out-Null
    } catch {
        Write-Host ("  [WARN] Could not unpack {0}: {1}" -f $sta.Name, $_.Exception.Message) -ForegroundColor Yellow
    }
}

# --- Step 4: try to extract any installer-style EXEs (Pattern C) ---
# Heuristic: a single >5MB .exe in a directory whose only other contents
# are .pdf / .txt / .md / a tiny number of files is almost certainly an
# installer EXE that wraps the actual firmware payload.
$sevenZip = $null
foreach ($cand in 'C:\Program Files\7-Zip\7z.exe', 'C:\Program Files (x86)\7-Zip\7z.exe') {
    if (Test-Path $cand) { $sevenZip = $cand; break }
}
if (-not $sevenZip) {
    $sevenZip = (Get-Command 7z -ErrorAction SilentlyContinue).Source
}

$installerCandidates = New-Object System.Collections.Generic.List[System.IO.FileInfo]
$dirs = New-Object System.Collections.Generic.List[string]
$dirs.Add($OutputDir)
$subdirs = @(Get-ChildItem -LiteralPath $OutputDir -Recurse -Directory -ErrorAction SilentlyContinue)
foreach ($sd in $subdirs) {
    if ($sd -and $sd.FullName) { $dirs.Add($sd.FullName) }
}
foreach ($d in $dirs) {
    if ([string]::IsNullOrWhiteSpace($d)) { continue }
    # Skip already-unpacked installer dirs from prior runs
    if ($d -match '-unpacked($|[\\/])' -or $d -match 'sta-unpacked($|[\\/])') { continue }
    $localFiles = @(Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue)
    # 1MB threshold: 5MB was too restrictive -- APC's SNS Tool installer
    # (apc_hw21_su_*.exe / NMC3 firmware) ships at 4MB and wasn't getting
    # detected. Standalone non-installer .exes in our corpus all sit below 1MB.
    $bigExes = @($localFiles | Where-Object { $_.Extension -ieq '.exe' -and $_.Length -gt 1MB })
    $nonSidecars = @($localFiles | Where-Object { $_.Extension -inotin @('.exe', '.pdf', '.txt', '.md', '.zip', '.sta') })
    if ($bigExes.Count -ge 1 -and $nonSidecars.Count -eq 0) {
        foreach ($e in $bigExes) { [void]$installerCandidates.Add($e) }
    }
}

if ($installerCandidates.Count -gt 0) {
    if (-not $Quiet) {
        Write-Host ""
        Write-Host ("Step 4: detected {0} installer-style EXE(s)" -f $installerCandidates.Count) -ForegroundColor DarkCyan
    }
    if ($sevenZip) {
        if (-not $Quiet) { Write-Host "  Using 7-Zip: $sevenZip" -ForegroundColor DarkGray }
        foreach ($exe in $installerCandidates) {
            $unpackDir = Join-Path $exe.DirectoryName ($exe.BaseName + '-unpacked')
            if (Test-Path -LiteralPath $unpackDir) { continue }
            try {
                New-Item -ItemType Directory -Path $unpackDir -Force | Out-Null
                if (-not $Quiet) { Write-Host ("  Extracting {0} ..." -f $exe.Name) -ForegroundColor DarkGray }
                & $sevenZip x -y "-o$unpackDir" "$($exe.FullName)" *>$null
                if ($LASTEXITCODE -ne 0) {
                    Write-Host ("  [WARN] 7z exited {0} on {1}" -f $LASTEXITCODE, $exe.Name) -ForegroundColor Yellow
                }
            } catch {
                Write-Host ("  [WARN] 7z extraction failed for {0}: {1}" -f $exe.Name, $_.Exception.Message) -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "  [WARN] 7-Zip not found. Installer EXEs left as opaque blobs." -ForegroundColor Yellow
        Write-Host "  Install hint: winget install --id 7zip.7zip" -ForegroundColor DarkGray
    }
}

# --- Step 5: recursively expand nested .7z bundles (9PXM exposes per-module
# .7z files after the installer EXE is cracked open: 9PXM-CSB-frw.7z,
# 9PXM_UpmFW.7z, etc.). Bounded depth like Step 2. ---
function Expand-Nested7zRecursive {
    param([string]$Root, [string]$SevenZipExe, [int]$Depth, [int]$MaxDepth)
    if ($Depth -ge $MaxDepth) { return }
    $nested = Get-ChildItem -LiteralPath $Root -Recurse -File -Filter '*.7z' -ErrorAction SilentlyContinue
    foreach ($nz in $nested) {
        # .7z files live INSIDE the installer's '-unpacked' dir (Pattern C),
        # so do not skip on parent-name. Test-Path below gives idempotency.
        $dest = Join-Path $nz.DirectoryName ($nz.BaseName + '-unpacked')
        if (Test-Path -LiteralPath $dest) { continue }
        try {
            # Known Eaton 9PXM install-script passwords (from SetUPS-Batchv*.bat).
            # First entry is empty (covers unencrypted bundles); each is tried in
            # order until extraction returns exit 0. Dest is wiped between tries
            # so partial output from a wrong-password attempt doesn't pollute the
            # next one (CSB_Firmware_Upgrade.7z and Utility.7z mix encrypted +
            # unencrypted entries).
            $passwords = @('', 'eaton', 'password')
            $usedPw = $null
            foreach ($pw in $passwords) {
                if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
                New-Item -ItemType Directory -Path $dest -Force | Out-Null
                & $SevenZipExe x -y "-p$pw" "-o$dest" "$($nz.FullName)" *>$null
                if ($LASTEXITCODE -eq 0) { $usedPw = $pw; break }
            }
            if ($null -eq $usedPw) {
                Write-Host ("  [SKIP] {0}: no known password worked (last exit {1})" -f $nz.Name, $LASTEXITCODE) -ForegroundColor Yellow
                if ((Get-ChildItem -LiteralPath $dest -Force -ErrorAction SilentlyContinue).Count -eq 0) {
                    Remove-Item -LiteralPath $dest -Recurse -Force -ErrorAction SilentlyContinue
                }
                continue
            }
            if (-not $script:eatonFwQuiet) {
                $pwTag = if ($usedPw -eq '') { 'none' } else { "'$usedPw'" }
                Write-Host ("  Expanded nested {0} -> {1}/ (pw={2})" -f $nz.Name, ($nz.BaseName + '-unpacked'), $pwTag) -ForegroundColor DarkGray
            }
            Expand-Nested7zRecursive -Root $dest -SevenZipExe $SevenZipExe -Depth ($Depth + 1) -MaxDepth $MaxDepth
        } catch {
            Write-Host ("  [WARN] Could not expand nested {0}: {1}" -f $nz.Name, $_.Exception.Message) -ForegroundColor Yellow
        }
    }
}

if ($sevenZip) {
    $existing7z = Get-ChildItem -LiteralPath $OutputDir -Recurse -File -Filter '*.7z' -ErrorAction SilentlyContinue
    if ($existing7z) {
        if (-not $Quiet) { Write-Host ""; Write-Host ("Step 5: expand {0} nested .7z bundle(s) (recursion depth <=3)" -f $existing7z.Count) -ForegroundColor DarkCyan }
        Expand-Nested7zRecursive -Root $OutputDir -SevenZipExe $sevenZip -Depth 0 -MaxDepth 3
    }
}

# --- Step 6: deep-extract embedded Linux firmware via WSL + binwalk/ubireader ---
# Eaton's network / PDU / gateway products ship as .tar containing a UBIFS or
# squashfs rootfs (xz-compressed). Without this step, those firmware payloads
# stay as opaque blobs in the catalog and 5a only hashes ~4 vendor artifacts
# per product. With it, the catalog grows to thousands of rows per product
# (every binary, library, config, and HTML file in the embedded OS).
# Requires WSL + Ubuntu + binwalk/squashfs-tools/xz/ubi_reader.

$wslAvailable = $false
try {
    & wsl.exe --status *>$null
    if ($LASTEXITCODE -eq 0) {
        & wsl.exe --user root -d Ubuntu -- bash -lc 'command -v ubireader_extract_files >/dev/null && command -v binwalk >/dev/null' *>$null
        if ($LASTEXITCODE -eq 0) { $wslAvailable = $true }
    }
} catch {}

if ($wslAvailable) {
    # USHA-format firmware (BestLink / ConnectUPS / ConnectUPS-Web-SNMP-Card /
    # X-Slot-Modbus) is ESP32-style and typically <1MB, so it'd be filtered
    # out by the size threshold below. The bash script's USHA handler can
    # carve embedded web-UI files from it, so detect by magic and force-include.
    function Test-IsUshaFirmware {
        param([System.IO.FileInfo]$File)
        if ($File.Length -lt 4) { return $false }
        try {
            $b = [byte[]]::new(4)
            $fs = [System.IO.File]::OpenRead($File.FullName)
            try { [void]$fs.Read($b, 0, 4) } finally { $fs.Dispose() }
            return ($b[0] -eq 0x55 -and $b[1] -eq 0x53 -and $b[2] -eq 0x48 -and $b[3] -eq 0x41)
        } catch { return $false }
    }
    $candidates = @(Get-ChildItem -LiteralPath $OutputDir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            if ($_.FullName -match '-deep[\\/]') { return $false }
            # .nmc3/.spkg added for APC: NMC3 firmware is a ZIP wrapping
            # AOS+APP+sig; .spkg is the signed-package sub-bundle inside.
            $isContainer = $_.Extension -in @('.tar','.fw','.img','.rom','.nmc3','.spkg')
            $isBigBin    = $_.Extension -in @('.bin','.gz','.xz') -and $_.Length -gt 1MB
            $isUsha      = $_.Extension -ieq '.bin' -and (Test-IsUshaFirmware $_)
            $isContainer -or $isBigBin -or $isUsha
        })
    if (-not $Quiet) {
        Write-Host ""
        Write-Host ("Step 6: deep-extract {0} firmware payload(s) via WSL+binwalk" -f $candidates.Count) -ForegroundColor DarkCyan
    }
    $extractorWsl = '/mnt/c/githubProjects/statisticalDifferentialPotato/tools/extract-firmware.sh'
    foreach ($f in $candidates) {
        $deepDir = $f.FullName + '-deep'
        if (Test-Path -LiteralPath $deepDir) {
            if (-not $Quiet) { Write-Host ("  [skip] {0} already deep-extracted" -f $f.Name) -ForegroundColor DarkGray }
            continue
        }
        $wslIn  = '/mnt/c' + ($f.FullName -replace '^C:','' -replace '\\','/')
        $wslOut = '/mnt/c' + ($deepDir   -replace '^C:','' -replace '\\','/')
        if (-not $Quiet) { Write-Host ("  {0} ..." -f $f.Name) -ForegroundColor DarkGray -NoNewline }
        & wsl.exe --user root -d Ubuntu -- bash "$extractorWsl" "$wslIn" "$wslOut" *>$null
        $extractedCount = @(Get-ChildItem -LiteralPath $deepDir -Recurse -File -ErrorAction SilentlyContinue).Count
        if ($extractedCount -gt 0) {
            if (-not $Quiet) { Write-Host (" {0} files" -f $extractedCount) -ForegroundColor Green }
        } else {
            if (-not $Quiet) { Write-Host " no filesystem detected" -ForegroundColor DarkGray }
            if (Test-Path -LiteralPath $deepDir) {
                Remove-Item -LiteralPath $deepDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
} else {
    if (-not $Quiet) {
        Write-Host ""
        Write-Host "Step 6: skipped (WSL+binwalk+ubi_reader not installed)" -ForegroundColor DarkGray
        Write-Host "  To enable embedded-Linux filesystem extraction:" -ForegroundColor DarkGray
        Write-Host "    wsl --install -d Ubuntu --no-launch" -ForegroundColor DarkGray
        Write-Host "    wsl --user root -d Ubuntu -- bash -c 'apt update && apt install -y binwalk squashfs-tools xz-utils python3-pip cpio && pip3 install --break-system-packages ubi_reader'" -ForegroundColor DarkGray
    }
}

# --- Done ---
if (-not $Quiet) {
    $allFiles = @(Get-ChildItem -LiteralPath $OutputDir -Recurse -File -ErrorAction SilentlyContinue)
    Write-Host ""
    Write-Host "[DONE]"
    Write-Host ("  Total files extracted to {0}: {1}" -f $OutputDir, $allFiles.Count)
    Write-Host ""
    Write-Host "Next step: build the catalog:" -ForegroundColor DarkCyan
    Write-Host "  .\tools\Build-OsCatalog.ps1 -OsName '<product version>' -SourceDir '$OutputDir' -OutputCsv '$(Join-Path (Split-Path -Parent $OutputDir) 'catalog.csv')'"
}

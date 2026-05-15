[CmdletBinding()]
param(
    [string]$Root    = "output-baseline",
    [string]$NsrlCsv = "NSRL\nsrl_reduced.csv",
    [switch]$Apply
)

function Get-NSRLOsSlug {
    param([string]$OsName)
    if ([string]::IsNullOrWhiteSpace($OsName)) { return $null }
    $slug = $OsName -replace ' Version \S+(\s+X64)?$', ''
    $slug = $slug -replace ' LTS$', ''
    $slug = $slug -replace '\s+', '-'
    return $slug
}

if (-not (Test-Path $NsrlCsv)) {
    Write-Error "NSRL CSV not found at $NsrlCsv"
    return
}

Write-Host "Loading NSRL hash -> OS map from $NsrlCsv..." -ForegroundColor DarkCyan
$hashToOs = @{}
Import-Csv $NsrlCsv | ForEach-Object {
    if ($_.Hash -and $_.OsName) { $hashToOs[$_.Hash.ToLowerInvariant()] = $_.OsName }
}
Write-Host "Loaded $($hashToOs.Count) NSRL hashes." -ForegroundColor DarkGray

$kinds      = @('VirusTotal-main', 'VirusTotal-behaviors')
$sigFolders = @('SignedVerified', 'unsignedWin', 'unsignedLinux', 'unverified', 'drivers')

$stats    = [ordered]@{}
$movePlan = New-Object System.Collections.Generic.List[object]

foreach ($kind in $kinds) {
    foreach ($sig in $sigFolders) {
        $src = Join-Path $Root (Join-Path $kind $sig)
        if (-not (Test-Path $src)) { continue }

        Get-ChildItem -Path $src -Filter "*.json" -File -ErrorAction SilentlyContinue | ForEach-Object {
            $hash    = $_.BaseName.ToLowerInvariant()
            $destDir = $null
            $bucket  = $null

            if ($hashToOs.ContainsKey($hash)) {
                $slug    = Get-NSRLOsSlug $hashToOs[$hash]
                $destDir = Join-Path $Root (Join-Path $kind (Join-Path 'NSRL' (Join-Path $slug $sig)))
                $bucket  = "$kind\NSRL\$slug\$sig"
            }
            else {
                $destDir = Join-Path $Root (Join-Path $kind (Join-Path 'localBaseline' $sig))
                $bucket  = "$kind\localBaseline\$sig"
            }

            $movePlan.Add([pscustomobject]@{
                Src    = $_.FullName
                Dest   = (Join-Path $destDir $_.Name)
                Bucket = $bucket
            })
            if (-not $stats.Contains($bucket)) { $stats[$bucket] = 0 }
            $stats[$bucket]++
        }
    }
}

Write-Host ""
Write-Host "Move plan ($($movePlan.Count) files):" -ForegroundColor Cyan
$stats.GetEnumerator() | Sort-Object Name | ForEach-Object {
    Write-Host ('  {0,8}  {1}' -f $_.Value, $_.Name)
}

foreach ($kind in $kinds) {
    $maliciousPath = Join-Path $Root (Join-Path $kind 'malicious')
    if (Test-Path $maliciousPath) {
        $count = (Get-ChildItem -Path $maliciousPath -Filter "*.json" -File -ErrorAction SilentlyContinue).Count
        Write-Host ('  {0,8}  {1}\malicious  (unchanged)' -f $count, $kind) -ForegroundColor DarkGray
    }
}

if (-not $Apply) {
    Write-Host ""
    Write-Host "[DRY RUN] Re-run with -Apply to perform the moves." -ForegroundColor Yellow
    return
}

Write-Host ""
Write-Host "Applying moves..." -ForegroundColor Green
$moved  = 0
$errors = 0
foreach ($m in $movePlan) {
    try {
        $destDir = Split-Path $m.Dest -Parent
        if (-not (Test-Path $destDir)) {
            [System.IO.Directory]::CreateDirectory($destDir) | Out-Null
        }
        if (Test-Path $m.Dest) {
            Write-Host "  [SKIP] Already at $($m.Dest)" -ForegroundColor DarkGray
        }
        else {
            [System.IO.File]::Move($m.Src, $m.Dest)
            $moved++
            if ($moved % 5000 -eq 0) {
                Write-Host "  Moved $moved / $($movePlan.Count)..." -ForegroundColor DarkGray
            }
        }
    }
    catch {
        $errors++
        Write-Host "  [ERROR] $($m.Src) -> $($m.Dest): $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "[DONE] Moved $moved files, $errors errors." -ForegroundColor Green

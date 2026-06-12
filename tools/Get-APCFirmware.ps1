<#
.SYNOPSIS
  Manifest-driven APC firmware fetcher. Handles two modes:
    1) Direct download (-Mode Direct) for entries whose URL points to a
       public binary that resolves with a normal browser User-Agent.
    2) Drop-folder watcher (-Mode Drop) for entries where Schneider's
       EULA/login gate requires a human click; the user downloads via
       browser into an 'incoming/' folder and this script picks the
       file up, verifies the hash if a manifest checksum exists, and
       moves it to the correct firmware-staging/.../raw/ location.

.DESCRIPTION
  Reads a CSV manifest with columns:
    Product       — short slug matching firmware-staging\APC\<Cat>\<Product>\
    Category      — UPS | PDU | Network | Cooling | Software
    ProductPageUrl — vendor page the user opens to read description/version
    BinaryUrl     — direct CDN URL if known; empty for login/EULA-gated entries
    Filename      — recommended filename (script will save as this)
    Sha256        — optional integrity check; empty = skip verification
    LoginRequired — yes | no | unknown
    Priority      — 1 (highest) to 5 (lowest)
    Notes         — free-form

  Direct-mode pulls each manifest entry whose BinaryUrl is set. Drop-mode
  watches firmware-staging\APC\incoming\ for files matching any manifest
  Filename, verifies SHA-256 if available, and moves them into the
  Product's raw\ folder.

.PARAMETER ManifestPath
  CSV manifest. Defaults to firmware-staging\APC\firmware-manifest.csv.

.PARAMETER StagingRoot
  Root of the APC staging tree. Defaults to firmware-staging\APC.

.PARAMETER Mode
  Direct | Drop | List

.PARAMETER PriorityMax
  Only act on entries with Priority <= this value (Direct mode).

.PARAMETER WhatIf
  Print what would happen without downloading or moving anything.
#>

[CmdletBinding()]
param(
    [string]$ManifestPath = (Join-Path (Split-Path $PSCommandPath -Parent | Split-Path -Parent) '..\firmware-staging\APC\firmware-manifest.csv'),
    [string]$StagingRoot  = (Join-Path (Split-Path $PSCommandPath -Parent | Split-Path -Parent) '..\firmware-staging\APC'),
    [ValidateSet('Direct','Drop','List')] [string]$Mode = 'List',
    [int]$PriorityMax = 99,
    [switch]$WhatIfMode
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ManifestPath)) {
    throw "Manifest not found: $ManifestPath"
}
if (-not (Test-Path -LiteralPath $StagingRoot)) {
    throw "Staging root not found: $StagingRoot"
}

$ManifestPath = (Resolve-Path -LiteralPath $ManifestPath).ProviderPath
$StagingRoot  = (Resolve-Path -LiteralPath $StagingRoot).ProviderPath
$IncomingDir  = Join-Path $StagingRoot 'incoming'

$Manifest = Import-Csv -LiteralPath $ManifestPath

# Pose as a modern Edge browser - Schneider's CDN rejects empty/Python/PSH UAs.
$BrowserUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0'

function Get-TargetRawDir {
    param([Parameter(Mandatory)] [pscustomobject]$Entry)
    Join-Path $StagingRoot (Join-Path $Entry.Category (Join-Path $Entry.Product 'raw'))
}

function Test-Sha256 {
    param([Parameter(Mandatory)] [string]$Path, [string]$Expected)
    if ([string]::IsNullOrWhiteSpace($Expected)) { return $true }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    return ($actual -eq $Expected.ToLowerInvariant())
}

function Invoke-DirectDownload {
    param([pscustomobject]$Entry)
    $rawDir = Get-TargetRawDir -Entry $Entry
    $dest = Join-Path $rawDir $Entry.Filename
    if (Test-Path -LiteralPath $dest) {
        if (Test-Sha256 -Path $dest -Expected $Entry.Sha256) {
            Write-Host ("  [skip] already present (hash OK): {0}" -f $Entry.Filename) -ForegroundColor DarkGray
            return @{ Status = 'skip-present'; Path = $dest }
        } else {
            Write-Host ("  [warn] file exists but hash mismatch -- backing up: {0}" -f $Entry.Filename) -ForegroundColor Yellow
            Move-Item -LiteralPath $dest -Destination ("{0}.bad.{1}" -f $dest, (Get-Date -Format yyyyMMddHHmmss))
        }
    }
    if ($WhatIfMode) {
        Write-Host ("  [dryrun] would GET {0} -> {1}" -f $Entry.BinaryUrl, $dest) -ForegroundColor Cyan
        return @{ Status = 'dryrun'; Path = $dest }
    }
    New-Item -ItemType Directory -Force -Path $rawDir | Out-Null
    Write-Host ("  [get ] {0}" -f $Entry.Filename) -ForegroundColor Cyan
    try {
        Invoke-WebRequest -Uri $Entry.BinaryUrl `
                          -UserAgent $BrowserUA `
                          -Headers @{ 'Accept' = 'application/octet-stream, */*' } `
                          -OutFile $dest `
                          -UseBasicParsing `
                          -TimeoutSec 600 `
                          -ErrorAction Stop
    } catch {
        Write-Host ("  [FAIL] $($_.Exception.Message)") -ForegroundColor Red
        if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Force }
        return @{ Status = 'http-error'; Error = $_.Exception.Message }
    }
    if (-not (Test-Sha256 -Path $dest -Expected $Entry.Sha256)) {
        Write-Host ("  [FAIL] SHA-256 mismatch on $($Entry.Filename); see *.bad.* sibling") -ForegroundColor Red
        Move-Item -LiteralPath $dest -Destination ("{0}.bad.{1}" -f $dest, (Get-Date -Format yyyyMMddHHmmss))
        return @{ Status = 'hash-mismatch'; Path = $dest }
    }
    $size = (Get-Item -LiteralPath $dest).Length
    Write-Host ("  [ ok ] {0:N0} bytes -> {1}" -f $size, $dest) -ForegroundColor Green
    return @{ Status = 'downloaded'; Path = $dest; Bytes = $size }
}

function Move-FromIncoming {
    param([pscustomobject]$Entry)
    $src = Join-Path $IncomingDir $Entry.Filename
    if (-not (Test-Path -LiteralPath $src)) {
        return @{ Status = 'not-in-incoming' }
    }
    $rawDir = Get-TargetRawDir -Entry $Entry
    $dest = Join-Path $rawDir $Entry.Filename
    if (Test-Path -LiteralPath $dest) {
        Write-Host ("  [warn] dest already exists, archiving incoming copy: {0}" -f $Entry.Filename) -ForegroundColor Yellow
        Move-Item -LiteralPath $src -Destination ("{0}.dup.{1}" -f $src, (Get-Date -Format yyyyMMddHHmmss))
        return @{ Status = 'dup-archived' }
    }
    if (-not (Test-Sha256 -Path $src -Expected $Entry.Sha256)) {
        Write-Host ("  [FAIL] SHA-256 mismatch on incoming/{0}" -f $Entry.Filename) -ForegroundColor Red
        return @{ Status = 'hash-mismatch' }
    }
    if ($WhatIfMode) {
        Write-Host ("  [dryrun] would move {0} -> {1}" -f $src, $dest) -ForegroundColor Cyan
        return @{ Status = 'dryrun' }
    }
    New-Item -ItemType Directory -Force -Path $rawDir | Out-Null
    Move-Item -LiteralPath $src -Destination $dest
    $size = (Get-Item -LiteralPath $dest).Length
    Write-Host ("  [move] {0:N0} bytes -> {1}" -f $size, $dest) -ForegroundColor Green
    return @{ Status = 'moved'; Path = $dest; Bytes = $size }
}

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

Write-Host ("Manifest: {0}" -f $ManifestPath) -ForegroundColor DarkCyan
Write-Host ("Staging:  {0}" -f $StagingRoot)  -ForegroundColor DarkCyan
Write-Host ("Mode:     {0}" -f $Mode)         -ForegroundColor DarkCyan
Write-Host ("Entries:  {0}" -f $Manifest.Count) -ForegroundColor DarkCyan
Write-Host ''

switch ($Mode) {

    'List' {
        # Show the manifest grouped by priority + readiness state
        $Manifest |
            Sort-Object @{e='Priority';asc=$true}, Category, Product |
            ForEach-Object {
                $state = if ($_.BinaryUrl) { 'direct' } elseif ($_.LoginRequired -eq 'yes') { 'manual-EULA' } else { 'manual' }
                $dest = Get-TargetRawDir -Entry $_
                $have = if (Test-Path -LiteralPath (Join-Path $dest $_.Filename)) { 'HAVE' } else { '----' }
                "{0}  P{1}  {2,-10}  {3}/{4,-40}  {5,-12}  {6}" -f $have, $_.Priority, $state, $_.Category, $_.Product, $_.Filename, $_.ProductPageUrl
            } | ForEach-Object { Write-Host $_ }
    }

    'Direct' {
        New-Item -ItemType Directory -Force -Path $IncomingDir | Out-Null
        $todo = $Manifest | Where-Object { $_.BinaryUrl -and ([int]$_.Priority -le $PriorityMax) }
        Write-Host ("Direct-mode targets: {0}" -f @($todo).Count)
        foreach ($entry in $todo) {
            Write-Host ("`n--- {0}/{1} ---" -f $entry.Category, $entry.Product) -ForegroundColor Yellow
            $r = Invoke-DirectDownload -Entry $entry
            $entry | Add-Member -NotePropertyName Result -NotePropertyValue $r.Status -Force
        }
    }

    'Drop' {
        if (-not (Test-Path -LiteralPath $IncomingDir)) {
            Write-Host ("Incoming folder does not exist yet: {0}" -f $IncomingDir) -ForegroundColor Yellow
            Write-Host "Create it and drop browser-downloaded firmware files in by their canonical filename."
            return
        }
        $todo = $Manifest | Where-Object { ([int]$_.Priority -le $PriorityMax) }
        $moved = 0
        foreach ($entry in $todo) {
            $r = Move-FromIncoming -Entry $entry
            if ($r.Status -eq 'moved' -or $r.Status -eq 'dryrun') { $moved++ }
        }
        Write-Host ("`nMoved {0} file(s) from incoming/" -f $moved) -ForegroundColor Green

        # Surface unrecognized files in incoming/ so user can update the manifest
        $known = @($Manifest | Where-Object { ([int]$_.Priority -le $PriorityMax) } | Select-Object -ExpandProperty Filename)
        $unknown = Get-ChildItem -LiteralPath $IncomingDir -File -ErrorAction SilentlyContinue |
                   Where-Object { $known -notcontains $_.Name }
        if ($unknown) {
            Write-Host "`nUnknown files in incoming/ (not in manifest):" -ForegroundColor Yellow
            $unknown | ForEach-Object { Write-Host ("  {0}" -f $_.Name) }
            Write-Host "Add manifest entries for these or remove them from incoming/."
        }
    }
}

<#
.SYNOPSIS
  Render firmware-threat-brief markdown files to PDF (markdown -> HTML via pandoc
  -> Chrome headless print-to-PDF). Matches the look of the existing brief PDFs.

.DESCRIPTION
  Standing requirement: every threat brief should also have a PDF. Re-run this
  after editing briefs. Pass -Path to render specific files; omit it to render
  every *.md in firmware-threat-briefs/.

.EXAMPLE
  pwsh -NoProfile -File tools/Render-BriefsToPdf.ps1 -Path firmware-threat-briefs/axis-communications-firmware-threat-brief.md
.EXAMPLE
  pwsh -NoProfile -File tools/Render-BriefsToPdf.ps1   # all briefs
#>
[CmdletBinding()]
param(
    [string[]] $Path,
    [string]   $BriefDir = (Join-Path $PSScriptRoot '..\firmware-threat-briefs'),
    [string]   $Css      = (Join-Path $PSScriptRoot 'brief-print.css')
)

$ErrorActionPreference = 'Stop'

# --- locate pandoc ---
$pandoc = (Get-Command pandoc -ErrorAction SilentlyContinue).Source
if (-not $pandoc) {
    $cand = Join-Path $env:LOCALAPPDATA 'Pandoc\pandoc.exe'
    if (Test-Path $cand) { $pandoc = $cand }
}
if (-not $pandoc) { throw "pandoc not found (install or add to PATH)." }

# --- locate a Chromium browser ---
$chrome = $null
foreach ($c in @(
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
)) { if (Test-Path $c) { $chrome = $c; break } }
if (-not $chrome) { throw "No Chrome/Edge found for print-to-PDF." }

if (-not $Path -or $Path.Count -eq 0) {
    $Path = Get-ChildItem -Path $BriefDir -Filter *.md | Select-Object -ExpandProperty FullName
}

$tmp = Join-Path $env:TEMP ("brief-pdf-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$profileDir = Join-Path $tmp 'chrome-profile'

$ok = 0; $fail = 0
foreach ($md in $Path) {
    if (-not (Test-Path $md)) { Write-Warning "skip (missing): $md"; continue }
    $md   = (Resolve-Path $md).Path
    $base = [IO.Path]::GetFileNameWithoutExtension($md)
    $html = Join-Path $tmp ($base + '.html')
    $pdf  = [IO.Path]::ChangeExtension($md, '.pdf')

    & $pandoc $md -f gfm -t html5 --standalone --embed-resources `
        --metadata "title=$base" -c $Css -o $html
    if ($LASTEXITCODE -ne 0) { Write-Warning "pandoc failed: $base"; $fail++; continue }

    $uri = ([Uri]$html).AbsoluteUri
    & $chrome --headless=new --disable-gpu --no-first-run --no-default-browser-check `
        "--user-data-dir=$profileDir" --no-pdf-header-footer `
        "--print-to-pdf=$pdf" $uri 2>$null
    if ((Test-Path $pdf) -and ((Get-Item $pdf).Length -gt 1000)) {
        Write-Host ("  [PDF] {0}" -f (Split-Path $pdf -Leaf)); $ok++
    } else { Write-Warning "chrome failed: $base"; $fail++ }
}

Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ("Done: {0} rendered, {1} failed." -f $ok, $fail)

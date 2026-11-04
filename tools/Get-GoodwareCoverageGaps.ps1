#Requires -Version 7.0
<#
.SYNOPSIS
    Rank fidelity-index entries by "malware uses this, our goodware corpus
    barely covers it" - i.e. where the next false positives will come from.

.DESCRIPTION
    The goodware side of the differential is the scarce side (see
    memory: risk-score-accumulation-model). An artifact with high M and low G
    scores as highly malicious whether or not it actually is, because G=0 means
    "never observed in goodware", not "benign software does not do this".

    This ranks each dimension's entries by that gap so goodware acquisition can
    be targeted at what the corpus is actually missing, rather than at whatever
    software happens to be installed on the analyst's workstation.

    Lift is reported because it separates two very different cases:
      lift >> 1  the artifact really is malware-associated; high score is correct
      lift ~ 1   no discriminative power; a high score here is a scoring artifact
    Both are acquisition targets, but only the second is a scoring bug.

.PARAMETER Dimension
    Which fidelity dimension to rank. Default 'process'.

.PARAMETER MinM
    Ignore entries seen in fewer than this many malicious samples. Default 25.

.PARAMETER MaxG
    Only report entries whose goodware count is at or below this. Default 5.

.PARAMETER Top
    Rows to print. Default 40.

.EXAMPLE
    .\tools\Get-GoodwareCoverageGaps.ps1
    .\tools\Get-GoodwareCoverageGaps.ps1 -Dimension module-load -MinM 50
    .\tools\Get-GoodwareCoverageGaps.ps1 -Dimension command-execution -MaxG 0
#>
[CmdletBinding()]
param(
    [string]$Dimension    = 'process',
    [string]$BaselineRoot = 'output-baseline',
    [int]$MinM            = 25,
    [int]$MaxG            = 5,
    [int]$Top             = 40,
    [string]$CsvOut
)

$ErrorActionPreference = 'Stop'
if (-not [System.IO.Path]::IsPathRooted($BaselineRoot)) {
    $BaselineRoot = Join-Path (Split-Path $PSScriptRoot -Parent) $BaselineRoot
}
$dimFile  = Join-Path $BaselineRoot "fidelity-$Dimension.json"
$manifest = Join-Path $BaselineRoot 'fidelity-manifest.json'
foreach ($f in @($dimFile,$manifest)) {
    if (-not (Test-Path -LiteralPath $f)) { Write-Error "Not found: $f"; return }
}

$mf = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
$Mtotal = [double]$mf.totals.Mtotal
$Gtotal = [double]$mf.totals.Gtotal
if ($Mtotal -le 0 -or $Gtotal -le 0) { Write-Error "Manifest totals unusable (M=$Mtotal G=$Gtotal)."; return }
$usage = $null
if ($mf.dimension_meta.PSObject.Properties[$Dimension]) { $usage = $mf.dimension_meta.$Dimension.usage }

Write-Host ""
Write-Host "Goodware coverage gaps - dimension '$Dimension' (usage: $usage)" -ForegroundColor DarkCyan
Write-Host ("  corpus: Mtotal={0:N0}  Gtotal={1:N0}   filter: M>={2}, G<={3}" -f $Mtotal,$Gtotal,$MinM,$MaxG) -ForegroundColor DarkGray

$idx  = Get-Content -LiteralPath $dimFile -Raw | ConvertFrom-Json
$rows = foreach ($p in $idx.PSObject.Properties) {
    $e = $p.Value
    $m = [int]$e.M; $g = [int]$e.G
    if ($m -lt $MinM -or $g -gt $MaxG) { continue }
    # Additive smoothing on G so G=0 yields a finite, comparable lift.
    $lift = ($m / $Mtotal) / ((($g + 0.5)) / $Gtotal)
    [pscustomobject]@{
        Artifact = $p.Name
        M        = $m
        G        = $g
        M_obs    = if ($e.PSObject.Properties['M_obs']) { [int]$e.M_obs } else { $null }
        Lift     = [Math]::Round($lift,1)
        Score100 = if ($e.PSObject.Properties['Score100']) { [int]$e.Score100 } else { $null }
        VP       = if ($e.PSObject.Properties['VerdictPoints']) { [int]$e.VerdictPoints } else { $null }
        Phase2   = if ($e.PSObject.Properties['Phase2']) { [bool]$e.Phase2 } else { $null }
    }
}
$rows = @($rows | Sort-Object M -Descending)
Write-Host ("  matching entries: {0}" -f $rows.Count) -ForegroundColor DarkGray
Write-Host ""
"{0,-42} {1,7} {2,5} {3,8} {4,5} {5,4}" -f 'artifact','M','G','lift','S100','VP' | Write-Host
foreach ($r in ($rows | Select-Object -First $Top)) {
    $p2 = if ($r.Phase2) { ' P2' } else { '' }
    "{0,-42} {1,7} {2,5} {3,8} {4,5} {5,4}{6}" -f `
        $r.Artifact.Substring(0,[Math]::Min(42,$r.Artifact.Length)), $r.M, $r.G, $r.Lift, $r.Score100, $r.VP, $p2 | Write-Host
}
if ($CsvOut) { $rows | Export-Csv -Path $CsvOut -NoTypeInformation -Encoding UTF8; Write-Host "`n  wrote $CsvOut" -ForegroundColor DarkGray }
Write-Host ""
Write-Host "  lift >> 1 : genuinely malware-associated - high score is CORRECT" -ForegroundColor DarkGray
Write-Host "  lift ~ 1  : no discriminative power - a high score here is a SCORING artifact" -ForegroundColor DarkGray

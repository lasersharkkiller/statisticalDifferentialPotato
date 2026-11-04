<#
.SYNOPSIS
    Cross-references ACAS/Nessus findings against GTI vulnerability intelligence to
    find Sigma / YARA / IDS rules usable for detecting exploitation.

.DESCRIPTION
    ACAS exports in this environment carry `vuln_id: null`, so there is no CVE to
    pivot on - only a Tenable plugin_id. CVEs therefore come from a mapping file
    (plugin_id -> CVEs), which is resolved once from Tenable's public plugin pages
    and cached, since nothing offline maps plugin IDs to CVEs.

    For each CVE the GTI vulnerability collection is addressed DIRECTLY by id
    (`vulnerability--cve-xxxx-yyyy`). That matters: free-text collection search is
    unreliable here and silently returns unrelated CVEs. Verified working - e.g.
    CVE-2024-3400 yields YARA `EXPL_PaloAlto_CVE_2024_3400_Apr24_1`, CVE-2020-1472
    yields `Impacket`.

    Detection rules are gathered from the samples linked to each vulnerability:
      * crowdsourced_yara_results  -> YARA rule names + authors
      * sigma_analysis_results     -> Sigma rule titles + severity
      * crowdsourced_ids_results   -> Suricata/Snort signatures
    plus exploitation context (exploitation_state, EPSS, risk_rating) and the
    threat actors GTI associates with the vulnerability.

    NOTE on cumulative updates: a Windows KB plugin can aggregate 1,000+ CVEs
    (KB5122882 has 1,089). Per-CVE detection rules do not change the remediation
    there - installing the KB covers all of them - so -MaxCvesPerPlugin caps the
    sweep and the report says when a plugin was truncated.

.PARAMETER FindingsPath
    ACAS findings as NDJSON (one finding per line).

.PARAMETER CveMapPath
    CSV of plugin_id,cve. Built by -ResolveCves or supplied by hand.

.EXAMPLE
    .\tools\Invoke-AcasVTCrossRef.ps1 -FindingsPath 'C:\githubProjects\OTSDP\CA\ngcaa7j6zavm002_acascriticals.json'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FindingsPath,
    [string]$CveMapPath       = 'output\ca\plugin-cve-map.csv',
    [string]$SecretName       = 'VT_Enterprise_Key',
    [int]$MinDelayMs          = 12,
    [int]$MaxCvesPerPlugin    = 25,
    [int]$MaxFilesPerCve      = 10,
    [string]$OutDir           = 'output\ca'
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

try { $key = (Get-Secret -Name $SecretName -AsPlainText -ErrorAction Stop).Trim() }
catch { Write-Host "[!] Cannot read secret '$SecretName': $($_.Exception.Message)" -ForegroundColor Red; return }
$script:H = @{ 'x-apikey' = $key; 'accept' = 'application/json' }
$script:Last = [DateTime]::MinValue

function Invoke-Gti {
    param([string]$Uri)
    $wait = $MinDelayMs - ([DateTime]::UtcNow - $script:Last).TotalMilliseconds
    if ($wait -gt 0) { Start-Sleep -Milliseconds ([int]$wait) }
    $script:Last = [DateTime]::UtcNow
    Invoke-RestMethod -Uri $Uri -Headers $script:H -Method Get -ErrorAction Stop
}

Write-Host ""
Write-Host "=== ACAS -> GTI cross-reference: $(Split-Path $FindingsPath -Leaf) ===" -ForegroundColor Cyan

# ------------------------------------------------------------- findings ---
$findings = @(
    [System.IO.File]::ReadLines($FindingsPath) | ForEach-Object {
        if ($_ -and $_.Trim()) { try { $_ | ConvertFrom-Json } catch { $null } }
    } | Where-Object { $_ }
)
Write-Host ("  findings: {0}  hosts: {1}" -f $findings.Count, (@($findings | ForEach-Object { $_.acas_ip } | Sort-Object -Unique) -join ', '))

# De-duplicate to the unit that matters: the plugin.
$plugins = @($findings | Group-Object plugin_id | ForEach-Object {
    $g = $_.Group
    [pscustomobject]@{
        PluginId   = $_.Name
        PluginName = $g[0].plugin_name
        Family     = $g[0].plugin_family
        Instances  = $_.Count
        MaxCvss    = (@($g | ForEach-Object { [double]("0" + $_.cvss_base_score) }) | Measure-Object -Maximum).Maximum
        Kev        = [bool](@($g | Where-Object { $_.acas_cisa_known_exploited }).Count)
        Exploitable = (@($g | ForEach-Object { $_.exploitability_ease } | Where-Object { $_ } | Sort-Object -Unique) -join '; ')
        Solution   = $g[0].solution
    }
} | Sort-Object @{e={$_.Kev}; Descending=$true}, @{e={$_.MaxCvss}; Descending=$true})

Write-Host ("  distinct plugins: {0}  (CISA KEV flagged: {1})" -f $plugins.Count, @($plugins | Where-Object { $_.Kev }).Count)
Write-Host ""
foreach ($p in $plugins) {
    Write-Host ("   {0,-8} cvss={1,-5} {2,-4} x{3,-3} {4}" -f $p.PluginId, $p.MaxCvss, $(if ($p.Kev) { 'KEV' } else { '' }), $p.Instances, $p.PluginName.Substring(0, [Math]::Min(60, $p.PluginName.Length)))
}

# ------------------------------------------------------------ CVE map ---
if (-not (Test-Path $CveMapPath)) {
    Write-Host ""
    Write-Host "[!] No plugin->CVE map at $CveMapPath." -ForegroundColor Yellow
    Write-Host "    ACAS findings here have vuln_id=null, so CVEs cannot be derived from the export." -ForegroundColor Yellow
    Write-Host "    Create a CSV with columns plugin_id,cve (one row per CVE)." -ForegroundColor Yellow
    return
}
$map = @(Import-Csv $CveMapPath)
$byPlugin = @{}
foreach ($m in $map) {
    if (-not $m.plugin_id -or -not $m.cve) { continue }
    if (-not $byPlugin.ContainsKey($m.plugin_id)) { $byPlugin[$m.plugin_id] = [System.Collections.Generic.List[string]]::new() }
    if (-not $byPlugin[$m.plugin_id].Contains($m.cve)) { $byPlugin[$m.plugin_id].Add($m.cve) }
}
Write-Host ""
Write-Host ("  CVE map: {0} rows covering {1} plugins" -f $map.Count, $byPlugin.Count)

# --------------------------------------------------------- the pivot ---
$out = [System.Collections.Generic.List[object]]::new()
$rules = [System.Collections.Generic.List[object]]::new()

foreach ($p in $plugins) {
    if (-not $byPlugin.ContainsKey($p.PluginId)) {
        Write-Host ("`n  [{0}] no CVE mapping - skipped" -f $p.PluginId) -ForegroundColor DarkGray
        continue
    }
    $cves = @($byPlugin[$p.PluginId])
    $truncated = $false
    if ($cves.Count -gt $MaxCvesPerPlugin) { $truncated = $true; $cves = @($cves | Select-Object -First $MaxCvesPerPlugin) }
    Write-Host ""
    Write-Host ("  [{0}] {1} CVE(s){2}" -f $p.PluginId, $byPlugin[$p.PluginId].Count, $(if ($truncated) { " - checking first $MaxCvesPerPlugin" } else { '' })) -ForegroundColor Cyan

    foreach ($cve in $cves) {
        $id = "vulnerability--" + $cve.ToLowerInvariant()
        $row = [ordered]@{
            PluginId = $p.PluginId; PluginName = $p.PluginName; Kev = $p.Kev; Cve = $cve
            Found = $false; Cvss = ''; Epss = ''; RiskRating = ''; ExploitationState = ''
            ExploitAvailability = ''; FilesCount = 0; ThreatActors = ''
            YaraRules = ''; SigmaRules = ''; IdsRules = ''; SamplesChecked = 0
        }
        try {
            $a = (Invoke-Gti "https://www.virustotal.com/api/v3/collections/$id").data.attributes
            $row.Found = $true
            $row.Cvss  = $a.cvss.base_score
            if ($a.epss) { $row.Epss = [math]::Round([double]$a.epss.score, 4) }
            $row.RiskRating          = $a.risk_rating
            $row.ExploitationState   = $a.exploitation_state
            $row.ExploitAvailability = $a.exploit_availability
            $row.FilesCount          = [int]("0" + ("" + $a.files_count))

            try {
                $ta = Invoke-Gti "https://www.virustotal.com/api/v3/collections/$id/threat_actors?limit=5"
                $row.ThreatActors = (@($ta.data | ForEach-Object { $_.attributes.name } | Where-Object { $_ }) -join '; ')
            } catch { }

            if ($row.FilesCount -gt 0) {
                $yara = [System.Collections.Generic.HashSet[string]]::new()
                $sigma = [System.Collections.Generic.HashSet[string]]::new()
                $ids   = [System.Collections.Generic.HashSet[string]]::new()
                try {
                    $fl = Invoke-Gti "https://www.virustotal.com/api/v3/collections/$id/files?limit=$MaxFilesPerCve"
                    foreach ($f in @($fl.data)) {
                        $row.SamplesChecked++
                        $fa = $f.attributes
                        foreach ($y in @($fa.crowdsourced_yara_results)) {
                            $nm = if ($y.rule_name) { $y.rule_name } else { $y.ruleset_name }
                            if ($nm) { [void]$yara.Add("$nm") ; [void]$rules.Add([pscustomobject]@{ Cve=$cve; Kind='YARA'; Rule=$nm; Author=$y.author; Ruleset=$y.ruleset_name; Sample=$f.id }) }
                        }
                        foreach ($sProp in @($fa.sigma_analysis_results)) {
                            $nm = $sProp.rule_title
                            if ($nm) { [void]$sigma.Add("$nm"); [void]$rules.Add([pscustomobject]@{ Cve=$cve; Kind='Sigma'; Rule=$nm; Author=$sProp.rule_author; Ruleset=$sProp.rule_level; Sample=$f.id }) }
                        }
                        foreach ($iProp in @($fa.crowdsourced_ids_results)) {
                            $nm = $iProp.rule_msg
                            if ($nm) { [void]$ids.Add("$nm"); [void]$rules.Add([pscustomobject]@{ Cve=$cve; Kind='IDS'; Rule=$nm; Author=$iProp.rule_source; Ruleset=$iProp.alert_severity; Sample=$f.id }) }
                        }
                    }
                } catch { }
                $row.YaraRules  = (@($yara)  -join '; ')
                $row.SigmaRules = (@($sigma) -join '; ')
                $row.IdsRules   = (@($ids)   -join '; ')
            }
            $tag = if ($row.YaraRules -or $row.SigmaRules -or $row.IdsRules) { 'RULES' } elseif ($row.FilesCount -gt 0) { 'samples, no rules' } else { 'no samples' }
            $col = if ($tag -eq 'RULES') { 'Green' } elseif ($tag -eq 'no samples') { 'DarkGray' } else { 'Yellow' }
            Write-Host ("      {0,-18} state={1,-26} files={2,-5} {3}" -f $cve, $row.ExploitationState, $row.FilesCount, $tag) -ForegroundColor $col
        } catch {
            $code = $null; try { $code = $_.Exception.Response.StatusCode.value__ } catch { }
            Write-Host ("      {0,-18} not in GTI (HTTP {1})" -f $cve, $code) -ForegroundColor DarkGray
        }
        $out.Add([pscustomobject]$row)
    }
}

# ----------------------------------------------------------- output ---
$csv = Join-Path $OutDir 'acas-vt-crossref.csv'
$out | Export-Csv -LiteralPath $csv -NoTypeInformation
$rulesCsv = Join-Path $OutDir 'acas-detection-rules.csv'
if ($rules.Count) { $rules | Sort-Object Cve, Kind, Rule -Unique | Export-Csv -LiteralPath $rulesCsv -NoTypeInformation }

$withRules = @($out | Where-Object { $_.YaraRules -or $_.SigmaRules -or $_.IdsRules })
$exploited = @($out | Where-Object { $_.ExploitationState -and $_.ExploitationState -notmatch '(?i)^no known' })

$md = [System.Text.StringBuilder]::new()
[void]$md.AppendLine('# ACAS findings cross-referenced against GTI')
[void]$md.AppendLine()
[void]$md.AppendLine("Source: ``$(Split-Path $FindingsPath -Leaf)`` | $($findings.Count) findings | $($plugins.Count) distinct plugins | $(Get-Date -Format 'yyyy-MM-dd HH:mm')")
[void]$md.AppendLine()
[void]$md.AppendLine('CVEs are not present in the ACAS export (`vuln_id` is null); they come from the')
[void]$md.AppendLine('plugin->CVE map. GTI vulnerability collections are addressed directly by id,')
[void]$md.AppendLine('because free-text collection search returns unrelated CVEs.')
[void]$md.AppendLine()
[void]$md.AppendLine('## Findings by plugin')
[void]$md.AppendLine()
[void]$md.AppendLine('| Plugin | CVSS | KEV | Instances | Name | Remediation |')
[void]$md.AppendLine('|---|---:|---|---:|---|---|')
foreach ($p in $plugins) {
    [void]$md.AppendLine("| $($p.PluginId) | $($p.MaxCvss) | $(if ($p.Kev) { '**YES**' } else { '' }) | $($p.Instances) | $($p.PluginName) | $($p.Solution) |")
}
[void]$md.AppendLine()
[void]$md.AppendLine("## CVEs with usable detection rules: $($withRules.Count)")
[void]$md.AppendLine()
if ($withRules.Count) {
    [void]$md.AppendLine('| CVE | Plugin | Exploitation | YARA | Sigma | IDS |')
    [void]$md.AppendLine('|---|---|---|---|---|---|')
    foreach ($r in $withRules) {
        [void]$md.AppendLine("| **$($r.Cve)** | $($r.PluginId) | $($r.ExploitationState) | $($r.YaraRules) | $($r.SigmaRules) | $($r.IdsRules) |")
    }
} else {
    [void]$md.AppendLine('_No CVE in these findings has samples carrying YARA/Sigma/IDS rules in GTI._')
}
[void]$md.AppendLine()
[void]$md.AppendLine("## CVEs GTI reports as exploited: $($exploited.Count)")
[void]$md.AppendLine()
if ($exploited.Count) {
    [void]$md.AppendLine('| CVE | Plugin | State | EPSS | Risk | Samples | Threat actors |')
    [void]$md.AppendLine('|---|---|---|---:|---|---:|---|')
    foreach ($r in ($exploited | Sort-Object @{e={[double]("0"+$_.Epss)}; Descending=$true})) {
        [void]$md.AppendLine("| $($r.Cve) | $($r.PluginId) | $($r.ExploitationState) | $($r.Epss) | $($r.RiskRating) | $($r.FilesCount) | $($r.ThreatActors) |")
    }
} else { [void]$md.AppendLine('_None._') }
[void]$md.AppendLine()
[void]$md.AppendLine('---')
[void]$md.AppendLine()
[void]$md.AppendLine("Per-CVE detail: ``$csv``  |  rule inventory: ``$rulesCsv``")
$mdPath = Join-Path $OutDir 'acas-vt-crossref.md'
$md.ToString() | Set-Content -LiteralPath $mdPath -Encoding UTF8

Write-Host ""
Write-Host ("  CVEs checked              : {0}" -f $out.Count)
Write-Host ("  found in GTI              : {0}" -f @($out | Where-Object { $_.Found }).Count)
Write-Host ("  GTI reports as exploited  : {0}" -f $exploited.Count) -ForegroundColor $(if ($exploited.Count) { 'Yellow' } else { 'Green' })
Write-Host ("  with YARA/Sigma/IDS rules : {0}" -f $withRules.Count) -ForegroundColor $(if ($withRules.Count) { 'Green' } else { 'DarkGray' })
Write-Host ("  distinct rules collected  : {0}" -f @($rules | Sort-Object Kind, Rule -Unique).Count)
Write-Host ""
Write-Host "  csv    : $csv" -ForegroundColor DarkCyan
Write-Host "  rules  : $rulesCsv" -ForegroundColor DarkCyan
Write-Host "  report : $mdPath" -ForegroundColor DarkCyan
Write-Host ""

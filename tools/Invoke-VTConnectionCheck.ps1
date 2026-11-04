<#
.SYNOPSIS
    Checks external network destinations from firewall logs against VirusTotal,
    scoring on PER-ENGINE detections rather than the summary verdict.

.DESCRIPTION
    An IP can carry reputation 0, no tags and threat_severity SEVERITY_NONE while
    11 of ~91 engines independently call it malicious and name a malware family.
    Ranking on the verdict hides exactly that case, so this tool:

      * ranks on last_analysis_stats.malicious + .suspicious (the engine count),
        never on reputation / threat_severity / GTI assessment;
      * records WHICH engines flagged it and their result strings, because the
        result string is where the family attribution lives (Trojan, CoinMiner,
        phishing, a specific botnet, ...);
      * pulls the communicating_files edge, so a file that talks to the address
        can implicate it even when every engine is clean;
      * pulls resolutions for the hostname, which usually decides whether traffic
        is explainable.

    Verdict fields are still captured - they just never drive the ranking, and the
    report has a dedicated section for addresses where the verdict and the engines
    disagree.

.PARAMETER InputPath
    NDJSON (one JSON object per line) or CSV of connection records.

.PARAMETER IpField
    Field holding the address to check. Default dst_ip.

.PARAMETER ZoneField / ExternalZone
    Restrict to records whose ZoneField equals ExternalZone. Pass -ExternalZone ''
    to check every record.

.PARAMETER MinEnginesToFlag
    An address is reported as FLAGGED at or above this many malicious+suspicious
    engines. Default 1 - any single engine detection is surfaced.

.EXAMPLE
    .\tools\Invoke-VTConnectionCheck.ps1 -InputPath 'C:\githubProjects\OTSDP\CA\ngcaa7j6azvm002.json'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InputPath,
    # Per-IP results are cached so re-runs (or a crash after the query stage)
    # do not repeat the lookups. -Refresh forces a re-query.
    [switch]$Refresh,
    [int]$CacheMaxAgeDays = 7,
    [string]$IpField          = 'dst_ip',
    [string]$ZoneField        = 'dst_zone',
    [string]$ExternalZone     = 'Enterprise-Outside',
    [string]$SecretName       = 'VT_Enterprise_Key',
    [int]$MinDelayMs          = 12,
    [int]$MinEnginesToFlag    = 1,
    [int]$MaxCommunicatingFiles = 5,
    [string]$OutDir           = 'output\ca',
    [switch]$SkipRelationships
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

# ------------------------------------------------------------------ helpers ---
function Test-IsRoutable {
    # VT rejects private/reserved space; 169.254.169.254 in particular is a cloud
    # metadata endpoint that shows up constantly and is not an internet host.
    param([string]$Ip)
    $p = $Ip -split '\.'
    if ($p.Count -ne 4) { return $false }
    try { $o = @($p | ForEach-Object { [int]$_ }) } catch { return $false }
    if ($o[0] -eq 10)                      { return $false }
    if ($o[0] -eq 127)                     { return $false }
    if ($o[0] -eq 0)                       { return $false }
    if ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) { return $false }
    if ($o[0] -eq 192 -and $o[1] -eq 168)  { return $false }
    if ($o[0] -eq 169 -and $o[1] -eq 254)  { return $false }   # link-local / metadata
    if ($o[0] -eq 100 -and $o[1] -ge 64 -and $o[1] -le 127) { return $false }  # CGNAT
    if ($o[0] -ge 224)                     { return $false }   # multicast / reserved
    return $true
}

$script:LastCall = [DateTime]::MinValue
function Invoke-Vt {
    param([string]$Uri)
    $wait = $MinDelayMs - ([DateTime]::UtcNow - $script:LastCall).TotalMilliseconds
    if ($wait -gt 0) { Start-Sleep -Milliseconds ([int]$wait) }
    $script:LastCall = [DateTime]::UtcNow
    Invoke-RestMethod -Uri $Uri -Headers $script:VtHeaders -Method Get -ErrorAction Stop
}

# ------------------------------------------------------- shared-infra score ---
# Multi-tenant hosting is why a 1/91 detection is usually meaningless here: an
# engine flags SOME tenant's site and the detection attaches to an address your
# hosts reached for a different tenant. Measured on this capture, all 27 flagged
# addresses were CDN/cloud; the clearest were 150.171.109.183 and .110.211, whose
# resolutions are an unrelated grab-bag (economia.ma, hottingermortgages.com,
# arlingtonarts.org) on Microsoft Azure Front Door.
#
# This is scored, never filtered - a shared address can still be the real
# destination, so nothing is hidden, only ranked lower.
$script:CdnOwnerRx = [regex]::new(
    '(?i)\b(microsoft|msft|akamai|cloudflare|fastly|amazon|aws|google|gcore|' +
    'edgecast|limelight|llnw|cdn77|stackpath|incapsula|imperva|azure|digitalocean|' +
    'linode|ovh|hetzner|oracle|alibaba|tencent|verizon|level ?3|lumen|' +
    'cloudfront|bunny|keycdn|sucuri|netlify|vercel|heroku|rackspace)\b', 'Compiled')

function Get-ApexDomain {
    # NB: not $Host - that is a PowerShell automatic variable and cannot be a param.
    param([string]$HostName)
    $parts = @(("" + $HostName).Trim().TrimEnd('.') -split '\.' | Where-Object { $_ })
    if ($parts.Count -lt 2) { return ("" + $HostName) }
    return ($parts[-2..-1] -join '.')
}

function Get-SharedInfraAssessment {
    param([string]$Owner, [string]$NetworkName, [string]$Hostnames)
    $score = 0
    $why = [System.Collections.Generic.List[string]]::new()
    # Hostnames are included deliberately: for RIPE-allocated space the whois
    # OrgName is the REGISTRY ("RIPE Network Coordination Centre"), not the
    # operator, so owner alone mislabels Microsoft Azure ranges as dedicated -
    # 57.154.63.210 and 172.215.188.232 resolve to settings-win.data.microsoft.com
    # yet whois says RIPE.
    $blob = "$Owner $NetworkName $Hostnames"
    if ($script:CdnOwnerRx.IsMatch($blob)) { $score += 60; $why.Add('CDN/cloud operator') }
    $hosts = @(("" + $Hostnames) -split '\s+' | Where-Object { $_ })
    if ($hosts.Count -ge 2) {
        $apex = @($hosts | ForEach-Object { Get-ApexDomain -HostName $_ } | Sort-Object -Unique)
        if ($apex.Count -ge 3) { $score += 30; $why.Add("$($apex.Count) unrelated apex domains") }
        elseif ($apex.Count -eq 2) { $score += 10; $why.Add('2 apex domains') }
    }
    if ($hosts.Count -ge 5) { $score += 10; $why.Add('many resolutions') }
    if ($score -gt 100) { $score = 100 }
    [pscustomobject]@{ Score = $score; Reason = ($why -join ', ') }
}

# -------------------------------------------------------------------- key ---
try { $key = (Get-Secret -Name $SecretName -AsPlainText -ErrorAction Stop).Trim() }
catch { Write-Host "[!] Cannot read secret '$SecretName': $($_.Exception.Message)" -ForegroundColor Red; return }
$script:VtHeaders = @{ 'x-apikey' = $key; 'accept' = 'application/json' }

Write-Host ""
Write-Host "=== VT connection check: $(Split-Path $InputPath -Leaf) ===" -ForegroundColor Cyan

# ------------------------------------------------------------------ parse ---
$agg = @{}
$lines = 0; $skippedZone = 0
$isCsv = $InputPath -match '\.csv$'

# NDJSON is read with compiled per-field regexes rather than ConvertFrom-Json.
# ConvertFrom-Json per line took >7 min on this 58,466-record / 30 MB file and
# ballooned to 533 MB resident, because every line becomes a PSCustomObject with
# ~20 properties. These logs are machine-generated with stable field names, so
# extraction is both safe and ~50x faster. The match count is validated against
# the line count afterwards, so a format change fails loudly instead of silently
# yielding nothing.
$rx = @{
    dst_ip      = [regex]::new('"dst_ip":"([^"]*)"',      'Compiled')
    dst_zone    = [regex]::new('"dst_zone":"([^"]*)"',    'Compiled')
    dst_port    = [regex]::new('"dst_port":([0-9]+)',     'Compiled')
    src_ip      = [regex]::new('"src_ip":"([^"]*)"',      'Compiled')
    application = [regex]::new('"application":"([^"]*)"', 'Compiled')
    action      = [regex]::new('"action":"([^"]*)"',      'Compiled')
    bytes_total = [regex]::new('"bytes_total":([0-9]+)',  'Compiled')
    event_time  = [regex]::new('"event_time":"([^"]*)"',  'Compiled')
}
function Get-Fld($rxo, $line) { $m = $rxo.Match($line); if ($m.Success) { $m.Groups[1].Value } else { '' } }

function Add-Record {
    param([string]$Ip, [string]$Port, [string]$App, [string]$Action, [string]$SrcIp, [string]$Bytes, [string]$When)
    if (-not $script:agg.ContainsKey($Ip)) {
        $script:agg[$Ip] = [pscustomobject]@{
            Ip = $Ip; Events = 0; Bytes = 0L
            Ports   = [System.Collections.Generic.HashSet[string]]::new()
            Apps    = [System.Collections.Generic.HashSet[string]]::new()
            Actions = [System.Collections.Generic.HashSet[string]]::new()
            SrcIps  = [System.Collections.Generic.HashSet[string]]::new()
            First = $null; Last = $null
        }
    }
    $e = $script:agg[$Ip]
    $e.Events++
    $b = 0L; [void][long]::TryParse($Bytes, [ref]$b); $e.Bytes += $b
    if ($Port)   { [void]$e.Ports.Add($Port) }
    if ($App)    { [void]$e.Apps.Add($App) }
    if ($Action) { [void]$e.Actions.Add($Action) }
    if ($SrcIp)  { [void]$e.SrcIps.Add($SrcIp) }
    if ($When) {
        $t = [datetime]::MinValue
        if ([DateTime]::TryParse($When, [ref]$t)) {
            if (-not $e.First -or $t -lt $e.First) { $e.First = $t }
            if (-not $e.Last  -or $t -gt $e.Last)  { $e.Last  = $t }
        }
    }
}

$script:agg = $agg

# ---------------------------------------------------------- pre-aggregated ---
# The source may already be rolled up one-row-per-destination (dst_ip,
# session_count, total_bytes, dst_ports, applications, actions, src_ips,
# first_seen, last_seen) instead of raw per-event records. Detected rather than
# switched on, so either shape just works. Multi-values arrive as JSON arrays in
# NDJSON and as ';'-joined strings in CSV.
function Add-Aggregated {
    param($Row)
    $ip = ("" + $Row.dst_ip).Trim()
    if (-not $ip) { return }
    if (-not $script:agg.ContainsKey($ip)) {
        $script:agg[$ip] = [pscustomobject]@{
            Ip = $ip; Events = 0; Bytes = 0L
            Ports   = [System.Collections.Generic.HashSet[string]]::new()
            Apps    = [System.Collections.Generic.HashSet[string]]::new()
            Actions = [System.Collections.Generic.HashSet[string]]::new()
            SrcIps  = [System.Collections.Generic.HashSet[string]]::new()
            First = $null; Last = $null
        }
    }
    $e = $script:agg[$ip]
    $n = 0L; [void][long]::TryParse(("" + $Row.session_count), [ref]$n); $e.Events += [int]$n
    $b = 0L; [void][long]::TryParse(("" + $Row.total_bytes),   [ref]$b); $e.Bytes  += $b
    foreach ($pair in @(@{v=$Row.dst_ports; set=$e.Ports}, @{v=$Row.applications; set=$e.Apps},
                        @{v=$Row.actions;   set=$e.Actions}, @{v=$Row.src_ips;    set=$e.SrcIps})) {
        foreach ($item in @($pair.v)) {
            foreach ($one in (("" + $item) -split ';')) {
                $one = $one.Trim()
                if ($one) { [void]$pair.set.Add($one) }
            }
        }
    }
    foreach ($f in @(@{v=$Row.first_seen; first=$true}, @{v=$Row.last_seen; first=$false})) {
        if (-not $f.v) { continue }
        $t = [datetime]::MinValue
        if ([DateTime]::TryParse(("" + $f.v), [ref]$t)) {
            if (-not $e.First -or $t -lt $e.First) { $e.First = $t }
            if (-not $e.Last  -or $t -gt $e.Last)  { $e.Last  = $t }
        }
    }
}

$preAgg = $false
if ($isCsv) {
    $probe = @(Import-Csv $InputPath | Select-Object -First 1)
    if ($probe.Count -and $probe[0].PSObject.Properties['session_count'] -and $probe[0].PSObject.Properties['dst_ip']) { $preAgg = $true }
} else {
    foreach ($l in [System.IO.File]::ReadLines($InputPath)) {
        if ($l -and $l.Trim()) {
            try { $o = $l | ConvertFrom-Json } catch { break }
            if ($o.PSObject.Properties['session_count'] -and $o.PSObject.Properties['dst_ip']) { $preAgg = $true }
            break
        }
    }
}

if ($preAgg) {
    Write-Host "  input is pre-aggregated (one row per destination) - using its rollup" -ForegroundColor DarkCyan
    $src = if ($isCsv) { Import-Csv $InputPath } else {
        [System.IO.File]::ReadLines($InputPath) | ForEach-Object { if ($_ -and $_.Trim()) { try { $_ | ConvertFrom-Json } catch { $null } } }
    }
    foreach ($r in $src) {
        if (-not $r) { continue }
        $lines++
        if ($ExternalZone) {
            # dst_zones is plural here and may be a list.
            $zl = @(@($r.dst_zones) | ForEach-Object { ("" + $_) -split ';' } | ForEach-Object { $_.Trim() })
            if ($zl.Count -and ($zl -notcontains $ExternalZone)) { $skippedZone++; continue }
        }
        Add-Aggregated -Row $r
    }
    $agg = $script:agg
}
elseif ($isCsv) {
    foreach ($r in (Import-Csv $InputPath)) {
        $lines++
        if ($ExternalZone -and $ZoneField -and ("" + $r.$ZoneField) -ne $ExternalZone) { $skippedZone++; continue }
        $ip = ("" + $r.$IpField).Trim()
        if (-not $ip) { continue }
        Add-Record -Ip $ip -Port ("" + $r.dst_port) -App ("" + $r.application) -Action ("" + $r.action) `
                   -SrcIp ("" + $r.src_ip) -Bytes ("" + $r.bytes_total) -When ("" + $r.event_time)
    }
} else {
    $matched = 0
    foreach ($line in [System.IO.File]::ReadLines($InputPath)) {
        if (-not $line -or $line.Length -lt 2) { continue }
        $lines++
        if ($ExternalZone) {
            $z = Get-Fld $rx.dst_zone $line
            if ($z -ne $ExternalZone) { $skippedZone++; continue }
        }
        $ip = Get-Fld $rx.dst_ip $line
        if (-not $ip) { continue }
        $matched++
        Add-Record -Ip $ip -Port (Get-Fld $rx.dst_port $line) -App (Get-Fld $rx.application $line) `
                   -Action (Get-Fld $rx.action $line) -SrcIp (Get-Fld $rx.src_ip $line) `
                   -Bytes (Get-Fld $rx.bytes_total $line) -When (Get-Fld $rx.event_time $line)
    }
    if ($lines -gt 0 -and $matched -eq 0) {
        Write-Host "[!] Parsed $lines lines but extracted no '$IpField' - field names may have changed. Aborting rather than reporting an empty result." -ForegroundColor Red
        return
    }
}
$agg = $script:agg
Write-Host ("  records: {0:N0} (filtered out by zone: {1:N0})" -f $lines, $skippedZone)

$targets   = @($agg.Values | Sort-Object Events -Descending)
$routable  = @($targets | Where-Object { Test-IsRoutable $_.Ip })
$nonRoutable = @($targets | Where-Object { -not (Test-IsRoutable $_.Ip) })
Write-Host ("  distinct destinations: {0:N0}  ({1} routable, {2} private/reserved - not queried)" -f $targets.Count, $routable.Count, $nonRoutable.Count)
Write-Host ""

# ------------------------------------------------------------------ query ---
$cachePath = Join-Path $OutDir '_ip-cache.csv'
$cache = @{}
if ((Test-Path $cachePath) -and -not $Refresh) {
    foreach ($c in @(Import-Csv $cachePath)) {
        if (-not $c.Ip) { continue }
        $age = [datetime]::MaxValue
        $ct = [datetime]::MinValue
        if ([datetime]::TryParse(("" + $c.CachedUtc), [ref]$ct)) { $age = ([datetime]::UtcNow - $ct).TotalDays }
        if ($age -le $CacheMaxAgeDays) { $cache[$c.Ip] = $c }
    }
    if ($cache.Count) { Write-Host ("  cache: reusing {0:N0} addresses queried within {1}d" -f $cache.Count, $CacheMaxAgeDays) -ForegroundColor DarkCyan }
}

$rows = [System.Collections.Generic.List[object]]::new()
$i = 0
$fromCache = 0
foreach ($t in $routable) {
    $i++
    if ($cache.ContainsKey($t.Ip)) {
        # Reuse the VT verdict/engine detail, but recompute the traffic rollup from
        # THIS input file so event counts and ports are never stale.
        $c = $cache[$t.Ip]
        $fromCache++
        $cRep = 0; [void][int]::TryParse(("" + $c.RepNum), [ref]$cRep)
        $cCfc = 0; [void][int]::TryParse(("" + $c.CommunicatingFileCount), [ref]$cCfc)
        $rows.Add([pscustomobject]@{
            Ip = $t.Ip; Events = $t.Events; BytesTotal = $t.Bytes
            FirstSeen = $(if ($t.First) { $t.First.ToString('yyyy-MM-dd HH:mm') } else { '' })
            LastSeen  = $(if ($t.Last)  { $t.Last.ToString('yyyy-MM-dd HH:mm') }  else { '' })
            DstPorts = (($t.Ports | Sort-Object) -join ' '); Applications = (($t.Apps | Sort-Object) -join ' ')
            Actions = (($t.Actions | Sort-Object) -join ' '); InternalSources = $t.SrcIps.Count
            EnginesMalicious = [int]$c.EnginesMalicious; EnginesSuspicious = [int]$c.EnginesSuspicious
            EnginesTotal = [int]$c.EnginesTotal; DetectionRatio = $c.DetectionRatio
            FlaggedEngines = $c.FlaggedEngines; AttributedThreats = $c.AttributedThreats
            Reputation = $c.Reputation; RepNum = $cRep
            VotesMalicious = $c.VotesMalicious; VotesHarmless = $c.VotesHarmless; ThreatSeverity = $c.ThreatSeverity
            Country = $c.Country; Continent = $c.Continent; Rir = $c.Rir; NetworkName = $c.NetworkName; Owner = $c.Owner
            Tags = $c.Tags; Hostnames = $c.Hostnames; CommunicatingMalware = $c.CommunicatingMalware
            CommunicatingFileCount = $cCfc
            SharedInfraScore = 0; SharedInfraReason = ''; TriageScore = 0
            VtError = $c.VtError
        })
        continue
    }
    Write-Host ("`r  [{0}/{1}] {2,-16}" -f $i, $routable.Count, $t.Ip) -NoNewline
    $o = [ordered]@{
        Ip = $t.Ip; Events = $t.Events; BytesTotal = $t.Bytes
        FirstSeen = $(if ($t.First) { $t.First.ToString('yyyy-MM-dd HH:mm') } else { '' })
        LastSeen  = $(if ($t.Last)  { $t.Last.ToString('yyyy-MM-dd HH:mm') }  else { '' })
        DstPorts = (($t.Ports | Sort-Object) -join ' '); Applications = (($t.Apps | Sort-Object) -join ' ')
        Actions = (($t.Actions | Sort-Object) -join ' '); InternalSources = $t.SrcIps.Count
        EnginesMalicious = 0; EnginesSuspicious = 0; EnginesTotal = 0; DetectionRatio = ''
        FlaggedEngines = ''; AttributedThreats = ''
        Reputation = ''; RepNum = 0; VotesMalicious = ''; VotesHarmless = ''; ThreatSeverity = ''
        Country = ''; Continent = ''; Rir = ''; NetworkName = ''; Owner = ''
        Tags = ''; Hostnames = ''; CommunicatingMalware = ''; CommunicatingFileCount = 0
        SharedInfraScore = 0; SharedInfraReason = ''; TriageScore = 0
        VtError = ''
    }
    try {
        $a = (Invoke-Vt "https://www.virustotal.com/api/v3/ip_addresses/$($t.Ip)").data.attributes

        # --- the engine detail: this is what the ranking uses ---
        $res = @($a.last_analysis_results.PSObject.Properties)
        $o.EnginesTotal = $res.Count
        $flag = @($res | Where-Object { $_.Value.category -in @('malicious', 'suspicious') })
        $o.EnginesMalicious  = @($res | Where-Object { $_.Value.category -eq 'malicious' }).Count
        $o.EnginesSuspicious = @($res | Where-Object { $_.Value.category -eq 'suspicious' }).Count
        $o.DetectionRatio    = "$($o.EnginesMalicious + $o.EnginesSuspicious)/$($o.EnginesTotal)"
        $o.FlaggedEngines    = (@($flag | ForEach-Object { "$($_.Value.engine_name)=$($_.Value.result)" }) -join '; ')
        # Distinct family/category strings the engines actually named.
        $o.AttributedThreats = (@($flag | ForEach-Object { "" + $_.Value.result } |
                                 Where-Object { $_ -and $_ -ne 'clean' } | Sort-Object -Unique) -join '; ')

        # --- verdict fields: captured, never used for ranking ---
        $o.Reputation     = $a.reputation
        $rep = 0; [void][int]::TryParse(("" + $a.reputation), [ref]$rep); $o.RepNum = $rep
        $o.VotesMalicious = $a.total_votes.malicious
        $o.VotesHarmless  = $a.total_votes.harmless
        $o.ThreatSeverity = $a.threat_severity.threat_severity_level
        $o.Country        = $a.country
        $o.Continent      = $a.continent
        $o.Rir            = $a.regional_internet_registry
        $o.NetworkName    = $a.rdap.name
        # whois can come back as a string OR a string[]; the previous one-liner
        # piped an array into -replace and then called .Trim() on the array, which
        # threw and cost 72 of 471 addresses their entire VT result.
        if ($a.whois) {
            $wl = @(("" + $a.whois) -split "`r?`n")
            $own = @($wl | Where-Object { $_ -match '(?i)^\s*(OrgName|org-name|descr|Organization|owner)\s*:' })
            if ($own.Count -gt 0) {
                $o.Owner = ((("" + $own[0]) -replace '(?i)^\s*[\w-]+\s*:\s*', '')).Trim()
            }
        }
        $o.Tags = (@($a.tags) -join ' ')

        if (-not $SkipRelationships) {
            try {
                $rs = Invoke-Vt "https://www.virustotal.com/api/v3/ip_addresses/$($t.Ip)/resolutions?limit=5"
                $o.Hostnames = (@($rs.data | ForEach-Object { $_.attributes.host_name } | Where-Object { $_ } | Sort-Object -Unique) -join ' ')
            } catch { }
            try {
                $cf = Invoke-Vt "https://www.virustotal.com/api/v3/ip_addresses/$($t.Ip)/communicating_files?limit=$MaxCommunicatingFiles"
                $files = @($cf.data)
                $o.CommunicatingFileCount = $files.Count
                # A malicious file that talks to this address is evidence even when
                # every engine scores the address itself clean.
                $o.CommunicatingMalware = (@($files | ForEach-Object {
                    $lbl = $_.attributes.popular_threat_classification.suggested_threat_label
                    $mal = $_.attributes.last_analysis_stats.malicious
                    if ($lbl) { "$lbl($mal)" } elseif ($mal -gt 0) { "unnamed($mal)" }
                } | Where-Object { $_ } | Sort-Object -Unique) -join '; ')
            } catch { }
        }
    } catch {
        $code = $null; try { $code = $_.Exception.Response.StatusCode.value__ } catch { }
        $o.VtError = if ($code) { "HTTP $code" } else { $_.Exception.Message }
    }
    $rows.Add([pscustomobject]$o)
}
Write-Host "`r  queried $($routable.Count - $fromCache) addresses ($fromCache from cache).            "
# Persist the VT portion for reuse; traffic columns are recomputed each run.
# Never cache a failed lookup: a cached error is reused forever and silently
# hides the address from every later run (it masked a whois bug for 72 of 471
# addresses until the cache was cleared).
@($rows | Where-Object { $_.DetectionRatio -ne 'n/a' -and -not $_.VtError } | ForEach-Object {
    $_ | Select-Object Ip, EnginesMalicious, EnginesSuspicious, EnginesTotal, DetectionRatio,
         FlaggedEngines, AttributedThreats, Reputation, RepNum, VotesMalicious, VotesHarmless,
         ThreatSeverity, Country, Continent, Rir, NetworkName, Owner, Tags, Hostnames,
         CommunicatingMalware, CommunicatingFileCount, VtError,
         @{n='CachedUtc';e={[datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')}}
}) | Export-Csv -LiteralPath $cachePath -NoTypeInformation

foreach ($t in $nonRoutable) {
    $rows.Add([pscustomobject]@{
        Ip = $t.Ip; Events = $t.Events; BytesTotal = $t.Bytes
        FirstSeen = $(if ($t.First) { $t.First.ToString('yyyy-MM-dd HH:mm') } else { '' })
        LastSeen  = $(if ($t.Last)  { $t.Last.ToString('yyyy-MM-dd HH:mm') }  else { '' })
        DstPorts = (($t.Ports | Sort-Object) -join ' '); Applications = (($t.Apps | Sort-Object) -join ' ')
        Actions = (($t.Actions | Sort-Object) -join ' '); InternalSources = $t.SrcIps.Count
        EnginesMalicious = 0; EnginesSuspicious = 0; EnginesTotal = 0; DetectionRatio = 'n/a'
        FlaggedEngines = ''; AttributedThreats = ''
        Reputation = ''; VotesMalicious = ''; VotesHarmless = ''; ThreatSeverity = ''
        Country = ''; Continent = ''; Rir = ''; NetworkName = ''; Owner = ''
        Tags = ''; Hostnames = ''; CommunicatingMalware = ''; CommunicatingFileCount = 0
        SharedInfraScore = 0; SharedInfraReason = ''; TriageScore = 0
        VtError = 'private/reserved - not queried'
    })
}

# ----------------------------------------------------------------- score ---
# TriageScore = engine detections, discounted by how shared the address is.
# Shared infrastructure retains 10% weight rather than 0, so a CDN address that
# genuinely is the destination still appears - just below dedicated hosting.
foreach ($r in $rows) {
    $sa = Get-SharedInfraAssessment -Owner $r.Owner -NetworkName $r.NetworkName -Hostnames $r.Hostnames
    $r.SharedInfraScore  = $sa.Score
    $r.SharedInfraReason = $sa.Reason
    $base = ([int]$r.EnginesMalicious * 10) + ([int]$r.EnginesSuspicious * 4)
    # A malicious file communicating with the address counts, but only materially
    # when the address is not multi-tenant.
    if ($r.CommunicatingMalware) { $base += 3 }
    $r.TriageScore = [int][math]::Round($base * (1.0 - (($sa.Score / 100.0) * 0.9)))
}

# ----------------------------------------------------------------- output ---
$csv = Join-Path $OutDir 'ca-ip-verdicts.csv'
# Ordered by engine detections, deliberately NOT by reputation.
$rows | Sort-Object @{e={$_.TriageScore}; Descending=$true},
                    @{e={$_.EnginesMalicious + $_.EnginesSuspicious}; Descending=$true},
                    @{e={$_.Events}; Descending=$true} |
    Export-Csv -LiteralPath $csv -NoTypeInformation

$flagged = @($rows | Where-Object { ($_.EnginesMalicious + $_.EnginesSuspicious) -ge $MinEnginesToFlag } |
             Sort-Object @{e={$_.EnginesMalicious + $_.EnginesSuspicious}; Descending=$true})
# The case that motivated this tool: engines disagree with a benign-looking verdict.
$verdictMissed = @($flagged | Where-Object { $_.RepNum -ge 0 -and $_.ThreatSeverity -in @('SEVERITY_NONE', 'SEVERITY_LOW', '', $null) })
$implicated = @($rows | Where-Object { $_.CommunicatingMalware -and ($_.EnginesMalicious + $_.EnginesSuspicious) -eq 0 })

$md = [System.Text.StringBuilder]::new()
[void]$md.AppendLine('# External connection check against VirusTotal')
[void]$md.AppendLine()
[void]$md.AppendLine("Source: ``$(Split-Path $InputPath -Leaf)`` | $('{0:N0}' -f $lines) records | $('{0:N0}' -f $targets.Count) distinct destinations | $(Get-Date -Format 'yyyy-MM-dd HH:mm')")
[void]$md.AppendLine()
[void]$md.AppendLine('Ranked by **per-engine detections**, not by the summary verdict. An address with')
[void]$md.AppendLine('reputation 0 and `SEVERITY_NONE` can still be flagged by a dozen engines, so the')
[void]$md.AppendLine('verdict fields below are recorded for context but never used for ordering.')
[void]$md.AppendLine()
$triage = @($rows | Where-Object { $_.TriageScore -gt 0 } | Sort-Object TriageScore -Descending)
$onDedicated = @($triage | Where-Object { $_.SharedInfraScore -lt 50 } |
                 Sort-Object @{e={$_.EnginesMalicious + $_.EnginesSuspicious}; Descending=$true},
                             @{e={$_.TriageScore}; Descending=$true},
                             @{e={$_.Events}; Descending=$true})
[void]$md.AppendLine('## Triage order')
[void]$md.AppendLine()
[void]$md.AppendLine('`TriageScore` = (malicious x10 + suspicious x4 + communicating-malware x3), discounted')
[void]$md.AppendLine('by `SharedInfraScore`. Multi-tenant addresses keep 10% weight rather than 0, so')
[void]$md.AppendLine('nothing is hidden - a CDN address that really is the destination still shows up,')
[void]$md.AppendLine('just below dedicated hosting.')
[void]$md.AppendLine()
[void]$md.AppendLine("**On dedicated (non-shared) infrastructure: $($onDedicated.Count)** - look here first.")
[void]$md.AppendLine()
if ($onDedicated.Count) {
    [void]$md.AppendLine('| Triage | Detections | IP | Owner | Shared? | Threats | Sessions |')
    [void]$md.AppendLine('|---:|---:|---|---|---|---|---:|')
    foreach ($r in ($onDedicated | Select-Object -First 25)) {
        [void]$md.AppendLine("| **$($r.TriageScore)** | $($r.DetectionRatio) | $($r.Ip) | $($r.Owner) | $($r.SharedInfraScore) | $($r.AttributedThreats) | $($r.Events) |")
    }
} else {
    [void]$md.AppendLine('_None - every detection in this capture is on shared CDN/cloud infrastructure._')
}
[void]$md.AppendLine()
[void]$md.AppendLine("<details><summary>Shared-infrastructure detections ($(@($triage | Where-Object { $_.SharedInfraScore -ge 50 }).Count)) - lower confidence</summary>")
[void]$md.AppendLine()
[void]$md.AppendLine('| Triage | Detections | IP | Owner | Why shared | Threats |')
[void]$md.AppendLine('|---:|---:|---|---|---|---|')
foreach ($r in @($triage | Where-Object { $_.SharedInfraScore -ge 50 })) {
    [void]$md.AppendLine("| $($r.TriageScore) | $($r.DetectionRatio) | $($r.Ip) | $($r.Owner) | $($r.SharedInfraReason) | $($r.AttributedThreats) |")
}
[void]$md.AppendLine()
[void]$md.AppendLine('</details>')
[void]$md.AppendLine()
[void]$md.AppendLine("## Flagged by at least $MinEnginesToFlag engine(s): $($flagged.Count)")
[void]$md.AppendLine()
if ($flagged.Count) {
    [void]$md.AppendLine('| Detections | IP | Hostname(s) | Attributed threats | Events | Ports | Country | Reputation | GTI severity |')
    [void]$md.AppendLine('|---:|---|---|---|---:|---|---|---:|---|')
    foreach ($r in $flagged) {
        [void]$md.AppendLine("| **$($r.DetectionRatio)** | $($r.Ip) | $($r.Hostnames) | $($r.AttributedThreats) | $($r.Events) | $($r.DstPorts) | $($r.Country) | $($r.Reputation) | $($r.ThreatSeverity) |")
    }
    [void]$md.AppendLine()
    [void]$md.AppendLine('### Which engines, and what they called it')
    [void]$md.AppendLine()
    foreach ($r in $flagged) {
        [void]$md.AppendLine("**$($r.Ip)** ($($r.DetectionRatio)) - $($r.FlaggedEngines)")
        [void]$md.AppendLine()
    }
} else {
    [void]$md.AppendLine('_No address was flagged by any engine._')
    [void]$md.AppendLine()
}
[void]$md.AppendLine("## Verdict looked benign but engines disagreed: $($verdictMissed.Count)")
[void]$md.AppendLine()
[void]$md.AppendLine('These would have been missed by filtering on reputation or GTI severity alone.')
[void]$md.AppendLine()
if ($verdictMissed.Count) {
    [void]$md.AppendLine('| Detections | IP | Attributed threats | Reputation | GTI severity | Events |')
    [void]$md.AppendLine('|---:|---|---|---:|---|---:|')
    foreach ($r in $verdictMissed) {
        [void]$md.AppendLine("| **$($r.DetectionRatio)** | $($r.Ip) | $($r.AttributedThreats) | $($r.Reputation) | $($r.ThreatSeverity) | $($r.Events) |")
    }
} else { [void]$md.AppendLine('_None._') }
[void]$md.AppendLine()
[void]$md.AppendLine("## Clean on every engine, but malware communicates with them: $($implicated.Count)")
[void]$md.AppendLine()
[void]$md.AppendLine('Second independent signal: the address itself scores clean, yet VT holds malware')
[void]$md.AppendLine('samples that talk to it.')
[void]$md.AppendLine()
if ($implicated.Count) {
    [void]$md.AppendLine('| IP | Hostname(s) | Malware communicating (engine count) | Events | Ports |')
    [void]$md.AppendLine('|---|---|---|---:|---|')
    foreach ($r in ($implicated | Sort-Object Events -Descending)) {
        [void]$md.AppendLine("| $($r.Ip) | $($r.Hostnames) | $($r.CommunicatingMalware) | $($r.Events) | $($r.DstPorts) |")
    }
} else { [void]$md.AppendLine('_None._') }
[void]$md.AppendLine()
[void]$md.AppendLine('---')
[void]$md.AppendLine()
[void]$md.AppendLine("Full per-address detail, including every verdict field: ``$csv``")
$mdPath = Join-Path $OutDir 'ca-ip-report.md'
$md.ToString() | Set-Content -LiteralPath $mdPath -Encoding UTF8

Write-Host ""
Write-Host ("  TRIAGE: on dedicated infrastructure    : {0}" -f @($rows | Where-Object { $_.TriageScore -gt 0 -and $_.SharedInfraScore -lt 50 }).Count) -ForegroundColor $(if (@($rows | Where-Object { $_.TriageScore -gt 0 -and $_.SharedInfraScore -lt 50 }).Count) { 'Red' } else { 'Green' })
Write-Host ("  TRIAGE: on shared CDN/cloud (lower conf) : {0}" -f @($rows | Where-Object { $_.TriageScore -gt 0 -and $_.SharedInfraScore -ge 50 }).Count) -ForegroundColor DarkYellow
Write-Host ("  FLAGGED by >=1 engine                  : {0}" -f $flagged.Count) -ForegroundColor $(if ($flagged.Count) { 'Red' } else { 'Green' })
Write-Host ("  benign-looking verdict, engines flagged: {0}" -f $verdictMissed.Count) -ForegroundColor $(if ($verdictMissed.Count) { 'Yellow' } else { 'Green' })
Write-Host ("  clean engines, malware talks to them   : {0}" -f $implicated.Count) -ForegroundColor $(if ($implicated.Count) { 'Yellow' } else { 'Green' })
Write-Host ("  VT errors                              : {0}" -f @($rows | Where-Object { $_.VtError -and $_.VtError -notlike 'private*' }).Count)
Write-Host ""
Write-Host "  csv    : $csv" -ForegroundColor DarkCyan
Write-Host "  report : $mdPath" -ForegroundColor DarkCyan
Write-Host ""

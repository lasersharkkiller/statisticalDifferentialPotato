<#
.SYNOPSIS
    Harvests APT / malware intel from Google Threat Intelligence (GTI) curated
    collections into the existing <Actor>_Master_Intel.csv corpus.

.DESCRIPTION
    The older harvester in aptIocs.psm1 queried VT file search with
    threat_actor:"<name>" using a FREE key. That operator needs a paid tier, so
    every call failed - and the failure was invisible because the loop ended in a
    bare `catch {}`. With a GTI (gti-enterprise-plus) key the operator works, but
    the curated collections are far better than file search: each threat actor is
    an object carrying vendor-attributed aliases plus relationships to files,
    domains, IPs, URLs, MITRE techniques, malware families and campaigns.

    MITRE techniques are the reason this matters. The project's goal is detections
    as high on the Pyramid of Pain as possible, so an actor -> technique edge is
    worth far more than another hash.

    ATTRIBUTION SAFETY. GTI's collection filter does free-text matching, so
    searching "ELECTRUM" returns Sandworm even though Sandworm's alt_names do not
    contain Electrum. Writing that into the corpus would be a mis-attribution, so
    every candidate is validated: the search term must match the collection's
    name or one of its alt_names (normalised - vendor suffixes like
    "Magnallium (Dragos)" are stripped, case and punctuation folded). Unvalidated
    actors are reported, never guessed at.

.PARAMETER Actors
    Actor names to update. Default: every actor that already has a folder under
    apt\APTs\<Country>\<Actor>.

.PARAMETER MaxPerRelationship
    Cap on IOCs pulled per relationship per actor. APT44 alone has 4,319 files,
    2,076 IPs and 1,043 URLs, so an uncapped sweep across 286 actors is large.

.PARAMETER Relationships
    Which edges to harvest. Order matters only for log readability.

.PARAMETER ProfileOnly
    Write the GTI_PROFILE.md and alias-delta report, pull no IOCs.

.EXAMPLE
    # See what GTI knows and how its aliases compare, writing no IOCs
    Update-AptIntelFromGTI -ProfileOnly

.EXAMPLE
    Update-AptIntelFromGTI -Actors 'APT44','Volt Typhoon' -MaxPerRelationship 1000
#>

$script:GtiBase = 'https://www.virustotal.com/api/v3'

function Initialize-GtiClient {
    [CmdletBinding()]
    param([string]$SecretName = 'VT_Enterprise_Key', [int]$MinDelayMs = 12)

    try {
        $k = (Get-Secret -Name $SecretName -AsPlainText -ErrorAction Stop).Trim()
    } catch {
        Write-Host "[!] Could not read secret '$SecretName': $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
    if ([string]::IsNullOrWhiteSpace($k)) { Write-Host "[!] Secret '$SecretName' is empty." -ForegroundColor Red; return $false }

    $script:GtiHeaders    = @{ 'x-apikey' = $k; 'accept' = 'application/json' }
    $script:GtiMinDelayMs = $MinDelayMs
    $script:GtiLastCall   = [DateTime]::MinValue

    # Confirm the key really has the GTI privileges this module depends on,
    # rather than discovering it through empty result sets later.
    try {
        $u = Invoke-RestMethod -Uri "$script:GtiBase/users/$k" -Headers $script:GtiHeaders -ErrorAction Stop
        $priv = @($u.data.attributes.privileges.PSObject.Properties |
                  Where-Object { $_.Value.granted } | ForEach-Object { $_.Name })
        $need = @('collections', 'threat-actors', 'intelligence')
        $miss = @($need | Where-Object { $priv -notcontains $_ })
        if ($miss.Count) {
            Write-Host "[!] Key lacks required GTI privileges: $($miss -join ', ')" -ForegroundColor Red
            return $false
        }
        Write-Host "[GTI] key OK ($($priv.Count) privileges; collections + threat-actors granted)" -ForegroundColor Green
    } catch {
        Write-Host "[!] Privilege probe failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
    return $true
}

function Invoke-Gti {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Uri)

    $wait = $script:GtiMinDelayMs - ([DateTime]::UtcNow - $script:GtiLastCall).TotalMilliseconds
    if ($wait -gt 0) { Start-Sleep -Milliseconds ([int]$wait) }
    $script:GtiLastCall = [DateTime]::UtcNow
    Invoke-RestMethod -Uri $Uri -Headers $script:GtiHeaders -Method Get -ErrorAction Stop
}

function Get-GtiNameKey {
    # Fold a name for comparison: drop any vendor suffix in parentheses
    # ("Magnallium (Dragos)" -> "magnallium"), strip non-alphanumerics, lowercase.
    param([string]$Name)
    if (-not $Name) { return '' }
    ($Name -replace '\(.*?\)', '' -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
}

function Resolve-GtiActor {
    <#
      Returns the collection object only when the search term genuinely matches
      its name or an alt_name. See ATTRIBUTION SAFETY in the module header.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name, [string]$CollectionType = 'threat-actor')

    $filter = [Uri]::EscapeDataString("collection_type:$CollectionType $Name")
    try {
        $resp = Invoke-Gti "$script:GtiBase/collections?filter=$filter&limit=10"
    } catch {
        Write-Host ("    [ERROR] search failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
        return $null
    }
    if (-not $resp.data) { return $null }

    $want = Get-GtiNameKey $Name
    foreach ($cand in $resp.data) {
        $keys = @(Get-GtiNameKey $cand.attributes.name)
        foreach ($alt in @($cand.attributes.alt_names)) { $keys += Get-GtiNameKey $alt }
        if ($keys -contains $want) { return $cand }
    }
    # Nothing validated - report the near-misses so a human can judge.
    $near = @($resp.data | ForEach-Object { $_.attributes.name }) -join ', '
    Write-Host ("    [UNVALIDATED] '{0}' matched only: {1}" -f $Name, $near) -ForegroundColor DarkYellow
    return $null
}

function Resolve-GtiActorSmart {
    <#
      Resolve-GtiActor with the fallbacks that a real folder list needs. Measured
      on this repo's 98 folders: plain threat-actor lookup resolved 85. Of the 13
      misses, 4 resolve once you (a) try malware-family collections, because some
      folders track ransomware rather than an actor (BlackByte -> BLACKBYTE,
      "Play Ransomware" -> PLAY), and (b) normalise folder names that carry a
      suffix or a prefix ("Konni Group" -> UNC4531, "dev-1084_MuddyWater" ->
      MuddyWater). The remaining 8 are genuinely not in GTI.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    $variants = [System.Collections.Generic.List[string]]::new()
    $variants.Add($Name)
    if ($Name -match '_')                             { $variants.Add(($Name -split '_')[-1]) }
    if ($Name -match '(?i)\s+(Ransomware|Group|Gang|Team)$') { $variants.Add(($Name -replace '(?i)\s+(Ransomware|Group|Gang|Team)$', '')) }

    foreach ($v in ($variants | Select-Object -Unique)) {
        foreach ($ct in @('threat-actor', 'malware-family')) {
            $c = Resolve-GtiActor -Name $v -CollectionType $ct
            if ($c) {
                if ($v -ne $Name -or $ct -ne 'threat-actor') {
                    Write-Host ("    [fallback] matched as {0} via '{1}'" -f $ct, $v) -ForegroundColor DarkCyan
                }
                return $c
            }
        }
    }
    return $null
}

function Get-GtiRelationshipRows {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CollectionId,
        [Parameter(Mandatory)][string]$Relationship,
        [Parameter(Mandatory)][string]$ActorName,
        [int]$Max = 500
    )

    # NOTE: /collections/{id}/{rel} returns full objects; the /relationships/{rel}
    # form returns bare descriptors with no attributes at all.
    $rows = [System.Collections.Generic.List[object]]::new()
    $uri  = "$script:GtiBase/collections/$CollectionId/$Relationship`?limit=40"
    while ($uri -and $rows.Count -lt $Max) {
        try { $resp = Invoke-Gti $uri } catch {
            Write-Host ("      [ERROR] {0}: {1}" -f $Relationship, $_.Exception.Message) -ForegroundColor Red
            break
        }
        foreach ($o in @($resp.data)) {
            if ($rows.Count -ge $Max) { break }
            $a = $o.attributes
            $iocType = $null; $iocValue = $null; $context = ''; $link = ''
            $date = ''
            switch ($Relationship) {
                'files' {
                    $iocType = 'SHA256'; $iocValue = if ($a.sha256) { $a.sha256 } else { $o.id }
                    $nm = @($a.names) | Select-Object -First 2
                    $context = (@("type=$($a.type_description)") + @(if ($nm) { "names=$($nm -join '|')" }) +
                                @(if ($a.tags) { "tags=$((@($a.tags) | Select-Object -First 4) -join '|')" })) -join '; '
                    $link = "https://www.virustotal.com/gui/file/$iocValue"
                    if ($a.first_submission_date) { $date = [DateTimeOffset]::FromUnixTimeSeconds($a.first_submission_date).UtcDateTime.ToString('yyyy-MM-dd') }
                }
                'domains' {
                    $iocType = 'Domain'; $iocValue = $o.id
                    $context = "registrar=$($a.registrar); reputation=$($a.reputation)"
                    $link = "https://www.virustotal.com/gui/domain/$iocValue"
                }
                'ip_addresses' {
                    $iocType = 'IP'; $iocValue = $o.id
                    $context = "asn=$($a.asn); country=$($a.country); owner=$($a.as_owner)"
                    $link = "https://www.virustotal.com/gui/ip-address/$iocValue"
                }
                'urls' {
                    $iocType = 'URL'; $iocValue = if ($a.url) { $a.url } else { $o.id }
                    $context = "reputation=$($a.reputation)"
                    $link = "https://www.virustotal.com/gui/url/$($o.id)"
                    if ($a.first_submission_date) { $date = [DateTimeOffset]::FromUnixTimeSeconds($a.first_submission_date).UtcDateTime.ToString('yyyy-MM-dd') }
                }
                'attack_techniques' {
                    # Top of the Pyramid of Pain - the most valuable edge here.
                    $iocType = 'MitreTechnique'; $iocValue = $o.id
                    $context = "$($a.name)"
                    $link = if ($a.link) { $a.link } else { "https://attack.mitre.org/techniques/$($o.id)/" }
                }
                'malware_families' {
                    $iocType = 'MalwareFamily'; $iocValue = if ($a.name) { $a.name } else { $o.id }
                    $context = "collection=$($o.id)"
                    $link = "https://www.virustotal.com/gui/collection/$($o.id)"
                }
                'campaigns' {
                    $iocType = 'Campaign'; $iocValue = if ($a.name) { $a.name } else { $o.id }
                    $context = "collection=$($o.id)"
                    $link = "https://www.virustotal.com/gui/collection/$($o.id)"
                }
            }
            if (-not $iocType -or [string]::IsNullOrWhiteSpace($iocValue)) { continue }
            if (-not $date) { $date = (Get-Date).ToString('yyyy-MM-dd') }
            $rows.Add([PSCustomObject]@{
                Date = $date; Source = 'GTI'; Actor = $ActorName
                IOCType = $iocType; IOCValue = $iocValue; Context = $context; Link = $link
            })
        }
        $uri = $resp.links.next
    }
    return $rows
}

function Update-AptIntelFromGTI {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string[]]$Actors,
        [string]$SecretName         = 'VT_Enterprise_Key',
        [int]$MinDelayMs            = 12,
        [int]$MaxPerRelationship    = 500,
        [string[]]$Relationships    = @('attack_techniques', 'malware_families', 'campaigns',
                                        'files', 'domains', 'ip_addresses', 'urls'),
        [string]$AptRoot            = 'apt\APTs',
        [switch]$ProfileOnly
    )

    if (-not (Initialize-GtiClient -SecretName $SecretName -MinDelayMs $MinDelayMs)) { return }

    # Target set: existing actor folders, so this UPDATES the tracker rather than
    # inventing new taxonomy.
    $folders = @(Get-ChildItem $AptRoot -Directory -ErrorAction SilentlyContinue |
                 ForEach-Object { Get-ChildItem $_.FullName -Directory -ErrorAction SilentlyContinue })
    if ($Actors) {
        $want = @($Actors | ForEach-Object { Get-GtiNameKey $_ })
        $folders = @($folders | Where-Object { $want -contains (Get-GtiNameKey $_.Name) })
        $missing = @($Actors | Where-Object { $n = Get-GtiNameKey $_; -not ($folders | Where-Object { (Get-GtiNameKey $_.Name) -eq $n }) })
        foreach ($m in $missing) { Write-Host "[WARN] no folder under $AptRoot for '$m' - skipped" -ForegroundColor Yellow }
    }
    Write-Host ""
    Write-Host "=== GTI tracker update: $($folders.Count) actors ===" -ForegroundColor Cyan
    Write-Host ("    relationships: {0}" -f ($Relationships -join ', '))
    Write-Host ("    cap per relationship: {0:N0}{1}" -f $MaxPerRelationship, $(if ($ProfileOnly) { '  (ProfileOnly - no IOCs written)' } else { '' }))
    Write-Host ""

    # ---- PASS 1: resolve every actor before writing anything -----------------
    # Several local folders can legitimately be the same GTI actor (the repo has
    # both Russia\ELECTRUM and Russia\Sandworm, and GTI lists ELECTRUM as an
    # alt_name of Sandworm). Harvesting into both would duplicate every IOC, which
    # inflates the malicious-side M counts in the fidelity index. So resolve
    # first, group by collection, and write IOCs to one canonical folder per actor.
    Write-Host "--- pass 1: resolving actors ---" -ForegroundColor DarkCyan
    $resolved = [System.Collections.Generic.List[object]]::new()
    $i = 0
    foreach ($f in ($folders | Sort-Object FullName)) {
        $i++
        $actor   = $f.Name
        $country = Split-Path (Split-Path $f.FullName -Parent) -Leaf
        Write-Host ("  [{0}/{1}] {2}/{3}" -f $i, $folders.Count, $country, $actor) -NoNewline
        $col = Resolve-GtiActorSmart -Name $actor
        if ($col) {
            Write-Host (" -> {0}" -f $col.attributes.name) -ForegroundColor Green
        } else {
            Write-Host " -> (unresolved)" -ForegroundColor DarkGray
        }
        $resolved.Add([PSCustomObject]@{ Folder = $f; Actor = $actor; Country = $country; Col = $col })
    }

    # Group by GTI collection id and choose a canonical folder for each group.
    $groups  = @($resolved | Where-Object { $_.Col } | Group-Object { $_.Col.id })
    $canonical = @{}
    $aliasOf   = @{}
    foreach ($g in $groups) {
        if ($g.Count -eq 1) { $canonical[$g.Name] = $g.Group[0]; continue }
        $gtiKey = Get-GtiNameKey $g.Group[0].Col.attributes.name
        # Prefer the folder actually named like the GTI actor; otherwise the one
        # with the most existing intel, so the established file stays primary.
        $pick = @($g.Group | Where-Object { (Get-GtiNameKey $_.Actor) -eq $gtiKey }) | Select-Object -First 1
        if (-not $pick) {
            $pick = @($g.Group | Sort-Object {
                $c = Join-Path $_.Folder.FullName "$($_.Actor)_Master_Intel.csv"
                if (Test-Path $c) { -((Get-Item $c).Length) } else { 0 }
            }) | Select-Object -First 1
        }
        $canonical[$g.Name] = $pick
        foreach ($other in @($g.Group | Where-Object { $_.Folder.FullName -ne $pick.Folder.FullName })) {
            $aliasOf[$other.Folder.FullName] = $pick
        }
        Write-Host ("  [MERGE] GTI '{0}' maps to {1} local folders: {2} -> canonical '{3}'" -f `
            $g.Group[0].Col.attributes.name, $g.Count,
            (@($g.Group | ForEach-Object { "$($_.Country)/$($_.Actor)" }) -join ', '),
            $pick.Actor) -ForegroundColor Yellow
    }
    Write-Host ""

    $aliasDelta = [System.Collections.Generic.List[object]]::new()
    $summary    = [System.Collections.Generic.List[object]]::new()
    $n = 0

    Write-Host "--- pass 2: harvesting ---" -ForegroundColor DarkCyan
    foreach ($entry in $resolved) {
        $f = $entry.Folder
        $n++
        $actor   = $entry.Actor
        $country = $entry.Country
        Write-Host ("[{0}/{1}] {2} / {3}" -f $n, $resolved.Count, $country, $actor) -ForegroundColor Cyan

        $col = $entry.Col
        if (-not $col) {
            $summary.Add([PSCustomObject]@{ Actor = $actor; Country = $country; GtiName = ''; Resolved = $false; New = 0 })
            continue
        }
        # Non-canonical duplicate of another folder's actor: leave a pointer and
        # do not duplicate the IOC set.
        if ($aliasOf.ContainsKey($f.FullName)) {
            $primary = $aliasOf[$f.FullName]
            $note = Join-Path $f.FullName 'GTI_ALIAS_OF.md'
            $txt  = @(
                "# $actor is the same GTI actor as $($primary.Actor)",
                "",
                "GTI resolves both to collection **$($col.attributes.name)** (``$($col.id)``):",
                "$actor matches one of its alt_names.",
                "",
                "GTI-sourced IOCs are therefore written only to",
                "``$($primary.Country)/$($primary.Actor)/$($primary.Actor)_Master_Intel.csv``,",
                "to avoid duplicating every indicator across two files - which would",
                "double-count them on the malicious side of the fidelity index.",
                "",
                "This folder's own hand-seeded intel is left untouched; the separate folder",
                "is kept deliberately where the vendor taxonomies differ (see NOTES.md).",
                "",
                "Full GTI alt_names: $((@($col.attributes.alt_names) | Sort-Object) -join '; ')"
            ) -join "`n"
            if ($PSCmdlet.ShouldProcess($note, 'write alias pointer')) { $txt | Set-Content -LiteralPath $note -Encoding UTF8 }
            Write-Host ("    [ALIAS] same actor as {0} - IOCs go there; pointer written" -f $primary.Actor) -ForegroundColor DarkYellow
            $summary.Add([PSCustomObject]@{ Actor = $actor; Country = $country; GtiName = $col.attributes.name; Resolved = $true; New = 0 })
            continue
        }
        $a = $col.attributes
        Write-Host ("    -> {0}  files={1:N0} domains={2:N0} ips={3:N0} urls={4:N0}" -f $a.name, $a.files_count, $a.domains_count, $a.ip_addresses_count, $a.urls_count) -ForegroundColor Green

        # --- profile ---
        $prof = Join-Path $f.FullName 'GTI_PROFILE.md'
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine("# $actor - GTI profile")
        [void]$sb.AppendLine()
        [void]$sb.AppendLine("Generated $(Get-Date -Format 'yyyy-MM-dd') from Google Threat Intelligence curated collections.")
        [void]$sb.AppendLine("Matched GTI collection **$($a.name)** (`$($col.id)`), validated against name/alt_names.")
        [void]$sb.AppendLine()
        [void]$sb.AppendLine("| Field | Value |")
        [void]$sb.AppendLine("|---|---|")
        [void]$sb.AppendLine("| GTI name | $($a.name) |")
        [void]$sb.AppendLine("| Alt names | $((@($a.alt_names) | Sort-Object) -join '; ') |")
        [void]$sb.AppendLine("| Source region | $($a.source_region) |")
        [void]$sb.AppendLine("| Targeted regions | $((@($a.targeted_regions) | Select-Object -First 15) -join '; ') |")
        [void]$sb.AppendLine("| Targeted industries | $((@($a.targeted_industries) | Select-Object -First 15) -join '; ') |")
        [void]$sb.AppendLine("| Motivations | $((@($a.motivations) | Where-Object { $_ }) -join '; ') |")
        [void]$sb.AppendLine("| First / last seen | $($a.first_seen) / $($a.last_seen) |")
        [void]$sb.AppendLine("| Counters | files $($a.files_count); domains $($a.domains_count); ips $($a.ip_addresses_count); urls $($a.urls_count); refs $($a.references_count) |")
        [void]$sb.AppendLine()
        if ($a.description) {
            [void]$sb.AppendLine('## Description')
            [void]$sb.AppendLine()
            [void]$sb.AppendLine($a.description)
            [void]$sb.AppendLine()
        }
        if ($PSCmdlet.ShouldProcess($prof, 'write GTI profile')) {
            $sb.ToString() | Set-Content -LiteralPath $prof -Encoding UTF8
        }

        # --- alias delta vs what the repo already claims ---
        $aliasFile = Join-Path $f.FullName 'ALIASES.md'
        $aliasDelta.Add([PSCustomObject]@{
            Actor = $actor; Country = $country; GtiName = $a.name
            GtiAltNames = (@($a.alt_names) | Sort-Object) -join '; '
            HasLocalAliasDoc = (Test-Path $aliasFile)
        })

        if ($ProfileOnly) {
            $summary.Add([PSCustomObject]@{ Actor = $actor; Country = $country; GtiName = $a.name; Resolved = $true; New = 0 })
            continue
        }

        # --- IOCs ---
        $csv = Join-Path $f.FullName "$($actor)_Master_Intel.csv"
        $existing = @(if (Test-Path $csv) { Import-Csv $csv })
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($r in $existing) { [void]$seen.Add("$($r.IOCType)|$($r.IOCValue)") }

        $fresh = [System.Collections.Generic.List[object]]::new()
        foreach ($rel in $Relationships) {
            $got = Get-GtiRelationshipRows -CollectionId $col.id -Relationship $rel -ActorName $actor -Max $MaxPerRelationship
            $added = 0
            foreach ($r in $got) { if ($seen.Add("$($r.IOCType)|$($r.IOCValue)")) { $fresh.Add($r); $added++ } }
            if ($got.Count) { Write-Host ("      {0,-18} {1,5:N0} pulled, {2,5:N0} new" -f $rel, $got.Count, $added) }
        }

        if ($fresh.Count -gt 0) {
            if ($PSCmdlet.ShouldProcess($csv, "append $($fresh.Count) GTI rows")) {
                if (Test-Path $csv) {
                    $fresh | Export-Csv -LiteralPath $csv -Append -NoTypeInformation
                } else {
                    $fresh | Export-Csv -LiteralPath $csv -NoTypeInformation
                }
            }
            Write-Host ("    [+] {0:N0} new rows -> {1}" -f $fresh.Count, (Split-Path $csv -Leaf)) -ForegroundColor Green
        } else {
            Write-Host "    [=] nothing new" -ForegroundColor DarkGray
        }
        $summary.Add([PSCustomObject]@{ Actor = $actor; Country = $country; GtiName = $a.name; Resolved = $true; New = $fresh.Count })
    }

    # --- reports ---
    $outDir = 'output\gti'
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    $aliasDelta | Export-Csv -LiteralPath (Join-Path $outDir 'gti-actor-aliases.csv') -NoTypeInformation
    $summary    | Export-Csv -LiteralPath (Join-Path $outDir 'gti-update-summary.csv') -NoTypeInformation

    $res = @($summary | Where-Object { $_.Resolved })
    Write-Host ""
    Write-Host ("=== resolved {0}/{1} actors; {2:N0} new IOC rows ===" -f $res.Count, $summary.Count, (($summary | Measure-Object New -Sum).Sum)) -ForegroundColor Green
    Write-Host ("    unresolved: {0}" -f ((@($summary | Where-Object { -not $_.Resolved } | ForEach-Object { $_.Actor }) -join ', ')))
    Write-Host ("    reports: {0}" -f $outDir) -ForegroundColor DarkCyan
    Write-Host ""
}

Export-ModuleMember -Function Update-AptIntelFromGTI, Initialize-GtiClient, Resolve-GtiActor, Resolve-GtiActorSmart

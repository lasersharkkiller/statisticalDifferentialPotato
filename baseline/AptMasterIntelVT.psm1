# AptMasterIntelVT.psm1
# Pulls VirusTotal metadata (main report + behaviour_summary) for hashes
# harvested from apt\APTs\**\*_Master_Intel.csv files.
#
# Two entry points:
#   Get-AptMasterIntelVTAll       - every master intel CSV across all actors
#   Get-AptMasterIntelVTByActor   - prompts for an actor/family name, pulls that
#                                   subtree only
#
# Both share the dynamic multi-key rotation pattern used by Get-VTBaseline
# (baseline\VTBaseline.psm1): auto-discovers VT_API_Key_* secrets, spaces
# requests 15s/key, honors MissingHashes.csv, handles 429/404 cleanly.

function Initialize-AptVTRotator {
    # Returns a PSCustomObject carrying the loaded keys + cooldown tracker.
    # Also installs script-scope state used by Invoke-AptVTRequest.
    param(
        [string]$ProxyRegion,
        [string]$Proxy,
        [pscredential]$ProxyCredential,
        # Subset of VT API keys to use (e.g. '1,3' or 'all'). Falls back to
        # $env:VT_KEYS. Matches Get-VTBaseline's -Keys parameter.
        [string]$Keys
    )

    # --- PROXY RESOLUTION (mirrors Get-VTBaseline; uses VTBaseline's exported
    #     Get-VTProxyForRegion helper for the region->URL+secret-names mapping) ---
    if ([string]::IsNullOrWhiteSpace($ProxyRegion)) { $ProxyRegion = $env:VT_PROXY_REGION }
    $regionInfo = $null
    if (Get-Command Get-VTProxyForRegion -ErrorAction SilentlyContinue) {
        $regionInfo = Get-VTProxyForRegion -Region $ProxyRegion
    }
    if ($regionInfo) {
        if ([string]::IsNullOrWhiteSpace($Proxy)) { $Proxy = $regionInfo.Proxy }
    }
    if ([string]::IsNullOrWhiteSpace($Proxy)) { $Proxy = $env:VT_PROXY }

    if ($Proxy -and -not $ProxyCredential) {
        $userSecret = if ($regionInfo) { $regionInfo.UserSecret } else { 'PIA_SOCKS_User' }
        $passSecret = if ($regionInfo) { $regionInfo.PassSecret } else { 'PIA_SOCKS_Password' }
        try {
            $puser = Get-Secret -Name $userSecret -AsPlainText -ErrorAction Stop
            $ppass = Get-Secret -Name $passSecret -ErrorAction Stop
            if ($puser -and $ppass) {
                $securePass = if ($ppass -is [System.Security.SecureString]) { $ppass }
                              else { ConvertTo-SecureString -String $ppass -AsPlainText -Force }
                $ProxyCredential = [pscredential]::new($puser, $securePass)
            }
        } catch {}
        if (-not $ProxyCredential) {
            $ProxyCredential = Get-Credential -Message "Enter SOCKS5 credentials for $Proxy"
        }
    }
    $script:AptVTProxy           = $Proxy
    $script:AptVTProxyCredential = $ProxyCredential
    if ($Proxy) {
        $regionTag = if ($ProxyRegion) { " region=$ProxyRegion" } else { '' }
        Write-Host ("Proxy: {0}{1} (user: {2})" -f $Proxy, $regionTag, $ProxyCredential.UserName) -ForegroundColor DarkCyan
    }

    $VTKeys      = @()
    $loadedNames = @()
    $infos = $null
    try {
        $infos = Get-SecretInfo -Name 'VT_API_Key_*' -ErrorAction Stop |
                 Sort-Object { if ($_.Name -match '_(\d+)$') { [int]$matches[1] } else { [int]::MaxValue } }
    } catch {
        $firstErr = $_.Exception.Message
        # Most common cause is the SecretStore vault auto-locking after its
        # PasswordTimeout (default 15 min). Retry once after explicit unlock.
        if (Get-Command Unlock-SecretStore -ErrorAction SilentlyContinue) {
            Write-Host "[INFO] Vault enumeration failed - attempting Unlock-SecretStore..." -ForegroundColor DarkYellow
            try {
                Unlock-SecretStore -ErrorAction Stop
                $infos = Get-SecretInfo -Name 'VT_API_Key_*' -ErrorAction Stop |
                         Sort-Object { if ($_.Name -match '_(\d+)$') { [int]$matches[1] } else { [int]::MaxValue } }
            } catch {
                Write-Error ("Unable to enumerate secrets matching 'VT_API_Key_*' even after unlock attempt. First error: {0}. Unlock error: {1}" -f $firstErr, $_.Exception.Message)
                return $null
            }
        } else {
            Write-Error ("Unable to enumerate secrets matching 'VT_API_Key_*': {0}. Is SecretManagement loaded and a vault registered?" -f $firstErr)
            return $null
        }
    }

    foreach ($info in $infos) {
        try {
            $k = (Get-Secret -Name $info.Name -AsPlainText -ErrorAction Stop).Trim()
            if (-not [string]::IsNullOrWhiteSpace($k) -and $VTKeys -notcontains $k) {
                $VTKeys      += $k
                $loadedNames += $info.Name
            }
        } catch {
            Write-Host "[WARN] Could not load $($info.Name) from vault." -ForegroundColor Yellow
        }
    }

    if ($VTKeys.Count -eq 0) {
        Write-Error "No VT API keys found in vault (expected one or more VT_API_Key_* secrets)."
        return $null
    }

    # --- KEY SUBSET RESOLUTION (mirrors Get-VTBaseline) ---
    if ([string]::IsNullOrWhiteSpace($Keys)) { $Keys = $env:VT_KEYS }

    if ([string]::IsNullOrWhiteSpace($Keys)) {
        Write-Host ""
        Write-Host "Available VT API keys:" -ForegroundColor DarkCyan
        for ($i = 0; $i -lt $VTKeys.Count; $i++) {
            $k  = $VTKeys[$i]
            $fp = $k.Substring(0,6) + '...' + $k.Substring($k.Length-4)
            Write-Host ("  {0,2}) {1,-16}  {2}" -f ($i + 1), $loadedNames[$i], $fp) -ForegroundColor DarkCyan
        }
        Write-Host ("  {0,2}) ALL keys (default)" -f ($VTKeys.Count + 1)) -ForegroundColor DarkCyan
        Write-Host ""
        $Keys = (Read-Host "Which key(s) to use? (comma-separated numbers, '$($VTKeys.Count + 1)' or 'all' for all; Enter=all)").Trim()
        if ([string]::IsNullOrWhiteSpace($Keys) -or $Keys -eq ($VTKeys.Count + 1).ToString()) {
            $Keys = 'all'
        }
    }

    $useAll = $Keys -ieq 'all' -or $Keys -eq '*'

    if (-not $useAll) {
        $selectedIdxs = @($Keys -split '[,\s]+' |
            Where-Object { $_ -match '^\d+$' } |
            ForEach-Object { [int]$_ - 1 } |
            Where-Object { $_ -ge 0 -and $_ -lt $VTKeys.Count } |
            Sort-Object -Unique)
        if ($selectedIdxs.Count -eq 0) {
            Write-Host "[WARN] No valid keys selected from '$Keys'; using ALL keys." -ForegroundColor Yellow
        } else {
            $VTKeys      = @($selectedIdxs | ForEach-Object { $VTKeys[$_] })
            $loadedNames = @($selectedIdxs | ForEach-Object { $loadedNames[$_] })
        }
    }

    Write-Host "Using $($VTKeys.Count) VT API key(s) ($($loadedNames -join ', ')). Rotating with 15s spacing per key (~$($VTKeys.Count * 4) req/min combined)." -ForegroundColor DarkCyan

    $script:AptVTKeys        = $VTKeys
    $script:AptVTMinDelayMs  = 15000
    $script:AptVTKeyLastCall = @{}
    for ($j = 0; $j -lt $VTKeys.Count; $j++) {
        $script:AptVTKeyLastCall[$j] = [DateTime]::MinValue
    }
    return $true
}

function Invoke-AptVTRequest {
    param([string]$Uri, [string]$Method = "Get")

    $now           = [DateTime]::UtcNow
    $chosenIdx     = -1
    $earliestReady = [DateTime]::MaxValue

    for ($k = 0; $k -lt $script:AptVTKeys.Count; $k++) {
        $readyAt = $script:AptVTKeyLastCall[$k].AddMilliseconds($script:AptVTMinDelayMs)
        if ($readyAt -le $now) {
            $chosenIdx = $k
            break
        }
        if ($readyAt -lt $earliestReady) {
            $earliestReady = $readyAt
            $chosenIdx     = $k
        }
    }

    $waitMs = ($script:AptVTKeyLastCall[$chosenIdx].AddMilliseconds($script:AptVTMinDelayMs) - [DateTime]::UtcNow).TotalMilliseconds
    if ($waitMs -gt 0) {
        $waitSec = [Math]::Round($waitMs / 1000, 1)
        Write-Host "    [Rate Limit] Key $($chosenIdx + 1) cooling down - waiting ${waitSec}s..." -ForegroundColor DarkGray
        Start-Sleep -Milliseconds ([Math]::Ceiling($waitMs))
    }

    $script:AptVTKeyLastCall[$chosenIdx] = [DateTime]::UtcNow
    $Headers = @{ "x-apikey" = $script:AptVTKeys[$chosenIdx]; "Content-Type" = "application/json" }

    $proxyArgs = @{}
    if ($script:AptVTProxy) {
        $proxyArgs['Proxy'] = $script:AptVTProxy
        if ($script:AptVTProxyCredential) { $proxyArgs['ProxyCredential'] = $script:AptVTProxyCredential }
    }

    return Invoke-RestMethod -Uri $Uri -Headers $Headers -Method $Method @proxyArgs
}

function Get-AptHashRecords {
    # Parses a single master intel CSV and returns hash-bearing rows
    # normalized to @{ Hash, Type, Actor }.
    param([string]$CsvPath, [string]$ActorName)

    if (-not (Test-Path $CsvPath)) { return @() }
    $rows = @()
    try {
        $rows = Import-Csv -Path $CsvPath
    } catch {
        Write-Host "  [WARN] Could not parse $CsvPath - $($_.Exception.Message)" -ForegroundColor Yellow
        return @()
    }

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $rows) {
        if (-not $row.IOCType -or -not $row.IOCValue) { continue }
        $type  = ($row.IOCType).Trim().ToUpperInvariant()
        $value = ($row.IOCValue).Trim()
        $valid = switch ($type) {
            'SHA256' { $value -match '^[0-9a-fA-F]{64}$' }
            'SHA1'   { $value -match '^[0-9a-fA-F]{40}$' }
            'MD5'    { $value -match '^[0-9a-fA-F]{32}$' }
            default  { $false }
        }
        if (-not $valid) { continue }
        $results.Add([PSCustomObject]@{
            Hash  = $value.ToLowerInvariant()
            Type  = $type
            Actor = $ActorName
        })
    }
    return $results
}

function Build-AptVTLocalIndex {
    # Walks every existing <hash>.json under output-baseline\VirusTotal-main\**
    # and output-baseline\VirusTotal-behaviors\** once, so any future Process-AptHash
    # call can reuse an already-fetched report (from another actor folder or from
    # a 15b bucket) instead of burning a VT request.
    param(
        [string]$MainRoot      = "output-baseline\VirusTotal-main",
        [string]$BehaviorsRoot = "output-baseline\VirusTotal-behaviors"
    )

    $mainIdx = @{}
    $behIdx  = @{}
    if (Test-Path $MainRoot) {
        Get-ChildItem -Path $MainRoot -Recurse -Filter "*.json" -File -ErrorAction SilentlyContinue |
            ForEach-Object { if (-not $mainIdx.ContainsKey($_.BaseName)) { $mainIdx[$_.BaseName] = $_.FullName } }
    }
    if (Test-Path $BehaviorsRoot) {
        Get-ChildItem -Path $BehaviorsRoot -Recurse -Filter "*.json" -File -ErrorAction SilentlyContinue |
            ForEach-Object { if (-not $behIdx.ContainsKey($_.BaseName)) { $behIdx[$_.BaseName] = $_.FullName } }
    }
    Write-Host "Local VT cache: $($mainIdx.Count) main / $($behIdx.Count) behavior reports indexed." -ForegroundColor DarkGray
    $script:AptVTMainIndex      = $mainIdx
    $script:AptVTBehaviorsIndex = $behIdx
}

function Process-AptHash {
    param(
        [string]$Hash,
        [string]$MainPath,
        [string]$BehaviorsPath,
        [System.Collections.Generic.HashSet[string]]$MissingHashes,
        [string]$MissingHashesPath
    )

    $mainFile   = Join-Path $MainPath      "$Hash.json"
    $behaveFile = Join-Path $BehaviorsPath "$Hash.json"

    if ($MissingHashes.Contains($Hash)) {
        Write-Host "  [SKIP] $Hash is in MissingHashes.csv - known 404." -ForegroundColor DarkGray
        return
    }
    if ((Test-Path $mainFile) -and (Test-Path $behaveFile)) { return }

    # Cross-folder cache: if any other bucket (15b or another APT actor) already
    # has this hash, copy locally instead of re-querying VT.
    if (-not (Test-Path $mainFile) -and $script:AptVTMainIndex.ContainsKey($Hash)) {
        $src = $script:AptVTMainIndex[$Hash]
        Copy-Item -Path $src -Destination $mainFile -Force
        Write-Host "  [CACHE] Main report copied from $src" -ForegroundColor DarkGreen
    }
    if (-not (Test-Path $behaveFile) -and $script:AptVTBehaviorsIndex.ContainsKey($Hash)) {
        $src = $script:AptVTBehaviorsIndex[$Hash]
        Copy-Item -Path $src -Destination $behaveFile -Force
        Write-Host "  [CACHE] Behaviors report copied from $src" -ForegroundColor DarkGreen
    }
    if ((Test-Path $mainFile) -and (Test-Path $behaveFile)) { return }

    if (-not (Test-Path $mainFile)) {
        Write-Host "  Main report missing for $Hash. Querying VirusTotal..." -ForegroundColor Yellow
        try {
            $response = Invoke-AptVTRequest -Uri "https://www.virustotal.com/api/v3/files/$Hash"
            $response | ConvertTo-Json -Depth 100 | Set-Content -Path $mainFile
            $script:AptVTMainIndex[$Hash] = $mainFile
            Write-Host "  [OK] Main report saved." -ForegroundColor Green
        } catch {
            $code = $null
            try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
            if ($code -eq 429) {
                Write-Host "  [!] VT Quota Exceeded (429). Stopping." -ForegroundColor Red
                $script:AptVTQuotaHit = $true
                return
            } elseif ($code -eq 404) {
                Write-Host "  [404] $Hash not found in VT. Adding to MissingHashes.csv." -ForegroundColor DarkGray
                [void]$MissingHashes.Add($Hash)
                [PSCustomObject]@{ Hash = $Hash; DateChecked = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ") } |
                    Export-Csv -Path $MissingHashesPath -Append -NoTypeInformation
                return
            } else {
                Write-Host "  [ERROR] HTTP $code - $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    if ($script:AptVTQuotaHit) { return }

    if (-not (Test-Path $behaveFile)) {
        Write-Host "  Behaviors report missing for $Hash. Querying VirusTotal..." -ForegroundColor Yellow
        try {
            $response = Invoke-AptVTRequest -Uri "https://www.virustotal.com/api/v3/files/$Hash/behaviour_summary"
            $response | ConvertTo-Json -Depth 100 | Set-Content -Path $behaveFile
            $script:AptVTBehaviorsIndex[$Hash] = $behaveFile
            Write-Host "  [OK] Behaviors report saved." -ForegroundColor Green
        } catch {
            $code = $null
            try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
            if ($code -eq 429) {
                Write-Host "  [!] VT Quota Exceeded (429). Stopping." -ForegroundColor Red
                $script:AptVTQuotaHit = $true
            } else {
                Write-Host "  [ERROR] Behaviors HTTP $code - $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}

function Initialize-AptMissingHashTracker {
    $missingHashesPath = "output\MissingHashes.csv"
    $missingHashes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if (Test-Path $missingHashesPath) {
        try {
            Import-Csv -Path $missingHashesPath | ForEach-Object {
                if ($_.Hash) { [void]$missingHashes.Add($_.Hash) }
            }
            Write-Host "Loaded $($missingHashes.Count) known-404 hashes from MissingHashes.csv." -ForegroundColor DarkGray
        } catch {
            Write-Host "[WARN] Could not read MissingHashes.csv: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    return [PSCustomObject]@{ Path = $missingHashesPath; Set = $missingHashes }
}

function Invoke-AptActorCsv {
    param(
        [System.IO.FileInfo]$CsvFile,
        [string]$MainBase,
        [string]$BehaviorsBase,
        $Missing
    )

    $actorName = $CsvFile.BaseName -replace '_Master_Intel$',''
    Write-Host "`n=== $actorName ($($CsvFile.FullName)) ===" -ForegroundColor Cyan

    $records = Get-AptHashRecords -CsvPath $CsvFile.FullName -ActorName $actorName
    if ($records.Count -eq 0) {
        Write-Host "  (no hash IOCs found)" -ForegroundColor DarkGray
        return
    }

    # Deduplicate per actor file
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $unique = foreach ($r in $records) { if ($seen.Add($r.Hash)) { $r } }
    Write-Host "  $($unique.Count) unique hash IOCs ($($records.Count) raw rows)" -ForegroundColor DarkCyan

    $mainActor      = Join-Path $MainBase      $actorName
    $behaviorsActor = Join-Path $BehaviorsBase $actorName
    New-Item -ItemType Directory -Path $mainActor      -Force | Out-Null
    New-Item -ItemType Directory -Path $behaviorsActor -Force | Out-Null

    foreach ($rec in $unique) {
        if ($script:AptVTQuotaHit) { return }
        Process-AptHash -Hash $rec.Hash `
                        -MainPath $mainActor `
                        -BehaviorsPath $behaviorsActor `
                        -MissingHashes $Missing.Set `
                        -MissingHashesPath $Missing.Path
    }
}

function Get-AptMasterIntelVTAll {
    [CmdletBinding()]
    param(
        [string]$AptRoot = "apt",
        [string]$ProxyRegion,
        [string]$Proxy,
        [pscredential]$ProxyCredential,
        [string]$Keys
    )

    if (-not (Test-Path $AptRoot)) {
        Write-Error "APT root not found at '$AptRoot'."
        return
    }
    if (-not (Initialize-AptVTRotator -ProxyRegion $ProxyRegion -Proxy $Proxy -ProxyCredential $ProxyCredential -Keys $Keys)) { return }

    $mainBaseRoot      = "output-baseline\VirusTotal-main\apt-master-intel"
    $behaviorsBaseRoot = "output-baseline\VirusTotal-behaviors\apt-master-intel"
    New-Item -ItemType Directory -Path $mainBaseRoot      -Force | Out-Null
    New-Item -ItemType Directory -Path $behaviorsBaseRoot -Force | Out-Null

    $missing = Initialize-AptMissingHashTracker
    Build-AptVTLocalIndex
    $script:AptVTQuotaHit = $false

    # Two-pass: APTs subtree, then Malware Families subtree.
    # Each gets its own output bucket under apt-master-intel\.
    $passes = @(
        @{ Source = (Join-Path $AptRoot 'APTs');             Bucket = 'APTs' },
        @{ Source = (Join-Path $AptRoot 'Malware Families'); Bucket = 'Malware Families' }
    )

    foreach ($pass in $passes) {
        if ($script:AptVTQuotaHit) { break }
        $src    = $pass.Source
        $bucket = $pass.Bucket

        if (-not (Test-Path $src)) {
            Write-Host "[SKIP] $src not present - skipping $bucket pass." -ForegroundColor DarkGray
            continue
        }

        $csvFiles = Get-ChildItem -Path $src -Recurse -Filter "*_Master_Intel.csv" -File -ErrorAction SilentlyContinue
        if (-not $csvFiles -or $csvFiles.Count -eq 0) {
            Write-Host "[WARN] No *_Master_Intel.csv files found under $src." -ForegroundColor Yellow
            continue
        }

        $mainBase      = Join-Path $mainBaseRoot      $bucket
        $behaviorsBase = Join-Path $behaviorsBaseRoot $bucket
        New-Item -ItemType Directory -Path $mainBase      -Force | Out-Null
        New-Item -ItemType Directory -Path $behaviorsBase -Force | Out-Null

        Write-Host ""
        Write-Host "=== Pass: $bucket ($($csvFiles.Count) CSV(s) under $src) ===" -ForegroundColor Cyan

        foreach ($csv in $csvFiles) {
            if ($script:AptVTQuotaHit) { break }
            Invoke-AptActorCsv -CsvFile $csv -MainBase $mainBase -BehaviorsBase $behaviorsBase -Missing $missing
        }
    }

    if ($script:AptVTQuotaHit) {
        Write-Host "`n[!] Run stopped early due to VT quota. Re-run to resume (existing files are skipped)." -ForegroundColor Yellow
    } else {
        Write-Host "`n[DONE] APT master intel VT collection complete." -ForegroundColor Green
    }
}

function Get-AptMasterIntelVTByActor {
    [CmdletBinding()]
    param(
        [string]$AptRoot = "apt",
        [string]$ActorName,
        [string]$ProxyRegion,
        [string]$Proxy,
        [pscredential]$ProxyCredential,
        [string]$Keys
    )

    if (-not (Test-Path $AptRoot)) {
        Write-Error "APT root not found at '$AptRoot'."
        return
    }

    if ([string]::IsNullOrWhiteSpace($ActorName)) {
        $ActorName = Read-Host "Enter APT / malware family name to pull (partial match OK, e.g. APT29, Lazarus, Qakbot)"
    }
    if ([string]::IsNullOrWhiteSpace($ActorName)) {
        Write-Host "[ABORT] No actor name provided." -ForegroundColor Yellow
        return
    }

    $pattern = "*${ActorName}*_Master_Intel.csv"
    $csvFiles = Get-ChildItem -Path $AptRoot -Recurse -Filter $pattern -File -ErrorAction SilentlyContinue

    if (-not $csvFiles -or $csvFiles.Count -eq 0) {
        Write-Host "[WARN] No master intel CSV found matching '$pattern' under $AptRoot." -ForegroundColor Yellow
        $all = Get-ChildItem -Path $AptRoot -Recurse -Filter "*_Master_Intel.csv" -File -ErrorAction SilentlyContinue |
               ForEach-Object { $_.BaseName -replace '_Master_Intel$','' }
        if ($all) {
            Write-Host "Available actors:" -ForegroundColor DarkGray
            $all | Sort-Object -Unique | ForEach-Object { Write-Host "  - $_" -ForegroundColor DarkGray }
        }
        return
    }

    Write-Host "Matched $($csvFiles.Count) file(s):" -ForegroundColor DarkCyan
    $csvFiles | ForEach-Object { Write-Host "  $($_.FullName)" -ForegroundColor DarkGray }

    if (-not (Initialize-AptVTRotator -ProxyRegion $ProxyRegion -Proxy $Proxy -ProxyCredential $ProxyCredential -Keys $Keys)) { return }

    $mainBaseRoot      = "output-baseline\VirusTotal-main\apt-master-intel"
    $behaviorsBaseRoot = "output-baseline\VirusTotal-behaviors\apt-master-intel"
    New-Item -ItemType Directory -Path $mainBaseRoot      -Force | Out-Null
    New-Item -ItemType Directory -Path $behaviorsBaseRoot -Force | Out-Null

    $missing = Initialize-AptMissingHashTracker
    Build-AptVTLocalIndex
    $script:AptVTQuotaHit = $false

    # Per-CSV bucket: first directory segment under $AptRoot
    # (e.g. 'APTs' or 'Malware Families') determines output subfolder.
    $aptRootResolved = (Resolve-Path $AptRoot).Path
    foreach ($csv in $csvFiles) {
        if ($script:AptVTQuotaHit) { break }
        $rel    = $csv.FullName.Substring($aptRootResolved.Length).TrimStart('\','/')
        $bucket = ($rel -split '[\\/]' | Select-Object -First 1)
        $mainBase      = Join-Path $mainBaseRoot      $bucket
        $behaviorsBase = Join-Path $behaviorsBaseRoot $bucket
        New-Item -ItemType Directory -Path $mainBase      -Force | Out-Null
        New-Item -ItemType Directory -Path $behaviorsBase -Force | Out-Null
        Invoke-AptActorCsv -CsvFile $csv -MainBase $mainBase -BehaviorsBase $behaviorsBase -Missing $missing
    }

    if ($script:AptVTQuotaHit) {
        Write-Host "`n[!] Run stopped early due to VT quota. Re-run to resume (existing files are skipped)." -ForegroundColor Yellow
    } else {
        Write-Host "`n[DONE] APT master intel VT collection complete for '$ActorName'." -ForegroundColor Green
    }
}

Export-ModuleMember -Function Get-AptMasterIntelVTAll, Get-AptMasterIntelVTByActor

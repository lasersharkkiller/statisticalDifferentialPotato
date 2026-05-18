# OtBaseline.psm1
# OT (Operational Technology) firmware baselining + opt-in VT submission.
# Separate pipeline from Get-VTBaseline because:
#   - Output goes to output-baseline/VirusTotal-{main,behaviors}/OT/<Vendor>/
#     flat (per-vendor) instead of the NSRL/localBaseline/malicious hierarchy.
#     Flat keying means a SHA256 shared across multiple products of the same
#     vendor (e.g. Eaton ships the same Network-M2 rootfs as Industrial-
#     Gateway-Card and Industrial-Gateway-Card-X2) only consumes one VT
#     lookup. The catalog.csv files still encode the per-product mapping.
#   - We expect heavy 404 rate (most OT firmware isn't in VT) and have a
#     follow-on Submit-OtFilesNotInVT step that uploads the files so VT
#     will have something to return on the next pull
#   - Submission is async (record analysis_id, poll later via
#     Sync-VTPendingSubmissions) so 5b can fire a lot of uploads without
#     blocking
#
# Three exports:
#   Get-OtBaseline             - pull VT metadata for a catalog (5a)
#   Submit-OtFilesNotInVT      - upload the 404'd files to VT (5b)
#   Sync-VTPendingSubmissions  - poll submitted files for completion (5z)
#
# Internal helpers (Initialize-OtVTClient, Invoke-OtVTRequest) mirror
# Get-VTBaseline's machinery so the same proxy / 499 soft-cap /
# disjoint-key-subset / retry-on-vault-lock behavior applies.

function Initialize-OtVTClient {
    param(
        [string]$ProxyRegion,
        [string]$Proxy,
        [pscredential]$ProxyCredential,
        [string]$Keys
    )

    # --- PROXY RESOLUTION ---
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
    $script:OtVTProxy           = $Proxy
    $script:OtVTProxyCredential = $ProxyCredential
    if ($Proxy) {
        $regionTag = if ($ProxyRegion) { " region=$ProxyRegion" } else { '' }
        Write-Host ("Proxy: {0}{1} (user: {2})" -f $Proxy, $regionTag, $ProxyCredential.UserName) -ForegroundColor DarkCyan
    } else {
        Write-Host "Proxy: <none> (direct connection)" -ForegroundColor DarkGray
    }

    # --- KEY LOAD (with retry-on-locked-vault) ---
    $infos = $null
    try {
        $infos = Get-SecretInfo -Name 'VT_API_Key_*' -ErrorAction Stop |
                 Sort-Object { if ($_.Name -match '_(\d+)$') { [int]$matches[1] } else { [int]::MaxValue } }
    } catch {
        $firstErr = $_.Exception.Message
        if (Get-Command Unlock-SecretStore -ErrorAction SilentlyContinue) {
            Write-Host "[INFO] Vault enumeration failed - attempting Unlock-SecretStore..." -ForegroundColor DarkYellow
            try {
                Unlock-SecretStore -ErrorAction Stop
                $infos = Get-SecretInfo -Name 'VT_API_Key_*' -ErrorAction Stop |
                         Sort-Object { if ($_.Name -match '_(\d+)$') { [int]$matches[1] } else { [int]::MaxValue } }
            } catch {
                Write-Error ("Unable to enumerate VT keys after unlock attempt. First: {0}. Unlock: {1}" -f $firstErr, $_.Exception.Message)
                return $false
            }
        } else {
            Write-Error ("Unable to enumerate VT_API_Key_* secrets: {0}" -f $firstErr)
            return $false
        }
    }

    $VTKeys      = @()
    $loadedNames = @()
    foreach ($info in $infos) {
        try {
            $k = (Get-Secret -Name $info.Name -AsPlainText -ErrorAction Stop).Trim()
            if (-not [string]::IsNullOrWhiteSpace($k) -and $VTKeys -notcontains $k) {
                $VTKeys      += $k
                $loadedNames += $info.Name
            }
        } catch {
            Write-Host "[WARN] Could not load $($info.Name)" -ForegroundColor Yellow
        }
    }

    if ($VTKeys.Count -eq 0) {
        Write-Error "No VT API keys found in vault"
        return $false
    }

    # --- KEY SUBSET RESOLUTION ---
    if ([string]::IsNullOrWhiteSpace($Keys)) { $Keys = $env:VT_KEYS }

    # Sticky-select: reuse the user's prior selection from earlier in the
    # session (e.g. 5a over all 45 Eaton catalogs) without re-prompting.
    if ([string]::IsNullOrWhiteSpace($Keys) -and -not [string]::IsNullOrWhiteSpace($script:OtVTKeysSelection)) {
        $Keys = $script:OtVTKeysSelection
        Write-Host "Reusing previously selected key subset: $Keys" -ForegroundColor DarkGray
    }

    if ([string]::IsNullOrWhiteSpace($Keys)) {
        Write-Host ""
        Write-Host "Available VT API keys:" -ForegroundColor DarkCyan
        for ($i = 0; $i -lt $VTKeys.Count; $i++) {
            $fp = $VTKeys[$i].Substring(0,6) + '...' + $VTKeys[$i].Substring($VTKeys[$i].Length - 4)
            Write-Host ("  {0,2}) {1,-16}  {2}" -f ($i + 1), $loadedNames[$i], $fp) -ForegroundColor DarkCyan
        }
        Write-Host ("  {0,2}) ALL keys (default)" -f ($VTKeys.Count + 1)) -ForegroundColor DarkCyan
        Write-Host ""
        $Keys = (Read-Host "Which key(s) to use? (comma-separated numbers or 'all'; Enter=all)").Trim()
        if ([string]::IsNullOrWhiteSpace($Keys) -or $Keys -eq ($VTKeys.Count + 1).ToString()) { $Keys = 'all' }
    }

    $script:OtVTKeysSelection = $Keys

    $useAll = $Keys -ieq 'all' -or $Keys -eq '*'
    if (-not $useAll) {
        $selectedIdxs = @($Keys -split '[,\s]+' |
            Where-Object { $_ -match '^\d+$' } |
            ForEach-Object { [int]$_ - 1 } |
            Where-Object { $_ -ge 0 -and $_ -lt $VTKeys.Count } |
            Sort-Object -Unique)
        if ($selectedIdxs.Count -gt 0) {
            $VTKeys      = @($selectedIdxs | ForEach-Object { $VTKeys[$_] })
            $loadedNames = @($selectedIdxs | ForEach-Object { $loadedNames[$_] })
        }
    }

    Write-Host "Using $($VTKeys.Count) VT API key(s) ($($loadedNames -join ', '))." -ForegroundColor DarkCyan

    # --- 499 SOFT-CAP STATE + STARTUP PROBE ---
    $script:OtVTKeys              = $VTKeys
    $script:OtVTLoadedNames       = $loadedNames
    $script:OtVTMinDelayMs        = 15000
    $script:OtVTKeyLastCall       = @{}
    $script:OtVTKeyDisabledUntil  = @{}
    $script:OtVTKeyCallCount      = @{}
    $script:OtVTKeyCapPerDay      = 499

    Write-Host "Seeding per-key daily-used counters from VT..." -ForegroundColor DarkGray
    for ($j = 0; $j -lt $VTKeys.Count; $j++) {
        $script:OtVTKeyLastCall[$j]      = [DateTime]::MinValue
        $script:OtVTKeyDisabledUntil[$j] = [DateTime]::MinValue
        $used = 0
        $probeArgs = @{
            Uri        = "https://www.virustotal.com/api/v3/users/$($VTKeys[$j])"
            Headers    = @{ 'x-apikey' = $VTKeys[$j] }
            TimeoutSec = 15
        }
        if ($script:OtVTProxy) {
            $probeArgs['Proxy'] = $script:OtVTProxy
            if ($script:OtVTProxyCredential) { $probeArgs['ProxyCredential'] = $script:OtVTProxyCredential }
        }
        try {
            $u    = Invoke-RestMethod @probeArgs
            $used = [int]$u.data.attributes.quotas.api_requests_daily.used
        } catch {
            Write-Host ("  [WARN] Daily-used probe failed for {0}: {1}" -f $loadedNames[$j], $_.Exception.Message) -ForegroundColor Yellow
        }
        $script:OtVTKeyCallCount[$j] = $used
        if ($used -ge $script:OtVTKeyCapPerDay) {
            $script:OtVTKeyDisabledUntil[$j] = [DateTime]::UtcNow.Date.AddDays(1)
            Write-Host ("  Key {0,2} ({1,-16}) {2}/{3} - at cap, skipping" -f ($j + 1), $loadedNames[$j], $used, $script:OtVTKeyCapPerDay) -ForegroundColor Yellow
        } else {
            Write-Host ("  Key {0,2} ({1,-16}) {2}/{3} used today" -f ($j + 1), $loadedNames[$j], $used, $script:OtVTKeyCapPerDay) -ForegroundColor DarkGray
        }
    }

    return $true
}

function Invoke-OtVTRequest {
    param(
        [string]$Uri,
        [string]$Method = "Get",
        $Form = $null
    )

    for ($attempt = 0; $attempt -lt $script:OtVTKeys.Count; $attempt++) {
        $now          = [DateTime]::UtcNow
        $chosenIdx    = -1
        $earliestReady = [DateTime]::MaxValue
        $activeCount  = 0

        for ($k = 0; $k -lt $script:OtVTKeys.Count; $k++) {
            if ($script:OtVTKeyDisabledUntil[$k] -gt $now) { continue }
            if ($script:OtVTKeyCallCount[$k] -ge $script:OtVTKeyCapPerDay) {
                $script:OtVTKeyDisabledUntil[$k] = [DateTime]::UtcNow.Date.AddDays(1)
                Write-Host ("    [Cap] Key $($k + 1) hit local cap; disabled.") -ForegroundColor Yellow
                continue
            }
            $activeCount++
            $readyAt = $script:OtVTKeyLastCall[$k].AddMilliseconds($script:OtVTMinDelayMs)
            if ($readyAt -le $now) { $chosenIdx = $k; break }
            if ($readyAt -lt $earliestReady) { $earliestReady = $readyAt; $chosenIdx = $k }
        }

        if ($activeCount -eq 0) {
            throw "VT_ALL_KEYS_EXHAUSTED: all keys at cap or disabled. Earliest re-enable next UTC midnight."
        }

        $waitMs = ($script:OtVTKeyLastCall[$chosenIdx].AddMilliseconds($script:OtVTMinDelayMs) - [DateTime]::UtcNow).TotalMilliseconds
        if ($waitMs -gt 0) {
            $waitSec = [Math]::Round($waitMs / 1000, 1)
            Write-Host "    [Rate Limit] Key $($chosenIdx + 1) cooling down - waiting ${waitSec}s..." -ForegroundColor DarkGray
            Start-Sleep -Milliseconds ([Math]::Ceiling($waitMs))
        }

        $script:OtVTKeyLastCall[$chosenIdx]    = [DateTime]::UtcNow
        $script:OtVTKeyCallCount[$chosenIdx]++

        $reqArgs = @{
            Uri        = $Uri
            Headers    = @{ 'x-apikey' = $script:OtVTKeys[$chosenIdx] }
            Method     = $Method
            TimeoutSec = 120  # uploads can be slow
        }
        if ($Form) { $reqArgs['Form'] = $Form }
        if ($script:OtVTProxy) {
            $reqArgs['Proxy'] = $script:OtVTProxy
            if ($script:OtVTProxyCredential) { $reqArgs['ProxyCredential'] = $script:OtVTProxyCredential }
        }

        try {
            return Invoke-RestMethod @reqArgs
        } catch {
            $code = $null; try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
            if ($code -ne 429) { throw }
            $script:OtVTKeyDisabledUntil[$chosenIdx] = [DateTime]::UtcNow.Date.AddDays(1)
            Write-Host "    [Rate Limit] Key $($chosenIdx + 1) hit 429; disabled. Rotating..." -ForegroundColor Yellow
        }
    }

    throw "VT_ALL_KEYS_EXHAUSTED: retry budget exhausted while attempting $Uri"
}

function Submit-OtVTFile {
    # Upload a file to VT, returning the analysis_id. Picks the right
    # endpoint based on file size:
    #   <= 32MB : direct POST /api/v3/files
    #   > 32MB  : GET /api/v3/files/upload_url, then POST to that one-time URL
    # The upload_url path is gated to premium VT tiers on accounts > 32MB; if
    # the user's account doesn't allow it, the GET fails with 403.
    param([System.IO.FileInfo]$FileInfo)

    if ($FileInfo.Length -le 32MB) {
        $form = @{ file = $FileInfo }
        $response = Invoke-OtVTRequest -Uri 'https://www.virustotal.com/api/v3/files' -Method 'POST' -Form $form
        return $response.data.id
    }

    # Two-step path for >32MB
    $urlResp   = Invoke-OtVTRequest -Uri 'https://www.virustotal.com/api/v3/files/upload_url'
    $uploadUrl = $urlResp.data
    if ([string]::IsNullOrWhiteSpace($uploadUrl)) {
        throw "VT did not return an upload_url (account tier may not allow >32MB uploads)"
    }

    # The one-time upload URL embeds auth, so we don't reuse Invoke-OtVTRequest
    # (which would attach x-apikey + count against rotation). Direct POST.
    $reqArgs = @{
        Uri        = $uploadUrl
        Method     = 'POST'
        Form       = @{ file = $FileInfo }
        TimeoutSec = 600
    }
    if ($script:OtVTProxy) {
        $reqArgs['Proxy'] = $script:OtVTProxy
        if ($script:OtVTProxyCredential) { $reqArgs['ProxyCredential'] = $script:OtVTProxyCredential }
    }
    $response = Invoke-RestMethod @reqArgs
    return $response.data.id
}

function Resolve-OtCatalogContext {
    # Derive Vendor/Category/Product from the path of a catalog.csv, e.g.
    #   .../firmware-staging/Eaton/UPS/9PX 5-11K-UPS/catalog.csv
    #   -> Vendor='Eaton', Category='UPS', Product='9PX 5-11K-UPS'
    param([string]$CatalogCsv)
    $resolved = (Resolve-Path $CatalogCsv).Path
    $parts    = $resolved -split '[\\/]'
    $idx      = [array]::IndexOf($parts, 'firmware-staging')
    if ($idx -lt 0 -or $parts.Count -lt $idx + 4) {
        return $null
    }
    return [pscustomobject]@{
        Vendor   = $parts[$idx + 1]
        Category = $parts[$idx + 2]
        Product  = $parts[$idx + 3]
    }
}

function Get-OtBaseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$CatalogCsv,
        [string]$Vendor,
        [string]$Category,
        [string]$Product,
        [string]$ProxyRegion,
        [string]$Proxy,
        [pscredential]$ProxyCredential,
        [string]$Keys
    )

    if (-not (Test-Path -LiteralPath $CatalogCsv)) {
        Write-Error "Catalog CSV not found: $CatalogCsv"
        return
    }

    if (-not $Vendor -or -not $Category -or -not $Product) {
        $ctx = Resolve-OtCatalogContext -CatalogCsv $CatalogCsv
        if ($ctx) {
            if (-not $Vendor)   { $Vendor   = $ctx.Vendor }
            if (-not $Category) { $Category = $ctx.Category }
            if (-not $Product)  { $Product  = $ctx.Product }
        }
    }
    if (-not $Vendor -or -not $Category -or -not $Product) {
        Write-Error "Could not derive Vendor/Category/Product from $CatalogCsv. Pass them explicitly."
        return
    }

    Write-Host ""
    Write-Host "=== OT Baseline ===" -ForegroundColor Cyan
    Write-Host "  Catalog:  $CatalogCsv"
    Write-Host "  Vendor:   $Vendor"
    Write-Host "  Category: $Category"
    Write-Host "  Product:  $Product"

    if (-not (Initialize-OtVTClient -ProxyRegion $ProxyRegion -Proxy $Proxy -ProxyCredential $ProxyCredential -Keys $Keys)) {
        return
    }

    # Flat per-vendor cache so SHA256s shared across products of the same
    # vendor (rebadged firmware, common libc, busybox, etc.) only consume
    # one VT lookup. Per-product mapping lives in catalog.csv.
    $mainBase = "output-baseline\VirusTotal-main\OT\$Vendor"
    $behBase  = "output-baseline\VirusTotal-behaviors\OT\$Vendor"
    New-Item -ItemType Directory -Path $mainBase -Force | Out-Null
    New-Item -ItemType Directory -Path $behBase  -Force | Out-Null

    # Load 404 trackers
    $missingHashesPath = "output\MissingHashes.csv"
    $missingHashes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if (Test-Path $missingHashesPath) {
        Import-Csv $missingHashesPath | ForEach-Object { if ($_.Hash) { [void]$missingHashes.Add($_.Hash) } }
    }
    $missingBehaviorsPath = "output\MissingBehaviors.csv"
    $missingBehaviors = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if (Test-Path $missingBehaviorsPath) {
        Import-Csv $missingBehaviorsPath | ForEach-Object { if ($_.Hash) { [void]$missingBehaviors.Add($_.Hash) } }
    }

    $rows = @(Import-Csv $CatalogCsv)
    Write-Host "  Hashes:   $($rows.Count)"
    Write-Host ""

    $script:OtQuotaHit = $false
    $pulled = 0
    $missed = 0
    $cached = 0

    foreach ($row in $rows) {
        if ($script:OtQuotaHit) { break }
        $h        = $row.Hash
        $mainFile = Join-Path $mainBase "$h.json"
        $behFile  = Join-Path $behBase  "$h.json"

        $haveBeh = (Test-Path $behFile) -or $missingBehaviors.Contains($h)
        if ((Test-Path $mainFile) -and $haveBeh) { $cached++; continue }
        if ($missingHashes.Contains($h)) { $missed++; continue }

        if (-not (Test-Path $mainFile)) {
            Write-Host "  Pulling main for $($row.FileName) [$($h.Substring(0,8))...]" -ForegroundColor Yellow
            try {
                $response = Invoke-OtVTRequest -Uri "https://www.virustotal.com/api/v3/files/$h"
                $response | ConvertTo-Json -Depth 100 | Set-Content -Path $mainFile
                Write-Host "    [OK] main" -ForegroundColor Green
                $pulled++
            } catch {
                $code = $null; try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
                if ($_.Exception.Message -like 'VT_ALL_KEYS_EXHAUSTED*') {
                    Write-Host "    [!] $($_.Exception.Message)" -ForegroundColor Red
                    $script:OtQuotaHit = $true
                    break
                } elseif ($code -eq 404) {
                    Write-Host "    [404] not in VT" -ForegroundColor DarkGray
                    [void]$missingHashes.Add($h)
                    [PSCustomObject]@{ Hash = $h; DateChecked = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ") } |
                        Export-Csv -Path $missingHashesPath -Append -NoTypeInformation
                    $missed++
                    continue
                } else {
                    Write-Host "    [ERROR] HTTP $code - $($_.Exception.Message)" -ForegroundColor Red
                    continue
                }
            }
        }

        if ($script:OtQuotaHit) { break }

        if (-not (Test-Path $behFile) -and -not $missingBehaviors.Contains($h)) {
            try {
                $response = Invoke-OtVTRequest -Uri "https://www.virustotal.com/api/v3/files/$h/behaviour_summary"
                $response | ConvertTo-Json -Depth 100 | Set-Content -Path $behFile
                Write-Host "    [OK] behaviors" -ForegroundColor Green
            } catch {
                $code = $null; try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
                if ($_.Exception.Message -like 'VT_ALL_KEYS_EXHAUSTED*') {
                    $script:OtQuotaHit = $true
                    break
                } elseif ($code -eq 404) {
                    [void]$missingBehaviors.Add($h)
                    [PSCustomObject]@{ Hash = $h; DateChecked = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ") } |
                        Export-Csv -Path $missingBehaviorsPath -Append -NoTypeInformation
                }
            }
        }
    }

    Write-Host ""
    Write-Host "[DONE] cached=$cached pulled=$pulled missing=$missed total=$($rows.Count)" -ForegroundColor $(if ($script:OtQuotaHit) { 'Yellow' } else { 'Green' })
    if ($script:OtQuotaHit) {
        Write-Host "       Run stopped early due to VT quota." -ForegroundColor Yellow
    }
}

function Submit-OtFilesNotInVT {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$CatalogCsv,
        [string]$Vendor,
        [string]$Category,
        [string]$Product,
        [string]$ProxyRegion,
        [string]$Proxy,
        [pscredential]$ProxyCredential,
        [string]$Keys,
        # Hard ceiling - VT's documented per-file maximum is 650MB; anything
        # larger gets skipped with a warning rather than attempted.
        [int64]$MaxFileSizeBytes = 650MB
    )

    if (-not (Test-Path -LiteralPath $CatalogCsv)) {
        Write-Error "Catalog CSV not found: $CatalogCsv"
        return
    }

    if (-not $Vendor -or -not $Category -or -not $Product) {
        $ctx = Resolve-OtCatalogContext -CatalogCsv $CatalogCsv
        if ($ctx) {
            if (-not $Vendor)   { $Vendor   = $ctx.Vendor }
            if (-not $Category) { $Category = $ctx.Category }
            if (-not $Product)  { $Product  = $ctx.Product }
        }
    }

    Write-Host ""
    Write-Host "=== Submit OT Files (404'd) ===" -ForegroundColor Cyan
    Write-Host "  Catalog:  $CatalogCsv"
    Write-Host "  Vendor:   $Vendor / $Category / $Product"

    if (-not (Initialize-OtVTClient -ProxyRegion $ProxyRegion -Proxy $Proxy -ProxyCredential $ProxyCredential -Keys $Keys)) {
        return
    }

    # Load trackers
    $missingHashesPath = "output\MissingHashes.csv"
    $missingHashes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if (Test-Path $missingHashesPath) {
        Import-Csv $missingHashesPath | ForEach-Object { if ($_.Hash) { [void]$missingHashes.Add($_.Hash) } }
    }

    $pendingPath = "output\PendingVTSubmissions.csv"
    $pendingHashes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if (Test-Path $pendingPath) {
        Import-Csv $pendingPath | ForEach-Object { if ($_.Hash) { [void]$pendingHashes.Add($_.Hash) } }
    }

    # Flat per-vendor cache (same scheme as Get-OtBaseline).
    $mainBase = "output-baseline\VirusTotal-main\OT\$Vendor"
    $behBase  = "output-baseline\VirusTotal-behaviors\OT\$Vendor"

    $rows = @(Import-Csv $CatalogCsv)

    $script:OtQuotaHit = $false
    $submitted   = 0
    $skipped404  = 0   # not 404'd, nothing to submit
    $skippedPend = 0
    $skippedBig  = 0
    $skippedNoFile = 0
    $errors      = 0

    foreach ($row in $rows) {
        if ($script:OtQuotaHit) { break }
        $h = $row.Hash

        if (-not $missingHashes.Contains($h)) { $skipped404++; continue }
        if ($pendingHashes.Contains($h))      { $skippedPend++; continue }

        $fp = $row.FullPath
        if ([string]::IsNullOrWhiteSpace($fp) -or -not (Test-Path -LiteralPath $fp)) {
            Write-Host "  [SKIP] $($row.FileName): file not at recorded FullPath" -ForegroundColor Yellow
            $skippedNoFile++
            continue
        }
        $fi = Get-Item -LiteralPath $fp
        if ($fi.Length -eq 0) { Write-Host "  [SKIP] $($row.FileName): zero bytes" -ForegroundColor Yellow; $skippedNoFile++; continue }
        if ($fi.Length -gt $MaxFileSizeBytes) {
            Write-Host ("  [SKIP] {0}: too large ({1:N1}MB > {2:N0}MB direct-upload limit)" -f $row.FileName, ($fi.Length / 1MB), ($MaxFileSizeBytes / 1MB)) -ForegroundColor Yellow
            $skippedBig++
            continue
        }

        $uploadMode = if ($fi.Length -le 32MB) { 'direct' } else { 'upload_url (2-step)' }
        Write-Host ("  Submitting {0} ({1:N1} KB, {2})..." -f $row.FileName, ($fi.Length / 1KB), $uploadMode) -ForegroundColor Yellow
        try {
            $analysisId  = Submit-OtVTFile -FileInfo $fi
            $mainOutPath = Join-Path $mainBase "$h.json"
            $behOutPath  = Join-Path $behBase  "$h.json"
            [PSCustomObject]@{
                Hash                = $h
                FileName            = $row.FileName
                AnalysisId          = $analysisId
                SubmittedAt         = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                MainOutputPath      = $mainOutPath
                BehaviorsOutputPath = $behOutPath
            } | Export-Csv -Path $pendingPath -Append -NoTypeInformation
            Write-Host "    [OK] analysis_id=$analysisId" -ForegroundColor Green
            $submitted++
        } catch {
            if ($_.Exception.Message -like 'VT_ALL_KEYS_EXHAUSTED*') {
                Write-Host "  [!] $($_.Exception.Message)" -ForegroundColor Red
                $script:OtQuotaHit = $true
                break
            }
            Write-Host "    [ERROR] $($_.Exception.Message)" -ForegroundColor Red
            $errors++
        }
    }

    Write-Host ""
    Write-Host "[DONE] submitted=$submitted pending-already=$skippedPend not-missing=$skipped404 too-big=$skippedBig no-file=$skippedNoFile errors=$errors"
    if ($script:OtQuotaHit) {
        Write-Host "       Run stopped early due to VT quota." -ForegroundColor Yellow
    }
    if ($submitted -gt 0) {
        Write-Host ""
        Write-Host "Next: wait 5-30 minutes, then run option 5z to poll for completed analyses." -ForegroundColor DarkCyan
    }
}

function Sync-VTPendingSubmissions {
    [CmdletBinding()]
    param(
        [string]$ProxyRegion,
        [string]$Proxy,
        [pscredential]$ProxyCredential,
        [string]$Keys
    )

    $pendingPath = "output\PendingVTSubmissions.csv"
    if (-not (Test-Path $pendingPath)) {
        Write-Host "No pending submissions tracker at $pendingPath - nothing to do."
        return
    }

    $rows = @(Import-Csv $pendingPath)
    if ($rows.Count -eq 0) {
        Write-Host "Tracker is empty - nothing to poll."
        return
    }

    Write-Host ""
    Write-Host "=== Polling $($rows.Count) pending VT submissions ===" -ForegroundColor Cyan

    if (-not (Initialize-OtVTClient -ProxyRegion $ProxyRegion -Proxy $Proxy -ProxyCredential $ProxyCredential -Keys $Keys)) {
        return
    }

    # Load 404 tracker so we can DEREGISTER hashes that successfully complete
    $missingHashesPath = "output\MissingHashes.csv"
    $missingHashes = New-Object System.Collections.Generic.List[object]
    if (Test-Path $missingHashesPath) {
        $missingHashes = @(Import-Csv $missingHashesPath)
    }

    $remaining   = New-Object System.Collections.Generic.List[object]
    $completed   = 0
    $stillPending = 0
    $expired     = 0
    $errors      = 0

    $script:OtQuotaHit = $false
    foreach ($row in $rows) {
        if ($script:OtQuotaHit) { $remaining.Add($row); continue }

        Write-Host "  $($row.FileName) [$($row.AnalysisId)]" -ForegroundColor DarkGray
        try {
            $a = Invoke-OtVTRequest -Uri "https://www.virustotal.com/api/v3/analyses/$($row.AnalysisId)"
            $status = $a.data.attributes.status
            if ($status -eq 'completed') {
                Write-Host "    [COMPLETED] pulling main + behaviors..." -ForegroundColor Green
                $mainDir = Split-Path -Parent $row.MainOutputPath
                $behDir  = Split-Path -Parent $row.BehaviorsOutputPath
                if (-not (Test-Path $mainDir)) { New-Item -ItemType Directory -Path $mainDir -Force | Out-Null }
                if (-not (Test-Path $behDir))  { New-Item -ItemType Directory -Path $behDir  -Force | Out-Null }
                try {
                    $main = Invoke-OtVTRequest -Uri "https://www.virustotal.com/api/v3/files/$($row.Hash)"
                    $main | ConvertTo-Json -Depth 100 | Set-Content -Path $row.MainOutputPath
                } catch {
                    if ($_.Exception.Message -like 'VT_ALL_KEYS_EXHAUSTED*') { $script:OtQuotaHit = $true }
                    Write-Host "      [WARN] main fetch failed: $($_.Exception.Message)" -ForegroundColor Yellow
                }
                try {
                    $beh = Invoke-OtVTRequest -Uri "https://www.virustotal.com/api/v3/files/$($row.Hash)/behaviour_summary"
                    $beh | ConvertTo-Json -Depth 100 | Set-Content -Path $row.BehaviorsOutputPath
                } catch {
                    if ($_.Exception.Message -like 'VT_ALL_KEYS_EXHAUSTED*') { $script:OtQuotaHit = $true }
                }
                # Remove this hash from MissingHashes since VT now knows it
                $missingHashes = @($missingHashes | Where-Object { $_.Hash -ne $row.Hash })
                $completed++
            } else {
                Write-Host "    [STILL $($status.ToUpper())]" -ForegroundColor DarkGray
                $remaining.Add($row)
                $stillPending++
            }
        } catch {
            $code = $null; try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
            if ($_.Exception.Message -like 'VT_ALL_KEYS_EXHAUSTED*') {
                $script:OtQuotaHit = $true
                $remaining.Add($row)
            } elseif ($code -eq 404) {
                Write-Host "    [404] analysis expired - dropping from tracker" -ForegroundColor Yellow
                $expired++
            } else {
                Write-Host "    [ERROR] $($_.Exception.Message)" -ForegroundColor Red
                $errors++
                $remaining.Add($row)
            }
        }
    }

    # Rewrite the pending tracker with whatever's left
    if ($remaining.Count -eq 0) {
        Remove-Item -LiteralPath $pendingPath -Force
    } else {
        $remaining | Export-Csv -Path $pendingPath -NoTypeInformation
    }

    # Rewrite MissingHashes (we may have removed some)
    if ($missingHashes.Count -gt 0) {
        $missingHashes | Export-Csv -Path $missingHashesPath -NoTypeInformation
    } elseif (Test-Path $missingHashesPath) {
        # don't delete the file just in case - leave it as a header-only csv
        'Hash,DateChecked' | Set-Content -Path $missingHashesPath
    }

    Write-Host ""
    Write-Host "[DONE] completed=$completed still-pending=$stillPending expired=$expired errors=$errors"
    if ($script:OtQuotaHit) {
        Write-Host "       Stopped early due to VT quota." -ForegroundColor Yellow
    }
}

Export-ModuleMember -Function Get-OtBaseline, Submit-OtFilesNotInVT, Sync-VTPendingSubmissions

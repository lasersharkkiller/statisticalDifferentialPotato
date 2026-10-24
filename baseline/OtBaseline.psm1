# OtBaseline.psm1
# OT (Operational Technology) firmware baselining + opt-in VT submission.
# Separate pipeline from Get-VTBaseline because:
#   - Output goes to output-baseline/VirusTotal-{main,behaviors}/<Branch>/<Vendor>/
#     where <Branch> defaults to OT. Use -Branch autonomousSystems for UAV/UGV.
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
        [string]$Keys,
        # Enterprise tier - mirrors VTBaseline.psm1. The enterprise secret is
        # named so it cannot match the free 'VT_API_Key_*' wildcard, and with
        # -Enterprise the wildcard enumeration is skipped entirely. Free-tier
        # constants (15s/key, 499/key/day) are calibrated and untouched.
        [switch]$Enterprise,
        [string]$EnterpriseSecretName = 'VT_Enterprise_Key',
        [int]$EnterpriseMinDelayMs    = 50,
        [int]$EnterpriseCapPerDay     = 0
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
    $script:OtVTIsEnterprise = [bool]$Enterprise
    if ($Enterprise) {
        if ($EnterpriseSecretName -like 'VT_API_Key_*') {
            Write-Error ("Refusing to run: -EnterpriseSecretName '{0}' matches the free-key wildcard 'VT_API_Key_*'." -f $EnterpriseSecretName)
            return $false
        }
        $ek = $null
        try { $ek = (Get-Secret -Name $EnterpriseSecretName -AsPlainText -ErrorAction Stop).Trim() }
        catch {
            if (Get-Command Unlock-SecretStore -ErrorAction SilentlyContinue) {
                try { Unlock-SecretStore -ErrorAction Stop; $ek = (Get-Secret -Name $EnterpriseSecretName -AsPlainText -ErrorAction Stop).Trim() }
                catch { Write-Error ("Enterprise key '{0}' not readable: {1}" -f $EnterpriseSecretName, $_.Exception.Message); return $false }
            } else { Write-Error ("Enterprise key '{0}' not found in vault." -f $EnterpriseSecretName); return $false }
        }
        if ([string]::IsNullOrWhiteSpace($ek)) { Write-Error "Enterprise key is empty."; return $false }
        $script:OtVTKeys = @($ek)
        $loadedNames     = @($EnterpriseSecretName)
        Write-Host ("Using ENTERPRISE key ({0}) for OT baseline. Spacing {1}ms, cap {2}." -f `
            $EnterpriseSecretName, $EnterpriseMinDelayMs,
            $(if ($EnterpriseCapPerDay -gt 0) { $EnterpriseCapPerDay } else { 'none' })) -ForegroundColor Green
    }

    $infos = $null
    if (-not $Enterprise) {
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

    }   # end: free-tier key enumeration + subset resolution

    # --- SOFT-CAP STATE + STARTUP PROBE ---
    # $script:OtVTKeys is already set on the enterprise path; only the free path
    # populates $VTKeys.
    if (-not $Enterprise) { $script:OtVTKeys = $VTKeys }
    $script:OtVTLoadedNames       = $loadedNames
    $script:OtVTKeyLastCall       = @{}
    $script:OtVTKeyDisabledUntil  = @{}
    $script:OtVTKeyCallCount      = @{}
    if ($Enterprise) {
        $script:OtVTMinDelayMs   = [Math]::Max(0, $EnterpriseMinDelayMs)
        $script:OtVTKeyCapPerDay = if ($EnterpriseCapPerDay -gt 0) { $EnterpriseCapPerDay } else { [int]::MaxValue }
    } else {
        # Calibrated free-tier values - do not change.
        $script:OtVTMinDelayMs   = 15000
        $script:OtVTKeyCapPerDay = 499
    }

    Write-Host "Seeding per-key daily-used counters from VT..." -ForegroundColor DarkGray
    for ($j = 0; $j -lt $script:OtVTKeys.Count; $j++) {
        $script:OtVTKeyLastCall[$j]      = [DateTime]::MinValue
        $script:OtVTKeyDisabledUntil[$j] = [DateTime]::MinValue
        $used = 0
        $probeArgs = @{
            # Must read the RESOLVED key list: on the enterprise path $VTKeys
            # is never populated (only $script:OtVTKeys is), which made this
            # probe pass a null Uri and emit "Cannot index into a null array".
            Uri        = "https://www.virustotal.com/api/v3/users/$($script:OtVTKeys[$j])"
            Headers    = @{ 'x-apikey' = $script:OtVTKeys[$j] }
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
        # Stage to temp before submitting. Passing the FileInfo straight to
        # Invoke-RestMethod -Form throws UnauthorizedAccessException on files
        # under C:\Program Files, because -Form opens the file demanding more
        # than read access - verified 2026-10-07: [System.IO.File]::OpenRead()
        # on the identical path succeeds while -Form fails. That silently cost
        # 24 of 31 DJI submissions, including every DJI*Service.dll and every
        # driver .cat/.inf. Copying first costs one local write and makes
        # read-only install directories submittable.
        $staged = Join-Path ([System.IO.Path]::GetTempPath()) ("vtsm-" + [Guid]::NewGuid().ToString('N') + ".bin")
        try {
            Copy-Item -LiteralPath $FileInfo.FullName -Destination $staged -Force -ErrorAction Stop
            # Copy-Item preserves the source's ReadOnly attribute, and -Form opens the
            # file demanding more than read access - so a ReadOnly source still failed
            # here with "Access to the path '...vtsm-....bin' is denied", even though
            # staging was supposed to be the fix for exactly that error. Extracted
            # firmware is full of ReadOnly files: this silently skipped 1,449 of a
            # 6,250-file submission (23%) on 2026-10-22. Clear it on our own copy.
            $stagedItem = Get-Item -LiteralPath $staged
            if ($stagedItem.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
                $stagedItem.Attributes = [System.IO.FileAttributes]::Normal
                $stagedItem.Refresh()
            }
            $form = @{ file = $stagedItem }
            $response = Invoke-OtVTRequest -Uri 'https://www.virustotal.com/api/v3/files' -Method 'POST' -Form $form
            return $response.data.id
        } finally {
            Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
        }
    }

    # Two-step path for >32MB
    $urlResp   = Invoke-OtVTRequest -Uri 'https://www.virustotal.com/api/v3/files/upload_url'
    $uploadUrl = $urlResp.data
    if ([string]::IsNullOrWhiteSpace($uploadUrl)) {
        throw "VT did not return an upload_url (account tier may not allow >32MB uploads)"
    }

    # TWO bugs were in play here, diagnosed 2026-10-01. Both real:
    #
    # 1. The big-file POST REQUIRES the x-apikey header. The original comment
    #    asserted the one-time URL "embeds auth" and deliberately omitted it.
    #    Unauthenticated, VT answers 401 AuthenticationRequiredError.
    # 2. Independently, .NET's multipart serialisation is rejected by the
    #    blobstore handler at bigfiles.virustotal.com with HTTP 400 "Malformed
    #    multipart body." - with or without x-apikey, with Invoke-RestMethod
    #    -Form or a hand-built MultipartFormDataContent, with the boundary
    #    quoted or unquoted, and with or without an explicit Content-Length.
    #    A 2 KB file fails identically to a 335 MB one, so it is framing, not
    #    size. curl sends a body the same endpoint accepts (verified: 200 +
    #    analysis id on the same URL and file), so this path shells out to
    #    curl.exe, which ships with Windows 10+.
    #
    # The key is passed via a -K config file, never on the command line, so it
    # does not appear in the process table. The file is written to the user
    # profile (not a world-readable temp dir) and deleted in finally.
    $curl = (Get-Command curl.exe -ErrorAction SilentlyContinue).Source
    if (-not $curl) {
        throw "curl.exe not found - required for VT uploads >32MB (see Submit-OtVTFile). Files <=32MB are unaffected."
    }
    $cfg = Join-Path ([System.IO.Path]::GetTempPath()) ("vtup-" + [Guid]::NewGuid().ToString('N') + ".cfg")

    # Third bug, found 2026-10-01: every >32MB upload failed with
    # "curl: (26) Failed to open/read local data from file/application".
    # curl.exe opens files through the ANSI Win32 API, so unlike .NET it cannot
    # read a path longer than 260 characters - and several OT extraction paths
    # run 300-550. Independently, curl's -F/form syntax treats ',' as a
    # separator between file specs and ';' as the start of a parameter, and OT
    # firmware really does ship directories like
    # "RHEL 8-9, Alma 8-9, Ubuntu 20-24, SUSE 15". Staging the file at a short,
    # plain temp path fixes both at once, and costs one local copy.
    $staged = Join-Path ([System.IO.Path]::GetTempPath()) ("vtup-" + [Guid]::NewGuid().ToString('N') + ".bin")
    Copy-Item -LiteralPath $FileInfo.FullName -Destination $staged -Force
    # Keep the real filename for VT's UI, minus characters curl's form parser eats.
    $safeName = ($FileInfo.Name -replace '[,;"]', '_')

    try {
        $cfgLines = @(
            'header = "x-apikey: ' + $script:OtVTKeys[0] + '"'
            'request = POST'
            'form = "file=@' + ($staged.Replace([char]92,[char]47)) + ';filename=' + $safeName + '"'
            'silent'
            'show-error'
            'max-time = 1800'
            'write-out = "\nHTTPSTATUS:%{http_code}"'
        )
        if ($script:OtVTProxy) { $cfgLines += ('proxy = "' + $script:OtVTProxy + '"') }
        Set-Content -LiteralPath $cfg -Value $cfgLines -Encoding UTF8
        $raw = & $curl -K $cfg $uploadUrl 2>&1 | Out-String
        $code = if ($raw -match 'HTTPSTATUS:(\d+)') { [int]$Matches[1] } else { 0 }
        $json = ($raw -replace 'HTTPSTATUS:\d+\s*$','').Trim()
        if ($code -lt 200 -or $code -ge 300) {
            throw ("VT big-file upload failed: HTTP {0} - {1}" -f $code, $json)
        }
        return ($json | ConvertFrom-Json).data.id
    } finally {
        Remove-Item -LiteralPath $cfg    -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
    }
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

function Test-IsExecutableArtifact {
    # True when the file's magic says it can execute or carries code:
    # ELF (Linux binaries, .so, .ko), shebang scripts, PE (Windows),
    # zip/jar containers, Java class files.
    #
    # Used by -ExecutableOnly. Extension matching is not good enough here:
    # embedded Linux trees carry versioned libraries (libfoo.so.1.2.3),
    # extensionless binaries in /bin, and .ko modules, while ~84% of a
    # firmware catalog is inert text, packaging metadata and assets that
    # VT has no intelligence on. Reads 4 bytes via .NET so long (>260
    # char) paths still open - Windows' own APIs refuse those.
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $n = 0
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        try {
            $b = [byte[]]::new(4)
            $n = $fs.Read($b, 0, 4)
        } finally { $fs.Dispose() }
    } catch { return $false }
    if ($n -lt 2) { return $false }
    if ($b[0] -eq 0x7F -and $b[1] -eq 0x45 -and $b[2] -eq 0x4C -and $b[3] -eq 0x46) { return $true }  # ELF
    if ($b[0] -eq 0x23 -and $b[1] -eq 0x21) { return $true }                                          # shebang
    if ($b[0] -eq 0x4D -and $b[1] -eq 0x5A) { return $true }                                          # PE/MZ
    if ($b[0] -eq 0x50 -and $b[1] -eq 0x4B -and $b[2] -eq 0x03 -and $b[3] -eq 0x04) { return $true }  # zip/jar
    if ($b[0] -eq 0xCA -and $b[1] -eq 0xFE -and $b[2] -eq 0xBA -and $b[3] -eq 0xBE) { return $true }  # Java class
    return $false
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
        [string]$Keys,
        [switch]$ExecutableOnly,
        # Corpus branch under output-baseline. Defaults to OT so every existing
        # caller is unchanged; 'autonomousSystems' keeps UAV/UGV (DJI, Yahboom)
        # out of both the OT and IT corpora, which matters because the fidelity
        # index treats each branch as a separate population.
        [string]$Branch = 'OT',
        # Enterprise tier - see Initialize-OtVTClient. Free-tier throttle
        # constants (15s/key, 499/key/day) are calibrated and unaffected.
        [switch]$Enterprise,
        [string]$EnterpriseSecretName = 'VT_Enterprise_Key',
        [int]$EnterpriseMinDelayMs    = 50,
        [int]$EnterpriseCapPerDay     = 0,
        # Set by the parallel orchestrator: new 404s are appended to
        # MissingHashes<suffix>.csv instead of the shared tracker, because
        # Export-Csv -Append is not safe across processes. The orchestrator
        # merges the parts when every worker has finished.
        [string]$TrackerSuffix = ''
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

    if (-not (Initialize-OtVTClient -ProxyRegion $ProxyRegion -Proxy $Proxy -ProxyCredential $ProxyCredential -Keys $Keys -Enterprise:$Enterprise -EnterpriseSecretName $EnterpriseSecretName -EnterpriseMinDelayMs $EnterpriseMinDelayMs -EnterpriseCapPerDay $EnterpriseCapPerDay)) {
        return
    }

    # Flat per-vendor cache so SHA256s shared across products of the same
    # vendor (rebadged firmware, common libc, busybox, etc.) only consume
    # one VT lookup. Per-product mapping lives in catalog.csv.
    $mainBase = "output-baseline\VirusTotal-main\$Branch\$Vendor"
    $behBase  = "output-baseline\VirusTotal-behaviors\$Branch\$Vendor"
    New-Item -ItemType Directory -Path $mainBase -Force | Out-Null
    New-Item -ItemType Directory -Path $behBase  -Force | Out-Null

    # Load 404 trackers
    $missingHashesPath = if ($TrackerSuffix) { "output\MissingHashes$TrackerSuffix.csv" } else { "output\MissingHashes.csv" }
    $missingHashes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    # Explicit list, NOT MissingHashes*.csv - that glob also matches the sync
    # orchestrator's MissingHashesRemove.sync<N>.csv files, which would load
    # deregistrations as if they were fresh 404s.
    $mhParts = @($missingHashesPath) + @(Get-ChildItem 'output\MissingHashes.q*.csv' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    if ($TrackerSuffix) { $mhParts += 'output\MissingHashes.csv' }
    foreach ($mf in @($mhParts | Sort-Object -Unique | Where-Object { Test-Path $_ })) {
        Import-Csv $mf | ForEach-Object { if ($_.Hash) { [void]$missingHashes.Add($_.Hash) } }
    }
    $missingBehaviorsPath = "output\MissingBehaviors.csv"
    $missingBehaviors = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if (Test-Path $missingBehaviorsPath) {
        Import-Csv $missingBehaviorsPath | ForEach-Object { if ($_.Hash) { [void]$missingBehaviors.Add($_.Hash) } }
    }

    $rows = @(Import-Csv $CatalogCsv)
    if ($ExecutableOnly) {
        $before = $rows.Count
        $rows = @($rows | Where-Object { Test-IsExecutableArtifact $_.FullPath })
        Write-Host ("  Filter:   -ExecutableOnly kept {0} of {1} rows ({2} skipped)" -f $rows.Count, $before, ($before - $rows.Count)) -ForegroundColor DarkCyan
    }
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
        [int64]$MaxFileSizeBytes = 650MB,
        # See -Branch on Get-OtBaseline.
        [string]$Branch = 'OT',
        # Set by the parallel orchestrator so concurrent workers never append to
        # the same CSV (Export-Csv -Append is not safe across processes). Worker
        # files are merged back into the real trackers when the run finishes.
        [string]$TrackerSuffix = '',
        # Enterprise tier - see Initialize-OtVTClient. Free-tier throttle
        # constants (15s/key, 499/key/day) are calibrated and unaffected.
        [switch]$Enterprise,
        [string]$EnterpriseSecretName = 'VT_Enterprise_Key',
        [int]$EnterpriseMinDelayMs    = 50,
        [int]$EnterpriseCapPerDay     = 0
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

    if (-not (Initialize-OtVTClient -ProxyRegion $ProxyRegion -Proxy $Proxy -ProxyCredential $ProxyCredential -Keys $Keys -Enterprise:$Enterprise -EnterpriseSecretName $EnterpriseSecretName -EnterpriseMinDelayMs $EnterpriseMinDelayMs -EnterpriseCapPerDay $EnterpriseCapPerDay)) {
        return
    }

    # Load trackers
    $missingHashesPath = "output\MissingHashes.csv"
    $missingHashes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if (Test-Path $missingHashesPath) {
        Import-Csv $missingHashesPath | ForEach-Object { if ($_.Hash) { [void]$missingHashes.Add($_.Hash) } }
    }

    $pendingPath = if ($TrackerSuffix) { "output\PendingVTSubmissions$TrackerSuffix.csv" } else { "output\PendingVTSubmissions.csv" }
    $pendingHashes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($pf in @(Get-ChildItem 'output\PendingVTSubmissions*.csv' -ErrorAction SilentlyContinue)) {
        Import-Csv $pf.FullName | ForEach-Object { if ($_.Hash) { [void]$pendingHashes.Add($_.Hash) } }
    }

    # Flat per-vendor cache (same scheme as Get-OtBaseline).
    $mainBase = "output-baseline\VirusTotal-main\$Branch\$Vendor"
    $behBase  = "output-baseline\VirusTotal-behaviors\$Branch\$Vendor"

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
        if ($fi.Length -eq 0) {
            Write-Host "  [SKIP] $($row.FileName): zero bytes" -ForegroundColor Yellow
            [void]$pendingHashes.Add($h)   # content-derived: no other path for this hash will differ
            $skippedNoFile++
            continue
        }
        if ($fi.Length -gt $MaxFileSizeBytes) {
            Write-Host ("  [SKIP] {0}: too large ({1:N1}MB > {2:N0}MB direct-upload limit)" -f $row.FileName, ($fi.Length / 1MB), ($MaxFileSizeBytes / 1MB)) -ForegroundColor Yellow
            [void]$pendingHashes.Add($h)
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
            # Durable, append-only record of what WE introduced to VT. Required
            # because PendingVTSubmissions.csv has rows removed as analyses
            # complete, so it cannot answer "what did we contribute". A 404'd
            # hash means VT had never seen it, so we are the first submitter.
            try {
                $ledgerPath = if ($TrackerSuffix) { "output\metrics\VTSubmissionLedger$TrackerSuffix.csv" } else { "output\metrics\VTSubmissionLedger.csv" }
                $ledgerDir  = Split-Path $ledgerPath -Parent
                if (-not (Test-Path $ledgerDir)) { New-Item -ItemType Directory -Path $ledgerDir -Force | Out-Null }
                $nowUtc = [DateTime]::UtcNow
                [PSCustomObject]@{
                    Hash               = $h
                    Branch             = 'OT'
                    CatalogPath        = "$Vendor\$Category\$Product"
                    WeekISO            = ('{0}-W{1:D2}' -f [System.Globalization.ISOWeek]::GetYear($nowUtc), [System.Globalization.ISOWeek]::GetWeekOfYear($nowUtc))
                    FirstSubmissionUtc = $nowUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
                    UniqueSources      = 1
                    TimesSubmitted     = ''
                    SizeBytes          = $fi.Length
                    Provenance         = 'ledger-exact'
                } | Export-Csv -Path $ledgerPath -Append -NoTypeInformation
            } catch {
                Write-Host "    [WARN] ledger append failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
            }

            # Track in-memory too: the same content hash recurs across many catalog
            # rows (same file at different paths / in different firmware images).
            # Without this the hash is resubmitted once per row - one hash was
            # submitted 257 times, wasting ~34% of a submission run's quota.
            [void]$pendingHashes.Add($h)
            Write-Host "    [OK] analysis_id=$analysisId" -ForegroundColor Green
            $submitted++
        } catch {
            if ($_.Exception.Message -like 'VT_ALL_KEYS_EXHAUSTED*') {
                Write-Host "  [!] $($_.Exception.Message)" -ForegroundColor Red
                $script:OtQuotaHit = $true
                break
            }
            if ($_.Exception.Message -like '*Access to the path*is denied*') {
                # Keep the real message: this class of error is usually NOT an
                # ACL problem on the source file (see Submit-OtVTFile).
                Write-Host "    [SKIP] $($row.FileName): access denied - $($_.Exception.Message)" -ForegroundColor Yellow
                [void]$pendingHashes.Add($h)
                $skippedNoFile++
            } else {
                Write-Host "    [ERROR] $($_.Exception.Message)" -ForegroundColor Red
                # Suppress per-row retry storms for this hash within this run; a
                # later run retries it, since it never reached the pending CSV.
                [void]$pendingHashes.Add($h)
                $errors++
            }
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
        [string]$Keys,
        # Enterprise tier - see Initialize-OtVTClient. Free-tier throttle
        # constants (15s/key, 499/key/day) are calibrated and unaffected.
        [switch]$Enterprise,
        [string]$EnterpriseSecretName = 'VT_Enterprise_Key',
        [int]$EnterpriseMinDelayMs    = 50,
        [int]$EnterpriseCapPerDay     = 0,
        # Set by the parallel orchestrator. Each worker polls its own slice of the
        # pending tracker and, instead of rewriting MissingHashes.csv (where the
        # last writer would clobber every other worker's deregistrations), writes
        # what it confirmed into MissingHashesRemove<suffix>.csv for the
        # orchestrator to apply exactly once.
        [string]$TrackerSuffix = ''
    )

    $pendingPath = if ($TrackerSuffix) { "output\PendingVTSubmissions$TrackerSuffix.csv" } else { "output\PendingVTSubmissions.csv" }
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

    if (-not (Initialize-OtVTClient -ProxyRegion $ProxyRegion -Proxy $Proxy -ProxyCredential $ProxyCredential -Keys $Keys -Enterprise:$Enterprise -EnterpriseSecretName $EnterpriseSecretName -EnterpriseMinDelayMs $EnterpriseMinDelayMs -EnterpriseCapPerDay $EnterpriseCapPerDay)) {
        return
    }

    # Hashes this worker confirmed VT now has (sharded mode only).
    $confirmedHashes = New-Object System.Collections.Generic.List[string]

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
                if ($TrackerSuffix) {
                    [void]$confirmedHashes.Add($row.Hash)
                } else {
                    $missingHashes = @($missingHashes | Where-Object { $_.Hash -ne $row.Hash })
                }
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

    if ($TrackerSuffix) {
        # Sharded: hand deregistrations to the orchestrator; never touch the
        # shared MissingHashes.csv from a worker.
        $removePath = "output\MissingHashesRemove$TrackerSuffix.csv"
        @($confirmedHashes | ForEach-Object { [pscustomobject]@{ Hash = $_ } }) |
            Export-Csv -Path $removePath -NoTypeInformation
        Write-Host ""
        Write-Host "[DONE] completed=$completed still-pending=$stillPending expired=$expired errors=$errors deregistered=$($confirmedHashes.Count)"
        if ($script:OtQuotaHit) { Write-Host "       Stopped early due to VT quota." -ForegroundColor Yellow }
        return
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

function Get-NSRLOsSlug {
    param([string]$OsName)
    if ([string]::IsNullOrWhiteSpace($OsName)) { return $null }
    $slug = $OsName -replace ' Version \S+(\s+X64)?$', ''
    $slug = $slug -replace ' LTS$', ''
    $slug = $slug -replace '\s+', '-'
    return $slug
}

function Get-VTProxyForRegion {
    # Maps a short region name to a (Proxy URL, user-secret-name, password-secret-name)
    # triple. Used by -ProxyRegion on Get-VTBaseline / Get-AptMasterIntelVT*.
    # To add a new provider/region, append an entry here and store the matching
    # secrets in your SecretManagement vault.
    param([string]$Region)

    $regions = @{
        'pia-nl' = @{
            Proxy      = 'socks5://proxy-nl.privateinternetaccess.com:1080'
            UserSecret = 'PIA_SOCKS_User'
            PassSecret = 'PIA_SOCKS_Password'
        }
        # Add more once you've configured additional providers, e.g.:
        # 'mullvad-se' = @{
        #     Proxy      = 'socks5://se-mma-wg-001.relays.mullvad.net:1080'
        #     UserSecret = 'MULLVAD_SOCKS_User'
        #     PassSecret = 'MULLVAD_SOCKS_Password'
        # }
        # 'vps-fra' = @{
        #     Proxy      = 'socks5://fra1.my-vps.example:1080'
        #     UserSecret = 'VPS_FRA_User'
        #     PassSecret = 'VPS_FRA_Password'
        # }
    }

    if ([string]::IsNullOrWhiteSpace($Region) -or $Region -eq 'direct') {
        return $null  # no proxy
    }
    $key = $Region.ToLowerInvariant()
    if (-not $regions.ContainsKey($key)) {
        $known = ($regions.Keys | Sort-Object) -join ', '
        throw "Unknown proxy region '$Region'. Known regions: $known. Use 'direct' or omit for no proxy."
    }
    return $regions[$key]
}

function Get-PlatformBaselineRoots {
    # Returns the list of directories that make up the "known-good" corpus
    # for differential analysis, filtered by platform.
    #
    # All     -> NSRL/ (all OSes) + localBaseline/ (all sigs)
    # Windows -> NSRL/Windows-*/  + localBaseline/{SignedVerified,unsignedWin,unverified,drivers}/
    # Linux   -> NSRL/<non-Windows>/ + localBaseline/unsignedLinux/
    #
    # NSRL OS subfolders are auto-discovered; classification by slug prefix
    # (Windows-* vs everything else) so new OSes work without code changes.
    param(
        [string]$BasePath = "output-baseline\VirusTotal-main",
        [ValidateSet('All','Windows','Linux')]
        [string]$Platform = 'All'
    )

    $nsrlRoot  = Join-Path $BasePath 'NSRL'
    $localRoot = Join-Path $BasePath 'localBaseline'

    if ($Platform -eq 'All') {
        return @($nsrlRoot, $localRoot)
    }

    $roots = @()
    if (Test-Path $nsrlRoot) {
        Get-ChildItem -Path $nsrlRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $isWin = ($_.Name -match '^Windows')
            if (($Platform -eq 'Windows' -and $isWin) -or ($Platform -eq 'Linux' -and -not $isWin)) {
                $roots += $_.FullName
            }
        }
    }
    $sigs = if ($Platform -eq 'Windows') { @('SignedVerified','unsignedWin','unverified','drivers') }
            else                          { @('unsignedLinux') }
    foreach ($sig in $sigs) {
        $p = Join-Path $localRoot $sig
        if (Test-Path $p) { $roots += $p }
    }
    return $roots
}

function Get-VTBaseline {
    [CmdletBinding()]
    param(
        [ValidateSet('All','NSRL','NSRLOs','LocalBaseline','Malicious')]
        [string]$Mode = 'All',
        [string]$OsFilter,
        [string]$AttributionPattern = "equifax",
        # Short region name (e.g. 'pia-nl'). Resolved via Get-VTProxyForRegion to
        # a Proxy URL + matching credential secret names. Falls back to
        # $env:VT_PROXY_REGION when omitted. Use 'direct' or leave empty for no proxy.
        [string]$ProxyRegion,
        # Explicit proxy URL, e.g. 'socks5://proxy-nl.privateinternetaccess.com:1080'.
        # Overrides -ProxyRegion's proxy if both are set. Falls back to $env:VT_PROXY.
        [string]$Proxy,
        # Explicit credentials for the proxy. Overrides whatever -ProxyRegion would
        # have resolved. Final fallback is an interactive Get-Credential prompt.
        [pscredential]$ProxyCredential
    )

    if ($Mode -eq 'NSRLOs' -and [string]::IsNullOrWhiteSpace($OsFilter)) {
        Write-Error "Mode 'NSRLOs' requires -OsFilter to be specified."
        return
    }

    # --- PROXY RESOLUTION ---
    if ([string]::IsNullOrWhiteSpace($ProxyRegion)) { $ProxyRegion = $env:VT_PROXY_REGION }
    $regionInfo = Get-VTProxyForRegion -Region $ProxyRegion
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
    $script:VTProxy           = $Proxy
    $script:VTProxyCredential = $ProxyCredential
    if ($Proxy) {
        $regionTag = if ($ProxyRegion) { " region=$ProxyRegion" } else { '' }
        Write-Host ("Proxy: {0}{1} (user: {2})" -f $Proxy, $regionTag, $ProxyCredential.UserName) -ForegroundColor DarkCyan
    } else {
        Write-Host "Proxy: <none> (direct connection)" -ForegroundColor DarkGray
    }

    # --- API SETUP ---
    $VTKeys = @()
    try {
        $infos = Get-SecretInfo -Name 'VT_API_Key_*' -ErrorAction Stop |
                 Sort-Object { if ($_.Name -match '_(\d+)$') { [int]$matches[1] } else { [int]::MaxValue } }
    } catch {
        Write-Error "Unable to enumerate secrets matching 'VT_API_Key_*'. Is SecretManagement loaded and a vault registered?"
        return
    }

    $loadedNames = @()
    foreach ($info in $infos) {
        try {
            $k = (Get-Secret -Name $info.Name -AsPlainText -ErrorAction Stop).Trim()
            if (-not [string]::IsNullOrWhiteSpace($k) -and $VTKeys -notcontains $k) {
                $VTKeys += $k
                $loadedNames += $info.Name
            }
        } catch {
            Write-Host "[WARN] Could not load $($info.Name) from vault." -ForegroundColor Yellow
        }
    }

    if ($VTKeys.Count -eq 0) {
        Write-Error "No VT API keys found in vault (expected one or more VT_API_Key_* secrets, e.g. VT_API_Key_1, VT_API_Key_2)."
        return
    }

    Write-Host ""
    Write-Host "Available VT API keys:" -ForegroundColor DarkCyan
    for ($i = 0; $i -lt $VTKeys.Count; $i++) {
        $k  = $VTKeys[$i]
        $fp = $k.Substring(0,6) + '...' + $k.Substring($k.Length-4)
        Write-Host ("  {0,2}) {1,-16}  {2}" -f ($i + 1), $loadedNames[$i], $fp) -ForegroundColor DarkCyan
    }
    Write-Host ("  {0,2}) ALL keys (default)" -f ($VTKeys.Count + 1)) -ForegroundColor DarkCyan
    Write-Host ""
    $keyChoice = (Read-Host "Which key(s) to use? (comma-separated numbers, '$($VTKeys.Count + 1)' or 'all' for all; Enter=all)").Trim()

    $useAll = [string]::IsNullOrWhiteSpace($keyChoice) -or
              $keyChoice -ieq 'all' -or
              $keyChoice -eq ($VTKeys.Count + 1).ToString()

    if (-not $useAll) {
        $selectedIdxs = @($keyChoice -split '[,\s]+' |
            Where-Object { $_ -match '^\d+$' } |
            ForEach-Object { [int]$_ - 1 } |
            Where-Object { $_ -ge 0 -and $_ -lt $VTKeys.Count } |
            Sort-Object -Unique)
        if ($selectedIdxs.Count -eq 0) {
            Write-Host "[WARN] No valid keys selected from '$keyChoice'; using ALL keys." -ForegroundColor Yellow
        } else {
            $VTKeys      = @($selectedIdxs | ForEach-Object { $VTKeys[$_] })
            $loadedNames = @($selectedIdxs | ForEach-Object { $loadedNames[$_] })
        }
    }

    Write-Host "Using $($VTKeys.Count) VT API key(s) ($($loadedNames -join ', ')). Rotating with 15s spacing per key (~$($VTKeys.Count * 4) req/min combined)." -ForegroundColor DarkCyan

    $script:VTMinDelayMs       = 15000
    $script:VTKeyLastCall      = @{}
    $script:VTKeyDisabledUntil = @{}
    for ($j = 0; $j -lt $VTKeys.Count; $j++) {
        $script:VTKeyLastCall[$j]      = [DateTime]::MinValue
        $script:VTKeyDisabledUntil[$j] = [DateTime]::MinValue
    }

    function Invoke-VTRequest {
        param([string]$Uri, [string]$Method = "Get")

        for ($attempt = 0; $attempt -lt $VTKeys.Count; $attempt++) {
            $now           = [DateTime]::UtcNow
            $chosenIdx     = -1
            $earliestReady = [DateTime]::MaxValue
            $activeCount   = 0

            for ($k = 0; $k -lt $VTKeys.Count; $k++) {
                if ($script:VTKeyDisabledUntil[$k] -gt $now) { continue }
                $activeCount++
                $readyAt = $script:VTKeyLastCall[$k].AddMilliseconds($script:VTMinDelayMs)
                if ($readyAt -le $now) {
                    $chosenIdx = $k
                    break
                }
                if ($readyAt -lt $earliestReady) {
                    $earliestReady = $readyAt
                    $chosenIdx     = $k
                }
            }

            if ($activeCount -eq 0) {
                $next = ($script:VTKeyDisabledUntil.Values | Measure-Object -Minimum).Minimum
                throw "VT_ALL_KEYS_EXHAUSTED: every key 429'd; earliest re-enable $($next.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
            }

            $waitMs = ($script:VTKeyLastCall[$chosenIdx].AddMilliseconds($script:VTMinDelayMs) - [DateTime]::UtcNow).TotalMilliseconds
            if ($waitMs -gt 0) {
                $waitSec = [Math]::Round($waitMs / 1000, 1)
                Write-Host "    [Rate Limit] Key $($chosenIdx + 1) cooling down - waiting ${waitSec}s..." -ForegroundColor DarkGray
                Start-Sleep -Milliseconds ([Math]::Ceiling($waitMs))
            }

            $script:VTKeyLastCall[$chosenIdx] = [DateTime]::UtcNow
            $Headers = @{ "x-apikey" = $VTKeys[$chosenIdx]; "Content-Type" = "application/json" }

            $proxyArgs = @{}
            if ($script:VTProxy) {
                $proxyArgs['Proxy'] = $script:VTProxy
                if ($script:VTProxyCredential) { $proxyArgs['ProxyCredential'] = $script:VTProxyCredential }
            }

            try {
                return Invoke-RestMethod -Uri $Uri -Headers $Headers -Method $Method @proxyArgs
            } catch {
                $code = $null
                try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
                if ($code -ne 429) { throw }

                $retryAfterSec = $null
                try {
                    $ra = $_.Exception.Response.Headers.RetryAfter
                    if ($ra) {
                        if ($ra.Delta -and $ra.Delta.TotalSeconds -gt 0) {
                            $retryAfterSec = [int]$ra.Delta.TotalSeconds
                        } elseif ($ra.Date) {
                            $retryAfterSec = [int](($ra.Date - [DateTimeOffset]::UtcNow).TotalSeconds)
                        }
                    }
                } catch {}
                if (-not $retryAfterSec) {
                    try { $retryAfterSec = [int]$_.Exception.Response.Headers['Retry-After'] } catch {}
                }
                $disabledUntil = if ($retryAfterSec -and $retryAfterSec -gt 0) {
                    [DateTime]::UtcNow.AddSeconds($retryAfterSec)
                } else {
                    [DateTime]::UtcNow.Date.AddDays(1)
                }
                if ($disabledUntil -gt $script:VTKeyDisabledUntil[$chosenIdx]) {
                    $script:VTKeyDisabledUntil[$chosenIdx] = $disabledUntil
                }
                Write-Host "    [Rate Limit] Key $($chosenIdx + 1) hit 429; disabled until $($disabledUntil.ToString('yyyy-MM-dd HH:mm:ss')) UTC. Rotating to next key..." -ForegroundColor Yellow
            }
        }

        throw "VT_ALL_KEYS_EXHAUSTED: retry budget exhausted while attempting $Uri"
    }

    # --- MODE FLAGS ---
    $doProcs     = ($Mode -in @('All','LocalBaseline'))
    $doNSRL      = ($Mode -in @('All','NSRL','NSRLOs'))
    $doMalicious = ($Mode -in @('All','Malicious'))
    $doDrivers   = ($Mode -in @('All','LocalBaseline'))
    Write-Host "Mode: $Mode  (procs=$doProcs nsrl=$doNSRL malicious=$doMalicious drivers=$doDrivers$(if($OsFilter){"  osFilter=$OsFilter"}))" -ForegroundColor DarkCyan

    # --- PATH CONFIG ---
    $mainBase = "output-baseline\VirusTotal-main"
    $behBase  = "output-baseline\VirusTotal-behaviors"
    $localMain     = Join-Path $mainBase 'localBaseline'
    $localBeh      = Join-Path $behBase  'localBaseline'
    $maliciousMain = Join-Path $mainBase 'malicious'
    $maliciousBeh  = Join-Path $behBase  'malicious'
    $nsrlMain      = Join-Path $mainBase 'NSRL'
    $nsrlBeh       = Join-Path $behBase  'NSRL'

    foreach ($p in @($localMain, $localBeh, $maliciousMain, $maliciousBeh, $nsrlMain, $nsrlBeh)) {
        New-Item -ItemType Directory -Path $p -Force | Out-Null
    }

    # --- WARN IF OLD-LAYOUT FILES STILL EXIST ---
    $stale = @()
    foreach ($base in @($mainBase, $behBase)) {
        foreach ($sig in @('SignedVerified','unsignedWin','unsignedLinux','unverified','drivers')) {
            $p = Join-Path $base $sig
            if (Test-Path $p) {
                $c = (Get-ChildItem -Path $p -Filter "*.json" -File -ErrorAction SilentlyContinue).Count
                if ($c -gt 0) { $stale += "$p ($c files)" }
            }
        }
    }
    if ($stale.Count -gt 0) {
        Write-Host "[WARN] Old-layout cached files detected - run tools\Migrate-NSRLToPerOS.ps1 -Apply first:" -ForegroundColor Yellow
        foreach ($s in $stale) { Write-Host "       $s" -ForegroundColor Yellow }
    }

    # --- BUILD NSRL HASH -> OS MAP (used for NSRL-overrules-localBaseline routing) ---
    $hashToOs = @{}
    $nsrlCsvPath = "NSRL\nsrl_reduced.csv"
    if (Test-Path $nsrlCsvPath) {
        Import-Csv $nsrlCsvPath | ForEach-Object {
            if ($_.Hash -and $_.OsName) { $hashToOs[$_.Hash.ToLowerInvariant()] = $_.OsName }
        }
        Write-Host "Loaded NSRL map: $($hashToOs.Count) hash->OS entries." -ForegroundColor DarkGray
    } else {
        Write-Host "[WARN] NSRL\nsrl_reduced.csv not found - NSRL routing disabled; everything goes to localBaseline." -ForegroundColor Yellow
    }

    function Get-DestPaths {
        param([string]$Hash, [string]$Sig)
        $key = $Hash.ToLowerInvariant()
        if ($hashToOs.ContainsKey($key)) {
            $slug = Get-NSRLOsSlug $hashToOs[$key]
            return @{
                Main = Join-Path $nsrlMain (Join-Path $slug $Sig)
                Beh  = Join-Path $nsrlBeh  (Join-Path $slug $Sig)
            }
        } else {
            return @{
                Main = Join-Path $localMain $Sig
                Beh  = Join-Path $localBeh  $Sig
            }
        }
    }

    # --- LOAD MISSING HASHES TRACKER ---
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

    # --- LOAD PROCS BASELINES (only needed if doProcs/doMalicious/doDrivers) ---
    $unverifiedProcsBaseline    = @()
    $unsignedWinProcsBaseline   = @()
    $unsignedLinuxProcsBaseline = @()
    $signedVerifiedProcsBaseline = @()
    $maliciousProcsBaseline     = @()
    $driversBaseline            = @()
    if ($doProcs) {
        if (Test-Path output\unverifiedProcsBaseline.json)     { $unverifiedProcsBaseline     = Get-Content output\unverifiedProcsBaseline.json     | ConvertFrom-Json }
        if (Test-Path output\unsignedWinProcsBaseline.json)    { $unsignedWinProcsBaseline    = Get-Content output\unsignedWinProcsBaseline.json    | ConvertFrom-Json }
        if (Test-Path output\unsignedLinuxProcsBaseline.json)  { $unsignedLinuxProcsBaseline  = Get-Content output\unsignedLinuxProcsBaseline.json  | ConvertFrom-Json }
        if (Test-Path output\signedVerifiedProcsBaseline.json) { $signedVerifiedProcsBaseline = Get-Content output\signedVerifiedProcsBaseline.json | ConvertFrom-Json }
    }
    if ($doMalicious -and (Test-Path output\maliciousProcsBaseline.json)) {
        $maliciousProcsBaseline = Get-Content output\maliciousProcsBaseline.json | ConvertFrom-Json
    }
    if ($doDrivers -and (Test-Path output\driversBaseline.json)) {
        $driversBaseline = Get-Content output\driversBaseline.json | ConvertFrom-Json
    }

    # --- BUILD NSRL ENTRY LISTS (with OsName per hash for slug routing) ---
    $nsrlWindowsEntries = New-Object System.Collections.Generic.List[object]
    $nsrlLinuxEntries   = New-Object System.Collections.Generic.List[object]
    if ($doNSRL -and (Test-Path $nsrlCsvPath)) {
        Import-Csv $nsrlCsvPath | ForEach-Object {
            if (-not $_.Hash) { return }
            $entry = [pscustomobject]@{ Hash = $_.Hash; OsName = $_.OsName }
            if ($_.OsName -like '*Windows*') { $nsrlWindowsEntries.Add($entry) }
            else                              { $nsrlLinuxEntries.Add($entry)   }
        }
        Write-Host "NSRL queue: $($nsrlWindowsEntries.Count) Windows, $($nsrlLinuxEntries.Count) Linux." -ForegroundColor DarkGray
    }

    # --- HELPER: Process-Hash ---
    function Process-Hash {
        param(
            [string]$Hash,
            [string]$MainPath,
            [string]$BehaviorsPath
        )

        if ($missingHashes.Contains($Hash)) {
            Write-Host "  [SKIP] $Hash is in MissingHashes.csv - known 404." -ForegroundColor DarkGray
            return
        }

        $mainFile   = Join-Path $MainPath      "$Hash.json"
        $behaveFile = Join-Path $BehaviorsPath "$Hash.json"

        if ((Test-Path $mainFile) -and (Test-Path $behaveFile)) { return }

        if (-not (Test-Path $MainPath))      { New-Item -ItemType Directory -Path $MainPath      -Force | Out-Null }
        if (-not (Test-Path $BehaviorsPath)) { New-Item -ItemType Directory -Path $BehaviorsPath -Force | Out-Null }

        if (-not (Test-Path $mainFile)) {
            Write-Host "  Main report missing for $Hash. Querying VirusTotal..." -ForegroundColor Yellow
            try {
                $response = Invoke-VTRequest -Uri "https://www.virustotal.com/api/v3/files/$Hash"
                $response | ConvertTo-Json -Depth 10 | Set-Content -Path $mainFile
                Write-Host "  [OK] Main report saved." -ForegroundColor Green
            } catch {
                $code = $null
                try { $code = $_.Exception.Response.StatusCode.value__ } catch {}

                if ($_.Exception.Message -like 'VT_ALL_KEYS_EXHAUSTED*') {
                    Write-Host "  [!] $($_.Exception.Message)" -ForegroundColor Red
                    $script:QuotaHit = $true
                    return
                } elseif ($code -eq 404) {
                    Write-Host "  [404] $Hash not found in VT. Adding to MissingHashes.csv." -ForegroundColor DarkGray
                    [void]$missingHashes.Add($Hash)
                    [PSCustomObject]@{ Hash = $Hash; DateChecked = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ") } |
                        Export-Csv -Path $missingHashesPath -Append -NoTypeInformation
                    return
                } else {
                    Write-Host "  [ERROR] HTTP $code - $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }

        if ($script:QuotaHit) { return }

        if (-not (Test-Path $behaveFile)) {
            Write-Host "  Behaviors report missing for $Hash. Querying VirusTotal..." -ForegroundColor Yellow
            try {
                $response = Invoke-VTRequest -Uri "https://www.virustotal.com/api/v3/files/$Hash/behaviour_summary"
                $response | ConvertTo-Json -Depth 10 | Set-Content -Path $behaveFile
                Write-Host "  [OK] Behaviors report saved." -ForegroundColor Green
            } catch {
                $code = $null
                try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
                if ($_.Exception.Message -like 'VT_ALL_KEYS_EXHAUSTED*') {
                    Write-Host "  [!] $($_.Exception.Message)" -ForegroundColor Red
                    $script:QuotaHit = $true
                }
                else { Write-Host "  [ERROR] Behaviors HTTP $code - $($_.Exception.Message)" -ForegroundColor Red }
            }
        }
    }

    # --- PROCESSING ---
    $script:QuotaHit = $false

    if ($doProcs) {
        Write-Host "`nIterating Through Unverified Baseline..." -ForegroundColor DarkCyan
        foreach ($proc in $unverifiedProcsBaseline) {
            if ($script:QuotaHit) { break }
            $h = $proc.value[2]; if (-not $h) { continue }
            $p = Get-DestPaths -Hash $h -Sig 'unverified'
            Process-Hash -Hash $h -MainPath $p.Main -BehaviorsPath $p.Beh
        }

        Write-Host "`nIterating Through Windows Unsigned Baseline..." -ForegroundColor DarkCyan
        foreach ($proc in $unsignedWinProcsBaseline) {
            if ($script:QuotaHit) { break }
            $h = $proc.value[2]; if (-not $h) { continue }
            $p = Get-DestPaths -Hash $h -Sig 'unsignedWin'
            Process-Hash -Hash $h -MainPath $p.Main -BehaviorsPath $p.Beh
        }

        Write-Host "`nIterating Through Linux Unsigned Baseline..." -ForegroundColor DarkCyan
        foreach ($proc in $unsignedLinuxProcsBaseline) {
            if ($script:QuotaHit) { break }
            $h = $proc.value[2]; if (-not $h) { continue }
            $p = Get-DestPaths -Hash $h -Sig 'unsignedLinux'
            Process-Hash -Hash $h -MainPath $p.Main -BehaviorsPath $p.Beh
        }

        Write-Host "`nIterating Through SignedVerified Baseline..." -ForegroundColor DarkCyan
        foreach ($proc in $signedVerifiedProcsBaseline) {
            if ($script:QuotaHit) { break }
            $h = $proc.value[2]; if (-not $h) { continue }
            $p = Get-DestPaths -Hash $h -Sig 'SignedVerified'
            Process-Hash -Hash $h -MainPath $p.Main -BehaviorsPath $p.Beh
        }
    }

    if ($doNSRL) {
        Write-Host "`nIterating Through NSRL Windows Hashes$(if($OsFilter){" (filter: $OsFilter)"})..." -ForegroundColor DarkCyan
        foreach ($entry in $nsrlWindowsEntries) {
            if ($script:QuotaHit) { break }
            $h  = $entry.Hash
            $os = $entry.OsName
            if ($Mode -eq 'NSRLOs' -and $os -ne $OsFilter) { continue }
            if ($missingHashes.Contains($h)) { continue }

            $slug = Get-NSRLOsSlug $os
            $sigOrder = @('SignedVerified','unverified','unsignedWin')

            $existingBehPath = $null
            foreach ($sig in $sigOrder) {
                if (Test-Path (Join-Path (Join-Path $nsrlMain (Join-Path $slug $sig)) "$h.json")) {
                    $existingBehPath = Join-Path $nsrlBeh (Join-Path $slug $sig)
                    break
                }
            }

            if ($existingBehPath) {
                $behFile = Join-Path $existingBehPath "$h.json"
                if (Test-Path $behFile) { continue }
                if (-not (Test-Path $existingBehPath)) { New-Item -ItemType Directory -Path $existingBehPath -Force | Out-Null }
                try {
                    $beh = Invoke-VTRequest -Uri "https://www.virustotal.com/api/v3/files/$h/behaviour_summary"
                    $beh | ConvertTo-Json -Depth 10 | Set-Content $behFile
                    Write-Host "  [OK] $h behaviors (main was cached)" -ForegroundColor Green
                } catch {
                    $code = $null; try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
                    if ($_.Exception.Message -like 'VT_ALL_KEYS_EXHAUSTED*') {
                        Write-Host "  [!] $($_.Exception.Message)" -ForegroundColor Red
                        $script:QuotaHit = $true
                    } else {
                        Write-Host "  [WARN] Behaviors unavailable for $h (HTTP $code)" -ForegroundColor DarkGray
                    }
                }
                continue
            }

            try {
                $vtData      = Invoke-VTRequest -Uri "https://www.virustotal.com/api/v3/files/$h"
                $sigInfo     = $vtData.data.attributes.signature_info
                $sigVerified = if ($sigInfo) { $sigInfo.verified } else { $null }
                $destSig = if ([string]::IsNullOrEmpty($sigVerified)) { 'unsignedWin' }
                           elseif ($sigVerified -eq 'Signed')          { 'SignedVerified' }
                           else                                         { 'unverified' }
                $destMain = Join-Path $nsrlMain (Join-Path $slug $destSig)
                $destBeh  = Join-Path $nsrlBeh  (Join-Path $slug $destSig)
                if (-not (Test-Path $destMain)) { New-Item -ItemType Directory -Path $destMain -Force | Out-Null }
                if (-not (Test-Path $destBeh))  { New-Item -ItemType Directory -Path $destBeh  -Force | Out-Null }
                $vtData | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $destMain "$h.json")
                Write-Host "  [OK] $h -> NSRL/$slug/$destSig" -ForegroundColor Green

                try {
                    $beh = Invoke-VTRequest -Uri "https://www.virustotal.com/api/v3/files/$h/behaviour_summary"
                    $beh | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $destBeh "$h.json")
                } catch {
                    if ($_.Exception.Message -like 'VT_ALL_KEYS_EXHAUSTED*') {
                        Write-Host "  [!] $($_.Exception.Message)" -ForegroundColor Red
                        $script:QuotaHit = $true
                    } else {
                        Write-Host "  [WARN] Behaviors unavailable for $h" -ForegroundColor DarkGray
                    }
                }
            } catch {
                $code = $null; try { $code = $_.Exception.Response.StatusCode.value__ } catch {}
                if ($_.Exception.Message -like 'VT_ALL_KEYS_EXHAUSTED*') {
                    Write-Host "  [!] $($_.Exception.Message)" -ForegroundColor Red
                    $script:QuotaHit = $true
                } elseif ($code -eq 404) {
                    Write-Host "  [404] $h not in VT." -ForegroundColor DarkGray
                    [void]$missingHashes.Add($h)
                    [PSCustomObject]@{ Hash = $h; DateChecked = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ") } |
                        Export-Csv -Path $missingHashesPath -Append -NoTypeInformation
                } else {
                    Write-Host "  [ERROR] HTTP $code - $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }

        Write-Host "`nIterating Through NSRL Linux Hashes$(if($OsFilter){" (filter: $OsFilter)"})..." -ForegroundColor DarkCyan
        foreach ($entry in $nsrlLinuxEntries) {
            if ($script:QuotaHit) { break }
            $h  = $entry.Hash
            $os = $entry.OsName
            if ($Mode -eq 'NSRLOs' -and $os -ne $OsFilter) { continue }
            $slug = Get-NSRLOsSlug $os
            $destMain = Join-Path $nsrlMain (Join-Path $slug 'unsignedLinux')
            $destBeh  = Join-Path $nsrlBeh  (Join-Path $slug 'unsignedLinux')
            Process-Hash -Hash $h -MainPath $destMain -BehaviorsPath $destBeh
        }
    }

    if ($doMalicious) {
        Write-Host "`nIterating Through Malicious Baseline..." -ForegroundColor DarkCyan
        foreach ($proc in $maliciousProcsBaseline) {
            if ($script:QuotaHit) { break }
            $h = $proc.value[2]; if (-not $h) { continue }
            Process-Hash -Hash $h -MainPath $maliciousMain -BehaviorsPath $maliciousBeh
        }
    }

    if ($doDrivers) {
        Write-Host "`nIterating Through Drivers Baseline..." -ForegroundColor DarkCyan
        foreach ($proc in $driversBaseline) {
            if ($script:QuotaHit) { break }
            $h = $proc.value[2]; if (-not $h) { continue }
            $p = Get-DestPaths -Hash $h -Sig 'drivers'
            Process-Hash -Hash $h -MainPath $p.Main -BehaviorsPath $p.Beh
        }
    }

    if ($script:QuotaHit) {
        Write-Host "`n[!] Run stopped early due to VT quota. Re-run to continue from where it left off (existing files are skipped)." -ForegroundColor Yellow
    } else {
        Write-Host "`n[DONE] Baseline collection complete." -ForegroundColor Green
    }
}

Export-ModuleMember -Function Get-VTBaseline, Get-NSRLOsSlug, Get-PlatformBaselineRoots, Get-VTProxyForRegion

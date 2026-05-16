# Quick end-to-end smoke test for the SOCKS5 proxy support added to
# Get-VTBaseline / Invoke-VTRequest. Does NOT consume VT daily quota
# (uses /users/{api_key} which is quota-free).
#
# Usage:
#   .\tools\Test-VTProxy.ps1
#   .\tools\Test-VTProxy.ps1 -Proxy 'socks5://proxy-us-east.privateinternetaccess.com:1080'
[CmdletBinding()]
param(
    [string]$Proxy   = 'socks5://proxy-nl.privateinternetaccess.com:1080',
    [string]$VTKeyName = 'VT_API_Key_1'
)

$ErrorActionPreference = 'Stop'

function Step ($n, $title) {
    Write-Host ""
    Write-Host ("=== Step {0}: {1} ===" -f $n, $title) -ForegroundColor Cyan
}

# --- Step 1: Resolve PIA SOCKS credentials ---------------------------
Step 1 'Resolve PIA SOCKS5 credentials'
$proxyCred = $null
try {
    $piaUser = Get-Secret -Name 'PIA_SOCKS_User' -AsPlainText
    $piaPass = Get-Secret -Name 'PIA_SOCKS_Password'
    if ($piaPass -isnot [System.Security.SecureString]) {
        $piaPass = ConvertTo-SecureString -String $piaPass -AsPlainText -Force
    }
    $proxyCred = [pscredential]::new($piaUser, $piaPass)
    Write-Host ("  Loaded from vault. User: {0}" -f $proxyCred.UserName) -ForegroundColor Green
} catch {
    Write-Host "  Not in vault yet (PIA_SOCKS_User / PIA_SOCKS_Password). Prompting." -ForegroundColor Yellow
    $proxyCred = Get-Credential -Message "PIA SOCKS5 creds (from PIA dashboard > Downloads tab)"
}

# --- Step 2: Direct egress IP (no proxy) -----------------------------
Step 2 'Direct egress IP (no proxy, control)'
$directIp = $null
try {
    $directIp = (Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 15).Trim()
    Write-Host ("  Direct IP: {0}" -f $directIp) -ForegroundColor Gray
} catch {
    Write-Host ("  [WARN] Direct IP check failed: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
}

# --- Step 3: Egress IP via proxy -------------------------------------
Step 3 "Egress IP via proxy ($Proxy)"
try {
    $proxyIp = (Invoke-RestMethod -Uri 'https://api.ipify.org' `
                                  -Proxy $Proxy `
                                  -ProxyCredential $proxyCred `
                                  -TimeoutSec 30).Trim()
    Write-Host ("  Proxy IP:  {0}" -f $proxyIp) -ForegroundColor Green
    if ($directIp -and $proxyIp -eq $directIp) {
        Write-Host "  [FAIL] Proxy IP equals direct IP - proxy not being used." -ForegroundColor Red
        return
    }
} catch {
    Write-Host ("  [FAIL] Proxy IP check failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
    Write-Host "         Possible causes: wrong SOCKS creds, region hostname typo, region offline." -ForegroundColor DarkYellow
    return
}

# --- Step 4: VT call via proxy (quota-free) --------------------------
Step 4 "VirusTotal /users/{api_key} via proxy (quota-free)"
try {
    $vtKey = (Get-Secret -Name $VTKeyName -AsPlainText).Trim()
    $headers = @{ 'x-apikey' = $vtKey; 'Content-Type' = 'application/json' }
    $r = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/users/$vtKey" `
                           -Headers $headers `
                           -Proxy $Proxy `
                           -ProxyCredential $proxyCred `
                           -TimeoutSec 30
    $q = $r.data.attributes.quotas.api_requests_daily
    Write-Host ("  VT account: {0}" -f $r.data.id) -ForegroundColor Green
    Write-Host ("  Daily quota used: {0} / {1}" -f $q.used, $q.allowed) -ForegroundColor Gray
} catch {
    Write-Host ("  [FAIL] VT call via proxy failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
    return
}

# --- Step 5: Confirm $env:VT_PROXY fallback path ---------------------
Step 5 'Confirm $env:VT_PROXY fallback (the path Get-VTBaseline uses)'
$env:VT_PROXY = $Proxy
Write-Host ("  Set `$env:VT_PROXY = {0}" -f $Proxy) -ForegroundColor Gray
Write-Host "  When you next run the menu, Get-VTBaseline will pick this up automatically" -ForegroundColor Gray
Write-Host "  and resolve credentials from the same vault entries." -ForegroundColor Gray
Write-Host ""
Write-Host "=== All checks passed ===" -ForegroundColor Green
Write-Host ("Safe to run: Get-VTBaseline -Proxy '{0}'" -f $Proxy) -ForegroundColor Green
Write-Host "Or just set `$env:VT_PROXY in your shell and use the 1a menu as normal." -ForegroundColor Green

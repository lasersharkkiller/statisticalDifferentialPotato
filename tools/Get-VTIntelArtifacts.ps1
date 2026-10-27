<#
.SYNOPSIS
    Finds and downloads vendor artefacts from VT Intelligence for firmware we
    cannot obtain from the vendor's own portal.

.DESCRIPTION
    Several OT vendors in the census gate their downloads behind partner/dealer
    accounts we do not have (Tridium, Galaxy, JCI, AutomatedLogic, Mercury, TAC).
    The enterprise key carries `intelligence` + `intelligence-search-tier-3` and
    `downloads-tier-2`, so where a file already sits in VT we can search for it
    and pull the sample directly.

    WHAT THIS REALISTICALLY FINDS - measured 2026-10-22, not assumed:
      * Vendor SOFTWARE (Windows installers, DLLs, management-server packages).
        These reach VT because people scan .exe/.msi files. Confirmed finds
        include Niagara_Setup_Customer_4.3.exe (53 MB) and SystemGalaxy.exe.
      * It does NOT reliably find DEVICE FIRMWARE images (JACE, Xenta, Mercury
        LP/MR panel images). Those are rarely submitted, and a bare `name:` glob
        for them returns tokenised noise - `name:"jace"` matched a Sims clothing
        mod and an FL Studio project.

    RELEVANCE FILTER: VT's `name:` operator is tokenised, not a glob, so a query
    for a vendor term happily returns unrelated files, plus security scanners and
    ICS exploit kits that merely mention the vendor in their signature data. Every
    hit is therefore re-checked against -MustMatch before anything is downloaded.

.PARAMETER WhatIfPlan
    Search and report only - download nothing. Use this first, always.

.EXAMPLE
    .\tools\Get-VTIntelArtifacts.ps1 -WhatIfPlan
    .\tools\Get-VTIntelArtifacts.ps1 -Vendors Tridium
#>
[CmdletBinding()]
param(
    [string[]]$Vendors,
    [int]$MaxPerQuery          = 40,
    [int64]$MinSizeBytes       = 300KB,   # below this it is a fragment, not a product
    [int64]$MaxSizeBytes       = 900MB,
    [string]$Staging           = 'C:\githubProjects\firmware-staging',
    [string]$EnterpriseSecretName = 'VT_Enterprise_Key',
    [switch]$WhatIfPlan
)

$ErrorActionPreference = 'Stop'

# --------------------------------------------------------------- targets ---
# MustMatch is a regex the resolved filename has to satisfy before we download.
# It is deliberately stricter than the query: the query casts, this filters.
$targets = @(
    @{ Vendor='Tridium';          Category='Niagara';        Product='Niagara-Framework'
       # "Niagara" is badly overloaded: an Android launcher app, Unreal Engine's
       # particle system, screensavers. Require a Tridium-specific companion token
       # (Vykon is Tridium's own brand) rather than the bare word.
       Queries=@('name:"Niagara_Setup"','name:"niagara" type:peexe','name:"vykon"','name:"niagara" type:msi')
       MustMatch='niagara[_ ]?(setup|install|workbench|station|daemon|4)|vykon' }

    @{ Vendor='Digital-Systems-Corp'; Category='Access-Control'; Product='System-Galaxy'
       Queries=@('name:"systemgalaxy"','name:"system galaxy"')
       MustMatch='systemgalaxy|system.?galaxy' }

    @{ Vendor='Johnson-Controls'; Category='Metasys';         Product='Metasys-Software'
       Queries=@('name:"metasys" type:peexe','name:"metasys" type:msi')
       MustMatch='metasys' }

    @{ Vendor='AutomatedLogic';   Category='WebCTRL';         Product='WebCTRL-Software'
       Queries=@('name:"webctrl" type:peexe','name:"webctrl" type:msi','name:"webctrl" type:jar')
       MustMatch='webctrl' }

    @{ Vendor='Schneider';        Category='TAC-Vista';       Product='TAC-Vista-Software'
       Queries=@('name:"tac vista"','name:"tacvista"','name:"xenta"')
       MustMatch='tac.?vista|xenta' }

    @{ Vendor='Mercury-Security'; Category='Access-Control';  Product='LP-MR-Series'
       Queries=@('name:"LP1502"','name:"LP4502"','name:"MR52"','name:"ep1501"')
       MustMatch='lp1501|lp1502|lp2500|lp4502|mr5[02]|mr16|ep1501|ep2500' }

    # --- 2026-10-26: the OSINT-brief vendors, to attempt a software/firmware pull ---
    @{ Vendor='Genetec';          Category='Security-Center'; Product='Security-Center-Software'
       Queries=@('name:"genetec" type:peexe','name:"security center" type:peexe','name:"synergis"','name:"omnicast"','name:"streamvault"')
       MustMatch='genetec|synergis|omnicast|streamvault|autovu|securitydesk' }

    @{ Vendor='Motorola-Avigilon'; Category='Video';          Product='Avigilon-ACC'
       Queries=@('name:"avigilon"','name:"ACC" type:peexe','name:"ava security"')
       MustMatch='avigilon|acc[-_ ]?(client|server|player)|ava[-_ ]?security' }

    @{ Vendor='Hanwha-Vision';    Category='Video';           Product='Wisenet'
       Queries=@('name:"wisenet"','name:"hanwha"','name:"SmartViewer"','name:"SSM" type:peexe')
       MustMatch='wisenet|hanwha|smartviewer|techwin|wave[-_ ]?vms' }

    @{ Vendor='Gallagher';        Category='Access-Control';  Product='Command-Centre'
       # Require the brand literally: "command centre" alone matched Alienware,
       # Unitron and PEAQ products (other vendors' unrelated "Command Centre" apps).
       Queries=@('name:"gallagher" type:peexe','name:"gallagher command"','name:"gallagher controller"')
       MustMatch='gallagher' }

    @{ Vendor='Sensormatic';      Category='Access-Control';  Product='Software-House-CCURE'
       Queries=@('name:"C-CURE"','name:"ccure"','name:"istar"','name:"victor" type:peexe','name:"exacqvision"')
       MustMatch='c.?cure|istar|exacq|american.?dynamics|software.?house|victor' }

    @{ Vendor='Trane';            Category='Building-Automation'; Product='Tracer'
       Queries=@('name:"tracer" type:peexe','name:"trane"','name:"tracer SC"','name:"rover" trane')
       MustMatch='tracer[-_ ]?(sc|es|synchrony)?|trane' }

    @{ Vendor='Daikin';           Category='HVAC';            Product='Daikin-Controllers'
       Queries=@('name:"daikin"','name:"SVMPC"','name:"DCC601"','name:"intelligent touch"')
       MustMatch='daikin|svmpc|dcc601|itm|intelligent.?touch|itc' }

    @{ Vendor='Sierra-Monitor';   Category='Gateway';         Product='FieldServer'
       Queries=@('name:"fieldserver"','name:"sierra monitor"','name:"FS-GW"','name:"fieldpoptools"')
       MustMatch='fieldserver|sierra.?monitor|fs-?gw|fieldpop|fs-b' }

    @{ Vendor='Advanced-Network-Devices'; Category='Mass-Notification'; Product='IP-Speakers'
       Queries=@('name:"anetd"','name:"advanced network devices"','name:"ipclock"','name:"IPSpeaker"')
       MustMatch='anetd|advanced.?network.?devices|ipspeaker|ipclock|ipsw' }

    @{ Vendor='Dormakaba';        Category='Access-Control';  Product='Omnilock-BEST'
       Queries=@('name:"omnilock"','name:"dormakaba"','name:"BEST" lock','name:"saflok"')
       MustMatch='omnilock|dormakaba|saflok|b.?a.?s.?i.?s|exigo' }

    @{ Vendor='VCS-Bosch-Video';  Category='Video';           Product='VideoJet-Encoders'
       Queries=@('name:"videojet" bosch','name:"VIP X"','name:"configuration manager" bosch','name:"bvms"')
       MustMatch='videojet|vip[-_ ]?x|bvms|bosch.?config' }

    # --- 2026-10-26: gated missing-vendors whose firmware may still sit in VT ---
    @{ Vendor='Hikvision';        Category='Video';           Product='IP-Camera-Firmware'
       Queries=@('name:"digicap.dav"','name:"hikvision"','name:"DS-2CD"','name:"IPC_" hikvision')
       MustMatch='digicap|hikvision|ds-2cd|ds-7|hikcentral' }

    @{ Vendor='Vivotek';          Category='Video';           Product='IP-Camera-Firmware'
       Queries=@('name:"vivotek"','name:"VVTK"','name:"FD8" firmware','name:"shepherd" vivotek')
       MustMatch='vivotek|vvtk|fe8|fd8|ib9|shepherd' }

    @{ Vendor='Suprema';          Category='Access-Control';  Product='BioStar'
       Queries=@('name:"biostar"','name:"biostation"','name:"suprema"','name:"BioEntry"')
       MustMatch='biostar|biostation|suprema|bioentry|facestation' }

    @{ Vendor='LOYTEC';           Category='Building-Automation'; Product='L-INX'
       Queries=@('name:"loytec"','name:"L-INX"','name:"LINX-" loytec','name:"L-VIS"')
       MustMatch='loytec|l-inx|linx-|l-vis|lgate|lroc' }

    @{ Vendor='Paxton-Access';    Category='Access-Control';  Product='Net2'
       Queries=@('name:"paxton"','name:"Net2" paxton','name:"Paxton10"','name:"paxlock"')
       MustMatch='paxton|net2|paxlock|paxton10' }

    @{ Vendor='Alerton';          Category='Building-Automation'; Product='BACtalk'
       Queries=@('name:"alerton"','name:"bactalk"','name:"envision" alerton','name:"Ascent" alerton')
       MustMatch='alerton|bactalk|envision.?for.?bactalk|ascent' }

    @{ Vendor='KMC-Controls';     Category='Building-Automation'; Product='Conquest'
       Queries=@('name:"KMC Connect"','name:"KMC Conquest"','name:"flexstat"')
       MustMatch='kmc.?connect|kmc.?conquest|flexstat|kmc.?controls' }

    @{ Vendor='Phoenix-Contact';  Category='PLC';             Product='PLCnext'
       Queries=@('name:"plcnext"','name:"AXC F 2152"','name:"AXC F 1152"','name:"phoenix contact" firmware')
       MustMatch='plcnext|axc.?f.?[12]152|phoenix.?contact' }

    @{ Vendor='Electro-Industries'; Category='Power-Meter';   Product='Nexus-Shark'
       Queries=@('name:"Communicator" EIG','name:"MeterManager"','name:"EnergyPQA"','name:"Nexus" meter')
       MustMatch='communicatorpqa|metermanager|energypqa|electro.?industries|gauge.?tech' }

    @{ Vendor='FLIR';             Category='Video';           Product='FLIR-Security'
       Queries=@('name:"FLIR" DNA','name:"FLIR Latitude"','name:"Elara FC"','name:"flir" firmware')
       MustMatch='flir.?(dna|latitude|united|elara|fc-)|flir.?security' }

    @{ Vendor='Sur-Gard';         Category='Alarm';           Product='System-Receivers'
       Queries=@('name:"sur-gard"','name:"surgard"','name:"SG-System"','name:"System 5" surgard')
       MustMatch='sur-?gard|sg-system|system.?[5i]' }
)

if ($Vendors) { $targets = @($targets | Where-Object { $Vendors -contains $_.Vendor }) }
if (-not $targets) { Write-Host "  no matching targets." -ForegroundColor Yellow; return }

# ------------------------------------------------------------------ key ---
try { $key = (Get-Secret -Name $EnterpriseSecretName -AsPlainText -ErrorAction Stop).Trim() }
catch {
    try { Unlock-SecretStore -ErrorAction Stop
          $key = (Get-Secret -Name $EnterpriseSecretName -AsPlainText -ErrorAction Stop).Trim() }
    catch { throw "Cannot read secret '$EnterpriseSecretName': $($_.Exception.Message)" }
}
$headers = @{ 'x-apikey' = $key }

Write-Host ""
Write-Host "=== VT Intelligence artefact hunt ===" -ForegroundColor Cyan
if ($WhatIfPlan) { Write-Host "  -WhatIfPlan: searching only, nothing will be downloaded." -ForegroundColor Yellow }

# Hashes we already hold anywhere in staging - never re-download one.
$have = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($c in @(Get-ChildItem (Join-Path $Staging '*\*\*\catalog.csv') -ErrorAction SilentlyContinue)) {
    foreach ($r in (Import-Csv $c.FullName)) { if ($r.Hash) { [void]$have.Add($r.Hash) } }
}
Write-Host ("  hashes already in staging catalogs: {0:N0}" -f $have.Count)

$found = [System.Collections.Generic.List[object]]::new()
$seen  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($t in $targets) {
    Write-Host ""
    Write-Host ("--- {0} / {1} ---" -f $t.Vendor, $t.Product) -ForegroundColor Cyan
    foreach ($q in $t.Queries) {
        $uri = 'https://www.virustotal.com/api/v3/intelligence/search?query=' +
               [uri]::EscapeDataString($q) + "&limit=$MaxPerQuery"
        try { $resp = Invoke-RestMethod -Uri $uri -Headers $headers -ErrorAction Stop }
        catch {
            Write-Host ("    [{0}] query failed: {1}" -f $q, $_.Exception.Message) -ForegroundColor DarkYellow
            continue
        }
        $kept = 0
        foreach ($d in @($resp.data)) {
            $sha  = $d.id
            $size = [int64]$d.attributes.size
            # Prefer a name that actually matches; VT reports several aliases.
            # Match the LEAF name, never the full submission path. VT records the
            # path a sample was submitted from, so matching the whole string pulled
            # in OneDrive.exe and OdfConverter.exe purely because someone had once
            # submitted them out of a directory called "webctrl".
            $names = @($d.attributes.names) + @($d.attributes.meaningful_name) |
                     Where-Object { $_ } | ForEach-Object { Split-Path $_ -Leaf }
            $match = @($names | Where-Object { $_ -match $t.MustMatch }) | Select-Object -First 1
            if (-not $match)                       { continue }   # tokenised noise
            # Media/document types are never vendor software, however the name reads
            # ("Satellite_Galaxy_Sound_Soundtheme.mp3" cleared the name filter).
            if ($d.attributes.type_description -match 'MP3|PDF|GIF|JPEG|PNG|PowerPoint|Word|Video|Audio|Torrent|Android|Macintosh|Disk Image|DMG') { continue }
            # Name-based noise: third-party ecosystems that borrow a vendor word.
            # homebridge/npm plugins (@scope__pkg), community integrations, and
            # consumer apps that collide on "command centre"/"streamvault" etc.
            if ($match -match 'homebridge|node[-_]?red|__|alienware|unitron|peaq|npm|homeassistant|hacs') { continue }
            if ($size -lt $MinSizeBytes -or $size -gt $MaxSizeBytes) { continue }
            if ($have.Contains($sha))              { continue }   # already on disk
            if (-not $seen.Add($sha))              { continue }   # dupe across queries
            $kept++
            $found.Add([pscustomobject]@{
                Vendor = $t.Vendor; Category = $t.Category; Product = $t.Product
                Sha256 = $sha; Size = $size
                Name   = $match
                Type   = $d.attributes.type_description
                First  = if ($d.attributes.first_submission_date) {
                            [DateTimeOffset]::FromUnixTimeSeconds($d.attributes.first_submission_date).ToString('yyyy-MM-dd') } else { '' }
                Det    = ('{0}/{1}' -f $d.attributes.last_analysis_stats.malicious,
                            ([int]$d.attributes.last_analysis_stats.malicious + [int]$d.attributes.last_analysis_stats.undetected))
            })
        }
        Write-Host ("    [{0,-34}] {1,3} returned, {2,2} relevant" -f $q, @($resp.data).Count, $kept)
        Start-Sleep -Milliseconds 300
    }
}

Write-Host ""
if (-not $found.Count) { Write-Host "  nothing relevant found." -ForegroundColor Yellow; return }

# A file carrying the vendor's name AND a high detection count is not vendor
# software - it is malware wearing the vendor's name. That is threat intel, not a
# firmware acquisition, so report it separately and never file it as vendor code.
$impostors = @($found | Where-Object { [int]($_.Det -split '/')[0] -ge 5 })
$genuine   = @($found | Where-Object { [int]($_.Det -split '/')[0] -lt 5 })

Write-Host ("=== {0} candidate vendor artefacts ===" -f $genuine.Count) -ForegroundColor Green
$genuine | Sort-Object Vendor, Size -Descending | ForEach-Object {
    Write-Host ("  {0,-22} {1,-34} {2,12:N0} B  {3,-16} {4}  det {5}" -f `
        $_.Vendor, $_.Name.Substring(0,[Math]::Min(33,$_.Name.Length)), $_.Size, $_.Type, $_.First, $_.Det)
}
if ($impostors.Count) {
    Write-Host ""
    Write-Host ("=== {0} files impersonating these vendors (NOT downloaded as vendor software) ===" -f $impostors.Count) -ForegroundColor Magenta
    $impostors | Sort-Object { [int]($_.Det -split '/')[0] } -Descending | ForEach-Object {
        Write-Host ("  {0,-22} {1,-34} {2,12:N0} B  det {3}  first {4}" -f `
            $_.Vendor, $_.Name.Substring(0,[Math]::Min(33,$_.Name.Length)), $_.Size, $_.Det, $_.First) -ForegroundColor Magenta
    }
    $impostors | Export-Csv -LiteralPath (Join-Path $Staging 'vt-vendor-impersonation.csv') -NoTypeInformation
    Write-Host ("  written: {0}" -f (Join-Path $Staging 'vt-vendor-impersonation.csv')) -ForegroundColor DarkCyan
}
$found = $genuine

if ($WhatIfPlan) { Write-Host ""; Write-Host "  -WhatIfPlan: stopping before download." -ForegroundColor Yellow; return }

# ------------------------------------------------------------- download ---
Write-Host ""
Write-Host "  downloading..." -ForegroundColor Cyan
$ok = 0; $fail = 0
foreach ($f in $found) {
    # Downloaded samples are untrusted: each vendor product gets its own raw dir.
    $dir = Join-Path $Staging ("{0}\{1}\{2}\raw" -f $f.Vendor, $f.Category, $f.Product)
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $safeName = ($f.Name -replace '[\\/:*?"<>|]', '_')
    $out = Join-Path $dir ("{0}__{1}" -f $f.Sha256.Substring(0,12), $safeName)
    if (Test-Path $out) { Write-Host ("    [HAVE] {0}" -f $safeName); continue }
    try {
        Invoke-WebRequest -Uri "https://www.virustotal.com/api/v3/files/$($f.Sha256)/download" `
            -Headers $headers -OutFile $out -ErrorAction Stop
        $actual = (Get-FileHash -LiteralPath $out -Algorithm SHA256).Hash
        if ($actual -ne $f.Sha256) {
            Write-Host ("    [BAD ] {0}: hash mismatch, deleting" -f $safeName) -ForegroundColor Red
            Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue; $fail++; continue
        }
        Write-Host ("    [OK  ] {0,-40} {1,12:N0} B" -f $safeName, $f.Size) -ForegroundColor Green
        $ok++
    } catch {
        Write-Host ("    [FAIL] {0}: {1}" -f $safeName, $_.Exception.Message) -ForegroundColor Red
        Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
        $fail++
    }
}
Write-Host ""
Write-Host ("  downloaded {0}, failed {1}" -f $ok, $fail) -ForegroundColor Green
Write-Host "  Next: extract, then tools\Build-OsCatalog.ps1 and the normal VT pipeline." -ForegroundColor DarkCyan
Write-Host ""

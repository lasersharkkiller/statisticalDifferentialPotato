<#
.Module Name
    ThreatActorIOCs
.SYNOPSIS
    Bulk Threat Intelligence Harvester (Optional VT Intelligence + Optional Cybersixgill + Community Feeds).
    v14.0 - UPDATE:
     - Fixed alias casing: Lazarus "MimiKatz" -> "Mimikatz"
     - Fixed alias mismatch: ShinyHunters "ConnectWise" -> "ConnectWise ScreenConnect"
     - Added 36 missing standalone malware/tool entries for all LinkedTools gaps:
        Tick: Daserf, Datper, Gofarer, SymonLoader, Gokcpdoor
        Velvet Ant: VelvetSting, VelvetTap
        Lotus Blossom: Hannotog, Emissary
        BlackTech: Pled, Consock
        Ke3chang: Ketrican, RoyalDNS
        APT31: SOGU, LuckyBird
        APT27: HyperBro
        Hafnium: Tarrask
        Storm-2603: AK47 C2, ToolShell
        UAT-7290: DriveSwitch
        Volt Typhoon: FastReverseProxy
        UNC3886: TinyShell, Medusa Backdoor
        Gallium: PingPull
        Lazarus: Manuscrypt
        APT32: Kerrdown
        Sandworm: BlackEnergy, Industroyer
        Flax Typhoon: JuicyPotato/BadPotato, SoftEther
        General: China Chopper, AdFind, ADExplorer, Valak, Bland AI
     - PureHVNC confirmed covered as alias under PureRAT (no new entry needed)
#>

function ConvertTo-HashIocType {
    param([string]$Type)
    if (-not $Type) { return $null }
    $t = $Type.ToLowerInvariant()

    if ($t -match "sha256") { return "SHA256" }
    if ($t -match "sha1")   { return "SHA1" }
    if ($t -match "md5")    { return "MD5" }
    if ($t -match "hash")   { return "Hash" }

    return $Type
}

function Test-HasValue {
    param([string]$s)
    return (-not [string]::IsNullOrWhiteSpace($s))
}

function Get-ThreatFoxIOCsByTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Tag,
        [int]$Limit = 200,
        [hashtable]$Headers
    )

    $uri  = "https://threatfox-api.abuse.ch/api/v1/"
    $body = @{ query="taginfo"; tag=$Tag; limit=$Limit } | ConvertTo-Json -Depth 5

    try {
        $resp = Invoke-RestMethod -Method Post -Uri $uri -Headers $Headers -Body $body -ErrorAction Stop
        if ($resp.query_status -ne "ok" -or -not $resp.data) { return @() }

        $out = @()
        foreach ($d in $resp.data) {
            $out += [PSCustomObject]@{
                Date     = $d.first_seen
                Source   = "ThreatFox"
                IOCType  = $d.ioc_type
                IOCValue = $d.ioc
                Context  = "threat=$($d.threat_type); malware=$($d.malware)"
                Link     = $null
            }
        }
        return $out
    } catch { return @() }
}

function Get-MalwareBazaarByTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Tag,
        [int]$Limit = 200,
        [hashtable]$Headers
    )

    $uri  = "https://mb-api.abuse.ch/api/v1/"
    $form = "query=get_taginfo&tag=$([Uri]::EscapeDataString($Tag))&limit=$Limit"

    try {
        $resp = Invoke-RestMethod -Method Post -Uri $uri -Headers $Headers -Body $form -ErrorAction Stop
        if ($resp.query_status -ne "ok" -or -not $resp.data) { return @() }

        $out = @()
        foreach ($d in $resp.data) {
            $out += [PSCustomObject]@{
                Date     = $d.first_seen
                Source   = "MalwareBazaar"
                IOCType  = "SHA256"
                IOCValue = $d.sha256_hash
                Context  = "signature=$($d.signature); file=$($d.file_name)"
                Link     = $null
            }
        }
        return $out
    } catch { return @() }
}

function Get-URLhausByTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Tag,
        [int]$Limit = 200,
        [hashtable]$Headers
    )

    $uri  = "https://urlhaus-api.abuse.ch/v1/"
    $form = "query=taginfo&tag=$([Uri]::EscapeDataString($Tag))&limit=$Limit"

    try {
        $resp = Invoke-RestMethod -Method Post -Uri $uri -Headers $Headers -Body $form -ErrorAction Stop
        if ($resp.query_status -ne "ok" -or -not $resp.urls) { return @() }

        $out = @()
        foreach ($u in $resp.urls) {
            $out += [PSCustomObject]@{
                Date     = $u.date_added
                Source   = "URLhaus"
                IOCType  = "url"
                IOCValue = $u.url
                Context  = "status=$($u.url_status); threat=$($u.threat)"
                Link     = $u.urlhaus_reference
            }
        }
        return $out
    } catch { return @() }
}

function Get-OTXPulseIndicatorsByKeyword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Keyword,
        [int]$MaxPulses = 5,
        [hashtable]$Headers
    )

    $searchUri = "https://otx.alienvault.com/api/v1/search/pulses?q=$([Uri]::EscapeDataString($Keyword))"

    try {
        $search = Invoke-RestMethod -Method Get -Uri $searchUri -Headers $Headers -ErrorAction Stop
        if (-not $search.results) { return @() }

        $pulses = $search.results | Select-Object -First $MaxPulses
        $out = @()

        foreach ($p in $pulses) {
            if (-not $p.id) { continue }

            $pulseUri = "https://otx.alienvault.com/api/v1/pulses/$($p.id)"
            $pulse = Invoke-RestMethod -Method Get -Uri $pulseUri -Headers $Headers -ErrorAction SilentlyContinue
            if (-not $pulse -or -not $pulse.indicators) { continue }

            foreach ($i in $pulse.indicators) {
                $out += [PSCustomObject]@{
                    Date     = $pulse.modified
                    Source   = "AlienVault OTX"
                    IOCType  = $i.type
                    IOCValue = $i.indicator
                    Context  = "pulse=$($pulse.name)"
                    Link     = "https://otx.alienvault.com/pulse/$($p.id)"
                }
            }
        }

        return $out
    } catch { return @() }
}

function Get-ThreatActorIOCs {
    [CmdletBinding()]
    param (
        [string]$StartDate = ((Get-Date).AddYears(-6).ToString("yyyy-MM-dd")),
        [string]$SpecificActor = $null,
        [int]$MaxSamples = 275,

        [switch]$EnableVTIntelligence = $true,
        [switch]$EnableVTHashResolution = $true,
        [switch]$EnableCybersixgill = $true,
        [switch]$EnableThreatFox = $true,
        [switch]$EnableMalwareBazaar = $true,
        [switch]$EnableURLhaus = $false,
        [switch]$EnableOTX = $true
    )

    process {
        $MasterConfig = @(
            # =========================================================
            # SECTION 1: NATION STATE (APT)
            # =========================================================

            # === CHINA ===
            @{ Name = "Tick"; Country = "China"; Type = "APT"; Aliases = @("Tick", "Bronze Butler", "REDBALDKNIGHT", "Stalker Panda", "Swirl Typhoon", "Stalker Taurus", "TAG-74"); LinkedTools = @("Daserf", "Datper", "Gofarer", "SymonLoader", "Gokcpdoor") },
            @{ Name = "Velvet Ant"; Country = "China"; Type = "APT"; Aliases = @("Velvet Ant"); LinkedTools = @("VelvetSting", "VelvetTap", "PlugX", "Impacket") },
            @{ Name = "Lotus Blossom"; Country = "China"; Type = "APT"; Aliases = @("Lotus Blossom", "Spring Dragon", "Billbug", "Thrip", "Dragonfish"); LinkedTools = @("Chrysalis", "Sagerunex", "Elise", "Hannotog", "Emissary") },
            @{ Name = "Flax Typhoon"; Country = "China"; Type = "APT"; Aliases = @("Flax Typhoon", "Ethereal Panda", "RedJuliett"); LinkedTools = @("China Chopper", "JuicyPotato", "BadPotato", "SoftEther", "Metasploit") },
            @{ Name = "UAT-8837"; Country = "China"; Type = "APT"; Aliases = @("UAT-8837"); LinkedTools = @("GoTokenTheft", "DWAgent", "SharpHound", "Impacket", "GoExec", "Rubeus", "Certipy") },
            @{ Name = "Salt Typhoon"; Country = "China"; Type = "APT"; Aliases = @("Salt Typhoon", "GhostEmperor", "FamousSparrow"); LinkedTools = @("ShadowPad") },
            @{ Name = "Storm-2603"; Country = "China"; Type = "APT"; Aliases = @("Storm-2603", "CL-CRI-1040", "Gold Salem"); LinkedTools = @("AK47 C2", "ToolShell", "Impacket") },
            @{ Name = "Earth Krahang"; Country = "China"; Type = "APT"; Aliases = @("Earth Krahang"); LinkedTools = @("RESHELL", "XDealer", "Cobalt Strike", "Fscan") },
            @{ Name = "UAT-7290"; Country = "China"; Type = "APT"; Aliases = @("UAT-7290", "Red Foxtrot"); LinkedTools = @("RushDrop", "SilentRaid", "DriveSwitch", "ShadowPad") },
            @{ Name = "UNC3886"; Country = "China"; Type = "APT"; Aliases = @("UNC3886", "Fire Ant"); LinkedTools = @("TinyShell", "Medusa Backdoor") },
            @{ Name = "Volt Typhoon"; Country = "China"; Type = "APT"; Aliases = @("Volt Typhoon", "Bronze Silhouette"); LinkedTools = @("KV-Botnet", "Impacket", "EarthWorm", "FastReverseProxy") },
            @{ Name = "APT1"; Country = "China"; Type = "APT"; Aliases = @("APT1", "Comment Crew", "Comment Panda"); LinkedTools = @("PoisonIvy", "PlugX") },
            @{ Name = "APT10"; Country = "China"; Type = "APT"; Aliases = @("APT10", "Stone Panda", "MenuPass"); LinkedTools = @("PlugX", "QuasarRAT", "Chisel") },
            @{ Name = "APT27"; Country = "China"; Type = "APT"; Aliases = @("APT27", "Emissary Panda", "LuckyMouse"); LinkedTools = @("PlugX", "HyperBro", "Fscan") },
            @{ Name = "APT30"; Country = "China"; Type = "APT"; Aliases = @("APT30", "Naikon", "Lotus Panda"); LinkedTools = @("PlugX", "Sumatra") },
            @{ Name = "APT31"; Country = "China"; Type = "APT"; Aliases = @("APT31", "Zirconium", "Judgment Panda"); LinkedTools = @("SOGU", "LuckyBird") },
            @{ Name = "APT40"; Country = "China"; Type = "APT"; Aliases = @("APT40", "Leviathan", "Hainan Xiandun", "Kryptonite Panda", "TEMP.Periscope", "MUDCARP", "Bronze Mohawk", "GADOLINIUM"); LinkedTools = @("AIRBREAK", "ScanBox", "China Chopper") },
            @{ Name = "APT41"; Country = "China"; Type = "APT"; Aliases = @("APT41", "Barium", "Winnti", "Wicked Panda"); LinkedTools = @("ShadowPad", "Cobalt Strike", "Winnti", "EarthWorm") },
            @{ Name = "Aquatic Panda"; Country = "China"; Type = "APT"; Aliases = @("Aquatic Panda", "Earth Lusca"); LinkedTools = @("ShadowPad", "Winnti") },
            @{ Name = "BlackTech"; Country = "China"; Type = "APT"; Aliases = @("BlackTech", "Palmerworm"); LinkedTools = @("Kivars", "Pled", "Consock") },
            @{ Name = "Gallium"; Country = "China"; Type = "APT"; Aliases = @("Gallium", "Soft Cell"); LinkedTools = @("PingPull", "Gh0st RAT") },
            @{ Name = "Hafnium"; Country = "China"; Type = "APT"; Aliases = @("Hafnium", "Silk Typhoon"); LinkedTools = @("Tarrask", "China Chopper") },
            @{ Name = "Ke3chang"; Country = "China"; Type = "APT"; Aliases = @("Ke3chang", "APT15", "Vixen Panda"); LinkedTools = @("Okrum", "Ketrican", "RoyalDNS") },
            @{ Name = "Mustang Panda"; Country = "China"; Type = "APT"; Aliases = @("Mustang Panda", "Bronze President"); LinkedTools = @("PlugX", "Cobalt Strike", "PDFSider") },
            @{ Name = "Earth Lamia"; Country = "China"; Type = "APT"; Aliases = @("Earth Lamia", "FamousSparrow", "UNC4841") },
            @{ Name = "Jackpot Panda"; Country = "China"; Type = "APT"; Aliases = @("Jackpot Panda", "RedDelta") },
            @{ Name = "UAT-8099"; Country = "China"; Type = "APT"; Aliases = @("UAT-8099", "BadIIS Group"); LinkedTools = @("BadIIS", "GotoHTTP", "Sharp4RemoveLog", "CnCrypt Protect") },

            # === IRAN ===
            @{ Name = "Agrius"; Country = "Iran"; Type = "APT"; Aliases = @("Agrius", "Pink Sandstorm") },
            @{ Name = "APT33"; Country = "Iran"; Type = "APT"; Aliases = @("APT33", "Elfin", "Holmium") },
            @{ Name = "APT34 (OilRig)"; Country = "Iran"; Type = "APT"; Aliases = @("APT34", "OilRig", "Helix Kitten") },
            @{ Name = "APT35 (Charming Kitten)"; Country = "Iran"; Type = "APT"; Aliases = @("APT35", "Charming Kitten", "Phosphorus") },
            @{ Name = "APT39"; Country = "Iran"; Type = "APT"; Aliases = @("APT39", "Chafer", "Remix Kitten", "ITG07"); LinkedTools = @("Remexi") },
            @{ Name = "APT42"; Country = "Iran"; Type = "APT"; Aliases = @("APT42", "Mint Sandstorm", "TA453") },
            @{ Name = "Cleaver"; Country = "Iran"; Type = "APT"; Aliases = @("Cleaver", "Operation Cleaver") },
            @{ Name = "CyberAv3ngers"; Country = "Iran"; Type = "APT"; Aliases = @("CyberAv3ngers") },
            @{ Name = "Fox Kitten"; Country = "Iran"; Type = "APT"; Aliases = @("Fox Kitten", "Pioneer Kitten") },
            @{ Name = "MuddyWater"; Country = "Iran"; Type = "APT"; Aliases = @("MuddyWater", "DEV-1084", "Seedworm"); LinkedTools = @("Ligolo", "Chisel") },

            # === NORTH KOREA ===
            @{ Name = "Andariel"; Country = "NorthKorea"; Type = "APT"; Aliases = @("Andariel", "Stonefly", "Onyx Sleet") },
            @{ Name = "APT37"; Country = "NorthKorea"; Type = "APT"; Aliases = @("APT37", "Reaper", "ScarCruft") },
            @{ Name = "APT38"; Country = "NorthKorea"; Type = "APT"; Aliases = @("APT38", "BlueNoroff", "BeagleBoyz") },
            @{ Name = "Famous Chollima"; Country = "NorthKorea"; Type = "APT"; Aliases = @("Famous Chollima", "Nickel Tapestry") },
            @{ Name = "Kimsuky"; Country = "NorthKorea"; Type = "APT"; Aliases = @("Kimsuky", "APT43", "Velvet Chollima", "Black Banshee", "Thallium", "Sparkling Pisces") },
            @{ Name = "Lazarus"; Country = "NorthKorea"; Type = "APT"; Aliases = @("Lazarus Group", "Hidden Cobra", "Zinc"); LinkedTools = @("Manuscrypt", "Mimikatz") },
            @{ Name = "Konni Group"; Country = "NorthKorea"; Type = "APT"; Aliases = @("Konni Group", "TA406"); LinkedTools = @("Konni RAT", "Amadey") },
            @{ Name = "UNC5454"; Country = "NorthKorea"; Type = "APT"; Aliases = @("UNC5454") },

            # === RUSSIA ===
            @{ Name = "ALLANITE"; Country = "Russia"; Type = "APT"; Aliases = @("ALLANITE", "Dragonfly", "Energetic Bear") },
            @{ Name = "APT28"; Country = "Russia"; Type = "APT"; Aliases = @("APT28", "Fancy Bear", "Forest Blizzard"); LinkedTools = @("Mimikatz", "Impacket", "Chisel") },
            @{ Name = "APT29"; Country = "Russia"; Type = "APT"; Aliases = @("APT29", "Cozy Bear", "Midnight Blizzard") },
            @{ Name = "Gamaredon"; Country = "Russia"; Type = "APT"; Aliases = @("Gamaredon", "Primitive Bear", "Shuckworm") },
            @{ Name = "Sandworm"; Country = "Russia"; Type = "APT"; Aliases = @("Sandworm", "APT44", "Voodoo Bear", "Seashell Blizzard", "Iridium", "Telebots", "UAC-0113"); LinkedTools = @("DynoWiper", "BlackEnergy", "Industroyer", "Chisel", "WAVESIGN", "Infamous Chisel") },
            @{ Name = "Silence"; Country = "Russia"; Type = "APT"; Aliases = @("Silence", "Whisper Spider") },
            @{ Name = "Star Blizzard"; Country = "Russia"; Type = "APT"; Aliases = @("Star Blizzard", "ColdRiver", "Callisto") },
            @{ Name = "Turla"; Country = "Russia"; Type = "APT"; Aliases = @("Turla", "Venomous Bear", "Waterbug") },
            @{ Name = "UNC5792"; Country = "Russia"; Type = "APT"; Aliases = @("UNC5792") },
            @{ Name = "UNC4221"; Country = "Russia"; Type = "APT"; Aliases = @("UNC4221") },

            # === VIETNAM / S. AMERICA ===
            @{ Name = "APT32"; Country = "Vietnam"; Type = "APT"; Aliases = @("APT32", "OceanLotus"); LinkedTools = @("Cobalt Strike", "Kerrdown") },
            @{ Name = "Blind Eagle"; Country = "SouthAmerica"; Type = "APT"; Aliases = @("Blind Eagle", "APT-C-36") },
            @{ Name = "Huna"; Country = "Vietnam"; Type = "APT"; Aliases = @("Huna", "Huna Phishing", "PXA Stealer Group"); LinkedTools = @("PureRAT", "PureLogs", "PXA Stealer", "PureHVNC") },

            # === PAKISTAN ===
            @{ Name = "APT36"; Country = "Pakistan"; Type = "APT"; Aliases = @("APT36", "Transparent Tribe", "Mythic Leopard", "Earth Karkaddan", "ProjectM", "COPPER FIELDSTONE"); LinkedTools = @("Crimson RAT", "Capra RAT", "ObliqueRAT", "ElizaRAT", "Poseidon") },

            # === E-CRIME ===
            @{ Name = "TA584"; Country = "eCrime"; Type = "APT"; Aliases = @("TA584", "Storm-0900", "UNC4122"); LinkedTools = @("Tsundere Bot", "XWorm", "SharpHide", "ClickFix") },
            @{ Name = "ShinyHunters"; Country = "eCrime"; Type = "APT"; Aliases = @("ShinyHunters", "ShinyCorp", "UNC6040"); LinkedTools = @("ShinySp1d3r", "Impacket", "AsyncRAT", "ConnectWise ScreenConnect", "Bland AI") },
            @{ Name = "LAPSUS$"; Country = "eCrime"; Type = "APT"; Aliases = @("LAPSUS$", "DEV-0537", "Lapsus Group"); LinkedTools = @("Mimikatz", "ADExplorer") },
            @{ Name = "DragonForce"; Country = "eCrime"; Type = "APT"; Aliases = @("DragonForce", "DragonForce Ransomware") },
            @{ Name = "RansomHub"; Country = "eCrime"; Type = "APT"; Aliases = @("RansomHub", "Cyclops", "Knight"); LinkedTools = @("Cobalt Strike", "Mimikatz", "Chisel", "AnyDesk") },
            @{ Name = "Play Ransomware"; Country = "eCrime"; Type = "APT"; Aliases = @("Play Ransomware", "PlayCrypt"); LinkedTools = @("Cobalt Strike", "AdFind", "Grixba", "SystemBC") },
            @{ Name = "Akira"; Country = "eCrime"; Type = "APT"; Aliases = @("Akira", "Storm-1567") },
            @{ Name = "BlackByte"; Country = "eCrime"; Type = "APT"; Aliases = @("BlackByte", "Hecamede") },
            @{ Name = "Carbanak"; Country = "eCrime"; Type = "APT"; Aliases = @("Carbanak", "Anunak") },
            @{ Name = "FIN6"; Country = "eCrime"; Type = "APT"; Aliases = @("FIN6", "Skeleton Spider") },
            @{ Name = "FIN7"; Country = "eCrime"; Type = "APT"; Aliases = @("FIN7", "Carbon Spider") },
            @{ Name = "Scattered Spider"; Country = "eCrime"; Type = "APT"; Aliases = @("Scattered Spider", "Octo Tempest", "0ktapus"); LinkedTools = @("BlackCat", "Rubeus", "Mimikatz", "Rhadamanthys") },
            @{ Name = "TeamTNT"; Country = "eCrime"; Type = "APT"; Aliases = @("TeamTNT") },
            @{ Name = "Wizard Spider"; Country = "eCrime"; Type = "APT"; Aliases = @("Wizard Spider", "TrickBot", "Ryuk") },
            @{ Name = "Exotic Lily"; Country = "eCrime"; Type = "APT"; Aliases = @("Exotic Lily", "DEV-0413"); LinkedTools = @("Bumblebee", "IcedID") },
            @{ Name = "TA551"; Country = "eCrime"; Type = "APT"; Aliases = @("TA551", "Shathak"); LinkedTools = @("Valak", "IcedID") },

            # =========================================================
            # SECTION 2: MALWARE FAMILIES & TOOLS
            # =========================================================

            # --- A. RANSOMWARE ---
            @{ Name = "ShinySp1d3r";      Type = "Malware"; Aliases = @("ShinySp1d3r", "shinysp1d3r ransomware") },
            @{ Name = "Osiris Ransomware"; Type = "Malware"; Aliases = @("Osiris Ransomware", "Ransom.Osiris") },
            @{ Name = "LockBit";          Type = "Malware"; Aliases = @("LockBit", "LockBit 3.0", "LockBit Black") },
            @{ Name = "BlackCat";         Type = "Malware"; Aliases = @("BlackCat", "ALPHV", "Nokoyawa") },
            @{ Name = "BlackBasta";       Type = "Malware"; Aliases = @("BlackBasta") },
            @{ Name = "Rhysida";          Type = "Malware"; Aliases = @("Rhysida", "Rhysida Ransomware") },
            @{ Name = "8Base";            Type = "Malware"; Aliases = @("8Base") },
            @{ Name = "Phobos";           Type = "Malware"; Aliases = @("Phobos", "Eking") },
            @{ Name = "MedusaLocker";     Type = "Malware"; Aliases = @("MedusaLocker", "Medusa Ransomware") },
            @{ Name = "BianLian";         Type = "Malware"; Aliases = @("BianLian") },
            @{ Name = "Mallox";           Type = "Malware"; Aliases = @("Mallox", "TargetCompany") },
            @{ Name = "Inc Ransom";       Type = "Malware"; Aliases = @("Inc Ransom", "IncRansom") },
            @{ Name = "Qilin";            Type = "Malware"; Aliases = @("Qilin", "Agenda Ransomware", "AgendaCrypt") },
            @{ Name = "Cactus";           Type = "Malware"; Aliases = @("Cactus Ransomware", "Trojan.Cactus", "Cactus") },
            @{ Name = "Cuba";             Type = "Malware"; Aliases = @("Cuba Ransomware", "Fidel") },
            @{ Name = "BlackSuit";        Type = "Malware"; Aliases = @("BlackSuit", "BlackSuit Ransomware", "Royal Ransomware") },
            @{ Name = "Clop";             Type = "Malware"; Aliases = @("Clop", "Cl0p") },
            @{ Name = "AvosLocker";       Type = "Malware"; Aliases = @("AvosLocker") },
            @{ Name = "Knight";           Type = "Malware"; Aliases = @("Knight Ransomware", "Cyclops") },
            @{ Name = "DarkSide";         Type = "Malware"; Aliases = @("DarkSide") },
            @{ Name = "Conti";            Type = "Malware"; Aliases = @("Conti") },
            @{ Name = "Babuk";            Type = "Malware"; Aliases = @("Babuk") },
            @{ Name = "Wannacry";         Type = "Malware"; Aliases = @("Wannacry", "WanaCrypt0r") },
            @{ Name = "Dharma";           Type = "Malware"; Aliases = @("Dharma", "Crysis") },
            @{ Name = "StopDjvu";         Type = "Malware"; Aliases = @("StopDjvu", "STOP Ransomware", "Djvu", "Trojan.Djvu") },
            @{ Name = "Interlock";        Type = "Malware"; Aliases = @("Interlock Ransomware", "Interlock") },
            @{ Name = "Morte";            Type = "Malware"; Aliases = @("Morte Ransomware", "Morte") },
            @{ Name = "Aisuru";           Type = "Malware"; Aliases = @("Aisuru Ransomware", "Aisuru") },
            @{ Name = "Rondo";            Type = "Malware"; Aliases = @("Rondo Ransomware", "RondoDoX", "RondoBOT") },

            # --- B. INFOSTEALERS ---
            @{ Name = "Lumma Stealer";    Type = "Malware"; Aliases = @("Lumma", "LummaC2") },
            @{ Name = "Osiris Banking Trojan"; Type = "Malware"; Aliases = @("Osiris Banking Trojan", "Kronos", "Trojan:Win32/Osiris") },
            @{ Name = "RedLine";          Type = "Malware"; Aliases = @("RedLine", "RedLine Stealer") },
            @{ Name = "Vidar";            Type = "Malware"; Aliases = @("Vidar", "Vidar Stealer") },
            @{ Name = "Rhadamanthys";     Type = "Malware"; Aliases = @("Rhadamanthys") },
            @{ Name = "Stealc";           Type = "Malware"; Aliases = @("Stealc") },
            @{ Name = "RisePro";          Type = "Malware"; Aliases = @("RisePro") },
            @{ Name = "Meduza";           Type = "Malware"; Aliases = @("Meduza Stealer") },
            @{ Name = "Atomic Stealer";   Type = "Malware"; Aliases = @("Atomic Stealer", "AMOS", "Atomic macOS") },
            @{ Name = "Raccoon";          Type = "Malware"; Aliases = @("Raccoon Stealer", "RecordBreaker") },
            @{ Name = "Meta Stealer";     Type = "Malware"; Aliases = @("Meta Stealer", "MetaStealer") },
            @{ Name = "Aurora";           Type = "Malware"; Aliases = @("Aurora Stealer", "Aurora Go") },
            @{ Name = "Ducktail";         Type = "Malware"; Aliases = @("Ducktail") },
            @{ Name = "Graphiron";        Type = "Malware"; Aliases = @("Graphiron") },
            @{ Name = "Mars Stealer";     Type = "Malware"; Aliases = @("Mars Stealer") },
            @{ Name = "BlackGuard";       Type = "Malware"; Aliases = @("BlackGuard") },
            @{ Name = "Echelon";          Type = "Malware"; Aliases = @("Echelon Stealer") },
            @{ Name = "StormKitty";       Type = "Malware"; Aliases = @("StormKitty") },
            @{ Name = "Predator";         Type = "Malware"; Aliases = @("Predator The Thief") },
            @{ Name = "Azorult";          Type = "Malware"; Aliases = @("Azorult") },
            @{ Name = "Stealerv37";       Type = "Malware"; Aliases = @("Stealerv37", "Stealer v37") },
            @{ Name = "PXA Stealer";      Type = "Malware"; Aliases = @("PXA Stealer", "PXA") },
            @{ Name = "PureLogs";         Type = "Malware"; Aliases = @("PureLogs", "PureLog Stealer") },

            # --- C. LOADERS & DROPPERS ---
            @{ Name = "Tsundere Bot";     Type = "Malware"; Aliases = @("Tsundere Bot", "Tsundere", "Trojan:JS/Tsundere") },
            @{ Name = "ClickFix";         Type = "Malware"; Aliases = @("ClickFix", "ClearFake", "Trojan.ClickFix") },
            @{ Name = "Latrodectus";      Type = "Malware"; Aliases = @("Latrodectus", "BlackWidow", "IceNova") },
            @{ Name = "Pikabot";          Type = "Malware"; Aliases = @("Pikabot") },
            @{ Name = "SocGholish";       Type = "Malware"; Aliases = @("SocGholish", "FakeUpdates") },
            @{ Name = "DarkGate";         Type = "Malware"; Aliases = @("DarkGate") },
            @{ Name = "GuLoader";         Type = "Malware"; Aliases = @("GuLoader", "CloudEyE") },
            @{ Name = "GootLoader";       Type = "Malware"; Aliases = @("GootLoader", "Gootkit") },
            @{ Name = "Bumblebee";        Type = "Malware"; Aliases = @("Bumblebee", "ColdTrain") },
            @{ Name = "IcedID";           Type = "Malware"; Aliases = @("IcedID", "BokBot") },
            @{ Name = "SystemBC";         Type = "Malware"; Aliases = @("SystemBC", "Coroxy") },
            @{ Name = "SmokeLoader";      Type = "Malware"; Aliases = @("SmokeLoader", "Dofoil") },
            @{ Name = "PrivateLoader";    Type = "Malware"; Aliases = @("PrivateLoader") },
            @{ Name = "Amadey";           Type = "Malware"; Aliases = @("Amadey", "Amadey Bot") },
            @{ Name = "Emotet";           Type = "Malware"; Aliases = @("Emotet", "Geodo", "Heodo") },
            @{ Name = "QakBot";           Type = "Malware"; Aliases = @("QakBot", "QBot", "Pinkslipbot") },
            @{ Name = "TrickBot";         Type = "Malware"; Aliases = @("TrickBot") },
            @{ Name = "Dridex";           Type = "Malware"; Aliases = @("Dridex") },
            @{ Name = "ZLoader";          Type = "Malware"; Aliases = @("ZLoader", "SilentNight") },
            @{ Name = "Ursnif";           Type = "Malware"; Aliases = @("Ursnif", "Gozi", "ISFB") },
            @{ Name = "Valak";            Type = "Malware"; Aliases = @("Valak", "Valak Loader", "Trojan.Valak") },

            # --- D. RATs ---
            @{ Name = "Agent Tesla";      Type = "Malware"; Aliases = @("Agent Tesla", "AgentTesla") },
            @{ Name = "AsyncRAT";         Type = "Malware"; Aliases = @("AsyncRAT") },
            @{ Name = "Remcos";           Type = "Malware"; Aliases = @("Remcos", "RemcosRAT") },
            @{ Name = "NjRAT";            Type = "Malware"; Aliases = @("NjRAT", "Bladabindi") },
            @{ Name = "XWorm";            Type = "Malware"; Aliases = @("XWorm") },
            @{ Name = "NanoCore";         Type = "Malware"; Aliases = @("NanoCore") },
            @{ Name = "QuasarRAT";        Type = "Malware"; Aliases = @("QuasarRAT", "Quasar") },
            @{ Name = "FormBook";         Type = "Malware"; Aliases = @("FormBook") },
            @{ Name = "XLoader";          Type = "Malware"; Aliases = @("XLoader", "FormBook") },
            @{ Name = "WarzoneRAT";       Type = "Malware"; Aliases = @("WarzoneRAT", "Ave Maria") },
            @{ Name = "BitRAT";           Type = "Malware"; Aliases = @("BitRAT") },
            @{ Name = "DcRAT";            Type = "Malware"; Aliases = @("DcRAT") },
            @{ Name = "OrcusRAT";         Type = "Malware"; Aliases = @("OrcusRAT") },
            @{ Name = "StrRAT";           Type = "Malware"; Aliases = @("StrRAT") },
            @{ Name = "Parallax";         Type = "Malware"; Aliases = @("Parallax RAT") },
            @{ Name = "NetWire";          Type = "Malware"; Aliases = @("NetWire") },
            @{ Name = "ModeloRAT";        Type = "Malware"; Aliases = @("ModeloRAT") },
            @{ Name = "Konni RAT";        Type = "Malware"; Aliases = @("Konni", "Konni RAT", "Trojan:Win32/Konni") },
            @{ Name = "Nezha";            Type = "Malware"; Aliases = @("Nezha", "Nezha RAT", "Nezha Monitoring") },
            @{ Name = "Noodle RAT";       Type = "Malware"; Aliases = @("Noodle RAT", "Nood RAT", "Backdoor.Noodle") },
            @{ Name = "EtherRAT";         Type = "Malware"; Aliases = @("EtherRAT") },
            @{ Name = "Pulsar RAT";       Type = "Malware"; Aliases = @("Pulsar RAT", "Pulsar", "Trojan:Win32/Pulsar") },
            @{ Name = "PureRAT";          Type = "Malware"; Aliases = @("PureRAT", "ResolverRAT", "PureHVNC", "Trojan:MSIL/PureRAT") },
            @{ Name = "Sagerunex";        Type = "Malware"; Aliases = @("Sagerunex", "Billbug Backdoor") },
            @{ Name = "Elise";            Type = "Malware"; Aliases = @("Elise", "Elise Backdoor") },
            @{ Name = "Chrysalis";        Type = "Malware"; Aliases = @("Chrysalis", "Chrysalis Backdoor") },

            # --- E. LINUX & CLOUD ---
            @{ Name = "Mirai";            Type = "Malware"; Aliases = @("Mirai", "Mirai Botnet", "Satori", "Masuta", "Okiru", "PureMasuta", "Miori", "Wicked", "Mori") },
            @{ Name = "XorDDoS";          Type = "Malware"; Aliases = @("XorDDoS") },
            @{ Name = "Kinsing";          Type = "Malware"; Aliases = @("Kinsing", "H2Miner") },
            @{ Name = "Tsunami";          Type = "Malware"; Aliases = @("Tsunami", "Kaiten") },
            @{ Name = "Gafgyt";           Type = "Malware"; Aliases = @("Gafgyt", "Bashlite", "Bash0day", "Lizkebab", "Torlus") },
            @{ Name = "Mozi";             Type = "Malware"; Aliases = @("Mozi") },
            @{ Name = "TeamTNT Tools";    Type = "Malware"; Aliases = @("TeamTNT", "Hildegard") },
            @{ Name = "CoinMiner";        Type = "Malware"; Aliases = @("CoinMiner", "XMRig") },
            @{ Name = "Sysrv";            Type = "Malware"; Aliases = @("Sysrv", "Sysrv-hello") },
            @{ Name = "BPFDoor";          Type = "Malware"; Aliases = @("BPFDoor", "Tricephalic Hellkeeper") },
            @{ Name = "KSwapDoor";        Type = "Malware"; Aliases = @("KSwapDoor") },
            @{ Name = "LZRD";             Type = "Malware"; Aliases = @("LZRD", "Lizard Botnet") },
            @{ Name = "PeerBlight";       Type = "Malware"; Aliases = @("PeerBlight") },
            @{ Name = "resgod";           Type = "Malware"; Aliases = @("resgod", "resgod botnet") },
            @{ Name = "SoftEther";        Type = "Malware"; Aliases = @("SoftEther", "SoftEther VPN", "SoftEtherVPN") },

            # --- F. APT-SPECIFIC & BESPOKE TOOLS ---
            @{ Name = "GoTokenTheft";     Type = "Malware"; Aliases = @("GoTokenTheft", "token-theft") },
            @{ Name = "EarthWorm";        Type = "Malware"; Aliases = @("EarthWorm", "EW_Tunnel", "ew_linux", "ew_win") },
            @{ Name = "RESHELL";          Type = "Malware"; Aliases = @("RESHELL") },
            @{ Name = "XDealer";          Type = "Malware"; Aliases = @("XDealer", "Luoyu") },
            @{ Name = "RushDrop";         Type = "Malware"; Aliases = @("RushDrop", "ChronosRAT") },
            @{ Name = "SilentRaid";       Type = "Malware"; Aliases = @("SilentRaid", "MystRodX") },
            @{ Name = "ShadowPad";        Type = "Malware"; Aliases = @("ShadowPad", "PoisonPlug") },
            @{ Name = "Winnti";           Type = "Malware"; Aliases = @("Winnti Malware") },
            @{ Name = "PlugX";            Type = "Malware"; Aliases = @("PlugX", "Korplug") },
            @{ Name = "Kivars";           Type = "Malware"; Aliases = @("Kivars") },
            @{ Name = "Okrum";            Type = "Malware"; Aliases = @("Okrum") },
            @{ Name = "KV-Botnet";        Type = "Malware"; Aliases = @("KV-Botnet", "JDYFJ Botnet") },
            @{ Name = "Voidlink";         Type = "Malware"; Aliases = @("Voidlink") },
            @{ Name = "DynoWiper";        Type = "Malware"; Aliases = @("DynoWiper", "KillFiles", "Win32/KillFiles.NMO") },
            @{ Name = "PDFSider";         Type = "Malware"; Aliases = @("PDFSider", "Trojan:PDF/Miner") },
            @{ Name = "Malicious Data Loader"; Type = "Malware"; Aliases = @("SalesforceDataLoader123", "MyTicketingPortal", "Salesforce Data Loader") },
            @{ Name = "Splinter";         Type = "Malware"; Aliases = @("Splinter") },
            @{ Name = "PULSEPACK";        Type = "Malware"; Aliases = @("PULSEPACK") },
            @{ Name = "VShell";           Type = "Malware"; Aliases = @("VShell") },
            @{ Name = "COMPOOD";          Type = "Malware"; Aliases = @("COMPOOD") },
            @{ Name = "ANGRYREBEL";       Type = "Malware"; Aliases = @("ANGRYREBEL") },
            @{ Name = "BadIIS";           Type = "Malware"; Aliases = @("BadIIS", "Win.Trojan.BadIIS", "WEBJACK") },
            @{ Name = "GotoHTTP";         Type = "Malware"; Aliases = @("GotoHTTP", "Trojan.GotoHTTP") },
            @{ Name = "Sharp4RemoveLog";  Type = "Malware"; Aliases = @("Sharp4RemoveLog", "Log Wiper") },
            @{ Name = "CnCrypt Protect";  Type = "Malware"; Aliases = @("CnCrypt", "CnCrypt Protect") },
            @{ Name = "OpenArk64";        Type = "Malware"; Aliases = @("OpenArk64", "OpenArk") },
            # --- Tick / Bronze Butler ---
            @{ Name = "Daserf";           Type = "Malware"; Aliases = @("Daserf", "Nioupale", "Backdoor.Daserf") },
            @{ Name = "Datper";           Type = "Malware"; Aliases = @("Datper", "Trojan.Datper", "Tick Datper") },
            @{ Name = "Gofarer";          Type = "Malware"; Aliases = @("Gofarer", "Tick Backdoor") },
            @{ Name = "SymonLoader";      Type = "Malware"; Aliases = @("SymonLoader", "Symon Loader") },
            @{ Name = "Gokcpdoor";        Type = "Malware"; Aliases = @("Gokcpdoor", "GOKCP", "Trojan.Gokcpdoor") },
            # --- Velvet Ant ---
            @{ Name = "VelvetSting";      Type = "Malware"; Aliases = @("VelvetSting", "Velvet Sting") },
            @{ Name = "VelvetTap";        Type = "Malware"; Aliases = @("VelvetTap", "Velvet Tap") },
            # --- Lotus Blossom ---
            @{ Name = "Hannotog";         Type = "Malware"; Aliases = @("Hannotog", "Backdoor.Hannotog") },
            @{ Name = "Emissary";         Type = "Malware"; Aliases = @("Emissary", "Trojan.Emissary", "Emissary Backdoor") },
            # --- BlackTech ---
            @{ Name = "Pled";             Type = "Malware"; Aliases = @("Pled", "Backdoor.Pled") },
            @{ Name = "Consock";          Type = "Malware"; Aliases = @("Consock", "Backdoor.Consock") },
            # --- Ke3chang ---
            @{ Name = "Ketrican";         Type = "Malware"; Aliases = @("Ketrican", "Backdoor.Ketrican") },
            @{ Name = "RoyalDNS";         Type = "Malware"; Aliases = @("RoyalDNS", "Royal DNS") },
            # --- APT31 ---
            @{ Name = "SOGU";             Type = "Malware"; Aliases = @("SOGU", "PlugX SOGU", "Korplug SOGU") },
            @{ Name = "LuckyBird";        Type = "Malware"; Aliases = @("LuckyBird", "Lucky Bird") },
            # --- APT27 ---
            @{ Name = "HyperBro";         Type = "Malware"; Aliases = @("HyperBro", "Hyper Bro", "Backdoor.HyperBro") },
            # --- Hafnium ---
            @{ Name = "Tarrask";          Type = "Malware"; Aliases = @("Tarrask", "Trojan.Tarrask") },
            # --- Storm-2603 ---
            @{ Name = "AK47 C2";          Type = "Malware"; Aliases = @("AK47 C2", "AK47C2") },
            @{ Name = "ToolShell";        Type = "Malware"; Aliases = @("ToolShell", "Tool Shell", "Backdoor.ToolShell") },
            # --- UAT-7290 ---
            @{ Name = "DriveSwitch";      Type = "Malware"; Aliases = @("DriveSwitch", "Drive Switch") },
            # --- Volt Typhoon ---
            @{ Name = "FastReverseProxy"; Type = "Malware"; Aliases = @("FastReverseProxy", "FRP", "frp tunnel") },
            # --- UNC3886 ---
            @{ Name = "TinyShell";        Type = "Malware"; Aliases = @("TinyShell", "Tiny Shell", "TriFin") },
            @{ Name = "Medusa Backdoor";  Type = "Malware"; Aliases = @("Medusa Backdoor", "Medusa Go", "Trojan.Medusa") },
            # --- Gallium ---
            @{ Name = "PingPull";         Type = "Malware"; Aliases = @("PingPull", "Ping Pull", "Backdoor.PingPull") },
            @{ Name = "Gh0st RAT";        Type = "Malware"; Aliases = @("Gh0st RAT", "Gh0stRAT", "Ghost RAT", "Trojan.Gh0st") },
            # --- Lazarus ---
            @{ Name = "Manuscrypt";       Type = "Malware"; Aliases = @("Manuscrypt", "NukeSped", "Backdoor.Manuscrypt") },
            # --- APT32 ---
            @{ Name = "Kerrdown";         Type = "Malware"; Aliases = @("Kerrdown", "Kerr Down", "Trojan.Kerrdown") },
            # --- Sandworm ---
            @{ Name = "BlackEnergy";      Type = "Malware"; Aliases = @("BlackEnergy", "BlackEnergy2", "BlackEnergy3", "Quedagh", "Backdoor.Quedagh") },
            @{ Name = "Industroyer";      Type = "Malware"; Aliases = @("Industroyer", "Industroyer2", "CrashOverride", "Crash Override") },
            @{ Name = "WAVESIGN";         Type = "Malware"; Aliases = @("WAVESIGN", "Wave Sign", "Wavesign") },
            @{ Name = "Infamous Chisel";  Type = "Malware"; Aliases = @("Infamous Chisel", "InfamousChisel") },
            # --- APT1 ---
            @{ Name = "PoisonIvy";        Type = "Malware"; Aliases = @("PoisonIvy", "Poison Ivy", "Backdoor.PoisonIvy") },

            # --- G. OFFENSIVE SECURITY / DUAL-USE TOOLS ---
            @{ Name = "SharpHide";        Type = "Malware"; Aliases = @("SharpHide", "SharpHide Tool") },
            @{ Name = "Cobalt Strike";    Type = "Malware"; Aliases = @("Cobalt Strike", "Beacon", "BEACON") },
            @{ Name = "Sliver";           Type = "Malware"; Aliases = @("Sliver", "Sliver C2", "Implant.Sliver", "Golang.Sliver") },
            @{ Name = "Brute Ratel";      Type = "Malware"; Aliases = @("Brute Ratel", "BRC4") },
            @{ Name = "Havoc";            Type = "Malware"; Aliases = @("Havoc", "Havoc C2", "Demon.bin", "Demon.exe") },
            @{ Name = "Mythic";           Type = "Malware"; Aliases = @("Mythic", "Mythic C2", "Apfell") },
            @{ Name = "Maestro";          Type = "Malware"; Aliases = @("Maestro", "Maestro Toolkit") },
            @{ Name = "Mimikatz";         Type = "Malware"; Aliases = @("Mimikatz", "sekurlsa") },
            @{ Name = "Impacket";         Type = "Malware"; Aliases = @("Impacket", "secretsdump", "psexec.py", "wmiexec.py") },
            @{ Name = "Rubeus";           Type = "Malware"; Aliases = @("Rubeus", "Kerberos abuse") },
            @{ Name = "Certipy";          Type = "Malware"; Aliases = @("Certipy") },
            @{ Name = "SharpHound";       Type = "Malware"; Aliases = @("SharpHound", "BloodHound Collector") },
            @{ Name = "GoExec";           Type = "Malware"; Aliases = @("GoExec", "goexec") },
            @{ Name = "DWAgent";          Type = "Malware"; Aliases = @("DWAgent", "DWService") },
            @{ Name = "Chisel";           Type = "Malware"; Aliases = @("Chisel", "Chisel Tunnel") },
            @{ Name = "Fscan";            Type = "Malware"; Aliases = @("Fscan", "Fscan tool") },
            @{ Name = "Rclone";           Type = "Malware"; Aliases = @("Rclone", "Rclone tool") },
            @{ Name = "AnyDesk";          Type = "Malware"; Aliases = @("AnyDesk", "AnyDesk abuse") },
            @{ Name = "ConnectWise ScreenConnect"; Type = "Malware"; Aliases = @("ConnectWise", "ScreenConnect", "ConnectWise Control", "RemoteSupport") },
            @{ Name = "NetSupport";       Type = "Malware"; Aliases = @("NetSupport Manager", "NetSupport RAT") },
            @{ Name = "Ligolo";           Type = "Malware"; Aliases = @("Ligolo", "Ligolo-ng") },
            @{ Name = "Restic";           Type = "Malware"; Aliases = @("Restic", "restic backup") },
            @{ Name = "Metasploit";       Type = "Malware"; Aliases = @("Metasploit", "Meterpreter") },
            @{ Name = "China Chopper";    Type = "Malware"; Aliases = @("China Chopper", "ChinaChopper", "Webshell.ChinaChopper", "Chopper Webshell") },
            @{ Name = "JuicyPotato";      Type = "Malware"; Aliases = @("JuicyPotato", "Juicy Potato", "BadPotato", "Bad Potato") },
            @{ Name = "AdFind";           Type = "Malware"; Aliases = @("AdFind", "adfind.exe") },
            @{ Name = "ADExplorer";       Type = "Malware"; Aliases = @("ADExplorer", "ADExplorer64", "Sysinternals ADExplorer") },
            @{ Name = "Grixba";           Type = "Malware"; Aliases = @("Grixba", "Trojan.Grixba") },
            @{ Name = "Bland AI";         Type = "Malware"; Aliases = @("Bland AI", "BlandAI") }
        )

        Write-Host "==========================================" -ForegroundColor Cyan
        Write-Host "    GLOBAL THREAT INTEL HARVESTER v14.0"
        Write-Host "    Total Targets: $($MasterConfig.Count) | Max Samples: $MaxSamples"
        Write-Host "    StartDate: $StartDate"
        Write-Host "==========================================" -ForegroundColor Cyan

        # --- 2. AUTHENTICATION (OPTIONAL) ---
        if (-not (Get-Module -Name "Microsoft.PowerShell.SecretManagement" -ListAvailable)) {
            Write-Warning "SecretManagement module not found. API keys will not load; only sources without keys may work."
        } else {
            Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction SilentlyContinue | Out-Null
        }

        $VTKey = $null; $SixID = $null; $SixSecret = $null
        $TFKey = $null; $MBKey = $null; $UHKey = $null; $OTXKey = $null

        try { $VTKey     = (Get-Secret -Name 'VT_API_Key_1' -AsPlainText -ErrorAction Stop).Trim() } catch {}
        try { $SixID     = (Get-Secret -Name 'Cyber6Gil_Client_Id' -AsPlainText -ErrorAction Stop).Trim() } catch {}
        try { $SixSecret = (Get-Secret -Name 'Cyber6Gil_API_Key' -AsPlainText -ErrorAction Stop).Trim() } catch {}
        try { $TFKey  = (Get-Secret -Name 'ThreatFox_AuthKey' -AsPlainText -ErrorAction Stop).Trim() } catch {}
        try { $MBKey  = (Get-Secret -Name 'MalwareBazaar_AuthKey' -AsPlainText -ErrorAction Stop).Trim() } catch {}
        try { $UHKey  = (Get-Secret -Name 'URLhaus_AuthKey' -AsPlainText -ErrorAction Stop).Trim() } catch {}
        try { $OTXKey = (Get-Secret -Name 'OTX_API_Key' -AsPlainText -ErrorAction Stop).Trim() } catch {}

        $VTHeaders = $null
        if (Test-HasValue $VTKey) {
            $VTHeaders = @{ "x-apikey" = $VTKey; "accept" = "application/json" }
        }

        $SixHeaders = $null
        if ($EnableCybersixgill -and (Test-HasValue $SixID) -and (Test-HasValue $SixSecret)) {
            try {
                $AuthBody = @{ grant_type="client_credentials"; client_id=$SixID; client_secret=$SixSecret }
                $Token = (Invoke-RestMethod -Method Post -Uri "https://api.cybersixgill.com/auth/token" -Body $AuthBody -ErrorAction Stop).access_token
                $SixHeaders = @{ "Authorization"="Bearer $Token"; "Content-Type"="application/json" }
            } catch {
                Write-Warning "Cybersixgill auth failed. Skipping C6G."
                $SixHeaders = $null
            }
        }

        $TFHeaders = $null
        if ($EnableThreatFox -and (Test-HasValue $TFKey)) {
            $TFHeaders = @{ "Auth-Key"=$TFKey; "Content-Type"="application/json" }
        }

        $MBHeaders = $null
        if ($EnableMalwareBazaar -and (Test-HasValue $MBKey)) {
            $MBHeaders = @{ "Auth-Key"=$MBKey; "Content-Type"="application/x-www-form-urlencoded" }
        }

        $UHHeaders = $null
        if ($EnableURLhaus -and (Test-HasValue $UHKey)) {
            $UHHeaders = @{ "Auth-Key"=$UHKey; "Content-Type"="application/x-www-form-urlencoded" }
        } elseif ($EnableURLhaus) {
            $UHHeaders = @{ "Content-Type"="application/x-www-form-urlencoded" }
        }

        $OTXHeaders = $null
        if ($EnableOTX -and (Test-HasValue $OTXKey)) {
            $OTXHeaders = @{ "X-OTX-API-KEY"=$OTXKey; "accept"="application/json" }
        }

        # --- 3. EXECUTION LOOP ---
        foreach ($Entry in $MasterConfig) {
            if ($SpecificActor -and ($Entry.Name -ne $SpecificActor)) { continue }

            $ActorName = $Entry.Name
            $Aliases   = $Entry.Aliases
            $Type      = $Entry.Type

            Write-Host "`n---------------------------------------------------"
            Write-Host "PROCESSING: $ActorName ($Type)" -ForegroundColor Yellow
            if ($Entry.LinkedTools) { Write-Host "Known Toolset: $($Entry.LinkedTools -join ', ')" -ForegroundColor DarkGray }

            $BaseRoot = "$PSScriptRoot\..\apt"
            if ($Type -eq "APT") {
                $TargetFolder = Join-Path -Path $BaseRoot -ChildPath "APTs\$($Entry.Country)\$($Entry.Name)"
            } else {
                $TargetFolder = Join-Path -Path $BaseRoot -ChildPath "Malware Families\$($Entry.Name)"
            }

            try { $TargetFolder = [System.IO.Path]::GetFullPath($TargetFolder) } catch {}
            if (-not (Test-Path $TargetFolder)) { New-Item -ItemType Directory -Path $TargetFolder -Force | Out-Null }

            $SafeName = $ActorName -replace '[\\/*?:"<>|]', ''
            $OutFile = Join-Path -Path $TargetFolder -ChildPath "${SafeName}_Master_Intel.csv"

            $ExistingData = @()
            if (Test-Path $OutFile) {
                try {
                    $ExistingData = Import-Csv $OutFile
                    Write-Host "    Loaded $($ExistingData.Count) existing records." -ForegroundColor Gray
                } catch {
                    Write-Warning "    Could not read existing CSV. Starting fresh."
                }
            }

            $Raw_IOCs  = @()
            $HashCache = @{}

            # =========================================================
            # [A] VIRUSTOTAL INTELLIGENCE HARVEST (OPTIONAL)
            # =========================================================
            $VTIntelligenceRan = $false

            if ($EnableVTIntelligence -and $VTHeaders) {
                Write-Host " -> [VT] Searching..." -NoNewline

                $QueriesToRun = @()
                if ($Type -eq "APT") {
                    foreach ($Alias in $Aliases) {
                        $QueriesToRun += [PSCustomObject]@{ Query = "threat_actor:`"$Alias`""; Type = "Strict"; Term = $Alias }
                    }
                } else {
                    $CombinedAlias = ($Aliases | ForEach-Object { "engines:`"$_`" OR name:`"$_`" OR tags:`"$_`" OR caption:`"$_`" OR family:`"$_`" OR threat_label:`"$_`"" }) -join " OR "
                    $QueriesToRun += [PSCustomObject]@{ Query = "($CombinedAlias)"; Type = "Bulk"; Term = "MalwareFamily" }
                }

                foreach ($Q in $QueriesToRun) {
                    if ($Raw_IOCs.Count -ge $MaxSamples) { break }

                    try {
                        $CurrentQuery = "$($Q.Query) AND fs:$StartDate+"
                        $Encoded = [Uri]::EscapeDataString($CurrentQuery)
                        $Uri = "https://www.virustotal.com/api/v3/intelligence/search?query=$Encoded&limit=$MaxSamples&order=first_submission_date-"

                        $Response = Invoke-RestMethod -Uri $Uri -Headers $VTHeaders -Method Get -ErrorAction Stop
                        $VTIntelligenceRan = $true

                        if ($Response.data) {
                            foreach ($File in $Response.data) {
                                if ($Raw_IOCs.Count -ge $MaxSamples) { break }

                                $SHA256 = $File.id
                                if ($File.attributes.md5)  { $HashCache[$File.attributes.md5]  = $SHA256 }
                                if ($File.attributes.sha1) { $HashCache[$File.attributes.sha1] = $SHA256 }

                                $Raw_IOCs += [PSCustomObject]@{
                                    Date=$([DateTimeOffset]::FromUnixTimeSeconds($File.attributes.first_submission_date).DateTime.ToString("yyyy-MM-dd"));
                                    Source="VirusTotal"; Actor=$ActorName; IOCType="SHA256"; IOCValue=$SHA256;
                                    Context=$File.attributes.meaningful_name; Link="https://www.virustotal.com/gui/file/$($SHA256)"
                                }
                            }
                        } else {
                            if ($Q.Type -eq "Strict") {
                                Write-Host " [0 hits, trying fallback]" -NoNewline -ForegroundColor DarkGray
                                $FallbackQuery = "`"$($Q.Term)`" AND fs:$StartDate+"
                                $EncodedFallback = [Uri]::EscapeDataString($FallbackQuery)
                                $FallbackUri = "https://www.virustotal.com/api/v3/intelligence/search?query=$EncodedFallback&limit=100&order=first_submission_date-"

                                $FallbackResp = Invoke-RestMethod -Uri $FallbackUri -Headers $VTHeaders -Method Get -ErrorAction SilentlyContinue
                                $VTIntelligenceRan = $true

                                if ($FallbackResp.data) {
                                    foreach ($File in $FallbackResp.data) {
                                        if ($Raw_IOCs.Count -ge $MaxSamples) { break }
                                        $SHA256 = $File.id
                                        if ($File.attributes.md5) { $HashCache[$File.attributes.md5] = $SHA256 }
                                        $Raw_IOCs += [PSCustomObject]@{
                                            Date=$([DateTimeOffset]::FromUnixTimeSeconds($File.attributes.first_submission_date).DateTime.ToString("yyyy-MM-dd"));
                                            Source="VirusTotal (Fallback)"; Actor=$ActorName; IOCType="SHA256"; IOCValue=$SHA256;
                                            Context="Text Match: $($Q.Term)"; Link="https://www.virustotal.com/gui/file/$($SHA256)"
                                        }
                                    }
                                }
                            }
                        }
                    } catch {}
                }

                if ($Raw_IOCs.Count -gt 0) { Write-Host " Found $($Raw_IOCs.Count)." -ForegroundColor Green }
                elseif ($VTIntelligenceRan) { Write-Host " Found 0." -ForegroundColor Gray }
                else { Write-Host " Skipped (no VT Intelligence access)." -ForegroundColor DarkGray }
            } else {
                Write-Host " -> [VT] Skipped (no VT key or disabled)." -ForegroundColor DarkGray
            }

            # =========================================================
            # [B] CYBERSIXGILL HARVEST (OPTIONAL, LEGACY)
            # =========================================================
            if ($EnableCybersixgill -and $SixHeaders) {
                Write-Host " -> [C6G] Searching..." -NoNewline
                $SixCount = 0

                if ($Type -eq "Malware") {
                    $C6G_Url = "https://api.cybersixgill.com/threat_hunting/malware/ioc"
                    $C6G_Key = "malware_name"
                } else {
                    $C6G_Url = "https://api.cybersixgill.com/threat_hunting/apts/ioc"
                    $C6G_Key = "apt_name"
                }

                foreach ($Alias in $Aliases) {
                    if ($SixCount -ge $MaxSamples) { break }

                    $Offset = 0; $PageLimit = 100; $MorePages = $true
                    do {
                        if ($SixCount -ge $MaxSamples) { $MorePages = $false; break }

                        $PayloadMap = @{ pagination = @{ limit = $PageLimit; offset = $Offset } }
                        $PayloadMap[$C6G_Key] = $Alias
                        $Payload = $PayloadMap | ConvertTo-Json -Depth 5

                        try {
                            $Response = Invoke-RestMethod -Method Post -Uri $C6G_Url -Headers $SixHeaders -Body $Payload
                            if ($Response.objects) {
                                foreach ($Item in $Response.objects) {
                                    if ($SixCount -ge $MaxSamples) { break }

                                    if ($Item.ioc_type -match "Hash|MD5|SHA") {
                                        $Raw_IOCs += [PSCustomObject]@{
                                            Date=$Item.ioc_last_seen; Source="Cybersixgill"; Actor=$ActorName;
                                            IOCType=$Item.ioc_type; IOCValue=$Item.ioc_value;
                                            Context="Confidence: $($Item.ioc_confidence)"; Link="N/A"
                                        }
                                        $SixCount++
                                    }
                                }
                                $Offset += $PageLimit
                                if ($Response.objects.Count -lt $PageLimit) { $MorePages = $false }
                            } else { $MorePages = $false }
                        } catch { $MorePages = $false }
                    } while ($MorePages)
                }
                Write-Host " Found $SixCount." -ForegroundColor Green
            } else {
                Write-Host " -> [C6G] Skipped (no creds/token or disabled)." -ForegroundColor DarkGray
            }

            # =========================================================
            # [C] COMMUNITY FEEDS
            # =========================================================
            $addedCommunity = 0
            Write-Host " -> [Community] Searching..." -NoNewline

            $TagsToQuery = @()
            if ($Type -eq "APT") {
                $TagsToQuery += $Aliases
                if ($Entry.LinkedTools) { $TagsToQuery += $Entry.LinkedTools }
            } else {
                $TagsToQuery += $Aliases
            }
            $TagsToQuery = $TagsToQuery | Where-Object { $_ } | Select-Object -Unique

            foreach ($tag in $TagsToQuery) {
                if ($Raw_IOCs.Count -ge $MaxSamples) { break }

                if ($EnableThreatFox -and $TFHeaders) {
                    foreach ($row in (Get-ThreatFoxIOCsByTag -Tag $tag -Limit 200 -Headers $TFHeaders)) {
                        if ($Raw_IOCs.Count -ge $MaxSamples) { break }
                        $Raw_IOCs += [PSCustomObject]@{
                            Date=$row.Date; Source=$row.Source; Actor=$ActorName;
                            IOCType=$row.IOCType; IOCValue=$row.IOCValue;
                            Context="$($row.Context) (tag=$tag)"; Link=$row.Link
                        }
                        $addedCommunity++
                    }
                }

                if ($Raw_IOCs.Count -ge $MaxSamples) { break }

                if ($EnableMalwareBazaar -and $MBHeaders) {
                    foreach ($row in (Get-MalwareBazaarByTag -Tag $tag -Limit 200 -Headers $MBHeaders)) {
                        if ($Raw_IOCs.Count -ge $MaxSamples) { break }
                        $Raw_IOCs += [PSCustomObject]@{
                            Date=$row.Date; Source=$row.Source; Actor=$ActorName;
                            IOCType=$row.IOCType; IOCValue=$row.IOCValue;
                            Context="$($row.Context) (tag=$tag)"; Link=$row.Link
                        }
                        $addedCommunity++
                    }
                }

                if ($Raw_IOCs.Count -ge $MaxSamples) { break }

                if ($EnableURLhaus -and $UHHeaders) {
                    foreach ($row in (Get-URLhausByTag -Tag $tag -Limit 200 -Headers $UHHeaders)) {
                        if ($Raw_IOCs.Count -ge $MaxSamples) { break }
                        $Raw_IOCs += [PSCustomObject]@{
                            Date=$row.Date; Source=$row.Source; Actor=$ActorName;
                            IOCType=$row.IOCType; IOCValue=$row.IOCValue;
                            Context="$($row.Context) (tag=$tag)"; Link=$row.Link
                        }
                        $addedCommunity++
                    }
                }

                if ($Raw_IOCs.Count -ge $MaxSamples) { break }

                if ($EnableOTX -and $OTXHeaders -and $Type -eq "APT") {
                    foreach ($row in (Get-OTXPulseIndicatorsByKeyword -Keyword $tag -MaxPulses 3 -Headers $OTXHeaders)) {
                        if ($Raw_IOCs.Count -ge $MaxSamples) { break }
                        $Raw_IOCs += [PSCustomObject]@{
                            Date=$row.Date; Source=$row.Source; Actor=$ActorName;
                            IOCType=$row.IOCType; IOCValue=$row.IOCValue;
                            Context="$($row.Context) (kw=$tag)"; Link=$row.Link
                        }
                        $addedCommunity++
                    }
                }
            }

            Write-Host " Added $addedCommunity." -ForegroundColor Green

            # =========================================================
            # [D] NORMALIZATION & MERGE
            # =========================================================
            if ($Raw_IOCs.Count -gt 0) {
                Write-Host " -> Normalizing & Merging..." -ForegroundColor Cyan

                $FinalList = @()
                $UniqueUnknownHashes = @()

                foreach ($Row in $Raw_IOCs) {
                    $Row.IOCType = ConvertTo-HashIocType $Row.IOCType

                    if ($Row.IOCType -eq "SHA256") {
                        $FinalList += $Row
                    }
                    elseif ($Row.IOCType -match "MD5|SHA1") {
                        if ($HashCache.ContainsKey($Row.IOCValue)) {
                            $Row.IOCType = "SHA256"
                            $Row.IOCValue = $HashCache[$Row.IOCValue]
                            $FinalList += $Row
                        } else {
                            $UniqueUnknownHashes += $Row.IOCValue
                            $FinalList += $Row
                        }
                    } else {
                        $FinalList += $Row
                    }
                }

                if ($EnableVTHashResolution -and $VTHeaders) {
                    $ToQuery = $UniqueUnknownHashes | Select-Object -Unique
                    if ($ToQuery) {
                        $Count = if ($ToQuery -is [array]) { $ToQuery.Count } else { 1 }
                        Write-Host "    Resolving $Count unique hashes via VirusTotal files API..." -ForegroundColor Gray

                        foreach ($Hash in $ToQuery) {
                            if ($HashCache.ContainsKey($Hash)) { continue }

                            try {
                                $VTFileUri = "https://www.virustotal.com/api/v3/files/$Hash"
                                $VTRes = Invoke-RestMethod -Uri $VTFileUri -Headers $VTHeaders -Method Get -ErrorAction SilentlyContinue

                                if ($VTRes.data.id) {
                                    $NewSHA256 = $VTRes.data.id

                                    if ($VTRes.data.attributes.md5)  { $HashCache[$VTRes.data.attributes.md5]  = $NewSHA256 }
                                    if ($VTRes.data.attributes.sha1) { $HashCache[$VTRes.data.attributes.sha1] = $NewSHA256 }
                                    $HashCache[$Hash] = $NewSHA256

                                    foreach ($Row in $FinalList) {
                                        if ($Row.IOCValue -eq $Hash) {
                                            $Row.IOCType  = "SHA256"
                                            $Row.IOCValue = $NewSHA256
                                        }
                                    }
                                }
                            } catch {}
                        }
                    }
                } else {
                    Write-Host "    Hash resolution skipped (no VT key or disabled)." -ForegroundColor DarkGray
                }

                $CombinedList = $FinalList + $ExistingData
                $UniqueSet = $CombinedList | Sort-Object Date -Descending | Group-Object IOCValue | ForEach-Object { $_.Group[0] }

                $UniqueSet | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8

                # Report actual unique additions, not the raw pre-dedup pull
                # count. The community feeds (ThreatFox, MalwareBazaar, etc.)
                # return all tag-matching IOCs every run, so $Raw_IOCs.Count is
                # an inbound-volume number and most rows usually collide with
                # existing values - showing it as "New" is misleading.
                $priorTotal = if ($ExistingData) { @($ExistingData).Count } else { 0 }
                $actualNew  = $UniqueSet.Count - $priorTotal
                Write-Host " -> SAVED: $OutFile" -ForegroundColor Cyan
                Write-Host ("    New: {0} | Fetched: {1} | Total: {2}" -f $actualNew, $Raw_IOCs.Count, $UniqueSet.Count) -ForegroundColor Gray
            } else {
                Write-Host " -> No new data found. Existing data preserved." -ForegroundColor Gray
            }
        }

        Write-Host "`n[BATCH COMPLETE]" -ForegroundColor Green
    }
}

Export-ModuleMember -Function Get-ThreatActorIOCs
function New-ArtOfWarMitreMatrix {
    [CmdletBinding()]
    param(
        [string]$AptRootPath = ".\apt",
        [string]$BehaviorRootPath = "output-baseline\VirusTotal-behaviors",
        [string]$OutputCsvPath = ".\reports\ArtOfWar\ArtOfWar_MITRE_Matrix.csv",
        [string]$OutputJsonPath = ".\reports\ArtOfWar\ArtOfWar_MITRE_Matrix.json",
        [int]$ExampleHashLimit = 5
    )

    function Resolve-AbsolutePath {
        param([Parameter(Mandatory = $true)][string]$Path)
        if ([System.IO.Path]::IsPathRooted($Path)) { return $Path }
        return (Join-Path (Get-Location).Path ($Path.TrimStart('.\').TrimStart('./')))
    }

    function Get-NormalizedHash {
        param([string]$HashText)
        if ([string]::IsNullOrWhiteSpace($HashText)) { return $null }
        $h = $HashText.Trim().ToLowerInvariant()
        if ($h -match '^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$') { return $h }
        return $null
    }

    function Get-MitreIdsFromText {
        param([string]$Text)
        if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
        return ([regex]::Matches($Text, 'T\d{4}(?:\.\d{3})?') | ForEach-Object { $_.Value.ToUpperInvariant() } | Select-Object -Unique)
    }

    function Ensure-StringSet {
        param(
            [hashtable]$Map,
            [string]$Key
        )
        if (-not $Map.ContainsKey($Key)) {
            $Map[$Key] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        }
        return ,$Map[$Key]
    }

    function Ensure-MappingBucket {
        param(
            [hashtable]$Map,
            [string]$Key,
            [string]$ArtOfWarId,
            [string]$ArtOfWarObjective,
            [string]$ArtOfWarBehavior,
            [string]$ArtOfWarMethod,
            [string]$MappedMitreTechnique
        )
        if (-not $Map.ContainsKey($Key)) {
            $Map[$Key] = [PSCustomObject]@{
                ArtOfWarId          = $ArtOfWarId
                ArtOfWarObjective   = $ArtOfWarObjective
                ArtOfWarBehavior    = $ArtOfWarBehavior
                ArtOfWarMethod      = $ArtOfWarMethod
                ArtOfWarEntry       = if ([string]::IsNullOrWhiteSpace($ArtOfWarId)) {
                    "[$ArtOfWarObjective] $ArtOfWarBehavior"
                } else {
                    "$ArtOfWarId [$ArtOfWarObjective] $ArtOfWarBehavior"
                }
                MappedMitreTechnique = $MappedMitreTechnique
                _SampleHashes        = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                _Actors              = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            }
        }
        return $Map[$Key]
    }

    Write-Host "Generating Art of War -> MITRE Matrix..." -ForegroundColor DarkCyan

    if (-not (Test-Path $AptRootPath)) {
        Write-Error "APT root path not found: $AptRootPath"
        return
    }

    $analysisFiles = Get-ChildItem -Path $AptRootPath -Recurse -File -Filter "Targeted_Analysis_Map.csv" -ErrorAction SilentlyContinue
    if (-not $analysisFiles -or $analysisFiles.Count -eq 0) {
        Write-Error "No Targeted_Analysis_Map.csv files found under: $AptRootPath"
        return
    }

    Write-Host ("  [1/4] Indexing behavior JSON files from: {0}" -f $BehaviorRootPath) -NoNewline
    $behaviorIndex = @{}
    $behaviorFileCount = 0
    if (Test-Path $BehaviorRootPath) {
        Get-ChildItem -Path $BehaviorRootPath -Recurse -File -Filter "*.json" -ErrorAction SilentlyContinue | ForEach-Object {
            $behaviorFileCount++
            $h = Get-NormalizedHash ([System.IO.Path]::GetFileNameWithoutExtension($_.Name))
            if ($h -and -not $behaviorIndex.ContainsKey($h)) {
                $behaviorIndex[$h] = $_.FullName
            }
        }
    }
    Write-Host (" Done ({0} files, {1} indexed hashes)." -f $behaviorFileCount, $behaviorIndex.Count) -ForegroundColor Green

    Write-Host ("  [2/4] Parsing MITRE context from {0} targeted map file(s)..." -f $analysisFiles.Count) -NoNewline
    $sampleToMitre = @{}
    $sampleToActors = @{}
    $sampleHashes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($file in $analysisFiles) {
        $actorName = (Split-Path $file.DirectoryName -Leaf)
        try {
            $rows = Import-Csv -Path $file.FullName -ErrorAction Stop
            foreach ($row in $rows) {
                $hash = Get-NormalizedHash $row.File_Hash
                if (-not $hash) { continue }

                [void]$sampleHashes.Add($hash)
                $actorSet = Ensure-StringSet -Map $sampleToActors -Key $hash
                if (-not [string]::IsNullOrWhiteSpace($actorName)) { [void]$actorSet.Add($actorName) }

                if ($row.Indicator_Type -ieq "MITRE Technique") {
                    $mitreSet = Ensure-StringSet -Map $sampleToMitre -Key $hash
                    foreach ($tid in (Get-MitreIdsFromText $row.Unique_Item)) {
                        [void]$mitreSet.Add($tid)
                    }
                }
            }
        }
        catch {
            Write-Host ("`n    Warning: failed to parse {0}" -f $file.FullName) -ForegroundColor Yellow
        }
    }
    Write-Host (" Done ({0} unique sample hash(es))." -f $sampleHashes.Count) -ForegroundColor Green

    Write-Host "  [3/4] Joining Art of War (MBC) with MITRE techniques..." -NoNewline
    $mappingAgg = @{}
    $unmappedArtOfWar = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $samplesWithBehavior = 0
    $samplesWithMbc = 0

    foreach ($hash in $sampleHashes) {
        $behaviorPath = $behaviorIndex[$hash]
        if (-not $behaviorPath) { continue }

        $samplesWithBehavior++
        $json = $null
        try {
            $json = Get-Content -Path $behaviorPath -Raw -ErrorAction Stop | ConvertFrom-Json
        }
        catch {
            continue
        }

        $mbcRows = @($json.data.mbc | Where-Object { $_ })
        if ($mbcRows.Count -eq 0) { continue }
        $samplesWithMbc++

        $mitreSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        if ($sampleToMitre.ContainsKey($hash)) {
            foreach ($tid in $sampleToMitre[$hash]) { [void]$mitreSet.Add($tid) }
        }
        if ($json.data.mitre_attack_techniques) {
            foreach ($m in $json.data.mitre_attack_techniques) {
                foreach ($tid in (Get-MitreIdsFromText ([string]$m.id))) {
                    [void]$mitreSet.Add($tid)
                }
            }
        }

        foreach ($m in $mbcRows) {
            $aowId = [string]$m.id
            $aowObj = [string]$m.objective
            $aowBeh = [string]$m.behavior
            $aowMethod = [string]$m.method

            if ([string]::IsNullOrWhiteSpace($aowId) -and
                [string]::IsNullOrWhiteSpace($aowObj) -and
                [string]::IsNullOrWhiteSpace($aowBeh)) {
                continue
            }

            $aowKey = "{0}|{1}|{2}|{3}" -f $aowId, $aowObj, $aowBeh, $aowMethod

            $targetMitre = @()
            if ($mitreSet.Count -gt 0) {
                $targetMitre = @($mitreSet)
            } else {
                $targetMitre = @("UNMAPPED")
                [void]$unmappedArtOfWar.Add($aowKey)
            }

            foreach ($tid in $targetMitre) {
                $k = "{0}||{1}" -f $aowKey, $tid
                $bucket = Ensure-MappingBucket -Map $mappingAgg -Key $k -ArtOfWarId $aowId -ArtOfWarObjective $aowObj -ArtOfWarBehavior $aowBeh -ArtOfWarMethod $aowMethod -MappedMitreTechnique $tid
                [void]$bucket._SampleHashes.Add($hash)

                if ($sampleToActors.ContainsKey($hash)) {
                    foreach ($actor in $sampleToActors[$hash]) {
                        [void]$bucket._Actors.Add($actor)
                    }
                }
            }
        }
    }
    Write-Host (" Done ({0} mapping pair(s))." -f $mappingAgg.Count) -ForegroundColor Green

    Write-Host "  [4/4] Writing output files..." -NoNewline
    $csvOut = Resolve-AbsolutePath $OutputCsvPath
    $jsonOut = Resolve-AbsolutePath $OutputJsonPath
    $csvDir = Split-Path -Path $csvOut -Parent
    $jsonDir = Split-Path -Path $jsonOut -Parent
    if (-not (Test-Path $csvDir)) { New-Item -Path $csvDir -ItemType Directory -Force | Out-Null }
    if (-not (Test-Path $jsonDir)) { New-Item -Path $jsonDir -ItemType Directory -Force | Out-Null }

    $matrixRows = $mappingAgg.Values | ForEach-Object {
        [PSCustomObject]@{
            ArtOfWarId           = $_.ArtOfWarId
            ArtOfWarObjective    = $_.ArtOfWarObjective
            ArtOfWarBehavior     = $_.ArtOfWarBehavior
            ArtOfWarMethod       = $_.ArtOfWarMethod
            ArtOfWarEntry        = $_.ArtOfWarEntry
            MappedMitreTechnique = $_.MappedMitreTechnique
            SampleCount          = $_._SampleHashes.Count
            ActorCount           = $_._Actors.Count
            Actors               = (($_._Actors | Sort-Object) -join "; ")
            ExampleHashes        = (($_._SampleHashes | Sort-Object | Select-Object -First $ExampleHashLimit) -join "; ")
        }
    } | Sort-Object ArtOfWarObjective, ArtOfWarBehavior, ArtOfWarMethod, MappedMitreTechnique

    $aowEntryGroups = @{}
    foreach ($r in $matrixRows) {
        $ek = "{0}|{1}|{2}|{3}|{4}" -f $r.ArtOfWarId, $r.ArtOfWarObjective, $r.ArtOfWarBehavior, $r.ArtOfWarMethod, $r.ArtOfWarEntry
        if (-not $aowEntryGroups.ContainsKey($ek)) {
            $aowEntryGroups[$ek] = [PSCustomObject]@{
                ArtOfWarId        = $r.ArtOfWarId
                ArtOfWarObjective = $r.ArtOfWarObjective
                ArtOfWarBehavior  = $r.ArtOfWarBehavior
                ArtOfWarMethod    = $r.ArtOfWarMethod
                ArtOfWarEntry     = $r.ArtOfWarEntry
                _Mitre            = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                _Actors           = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                _Hashes           = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            }
        }
        $g = $aowEntryGroups[$ek]
        if (-not [string]::IsNullOrWhiteSpace($r.MappedMitreTechnique)) { [void]$g._Mitre.Add($r.MappedMitreTechnique) }
        foreach ($a in ($r.Actors -split '; ' | Where-Object { $_ })) { [void]$g._Actors.Add($a) }
        foreach ($h in ($r.ExampleHashes -split '; ' | Where-Object { $_ })) { [void]$g._Hashes.Add($h) }
    }

    $aowRows = $aowEntryGroups.Values | ForEach-Object {
        [PSCustomObject]@{
            ArtOfWarId        = $_.ArtOfWarId
            ArtOfWarObjective = $_.ArtOfWarObjective
            ArtOfWarBehavior  = $_.ArtOfWarBehavior
            ArtOfWarMethod    = $_.ArtOfWarMethod
            ArtOfWarEntry     = $_.ArtOfWarEntry
            MitreTechniques   = @($_._Mitre | Sort-Object)
            Actors            = @($_._Actors | Sort-Object)
            ExampleHashes     = @($_._Hashes | Sort-Object | Select-Object -First $ExampleHashLimit)
        }
    } | Sort-Object ArtOfWarObjective, ArtOfWarBehavior, ArtOfWarMethod

    $matrixRows | Export-Csv -Path $csvOut -NoTypeInformation -Encoding UTF8

    $allTechniques = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $matrixRows) {
        if ($r.MappedMitreTechnique -and $r.MappedMitreTechnique -ne "UNMAPPED") {
            [void]$allTechniques.Add($r.MappedMitreTechnique)
        }
    }

    $report = [PSCustomObject]@{
        GeneratedAtUtc          = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        AptRootPath             = (Resolve-AbsolutePath $AptRootPath)
        BehaviorRootPath        = (Resolve-AbsolutePath $BehaviorRootPath)
        AnalysisMapFileCount    = $analysisFiles.Count
        UniqueSampleHashes      = $sampleHashes.Count
        BehaviorHashesIndexed   = $behaviorIndex.Count
        SamplesWithBehavior     = $samplesWithBehavior
        SamplesWithMBC          = $samplesWithMbc
        UniqueArtOfWarEntries   = $aowRows.Count
        UniqueMitreTechniques   = $allTechniques.Count
        UnmappedArtOfWarEntries = $unmappedArtOfWar.Count
        Matrix                  = $matrixRows
        ArtOfWarEntries         = $aowRows
    }

    $report | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonOut -Encoding UTF8
    Write-Host (" Done.`n  CSV: {0}`n  JSON: {1}" -f $csvOut, $jsonOut) -ForegroundColor Green

    Write-Host ""
    Write-Host "Art of War -> MITRE matrix complete." -ForegroundColor Cyan
    Write-Host ("  Unique Art of War entries: {0}" -f $aowRows.Count)
    Write-Host ("  Unique MITRE techniques:   {0}" -f $allTechniques.Count)
    Write-Host ("  Unmapped entries:          {0}" -f $unmappedArtOfWar.Count) -ForegroundColor DarkYellow

    return [PSCustomObject]@{
        CsvPath               = $csvOut
        JsonPath              = $jsonOut
        UniqueArtOfWarEntries = $aowRows.Count
        UniqueMitreTechniques = $allTechniques.Count
        UnmappedEntries       = $unmappedArtOfWar.Count
    }
}

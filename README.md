# statisticalDifferentialPotato

Offline threat-intelligence corpus and fidelity-index builder. Ingests raw VirusTotal
metadata + behaviors, NSRL clean-software hashes, and per-APT differential analyses,
then produces the fidelity manifest + 18 per-dimension `fidelity-*.json` indices that drive
Bayesian verdict scoring in [`lasersharkkiller/elasticPotato`](https://github.com/lasersharkkiller/elasticPotato).

If elasticPotato is the runtime detection engine, this repo is the corpus + math
that gives it a prior.

> **Disk footprint.** Reference tree measured ~41 GB (`VirusTotal-main/` ~12 GB, `VirusTotal-behaviors/` ~29 GB, `apt/` ~1 GB). Plan for **40-60 GB** at full corpus.

---

## What lives here

| Path | Role |
| --- | --- |
| `output-baseline/VirusTotal-main/` | Per-hash VT v3 file objects (signatures, sandbox verdicts, YARA, cert chains, `last_analysis_results`). Six-way split: `malicious/`, `SignedVerified/`, `unsignedWin/`, `unsignedLinux/`, `unverified/`, `drivers/`; plus `NSRL/<os>/`, `OT/<vendor>/`, `apt-master-intel/`, `localBaseline/`. Filenames are `<hash>.json` (SHA256 preferred; MD5/SHA1 also accepted for legacy drops, normalise via menu `1g`). |
| `output-baseline/VirusTotal-behaviors/` | Per-hash merged VT behavioral telemetry: `processes_created`, `mutexes_created`, `files_written`, `registry_keys_set`, `modules_loaded`, `dns_lookups`, `ip_traffic`, `command_executions`, `mitre_attack_techniques`. Actual on-disk buckets: `NSRL/`, `OT/`, `apt-master-intel/`, `localBaseline/`, `malicious/`. The five goodware buckets (`SignedVerified/unsignedWin/unsignedLinux/unverified/drivers`) are what the builder **scans** but must be populated manually — see the first-build warning below. |
| `NSRL/nsrl_reduced.csv` (root) + `output-baseline/behavioral-fingerprints/NSRL/<os>/` | NIST National Software Reference Library — clean-software hash corpus and per-OS known-good behavioral fingerprints (`Debian-13`, `Ubuntu-24.04`, `Windows-11`, `Windows-Server-2025`). |
| `output-baseline/IntezerStrings/` | Intezer code-reuse string enrichment per malicious hash (sparse). |
| `output-baseline/Cert_Analysis_Results/` | Certificate revocation/expiration hash lists. |
| `output-baseline/behavioral-fingerprints/` | Known-good behavioral reference per NSRL OS + per OT vendor. Each has `behaviors_index.json` + `Detailed_Report.html` + `Master_Intel.csv`. |
| `apt/APTs/<country>/<actor>/` | Per-actor intel: `<Actor>_Master_Intel.csv`, `Detailed_Report.html`, `report_data.js`, dated snapshot CSVs, up to 13 `Targeted*DifferentialAnalysis.json` files (typically 9 — IDS/Memory/ELF dims empty on non-Linux corpora). 10 country/motive buckets. |
| `apt/Malware Families/<name>/` | ~265 malware family folders using the identical template as APT actors. |
| `output-baseline/fidelity-manifest.json` | **Produced.** Eager-loaded index of the 18 per-dim files, corpus totals, scoring params, calibration state. Schema `v2`, sub-MB in typical corpora (hard ceiling 10 MB enforced by Phase 3). |
| `output-baseline/fidelity-<dim>.json` (x18) | **Produced.** Per-dimension indices: `ip`, `dns`, `process`, `file`, `registry`, `sigma-rule`, `yara-rule`, `cert-status`, `cert-publisher`, `mitre-technique`, `service`, `scheduled-task`, `module-load`, `command-execution`, `mutex`, `pipe`, `win-api`, `vt-tag`. |
| `output-baseline/fidelity-index.json` | **Produced (legacy compat shim).** Flat union across all dims. Grows linearly with unique key count. v2 consumers read the manifest + per-dim files, not this file. |
| `output-baseline/process-baseline.json` | **Produced.** Per-process-name goodware/malware counts + signer set + install-dir set. |
| `docs/` | 40+ curated threat briefs (firmware, ICS controllers, Purdue Model layers). |
| `tools/` | Firmware extractors (Eaton, APC), NSRL migrator, VT proxy tester, OS catalog builder. |

<!-- Review-note: reviewers flagged an 18/19/20-dim disagreement across sister repos. On-disk truth is 18; the elasticPotato README will be brought inline separately. The Test-FidelityIndexCalibration doc-comment still says "20-file schema" for historical reasons — the runtime check enumerates the 18 actual dims. -->

---

## Menu at a glance

The interactive entry point is `statisticalDifferentialPotato_Main.ps1`. It imports 16 modules from `baseline/`, `agentic/`, `purpleTeaming/`, and `reports/` at load time, sanity-pings 8.8.8.8, then prompts.

### 1. Build process baseline

| Opt | Action | Function |
| --- | --- | --- |
| **1a** | Baseline procs with VT — submenu splits into three code paths | see below |
| **1a → per-OS continue / local / malicious bucket** | Bulk VT metadata + behaviors sweep | `Get-VTBaseline` |
| **1a → APT (all actors)** | Fan-out over every actor's `Master_Intel.csv` | `Get-AptMasterIntelVTAll` |
| **1a → APT (specific actor)** | Prompt for actor, pull just that CSV | `Get-AptMasterIntelVTByActor` |
| **1b** | Harvest IOCs per actor/family (VT Intel + ThreatFox + MalwareBazaar + URLhaus + OTX + Cybersixgill) | `Get-ThreatActorIOCs` |
| **1d** | Build fidelity index (manifest + 18 dim files + compat shim + `process-baseline.json`) | `Build-VTFidelityIndex` |
| **1e** | Pull VT YARA + Sigma detections for a hash list | `Get-VTDetectionsFromList` |
| **1f** | Organize + dedup local baselines under `output-baseline/` | `Move-OrganizeBaselines` |
| **1g** | Normalize MD5/SHA1 → SHA256 via VT | `Get-DedupHashesToSha256` |
| **1h** | Remove MalwareBazaar hashes from IOC list | `Get-RemoveMalwareBazaarEntries` |
| **1i** | Build behavioral fingerprint tables (known-good reference) | `Build-BehavioralFingerprintTable` |

<!-- Review-note: option `1c` is intentionally absent — kept as a reserved slot in the menu numbering. -->

### 2. Statistical differential analysis

| Opt | Action | Function |
| --- | --- | --- |
| **2a** | Bulk APT sweep — malicious API/DLL differential across every actor | `Get-MaliciousDifferentialAnalysis` |
| **2b** | Targeted single-CSV drilldown (13 dimensions) | `Get-TargetedMalwareAnalysis` |

### 3. Reports

| Opt | Action | Function |
| --- | --- | --- |
| **3a** | Iterate APT analyses → API matrix dashboard | `New-ApiMatrixDashboard` |

### 4. OT firmware extraction + NSRL catalog

Auto-discovers ZIPs / firmware blobs under `..\firmware-staging\<Vendor>\**\raw\*`. Runs `tools\Expand-EatonFirmware.ps1` then `tools\Build-OsCatalog.ps1`. Per-vendor variants `4a` (Eaton), `4b` (APC), `4c` (Vertiv), `4d` (SEL), `4e-4h` (Honeywell / Schneider / Rockwell / Siemens via consolidated `vendorMap`).

### 5. OT baselining + VT submission

| Opt | Action | Function |
| --- | --- | --- |
| **5a** | Pull VT metadata for firmware hashes in each `catalog.csv` | `Get-OtBaseline` |
| **5b** | Opt-in submit 404'd firmware files to VT | `Submit-OtFilesNotInVT` |
| **5z** | Poll pending VT submissions until analysis completes | `Sync-VTPendingSubmissions` |

---

## Building the fidelity index

The fidelity index is the corpus-normalized differential prior that elasticPotato consumes. Every indicator (mutex, YARA rule, MITRE technique, cert publisher, ...) gets a Bayesian rarity score derived from how often it appears in malicious VT samples vs. goodware.

### Command

```powershell
Import-Module .\agentic\Build-VTFidelityIndex.psm1

Build-VTFidelityIndex `
    -BaselineRoot   'output-baseline' `   # relative paths resolve against agentic\..
    -AptRoot        'apt\APTs' `          # pass '' to skip Phase 2
    -MaxLegitNames  5 `                   # legit product names retained per indicator (display-only, l_weight=0)
    [-SkipPhase2]                         # unit-test convenience
```

### First build — expect `Gtotal=0` until goodware is populated

**Critical.** The Phase 1 scanner reads `<BaselineRoot>\VirusTotal-behaviors\{malicious, SignedVerified, unsignedWin, unsignedLinux, unverified, drivers}\*.json`. Fresh checkouts ship the five goodware buckets **empty** — behavioral goodware currently lives under `NSRL/`, `localBaseline/`, `apt-master-intel/` which the current builder does **not** scan. Consequence: shipped `fidelity-manifest.json` has `Mtotal=19629, Gtotal=0`. Every entry gets `G=0`, `G_eff=0`, PMI collapses toward -1 (mutex example: PMI=-0.999). The scoring interpretation "positive PMI = enriched in malicious" only holds once `Gtotal > 0`.

To get valid v2 scores you must either populate `VirusTotal-behaviors/{SignedVerified,unsignedWin,unsignedLinux,unverified,drivers}/` manually (menu `1a` per-OS continue, or manual drops of `<hash>.json`) or move NSRL/localBaseline behaviors into those buckets before `1d`. The RiskScore is well-defined at `Gtotal=0` (falls back to `G_eff = G`) but PMI is not.

### Inputs (READ-ONLY)

- `<BaselineRoot>\VirusTotal-behaviors\{malicious,SignedVerified,unsignedWin,unsignedLinux,unverified,drivers}\*.json`
- `<BaselineRoot>\VirusTotal-main\<cat>\*.json` (optional; supplies cert + tag fields)
- `<AptRoot>\**\Targeted*DifferentialAnalysis.json` (Phase 2)

The VT corpus is never mutated.

### Outputs (all under `<BaselineRoot>`)

- `fidelity-manifest.json` — corpus totals, dim metadata, scoring params, calibration state, `build_signature` (SHA-256 over Mtotal/Gtotal/entry counts).
- `fidelity-<dim>.json` (x18) — each dim is a hashtable keyed by canonical value; every entry has `M, G, S, U, R, L, RiskScore, Confidence, PMI, Score100, Dimension, VerdictPoints`.
- `fidelity-index.json` — legacy flat compat shim, cross-dim keyed by bare value.
- `process-baseline.json` — process-name → `{G, M, S:[signers], D:[dirs]}`.

### Two-phase pipeline

**Phase 1 — VT behavior baseline pass.** Streams every VT behavior JSON under the scanned buckets, canonicalizes each indicator (lowercase paths, strip user-profile suffix, normalize cert publisher, MITRE T-codes to root), and accumulates `M` (malicious count) or `G` (goodware count) per `(dimension, value)` key. Emits a progress line every 1,000 files.

**Phase 2 — APT differential merge.** Recursively globs `Targeted*DifferentialAnalysis.json` under `<AptRoot>`, infers the dimension from the filename (`*Mutex*` → `mutex`, `*Sigma*` → `sigma-rule`, `*Mitre*` → `mitre-technique`, ...) with row-level `Item_Type` override, then merges into Phase 1 counts. Merge rule:

- **`M`** — highest-M wins unconditionally; a Phase-2 `M=0` never overwrites a Phase-1 `M>0`.
- **`G`** — lowest-G wins with safeguard: an incoming `G > 0` only overwrites an existing `G` if it is *less than half* of the existing value, preventing Phase-2 G=0 rows from clobbering legitimate Phase-1 counts (e.g. `chrome.exe G=500`).

### Runtime characteristics

- **Full pass, no resume.** No checkpoint file. Prior `fidelity-manifest.json` is read only to preserve `calibration_passed` when `build_signature` is unchanged; on any drift the flag is cleared to `null`.
- **Memory.** Peak scales with unique `(dim,value)` key count — typically hundreds of MB on the full VT corpus.
- **Disk.** ~20 JSON files under `<BaselineRoot>`. Manifest sub-MB, flat compat shim grows linearly with unique key count, `process-baseline.json` MB-scale.
- **Wall time.** Full pass scans the `malCats + goodCats` buckets (~40k VT files in a fully populated tree, ~19k in the reference checkout); wall time 10-30 min. Note the reference checkout ships ~150k additional behavior JSONs under `NSRL/OT/apt-master-intel/localBaseline/` that the current builder does **not** scan.
- **Return value.** `PSCustomObject` with `SchemaVersion=2, ManifestPath, FlatIndexPath, Entries, Dimensions, UniqueCount, RareCount, FilesScanned, Mtotal, Gtotal, BuildSeconds, BlockingZeroDims`.

---

## Calibration gate

Nothing consumes v2 scoring until the manifest carries `calibration_passed=true`.

**First run — expect `calibration_passed=null`.** Every fresh build writes `null`. The elasticPotato consumer falls back to the legacy flat compat shim until you run `Test-FidelityIndexCalibration` and Phase 4 records `PASSED`. Phase 4 requires >=`MinCorpora` labeled NDJSON corpora; default is 20. If you don't have 20 yet, use pilot mode (`-MinCorpora 3`) — Phase 4 still runs, still writes `calibration_passed=true`, but with a weakened / reduced-confidence bar and a `PILOT MODE` banner recorded in `calibration_min_corpora`.

```powershell
Import-Module .\agentic\Test-FidelityIndexCalibration.psm1

# Autodetect: BaselineRoot -> ..\output-baseline; LabeledCorpusRoot -> ..\elasticPotato\purpleTeaming
Test-FidelityIndexCalibration -Verbose

# Explicit:
Test-FidelityIndexCalibration `
    -BaselineRoot      'C:\...\output-baseline' `
    -LabeledCorpusRoot 'C:\...\purpleTeaming' `
    -MinCorpora        20 `
    -Verbose
```

### Five phases

| Phase | Name | What it checks |
| --- | --- | --- |
| 1 | Schema Sanity | Manifest is `v2`, 18 dim files present, entry counts match, dimension gates coherent. |
| 2 | Normalization | Canonical form of cert publishers, MITRE T-codes, IPs, DNS names, file paths is stable and idempotent. |
| 3 | Performance | Eager manifest load <10 MB, all 18 dim files simultaneously warm-loaded <200 MB. Warm objects released before Phase 4. |
| 4 | Verdict Regression | Runs `Invoke-ElasticAlertAgentAnalysis -UseLegacyFidelity` vs. `-ForceLegacyScoring` across labeled NDJSON corpora under `-LabeledCorpusRoot`. Requires >= `MinCorpora` labeled runs. Measures agreement %; SKIPS if too few corpora or the elasticPotato consumer surface is missing. |
| 5 | Persistence | Round-trip rewrite of `fidelity-manifest.json` with new `scoring.calibration_*` fields; guarded by equivalence check so no top-level field is silently dropped. |

### What passes unlocks

On PASS, `manifest.scoring.calibration_passed = true` and `calibration_phase4_status = 'PASSED'`. Enforced in code (not by convention): elasticPotato's `Invoke-ElasticAlertAgentAnalysis` reads `manifest.scoring.calibration_passed` and refuses the v2 code path unless it is `true`.

Returned `PSCustomObject.Passed` is the source of truth for CI — trust that over `$LASTEXITCODE`.

---

## Differential analysis modules

Two writers produce every `Targeted*DifferentialAnalysis.json` file that Phase 2 ingests. Two older API-only modules exist as historical precursors but write to `.\baseline\` (not `apt\`) and are **not** consumed by `Build-VTFidelityIndex`.

| Module | Scope | Outputs (per actor/family folder) |
| --- | --- | --- |
| `baseline\maliciousDifferential.psm1` (`Get-MaliciousDifferentialAnalysis`) | Bulk parallel sweep — every `apt\**\*_Master_Intel.csv` | Up to 13 `Targeted*DifferentialAnalysis.json` (typically 9 — IDS/Memory/ELF empty on non-Linux corpora) + `Targeted_Analysis_Map.csv` |
| `baseline\targetedMalwareDifferentialAnalysis.psm1` (`Get-TargetedMalwareAnalysis`) | Single-CSV drilldown (prompted path) | Same set; rows carry `Baseline_Count` (Phase 2 recognizes this shape) |
| `baseline\maliciousApiDllDifferential.psm1` | **Legacy, not consumed.** Ranks malicious APIs by baseline rarity | `.\baseline\APIDifferentialAnalysis.json` |
| `baseline\specifiedMaliciousApiDllDifferential.psm1` | **Legacy, not consumed.** Same, scoped to a hash-list TXT | `.\baseline\TargetedAPIDifferentialAnalysis.json` |

The 13 dimensions live in the shared CatMap inside `maliciousDifferential.psm1` — filename ↔ fidelity dim mapping is enumerated there; each record has `Item_Name, Type, Baseline_Rarity_Score (0-100), Malicious_Count, Last_Seen`; `targetedMalwareDifferentialAnalysis` additionally emits `Baseline_Count`.

---

## The scoring model

Every fidelity-index entry gets four scalar scores derived from `M` (malicious count) and `G` (goodware count) plus corpus totals `Mtotal, Gtotal`.

### Formulas

**Corpus normalization.** Goodware counts are scaled to the malicious corpus size:

```
G_eff = G · (Mtotal / Gtotal)     if Gtotal > 0
G_eff = G                          if Gtotal = 0   (RiskScore stays well-defined; PMI does not)
```

**RiskScore** ∈ `[0, 1]` — regularized incomplete beta, Beta-Binomial posterior (prior = Beta(1,1)):

```
RiskScore = 1 − I_{0.5}(M + 1, G_eff + 1)
```

Interpretation: probability that the malicious-conditional rate exceeds the goodware-conditional rate.

**PMI** ∈ `[−1, +1]` — bounded pointwise mutual information (Jeffreys smoothing +0.5/+1, log2, dampened by tanh):

```
mal_rate  = (M + 0.5) / (Mtotal + 1)
good_rate = (G + 0.5) / (Gtotal + 1)
PMI = tanh( (log2(mal_rate) − log2(good_rate)) / 3 )
```

Positive = enriched in malicious; negative = enriched in goodware. *Only meaningful when `Gtotal > 0`.*

**Confidence** ∈ `[0, 1]` — log-scaled evidence count, normalized to the dimension's p95:

```
Confidence = min(1, log10(M + G + 1) / log10(p95_total[dim] + 1))
```

Prevents a single-hit indicator from claiming the same certainty as one seen 10,000 times.

**Score100** is `RiskScore` rescaled to `[0, 100]` for UI/dashboard consumption. **VerdictPoints** is dimension-gated per `dimension_gates` in the manifest.

### Field semantics + gates

- **`M`, `G`** — malicious / goodware occurrence counts (Phase 1 + Phase 2 merged). **`S`** — legacy severity 0-100 for pre-v2 consumers. **`U`, `R`** — `U` set when `Score100 >= 95 AND Confidence >= 0.4`; `R` when `85 <= Score100 < 95 AND Confidence >= 0.4`. **`L`** — up to `MaxLegitNames` product names, **display-only** (`manifest.scoring.l_weight = 0.0`; posterior does not consume it).
- Four dims are tagged `usage: enrichment` in the manifest: `mutex`, `pipe`, `win-api`, `vt-tag`. Only `win-api` is enforced non-verdict-contributing (via `dimension_gates.behavior.win_api_call.verdict_points_enabled=false`, consumed by elasticPotato). `mutex/pipe/vt-tag` are advisory tags but their VerdictPoints still flow through today.

### Worked examples

Hypothetical, assuming a fully populated goodware corpus (~3.8:1 goodware:malicious):

| M | G | RiskScore | Interpretation |
| --- | --- | --- | --- |
| 47 | 1 | ~0.9999 | 47x malicious, once goodware → near-certain malicious |
| 0 | 500 | ~0.002 | Chrome-typical process — treated as benign |

---

## APT intel

`apt/` is a curated, per-actor and per-family intel corpus. There is **no** master `index.json` or `APTs.md` at `apt/` root — the directory structure is the index.

### Layout

```
apt/
  APTs/
    Belarus/  China/  Iran/  NorthKorea/  Pakistan/
    Picus/    Russia/ SouthAmerica/  Vietnam/  eCrime/
      <ActorName>/
        <Actor>_Master_Intel.csv          # aggregated IOC feed
        Detailed_Report.html              # interactive report
        report_data.js
        <actor>_YYYY-MM-DD.csv            # optional dated snapshot
        UNC-OVERLAP.md                    # optional overlap notes
        Targeted{API,Certificate,Mitre,Mutex,Process,Registry,Sigma,Tags,Yara}DifferentialAnalysis.json
        # + IDS/MemoryPattern/MemoryDomain/Elf variants when the corpus supports them
  Malware Families/
    <FamilyName>/     # ~265 folders, identical template
```

Coverage spans Russia (apt28/29, Sandworm, Turla), China (APT1/10/27/30/31/40/41, Volt/Salt/Flax Typhoon, Mustang Panda), NorthKorea (lazarus, kimsuky, APT37/38), Iran (APT33/34/35/39, MuddyWater), and eCrime (Scattered Spider, LAPSUS$, Akira, LockBit, Wizard Spider).

### `<Actor>_Master_Intel.csv` schema

`Date, Source (ThreatFox|MalwareBazaar|URLhaus|OTX|Cybersixgill|VT Intel), Actor, IOCType (SHA256|MD5|IP|URL|Domain), IOCValue, Context, Link`

### `Targeted*DifferentialAnalysis.json` record

```json
{
  "Item_Name": "C:\\windows\\system32\\rundll32.exe",
  "Type": "Process",
  "Baseline_Rarity_Score": 100,
  "Malicious_Count": 12,
  "Last_Seen": "2025-09-27"
}
```

### Consumption by elasticPotato

- `Build-VTFidelityIndex` Phase 2 recursively globs these JSONs and merges them into the corpus.
- elasticPotato's `Invoke-UACTriage` reads `apt/` at attribution time to map observed IOC clusters back to actor / family folders and surfaces the matching `Detailed_Report.html`.

---

## Requirements

- **PowerShell 7+** (`ForEach-Object -Parallel`, `[CmdletBinding()]` niceties, PS7 JSON perf).
- **Microsoft.PowerShell.SecretManagement + SecretStore** with vault named `LocalSecrets`:
  - `VT_API_Key_1` — VirusTotal Premium API key (required)
  - `VT_API_Key_2` — additional key to spread rate limits (recommended)
  - `Intezer_API_Key` — optional, for string enrichment
- **Disk footprint.** ~40-60 GB at full corpus (see banner at top).
- **NSRL.** `NSRL/nsrl_reduced.csv` at repo root, plus per-OS behavioral fingerprints under `output-baseline/behavioral-fingerprints/NSRL/<OS>/`.
- **Firmware staging (optional).** For menu 4a-4h and 5a/5b, expects `..\firmware-staging\<Vendor>\<Product>\raw\*` as a **sibling** of the repo.

### Install helpers

```powershell
# One-time vault setup
Install-Module Microsoft.PowerShell.SecretManagement, Microsoft.PowerShell.SecretStore -Scope CurrentUser -Force
Register-SecretVault -Name LocalSecrets -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
Set-Secret -Name VT_API_Key_1 -Secret '<your-vt-key>'

# Kick off
pwsh -File .\statisticalDifferentialPotato_Main.ps1
```

Manual corpus drops are supported — drop VT v3 file JSONs into `output-baseline/VirusTotal-main/<bucket>/<hash>.json` and behavior JSONs into `output-baseline/VirusTotal-behaviors/<bucket>/<hash>.json` if you cannot / do not want to hit the VT API from this host. Menu `1g` normalises legacy MD5/SHA1-named files to SHA256.

---

## Contributing

### Add a new APT actor

1. Create `apt/APTs/<Country>/<Actor>/` (or `apt/Malware Families/<Family>/`).
2. Add an entry to the MasterConfig used by `Get-ThreatActorIOCs` (`purpleTeaming\aptIocs.psm1`) — actor → alias / tool table that drives the harvester.
3. Menu `1b` (specific actor) → populate `<Actor>_Master_Intel.csv` from ThreatFox + MalwareBazaar + URLhaus + OTX + Cybersixgill + VT Intel.
4. Menu `1a` → "Pull VT Metadata for Specific APT / Malware Family" to fetch VT main + behavior JSONs per hash IOC.
5. Menu `2a` (or `2b` scoped to that actor's CSV) → generate the `Targeted*DifferentialAnalysis.json` files.
6. Menu `1d` (`Build-VTFidelityIndex`) — Phase 2 will pick the new files up automatically via the recursive glob.
7. Run `Test-FidelityIndexCalibration` — confirm `calibration_passed=true`.

### Add a new differential module

Emit `Targeted*DifferentialAnalysis.json` into `apt/APTs/<Country>/<Actor>/` (not `.\baseline\` — Phase 2's glob is rooted at `$AptRoot`). Filename must encode the dimension; Phase 2 inference in `Build-VTFidelityIndex.psm1` matches: `ip, dns|domain|host, mutex, sigma, yara, mitre|ttp|technique, registry, service, task|schedule, cmd|command, module|dll, pipe, cert, tag, files|written|writes|dropped` — anything else falls through to `process`. Per-row `Item_Type` overrides the filename inference. Record shape: `{ Item_Name, Type, Baseline_Rarity_Score, Malicious_Count, Last_Seen }`; optional `Baseline_Count` is trusted over score inversion. Rebuild + recalibrate.

---

## License

TBD — see repository root for `LICENSE` file if present; otherwise treat as "all rights reserved, ask before redistribution" until an OSS license is committed.

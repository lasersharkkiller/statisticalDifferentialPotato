# KAMACITE

**Status:** **112 IOCs, hand-seeded from published reporting.** See
[KAMACITE_Master_Intel.csv](KAMACITE_Master_Intel.csv).

## Why this was seeded by hand, not harvested

The `Get-ThreatActorIOCs` run returned **zero** rows for KAMACITE, and that is
a structural limit rather than a config error. Both of its LinkedTools are
pre-2020 malware, and the community feeds do not reach back that far —
MalwareBazaar only began operating in 2020:

| LinkedTool | Feed rows |
|---|---|
| BlackEnergy | 1 |
| GreyEnergy | 0 |

The Dragos activity-group name itself has no feed footprint either, and VT's
`threat_actor:` taxonomy does not use Dragos names. So the IOCs had to come
from the original vendor reporting:

- **28 hashes — 2015 Ukraine grid intrusion** (ESET, Jan 2016): the malicious
  XLS macro, BlackEnergy Lite and Big droppers, 23 BlackEnergy drivers, the
  VBS/Agent.AD trojan, and Win32/SSHBearDoor.A.
- **84 hashes — GreyEnergy** (ESET whitepaper, Oct 2018): mini, droppers,
  dropped and in-memory-only DLLs, Moonraker Petya, PHP/ASP scripts, a custom
  port scanner, Mimikatz builds, and WinExe.

All hashes are **SHA-1**, parsed programmatically from the source documents
rather than transcribed, and each row carries its source URL.

## KillDisk went to ELECTRUM, not here

The 2015 campaign's four **KillDisk** hashes are recorded under
[ELECTRUM](../ELECTRUM/NOTES.md) instead. KAMACITE is the access half of the
pair and KillDisk is the destructive payload — the effects half. Splitting
them is the entire reason these two are tracked as separate folders, so the
seed data follows that split.

## Role

Dragos assesses KAMACITE as the **initial-access provider for
[ELECTRUM](../ELECTRUM/NOTES.md)**. It is the access half of the pair;
ELECTRUM is the effects half. Both overlap the Sandworm cluster, and both
are tracked here as separate folders for the same reason given in the
ELECTRUM notes — the technique sets are genuinely different.

Dragos summary: *"Spearphishing, exploiting SOHO routers, and leveraging
custom capabilities to enable ELECTRUM operations."*

## Tradecraft

- **Spearphishing** into IT networks adjacent to ICS.
- **SOHO router exploitation** for access and relay infrastructure.
- **BlackEnergy3** — the access tooling behind the 2015 Ukraine power
  outage.
- **GreyEnergy** — the successor framework.

Because KAMACITE's job is access rather than ICS manipulation, its
behavioral profile should look far more like commodity phishing +
edge-device exploitation than like ELECTRUM's protocol-level tooling.
That contrast is the point of tracking it separately.

## Coverage in this repo

| Capability | Tracked as |
|---|---|
| BlackEnergy / BlackEnergy2 / BlackEnergy3 | [BlackEnergy](../../../Malware%20Families/BlackEnergy/) |
| GreyEnergy | new MasterConfig entry, no folder yet |

## Sources

- [Dragos — ICS/OT threat groups](https://www.dragos.com/threat-groups)
- [Dragos — 2025 OT Cybersecurity Report (Year in Review)](https://hub.dragos.com/hubfs/312-Year-in-Review/2025/Dragos-2025-OT-Cybersecurity-Report-A-Year-in-Review.pdf)

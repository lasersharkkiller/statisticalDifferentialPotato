# ELECTRUM

**Status:** **12 IOCs** — 8 harvested (Industroyer 3, CaddyWiper 5, AcidPour 2)
plus 4 **KillDisk** hashes seeded from ESET's Jan 2016 report on the 2015
Ukraine grid intrusion. See [ELECTRUM_Master_Intel.csv](ELECTRUM_Master_Intel.csv).

KillDisk sits here rather than with [KAMACITE](../KAMACITE/NOTES.md) because it
is the **destructive payload** of that campaign — the effects stage. KAMACITE
supplied the access (BlackEnergy3, SSHBearDoor); ELECTRUM did the damage.

## Why this is its own folder and not a Sandworm alias

The two vendors disagree, and we follow Dragos here:

- **MITRE ATT&CK G0034** folds ELECTRUM in as a plain *alias* of Sandworm
  Team, alongside Telebots, IRON VIKING, Voodoo Bear, Seashell Blizzard
  and APT44.
- **Dragos** holds that ELECTRUM, *although it overlaps with Sandworm
  (APT44), is a distinct activity cluster* — specifically the ICS-effects
  arm, fed by [KAMACITE](../KAMACITE/NOTES.md) on the access side.

For this pipeline the Dragos split is the useful one. We are extracting
**behaviors and MITRE techniques**, not matching hashes — and ELECTRUM's
profile (custom ICS protocol malware, electric-grid manipulation) is
behaviorally separate from the broad IT-side tradecraft that dominates
the [Sandworm](../Sandworm/Sandworm_Master_Intel.csv) corpus. Collapsing
them would smear two distinct technique sets into one differential.

`APT44` is already carried as an alias on the Sandworm entry, so the
Sandworm corpus keeps its GRU-74455 breadth regardless.

## Tradecraft

Dragos summary: *"Electric grid disruption and long-term persistence
using LOTL tactics and custom ICS Malware."*

- **2016 — Kyiv / Ukrenergo.** CRASHOVERRIDE (Industroyer), the first
  malware framework purpose-built to manipulate electric grid protocols.
- **2022 — Ukrainian electric utility.** Industroyer2 (a scaled-back
  CRASHOVERRIDE) paired with a new **CaddyWiper** version plus other
  custom wipers.
- **2024 — AcidPour.** Linux-compiled wiper, an **AcidRain** variant
  extended to search and wipe **UBI** directories and **Memory Technology
  Devices (MTDs)** — i.e. the embedded flash found in OT field devices,
  not just servers.
- Uses **hacktivist personas** as cover for other operations.

## Coverage in this repo

| Capability | Tracked as |
|---|---|
| Industroyer / Industroyer2 / CRASHOVERRIDE | [Industroyer](../../../Malware%20Families/Industroyer/) |
| CaddyWiper | new MasterConfig entry, no folder yet |
| AcidPour / AcidRain | new MasterConfig entry, no folder yet |

## Sources

- [Dragos — ICS/OT threat groups](https://www.dragos.com/threat-groups)
- [Dragos — ELECTRUM targeted Ukrainian electric entity using custom tools and CaddyWiper, Oct 2022](https://www.dragos.com/blog/new-details-electrum-ukraine-electric-sector-compromise-2022)
- [MITRE ATT&CK G0034 — Sandworm Team (lists ELECTRUM as an alias)](https://attack.mitre.org/groups/G0034/)

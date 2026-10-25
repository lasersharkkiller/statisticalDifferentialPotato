# CyberAv3ngers — alias coverage

**Shahid Kaveh / Shahid Kaveh Group is tracked HERE.** It is not a
separate actor and does not get its own folder. Likewise **BAUXITE**,
the Dragos activity-group name for this cluster.

| Alias | Origin |
|---|---|
| CyberAv3ngers | self-assigned persona |
| **Shahid Kaveh Group** | IRGC-CEC subordinate unit name |
| **BAUXITE** | Dragos activity group |
| Hydro Kitten | vendor |
| Storm-0784 | Microsoft |
| UNC5691 | Mandiant / Google TIG |

## Attribution

Iran, **IRGC-CEC** (Islamic Revolutionary Guard Corps Cyber-Electronic
Command). CISA and the FBI have both attributed CyberAv3ngers to the
IRGC-CEC. The group presents itself publicly as a decentralized
hacktivist collective; the available evidence indicates a centralized,
state-directed organization.

- **February 2024** — US Treasury sanctioned **six IRGC-CEC officials**
  over the CyberAv3ngers attacks on **Unitronics Vision-series PLCs** at
  US water utilities (November 2023).
- **State Department** has offered a **$10M reward** for information on
  the group's activity.
- **June 2025** — per Dragos, BAUXITE deployed **two custom wiper
  variants** against Israeli targets during the Iran–Israel conflict,
  escalating from access-and-disruption to **destructive intent**.

## Why this matters for the harvest

This folder's `CyberAv3ngers_Master_Intel.csv` holds only **6 IOC rows**,
because the MasterConfig entry carried exactly one alias and the feeds
were only ever queried for the string `CyberAv3ngers`. The entry now
carries all six aliases plus `LinkedTools = @("IOCONTROL")`, so a re-run
should pull substantially more:

```powershell
Get-ThreatActorIOCs -SpecificActor "CyberAv3ngers"
```

## Coverage in this repo

| Capability | Tracked as |
|---|---|
| IOCONTROL / OrpaCrab | [IOCONTROL](../../../Malware%20Families/IOCONTROL/) |

## Sources

- [US Treasury — sanctions on actors responsible for malicious cyber activities on critical infrastructure](https://home.treasury.gov/news/press-releases/jy2072)
- [Tenable — CyberAv3ngers FAQ](https://www.tenable.com/blog/what-to-know-about-cyberav3ngers-the-irgc-linked-group-targeting-critical-infrastructure)
- [Dragos — ICS/OT threat groups](https://www.dragos.com/threat-groups)

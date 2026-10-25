# APT33 — alias coverage

**MAGNALLIUM is tracked HERE.** It is the Dragos activity-group name for
this cluster, not a separate actor.

| Alias | Origin |
|---|---|
| APT33 | Mandiant |
| **MAGNALLIUM** | Dragos activity group |
| Elfin | Symantec |
| Holmium | Microsoft (legacy) |
| Peach Sandstorm | Microsoft (current) |
| Refined Kitten | CrowdStrike |

Dragos summary for MAGNALLIUM: *"Relies on phishing campaigns, password
spraying, and malware delivery for reconnaissance."* Dragos publicly
tracks it as targeting **manufacturing**, in addition to the oil & gas /
aviation targeting in the APT33 reporting.

`Holmium` was already present but is Microsoft's retired name —
**Peach Sandstorm** is the current one and is what recent reporting uses,
so it matters more for feed hits. Re-run to pick up the new aliases:

```powershell
Get-ThreatActorIOCs -SpecificActor "APT33"
```

## Sources

- [Dragos — ICS/OT threat groups](https://www.dragos.com/threat-groups)
- [Dragos — ICS threat activity on the rise in manufacturing sector](https://www.dragos.com/blog/industry-news/manufacturing-sector-cyber-threats/)

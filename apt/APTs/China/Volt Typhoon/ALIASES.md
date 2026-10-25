# Volt Typhoon — alias coverage

**VOLTZITE is tracked HERE.** It is the Dragos activity-group name for
this cluster, not a separate actor, so it gets no separate folder — that
would duplicate the hash corpus and burn VT quota re-querying identical
samples.

| Alias | Origin |
|---|---|
| Volt Typhoon | Microsoft |
| **VOLTZITE** | Dragos activity group |
| Bronze Silhouette | Secureworks |
| Vanguard Panda | CrowdStrike |
| Insidious Taurus | Palo Alto Unit 42 |
| DEV-0391 | Microsoft (pre-naming) |
| UNC3236 | Mandiant / Google TIG |

Dragos summary for VOLTZITE: *"Uses LOTL techniques for reconnaissance,
enumeration, lateral movement, and long-term persistent access."* Dragos
has reported continued VOLTZITE evolution across the ICS Cyber Kill
Chain, with **increased focus on mapping control loops** — an OT-side
detail that the Microsoft-centric Volt Typhoon reporting does not
emphasize, and worth carrying into the technique extraction.

The added aliases widen both the VT `threat_actor:` queries and the
ThreatFox / MalwareBazaar / OTX tag queries. Re-run to pick them up:

```powershell
Get-ThreatActorIOCs -SpecificActor "Volt Typhoon"
```

## Sources

- [Dragos — ICS/OT threat groups](https://www.dragos.com/threat-groups)
- [Dragos — OT threat landscape 2026](https://www.dragos.com/blog/ot-threat-landscape-2026)

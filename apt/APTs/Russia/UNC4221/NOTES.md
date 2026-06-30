# UNC4221

**Status:** Tracking namespace scaffolded; **no IOCs published yet** (as of the
2026-06-29 State Department reward announcement). Master_Intel.csv is empty
pending CISA / Mandiant / NCSC technical advisory.

## Attribution

Russian **Border Guards + military intelligence**. Per the State Department
$10M reward announcement covered in The Record, June 2026.

The article phrasing is ambiguous: Border Guards historically sit under
the FSB (Border Service of the Russian Federation), while "military
intelligence" is GRU. UNC4221 may be either a Border-Service intel arm
or a joint Border-Service + GRU collaboration. Treat the GRU side as
primary for cluster-overlap reasoning until clarified.

## Targets

- Government officials
- Journalists
- Military personnel
- Politicians, activists
- Geographic focus: **Ukraine, Europe, United States**

## Tradecraft (article-disclosed; no hashes/IPs/domains)

- **Signal messenger account takeover** is the headline tactic
- Phishing for verification codes, account PINs, **backup recovery keys**
- SMS phishing impersonating Signal support
- Altered legitimate Signal group invitation pages redirecting to
  credential-harvesting infrastructure
- People-ops-heavy: credential phishing, not endpoint malware deployment

## Operational overlap with clusters we already track

UNC-numbered Mandiant clusters historically fold into existing groups
when attribution matures (UNC2452 → Cozy Bear, UNC1878 → FIN12, etc.).
The military-intelligence / GRU side of UNC4221 puts it in operational
proximity to:

- **[APT28](../apt28/)** — GRU 26165 (Fancy Bear). Closest match for
  the GRU-targeting-Ukrainian-government pattern.
- **[Sandworm](../Sandworm/)** — GRU 74455 (Voodoo Bear). Different
  destructive-attack focus but same parent organization.

If the Border-Guards / FSB-Border-Service framing is the primary one,
cluster proximity may shift toward Gamaredon / Star Blizzard (see
[../UNC5792/NOTES.md](../UNC5792/NOTES.md)).

Ingest IOCs into Master_Intel.csv here once CISA / NCSC publishes the
post-reward technical advisory and re-run
`baseline\targetedMalwareDifferentialAnalysis.psm1`.

## Sources

- [The Record — $10M reward on Russian hackers UNC4221 + UNC5792](https://therecord.media/10million-reward-us-russian-hackers-unc4221-unc5792)
- [US Department of State Rewards for Justice (RFJ)](https://rewardsforjustice.net/) — search for the specific reward listing once indexed

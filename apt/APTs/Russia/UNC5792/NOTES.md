# UNC5792

**Status:** Tracking namespace scaffolded; **no IOCs published yet** (as of the
2026-06-29 State Department reward announcement). Master_Intel.csv is empty
pending CISA / Mandiant / NCSC technical advisory.

## Attribution

Russian **FSB** (Federal Security Service). Per the State Department
$10M reward announcement covered in The Record, June 2026.

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
- People-ops-heavy: this is credential phishing, **not endpoint malware
  deployment** — our hash-baseline + MITRE differential pipeline has
  limited direct leverage on this cluster

## Operational overlap with clusters we already track

UNC-numbered Mandiant clusters historically fold into existing groups
when attribution matures (UNC2452 → Cozy Bear, UNC1878 → FIN12, etc.).
FSB attribution puts UNC5792 in operational proximity to:

- **[Star Blizzard](../Star%20Blizzard/)** — FSB Center 18 (publicly
  attributed by Microsoft / CISA / NCSC). Similar credential-phishing
  tradecraft pattern.
- **[Gamaredon](../Gamaredon/)** — FSB, Crimea-based. Different target
  set (Ukrainian government) but same parent service.
- **[Turla](../Turla/)** — FSB Center 16.

If/when CISA publishes the post-reward technical advisory with hashes
or domains, ingest the IOCs into Master_Intel.csv here and re-run
`baseline\targetedMalwareDifferentialAnalysis.psm1`. The OT Capability
Matrix + Global Threat Dashboard will automatically pick up the new
cluster.

## Sources

- [The Record — $10M reward on Russian hackers UNC4221 + UNC5792](https://therecord.media/10million-reward-us-russian-hackers-unc4221-unc5792)
- [US Department of State Rewards for Justice (RFJ)](https://rewardsforjustice.net/) — search for the specific reward listing once indexed

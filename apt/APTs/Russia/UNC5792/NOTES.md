# UNC5792

**Status:** Seeded with **17 GTIG-direct IOCs** (15 domains + 1 MD5 + 1
sgnl:// URI template) and **2 single-source-confirmed Eventus domains**.
See [UNC5792_Master_Intel.csv](UNC5792_Master_Intel.csv).

## Attribution

- **Mandiant / Google TIG:** UNC5792, Russian **FSB**. Per the State
  Department $10M reward announcement covered in The Record, June 2026,
  specifically attributed to FSB Border Guards.
- **CERT-UA:** **UAC-0195** (Ukrainian designation, same cluster).
- GTIG explicitly distinguishes UNC5792 from APT44 (Sandworm), Turla
  (FSB Center 16), UNC1151 (Belarus), and COLDRIVER / Star Blizzard —
  the [UNC-OVERLAP.md](../Star%20Blizzard/UNC-OVERLAP.md) sidecars in
  adjacent folders capture only operational adjacency, not equivalence.

## Targets

- Government officials, journalists, military personnel, politicians,
  activists
- Geographic focus: **Ukraine, Europe, United States**

## Tradecraft (GTIG-disclosed, Feb 2025)

- **Signal messenger account takeover** is the headline tactic.
- **Altered Signal group-invite HTML pages** (MD5
  `e078778b62796bab2d7ab2b04d6b01bf`) redirect victim browsers to
  attacker-controlled phishing infrastructure instead of joining the
  intended group.
- **`sgnl://linkdevice?uuid=...&pub_key=...` URI payloads** sent to
  victims trick the Signal client into linking the attacker's device
  to the victim's account (canonical QR-code-replacement attack).
- Domain themes: `signal-group`, `signal-groups`, `signal-security`,
  `signal-device-off`, `groups-signal`, plus variants. Hunt by
  substring / cert-CN keyword rather than literal value.
- **No SHA256 published** for this cluster — only the MD5 of the
  altered HTML page. Pivoting on hashes alone is low-yield; pivot on
  the domain set + the sgnl:// URI shape instead.

## Operational overlap with clusters we already track

UNC-numbered Mandiant clusters historically fold into existing groups
when attribution matures (UNC2452 → Cozy Bear, UNC1878 → FIN12, etc.).
FSB attribution puts UNC5792 in operational proximity to:

- **[Star Blizzard](../Star%20Blizzard/)** — FSB Center 18 (publicly
  attributed by Microsoft / CISA / NCSC). Similar credential-phishing
  tradecraft pattern; Microsoft has separately documented Star Blizzard
  using WhatsApp linked-device abuse (not Signal), GTIG references this
  cross-platform overlap.
- **[Gamaredon](../Gamaredon/)** — FSB, Crimea-based. Different target
  set (Ukrainian government) but same parent service.
- **[Turla](../Turla/)** — FSB Center 16.

## Sources

- **[GTIG/Mandiant — "Signals of Trouble: Multiple Russia-Aligned Threat Actors Actively Targeting Signal Messenger" (2025-02-19)](https://cloud.google.com/blog/topics/threat-intelligence/russia-targeting-signal-messenger/)** — primary IOC source
- [Eventus Security — UNC5792 Deploys Signal-Based Phishing Tactics (2025-05)](https://advisory.eventussecurity.com/advisory/unc5792-deploys-signal-based-phishing-tactics/) — secondary, 3 domains (1 overlaps GTIG)
- [Threadlinqs TL-2026-0111 (2026-02-22)](https://threadlinqs.com/blog/TL-2026-0111-signal-hijacking-apt44/) — independent corroboration of `signal-groups.tech`
- [The Record — $10M reward on Russian hackers UNC4221 + UNC5792 (2026-06)](https://therecord.media/10million-reward-us-russian-hackers-unc4221-unc5792) — bounty announcement (no IOCs)
- [FBI/IC3 PSA260626 (2026-06-26)](https://www.ic3.gov/PSA/2026/PSA260626) — narrative only, no IOC appendix

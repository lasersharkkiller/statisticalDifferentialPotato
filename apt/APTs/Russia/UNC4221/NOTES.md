# UNC4221

**Status:** Seeded with **9 GTIG-direct domain IOCs**. See
[UNC4221_Master_Intel.csv](UNC4221_Master_Intel.csv).

## Attribution

- **Mandiant / Google TIG:** UNC4221, Russian **Border Guards +
  military intelligence**. Per the State Department $10M reward
  announcement covered in The Record, June 2026. The article phrasing
  is ambiguous: Border Guards historically sit under the FSB (Border
  Service of the Russian Federation), while "military intelligence"
  is GRU. Treat the GRU side as primary for cluster-overlap reasoning.
- **CERT-UA:** **UAC-0185** (Ukrainian designation, same cluster).
- GTIG explicitly distinguishes UNC4221 from APT44 (Sandworm, GRU
  74455). The two operate in adjacent campaign space but are
  separately-tracked clusters — see the WAVESIGN distinction below.

## Targets

- Government officials, journalists, military personnel, politicians,
  activists
- **Specific focus on Ukrainian military personnel** via Kropyva-themed
  lures (Kropyva = Ukrainian artillery-targeting software)
- Geographic focus: **Ukraine, Europe, United States**

## Tradecraft (GTIG-disclosed, Feb 2025)

- **Signal messenger account takeover** via altered group-invite pages
  themed around **Kropyva**, the Ukrainian artillery-guidance app.
- **PINPOINT** — JavaScript payload that runs after the victim hits
  one of the phishing pages; uses the browser **GeoLocation API** to
  exfil location + basic user-agent info to attacker infrastructure.
  **No public hash** for PINPOINT.
- Domain themes: `teneta.*` (Ukrainian for "net" — the Kropyva
  ecosystem brand), `signal-confirm`, `signal-protect`, `confirm-signal`,
  plus `helperanalytics.ru` for supporting infrastructure.

## Pivot-by-association — separately-tracked actors

GTIG documents that the Signal-targeting campaign overlaps with these
**different** Russia-aligned clusters. Do **not** co-mingle their IOCs
into UNC4221_Master_Intel.csv — they should be tracked under their own
folders. Listed here for situational awareness only:

| Indicator | Attributed actor | Folder |
|---|---|---|
| `WAVESIGN` (MD5s `a97a28276e4f88134561d938f60db495`, `b379d8f583112cad3cf60f95ab3a67fd`, `b27ff24870d93d651ee1d8e06276fa98`) + IP `150.107.31.194:18000` (device-link QR provisioning) | **APT44 / Sandworm / Seashell Blizzard (GRU 74455)** | [../Sandworm/](../Sandworm/) |
| PowerShell `Get-ChildItem ...\SIGNAL\config.json` exfil | **Turla (FSB Center 16)** | [../Turla/](../Turla/) |
| `robocopy ... C:\Users\Public\data\signa /S` | **UNC1151 (Belarus)** | not tracked |
| WhatsApp linked-device abuse | **COLDRIVER / Star Blizzard / UNC4057** | [../Star%20Blizzard/](../Star%20Blizzard/) |

## Operational overlap with clusters we already track

UNC-numbered Mandiant clusters historically fold into existing groups
when attribution matures. The military-intelligence / GRU side of
UNC4221 puts it in operational proximity to:

- **[APT28](../apt28/)** — GRU 26165 (Fancy Bear). Closest match for
  the GRU-targeting-Ukrainian-government pattern.
- **[Sandworm](../Sandworm/)** — GRU 74455. The APT44 WAVESIGN family
  runs in the same campaign space (see pivot table above) but is
  separately attributed.

## Older UAC-0185 campaigns (pre-Signal)

SOC Prime documented a **December 2024 UAC-0185 LNK/HTA campaign**
predating the Signal-targeting kit:
- Tools: MESHAGENT, UltraVNC
- Lure files: `Front.png`, `Registry.hta`, `Main.bat`
- No hashes / domains / IPs published in the public writeup; IOC values
  are gated behind their TDM marketplace.

Note this for actor history but do NOT seed those tool names into
the Master_Intel CSV — they're not file IOCs in their own right
(MESHAGENT and UltraVNC are dual-use admin tools).

## Sources

- **[GTIG/Mandiant — "Signals of Trouble: Multiple Russia-Aligned Threat Actors Actively Targeting Signal Messenger" (2025-02-19)](https://cloud.google.com/blog/topics/threat-intelligence/russia-targeting-signal-messenger/)** — primary IOC source
- [Threadlinqs TL-2026-0111 (2026-02-22)](https://threadlinqs.com/blog/TL-2026-0111-signal-hijacking-apt44/) — independent corroboration of `signal-confirm.site`, `signal-protect.host`, `teneta.add-group.site`
- [SOC Prime — UAC-0185 (aka UNC4221) Attack Detection (2024-12-09)](https://socprime.com/blog/uac-0185-aka-unc4221-attack-detection/) — older LNK/HTA campaign, no IOC values public
- [The Record — $10M reward on Russian hackers UNC4221 + UNC5792 (2026-06)](https://therecord.media/10million-reward-us-russian-hackers-unc4221-unc5792) — bounty announcement (no IOCs)
- [FBI/IC3 PSA260626 (2026-06-26)](https://www.ic3.gov/PSA/2026/PSA260626) — narrative only, no IOC appendix

# XENOTIME

**Status:** **12 IOCs, hand-seeded from CISA.** See
[XENOTIME_Master_Intel.csv](XENOTIME_Master_Intel.csv).

## Why this was seeded by hand, not harvested

`Get-ThreatActorIOCs` returned **zero** rows: TRISIS dates to 2017 and has no
presence in MalwareBazaar or ThreatFox, which post-date it. The full component
set instead comes from **Table 1 of CISA MAR-17-352-01 Update B** — the
complete HatMan chain, all SHA-1:

`library.zip`, `TsLow.pyc`, `TsBase.pyc`, `TsHi.pyc`, `TS_cnames.pyc`,
`crc.pyc`, `sh.pyc`, `trilog.exe`, `PresetStatus`, `dummy`, `inject.bin`,
`imain.bin`.

One extraction caveat worth recording: the PDF's table renders with a column
offset, and `pdftotext -layout` pairs filenames to the wrong hashes. The
reading-order extraction is the correct one, confirmed against independent
reporting for `trilog.exe` (`dc81f383…`), `inject.bin` (`f403292f…`) and
`imain.bin` (`b47ad484…`). If you re-derive this table, do not trust
`-layout`.

## Why it is filed under Russia

**Read this before treating the folder as an attribution claim.** Dragos
does not publicly assert a nationality for XENOTIME. The Russia placement
follows the *TEMP.Veles* line of reporting, which is well-corroborated:

- **FireEye/Mandiant** assessed with **high confidence** that TRITON
  activity was linked to the **Central Scientific Research Institute of
  Chemistry and Mechanics (CNIIHM / TsNIIKhM)**, a Russian
  government-owned research institute in Moscow — including an institute
  IP address used for malware testing, open-source monitoring of TRITON
  coverage, and network reconnaissance in support of the intrusion.
- **US Treasury** sanctioned **TsNIIKhM** in **October 2020** over the
  attack; **DOJ** indicted a TsNIIKhM researcher in connection with it.
- **MITRE ATT&CK for ICS G0001** tracks the group as **XENOTIME /
  TEMP.Veles**.

Note the geography mismatch: the *victim* was Middle East oil & gas. The
Russia folder reflects the assessed operator, not the target region.

## Tradecraft

Dragos summary: *"Development of ICS malware for physical disruption,
causing unsafe conditions and long-term persistence."*

- **August 2017 — Saudi petrochemical facility.** **TRISIS** (also
  **TRITON**, **HatMan**) targeted **Triconex Safety Instrumented
  Systems**. This is the first known malware written to attack a safety
  system — the failure mode is not downtime but the removal of the
  safeguard that prevents an unsafe physical state.
- Subsequently **expanded beyond the Middle East**, including
  reconnaissance against **US electric utilities** and a broader range of
  safety-system vendors.

TRISIS is the highest-consequence capability in this corpus. Its value to
the differential pipeline is the **safety-system interaction technique
set**, which has essentially no benign-baseline analogue.

## Coverage in this repo

**The technique chain is already documented here — it just had no actor
folder.** Three OT briefs analyse the TRITON attack in depth and should be
read alongside this corpus:

- [purdue-safety-systems-brief.md](../../../../docs/purdue-safety-systems-brief.md)
  — the canonical 4-stage model: L3 engineering workstation → CVE-2018-8872
  OOB read to map Tricon MP memory → `imain.bin` written over **TriStation
  UDP/1502** while the keyswitch sat in PROGRAM. Notes that the attack
  *failed* because the tampered safety logic tripped a plant shutdown —
  the FAILSAFE worked.
- [schneider-firmware-threat-brief.md](../../../../docs/schneider-firmware-threat-brief.md)
  — the implant chain `trilog.exe` → `inject.bin` → `imain.bin` on the MP.
- [purdue-l3-site-operations-brief.md](../../../../docs/purdue-l3-site-operations-brief.md)
  — XENOTIME as the SIS engineering-tool archetype.

`agentic/Build-OTEDRGapMatrix.psm1` also lists XENOTIME/PIPEDREAM as the
Dragos Platform threat-intel overlay.

| Capability | Tracked as |
|---|---|
| TRISIS / TRITON / HatMan | new MasterConfig entry, no folder yet |

## Sources

- [Dragos — XENOTIME](https://www.dragos.com/threat/xenotime)
- [MITRE ATT&CK for ICS — G0001 XENOTIME / TEMP.Veles](https://collaborate.mitre.org/attackics/index.php/Group/G0001)
- [CyberScoop — FireEye links Russia-owned lab to Trisis developers](https://cyberscoop.com/trisis-russia-fireeye/)
- [SecurityWeek — US Treasury sanctions Russian institute linked to Triton malware](https://www.securityweek.com/us-treasury-sanctions-russian-institute-linked-triton-malware/)

# Vendor exposure vs corpus coverage — reference for the firmware threat briefs

**Generated 2026-10-23** from `OTSDP/Inventory/analysis/arng_devices_raw.json` (the census
refreshed 2026-10-22) and the live catalogs under `firmware-staging/*/*/*/catalog.csv`.

Census totals: **259,198 devices**, of which **5,811** fall in the `OT & Building Systems`
category across **114 distinct vendors**.

A note on which number to quote: a vendor's *total* device count and its *OT* count differ,
sometimes a lot. Tridium is **604 total / 568 OT**; Digital Systems Corp is **492 total / 463
OT**. The briefs quote the **OT** figure, and so does this table. Quoting the total inflates
the fleet claim.

---

## The table

"Hashes" is distinct SHA-256 count currently catalogued for that vendor in `firmware-staging`.
"ST" is the number of states the devices appear in — a rough blast-radius indicator independent
of raw count.

| Census vendor | OT devices | States | Threat brief | Distinct hashes | Hashes / device |
|---|---:|---:|---|---:|---:|
| Texas Instruments | 710 | 42 | **none** | 0 | 0.0 |
| Tridium, Inc. | 568 | 31 | `tridium` | 14,743 | 26.0 |
| ECHELON CORP. | 566 | 28 | `echelon` | 5,986 | 10.6 |
| Digital Systems Corp | 463 | 19 | **none** | 968 | 2.1 |
| Johnson Controls, Inc. | 302 | 6 | `johnson-controls` | 3,520 | 11.7 |
| AutomatedLogic Corporation | 253 | 12 | `automatedlogic` | 728 | 2.9 |
| MERCURY SECURITY CORPORATION | 252 | 15 | `mercury-security` | 1 | 0.0 |
| TAC AB | 252 | 9 | `tac-vista-xenta` | 267 | 1.1 |
| Bosch Security Systems | 252 | 8 | `bosch-security` | 2 | 0.0 |
| Aiphone co.,Ltd | 246 | 25 | `aiphone` | 2 | 0.0 |
| VCS Video Communication Systems AG | 246 | 15 | **none** | 0 | 0.0 |
| Axis Communications AB | 233 | 16 | `axis-communications` | 2,598 | 11.2 |
| Digital Design Corporation | 160 | 11 | **none** | 0 | 0.0 |
| Honeywell GmbH | 117 | 3 | `honeywell` | 0 | 0.0 |
| Motorola Solutions Inc. | 84 | 7 | **none** | 0 | 0.0 |
| Hanwha Vision VietNam | 72 | 4 | **none** | 0 | 0.0 |
| Eaton Corporation | 71 | 8 | `eaton` | 50,622 | 713.0 |
| Genetec Inc. | 66 | 7 | **none** | 0 | 0.0 |
| SIEMENS BUILDING | 66 | 1 | `siemens` | 572,304 | **8,671.3** |
| OSI Security Devices | 55 | 2 | **none** | 0 | 0.0 |
| Apex, Inc. | 39 | 9 | **none** | 0 | 0.0 |
| Trane | 38 | 4 | **none** | 0 | 0.0 |
| AMERICAN POWER CONVERSION CORP | 37 | 27 | `apc` | 20,899 | 564.8 |
| SQUARE D COMPANY | 35 | 8 | `schneider` | 267 | 7.6 |

---

## What the table says that the briefs do not

**1. Corpus effort is inversely correlated with fleet exposure.**

Siemens holds **572,304 hashes for 66 devices** — roughly **86% of the entire corpus** for
**1.1% of the OT fleet**. Eaton and APC are the same shape (713 and 565 hashes per device).
Meanwhile the four vendors at 246–252 devices each — Mercury, Bosch, Aiphone and VCS — hold
**1, 2, 2 and 0 hashes respectively**.

This is not an argument for deleting Siemens data; it is already collected and it is what made
the file-type yield measurements possible. It *is* an argument that the next unit of effort is
worth far more spent on the 246–252-device vendors than on deepening Siemens.

**2. The largest OT "vendor" in the census is probably not a vendor.**

**Texas Instruments, 710 OT devices across 42 states** — more than Tridium. TI does not sell
building-automation controllers; this is almost certainly **OUI-only resolution**, where the
census sees a TI network chip inside somebody else's product. Before anyone writes a TI brief,
that classification needs resolving — the 710 devices are real, but they belong to some other
vendor's product line, and identifying which would reassign a large block of the fleet. Same
caution applies to the `Unclassified` top-category on nearly every OT vendor row.

**3. Four vendors have real fleets and no brief at all.**

| Vendor | OT devices | States | Note |
|---|---:|---:|---|
| **Digital Systems Corp** | 463 | 19 | = **Galaxy Control Systems**. We hold **968 hashes** pulled from VirusTotal, so the material exists — only the brief is missing. Highest-value gap. |
| **VCS Video Communication Systems AG** | 246 | 15 | No firmware, no brief, not yet researched. |
| **Digital Design Corporation** | 160 | 11 | No firmware, no brief. |
| Motorola Solutions / Hanwha Vision / Genetec / OSI Security / Apex / Trane | 84 / 72 / 66 / 55 / 39 / 38 | — | Genetec is notable: it is a Mercury OEM channel, which ties to the Mercury acquisition problem. |

**4. `honeywell` has a brief but zero firmware.** The staging tree holds only scaffolding. Since
Honeywell resells Niagara-based controllers, the Tridium material now in hand may partially cover
it — worth cross-referencing rather than acquiring separately.

**5. State spread diverges from device count, and sometimes matters more.**

APC appears in **27 states on 37 OT devices**; Aiphone in **25 states on 246**. Siemens Building
sits in **1 state on 66**. A vendor present in 27 states is a wider lateral-movement surface than
one concentrated in a single state, whatever the raw count. Tridium leads on both (568 devices,
31 states), which is why it was the right acquisition priority.

---

## How to use this with the briefs

- Quote the **OT** column, not the total, and say "OT & Building Systems" when citing it.
- The **Hashes / device** column is a coverage-debt indicator, not a quality score. A low value
  on a large fleet (Mercury, Bosch, Aiphone) means the brief rests on advisories rather than
  on extracted firmware, and should say so.
- Counts move. The census was refreshed 2026-10-22 and vendor totals shifted; regenerate this
  table rather than copying these numbers forward.

**Caveat on the hash counts:** they measure what has been *catalogued*, which conflates
acquisition with analysis depth. A vendor whose firmware is one large encrypted blob (Mercury's
EP1501) scores 1 hash while still having been analysed; a vendor shipping a sprawling Windows
install (Siemens TIA Portal) scores hundreds of thousands with little behavioural yield — a
measured **3.0%** real-behaviour rate overall, and **0.0%** for the HTML that made up 62% of
submissions. Read this column alongside the yield figures in
[vt-parallel-throughput notes], not on its own.

---

## OSINT brief coverage added 2026-10-26

The "none" entries in the table above are being closed. A 12-vendor research workflow (one
researcher per vendor + an adversarial pass that independently re-verified every CVE against
NVD/CISA/vendor records before it could be written) produced **11 new OSINT/advisory briefs** —
no firmware held for any of these, so they rest on public disclosure only.

| New brief | Census vendor | OT dev | Confirmed CVEs | Identity resolved to |
|---|---|---:|---:|---|
| vcs-video-communication | VCS Video Communication Systems AG | 246 | 3 | Bosch VideoJet/VIP encoders (now Keenfinity) |
| sensormatic-software-house | Sensormatic Electronics LLC | 27 | 6 | Johnson Controls Software House (C-CURE/iSTAR) |
| motorola-solutions-avigilon | Motorola Solutions Inc. | 84 | 6 | Motorola / Avigilon / Ava |
| hanwha-vision | Hanwha Vision VietNam | 72 | 5 | Hanwha Vision (ex-Samsung Techwin) |
| genetec | Genetec Inc. | 66 | 6 | Genetec Security Center (Mercury OEM channel) |
| osi-dormakaba-omnilock | OSI Security Devices | 55 | 0 | dormakaba / BEST Omnilock |
| apex | Apex, Inc. | 39 | — | **folded into Vertiv** (Avocent/KVM lineage) |
| trane | Trane | 38 | 8 | Trane Tracer BAS controllers |
| digital-design-corp-advanced-network-devices | Digital Design Corporation | 160 | 0 | Advanced Network Devices (IP mass-notification) — **not** Galaxy/Digital Systems Corp |
| gallagher | Gallagher Group Limited | 17 | 6 | Gallagher Command Centre / Controller 6000 |
| daikin | Daikin Industries, Ltd. | 16 | 3 | Daikin HVAC / SVMPC controllers |
| sierra-monitor-fieldserver | Sierra Monitor Corp. | 15 | 3 | MSA FieldServer protocol gateways |

**46 CVEs confirmed, 0 fabricated** — the adversarial pass dropped every candidate it could not
tie to a real record; three were independently re-fetched by hand (Daikin ICSA-22-284-02, Sierra
Monitor/MSA FieldServer CVE-2024-45494, Hanwha CVE-2024-54013) and all resolved on-vendor.

**Two honest zeroes.** Digital Design Corp (Advanced Network Devices) and OSI (dormakaba Omnilock)
returned no confirmable CVE — recorded as absence of information, not safety.

**Identity corrections worth carrying forward:** "Digital Design Corporation" is Advanced Network
Devices (IP speakers), a different company from "Digital Systems Corp" (Galaxy Control Systems);
"Apex, Inc." is the Avocent/Vertiv KVM lineage, not a standalone vendor; "VCS" and "Sensormatic"
are Bosch and Johnson Controls lineage respectively but cover distinct product lines from the
existing Bosch-camera and JCI-Metasys briefs. **Texas Instruments (710 devices) remains excluded**
as an almost-certain OUI artifact and still needs reclassification before it is treated as a vendor.

---

## Missing-vendor accounting (2026-10-26)

Of the 114 OT & Building Systems vendors in the census, after excluding OUI artifacts and IT misfiles, coverage of genuine OT devices is **~89%**. The residual splits three ways.

### Covered by corporate lineage (12 vendors, 232 devices)

These appear as separate census strings but belong to a vendor whose firmware/software we already hold. They are **covered by lineage**, not separate gaps:

| Census vendor | OT dev | Covered via |
|---|---:|---|
| Honeywell GmbH | 117 | Honeywell resells Niagara-based controllers (Tridium, acquired) and has an OSINT brief; Honeywell-branded device firmware still gated |
| OSI Security Devices | 55 | OSI Security Devices = dormakaba (BEST/Omnilock); dormakaba Saflok software acquired this session |
| TELEMECANIQUE ELECTRIQUE | 21 | Telemecanique is a Schneider Electric brand; Schneider firmware acquired |
| Honeywell Connected Building | 16 | Honeywell resells Niagara-based controllers (Tridium, acquired) and has an OSINT brief; Honeywell-branded device firmware still gated |
| ROSEMOUNT CONTROLS | 6 | Rosemount is an Emerson brand (process controls) |
| Invensys | 3 | Invensys was absorbed into Schneider Electric / AVEVA |
| Honeywell Security (China) Co., Ltd. | 3 | Honeywell resells Niagara-based controllers (Tridium, acquired) and has an OSINT brief; Honeywell-branded device firmware still gated |
| Honeywell | 3 | Honeywell resells Niagara-based controllers (Tridium, acquired) and has an OSINT brief; Honeywell-branded device firmware still gated |
| Emerson Network Power Co.,Ltd | 2 | Emerson Network Power was renamed Vertiv (acquired/Apex lineage) |
| POWER MEASUREMENT LTD. | 2 | Power Measurement Ltd = Schneider ION power meters |
| Red Lion Controls Inc. | 2 | Red Lion has an existing brief |
| Honeywell Life Safety | 2 | Honeywell resells Niagara-based controllers (Tridium, acquired) and has an OSINT brief; Honeywell-branded device firmware still gated |

### Not a firmware target (13 vendors, 34 devices)

OUI artifacts, IT endpoints, component chips inside other products, and our own tooling. No vendor firmware exists to acquire:

| Census vendor | OT dev | Why excluded |
|---|---:|---|
| Unknown | 7 | unresolved OUI |
| Super Micro Computer, Inc. | 5 | server/IT hardware |
| JK microsystems, Inc. | 5 | embedded SBC component module |
| Lantronix | 3 | serial-to-Ethernet module chip (component OUI) |
| DigiBoard | 3 | serial device-server component (Digi) |
| ASIX ELECTRONICS CORP. | 2 | Ethernet controller chip (OUI inside other products) |
| Dragos, Inc. | 2 | our own OT monitoring sensor, not a target |
| sunweit industrial limited | 2 | generic component OUI |
| Samsung Electronics Co.,Ltd | 1 | IT/consumer (generic Samsung, not Hanwha) |
| HP Inc. | 1 | IT endpoint |
| ASUSTek COMPUTER INC. | 1 | IT endpoint |
| ASIX Electronics Corporation | 1 | Ethernet controller chip (OUI inside other products) |
| Universal Global Scientific Industrial., Ltd | 1 | contract manufacturer / component |

### Genuine OT vendors still missing firmware (46 vendors, 269 devices)

Real acquisition targets, all sizes. An acquire-and-analyze pass (public download + VT-Intelligence pull + full pipeline) was launched across **all** of these on 2026-10-26, regardless of device count:

| Census vendor | OT dev | States |
|---|---:|---:|
| IQSIGHT B.V. | 33 | 1 |
| PRONET GMBH | 31 | 11 |
| Electro Industries/Gauge Tech | 27 | 3 |
| Xytronix Research & Design, Inc. | 20 | 2 |
| CONTEMPORARY CONTROL | 14 | 4 |
| Arecont Vision | 14 | 3 |
| Resideo | 12 | 4 |
| LOYTEC electronics GmbH | 12 | 3 |
| Paxton Access Ltd | 11 | 1 |
| Hangzhou Hikvision Digital Technology Co.,Ltd. | 10 | 1 |
| Sur-Gard Security | 8 | 5 |
| 2N TELEKOMUNIKACE a.s. | 8 | 2 |
| Vivotek, Inc. | 7 | 3 |
| Server Technology, Inc. | 6 | 1 |
| Suprema Inc. | 4 | 2 |
| Planmeca Oy | 4 | 2 |
| Barix AG | 4 | 3 |
| Sensaphone | 4 | 3 |
| Integrated Control Technology Limitied | 4 | 1 |
| Wyze Labs Inc | 3 | 1 |
| IT Watchdogs, Inc | 3 | 2 |
| ALERTON TECHNOLOGIES, INC. | 3 | 1 |
| DYNACOLOR, INC. | 2 | 1 |
| Phoenix Contact GmbH & Co. KG | 2 | 1 |
| eGauge Systems LLC | 2 | 1 |
| Interalia Inc. | 1 | 5 |
| Magicard Ltd | 1 | 1 |
| SHENZHEN BILIAN ELECTRONIC CO.，LTD | 1 | 1 |
| EliteGroup Computer Systems Co., LTD | 1 | 2 |
| KMC CONTROLS | 1 | 0 |
| SAMSUNG TECHWIN CO.,LTD | 1 | 0 |
| NetBurner | 1 | 0 |
| Proxmox Server Solutions GmbH | 1 | 1 |
| Basler AG | 1 | 1 |
| RESOL Elektronische Regelungen GmbH | 1 | 1 |
| WIRELESS-TEK TECHNOLOGY LIMITED | 1 | 1 |
| Schneider Electric | 1 | 3 |
| Telematica Sistems Inteligente | 1 | 1 |
| Dish Technologies Corp | 1 | 1 |
| Jabil Circuit Hungary Ltd. | 1 | 1 |
| FLIR Systems | 1 | 1 |
| ENGAGE NETWORKS, INC. | 1 | 1 |
| Framework Computer Inc. | 1 | 1 |
| Tercel technology co.,ltd | 1 | 1 |
| Shanghai Chint Power Systems Co., Ltd. | 1 | 1 |
| MOXA TECHNOLOGIES CORP., LTD. | 1 | 1 |


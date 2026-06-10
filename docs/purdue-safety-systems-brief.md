# Purdue Safety Instrumented Systems (parallel to L1, often called Level 0.5 / 1.5) — Cross-Vendor Threat & Detection Brief

**Scope:** This brief covers Safety Instrumented Systems (SIS) — the dedicated, independent control layer whose sole function is to bring a process to a safe state when defined limits are exceeded. SIS sits parallel to Purdue Level 1 (often labeled Level 0.5 for safety-rated field sensors/final elements or Level 1.5 for the safety logic solver bus) and is intended to be functionally and physically independent of the Basic Process Control System (BPCS). In-scope devices cross-vendor: Schneider **Triconex Tricon / Trident / Tri-GP** (TriStation 1131), Honeywell **Safety Manager FSC** (SM Builder), Siemens **SIMATIC S7-1500F / S7-1500TF + Distributed Safety + Safety Matrix**, Yokogawa **ProSafe-RS**, HIMA **HIMatrix F / HIQuad / HIMax**, Rockwell **GuardLogix 5580 / Compact GuardLogix 5380**, ABB **SafeGuard 800xA**, Emerson **DeltaV SIS (CHARMs / SLS 1508)**, plus IEC 61508 SIL2/SIL3 field instruments (gas, pressure, flame). Relationship to other layers: the SIS receives engineering downloads from L3/L3.5 engineering workstations (EWS), is wired to L0 SIL-rated transmitters and final elements, and historically isolated from L2 HMI / L1 BPCS — but increasingly bridged via OPC-UA, Modbus, or dedicated safety-network gateways for asset-management and alarm aggregation. The SIS is the layer of last resort: bypassing it enables follow-on destructive attack at L1/L0 that safety would otherwise halt.

## Architecture grouping (organized by ROLE within this layer, not by vendor)

| Class (role) | Products (cross-vendor) | Stack (RTOS/protocol/OS) | Catalog depth |
|---|---|---|---|
| Safety Logic Solver (triple/dual-MCU SIS controller) | Schneider Triconex Tricon/Trident/Tri-GP, Honeywell Safety Manager FSC, Siemens S7-1500F/TF, Yokogawa ProSafe-RS, HIMA HIMax/HIQuad/HIMatrix, Rockwell GuardLogix 5580, Emerson DeltaV SLS 1508 | Proprietary RTOS (Tricon, FSC firmware), VxWorks-class on several platforms; TriStation (UDP/1502), CIP-Safety (TCP/44818 + UDP/2222), PROFIsafe over PROFINET, Modbus TCP/502, OPC-UA TCP/4840 | Research-only for most; Triconex has TRITON catalog depth |
| SIS Engineering Workstation (safety configuration tool) | Schneider TriStation 1131, Siemens TIA Portal + Step 7 Safety Advanced + Safety Matrix Tool, Honeywell SM Builder, Yokogawa SENG, Rockwell Studio 5000 Logix Designer (safety), HIMA SILworX | Windows; project-file formats, protocol-specific download (TriStation UDP/1502, S7Comm TCP/102) | EWS-side covered in vendor briefs (Siemens, Schneider, Rockwell) |
| Safety I/O & Field-Instrument layer (L0.5) | IEC 61508 SIL2/SIL3 transmitters, gas/flame detectors, ESD valves, partial-stroke testers | HART, HART-IP TCP/5094, FOUNDATION Fieldbus, PROFIsafe-on-PROFINET, ASi-Safety | Research-only |
| Safety Network Bridge / Gateway | Honeywell FSC Modbus gateway, Schneider Triconex TCM (Tricon Communication Module), Siemens CP1543-1 with PROFIsafe, ProSafe-RS Vnet/IP gateway | Modbus TCP/502, OPC-UA TCP/4840, PROFIsafe, EtherNet/IP (CIP TCP/44818 + UDP/2222) | Research-only |
| SIS Asset / Diagnostic Server | Honeywell SM Manager, Emerson AMS Device Manager (safety), Yokogawa SDC, HIMA SILworX OPC, ABB 800xA Safety Workplace | Windows, OPC-UA/DA, vendor-proprietary diagnostic protocols | Research-only |

## Group 1 — Safety Logic Solver (the SIS controller itself)

**Direct attack surface:** TriStation protocol (UDP/1502, unauthenticated in pre-v11 Tricon firmware), PROFIsafe over PROFINET (Siemens F-CPU), CIP-Safety over EtherNet/IP (Rockwell GuardLogix, TCP/44818 + UDP/2222 implicit messaging), Modbus TCP/502 diagnostic ports, OPC-UA servers (TCP/4840) exposed for asset-management, key-switch position (PROGRAM / RUN / REMOTE) often left in PROGRAM in field installations, firmware-upload pathway, RAM-resident logic injection.

**Confirmed CVEs across vendors:**

| CVE | CVSS | Vendor | Product | Vector |
|---|---|---|---|---|
| [CVE-2018-7522](https://nvd.nist.gov/vuln/detail/CVE-2018-7522) | 7.5 | Schneider | Triconex Tricon (TRITON / TRISIS) | TriStation protocol firmware upload + RAM-resident `inject.bin` / `imain.bin` payload while key-switch in PROGRAM mode |
| [ICSA-18-107-02](https://www.cisa.gov/news-events/ics-advisories/icsa-18-107-02) | n/a | Schneider | Triconex Tricon 3008 | Companion CISA advisory to TRITON; details mitigation |
| [CVE-2022-1161](https://nvd.nist.gov/vuln/detail/CVE-2022-1161) | 7.7 | Rockwell | ControlLogix / CompactLogix (incl. GuardLogix family advisory cross-ref) | Stealthy logic injection — engineer's Studio 5000 online view differs from running bytecode; bypasses standard CR walk-through |
| [CVE-2021-22681](https://nvd.nist.gov/vuln/detail/CVE-2021-22681) | 10.0 | Rockwell | Studio 5000 Logix Designer (used for GuardLogix safety projects) | Hardcoded crypto key — attacker can authenticate to controller, applies to safety variants ([ICSA-21-056-03](https://www.cisa.gov/news-events/ics-advisories/icsa-21-056-03)) |
| [CVE-2024-6242](https://nvd.nist.gov/vuln/detail/CVE-2024-6242) | 7.5 | Rockwell | 1756-EN4TR (chassis bridge to GuardLogix) | CIP trusted-slot bypass — attacker on local IP can send CIP messages to safety controller in same chassis |
| Siemens [SSA-381290](https://cert-portal.siemens.com/productcert/html/ssa-381290.html) (representative) | varies | Siemens | SIMATIC S7-1500F / TF | PROFIsafe / TIA-Portal class advisories; see ProductCERT monthly bundles |
| [Honeywell PSIRT advisories](https://www.honeywell.com/us/en/cyber-security-resources) | varies | Honeywell | Safety Manager FSC | Vendor-portal-distributed advisories for FSC firmware and SM Builder; OT:ICEFALL covered Experion C300, not FSC directly |
| [Emerson PSIRT advisories](https://www.emerson.com/en-us/support/security-center) | varies | Emerson | DeltaV SIS / SLS 1508 / CHARMs | Vendor-portal-distributed advisories on diagnostic-port and OPC-UA exposure |
| [Yokogawa Security Bulletins](https://web-material3.yokogawa.com/security-bulletin.html) | varies | Yokogawa | ProSafe-RS | Vnet/IP exposure and SENG-host advisories |
| [Forescout OT:ICEFALL report](https://www.forescout.com/resources/ot-icefall-report) (2022) | varies | Honeywell / Emerson / Motorola | Experion C300, DeltaV M-series, ACE3600 — safety-adjacent | Insecure-by-design firmware-update + unauth engineering protocols across vendors |

**Top attack vector (MITRE ATT&CK ICS):** [T0857 System Firmware](https://attack.mitre.org/techniques/T0857/) — TRITON's signature move: upload of crafted SIS firmware while the controller is in PROGRAM mode, followed by [T0833 Modify Control Logic](https://attack.mitre.org/techniques/T0833/) to disable the FAILSAFE trip.

## Group 2 — SIS Engineering Workstation (the EWS that downloads safety logic)

**Direct attack surface:** Windows OS surface (the EWS is a normal PC), TriStation 1131 / TIA Portal Safety / SM Builder / SILworX / Studio 5000 installation, project-file parser (`.ACD`, `.AP1x`/`.AP18`, `.tsproj`, vendor SM/SILworX project bundles), USB/removable-media transfer (TRITON propagated EWS-side this way), VPN/Citrix jumphost into OT, weak EWS auth (often shared `engineer` account), unsigned firmware download tooling.

**Confirmed CVEs across vendors:**

| CVE | CVSS | Vendor | Product | Vector |
|---|---|---|---|---|
| [Evil PLC Attack (Claroty Team82)](https://claroty.com/team82/research/evil-plc-attack-weaponizing-plcs-to-attack-engineering-workstations) | n/a (research) | Rockwell / Siemens / Schneider / GE / Ovarro / Emerson | Studio 5000, TIA Portal, Control Expert, others | Weaponized PLC project file pulls RCE back into EWS upon engineer's "upload" — directly applicable to safety EWS workflows |
| [CVE-2021-22681](https://nvd.nist.gov/vuln/detail/CVE-2021-22681) | 10.0 | Rockwell | Studio 5000 Logix Designer (safety) | Hardcoded key, see above |
| [CVE-2024-21915](https://nvd.nist.gov/vuln/detail/CVE-2024-21915) | 9.8 | Rockwell | FactoryTalk Services Platform | Privilege escalation on EWS host ([ICSA-24-018-01](https://www.cisa.gov/news-events/ics-advisories/icsa-24-018-01)) |
| [Siemens ProductCERT TIA advisories](https://cert-portal.siemens.com/productcert/html) | varies | Siemens | TIA Portal + Step 7 Safety Advanced | Recurring project-file parser and S7Comm (TCP/102) protocol findings; second-Tuesday cycle |
| [CVE-2018-7841](https://nvd.nist.gov/vuln/detail/CVE-2018-7841) / [CVE-2021-22779](https://nvd.nist.gov/vuln/detail/CVE-2021-22779) | varies | Schneider | Modicon / Control Expert (UMAS over Modbus TCP/502) | UMAS / project-format CVEs on adjacent Modicon tooling — TriStation 1131 advisories follow the same [Schneider PSIRT](https://www.se.com/ww/en/work/support/cybersecurity/security-notifications.jsp) cycle |

**Top attack vector (MITRE ATT&CK ICS):** [T0843 Program Download](https://attack.mitre.org/techniques/T0843/) following [T0817 Drive-by Compromise](https://attack.mitre.org/techniques/T0817/) of the EWS — the TRITON pattern of "RAT on EWS → dropper on Tricon → override of FAILSAFE."

## Group 3 — Safety I/O & Field-Instrument layer (L0.5)

**Direct attack surface:** HART pass-through (HART-IP gateways exposing 4–20 mA loop devices on TCP/5094), FOUNDATION Fieldbus H1 segments, PROFIsafe device names hijack (rogue device taking PROFIsafe address), ESD valve solenoid wiring, partial-stroke test (PST) command messages, gas/flame detector calibration menus reachable over Modbus TCP/502 or HART-IP.

**Confirmed CVEs across vendors:** Limited public CVE coverage at this layer — most safety-rated transmitter vulnerabilities are disclosed under vendor PSIRT NDA. Anchor research:

| CVE | CVSS | Vendor | Product | Vector |
|---|---|---|---|---|
| [Forescout OT:ICEFALL report](https://www.forescout.com/resources/ot-icefall-report) (Honeywell Experion C300 cluster) | varies | Honeywell | Experion C300 + related safety-adjacent I/O | Unauthenticated firmware update + insecure engineering protocol |
| [Emerson PSIRT advisories](https://www.emerson.com/en-us/support/security-center) | varies | Emerson | DeltaV SLS 1508, CHARMs | OPC-UA + diagnostic-port exposure |
| [Yokogawa Security Bulletins](https://web-material3.yokogawa.com/security-bulletin.html) | varies | Yokogawa | ProSafe-RS | Vnet/IP exposure on shared safety/control network |
| [HART-IP exposure research](https://www.dragos.com/blog/) | n/a (research) | Multi-vendor | HART-IP gateways (TCP/5094) | Unauthenticated re-ranging of field transmitters |

**Top attack vector (MITRE ATT&CK ICS):** [T0832 Manipulation of View](https://attack.mitre.org/techniques/T0832/) and [T0836 Modify Parameter](https://attack.mitre.org/techniques/T0836/) — falsify transmitter values so the logic solver's safe-state algorithm never trips, or tamper with SIL alarm setpoints.

## Group 4 — Safety Network Bridge / Gateway

**Direct attack surface:** Modbus TCP/502 diagnostic taps off the safety bus, OPC-UA aggregation servers (TCP/4840) feeding L2 HMI, PROFINET + PROFIsafe on a shared physical network, EtherNet/IP (CIP TCP/44818 + UDP/2222) between GuardLogix and L1 ControlLogix sharing producer/consumer tags, Vnet/IP gateways between ProSafe-RS and CENTUM VP.

**Confirmed CVEs across vendors:**

| CVE | CVSS | Vendor | Product | Vector |
|---|---|---|---|---|
| [CVE-2023-3596](https://nvd.nist.gov/vuln/detail/CVE-2023-3596) | 7.5 | Rockwell | 1756-EN2T/EN3TR/EN4TR | CIP DoS — knocks safety chassis comms off the network |
| [CVE-2024-6242](https://nvd.nist.gov/vuln/detail/CVE-2024-6242) | 7.5 | Rockwell | 1756-EN4TR | CIP trusted-slot bypass — cross-slot reach into GuardLogix |
| [Siemens SCALANCE / CP advisories](https://cert-portal.siemens.com/productcert/html) | varies | Siemens | CP1543-1, SCALANCE XC/XR | PROFINET / PROFIsafe-adjacent findings |
| [Honeywell PSIRT advisories](https://www.honeywell.com/us/en/cyber-security-resources) | varies | Honeywell | FSC Modbus gateway | Modbus TCP/502 gateway exposure to BPCS network |
| [Yokogawa Security Bulletins](https://web-material3.yokogawa.com/security-bulletin.html) | varies | Yokogawa | Vnet/IP gateway | Cross-segment exposure between ProSafe-RS and CENTUM VP |

**Top attack vector (MITRE ATT&CK ICS):** [T0830 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T0830/) on the safety/control shared segment to suppress trip messages or replay healthy-state telemetry to L2.

## Group 5 — SIS Asset / Diagnostic Server

**Direct attack surface:** Windows host running OPC-UA/DA aggregator (TCP/4840), RDP / SMB on management LAN, vendor diagnostic protocol (Honeywell SM Manager, Yokogawa SDC, HIMA SILworX OPC server), shared `safety_engineer` credentials, lateral movement target from L3.

**Confirmed CVEs across vendors:** Honeywell and HIMA disclosures are largely vendor-portal-only. Anchor with [Honeywell cyber resources](https://www.honeywell.com/us/en/cyber-security-resources), [Schneider PSIRT](https://www.se.com/ww/en/work/support/cybersecurity/security-notifications.jsp), [Rockwell Trust Center](https://www.rockwellautomation.com/en-us/trust-center/security-advisories.html), [Emerson Security Center](https://www.emerson.com/en-us/support/security-center), [Yokogawa Security Bulletins](https://web-material3.yokogawa.com/security-bulletin.html), [HIMA Cyber Security](https://www.hima.com/en/services/cyber-security/), and [Siemens ProductCERT](https://cert-portal.siemens.com/productcert/html). Honest scope: SIS asset-server CVE data is sparser than EWS/PLC equivalents.

**Top attack vector (MITRE ATT&CK ICS):** [T0859 Valid Accounts](https://attack.mitre.org/techniques/T0859/) → [T0822 External Remote Services](https://attack.mitre.org/techniques/T0822/) on the diagnostic server, used as a staging beachhead for Group 1 firmware tamper.

## Logging matrix (highest priority for this layer)

| # | Source | Event | What it catches | MITRE ATT&CK ICS |
|---|---|---|---|---|
| 1 | SIS controller keyswitch sensor (Tricon, GuardLogix, S7-1500F) | Position change PROGRAM ↔ RUN ↔ REMOTE | TRITON-class precondition: SIS left in PROGRAM enables firmware/logic write | [T0858 Change Operating Mode](https://attack.mitre.org/techniques/T0858/) |
| 2 | Network tap on safety segment | TriStation UDP/1502, CIP-Safety (TCP/44818 + UDP/2222), PROFIsafe write requests from non-engineering hosts | Unauthorized download path | [T0843 Program Download](https://attack.mitre.org/techniques/T0843/) |
| 3 | SIS firmware integrity (vendor-native + secondary hash) | Firmware version, CRC, build-ID change | TRITON `inject.bin` / `imain.bin` RAM payload, malicious firmware push | [T0857 System Firmware](https://attack.mitre.org/techniques/T0857/) |
| 4 | SIS application-program CRC / signature | Safety-program checksum mismatch vs golden | CVE-2022-1161-class stealthy logic injection where online view lies | [T0833 Modify Control Logic](https://attack.mitre.org/techniques/T0833/) |
| 5 | EWS host (TriStation 1131 / TIA Portal Safety / SM Builder / Studio 5000) | Process exec, USB mount, project-file open, outbound to controller IP outside change window | EWS pivot into SIS — TRITON, Evil PLC | [T0843](https://attack.mitre.org/techniques/T0843/) |
| 6 | SIS diagnostic alarms | Voted I/O channel discrepancy, partial-stroke-test bypass, SOE (sequence-of-events) gap | Suppression of trip indications | [T0820 Exploitation for Evasion](https://attack.mitre.org/techniques/T0820/) |
| 7 | Field-instrument calibration writes (HART-IP TCP/5094, FOUNDATION Fieldbus) | Setpoint, range, dampening change | Setpoint manipulation that prevents trip | [T0836 Modify Parameter](https://attack.mitre.org/techniques/T0836/) |
| 8 | OPC-UA / Modbus gateway between SIS and BPCS | Tag-mapping change, new client subscription on TCP/4840 or TCP/502 | Bridge weaponization for AitM trip-suppression | [T0830 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T0830/) |

**Secondary:** Vendor-native audit logs — Triconex TriStation event log, Honeywell SM Builder audit, Siemens TIA Portal safety-program change log, Rockwell FactoryTalk AssetCentre safety-revision audit, HIMA SILworX change history; OT-native anomalies — safety-bus cycle-time jitter, PROFIsafe F-address conflicts, CIP-Safety connection-timeout-multiplier changes, unexpected `RUN` → `STOP` solicitations from non-EWS hosts, SOE recorder gaps coinciding with EWS activity, lab-test of golden firmware hashes against running controller via offline copy.

## Cross-layer pivots

1. **L3 EWS → L1.5 SIS (the TRITON path).** Spear-phish or supply-chain compromise lands on an EWS host at L3 / L3.5. Attacker installs an attacker-controlled TriStation client, observes that the Tricon keyswitch is in PROGRAM, and uploads a crafted firmware payload (`inject.bin` + `imain.bin`) plus an override of the FAILSAFE function block. The intent — wait for an attacker-chosen physical excursion at L0, at which point the safety system fails to trip and L1 damage propagates to L0 destruction. The 2017 incident failed only because the FAILSAFE itself triggered a plant shutdown, exposing the campaign. Detection priorities: rows 1, 2, 3, 5 of the matrix.
2. **L1 PLC → L1.5 SIS via shared safety-network segment.** Where the BPCS and SIS share Ethernet (common in Rockwell GuardLogix-in-ControlLogix-chassis deployments and in Siemens F-CPU on the same PROFINET), compromise of a non-safety controller via CVE-2024-6242 trusted-slot bypass or CIP-Safety AitM lets the attacker reach the safety CPU without ever touching the EWS. Detection priorities: rows 2, 8.
3. **L1.5 SIS bypass enables L1/L0 destructive attack.** Once the SIS trip is suppressed, follow-on Manipulation of Control ([T0831](https://attack.mitre.org/techniques/T0831/)) at L1 (e.g. overspeed a compressor, overpressure a vessel) escalates to [T0879 Damage to Property](https://attack.mitre.org/techniques/T0879/) at L0 — the entire reason an attacker targets SIS in the first place. Detection priority: row 6 SOE gap analysis is the late-stage smoking gun.
4. **L3.5 asset-management diagnostic server → L1.5 SIS via OPC-UA / HART-IP.** Compromise of the SIS diagnostic / OPC aggregator (Honeywell SM Manager, Emerson AMS, Yokogawa SDC) reaches SIL-rated transmitters through HART pass-through (TCP/5094) and re-ranges the device so the SIS logic solver sees safe values during an actual excursion ([T0832 Manipulation of View](https://attack.mitre.org/techniques/T0832/)). Detection priorities: rows 7, 8.

## Sources

- [CISA ICSA-18-107-02 — Schneider Triconex TRITON](https://www.cisa.gov/news-events/ics-advisories/icsa-18-107-02)
- [CVE-2018-7522 — Triconex Tricon](https://nvd.nist.gov/vuln/detail/CVE-2018-7522)
- [Dragos TRISIS / TRITON analysis](https://www.dragos.com/blog/trisis-analyzing-safety-system-targeted-malware/) + [Mandiant TRITON attribution](https://www.mandiant.com/resources/blog/triton-actor-ttp-profile-custom-attack-tools-detections)
- [Dragos XENOTIME activity group](https://www.dragos.com/threat/xenotime/)
- [Claroty Team82 — Evil PLC Attack](https://claroty.com/team82/research/evil-plc-attack-weaponizing-plcs-to-attack-engineering-workstations)
- [CVE-2022-1161 — Rockwell ControlLogix stealthy logic injection](https://nvd.nist.gov/vuln/detail/CVE-2022-1161)
- [CVE-2021-22681 / ICSA-21-056-03 — Studio 5000 hardcoded key](https://www.cisa.gov/news-events/ics-advisories/icsa-21-056-03)
- [CVE-2024-6242 — 1756-EN4TR CIP trusted-slot bypass](https://nvd.nist.gov/vuln/detail/CVE-2024-6242)
- [CVE-2023-3596 — Rockwell 1756 CIP DoS](https://nvd.nist.gov/vuln/detail/CVE-2023-3596)
- [CVE-2024-21915 / ICSA-24-018-01 — FactoryTalk Services Platform](https://www.cisa.gov/news-events/ics-advisories/icsa-24-018-01)
- [CVE-2018-7841 — Schneider Modicon / Control Expert](https://nvd.nist.gov/vuln/detail/CVE-2018-7841)
- [CVE-2021-22779 — Schneider Modicon UMAS](https://nvd.nist.gov/vuln/detail/CVE-2021-22779)
- [Forescout OT:ICEFALL report](https://www.forescout.com/resources/ot-icefall-report)
- [Siemens ProductCERT](https://cert-portal.siemens.com/productcert/html)
- [Schneider Electric PSIRT](https://www.se.com/ww/en/work/support/cybersecurity/security-notifications.jsp)
- [Rockwell Automation Trust Center](https://www.rockwellautomation.com/en-us/trust-center/security-advisories.html)
- [Honeywell Cyber Security Resources](https://www.honeywell.com/us/en/cyber-security-resources)
- [Emerson Security Center](https://www.emerson.com/en-us/support/security-center)
- [Yokogawa Security Bulletins](https://web-material3.yokogawa.com/security-bulletin.html)
- [HIMA Cyber Security](https://www.hima.com/en/services/cyber-security/)
- [CISA Volt Typhoon AA24-038A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a)
- MITRE ATT&CK ICS — [T0833](https://attack.mitre.org/techniques/T0833/), [T0843](https://attack.mitre.org/techniques/T0843/), [T0857](https://attack.mitre.org/techniques/T0857/), [T0858](https://attack.mitre.org/techniques/T0858/), [T0830](https://attack.mitre.org/techniques/T0830/), [T0820](https://attack.mitre.org/techniques/T0820/), [T0832](https://attack.mitre.org/techniques/T0832/), [T0836](https://attack.mitre.org/techniques/T0836/), [T0859](https://attack.mitre.org/techniques/T0859/), [T0822](https://attack.mitre.org/techniques/T0822/), [T0831](https://attack.mitre.org/techniques/T0831/), [T0879](https://attack.mitre.org/techniques/T0879/)
- [ISA/IEC 61511 — Functional safety: SIS for the process industry](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-standards-committee-isa84)
- [IEC 62443-3-3 — System security requirements (SR-7 safety-function integrity)](https://www.iec.ch/cyber-security)
- [ISA-95 / Purdue Reference Model](https://www.isa.org/standards-and-publications/isa-standards/isa-standards-committees/isa95)

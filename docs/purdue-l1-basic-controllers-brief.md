# Purdue Basic Controllers (L1) — Cross-Vendor Threat & Detection Brief

**Scope:** Purdue Level 1 — the *Basic Control* layer — comprises the programmable logic controllers (PLCs), remote terminal units (RTUs), intelligent electronic devices (IEDs), protective relays, variable-frequency drives (VFDs), and distributed I/O modules that physically read sensors and command actuators in real time. This brief cross-cuts Rockwell Automation (ControlLogix / CompactLogix / Micro800 / PowerFlex), Siemens (SIMATIC S7-300/400/1200/1500, SINAMICS, SIPROTEC, ET200), Schneider Electric (Modicon Quantum / M340 / M580 / M221, Altivar, Sepam/MiCOM), Honeywell (C300, ControlEdge RTU), SEL (RTAC, 300/400/700-series relays), and ABB (REF/REL/RET). L1 sits between L0 (field instrumentation — sensors, actuators, valves) and L2 (HMI / Supervisory). It is the *last programmable layer before physics*: a compromised L1 device can damage equipment, injure people, or falsify the view sent upward to L2/L3. L1 also frequently shares Ethernet segments with the Safety Instrumented System (SIS), making it the proven pivot point of the TRITON/TRISIS pattern.

## Architecture grouping (organized by ROLE within this layer, not by vendor)

| Class (role) | Products (cross-vendor) | Stack (RTOS/protocol/OS) | Catalog depth |
|---|---|---|---|
| Chassis PLC (large process) | Rockwell ControlLogix/GuardLogix 1756-L7x/L8x + 1756-EN2T/EN3TR/EN4TR; Siemens SIMATIC S7-400, S7-1500 (CPU 151x); Schneider Modicon Quantum 140 / Premium TSX | VxWorks / proprietary; EtherNet/IP CIP; S7Comm (TCP/102); Modbus/UMAS TCP/502 | Deep CVE coverage |
| Rack/compact PLC (mid-tier) | Rockwell CompactLogix/Compact GuardLogix 5380/5480/5370; Siemens S7-1200; Schneider Modicon M340/M580; Honeywell C300 / C200E Series-C | VxWorks; ARM/PowerPC RTOS; CIP / PROFINET / Modbus / CDA over UDP | Deep CVE coverage |
| Entry-level / micro PLC | Rockwell Micro800 (820/830/850/870); Siemens S7-1200 Basic; Schneider M221/M241 | Lightweight RTOS; Modbus TCP/502; CIP; proprietary | Moderate CVE coverage |
| Distributed I/O / remote I/O | Siemens ET200SP / ET200MP / ET200ECO; Rockwell 1734-AENTR POINT I/O; Schneider Modicon X80 drops | PROFINET RT/IRT; EtherNet/IP CIP; Modbus | Research only (low public CVE volume) |
| RTU / utility comms processor | SEL-3530 / SEL-3555 RTAC; Schneider SCADAPack; Siemens SIMATIC RTU3030C; Honeywell ControlEdge RTU | Linux-based (RTAC); DNP3 TCP/20000; IEC 60870-5-104; IEC 61850 | Moderate CVE coverage |
| Protective relay / IED (substation) | SEL-300/351/387/421/451/487/700/751; Siemens SIPROTEC 4/5; Schneider Sepam / MiCOM; ABB REF/REL/RET | Embedded RTOS; IEC 61850 GOOSE + MMS (TCP/102); DNP3; proprietary engineering | Deep CVE coverage |
| Variable-frequency drive (VFD) | Rockwell PowerFlex 525/527/753/755/755T/6000T; Siemens SINAMICS G120/S120/V90; Schneider Altivar | Embedded RTOS; CIP-Motion; PROFINET; Modbus; embedded web servers | Moderate CVE coverage |

## Group 1 — Chassis PLC (large process)

**Direct attack surface:** EtherNet/IP CIP (TCP/44818, UDP/2222 implicit messaging), S7Comm (TCP/102), Modbus TCP/502, embedded HTTP/HTTPS engineering ports, SNMP, FTP/TFTP on legacy comms cards. Studio 5000 / TIA Portal / Control Expert online sessions are authenticated by weak or proprietary schemes.

**Confirmed CVEs across vendors:**

| CVE | CVSS | Vendor | Product | Vector |
|---|---|---|---|---|
| [CVE-2021-22681](https://nvd.nist.gov/vuln/detail/CVE-2021-22681) | 10.0 | Rockwell | Logix family (1756/1769) | Hardcoded Studio 5000 cryptographic key — auth bypass, see [ICSA-21-056-03](https://www.cisa.gov/news-events/ics-advisories/icsa-21-056-03) |
| [CVE-2022-1161](https://nvd.nist.gov/vuln/detail/CVE-2022-1161) | 7.7 | Rockwell | ControlLogix/CompactLogix/GuardLogix 5380/5480/5580 | Stealthy logic injection — online view differs from running bytecode |
| [CVE-2023-3596](https://nvd.nist.gov/vuln/detail/CVE-2023-3596) | 7.5 | Rockwell | 1756-EN2T/EN3TR/EN4TR | Crafted CIP message → comms-card DoS |
| [CVE-2024-6242](https://nvd.nist.gov/vuln/detail/CVE-2024-6242) | 7.7 | Rockwell | 1756-EN4TR | CIP "trusted-slot" bypass — write to controller from untrusted slot |
| [Siemens ProductCERT advisories](https://cert-portal.siemens.com/productcert/) | varied | Siemens | S7-1500 / S7-1500F / S7-400 | Multiple firmware advisories (CPU 151x denial-of-service, web-server XSS, MMS) — see ProductCERT monthly cycle |
| [CVE-2018-7841](https://nvd.nist.gov/vuln/detail/CVE-2018-7841) | 9.8 | Schneider | Modicon Quantum / Premium / M580 | UMAS auth bypass — unauthenticated stop/start/logic-write |
| [Stuxnet (S7-300/400 PROFIBUS payload)](https://attack.mitre.org/software/S0603/) | n/a | Siemens | S7-315/417 + CP 342-5 | DLL hijack of s7otbxdx.dll, OB35 rewrite → centrifuge over-speed |

**Top attack vector (MITRE ATT&CK ICS):** [T0833 Modify Control Logic](https://attack.mitre.org/techniques/T0833/), often chained with [T0843 Program Download](https://attack.mitre.org/techniques/T0843/) and [T0832 Manipulation of View](https://attack.mitre.org/techniques/T0832/).

## Group 2 — Rack/compact PLC (mid-tier)

**Direct attack surface:** Same CIP/S7Comm/Modbus/UMAS stacks as Group 1 but typically fewer security features (no 1756-EN4TR trusted-slot enforcement; smaller key store). Honeywell C300 uses Control Data Access (CDA) over UDP — flat, unauthenticated, broadcast-rich.

**Confirmed CVEs across vendors:**

| CVE | CVSS | Vendor | Product | Vector |
|---|---|---|---|---|
| [CVE-2023-2071](https://nvd.nist.gov/vuln/detail/CVE-2023-2071) | 9.8 | Rockwell | CompactLogix 5370 | Unauthenticated CIP RCE — see [ICSA-23-136-04](https://www.cisa.gov/news-events/ics-advisories/icsa-23-136-04) |
| [CVE-2021-22779](https://nvd.nist.gov/vuln/detail/CVE-2021-22779) | 8.1 | Schneider | Modicon M340/M580/Quantum/Premium | UMAS reservation-bypass — write logic without engineering session |
| [Honeywell Experion / C300 ICEFALL family](https://www.forescout.com/research-labs/ot-icefall/) | varied | Honeywell | Experion PKS / C300 | CDA protocol weaknesses disclosed in the Claroty/Forescout OT:ICEFALL set (see Honeywell SN and Forescout writeup) |
| [Siemens ProductCERT S7-1200 advisories](https://cert-portal.siemens.com/productcert/) | varied | Siemens | S7-1200 | Multiple denial-of-service via crafted S7Comm/web-server requests |
| [CVE-2022-1161](https://nvd.nist.gov/vuln/detail/CVE-2022-1161) | 7.7 | Rockwell | CompactLogix 5380 | Stealthy logic injection (also lists this device) |

**Top attack vector (MITRE ATT&CK ICS):** [T0836 Modify Parameter](https://attack.mitre.org/techniques/T0836/), enabled by [T0866 Exploitation of Remote Services](https://attack.mitre.org/techniques/T0866/).

## Group 3 — Entry-level / micro PLC

**Direct attack surface:** Modbus TCP/502 unauthenticated by spec; embedded web servers; cleartext configuration; many devices ship reachable on plant-wide VLANs. Shodan/Censys exposure is the dominant initial-access path.

**Confirmed CVEs across vendors:** Coverage is uneven — micro PLCs are under-disclosed relative to chassis siblings.

| CVE | CVSS | Vendor | Product | Vector |
|---|---|---|---|---|
| [CVE-2018-7841](https://nvd.nist.gov/vuln/detail/CVE-2018-7841) | 9.8 | Schneider | M221 (UMAS implementation) | Auth-bypass over Modbus/UMAS |
| [Rockwell Micro800 advisories](https://www.rockwellautomation.com/en-us/trust-center/security-advisories.html) | varied | Rockwell | Micro820/830/850/870 | Multiple Connected Components Workbench (CCW) CVEs published via Trust Center |
| [Siemens ProductCERT S7-1200 advisories](https://cert-portal.siemens.com/productcert/) | varied | Siemens | S7-1200 Basic | Web-server / S7Comm DoS series |

**Top attack vector (MITRE ATT&CK ICS):** [T0883 Internet Accessible Device](https://attack.mitre.org/techniques/T0883/) → [T0855 Unauthorized Command Message](https://attack.mitre.org/techniques/T0855/), often combined with [T0812 Default Credentials](https://attack.mitre.org/techniques/T0812/) on embedded web servers.

## Group 4 — Distributed I/O / remote I/O

**Direct attack surface:** PROFINET RT (Ethertype 0x8892) and IRT are unauthenticated by IEC 61784 spec; DCP (Discovery and Configuration Protocol) supports SetName/SetIP without authentication. EtherNet/IP I/O drops trust any CIP producer on the segment.

**Confirmed CVEs across vendors:** Public CVE volume is low — most attacks are *protocol-level abuse* (PROFINET DCP name/IP hijack, CIP I/O spoofing) rather than firmware CVEs. Siemens ET200SP firmware has periodic ProductCERT advisories (denial-of-service via crafted PROFINET frames). Research anchor: [Claroty Team82 research](https://claroty.com/team82/research).

**Top attack vector (MITRE ATT&CK ICS):** [T0830 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T0830/) — protocol-spoofed I/O updates that desynchronize the PLC's image of physical state.

## Group 5 — RTU / utility comms processor

**Direct attack surface:** DNP3 TCP/20000 (authenticated only when DNP3 Secure Authentication v5 is enabled — rarely is), IEC 60870-5-104 (TCP/2404), IEC 61850 MMS (TCP/102), embedded Linux on RTAC family with SSH/HTTPS management.

**Confirmed CVEs across vendors:**

| CVE | CVSS | Vendor | Product | Vector |
|---|---|---|---|---|
| [SEL RTAC advisories](https://selinc.com/support/security-advisories/) | varied | SEL | SEL-3530 / SEL-3555 RTAC | Multiple RTAC firmware issues (web UI, auth) — see SEL Security Advisories index |
| [SEL acSELerator advisories](https://selinc.com/support/security-advisories/) | varied | SEL | acSELerator family | Engineering-tool CVEs that feed RTAC config |
| [Schneider SCADAPack advisories](https://www.se.com/ww/en/work/support/cybersecurity/security-notifications.jsp) | varied | Schneider | SCADAPack 32/350/470/474 | PSIRT-listed DoS + auth issues |

**Top attack vector (MITRE ATT&CK ICS):** [T0855 Unauthorized Command Message](https://attack.mitre.org/techniques/T0855/) (DNP3 / IEC 104 / IEC 61850 control-direction frames).

## Group 6 — Protective relay / IED (substation)

**Direct attack surface:** IEC 61850 GOOSE (multicast, Ethertype 0x88B8 — *no auth, no encryption by base spec*) and MMS (TCP/102); DNP3; proprietary engineering protocols (SEL Fast Message, SIPROTEC DIGSI). Industroyer/Industroyer2 are the canonical adversary tooling.

**Confirmed CVEs across vendors:**

| CVE | CVSS | Vendor | Product | Vector |
|---|---|---|---|---|
| [SEL security advisories index](https://selinc.com/support/security-advisories/) | varied | SEL | 300/351/387/421/451/487/700/751 | Multiple firmware advisories — engineering protocol + web UI |
| [Siemens SIPROTEC advisories](https://cert-portal.siemens.com/productcert/) | varied | Siemens | SIPROTEC 4/5 | DIGSI engineering session and IEC 61850 stack CVEs |
| [Schneider Sepam/MiCOM advisories](https://www.se.com/ww/en/work/support/cybersecurity/security-notifications.jsp) | varied | Schneider | Sepam 20/40/80, MiCOM P-series | PSIRT-listed firmware/web CVEs |
| [ABB relay advisories](https://global.abb/group/en/technology/cyber-security/alerts-and-notifications) | varied | ABB | REF/REL/RET 615/620/630 series | PSIRT-listed IEC 61850 and web-server CVEs |
| [Industroyer2 (Dragos)](https://www.dragos.com/blog/industry-news/industroyer2-in-perspective/) | n/a | multi | IEC 61850 MMS / IEC 104 | Direct breaker-open commands, attributed to SANDWORM |

**Top attack vector (MITRE ATT&CK ICS):** [T0831 Manipulation of Control](https://attack.mitre.org/techniques/T0831/) via GOOSE injection or MMS control-block writes.

## Group 7 — Variable-frequency drive (VFD)

**Direct attack surface:** Embedded web servers (often unauthenticated or default-credentialed), Modbus TCP/502, CIP-Motion, PROFINET. Drives are L1 *actuators-with-firmware*: a tampered drive will under/over-speed a motor regardless of correct PLC commands.

**Confirmed CVEs across vendors:**

| CVE | CVSS | Vendor | Product | Vector |
|---|---|---|---|---|
| [CVE-2018-19282](https://nvd.nist.gov/vuln/detail/CVE-2018-19282) | 7.5 | Rockwell | PowerFlex 525 | Embedded web server — unauthenticated information disclosure / DoS |
| [Siemens SINAMICS advisories](https://cert-portal.siemens.com/productcert/) | varied | Siemens | SINAMICS V90 / G120 / S120 | Web server XSS, auth-bypass series via ProductCERT |
| [Schneider Altivar advisories](https://www.se.com/ww/en/work/support/cybersecurity/security-notifications.jsp) | varied | Schneider | Altivar Process / Machine | PSIRT-listed Modbus/web CVEs |

**Top attack vector (MITRE ATT&CK ICS):** [T0879 Damage to Property](https://attack.mitre.org/techniques/T0879/) via [T0836 Modify Parameter](https://attack.mitre.org/techniques/T0836/) on drive setpoints.

## Logging matrix (highest priority for this layer)

| # | Source | Event | What it catches | MITRE ATT&CK ICS |
|---|---|---|---|---|
| 1 | OT IDS (Nozomi / Dragos / Claroty / Forescout SilentDefense) | CIP `Service 0x4B` (Forward_Open) to controller object, `Class 0x6B/0x68` (program download), S7Comm function `0x1A/0x1B/0x28/0x29` (PLC stop/start, block download) | Logic download or run-mode change | [T0843](https://attack.mitre.org/techniques/T0843/) / [T0858](https://attack.mitre.org/techniques/T0858/) |
| 2 | OT IDS | Modbus function codes 8 (diagnostics), 43 (encapsulated UMAS), 90 (Schneider proprietary UMAS) from non-engineering host | Schneider UMAS auth-bypass attempts | [T0855](https://attack.mitre.org/techniques/T0855/) |
| 3 | PLC native audit log | Rockwell Logix Audit Source change-of-state; Siemens S7-1500 Security Event Log; Schneider M580 syslog | Mode key turned to REM, online edits, firmware update | [T0858](https://attack.mitre.org/techniques/T0858/) / [T0857](https://attack.mitre.org/techniques/T0857/) |
| 4 | Engineering workstation (L3.5) EDR | Studio 5000 / TIA Portal / Control Expert / DIGSI / acSELerator project file open from unusual path or after email/download | Evil PLC reverse-attack pattern | [T0817](https://attack.mitre.org/techniques/T0817/) / [T0890](https://attack.mitre.org/techniques/T0890/) |
| 5 | Switch / TAP | New MAC at PROFINET / EtherNet-IP segment; DCP SetName/SetIP frames; GOOSE traffic with new stNum jumps or duplicate goCBRef | Rogue device on L1 segment; GOOSE spoofing | [T0830](https://attack.mitre.org/techniques/T0830/) |
| 6 | Historian / SCADA | Setpoint write from non-operator workstation; setpoint write outside engineering window | Unauthorized command message to L1 | [T0855](https://attack.mitre.org/techniques/T0855/) / [T0831](https://attack.mitre.org/techniques/T0831/) |
| 7 | Network flow | New TCP/102, TCP/44818, TCP/502, TCP/20000, TCP/2404 talker; outbound from a PLC to anywhere | PLC-as-pivot (Evil PLC backchannel) | [T0884](https://attack.mitre.org/techniques/T0884/) / [T0822](https://attack.mitre.org/techniques/T0822/) |
| 8 | Process historian | View-vs-reality delta: PLC reports nominal but downstream tag (flow, level, current) diverges | CVE-2022-1161 / Stuxnet view-vs-bytecode mismatch | [T0832](https://attack.mitre.org/techniques/T0832/) |

**Secondary:**
- Vendor-native audit: Rockwell FactoryTalk AssetCentre disaster-recovery diff; Siemens TIA Portal Security Audit; Schneider EcoStruxure Cybersecurity Admin Expert (CAE) event log; SEL acSELerator audit trail.
- OT-native anomalies: PROFINET cycle-time jitter, CIP connection-count baseline drift, GOOSE stNum/sqNum baseline drift, drive parameter checksum baseline, IEC 61850 control-block (CTLNUM, OperOK) anomalies.
- Hardware: PLC keyswitch position telemetry (REM/PROG/RUN), chassis temperature/redundancy bit flips that often accompany firmware updates.

## Cross-layer pivots

1. **L3 EWS → L1 PLC (Stuxnet pattern).** A compromised engineering workstation at L3.5/L3 (Studio 5000, TIA Portal, Control Expert, DIGSI, acSELerator) issues authenticated logic downloads or parameter writes to the L1 controller. The session is indistinguishable from legitimate engineering. Detection lives on the EWS host (Logging matrix #4) and in CIP/S7Comm/UMAS payload inspection (#1, #2).
2. **L1 PLC → L0 actuator (the whole point).** A logic-modified PLC writes manipulated setpoints/outputs to drives, breakers, valves — directly moving physical state. PowerFlex/SINAMICS/Altivar drive over-speed and SIPROTEC/SEL/Sepam breaker trip are the canonical destructive results ([T0879](https://attack.mitre.org/techniques/T0879/)).
3. **L1 → L3 *Evil PLC* reverse-attack (Claroty Team82).** Attacker weaponizes the PLC project blob so that the next engineer to *open* a session is exploited and the engineering workstation is compromised — completing the loop in the opposite direction from Stuxnet. Applies to Rockwell, Siemens, Schneider engineering suites.
4. **L1 → L1 lateral via PROFINET / EtherNet-IP.** A compromised PLC abuses shared layer-2 to spoof PROFINET DCP, hijack ET200/POINT-I/O drops, or push CIP Forward_Open sessions to neighboring controllers and drives. The flat segment IS the trust boundary.
5. **L1 BPCS → SIS (TRITON pattern).** Where the Basic Process Control System shares network with the Safety Instrumented System (Triconex Tricon, ProSafe-RS, AADvance, ControlEdge SC), a compromised L1 controller becomes the staging point to push firmware/logic into the SIS — the XENOTIME 2017 Saudi petrochemical playbook (Triconex TriStation protocol abuse).

## Sources

- [CISA ICSA-21-056-03 — Rockwell Logix CVE-2021-22681](https://www.cisa.gov/news-events/ics-advisories/icsa-21-056-03)
- [CISA ICSA-23-136-04 — Rockwell CompactLogix 5370 CVE-2023-2071](https://www.cisa.gov/news-events/ics-advisories/icsa-23-136-04)
- [CISA AA24-038A — Volt Typhoon pre-positioning](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a)
- [NVD CVE-2022-1161 — Rockwell stealthy logic injection](https://nvd.nist.gov/vuln/detail/CVE-2022-1161)
- [NVD CVE-2018-7841 — Schneider Modicon UMAS](https://nvd.nist.gov/vuln/detail/CVE-2018-7841)
- [NVD CVE-2021-22779 — Schneider Modicon UMAS reservation bypass](https://nvd.nist.gov/vuln/detail/CVE-2021-22779)
- [NVD CVE-2023-3596 — Rockwell 1756-EN2T/EN3TR/EN4TR](https://nvd.nist.gov/vuln/detail/CVE-2023-3596)
- [NVD CVE-2024-6242 — Rockwell 1756-EN4TR trusted-slot](https://nvd.nist.gov/vuln/detail/CVE-2024-6242)
- [NVD CVE-2018-19282 — Rockwell PowerFlex 525](https://nvd.nist.gov/vuln/detail/CVE-2018-19282)
- [NVD CVE-2023-2071 — Rockwell CompactLogix 5370](https://nvd.nist.gov/vuln/detail/CVE-2023-2071)
- [Claroty Team82 research index](https://claroty.com/team82/research)
- [Claroty Evil PLC Attack whitepaper](https://claroty.com/team82/research/evil-plc-attack-weaponizing-plcs-to-attack-engineering-workstations)
- [Forescout OT:ICEFALL](https://www.forescout.com/research-labs/ot-icefall/)
- [Dragos Industroyer2 analysis](https://www.dragos.com/blog/industry-news/industroyer2-in-perspective/)
- [Dragos TRISIS / TRITON / XENOTIME analysis](https://www.dragos.com/threat/xenotime/)
- [Rockwell Trust Center — security advisories](https://www.rockwellautomation.com/en-us/trust-center/security-advisories.html)
- [Siemens ProductCERT](https://cert-portal.siemens.com/productcert/)
- [Schneider Electric PSIRT — cybersecurity notifications](https://www.se.com/ww/en/work/support/cybersecurity/security-notifications.jsp)
- [Honeywell Cybersecurity Resources](https://www.honeywell.com/us/en/cyber-security-resources)
- [SEL Security Advisories](https://selinc.com/support/security-advisories/)
- [ABB Cyber Security Alerts and Notifications](https://global.abb/group/en/technology/cyber-security/alerts-and-notifications)
- [MITRE ATT&CK for ICS — Techniques](https://attack.mitre.org/techniques/ics/)
- [ISA/IEC 62443 series overview](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards)
- [Purdue Enterprise Reference Architecture (ISA-95)](https://www.isa.org/standards-and-publications/isa-standards/isa-standards-committees/isa95)

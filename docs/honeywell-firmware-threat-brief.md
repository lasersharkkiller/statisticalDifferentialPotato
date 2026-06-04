# Honeywell Firmware Attack Surface & Detection Brief

**Scope:** Research-only brief covering 5 architecture classes spanning Honeywell Process Solutions (HPS), ControlEdge, Forge IIoT, Honeywell Building Technologies (HBT), and Safety Manager FSC. **Firmware extraction is pending** — no Honeywell binaries have been carved, hashed, or examined. Findings combine vendor PSIRT bulletins, CISA ICS advisories, Claroty Team82 ICEFALL research, and Dragos/Forescout DCS field telemetry. The brief primes the analyst queue for the moment Experion / ControlEdge / Saia / FSC firmware lands in `firmware-staging\Honeywell\`.

## Architecture grouping (drives the threat model, not the SKU)

| Class | Products | Stack | Catalog depth |
|---|---|---|---|
| **A. Experion PKS DCS controllers** | C300, C200/E, ACE-T, Series-C I/O, FIM | VxWorks 6.x / pSOS on PowerPC + proprietary CEE control engine, Control Data Access (CDA) over UDP/55555 | research only |
| **B. ControlEdge UOC / PLC / RTU** | UOC, ControlEdge 900 PLC, ControlEdge 2020 RTU | Embedded Linux (post-2018) + IEC-61131 runtime, OPC UA server, Modbus TCP, DNP3 (RTU) | research only |
| **C. Honeywell Forge IIoT** | Forge cloud connectors, on-prem edge agents (Forge Performance+) | Windows / containerized .NET, MQTT/AMQP to Azure backplane, on-prem ETL | research only |
| **D. Honeywell Building Technologies (HBT)** | Niagara-based controllers (Tridium-derived), Saia Burgess PCD3/PCD7, NOTIFIER fire panels, WEBs-AX | Java/Niagara Fox protocol (1911/4911), Saia S-Bus, BACnet/IP, proprietary fire-panel bus | research only |
| **E. Safety Manager FSC (SIS)** | Safety Manager R200+, FSC10/20, QPP-quad processor | Proprietary safety OS on quad-redundant CPU, FSC-SafeNet (UDP/51966), serial diagnostic | research only |

---

## Group A — Experion PKS DCS controllers (highest blast radius)

**Direct attack surface (per Honeywell HPS Network & Security Planning Guide + Claroty Team82 ICEFALL teardown):**

```
CDA (Control Data Access) UDP/55555 · FTE redundancy heartbeats · embedded HTTP diag · Modbus TCP/502 (gateway) · OPC Classic DCOM · ControlNet/EtherNet-IP on Series-C
```

C300/C200E controllers historically ship without firmware signing and accept boot images over CDA from any host trusted as a "supervisory" peer. ICEFALL showed the supervisory trust model is the bug: the *protocol* authenticates, the *firmware* doesn't.

**Confirmed advisories / CVE families:**

| Reference | Severity | Product | Vector | Status on the firmware you have |
|---|---|---|---|---|
| [ICSA-23-061-02](https://www.cisa.gov/news-events/ics-advisories/icsa-23-061-02) | Critical (CVSS 9.x) | Experion PKS / LX / PlantCruise | Multiple memory-corruption + auth-bypass bugs in CDA (ICEFALL "Crystallized Insecurity" cluster) | research only — verify on extraction |
| [Claroty Team82 — ICEFALL "Crystallized Insecurity" (2023)](https://claroty.com/team82/research/icefall-continues-broken-trust-broken-code) | varied | Experion C300 family | 9 ICEFALL-class flaws: unauth firmware update, unauth CDA writes, weak/no signing | research only |
| [Honeywell PSIRT — Experion PKS Server / ControlEdge bulletins](https://www.honeywell.com/us/en/product-security) | high | Experion PKS Server, ControlEdge | Hard-coded credentials in library → unauth RCE (family) | research only |
| [Honeywell PSIRT — Experion PKS C300 bulletins](https://www.honeywell.com/us/en/product-security) | high | Experion PKS C300 | Improper input validation in CDA → DoS / control disruption (family) | research only |

> Note: Specific CVE IDs in the ICSA-23-061-02 cluster (the "Crystallized Insecurity" disclosure) are catalogued by the linked CISA advisory — confirm exact CVE IDs against the advisory at extraction time before quoting them in customer-facing material.

**Top attack vector (MITRE ATT&CK ICS):** [T0857 System Firmware](https://attack.mitre.org/techniques/T0857/) via the unsigned CDA firmware-update path, chained with [T0836 Modify Parameter](https://attack.mitre.org/techniques/T0836/) to push tampered control logic to the C300 CEE.

---

## Group B — ControlEdge UOC / PLC / RTU

**Direct attack surface (per Honeywell ControlEdge Network Planning Guide):**

OPC UA TCP/4840 (server), Modbus TCP/502, DNP3 (RTU variant, TCP/20000), embedded HTTPS config UI, SSH (later firmware), IEC-61131 download protocol over proprietary TCP.

**Confirmed advisories / CVE families:**

| Reference | Severity | Product | Vector | Status |
|---|---|---|---|---|
| [ICSA-23-353-01 / ControlEdge UOC advisories on CISA](https://www.cisa.gov/news-events/cybersecurity-advisories/ics-advisories) | high | ControlEdge UOC / VirtualUOC | Cluster — improper authentication, privilege management, cleartext transmission on engineering link | research only |
| [Honeywell PSIRT — ControlEdge bulletins](https://www.honeywell.com/us/en/product-security) | high | ControlEdge UOC, RTU | Improper auth on engineering interface → config tamper (family) | research only |
| [Honeywell PSIRT — ControlEdge VirtualUOC bulletins](https://www.honeywell.com/us/en/product-security) | medium-high | ControlEdge VirtualUOC, UOC | Improper privilege management → controller config modification; cleartext sensitive info on engineering link | research only |

> Note: ControlEdge UOC CVE IDs in the 2023 disclosure cycle were issued by Honeywell PSIRT and aggregated into a CISA ICSA. Confirm the exact CVE numbers and ICSA identifier directly from the CISA advisory index at extraction time rather than quoting from memory.

**Top attack vector (MITRE ATT&CK ICS):** [T0843 Program Download](https://attack.mitre.org/techniques/T0843/) — the IEC-61131 download path on UOC is the standard ICS persistence vector; the authentication weaknesses in the 2023 ControlEdge cluster make it reachable without strong authentication on affected firmware.

---

## Group C — Honeywell Forge IIoT (cloud + on-prem agent)

Forge is the "soft" pivot: customer-side agents brokering plant data into Azure-hosted analytics. Attack surface is closer to a normal Windows/Linux app stack than a controller.

**Direct attack surface:** on-prem Forge Performance+ historical/edge agents (Windows services), MQTT/AMQPS outbound to Honeywell Forge Azure tenants, optional inbound HTTPS for the local operator portal. Historically also: an OPC UA client into Experion, which is the bridge between Forge and Group A.

**Confirmed advisories / CVE families:**

| Reference | Severity | Product | Vector | Status |
|---|---|---|---|---|
| [CVE-2021-38397](https://nvd.nist.gov/vuln/detail/CVE-2021-38397) | 10.0 | Experion PKS / LX / PlantCruise | Unrestricted file upload → unauth RCE | research only |
| [CVE-2021-38395](https://nvd.nist.gov/vuln/detail/CVE-2021-38395) | 9.1 | Experion PKS / LX / PlantCruise | Argument injection in a Honeywell-signed binary | research only |
| [ICSA-21-294-02](https://www.cisa.gov/news-events/ics-advisories/icsa-21-294-02) | Critical | Experion PKS Server / engineering host | Cluster of upload / argument-injection / DLL-hijack flaws | research only |

**Top attack vector (MITRE ATT&CK ICS):** [T0817 Drive-by Compromise](https://attack.mitre.org/techniques/T0817/) of the Windows engineering workstation hosting the Forge edge agent, then OPC UA pivot into the Experion CEE.

---

## Group D — Honeywell Building Technologies (HBT)

Niagara-derived controllers (Honeywell WEBs-AX is a Tridium OEM), Saia Burgess PCD3/PCD7 PLCs, NOTIFIER fire alarm panels. Same protocol family that Forescout's OT:ICEFALL / "Niagara" research repeatedly demolished.

**Direct attack surface:** Niagara Fox protocol TCP/1911 + Foxs (TLS) TCP/4911, Saia S-Bus UDP/5050, BACnet/IP UDP/47808, embedded HTTP/HTTPS station UI, default `tridium`/`niagara`/`Saia` credentials.

**Confirmed advisories / CVE families:**

| Reference | Severity | Product | Vector | Status |
|---|---|---|---|---|
| [Tridium Niagara Framework advisories (CISA / vendor)](https://www.cisa.gov/news-events/cybersecurity-advisories/ics-advisories) | high | Niagara Framework (Tridium / OEM'd by HBT WEBs-AX) | Path traversal / information disclosure family | research only |
| [CVE-2020-24693](https://nvd.nist.gov/vuln/detail/CVE-2020-24693) | high | Saia PCD controllers | Unauthenticated download of cleartext password file (S-Bus) | research only |
| [Forescout — NUCLEUS:13](https://www.forescout.com/blog/nucleus13-mitigation-recommendations-for-nucleus-tcp-ip-stack-vulnerabilities/) | varied | Nucleus RTOS used in some HBT fire/security panels | TCP/IP stack memory corruption | research only |
| [ICSA-22-167-01 — Honeywell Alerton Ascent Control Module](https://www.cisa.gov/news-events/ics-advisories/icsa-22-167-01) | high | Honeywell Alerton (HBT) | Authentication / authorization weaknesses on BACnet control module | research only |

> Note: Niagara Framework (Tridium) carries its own multi-year CVE history — when WEBs-AX firmware is extracted, cross-walk against the current Tridium security bulletin list rather than relying on a single CVE ID quoted from memory.

**Top attack vector (MITRE ATT&CK ICS):** [T0859 Valid Accounts](https://attack.mitre.org/techniques/T0859/) — HBT environments routinely keep factory `tridium/niagara` and Saia default credentials ([T0812 Default Credentials](https://attack.mitre.org/techniques/T0812/)). Internet-exposed Niagara stations are a recurring Shodan finding.

---

## Group E — Safety Manager FSC (SIS)

The crown jewel: Safety Instrumented Systems. A successful tamper here is the [TRITON / TRISIS](https://www.dragos.com/threat/trisis/) class of incident (FireEye / Dragos 2017 — different vendor, Schneider Electric Triconex Tricon, but identical impact model).

**Direct attack surface:** FSC-SafeNet (UDP/51966), SafeBuilder engineering link (proprietary TCP), serial diagnostic ports, mandatory physical key switch for "PROGRAM" mode (the operational control that Triconex *also* relied on and that *was bypassed* in TRITON because the key was left in PROGRAM).

**Confirmed advisories / CVE families:**

| Reference | Severity | Product | Vector | Status |
|---|---|---|---|---|
| [CVE-2022-30313](https://nvd.nist.gov/vuln/detail/CVE-2022-30313) | high | Safety Manager FSC | Use of unauthenticated FSC SafeNet protocol — diagnostic/control commands accepted without authentication | research only |
| [CVE-2022-30314](https://nvd.nist.gov/vuln/detail/CVE-2022-30314) | high | Safety Manager FSC | Improper authentication / firmware update path on FSC | research only |
| [CVE-2022-30315](https://nvd.nist.gov/vuln/detail/CVE-2022-30315) | high | Safety Manager FSC | Use of insufficiently protected credentials / file-parsing memory corruption | research only |
| [ICSA-22-179-02 — Honeywell Safety Manager (Claroty ICEFALL)](https://www.cisa.gov/news-events/ics-advisories/icsa-22-179-02) | high | Safety Manager R145.1–R152.2 | Cluster — Claroty Team82 ICEFALL findings on FSC | research only |

> Note: The exact CVSS scores and one-line summaries for the CVE-2022-30313/14/15 trio differ slightly between NVD, Honeywell PSIRT, and Claroty's writeup. Treat the table above as a pointer to the advisory cluster, not as the authoritative one-line per CVE — confirm at extraction time.

**Top attack vector (MITRE ATT&CK ICS):** [T0858 Change Operating Mode](https://attack.mitre.org/techniques/T0858/) — flip the SIS out of RUN, then [T0839 Module Firmware](https://attack.mitre.org/techniques/T0839/) to push a malicious logic block. Key-switch state is the single physical control between attacker and a TRITON-grade outcome.

---

## Logging matrix (highest priority)

Top 8 — ordered by detection value per ingest dollar:

| # | Source | Event | What it catches | MITRE ATT&CK ICS |
|---|---|---|---|---|
| 1 | **Experion PKS server audit log** | `OperatorLogin` followed by `PointParameterChange` from non-engineering station | Operator-account abuse | [T0859 Valid Accounts](https://attack.mitre.org/techniques/T0859/) |
| 2 | Experion `CDAEvent` / system event journal | `Firmware download` to C300/C200E | Unsigned-firmware push | [T0857 System Firmware](https://attack.mitre.org/techniques/T0857/) |
| 3 | **Network IDS (Zeek/Suricata with ICS protocol parsers)** | CDA UDP/55555 from outside Level-2 supervisory VLAN | ICEFALL-class lateral movement | [T0843 Program Download](https://attack.mitre.org/techniques/T0843/) |
| 4 | Network IDS | OPC UA `CreateMonitoredItems` / `Write` from non-engineering host to UOC | ControlEdge config tamper | [T0836 Modify Parameter](https://attack.mitre.org/techniques/T0836/) |
| 5 | Network IDS | Modbus FC 5/6/15/16 (write coils/registers) on ControlEdge RTU / Series-C gateway | Control-logic tamper | [T0833 Modify Control Logic](https://attack.mitre.org/techniques/T0833/) |
| 6 | **Niagara station audit (HBT)** | `fox:program` / station file write from non-engineering account | HBT/Niagara persistence | [T0889 Modify Program](https://attack.mitre.org/techniques/T0889/) |
| 7 | **Safety Manager FSC diagnostic log + key-switch position telemetry** | Key-switch state change to PROGRAM during unscheduled window | SIS pre-tamper precursor | [T0858 Change Operating Mode](https://attack.mitre.org/techniques/T0858/) |
| 8 | Sysmon on engineering workstations | EventID 1 where parent = `ConfigurationStudio.exe` / `SafeBuilder.exe` and child not on Honeywell allow-list | Forge / SafeBuilder host compromise | T1059 (Enterprise) |

**Secondary:**

- Firewall egress: any outbound from Level-2 / Level-3.5 DMZ to non-Honeywell destinations besides the documented Forge Azure tenant endpoints. Forge agents have a *narrow* known-good list — anything else is a pivot.
- Honeywell Experion native audit: enable **Operator Action Journal** + **System Event Journal** + **Control Builder change tracking** and forward to SIEM via syslog or OPC A&E.
- HBT-side: Niagara station has a built-in `AuditHistory` and `LogHistory` — point both at SIEM. Saia PCD has only sparse logging; compensate with network IDS.
- OT-native process anomalies: setpoint changes outside operator shift windows, valve / pump commands without corresponding HMI operator action, SIS bypass-counter increments, redundancy-pair desync events on FTE.

---

## Specific zero-day-ish concerns for your dataset

1. **No Honeywell firmware extracted yet — extraction is the unblocking step.** Until C300, UOC, and FSC blobs are in `firmware-staging\Honeywell\`, every claim above is research-derived. Priority extraction order: (a) Safety Manager FSC (highest consequence, ICEFALL-disclosed), (b) C300 (largest installed base), (c) ControlEdge UOC (newest, least public scrutiny).

2. **ICEFALL is structural, not patch-level.** Claroty's thesis was that DCS protocols trust *by design* — patching individual CVEs (the CVE-2022-30313/14/15 trio) doesn't fix the trust model. Plan to diff post-2022 FSC firmware against pre-ICEFALL versions to see what actually changed in the SafeNet handler, not just what was renamed in release notes.

3. **Forge OPC UA bridge is the IT→OT seam.** When the Forge edge-agent extraction happens, prioritize the OPC UA client configuration — that's the line where a normal Windows compromise becomes a C300 setpoint write. Look for hard-coded service accounts and trust-list bypass.

4. **HBT/Niagara reuse means Honeywell inherits every Tridium CVE.** When Niagara WEBs-AX firmware arrives, do not treat it as a Honeywell-only artifact — diff it against public Tridium Niagara 4.x to see which Tridium patches HBT has actually back-ported.

---

## Sources

- [Claroty Team82 — OT:ICEFALL (2022)](https://claroty.com/team82/research/icefall-56-vulnerabilities-caused-by-insecure-by-design-practices-in-ot)
- [Claroty Team82 — ICEFALL Continues: Broken Trust, Broken Code (Honeywell Experion)](https://claroty.com/team82/research/icefall-continues-broken-trust-broken-code)
- [Honeywell PSIRT / Security Notifications](https://www.honeywell.com/us/en/product-security)
- [CISA ICSA-22-179-02 — Honeywell Safety Manager (FSC)](https://www.cisa.gov/news-events/ics-advisories/icsa-22-179-02)
- [CISA ICSA-23-061-02 — Honeywell Experion PKS / LX / PlantCruise](https://www.cisa.gov/news-events/ics-advisories/icsa-23-061-02)
- [CISA ICS Advisories index — ControlEdge UOC / VirtualUOC](https://www.cisa.gov/news-events/cybersecurity-advisories/ics-advisories)
- [CISA ICSA-21-294-02 — Honeywell Experion PKS file upload / argument injection](https://www.cisa.gov/news-events/ics-advisories/icsa-21-294-02)
- [CISA ICSA-22-167-01 — Honeywell Alerton (HBT)](https://www.cisa.gov/news-events/ics-advisories/icsa-22-167-01)
- [Dragos — TRISIS / TRITON malware analysis (SIS attack archetype)](https://www.dragos.com/threat/trisis/)
- [Forescout — NUCLEUS:13 RTOS vulnerabilities](https://www.forescout.com/blog/nucleus13-mitigation-recommendations-for-nucleus-tcp-ip-stack-vulnerabilities/)
- [Forescout — OT:ICEFALL companion research](https://www.forescout.com/blog/ot-icefall-the-legacy-of-insecure-by-design-and-its-implications-for-certifications-and-risk-management/)
- [MITRE ATT&CK for ICS — Impair Process Control (TA0106)](https://attack.mitre.org/tactics/TA0106/)
- [MITRE ATT&CK for ICS — T0857 System Firmware](https://attack.mitre.org/techniques/T0857/)
- [MITRE ATT&CK for ICS — T0858 Change Operating Mode](https://attack.mitre.org/techniques/T0858/)
- [MITRE ATT&CK for ICS — T0812 Default Credentials](https://attack.mitre.org/techniques/T0812/)
- [CISA/NSA/FBI/ASD — Best Practices for Event Logging and Threat Detection (2024)](https://www.cisa.gov/resources-tools/resources/best-practices-event-logging-and-threat-detection)

# Purdue Site Operations (L3) — Cross-Vendor Threat & Detection Brief

**Scope:** This brief covers Purdue Level 3 (Site Operations) — the "domain controller" tier of OT. Roles in scope: SCADA servers, plant historians, engineering workstations (EWS), asset/configuration management servers, power-monitoring SCADA, substation Industrial PCs, console aggregators, and Windows-side power-management agents. Source material is aggregated from the [Eaton brief](eaton-firmware-threat-brief.md) (Group F Windows-side), [APC brief](apc-firmware-threat-brief.md) (Group D PowerChute / EcoStruxure IT), [Vertiv brief](vertiv-firmware-threat-brief.md) (Group A ACS 8000 + Group F DSView/Trellis), [SEL brief](sel-firmware-threat-brief.md) (Group A SEL Industrial PCs + Group B acSELerator / BaRT / Compass / VPS), [Siemens brief](siemens-firmware-threat-brief.md) (TIA Portal V21 + WinCC), [Honeywell brief](honeywell-firmware-threat-brief.md) (Experion PKS + Forge), [Schneider brief](schneider-firmware-threat-brief.md) (Control Expert, Citect, Power Operation, Vijeo), and [Rockwell brief](rockwell-firmware-threat-brief.md) (Groups D + E: FactoryTalk + Studio 5000). Honeywell L3 content is research-only — firmware extraction is pending and is explicitly marked as such throughout.

## Architecture grouping (organized by ROLE within this layer, not by vendor)

| Class (role) | Products (cross-vendor) | Stack | Catalog depth |
|---|---|---|---|
| **A. SCADA / HMI Server** | Siemens WinCC + WinCC Unified; Rockwell FactoryTalk View SE / View ME; Schneider Citect SCADA / Plant SCADA; Schneider EcoStruxure Power Operation / Power Monitoring Expert; Schneider Vijeo Designer (Operator Terminal Expert); Honeywell Experion PKS Server | Windows Server + .NET + MSSQL + Tomcat / IIS; RNA / CTAPI / OPC UA backends | see [siemens brief Group B](siemens-firmware-threat-brief.md), [rockwell brief Group D](rockwell-firmware-threat-brief.md), [schneider brief Groups B/D/E](schneider-firmware-threat-brief.md), [honeywell brief Group A](honeywell-firmware-threat-brief.md) |
| **B. Engineering Workstation (EWS)** | Siemens TIA Portal V21 (STEP7 + Openness + ALM); Rockwell Studio 5000 + RSLinx + FactoryTalk Linx; Schneider EcoStruxure Control Expert; SEL acSELerator QuickSet + BaRT + Compass + Virtual Port Service 5828; SEL-3355-2 / 3355 / 3300 Industrial PCs | Windows 10 IoT / Win Server, .NET, MSI/MSP, vendor IDE + project-file handlers | see [siemens brief Group A](siemens-firmware-threat-brief.md), [rockwell brief Group E](rockwell-firmware-threat-brief.md), [schneider brief Group B](schneider-firmware-threat-brief.md), [sel brief Groups A+B](sel-firmware-threat-brief.md) |
| **C. Asset / Config Management Server** | Rockwell FactoryTalk AssetCentre; Rockwell FactoryTalk Historian SE; Rockwell FactoryTalk Linx Gateway; Vertiv Avocent DSView; Vertiv Trellis Platform; Vertiv Environet Alert; Vertiv Power Insight | Windows Server + MSSQL / Postgres + Java/Tomcat, holds crown-jewel PLC project archives + credentials | see [rockwell brief Group D](rockwell-firmware-threat-brief.md), [vertiv brief Group F](vertiv-firmware-threat-brief.md) |
| **D. Windows-side Power-Mgmt Agent** | Eaton UPS Companion, Eaton IPM/IPP, Eaton setUPS, Eaton MIBs/PX-UPS/RNDIS drivers; APC PowerChute Network Shutdown, PowerChute Business / Personal; Schneider EcoStruxure IT Gateway / Expert | Windows .NET / Java services that broker between OS and UPS NMC | see [eaton brief Group F](eaton-firmware-threat-brief.md), [apc brief Group D](apc-firmware-threat-brief.md) |
| **E. Console / Serial Aggregator** | Vertiv Avocent ACS 8000 (4/8/16/32/48-port); SEL Virtual Port Service 5828 (serial-over-TCP) | ARM Linux + busybox + portmgr / cycladesd; Windows TCP-serial bridge | see [vertiv brief Group A](vertiv-firmware-threat-brief.md), [sel brief Group B](sel-firmware-threat-brief.md) |

---

## Group A — SCADA / HMI Server

**Direct attack surface (cross-vendor):**

```
WinCC CCEServer/CCAgent · WinCC Unified Web Runtime (HTTPS/443) · OPC UA (TCP/4840) ·
MSSQL backend (Stuxnet's path) · Rockwell RNA + FactoryTalk Linx (TCP/3060 + dynamic) ·
Citect CTAPI (TCP/5482) + IOServer · Cicode runtime · Experion Control Data Access (UDP/55555) ·
WebNavigator IIS app · Schneider OFS OPC server · Vijeo Designer runtime download (TCP/6000)
```

**Confirmed CVEs across vendors:**

| CVE | CVSS | Vendor | Product | Vector |
|---|---|---|---|---|
| [Siemens ProductCERT WinCC web-client auth class](https://cert-portal.siemens.com/productcert/html/index.html) | 9.x | Siemens | WinCC | Improper auth in WinCC web client (V7.x family) |
| [Siemens ProductCERT WinCC Unified Web Runtime class](https://cert-portal.siemens.com/productcert/html/index.html) | 8.x | Siemens | WinCC Unified | Path traversal in Unified Web Runtime |
| [Siemens ProductCERT WinCC installer DLL-hijack class](https://cert-portal.siemens.com/productcert/html/index.html) | 7.8 | Siemens | WinCC | DLL hijack on install |
| [CVE-2024-21914](https://nvd.nist.gov/vuln/detail/CVE-2024-21914) (ICSA-24-018-02) | 6.5 | Rockwell | FactoryTalk View SE | DoS via crafted message |
| [Rockwell PSIRT — View SE project-import RCE family](https://www.rockwellautomation.com/en-us/trust-center/security-advisories.html) | high | Rockwell | FactoryTalk View SE | RCE via crafted HMI project import |
| [ICSA-23-193-01](https://www.cisa.gov/news-events/ics-advisories/icsa-23-193-01) | varies | Rockwell | FactoryTalk View ME | Multiple unauth issues |
| [CVE-2008-2639](https://nvd.nist.gov/vuln/detail/CVE-2008-2639) | 10.0 | Schneider | CitectSCADA | ODBC server stack overflow (Core Security) |
| [CVE-2020-7548](https://nvd.nist.gov/vuln/detail/CVE-2020-7548) | 7.8 | Schneider | Citect Anywhere | Auth bypass |
| [Schneider PSIRT — Plant SCADA path traversal family](https://www.se.com/ww/en/work/support/cybersecurity/vulnerability-policy.jsp) | n/a | Schneider | Plant SCADA (EcoStruxure) | Authenticated path traversal |
| [CVE-2021-22722](https://nvd.nist.gov/vuln/detail/CVE-2021-22722) | 7.5 | Schneider | EcoStruxure Power Monitoring Expert | Improper privilege management |
| [Schneider PSIRT — PME report-generator RCE family](https://www.se.com/ww/en/work/support/cybersecurity/vulnerability-policy.jsp) | n/a | Schneider | Power Monitoring Expert | RCE via report generator |
| [CVE-2021-38397](https://nvd.nist.gov/vuln/detail/CVE-2021-38397) | 10.0 | Honeywell | Experion PKS / LX / PlantCruise | Unrestricted file upload → unauth RCE (research only) |
| [CVE-2021-38395](https://nvd.nist.gov/vuln/detail/CVE-2021-38395) | 9.1 | Honeywell | Experion PKS / LX / PlantCruise | Argument injection in Honeywell-signed binary (research only) |
| [ICSA-21-294-02](https://www.cisa.gov/news-events/ics-advisories/icsa-21-294-02) | Critical | Honeywell | Experion PKS Server | Upload / argument injection / DLL-hijack cluster (research only) |
| [ICSA-23-061-02](https://www.cisa.gov/news-events/ics-advisories/icsa-23-061-02) | 9.x | Honeywell | Experion PKS / LX / PlantCruise | ICEFALL "Crystallized Insecurity" cluster (research only) |

**Top attack vector (MITRE ATT&CK ICS):** [T0832 Manipulation of View](https://attack.mitre.org/techniques/T0832/) + [T0859 Valid Accounts](https://attack.mitre.org/techniques/T0859/) on the SCADA SQL backend (the Stuxnet WinCC path) — tamper tag values shown to the operator while logic runs free.

---

## Group B — Engineering Workstation (EWS)

**Direct attack surface (cross-vendor):**

```
TIA Portal Openness API (.NET, PowerShell-callable) · Automation License Manager (TCP/4410) ·
project-file handlers (.ap21/.zap21, .stu/.xef/.zef, .ACD, .aclx, .RDB) · Studio 5000 + RSLinx ·
FactoryTalk Services Platform · Control Expert + Vijeo Designer · acSELerator QuickSet ·
SEL-BaRT (Fast Message + ASCII serial-over-TCP firmware push) · SEL Compass updater ·
Virtual Port Service 5828 TCP listener (serial bridge) · SMB · RDP · WinRM
```

**Confirmed CVEs across vendors:**

| CVE | CVSS | Vendor | Product | Vector |
|---|---|---|---|---|
| [CVE-2024-49775](https://nvd.nist.gov/vuln/detail/CVE-2024-49775) | 7.8 | Siemens | TIA Portal (UMC) | Local privilege escalation via User Management Component |
| [Siemens ProductCERT TIA Portal Openness class](https://cert-portal.siemens.com/productcert/html/index.html) | 7.x | Siemens | TIA Portal Openness | Project-file deserialization → code exec |
| [Siemens ProductCERT Automation License Manager class](https://cert-portal.siemens.com/productcert/html/index.html) | 7.x | Siemens | Automation License Manager | LPE on ALM service |
| [CVE-2021-22681](https://www.cisa.gov/news-events/ics-advisories/icsa-21-056-03) | 10.0 | Rockwell | Logix / Studio 5000 | Hardcoded crypto key → remote auth bypass to controller |
| [CVE-2022-1161](https://claroty.com/team82/research/stealthy-rockwell-plc-hack) | 7.7 | Rockwell | Studio 5000 / CompactLogix 5380, ControlLogix 5580 | Stealth logic injection (view ≠ controller bytecode) |
| [CVE-2024-45824](https://www.rockwellautomation.com/en-us/trust-center/security-advisories.html) | 9.8 | Rockwell | FactoryTalk View ME / Studio 5000 | Remote code injection via crafted project |
| [CVE-2023-46290](https://nvd.nist.gov/vuln/detail/CVE-2023-46290) | 7.5 | Rockwell | FactoryTalk Services Platform | Improper auth, unauth user enumeration |
| [CVE-2024-21915](https://www.cisa.gov/news-events/ics-advisories/icsa-24-018-01) | 9.8 | Rockwell | FactoryTalk Service Platform | Privilege escalation, affects Logix sessions |
| [Rockwell PSIRT — Studio 5000 DLL hijack family](https://www.rockwellautomation.com/en-us/trust-center/security-advisories.html) | high | Rockwell | Studio 5000 Logix Designer | DLL hijack on launch |
| [Claroty "Evil PLC" — Studio 5000](https://claroty.com/team82/research/white-papers/evil-plc-attack-weaponizing-plcs) | n/a | Rockwell | Studio 5000 | Weaponized PLC project file → RCE on EWS |
| [CVE-2020-7559](https://nvd.nist.gov/vuln/detail/CVE-2020-7559) | 7.8 | Schneider | EcoStruxure Control Expert | DLL hijack at engineering workstation startup |
| [CVE-2021-22779](https://nvd.nist.gov/vuln/detail/CVE-2021-22779) | 8.1 | Schneider | Control Expert ↔ PLC | UMAS session hijack from EWS (ModiPwn) |
| [Schneider PSIRT 2023 Control Expert project-file RCE](https://www.se.com/ww/en/work/support/cybersecurity/vulnerability-policy.jsp) | n/a | Schneider | EcoStruxure Control Expert | RCE via crafted `.stu` project (Armis-class) |
| [Claroty "Evil PLC" — Control Expert](https://claroty.com/team82/research/evil-plc-attack-weaponizing-plcs) | n/a | Schneider | Control Expert | Weaponized PLC pushes payload to EWS on upload |
| [ICSA-23-131-08](https://www.cisa.gov/news-events/ics-advisories/icsa-23-131-08) | n/a | SEL | acSELerator QuickSet (SEL-5030), RTAC (SEL-5033), ICS Studio (SEL-5045) | CWE-276 insecure perms + CWE-22 path traversal + CWE-269 improper privilege mgmt |
| [SEL Security Advisories index](https://selinc.com/support/security-advisories/) | n/a | SEL | acSELerator QuickSet | XXE on `.aclx` import → local file disclosure / SSRF |
| [SEL Security Advisories index](https://selinc.com/support/security-advisories/) | n/a | SEL | SEL-5037 Grid Configurator | Cleartext / weakly-protected credential storage |
| [SEL Security Advisories index](https://selinc.com/support/security-advisories/) | n/a | SEL | acSELerator Architect (SEL-5032) | Authorization / project-import handling weaknesses |
| [ICSA-23-194-02](https://www.cisa.gov/news-events/ics-advisories/icsa-23-194-02) | n/a | SEL | RTAC + co-installed mgmt binaries | Multiple weaknesses in RTAC firmware and mgmt interfaces |

**Top attack vector (MITRE ATT&CK ICS):** [T0843 Program Download](https://attack.mitre.org/techniques/T0843/) — the EWS is the single highest-value pivot in any OT network because it holds project files and the credentials/certs to push logic. Chains with [T0873 Project File Infection](https://attack.mitre.org/techniques/T0873/) and [T0853 Scripting](https://attack.mitre.org/techniques/T0853/) (Openness API / Cicode payloads in tampered project archives — Stuxnet shape, modernised). Forescout's OT:ICEFALL and Claroty's "Evil PLC" both centred this surface.

---

## Group C — Asset / Config Management Server

**Direct attack surface (cross-vendor):**

```
FactoryTalk Directory + AssetCentre (project archives + encrypted PLC credential vault) ·
FactoryTalk Historian SE · FactoryTalk Linx Gateway (TCP/3060) · DSView mgmt-plane (Java) ·
Trellis Platform (Apache Tomcat + Postgres) · Environet Alert · Power Insight ·
MSSQL backends · IIS / Tomcat admin endpoints · OPC HDA + A&E
```

**Confirmed CVEs across vendors:**

| CVE | CVSS | Vendor | Product | Vector |
|---|---|---|---|---|
| [Rockwell PSIRT — AssetCentre deserialization RCE family](https://www.rockwellautomation.com/en-us/trust-center/security-advisories.html) | high | Rockwell | FactoryTalk AssetCentre | RCE via deserialization of project archive |
| [CVE-2024-21915](https://www.cisa.gov/news-events/ics-advisories/icsa-24-018-01) | 9.8 | Rockwell | FactoryTalk Service Platform | Privilege escalation across FT user store |
| [Vertiv PSIRT — Avocent DSView advisories](https://www.vertiv.com/en-us/support/security-advisories/) | n/a | Vertiv | Avocent DSView | Pre-auth deserialization / RCE per vendor advisory |
| [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) | 10.0 | Vertiv | Trellis 5.x (Tomcat) | Apache Log4j JNDI RCE (Log4Shell) on unpatched Trellis |
| [Synopsys CyRC — Avocent / HPE KVM advisory](https://www.synopsys.com/blogs/software-security/) | n/a | Vertiv | Avocent KVM family (shared firmware) | Hardcoded creds + buffer overflow (unauth → root) |

**Top attack vector (MITRE ATT&CK ICS):** [T0866 Exploitation of Remote Services](https://attack.mitre.org/techniques/T0866/) → [T0852 Screen Capture / Theft of Operational Information](https://attack.mitre.org/techniques/T0852/). AssetCentre / DSView / Trellis hold credentials and trust to every device they manage — single compromise yields every PLC password and KVM session in the plant.

---

## Group D — Windows-side Power-Management Agent

**Direct attack surface (cross-vendor):**

```
Eaton setUPS.exe / IPM / UPS Companion installer + LocalSystem services ·
APC PowerChute Java mgmt agent + IIS local web mgmt · EcoStruxure IT Gateway (Java) ·
HTTPS / SNMP outbound to NMC fleet · DLL search-order surface in installer paths
```

**Confirmed CVEs across vendors:**

| CVE | CVSS | Vendor | Product | Vector |
|---|---|---|---|---|
| [CVE-2025-59887](https://www.thehackerwire.com/eaton-ups-companion-installer-rce-cve-2025-59887/) | 8.6 | Eaton | UPS Companion <3.0 (all versions) | DLL hijack RCE in installer |
| [CVE-2025-59888](https://nvd.nist.gov/vuln/detail/CVE-2025-59888) | 6.7 | Eaton | UPS Companion <3.0 | Unquoted service path → SYSTEM |
| [CVE-2020-6650](https://github.com/RavSS/Eaton-UPS-Companion-Exploit) | 7.x | Eaton | UPS Companion <1.06 | Plaintext HTTP update + `eval()` of response |
| [IPM pre-1.69 (ICSA-21-110-06)](https://www.cisa.gov/news-events/ics-advisories/icsa-21-110-06) | 9.8 | Eaton | Intelligent Power Manager | Unauth eval injection RCE + unauth file upload + SQLi |
| [CVE-2021-22812](https://nvd.nist.gov/vuln/detail/CVE-2021-22812) | 9.8 | APC / Schneider | PowerChute Business Edition | Unauth RCE via deserialization in management agent |
| [CVE-2021-22813](https://nvd.nist.gov/vuln/detail/CVE-2021-22813) | 7.5 | APC / Schneider | PowerChute Business Edition | Auth bypass on local web mgmt |
| [Schneider PSIRT — PowerChute Serial Shutdown LPE class](https://www.se.com/ww/en/work/support/cybersecurity/security-notifications.jsp) | 7.x | APC / Schneider | PowerChute Serial Shutdown | Local privesc via insecure dir / service-permissions |
| [Schneider PSIRT — EcoStruxure IT Gateway mgmt-plane class](https://www.se.com/ww/en/work/support/cybersecurity/security-notifications.jsp) | 7.x | APC / Schneider | EcoStruxure IT Gateway | Auth / management-plane vuln class |

**Top attack vector (MITRE ATT&CK ICS):** [T1574.001 DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001/) (Enterprise) chained into [T0857 System Firmware](https://attack.mitre.org/techniques/T0857/) — admin host runs a tampered installer → SYSTEM → push tampered firmware via the legitimate update channel to every UPS NMC the agent trusts.

---

## Group E — Console / Serial Aggregator

**Direct attack surface (cross-vendor):**

```
Vertiv ACS 8000: sshd · lighttpd HTTPS · portslave / cycladesd serial multiplexer ·
snmpd v1/v2c/v3 · strongSwan ipsec · root/admin default accounts.
SEL VPS 5828: Windows TCP listener bridging to local COM ports · default bind / no auth class.
```

**Confirmed CVEs across vendors:**

| CVE | CVSS | Vendor | Product | Vector |
|---|---|---|---|---|
| [ICSA-23-285-06](https://www.cisa.gov/news-events/ics-advisories/icsa-23-285-06) | n/a | Vertiv | Avocent ACS 8000 firmware ≤3.3.x | OS command injection + auth bypass + hardcoded root cred |
| [Vertiv PSIRT — ACS 8000 advisories](https://www.vertiv.com/en-us/support/security-advisories/) | n/a | Vertiv | Avocent ACS 8000 | Hardcoded credential / insecure default |
| [Nozomi Networks Labs — ACS 8000 research](https://www.nozominetworks.com/blog/) | n/a | Vertiv | Avocent ACS 8000 | Chained unauth → root via web UI + serial daemon |
| [ICSA-23-131-08](https://www.cisa.gov/news-events/ics-advisories/icsa-23-131-08) | n/a | SEL | Virtual Port Service 5828 (co-installed mgmt class) | DLL search-order / writable install-path → LPE to SYSTEM (acSELerator family covered by same advisory) |

**Top attack vector (MITRE ATT&CK ICS):** [T0822 External Remote Services](https://attack.mitre.org/techniques/T0822/) + [T0886 Remote Services](https://attack.mitre.org/techniques/T0886/) — every serial port the aggregator brokers becomes a console-level pivot into a downstream device, bypassing that device's own network ACLs. Honour ICSA-23-285-06's "blast radius = every cabled device" framing.

---

## Logging matrix (highest priority for this layer)

| # | Source | Event | What it catches | MITRE ATT&CK ICS |
|---|---|---|---|---|
| 1 | **Sysmon on EWS hosts (TIA Portal / Studio 5000 / Control Expert / acSELerator / BaRT)** | EventID 1 ProcessCreate where ParentImage = `Siemens.Automation.*` / `RSLogix5000.exe` / `Studio5000.exe` / `RSLinx.exe` / `ControlExpert.exe` / `AcSELeratorQuickSet.exe` / `BaRT.exe` / `Compass.exe` AND child = `cmd.exe` / `powershell.exe` / `rundll32.exe` | Evil-PLC / Openness-API abuse / scripted PLC push | [T0853 Scripting](https://attack.mitre.org/techniques/T0853/) → [T0843 Program Download](https://attack.mitre.org/techniques/T0843/) |
| 2 | Sysmon on EWS / SCADA / asset-mgmt hosts | EventID 7 ImageLoad — non-vendor DLLs loaded by `CCEServer.exe` / `Siemens.Automation.*.exe` / `FTAC.exe` / `ViewSE*.exe` / `Studio5000.exe` / `ControlExpert.exe` / `AcSELerator*.exe` / `setUPS*.exe` / `PowerChute*.exe` from user-writable paths | DLL search-order hijack class (WinCC installer, Studio 5000, Eaton UPS Companion CVE-2025-59887, acSELerator ICSA-23-131-08, Schneider CVE-2020-7559) | [T1574.001 DLL Search-Order Hijack](https://attack.mitre.org/techniques/T1574/001/) |
| 3 | Sysmon EventID 11 (FileCreate) on EWS | `.stu` / `.xef` / `.zef` / `.ACD` / `.aclx` / `.RDB` / `.crd` / `.ctz` / `nmc_*.bin` / `apc_hw*.bin` created outside project directory or by non-engineer accounts | Project-file infection / staged tampered firmware (Evil-PLC, Cicode payload, NMC firmware staging) | [T0873 Project File Infection](https://attack.mitre.org/techniques/T0873/) + [T0857 System Firmware](https://attack.mitre.org/techniques/T0857/) |
| 4 | **FactoryTalk Diagnostics + AssetCentre audit** | FT Directory `LogOn`/`LogOff` correlated with AssetCentre `CheckOut` of PLC project outside change-ticket window | Attacker pulling project to weaponize / credential mother-lode access | [T0866 Exploitation of Remote Services](https://attack.mitre.org/techniques/T0866/) |
| 5 | **WinCC / Experion / Citect audit logs** | `User logon failed` × N then `success`; `Project loaded` / `PointParameterChange` / `Configuration changed` outside maintenance window | Brute force on SCADA + unauthorised project load + operator-action abuse | [T0859 Valid Accounts](https://attack.mitre.org/techniques/T0859/) + [T0832 Manipulation of View](https://attack.mitre.org/techniques/T0832/) |
| 6 | **Network IDS (Suricata / Zeek)** | S7comm-Plus, UMAS function 0x5A, CIP service codes 0x4B/0x4C/0x4D (program download) + 0x6B (mode change), DNP3 FC 5/6, IEC 61850 MMS `write`, GOOSE from non-relay MACs — all sourced from any host outside the EWS VLAN | Cross-vendor unauthorised PLC programming / mode flip / breaker tamper | [T0843 Program Download](https://attack.mitre.org/techniques/T0843/) + [T0855 Unauthorized Command Message](https://attack.mitre.org/techniques/T0855/) |
| 7 | Network IDS | Connections to **Virtual Port Service 5828** TCP listener or **ACS 8000 portmgr** from non-loopback / non-engineer IPs; `login.success` for `root` on ACS 8000 from any IP | Lateral relay/console access via serial-tunnel pivot | [T0822 External Remote Services](https://attack.mitre.org/techniques/T0822/) + [T0886 Remote Services](https://attack.mitre.org/techniques/T0886/) |
| 8 | **Sysmon on power-mgmt + KVM-mgmt hosts (PowerChute / DSView / Trellis / Tomcat)** | EventID 1 where ParentImage = `tomcat*.exe` / `PowerChute*.exe` / `setUPS*.exe` / `IPM*.exe` AND child not in vendor allow-list | DSView pre-auth deserialization, Log4Shell on Trellis, PowerChute CVE-2021-22812 deserialization, Eaton UPS Companion installer RCE post-ex | [T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) (Enterprise) + [T0857 System Firmware](https://attack.mitre.org/techniques/T0857/) |

**Secondary:**

- Firewall egress: any outbound from L3 SCADA / EWS / asset-mgmt VLANs to non-RFC1918 destinations besides documented vendor cloud endpoints (Forge Azure tenants, Compass `updates.selinc.com`, Rockwell PSIRT mirror). Volt Typhoon's 2024 US-infrastructure campaign (CISA AA24-038A) used exactly this kind of callback path off the EWS.
- Vendor-native audit feeds (turn on + forward via syslog): WinCC audit log; Experion Operator Action Journal + System Event Journal + Control Builder change tracking; FactoryTalk Diagnostics (`Audit`, `Security`, `Configuration` categories); SEL relay SER buffer / Audit log via Fast Message `HIS` / `MET`; ACS 8000 Data Buffering + Auditing.
- Subscribe to ProductCERT-feeds with monthly review jobs: Siemens ProductCERT (2nd Tuesday), Rockwell Trust Center RSS, Schneider PSIRT bulletins, Honeywell PSIRT, SEL Security Advisories, Eaton PSIRT, APC / Schneider, Vertiv PSIRT.
- Active Directory: monitor service accounts used by FactoryTalk, Citect, WinCC, Power Operation, ACS 8000 RADIUS clients for interactive logons — they should be service-only.

---

## Cross-layer pivots

1. **L3 EWS → L1 PLC via authenticated CIP / S7Comm-Plus / UMAS write (Stuxnet model).** Compromise the engineering workstation (Studio 5000, TIA Portal Openness, Control Expert, acSELerator BaRT), then use the vendor's own programming protocol from a legitimate session to push tampered logic. Chains DLL-hijack + project-file infection on the EWS into [T0843 Program Download](https://attack.mitre.org/techniques/T0843/) at L1. CVE-2021-22681 (Rockwell hardcoded crypto key), CVE-2022-38465 (Siemens S7-1500 global private key), and CVE-2021-22779 (Schneider ModiPwn) all reduce this to a single-step pivot once the EWS is owned.

2. **L3 historian → L4 corporate (the IT/OT data path attackers ride backward).** FactoryTalk Historian SE, WinCC archives, and Experion Forge OPC UA bridges all push plant data northbound through documented IT/OT seams. The same TLS / MQTT / Tomcat endpoints that publish historian data are the soft re-entry point: Log4Shell on Trellis ([CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)), Forge edge-agent OPC UA client misconfiguration, and FactoryTalk Service Platform privilege escalation ([CVE-2024-21915](https://www.cisa.gov/news-events/ics-advisories/icsa-24-018-01)) all enable corporate-to-historian pivots that then reach the L2 HMI / L1 controller plane. Maps to [T0884 Connection Proxy](https://attack.mitre.org/techniques/T0884/) + [T0866 Exploitation of Remote Services](https://attack.mitre.org/techniques/T0866/).

3. **L3 AssetCentre → L1 mass-PLC config push (legitimate workflow, weaponized for tampering).** FactoryTalk AssetCentre is the disaster-recovery vault — it holds every PLC project archive + credentials in the plant. The Rockwell PSIRT AssetCentre deserialization family + [CVE-2024-21915](https://www.cisa.gov/news-events/ics-advisories/icsa-24-018-01) yield one-shot access to the entire fleet's program-download credential bundle, then attacker pushes tampered logic via the *normal* DR-restore workflow. Same model applies to SEL Compass-managed BaRT trees (silent relay-firmware tamper) and Schneider Secure Connect Advisor (cloud-pair token → on-prem PLC). [T0857 System Firmware](https://attack.mitre.org/techniques/T0857/) at fleet scale.

4. **L3 SCADA → L2 HMI display tamper (Manipulation of View).** WinCC SQL backend compromise (Stuxnet's path) or Citect Cicode runtime exploitation rewrites tag values shown to operators while real process data deviates. Operators see green when valves are open. [T0832 Manipulation of View](https://attack.mitre.org/techniques/T0832/) is the precondition for any L1 manipulation that must remain undetected long enough to cause physical effect — CRASHOVERRIDE and TRITON both depended on it.

---

## Sources

- [CISA AA24-038A — Volt Typhoon US Critical Infrastructure](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a)
- [CISA ICSA-21-056-03 — Rockwell Logix Controllers (CVE-2021-22681)](https://www.cisa.gov/news-events/ics-advisories/icsa-21-056-03)
- [CISA ICSA-21-110-06 — Eaton IPM](https://www.cisa.gov/news-events/ics-advisories/icsa-21-110-06)
- [CISA ICSA-21-294-02 — Honeywell Experion PKS upload / argument injection](https://www.cisa.gov/news-events/ics-advisories/icsa-21-294-02)
- [CISA ICSA-23-061-02 — Honeywell Experion PKS / LX / PlantCruise (ICEFALL "Crystallized Insecurity")](https://www.cisa.gov/news-events/ics-advisories/icsa-23-061-02)
- [CISA ICSA-23-131-08 — SEL acSELerator family](https://www.cisa.gov/news-events/ics-advisories/icsa-23-131-08)
- [CISA ICSA-23-193-01 — Rockwell FactoryTalk View ME](https://www.cisa.gov/news-events/ics-advisories/icsa-23-193-01)
- [CISA ICSA-23-194-02 — SEL Real-Time Automation Controller (RTAC)](https://www.cisa.gov/news-events/ics-advisories/icsa-23-194-02)
- [CISA ICSA-23-285-06 — Vertiv Avocent ACS 8000](https://www.cisa.gov/news-events/ics-advisories/icsa-23-285-06)
- [CISA ICSA-24-018-01 — Rockwell FactoryTalk Service Platform (CVE-2024-21915)](https://www.cisa.gov/news-events/ics-advisories/icsa-24-018-01)
- [CISA/NSA/FBI/ASD — Best Practices for Event Logging and Threat Detection (2024)](https://www.cisa.gov/resources-tools/resources/best-practices-event-logging-and-threat-detection)
- [Siemens ProductCERT advisory index](https://cert-portal.siemens.com/productcert/html/index.html)
- [Rockwell Automation Trust Center — Security Advisories](https://www.rockwellautomation.com/en-us/trust-center/security-advisories.html)
- [Schneider Electric Cybersecurity Support Portal / PSIRT](https://www.se.com/ww/en/work/support/cybersecurity/overview.jsp)
- [Honeywell PSIRT / Security Notifications](https://www.honeywell.com/us/en/product-security)
- [SEL Security Advisories index](https://selinc.com/support/security-advisories/)
- [Vertiv PSIRT / security advisory index](https://www.vertiv.com/en-us/support/security-advisories/)
- [Eaton PSIRT advisory index](https://www.eaton.com/us/en-us/company/news-insights/cybersecurity/security-notifications.html)
- [Claroty Team82 — Evil PLC Attack (Rockwell + Schneider EcoStruxure Control Expert)](https://claroty.com/team82/research/white-papers/evil-plc-attack-weaponizing-plcs)
- [Claroty Team82 — Stealthy Rockwell PLC Hack (CVE-2022-1161)](https://claroty.com/team82/research/stealthy-rockwell-plc-hack)
- [Claroty Team82 — ICEFALL Continues: Broken Trust, Broken Code (Honeywell Experion)](https://claroty.com/team82/research/icefall-continues-broken-trust-broken-code)
- [Claroty Team82 — ModiPwn research (CVE-2021-22779)](https://claroty.com/team82/research/the-race-to-native-code-execution-in-plcs)
- [Forescout Vedere — OT:ICEFALL research](https://www.forescout.com/research-labs/ot-icefall/)
- [Dragos — XENOTIME / TRITON profile (SIS engineering-tool archetype)](https://www.dragos.com/threat/xenotime/)
- [Dragos — PIPEDREAM/CHERNOVITE analysis (engineering-workstation pivot)](https://www.dragos.com/blog/industry-news/chernovite-pipedream-malware-targeting-industrial-control-systems/)
- [Mandiant — TRITON technical analysis](https://www.mandiant.com/resources/blog/attackers-deploy-new-ics-attack-framework-triton)
- [Armis — research index](https://www.armis.com/research/)
- [Nozomi Networks Labs — Avocent ACS 8000 research](https://www.nozominetworks.com/blog/)
- [MITRE ATT&CK for ICS — T0843 Program Download](https://attack.mitre.org/techniques/T0843/)
- [MITRE ATT&CK for ICS — T0857 System Firmware](https://attack.mitre.org/techniques/T0857/)
- [MITRE ATT&CK for ICS — T0873 Project File Infection](https://attack.mitre.org/techniques/T0873/)
- [MITRE ATT&CK for ICS — T0832 Manipulation of View](https://attack.mitre.org/techniques/T0832/)
- [MITRE ATT&CK for ICS — T0866 Exploitation of Remote Services](https://attack.mitre.org/techniques/T0866/)
- [MITRE ATT&CK for ICS — T0822 External Remote Services](https://attack.mitre.org/techniques/T0822/)
- [MITRE ATT&CK for ICS — T0853 Scripting](https://attack.mitre.org/techniques/T0853/)
- [MITRE ATT&CK for ICS — T0859 Valid Accounts](https://attack.mitre.org/techniques/T0859/)
- [IEC 62443 / Purdue reference model](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards)
- Internal: [Eaton brief](eaton-firmware-threat-brief.md), [APC brief](apc-firmware-threat-brief.md), [Vertiv brief](vertiv-firmware-threat-brief.md), [SEL brief](sel-firmware-threat-brief.md), [Siemens brief](siemens-firmware-threat-brief.md), [Honeywell brief](honeywell-firmware-threat-brief.md), [Schneider brief](schneider-firmware-threat-brief.md), [Rockwell brief](rockwell-firmware-threat-brief.md)

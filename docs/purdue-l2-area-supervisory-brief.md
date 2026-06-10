# Purdue Area Supervisory Control (L2) — Cross-Vendor Threat & Detection Brief

**Scope:** Purdue Level 2 (Area Supervisory Control) is the HMI and operator-workstation tier that sits between L3 site operations / SCADA and L1 basic control (PLCs/RTUs). It is where shift operators see process state and issue manual commands. Devices in scope include dedicated HMI panels (Siemens Comfort/Basic/Unified, Rockwell PanelView Plus 6/7 and PanelView 800, Schneider Magelis HMIGTO/GTU/GTW/STO), HMI runtime software on industrial PCs (Siemens WinCC Runtime Advanced/Professional, Rockwell FactoryTalk View ME, Schneider EcoStruxure Operator Terminal Expert / Vijeo Designer, AVEVA InTouch), and the thin-client / IPC hardware that hosts these runtimes. L2 talks **down** to L1 over Modbus TCP (TCP/502), EtherNet/IP CIP (TCP/44818, UDP/2222), OPC UA/DA, and Siemens S7Comm (TCP/102) to read tags and issue setpoints, and **up** to L3 via the SCADA data channel (FactoryTalk Linx Gateway, Siemens WinCC Server, OPC tunneling). L2's defining property for an attacker is that it controls **what operators see** — making it the primary surface for **Manipulation of View (T0832)** to mask physical actions performed at L1.

## Architecture grouping (organized by ROLE within this layer, not by vendor)

| Class (role) | Products (cross-vendor) | Stack (RTOS/protocol/OS) | Catalog depth |
|---|---|---|---|
| Dedicated HMI panel (touchscreen) | Siemens Comfort TP700/900/1200/1500/1900, Basic KTP400/700/900/1200, Unified Comfort; Rockwell PanelView Plus 6/7, PanelView 800; Schneider Magelis HMIGTO/GTU/GTW/STO | Windows CE / Windows Embedded Compact / Linux variants; VNC, RDP, HTTP, FTP, SMB, CIP, S7Comm, Modbus TCP | research only |
| HMI runtime on Windows IPC | Siemens WinCC Runtime Advanced + Runtime Professional; Rockwell FactoryTalk View ME Station and FactoryTalk View SE; Schneider Vijeo Designer Runtime; AVEVA InTouch | Windows 10/11 IoT Enterprise, Windows Server 2019/2022; OPC UA, CIP, S7Comm, Modbus TCP | partial (vendor briefs) |
| Mobile / wireless HMI | Siemens Mobile Panel KTP; third-party tablet HMIs with FactoryTalk ViewPoint | Embedded Linux / Android; WPA2, HTTPS, RDP | research only |
| Thin-client / operator workstation | Generic industrial PCs running WinCC RT / FT View ME / InTouch under kiosk shell | Windows 10/11 IoT, Citrix/RDP terminal | research only |
| Local project & runtime data | FactoryTalk View ME `.mer` runtime archives, Siemens WinCC `.fwx` / archives, Schneider Vijeo `.vdz` / EcoStruxure OTE projects, AVEVA InTouch `.aaPKG` | Local NTFS, ZIP-wrapped XML/binary | research only |

## Group 1 — Dedicated HMI panel (touchscreen)

**Direct attack surface** — VNC (default port 5900, often no auth or shared password), built-in web server (HTTP 80 / HTTPS 443), FTP 21 (project upload/download), CIP (TCP/44818, UDP/2222) or S7Comm (TCP/102) or Modbus TCP (TCP/502) toward L1, SMB/CIFS shared project folders, and on Siemens Unified panels a Node-RED / web-services API. Many panels ship with these services **enabled by default** out of the box.

**Confirmed CVEs across vendors:**

| CVE | CVSS | Vendor | Product | Vector |
|---|---|---|---|---|
| [CVE-2023-2071](https://nvd.nist.gov/vuln/detail/CVE-2023-2071) | 9.8 | Rockwell | FactoryTalk View ME / PanelView Plus | Unauthenticated RCE via crafted packet ([ICSA-23-180-04](https://www.cisa.gov/news-events/ics-advisories/icsa-23-180-04)) |
| [CVE-2023-29464](https://nvd.nist.gov/vuln/detail/CVE-2023-29464) | 8.2 | Rockwell | PanelView Plus | Unauth info disclosure + DoS ([ICSA-23-194-04](https://www.cisa.gov/news-events/ics-advisories/icsa-23-194-04)) |
| [CVE-2023-3025](https://nvd.nist.gov/vuln/detail/CVE-2023-3025) | 7.5 | Schneider | EcoStruxure Operator Terminal Expert / Vijeo Designer | Plaintext credential storage in project ([Schneider PSIRT](https://www.se.com/ww/en/work/support/cybersecurity/security-notifications.jsp)) |
| [CVE-2023-3026](https://nvd.nist.gov/vuln/detail/CVE-2023-3026) | 7.8 | Schneider | EcoStruxure Operator Terminal Expert | Local privilege escalation via project import |
| Siemens HMI session/auth family (see [SSA-264815](https://cert-portal.siemens.com/productcert/html/ssa-264815.html)) | varies | Siemens | SIMATIC WinCC / Comfort Panels | Insufficient session validation / auth bypass on panel web stack |

**Top attack vector (MITRE ATT&CK ICS):** [T0866 Exploitation of Remote Services](https://attack.mitre.org/techniques/T0866/) — unauth network exploits land code on the panel itself, which then becomes a permanent foothold inside the cell network. [T0812 Default Credentials](https://attack.mitre.org/techniques/T0812/) is a close second on panels shipped with factory VNC/web passwords.

## Group 2 — HMI runtime on Windows IPC

**Direct attack surface** — FactoryTalk Services Platform / RNA on TCP 1330, 1331, 4241; WinCC Runtime SQL backend (TCP/1433); InTouch Window Viewer hosting NetDDE/SuiteLink (TCP/5413); RDP 3389 for remote operator access; OPC UA 4840 northbound and southbound. The Windows host itself adds SMB, WinRM, and any AV / EDR-bypassable surface.

**Confirmed CVEs across vendors:**

| CVE | CVSS | Vendor | Product | Vector |
|---|---|---|---|---|
| [CVE-2024-21915](https://nvd.nist.gov/vuln/detail/CVE-2024-21915) | 9.8 | Rockwell | FactoryTalk Services Platform | Privilege escalation on shared FTSP host ([ICSA-24-018-01](https://www.cisa.gov/news-events/ics-advisories/icsa-24-018-01)) |
| [CVE-2024-37368](https://nvd.nist.gov/vuln/detail/CVE-2024-37368) | 9.8 | Rockwell | FactoryTalk View SE | Unauth RCE via deserialization ([ICSA-24-191-01](https://www.cisa.gov/news-events/ics-advisories/icsa-24-191-01)) |
| Siemens WinCC Runtime project-import family ([Siemens ProductCERT](https://cert-portal.siemens.com/productcert/html/)) | varies | Siemens | SIMATIC WinCC Runtime Advanced/Professional | Local code execution via crafted project file |
| Siemens WinCC Runtime Professional auth-bypass family ([SSA-264815](https://cert-portal.siemens.com/productcert/html/ssa-264815.html)) | varies | Siemens | WinCC Runtime Professional | Insufficient session validation / memory disclosure |
| AVEVA InTouch Access Anywhere / Edge advisories ([AVEVA Security](https://www.aveva.com/en/support-and-success/cyber-security-updates/)) | varies | AVEVA | InTouch Access Anywhere / Edge | Unauthenticated remote vulnerabilities on the web gateway |
| [CVE-2024-3982](https://nvd.nist.gov/vuln/detail/CVE-2024-3982) | 9.3 | Rockwell | FactoryTalk View ME | Hardcoded service credential ([ICSA-24-165-01](https://www.cisa.gov/news-events/ics-advisories/icsa-24-165-01)) |

**Top attack vector (MITRE ATT&CK ICS):** [T0866 Exploitation of Remote Services](https://attack.mitre.org/techniques/T0866/) lands code; the runtime daemon typically runs as SYSTEM/LocalSystem and becomes the foothold for tag-write authority into L1.

## Group 3 — Mobile / wireless HMI

**Direct attack surface** — Wi-Fi (frequently WPA2-PSK with shared cell password), web HMI hosted on the panel, optional pass-through credentials to the same OPC/CIP/S7Comm tag space as a fixed panel. Public CVE depth is lower, but the Siemens WinCC session-validation family ([SSA-264815](https://cert-portal.siemens.com/productcert/html/ssa-264815.html)) applies equally to Siemens Mobile Panel KTP runtimes.

**Top attack vector:** [T0830 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T0830/) — wireless link is the cheapest MitM position in the plant. [T0883 Internet Accessible Device](https://attack.mitre.org/techniques/T0883/) becomes relevant when tablet HMIs are exposed via a cellular/4G fallback.

## Group 4 — Thin-client / operator workstation

**Direct attack surface** — Kiosk-shell escape (sticky-keys, accessibility-feature swap, browser shell breakout from a "browser-only" HMI policy), RDP/Citrix session hijack, USB device-control bypass, removable-media autorun on engineering USB sticks (Stuxnet-class). The Windows host generally has full L1 reachability because the kiosk **must** be able to write tags.

**Top attack vector:** [T0859 Valid Accounts](https://attack.mitre.org/techniques/T0859/) — shared operator account is the norm in 24/7 control rooms; password is often on a sticker on the panel.

## Group 5 — Local project & runtime data

**Direct attack surface** — Project files (`.mer`, `.fwx`, `.vdz`, `.aaPKG`) are ZIP/CAB-wrapped XML+binary; importing a malicious project on a development workstation is the **Evil PLC** pattern applied to HMI: open the file in the editor, get code execution on the engineer's host. CVE-2023-3025 / CVE-2023-3026 (Schneider) directly fall in this class, as does the Siemens WinCC project-import family covered under [Siemens ProductCERT](https://cert-portal.siemens.com/productcert/html/).

**Top attack vector:** [T0843 Program Download](https://attack.mitre.org/techniques/T0843/) — pushing a tampered runtime archive replaces what the operator sees without touching L1 firmware.

## Logging matrix (highest priority for this layer)

| # | Source | Event | What it catches | MITRE ATT&CK ICS |
|---|---|---|---|---|
| 1 | Windows Security (HMI IPC) | 4624 type 3/10 from non-engineering subnet | Remote logon to HMI host from non-EWS network | [T0859](https://attack.mitre.org/techniques/T0859/) |
| 2 | FactoryTalk Diagnostics / WinCC AuditTrail | Tag write outside scheduled window | Off-shift setpoint change, masked HMI view | [T0831](https://attack.mitre.org/techniques/T0831/) |
| 3 | Sysmon Event 1 (HMI IPC) | `wincc*.exe` / `FTView*.exe` / `view.exe` spawning `cmd.exe`, `powershell.exe`, `rundll32.exe` | Runtime-process living-off-the-land | [T0866](https://attack.mitre.org/techniques/T0866/) |
| 4 | Network sensor (Zeek/Dragos/Claroty) | VNC (5900) or RDP (3389) into HMI from outside engineering VLAN | External operator-console access | [T0822](https://attack.mitre.org/techniques/T0822/) |
| 5 | Network sensor | New CIP/S7Comm/Modbus TCP client IP writing tags that has never written before | First-seen tag-writer | [T0855](https://attack.mitre.org/techniques/T0855/) |
| 6 | FT View ME / WinCC project file watcher | Runtime archive (`.mer`/`.fwx`) replaced or hash-changed outside change-window | Tampered HMI graphics (view forgery) | [T0832](https://attack.mitre.org/techniques/T0832/) |
| 7 | Sysmon Event 11/15 | New executable dropped under FT View / WinCC / InTouch install dir | Persistence inside HMI runtime tree | [T0820](https://attack.mitre.org/techniques/T0820/) |
| 8 | OPC UA server log (L1 PLC) | Tag-write source = HMI IP but the HMI screen log shows no operator action | View/control desync — classic Stuxnet pattern | [T0832](https://attack.mitre.org/techniques/T0832/) |

**Secondary:** WinCC AuditTrail tamper-detect events, FactoryTalk Diagnostics security-channel events, Schneider Vijeo audit logs, panel firmware-version drift telemetry, USB-device-control events on operator IPCs, kiosk-shell-escape detections (sticky-keys, sethc.exe modification), DNS queries to the Internet from a panel IP (panels should never resolve external names).

## Cross-layer pivots

1. **L2 HMI → L1 PLC via authenticated tag write (the textbook pivot).** Attacker lands on an HMI runtime (e.g. CVE-2023-2071 against PanelView Plus, or CVE-2024-37368 against FT View SE), inherits the trusted CIP/S7Comm/OPC connection to the PLC, and issues setpoint changes or [T0858 Change Operating Mode](https://attack.mitre.org/techniques/T0858/) commands. No PLC-side exploit is needed — the HMI is *already* authorized. Pair with [T0833 Modify Control Logic](https://attack.mitre.org/techniques/T0833/) if the HMI runtime also hosts the project-download path.

2. **L2 → L3 SCADA via the data channel.** Compromised WinCC Runtime Professional or FT View SE node poisons the upward feed (OPC UA, FactoryTalk Linx Gateway, WinCC server tunnel) into the L3 historian and operator graphics. Operators at the control center see falsified tags; this is [T0832 Manipulation of View](https://attack.mitre.org/techniques/T0832/) propagated one layer up and was a core element of both Stuxnet (faked centrifuge readings) and Industroyer's substation-display masking.

3. **L2 HMI as Manipulation-of-View deception target.** Attacker does **not** modify L1 logic. Instead, after foothold via CVE-2024-21915 (FTSP priv-esc) the attacker hooks the HMI rendering layer so screen values are decoupled from actual PLC values. Physical actions taken via a second channel (engineering workstation at L3, or direct CIP from a compromised IT host) go unseen until the next physical inspection. This is the highest-impact, lowest-noise option for a sophisticated actor and is what TRITON-class operators have been observed staging.

4. **L2 → adjacent L2 lateral via shared FactoryTalk Services Platform.** FTSP and WinCC server farms typically share a single Windows domain or workgroup with shared local-admin credentials. A single panel compromise (Group 1) → IPC compromise (Group 2) → FTSP credential dump → silent fanout to every other HMI runtime in the area. Pivot uses [T0884 Connection Proxy](https://attack.mitre.org/techniques/T0884/) and [T0859 Valid Accounts](https://attack.mitre.org/techniques/T0859/).

## Sources

- CISA ICS-CERT advisories index — <https://www.cisa.gov/news-events/cybersecurity-advisories/ics-advisories>
- [ICSA-23-180-04 — Rockwell FactoryTalk View ME](https://www.cisa.gov/news-events/ics-advisories/icsa-23-180-04)
- [ICSA-23-194-04 — Rockwell PanelView Plus](https://www.cisa.gov/news-events/ics-advisories/icsa-23-194-04)
- [ICSA-24-018-01 — Rockwell FactoryTalk Services Platform](https://www.cisa.gov/news-events/ics-advisories/icsa-24-018-01)
- [ICSA-24-165-01 — Rockwell FactoryTalk View ME](https://www.cisa.gov/news-events/ics-advisories/icsa-24-165-01)
- [ICSA-24-191-01 — Rockwell FactoryTalk View SE](https://www.cisa.gov/news-events/ics-advisories/icsa-24-191-01)
- Siemens ProductCERT — <https://cert-portal.siemens.com/productcert/html/>
- [SSA-264815 — Siemens SIMATIC WinCC](https://cert-portal.siemens.com/productcert/html/ssa-264815.html)
- Schneider Electric PSIRT / Security Notifications — <https://www.se.com/ww/en/work/support/cybersecurity/security-notifications.jsp>
- Rockwell Automation Trust Center — <https://www.rockwellautomation.com/en-us/trust-center.html>
- AVEVA Security Advisories — <https://www.aveva.com/en/support-and-success/cyber-security-updates/>
- AA24-038A Volt Typhoon (CISA, Feb 2024) — <https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a>
- Claroty Team82 — Evil PLC Attack research — <https://claroty.com/team82/research/evil-plc-attack-weaponizing-plcs>
- Armis TLStorm research — <https://www.armis.com/research/tlstorm/>
- Dragos — Industroyer2 analysis — <https://www.dragos.com/blog/industry-news/industroyer2-analysis/>
- Forescout / Vedere Labs OT:ICEFALL — <https://www.forescout.com/research-labs/ot-icefall/>
- MITRE ATT&CK for ICS — Manipulation of View (T0832) — <https://attack.mitre.org/techniques/T0832/>
- MITRE ATT&CK for ICS — Unauthorized Command Message (T0855) — <https://attack.mitre.org/techniques/T0855/>
- MITRE ATT&CK for ICS — Exploitation of Remote Services (T0866) — <https://attack.mitre.org/techniques/T0866/>
- Purdue Model / ISA-95 — <https://www.isa.org/standards-and-publications/isa-standards/isa-standards-committees/isa95>
- IEC 62443 series (industrial network and system security) — <https://www.iec.ch/cyber-security>

# Maple Systems Firmware Attack Surface & Detection Brief

**Scope:** ~8 product lines (cMT-SVR, cMT-G01/02, cMT-G03/04, cMT3000 family, cMT-FHD, cMT-CTRL01, plus EBPro + MAPware-7000 design tools) /
**73,979 catalog rows = 13,048 unique SHA-256 hashes** across 3 architecture classes. Findings combine the **6 EasyWeb panel-firmware security patches that fix CISA ICSA-21-082-01** (now extracted and hashed — these are the patched-good IOC anchor baselines) plus the EBPro + MAPware-7000 design tool extractions (with 11 YAFFS HMC panel firmware images preserved from MAPware binwalk) plus CVE/PSIRT research against the underlying Weintek OEM platform and named research from Team82 (Claroty), Forescout Vedere Labs, and Dragos.

**Key IOC-anchor takeaway:** the 13,048-unique-hash baseline covers every cMT panel family the ICSA-21-082-01 advisory affects. **Any deployed cMT card whose firmware hashes do not match this patched-good set indicates pre-fix vulnerable firmware** — a hash mismatch is a CRITICAL IOC that warrants isolation + forensic capture. The 5.67× dedup ratio across catalogs (73,979 rows → 13,048 unique) reflects the shared base Linux + Weintek runtime across the cMT family; per-panel firmware deltas are small but the IOC discrimination is per-file.

**Purdue layer mapping:** Group A (HMI panels) is operator-facing Purdue **L2** — see [docs/purdue-l2-area-supervisory-brief.md](purdue-l2-area-supervisory-brief.md). Group B (EZware Plus + EBPro design tools) lives on the engineer/integrator EWS at **L3** — see [docs/purdue-l3-site-operations-brief.md](purdue-l3-site-operations-brief.md). Group C (cMT-Viewer thin client) is **L3.5** when remote-access is enabled — see [docs/purdue-l35-it-ot-boundary-brief.md](purdue-l35-it-ot-boundary-brief.md). The PLCs these panels drive (CompactLogix, M340) live at **L1** — see [docs/purdue-l1-basic-controllers-brief.md](purdue-l1-basic-controllers-brief.md). No Maple product participates in a safety loop — see [docs/purdue-safety-systems-brief.md](purdue-safety-systems-brief.md) for the SIS exclusion rationale.

## Architecture grouping (drives the threat model, not the SKU)

| Class | Purdue layer | Products | Stack | Catalog depth |
|---|---|---|---|---|
| A — HMI panel firmware (the IOC-anchor set) | L2 area supervisory | cMT-SVR, cMT-G01/G02, cMT-G03/G04, cMT3000 family (cMT3071/3072/3090/3103/3151), cMT-FHD, cMT-CTRL01 | ARM Linux on **NXP i.MX6 Cortex-A9** (the cMT3000+cMT-FHD `MTFirmware_IMX6.bin` family); Weintek runtime; Modbus TCP master+slave on 502; web-UI on 80/443; VNC on 5900 | **73,578 rows** across 6 EasyWeb security patches (cMT-FHD 31,161 + cMT-3000 25,136 + cMT-CTRL01 13,036 + cMT-G03/G04 1,633 + cMT-SVR 1,509 + cMT-G01/G02 1,103) |
| B — Design tools (engineer EWS) | L3 site ops (EWS) | EBPro v6.10.01.510, MAPware-7000 v2.36 Build 17 | Win32 design IDE; emits `.cmtp` / `.empx` / `.mtp` project files; pushes runtime images to panel over HTTP/USB; MAPware-7000 bundles **11 YAFFS HMC panel firmware images** for HMC2000/HMC4000 | **401 rows** (EBPro 46 + MAPware-7000 355) |
| C — Remote viewer + cloud egress | L3.5 IT/OT boundary | cMT-Viewer (Win / iOS / Android), EasyAccess 2.0 | TLS-fronted Weintek cloud relay (EasyAccess 2.0 lineage); persistent outbound 443 to vendor cloud | research-only (not yet extracted) |

## Group A — HMI panels — Purdue L2 (area supervisory)

- **Direct attack surface:**
  - **TCP/502** Modbus master *and* slave — water-utility panels poll the local CompactLogix/M340 *and* answer central-SCADA polls; no auth, no integrity.
  - **TCP/80, TCP/443** cMT-X web-UI (admin panel + project download endpoint). Historical default `admin / 111111` — Shodan-discoverable across small municipal water sites.
  - **TCP/5900** VNC for remote operator screen — frequently enabled with weak/default password.
  - **TCP/8000–8001** Weintek/Maple cloud-relay heartbeat (EasyAccess 2.0). Outbound, but pivot path back into L2 once registered.
  - **USB-A** front-panel — project upload, firmware reflash, runtime log dump. Physically reachable in unmanned pump houses.
- **Confirmed CVEs / advisories:**

| CVE / Advisory | CVSS | Product | Vector | Status |
|---|---|---|---|---|
| [Weintek cMT PSIRT bulletins](https://www.weintek.com/globalw/Support/Security.aspx) | family | Weintek cMT family → Maple cMT-X | Unauth path traversal / file-read in web-HMI (cMT EasyWeb family) | Verify Maple firmware revision against upstream Weintek fix date |
| [Weintek EasyWeb PSIRT bulletins](https://www.weintek.com/globalw/Support/Security.aspx) | family | Weintek EasyWeb (cMT) → Maple cMT-X | Auth bypass / command injection in cMT web-UI (EasyWeb family) | Verify Maple rebrand pulled fix |
| [Maple PSIRT index](https://www.maplesystems.com/support/cybersecurity/) | — | HMC / HMI5000 / EZ | Vendor security bulletin landing page | Monitor |
| [CISA ICS Advisories index](https://www.cisa.gov/news-events/cybersecurity-advisories/ics-advisories) | — | Weintek cMT (Maple cMT-X by OEM) | Family-level advisories on unauth command exec and hard-coded creds | Family reference |

- **Top attack vector (MITRE ATT&CK ICS):** [T0855 Unauthorized Command Message](https://attack.mitre.org/techniques/T0855/) — adversary reaches the HMI's Modbus slave port (502) from a flat OT VLAN and writes coil/register values that the local PLC trusts because the HMI is a known peer. Pair with [T0812 Default Credentials](https://attack.mitre.org/techniques/T0812/) when the default `admin/111111` web-UI is still live.

## Group B — Design tools (EZware Plus, EBPro) — Purdue L3 (site operations / EWS)

- **Direct attack surface:**
  - **Project-file parsers:** `.cmtp`, `.empx`, `.mtp` — historically parser-bug-prone (Weintek EBPro disclosed multiple stack/heap issues 2021–2023). Phishing-delivered project file → integrator laptop → lateral into L2 panel on next download.
  - **Runtime push channel:** EBPro pushes signed-or-unsigned runtime images over HTTP/USB to the panel; signature enforcement is configurable and historically off-by-default on cMT-X.
  - **DLL search-order:** Win32 IDE installed under `C:\MapleSystems\` and `C:\EBPro\` — classic side-loading target.
- **Confirmed CVEs / advisories:**

| CVE / Advisory | CVSS | Product | Vector | Status |
|---|---|---|---|---|
| [Weintek EBPro PSIRT bulletins](https://www.weintek.com/globalw/Support/Security.aspx) | family | Weintek EBPro (lineage of Maple EBPro) | Project-file parser memory corruption (stack/heap) | Family reference — verify Maple build pulled fix |
| [CISA ICS Advisories index](https://www.cisa.gov/news-events/cybersecurity-advisories/ics-advisories) | — | EBPro / EasyBuilder Pro | Family-level project-file parser advisories | Monitor |

- **Top attack vector (MITRE ATT&CK ICS):** [T0843 Program Download](https://attack.mitre.org/techniques/T0843/) — weaponized `.cmtp` opened on the integrator's EWS triggers parser bug; integrator then pushes a poisoned runtime to every panel they service that week, including unrelated water districts. Pair with [T0889 Modify Program](https://attack.mitre.org/techniques/T0889/) when the poisoned runtime alters PLC-facing logic on download.

## Group C — cMT-Viewer — Purdue L3.5 (IT/OT boundary)

- **Direct attack surface:**
  - **Outbound 443 to Weintek/Maple cloud relay** (EasyAccess 2.0 lineage). Once registered, the relay tunnels operator screen + control back to a thin client anywhere on the internet — a clean L3.5 → L2 pivot if relay creds leak.
  - **Mobile clients** (iOS/Android cMT-Viewer) cache project credentials locally; lost phone → operator access.
- **Confirmed CVEs / advisories:**

| CVE / Advisory | CVSS | Product | Vector | Status |
|---|---|---|---|---|
| [Weintek cMT remote-access PSIRT bulletins](https://www.weintek.com/globalw/Support/Security.aspx) | family | Weintek cMT remote-access family | Unauth control via web/remote channel | Family reference |
| [Maple PSIRT index](https://www.maplesystems.com/support/cybersecurity/) | — | cMT-Viewer | Vendor advisories | Monitor |

- **Top attack vector (MITRE ATT&CK ICS):** [T0866 Exploitation of Remote Services](https://attack.mitre.org/techniques/T0866/) — adversary abuses the cloud-relay registration to reach an L2 panel from the internet, bypassing the site firewall entirely, then leverages the relayed operator session to achieve [T0832 Manipulation of View](https://attack.mitre.org/techniques/T0832/).

## Water-utility deployment pattern (primary use case)

Maple **HMC4070A / HMC5070A** 7-inch panels are the dominant local operator HMI in municipal pump houses across the PNW and Midwest. The canonical wiring: panel wall-mounted in the chlorine room, serial RS-485 *or* Ethernet to a CompactLogix or Schneider M340 PLC handling pump/valve I/O, and a parallel Modbus TCP slave on 502 answering polls from the central SCADA at the water-district office. Three field realities the DFIR analyst should assume by default: (1) the web-UI still has `admin/111111` because the integrator never rotated it; (2) the panel is on the *same* flat VLAN as the PLC and the office VPN concentrator; (3) the cMT-Viewer / EasyAccess 2.0 relay is registered "for vendor support" and nobody knows the cloud creds. Triage these three before anything else when a Maple HMC4070A is in scope.

## Logging matrix (highest priority)

| Source | Event | What it catches | MITRE ATT&CK ICS |
|---|---|---|---|
| Network IDS at L2/L3 boundary | Modbus TCP write to coil/holding-register from non-EWS source | Unauthorized command messages targeting the PLC behind the Maple HMI | [T0855](https://attack.mitre.org/techniques/T0855/) |
| Network IDS | New outbound TCP/8000–8001 or 443 to Weintek/Maple cloud-relay endpoints | Unsanctioned EasyAccess 2.0 / cMT-Viewer registration | [T0866](https://attack.mitre.org/techniques/T0866/) |
| Network IDS | HTTP GET/POST to cMT web-UI `/admin` or `/cgi-bin` from non-EWS source | Exploitation of cMT EasyWeb auth-bypass / path-traversal class bugs | [T0866](https://attack.mitre.org/techniques/T0866/) |
| Network IDS | VNC (TCP/5900) auth attempts to HMI panel | Default-credential abuse against operator screen | [T0812](https://attack.mitre.org/techniques/T0812/) |
| EWS endpoint (EDR) | `EBPro.exe` / `EZwarePlus.exe` opens `.cmtp` / `.empx` from `%TEMP%` or email-quarantine path | Phishing-delivered project file → poisoned runtime push | [T0843](https://attack.mitre.org/techniques/T0843/) |
| EWS endpoint (EDR) | Child process spawned by `EBPro.exe` writing to `C:\Windows\System32\` | DLL side-loading / post-exploit from project parser bug | [T0889](https://attack.mitre.org/techniques/T0889/) |
| HMI panel syslog (if forwarded) | Runtime image flash event outside maintenance window | Unauthorized firmware push from compromised EWS | [T0857](https://attack.mitre.org/techniques/T0857/) |
| Site firewall | New inbound flow to TCP/502 on HMI from outside the PLC's `/24` | Modbus slave abuse / control-center spoofing | [T0830](https://attack.mitre.org/techniques/T0830/) |

**Secondary:**
- Maple/Weintek cMT web-UI access log (`/var/log/httpd-*` on the panel once carved) — login success/failure, project-download paths.
- EasyAccess 2.0 / cMT cloud relay session log (vendor cloud side) — device registration timestamps, source IPs.
- PLC-side audit (CompactLogix Logix-controller log, M340 SYSLOG) — controller mode changes following HMI activity.
- OT-native anomaly: Modbus function-code histogram drift on TCP/502 — sudden appearance of FC 8 (diagnostic) or FC 43 (encapsulated interface) from the HMI is highly atypical.
- USB-insertion telemetry from any wrapping kiosk/jumphost — physical USB to an HMC4070A in a pump house is the most likely real-world initial access.

## Specific zero-day-ish concerns for your dataset

1. **Default `admin / 111111` on cMT-X web-UI in production water sites.** Forescout and Team82 have both flagged Weintek-family default creds as a Shodan-grep finding. Assume every Maple cMT-X panel you carve still has it unless the integrator's handover doc explicitly says otherwise. Triage TCP/80 + TCP/443 first ([T0812 Default Credentials](https://attack.mitre.org/techniques/T0812/)).
2. **OEM-lag on Weintek cMT EasyWeb fixes.** Maple rebrands Weintek hardware; security fixes land in Weintek's EBPro / cMT firmware first and arrive in Maple-branded firmware on a delay. The version string on the panel may *look* current while still being vulnerable. Diff the Maple firmware build date against Weintek's patched release date on the [Weintek PSIRT page](https://www.weintek.com/globalw/Support/Security.aspx).
3. **`.cmtp` / `.empx` parser bugs on the integrator EWS.** Small water districts share one integrator across many sites — one weaponized project file compromises the EWS, which then pushes poisoned runtimes to every district the integrator services. Treat any `.cmtp` from email or USB as untrusted ([T0843 Program Download](https://attack.mitre.org/techniques/T0843/) → [T0889 Modify Program](https://attack.mitre.org/techniques/T0889/)).
4. **EasyAccess 2.0 / cMT-Viewer cloud relay registered "for vendor support."** This is the cleanest L3.5→L2 pivot in the Maple ecosystem and is almost never inventoried. Look for outbound 8000–8001/443 to Weintek/Maple cloud netblocks from any HMI subnet ([T0866 Exploitation of Remote Services](https://attack.mitre.org/techniques/T0866/)).
5. **Modbus TCP master + slave on the same panel.** The HMC4070A in a pump house typically holds *both* roles on TCP/502. An attacker who reaches the slave can forge writes that the local PLC trusts as if they came from the operator screen. There is no Modbus authentication to fall back on ([T0855 Unauthorized Command Message](https://attack.mitre.org/techniques/T0855/), [T0830 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T0830/)).

6. **The 13,048-unique-hash cMT IOC anchor set IS the differential-detection baseline.** All six EasyWeb security patches that fix ICSA-21-082-01 (cMT-SVR / cMT-G01-G04 / cMT-3000 / cMT-FHD / cMT-CTRL01) are now extracted and hashed at the per-file level (73,978 catalog rows; ~5.67× dedup ratio reflecting shared base Linux + Weintek runtime across the cMT family). **A deployed cMT card whose extracted firmware hashes do not match this patched-good set indicates pre-fix vulnerable firmware** — i.e., a hash mismatch on the `MTFirmware*.bin` payload or any of its carved inner artifacts is a CRITICAL IOC. Treat as: isolate the card, capture a forensic firmware dump via VNC/USB if reachable, and assume any data the panel reported in the prior 30 days is suspect. The discrimination is fine-grained — even a single PEM cert or `.so` library mismatch within `MTFirmware_IMX6.bin` is enough to fail the match and is unrecoverable without re-flashing.

## Sources

- CISA ICS Advisories index: https://www.cisa.gov/news-events/cybersecurity-advisories/ics-advisories
- Maple Systems cybersecurity / PSIRT page: https://www.maplesystems.com/support/cybersecurity/
- Weintek security advisories (OEM upstream): https://www.weintek.com/globalw/Support/Security.aspx
- NVD CVE search portal: https://nvd.nist.gov/vuln/search
- Claroty Team82 research index: https://claroty.com/team82/research
- Forescout Vedere Labs research: https://www.forescout.com/research-labs/
- Dragos blog (HMI / water-utility threat coverage): https://www.dragos.com/blog/
- MITRE ATT&CK for ICS T0812 Default Credentials: https://attack.mitre.org/techniques/T0812/
- MITRE ATT&CK for ICS T0830 Adversary-in-the-Middle: https://attack.mitre.org/techniques/T0830/
- MITRE ATT&CK for ICS T0832 Manipulation of View: https://attack.mitre.org/techniques/T0832/
- MITRE ATT&CK for ICS T0843 Program Download: https://attack.mitre.org/techniques/T0843/
- MITRE ATT&CK for ICS T0855 Unauthorized Command Message: https://attack.mitre.org/techniques/T0855/
- MITRE ATT&CK for ICS T0857 System Firmware: https://attack.mitre.org/techniques/T0857/
- MITRE ATT&CK for ICS T0866 Exploitation of Remote Services: https://attack.mitre.org/techniques/T0866/
- MITRE ATT&CK for ICS T0889 Modify Program: https://attack.mitre.org/techniques/T0889/

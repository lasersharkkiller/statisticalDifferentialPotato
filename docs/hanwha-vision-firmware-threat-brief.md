# Hanwha Vision (formerly Samsung Techwin / Hanwha Techwin) — Firmware Attack Surface & Detection Brief

**Scope:** CVE and public-advisory (OSINT) research only — **no firmware or software has been acquired or extracted for this vendor.** Every finding below comes from public vulnerability disclosures (NVD, CISA ICS advisories, vendor PSIRT) and product documentation. CVE IDs listed in the Confirmed table were each independently re-verified against NVD/CISA/vendor records before inclusion; candidate IDs that could not be confirmed were dropped, not guessed.

## Identity

| Field | Value |
|---|---|
| Census / OUI string | `Hanwha Vision VietNam` |
| Operating company | Hanwha Vision Co., Ltd. (Seongnam, South Korea), a subsidiary of Hanwha Group. "Hanwha Vision VietNam" is the company's Vietnam manufacturing subsidiary (60,000 sq m smart factory in Que Vo Industrial Park, Bac Ninh Province, opened 2017, mass production from 2018). The Vietnam plant is where Wisenet cameras/NVRs/lenses are built and MAC addresses are burned, so the OUI/registered name resolves to that entity, but the product line, firmware, and vulnerability response all belong to Hanwha Vision Co., Ltd. |
| OT devices (ARNG census) | 72 across 4 states |
| Genuine OT vendor? | Yes |
| Purdue placement | Levels 0-2 of a physical-security OT network. Cameras are edge sensors/field devices (L0 image sensor / L1 embedded device); NVRs doing local recording and the VMS doing local viewing sit at L2 (local supervision). Management tooling - Wisenet Device Manager and WAVE VMS servers/consoles - sits at L2-L3 (supervisory/operations), and on converged installs the security VLAN typically crosses into the IT/DMZ at L3-L3.5. Justification: cameras generate/forward streams but are managed, so they are edge devices; the NVR/VMS is the local control-and-record layer; WDM is the human-management layer. |

**Identity note.** Census string "Hanwha Vision VietNam" is an OUI/registered-name artifact of the manufacturing subsidiary, NOT a different company. Corporate lineage: Samsung Aerospace/Precision (late 1970s) -> Samsung Techwin -> acquired by Hanwha Group 2015 and renamed Hanwha Techwin -> rebranded Hanwha Vision in March 2023. The 72 census devices are genuine Hanwha/Samsung-Techwin physical-security products (Wisenet IP cameras, NVRs). Asset-owners should expect the installed base to span three brand generations of device labels/firmware (Samsung Techwin, Hanwha Techwin, Hanwha Vision) that are the same product family. Note: some OUIs on these devices may also appear registered to "Hanwha Techwin" or legacy "Samsung Techwin" ranges - treat all three as the same vendor for inventory.

## Product lines & OT relevance

Core physical-security OT: IP video surveillance (CCTV) and video management, deployed as force-protection/perimeter monitoring on National Guard facilities. These devices routinely bridge the physical-security VLAN to IT and to the facility environment, making them a recurring IT/OT pivot and a high-value target for both surveillance-blinding and lateral movement.

- Wisenet network/IP cameras - fixed, dome, bullet, PTZ, multi-sensor, AI, thermal (e.g. QNV-C8012, QND-8080R, and the P/Q/X/T/L series)
- Network Video Recorders (NVRs) and legacy DVRs (Wisenet recorders)
- WAVE VMS and SSM/SmartViewer video management software
- Wisenet Device Manager (WDM) - Windows fleet discovery/management/firmware tool
- WAVE/SolidEDGE SSD-based edge-storage cameras running VMS at the edge
- Thermal imaging and radiometric cameras
- Camera lenses, storage/accessory devices, and integrated access/security peripherals

## Attack surface

- HTTP/HTTPS web management UI with proprietary CGI endpoints (e.g. /stw-cgi/*, /cgi-bin/stw.cgi) - source of command injection and XSS flaws
- ONVIF (TCP 80/443) plus WS-Discovery device discovery (UDP 3702)
- RTSP video streaming (TCP 554), with RTP media ports
- Legacy default credentials: older Samsung/Hanwha Techwin cameras historically shipped with weak admin defaults (e.g. admin/4321); Wisenet Device Manager held hard-coded/shared default credentials (CVE-2025-52601). Modern firmware forces password-set on first boot, but unmanaged legacy units may still carry defaults
- ThroughTek Kalay P2P cloud connectivity embedded in NVRs - outbound P2P tunnels to vendor cloud (CVE-2021-28372)
- Wisenet Device Manager (Windows app) storing device credentials in UserConfig.xml readable by all local Windows users
- FTP/SMTP event delivery used to push analytics reports (abused in CVE-2025-52600)
- Unauthenticated/auth-bypass and OS command injection in the camera web server (CVE-2024-54012 / 54013)
- Firmware update channel via web UI and WDM; legacy devices may expose Telnet/SSH/SNMP/UPnP/mDNS

## Confirmed CVEs / advisories

Each row was re-verified against an authoritative record (URL given). This is the public disclosure history, not an exhaustive list.

| CVE / advisory | Applies to | Summary | Source |
|---|---|---|---|
| `CVE-2024-54013` | Named-product CVE for Hanwha Vision network cameras (QND-8080R and a long list of other Ha | Request-handling flaw in the Hanwha Vision camera web server allows authentication bypass / access to protected functions under certain conditions (CWE-306 miss | https://nvd.nist.gov/vuln/detail/CVE-2024-54013 |
| `CVE-2024-54012` | Named-product CVE for Hanwha Vision network cameras (QND-8080R plus many other models). Co | OS command injection via improper input validation in the Hanwha Vision camera web server (CWE-78); specially crafted requests run malicious commands on the dev | https://nvd.nist.gov/vuln/detail/CVE-2024-54012 |
| `CVE-2025-52601` | Affects Wisenet Device Manager, Hanwha's Windows fleet-management tool used to administer  | Hard-coded cryptographic key in Hanwha Vision Device Manager (WDM) lets an attacker decrypt stored sensitive information, including shared/default device creden | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-52601 |
| `CVE-2025-52600` | Named-product CVE spanning a wide range of Hanwha Vision network cameras. The malicious re | Client-side enforcement of server-side security / improper input validation in Hanwha Vision camera video-analytics (People Counting) reporting (CWE-602/CWE-20) | https://nvd.nist.gov/vuln/detail/CVE-2025-52600 |
| `CVE-2021-28372` | Supply-chain CVE: Hanwha NVRs embed the ThroughTek Kalay P2P SDK for cloud/remote connecti | Improper access control / device impersonation in ThroughTek's Kalay P2P SDK (Kalay Platform 2.0); an attacker with a device UID can hijack a victim's P2P conne | https://nvd.nist.gov/vuln/detail/CVE-2021-28372 |

## Detection guidance

- Inventory by OUI across Hanwha Vision / Hanwha Techwin / Samsung Techwin ranges; reconcile against the 72 census devices and flag any beyond the 4 expected states
- Monitor and baseline RTSP (TCP 554), HTTP/HTTPS (TCP 80/443), and ONVIF WS-Discovery (UDP 3702); alert on new talkers on these ports in the security VLAN
- Allowlist camera egress: a camera/NVR should only reach its NVR/VMS, NTP, DNS, and the firmware host. Alert on ANY camera or NVR initiating outbound Internet connections
- Specifically detect/deny outbound ThroughTek Kalay/TUTK P2P traffic (UDP to Kalay cloud) from NVRs - P2P should be disabled in an OT enclave
- Alert on HTTP access to proprietary CGI paths (/stw-cgi/eventsources.cgi, /cgi-bin/stw.cgi) from any host that is not the authorized VMS/WDM management station
- Collect logs from NVR/VMS audit trails, camera syslog, WDM activity, and the firewall at the security-VLAN boundary; watch WDM host filesystem for reads of UserConfig.xml
- Flag devices running firmware below patched baselines (camera X-series fixed in 2.24.00; WDM fixed in 2.9.3.1) as part of vuln management
- Segment the physical-security VLAN from IT/OT; force all management through a dedicated jump host and alert on management traffic originating elsewhere
- Watch FTP/SMTP event-delivery destinations configured on cameras for unexpected external targets

## Acquisition status

We currently hold NONE for this vendor. Firmware and software are distributed from Hanwha Vision's support portals (hanwhavision.com and hanwhavisionamerica.com) and are pulled/applied through the free Wisenet Device Manager (WDM) tool and WAVE/SSM VMS installers. Management software (WDM, WAVE, SmartViewer) is generally freely downloadable, while per-model camera/NVR firmware images are typically gated behind a free registered support account (partner/dealer tiers get broader access); some firmware is only delivered in-band via WDM rather than as a standalone file. S-CERT vulnerability reports are public PDFs on the vendor site. Realistic acquisition paths: (1) register a free support account and download management tooling plus available firmware; (2) obtain firmware in-band from a lab device via WDM; (3) extract firmware from a physical unit. Acquisition is therefore partially gated - low friction for tooling, account-gated for many firmware images.

## Notes

Verification discipline: every CVE above was confirmed in THIS research by fetching a live authoritative source - the NVD REST API (services.nvd.nist.gov) for each ID and the CISA page (cisa.gov/news-events/ics-advisories/icsa-21-229-01) for the ThroughTek advisory; the two Nozomi-disclosed 2025 IDs were cross-checked against the Nozomi Networks Labs write-up. No CVE here is from memory. Additional candidate IDs surfaced in search but were NOT individually verified and are therefore excluded from cve_claims: CVE-2025-52598/52599/8075 (Nozomi set - cert-validation, permission, XSS), CVE-2024-54011, CVE-2023-31994/31995/31996, CVE-2023-5037/5038, CVE-2021-32934, and CVE-2018-6301. Hanwha publishes its own S-CERT vulnerability-report PDFs (hanwhavision.com/.../wp-content/uploads/...) which are the authoritative vendor advisory source for follow-up. No standalone CISA/ICS-CERT advisory dedicated to Hanwha-branded cameras was found in this pass (only the upstream ThroughTek advisory). We hold no firmware/software, so this brief is OSINT/advisory only; detection guidance is behavior/protocol-based and does not depend on hash or firmware acquisition.

## Status

| Item | State |
|---|---|
| Firmware/software acquired | **No** — OSINT/advisory only |
| Confirmed CVEs | 5 (independently re-verified) |
| Behavioural baseline | None — no samples held |
| Next step | CISA/PSIRT deep pass; attempt firmware acquisition |

*Generated 2026-10-26 from the ot-vendor-briefs workflow (12 researchers + adversarial CVE verification). Device counts from the 2026-10-22 ARNG OT census.*

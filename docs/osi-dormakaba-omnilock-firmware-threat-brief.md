# OSI Security Devices / dormakaba (BEST Omnilock) — Firmware Attack Surface & Detection Brief

**Scope:** CVE and public-advisory (OSINT) research only — **no firmware or software has been acquired or extracted for this vendor.** Every finding below comes from public vulnerability disclosures (NVD, CISA ICS advisories, vendor PSIRT) and product documentation. CVE IDs listed in the Confirmed table were each independently re-verified against NVD/CISA/vendor records before inclusion; candidate IDs that could not be confirmed were dropped, not guessed.

## Identity

| Field | Value |
|---|---|
| Census / OUI string | `OSI Security Devices` |
| Operating company | dormakaba (dormakaba Americas / BEST brand) is the current operating and support company. Lineage: OSI Security Devices, Inc. (Chula Vista / originally Sunnyvale, CA) -> acquired by The Stanley Works (Stanley Security Solutions, later Stanley Black & Decker) -> BEST Access / commercial mechanical-hardware portfolio sold to dormakaba, deal closed 22 Feb 2017. The Omnilock product line was discontinued 31 Jan 2022 and succeeded by dormakaba's BEST Wi-Q. |
| OT devices (ARNG census) | 55 across 2 states |
| Genuine OT vendor? | Yes |
| Purdue placement | Spans Purdue Level 0-2 as a physical access control system. Door locks/readers = Level 0 (field actuators/sensors); the networked Portal Gateway (the 00:14:F5 IP device) = Level 1/2, bridging proprietary ISM-band RF field devices to the IP network; the WAMS/Wi-Q management host + Microsoft SQL Server = Level 2/3 (site/supervisory operations). The in-scope IP-reachable OUI devices sit at Level 1-2. |

**Identity note.** OUI 00:14:F5 (MA-L, ~16.7M addresses) is registered to OSI Security Devices, Inc., 1580 Jayken Way, Chula Vista, CA 91911; initial IEEE registration 17 Jun 2005, last updated 17 Nov 2015 (confirmed via maclookup.app; IEEE oui.txt is the authoritative source). OSI Security Devices was the maker of the Omnilock battery-powered standalone and wireless electronic access-control locks and the first vendor of a battery-operated standalone access system. The census string is the original OUI owner; the devices are OSI's own networked access-control hardware (Portal Gateways / networked locks), NOT a chip embedded in a third party's product. The real operating/support entity today is dormakaba, via the acquisition chain OSI -> Stanley -> dormakaba (2017). Treat the census name as an acquisition-lineage alias for dormakaba BEST Omnilock/Wi-Q when searching advisories and firmware.

## Product lines & OT relevance

Electronic physical access control (PACS): battery-powered door locks/readers, networked Portal Gateways, and the Windows/SQL management head-end. This is a legitimate OT / building-security asset class for a National Guard facility - these devices are the enforcement point for door access, so compromise translates directly to unauthorized physical entry, credential-database theft, or denial of access. 55 devices across 2 US states bearing OUI 00:14:F5 are almost certainly the IP-reachable components (Portal Gateways and/or networked locks); each Portal Gateway can fan out over RF to many doors (Wi-Q: up to 64 readers/gateway), so the physical footprint may be several times larger than the IP device count.

- Omnilock standalone electronic locks (OM100 / OM300 / OM500, OM2000 series) - keypad and/or HID prox / magstripe, programmed locally (historically via IR hand-held or PocketPC), factory-default master/programming codes
- Omnilock Wireless Access Management System (WAMS) - networked battery locks reporting to a Portal Gateway: 45HOM wireless mortise, 9KOM wireless cylindrical, OMEM electric modules
- Portal Gateway - the IP-connected bridge (carries the 00:14:F5 MAC) that acts like a wireless router between proprietary RF field locks and the TCP/IP management host
- BEST Wi-Q (dormakaba successor to Omnilock, EoS 2022 migration path) - 10/100/1000 Base-T + PoE portal gateway, up to 64 readers/gateway, up to 14,000 credentials/lock, AES-128 on the wireless link
- Management software: WAMS / Omnilock Facility Manager / OmniLink with a Microsoft SQL Server credential/audit database; integrates with C-CURE 9000 and Keri Doors.NET

## Attack surface

- End-of-life hardware: Omnilock discontinued 31 Jan 2022, so dormakaba issues no further firmware/security updates - these are unpatchable aging field devices with no vendor fix path (only warranty repair/replacement).
- IP-reachable Portal Gateway (OUI 00:14:F5) bridges proprietary RF locks to a Windows host running WAMS/Wi-Q over TCP/IP with a Microsoft SQL Server backend; the gateway, the management service, and the SQL instance are the primary network attack surface.
- Proprietary ISM-band spread-spectrum RF link (vendor literature cites ~900 MHz / 2.4 GHz for the Wi-Q generation) between gateway and battery locks; legacy Omnilock WAMS 'encrypted wireless' predates the AES-128 used by the Wi-Q successor, raising RF eavesdrop/replay/relay risk on the lock link (not standard 802.11/WPA, so no conventional Wi-Fi hardening applies).
- Documented factory-default master/programming codes on standalone locks (OM100/300/500, OM2000, OM Wireless differ by model); unchanged defaults permit trivial physical bypass at the keypad.
- Management-software and database exposure: WAMS / Omnilock Facility Manager / OmniLink credentials and the MS SQL credential/audit store - a host-PC or SQL compromise yields mass door control and theft of the full credential database.
- Credential layer: historical support for HID 125 kHz low-frequency prox cards, which are clonable, enabling credential duplication independent of the network.
- Corporate-parent context (NOT these devices): dormakaba's other PACS lines had critical unauthenticated remote-door-unlock vulnerabilities in 2024-2025 (Saflok 'Unsaflok'; exos 9300 / Access Manager), indicating the vendor's broader PACS exposure and that OSI/Omnilock assets live under a vendor with a demonstrated recent advisory burden.

## Confirmed CVEs / advisories

**No CVE or advisory was confirmed for this vendor in this pass.** This is recorded as an **absence of information, not a clean bill of health** — for a vendor of this fleet size the likelier explanations are limited public research attention or a vendor that does not publish advisories where researchers find them. A direct CISA/vendor-PSIRT pass and, ultimately, firmware acquisition are the ways to close it.

## Detection guidance

- Asset ID: fingerprint OUI 00:14:F5 (OSI Security Devices) in DHCP lease logs, switch CAM/MAC tables, and ARP caches - primary signal to locate and inventory the 55 devices and map each to a physical door/gateway.
- Segmentation + allowlist: place all OSI/Omnilock gateways on a dedicated PACS VLAN; allowlist so each gateway talks ONLY to the WAMS/Wi-Q management host - no peer gateway traffic, no Internet egress, no lateral IT paths.
- Management server monitoring: watch Microsoft SQL Server (TCP 1433) and the WAMS/Wi-Q gateway-to-host service (vendor-configured TCP port - verify per deployment); alert on new gateways, off-hours sessions, or sources outside the PACS VLAN.
- SIEM log sources: WAMS/Wi-Q application + audit logs (grant/deny, door-forced, door-held, battery, programming/credential-change), Windows host event logs, MS SQL audit, switch/DHCP logs.
- Treat as unpatchable (EoL): deny inbound from IT/corporate, block outbound Internet, alert on any firmware/config write, new management session, or bulk credential change; reconcile changes against change-control.
- Behavioral baselining: alert on repeated denied credentials, door-forced/held events, and mass credential/schedule changes suggesting RF replay/relay or head-end compromise.

## Acquisition status

We currently hold NO firmware or software for this vendor. Firmware images are NOT publicly downloadable. Omnilock/Wi-Q software (WAMS / Access Control Management) and lock firmware are distributed through the dormakaba / BEST authorized-dealer channel and the dormakaba hardware support portal (dhwsupport.dormakaba.com). That portal exposes public user/admin manuals (OM100/300/500 user guides, 2000-series Administrator's Guide, reset articles) but gates firmware and software binaries behind dealer accounts or support registration. Because Omnilock is end-of-sale (2022), current firmware is archive-only via dormakaba support. No images are present on open firmware/malware repositories; acquisition would require a dealer/support account or a direct request to dormakaba. Acquisition is gated, not open.

## Notes

NO CVE applies to the OUI 00:14:F5 (OSI Security Devices / Omnilock) hardware. NVD keyword searches returned totalResults=0 for both 'Omnilock' and 'OSI Security Devices' (queried via services.nvd.nist.gov in this research). Per the no-fabrication rule, cve_claims is intentionally empty rather than padded with inapplicable IDs.

PARENT-COMPANY CONTEXT (verified real, but these are OTHER dormakaba product lines, NOT the census devices - do NOT pivot on them as if they affect Omnilock/Wi-Q):
- dormakaba exos 9300 / Access Manager (9200-K5 Windows CE, 9200-K7 Linux): CVE-2025-59097 through CVE-2025-59108 (e.g. CVE-2025-59097 unauthenticated SOAP API CVSS ~9.3, CVE-2025-59103 weak default SSH passwords, CVE-2025-59108 weak default web password), disclosed by SEC Consult (sec-consult.com/vulnerability-lab/advisory/multiple-critical-vulnerabilities-in-dormakaba-access-manager/) in 2025. The advisory's affected-products field names ONLY the dormakaba Access Manager / exos 9300 and explicitly does not mention Omnilock, BEST Wi-Q, or Stanley Wi-Q.
- dormakaba Saflok RFID hotel locks: 'Unsaflok' keycard-forgery flaws (2024), a separate hospitality product line, not Omnilock/PACS.
These show the current parent (dormakaba) carries a real recent PACS advisory burden, which matters for vendor-risk scoring, but none of these IDs were verified to touch the OSI/Omnilock/Wi-Q hardware in scope.

RF/crypto caveat: 900 MHz / 2.4 GHz ISM spread-spectrum and AES-128 (Wi-Q) come from vendor/integration literature (Doors.NET note cited firmware 4.11.7, AES-128, 10/100/1000 PoE portal gateway); the legacy Omnilock WAMS used older 'encrypted wireless'. Confirm exact RF band, ports, and firmware against the specific deployed models before acting.

SUGGESTED BRIEF TITLE/ALIASES for the OTSDP inventory: 'OSI Security Devices (dormakaba BEST Omnilock / Wi-Q)'.

## Status

| Item | State |
|---|---|
| Firmware/software acquired | **No** — OSINT/advisory only |
| Confirmed CVEs | 0 (independently re-verified) |
| Behavioural baseline | None — no samples held |
| Next step | CISA/PSIRT deep pass; attempt firmware acquisition |

*Generated 2026-10-26 from the ot-vendor-briefs workflow (12 researchers + adversarial CVE verification). Device counts from the 2026-10-22 ARNG OT census.*

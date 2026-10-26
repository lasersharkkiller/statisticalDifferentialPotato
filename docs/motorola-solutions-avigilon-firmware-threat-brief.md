# Motorola Solutions (Avigilon / Ava video + LMR) — Firmware Attack Surface & Detection Brief

**Scope:** CVE and public-advisory (OSINT) research only — **no firmware or software has been acquired or extracted for this vendor.** Every finding below comes from public vulnerability disclosures (NVD, CISA ICS advisories, vendor PSIRT) and product documentation. CVE IDs listed in the Confirmed table were each independently re-verified against NVD/CISA/vendor records before inclusion; candidate IDs that could not be confirmed were dropped, not guessed.

## Identity

| Field | Value |
|---|---|
| Census / OUI string | `Motorola Solutions Inc.` |
| Operating company | Motorola Solutions, Inc. (NYSE: MSI), Chicago, IL. The census/OUI registrant maps directly to the real company — this is not a rebrand mismatch. Motorola Solutions is the enterprise/government/public-safety half of the old Motorola that split in 2011 (consumer handsets went to Motorola Mobility -> Google -> Lenovo). The OT-relevant business is its Video Security & Access Control (VS&A) portfolio plus Land Mobile Radio (LMR). |
| OT devices (ARNG census) | 84 across 7 states |
| Genuine OT vendor? | Yes |
| Purdue placement | Mixed physical-security zone spanning Purdue L1-L3: cameras/door-controllers/LPR at the field/edge (L1-L2), VMS and radio dispatch head-ends at supervisory (L2-L3), and cloud-managed lines (Avigilon Alta, Ava, WAVE, CommandCentral) egressing to the internet (L3/L4-5), so the cloud path must be modeled as crossing the DMZ rather than as isolated OT. |

**Identity note.** The string is the true registrant, but "Motorola Solutions" is a very broad OUI owner, so a bare OUI/name match does NOT tell you which product you have. For an OT/physical-security census it almost always resolves to one of several acquired brands: Avigilon (acquired 2018 — IP cameras, NVRs, Avigilon Control Center VMS), Ava Security (2021 — cloud cameras), Pelco, Inc. (acquired 2020; Pelco was a Schneider Electric brand 2007-2020, so older Pelco advisories are filed under Schneider Electric), Openpath (2021, now rebranded "Avigilon Alta" cloud access control), IndigoVision, and Vigilant Solutions / VaaS (2019 — automatic license-plate readers / ALPR). On the comms side the same registrant covers APX and ASTRO (P25) LMR, MOTOTRBO (DMR), and Dimetra / MTM5000-MTM5400 (TETRA) infrastructure and subscriber radios. Caveat for the 84 devices: fingerprint each one to a product family (ONVIF/RTSP/HTTP banner, device model, VLAN) before acting — a Motorola OUI cannot by itself distinguish a camera from a door controller from a radio, and some legacy Motorola OUI blocks historically shipped in third-party/consumer gear (e.g., cable modems). US National Guard LMR is typically P25/ASTRO (APX), not TETRA, so TETRA findings may not apply unless Dimetra/MTM gear is actually present.

## Product lines & OT relevance

Genuine OT / physical-security vendor. Supplies video surveillance, access control, ALPR, and mission-critical land-mobile-radio that run on a Guard facility's security/operations networks.

- Avigilon IP cameras / multi-sensor cameras / H4-H5 series and NVRs (Avigilon Unity on-prem)
- Avigilon Control Center (ACC) video management server/client; Ava / Avigilon Alta cloud-native video
- Pelco IP cameras (Sarix Professional / Sarix Enhanced series), Spectra PTZ, VideoXpert VMS
- Avigilon Alta (formerly Openpath) cloud access control: Smart Hub / ACU and Single Door Controller (PoE) with RS-485 readers; legacy Avigilon Access Control Manager (ACM)
- Vigilant / VaaS automatic license-plate readers (ALPR), e.g. Fixed LPR Coms Box (BCAV1F2-C600), and LEARN/CarDetector backend
- IndigoVision and HALO (IPVideo) sensor integrations
- Land Mobile Radio: APX subscriber radios and ASTRO 25 (P25) infrastructure, MOTOTRBO (DMR), Dimetra / MTM5000-MTM5400 (TETRA) — mission-critical voice/data
- CommandCentral / dispatch (CAD) and WAVE PTX broadband push-to-talk (higher-layer, cloud/enterprise)

## Attack surface

- IP cameras (Avigilon/Pelco/Ava): ONVIF (WS-Discovery UDP 3702), RTSP media TCP 554, HTTP/HTTPS web admin 80/443, RTP/RTCP streams; older/edge devices may expose Telnet/SSH. Web admin UIs are the primary foothold (XSS, auth bypass).
- Video management: Avigilon Control Center (ACC) proprietary client-server services and Pelco VideoXpert web services — high-value servers aggregating all camera feeds and credentials.
- Access control: Avigilon Alta/Openpath controllers connect outbound TCP 443 (cloud) and UDP 123 (NTP), optional UDP 53 (DNS); LAN-side TCP 443 inbound for mobile Wi-Fi unlock; RS-485 to readers (OSDP, or legacy Wiegand which is unauthenticated/clonable). Vendor prohibits TLS/SSL inspection of Alta traffic.
- ALPR (Vigilant Fixed LPR Coms Box): confirmed hidden maintenance Wi-Fi access point with hard-coded credentials, GRUB bootloader modifiable with physical access, local OS login via default credentials, cleartext on-disk storage of credentials/hotlist data, and capture-replay of device-to-backend transmissions.
- Default/hard-coded credential history: documented on Vigilant LPR (CVE-2024-38281/38282); default admin credentials have historically been common across Avigilon and Pelco camera lines.
- Land Mobile Radio: over-the-air interface and network side (P25 ISSI/console, DMR IP Site Connect, TETRA air interface). TETRA/Dimetra subscriber radios (MTM5000/5400) have air-interface encryption and PRNG weaknesses (TETRA:BURST) enabling traffic decryption/key recovery where that gear is present.
- Common exposure pattern: internet-reachable camera web UIs and RTSP streams discoverable via Shodan/Censys; cloud access-control egress; and physical tamper of curbside/perimeter LPR and camera units.

## Confirmed CVEs / advisories

Each row was re-verified against an authoritative record (URL given). This is the public disclosure history, not an exhaustive list.

| CVE / advisory | Applies to | Summary | Source |
|---|---|---|---|
| `CVE-2024-38282` | Directly a Motorola Solutions product — Vigilant/VaaS ALPR, acquired 2019. Applies if any  | Insufficiently protected credentials (CWE-522): default credentials allow login to the Vigilant Fixed LPR Coms Box (BCAV1F2-C600) operating system, enabling ope | https://nvd.nist.gov/vuln/detail/CVE-2024-38282 |
| `CVE-2024-38281` | Same Motorola Solutions Vigilant LPR product line; the hidden Wi-Fi AP is an on-site RF at | Hard-coded credentials (CWE-798) for a hidden wireless maintenance network on the Vigilant Fixed LPR Coms Box grant access to the maintenance console. CVSS v4.0 | https://nvd.nist.gov/vuln/detail/CVE-2024-38281 |
| `CVE-2024-38284` | Same Motorola Solutions Vigilant LPR product; network-reachable, so it is the highest-prio | Authentication bypass by capture-replay (CWE-294): logged device-to-backend transmissions from the Vigilant Fixed LPR Coms Box can be replayed. CVSS v3.1 8.8 /  | https://nvd.nist.gov/vuln/detail/CVE-2024-38284 |
| `CVE-2026-1241` | Pelco is a Motorola Solutions brand (acquired 2020). Applies if any devices are Pelco Sari | Authentication bypass in the web management interface (CWE-288) of Pelco Sarix Professional 3 Series cameras (models IMP/IXP/IBP/IWP 3, firmware <= 02.52): inad | https://nvd.nist.gov/vuln/detail/CVE-2026-1241 |
| `CVE-2021-38701` | Avigilon is a Motorola Solutions brand (acquired 2018). Applies to the Avigilon camera fle | Stored cross-site scripting (XSS) in the administrative interface of multiple Motorola Solutions Avigilon camera models (T008, T100-T103, T200/T201, T204, T205, | https://nvd.nist.gov/vuln/detail/CVE-2021-38701 |
| `CVE-2022-26943` | Motorola Solutions TETRA subscriber radio (Dimetra ecosystem). Applies ONLY if Dimetra/TET | Motorola MTM5000-series (TETRA) radio firmware derives TETRA authentication challenges from a PRNG whose only entropy source is a tick-count register; low boot  | https://nvd.nist.gov/vuln/detail/CVE-2022-26943 |

## Detection guidance

- Inventory and fingerprint: map each Motorola-OUI device to a product family using ONVIF WS-Discovery (UDP 3702), RTSP/HTTP server banners ('Avigilon', 'Pelco', 'Ava'), and device model pages — do not act on OUI alone.
- Watch camera/VMS ports: RTSP TCP 554, HTTP/HTTPS 80/443 on the camera VLAN; alert on RTSP/ONVIF sessions sourced from any host that is not the authorized VMS (ACC/VideoXpert) server.
- Access control egress: allowlist and monitor Avigilon Alta/Openpath outbound TCP 443 to vendor cloud FQDNs (alta.avigilon.com / openpath.com) and UDP 123 NTP; Enterprise-tier Alta offers a Static Cloud IP so egress can be pinned to a few addresses. Because the vendor forbids TLS inspection, allowlist by FQDN/IP rather than decrypt.
- Log sources to onboard to SIEM: ACC/VideoXpert audit logs, Avigilon Alta/Openpath cloud admin + door-event API, camera syslog, access-control door/reader events, and (for LMR) ASTRO/Dimetra system and KMF/key-management logs.
- Alert conditions: unexpected or hidden SSID beaconing near LPR/camera units (maintenance Wi-Fi), new/changed ONVIF or camera admin accounts, unscheduled firmware changes, and any inbound connection from the internet to a camera/VMS/controller.
- Segmentation/allowlisting: place cameras, VMS, controllers, and LPR on dedicated management VLANs behind a firewall, deny inbound internet, and permit only the specific cloud egress the access-control/cloud-camera products require (CISA ICSA-24-165-19 guidance).

## Acquisition status

We currently hold NO firmware or software for this vendor, and acquisition is largely gated by entitlement. Avigilon camera firmware and Avigilon Control Center (ACC) software are distributed through the Avigilon/Motorola partner and support portals (partner.avigilon.com / Motorola Solutions support), requiring an authorized partner or customer account; ACC can also pull/push camera firmware from the client. Pelco firmware is via pelco.com / Pelco Partner First — historically some camera firmware was publicly downloadable, but it is now largely account-gated. Vigilant ALPR software/firmware is fully gated (CJIS/law-enforcement entitlement) and updated by Motorola over-the-air. LMR (APX/ASTRO/MOTOTRBO/Dimetra) firmware and codeplugs come through Customer Programming Software (CPS) behind Motorola Online (MOL) with device entitlement and feature-key licensing — strongly gated, often needing a service agreement. Realistic near-term path for this advisory is OSINT only: public datasheets, admin/web-interface user guides, and CVE/ICS-CERT advisory detail; obtaining actual firmware blobs will require vendor/partner entitlement or lawful sample acquisition.

## Notes

Confidence: HIGH on identity and product mapping; HIGH on CVEs (every CVE below was verified in this session — CVE-2024-38279..38285 via the CISA advisory page fetched directly at cisa.gov/news-events/ics-advisories/icsa-24-165-19, and CVE-2026-1241 / CVE-2021-38701 / CVE-2022-26943 via the NVD REST API). No CVE here was recalled from memory; none fabricated. The full Vigilant LPR advisory ICSA-24-165-19 actually contains 7 CVEs (CVE-2024-38279 through CVE-2024-38285); I listed the three most SOC-actionable (default creds, hidden-Wi-Fi hard-coded creds, network capture-replay) — the remaining four (38279 bootloader auth bypass, 38280 cleartext disk, 38283 missing encryption, 38285 credential-logging) are all physical-access and also in that advisory if you want the complete set. KEY CAVEAT for the 84 devices: this is an OUI/name census, so fingerprint each device to a product family before applying any finding — Motorola Solutions OUIs span cameras, access controllers, LPR, and radios, and TETRA findings in particular likely do not apply to a P25/ASTRO (APX) Guard radio estate. Historical note for Pelco: pre-2020 Pelco advisories are filed under Schneider Electric (e.g., SEVD-2018-058-01, SEVD-2019-045), useful if older Sarix/Spectra firmware is in play.

## Status

| Item | State |
|---|---|
| Firmware/software acquired | **No** — OSINT/advisory only |
| Confirmed CVEs | 6 (independently re-verified) |
| Behavioural baseline | None — no samples held |
| Next step | CISA/PSIRT deep pass; attempt firmware acquisition |

*Generated 2026-10-26 from the ot-vendor-briefs workflow (12 researchers + adversarial CVE verification). Device counts from the 2026-10-22 ARNG OT census.*

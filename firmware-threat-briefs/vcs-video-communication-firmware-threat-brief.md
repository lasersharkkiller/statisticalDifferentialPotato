# VCS / Bosch Video Communication Systems (VideoJet encoders) — Firmware Attack Surface & Detection Brief

**Scope:** CVE and public-advisory (OSINT) research only — the firmware/software itself **was acquired** via VirusTotal Intelligence into the known-good baseline (_update 2026-10-27; see the behavioural-differential section where present_), though not fully rootfs-extracted. Every finding below comes from public vulnerability disclosures (NVD, CISA ICS advisories, vendor PSIRT) and product documentation. CVE IDs listed in the Confirmed table were each independently re-verified against NVD/CISA/vendor records before inclusion; candidate IDs that could not be confirmed were dropped, not guessed.

> **Lineage / cross-reference.** Bosch-lineage. Shares the Bosch PSIRT and download channel; see also bosch-security-firmware-threat-brief.md (camera generations). This brief covers the distinct VideoJet/VIP encoder line carried by OUI 00:07:5F.

## Identity

| Field | Value |
|---|---|
| Census / OUI string | `VCS Video Communication Systems AG` |
| Operating company | Bosch. VCS (Video Communication Systems, Nuremberg, Germany, founded 1995) was acquired 100% by Bosch Security Systems in July 2004 and absorbed into Bosch's video-surveillance product line (VideoJet / VIP family). That product business (Video, Access, Intrusion, Communications of Bosch Building Technologies) was divested to Triton Partners; the deal was announced Dec 2024 and completed in 2025, and the unit now operates independently (branded Keenfinity Group; support KB migrated to keenfinity-group.com). Fielded devices remain Bosch-branded. |
| OT devices (ARNG census) | 246 across 15 states |
| Genuine OT vendor? | Yes |
| Purdue placement | Primarily Purdue Level 1-2 within the physical-security subsystem: the encoders/video servers are edge field devices (digitize and stream camera feeds). The VMS/VRM/DIVAR IP recording-and-management tier sits at Level 2-3 (supervisory/operations). None of it is legitimately Internet-facing; on a flat/converged OT network it commonly lands on a dedicated security VLAN. |

**Identity note.** "VCS Video Communication Systems AG" is the IEEE-registered owner of MA-L OUI block 00:07:5F (00:07:5F:00:00:00 - 00:07:5F:FF:FF:FF), registered 2001-10-24, last updated 2015-11-17, address Forchheimer Str. 4, Nuremberg, Germany; Wireshark label "VCSVideoComm". This is an acquisition-lineage / rebrand artifact, NOT a component-chip OUI and NOT an IT vendor misfile: VCS was a genuine CCTV-over-IP video-server/encoder manufacturer bought by Bosch in 2004. Devices bearing 00:07:5F are VCS-origin / early-Bosch network video encoders and video servers now part of the Bosch VideoJet / VIP X family. The OUI block predates the acquisition and predates most modern Bosch IP-video OUIs, so these 246 census devices are likely legacy/EOL encoder hardware (circa 2001-2010).

## Product lines & OT relevance

Genuine physical-security OT. These are network video encoders / video servers that digitize analog CCTV cameras onto IP networks, plus the associated decoder/VMS/recording tier. In a National Guard facility context they belong to the physical-security subsystem (perimeter/surveillance CCTV) on the converged OT/building network. They are field/edge video devices, not IT endpoints: unauthenticated or default-credentialed video streams, proprietary control protocols, and long-lived EOL firmware make them a standard OT-SOC concern (reconnaissance of camera coverage, stream tampering, and pivot/foothold on the security VLAN).

- Network video encoders / video servers (VideoJet family): VideoJet X10/X20/X40 SN, VideoJet multi 4000, VideoJet 8000/1000, legacy VideoJet 10/100/400 - the direct VCS lineage carrying OUI 00:07:5F
- VIP (Video-over-IP) encoder modules: VIP X1600 / VIP X1-XF rack and standalone encoders
- Rugged/outdoor encoders: VideoJet X20S (VJT-X20S) hardened units with onboard storage
- Network video decoders: VIDEOJET decoder 7000/8000 (VJD-7513, VJD-8000)
- Supervisory/management tier these devices integrate with: Bosch Video Management System (BVMS), Video Recording Manager (VRM), DIVAR IP all-in-one / 7000 recorders

## Attack surface

- RCP+ (Bosch proprietary remote-control/discovery/config protocol) on TCP/UDP 1756, 1757, 1758 - used by Configuration Manager and BVMS to discover, configure and control devices; port 1756 can be toggled but 1757/1758 are the strong Bosch IP-video fingerprint
- Embedded web configuration UI over HTTP (80, or 10000-10100) and HTTPS (443, or 10443-10543)
- RTSP video streaming on 554 and RTSPS on 9554; ONVIF support added at firmware 4.10+ (older ONVIF may stream without auth)
- Three built-in accounts on every device: service (full admin), user (operator: playback+PTZ), live (live view only)
- Default-credential history: legacy VIP/VideoJet units shipped with NO password set or with service/service (some Dinion-class with blank password); forced password-on-first-use only arrived with firmware ~6.30-6.32, and the 00:07:5F census devices largely predate that - so unauthenticated or default-service access is a realistic live risk on these units
- Password-clear behavior: from firmware 6.51.0026 a clear resets the service password back to the literal string 'service'
- Unencrypted UDP multicast video distribution (interceptable on-path); UPnP/SSDP discovery; iSCSI (3260) to recording storage; SNMP (v3) where enabled
- Legacy/EOL exposure: discontinued encoder models receive no further firmware, so known web-UI and protocol bugs persist unpatched; Bosch IP-video web UIs, RCP+ and RTSP are routinely found exposed on Internet scan engines

## Confirmed CVEs / advisories

Each row was re-verified against an authoritative record (URL given). This is the public disclosure history, not an exhaustive list.

| CVE / advisory | Applies to | Summary | Source |
|---|---|---|---|
| `CVE-2022-40183` | Directly affects a Bosch VIDEOJET-family network video encoder - the exact product class t | Reflected cross-site scripting (CWE-79) in the web-based interface of the Bosch VIDEOJET multi 4000 network video encoder, via a URL-handler error; affects firm | https://cveawg.mitre.org/api/cve/CVE-2022-40183 |
| `CVE-2022-32540` | Affects the Bosch VideoJet/BVMS video ecosystem these VCS-origin encoders are deployed int | Information disclosure (CWE-200) in the BVMS Operator Client (10.1.1, 11.0, 11.1.0) and VIDEOJET Decoder VJD-7513 (10.23, 10.30): a man-in-the-middle attacker c | https://nvd.nist.gov/vuln/detail/CVE-2022-32540 |
| `CVE-2021-23862` | Affects the VIDEOJET decoder tier and management/recording components of the same Bosch Vi | Authenticated remote code execution / OS command injection (CWE-78/CWE-20): a crafted configuration packet from an authenticated administrator executes arbitrar | https://nvd.nist.gov/vuln/detail/CVE-2021-23862 |

## Detection guidance

- Asset-inventory by OUI 00:07:5F (VCS) and by current Bosch IP-video OUIs; flag any new/unexpected 00:07:5F MAC appearing on the network
- Fingerprint Bosch IP video on the wire by RCP+ traffic to TCP/UDP 1756-1758 - the most specific indicator; alert on RCP+ config-WRITE flows originating from any host other than the sanctioned Configuration Manager / BVMS management station
- Monitor RTSP 554 / RTSPS 9554 pulls and alert on stream requests from clients that are not the VMS/VRM; monitor HTTP 80 & 10000-10100 and HTTPS 443 & 10443-10543 to the device web UIs
- Log sources: BVMS/Configuration Manager audit logs; device syslog where firmware supports it; switch NetFlow/IPFIX for multicast video groups and for east-west RCP+/RTSP; ONVIF/SSDP discovery chatter
- Allowlisting/segmentation: place all encoders on a dedicated physical-security VLAN; permit each encoder to talk ONLY to the VMS/VRM/recorder (RCP+, video) and NTP; deny all inbound Internet and block RCP+/RTSP/ONVIF egress at the OT boundary; deny device-to-device traffic between encoders
- Alert on authentication to the service account, on firmware-upload attempts, and on config changes outside a maintenance window; baseline that these legacy units should essentially never initiate outbound connections

## Acquisition status

We currently hold NONE for this vendor. Firmware/software for in-support Bosch VideoJet/VIP devices is distributed as .fw images plus release letters from the Bosch Security download store (downloadstore.boschsecurity.com) and the Bosch Building Technologies / Keenfinity download area; these are generally publicly downloadable and NOT credential-gated, and the Bosch Configuration Manager tool used to flash/configure them is also a free download. However, the 00:07:5F census devices are VCS-era / discontinued models: their legacy firmware is largely archived or removed from the public store and may be hard to obtain without an EOL/support request. Some enterprise components (BVMS, VRM, DIVAR IP) sit behind a Bosch partner/account login. Net: ungated/obtainable for current-generation encoder firmware; gated-by-obsolescence (not by paywall) for the exact legacy units this OUI represents.

## Notes

Diligence: candidate CVE-2020-24215 surfaced in searches tied to "video encoder" but was INVESTIGATED AND EXCLUDED - it affects HiSilicon-based IPTV encoders (Szuray, Jtechdigital, Provideoinstruments Vecaster), NOT Bosch/VCS, so it is deliberately not listed. All three listed CVEs were verified against real NVD-mirror/CERT pages (INCIBE-CERT, GCVE) in this research with Bosch PSIRT advisory IDs cross-referenced; no CVE ID was recalled from memory. CAVEAT on OUI precision: the three CVEs are 2021-2022 vintage against current-generation VideoJet encoders/decoders and BVMS; the 246 census devices on OUI 00:07:5F are more likely VCS-era/legacy encoder hardware (block registered 2001). They share the product lineage and the protocol/credential attack surface, but exact affected-firmware overlap with these specific legacy units is unconfirmed without pulling the devices' actual model/firmware. The highest-confidence operational risk for these legacy units is not a specific CVE but the pre-forced-password default-credential posture (service/service or no password) plus unpatched EOL firmware. Recommended next step if higher fidelity is needed: enumerate actual model strings and firmware versions from the 246 devices and map against the Bosch PSIRT advisory catalog (psirt.bosch.com) and CERT@VDE Bosch bulletins.

## Status

| Item | State |
|---|---|
| Firmware/software acquired | **No** — OSINT/advisory only |
| Confirmed CVEs | 3 (independently re-verified) |
| Behavioural baseline | None — no samples held |
| Next step | CISA/PSIRT deep pass; attempt firmware acquisition |

*Generated 2026-10-26 from the ot-vendor-briefs workflow (12 researchers + adversarial CVE verification). Device counts from the 2026-10-22 ARNG OT census.*

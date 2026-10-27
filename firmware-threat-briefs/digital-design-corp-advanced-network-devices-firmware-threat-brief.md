# Digital Design Corporation / Advanced Network Devices (IP mass-notification) — Firmware Attack Surface & Detection Brief

**Scope:** CVE and public-advisory (OSINT) research only — **no firmware or software has been acquired or extracted for this vendor.** Every finding below comes from public vulnerability disclosures (NVD, CISA ICS advisories, vendor PSIRT) and product documentation. CVE IDs listed in the Confirmed table were each independently re-verified against NVD/CISA/vendor records before inclusion; candidate IDs that could not be confirmed were dropped, not guessed.

> **Lineage / cross-reference.** The census string 'Digital Design Corporation' resolves to Advanced Network Devices ('AND'); it is NOT the same company as 'Digital Systems Corp' (Galaxy Control Systems), which has its own brief.

## Identity

| Field | Value |
|---|---|
| Census / OUI string | `Digital Design Corporation` |
| Operating company | Advanced Network Devices, Inc. (brand "AND", anetd.com), the networked-endpoint product arm co-located with and sharing the IEEE OUI of Digital Design Corporation (digidescorp.com). Both are Donahoe-family firms in the same Arlington Heights, IL facility; DDC is the FPGA/embedded engineering parent and OUI registrant of record, AND is the commercial OT product brand under which the census devices actually ship. |
| OT devices (ARNG census) | 160 across 11 states |
| Genuine OT vendor? | Yes |
| Purdue placement | Level 1/2 field edge devices of a building mass-notification / public-address / life-safety OT system. The endpoints (speakers, displays, strobes, intercoms, GPIO relays) are the Level 1 actuators/sensors; the IPClockWise / InformaCast / Syn-Apps / BellCommander servers and SIP PBX that drive them are the Level 2-3 supervisory layer. On a typical flat Guard facility network they sit in a building-systems/physical-security VLAN alongside cameras, access control and BAS, which is where the census found them. |

**Identity note.** The census string is the OUI owner, not the product brand. OUI 00:11:90 (IEEE MA-L, registered 2004-06-15, last updated 2015-11-17) is registered to "Digital Design Corporation, 3820 Ventura Dr, Arlington Heights, IL 60004" (confirmed via maclookup.app). DDC (digidescorp.com) is an FPGA/ASIC/board design house whose own branded products are VAADR military/airborne video-and-data recorders and image-enhancement platforms — not the devices one would expect to see 160x across Guard facilities. DDC's corporate overview, however, lists an "Advanced Network Products & Solutions" line, and its sister/spinoff company Advanced Network Devices, Inc. (anetd.com, founded 2004 by Brian Donahoe; DDC founder/CEO is Debbie Donahoe) sits at 3860 N Ventura Dr in the same park, shares the same fax line (847-359-5418), and ships its IP endpoints under the shared OUI 00:11:90. Therefore devices carrying 00:11:90 on an OT/physical-security VLAN are almost certainly AND IP speakers/displays/clocks/intercoms, not DDC avionics recorders. Map the census entry to the AND / anetd.com product line.

## Product lines & OT relevance

Genuine OT / life-safety building system. AND (under OUI 00:11:90) makes IP-based mass-notification, emergency paging, intercom, bell-schedule and clock/display endpoints — PoE devices that live on the facility network and are exactly the kind of gear that appears in large counts (160 across 11 states is consistent with mass-notification/giant-voice, paging, intercom and clock coverage across many Guard buildings). They belong in the same physical-security/building-automation census bucket as the other vendors on the ARNG exposure page (Genetec, Hanwha Vision, Motorola Solutions, Trane, OSI Security Devices). This is NOT an OUI-artifact false positive and NOT an IT vendor misfiled as OT: the endpoints themselves are the networked OT assets. One nuance worth flagging to the SOC: the built-in microphone + two-way "monitoring"/paging-supervision on the speaker line makes these also an audio-surveillance exposure, not just an availability/notification concern.

- IP speakers (PoE/PoE+) incl. IPSWD (speaker + LED display), IPSWS surface/ceiling mount, indoor/outdoor models; built-in microphone for two-way talkback/intercom and 'paging supervision'/monitoring
- IP clocks / LED message displays (IPCS, IPCSL large-format, IPDisplay; NTP-synced, scrolling text, RSS/weather/alert feeds, double-sided models)
- IP visual-notification strobes/flashers and IP call/panic buttons (GPIO: 2 inputs, 1 output, activatable by phone or programmatically)
- IP intercom / classroom-to-office intercom and zone/overhead paging endpoints
- PoE hubs/injectors and mounting accessories
- Management/software: AND IPClockWise / 'Clockwise Campus' (bell schedules, alarms, events, sound library) and 'Vigilar' threat-detection; interoperates with Singlewire InformaCast, Syn-Apps SA-Announce, IPCelerate IPSession, MessageNet, AcroVista BellCommander, Cisco, and any SIP PBX (Asterisk/3CX/ShoreTel)
- (Parent DDC branded line, NOT the census devices: VAADR military/airborne video-and-data recorders, real-time image-enhancement platforms, AVB/TSN FPGA IP cores)

## Attack surface

- Protocol set per AND's own IPSWD datasheet: SIP, HTTP (cleartext web admin; no HTTPS advertised on these endpoints), SLP, TFTP, NTP, SNMPv1, DHCP, IGMP, ICMP, mDNS/mDNS-SD (Bonjour), IPv4/TCP/UDP, plus full multicast + broadcast audio/text.
- Untrusted zero-touch provisioning is the headline vector: on boot the device auto-discovers a config file via DHCP options or SLP, then downloads BOTH configuration AND firmware over cleartext TFTP/HTTP from a server supplied by (1) SLP, (2) DHCP option 150 TFTP, (3) DHCP option 66 TFTP, or (4) DHCP option 72 HTTP (dir '/ipspeaker/'). A rogue DHCP server or spoofed SLP responder on the L2 segment can redirect endpoints to attacker-controlled firmware/config — effectively an unauthenticated firmware-implant path.
- SIP credentials (extension id, password, digest_username) are stored in cleartext XML config files (e.g. AllSpeakers.cfg) delivered over TFTP/HTTP; AND's own guide example uses password="password123". Intercepting or pulling the provisioning file yields PBX-registerable SIP creds and a pivot/toll-fraud path.
- Built-in microphone with two-way talkback, hands-free 'monitoring' and 'paging supervision' on the speaker line = live audio eavesdropping risk if an endpoint or its control server is compromised — a counterintelligence concern at a Guard facility.
- Web server is 'field upgradable' (firmware uploaded via the on-box web UI). Public datasheets/guides do not document any default web-admin credential or mandatory auth; historically this class of endpoint shipped with weak or no enforced web authentication. Treat the web interface as unauthenticated-until-proven and verify on a sample; do NOT assume a hardened login.
- SNMPv1 only (cleartext, community-string based — default/guessable community strings typical) for status/management.
- SLP (udp/427) and mDNS/Bonjour (udp/5353) broadcast discovery expose device name/IP/firmware version for easy enumeration; devices are also reachable by Bonjour hostname (IPSpeaker<MAC>.local) and IPv6 link-local.
- Network-addressable GPIO (2 in / 1 out) 'activatable via telephone or programmatically' allows remote actuation of attached relays/strobes/contacts.

## Confirmed CVEs / advisories

**No CVE or advisory was confirmed for this vendor in this pass.** This is recorded as an **absence of information, not a clean bill of health** — for a vendor of this fleet size the likelier explanations are limited public research attention or a vendor that does not publish advisories where researchers find them. A direct CISA/vendor-PSIRT pass and, ultimately, firmware acquisition are the ways to close it.

## Detection guidance

- Asset-ID: sweep OT/building-systems VLANs for OUI 00:11:90 (IEEE MA-L); expect clusters of IP speakers/clocks/displays. Reconcile the 160-device census against the authorized IPClockWise/InformaCast inventory.
- Guard the provisioning trust chain: enable DHCP snooping and alert on any rogue DHCP server and on DHCP options 66/150 (TFTP) and 72 (HTTP '/ipspeaker/') offered by anything other than the sanctioned provisioning host; monitor SLP (udp/427) responses on the endpoint VLAN.
- Baseline and alert on TFTP (udp/69) and HTTP (tcp/80) config/firmware transfers to/from OUI 00:11:90 endpoints — permit only the one authorized IPClockWise/provisioning server; alert on firmware-upload POSTs to endpoint web UIs from any other host.
- SIP (5060/udp,tcp): permit registration only to the sanctioned PBX/registrar; alert on SIP from these endpoints to any external or unknown registrar (exfil/toll-fraud/pivot).
- Multicast: baseline expected IGMP joins / RTP multicast audio groups and the InformaCast SLP multicast group 239.255.255.253; alert on new or external multicast senders.
- SNMPv1 (udp/161): detect default/guessable community strings and unauthorized SNMP from off-VLAN; disable SNMPv1 if unused. Watch mDNS (udp/5353) and SLP (udp/427) for discovery/enumeration chatter.
- Log sources to onboard: switch DHCP-snooping logs, NetFlow/IPFIX on the building-systems VLAN, SIP registrar/PBX logs (Cisco CUCM, Asterisk, 3CX, ShoreTel), and the IPClockWise / InformaCast (Singlewire) / Syn-Apps SA-Announce / BellCommander / MessageNet server logs plus the SNMP trap receiver.
- Allowlist/segmentation to enforce and monitor: pin each endpoint to its provisioning host (TFTP/HTTP) + NTP server + SIP registrar + its multicast groups only; deny internet egress, deny inter-VLAN except to sanctioned servers, and disable zero-touch provisioning after commissioning where the firmware allows.

## Acquisition status

We currently hold NONE for this vendor. Firmware is gated: images and the IPClockWise application live behind the AND Customer Portal login at anetd.com/user-support/portal-login/ (account required; the device status page even tells operators to log in there to check for the latest firmware). No open/direct firmware download was found. Public, ungated material is limited to datasheets, install guides and the SIP-config application note (anetd.com technical-resources, and mirrors on fullcompass.com). Two realistic acquisition paths, both requiring authorization: (1) request images through the AND portal / support (tech@anetd.com, 847-463-2237); (2) because firmware is pushed in-band to devices over cleartext TFTP/HTTP during provisioning, a sample can be captured on-wire from the authorized provisioning server on the Guard network with proper authorization. Net: vendor-gated, obtainable only via portal account or on-net capture.

## Notes

No CVE or ICS-CERT/CISA advisory was found for this vendor in this research, so cve_claims is intentionally empty (none fabricated). Evidence checked: NVD REST API keywordSearch=anetd (exact) returned totalResults:0; keywordSearch="Advanced Network Devices" returned only generic 'network devices' hits for Siemens SIMATIC and Juniper — those are NOT this vendor and do not apply; no CISA ICS advisory, ZDI, or vendor security bulletin surfaced for AND/anetd/Digital Design Corporation. Absence of a published CVE is not assurance of safety: the cleartext TFTP/HTTP provisioning-and-firmware trust model, SNMPv1, cleartext-stored SIP creds, and undocumented web-admin auth posture are high-value review targets and likely pre-authentication/weak-auth issues if these endpoints were ever formally tested. Recommended next step for the SOC: pull one device's firmware (portal or on-net capture) to confirm the web-admin default-credential/auth state and whether firmware/config downloads are signed — none of the public documentation indicates image signing. Primary sources used: maclookup.app OUI 00:11:90; digidesco.com / digidescorp.com (overview PDF); anetd.com (about-us, IPSWD datasheet, IP Device Installation Guide, AN060 SIP config app-note); fullcompass.com datasheet mirrors; NVD REST API.

## Status

| Item | State |
|---|---|
| Firmware/software acquired | **No** — OSINT/advisory only |
| Confirmed CVEs | 0 (independently re-verified) |
| Behavioural baseline | None — no samples held |
| Next step | CISA/PSIRT deep pass; attempt firmware acquisition |

*Generated 2026-10-26 from the ot-vendor-briefs workflow (12 researchers + adversarial CVE verification). Device counts from the 2026-10-22 ARNG OT census.*

# FIN6 - GTI profile

Generated 2026-10-02 from Google Threat Intelligence curated collections.
Matched GTI collection **FIN6** ($(@{id=threat-actor--bae65c78-4797-570f-a09d-7ed41c83e85c; type=collection; links=; attributes=; context_attributes=}.id)), validated against name/alt_names.

| Field | Value |
|---|---|
| GTI name | FIN6 |
| Alt names | FIN6 (Morphisec); FIN6 (Trend Micro); FIN8 (Morphisec); ITG08 (IBM); Skeleton Spider; SQUID COMET (GTIG) |
| Source region | Eastern Europe |
| Targeted regions | US; CO; IN; FR; CA; CL; PH; KR; CH; ES; IE; GB; VG; CN; SG |
| Targeted industries |  |
| Motivations | @{value=Financial Gain; description=; last_seen=; confidence=confirmed; first_seen=} |
| First / last seen | 1399882930 / 1758837935 |
| Counters | files 2543; domains 785; ips 224; urls 557; refs 183 |

## Description

SQUID COMET (formerly FIN6) is a financially motivated intrusion set that has operated since at least mid-2014. While Google Threat Intelligence Group (GTIG) has not directly observed SQUID COMET monetize access in recent years, the intrusion set has historically compromised multiple point-of-sale (POS) environments through the use of TRINITY (aka FrameworkPOS) and SCRAPMINT POS malware to steal payment card data. Since early 2017, we have observed an expansion of tactics, techniques, and procedures (TTPs), indicating that the intrusion set is also targeting card-not-present (CNP) data in e-commerce environments. As of mid-2018, at least one SQUID COMET-affiliated actor began to deploy various ransomware payloads, including LOCKERGOGA, RYUK, MEGACORTEX, and MAZE malware. Since at least mid-2019, SQUID COMET campaigns have leveraged resume-themed lures and job-themed files, which have more recently been hosted on domains that appear to be fake personal websites. These sites deliver BULLZLINK payloads leading to SQUIDSLEEP and SQUIDGATE malware sold by the actor badbullzvenom. In early February 2024, LEAF COMET began distributing HAVOCDEMON via a CHUNKPILE loader that was downloaded from a SQUIDGATE controller.



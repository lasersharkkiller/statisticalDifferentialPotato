# Warp Panda - GTI profile

Generated 2026-10-02 from Google Threat Intelligence curated collections.
Matched GTI collection **UNC5221** ($(@{id=threat-actor--b797832d-0411-5574-b7cf-c51b22e08423; type=collection; links=; attributes=; context_attributes=}.id)), validated against name/alt_names.

| Field | Value |
|---|---|
| GTI name | UNC5221 |
| Alt names | UTA0178 (Volexity); Verdantbamboo (Volexity); Warp Panda (CrowdStrike) |
| Source region | CN |
| Targeted regions | ES; KR; JP; FR; TW; DE; GB; IE; US; NL |
| Targeted industries |  |
| Motivations | @{last_seen=; description=; confidence=confirmed; first_seen=; value=Espionage} |
| First / last seen | 1696821000 / 1788971426 |
| Counters | files 50; domains 41; ips 280; urls 6; refs 63 |

## Description

UNC5221 is a suspected China-nexus espionage actor that has been observed conducting operations as early as October 2023, with evidence of exploiting vulnerabilities in various edge devices. Their initial activity in December 2023 specifically involved the pre-disclosure, zero-day exploitation of CVE-2023-46805 (authentication bypass) and CVE-2024-21887 (command injection), which impacted Ivanti Connect Secure VPN (formerly Pulse Secure) and Ivanti Policy Security appliances. More recently, they have continued to leverage new Ivanti zero-day exploits, including CVE-2025-0282 and CVE-2025-22457, and most recently a critical pre-authentication remote code execution vulnerability within BeyondTrust Remote Support servers, CVE-2026-1731.



# Mocha Manakin - GTI profile

Generated 2026-10-02 from Google Threat Intelligence curated collections.
Matched GTI collection **Mocha Manakin** ($(@{id=threat-actor--f2bbe78d-0701-467a-bc5b-3f4423181503; type=collection; links=; attributes=; context_attributes=}.id)), validated against name/alt_names.

| Field | Value |
|---|---|
| GTI name | Mocha Manakin |
| Alt names |  |
| Source region |  |
| Targeted regions |  |
| Targeted industries |  |
| Motivations |  |
| First / last seen |  /  |
| Counters | files 0; domains 0; ips 0; urls 0; refs 0 |

## Description

Mocha Manakin is a threat actor that employs the paste and run technique for initial access, tricking users into executing scripts that download various payloads, including LummaC2, HijackLoader, and Vidar. This actor is notable for utilizing a bespoke NodeJS-based backdoor named NodeInitRAT, which facilitates persistence and reconnaissance activities while communicating with adversary-controlled servers over HTTP. Mocha Manakin has been linked to Interlock ransomware, and while direct ransomware activity has not been observed, there is moderate confidence that unmitigated activity may lead to such outcomes. The effectiveness of paste and run lures, distributed through methods like phishing and web browser injects, has contributed to the actor's increased scope and scale.



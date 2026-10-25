# BlackByte - GTI profile

Generated 2026-10-02 from Google Threat Intelligence curated collections.
Matched GTI collection **BLACKBYTE** ($(@{id=malware--8f8855df-ff1a-5ffd-953c-0db4ff27336a; type=collection; links=; attributes=; context_attributes=}.id)), validated against name/alt_names.

| Field | Value |
|---|---|
| GTI name | BLACKBYTE |
| Alt names |  |
| Source region |  |
| Targeted regions |  |
| Targeted industries |  |
| Motivations |  |
| First / last seen |  / 1689185335 |
| Counters | files 1; domains 0; ips 0; urls 0; refs 7 |

## Description

BLACKBYTE is a ransomware written in Go and Rust. The malware employs multiple anti-analysis techniques to defeat static and dynamic inspection and utilizes process hollowing to facilitate its operations. It targets files for encryption using ChaCha20 and Curve25519, while also encrypting filenames and appending a specific extension to compromised files. To maximize impact, the malware executes commands to delete shadow copies and stops various system services. It modifies system configurations, including registry keys associated with the Windows policy system, to ensure operational success. The malware generates a ransom note instructing victims to download the TOR browser to access a payment portal. It also attempts to disable security-related services and modifies firewall rules. The malware requires specific command-line arguments to execute successfully on a target system. It is known to spawn new processes to continue its encryption routine after replacing the original process.

This summary was generated with Gemini.



# Play Ransomware - GTI profile

Generated 2026-10-02 from Google Threat Intelligence curated collections.
Matched GTI collection **PLAY** ($(@{id=malpedia_win_play; type=collection; links=; attributes=; context_attributes=}.id)), validated against name/alt_names.

| Field | Value |
|---|---|
| GTI name | PLAY |
| Alt names | PlayCrypt |
| Source region |  |
| Targeted regions |  |
| Targeted industries |  |
| Motivations |  |
| First / last seen |  /  |
| Counters | files 21; domains 0; ips 0; urls 0; refs 15 |

## Description

According to PCrisk, PLAY is the name of a ransomware-type program. Malware categorized as such operates by encrypting data and demanding ransoms for the decryption.

After we executed a sample of this ransomware on our test machine, it encrypted files and appended their filenames with a ".PLAY" extension. For example, a file titled "1.jpg" appeared as "1.jpg.PLAY", "2.png" as "2.png.PLAY", etc. Once the encryption process was completed, PLAY created a text file named "ReadMe.txt" on the desktop.



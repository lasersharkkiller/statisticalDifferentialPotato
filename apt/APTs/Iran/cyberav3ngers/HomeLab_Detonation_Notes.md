# CyberAv3ngers HomeLab Detonation Findings

**Source**: HomeLab purple-team engagement on `C:\githubProjects\DetonationLogs\APTs\Iran\CyberAv3ngers\`
**Dates**: 2026-10-16 (Linux window 02:45Z, Windows window 03:20Z)
**Scope**: 6 detonation VMs across 3 EDR lanes (Elastic Defend EDRComplete, Sysmon+Winlogbeat, NortonEDR)

## Samples detonated

| Sample | SHA256 | Platform | Microsoft Threat ID |
|---|---|---|---|
| IOCONTROL ELF | `1b39f9b2b96a6586c4a11ab2fdbff8fdf16ba5a0ac7603149023d73f33b84498` | 32-bit BE ARM Linux | `Trojan:Linux/Multiverze!rfn` |
| p8ng2zc3.exe | `440b5385d3838e3f6bc21220caa83b65cd5f3618daea676f271c3671650ce9a3` | Windows PE x86-64 | `Ransom:Win64/CutBrooch.A!dha` |

## New IOCs added to Master_Intel

- **IMPHASH** `9cbefe68f395e67356e2a5d8d1b285c0` (p8ng2zc3.exe) — correlation surface for other CutBrooch variants
- **MD5** `ba284a4b508a7abd8070a427386e93e0` (p8ng2zc3.exe companion)
- **Microsoft threat family** `CutBrooch` — Microsoft Defender classifies this CyberAv3ngers Windows loader as `Ransom:Win64/CutBrooch.A!dha`, giving a signature-level ID that pre-empts without an exclusion path
- **Expanded Oct-2 GTI network IOCs**: `beavercountain.com`, `178.162.227.180` (Leaseweb DE), `185.162.235.206` (Nemtsov SE)

## New MITRE techniques observed at runtime

| Technique | Evidence | Sample | Detection source |
|---|---|---|---|
| **T1055** Process Injection | 5× injected threads into p8ng2zc3.exe's own address space within <1 second of launch | Windows PE | NortonEDR "Stack Base + VAD Inspection" |
| **T1027.002** Software Packing | High-entropy overlay / resource; "Hidden payload: p8ng2zc3.exe" | Windows PE | NortonEDR static heuristic |
| **T1497.003** Anti-emulation (new) | Manual `open("/lib/ld-linux.so.2")` + `read(..., 512)` syscall; mismatch between x86 loader bytes and expected BE-ARM content causes SIGSEGV | IOCONTROL ELF | HomeLab live strace of qemu-armeb-static |

## Lane telemetry comparison

| Lane | Linux (ubu-*) | Windows (win11-*) |
|---|---|---|
| A Elastic Defend EDRComplete | 795 events, zero semantic alerts (sample died in rtld) | ❌ win11-fleet stuck in Startup Repair |
| B Forwarder (Sysmon+Winlogbeat / filebeat+auditbeat) | 1,319 events, raw ancestry only | 262 events, Sysmon EID 1 with SHA256+MD5+IMPHASH confirmed |
| C NortonEDR | 479 events, no alert on sample itself (sample segfaulted before syscalls) | 207 events, **fired on T1055 + T1027.002 for p8ng2zc3.exe** |

**Headline**: NortonEDR is the only lane that fired a semantic detection on the sample at runtime (Windows side). Elastic Defend captured raw telemetry but no alerts (sample never produced malicious behavior to classify). Lane B is pure raw telemetry — no semantic detection by design.

## Known gaps / caveats

1. **BE-ARM anti-emulation defeats qemu-user on x86-64 hosts.** To observe real IOCONTROL runtime, options are: (a) native BE-ARM hardware (Unitronics Vision PLC class), (b) qemu-system-arm with BE-ARM Debian-ports-style rootfs, (c) static RE patch to NOP the anti-emulation syscall.
2. **Sinkhole + null routes active** during detonation — real C2 beaconing to `ocferda.com`, `tylarion867mino.com`, `beavercountain.com`, `91.205.105.146`, `159.100.6.69`, `178.162.227.180`, `185.162.235.206` was intercepted at 127.0.0.1. Any outbound-network observations in the ndjson are sinkholed, not real external traffic.
3. **win11-fleet (Lane A Windows) stuck in Startup Repair** post hard-stop — no Elastic Defend Windows data for this window. Recoverable via Proxmox console intervention or revert to `defender-off-baseline` snapshot.
4. **NortonEDR noise floor**: fires `sev=100` on Microsoft Defender's own post-boot behavior (UpdatePlatform.exe timestomping, MsMpEng.exe ETW manifest writes, wevtutil.exe ETW publisher registry edits). These are tunable incidental detections, not sample-related.

## Ndjson export locations

- Linux window: `DetonationLogs\APTs\Iran\CyberAv3ngers\CyberAv3ngers_2026-10-16_02-45_to_02-46UTC\`
  - process_events.ndjson (2,114 events, 3.6 MB) — Lanes A+B
  - nortonedr-ubu-edr.ndjson (479 events) — Lane C
  - network_events.ndjson, file_events.ndjson
- Windows window: `DetonationLogs\APTs\Iran\CyberAv3ngers\CyberAv3ngers_2026-10-16_03-20_to_03-22UTC_WINDOWS\`
  - winlogbeat-win11-fwd.ndjson (262 events, 2.3 MB) — Lane B
  - nortonedr-win11-edr.ndjson (207 events) — Lane C

Both windows have `session_info.txt` + `summary.csv`.

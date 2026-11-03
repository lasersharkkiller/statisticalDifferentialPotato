# Weekly progress - VT baseline & differential analysis

**Week 2026-W45** | snapshot 2026-11-03 16:40 UTC | previous: 2026-W40

## 1. Submitting files VirusTotal did not have

Every file that comes back 404 is one VT has never seen. Submitting it is what
makes a behaviour report possible at all, and extends VT's own baseline.

| Metric | Value | vs prev |
|---|---:|---:|
| Distinct hashes cataloged (universe) | 770,194 | +102,458 |
| Queried against VT | 770,193 | +103,877 |
| Not in VT when queried (404) | 414,595 | +55,406 |
| **Submitted by us, cumulative** | 389,813 | +62,057 |
| Submitted this week | 0 | -327,220 |
| GB submitted, cumulative | 150.733 | +41.433 |
| Confirmed added to VT | 389,606 | +61,953 |
| Awaiting analysis | 0 | -3 |
| **Still to submit (backlog)** | 0 | -2,845 |
| Backlog GB | 0.000 | -0.055 |
| Too large for VT (excluded) | 10 | -- |

<details><summary>Submissions by week</summary>

| Week | Files |
|---|---:|
| 2026-W21 | 393 |
| 2026-W23 | 41 |
| 2026-W25 | 2 |
| 2026-W29 | 20 |
| 2026-W35 | 10 |
| 2026-W36 | 1 |
| 2026-W37 | 69 |
| 2026-W40 | 327,220 |
| 2026-W41 | 31 |
| 2026-W43 | 56,842 |
| 2026-W44 | 5,184 |

</details>

## 2. Pulling behaviour reports for the files VirusTotal does have

A behaviour report only exists if VT actually detonated the file. Reports that come
back as `{"data": null}` stubs are counted separately, because only the real ones
turn `G=0` (never observed) into genuine known-good evidence.

| Metric | Value | vs prev |
|---|---:|---:|
| OT files VT has (main reports pulled) | 781,228 | +106,592 |
| Behaviour reports pulled | 781,060 | +106,581 |
| Behaviour pull coverage % | 99.98 | -- |
| **With real behaviour data** | 60,123 | +21,205 |
| Real as % of pulled | 7.66 | +1.91 |
| **Real reports added this week** | 0 | -38,179 |
| NSRL behaviour reports pulled | 34,617 | -- |
| NSRL with real behaviour data | 20,583 | -- |
| NSRL % real | 59.46 | -- |

## 3. Pyramid-of-pain yield (distinct TTPs observed)

| Metric | Value | vs prev |
|---|---:|---:|
| Distinct MITRE ATT&CK techniques | 222 | +19 |
| Distinct VT signature rules | 1,041 | +166 |
| Distinct MBC behaviours | 238 | +4 |
| High/critical technique hits | 28 | +2 |
| Fidelity index dimensions | 18 | -- |
| Fidelity index entries | 872,263 | -- |

## Trend

| Week | Submitted (cum.) | Backlog | Behav. pulled | Real behav. | MITRE techniques |
|---|---:|---:|---:|---:|---:|
| 2026-W40 | 327,756 | 2,845 | 674,479 | 38,918 | 203 |
| 2026-W45 | 389,813 | 0 | 781,060 | 60,123 | 222 |

---

*Series: `output\metrics\weekly-progress.csv`. Submissions are recorded at submit
time in `output\metrics\VTSubmissionLedger.csv`. Regenerate with menu option 3b.*


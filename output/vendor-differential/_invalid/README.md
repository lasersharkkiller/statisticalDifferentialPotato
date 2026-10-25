# Invalidated per-vendor differentials — do not cite

These two runs completed without error and produced normal-looking
`Targeted*DifferentialAnalysis.json` files. **They are not usable**, and they
were moved here rather than deleted so the reason is on the record.

| Vendor | Baseline | Native import coverage | Result |
|---|---:|---:|---|
| APC | 20,899 | **1%** | 17,613 API rows, only **10** distinct rarity values, 89.6% at ceiling |
| Inductive-Automation | 13,166 | **0%** | 1,186 ELF rows, **1** distinct rarity value, 93.6% at ceiling |

**Why.** A static import differential scores how rare a malicious import is
within the vendor's own corpus. That requires the baseline to contain native
import tables. Neither corpus does:

- **Inductive-Automation (Ignition)** is **94% Java Bytecode**. Zero sampled
  files carried an ELF or PE import list. Java has imports, but not in the
  `elf_info`/`pe_info` fields this analysis reads, so there is nothing to be
  rare *against*. Every row scored the ceiling.
- **APC** holds ~1% native executables; the rest is configs, text and firmware
  containers.

A rarity score with one distinct value cannot rank anything, so the file is
arithmetic on an empty baseline — and it is dangerous precisely because it
looks complete.

Both vendors are now gated out by the import-coverage check in
`tools/Invoke-VendorDifferential.ps1` (requires >=5% of the baseline to carry
native import tables). This was caught by noticing the rarity distribution was
degenerate, not by any error.

**These vendors are not un-analysable** — only the *static import* differential
is impossible. Their behaviour-derived categories (MITRE, Sigma, YARA, process,
mutex, registry) do not depend on import tables and remain valid; APC has 418
behaviour reports with data and Inductive 116. A behaviour-only differential is
the right approach for them, and is not yet implemented.

## Siemens — deferred, then skipped (2026-10-24)

Siemens was initially **deferred** rather than skipped, on the assumption that its
568,232-file baseline merely needed a sampled run to be tractable. That assumption was wrong,
and checking it before building the sampling infrastructure saved the effort.

**Siemens carries 0.5% native import coverage** (3 of 599 sampled reports). Composition:

| Type | Share |
|---|---:|
| HTML | 38.4% |
| unknown | 29.4% |
| C++ / Text / JavaScript | 14.3% |
| **native executables with import tables** | **0.5%** |

So Siemens fails the same >=5% gate as APC (1%) and Inductive-Automation (0%). **Sampling cannot
fix this** — a random sample of a corpus that is 99.5% non-native is still 99.5% non-native.
Sampling addresses baseline *size*; the limiting factor here is *import coverage*.

This is the sharpest illustration of the point in
[vendor-exposure-vs-coverage.md](../../../docs/vendor-exposure-vs-coverage.md): Siemens holds ~86%
of the entire corpus by hash count and is **the least analysable vendor in it** for static
differential purposes.

**The one viable variant** would be to filter the baseline to only its import-bearing files rather
than sample randomly — using the complete relevant population instead of a subset. At 0.5% that is
roughly 2,800 files, though the sampling error on 3 hits in 599 is wide (95% CI ~570–8,500). Either
way it is a thin baseline, comparable to Axis's ~1,000 ELF files, which produced a 57% ceiling rate.
Worth doing only if Siemens specifically matters; it is not a general fix.

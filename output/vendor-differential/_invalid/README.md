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

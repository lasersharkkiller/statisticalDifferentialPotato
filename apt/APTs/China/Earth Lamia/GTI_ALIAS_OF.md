# Earth Lamia is the same GTI actor as UNC5454

GTI resolves both to collection **UNC5454** (`threat-actor--fee6ecfd-a790-5a74-9bdc-c2bb7e4d0823`):
Earth Lamia matches one of its alt_names.

GTI-sourced IOCs are therefore written only to
`NorthKorea/UNC5454/UNC5454_Master_Intel.csv`,
to avoid duplicating every indicator across two files - which would
double-count them on the malicious side of the fidelity index.

This folder's own hand-seeded intel is left untouched; the separate folder
is kept deliberately where the vendor taxonomies differ (see NOTES.md).

Full GTI alt_names: Earth Lamia (Trend Micro); Ref0657 (Elastic)

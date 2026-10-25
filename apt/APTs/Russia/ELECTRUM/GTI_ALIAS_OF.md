# ELECTRUM is the same GTI actor as Sandworm

GTI resolves both to collection **Sandworm** (`threat-actor--f512de42-f76b-40d2-9923-59e7dbdfec35`):
ELECTRUM matches one of its alt_names.

GTI-sourced IOCs are therefore written only to
`Russia/Sandworm/Sandworm_Master_Intel.csv`,
to avoid duplicating every indicator across two files - which would
double-count them on the malicious side of the fidelity index.

This folder's own hand-seeded intel is left untouched; the separate folder
is kept deliberately where the vendor taxonomies differ (see NOTES.md).

Full GTI alt_names: APT44; Blue Echidna; ELECTRUM; FROZENBARENTS; G0034; IRIDIUM; IRON VIKING; Quedagh; SANDWORM RELIC; Seashell Blizzard; TeleBots; TEMP.Noble; UAC-0082; UAC-0113; UAC-0145; VOODOO BEAR

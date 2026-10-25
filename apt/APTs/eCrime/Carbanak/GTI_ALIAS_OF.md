# Carbanak is the same GTI actor as FIN7

GTI resolves both to collection **FIN7** (`threat-actor--80b173e4-2dbf-5139-9a35-b75ffb4eaef8`):
Carbanak matches one of its alt_names.

GTI-sourced IOCs are therefore written only to
`eCrime/FIN7/FIN7_Master_Intel.csv`,
to avoid duplicating every indicator across two files - which would
double-count them on the malicious side of the fidelity index.

This folder's own hand-seeded intel is left untouched; the separate folder
is kept deliberately where the vendor taxonomies differ (see NOTES.md).

Full GTI alt_names: Calcium (Symantec); Carbanak (RSA); Carbanak (Trustwave); Carbanak group (Forcepoint); Carbon Spider (CrowdStrike); FIN7 (Esentire); FIN7 (Flashpoint); FIN7 (Gemini Advisory); FIN7 (Kaspersky); FIN7 (Mnemo); FIN7 (Morphisec); FIN7 (PTI); Navigator (Fox-IT); Sangria Tempest (Microsoft); Squeamishlibra (Palo Alto Networks); Stac5143 (Sophos); TA543 (Proofpoint); TelePort Crew (tr1adx); WILD COMET (GTIG)

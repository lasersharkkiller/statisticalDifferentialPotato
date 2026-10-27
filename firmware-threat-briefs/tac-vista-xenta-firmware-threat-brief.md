# TAC AB / Schneider Vista-Xenta Firmware Attack Surface & Detection Brief

**Scope:** Access-verification pass only (2026-10-22). **No firmware was acquired and no CVE
research pass was performed.** The legacy TAC Vista product-range page
(`se.com/us/en/product-range/577-tac-vista/`) returns HTTP 200 with 1,416,739 bytes of product
content plus authentication prompts, and the Schneider firmware download facet
(`se.com/.../doc-group-type/...?docType=1555773-Firmware`) returns **HTTP 404** - the documented
legacy facet path no longer resolves. **Access verdict: NOT PUBLICLY DOWNLOADABLE at the paths
tested.** That is deliberately weaker than "confirmed login wall": it is a dead path on a live
site, so a different, currently-valid Schneider route may exist and was not found this pass. No
filename, byte count or SHA256 to report.

**php2shell context:** this brief's PHP determination was driven by CVE-2026-109618 / CVE-2026-109619 ("php2shell", CVSS 9.2, PHP 5.4+, emergency-patched 2026-10-21). Those two IDs are carried here **as supplied by the requester** - they were not independently corroborated against NVD/MITRE in this pass, and no vendor-specific CVE was invented to pair with them.

**PHP finding: UNDETERMINED.** TAC Vista/Xenta is a late-1990s-to-2000s LonWorks-era platform;
Xenta 500/700/900 controllers expose an embedded web UI and the Xenta 911/913 gateways historically
served HTML templates. Whether any of that used PHP cannot be established without a rootfs, and the
era makes PHP and a bespoke CGI about equally plausible. **Not recorded as in-scope or out-of-scope
for php2shell.**

## Fleet exposure

252 devices in the ARNG OT census, function class *Building Automation/BMS*. Vendor-lineage
complication: TAC AB was acquired by Schneider Electric and the line is discontinued in favour of
EcoStruxure Building Operation - so current Schneider portals are unlikely to carry Xenta firmware
at all, making an archive or dealer channel the realistic source.

## What would close the PHP question

1. A live-device HTTP check against one of the 252 units - `X-Powered-By` header and `.php`
   handling. Fastest route, no vendor dependency.
2. Schneider's legacy/discontinued-product archive, if a valid path can be found - the one recorded
   in this project is now HTTP 404.
3. A third-party licence manifest, the technique that definitively answered Axis without its gated
   binary.

## Status

| Item | State |
|---|---|
| Public firmware download | **No** at paths tested - product page HTTP 200, firmware facet HTTP 404 |
| Firmware acquired | No |
| Extraction run | N/A |
| PHP determination | **Undetermined** |
| CVE research pass | **Not performed** - no CVE IDs asserted here |

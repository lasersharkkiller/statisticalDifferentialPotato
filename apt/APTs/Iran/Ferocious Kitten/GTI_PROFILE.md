# Ferocious Kitten - GTI profile

Generated 2026-10-02 from Google Threat Intelligence curated collections.
Matched GTI collection **Ferocious Kitten** ($(@{id=threat-actor--f34962a4-a792-4f23-af23-a8bf0f053fcf; type=collection; links=; attributes=; context_attributes=}.id)), validated against name/alt_names.

| Field | Value |
|---|---|
| GTI name | Ferocious Kitten |
| Alt names |  |
| Source region | IR |
| Targeted regions |  |
| Targeted industries |  |
| Motivations |  |
| First / last seen |  /  |
| Counters | files 0; domains 0; ips 0; urls 0; refs 2 |

## Description

Ferocious Kitten is an APT group that has been active against Persian-speaking individuals since 2015 and appears to be based in Iran. Although it has been active over a large timespan, the group has mostly operated under the radar until a lure document was uploaded to VirusTotal and was brought to public knowledge by researchers on Twitter. Subsequently, one of its implants was analyzed by a Chinese intelligence firm. Kaspersky then expanded some of the findings on the group and provided insights on additional variants. The malware dropped from the aforementioned document is dubbed MarkiRAT and is used to record keystrokes and clipboard content, provide file download and upload capabilities as well as the ability to execute arbitrary commands on the victims machine. Kaspersky were able to trace the implant back to at least 2015, along with variants intended to hijack the execution of the Telegram and Chrome applications as a persistence method. Interestingly, some of the TTPs used by this threat actor are reminiscent of other groups operating in the domain of dissident surveillance. For example, it used the same C2 domains across its implants for years, which was witnessed in the activity of Domestic Kitten. In the same vein, the Telegram execution hijacking technique observed in this campaign by Ferocious Kitten was also observed being used by Rampant Kitten, as covered by Check Point.



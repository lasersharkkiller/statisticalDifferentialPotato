# BlackTech - GTI profile

Generated 2026-10-02 from Google Threat Intelligence curated collections.
Matched GTI collection **BlackTech** ($(@{id=threat-actor--320c42f7-eab7-4ef9-b09a-74396caa6c3e; type=collection; links=; attributes=; context_attributes=}.id)), validated against name/alt_names.

| Field | Value |
|---|---|
| GTI name | BlackTech |
| Alt names | Canary Typhoon; CAVERN CASTLE; CIRCUIT PANDA; Earth Hundun; G0098; HUAPI; Manga Taurus; Mobwork; Palmerworm; Red Djinn; T-APT-03; Temp.Overboard |
| Source region | CN |
| Targeted regions |  |
| Targeted industries |  |
| Motivations |  |
| First / last seen |  /  |
| Counters | files 96; domains 27; ips 2; urls 10; refs 11 |

## Description

BlackTech is a cyber espionage group operating against targets in East Asia, particularly Taiwan, and occasionally, Japan and Hong Kong. Based on the mutexes and domain names of some of their C&C servers, BlackTech’s campaigns are likely designed to steal their target’s technology.
Following their activities and evolving tactics and techniques helped us uncover the proverbial red string of fate that connected three seemingly disparate campaigns: PLEAD, Shrouded Crossbow, and of late, Waterbear.
PLEAD is an information theft campaign with a penchant for confidential documents. Active since 2012, it has so far targeted Taiwanese government agencies and private organizations. PLEAD’s toolset includes the self-named PLEAD backdoor and the DRIGO exfiltration tool. PLEAD uses spear-phishing emails to deliver and install their backdoor, either as an attachment or through links to cloud storage services. Some of the cloud storage accounts used to deliver PLEAD are also used as drop off points for exfiltrated documents stolen by DRIGO.
PLEAD actors use a router scanner tool to scan for vulnerable routers, after which the attackers will enable the router’s VPN feature then register a machine as virtual server. This virtual server will be used either as a C&C server or an HTTP server that delivers PLEAD malware to their targets.



function Build-OTEDRGapMatrix {
    <#
    .SYNOPSIS
        Builds the OT EDR Coverage Gap Matrix — detection-tool × behavior-
        dimension coverage cross-tab, scoped to the Purdue layers we care
        about for OT hunting.

    .DESCRIPTION
        OT analog of the historical IT "EDR Evasion & Gap Matrix" artifact.
        Answers: "for the behaviors that show up in my OT baseline, which
        of my detection tools can actually see them — and where are my
        blind spots?"

        This visualization is MORE CURATED and LESS data-derived than the
        Dashboard / Capability Matrix. Tool coverage capabilities come from
        vendor documentation + our research (collected in
        docs/purdue-layered briefs + the inventory-strategy doc); the
        data-derived part is per-row "how relevant is this dimension to
        my baseline" — pulled from the actual VT-behaviors corpus.

        Rows = behavior dimensions, grouped by Purdue layer scope:
          L4/L3.5 host telemetry  — process spawn, file write, registry
                                    set, DLL load, parent-child tree
          L3 site ops             — service create, scheduled task,
                                    privilege escalation, named pipe,
                                    WMI subscription
          L3.5 network            — TLS handshake anomaly, DNS lookup,
                                    HTTP/S egress, MQTT, cloud relay
          L3 OT-specific          — OPC UA write, Modbus function 5/6/15/16,
                                    CIP forward-open, S7Comm write, IEC 61850
                                    MMS write, UMAS function 0x5A
          L2 HMI                  — VNC session, web-UI auth, project-file
                                    push, EasyAccess cloud register
          L1 PLC                  — keyswitch state, program download,
                                    mode change RUN/PROG, firmware flash

        Columns = detection tools commonly considered in OT:
          ACAS                     (Tenable Nessus + Security Center)
          Elastic EDR              (Elastic Defend agent)
          Sysmon                   (Windows + Linux variants)
          auditd                   (Linux)
          MS Defender for IoT
          Forescout eyeInspect     (OT-native passive DPI)
          Forescout CounterACT     (IT NAC + DHCP/SNMP)
          Cisco ISE + IND          (NAC + OT-protocol via IND/Cyber Vision)
          Claroty CTD / xDome
          Nozomi Guardian / Vantage
          Tenable.ot               (formerly Indegy)
          Dragos Platform
          Vendor native audit log  (e.g., NMC syslog, iFIX SCU audit, Studio
                                    5000 FactoryTalk audit, cMT EasyWeb log)

        Per-cell value:
          FULL    — direct visibility, default config catches it
          PARTIAL — visible with non-default config / additional tuning /
                    a paired companion product (e.g. ISE+IND for OT decode)
          BLIND   — no native visibility regardless of config
          N/A     — tool architecturally cannot see this dimension
                    (e.g. host-agent EDR for a PLC with no OS to install on)

        The data-derived overlay:
          Each row has a "baseline relevance" badge driven by how often
          that behavior dimension appears in our cached VT-behaviors corpus.
          A row that fires constantly in OT baselines (e.g., process spawn
          on L3 Windows) is more urgent to have detection coverage on than
          one that fires rarely.

    .PARAMETER BaselineRoot
        Root of the offline VT baseline. Default: output-baseline.

    .PARAMETER OutputPath
        Path of the output HTML file.
        Default: output-baseline/visualizations/ot-edr-gap-matrix.html.

    .PARAMETER Force
        Regenerate even if output is newer than inputs.

    .EXAMPLE
        Import-Module .\agentic\Build-OTEDRGapMatrix.psm1
        Build-OTEDRGapMatrix
    #>
    [CmdletBinding()]
    param(
        [string] $BaselineRoot = 'output-baseline',
        [string] $OutputPath   = 'output-baseline/visualizations/ot-edr-gap-matrix.html',
        [switch] $Force
    )

    if (-not [System.IO.Path]::IsPathRooted($BaselineRoot)) {
        $BaselineRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\$BaselineRoot"))
    }
    if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
        $OutputPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\$OutputPath"))
    }
    $behRoot = Join-Path $BaselineRoot 'VirusTotal-behaviors'
    $outDir  = Split-Path $OutputPath -Parent
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }

    Write-Host "`n[Build-OTEDRGapMatrix] OutputPath = $OutputPath" -ForegroundColor DarkCyan

    # ----- Tool columns (in display order) -----------------------------------
    $tools = @(
        @{ id='acas';      name='ACAS (Nessus+SC)';        type='IT scan';  notes='Active credentialed scans only at L3.5/L4; NEVER unauth at L1/L2 (PLC crash class)' },
        @{ id='sysmon';    name='Sysmon';                  type='Host';     notes='Windows + Linux variants; high-fidelity process/file/network telemetry' },
        @{ id='auditd';    name='auditd';                  type='Host';     notes='Linux kernel audit; canonical Ignition Linux gateway telemetry source' },
        @{ id='elastic';   name='Elastic EDR (Defend)';    type='Host';     notes='Win+Linux agent; cannot install on PLC/SIS/relay firmware' },
        @{ id='msd4iot';   name='MS Defender for IoT';     type='OT/IoT';   notes='Formerly CyberX; passive DPI + agent variants; Sentinel pivot up to L4' },
        @{ id='forescout-ei'; name='Forescout eyeInspect'; type='OT pDPI';  notes='Formerly SilentDefense; CIP/S7Comm/UMAS/Modbus/DNP3/IEC 61850 DPI' },
        @{ id='forescout-ca'; name='Forescout CounterACT'; type='NAC';      notes='IT-side NAC; DHCP/SNMP fingerprint; not OT DPI' },
        @{ id='cisco-ise'; name='Cisco ISE + IND';         type='NAC+OT';   notes='ISE alone = identity only; IND/Cyber Vision adds CIP/PROFINET decode' },
        @{ id='claroty';   name='Claroty CTD / xDome';     type='OT pDPI';  notes='Multi-protocol passive OT discovery' },
        @{ id='nozomi';    name='Nozomi Guardian/Vantage'; type='OT pDPI';  notes='Passive OT DPI + cloud aggregation' },
        @{ id='tenable-ot';name='Tenable.ot';              type='OT';       notes='Formerly Indegy; passive + cautious active queries' },
        @{ id='dragos';    name='Dragos Platform';         type='OT pDPI';  notes='Passive DPI + XENOTIME/PIPEDREAM threat-intel overlay' },
        @{ id='vendor-log';name='Vendor native audit log'; type='Vendor';   notes='NMC syslog, iFIX SCU audit log, Studio 5000 FT audit, cMT EasyWeb, etc.' }
    )

    # ----- Rows: per-dimension coverage table --------------------------------
    # Each row: id, name, layerScope, baselineFieldHint, coverage map
    # Coverage map values: FULL, PARTIAL, BLIND, N/A
    $rows = @(
        # ----- L4 / L3.5 host telemetry on Windows/Linux admin hosts ---------
        @{ section='L4 / L3.5 host telemetry'; id='proc-spawn'; name='Process spawn (parent + child + cmdline)';
           hint='processes_tree, processes_created, command_executions';
           cov=@{ acas='BLIND'; sysmon='FULL'; auditd='FULL'; elastic='FULL'; msd4iot='PARTIAL'; 'forescout-ei'='BLIND'; 'forescout-ca'='BLIND'; 'cisco-ise'='BLIND'; claroty='BLIND'; nozomi='BLIND'; 'tenable-ot'='BLIND'; dragos='BLIND'; 'vendor-log'='BLIND' } },
        @{ section='L4 / L3.5 host telemetry'; id='file-write'; name='File write / drop';
           hint='files_written, files_dropped, files_opened';
           cov=@{ acas='PARTIAL'; sysmon='FULL'; auditd='FULL'; elastic='FULL'; msd4iot='PARTIAL'; 'forescout-ei'='BLIND'; 'forescout-ca'='BLIND'; 'cisco-ise'='BLIND'; claroty='BLIND'; nozomi='BLIND'; 'tenable-ot'='BLIND'; dragos='BLIND'; 'vendor-log'='BLIND' } },
        @{ section='L4 / L3.5 host telemetry'; id='reg-set'; name='Registry set / opened / deleted (Windows)';
           hint='registry_keys_set, registry_keys_opened, registry_keys_deleted';
           cov=@{ acas='BLIND'; sysmon='FULL'; auditd='N/A'; elastic='FULL'; msd4iot='PARTIAL'; 'forescout-ei'='BLIND'; 'forescout-ca'='BLIND'; 'cisco-ise'='BLIND'; claroty='BLIND'; nozomi='BLIND'; 'tenable-ot'='BLIND'; dragos='BLIND'; 'vendor-log'='BLIND' } },
        @{ section='L4 / L3.5 host telemetry'; id='module-load'; name='DLL / shared-object load (incl. hijacked path)';
           hint='modules_loaded';
           cov=@{ acas='BLIND'; sysmon='FULL'; auditd='PARTIAL'; elastic='FULL'; msd4iot='PARTIAL'; 'forescout-ei'='BLIND'; 'forescout-ca'='BLIND'; 'cisco-ise'='BLIND'; claroty='BLIND'; nozomi='BLIND'; 'tenable-ot'='BLIND'; dragos='BLIND'; 'vendor-log'='BLIND' } },
        @{ section='L4 / L3.5 host telemetry'; id='svc-create'; name='Service / unit-file create + start';
           hint='services_started, services_created';
           cov=@{ acas='PARTIAL'; sysmon='FULL'; auditd='FULL'; elastic='FULL'; msd4iot='PARTIAL'; 'forescout-ei'='BLIND'; 'forescout-ca'='BLIND'; 'cisco-ise'='BLIND'; claroty='BLIND'; nozomi='BLIND'; 'tenable-ot'='BLIND'; dragos='BLIND'; 'vendor-log'='BLIND' } },
        @{ section='L4 / L3.5 host telemetry'; id='sched-task'; name='Scheduled task / cron persistence';
           hint='scheduled_tasks';
           cov=@{ acas='PARTIAL'; sysmon='FULL'; auditd='FULL'; elastic='FULL'; msd4iot='PARTIAL'; 'forescout-ei'='BLIND'; 'forescout-ca'='BLIND'; 'cisco-ise'='BLIND'; claroty='BLIND'; nozomi='BLIND'; 'tenable-ot'='BLIND'; dragos='BLIND'; 'vendor-log'='BLIND' } },
        # ----- L3 site ops (Windows server tier) -----------------------------
        @{ section='L3 site ops (privileged host activity)'; id='wmi-sub'; name='WMI subscription persistence';
           hint='(API: __EventFilter, __EventConsumer)';
           cov=@{ acas='BLIND'; sysmon='FULL'; auditd='N/A'; elastic='FULL'; msd4iot='PARTIAL'; 'forescout-ei'='BLIND'; 'forescout-ca'='BLIND'; 'cisco-ise'='BLIND'; claroty='BLIND'; nozomi='BLIND'; 'tenable-ot'='BLIND'; dragos='BLIND'; 'vendor-log'='BLIND' } },
        @{ section='L3 site ops (privileged host activity)'; id='priv-esc'; name='Privilege escalation / token impersonation';
           hint='(API: SeImpersonatePrivilege, AdjustTokenPrivileges)';
           cov=@{ acas='BLIND'; sysmon='PARTIAL'; auditd='PARTIAL'; elastic='FULL'; msd4iot='PARTIAL'; 'forescout-ei'='BLIND'; 'forescout-ca'='BLIND'; 'cisco-ise'='BLIND'; claroty='BLIND'; nozomi='BLIND'; 'tenable-ot'='BLIND'; dragos='BLIND'; 'vendor-log'='BLIND' } },
        @{ section='L3 site ops (privileged host activity)'; id='proc-inject'; name='Process injection / hollowing';
           hint='(API: WriteProcessMemory, CreateRemoteThread)';
           cov=@{ acas='BLIND'; sysmon='PARTIAL'; auditd='PARTIAL'; elastic='FULL'; msd4iot='PARTIAL'; 'forescout-ei'='BLIND'; 'forescout-ca'='BLIND'; 'cisco-ise'='BLIND'; claroty='BLIND'; nozomi='BLIND'; 'tenable-ot'='BLIND'; dragos='BLIND'; 'vendor-log'='BLIND' } },
        # ----- L3.5 network / IT-OT boundary --------------------------------
        @{ section='L3.5 IT/OT boundary network'; id='dns'; name='DNS lookup (egress to non-vendor netblocks)';
           hint='dns_lookups';
           cov=@{ acas='BLIND'; sysmon='PARTIAL'; auditd='PARTIAL'; elastic='FULL'; msd4iot='FULL'; 'forescout-ei'='FULL'; 'forescout-ca'='PARTIAL'; 'cisco-ise'='PARTIAL'; claroty='FULL'; nozomi='FULL'; 'tenable-ot'='FULL'; dragos='FULL'; 'vendor-log'='BLIND' } },
        @{ section='L3.5 IT/OT boundary network'; id='http-egress'; name='HTTP/HTTPS egress (incl. TLS metadata)';
           hint='ip_traffic, http_destinations';
           cov=@{ acas='BLIND'; sysmon='PARTIAL'; auditd='PARTIAL'; elastic='FULL'; msd4iot='FULL'; 'forescout-ei'='FULL'; 'forescout-ca'='PARTIAL'; 'cisco-ise'='PARTIAL'; claroty='FULL'; nozomi='FULL'; 'tenable-ot'='FULL'; dragos='FULL'; 'vendor-log'='BLIND' } },
        @{ section='L3.5 IT/OT boundary network'; id='tls-anomaly'; name='TLS handshake anomaly (TLStorm class)';
           hint='(packet-level pattern)';
           cov=@{ acas='BLIND'; sysmon='BLIND'; auditd='BLIND'; elastic='BLIND'; msd4iot='PARTIAL'; 'forescout-ei'='PARTIAL'; 'forescout-ca'='BLIND'; 'cisco-ise'='BLIND'; claroty='PARTIAL'; nozomi='PARTIAL'; 'tenable-ot'='BLIND'; dragos='PARTIAL'; 'vendor-log'='BLIND' } },
        @{ section='L3.5 IT/OT boundary network'; id='mqtt'; name='MQTT / EasyAccess cloud-relay traffic';
           hint='ip_traffic (port 1883/8883/8000-8001)';
           cov=@{ acas='BLIND'; sysmon='BLIND'; auditd='BLIND'; elastic='PARTIAL'; msd4iot='FULL'; 'forescout-ei'='FULL'; 'forescout-ca'='PARTIAL'; 'cisco-ise'='BLIND'; claroty='FULL'; nozomi='FULL'; 'tenable-ot'='PARTIAL'; dragos='FULL'; 'vendor-log'='BLIND' } },
        @{ section='L3.5 IT/OT boundary network'; id='snmp-write'; name='SNMP Set (e.g. rPDU2OutletSwitchedControlCommand outletOff)';
           hint='(network protocol)';
           cov=@{ acas='BLIND'; sysmon='BLIND'; auditd='BLIND'; elastic='BLIND'; msd4iot='FULL'; 'forescout-ei'='FULL'; 'forescout-ca'='PARTIAL'; 'cisco-ise'='BLIND'; claroty='FULL'; nozomi='FULL'; 'tenable-ot'='FULL'; dragos='FULL'; 'vendor-log'='FULL' } },
        # ----- L3 OT-specific protocols --------------------------------------
        @{ section='L3 OT-protocol writes (the destructive surface)'; id='cip-write'; name='CIP forward-open + Execute_PCCC / SetAttribute write';
           hint='(EtherNet/IP TCP/44818 + UDP/2222)';
           cov=@{ acas='BLIND'; sysmon='BLIND'; auditd='BLIND'; elastic='BLIND'; msd4iot='FULL'; 'forescout-ei'='FULL'; 'forescout-ca'='BLIND'; 'cisco-ise'='PARTIAL'; claroty='FULL'; nozomi='FULL'; 'tenable-ot'='FULL'; dragos='FULL'; 'vendor-log'='PARTIAL' } },
        @{ section='L3 OT-protocol writes (the destructive surface)'; id='s7comm-write'; name='S7Comm / S7CommPlus write to Siemens PLC';
           hint='(TCP/102)';
           cov=@{ acas='BLIND'; sysmon='BLIND'; auditd='BLIND'; elastic='BLIND'; msd4iot='FULL'; 'forescout-ei'='FULL'; 'forescout-ca'='BLIND'; 'cisco-ise'='PARTIAL'; claroty='FULL'; nozomi='FULL'; 'tenable-ot'='FULL'; dragos='FULL'; 'vendor-log'='PARTIAL' } },
        @{ section='L3 OT-protocol writes (the destructive surface)'; id='modbus-write'; name='Modbus function 5/6/15/16 (write coil/register)';
           hint='(TCP/502)';
           cov=@{ acas='BLIND'; sysmon='BLIND'; auditd='BLIND'; elastic='BLIND'; msd4iot='FULL'; 'forescout-ei'='FULL'; 'forescout-ca'='BLIND'; 'cisco-ise'='PARTIAL'; claroty='FULL'; nozomi='FULL'; 'tenable-ot'='FULL'; dragos='FULL'; 'vendor-log'='PARTIAL' } },
        @{ section='L3 OT-protocol writes (the destructive surface)'; id='umas-fc5a'; name='UMAS function 0x5A (Modicon program / Memory Write)';
           hint='(Modbus TCP/502 sub-protocol)';
           cov=@{ acas='BLIND'; sysmon='BLIND'; auditd='BLIND'; elastic='BLIND'; msd4iot='PARTIAL'; 'forescout-ei'='FULL'; 'forescout-ca'='BLIND'; 'cisco-ise'='BLIND'; claroty='FULL'; nozomi='FULL'; 'tenable-ot'='FULL'; dragos='FULL'; 'vendor-log'='PARTIAL' } },
        @{ section='L3 OT-protocol writes (the destructive surface)'; id='dnp3-write'; name='DNP3 Operate / Direct-Operate (utility RTU)';
           hint='(TCP/20000)';
           cov=@{ acas='BLIND'; sysmon='BLIND'; auditd='BLIND'; elastic='BLIND'; msd4iot='FULL'; 'forescout-ei'='FULL'; 'forescout-ca'='BLIND'; 'cisco-ise'='BLIND'; claroty='FULL'; nozomi='FULL'; 'tenable-ot'='FULL'; dragos='FULL'; 'vendor-log'='PARTIAL' } },
        @{ section='L3 OT-protocol writes (the destructive surface)'; id='mms-write'; name='IEC 61850 MMS write / GOOSE publish-spoof';
           hint='(TCP/102 + Ethertype 0x88B8)';
           cov=@{ acas='BLIND'; sysmon='BLIND'; auditd='BLIND'; elastic='BLIND'; msd4iot='FULL'; 'forescout-ei'='FULL'; 'forescout-ca'='BLIND'; 'cisco-ise'='BLIND'; claroty='FULL'; nozomi='FULL'; 'tenable-ot'='FULL'; dragos='FULL'; 'vendor-log'='PARTIAL' } },
        @{ section='L3 OT-protocol writes (the destructive surface)'; id='opcua-write'; name='OPC UA write / call (any vendor)';
           hint='(TCP/4840)';
           cov=@{ acas='BLIND'; sysmon='BLIND'; auditd='BLIND'; elastic='BLIND'; msd4iot='FULL'; 'forescout-ei'='FULL'; 'forescout-ca'='BLIND'; 'cisco-ise'='BLIND'; claroty='FULL'; nozomi='FULL'; 'tenable-ot'='FULL'; dragos='FULL'; 'vendor-log'='FULL' } },
        # ----- L2 HMI --------------------------------------------------------
        @{ section='L2 HMI panels'; id='vnc-session'; name='VNC session establishment (panel default port 5900)';
           hint='ip_traffic';
           cov=@{ acas='BLIND'; sysmon='BLIND'; auditd='BLIND'; elastic='PARTIAL'; msd4iot='FULL'; 'forescout-ei'='FULL'; 'forescout-ca'='PARTIAL'; 'cisco-ise'='BLIND'; claroty='FULL'; nozomi='FULL'; 'tenable-ot'='PARTIAL'; dragos='FULL'; 'vendor-log'='PARTIAL' } },
        @{ section='L2 HMI panels'; id='hmi-web-auth'; name='HMI web-UI auth (default admin/admin or admin/111111)';
           hint='http_destinations + dns_lookups';
           cov=@{ acas='PARTIAL'; sysmon='BLIND'; auditd='BLIND'; elastic='BLIND'; msd4iot='PARTIAL'; 'forescout-ei'='FULL'; 'forescout-ca'='PARTIAL'; 'cisco-ise'='BLIND'; claroty='PARTIAL'; nozomi='PARTIAL'; 'tenable-ot'='PARTIAL'; dragos='PARTIAL'; 'vendor-log'='FULL' } },
        @{ section='L2 HMI panels'; id='project-push'; name='Project file push (Crimson .cd3, EBPro .cmtp, Vijeo .stu)';
           hint='(HTTP POST / USB / FTP)';
           cov=@{ acas='BLIND'; sysmon='FULL'; auditd='FULL'; elastic='FULL'; msd4iot='PARTIAL'; 'forescout-ei'='PARTIAL'; 'forescout-ca'='BLIND'; 'cisco-ise'='BLIND'; claroty='PARTIAL'; nozomi='PARTIAL'; 'tenable-ot'='PARTIAL'; dragos='PARTIAL'; 'vendor-log'='FULL' } },
        @{ section='L2 HMI panels'; id='easyaccess-reg'; name='Weintek EasyAccess cloud-relay registration';
           hint='ip_traffic to cloud.weintek/maple cloud netblocks';
           cov=@{ acas='BLIND'; sysmon='BLIND'; auditd='BLIND'; elastic='BLIND'; msd4iot='FULL'; 'forescout-ei'='FULL'; 'forescout-ca'='PARTIAL'; 'cisco-ise'='BLIND'; claroty='FULL'; nozomi='FULL'; 'tenable-ot'='PARTIAL'; dragos='FULL'; 'vendor-log'='PARTIAL' } },
        # ----- L1 PLCs / SIS -------------------------------------------------
        @{ section='L1 PLCs (and SIS by parallel)'; id='prog-download'; name='Program / project download to PLC';
           hint='(CIP forward-open + program-set, S7Comm download, UMAS)';
           cov=@{ acas='N/A'; sysmon='N/A'; auditd='N/A'; elastic='N/A'; msd4iot='FULL'; 'forescout-ei'='FULL'; 'forescout-ca'='BLIND'; 'cisco-ise'='PARTIAL'; claroty='FULL'; nozomi='FULL'; 'tenable-ot'='FULL'; dragos='FULL'; 'vendor-log'='PARTIAL' } },
        @{ section='L1 PLCs (and SIS by parallel)'; id='mode-change'; name='PLC mode change RUN/PROG/REMOTE';
           hint='(CIP service 0x06 Stop, 0x07 Start; S7Comm Stop/Start)';
           cov=@{ acas='N/A'; sysmon='N/A'; auditd='N/A'; elastic='N/A'; msd4iot='FULL'; 'forescout-ei'='FULL'; 'forescout-ca'='BLIND'; 'cisco-ise'='PARTIAL'; claroty='FULL'; nozomi='FULL'; 'tenable-ot'='FULL'; dragos='FULL'; 'vendor-log'='PARTIAL' } },
        @{ section='L1 PLCs (and SIS by parallel)'; id='fw-flash'; name='PLC / SIS firmware flash (incl. TRITON-class to Triconex)';
           hint='(CIP forward-open + firmware-class, TriStation UDP/1502)';
           cov=@{ acas='N/A'; sysmon='N/A'; auditd='N/A'; elastic='N/A'; msd4iot='FULL'; 'forescout-ei'='FULL'; 'forescout-ca'='BLIND'; 'cisco-ise'='BLIND'; claroty='FULL'; nozomi='FULL'; 'tenable-ot'='FULL'; dragos='FULL'; 'vendor-log'='PARTIAL' } },
        @{ section='L1 PLCs (and SIS by parallel)'; id='keyswitch'; name='PLC keyswitch position (RUN / PROG / REM)';
           hint='(physical input — observable via cyclic diagnostic poll)';
           cov=@{ acas='N/A'; sysmon='N/A'; auditd='N/A'; elastic='N/A'; msd4iot='PARTIAL'; 'forescout-ei'='PARTIAL'; 'forescout-ca'='BLIND'; 'cisco-ise'='BLIND'; claroty='PARTIAL'; nozomi='PARTIAL'; 'tenable-ot'='PARTIAL'; dragos='PARTIAL'; 'vendor-log'='FULL' } }
    )

    # ----- Data-derived: how relevant is each dimension in our baseline? -----
    Write-Host "`n  computing baseline-relevance scores per dimension ..." -ForegroundColor DarkGray
    # Count occurrences of behavior fields across all cached VT-behaviors
    $dimCounts = @{
        'proc-spawn' = 0; 'file-write' = 0; 'reg-set' = 0; 'module-load' = 0
        'svc-create' = 0; 'sched-task' = 0; 'dns' = 0; 'http-egress' = 0
        'wmi-sub' = 0; 'priv-esc' = 0; 'proc-inject' = 0; 'mqtt' = 0
    }
    $samplesTotal = 0
    if (Test-Path $behRoot) {
        foreach ($f in (Get-ChildItem -LiteralPath $behRoot -Filter '*.json' -File -Recurse -ErrorAction SilentlyContinue)) {
            if ($f.Length -gt 50MB) { continue }
            $samplesTotal++
            if ($samplesTotal % 5000 -eq 0) { Write-Host "    behaviors scanned: $samplesTotal" -ForegroundColor DarkGray }
            try {
                $j = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                $d = if ($j.data -is [System.Object[]]) { $j.data[0] } else { $j.data }
                if (-not $d) { continue }
                if ($d.processes_created       -and $d.processes_created.Count       -gt 0) { $dimCounts['proc-spawn']++ }
                if ($d.files_written           -and $d.files_written.Count           -gt 0) { $dimCounts['file-write']++ }
                if ($d.registry_keys_set       -and $d.registry_keys_set.Count       -gt 0) { $dimCounts['reg-set']++ }
                if ($d.modules_loaded          -and $d.modules_loaded.Count          -gt 0) { $dimCounts['module-load']++ }
                if ($d.services_started        -and $d.services_started.Count        -gt 0) { $dimCounts['svc-create']++ }
                if ($d.scheduled_tasks         -and $d.scheduled_tasks.Count         -gt 0) { $dimCounts['sched-task']++ }
                if ($d.dns_lookups             -and $d.dns_lookups.Count             -gt 0) { $dimCounts['dns']++ }
                if ($d.ip_traffic              -and $d.ip_traffic.Count              -gt 0) { $dimCounts['http-egress']++ }
            } catch { }
        }
    }
    Write-Host ("  scanned {0:N0} behavior JSONs; dimensions observed:" -f $samplesTotal) -ForegroundColor DarkGray
    foreach ($k in $dimCounts.Keys) {
        if ($dimCounts[$k] -gt 0) { Write-Host ("    {0,-15} {1,6:N0}" -f $k, $dimCounts[$k]) -ForegroundColor DarkGray }
    }

    # Attach baseline-relevance to each row (where we have data)
    foreach ($r in $rows) {
        $cnt = if ($dimCounts.ContainsKey($r.id)) { $dimCounts[$r.id] } else { 0 }
        $pct = if ($samplesTotal -gt 0) { [Math]::Round(100.0 * $cnt / $samplesTotal, 1) } else { 0 }
        $r.baselineCount = $cnt
        $r.baselinePct   = $pct
    }

    # ----- Payload -----------------------------------------------------------
    $payload = [ordered]@{
        generatedAt = (Get-Date).ToString('s')
        tools       = $tools
        rows        = $rows
        samples     = $samplesTotal
        totals      = [ordered]@{
            rows = $rows.Count
            tools = $tools.Count
            full   = ($rows | ForEach-Object { $r=$_; ($tools | Where-Object { $r.cov[$_.id] -eq 'FULL'    }).Count } | Measure-Object -Sum).Sum
            partial= ($rows | ForEach-Object { $r=$_; ($tools | Where-Object { $r.cov[$_.id] -eq 'PARTIAL' }).Count } | Measure-Object -Sum).Sum
            blind  = ($rows | ForEach-Object { $r=$_; ($tools | Where-Object { $r.cov[$_.id] -eq 'BLIND'   }).Count } | Measure-Object -Sum).Sum
            na     = ($rows | ForEach-Object { $r=$_; ($tools | Where-Object { $r.cov[$_.id] -eq 'N/A'     }).Count } | Measure-Object -Sum).Sum
        }
    }
    $payloadJson = $payload | ConvertTo-Json -Depth 10 -Compress

    # ----- Render HTML -------------------------------------------------------
    $html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<title>OT EDR Coverage Gap Matrix</title>
<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css' rel='stylesheet'>
<style>
  body { background:#f8f9fa; font-family:'Segoe UI',system-ui,sans-serif; padding:20px; }
  .breadcrumb-bar { background:#e5e7eb; padding:8px 16px; border-radius:6px; font-size:.85rem; color:#374151; margin-bottom:16px; }
  .panel { background:#fff; border-radius:8px; padding:18px; box-shadow:0 1px 3px rgba(0,0,0,.06); margin-bottom:18px; }
  .panel h2 { font-size:1.1rem; font-weight:600; color:#1f2937; margin-bottom:6px; }
  .panel-sub { color:#6b7280; font-size:.85rem; margin-bottom:14px; }
  .legend { display:flex; gap:14px; flex-wrap:wrap; font-size:.85rem; margin-bottom:10px; }
  .legend-swatch { display:inline-block; width:18px; height:18px; border-radius:3px; vertical-align:middle; margin-right:5px; border:1px solid #d1d5db; }
  .matrix-wrap { overflow:auto; max-height:80vh; border:1px solid #e5e7eb; border-radius:6px; }
  table.gap { border-collapse:separate; border-spacing:0; font-size:.78rem; width:100%; }
  table.gap th, table.gap td { padding:4px 6px; text-align:center; border-right:1px solid #f1f5f9; border-bottom:1px solid #f1f5f9; }
  table.gap thead th { position:sticky; top:0; background:#f9fafb; z-index:2; font-weight:600; vertical-align:bottom; height:120px; }
  table.gap thead th:first-child { transform:none; min-width:340px; max-width:340px; text-align:left; padding-left:10px; }
  table.gap thead th .col-rot { display:inline-block; transform:rotate(-30deg); transform-origin:bottom left; white-space:nowrap; padding-bottom:6px; }
  table.gap tbody td:first-child { position:sticky; left:0; background:#fff; text-align:left; min-width:340px; max-width:340px; padding-left:10px; border-right:2px solid #d1d5db; z-index:1; }
  table.gap tbody tr:hover td { background:#fffbeb; }
  table.gap tbody td:first-child:hover { background:#fff; }
  .section-row td { background:#eef2ff !important; font-weight:600; color:#3730a3; text-align:left; padding:8px 10px !important; font-size:.85rem; }
  .cov-FULL    { background:#86efac; color:#14532d; font-weight:600; }
  .cov-PARTIAL { background:#fde68a; color:#78350f; font-weight:600; }
  .cov-BLIND   { background:#fca5a5; color:#7f1d1d; font-weight:600; }
  .cov-NA      { background:#e5e7eb; color:#4b5563; font-style:italic; }
  .dim-name { font-weight:600; color:#1f2937; }
  .dim-hint { color:#6b7280; font-size:.7rem; font-family:'Consolas','Monaco',monospace; margin-top:2px; }
  .baseline-badge { display:inline-block; padding:1px 7px; border-radius:10px; font-size:.7rem; font-weight:600; margin-left:6px; }
  .baseline-high { background:#fca5a5; color:#7f1d1d; }
  .baseline-mid  { background:#fde68a; color:#78350f; }
  .baseline-low  { background:#e0e7ff; color:#3730a3; }
  .baseline-none { background:#f3f4f6; color:#6b7280; }
  .filter-bar { display:flex; gap:10px; align-items:center; margin-bottom:12px; flex-wrap:wrap; }
  .filter-bar select, .filter-bar input { font-size:.85rem; padding:4px 8px; border:1px solid #d1d5db; border-radius:4px; }
  .kpi { background:#fff; border-radius:8px; padding:14px; box-shadow:0 1px 3px rgba(0,0,0,.06); text-align:center; }
  .kpi-value { font-size:1.6rem; font-weight:600; }
  .kpi-label { color:#6b7280; font-size:.75rem; text-transform:uppercase; letter-spacing:.5px; margin-top:2px; }
  .tool-meta { font-size:.7rem; color:#6b7280; max-width:140px; white-space:normal; line-height:1.2; margin-top:4px; }
</style>
</head>
<body>

<div class='breadcrumb-bar'>OT EDR Coverage Gap Matrix &nbsp; · &nbsp; tool × behavior-dimension cross-tab &nbsp; · &nbsp; generated <span id='gen'></span></div>

<div class='row g-3 mb-3'>
  <div class='col'><div class='kpi'><div class='kpi-value' style='color:#15803d' id='kpi-full'>0</div><div class='kpi-label'>FULL cells</div></div></div>
  <div class='col'><div class='kpi'><div class='kpi-value' style='color:#b45309' id='kpi-partial'>0</div><div class='kpi-label'>PARTIAL cells</div></div></div>
  <div class='col'><div class='kpi'><div class='kpi-value' style='color:#b91c1c' id='kpi-blind'>0</div><div class='kpi-label'>BLIND cells</div></div></div>
  <div class='col'><div class='kpi'><div class='kpi-value' style='color:#4b5563' id='kpi-na'>0</div><div class='kpi-label'>N/A cells</div></div></div>
  <div class='col'><div class='kpi'><div class='kpi-value' id='kpi-samples'>0</div><div class='kpi-label'>Behavior samples</div></div></div>
</div>

<div class='panel'>
  <h2>OT EDR Coverage Gap Matrix</h2>
  <div class='panel-sub'>
    Rows = behavior dimensions an attacker exercises across Purdue layers. Columns = detection tools commonly considered in OT (host EDR, NAC, OT-native passive DPI, vendor audit logs). Each cell is the tool's coverage for that dimension; the per-row badge shows how often the dimension appears in our baselined VT-behaviors corpus (proxy for &quot;how often you'll see this in legit OT activity, so how often a deviation matters&quot;). Hover any column header for the tool's caveat.
  </div>
  <div class='legend'>
    <div><span class='legend-swatch' style='background:#86efac'></span>FULL — default config catches it</div>
    <div><span class='legend-swatch' style='background:#fde68a'></span>PARTIAL — visible with tuning / companion product</div>
    <div><span class='legend-swatch' style='background:#fca5a5'></span>BLIND — no native visibility</div>
    <div><span class='legend-swatch' style='background:#e5e7eb'></span>N/A — architecturally inapplicable (e.g. host EDR on a PLC)</div>
  </div>
  <div class='filter-bar'>
    <label>Section:
      <select id='filter-section'><option value=''>All</option></select>
    </label>
    <label>Filter dimension:
      <input type='text' id='filter-dim' placeholder='e.g. modbus, registry, vnc'>
    </label>
    <label><input type='checkbox' id='filter-blind-only'> Show only rows with at least one BLIND</label>
  </div>
  <div class='matrix-wrap'><table class='gap' id='gap-matrix'></table></div>
</div>

<script src='https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js'></script>
<script>
const DATA = $payloadJson;

document.getElementById('gen').textContent = DATA.generatedAt.replace('T',' ').substring(0,16);
document.getElementById('kpi-full').textContent    = DATA.totals.full;
document.getElementById('kpi-partial').textContent = DATA.totals.partial;
document.getElementById('kpi-blind').textContent   = DATA.totals.blind;
document.getElementById('kpi-na').textContent      = DATA.totals.na;
document.getElementById('kpi-samples').textContent = DATA.samples.toLocaleString();

// Populate section filter
const sections = [...new Set(DATA.rows.map(r => r.section))];
const secSel = document.getElementById('filter-section');
sections.forEach(s => {
  const o = document.createElement('option'); o.value = s; o.textContent = s;
  secSel.appendChild(o);
});

function baselineBadgeClass(pct) {
  if (pct >= 40) return 'baseline-high';
  if (pct >= 10) return 'baseline-mid';
  if (pct > 0)   return 'baseline-low';
  return 'baseline-none';
}

function renderMatrix() {
  const fSec = document.getElementById('filter-section').value;
  const fDim = document.getElementById('filter-dim').value.toLowerCase().trim();
  const fBlind = document.getElementById('filter-blind-only').checked;

  let html = '<thead><tr><th>Dimension &nbsp;·&nbsp; baseline relevance</th>';
  DATA.tools.forEach(t => {
    html += '<th title="' + t.notes.replace(/"/g,'&quot;') + '">' +
            '<div class="col-rot">' + t.name + '</div>' +
            '<div class="tool-meta">' + t.type + '</div></th>';
  });
  html += '</tr></thead><tbody>';

  let lastSection = null;
  DATA.rows.forEach(r => {
    if (fSec && r.section !== fSec) return;
    if (fDim && !(r.name.toLowerCase().includes(fDim) || (r.hint||'').toLowerCase().includes(fDim))) return;
    if (fBlind && !DATA.tools.some(t => r.cov[t.id] === 'BLIND')) return;
    if (r.section !== lastSection) {
      html += '<tr class="section-row"><td colspan="' + (1 + DATA.tools.length) + '">' + r.section + '</td></tr>';
      lastSection = r.section;
    }
    const blCls = baselineBadgeClass(r.baselinePct || 0);
    const blLabel = r.baselinePct > 0 ? r.baselinePct + '% of samples' : 'no baseline data';
    html += '<tr><td>' +
      '<div class="dim-name">' + r.name +
        '<span class="baseline-badge ' + blCls + '" title="Observed in this fraction of baselined VT behavior samples">' + blLabel + '</span>' +
      '</div>' +
      (r.hint ? '<div class="dim-hint">' + r.hint + '</div>' : '') +
      '</td>';
    DATA.tools.forEach(t => {
      const v = r.cov[t.id] || 'N/A';
      html += '<td class="cov-' + v.replace('/','') + '" title="' + t.name + ': ' + v + '">' + v + '</td>';
    });
    html += '</tr>';
  });
  html += '</tbody>';
  document.getElementById('gap-matrix').innerHTML = html;
}

document.getElementById('filter-section').onchange =
document.getElementById('filter-dim').oninput =
document.getElementById('filter-blind-only').onchange = renderMatrix;
renderMatrix();
</script>
</body>
</html>
"@

    Set-Content -LiteralPath $OutputPath -Value $html -Encoding UTF8
    Write-Host ("`n[Build-OTEDRGapMatrix] Wrote {0:N0} bytes -> {1}" -f (Get-Item $OutputPath).Length, $OutputPath) -ForegroundColor Green
    Write-Host ("[Build-OTEDRGapMatrix] Cells: {0} FULL / {1} PARTIAL / {2} BLIND / {3} N/A" -f $payload.totals.full, $payload.totals.partial, $payload.totals.blind, $payload.totals.na) -ForegroundColor DarkCyan
    Write-Host "[Build-OTEDRGapMatrix] Open in browser: file:///$($OutputPath -replace '\\','/')" -ForegroundColor Cyan
}

Export-ModuleMember -Function Build-OTEDRGapMatrix

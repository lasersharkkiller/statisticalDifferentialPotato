function New-ApiMatrixDashboard {
    param (
        [string]$RootPath = ".\apt",
        [string]$OutputHtmlPath = ".\output\API_Capabilities_Matrix.html",
        [string]$GlobalResolutionPath = "output\Global_Hash_Resolution.csv",
        [string]$ReportTitle = "Malware API Capabilities Matrix"
    )

    Write-Host "Generating API Matrix (v10.0 - Fixed + Enhanced)..." -ForegroundColor DarkCyan

    if (-not (Test-Path $RootPath)) { Write-Error "Root path not found."; return }
    $AbsRoot = (Resolve-Path $RootPath).Path

    # --- 1. THE "JOIN TABLE" (Defined Locally) ---
    $AptToolMap = @{
        "UAT-8837"         = @("GoTokenTheft", "EarthWorm", "DWAgent", "SharpHound", "Impacket", "GoExec", "Rubeus", "Certipy")
        "Salt Typhoon"     = @("GhostSpider", "Demodex", "ShadowPad")
        "Storm-2603"       = @("AK47 C2", "ToolShell", "Impacket")
        "Earth Krahang"    = @("RESHELL", "XDealer", "Cobalt Strike")
        "UAT-7290"         = @("RushDrop", "SilentRaid", "ShadowPad")
        "UNC3886"          = @("TinyShell", "Reptile", "Medusa")
        "Volt Typhoon"     = @("KV-Botnet", "Impacket", "EarthWorm")
        "APT1"             = @("PoisonIvy", "PlugX")
        "APT10"            = @("PlugX", "QuasarRAT")
        "APT27"            = @("PlugX", "HyperBro")
        "APT31"            = @("SOGU", "LuckyBird")
        "APT41"            = @("ShadowPad", "Cobalt Strike", "Winnti")
        "Aquatic Panda"    = @("ShadowPad", "Winnti")
        "BlackTech"        = @("Kivars", "Pled")
        "Gallium"          = @("PingPull", "Gh0st RAT")
        "Hafnium"          = @("China Chopper", "Tarrask")
        "Ke3chang"         = @("Okrum", "Ketrican")
        "Mustang Panda"    = @("PlugX", "Cobalt Strike")
        "APT28"            = @("Mimikatz", "Impacket")
        "APT29"            = @("Cobalt Strike", "Mimikatz")
        "Sandworm"         = @("BlackEnergy", "Industroyer")
        "Wizard Spider"    = @("TrickBot", "Ryuk", "Cobalt Strike")
        "Scattered Spider" = @("BlackCat", "Rubeus", "Mimikatz")
    }

    # --- 2. LOAD GLOBAL HASH MAP ---
    $DateMap = @{}
    if (Test-Path $GlobalResolutionPath) {
        Write-Host "  Loading Global Hash Map..." -NoNewline
        Import-Csv $GlobalResolutionPath | ForEach-Object {
            $d = $_.Date_Found
            if ($d -and $d -ne "1970-01-01") {
                if ($_.Canonical_SHA256) { $DateMap[$_.Canonical_SHA256] = $d }
                if ($_.MD5)              { $DateMap[$_.MD5]              = $d }
                if ($_.SHA1)             { $DateMap[$_.SHA1]             = $d }
            }
        }
        Write-Host " Done ($($DateMap.Count) hashes)." -ForegroundColor Green
    }

    # --- 3. CATEGORY DEFINITIONS (mapped to MITRE ATT&CK Enterprise tactics) ---
    # Each list is keyword prefixes/substrings matched case-insensitively against API names.
    # Tactic order follows ATT&CK Enterprise left-to-right.
    $ApiMatrix = [ordered]@{

        # TA0007 - Discovery
        # Enumerate users, groups, shares, sessions, hosts, network config, processes, files, registry
        "Discovery" = @(
            # User & group enumeration
            "NetUser", "NetLocalGroup", "NetGroupEnum", "NetGroupGet",
            "NetQueryDisplay", "NetGetDCName", "NetGetAnyDCName",
            "DsGetDcName", "DsEnumDomain", "DsGetSite",
            "LookupAccount", "GetUserName", "GetUserNameEx",
            "WNetEnum", "WNetGet", "WNetOpen",
            # Session & share enumeration
            "NetShare", "NetSession", "NetFile", "NetConnection",
            "NetWksta", "NetServer", "NetUse",
            "WTSEnumerate", "WTSQuery", "WTSOpen",
            # Host & system info
            "GetComputerName", "GetComputerNameEx",
            "GetSystemInfo", "GetNativeSystemInfo", "GetVersionEx",
            "RtlGetVersion", "VerifyVersionInfo",
            "GetProductInfo", "OsGetVersion",
            "GetTickCount", "GlobalMemoryStatusEx", "GlobalMemoryStatus",
            "GetDiskFreeSpace", "GetVolumeInformation", "GetDriveType",
            "GetLogicalDrives", "GetLogicalDriveStrings",
            "QueryDosDevice", "DeviceIoControl",
            # Process & service enumeration
            "EnumProcess", "Process32First", "Process32Next",
            "Module32First", "Module32Next", "Thread32First", "Thread32Next",
            "NtQuerySystemInformation", "ZwQuerySystemInformation",
            "NtQueryInformationProcess", "ZwQueryInformationProcess",
            "EnumServicesStatus", "QueryServiceStatus", "OpenSCManager",
            "EnumDeviceDrivers", "GetDeviceDriver",
            # Window & UI enumeration
            "EnumWindows", "EnumChildWindows", "EnumDesktopWindows",
            "GetWindowText", "GetClassName", "FindWindow",
            "GetForegroundWindow", "GetShellWindow",
            # Network config & ARP
            "GetAdapters", "GetAdapterInfo", "GetAdaptersAddresses",
            "GetNetworkParams", "GetIpAddrTable", "GetIpForwardTable",
            "GetIpNetTable", "GetTcpTable", "GetUdpTable",
            "GetIfTable", "GetIfEntry",
            "DnsQuery", "DnsQueryEx", "DnsGetCacheDataTable",
            "Icmp", "IcmpSendEcho", "Icmp6SendEcho",
            "GetHostByName", "GetHostByAddr", "GetHostName",
            "GetIpAddr", "inet_addr", "inet_ntoa",
            # Environment & path
            "GetEnvironmentVariable", "GetEnvironmentStrings",
            "WhoAmI", "GetCurrentDirectory", "GetTempPath",
            "GetWindowsDirectory", "GetSystemDirectory", "GetSystemWindowsDirectory",
            "SHGetFolderPath", "SHGetKnownFolderPath", "SHGetSpecialFolderPath",
            "ExpandEnvironmentStrings",
            # File system enumeration
            "FindFirst", "FindNext", "FindClose",
            "GetFileAttributes", "GetFileAttributesEx",
            "PathFind", "PathIs", "PathGet",
            "SHFind", "SHBrowse",
            # Registry enumeration
            "RegEnum", "RegQuery", "RegOpen",
            "NtEnumerateKey", "ZwEnumerateKey",
            "NtEnumerateValueKey", "ZwEnumerateValueKey"
        )

        # TA0006 - Credential Access
        # LSASS dumping, SAM, DPAPI, token theft, Kerberos, credential APIs
        "Credential Access" = @(
            # SAM / LSA secrets
            "SamConnect", "SamOpen", "SamEnum", "SamGet", "SamQuery",
            "SamLookup", "SamCreate", "SamSet",
            "LsaOpen", "LsaQuery", "LsaEnum", "LsaFree",
            "LsaRetrievePrivateData", "LsaStorePrivateData",
            "LsaLookup", "LsaGetLogonSession",
            "LsaRegisterLogonProcess", "LsaLogonUser",
            "LsaCallAuthentication",
            # SSPI / auth packages
            "Secur32", "AcquireCredentialsHandle", "InitializeSecurityContext",
            "AcceptSecurityContext", "QueryContextAttributes",
            "FreeCredentialsHandle", "FreeContextBuffer",
            "EncryptMessage", "DecryptMessage", "MakeSignature", "VerifySignature",
            "SspiEncodeAuthIdentity", "SspiPrepareForCredRead",
            # Credential manager
            "CredRead", "CredWrite", "CredDelete", "CredEnum", "CredFind",
            "CredGetTargetInfo", "CredIsMarshaledCredential",
            "CredUnmarshalCredential", "CredMarshalCredential",
            "VaultOpen", "VaultEnum", "VaultGet", "VaultClose",
            # Token & impersonation
            "OpenProcessToken", "OpenThreadToken",
            "DuplicateToken", "DuplicateTokenEx",
            "ImpersonateLoggedOnUser", "ImpersonateNamedPipe",
            "ImpersonateSelf", "ImpersonateAnonymousToken",
            "SetThreadToken", "RevertToSelf",
            "AdjustTokenPrivileges", "AdjustTokenGroups",
            "GetTokenInformation", "SetTokenInformation",
            "CreateRestrictedToken", "CheckTokenMembership",
            "LogonUser", "LogonUserEx", "CreateProcessWithLogon",
            # Kerberos / NTLM
            "Kerberos", "KerbQueryTicket", "KerbPurgeTicket",
            "LsaCallKerberosPackage",
            "NtlmShared", "NtlmInitialize",
            "GetMSV1_0", "MsvpPasswordValidate",
            # DPAPI
            "CryptProtectData", "CryptUnprotectData",
            "CryptProtectMemory", "CryptUnprotectMemory",
            "PFXExportCertStore", "PFXImportCertStore",
            # Certificate store
            "CertOpen", "CertFind", "CertGet", "CertEnum",
            "CertDuplicate", "CertClose", "CertAdd",
            "CryptFind", "CryptGet", "CryptAcquire",
            # Process memory (LSASS dump)
            "MiniDumpWrite", "DbgHelp",
            "ReadProcessMemory", "NtReadVirtualMemory", "ZwReadVirtualMemory",
            # Clipboard (password managers)
            "GetClipboardData", "OpenClipboard", "CloseClipboard"
        )

        # TA0002 - Execution
        # Process creation, script hosts, COM, WMI, DLL loading
        "Execution" = @(
            # Direct process creation
            "CreateProcess", "CreateProcessA", "CreateProcessW",
            "CreateProcessAsUser", "CreateProcessWithToken", "CreateProcessWithLogon",
            "NtCreateUserProcess", "ZwCreateUserProcess",
            "NtCreateProcess", "ZwCreateProcess",
            "RtlCreateUserProcess",
            "ShellExecute", "ShellExecuteEx",
            "WinExec", "system", "_wsystem",
            "execv", "execve", "execvp", "execvpe",
            "spawnv", "spawnve", "spawnvp",
            # COM / OLE execution
            "CoCreateInstance", "CoCreateInstanceEx",
            "CoGetClassObject", "CoInitialize", "CoInitializeEx",
            "OleRun", "OleLoad", "OleCreate",
            "CLSIDFromString", "CLSIDFromProgID",
            # WMI / scripting
            "IWbem", "WbemLocator", "WbemServices",
            "WScript", "WshShell", "ActiveXObject",
            "IDispatch", "IActiveScript", "IActiveScriptParse",
            # PowerShell / .NET hosting
            "PowerShell", "CLRCreate", "CorBind",
            "ICLRRuntime", "ICLRMetaHost",
            "CreateDomain", "AppDomain",
            # Module / DLL loading
            "LoadLibrary", "LoadLibraryA", "LoadLibraryW",
            "LoadLibraryEx", "LoadLibraryExA", "LoadLibraryExW",
            "LdrLoadDll", "LdrGetDllHandle", "LdrGetProcedureAddress",
            "GetProcAddress", "GetProcAddressForCaller",
            "NtMapViewOfSection", "ZwMapViewOfSection",
            # Scheduled / async execution
            "RegisterApplicationRestart", "RegisterApplicationRecovery",
            "CreateFiber", "ConvertThreadToFiber", "SwitchToFiber",
            "QueueUserWorkItem", "TpAllocWork", "SubmitThreadpoolWork",
            # Misc execution helpers
            "ExpandEnvironmentStrings",
            "PathGetArgs", "PathRemoveArgs",
            "AssocQuery", "FindExecutable"
        )

        # TA0003 - Persistence
        # Registry run keys, services, scheduled tasks, boot sectors, COM hijack, startup folder
        "Persistence" = @(
            # Registry run keys & autorun
            "RegCreate", "RegSet", "RegOpen", "RegDelete", "RegQuery",
            "RegConnectRegistry", "RegDisableReflectionKey",
            "NtSetValueKey", "ZwSetValueKey",
            "NtCreateKey", "ZwCreateKey",
            "NtOpenKey", "ZwOpenKey",
            "SHReg", "SHSetValue", "SHGetValue",
            # Services
            "CreateService", "OpenService", "ChangeServiceConfig",
            "StartService", "ControlService", "DeleteService",
            "RegisterServiceCtrl", "SetServiceStatus",
            # Scheduled tasks
            "ITaskScheduler", "ITask", "ITaskFolder", "ITaskService",
            "CoCreateInstance",         # used to instantiate Task Scheduler COM
            "NetScheduleJob",
            # Startup folder / shell
            "SHGetFolderPath", "SHGetKnownFolderPath",
            "SHFileOperation",
            # COM hijacking
            "RegSetValueEx",            # writing CLSID/InprocServer32
            "CoRegisterClassObject",
            # Boot / MBR
            "NtDiskIoControl", "IOCTL_DISK",
            # WMI subscriptions
            "IWbemServices", "IWbemLocator",
            # DLL search-order / AppInit
            "SetDllDirectory", "AddDllDirectory",
            "SetDefaultDllDirectories",
            # AppCert / AppInit DLLs (registry keys covered above)
            "AppCertDlls", "AppInitDLLs",
            # Netsh helper / LSA notification
            "LsaRegisterPolicyChangeNotification",
            # Accessibility / image file execution
            "GlobalAddAtom", "AddAtom", "FindAtom",
            # Time provider / print monitor (rare but seen)
            "AddTimeProvider", "AddPrintProvider"
        )

        # TA0005 - Defense Evasion
        # Anti-debug, timing, unhooking, process hollowing helpers, token manipulation, AMSI bypass
        "Defense Evasion" = @(
            # Anti-debug / sandbox detection
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "OutputDebugString", "NtQueryInformationProcess",
            "ZwQueryInformationProcess", "NtSetInformationThread",
            "ZwSetInformationThread",
            "NtClose",                  # invalid handle trick
            "RaiseException", "SetUnhandledExceptionFilter",
            "AddVectoredExceptionHandler", "RemoveVectoredExceptionHandler",
            # Timing / sleep evasion
            "NtDelayExecution", "ZwDelayExecution",
            "Sleep", "SleepEx", "WaitForSingleObject", "WaitForMultipleObjects",
            "GetTickCount", "GetTickCount64",
            "QueryPerformanceCounter", "QueryPerformanceFrequency",
            "GetLocalTime", "GetSystemTime", "GetSystemTimeAsFileTime",
            "timeGetTime", "NtQuerySystemTime",
            "GlobalMemoryStatusEx",     # memory size check
            # Process / thread hollowing & manipulation
            "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
            "NtSuspendProcess", "ZwSuspendProcess",
            "NtResumeProcess", "ZwResumeProcess",
            "SuspendThread", "ResumeThread",
            "Wow64", "Wow64DisableWow64FsRedirection",
            "Wow64RevertWow64FsRedirection",
            # Token / privilege manipulation
            "RtlAdjustPrivilege", "AdjustTokenPrivileges",
            "ImpersonateAnonymousToken",
            # Hooking / unhooking
            "SetWindowsHookEx", "UnhookWindowsHookEx",
            "NtSetEaFile",              # used for NTFS attribute hiding
            # AMSI / ETW bypass
            "AmsiScanBuffer", "AmsiOpenSession", "AmsiInitialize",
            "EtwEventWrite", "EtwEventWriteFull",
            "NtTraceEvent", "NtTraceControl",
            # File/path masquerading
            "SetFileAttributes", "SetFileAttributesEx",
            "SetFileTime", "GetFileTime",
            "MoveFileEx",               # MOVEFILE_DELAY_UNTIL_REBOOT
            "ReplaceFile",
            # Packing / obfuscation indicators
            "VirtualProtect", "VirtualProtectEx",
            "NtProtectVirtualMemory", "ZwProtectVirtualMemory",
            "FlushInstructionCache",
            # SFC bypass
            "SfcIsFileProtected", "SfcTerminateWatcherThread",
            # UAC bypass helpers
            "ShellExecute",             # runas verb
            "CoGetObject",              # Elevation moniker
            # Signed binary proxy
            "Mshta", "Regsvr32", "Rundll32", "Regasm",
            # Obfuscated imports / ordinals
            "Ord("
        )

        # TA0004 - Privilege Escalation
        # Kernel exploitation primitives, driver ops, token stealing, named pipe impersonation
        "Privilege Escalation" = @(
            # Kernel object manager
            "Ke", "KeInsertQueue", "KeRemoveQueue",
            "KeWaitForSingleObject", "KeWaitForMultipleObjects",
            "KeSetEvent", "KeClearEvent", "KeResetEvent",
            "KeAcquireSpinLock", "KeReleaseSpinLock",
            "KeBugCheck", "KeBugCheckEx",
            # I/O manager
            "Io", "IoCreateDevice", "IoDeleteDevice",
            "IoCreateSymbolicLink", "IoDeleteSymbolicLink",
            "IoAllocateIrp", "IoFreeIrp", "IoBuildDeviceIoControlRequest",
            "IoCallDriver", "IoCompleteRequest",
            "IoGetCurrentProcess", "IoGetCurrentThread",
            "IoAttachDeviceToDeviceStack", "IoDetachDevice",
            # Object manager
            "Ob", "ObOpenObjectByName", "ObReferenceObject",
            "ObDereferenceObject", "ObQueryNameString",
            "ObRegisterCallbacks", "ObUnRegisterCallbacks",
            # Memory manager
            "Mm", "MmAllocateNonPagedPool", "MmAllocateNonPagedPoolNx",
            "MmAllocateContiguousMemory", "MmFreeContiguousMemory",
            "MmGetSystemRoutineAddress", "MmIsAddressValid",
            "MmMapIoSpace", "MmUnmapIoSpace",
            "MmProbeAndLockPages", "MmUnlockPages",
            "MmCopyMemory",
            # Executive / pool
            "ExAllocate", "ExAllocatePool", "ExAllocatePoolWithTag",
            "ExFreePool", "ExFreePoolWithTag",
            "ExAcquireFastMutex", "ExReleaseFastMutex",
            # Process / thread (kernel)
            "Ps", "PsLookupProcessByProcessId", "PsLookupThreadByThreadId",
            "PsGetCurrentProcess", "PsGetCurrentThread",
            "PsGetProcessPeb", "PsGetProcessWow64Process",
            "PsSetCreateProcessNotifyRoutine", "PsRemoveCreateThreadNotifyRoutine",
            "PsCreateSystemThread", "PsTerminateSystemThread",
            # HAL / hardware
            "Hal", "HalAllocateCommonBuffer", "HalFreeCommonBuffer",
            "HalGetAdapter",
            # Runtime library
            "Rtl", "RtlCopyMemory", "RtlMoveMemory", "RtlZeroMemory",
            "RtlFillMemory", "RtlCompareMemory",
            "RtlInitUnicodeString", "RtlFreeUnicodeString",
            "RtlAnsiStringToUnicodeString", "RtlUnicodeStringToAnsiString",
            # Nt/Zw low-level
            "Zw", "NtLoadDriver", "ZwLoadDriver",
            "NtSetSystemInformation", "ZwSetSystemInformation",
            "NtQuerySystemInformation",
            "NtPrivilegeObjectAuditAlarm", "NtPrivilegeCheck",
            "SeDebugPrivilege",
            # Named pipe impersonation
            "ImpersonateNamedPipeClient", "ConnectNamedPipe",
            "CreateNamedPipe", "WaitNamedPipe",
            # FsFilter / cache
            "FsRtl", "FsRtlRegisterFileSystemFilterCallbacks",
            "FsRtlAllocateFileLock", "FsRtlFreeFileLock",
            "Cc", "CcInitializeCacheMap", "CcMapData",
            # Cc cache manager
            "CcPurgeCacheSection", "CcSetFileSizes"
        )

        # TA0008 - Lateral Movement
        # Remote execution, pass-the-hash, SMB/RPC, WMI, DCOM, injection into remote processes
        "Lateral Movement" = @(
            # Remote process / thread
            "CreateRemoteThread", "CreateRemoteThreadEx",
            "NtCreateThreadEx", "ZwCreateThreadEx",
            "NtCreateThread", "ZwCreateThread",
            "RtlCreateUserThread",
            # APC injection
            "QueueUserAPC", "NtQueueApcThread", "ZwQueueApcThread",
            "NtQueueApcThreadEx",
            # Virtual memory in remote process
            "VirtualAllocEx", "VirtualFreeEx",
            "NtAllocateVirtualMemory", "ZwAllocateVirtualMemory",
            "VirtualAlloc", "VirtualFree",
            "WriteProcessMemory", "NtWriteVirtualMemory", "ZwWriteVirtualMemory",
            "ReadProcessMemory", "NtReadVirtualMemory",
            # Thread context
            "GetThreadContext", "SetThreadContext",
            "SuspendThread", "ResumeThread",
            "NtSuspendThread", "ZwSuspendThread",
            "NtResumeThread", "ZwResumeThread",
            # Process handle
            "OpenProcess", "NtOpenProcess", "ZwOpenProcess",
            "OpenThread", "NtOpenThread",
            # Section / map
            "NtCreateSection", "ZwCreateSection",
            "NtMapViewOfSection", "ZwMapViewOfSection",
            "NtUnmapViewOfSection",
            # Hook injection
            "SetWindowsHookEx",
            # SMB / named pipe lateral movement
            "WNetAddConnection", "WNetAddConnection2",
            "WNetOpenEnum", "WNetCancelConnection",
            "NetUseAdd", "NetUseDel",
            "CreateNamedPipe", "ConnectNamedPipe",
            "CallNamedPipe", "TransactNamedPipe",
            # WMI remote execution
            "IWbemServices", "IWbemLocator",
            # DCOM remote
            "CoCreateInstanceEx",
            # Service-based (PsExec-style)
            "CreateService", "StartService",
            # RPC
            "RpcBind", "RpcCall", "NdrClientCall",
            "RpcStringBinding", "RpcEpRegister",
            # SCM remote
            "OpenSCManagerA", "OpenSCManagerW"
        )

        # TA0009 - Collection
        # File reads, screen capture, keylogging, clipboard, audio/video, staged archives
        "Collection" = @(
            # File read / staging
            "CreateFile", "ReadFile", "ReadFileEx",
            "NtCreateFile", "ZwCreateFile",
            "NtReadFile", "ZwReadFile",
            "fopen", "fread", "fgets", "fgetc", "fgetws",
            "GetFileSize", "GetFileSizeEx",
            "SetFilePointer", "SetFilePointerEx",
            "MapViewOfFile", "MapViewOfFileEx",
            # Directory traversal
            "FindFirstFile", "FindNextFile", "FindClose",
            "FindFirstFileEx", "FindFirstFileNameW",
            "SHFind", "SHBrowse",
            # Clipboard
            "OpenClipboard", "CloseClipboard", "EmptyClipboard",
            "GetClipboardData", "SetClipboardData",
            "GetClipboardOwner", "IsClipboardFormatAvailable",
            "AddClipboardFormatListener",
            # Screen capture
            "BitBlt", "StretchBlt", "PatBlt",
            "GetDC", "GetWindowDC", "ReleaseDC",
            "CreateCompatibleDC", "CreateCompatibleBitmap",
            "PrintWindow", "GetDIBits", "SetDIBits",
            # Keylogging
            "GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
            "SetWindowsHookEx",         # WH_KEYBOARD / WH_KEYBOARD_LL
            "MapVirtualKey", "VkKeyScan",
            "GetRawInputData", "RegisterRawInputDevices",
            # Input simulation (credential phishing)
            "SendInput", "keybd_event", "mouse_event",
            "PostMessage", "SendMessage", "SendMessageTimeout",
            "BlockInput",
            # Window / UI scraping
            "GetForegroundWindow", "GetCursorPos", "SetCursorPos",
            "GetWindowRect", "GetClientRect",
            "GetWindowText", "GetWindowTextLength",
            "GetDlgItemText", "GetDlgItem",
            # Audio / microphone
            "waveIn", "waveInOpen", "waveInStart", "waveInRead",
            "mciSend", "mciOpen",
            # Webcam / video
            "capCreateCaptureWindow", "capDriverConnect",
            "avicap32",
            # Email (MAPI)
            "MAPILogon", "MAPIFindNext", "MAPIReadMail",
            "MAPIGetMail", "MAPIAddress",
            # Archive staging
            "ZipFile", "CabFile", "CreateCabinet",
            "RtlCompressBuffer", "RtlDecompressBuffer",
            "FlushFileBuffers",
            # Device I/O (raw disk / USB collection)
            "DeviceIoControl", "GetModuleFileName"
        )

        # TA0011 - Command and Control
        # All network communication: raw sockets, WinInet, WinHTTP, DNS tunnelling, named pipes
        "Command and Control" = @(
            # WinSock / raw sockets
            "WSAStartup", "WSACleanup", "WSASocket",
            "WSAConnect", "WSASend", "WSARecv",
            "WSAIoctl", "WSAEventSelect", "WSAWaitForMultipleEvents",
            "socket", "bind", "listen", "accept", "connect",
            "send", "recv", "sendto", "recvfrom",
            "setsockopt", "getsockopt", "ioctlsocket",
            "select", "shutdown", "closesocket",
            "htons", "htonl", "ntohs", "ntohl",
            # WinInet (HTTP/FTP high-level)
            "InternetOpen", "InternetOpenUrl",
            "InternetConnect", "InternetCloseHandle",
            "InternetReadFile", "InternetWriteFile",
            "InternetQueryOption", "InternetSetOption",
            "InternetGetConnectedState", "InternetCheckConnection",
            "HttpOpenRequest", "HttpSendRequest", "HttpSendRequestEx",
            "HttpQueryInfo", "HttpAddRequestHeaders",
            "FtpOpenFile", "FtpGetFile", "FtpPutFile",
            "FtpCommand", "FtpCreateDirectory",
            "URLDownloadToFile", "URLDownloadToCacheFile",
            "URLOpenBlockingStream",
            # WinHTTP (lower-level, proxy-aware)
            "WinHttpOpen", "WinHttpConnect",
            "WinHttpOpenRequest", "WinHttpSendRequest",
            "WinHttpReceiveResponse", "WinHttpReadData",
            "WinHttpWriteData", "WinHttpQueryHeaders",
            "WinHttpCloseHandle", "WinHttpSetOption",
            "WinHttpGetProxyForUrl", "WinHttpGetIEProxyConfigForCurrentUser",
            # DNS (tunnelling)
            "DnsQuery", "DnsQueryEx",
            "DnsExtractRecordsFromMessage",
            "DnsFree", "DnsRecordListFree",
            "GetAddrInfo", "GetAddrInfoEx",
            "GetHostByName", "GetHostByAddr",
            "inet_addr", "inet_ntoa", "inet_ntop", "inet_pton",
            # Named pipes (C2 over local channels)
            "CreateNamedPipe", "ConnectNamedPipe",
            "CallNamedPipe", "TransactNamedPipe",
            "WaitNamedPipe", "PeekNamedPipe",
            # Mailslot / net messaging
            "CreateMailslot", "GetMailslotInfo",
            # BITS (Living-off-the-land C2)
            "IBackgroundCopyManager", "IBackgroundCopyJob",
            # COM-based HTTP (XMLHTTP / ServerXMLHTTP)
            "XMLHTTP", "ServerXMLHTTP", "IXMLHTTPRequest",
            # Net APIs sometimes used for beaconing
            "NetRemoteComputerSupports",
            "GetHost", "WSAAsyncGetHostByName"
        )

        # TA0010 - Exfiltration
        # Writing/copying data out, compression, encoding before send
        "Exfiltration" = @(
            # File write / copy / move
            "WriteFile", "WriteFileEx",
            "NtWriteFile", "ZwWriteFile",
            "CopyFile", "CopyFileEx", "CopyFileA", "CopyFileW",
            "MoveFile", "MoveFileEx", "MoveFileWithProgress",
            "ReplaceFile",
            "fwrite", "fputs", "fputc", "fputws",
            # Compression / archiving
            "RtlCompressBuffer", "RtlDecompressBuffer",
            "RtlGetCompressionWorkSpaceSize",
            "ZipFile", "CabFile", "CreateCabinet",
            # Encoding (base64 / custom)
            "CryptBinaryToString", "CryptStringToBinary",
            "Base64Encode", "Base64Decode",
            "BinToStr", "StrToBin",
            # Staging / temp files
            "GetTempPath", "GetTempFileName",
            "CreateFile",               # writing to temp location
            # Cloud / web upload
            "HttpSendRequest", "WinHttpSendRequest",
            "FtpPutFile", "FtpCommand",
            "URLUploadToFile",
            # Clipboard exfil
            "SetClipboardData",
            # Delete after exfil (cleanup)
            "DeleteFile", "DeleteFileA", "DeleteFileW",
            "NtDeleteFile", "ZwDeleteFile",
            "SHFileOperation",          # SHFILEOPSTRUCT delete
            "SetEndOfFile",
            # Email exfil (MAPI)
            "MAPISendMail", "MAPISendDocuments",
            "MAPILogon", "MAPILogoff"
        )

        # TA0040 - Impact
        # Ransomware encryption, disk wipe, service/process termination, log clearing
        "Impact" = @(
            # File encryption / destruction
            "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptGenRandom",
            "BCryptEncrypt", "BCryptDecrypt", "BCryptGenRandom",
            "BCryptGenerateSymmetricKey",
            "DeleteFile", "NtDeleteFile",
            "SetEndOfFile", "SetFileInformationByHandle",
            "SetFilePointer",           # overwrite / truncate
            "DeviceIoControl",          # raw disk wipe
            # Process / service termination
            "TerminateProcess", "NtTerminateProcess", "ZwTerminateProcess",
            "TerminateThread", "NtTerminateThread",
            "ExitProcess", "ExitThread",
            "ControlService",           # SERVICE_STOP
            "KillTimer",
            # System shutdown / reboot
            "ExitWindowsEx", "InitiateSystemShutdown", "InitiateShutdown",
            "NtShutdownSystem", "ZwShutdownSystem",
            "SetSystemPowerState",
            # MBR / boot sector overwrite
            "NtDiskIoControl", "WriteFile",
            # Event log clearing
            "ClearEventLog", "OpenEventLog", "BackupEventLog",
            "EvtClearLog", "EvtQuery",
            # Shadow copy deletion
            "IVssBackupComponents", "IWbemServices",
            "WMIDeleteObject",
            # Inhibit system recovery
            "BcdOpenStore", "BcdDeleteObject",
            "SetComputerNameEx",
            # Resource exhaustion / fork bomb
            "CreateThread", "CreateProcess",
            "GlobalAlloc", "VirtualAlloc"
        )

        # --- Noise / low-signal (kept for completeness, visually deprioritised) ---

        # API-specific: standalone crypto primitives
        "Cryptography" = @(
            "CryptAcquireContext", "CryptReleaseContext",
            "CryptCreateHash", "CryptHashData", "CryptDestroyHash",
            "CryptGetHashParam", "CryptSetHashParam",
            "CryptGenKey", "CryptDestroyKey", "CryptImportKey", "CryptExportKey",
            "CryptEncrypt", "CryptDecrypt",
            "CryptSignHash", "CryptVerifySignature",
            "CryptSetKeyParam", "CryptGetKeyParam",
            "BCryptOpenAlgorithmProvider", "BCryptCloseAlgorithmProvider",
            "BCryptCreateHash", "BCryptFinishHash", "BCryptDestroyHash",
            "BCryptEncrypt", "BCryptDecrypt",
            "BCryptGenerateSymmetricKey", "BCryptDestroyKey",
            "BCryptGenRandom",
            "MD5", "SHA", "SHA1", "SHA256", "SHA512",
            "AES", "RC4", "DES", "3DES", "Blowfish",
            "Hash", "Bcrypt", "Scrypt",
            "RtlCompress", "RtlDecompress",
            "SystemFunction032", "SystemFunction033",
            "Encoding", "Base64"
        )

        # API-specific: string/memory (high noise, low standalone signal)
        "String & Memory" = @(
            "str", "wcs", "mem",
            "strlen", "wcslen", "strnlen",
            "strcpy", "wcscpy", "strncpy", "wcsncpy",
            "strcat", "wcscat", "strncat",
            "strcmp", "wcscmp", "strncmp", "wcsncmp",
            "strchr", "wcschr", "strrchr",
            "strstr", "wcsstr",
            "sprintf", "swprintf", "snprintf",
            "printf", "fprintf", "wprintf",
            "vsprintf", "vsnprintf",
            "itoa", "atoi", "atol", "atof",
            "strtol", "strtoul", "wcstol",
            "mbstowcs", "wcstombs",
            "MultiByteToWideChar", "WideCharToMultiByte",
            "CharToOem", "OemToChar",
            "alloc", "free", "malloc", "calloc", "realloc",
            "ZeroMemory", "FillMemory",
            "RtlMoveMemory", "RtlZeroMemory", "RtlFillMemory",
            "LocalAlloc", "LocalFree", "LocalReAlloc",
            "GlobalAlloc", "GlobalFree", "GlobalReAlloc",
            "HeapAlloc", "HeapFree", "HeapCreate", "HeapDestroy",
            "CoTaskMemAlloc", "CoTaskMemFree"
        )

        # Noise: compiler artefacts, framework indicators, ordinal imports
        "Import by Ordinal" = @("Ord(")
        "C++ & Frameworks"  = @("Qt", "mfc", "atl", "vba", "msvcr", "msvcp", "libstdc")
        "Internal & CRT"    = @("_", "__", "crt", "dll", "dllmain", "dllentry")
    }

    # --- 4. INIT STORAGE ---
    $AggregatedMetadata = @{}
    $Hierarchy          = @{}
    # Aggregate by composite key - avoids exploding one PSObject per observation
    $ApiEventsAgg       = @{}

    # --- 5. DATA PROCESSING FUNCTION ---
    function Invoke-TargetFolder {
        param (
            $TargetFolder,
            $CountryLabel,
            $GroupLabel,
            $IsAPT,
            $AggRef,
            $HierRef,
            $MetaRef,
            $MatrixRef,
            $MapRef,
            $RootRef
        )

        if (-not $HierRef.ContainsKey($CountryLabel)) {
            $HierRef[$CountryLabel] = [System.Collections.Generic.HashSet[string]]::new()
        }
        [void]$HierRef[$CountryLabel].Add($GroupLabel)

        $FoldersToScan = @(@{ Path = $TargetFolder; Label = "Direct" })

        if ($IsAPT -and $MapRef.ContainsKey($GroupLabel)) {
            $MalwareRoot = Join-Path $RootRef "Malware Families"
            foreach ($ToolName in $MapRef[$GroupLabel]) {
                $ToolPath = Join-Path $MalwareRoot $ToolName
                if (Test-Path $ToolPath) {
                    $FoldersToScan += @{ Path = $ToolPath; Label = "Tool: $ToolName" }
                }
            }
        }

        foreach ($Source in $FoldersToScan) {
            $Path        = $Source.Path
            $SourceLabel = $Source.Label

            $FolderContextDate = (Get-Item $Path).CreationTime.ToString("yyyy-MM-dd")
            $IntelFile = Get-ChildItem -Path $Path -Filter "*Master_Intel*.csv" | Select-Object -First 1
            if ($IntelFile) {
                try {
                    $csv     = Import-Csv $IntelFile.FullName
                    $dateCol = $csv[0].PSObject.Properties.Name | Where-Object { $_ -match "Date" } | Select-Object -First 1
                    if ($dateCol) {
                        $earliest = $csv | Where-Object { $_.$dateCol -as [DateTime] } | Sort-Object { [DateTime]$_.$dateCol } | Select-Object -First 1
                        if ($earliest) { $FolderContextDate = $earliest.$dateCol }
                    }
                } catch {}
            }

            $TargetFile    = Join-Path $Path "TargetedAPIDifferentialAnalysis.json"
            $FilesToProcess = @()
            if (Test-Path $TargetFile) { $FilesToProcess += (Get-Item $TargetFile) }
            else { $FilesToProcess += Get-ChildItem -Path $Path -Filter "*TargetedAPIDifferentialAnalysis.json" }

            foreach ($jFile in $FilesToProcess) {
                if ($jFile.Length -lt 5) { continue }
                try {
                    $content = Get-Content $jFile.FullName -Raw | ConvertFrom-Json
                    $items   = @($content)

                    if ($items.Count -gt 0) {
                        if ($SourceLabel -eq "Direct") {
                            Write-Host "    + Found $($items.Count) API calls (Direct)" -ForegroundColor Gray
                        } else {
                            Write-Host "    + Merged $($items.Count) API calls from $($SourceLabel)" -ForegroundColor DarkGray
                        }

                        foreach ($row in $items) {
                            $rawName = $row.Item_Name
                            if (-not $rawName) { continue }

                            $cleanName = if ($rawName -match '!(.*)') { $matches[1] } else { $rawName }

                            $thisRar = if ($null -ne $row.Baseline_Rarity_Score) { [double]$row.Baseline_Rarity_Score } else { 100 }

                            if (-not $MetaRef.ContainsKey($cleanName)) {
                                # Category: first-match-wins (stable ordering)
                                $foundCat = "Other"
                                :catLoop foreach ($cat in $MatrixRef.Keys) {
                                    foreach ($keyword in $MatrixRef[$cat]) {
                                        $safeKeyword = [Regex]::Escape($keyword)
                                        if ($cleanName -match "(?i)$safeKeyword") {
                                            $foundCat = $cat
                                            break catLoop
                                        }
                                    }
                                }
                                $MetaRef[$cleanName] = @{
                                    Cat = $foundCat
                                    Rar = $thisRar
                                }
                            } elseif ($thisRar -lt $MetaRef[$cleanName].Rar) {
                                # Rarity: lowest score wins  -  that APT had the most baseline coverage
                                $MetaRef[$cleanName].Rar = $thisRar
                            }

                            $count = if ($row.Malicious_Count) { [int]$row.Malicious_Count } else { 1 }
                            $aggKey = "$cleanName|$FolderContextDate|$CountryLabel|$GroupLabel|$SourceLabel"
                            if ($AggRef.ContainsKey($aggKey)) {
                                $AggRef[$aggKey].N += $count
                            } else {
                                $AggRef[$aggKey] = [PSCustomObject]@{
                                    Api = $cleanName
                                    Date = $FolderContextDate
                                    C    = $CountryLabel
                                    A    = $GroupLabel
                                    Src  = $SourceLabel
                                    Rar  = $MetaRef[$cleanName].Rar
                                    N    = $count
                                }
                            }
                        }
                    }
                } catch {
                    Write-Warning "    ! Error in $($jFile.Name): $($_.Exception.Message)"
                }
            }
        }
    }

    # --- 6. TRAVERSE STRUCTURE ---
    $AptRoot = Join-Path $AbsRoot "APTs"
    if (Test-Path $AptRoot) {
        Write-Host "  Processing APT Structure..." -ForegroundColor Gray
        foreach ($cntry in (Get-ChildItem -Path $AptRoot -Directory)) {
            foreach ($grp in (Get-ChildItem -Path $cntry.FullName -Directory)) {
                Invoke-TargetFolder `
                    -TargetFolder $grp.FullName -CountryLabel $cntry.Name -GroupLabel $grp.Name `
                    -IsAPT $true -AggRef $ApiEventsAgg -HierRef $Hierarchy `
                    -MetaRef $AggregatedMetadata -MatrixRef $ApiMatrix -MapRef $AptToolMap -RootRef $AbsRoot
            }
        }
    }

    $MalRoot = Join-Path $AbsRoot "Malware Families"
    if (Test-Path $MalRoot) {
        Write-Host "  Processing Malware Families..." -ForegroundColor Gray
        foreach ($fam in (Get-ChildItem -Path $MalRoot -Directory)) {
            Invoke-TargetFolder `
                -TargetFolder $fam.FullName -CountryLabel "Malware Family" -GroupLabel $fam.Name `
                -IsAPT $false -AggRef $ApiEventsAgg -HierRef $Hierarchy `
                -MetaRef $AggregatedMetadata -MatrixRef $ApiMatrix -MapRef $AptToolMap -RootRef $AbsRoot
        }
    }

    Write-Host "  Processed $($ApiEventsAgg.Count) unique event buckets." -ForegroundColor Green

    # --- 7. SERIALIZE DATA ---
    $OutputDir = Split-Path $OutputHtmlPath -Parent
    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

    # Build compact per-API summary objects - one entry per unique API name.
    # Each entry contains the total count and a small attribution list.
    # This is far smaller than emitting one object per (Api x Date x Group x Src) bucket.
    $ApiSummary = @{}
    foreach ($bucket in $ApiEventsAgg.Values) {
        $api = $bucket.Api
        if (-not $ApiSummary.ContainsKey($api)) {
            $meta = if ($AggregatedMetadata.ContainsKey($api)) { $AggregatedMetadata[$api] } else { @{Cat="Other";Rar=0} }
            $ApiSummary[$api] = [PSCustomObject]@{
                Api    = $api
                Cat    = $meta.Cat
                Rar    = $meta.Rar
                Total  = 0
                Groups = [System.Collections.Generic.List[PSObject]]::new()
            }
        }
        $ApiSummary[$api].Total += $bucket.N
        $ApiSummary[$api].Groups.Add([PSCustomObject]@{
            C    = $bucket.C
            A    = $bucket.A
            Src  = $bucket.Src
            Date = $bucket.Date
            N    = $bucket.N
        })
    }

    # Write data as a sidecar JSON file next to the HTML.
    # The HTML fetches it via XHR at load time - avoids embedding huge payloads.
    # Write as a .js file (window.__API_DATA = [...]) so it loads via <script>
    # tag without CORS issues when opened from a local file:// path.
    $JsDataPath   = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($OutputHtmlPath), ([System.IO.Path]::GetFileNameWithoutExtension($OutputHtmlPath) + ".data.js"))
    $DataFileName = [System.IO.Path]::GetFileName($JsDataPath)
    Write-Host "  Serialising $($ApiSummary.Count) unique APIs to $JsDataPath..." -NoNewline
    $JsonPayload  = $ApiSummary.Values | ConvertTo-Json -Depth 5 -Compress
    "window.__API_DATA = $JsonPayload;" | Set-Content -Path $JsDataPath -Encoding UTF8
    Write-Host " Done." -ForegroundColor Green

    $HierObj   = @{}; foreach ($k in $Hierarchy.Keys) { $HierObj[$k] = ($Hierarchy[$k] | Sort-Object) }
    $JsonHier  = $HierObj | ConvertTo-Json -Depth 10
    $CatListJS = ($ApiMatrix.Keys | ForEach-Object { "'$([Regex]::Escape($_))'" }) -join ","
    $CatListJS = $CatListJS + ",'Other'"

    # --- 8. BUILD HTML ---
    $HtmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>MITRE ATT\&CK Re-Envisioned as API Calls</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap" rel="stylesheet">
<style>
  /* ── Reset & Tokens ─────────────────────────────────────── */
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg:        #0a0c10;
    --surface:   #111520;
    --surface2:  #1a2035;
    --border:    #252d45;
    --accent:    #00d4ff;
    --accent2:   #ff4d6d;
    --accent3:   #39d353;
    --warn:      #f5c542;
    --text:      #c9d1e0;
    --text-dim:  #6b7a99;
    --text-head: #e8eaf6;
    --mono:      'IBM Plex Mono', monospace;
    --sans:      'IBM Plex Sans', sans-serif;
    --sidebar-w: 240px;
    --topbar-h:  56px;
  }

  body { background: var(--bg); color: var(--text); font-family: var(--sans); display: flex; min-height: 100vh; overflow-x: hidden; }

  /* ── Scrollbars ─────────────────────────────────────────── */
  ::-webkit-scrollbar { width: 5px; height: 5px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

  /* ── Sidebar ────────────────────────────────────────────── */
  .sidebar {
    width: var(--sidebar-w); height: 100vh; background: var(--surface);
    border-right: 1px solid var(--border); position: fixed; top: 0; left: 0;
    overflow-y: auto; z-index: 1000; display: flex; flex-direction: column;
  }
  .sidebar-brand {
    padding: 18px 20px; font-family: var(--mono); font-size: .85rem;
    font-weight: 600; color: var(--accent); border-bottom: 1px solid var(--border);
    cursor: pointer; letter-spacing: .05em; line-height: 1.4;
  }
  .sidebar-brand span { display: block; font-size: .65rem; color: var(--text-dim); font-weight: 400; margin-top: 2px; }

  .sidebar-section-label {
    padding: 16px 20px 6px; font-size: .6rem; font-family: var(--mono);
    letter-spacing: .12em; color: var(--text-dim); text-transform: uppercase;
  }

  .nav-link {
    display: flex; align-items: center; gap: 10px; padding: 9px 20px;
    color: var(--text-dim); font-size: .78rem; cursor: pointer;
    border-left: 2px solid transparent; transition: all .15s; text-decoration: none;
    font-family: var(--sans);
  }
  .nav-link:hover  { background: var(--surface2); color: var(--text-head); }
  .nav-link.active { background: var(--surface2); color: var(--accent); border-left-color: var(--accent); }
  .nav-link-noise { opacity: .5; font-style: italic; }
  .nav-link-noise:hover { opacity: .8; }
  .nav-link .dot   { width: 6px; height: 6px; border-radius: 50%; background: var(--border); flex-shrink: 0; }
  .nav-link.active .dot { background: var(--accent); }

  /* Top-level nav items (Matrix, Timeline) */
  .nav-top {
    display: flex; align-items: center; gap: 10px; padding: 10px 20px;
    color: var(--text); font-size: .82rem; font-weight: 600; cursor: pointer;
    border-left: 2px solid transparent; transition: all .15s;
  }
  .nav-top:hover  { background: var(--surface2); color: var(--text-head); }
  .nav-top.active { color: var(--accent); border-left-color: var(--accent); background: var(--surface2); }

  /* ── Main ───────────────────────────────────────────────── */
  .main-content { margin-left: var(--sidebar-w); width: calc(100% - var(--sidebar-w)); display: flex; flex-direction: column; min-height: 100vh; }

  /* ── Topbar ─────────────────────────────────────────────── */
  .topbar {
    height: var(--topbar-h); background: var(--surface); border-bottom: 1px solid var(--border);
    padding: 0 24px; display: flex; align-items: center; gap: 12px;
    position: sticky; top: 0; z-index: 900;
  }
  .topbar-title { font-family: var(--mono); font-size: .82rem; color: var(--text-head); margin-right: auto; font-weight: 600; }
  .topbar-title span { color: var(--text-dim); font-weight: 400; margin-left: 6px; font-size: .75rem; }

  /* Search */
  .search-wrap { position: relative; }
  .search-wrap input {
    background: var(--surface2); border: 1px solid var(--border); color: var(--text);
    font-family: var(--mono); font-size: .75rem; padding: 6px 10px 6px 30px;
    border-radius: 4px; width: 200px; outline: none; transition: border .2s;
  }
  .search-wrap input:focus { border-color: var(--accent); }
  .search-wrap input::placeholder { color: var(--text-dim); }
  .search-icon { position: absolute; left: 9px; top: 50%; transform: translateY(-50%); color: var(--text-dim); font-size: .8rem; pointer-events: none; }

  /* Filters */
  select.f-sel {
    background: var(--surface2); border: 1px solid var(--border); color: var(--text);
    font-family: var(--mono); font-size: .72rem; padding: 5px 8px; border-radius: 4px;
    outline: none; cursor: pointer; transition: border .2s;
  }
  select.f-sel:focus { border-color: var(--accent); }
  select.f-sel option { background: var(--surface2); }

  /* ── View Panes ─────────────────────────────────────────── */
  .view-pane { padding: 24px; display: none; }
  .view-pane.active { display: block; }

  /* ── Matrix ─────────────────────────────────────────────── */
  .matrix-grid { display: flex; gap: 12px; overflow-x: auto; padding-bottom: 12px; }
  .tactic-col-noise { opacity: .45; filter: saturate(.4); }
  .tactic-col-noise:hover { opacity: .8; filter: saturate(.7); transition: opacity .2s, filter .2s; }
  .tactic-col  {
    min-width: 230px; max-width: 230px; background: var(--surface);
    border: 1px solid var(--border); border-radius: 6px; display: flex;
    flex-direction: column; max-height: calc(100vh - var(--topbar-h) - 80px);
  }
  .tactic-header {
    background: var(--surface2); padding: 10px 12px; font-family: var(--mono);
    font-size: .7rem; font-weight: 600; color: var(--text-head); border-radius: 6px 6px 0 0;
    border-bottom: 1px solid var(--border); letter-spacing: .04em;
    display: flex; justify-content: space-between; align-items: center;
  }
  .tactic-header .col-count { color: var(--text-dim); font-weight: 400; }
  .ta-id { font-size: .6rem; color: var(--accent); opacity: .7; font-weight: 400; margin-right: auto; margin-left: 6px; }
  .tactic-body { overflow-y: auto; flex: 1; }
  .matrix-cell {
    padding: 5px 10px; border-bottom: 1px solid rgba(37,45,69,.5);
    font-size: .73rem; font-family: var(--mono); cursor: pointer;
    display: flex; justify-content: space-between; align-items: center;
    transition: background .1s;
  }
  .matrix-cell:hover { background: var(--surface2); }
  .matrix-cell:last-child { border-bottom: none; }
  .cell-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 165px; }
  .cell-count { font-size: .65rem; padding: 1px 5px; border-radius: 3px; flex-shrink: 0; }

  /* Rarity bands */
  .band-unique .cell-name { color: var(--accent2); }
  .band-unique .cell-count { background: rgba(255,77,109,.15); color: var(--accent2); }
  .band-rare .cell-name   { color: var(--warn); }
  .band-rare .cell-count  { background: rgba(245,197,66,.12); color: var(--warn); }
  .band-common .cell-name { color: var(--text-dim); }
  .band-common .cell-count{ background: var(--surface2); color: var(--text-dim); }

  /* Band separator labels inside tactic columns */
  .band-divider {
    font-size: .58rem; font-family: var(--mono); letter-spacing: .08em;
    text-transform: uppercase; padding: 4px 8px 3px;
    border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 6px;
    user-select: none; pointer-events: none;
  }
  .band-divider::before { content: ''; flex: 1; height: 1px; background: var(--border); }
  .band-divider-unique { color: var(--accent2); border-top: 1px solid rgba(255,77,109,.25); background: rgba(255,77,109,.04); }
  .band-divider-rare   { color: var(--warn);    border-top: 1px solid rgba(245,197,66,.2);  background: rgba(245,197,66,.03); }
  .band-divider-common { color: var(--text-dim); border-top: 1px solid var(--border); }

  /* ── Category filter pills ──────────────────────────────── */
  .cat-pills { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 16px; }
  .cat-pill {
    padding: 4px 10px; border-radius: 20px; font-size: .7rem; font-family: var(--mono);
    border: 1px solid var(--border); color: var(--text-dim); cursor: pointer;
    transition: all .15s; background: transparent;
  }
  .cat-pill:hover  { border-color: var(--accent); color: var(--accent); }
  .cat-pill.active { background: var(--accent); border-color: var(--accent); color: #000; font-weight: 600; }

  /* ── List view ──────────────────────────────────────────── */
  .list-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
  .list-card  { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; overflow: hidden; display: flex; flex-direction: column; max-height: 70vh; }
  .list-card-header { padding: 10px 14px; font-family: var(--mono); font-size: .72rem; font-weight: 600; display: flex; align-items: center; gap: 8px; border-bottom: 1px solid var(--border); }
  .list-card-header.red    { color: var(--accent2); border-bottom-color: var(--accent2); }
  .list-card-header.yellow { color: var(--warn); border-bottom-color: var(--warn); }
  .list-card-header.green  { color: var(--accent3); border-bottom-color: var(--accent3); }
  .list-card-body { overflow-y: auto; flex: 1; }
  .list-row {
    display: flex; justify-content: space-between; align-items: center;
    padding: 5px 14px; border-bottom: 1px solid rgba(37,45,69,.5);
    cursor: pointer; font-size: .73rem; font-family: var(--mono);
    transition: background .1s;
  }
  .list-row:hover { background: var(--surface2); }
  .list-row:last-child { border-bottom: none; }
  .list-row-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 75%; }
  .badge-count { font-size: .62rem; padding: 1px 6px; border-radius: 3px; background: var(--surface2); color: var(--text-dim); }

  /* ── Timeline view ──────────────────────────────────────── */
  .timeline-wrap { display: flex; flex-direction: column; gap: 8px; }
  .tl-row {
    display: grid; grid-template-columns: 200px 1fr 60px; align-items: center; gap: 14px;
    padding: 8px 12px; background: var(--surface); border: 1px solid var(--border);
    border-radius: 5px; cursor: pointer; transition: border-color .15s;
  }
  .tl-row:hover { border-color: var(--accent); }
  .tl-name { font-family: var(--mono); font-size: .75rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .tl-bar-wrap { position: relative; height: 24px; }
  .tl-canvas { width: 100%; height: 100%; }
  .tl-total { font-family: var(--mono); font-size: .72rem; color: var(--text-dim); text-align: right; }

  /* ── Stat bar ───────────────────────────────────────────── */
  .stat-bar { display: flex; gap: 20px; margin-bottom: 18px; flex-wrap: wrap; }
  .stat-chip {
    background: var(--surface); border: 1px solid var(--border); border-radius: 5px;
    padding: 8px 16px; font-family: var(--mono); font-size: .72rem;
  }
  .stat-chip .sc-val  { font-size: 1.3rem; font-weight: 600; color: var(--text-head); display: block; }
  .stat-chip .sc-lbl  { color: var(--text-dim); font-size: .65rem; margin-top: 2px; }

  /* ── Modal ──────────────────────────────────────────────── */
  .modal-overlay {
    display: none; position: fixed; inset: 0; background: rgba(0,0,0,.7);
    z-index: 9000; align-items: center; justify-content: center;
  }
  .modal-overlay.open { display: flex; }
  .modal-box {
    background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
    width: 760px; max-width: 95vw; max-height: 88vh; display: flex; flex-direction: column;
    box-shadow: 0 24px 64px rgba(0,0,0,.6);
  }
  .modal-head {
    padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex;
    justify-content: space-between; align-items: flex-start; gap: 16px;
  }
  .modal-api-name { font-family: var(--mono); font-size: 1rem; color: var(--accent); font-weight: 600; }
  .modal-meta { display: flex; gap: 10px; margin-top: 6px; flex-wrap: wrap; }
  .m-badge { padding: 2px 8px; border-radius: 3px; font-family: var(--mono); font-size: .65rem; }
  .m-badge.cat  { background: rgba(0,212,255,.1); color: var(--accent); border: 1px solid rgba(0,212,255,.25); }
  .m-badge.rar  { background: rgba(255,77,109,.1); color: var(--accent2); border: 1px solid rgba(255,77,109,.25); }
  .m-badge.cnt  { background: rgba(57,211,83,.1);  color: var(--accent3); border: 1px solid rgba(57,211,83,.25); }
  .modal-close { background: none; border: none; color: var(--text-dim); font-size: 1.2rem; cursor: pointer; padding: 0 4px; line-height: 1; }
  .modal-close:hover { color: var(--text-head); }

  .modal-body { overflow-y: auto; padding: 20px; flex: 1; display: flex; flex-direction: column; gap: 20px; }

  /* Mini chart in modal */
  .modal-chart-wrap { height: 90px; position: relative; }
  #modalChart { width: 100%; height: 100%; }

  /* Attribution table */
  .attr-table { width: 100%; border-collapse: collapse; font-size: .75rem; font-family: var(--mono); }
  .attr-table th { padding: 6px 10px; text-align: left; color: var(--text-dim); border-bottom: 1px solid var(--border); font-weight: 400; font-size: .65rem; letter-spacing: .08em; text-transform: uppercase; }
  .attr-table td { padding: 6px 10px; border-bottom: 1px solid rgba(37,45,69,.4); }
  .attr-table tr:last-child td { border-bottom: none; }
  .attr-table tr:hover td { background: var(--surface2); }

  .src-badge { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: .62rem; }
  .src-direct { background: rgba(0,212,255,.12); color: var(--accent); }
  .src-tool   { background: rgba(245,197,66,.12); color: var(--warn); }

  /* Empty state */
  .empty { padding: 48px; text-align: center; color: var(--text-dim); font-family: var(--mono); font-size: .8rem; }

  /* No-results overlay */
  .no-results { color: var(--text-dim); font-family: var(--mono); font-size: .78rem; padding: 32px; text-align: center; }
</style>
</head>
<body>

<!-- ═══════════════════════════════════════════════════════════
     SIDEBAR
════════════════════════════════════════════════════════════ -->
<nav class="sidebar">
  <div class="sidebar-brand" onclick="switchView('MATRIX')">
    API Capability Matrix
    <span>$ReportTitle</span>
  </div>

  <div class="nav-top active" id="nav-top-MATRIX" onclick="switchView('MATRIX')">
    <svg width="13" height="13" viewBox="0 0 14 14" fill="none"><rect x="1" y="1" width="5" height="5" rx="1" fill="currentColor" opacity=".7"/><rect x="8" y="1" width="5" height="5" rx="1" fill="currentColor" opacity=".7"/><rect x="1" y="8" width="5" height="5" rx="1" fill="currentColor" opacity=".7"/><rect x="8" y="8" width="5" height="5" rx="1" fill="currentColor" opacity=".7"/></svg>
    Overview Matrix
  </div>
  <div class="nav-top" id="nav-top-TIMELINE" onclick="switchView('TIMELINE')">
    <svg width="13" height="13" viewBox="0 0 14 14" fill="none"><polyline points="1,11 4,6 7,8 10,3 13,5" stroke="currentColor" stroke-width="1.5" fill="none" stroke-linejoin="round"/></svg>
    Timeline Trends
  </div>

  <div class="sidebar-section-label">Categories</div>
  <div id="nav-cat-container"></div>
</nav>

<!-- ═══════════════════════════════════════════════════════════
     MAIN
════════════════════════════════════════════════════════════ -->
<div class="main-content">

  <!-- Topbar -->
  <div class="topbar">
    <div class="topbar-title" id="page-title">Overview Matrix <span id="result-count"></span></div>

    <div class="search-wrap">
      <span class="search-icon">⌕</span>
      <input type="text" id="api-search" placeholder="Search API…" oninput="renderCurrentView()">
    </div>

    <select id="filter-time" class="f-sel" onchange="renderCurrentView()">
      <option value="ALL" selected>All Time</option>
      <option value="7">Past 7 Days</option>
      <option value="30">Past 30 Days</option>
      <option value="90">Past 90 Days</option>
      <option value="365">Past Year</option>
    </select>

    <select id="filter-country" class="f-sel" onchange="countryChanged()">
      <option value="ALL">All Countries</option>
    </select>

    <select id="filter-apt" class="f-sel" onchange="renderCurrentView()">
      <option value="ALL">All Groups</option>
    </select>

    <select id="filter-rarity" class="f-sel" onchange="renderCurrentView()">
      <option value="ALL">All Rarity</option>
      <option value="100">Unique to Malware (≥100)</option>
      <option value="95">Rare (≥95)</option>
      <option value="0">Common</option>
    </select>
    <select id="filter-cap" class="f-sel" onchange="renderCurrentView()" title="Max APIs per column">
      <option value="25">Top 25</option>
      <option value="50" selected>Top 50</option>
      <option value="100">Top 100</option>
      <option value="250">Top 250</option>
      <option value="9999">All</option>
    </select>
  </div>

  <!-- ── MATRIX PANE ── -->
  <div id="view-MATRIX" class="view-pane active">
    <div class="stat-bar" id="stat-bar"></div>
    <div class="matrix-grid" id="matrix-container"></div>
  </div>

  <!-- ── LIST PANE ── -->
  <div id="view-LIST" class="view-pane">
    <div class="cat-pills" id="cat-pills"></div>
    <div class="stat-bar" id="list-stat-bar"></div>
    <div class="list-grid">
      <div class="list-card">
        <div class="list-card-header red">
          <span>⬤</span> Unique to Malware
          <span id="count-red" style="margin-left:auto; color:var(--text-dim); font-weight:400"></span>
        </div>
        <div class="list-card-body" id="list-red"></div>
      </div>
      <div class="list-card">
        <div class="list-card-header yellow">
          <span>⬤</span> Rare (&gt;95th pct)
          <span id="count-yellow" style="margin-left:auto; color:var(--text-dim); font-weight:400"></span>
        </div>
        <div class="list-card-body" id="list-yellow"></div>
      </div>
      <div class="list-card">
        <div class="list-card-header green">
          <span>⬤</span> Common
          <span id="count-green" style="margin-left:auto; color:var(--text-dim); font-weight:400"></span>
        </div>
        <div class="list-card-body" id="list-green"></div>
      </div>
    </div>
  </div>

  <!-- ── TIMELINE PANE ── -->
  <div id="view-TIMELINE" class="view-pane">
    <div class="stat-bar" id="tl-stat-bar"></div>
    <div class="cat-pills" id="tl-cat-pills"></div>
    <div class="timeline-wrap" id="timeline-container"></div>
  </div>

</div><!-- /main-content -->

<!-- ═══════════════════════════════════════════════════════════
     MODAL
════════════════════════════════════════════════════════════ -->
<div class="modal-overlay" id="drillModal" onclick="closeModal(event)">
  <div class="modal-box" onclick="event.stopPropagation()">
    <div class="modal-head">
      <div>
        <div class="modal-api-name" id="modal-api-name"></div>
        <div class="modal-meta" id="modal-meta"></div>
      </div>
      <button class="modal-close" onclick="closeModal()">✕</button>
    </div>
    <div class="modal-body">
      <div class="modal-chart-wrap">
        <canvas id="modalChart"></canvas>
      </div>
      <table class="attr-table">
        <thead><tr>
          <th>Date</th><th>Country</th><th>Group / APT</th><th>Source</th><th style="text-align:right">Obs.</th>
        </tr></thead>
        <tbody id="modal-table-body"></tbody>
      </table>
    </div>
  </div>
</div>

<script src="$DataFileName"></script>

<script>
// ═════════════════════════════════════════════════════════════
// BOOTSTRAP DATA
// ═════════════════════════════════════════════════════════════
const hierarchy  = $JsonHier;
const categories = [$CatListJS];
const TA_IDS = {
    'Discovery':            'TA0007',
    'Credential Access':    'TA0006',
    'Execution':            'TA0002',
    'Persistence':          'TA0003',
    'Defense Evasion':      'TA0005',
    'Privilege Escalation': 'TA0004',
    'Lateral Movement':     'TA0008',
    'Collection':           'TA0009',
    'Command and Control':  'TA0011',
    'Exfiltration':         'TA0010',
    'Impact':               'TA0040',
    'Other':                ''
};
// Categories rendered dimmed - noise / low-signal
const NOISE_CATS = new Set(['Cryptography','String & Memory','Import by Ordinal','C++ & Frameworks','Internal & CRT']);

let apiEvents = [];
let apiMeta   = {};   // key → {Cat, Rar}
let currentView     = 'MATRIX';
let currentCategory = categories[0] || '';
let tlCategory      = categories[0] || '';
let modalChartCtx   = null;

// ─── Bootstrap: read from window.__API_DATA (loaded via <script> tag) ──────
window.onload = function() {
  if (!window.__API_DATA) {
    showError('Data file ($DataFileName) not found or failed to load. '
            + 'Make sure it is in the same folder as this HTML file.');
    return;
  }
  apiEvents = Array.isArray(window.__API_DATA) ? window.__API_DATA : [];
  buildSidebar();
  buildCountryFilter();
  buildCatPills();
  renderCurrentView();
};

function showLoading(on) {
  let el = document.getElementById('loading-overlay');
  if (!el) {
    el = document.createElement('div');
    el.id = 'loading-overlay';
    el.style.cssText = 'position:fixed;inset:0;background:rgba(10,12,16,.92);display:flex;'
      + 'flex-direction:column;align-items:center;justify-content:center;z-index:9999;'
      + 'font-family:IBM Plex Mono,monospace;color:#00d4ff;font-size:.9rem;gap:16px;';
    el.innerHTML = '<div id="loading-spinner" style="width:36px;height:36px;border:3px solid #252d45;'
      + 'border-top-color:#00d4ff;border-radius:50%;animation:spin .7s linear infinite"></div>'
      + '<div>Loading API data...</div>'
      + '<style>@keyframes spin{to{transform:rotate(360deg)}}</style>';
    document.body.appendChild(el);
  }
  el.style.display = on ? 'flex' : 'none';
}

function showError(msg) {
  let el = document.getElementById('loading-overlay');
  if (!el) { showLoading(true); el = document.getElementById('loading-overlay'); }
  el.style.display = 'flex';
  el.innerHTML = '<div style="color:#ff4d6d;font-size:1.1rem">&#9888; Load Error</div>'
               + '<div style="max-width:420px;text-align:center;color:#c9d1e0;font-size:.78rem;line-height:1.6">' + msg + '</div>';
}

// ═════════════════════════════════════════════════════════════
// UI BUILDERS
// ═════════════════════════════════════════════════════════════
function buildSidebar() {
  const nav = document.getElementById('nav-cat-container');
  categories.forEach(cat => {
    const el = document.createElement('div');
    el.className = 'nav-link' + (NOISE_CATS.has(cat) ? ' nav-link-noise' : '');
    el.dataset.cat = cat;
    el.innerHTML = '<span class="dot"></span>' + cat
                 + (NOISE_CATS.has(cat) ? ' <span style="font-size:.6rem;opacity:.5">[noise]</span>' : '');
    el.onclick = () => switchView('LIST', cat);
    nav.appendChild(el);
  });
}

function buildCountryFilter() {
  const sel = document.getElementById('filter-country');
  if (hierarchy && Object.keys(hierarchy).length) {
    Object.keys(hierarchy).sort().forEach(c => sel.add(new Option(c, c)));
  }
}

// FIX: pills use data-cat attribute, not innerText matching
function buildCatPills() {
  ['cat-pills','tl-cat-pills'].forEach(id => {
    const wrap = document.getElementById(id);
    wrap.innerHTML = '';
    categories.forEach((cat, i) => {
      const btn = document.createElement('button');
      btn.className = 'cat-pill' + (i === 0 ? ' active' : '');
      btn.dataset.cat = cat;
      btn.textContent = cat;
      btn.onclick = () => {
        wrap.querySelectorAll('.cat-pill').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        if (id === 'cat-pills')    { currentCategory = cat; renderList(); }
        else                        { tlCategory = cat; renderTimeline(); }
      };
      wrap.appendChild(btn);
    });
  });
}

// ═════════════════════════════════════════════════════════════
// FILTER ENGINE
// ═════════════════════════════════════════════════════════════
function countryChanged() {
  const selC = document.getElementById('filter-country').value;
  const selA = document.getElementById('filter-apt');
  selA.innerHTML = '<option value="ALL">All Groups</option>';

  const groups = new Set();
  if (selC !== 'ALL' && hierarchy[selC]) {
    hierarchy[selC].forEach(g => groups.add(g));
  } else {
    Object.values(hierarchy || {}).forEach(arr => arr.forEach(g => groups.add(g)));
  }
  [...groups].sort().forEach(g => selA.add(new Option(g, g)));
  renderCurrentView();
}

function checkDate(dateStr, days) {
  if (!dateStr || dateStr === '1970-01-01') return days === 'ALL';
  if (days === 'ALL') return true;
  const cutoff  = new Date(); cutoff.setDate(cutoff.getDate() - parseInt(days));
  return new Date(dateStr) >= cutoff;
}

function getFilteredData() {
  const selC   = document.getElementById('filter-country').value;
  const selA   = document.getElementById('filter-apt').value;
  const selT   = document.getElementById('filter-time').value;
  const selR   = document.getElementById('filter-rarity').value;
  const search = document.getElementById('api-search').value.trim().toLowerCase();

  const result = [];

  for (const entry of apiEvents) {
    // API-level filters
    if (search && !entry.Api.toLowerCase().includes(search)) continue;
    const rar = +entry.Rar;
    if (selR !== 'ALL') {
      const t = +selR;
      if (t === 0   && rar >= 95)  continue;
      if (t === 95  && rar < 95)   continue;
      if (t === 100 && rar < 100)  continue;
    }

    // Filter the Groups sub-array
    const groups = (entry.Groups || []).filter(g => {
      if (selC !== 'ALL' && g.C !== selC)       return false;
      if (selA !== 'ALL' && g.A !== selA)       return false;
      if (!checkDate(g.Date, selT))             return false;
      return true;
    });

    if (groups.length === 0) continue;

    const count = groups.reduce((s, g) => s + (g.N || 1), 0);
    result.push({ Api: entry.Api, Cat: entry.Cat, Rar: rar, Count: count, Hits: groups });
  }

  return result;
}

// ═════════════════════════════════════════════════════════════
// VIEW ROUTER
// ═════════════════════════════════════════════════════════════
function switchView(mode, category) {
  currentView = mode;

  // Panes
  document.querySelectorAll('.view-pane').forEach(el => el.classList.remove('active'));
  document.getElementById('view-' + mode).classList.add('active');

  // Top nav highlight
  document.querySelectorAll('.nav-top').forEach(el => el.classList.remove('active'));
  const topEl = document.getElementById('nav-top-' + mode);
  if (topEl) topEl.classList.add('active');

  // Sidebar category highlight
  document.querySelectorAll('#nav-cat-container .nav-link').forEach(el => el.classList.remove('active'));

  if (mode === 'LIST') {
    if (category) currentCategory = category;
    // FIX: match by data-cat, not innerText
    const catEl = document.querySelector('#nav-cat-container .nav-link[data-cat="' + CSS.escape(currentCategory) + '"]');
    if (catEl) catEl.classList.add('active');
    // Sync pill
    syncPill('cat-pills', currentCategory);
  }
  if (mode === 'TIMELINE') {
    syncPill('tl-cat-pills', tlCategory);
  }

  renderCurrentView();
}

function syncPill(pillsId, cat) {
  const wrap = document.getElementById(pillsId);
  if (!wrap) return;
  wrap.querySelectorAll('.cat-pill').forEach(b => {
    b.classList.toggle('active', b.dataset.cat === cat);
  });
}

function renderCurrentView() {
  const titles = { MATRIX: 'MITRE ATT&CK Re-Envisioned as API Calls', LIST: currentCategory, TIMELINE: 'Timeline Trends' };
  document.getElementById('page-title').innerHTML =
    titles[currentView] + ' <span id="result-count"></span>';

  if (currentView === 'MATRIX')   renderMatrix();
  if (currentView === 'LIST')     renderList();
  if (currentView === 'TIMELINE') renderTimeline();
}

// ═════════════════════════════════════════════════════════════
// MATRIX VIEW
// ═════════════════════════════════════════════════════════════
function renderMatrix() {
  const data = getFilteredData();
  const container = document.getElementById('matrix-container');
  container.innerHTML = '';

  let totalShown = 0;
  categories.forEach(cat => {
    const displayCap = parseInt(document.getElementById('filter-cap').value) || 50;
    const all = data.filter(d => d.Cat === cat);

    // Partition by fidelity band  -  unique and rare always shown in full;
    // only the common tier is capped to keep high-fidelity items visible.
    const unique = all.filter(d => d.Rar >= 100).sort((a,b) => b.Count - a.Count);
    const rare   = all.filter(d => d.Rar >= 95 && d.Rar < 100).sort((a,b) => b.Count - a.Count);
    const common = all.filter(d => d.Rar < 95).sort((a,b) => b.Count - a.Count)
                      .slice(0, Math.max(0, displayCap - unique.length - rare.length));

    const items = [...unique, ...rare, ...common];
    totalShown += items.length;

    const col = document.createElement('div');
    col.className = 'tactic-col' + (NOISE_CATS.has(cat) ? ' tactic-col-noise' : '');

    const taId = TA_IDS[cat] || '';
    col.innerHTML = '<div class="tactic-header">'
                  + '<span>' + cat + '</span>'
                  + (taId ? '<span class="ta-id">' + taId + '</span>' : '')
                  + '<span class="col-count">' + items.length + '</span>'
                  + '</div>'
                  + '<div class="tactic-body" id="mc-' + cat.replace(/\W/g,'_') + '"></div>';
    container.appendChild(col);

    const body = col.querySelector('.tactic-body');
    if (items.length === 0) {
      body.innerHTML = '<div class="empty"> - </div>';
      return;
    }

    // Render each band with a divider label so fidelity is immediately visible
    function addBand(bandItems, divClass, divLabel) {
      if (bandItems.length === 0) return;
      const div = document.createElement('div');
      div.className = 'band-divider ' + divClass;
      div.textContent = divLabel;
      body.appendChild(div);
      bandItems.forEach(api => body.appendChild(makeMatrixCell(api)));
    }

    addBand(unique, 'band-divider-unique', 'not in baseline');
    addBand(rare,   'band-divider-rare',   'rare in baseline');
    addBand(common, 'band-divider-common', 'common');
  });

  renderStatBar('stat-bar', data, totalShown);
  document.getElementById('result-count').textContent = '(' + data.length + ' APIs)';
}

function makeMatrixCell(api) {
  const band = api.Rar >= 100 ? 'band-unique' : api.Rar >= 95 ? 'band-rare' : 'band-common';
  const el   = document.createElement('div');
  el.className = 'matrix-cell ' + band;
  el.innerHTML = '<span class="cell-name" title="' + api.Api + '">' + api.Api + '</span>'
               + '<span class="cell-count">' + api.Count + '</span>';
  el.onclick = () => showDrill(api);
  return el;
}

// ═════════════════════════════════════════════════════════════
// LIST VIEW
// ═════════════════════════════════════════════════════════════
function renderList() {
  const data     = getFilteredData();
  const catItems = data.filter(d => d.Cat === currentCategory).sort((a,b) => b.Count - a.Count);

  const redItems = catItems.filter(d => d.Rar >= 100);
  const yelItems = catItems.filter(d => d.Rar >= 95 && d.Rar < 100);
  const grnItems = catItems.filter(d => d.Rar < 95);

  fillListCard('list-red',    redItems);
  fillListCard('list-yellow', yelItems);
  fillListCard('list-green',  grnItems);

  document.getElementById('count-red').textContent    = redItems.length;
  document.getElementById('count-yellow').textContent = yelItems.length;
  document.getElementById('count-green').textContent  = grnItems.length;

  renderStatBar('list-stat-bar', catItems, catItems.length);
  document.getElementById('result-count').textContent = '(' + catItems.length + ' APIs)';
}

function fillListCard(id, items) {
  const el = document.getElementById(id);
  el.innerHTML = '';
  if (items.length === 0) { el.innerHTML = '<div class="no-results">No matching APIs</div>'; return; }
  items.forEach(api => {
    const row = document.createElement('div');
    row.className = 'list-row';
    row.innerHTML = '<span class="list-row-name" title="' + api.Api + '">' + api.Api + '</span>'
                  + '<span class="badge-count">' + api.Count + '</span>';
    row.onclick = () => showDrill(api);
    el.appendChild(row);
  });
}

// ═════════════════════════════════════════════════════════════
// TIMELINE VIEW
// ═════════════════════════════════════════════════════════════
function renderTimeline() {
  const data     = getFilteredData();
  const displayCap = parseInt(document.getElementById('filter-cap').value) || 50;
  const catItems = data.filter(d => d.Cat === tlCategory).sort((a,b) => b.Count - a.Count).slice(0, displayCap);
  const container = document.getElementById('timeline-container');
  container.innerHTML = '';

  if (catItems.length === 0) {
    container.innerHTML = '<div class="no-results">No data for this category with current filters.</div>';
    return;
  }

  // Determine global date range
  const allDates = apiEvents.map(e => e.Date).filter(d => d && d !== '1970-01-01').map(d => new Date(d));
  const minDate  = allDates.length ? new Date(Math.min(...allDates)) : new Date();
  const maxDate  = allDates.length ? new Date(Math.max(...allDates)) : new Date();
  const totalMs  = Math.max(maxDate - minDate, 1);

  catItems.forEach(api => {
    const row  = document.createElement('div');
    row.className = 'tl-row';

    const band  = api.Rar >= 100 ? 'var(--accent2)' : api.Rar >= 95 ? 'var(--warn)' : 'var(--text-dim)';
    const nameEl = '<div class="tl-name" style="color:' + band + '" title="' + api.Api + '">' + api.Api + '</div>';

    // Build mini sparkline
    const canvasId = 'spark_' + api.Api.replace(/\W/g,'_');
    row.innerHTML = nameEl
      + '<div class="tl-bar-wrap"><canvas id="' + canvasId + '" class="tl-canvas"></canvas></div>'
      + '<div class="tl-total">' + api.Count + '</div>';
    row.onclick = () => showDrill(api);
    container.appendChild(row);

    // Draw sparkline after insert
    requestAnimationFrame(() => {
      const canvas = document.getElementById(canvasId);
      if (!canvas) return;
      drawSparkline(canvas, api.Hits, minDate, totalMs, band);
    });
  });

  document.getElementById('result-count').textContent = '(' + catItems.length + ' APIs shown)';
  renderStatBar('tl-stat-bar', catItems, catItems.length);
}

function drawSparkline(canvas, hits, minDate, totalMs, color) {
  const W = canvas.offsetWidth || canvas.parentElement.clientWidth || 400;
  const H = canvas.offsetHeight || 24;
  canvas.width  = W;
  canvas.height = H;
  const ctx = canvas.getContext('2d');

  // Group by month buckets (12 buckets)
  const BUCKETS = 24;
  const counts  = new Array(BUCKETS).fill(0);
  hits.forEach(h => {
    if (!h.Date || h.Date === '1970-01-01') return;
    const ratio  = (new Date(h.Date) - minDate) / totalMs;
    const bucket = Math.min(Math.floor(ratio * BUCKETS), BUCKETS - 1);
    counts[bucket] += (h.N || 1);
  });
  const maxCount = Math.max(...counts, 1);

  // Draw bars
  const barW = W / BUCKETS;
  counts.forEach((c, i) => {
    if (c === 0) return;
    const bh = Math.max((c / maxCount) * (H - 2), 2);
    ctx.fillStyle = color;
    ctx.globalAlpha = 0.75;
    ctx.fillRect(i * barW + 1, H - bh, barW - 2, bh);
  });
  ctx.globalAlpha = 1;
}

// ═════════════════════════════════════════════════════════════
// STAT BAR
// ═════════════════════════════════════════════════════════════
function renderStatBar(id, data, shown) {
  const el    = document.getElementById(id);
  if (!el) return;
  const total = data.reduce((s,d) => s + d.Count, 0);
  const apts  = new Set(data.flatMap(d => (d.Hits||[]).map(h => h.A))).size;
  const uniq  = data.filter(d => d.Rar >= 100).length;

  el.innerHTML = chip(shown,  'APIs') + chip(total, 'Observations') + chip(apts, 'Groups') + chip(uniq, 'Unique-to-Malware');
}
function chip(v, l) {
  return '<div class="stat-chip"><span class="sc-val">' + v.toLocaleString() + '</span><span class="sc-lbl">' + l + '</span></div>';
}

// ═════════════════════════════════════════════════════════════
// DRILL-DOWN MODAL
// ═════════════════════════════════════════════════════════════
function showDrill(api) {
  document.getElementById('modal-api-name').textContent = api.Api;

  const rarLabel = api.Rar >= 100 ? 'Unique to Malware' : api.Rar >= 95 ? 'Rare (≥95th pct)' : 'Common';
  document.getElementById('modal-meta').innerHTML =
    '<span class="m-badge cat">' + api.Cat + '</span>' +
    '<span class="m-badge rar">' + rarLabel + ' (score: ' + api.Rar + ')</span>' +
    '<span class="m-badge cnt">' + api.Count + ' observations</span>';

  // Group hits by key
  const grouped = {};
  api.Hits.forEach(h => {
    const src = h.Src || 'Direct';
    const key = h.C + '|' + h.A + '|' + (h.Date||'unknown') + '|' + src;
    if (!grouped[key]) grouped[key] = { C: h.C, A: h.A, D: h.Date, S: src, N: 0 };
    grouped[key].N += (h.N || 1);   // each hit is already a pre-aggregated bucket
  });
  const rows = Object.values(grouped).sort((a,b) => (b.D||'').localeCompare(a.D||''));

  // Table
  const tbody = document.getElementById('modal-table-body');
  tbody.innerHTML = '';
  rows.forEach(r => {
    const srcClass = r.S === 'Direct' ? 'src-direct' : 'src-tool';
    const tr = document.createElement('tr');
    tr.innerHTML = '<td>' + (r.D || ' - ') + '</td><td>' + r.C + '</td><td>' + r.A + '</td>'
                 + '<td><span class="src-badge ' + srcClass + '">' + r.S + '</span></td>'
                 + '<td style="text-align:right; font-weight:600">' + r.N + '</td>';
    tbody.appendChild(tr);
  });

  // Mini bar chart over time
  drawModalChart(api.Hits);

  document.getElementById('drillModal').classList.add('open');
}

function drawModalChart(hits) {
  const canvas = document.getElementById('modalChart');
  const W = canvas.offsetWidth  || 680;
  const H = canvas.offsetHeight || 90;
  canvas.width  = W;
  canvas.height = H;
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, W, H);

  const validDates = hits.map(h => h.Date).filter(d => d && d !== '1970-01-01').map(d => new Date(d));
  if (validDates.length === 0) return;

  const minDate = new Date(Math.min(...validDates));
  const maxDate = new Date(Math.max(...validDates));
  const totalMs = Math.max(maxDate - minDate, 1);

  const BUCKETS = 30;
  const counts  = new Array(BUCKETS).fill(0);
  validDates.forEach(d => {
    const b = Math.min(Math.floor(((d - minDate) / totalMs) * BUCKETS), BUCKETS - 1);
    counts[b]++;
  });
  const maxC = Math.max(...counts, 1);

  const barW = W / BUCKETS;
  const grad = ctx.createLinearGradient(0, 0, 0, H);
  grad.addColorStop(0,   'rgba(0,212,255,0.9)');
  grad.addColorStop(1,   'rgba(0,212,255,0.1)');
  ctx.fillStyle = grad;

  counts.forEach((c, i) => {
    if (c === 0) return;
    const bh = Math.max((c / maxC) * (H - 8), 2);
    ctx.fillRect(i * barW + 1, H - bh, barW - 2, bh);
  });

  // X-axis labels
  ctx.fillStyle = 'rgba(107,122,153,0.8)';
  ctx.font = '9px IBM Plex Mono, monospace';
  ctx.fillText(minDate.toISOString().slice(0,7), 2, H - 1);
  const maxLabel = maxDate.toISOString().slice(0,7);
  ctx.fillText(maxLabel, W - ctx.measureText(maxLabel).width - 2, H - 1);
}

function closeModal(event) {
  if (!event || event.target === document.getElementById('drillModal')) {
    document.getElementById('drillModal').classList.remove('open');
  }
}

document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });
</script>
</body>
</html>
"@

    $HtmlContent | Set-Content -Path $OutputHtmlPath -Encoding UTF8
    Write-Host ""
    Write-Host "  >> Dashboard saved to: $OutputHtmlPath" -ForegroundColor Green
}
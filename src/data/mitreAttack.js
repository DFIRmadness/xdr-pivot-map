export const TACTICS = [
  { id: "TA0043", name: "Reconnaissance",        icon: "🔍", color: "#ff6b9d", description: "Gathering information to plan future operations." },
  { id: "TA0042", name: "Resource Development",  icon: "🏗️", color: "#ff9f43", description: "Establishing resources to support operations." },
  { id: "TA0001", name: "Initial Access",         icon: "🚪", color: "#b47fff", description: "Gaining an initial foothold within a network." },
  { id: "TA0002", name: "Execution",              icon: "⚡", color: "#00d4ff", description: "Running adversary-controlled code on a local or remote system." },
  { id: "TA0003", name: "Persistence",            icon: "🔩", color: "#ffb347", description: "Maintaining presence across restarts, credential changes, and other interruptions." },
  { id: "TA0004", name: "Privilege Escalation",   icon: "⬆️", color: "#ff6b35", description: "Gaining higher-level permissions on a system or network." },
  { id: "TA0005", name: "Defense Evasion",        icon: "🥷", color: "#ff4757", description: "Avoiding detection throughout the compromise." },
  { id: "TA0006", name: "Credential Access",      icon: "🔑", color: "#ffd700", description: "Stealing account names, passwords, and tokens." },
  { id: "TA0007", name: "Discovery",              icon: "🗺️", color: "#47ff8f", description: "Figuring out the environment to decide how to proceed." },
  { id: "TA0008", name: "Lateral Movement",       icon: "↔️", color: "#00e5ff", description: "Moving through the environment to reach the target." },
  { id: "TA0009", name: "Collection",             icon: "📦", color: "#c084fc", description: "Gathering data of interest prior to exfiltration." },
  { id: "TA0011", name: "Command & Control",      icon: "📡", color: "#f97316", description: "Communicating with compromised systems to control them." },
  { id: "TA0010", name: "Exfiltration",           icon: "📤", color: "#ff47a3", description: "Stealing data from the victim network." },
  { id: "TA0040", name: "Impact",                 icon: "💥", color: "#ef4444", description: "Disrupting availability or compromising integrity of data and systems." },
];

export const TECHNIQUES = [

  // ─── RECONNAISSANCE ────────────────────────────────────────────────────────
  {
    id: "T1595",
    name: "Active Scanning",
    tacticIds: ["TA0043"],
    description: "Adversaries execute active reconnaissance scans to gather information that can be used during targeting. Active scans probe victim infrastructure via network traffic — port scans, vulnerability scans, web service enumeration.",
    xdrMappings: [
      {
        table: "DeviceNetworkEvents",
        columns: ["RemoteIP", "RemotePort", "LocalPort", "ActionType", "InitiatingProcessFileName"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "InboundConnectionAccepted"
| summarize Ports = make_set(LocalPort), Count = count() by RemoteIP, bin(Timestamp, 1h)
| where array_length(Ports) > 10
| order by Count desc`,
      },
    ],
  },
  {
    id: "T1589",
    name: "Gather Victim Identity Information",
    tacticIds: ["TA0043"],
    description: "Adversaries gather identity information about victims — employee names, email addresses, credentials — to enable targeting or phishing.",
    xdrMappings: [
      {
        table: "IdentityQueryEvents",
        columns: ["QueryType", "QueryTarget", "AccountUpn", "DeviceName", "Protocol"],
        kql: `IdentityQueryEvents
| where Timestamp > ago(7d)
| where Protocol == "Ldap"
| where QueryType in ("AllUsers", "AllGroups")
| summarize Count = count() by AccountUpn, QueryTarget, bin(Timestamp, 1h)
| order by Count desc`,
      },
    ],
  },

  // ─── RESOURCE DEVELOPMENT ──────────────────────────────────────────────────
  {
    id: "T1586",
    name: "Compromise Accounts",
    tacticIds: ["TA0042"],
    description: "Adversaries compromise existing accounts — email, social media, cloud — rather than creating new ones, to blend in with normal activity.",
    xdrMappings: [
      {
        table: "AADSignInEventsBeta",
        columns: ["AccountUpn", "IPAddress", "Country", "IsAnonymousProxy", "RiskLevelDuringSignIn", "ErrorCode"],
        kql: `AADSignInEventsBeta
| where Timestamp > ago(7d)
| where RiskLevelDuringSignIn in ("high", "medium")
| where ErrorCode == 0
| project Timestamp, AccountUpn, IPAddress, Country, IsAnonymousProxy, RiskLevelDuringSignIn`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountDisplayName", "ActionType", "IPAddress", "Application"],
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("MailboxLogin", "UserLoggedIn")
| where IPTags has "anonymizer"
| project Timestamp, AccountDisplayName, ActionType, IPAddress, Application`,
      },
    ],
  },

  // ─── INITIAL ACCESS ────────────────────────────────────────────────────────
  {
    id: "T1566",
    name: "Phishing",
    tacticIds: ["TA0001"],
    description: "Adversaries send phishing messages to gain access to victim systems. Phishing can include spearphishing attachments, links, or service-based lures.",
    xdrMappings: [
      {
        table: "EmailEvents",
        columns: ["NetworkMessageId", "SenderFromAddress", "RecipientEmailAddress", "Subject", "DeliveryAction", "AttachmentCount"],
        kql: `EmailEvents
| where Timestamp > ago(7d)
| where DeliveryAction == "Delivered"
| where AttachmentCount > 0 or UrlCount > 0
| where SenderFromDomain !endswith ".microsoft.com"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, NetworkMessageId, DeliveryLocation`,
      },
      {
        table: "EmailAttachmentInfo",
        columns: ["NetworkMessageId", "FileName", "FileType", "SHA256", "MalwareDetectionMethod"],
        kql: `EmailAttachmentInfo
| where Timestamp > ago(7d)
| where isnotempty(MalwareDetectionMethod) or FileType in ("exe","dll","docm","xlsm","js","vbs","hta","ps1","lnk")
| join kind=inner EmailEvents on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress, FileName, FileType, SHA256, MalwareDetectionMethod`,
      },
      {
        table: "UrlClickEvents",
        columns: ["NetworkMessageId", "Url", "AccountUpn", "ActionType", "IsClickedThrough"],
        kql: `UrlClickEvents
| where Timestamp > ago(7d)
| where ActionType == "ClickAllowed"
| where IsClickedThrough == true
| project Timestamp, AccountUpn, Url, NetworkMessageId`,
      },
    ],
  },
  {
    id: "T1078",
    name: "Valid Accounts",
    tacticIds: ["TA0001", "TA0003", "TA0004", "TA0005"],
    description: "Adversaries obtain and abuse credentials of existing accounts to gain initial access and bypass security controls. Includes cloud, domain, and local accounts.",
    xdrMappings: [
      {
        table: "AADSignInEventsBeta",
        columns: ["AccountUpn", "IPAddress", "Country", "IsAnonymousProxy", "RiskLevelDuringSignIn", "ConditionalAccessStatus"],
        kql: `AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ErrorCode == 0
| where Country != "<expected_country>"
| where IsAnonymousProxy == true or RiskLevelDuringSignIn == "high"
| project Timestamp, AccountUpn, IPAddress, Country, RiskLevelDuringSignIn`,
      },
      {
        table: "IdentityLogonEvents",
        columns: ["AccountUpn", "LogonType", "ActionType", "IPAddress", "DeviceName"],
        kql: `IdentityLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonSuccess"
| where LogonType in ("Network", "Interactive")
| summarize LogonCount = count(), Devices = make_set(DeviceName) by AccountUpn, IPAddress
| where array_length(Devices) > 3`,
      },
    ],
  },
  {
    id: "T1190",
    name: "Exploit Public-Facing Application",
    tacticIds: ["TA0001"],
    description: "Adversaries exploit weaknesses in internet-facing applications to gain access. Targets include web servers, Exchange, VPNs, and cloud management interfaces.",
    xdrMappings: [
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteIP", "RemotePort", "LocalPort", "ActionType", "InitiatingProcessFileName"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where LocalPort in (80, 443, 8080, 8443)
| where ActionType == "InboundConnectionAccepted"
| join kind=leftouter DeviceProcessEvents on DeviceId, $left.InitiatingProcessId == $right.ProcessId
| project Timestamp, DeviceName, RemoteIP, LocalPort, FileName, ProcessCommandLine`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where AttackTechniques has "T1190"
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },

  // ─── EXECUTION ─────────────────────────────────────────────────────────────
  {
    id: "T1059.001",
    name: "PowerShell",
    tacticIds: ["TA0002"],
    description: "Adversaries abuse PowerShell to execute commands, download payloads, and move laterally. Common indicators include encoded commands, download cradles, and AMSI bypass attempts.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "InitiatingProcessFileName", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
| where ProcessCommandLine has_any ("-EncodedCommand", "-enc ", "IEX", "Invoke-Expression", "DownloadString", "WebClient", "bypass", "hidden")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1059.003",
    name: "Windows Command Shell",
    tacticIds: ["TA0002"],
    description: "Adversaries abuse cmd.exe to execute commands. Often used to chain tools, delete logs, and execute downloaded payloads.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "InitiatingProcessFileName", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has_any ("net user", "net localgroup", "whoami", "wscript", "certutil", "bitsadmin", "curl", "wget")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1047",
    name: "Windows Management Instrumentation",
    tacticIds: ["TA0002"],
    description: "Adversaries use WMI to execute code, gather information, and persist on systems. WMI can be abused locally or remotely.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "InitiatingProcessFileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName !in ("WmiPrvSE.exe", "msiexec.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName`,
      },
      {
        table: "DeviceEvents",
        columns: ["DeviceName", "ActionType", "InitiatingProcessFileName", "InitiatingProcessCommandLine"],
        kql: `DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == "WmiBindEventFilter"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields`,
      },
    ],
  },
  {
    id: "T1053.005",
    name: "Scheduled Task",
    tacticIds: ["TA0002", "TA0003", "TA0004"],
    description: "Adversaries abuse Windows scheduled tasks to execute malicious code and maintain persistence. schtasks.exe and the Task Scheduler COM API are common abuse vectors.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName", "InitiatingProcessFileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has_any ("/create", "/change")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
      {
        table: "DeviceEvents",
        columns: ["DeviceName", "ActionType", "AdditionalFields"],
        kql: `DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == "ScheduledTaskCreated"
| extend TaskName = tostring(parse_json(AdditionalFields).TaskName)
| extend Command = tostring(parse_json(AdditionalFields).Command)
| project Timestamp, DeviceName, TaskName, Command`,
      },
    ],
  },

  // ─── PERSISTENCE ───────────────────────────────────────────────────────────
  {
    id: "T1547.001",
    name: "Registry Run Keys",
    tacticIds: ["TA0003", "TA0004"],
    description: "Adversaries add programs to run-key registry locations so they execute on user login or system boot.",
    xdrMappings: [
      {
        table: "DeviceRegistryEvents",
        columns: ["DeviceName", "RegistryKey", "RegistryValueName", "RegistryValueData", "InitiatingProcessFileName"],
        kql: `DeviceRegistryEvents
| where Timestamp > ago(1d)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has_any (
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
  )
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1543.003",
    name: "Windows Service",
    tacticIds: ["TA0003", "TA0004"],
    description: "Adversaries create or modify Windows services to repeatedly execute malicious payloads as part of persistence.",
    xdrMappings: [
      {
        table: "DeviceRegistryEvents",
        columns: ["DeviceName", "RegistryKey", "RegistryValueName", "RegistryValueData", "InitiatingProcessFileName"],
        kql: `DeviceRegistryEvents
| where Timestamp > ago(1d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has "\\SYSTEM\\CurrentControlSet\\Services\\"
| where RegistryValueName == "ImagePath"
| where RegistryValueData !startswith "C:\\Windows\\system32\\"
| project Timestamp, DeviceName, RegistryKey, RegistryValueData, InitiatingProcessFileName`,
      },
      {
        table: "DeviceEvents",
        columns: ["DeviceName", "ActionType", "AdditionalFields", "InitiatingProcessFileName"],
        kql: `DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == "ServiceInstalled"
| extend ServiceName = tostring(parse_json(AdditionalFields).ServiceName)
| extend ServicePath = tostring(parse_json(AdditionalFields).ServicePath)
| where ServicePath !startswith "C:\\Windows\\"
| project Timestamp, DeviceName, ServiceName, ServicePath`,
      },
    ],
  },
  {
    id: "T1136",
    name: "Create Account",
    tacticIds: ["TA0003"],
    description: "Adversaries create accounts to maintain access. This includes local, domain, and cloud accounts.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "ProcessCommandLine", "AccountName", "InitiatingProcessFileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("net user /add", "net localgroup administrators")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
      {
        table: "IdentityDirectoryEvents",
        columns: ["AccountUpn", "AccountName", "ActionType", "TargetAccountUpn", "AdditionalFields"],
        kql: `IdentityDirectoryEvents
| where Timestamp > ago(1d)
| where ActionType == "Account created"
| project Timestamp, AccountUpn, TargetAccountUpn, AdditionalFields`,
      },
    ],
  },

  // ─── PRIVILEGE ESCALATION ──────────────────────────────────────────────────
  {
    id: "T1055",
    name: "Process Injection",
    tacticIds: ["TA0004", "TA0005"],
    description: "Adversaries inject code into processes to evade defenses and escalate privileges. Common methods include DLL injection, process hollowing, and reflective loading.",
    xdrMappings: [
      {
        table: "DeviceEvents",
        columns: ["DeviceName", "ActionType", "InitiatingProcessFileName", "InitiatingProcessId", "AdditionalFields"],
        kql: `DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == "CreateRemoteThread"
| extend TargetProcess = tostring(parse_json(AdditionalFields).TargetProcessName)
| where TargetProcess in ("lsass.exe", "svchost.exe", "explorer.exe", "winlogon.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, TargetProcess`,
      },
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "InitiatingProcessFileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe")
| where FileName !in~ ("conhost.exe", "WerFault.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine`,
      },
    ],
  },
  {
    id: "T1548.002",
    name: "Bypass UAC",
    tacticIds: ["TA0004", "TA0005"],
    description: "Adversaries bypass User Account Control to execute code with elevated privileges without prompting the user.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "InitiatingProcessFileName", "ProcessIntegrityLevel"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("fodhelper.exe", "eventvwr.exe", "sdclt.exe", "computerdefaults.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, ProcessIntegrityLevel`,
      },
    ],
  },

  // ─── DEFENSE EVASION ───────────────────────────────────────────────────────
  {
    id: "T1070.001",
    name: "Clear Windows Event Logs",
    tacticIds: ["TA0005"],
    description: "Adversaries clear Windows event logs to remove evidence of their activity.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "wevtutil.exe"
| where ProcessCommandLine has_any ("cl ", "clear-log")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
      {
        table: "DeviceEvents",
        columns: ["DeviceName", "ActionType", "AdditionalFields"],
        kql: `DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == "AuditPolicyModification"
| project Timestamp, DeviceName, AdditionalFields`,
      },
    ],
  },
  {
    id: "T1036",
    name: "Masquerading",
    tacticIds: ["TA0005"],
    description: "Adversaries rename or disguise malicious files and processes to appear legitimate — e.g. naming malware 'svchost.exe' but running from a non-system path.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "ProcessCommandLine", "SHA256"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "explorer.exe")
| where FolderPath !startswith "C:\\Windows\\System32"
    and FolderPath !startswith "C:\\Windows\\SysWOW64"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256`,
      },
    ],
  },
  {
    id: "T1562.001",
    name: "Disable or Modify Security Tools",
    tacticIds: ["TA0005"],
    description: "Adversaries disable security software to avoid detection — stopping AV services, modifying Defender settings, or disabling EDR agents.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "ProcessCommandLine", "FileName", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (
    "Set-MpPreference -Disable",
    "Add-MpPreference -ExclusionPath",
    "sc stop WinDefend",
    "net stop WinDefend",
    "sc config WinDefend start=disabled"
  )
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
      {
        table: "DeviceRegistryEvents",
        columns: ["DeviceName", "RegistryKey", "RegistryValueName", "RegistryValueData"],
        kql: `DeviceRegistryEvents
| where Timestamp > ago(1d)
| where RegistryKey has "Windows Defender"
| where RegistryValueName in ("DisableAntiSpyware", "DisableRealtimeMonitoring")
| where RegistryValueData == "1"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData`,
      },
    ],
  },
  {
    id: "T1218",
    name: "System Binary Proxy Execution",
    tacticIds: ["TA0005"],
    description: "Adversaries abuse trusted Windows binaries (LOLBins) to proxy execution of malicious code, bypassing application whitelisting.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "InitiatingProcessFileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("regsvr32.exe", "rundll32.exe", "mshta.exe", "certutil.exe", "msiexec.exe", "installutil.exe")
| where ProcessCommandLine has_any ("http://", "https://", "ftp://", "\\\\", ".dll,", "-urlcache", "-decode")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName`,
      },
    ],
  },

  // ─── CREDENTIAL ACCESS ─────────────────────────────────────────────────────
  {
    id: "T1003.001",
    name: "LSASS Memory Dump",
    tacticIds: ["TA0006"],
    description: "Adversaries access LSASS memory to extract credential material including NTLM hashes and Kerberos tickets.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName", "InitiatingProcessFileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("procdump.exe", "procdump64.exe", "mimikatz.exe", "wce.exe", "fgdump.exe")
    or (FileName =~ "taskmgr.exe" and ProcessCommandLine has "lsass")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`,
      },
      {
        table: "DeviceEvents",
        columns: ["DeviceName", "ActionType", "InitiatingProcessFileName", "AdditionalFields"],
        kql: `DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == "CreateRemoteThread"
| extend TargetProcess = tostring(parse_json(AdditionalFields).TargetProcessName)
| where TargetProcess =~ "lsass.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName, TargetProcess`,
      },
    ],
  },
  {
    id: "T1110",
    name: "Brute Force",
    tacticIds: ["TA0006"],
    description: "Adversaries attempt to gain access to accounts by brute force — repeated login attempts with different passwords or credential stuffing from breach databases.",
    xdrMappings: [
      {
        table: "IdentityLogonEvents",
        columns: ["AccountUpn", "IPAddress", "ActionType", "LogonType", "DeviceName"],
        kql: `IdentityLogonEvents
| where Timestamp > ago(1h)
| where ActionType == "LogonFailed"
| summarize FailCount = count(), Accounts = dcount(AccountUpn) by IPAddress, bin(Timestamp, 5m)
| where FailCount > 20 or Accounts > 5
| order by FailCount desc`,
      },
      {
        table: "AADSignInEventsBeta",
        columns: ["AccountUpn", "IPAddress", "ErrorCode", "Country", "RiskLevelDuringSignIn"],
        kql: `AADSignInEventsBeta
| where Timestamp > ago(1h)
| where ErrorCode in (50126, 50053, 50055, 50056)
| summarize Failures = count() by AccountUpn, IPAddress, bin(Timestamp, 5m)
| where Failures > 10
| order by Failures desc`,
      },
    ],
  },
  {
    id: "T1558.003",
    name: "Kerberoasting",
    tacticIds: ["TA0006"],
    description: "Adversaries request Kerberos service tickets for accounts with SPNs, then crack them offline to obtain credentials.",
    xdrMappings: [
      {
        table: "IdentityQueryEvents",
        columns: ["AccountUpn", "QueryType", "QueryTarget", "Protocol", "DeviceName"],
        kql: `IdentityQueryEvents
| where Timestamp > ago(1d)
| where QueryType == "KerberosServiceTicketRequest"
| summarize TicketCount = count(), Services = make_set(QueryTarget) by AccountUpn, DeviceName, bin(Timestamp, 1h)
| where TicketCount > 5
| order by TicketCount desc`,
      },
      {
        table: "IdentityDirectoryEvents",
        columns: ["AccountUpn", "ActionType", "TargetAccountUpn", "AdditionalFields"],
        kql: `IdentityDirectoryEvents
| where Timestamp > ago(1d)
| where ActionType == "LDAP query"
| where AdditionalFields has "servicePrincipalName"
| project Timestamp, AccountUpn, TargetAccountUpn, AdditionalFields`,
      },
    ],
  },

  // ─── DISCOVERY ─────────────────────────────────────────────────────────────
  {
    id: "T1082",
    name: "System Information Discovery",
    tacticIds: ["TA0007"],
    description: "Adversaries gather detailed OS and hardware information about the victim system to refine their attack.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("systeminfo", "hostname", "ver ", "ipconfig", "whoami /all", "set ", "echo %")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
    ],
  },
  {
    id: "T1018",
    name: "Remote System Discovery",
    tacticIds: ["TA0007"],
    description: "Adversaries attempt to discover remote systems — enumerating hosts on the network to find targets for lateral movement.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "ProcessCommandLine", "AccountName", "FileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("net view", "nmap", "ping -n", "arp -a", "nslookup", "nltest /dclist", "net group \"domain computers\"")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`,
      },
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteIP", "RemotePort", "ActionType", "InitiatingProcessFileName"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1h)
| where ActionType == "ConnectionRequest"
| where RemotePort in (135, 137, 139, 445, 3389, 22, 23)
| summarize Targets = dcount(RemoteIP), Ports = make_set(RemotePort) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)
| where Targets > 10
| order by Targets desc`,
      },
    ],
  },
  {
    id: "T1087",
    name: "Account Discovery",
    tacticIds: ["TA0007"],
    description: "Adversaries enumerate accounts to understand privilege levels, find targets for escalation, and identify admin accounts.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "ProcessCommandLine", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("net user", "net localgroup", "net group", "dsquery user", "Get-ADUser", "Get-LocalUser")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
      {
        table: "IdentityQueryEvents",
        columns: ["AccountUpn", "QueryType", "QueryTarget", "Protocol"],
        kql: `IdentityQueryEvents
| where Timestamp > ago(1d)
| where QueryType in ("AllUsers", "AllGroups", "User", "Group")
| summarize QueryCount = count() by AccountUpn, QueryType, bin(Timestamp, 1h)
| where QueryCount > 20
| order by QueryCount desc`,
      },
    ],
  },
  {
    id: "T1069",
    name: "Permission Groups Discovery",
    tacticIds: ["TA0007"],
    description: "Adversaries enumerate groups and permissions to understand the domain structure and identify accounts with elevated privileges.",
    xdrMappings: [
      {
        table: "IdentityQueryEvents",
        columns: ["AccountUpn", "QueryType", "QueryTarget", "Protocol", "DeviceName"],
        kql: `IdentityQueryEvents
| where Timestamp > ago(1d)
| where QueryType in ("AllGroups", "Group")
| where QueryTarget has_any ("admin", "domain admin", "enterprise admin", "schema admin")
| project Timestamp, AccountUpn, QueryType, QueryTarget, DeviceName`,
      },
    ],
  },

  // ─── LATERAL MOVEMENT ──────────────────────────────────────────────────────
  {
    id: "T1021.001",
    name: "Remote Desktop Protocol",
    tacticIds: ["TA0008"],
    description: "Adversaries use RDP to log on interactively to a remote system. Often used after credential theft.",
    xdrMappings: [
      {
        table: "DeviceLogonEvents",
        columns: ["DeviceName", "AccountName", "AccountDomain", "LogonType", "RemoteDeviceName", "RemoteIP"],
        kql: `DeviceLogonEvents
| where Timestamp > ago(1d)
| where LogonType == 10                   // RemoteInteractive (RDP)
| where not(AccountDomain =~ DeviceName)
| project Timestamp, DeviceName, AccountName, AccountDomain, RemoteDeviceName, RemoteIP`,
      },
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteIP", "RemotePort", "LocalPort", "ActionType"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort == 3389
| where ActionType == "ConnectionSuccess"
| project Timestamp, DeviceName, RemoteIP`,
      },
    ],
  },
  {
    id: "T1550.002",
    name: "Pass the Hash",
    tacticIds: ["TA0008"],
    description: "Adversaries authenticate to remote systems using stolen NTLM hashes instead of plaintext credentials.",
    xdrMappings: [
      {
        table: "DeviceLogonEvents",
        columns: ["DeviceName", "AccountName", "LogonType", "ActionType", "RemoteIP"],
        kql: `DeviceLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonSuccess"
| where LogonType == 3                    // Network (Pass-the-Hash)
| where not(AccountName endswith "$")
| summarize Targets = dcount(DeviceName), Hops = make_set(DeviceName) by AccountName, RemoteIP
| where Targets > 3
| order by Targets desc`,
      },
      {
        table: "IdentityLogonEvents",
        columns: ["AccountUpn", "ActionType", "Protocol", "IPAddress", "DeviceName"],
        kql: `IdentityLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonSuccess"
| where Protocol == "NTLM"
| summarize Count = count(), Targets = dcount(DeviceName) by AccountUpn, IPAddress
| where Targets > 4
| order by Targets desc`,
      },
    ],
  },
  {
    id: "T1021.002",
    name: "SMB / Windows Admin Shares",
    tacticIds: ["TA0008"],
    description: "Adversaries use SMB and Windows admin shares (C$, IPC$, ADMIN$) to transfer files and execute code on remote systems.",
    xdrMappings: [
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteIP", "RemotePort", "ActionType", "InitiatingProcessFileName"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
| summarize Targets = dcount(RemoteIP) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where Targets > 5
| order by Targets desc`,
      },
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "SHA256", "InitiatingProcessFileName"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where FolderPath startswith "\\\\"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1570",
    name: "Lateral Tool Transfer",
    tacticIds: ["TA0008"],
    description: "Adversaries transfer tools or files to systems in the victim network using SMB, WMI, BITS, or RDP clipboard.",
    xdrMappings: [
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "SHA256", "InitiatingProcessFileName"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileCreated"
| where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\ProgramData\\", "\\Users\\Public\\")
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".ps1"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName`,
      },
    ],
  },

  // ─── COLLECTION ────────────────────────────────────────────────────────────
  {
    id: "T1560",
    name: "Archive Collected Data",
    tacticIds: ["TA0009"],
    description: "Adversaries compress and archive data before exfiltration to minimise size and evade data loss prevention controls.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("7z.exe", "7za.exe", "winrar.exe", "rar.exe", "zip.exe", "tar.exe")
    or ProcessCommandLine has_any ("Compress-Archive", "-password", "-p ")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "FileSize"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileCreated"
| where FileName endswith ".zip" or FileName endswith ".rar" or FileName endswith ".7z"
| where FileSize > 10000000
| project Timestamp, DeviceName, FileName, FolderPath, FileSize`,
      },
    ],
  },
  {
    id: "T1114.002",
    name: "Remote Email Collection",
    tacticIds: ["TA0009"],
    description: "Adversaries access email remotely through Exchange or Graph API to gather intelligence and credentials.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountDisplayName", "ActionType", "Application", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Exchange Online"
| where ActionType in ("MailItemsAccessed", "HardDelete", "MessageBind")
| summarize Actions = count(), IPs = make_set(IPAddress) by AccountDisplayName, ActionType, bin(Timestamp, 1h)
| where Actions > 100
| order by Actions desc`,
      },
    ],
  },
  {
    id: "T1213",
    name: "Data from Information Repositories",
    tacticIds: ["TA0009"],
    description: "Adversaries mine data from information repositories such as SharePoint, Confluence, and Teams for credentials and sensitive information.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountDisplayName", "ActionType", "Application", "ObjectName"],
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where Application in ("Microsoft SharePoint Online", "Microsoft Teams")
| where ActionType in ("FileDownloaded", "FilePreviewed", "PageViewed")
| summarize Downloads = count(), Files = make_set(ObjectName) by AccountDisplayName, bin(Timestamp, 1h)
| where Downloads > 50
| order by Downloads desc`,
      },
    ],
  },

  // ─── COMMAND AND CONTROL ───────────────────────────────────────────────────
  {
    id: "T1071.001",
    name: "Web Protocols (HTTP/S)",
    tacticIds: ["TA0011"],
    description: "Adversaries communicate using HTTP/HTTPS to blend C2 traffic with legitimate web traffic.",
    xdrMappings: [
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteIP", "RemoteUrl", "RemotePort", "InitiatingProcessFileName", "BytesSent"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort in (80, 443, 8080, 8443)
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","svchost.exe","MsMpEng.exe","OneDrive.exe")
| summarize Connections = count(), BytesSent = sum(SentBytes) by DeviceName, RemoteIP, InitiatingProcessFileName, bin(Timestamp, 1h)
| where Connections > 20
| order by Connections desc`,
      },
    ],
  },
  {
    id: "T1071.004",
    name: "DNS",
    tacticIds: ["TA0011"],
    description: "Adversaries use DNS queries to communicate with C2 infrastructure. High-frequency queries, long subdomains, or queries to newly registered domains are indicators.",
    xdrMappings: [
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteUrl", "RemoteIP", "RemotePort", "InitiatingProcessFileName"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1h)
| where RemotePort == 53
| summarize QueryCount = count(), Domains = dcount(RemoteUrl) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)
| where QueryCount > 100 or Domains > 30
| order by QueryCount desc`,
      },
    ],
  },
  {
    id: "T1105",
    name: "Ingress Tool Transfer",
    tacticIds: ["TA0011"],
    description: "Adversaries transfer tools from external systems into the environment using native utilities like certutil, bitsadmin, curl, or PowerShell.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("certutil -urlcache", "bitsadmin /transfer", "Invoke-WebRequest", "DownloadFile", "curl -o", "wget ", "(New-Object Net.WebClient)")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "SHA256", "InitiatingProcessFileName"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileCreated"
| where InitiatingProcessFileName in~ ("certutil.exe", "bitsadmin.exe", "powershell.exe", "curl.exe", "wget.exe")
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".ps1" or FileName endswith ".bat"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName`,
      },
    ],
  },

  // ─── EXFILTRATION ──────────────────────────────────────────────────────────
  {
    id: "T1048",
    name: "Exfiltration Over Alternative Protocol",
    tacticIds: ["TA0010"],
    description: "Adversaries exfiltrate data using protocols other than the C2 channel — DNS tunneling, ICMP, FTP, or SMTP.",
    xdrMappings: [
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteIP", "RemotePort", "RemoteUrl", "BytesSent", "InitiatingProcessFileName"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort in (21, 22, 25, 53, 69, 143, 993)
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName !in~ ("svchost.exe", "System")
| summarize TotalBytesSent = sum(SentBytes) by DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| where TotalBytesSent > 50000000
| order by TotalBytesSent desc`,
      },
    ],
  },
  {
    id: "T1567.002",
    name: "Exfiltration to Cloud Storage",
    tacticIds: ["TA0010"],
    description: "Adversaries exfiltrate data to cloud storage services such as Dropbox, MEGA, Google Drive, or OneDrive personal accounts.",
    xdrMappings: [
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteUrl", "RemoteIP", "BytesSent", "InitiatingProcessFileName"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteUrl has_any ("dropbox.com", "mega.nz", "drive.google.com", "wetransfer.com", "anonfiles.com", "gofile.io")
| where ActionType == "ConnectionSuccess"
| summarize TotalSent = sum(SentBytes) by DeviceName, RemoteUrl, InitiatingProcessFileName
| where TotalSent > 5000000
| order by TotalSent desc`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountDisplayName", "ActionType", "Application", "ObjectName", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType == "FileUploaded"
| where Application !in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
| project Timestamp, AccountDisplayName, ActionType, Application, ObjectName, IPAddress`,
      },
    ],
  },

  // ─── IMPACT ────────────────────────────────────────────────────────────────
  {
    id: "T1486",
    name: "Data Encrypted for Impact",
    tacticIds: ["TA0040"],
    description: "Adversaries encrypt files on target systems to interrupt business and extort payment. Mass file rename/extension change within a short window is a key indicator.",
    xdrMappings: [
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "ActionType", "InitiatingProcessFileName"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType in ("FileModified", "FileRenamed")
| summarize FileCount = count(), Extensions = make_set(tostring(split(FileName, ".")[-1])) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)
| where FileCount > 100
| order by FileCount desc`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where Category == "Ransomware" or Title has "ransomware" or AttackTechniques has "T1486"
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },
  {
    id: "T1490",
    name: "Inhibit System Recovery",
    tacticIds: ["TA0040"],
    description: "Adversaries delete shadow copies and disable backup tools to prevent recovery of encrypted or deleted data.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (
    "vssadmin delete shadows",
    "wbadmin delete",
    "bcdedit /set",
    "wmic shadowcopy delete",
    "diskshadow /s"
  )
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
    ],
  },
  {
    id: "T1489",
    name: "Service Stop",
    tacticIds: ["TA0040"],
    description: "Adversaries stop or disable services to disable security software, interrupt backups, or prepare for ransomware deployment.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "ProcessCommandLine", "AccountName", "FileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("net stop", "sc stop", "sc config", "Stop-Service")
| summarize Services = make_set(ProcessCommandLine), Count = count() by DeviceName, AccountName, bin(Timestamp, 5m)
| where Count > 5
| order by Count desc`,
      },
    ],
  },
];

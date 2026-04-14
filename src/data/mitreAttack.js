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

  {
    id: "T1598",
    name: "Phishing for Information",
    tacticIds: ["TA0043"],
    description: "Adversaries send phishing messages specifically to elicit sensitive information — credentials, internal knowledge, or network details — rather than to deliver malware. Spearphishing links, attachments, and service-based lures are all used.",
    xdrMappings: [
      {
        table: "EmailEvents",
        columns: ["SenderFromAddress", "RecipientEmailAddress", "Subject", "DeliveryAction", "UrlCount", "NetworkMessageId"],
        kql: `EmailEvents
| where Timestamp > ago(7d)
| where DeliveryAction == "Delivered"
| where UrlCount > 0
// Credential-harvest indicators: login / verify / account / secure in subject
| where Subject has_any ("verify", "confirm", "unusual sign", "account suspended", "login", "credential")
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, NetworkMessageId`,
      },
      {
        table: "UrlClickEvents",
        columns: ["AccountUpn", "Url", "ActionType", "IsClickedThrough", "NetworkMessageId"],
        kql: `UrlClickEvents
| where Timestamp > ago(7d)
| where IsClickedThrough == true
| where Url has_any ("login", "signin", "verify", "account", "secure", "update")
| project Timestamp, AccountUpn, Url, ActionType, NetworkMessageId`,
      },
    ],
  },
  {
    id: "T1590",
    name: "Gather Victim Network Information",
    tacticIds: ["TA0043"],
    description: "Adversaries gather information about the victim's network — IP ranges, domain names, network topology — to plan intrusions. Observable from the inside via DNS queries and LDAP enumeration.",
    xdrMappings: [
      {
        table: "IdentityQueryEvents",
        columns: ["AccountUpn", "QueryType", "QueryTarget", "Protocol", "DeviceName"],
        kql: `IdentityQueryEvents
| where Timestamp > ago(7d)
| where QueryType in ("AllDomains", "AllSubnets", "DnsRecord")
| summarize Count = count(), Targets = make_set(QueryTarget) by AccountUpn, DeviceName, bin(Timestamp, 1h)
| where Count > 20
| order by Count desc`,
      },
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteIP", "RemotePort", "InitiatingProcessFileName", "ActionType"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort in (53, 636, 389, 3268, 3269)
| summarize Queries = count(), Targets = dcount(RemoteIP) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where Queries > 100
| order by Queries desc`,
      },
    ],
  },
  {
    id: "T1592",
    name: "Gather Victim Host Information",
    tacticIds: ["TA0043"],
    description: "Adversaries gather information about victim hosts — OS versions, installed software, hardware configurations — to identify exploitable vulnerabilities before attacking.",
    xdrMappings: [
      {
        table: "DeviceInfo",
        columns: ["DeviceName", "OSPlatform", "OSVersion", "PublicIP", "IsAzureADJoined", "OnboardingStatus"],
        kql: `DeviceInfo
| where Timestamp > ago(7d)
| where OnboardingStatus == "Onboarded"
| project DeviceName, OSPlatform, OSVersion, PublicIP, IsAzureADJoined, LastSeen`,
      },
      {
        table: "DeviceTvmSoftwareInventory",
        columns: ["DeviceName", "SoftwareName", "SoftwareVersion", "SoftwareVendor", "EndOfSupportStatus"],
        kql: `DeviceTvmSoftwareInventory
| where EndOfSupportStatus != "Supported"
| summarize EOLSoftware = count() by DeviceName, SoftwareName, SoftwareVersion, EndOfSupportStatus
| order by DeviceName asc`,
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

  {
    id: "T1189",
    name: "Drive-by Compromise",
    tacticIds: ["TA0001"],
    description: "Adversaries gain access by exploiting vulnerabilities in web browsers or plugins when a user visits a malicious or compromised website. Browser exploit kits, malvertising, and watering hole attacks all fall here.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "InitiatingProcessFileName", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe")
| where FileName !in~ (
    "chrome.exe","msedge.exe","firefox.exe","iexplore.exe",
    "splwow64.exe","WerFault.exe","conhost.exe","dwm.exe","dllhost.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine`,
      },
      {
        table: "DeviceEvents",
        columns: ["DeviceName", "ActionType", "InitiatingProcessFileName", "AdditionalFields"],
        kql: `DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == "ExploitGuardExploitDetected"
| where InitiatingProcessFileName in~ ("chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe")
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, AdditionalFields`,
      },
    ],
  },
  {
    id: "T1091",
    name: "Replication Through Removable Media",
    tacticIds: ["TA0001", "TA0008"],
    description: "Adversaries use removable media (USB drives) to gain initial access or spread laterally. Malware placed on removable media automatically executes when the drive is inserted via AutoRun or user interaction.",
    xdrMappings: [
      {
        table: "DeviceEvents",
        columns: ["DeviceName", "ActionType", "AdditionalFields", "InitiatingProcessFileName"],
        kql: `DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "UsbDriveMounted"
| project Timestamp, DeviceName, ActionType, AdditionalFields`,
      },
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "SHA256", "InitiatingProcessFileName", "ActionType"],
        kql: `DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath matches regex @"^[D-Z]:\\"   // Non-system drives
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".lnk"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1133",
    name: "External Remote Services",
    tacticIds: ["TA0001", "TA0003"],
    description: "Adversaries leverage external-facing remote services — VPNs, Citrix, RDP gateways, SSH, and cloud management portals — to gain initial access or maintain persistence. Often abused with stolen credentials or after exploiting a vulnerability in the service itself.",
    xdrMappings: [
      {
        table: "DeviceLogonEvents",
        columns: ["DeviceName", "AccountName", "LogonType", "RemoteIP", "ActionType", "Protocol"],
        kql: `DeviceLogonEvents
| where Timestamp > ago(1d)
| where LogonType in (10, 3)           // RemoteInteractive or Network
| where RemoteIP !startswith "10."
    and RemoteIP !startswith "192.168."
    and RemoteIP !startswith "172."
| where ActionType == "LogonSuccess"
| project Timestamp, DeviceName, AccountName, LogonType, RemoteIP`,
      },
      {
        table: "AADSignInEventsBeta",
        columns: ["AccountUpn", "IPAddress", "Country", "Application", "ConditionalAccessStatus", "RiskLevelDuringSignIn"],
        kql: `AADSignInEventsBeta
| where Timestamp > ago(1d)
| where Application in ("Azure VPN", "GlobalProtect", "Cisco AnyConnect", "F5 BIG-IP", "Citrix Gateway")
    or Application has_any ("VPN", "Remote Access", "Gateway")
| where ErrorCode == 0
| where RiskLevelDuringSignIn in ("medium", "high") or IsAnonymousProxy == true
| project Timestamp, AccountUpn, IPAddress, Country, Application, RiskLevelDuringSignIn`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where AttackTechniques has "T1133"
    or Title has_any ("VPN", "remote access", "external service")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },
  {
    id: "T1199",
    name: "Trusted Relationship",
    tacticIds: ["TA0001"],
    description: "Adversaries breach organisations through third-party partners, MSPs, or IT vendors that have privileged access to the target network. The initial compromise is of the trusted third party, which is then used to pivot into the victim.",
    xdrMappings: [
      {
        table: "IdentityLogonEvents",
        columns: ["AccountUpn", "AccountDomain", "ActionType", "IPAddress", "Protocol", "DeviceName"],
        kql: `IdentityLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess"
| where AccountDomain !endswith "<yourdomain.com>"   // flag cross-domain logons
| project Timestamp, AccountUpn, AccountDomain, IPAddress, Protocol, DeviceName
| summarize Count = count(), Targets = make_set(DeviceName) by AccountUpn, AccountDomain
| where array_length(Targets) > 3
| order by Count desc`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountDisplayName", "ActionType", "IPAddress", "Application", "UserAgent"],
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Add delegated permission grant", "Add app role assignment to service principal", "Consent to application")
| project Timestamp, AccountDisplayName, ActionType, Application, IPAddress`,
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

  {
    id: "T1059.005",
    name: "Visual Basic",
    tacticIds: ["TA0002"],
    description: "Adversaries abuse VBScript and Visual Basic for Applications (VBA) to execute malicious code — typically via Office macros, HTA files, or standalone .vbs scripts dropped and run by other malware.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "InitiatingProcessFileName", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("wscript.exe", "cscript.exe")
| where ProcessCommandLine has_any (".vbs", ".vbe", ".wsf", ".wsh", "//e:vbscript")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName`,
      },
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "SHA256", "InitiatingProcessFileName"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where FileName endswith ".vbs" or FileName endswith ".vbe" or FileName endswith ".wsf"
| where ActionType == "FileCreated"
| where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\Downloads\\", "\\Public\\")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1204.002",
    name: "User Execution: Malicious File",
    tacticIds: ["TA0002"],
    description: "Adversaries rely on a user opening a malicious file — an email attachment, a downloaded executable, or an Office document with macros — to execute their payload. The user is the unwitting delivery mechanism.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "InitiatingProcessFileName", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ (
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "onenote.exe", "msaccess.exe", "acrord32.exe", "foxit.exe")
| where FileName !in~ ("splwow64.exe", "WerFault.exe", "conhost.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine`,
      },
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "SHA256", "InitiatingProcessFileName"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileCreated"
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "outlook.exe", "onenote.exe")
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".ps1" or FileName endswith ".bat"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName`,
      },
    ],
  },

  {
    id: "T1651",
    name: "Cloud Administration Command",
    tacticIds: ["TA0002"],
    description: "Adversaries abuse cloud management services to execute commands on virtual machines without needing a direct network connection or credentials to the OS — Azure VM Run Command, AWS SSM RunCommand, and GCP's OS Login are common vectors.",
    xdrMappings: [
      {
        table: "CloudAuditEvents",
        columns: ["ActionType", "AccountDisplayName", "ResourceId", "AdditionalFields"],
        kql: `CloudAuditEvents
| where Timestamp > ago(1d)
| where ActionType in (
    "Microsoft.Compute/virtualMachines/runCommand/action",
    "Microsoft.Compute/virtualMachines/extensions/write",
    "RunShellScript", "RunPowerShellScript")
| project Timestamp, AccountDisplayName, ActionType, ResourceId, AdditionalFields`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountDisplayName", "ActionType", "Application", "IPAddress", "AdditionalFields"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType has_any ("RunCommand", "Invoke-AzVMRunCommand", "SendSSHPublicKey", "run-command")
| project Timestamp, AccountDisplayName, ActionType, Application, IPAddress, AdditionalFields`,
      },
      {
        table: "CloudProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName", "InitiatingProcessFileName"],
        kql: `CloudProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("waagent", "azure-vm-agent", "omiserver", "omsagent")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1059.006",
    name: "Python",
    tacticIds: ["TA0002"],
    description: "Adversaries abuse Python to execute arbitrary code, download payloads, and manipulate systems — particularly in cloud and Linux environments where Python is ubiquitous.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName", "InitiatingProcessFileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("python.exe", "python3.exe", "python3", "python")
| where ProcessCommandLine has_any (
    "-c ", "import os", "import subprocess", "socket", "base64",
    "requests", "urllib", "__import__", "exec(", "eval(")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName`,
      },
      {
        table: "CloudProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName"],
        kql: `CloudProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("python", "python3", "python2")
| where ProcessCommandLine has_any ("-c ", "import socket", "reverse_shell", "subprocess", "os.system")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
    ],
  },
  {
    id: "T1059.007",
    name: "JavaScript",
    tacticIds: ["TA0002"],
    description: "Adversaries use JavaScript via wscript.exe/cscript.exe (JScript) or Node.js to execute payloads. JScript is frequently used in phishing attachments to drop and execute second-stage malware.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "InitiatingProcessFileName", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where (FileName in~ ("wscript.exe", "cscript.exe") and ProcessCommandLine has_any (".js", ".jse", "//e:jscript"))
    or FileName in~ ("node.exe", "node")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName`,
      },
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "SHA256", "InitiatingProcessFileName"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where FileName endswith ".js" or FileName endswith ".jse"
| where ActionType == "FileCreated"
| where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\Downloads\\", "\\Public\\")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1059.009",
    name: "Cloud API",
    tacticIds: ["TA0002"],
    description: "Adversaries invoke cloud APIs — Azure Resource Manager, Microsoft Graph, AWS CLI, GCP SDK — to execute actions within cloud environments after obtaining credentials or tokens.",
    xdrMappings: [
      {
        table: "GraphApiAuditEvents",
        columns: ["ActionType", "ActorObjectId", "ActorIPAddress", "TargetObjectId", "AdditionalDetails"],
        kql: `GraphApiAuditEvents
| where Timestamp > ago(1d)
| summarize Actions = count(), Targets = dcount(TargetObjectId) by ActorObjectId, ActorIPAddress, bin(Timestamp, 1h)
| where Actions > 50
| order by Actions desc`,
      },
      {
        table: "CloudAuditEvents",
        columns: ["ActionType", "AccountDisplayName", "ResourceId", "AdditionalFields"],
        kql: `CloudAuditEvents
| where Timestamp > ago(1d)
| summarize Actions = count(), UniqueResources = dcount(ResourceId) by AccountDisplayName, bin(Timestamp, 1h)
| where Actions > 100
| order by Actions desc`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountDisplayName", "ActionType", "Application", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where Application in~ ("Microsoft Azure", "Azure Resource Manager", "Microsoft Graph")
| summarize Actions = count() by AccountDisplayName, Application, IPAddress, bin(Timestamp, 1h)
| where Actions > 100
| order by Actions desc`,
      },
    ],
  },
  {
    id: "T1203",
    name: "Exploitation for Client Execution",
    tacticIds: ["TA0002"],
    description: "Adversaries exploit client application vulnerabilities to execute arbitrary code — browser exploits, Office vulnerabilities, PDF reader bugs. The exploit triggers when a user opens a malicious document or visits a crafted page.",
    xdrMappings: [
      {
        table: "DeviceEvents",
        columns: ["DeviceName", "ActionType", "InitiatingProcessFileName", "AdditionalFields"],
        kql: `DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == "ExploitGuardExploitDetected"
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, AdditionalFields`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where AttackTechniques has "T1203"
    or Category == "Exploit"
    or Title has_any ("exploit", "CVE-", "use-after-free", "buffer overflow", "RCE")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },
  {
    id: "T1569.002",
    name: "Service Execution",
    tacticIds: ["TA0002"],
    description: "Adversaries create or abuse Windows services to execute malicious code — using sc.exe, PsExec, or direct API calls. Services run as SYSTEM by default, making this both an execution and privilege escalation vector.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName", "InitiatingProcessFileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "sc.exe"
| where ProcessCommandLine has_any ("create", "start", "binpath=", "config")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
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
    and ServicePath !startswith "C:\\Program Files"
| project Timestamp, DeviceName, ServiceName, ServicePath, InitiatingProcessFileName`,
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

  {
    id: "T1098",
    name: "Account Manipulation",
    tacticIds: ["TA0003", "TA0004"],
    description: "Adversaries manipulate accounts to maintain access or escalate privileges — adding accounts to privileged groups, modifying MFA methods, adding OAuth credentials to service principals, or changing account passwords.",
    xdrMappings: [
      {
        table: "IdentityDirectoryEvents",
        columns: ["AccountUpn", "ActionType", "TargetAccountUpn", "AdditionalFields", "DeviceName"],
        kql: `IdentityDirectoryEvents
| where Timestamp > ago(1d)
| where ActionType in (
    "Account added to group",
    "User account attributes modified",
    "Password reset",
    "Password changed")
| where AdditionalFields has_any ("Domain Admins", "Enterprise Admins", "Administrators", "Schema Admins")
    or ActionType == "Password reset"
| project Timestamp, AccountUpn, TargetAccountUpn, ActionType, AdditionalFields`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountDisplayName", "ActionType", "Application", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType in (
    "Update user",
    "Update StsRefreshTokenValidFrom Timestamp",
    "User registered security info",
    "User deleted security info",
    "Add service principal credentials")
| project Timestamp, AccountDisplayName, ActionType, Application, IPAddress`,
      },
      {
        table: "GraphApiAuditEvents",
        columns: ["ActionType", "ActorObjectId", "TargetObjectId", "ActorIPAddress", "AdditionalDetails"],
        kql: `GraphApiAuditEvents
| where Timestamp > ago(1d)
| where ActionType in (
    "Add member to role",
    "Add owner to service principal",
    "Add credentials to service principal")
| project Timestamp, ActionType, ActorObjectId, TargetObjectId, ActorIPAddress, AdditionalDetails`,
      },
    ],
  },
  {
    id: "T1197",
    name: "BITS Jobs",
    tacticIds: ["TA0003", "TA0005"],
    description: "Adversaries abuse Windows Background Intelligent Transfer Service (BITS) to download payloads, persist across reboots, and evade detection — BITS transfers look like legitimate Windows update activity.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName", "InitiatingProcessFileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "bitsadmin.exe"
| where ProcessCommandLine has_any ("/transfer", "/create", "/addfile", "/resume", "/complete")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteUrl", "RemoteIP", "InitiatingProcessFileName", "BytesSent"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName =~ "svchost.exe"
| where RemoteUrl has_any ("http://", "https://")
| summarize Downloads = count(), Hosts = make_set(RemoteUrl) by DeviceName, bin(Timestamp, 1h)
| where Downloads > 20
| order by Downloads desc`,
      },
    ],
  },
  {
    id: "T1505.003",
    name: "Web Shell",
    tacticIds: ["TA0003"],
    description: "Adversaries install web shells on internet-facing web servers (Exchange, IIS, SharePoint) to maintain persistent access and execute commands via HTTP requests. A key indicator is web server processes spawning unusual child processes.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "InitiatingProcessFileName", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe", "UMWorkerProcess.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "certutil.exe", "net.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine`,
      },
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "SHA256", "InitiatingProcessFileName"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "UMWorkerProcess.exe")
| where ActionType == "FileCreated"
| where FileName endswith ".aspx" or FileName endswith ".asp" or FileName endswith ".php" or FileName endswith ".jsp"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where AttackTechniques has "T1505"
    or Title has_any ("web shell", "webshell", "IIS", "Exchange exploit")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },

  {
    id: "T1098.001",
    name: "Additional Cloud Credentials",
    tacticIds: ["TA0003"],
    description: "Adversaries add credentials — passwords, certificates, or keys — to cloud service principals and applications to maintain persistent access even if the original user's credentials are rotated.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountDisplayName", "ActionType", "Application", "IPAddress", "AdditionalFields"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType in (
    "Add service principal credentials",
    "Update application – Certificates and secrets management",
    "Add password to service principal",
    "Add certificate to service principal")
| project Timestamp, AccountDisplayName, ActionType, Application, IPAddress, AdditionalFields`,
      },
      {
        table: "GraphApiAuditEvents",
        columns: ["ActionType", "ActorObjectId", "TargetObjectId", "ActorIPAddress", "AdditionalDetails"],
        kql: `GraphApiAuditEvents
| where Timestamp > ago(1d)
| where ActionType in ("Add credentials to service principal", "Update application")
| project Timestamp, ActionType, ActorObjectId, TargetObjectId, ActorIPAddress, AdditionalDetails`,
      },
    ],
  },
  {
    id: "T1098.002",
    name: "Additional Email Delegate Permissions",
    tacticIds: ["TA0003"],
    description: "Adversaries grant additional mailbox permissions to attacker-controlled accounts to read victim email without triggering forwarding rules — Add-MailboxPermission FullAccess is a common indicator.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountDisplayName", "ActionType", "Application", "ObjectName", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "Add-MailboxPermission",
    "Add delegate",
    "UpdateCalendarDelegation",
    "AddFolderPermissions")
| where Application == "Microsoft Exchange Online"
| project Timestamp, AccountDisplayName, ActionType, ObjectName, IPAddress`,
      },
    ],
  },
  {
    id: "T1098.003",
    name: "Additional Cloud Roles",
    tacticIds: ["TA0003"],
    description: "Adversaries assign high-privileged roles (Global Administrator, Exchange Administrator, etc.) to accounts they control to escalate privileges and maintain persistent access to cloud resources.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountDisplayName", "ActionType", "Application", "IPAddress", "AdditionalFields"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType in ("Add member to role", "Add user to role")
| where AdditionalFields has_any (
    "Global Administrator", "Privileged Role Administrator",
    "Exchange Administrator", "Security Administrator",
    "Application Administrator", "Cloud Application Administrator")
| project Timestamp, AccountDisplayName, ActionType, AdditionalFields, IPAddress`,
      },
      {
        table: "GraphApiAuditEvents",
        columns: ["ActionType", "ActorObjectId", "TargetObjectId", "ActorIPAddress", "AdditionalDetails"],
        kql: `GraphApiAuditEvents
| where Timestamp > ago(1d)
| where ActionType in ("Add member to role", "Add eligible member to role")
| project Timestamp, ActionType, ActorObjectId, TargetObjectId, ActorIPAddress, AdditionalDetails`,
      },
    ],
  },
  {
    id: "T1136.003",
    name: "Cloud Account",
    tacticIds: ["TA0003"],
    description: "Adversaries create cloud accounts — Entra ID users, service principals, or managed identities — as backdoors for persistent access.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountDisplayName", "ActionType", "Application", "IPAddress", "AdditionalFields"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType in ("Add user", "Create user", "Invite external user", "Add service principal")
| project Timestamp, AccountDisplayName, ActionType, Application, IPAddress, AdditionalFields`,
      },
      {
        table: "GraphApiAuditEvents",
        columns: ["ActionType", "ActorObjectId", "TargetObjectId", "ActorIPAddress", "AdditionalDetails"],
        kql: `GraphApiAuditEvents
| where Timestamp > ago(1d)
| where ActionType in ("Add user", "Add service principal", "Add application")
| project Timestamp, ActionType, ActorObjectId, TargetObjectId, ActorIPAddress, AdditionalDetails`,
      },
    ],
  },
  {
    id: "T1547.004",
    name: "Winlogon Helper DLL",
    tacticIds: ["TA0003", "TA0004"],
    description: "Adversaries modify Winlogon registry keys (Userinit, Shell, Notify) to load malicious DLLs on every user logon, achieving persistent execution with SYSTEM-level context.",
    xdrMappings: [
      {
        table: "DeviceRegistryEvents",
        columns: ["DeviceName", "RegistryKey", "RegistryValueName", "RegistryValueData", "InitiatingProcessFileName"],
        kql: `DeviceRegistryEvents
| where Timestamp > ago(1d)
| where RegistryKey has "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
| where RegistryValueName in ("Userinit", "Shell", "GinaDLL", "TaskMan")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1547.009",
    name: "Shortcut Modification",
    tacticIds: ["TA0003"],
    description: "Adversaries create or modify .lnk shortcut files — particularly in the Startup folder — to execute malicious code on user logon. Common delivery method for phishing attachments and post-compromise persistence.",
    xdrMappings: [
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "SHA256", "InitiatingProcessFileName", "ActionType"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where FileName endswith ".lnk"
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath has_any ("\\Startup\\", "\\Start Menu\\", "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1176",
    name: "Browser Extensions",
    tacticIds: ["TA0003"],
    description: "Adversaries install malicious browser extensions to steal credentials, intercept traffic, and maintain persistence. Extensions survive browser updates and are often overlooked by defenders.",
    xdrMappings: [
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "SHA256", "InitiatingProcessFileName", "ActionType"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileCreated"
| where FolderPath has_any (
    "\\Google\\Chrome\\User Data\\",
    "\\Microsoft\\Edge\\User Data\\",
    "\\Firefox\\Profiles\\",
    "\\Extensions\\")
| where FileName endswith ".crx" or FileName endswith ".xpi" or FileName == "manifest.json"
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1037.001",
    name: "Logon Script (Windows)",
    tacticIds: ["TA0003"],
    description: "Adversaries set logon scripts via the UserInitMprLogonScript registry value or Group Policy to execute code each time a user logs in.",
    xdrMappings: [
      {
        table: "DeviceRegistryEvents",
        columns: ["DeviceName", "RegistryKey", "RegistryValueName", "RegistryValueData", "InitiatingProcessFileName"],
        kql: `DeviceRegistryEvents
| where Timestamp > ago(1d)
| where RegistryKey has "Environment"
| where RegistryValueName == "UserInitMprLogonScript"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName`,
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

  {
    id: "T1068",
    name: "Exploitation for Privilege Escalation",
    tacticIds: ["TA0004"],
    description: "Adversaries exploit software vulnerabilities — kernel exploits, driver vulnerabilities, or local service bugs — to gain elevated privileges on a system. Often follows initial access via a low-privileged account.",
    xdrMappings: [
      {
        table: "DeviceEvents",
        columns: ["DeviceName", "ActionType", "InitiatingProcessFileName", "InitiatingProcessCommandLine", "AdditionalFields"],
        kql: `DeviceEvents
| where Timestamp > ago(1d)
| where ActionType in ("ExploitGuardNetworkProtectionBlocked", "ExploitGuardExploitDetected", "ControlFlowGuardViolation")
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, AdditionalFields`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where AttackTechniques has "T1068"
    or Title has_any ("privilege escalation", "kernel exploit", "elevation", "driver exploit")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
      {
        table: "DeviceTvmSoftwareVulnerabilities",
        columns: ["DeviceName", "CveId", "CvssScore", "SoftwareName", "SoftwareVersion", "VulnerabilitySeverityLevel"],
        kql: `DeviceTvmSoftwareVulnerabilities
| where VulnerabilitySeverityLevel in ("Critical", "High")
| where CvssScore >= 7.0
| summarize CVEs = make_set(CveId), Count = count() by DeviceName, SoftwareName
| order by Count desc`,
      },
    ],
  },

  {
    id: "T1134.001",
    name: "Token Impersonation / Theft",
    tacticIds: ["TA0004", "TA0005"],
    description: "Adversaries steal or impersonate access tokens from processes running under higher-privileged accounts to execute code in the context of those accounts. Tools like Incognito and token manipulation APIs are common.",
    xdrMappings: [
      {
        table: "DeviceEvents",
        columns: ["DeviceName", "ActionType", "InitiatingProcessFileName", "AdditionalFields"],
        kql: `DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == "OpenProcessApiCall"
| extend TargetProcess = tostring(parse_json(AdditionalFields).TargetProcessName)
| where TargetProcess in~ ("lsass.exe", "winlogon.exe", "services.exe", "svchost.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, TargetProcess, AdditionalFields`,
      },
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName", "InitiatingProcessFileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("Invoke-TokenManipulation", "incognito", "steal_token", "ImpersonateLoggedOnUser")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
    ],
  },
  {
    id: "T1134.002",
    name: "Create Process with Token",
    tacticIds: ["TA0004"],
    description: "Adversaries create new processes using stolen tokens — using CreateProcessWithTokenW or runas — to run code in the context of a higher-privileged user.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName", "InitiatingProcessFileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("runas /user:", "runas /savecred", "CreateProcessWithToken")
    or (InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe") and AccountName != "")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1548.005",
    name: "Temporary Elevated Cloud Access",
    tacticIds: ["TA0004"],
    description: "Adversaries abuse Privileged Identity Management (PIM) or Just-In-Time access features to temporarily elevate privileges in cloud environments, often activating roles that aren't normally assigned.",
    xdrMappings: [
      {
        table: "CloudAuditEvents",
        columns: ["ActionType", "AccountDisplayName", "ResourceId", "AdditionalFields"],
        kql: `CloudAuditEvents
| where Timestamp > ago(1d)
| where ActionType has_any (
    "Elevate access to manage all Azure subscriptions",
    "activateRole", "ActivatePIMRole",
    "Microsoft.Authorization/elevateAccess/action")
| project Timestamp, AccountDisplayName, ActionType, ResourceId, AdditionalFields`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountDisplayName", "ActionType", "Application", "IPAddress", "AdditionalFields"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType in (
    "Add member to role (PIM activation)",
    "PIM activation initiated",
    "PIM role activated",
    "Activate eligible assignment")
| project Timestamp, AccountDisplayName, ActionType, Application, IPAddress, AdditionalFields`,
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

  {
    id: "T1027",
    name: "Obfuscated Files or Information",
    tacticIds: ["TA0005"],
    description: "Adversaries obfuscate payloads and commands to evade signature detection — base64 encoding, XOR, string concatenation, compressed archives, and packed executables are all common techniques.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "InitiatingProcessFileName", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (
    "-EncodedCommand", "-enc ", "FromBase64String", "::FromBase64",
    "char(", "0x", "[Convert]::", "certutil -decode")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`,
      },
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "SHA256", "InitiatingProcessFileName"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileCreated"
| where FileName endswith ".bin" or FileName endswith ".dat" or FileName endswith ".tmp"
| where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\ProgramData\\")
| where InitiatingProcessFileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1070.004",
    name: "File Deletion",
    tacticIds: ["TA0005"],
    description: "Adversaries delete files — payloads, scripts, logs, and prefetch artifacts — to cover their tracks and remove evidence of compromise.",
    xdrMappings: [
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "InitiatingProcessFileName", "ActionType"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileDeleted"
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".ps1" or FileName endswith ".bat"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe", "svchost.exe", "TiWorker.exe")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName`,
      },
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (
    "del /f", "del /q", "rmdir /s", "Remove-Item -Force",
    "fsutil usn deletejournal", "wevtutil cl")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
    ],
  },
  {
    id: "T1112",
    name: "Modify Registry",
    tacticIds: ["TA0005"],
    description: "Adversaries modify the Windows registry to hide configuration data, disable security features, establish persistence, or store encoded payloads. Different from run-key persistence in that this covers general-purpose registry abuse for evasion.",
    xdrMappings: [
      {
        table: "DeviceRegistryEvents",
        columns: ["DeviceName", "RegistryKey", "RegistryValueName", "RegistryValueData", "InitiatingProcessFileName"],
        kql: `DeviceRegistryEvents
| where Timestamp > ago(1d)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has_any (
    "\\Policies\\System",
    "DisableTaskMgr",
    "DisableRegistryTools",
    "DisableCMD",
    "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1484",
    name: "Domain Policy Modification",
    tacticIds: ["TA0005", "TA0004"],
    description: "Adversaries modify Group Policy Objects or domain trust settings to weaken security controls, disable AV, deploy malware to all domain-joined systems, or escalate privileges across the domain.",
    xdrMappings: [
      {
        table: "IdentityDirectoryEvents",
        columns: ["AccountUpn", "ActionType", "AdditionalFields", "DeviceName"],
        kql: `IdentityDirectoryEvents
| where Timestamp > ago(1d)
| where ActionType in ("Group Policy Object Modification", "Domain trust modification", "Password Policy Modified")
| project Timestamp, AccountUpn, ActionType, AdditionalFields`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountDisplayName", "ActionType", "Application", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType in (
    "Set DirSync enabled",
    "Update domain",
    "Set federation settings on domain",
    "Update federation settings on domain")
| project Timestamp, AccountDisplayName, ActionType, Application, IPAddress`,
      },
    ],
  },

  {
    id: "T1070.003",
    name: "Clear Command History",
    tacticIds: ["TA0005"],
    description: "Adversaries clear PowerShell history, bash history, and other command-line logs to cover their tracks after executing commands.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (
    "Clear-History", "Set-PSReadLineOption -HistorySaveStyle SaveNothing",
    "del /f *ConsoleHost_history*", "Remove-Item.*history",
    "history -c", "cat /dev/null > ~/.bash_history")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
    ],
  },
  {
    id: "T1070.006",
    name: "Timestomp",
    tacticIds: ["TA0005"],
    description: "Adversaries modify file timestamps (creation, modification, access) to blend malicious files into the environment and evade forensic timeline analysis.",
    xdrMappings: [
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "InitiatingProcessFileName", "ActionType", "AdditionalFields"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileModified"
| where InitiatingProcessFileName !in~ ("svchost.exe", "TiWorker.exe", "MsMpEng.exe")
// Look for recently created executables with old timestamps
| extend FileCreateTime = tostring(parse_json(AdditionalFields).FileCreateTime)
| where isnotempty(FileCreateTime)
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, FileCreateTime`,
      },
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "ProcessCommandLine", "AccountName", "FileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("timestomp", "SetFileTime", "Touch-File", "(gi $_).CreationTime =")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
    ],
  },
  {
    id: "T1140",
    name: "Deobfuscate / Decode Files or Information",
    tacticIds: ["TA0005"],
    description: "Adversaries use tools like certutil, PowerShell, and built-in OS utilities to decode or decrypt obfuscated payloads after delivering them to the target system.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName", "InitiatingProcessFileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where (FileName =~ "certutil.exe" and ProcessCommandLine has_any ("-decode", "-decodehex", "-urlcache"))
    or ProcessCommandLine has_any (
        "[System.Convert]::FromBase64String",
        "[System.Text.Encoding]::UTF8.GetString",
        "Invoke-Expression [System.Convert]",
        "DecompressStream", "GzipStream")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`,
      },
    ],
  },
  {
    id: "T1202",
    name: "Indirect Command Execution",
    tacticIds: ["TA0005"],
    description: "Adversaries use trusted utilities to execute commands indirectly — forfiles, pcalua, bash (WSL), and similar — to bypass application whitelisting and script-block logging.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "InitiatingProcessFileName", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ (
    "forfiles.exe", "pcalua.exe", "bash.exe", "wsl.exe",
    "explorer.exe", "at.exe", "schtasks.exe")
| where ProcessCommandLine has_any ("/c", "-e ", "-c ", "cmd", "powershell", ".exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1578.002",
    name: "Create Cloud Instance",
    tacticIds: ["TA0005"],
    description: "Adversaries create new cloud compute instances to evade detection, establish C2 infrastructure, or move laterally through cloud environments — often in regions or subscriptions not normally used.",
    xdrMappings: [
      {
        table: "CloudAuditEvents",
        columns: ["ActionType", "AccountDisplayName", "ResourceId", "AdditionalFields"],
        kql: `CloudAuditEvents
| where Timestamp > ago(1d)
| where ActionType has_any (
    "Microsoft.Compute/virtualMachines/write",
    "CreateInstance", "RunInstances",
    "create virtual machine")
| project Timestamp, AccountDisplayName, ActionType, ResourceId, AdditionalFields`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountDisplayName", "ActionType", "Application", "IPAddress", "AdditionalFields"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType in ("Create virtual machine", "Create cloud instance", "Deploy VM")
| summarize VMsCreated = count() by AccountDisplayName, IPAddress, bin(Timestamp, 1h)
| where VMsCreated > 2
| order by VMsCreated desc`,
      },
    ],
  },
  {
    id: "T1578.003",
    name: "Delete Cloud Instance",
    tacticIds: ["TA0005"],
    description: "Adversaries delete cloud instances to cover their tracks after using them for malicious activity, removing evidence of the compromise.",
    xdrMappings: [
      {
        table: "CloudAuditEvents",
        columns: ["ActionType", "AccountDisplayName", "ResourceId", "AdditionalFields"],
        kql: `CloudAuditEvents
| where Timestamp > ago(1d)
| where ActionType has_any (
    "Microsoft.Compute/virtualMachines/delete",
    "TerminateInstances", "DeleteInstance",
    "delete virtual machine")
| project Timestamp, AccountDisplayName, ActionType, ResourceId, AdditionalFields`,
      },
    ],
  },
  {
    id: "T1207",
    name: "Rogue Domain Controller (DCShadow)",
    tacticIds: ["TA0005"],
    description: "Adversaries use DCShadow to register a rogue domain controller in AD replication and push arbitrary changes — modifying objects, escalating privileges — without generating standard DC event logs.",
    xdrMappings: [
      {
        table: "IdentityDirectoryEvents",
        columns: ["AccountUpn", "ActionType", "AdditionalFields", "DeviceName"],
        kql: `IdentityDirectoryEvents
| where Timestamp > ago(1d)
| where ActionType has_any ("Directory Service replication", "Replication access", "DrsAddEntry")
| where AdditionalFields has_any ("MS-DRSR", "DRSReplicaAdd", "DRSReplicaDel")
| project Timestamp, AccountUpn, ActionType, DeviceName, AdditionalFields`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where AttackTechniques has "T1207"
    or Title has_any ("DCShadow", "rogue domain controller", "unauthorized replication")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },
  {
    id: "T1553.002",
    name: "Code Signing",
    tacticIds: ["TA0005"],
    description: "Adversaries use code signing to sign malware with valid certificates, bypassing security controls that trust signed binaries. Stolen, purchased, or forged certificates are used.",
    xdrMappings: [
      {
        table: "DeviceFileCertificateInfo",
        columns: ["DeviceName", "SHA256", "Signer", "Issuer", "IsTrusted", "IsRootSignerMicrosoft", "CertificateSerialNumber"],
        kql: `DeviceFileCertificateInfo
| where Timestamp > ago(1d)
| where IsTrusted == true and IsRootSignerMicrosoft == false
| join kind=inner (
    DeviceFileEvents
    | where ActionType == "FileCreated"
    | where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\Downloads\\")
) on SHA256
| project Timestamp, DeviceName, SHA256, Signer, Issuer, FolderPath`,
      },
      {
        table: "DeviceImageLoadEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "SHA256", "IsSigned", "Signer"],
        kql: `DeviceImageLoadEvents
| where Timestamp > ago(1d)
| where IsSigned == true
| where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\ProgramData\\", "\\Users\\Public\\")
| where Signer !has "Microsoft"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, Signer`,
      },
    ],
  },
  {
    id: "T1564.001",
    name: "Hidden Files and Directories",
    tacticIds: ["TA0005"],
    description: "Adversaries mark files and directories as hidden to conceal tools and payloads from casual inspection.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (
    "attrib +h", "attrib +s", "SetFileAttributes.*Hidden",
    "$_.Attributes = 'Hidden'", "SetAttr.*hidden")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
    ],
  },
  {
    id: "T1564.003",
    name: "Hidden Window",
    tacticIds: ["TA0005"],
    description: "Adversaries hide process windows using -WindowStyle Hidden, SW_HIDE, or similar flags so that script execution is not visible to the logged-on user.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "InitiatingProcessFileName", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("-WindowStyle Hidden", "-w hidden", "-win hidden", "SW_HIDE", "ShowWindow(0)")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1550.001",
    name: "Application Access Token",
    tacticIds: ["TA0005", "TA0008"],
    description: "Adversaries use stolen OAuth tokens, service account tokens, or JWT tokens to authenticate to cloud services and APIs without needing passwords — bypassing MFA entirely.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountDisplayName", "ActionType", "Application", "IPAddress", "UserAgent"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType in (
    "Add OAuth2PermissionGrant",
    "Consent to application",
    "UserLoggedIn")
| summarize Logins = count(), IPs = make_set(IPAddress), UserAgents = make_set(UserAgent) by AccountDisplayName, Application
| where array_length(IPs) > 3 or array_length(UserAgents) > 4
| order by Logins desc`,
      },
      {
        table: "AADSignInEventsBeta",
        columns: ["AccountUpn", "IPAddress", "ClientAppUsed", "AppDisplayName", "IsDeviceCompliant"],
        kql: `AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ClientAppUsed in~ ("Browser", "Other clients", "Mobile Apps and Desktop clients")
| where IsDeviceCompliant != true
| where ErrorCode == 0
| summarize Locations = dcount(IPAddress) by AccountUpn, AppDisplayName, ClientAppUsed
| where Locations > 3
| order by Locations desc`,
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

  {
    id: "T1539",
    name: "Steal Web Session Cookie",
    tacticIds: ["TA0006"],
    description: "Adversaries steal session cookies from browsers or web applications to bypass authentication and MFA. AiTM proxies harvest tokens in real-time; malware and browser extensions exfiltrate stored cookies.",
    xdrMappings: [
      {
        table: "AADSignInEventsBeta",
        columns: ["AccountUpn", "IPAddress", "Country", "IsManaged", "SessionId", "UserAgent", "RiskLevelDuringSignIn"],
        kql: `AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ErrorCode == 0
// Replay: same account, different IP/country within short window
| summarize IPs = make_set(IPAddress), Countries = make_set(Country) by AccountUpn, bin(Timestamp, 1h)
| where array_length(IPs) > 2 or array_length(Countries) > 1
| order by array_length(Countries) desc`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountDisplayName", "ActionType", "IPAddress", "UserAgent", "Application"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType == "MailboxLogin"
// Sudden new UserAgent / IP after successful sign-in — token replay indicator
| summarize UserAgents = make_set(UserAgent), IPs = make_set(IPAddress) by AccountDisplayName, Application
| where array_length(UserAgents) > 3 or array_length(IPs) > 4
| order by array_length(IPs) desc`,
      },
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "InitiatingProcessFileName", "SHA256"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where FolderPath has_any ("\\User Data\\Default\\Cookies", "\\Firefox\\Profiles\\", "\\Edge\\User Data\\")
| where ActionType == "FileRead"
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe")
| project Timestamp, DeviceName, FolderPath, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1528",
    name: "Steal Application Access Token",
    tacticIds: ["TA0006"],
    description: "Adversaries steal OAuth access tokens and refresh tokens from applications, browsers, or the filesystem to access cloud resources without needing credentials — device code phishing is a common delivery vector.",
    xdrMappings: [
      {
        table: "AADSignInEventsBeta",
        columns: ["AccountUpn", "IPAddress", "ClientAppUsed", "AppDisplayName", "ErrorCode", "IsDeviceCompliant"],
        kql: `AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ClientAppUsed =~ "Azure Active Directory PowerShell"
    or ClientAppUsed has "device code"
    or AppDisplayName has_any ("Graph Explorer", "Azure PowerShell")
| where ErrorCode == 0
| where IsDeviceCompliant != true
| project Timestamp, AccountUpn, IPAddress, ClientAppUsed, AppDisplayName, IsDeviceCompliant`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountDisplayName", "ActionType", "Application", "IPAddress", "AdditionalFields"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType in (
    "Add OAuth2PermissionGrant",
    "Consent to application",
    "Add service principal")
| project Timestamp, AccountDisplayName, ActionType, Application, IPAddress, AdditionalFields`,
      },
      {
        table: "GraphApiAuditEvents",
        columns: ["ActionType", "ActorObjectId", "TargetObjectId", "ActorIPAddress", "AdditionalDetails"],
        kql: `GraphApiAuditEvents
| where Timestamp > ago(1d)
| where ActionType in ("Add delegated permission grant", "Update application")
| project Timestamp, ActionType, ActorObjectId, TargetObjectId, ActorIPAddress, AdditionalDetails`,
      },
    ],
  },
  {
    id: "T1557",
    name: "Adversary-in-the-Middle",
    tacticIds: ["TA0006", "TA0009"],
    description: "Adversaries position themselves between a user and a legitimate resource to intercept credentials and session tokens. AiTM (adversary-in-the-middle) phishing proxies real login pages, satisfying MFA while stealing the session cookie in real time.",
    xdrMappings: [
      {
        table: "AADSignInEventsBeta",
        columns: ["AccountUpn", "IPAddress", "Country", "UserAgent", "RiskLevelDuringSignIn", "IsAnonymousProxy"],
        kql: `AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ErrorCode == 0
| where RiskLevelDuringSignIn == "high" or IsAnonymousProxy == true
| join kind=inner (
    AADSignInEventsBeta
    | where Timestamp > ago(1d) and ErrorCode == 0
    | summarize SignInIPs = make_set(IPAddress) by AccountUpn
) on AccountUpn
| where array_length(SignInIPs) > 2
| project Timestamp, AccountUpn, IPAddress, Country, RiskLevelDuringSignIn, UserAgent`,
      },
      {
        table: "EmailEvents",
        columns: ["NetworkMessageId", "SenderFromAddress", "RecipientEmailAddress", "Subject", "DeliveryAction", "UrlCount"],
        kql: `EmailEvents
| where Timestamp > ago(7d)
| where DeliveryAction == "Delivered"
| where UrlCount > 0
// Look for evilginx/AiTM phishing kit domains: long subdomain, impersonating Microsoft
| join kind=inner (
    EmailUrlInfo
    | where UrlDomain matches regex @"^[a-z0-9-]{10,}\.(com|net|xyz|top|live)"
) on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, Url`,
      },
      {
        table: "IdentityLogonEvents",
        columns: ["AccountUpn", "ActionType", "Protocol", "IPAddress", "DeviceName"],
        kql: `IdentityLogonEvents
| where Timestamp > ago(1d)
| where Protocol == "NTLM"
| where ActionType == "LogonSuccess"
// NTLM relay: source IP differs from device IP
| summarize Targets = dcount(DeviceName), SourceIPs = make_set(IPAddress) by AccountUpn
| where Targets > 3
| order by Targets desc`,
      },
    ],
  },

  {
    id: "T1003.002",
    name: "Security Account Manager",
    tacticIds: ["TA0006"],
    description: "Adversaries dump the SAM database to extract local account NTLM hashes. Common tools include reg.exe, Mimikatz, and Volume Shadow Copy abuse.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where (FileName =~ "reg.exe" and ProcessCommandLine has_any ("save HKLM\\SAM", "save HKLM\\SYSTEM", "save HKLM\\SECURITY"))
    or ProcessCommandLine has_any ("sekurlsa::sam", "hashdump", "lsadump::sam")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
      {
        table: "DeviceRegistryEvents",
        columns: ["DeviceName", "RegistryKey", "ActionType", "InitiatingProcessFileName"],
        kql: `DeviceRegistryEvents
| where Timestamp > ago(1d)
| where RegistryKey has "SAM\\SAM\\Domains"
| where ActionType == "RegistryKeyQueried"
| where InitiatingProcessFileName !in~ ("lsass.exe", "svchost.exe", "services.exe")
| project Timestamp, DeviceName, RegistryKey, ActionType, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1003.003",
    name: "NTDS",
    tacticIds: ["TA0006"],
    description: "Adversaries dump the NTDS.dit Active Directory database to extract all domain account hashes. Methods include ntdsutil, volume shadow copy, and direct file copy with SYSTEM privileges.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "ntdsutil.exe"
    or ProcessCommandLine has_any (
        "ntdsutil", "activate instance ntds", "create full",
        "vssadmin create shadow /for=C:", "diskshadow /s")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "SHA256", "InitiatingProcessFileName"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where FileName in~ ("ntds.dit", "SYSTEM", "SECURITY")
| where ActionType in ("FileCopied", "FileRead")
| where FolderPath has_any ("\\Windows\\NTDS\\", "\\Temp\\", "\\AppData\\")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1003.006",
    name: "DCSync",
    tacticIds: ["TA0006"],
    description: "Adversaries mimic DC replication requests using MS-DRSR to extract credential material — including krbtgt hashes for Golden Ticket attacks — from Active Directory without requiring local access to a DC.",
    xdrMappings: [
      {
        table: "IdentityDirectoryEvents",
        columns: ["AccountUpn", "ActionType", "AdditionalFields", "DeviceName"],
        kql: `IdentityDirectoryEvents
| where Timestamp > ago(1d)
| where ActionType == "Directory Service replication"
| where AdditionalFields has_any ("MS-DRSR", "GetNCChanges", "DrsGetNCChanges")
// Flag non-DC source — legitimate replication only happens between DCs
| project Timestamp, AccountUpn, ActionType, DeviceName, AdditionalFields`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where AttackTechniques has "T1003.006"
    or Title has_any ("DCSync", "directory replication", "credential dumping")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },
  {
    id: "T1621",
    name: "Multi-Factor Authentication Request Generation",
    tacticIds: ["TA0006"],
    description: "Adversaries generate repeated MFA push notifications (MFA fatigue / MFA bombing) to overwhelm users into approving access. Often paired with a valid stolen password to trigger the MFA prompt.",
    xdrMappings: [
      {
        table: "AADSignInEventsBeta",
        columns: ["AccountUpn", "IPAddress", "ErrorCode", "RiskLevelDuringSignIn", "Country"],
        kql: `AADSignInEventsBeta
| where Timestamp > ago(1h)
// ErrorCode 500121 = MFA required, user hasn't completed; repeated = MFA fatigue
| where ErrorCode in (500121, 50074, 50076)
| summarize MFARequests = count() by AccountUpn, IPAddress, Country, bin(Timestamp, 10m)
| where MFARequests > 5
| order by MFARequests desc`,
      },
    ],
  },
  {
    id: "T1556.006",
    name: "Multi-Factor Authentication Modification",
    tacticIds: ["TA0006", "TA0005"],
    description: "Adversaries modify MFA configurations — registering attacker-controlled authenticators, deleting existing MFA methods, or disabling MFA policies — to gain persistent authentication access.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountDisplayName", "ActionType", "Application", "IPAddress", "AdditionalFields"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType in (
    "User registered security info",
    "User deleted security info",
    "Admin registered security info for user",
    "Update StsRefreshTokenValidFrom Timestamp",
    "User changed default security info")
| project Timestamp, AccountDisplayName, ActionType, Application, IPAddress, AdditionalFields`,
      },
      {
        table: "GraphApiAuditEvents",
        columns: ["ActionType", "ActorObjectId", "TargetObjectId", "ActorIPAddress", "AdditionalDetails"],
        kql: `GraphApiAuditEvents
| where Timestamp > ago(1d)
| where ActionType in (
    "Update authentication methods",
    "Delete authentication method",
    "Register authentication method")
| project Timestamp, ActionType, ActorObjectId, TargetObjectId, ActorIPAddress, AdditionalDetails`,
      },
    ],
  },
  {
    id: "T1606.002",
    name: "SAML Token Forgery",
    tacticIds: ["TA0006"],
    description: "Adversaries forge SAML tokens using stolen signing certificates (Golden SAML) to authenticate as any user without credentials. Requires compromise of AD FS or similar federation infrastructure.",
    xdrMappings: [
      {
        table: "AADSignInEventsBeta",
        columns: ["AccountUpn", "IPAddress", "Country", "AuthenticationRequirement", "ConditionalAccessStatus", "UserAgent"],
        kql: `AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ErrorCode == 0
| where AuthenticationRequirement == "singleFactorAuthentication"
// SAML assertions bypass MFA — look for federated logins without MFA
| where ConditionalAccessStatus == "notApplied"
| project Timestamp, AccountUpn, IPAddress, Country, AuthenticationRequirement, ConditionalAccessStatus`,
      },
      {
        table: "IdentityLogonEvents",
        columns: ["AccountUpn", "ActionType", "Protocol", "IPAddress", "DeviceName"],
        kql: `IdentityLogonEvents
| where Timestamp > ago(1d)
| where Protocol in ("SAML", "WS-Fed")
| where ActionType == "LogonSuccess"
| summarize Logins = count(), SourceIPs = make_set(IPAddress) by AccountUpn, bin(Timestamp, 1h)
| where array_length(SourceIPs) > 2
| order by Logins desc`,
      },
    ],
  },
  {
    id: "T1555.003",
    name: "Credentials from Web Browsers",
    tacticIds: ["TA0006"],
    description: "Adversaries extract saved credentials from browser password stores — Chrome's Login Data SQLite database, Edge, Firefox — to harvest plaintext usernames and passwords.",
    xdrMappings: [
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "InitiatingProcessFileName", "ActionType"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileRead"
| where (FolderPath has "Google\\Chrome\\User Data\\Default" and FileName == "Login Data")
    or (FolderPath has "Microsoft\\Edge\\User Data\\Default" and FileName == "Login Data")
    or (FolderPath has "Firefox\\Profiles\\" and FileName in ("logins.json", "key4.db", "key3.db"))
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1552.001",
    name: "Credentials in Files",
    tacticIds: ["TA0006"],
    description: "Adversaries search files for stored credentials — unattended installation files, scripts, config files, PowerShell history — that contain plaintext passwords.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "ProcessCommandLine", "AccountName", "FileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (
    "findstr /s password", "findstr /i pass", "Select-String -Pattern pass",
    "grep -r password", "grep -ri passwd",
    "dir /s *pass*", "dir /s *cred*", "dir /s *vnc*")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "InitiatingProcessFileName"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileRead"
| where FileName in~ ("unattend.xml", "sysprep.xml", "web.config", "appsettings.json", "credentials.xml", ".env")
    or FileName has_any ("password", "credential", "passwd", "secret")
| where InitiatingProcessFileName !in~ ("svchost.exe", "MsMpEng.exe")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1552.004",
    name: "Private Keys",
    tacticIds: ["TA0006"],
    description: "Adversaries search for and exfiltrate private key files (.pem, .pfx, .p12, .key) for code signing, SSH authentication, or decrypting captured data.",
    xdrMappings: [
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "InitiatingProcessFileName", "ActionType"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where FileName endswith ".pem" or FileName endswith ".pfx"
    or FileName endswith ".p12" or FileName endswith ".key"
    or FileName endswith ".ppk" or FileName endswith ".jks"
| where ActionType in ("FileRead", "FileCopied")
| where InitiatingProcessFileName !in~ ("svchost.exe", "MsMpEng.exe", "certmgr.exe")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1040",
    name: "Network Sniffing",
    tacticIds: ["TA0006", "TA0007"],
    description: "Adversaries run network sniffing tools to capture credentials and other data passing over the network in plaintext. WinPcap-based tools are detected via process and image load telemetry.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("Wireshark.exe", "tshark.exe", "windump.exe", "tcpdump", "dumpcap.exe", "pktmon.exe", "rawcap.exe")
    or ProcessCommandLine has_any ("-i ", "/pcap", "promiscuous")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`,
      },
      {
        table: "DeviceImageLoadEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "SHA256", "InitiatingProcessFileName"],
        kql: `DeviceImageLoadEvents
| where Timestamp > ago(1d)
| where FileName in~ ("wpcap.dll", "packet.dll", "npcap.dll", "NPcap.sys")
| where InitiatingProcessFileName !in~ ("Wireshark.exe", "dumpcap.exe")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1187",
    name: "Forced Authentication",
    tacticIds: ["TA0006"],
    description: "Adversaries force systems to authenticate to attacker-controlled servers to capture NTLM hashes — via UNC path injection in documents, responder tools, or specially crafted links.",
    xdrMappings: [
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteIP", "RemotePort", "InitiatingProcessFileName", "ActionType"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort in (445, 139)
| where ActionType == "ConnectionRequest"
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168." and RemoteIP !startswith "172."
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName`,
      },
      {
        table: "IdentityLogonEvents",
        columns: ["AccountUpn", "ActionType", "Protocol", "IPAddress", "DeviceName", "FailureReason"],
        kql: `IdentityLogonEvents
| where Timestamp > ago(1d)
| where Protocol == "NTLM"
| where ActionType == "LogonFailed"
| where FailureReason has_any ("Unknown user", "Bad password")
// Many NTLM failures to external IPs = likely coerced auth
| summarize Failures = count() by DeviceName, IPAddress
| where Failures > 5
| order by Failures desc`,
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

  {
    id: "T1057",
    name: "Process Discovery",
    tacticIds: ["TA0007"],
    description: "Adversaries enumerate running processes to identify security tools, understand the environment, find targets for injection, or determine what AV/EDR is present.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName", "InitiatingProcessFileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("tasklist", "Get-Process", "ps aux", "wmic process", "qprocess")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1083",
    name: "File and Directory Discovery",
    tacticIds: ["TA0007"],
    description: "Adversaries enumerate files and directories to find sensitive data, configuration files, credentials, and staged payloads.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (
    "dir /s", "dir /b", "Get-ChildItem", "ls -la", "find / -name",
    "tree /f", "dir C:\\Users", "dir C:\\Windows\\System32")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
    ],
  },
  {
    id: "T1135",
    name: "Network Share Discovery",
    tacticIds: ["TA0007"],
    description: "Adversaries enumerate network shares to find accessible file stores, understand the network topology, and identify targets for lateral movement or data collection.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("net share", "net view", "Get-SmbShare", "Get-WmiObject Win32_Share", "showmount")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteIP", "RemotePort", "ActionType", "InitiatingProcessFileName"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort in (139, 445)
| where ActionType == "ConnectionRequest"
| summarize ShareTargets = dcount(RemoteIP) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 10m)
| where ShareTargets > 5
| order by ShareTargets desc`,
      },
    ],
  },
  {
    id: "T1526",
    name: "Cloud Service Discovery",
    tacticIds: ["TA0007"],
    description: "Adversaries enumerate cloud services, tenants, subscriptions, and resources after obtaining cloud credentials — mapping out the environment before moving laterally or exfiltrating data.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountDisplayName", "ActionType", "Application", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType in (
    "ListKeys", "Get Storage Account", "List Subscriptions",
    "Get Tenant", "List Role Assignments", "ListSecrets")
| summarize Actions = count(), Apps = make_set(Application) by AccountDisplayName, IPAddress, bin(Timestamp, 1h)
| where Actions > 20
| order by Actions desc`,
      },
      {
        table: "GraphApiAuditEvents",
        columns: ["ActionType", "ActorObjectId", "TargetObjectId", "ActorIPAddress", "AdditionalDetails"],
        kql: `GraphApiAuditEvents
| where Timestamp > ago(1d)
| where ActionType in ("Get application", "List service principals", "List directory roles", "List users")
| summarize Count = count() by ActorObjectId, ActorIPAddress, ActionType, bin(Timestamp, 1h)
| where Count > 30
| order by Count desc`,
      },
    ],
  },

  {
    id: "T1482",
    name: "Domain Trust Discovery",
    tacticIds: ["TA0007"],
    description: "Adversaries enumerate domain trust relationships to identify paths for lateral movement across domains and forests — nltest, Get-ADTrust, and LDAP queries against trustedDomain objects.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "ProcessCommandLine", "AccountName", "FileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (
    "nltest /domain_trusts", "nltest /trusted_domains",
    "Get-ADTrust", "netdom query trust",
    "([System.DirectoryServices.ActiveDirectory.Domain])")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
      {
        table: "IdentityQueryEvents",
        columns: ["AccountUpn", "QueryType", "QueryTarget", "Protocol", "DeviceName"],
        kql: `IdentityQueryEvents
| where Timestamp > ago(1d)
| where QueryType == "AllDomains" or QueryTarget has "trustedDomain"
| project Timestamp, AccountUpn, QueryType, QueryTarget, Protocol, DeviceName`,
      },
    ],
  },
  {
    id: "T1049",
    name: "System Network Connections Discovery",
    tacticIds: ["TA0007"],
    description: "Adversaries enumerate active network connections to identify lateral movement paths, C2 channels, and services running on the host.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "ProcessCommandLine", "AccountName", "FileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (
    "netstat", "Get-NetTCPConnection", "Get-NetUDPEndpoint",
    "ss -", "lsof -i", "net session")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
    ],
  },
  {
    id: "T1033",
    name: "System Owner / User Discovery",
    tacticIds: ["TA0007"],
    description: "Adversaries enumerate current user context and logged-on users to understand privilege levels and identify targets for escalation.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "ProcessCommandLine", "AccountName", "FileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (
    "whoami", "query user", "quser", "qwinsta",
    "Get-LocalUser", "net user", "id ", "w ")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
    ],
  },
  {
    id: "T1007",
    name: "System Service Discovery",
    tacticIds: ["TA0007"],
    description: "Adversaries enumerate running services to identify security software, find services to tamper with, or understand the host's role.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "ProcessCommandLine", "AccountName", "FileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (
    "sc query", "sc queryex", "net start",
    "Get-Service", "tasklist /svc", "wmic service",
    "systemctl list-units")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
    ],
  },
  {
    id: "T1046",
    name: "Network Service Discovery",
    tacticIds: ["TA0007"],
    description: "Adversaries scan the network to identify open ports and services — mapping the environment for lateral movement targets.",
    xdrMappings: [
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteIP", "RemotePort", "ActionType", "InitiatingProcessFileName"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1h)
| where ActionType in ("ConnectionRequest", "ConnectionFailed")
| summarize Ports = dcount(RemotePort), Hosts = dcount(RemoteIP) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)
| where Ports > 10 or Hosts > 15
| order by Ports desc`,
      },
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "ProcessCommandLine", "AccountName", "FileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("nmap", "masscan", "zmap", "netscan.exe", "portscan.exe", "advanced_ip_scanner.exe")
    or ProcessCommandLine has_any ("nmap ", "masscan ", "-sV ", "-p 80,443,445")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
    ],
  },
  {
    id: "T1012",
    name: "Query Registry",
    tacticIds: ["TA0007"],
    description: "Adversaries query the Windows registry to gather system configuration information — installed software, OS settings, stored credentials, and persistence mechanisms.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "ProcessCommandLine", "AccountName", "FileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "reg.exe"
| where ProcessCommandLine has "query"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
      {
        table: "DeviceRegistryEvents",
        columns: ["DeviceName", "RegistryKey", "ActionType", "InitiatingProcessFileName"],
        kql: `DeviceRegistryEvents
| where Timestamp > ago(1d)
| where ActionType == "RegistryKeyQueried"
| summarize QueryCount = count(), Keys = make_set(RegistryKey) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)
| where QueryCount > 100
| order by QueryCount desc`,
      },
    ],
  },
  {
    id: "T1016",
    name: "System Network Configuration Discovery",
    tacticIds: ["TA0007"],
    description: "Adversaries enumerate network configuration — IP addresses, DNS settings, routing tables, network adapters — to understand the environment.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "ProcessCommandLine", "AccountName", "FileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (
    "ipconfig", "route print", "netsh interface",
    "arp -a", "nbtstat", "Get-NetIPAddress",
    "Get-NetRoute", "Get-DnsClientCache")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
    ],
  },
  {
    id: "T1580",
    name: "Cloud Infrastructure Discovery",
    tacticIds: ["TA0007"],
    description: "Adversaries enumerate cloud infrastructure — virtual machines, storage accounts, databases, network configurations — after obtaining cloud credentials, mapping the environment for further exploitation.",
    xdrMappings: [
      {
        table: "CloudAuditEvents",
        columns: ["ActionType", "AccountDisplayName", "ResourceId", "AdditionalFields"],
        kql: `CloudAuditEvents
| where Timestamp > ago(1d)
| where ActionType has_any (
    "list", "List", "Get-Az", "describe-instances",
    "DescribeInstances", "Microsoft.Resources/subscriptions/resourceGroups/read")
| summarize Actions = count(), Resources = dcount(ResourceId) by AccountDisplayName, bin(Timestamp, 1h)
| where Actions > 50
| order by Actions desc`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountDisplayName", "ActionType", "Application", "IPAddress", "AdditionalFields"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType in (
    "List virtual machines", "Get resource groups",
    "List storage accounts", "Get subscriptions")
| project Timestamp, AccountDisplayName, ActionType, Application, IPAddress`,
      },
    ],
  },
  {
    id: "T1538",
    name: "Cloud Service Dashboard",
    tacticIds: ["TA0007"],
    description: "Adversaries log in to cloud management portals (Azure Portal, AWS Console, GCP Console) via browser to enumerate and manage cloud resources after stealing credentials.",
    xdrMappings: [
      {
        table: "AADSignInEventsBeta",
        columns: ["AccountUpn", "IPAddress", "Country", "AppDisplayName", "IsDeviceCompliant", "RiskLevelDuringSignIn"],
        kql: `AADSignInEventsBeta
| where Timestamp > ago(1d)
| where AppDisplayName in ("Azure Portal", "Microsoft Azure", "Azure Active Directory")
| where ErrorCode == 0
| where IsDeviceCompliant != true or RiskLevelDuringSignIn in ("medium", "high")
| project Timestamp, AccountUpn, IPAddress, Country, AppDisplayName, RiskLevelDuringSignIn`,
      },
    ],
  },
  {
    id: "T1619",
    name: "Cloud Storage Object Discovery",
    tacticIds: ["TA0007"],
    description: "Adversaries enumerate cloud storage — Azure Blob containers, S3 buckets, SharePoint document libraries — to identify data stores worth exfiltrating.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountDisplayName", "ActionType", "Application", "ObjectName", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType in (
    "List blobs", "ListObjects", "GetBucketLocation",
    "FilePreviewed", "FolderVisited")
| summarize Listings = count(), Containers = dcount(ObjectName) by AccountDisplayName, Application, IPAddress, bin(Timestamp, 1h)
| where Listings > 50
| order by Listings desc`,
      },
      {
        table: "CloudAuditEvents",
        columns: ["ActionType", "AccountDisplayName", "ResourceId", "AdditionalFields"],
        kql: `CloudAuditEvents
| where Timestamp > ago(1d)
| where ActionType has_any ("ListContainers", "ListBuckets", "Get-AzStorageContainer", "List Blobs")
| project Timestamp, AccountDisplayName, ActionType, ResourceId`,
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

  {
    id: "T1021.006",
    name: "Windows Remote Management",
    tacticIds: ["TA0008"],
    description: "Adversaries use Windows Remote Management (WinRM/WSMan) to execute commands on remote systems. WinRM is enabled by default on servers and is a common target for lateral movement after credential theft.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName", "InitiatingProcessFileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName =~ "wsmprovhost.exe"
| where FileName !in~ ("conhost.exe", "WerFault.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`,
      },
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteIP", "RemotePort", "ActionType", "InitiatingProcessFileName"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort in (5985, 5986)   // WinRM HTTP / HTTPS
| where ActionType == "ConnectionSuccess"
| summarize Targets = dcount(RemoteIP) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| order by Targets desc`,
      },
      {
        table: "DeviceLogonEvents",
        columns: ["DeviceName", "AccountName", "LogonType", "RemoteIP", "ActionType"],
        kql: `DeviceLogonEvents
| where Timestamp > ago(1d)
| where LogonType == 3
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168."
| where ActionType == "LogonSuccess"
| summarize Hosts = dcount(DeviceName) by AccountName, RemoteIP
| where Hosts > 3
| order by Hosts desc`,
      },
    ],
  },
  {
    id: "T1550.003",
    name: "Pass the Ticket",
    tacticIds: ["TA0008"],
    description: "Adversaries use Kerberos tickets (TGTs or service tickets) stolen from memory or forged via Golden/Silver ticket attacks to authenticate to services without needing the account's password.",
    xdrMappings: [
      {
        table: "IdentityLogonEvents",
        columns: ["AccountUpn", "ActionType", "Protocol", "IPAddress", "DeviceName", "FailureReason"],
        kql: `IdentityLogonEvents
| where Timestamp > ago(1d)
| where Protocol == "Kerberos"
| where ActionType == "LogonSuccess"
| summarize Targets = dcount(DeviceName), SourceIPs = make_set(IPAddress) by AccountUpn
| where Targets > 5 or array_length(SourceIPs) > 3
| order by Targets desc`,
      },
      {
        table: "IdentityDirectoryEvents",
        columns: ["AccountUpn", "ActionType", "AdditionalFields", "DeviceName"],
        kql: `IdentityDirectoryEvents
| where Timestamp > ago(1d)
| where ActionType == "Kerberos authentication failed"
| extend FailureCode = tostring(parse_json(AdditionalFields).FailureCode)
| where FailureCode in ("0x18", "0x25", "0x26")  // bad ticket, skew, replay
| summarize Failures = count() by AccountUpn, DeviceName, bin(Timestamp, 5m)
| where Failures > 5
| order by Failures desc`,
      },
    ],
  },

  {
    id: "T1021.003",
    name: "Distributed Component Object Model",
    tacticIds: ["TA0008"],
    description: "Adversaries abuse DCOM to execute code on remote systems using protocols that traverse firewalls. MMC20.Application, ShellWindows, and ShellBrowserWindow are commonly abused.",
    xdrMappings: [
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteIP", "RemotePort", "InitiatingProcessFileName", "ActionType"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort == 135
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName in~ ("mmc.exe", "mshta.exe", "svchost.exe", "powershell.exe")
| project Timestamp, DeviceName, RemoteIP, InitiatingProcessFileName`,
      },
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName", "InitiatingProcessFileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName =~ "svchost.exe"
| where FileName !in~ ("conhost.exe", "WerFault.exe", "werfault.exe", "DllHost.exe")
| where ProcessCommandLine has_any ("MMC20.Application", "ShellWindows", "ShellBrowserWindow", "-dcom")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`,
      },
    ],
  },
  {
    id: "T1021.004",
    name: "SSH",
    tacticIds: ["TA0008"],
    description: "Adversaries use SSH for lateral movement — authenticating with stolen keys or credentials. Native Windows SSH (OpenSSH) and third-party clients like PuTTY are both used.",
    xdrMappings: [
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteIP", "RemotePort", "InitiatingProcessFileName", "ActionType"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort == 22
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName !in~ ("svchost.exe", "ssh-agent.exe")
| summarize Targets = dcount(RemoteIP) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| order by Targets desc`,
      },
      {
        table: "DeviceLogonEvents",
        columns: ["DeviceName", "AccountName", "LogonType", "RemoteIP", "ActionType"],
        kql: `DeviceLogonEvents
| where Timestamp > ago(1d)
| where LogonType == 3
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168."
| where ActionType == "LogonSuccess"
| summarize Hosts = dcount(DeviceName) by AccountName, RemoteIP
| where Hosts > 3
| order by Hosts desc`,
      },
    ],
  },
  {
    id: "T1021.007",
    name: "Cloud Services",
    tacticIds: ["TA0008"],
    description: "Adversaries move laterally by logging into cloud services and resources using stolen credentials or tokens — accessing cloud VMs, storage, email, or services in adjacent tenants.",
    xdrMappings: [
      {
        table: "AADSignInEventsBeta",
        columns: ["AccountUpn", "IPAddress", "AppDisplayName", "Country", "IsAnonymousProxy", "RiskLevelDuringSignIn"],
        kql: `AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ErrorCode == 0
| summarize Apps = dcount(AppDisplayName), IPs = make_set(IPAddress) by AccountUpn, bin(Timestamp, 1h)
| where Apps > 5 or array_length(IPs) > 3
| order by Apps desc`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountDisplayName", "ActionType", "Application", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType == "UserLoggedIn"
// Lateral movement: same account accessing many different apps from unusual IPs
| summarize Apps = dcount(Application), IPs = dcount(IPAddress) by AccountDisplayName, bin(Timestamp, 1h)
| where Apps > 5 or IPs > 3
| order by Apps desc`,
      },
    ],
  },
  {
    id: "T1534",
    name: "Internal Spearphishing",
    tacticIds: ["TA0008"],
    description: "Adversaries use a compromised account to send phishing messages internally — via email or Teams — to other employees, leveraging the trust of an internal sender to bypass defences.",
    xdrMappings: [
      {
        table: "EmailEvents",
        columns: ["SenderFromAddress", "RecipientEmailAddress", "Subject", "DeliveryAction", "NetworkMessageId"],
        kql: `EmailEvents
| where Timestamp > ago(7d)
// Internal sender (same domain) delivering with malicious indicators
| where SenderFromDomain == "<your_domain>"
| where DeliveryAction in ("Delivered", "DeliveredAsSpam")
| where AttachmentCount > 0 or UrlCount > 0
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, NetworkMessageId`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountDisplayName", "ActionType", "Application", "ObjectName", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType in ("MessageSent", "ChatMessageSent")
| where ObjectName has_any ("http://", "https://", "attachment", ".exe", ".ps1")
| project Timestamp, AccountDisplayName, ActionType, ObjectName, IPAddress`,
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

  {
    id: "T1530",
    name: "Data from Cloud Storage Object",
    tacticIds: ["TA0009"],
    description: "Adversaries access data stored in cloud storage buckets, Azure Blob Storage, or SharePoint/OneDrive to collect sensitive files without touching endpoint storage.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountDisplayName", "ActionType", "Application", "ObjectName", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business", "Azure Storage")
| where ActionType in ("FileDownloaded", "FileCopied", "FileAccessed", "GetBlob")
| summarize Downloads = count(), Files = make_set(ObjectName) by AccountDisplayName, IPAddress, bin(Timestamp, 1h)
| where Downloads > 100
| order by Downloads desc`,
      },
    ],
  },

  {
    id: "T1005",
    name: "Data from Local System",
    tacticIds: ["TA0009"],
    description: "Adversaries collect sensitive files directly from local system storage — documents, database files, config files — prior to exfiltration.",
    xdrMappings: [
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "InitiatingProcessFileName", "ActionType"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileCopied", "FileRead")
| where FolderPath has_any ("\\Documents\\", "\\Desktop\\", "\\Downloads\\", "\\OneDrive\\")
| where FileName endswith ".docx" or FileName endswith ".xlsx" or FileName endswith ".pdf"
    or FileName endswith ".pst" or FileName endswith ".csv" or FileName endswith ".kdbx"
| where InitiatingProcessFileName !in~ (
    "winword.exe", "excel.exe", "acrobat.exe", "MsMpEng.exe", "SearchIndexer.exe")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1039",
    name: "Data from Network Shared Drive",
    tacticIds: ["TA0009"],
    description: "Adversaries collect files from network shares — file servers, NAS devices, SharePoint mapped drives — prior to exfiltration.",
    xdrMappings: [
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "InitiatingProcessFileName", "ActionType"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where FolderPath startswith "\\\\"   // UNC path = network share
| where ActionType in ("FileCopied", "FileRead")
| summarize FileCount = count(), Files = make_set(FileName) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where FileCount > 50
| order by FileCount desc`,
      },
    ],
  },
  {
    id: "T1114.001",
    name: "Local Email Collection",
    tacticIds: ["TA0009"],
    description: "Adversaries collect email data from local PST/OST files or mail client databases, often before or after exfiltrating to a remote location.",
    xdrMappings: [
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "SHA256", "InitiatingProcessFileName", "ActionType"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where FileName endswith ".pst" or FileName endswith ".ost" or FileName endswith ".mbox"
| where ActionType in ("FileCopied", "FileRead", "FileCreated")
| where InitiatingProcessFileName !in~ ("outlook.exe", "MsMpEng.exe")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1114.003",
    name: "Email Forwarding Rule",
    tacticIds: ["TA0009"],
    description: "Adversaries create email forwarding rules to silently redirect all incoming email to an external attacker-controlled address — a critical BEC indicator that persists after password resets.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountDisplayName", "ActionType", "Application", "ObjectName", "IPAddress", "AdditionalFields"],
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Exchange Online"
| where ActionType in (
    "New-InboxRule", "Set-InboxRule",
    "UpdateInboxRules", "Set-Mailbox")
| where AdditionalFields has_any (
    "ForwardTo", "ForwardAsAttachmentTo",
    "RedirectTo", "DeleteMessage")
| project Timestamp, AccountDisplayName, ActionType, AdditionalFields, IPAddress`,
      },
    ],
  },
  {
    id: "T1074.001",
    name: "Local Data Staging",
    tacticIds: ["TA0009"],
    description: "Adversaries stage collected data in a local directory before exfiltration — compressing and archiving files in Temp, AppData, or ProgramData to prepare for exfil.",
    xdrMappings: [
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "FileSize", "InitiatingProcessFileName", "ActionType"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileCreated", "FileCopied")
| where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\ProgramData\\", "\\Users\\Public\\")
| where FileName endswith ".zip" or FileName endswith ".rar" or FileName endswith ".7z" or FileName endswith ".tar"
| project Timestamp, DeviceName, FileName, FolderPath, FileSize, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1119",
    name: "Automated Collection",
    tacticIds: ["TA0009"],
    description: "Adversaries use scripts or automated tools to collect large volumes of files, emails, or cloud data systematically — often using PowerShell, Python, or cloud CLI tools.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "ProcessCommandLine", "AccountName", "FileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (
    "Get-ChildItem -Recurse", "robocopy /e", "xcopy /s",
    "tar -czf", "zip -r", "dir /s /b")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "InitiatingProcessFileName", "ActionType"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType == "FileCopied"
| summarize FilesAccessed = count() by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)
| where FilesAccessed > 100
| order by FilesAccessed desc`,
      },
    ],
  },
  {
    id: "T1213.003",
    name: "Code Repositories",
    tacticIds: ["TA0009"],
    description: "Adversaries access code repositories (Azure DevOps, GitHub, GitLab) to collect proprietary source code, credentials stored in code, and infrastructure-as-code secrets.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountDisplayName", "ActionType", "Application", "ObjectName", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where Application in~ ("Azure DevOps", "GitHub", "GitLab", "Bitbucket")
| where ActionType in ("Clone repository", "Download", "FileDownloaded", "Git clone")
| summarize Actions = count() by AccountDisplayName, Application, IPAddress, bin(Timestamp, 1h)
| where Actions > 10
| order by Actions desc`,
      },
    ],
  },
  {
    id: "T1025",
    name: "Data from Removable Media",
    tacticIds: ["TA0009"],
    description: "Adversaries collect data from removable media — USB drives, optical discs — that may contain sensitive files from air-gapped or isolated systems.",
    xdrMappings: [
      {
        table: "DeviceEvents",
        columns: ["DeviceName", "ActionType", "AdditionalFields", "InitiatingProcessFileName"],
        kql: `DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "UsbDriveMounted"
| project Timestamp, DeviceName, ActionType, AdditionalFields`,
      },
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "InitiatingProcessFileName", "ActionType"],
        kql: `DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath matches regex @"^[D-Z]:\\"
| where ActionType == "FileCopied"
| summarize FileCount = count() by DeviceName, InitiatingProcessFileName, bin(Timestamp, 30m)
| where FileCount > 20
| order by FileCount desc`,
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

  {
    id: "T1219",
    name: "Remote Access Software",
    tacticIds: ["TA0011"],
    description: "Adversaries install or abuse legitimate remote access tools (AnyDesk, TeamViewer, ScreenConnect, Atera, Ngrok) to maintain persistent access and blend in with legitimate IT activity.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName", "SHA256"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("anydesk.exe", "teamviewer.exe", "screenconnect.exe", "rutserv.exe",
    "atera_agent.exe", "ngrok.exe", "ncat.exe", "frpc.exe", "chisel.exe")
    or ProcessCommandLine has_any ("anydesk", "teamviewer", "splashtop", "screenconnect", "ngrok")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256`,
      },
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteUrl", "RemoteIP", "RemotePort", "InitiatingProcessFileName"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteUrl has_any ("anydesk.com", "teamviewer.com", "screenconnect.com", "ngrok.io", "ngrok.com")
    or InitiatingProcessFileName in~ ("anydesk.exe", "teamviewer.exe", "ngrok.exe", "frpc.exe")
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1572",
    name: "Protocol Tunneling",
    tacticIds: ["TA0011"],
    description: "Adversaries encapsulate C2 traffic within legitimate protocols — SSH tunneling, DNS-over-HTTPS, ICMP tunneling, or wrapping traffic in WebSockets — to evade network detection.",
    xdrMappings: [
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteIP", "RemotePort", "RemoteUrl", "InitiatingProcessFileName", "BytesSent"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("ssh.exe", "plink.exe", "chisel.exe", "iodine.exe", "dnscat2.exe", "ngrok.exe")
    or (RemotePort == 22 and InitiatingProcessFileName !in~ ("svchost.exe", "winscp.exe"))
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName`,
      },
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("ssh -L", "ssh -R", "ssh -D", "-localforward", "-remoteforward", "chisel", "iodine")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
    ],
  },

  {
    id: "T1071.002",
    name: "File Transfer Protocols (C2)",
    tacticIds: ["TA0011"],
    description: "Adversaries use file transfer protocols — FTP, SFTP, SCP, FTPS — as C2 channels, leveraging their legitimacy to avoid detection.",
    xdrMappings: [
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteIP", "RemotePort", "InitiatingProcessFileName", "BytesSent"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort in (21, 22, 69, 990, 989)
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName !in~ ("svchost.exe", "FileZilla.exe", "WinSCP.exe")
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1071.003",
    name: "Mail Protocols (C2)",
    tacticIds: ["TA0011"],
    description: "Adversaries use email protocols — SMTP, IMAP, POP3 — as C2 channels, embedding commands in email subjects or bodies to blend with legitimate email traffic.",
    xdrMappings: [
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteIP", "RemotePort", "InitiatingProcessFileName", "ActionType"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort in (25, 587, 465, 143, 993, 110, 995)
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName !in~ (
    "svchost.exe", "outlook.exe", "thunderbird.exe", "msexchangetransport.exe")
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1571",
    name: "Non-Standard Port",
    tacticIds: ["TA0011"],
    description: "Adversaries use non-standard ports for C2 communication to evade network controls that monitor common ports.",
    xdrMappings: [
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteIP", "RemotePort", "InitiatingProcessFileName", "BytesSent"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort !in (80, 443, 53, 8080, 8443, 22, 25, 587, 465, 3389, 135, 445, 139, 636, 389)
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName !in~ ("svchost.exe", "MsMpEng.exe", "System")
| summarize Connections = count() by DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| where Connections > 5
| order by Connections desc`,
      },
    ],
  },
  {
    id: "T1568.002",
    name: "Domain Generation Algorithms",
    tacticIds: ["TA0011"],
    description: "Adversaries use domain generation algorithms (DGA) to produce large numbers of candidate C2 domains, making takedowns ineffective. High-entropy, short-lived subdomains are the key indicator.",
    xdrMappings: [
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteUrl", "RemoteIP", "InitiatingProcessFileName", "ActionType"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort == 53 or ActionType == "DnsQueryResponse"
// High volume of unique domains per process = potential DGA
| summarize Domains = dcount(RemoteUrl) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where Domains > 100
| order by Domains desc`,
      },
    ],
  },
  {
    id: "T1090.003",
    name: "Multi-hop Proxy (Tor)",
    tacticIds: ["TA0011"],
    description: "Adversaries use Tor or multi-hop proxy chains to anonymise C2 traffic and evade network-based attribution.",
    xdrMappings: [
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteIP", "RemotePort", "InitiatingProcessFileName", "ActionType"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort in (9001, 9030, 9050, 9051, 9150)   // Tor relay/browser ports
    or InitiatingProcessFileName in~ ("tor.exe", "torbrowser.exe")
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where Title has_any ("Tor", "anonymous proxy", "anonymizer")
    or AttackTechniques has "T1090"
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },
  {
    id: "T1102",
    name: "Web Service",
    tacticIds: ["TA0011"],
    description: "Adversaries use legitimate web services — Pastebin, GitHub, Discord, Slack, OneDrive — as C2 channels to blend traffic with normal corporate web use.",
    xdrMappings: [
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteUrl", "RemoteIP", "InitiatingProcessFileName", "BytesSent"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteUrl has_any (
    "pastebin.com", "paste.ee", "hastebin.com",
    "raw.githubusercontent.com", "gist.github.com",
    "discord.com/api", "discordapp.com")
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "slack.exe", "Teams.exe")
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName`,
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

  {
    id: "T1537",
    name: "Transfer Data to Cloud Account",
    tacticIds: ["TA0010"],
    description: "Adversaries exfiltrate data by transferring it to attacker-controlled cloud accounts — OneDrive personal, Google Drive, or Azure storage — using the victim's own cloud credentials.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountDisplayName", "ActionType", "Application", "ObjectName", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileUploaded", "FileCopied", "FileMoved", "SharingInvitationCreated")
| where Application in ("Microsoft OneDrive for Business", "Microsoft SharePoint Online")
// Flag shares going to external / personal accounts
| where AdditionalFields has "external" or AdditionalFields has "personal"
| project Timestamp, AccountDisplayName, ActionType, Application, ObjectName, IPAddress`,
      },
      {
        table: "DataSecurityEvents",
        columns: ["AccountUpn", "ActionType", "FileName", "Sensitivity", "PolicyName", "Application"],
        kql: `DataSecurityEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileUploadedToCloud", "FileCopiedToRemovableMedia", "FileSharedExternally")
| where isnotempty(Sensitivity)
| project Timestamp, AccountUpn, ActionType, FileName, Sensitivity, PolicyName, Application`,
      },
    ],
  },

  {
    id: "T1041",
    name: "Exfiltration Over C2 Channel",
    tacticIds: ["TA0010"],
    description: "Adversaries exfiltrate data over the same channel used for C2 communications — uploading collected data via HTTP/S beacons, DNS tunneling, or other C2 protocols.",
    xdrMappings: [
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteIP", "RemoteUrl", "RemotePort", "BytesSent", "InitiatingProcessFileName"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "ConnectionSuccess"
// High BytesSent to same external IP from non-browser process = C2 exfil
| summarize TotalSent = sum(SentBytes), Connections = count() by DeviceName, RemoteIP, InitiatingProcessFileName
| where TotalSent > 10000000   // > 10MB
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "firefox.exe", "OneDrive.exe")
| order by TotalSent desc`,
      },
    ],
  },
  {
    id: "T1020",
    name: "Automated Exfiltration",
    tacticIds: ["TA0010"],
    description: "Adversaries automate data exfiltration — scheduled tasks, scripts, or malware modules that continuously collect and send data without manual interaction.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountDisplayName", "ActionType", "Application", "ObjectName", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType == "FileUploaded"
| summarize UploadCount = count(), TotalFiles = dcount(ObjectName) by AccountDisplayName, Application, IPAddress, bin(Timestamp, 1h)
| where UploadCount > 100
| order by UploadCount desc`,
      },
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteIP", "RemoteUrl", "BytesSent", "InitiatingProcessFileName"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| summarize TotalSent = sum(SentBytes), Sessions = count() by DeviceName, RemoteIP, InitiatingProcessFileName, bin(Timestamp, 1h)
| where TotalSent > 100000000  // > 100MB per hour
| order by TotalSent desc`,
      },
    ],
  },
  {
    id: "T1567.001",
    name: "Exfiltration to Code Repository",
    tacticIds: ["TA0010"],
    description: "Adversaries exfiltrate data by committing it to public or private code repositories — GitHub, GitLab, Azure DevOps — where it blends with legitimate developer activity.",
    xdrMappings: [
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteUrl", "RemoteIP", "BytesSent", "InitiatingProcessFileName"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteUrl has_any ("github.com", "gitlab.com", "dev.azure.com", "bitbucket.org")
| where ActionType == "ConnectionSuccess"
| summarize TotalSent = sum(SentBytes), Connections = count() by DeviceName, RemoteUrl, InitiatingProcessFileName
| where TotalSent > 5000000   // > 5MB to code repo from non-IDE
| where InitiatingProcessFileName !in~ ("git.exe", "devenv.exe", "code.exe", "pycharm64.exe")
| order by TotalSent desc`,
      },
    ],
  },
  {
    id: "T1011",
    name: "Exfiltration over Other Network Medium",
    tacticIds: ["TA0010"],
    description: "Adversaries exfiltrate data using alternative network media — Bluetooth, cellular, or other out-of-band channels. USB-based exfiltration is the most XDR-visible variant.",
    xdrMappings: [
      {
        table: "DeviceEvents",
        columns: ["DeviceName", "ActionType", "AdditionalFields"],
        kql: `DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "UsbDriveMounted"
| join kind=inner (
    DeviceFileEvents
    | where ActionType == "FileCopied"
    | where FolderPath matches regex @"^[D-Z]:\\"
    | summarize FilesExfiled = count() by DeviceId, bin(Timestamp, 1h)
) on DeviceId
| where FilesExfiled > 10
| order by FilesExfiled desc`,
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
  {
    id: "T1485",
    name: "Data Destruction",
    tacticIds: ["TA0040"],
    description: "Adversaries destroy data to render systems inoperable or eliminate evidence — wiping disks, deleting files in bulk, or corrupting databases. Often used in destructive campaigns alongside ransomware.",
    xdrMappings: [
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "ActionType", "InitiatingProcessFileName"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType == "FileDeleted"
| summarize DeletedCount = count(), Extensions = make_set(tostring(split(FileName, ".")[-1])) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)
| where DeletedCount > 200
| order by DeletedCount desc`,
      },
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (
    "format ", "diskpart", "cipher /w", "sdelete",
    "dd if=/dev/zero", "shred ", "rm -rf /")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where AttackTechniques has "T1485"
    or Title has_any ("wiper", "data destruction", "disk wipe", "MBR")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },
  {
    id: "T1496",
    name: "Resource Hijacking",
    tacticIds: ["TA0040"],
    description: "Adversaries hijack system resources — CPU, GPU, network — for cryptomining or other purposes. Indicators include sustained high CPU on unusual processes, unexpected network connections to mining pools, and cloud compute spin-up.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "AccountName", "SHA256"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName in~ ("xmrig.exe", "minerd.exe", "cpuminer.exe", "ethminer.exe")
    or ProcessCommandLine has_any ("stratum+tcp://", "pool.supportxmr.com", "xmrig", "--donate-level")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256`,
      },
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteUrl", "RemoteIP", "RemotePort", "InitiatingProcessFileName"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort in (3333, 4444, 5555, 7777, 8888, 9999, 14444, 45700)  // common mining ports
    or RemoteUrl has_any ("xmr.", "monero", "pool.hashvault", "supportxmr", "nanopool")
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountDisplayName", "ActionType", "Application", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType in ("Create virtual machine", "Start virtual machine", "Create deployment")
| summarize VMCount = count() by AccountDisplayName, IPAddress, bin(Timestamp, 1h)
| where VMCount > 5
| order by VMCount desc`,
      },
    ],
  },
  {
    id: "T1531",
    name: "Account Access Removal",
    tacticIds: ["TA0040"],
    description: "Adversaries remove account access — deleting accounts, locking accounts, or changing passwords — to deny legitimate users access to systems during or after an attack.",
    xdrMappings: [
      {
        table: "IdentityDirectoryEvents",
        columns: ["AccountUpn", "ActionType", "TargetAccountUpn", "AdditionalFields"],
        kql: `IdentityDirectoryEvents
| where Timestamp > ago(1d)
| where ActionType in (
    "Disable account", "Account disabled",
    "Remove member from group", "Password reset")
| project Timestamp, AccountUpn, TargetAccountUpn, ActionType, AdditionalFields`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountDisplayName", "ActionType", "Application", "IPAddress", "AdditionalFields"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType in (
    "Delete user", "Disable account", "Block sign in",
    "Remove member from role", "Revoke refresh token")
| project Timestamp, AccountDisplayName, ActionType, Application, IPAddress, AdditionalFields`,
      },
    ],
  },
  {
    id: "T1529",
    name: "System Shutdown / Reboot",
    tacticIds: ["TA0040"],
    description: "Adversaries reboot or shut down systems to interrupt operations, force recovery sequences, or clear volatile evidence from memory.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "ProcessCommandLine", "AccountName", "FileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (
    "shutdown /r", "shutdown /s", "shutdown /f",
    "Restart-Computer", "Stop-Computer",
    "init 0", "init 6", "reboot", "poweroff")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`,
      },
    ],
  },
  {
    id: "T1491.001",
    name: "Internal Defacement",
    tacticIds: ["TA0040"],
    description: "Adversaries deface internal resources — intranet pages, SharePoint sites, shared drives — to intimidate victims, demonstrate access, or deliver ransom demands.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountDisplayName", "ActionType", "Application", "ObjectName", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where Application in ("Microsoft SharePoint Online", "Microsoft Teams")
| where ActionType in ("FileModified", "PageModified", "ChannelDeleted", "TeamDeleted")
| summarize Actions = count() by AccountDisplayName, Application, IPAddress, bin(Timestamp, 1h)
| where Actions > 20
| order by Actions desc`,
      },
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "InitiatingProcessFileName", "ActionType"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileModified"
| where FileName endswith ".html" or FileName endswith ".htm" or FileName endswith ".aspx"
| where FolderPath has_any ("\\inetpub\\", "\\wwwroot\\", "\\web\\")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName`,
      },
    ],
  },
  {
    id: "T1561.001",
    name: "Disk Content Wipe",
    tacticIds: ["TA0040"],
    description: "Adversaries wipe disk content to render systems inoperable — using tools like SDelete, cipher, or custom wiper malware. Often the final stage of a destructive attack.",
    xdrMappings: [
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "ProcessCommandLine", "AccountName", "FileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (
    "sdelete -p", "cipher /w", "dd if=/dev/zero",
    "diskpart", "format ", "bcdedit /set")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where AttackTechniques has "T1561"
    or Title has_any ("wiper", "disk wipe", "MBR wipe", "destructive")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },
];

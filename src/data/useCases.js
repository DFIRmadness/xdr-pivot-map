export const USE_CASES = [
  {
    id: "phishing",
    name: "Phishing → Execution",
    icon: "🎣",
    tactic: "Initial Access",
    color: "#b47fff",
    desc: "Trace from email delivery through URL/attachment to process execution on an endpoint.",
    steps: [
      {
        table: "EmailEvents",
        action: "Find the delivery event — sender, recipient, subject, delivery action",
        kql: `EmailEvents
| where Timestamp > ago(7d)
| where SenderFromAddress =~ "suspect@domain.com"  // or filter by RecipientEmailAddress
| where DeliveryAction in ("Delivered", "DeliveredAsSpam")
| project Timestamp, SenderFromAddress, SenderIPv4,
          RecipientEmailAddress, Subject, DeliveryAction,
          NetworkMessageId`,
      },
      {
        table: "EmailUrlInfo",
        action: "Extract URLs from the message body",
        kql: `EmailUrlInfo
| where Timestamp > ago(7d)
| where NetworkMessageId == "<NetworkMessageId from EmailEvents>"
| project Timestamp, NetworkMessageId, Url, UrlDomain, UrlLength`,
      },
      {
        table: "EmailAttachmentInfo",
        action: "Get attachment SHA256 for downstream correlation",
        kql: `EmailAttachmentInfo
| where Timestamp > ago(7d)
| where NetworkMessageId == "<NetworkMessageId from EmailEvents>"
| project Timestamp, NetworkMessageId, FileName, FileType,
          SHA256, MalwareDetectionMethod`,
      },
      {
        table: "EmailPostDeliveryEvents",
        action: "Check for post-delivery remediation or ZAP actions",
        kql: `EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| where NetworkMessageId == "<NetworkMessageId from EmailEvents>"
| project Timestamp, NetworkMessageId, ActionType,
          ActionTrigger, ActionResult, DeliveryLocation`,
      },
      {
        table: "UrlClickEvents",
        action: "Confirm recipient clicked the link (Safe Links telemetry)",
        kql: `UrlClickEvents
| where Timestamp > ago(7d)
| where Url has "<domain from EmailUrlInfo>"
| project Timestamp, AccountUpn, Url, ActionType,
          IPAddress, IsClickedThrough, UrlChain`,
      },
      {
        table: "DeviceLogonEvents",
        action: "Identify the device the user was on at click time via AccountUpn",
        kql: `DeviceLogonEvents
| where Timestamp > ago(7d)
| where AccountUpn =~ "<AccountUpn from UrlClickEvents>"
| where LogonType in (2, 10, 11)  // Interactive
| project Timestamp, DeviceName, DeviceId, AccountUpn,
          LogonType, LogonId, RemoteIP`,
      },
      {
        table: "DeviceProcessEvents",
        action: "Look for child processes of browser or Office after click time",
        kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceId == "<DeviceId from DeviceLogonEvents>"
| where InitiatingProcessFileName in~ (
    "chrome.exe","msedge.exe","firefox.exe",
    "winword.exe","excel.exe","outlook.exe","powerpnt.exe")
| project Timestamp, DeviceName, FileName, ProcessId,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessId, AccountName`,
      },
      {
        table: "DeviceFileEvents",
        action: "Find any files written by those child processes",
        kql: `DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceId == "<DeviceId>"
| where InitiatingProcessId == <ProcessId from DeviceProcessEvents>
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, FileName, FolderPath,
          SHA256, ActionType, InitiatingProcessFileName,
          InitiatingProcessId`,
      },
      {
        table: "DeviceNetworkEvents",
        action: "Identify C2 or staging server connections post-execution",
        kql: `DeviceNetworkEvents
| where Timestamp > ago(7d)
| where DeviceId == "<DeviceId from DeviceFileEvents>"
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, RemoteIP, RemoteUrl,
          RemotePort, InitiatingProcessFileName,
          InitiatingProcessId`,
      },
      {
        table: "AlertEvidence",
        action: "Validate findings against existing detections",
        kql: `AlertEvidence
| where Timestamp > ago(7d)
| where RemoteIP == "<RemoteIP from DeviceNetworkEvents>"
    or SHA256 == "<SHA256 from DeviceFileEvents>"
| project Timestamp, AlertId, EntityType, EvidenceRole,
          RemoteIP, SHA256, FileName, AccountUpn`,
      },
    ],
    links: [
      { from: "EmailEvents",          to: "EmailUrlInfo",             col: "NetworkMessageId" },
      { from: "EmailEvents",          to: "EmailAttachmentInfo",      col: "NetworkMessageId" },
      { from: "EmailEvents",          to: "EmailPostDeliveryEvents",  col: "NetworkMessageId" },
      { from: "EmailUrlInfo",         to: "UrlClickEvents",           col: "Url" },
      { from: "UrlClickEvents",       to: "DeviceLogonEvents",        col: "AccountUpn" },
      { from: "DeviceLogonEvents",    to: "DeviceProcessEvents",      col: "DeviceId + LogonId" },
      { from: "DeviceProcessEvents",  to: "DeviceFileEvents",         col: "InitiatingProcessId" },
      { from: "DeviceFileEvents",     to: "DeviceNetworkEvents",      col: "DeviceId" },
      { from: "DeviceNetworkEvents",  to: "AlertEvidence",            col: "RemoteIP" },
      { from: "EmailAttachmentInfo",  to: "DeviceFileEvents",         col: "SHA256" },
    ],
  },
  {
    id: "azurePortalBreach",
    name: "AiTM Phish > Azure VM Exec",
    icon: "🔑",
    tactic: "Initial Access > Execution",
    color: "#38bdf8",
    desc: "AiTM phishing steals a session token. Attacker signs in to Azure Portal, enumerates VMs, then executes commands via Run Command — all without touching the endpoint.",
    steps: [
      {
        table: "EmailEvents",
        action: "Find the AiTM phishing email — look for impersonated O365 / MFA prompt lures delivered to the victim",
        kql: `EmailEvents
| where Timestamp > ago(7d)
| where Subject has_any (
    "sign-in","verify","MFA","authentication",
    "unusual activity","action required")
| where DeliveryAction in ("Delivered","DeliveredAsSpam")
// AiTM kits often use domains that look like Microsoft login pages
| where SenderFromDomain !endswith "microsoft.com"
| project Timestamp, SenderFromAddress, SenderFromDomain,
          SenderIPv4, RecipientEmailAddress, Subject,
          DeliveryAction, NetworkMessageId`,
      },
      {
        table: "UrlClickEvents",
        action: "Confirm the victim clicked the AiTM link — note the URL and whether the click was proxied through Safe Links",
        kql: `UrlClickEvents
| where Timestamp > ago(7d)
| where NetworkMessageId == "<NetworkMessageId from EmailEvents>"
    or Url has "<domain from EmailUrlInfo>"
| project Timestamp, AccountUpn, Url, ActionType,
          IPAddress, IsClickedThrough, UrlChain
// UrlChain shows redirect hops — AiTM sites typically redirect
// through a proxy to the real Microsoft login page`,
      },
      {
        table: "AADSignInEventsBeta",
        action: "Spot the attacker's sign-in with the stolen session token — different IP/ASN from the victim's normal pattern, same account, no MFA challenge (token already has MFA claim)",
        kql: `AADSignInEventsBeta
| where Timestamp > ago(7d)
| where AccountUpn =~ "<AccountUpn from UrlClickEvents>"
// Victim's normal IP vs attacker's IP — look for the second sign-in
| summarize SignIns = count(),
            IPs = make_set(IPAddress),
            Countries = make_set(Country)
    by AccountUpn, bin(Timestamp, 1h)
| where array_length(IPs) > 1          // Multiple source IPs in short window
---
// Drill into the suspicious sign-in
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where AccountUpn =~ "<AccountUpn>"
| where IsManaged == false             // Unmanaged / unknown device
    or RiskLevelDuringSignIn in ("high","medium")
| project Timestamp, AccountUpn, IPAddress, Country, City,
          DeviceName, Application, AuthenticationRequirement,
          RiskLevelDuringSignIn, AccountObjectId, SessionId`,
      },
      {
        table: "CloudAppEvents",
        action: "Attacker is now in the Azure Portal — look for immediate resource browsing: subscription listing, VM enumeration, IAM inspection",
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where AccountObjectId == "<AccountObjectId from AADSignInEventsBeta>"
| where Application == "Microsoft Azure"
| where ActionType in (
    "ListVirtualMachines",
    "ListSubscriptions",
    "Get Virtual Machine",
    "List Role Assignments",
    "ListResourceGroups",
    "UserLoggedIn")
| project Timestamp, AccountUpn, ActionType, Application,
          IPAddress, ObjectName, ObjectId, AdditionalFields
| order by Timestamp asc`,
      },
      {
        table: "GraphApiAuditEvents",
        action: "ARM / Graph API calls enumerate the tenant: subscription IDs, VM names, resource groups — used to identify targets before executing commands",
        kql: `GraphApiAuditEvents
| where Timestamp > ago(7d)
| where AccountId == "<AccountId from CloudAppEvents>"
| where ActionType has_any (
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.Authorization/roleAssignments/read",
    "Microsoft.Resources/subscriptions/resourceGroups/read",
    "Get member objects")
| project Timestamp, AccountUpn, ActionType, IPAddress,
          TargetResources, AdditionalFields
| order by Timestamp asc`,
      },
      {
        table: "CloudAuditEvents",
        action: "The Azure portal Run Command feature appears here as a resource action — this is the execution primitive. Also watch for Custom Script Extension or Desired State Config writes.",
        kql: `CloudAuditEvents
| where Timestamp > ago(7d)
| where AccountId == "<AccountId from CloudAppEvents>"
| where ActionType has_any (
    "Microsoft.Compute/virtualMachines/runCommand/action",
    "Microsoft.Compute/virtualMachines/extensions/write",
    "microsoft.compute/virtualmachines/runcommand",
    "CustomScriptExtension")
| extend CommandDetails = parse_json(AdditionalFields)
| project Timestamp, AccountUpn, ActionType, ResourceId,
          ResourceType, IPAddress,
          CommandDetails, AdditionalFields`,
      },
      {
        table: "CloudProcessEvents",
        action: "Processes spawned inside the VM by the Run Command agent (WindowsAzureGuestAgent / waagent). Look for unusual shells or recon commands launched by the Azure agent.",
        kql: `CloudProcessEvents
| where Timestamp > ago(7d)
// Run Command spawns processes via the Azure Guest Agent
| where InitiatingProcessFileName in~ (
    "WindowsAzureGuestAgent.exe",
    "WaAppAgent.exe",
    "waagent","CustomScriptHandler")
| where FileName in~ (
    "cmd.exe","powershell.exe","bash","sh",
    "python.exe","python3","whoami.exe","net.exe")
| project Timestamp, DeviceName, DeviceId, FileName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessId, AccountName
| order by Timestamp asc`,
      },
      {
        table: "AlertInfo",
        action: "Correlate with AiTM, impossible travel, risky sign-in, and any cloud execution alerts generated across the chain",
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where Title has_any (
    "AiTM","adversary-in-the-middle",
    "impossible travel","token theft",
    "risky sign-in","suspicious sign-in",
    "Run Command","unusual VM",
    "suspicious Azure","suspicious cloud")
    or Category in ("InitialAccess","Execution","CredentialAccess")
| project Timestamp, AlertId, Title, Severity,
          Category, AttackTechniques
| join kind=leftouter AlertEvidence on AlertId
| project Timestamp, AlertId, Title, Severity,
          EntityType, EvidenceRole, AccountUpn, DeviceName`,
      },
    ],
    links: [
      { from: "EmailEvents",       to: "UrlClickEvents",       col: "NetworkMessageId" },
      { from: "UrlClickEvents",    to: "AADSignInEventsBeta",  col: "AccountUpn" },
      { from: "AADSignInEventsBeta", to: "CloudAppEvents",     col: "AccountObjectId" },
      { from: "CloudAppEvents",    to: "GraphApiAuditEvents",  col: "AccountId" },
      { from: "CloudAppEvents",    to: "CloudAuditEvents",     col: "AccountUpn" },
      { from: "CloudAuditEvents",  to: "CloudProcessEvents",   col: "DeviceId" },
      { from: "AlertInfo",         to: "AlertEvidence",        col: "AlertId" },
      { from: "AlertEvidence",     to: "AADSignInEventsBeta",  col: "AccountUpn" },
    ],
  },
  {
    id: "lateralMovement",
    name: "Lateral Movement",
    icon: "↔️",
    tactic: "Lateral Movement",
    color: "#ff6b35",
    desc: "Trace credential use, pass-the-hash/ticket, and remote execution across hosts.",
    steps: [
      {
        table: "DeviceLogonEvents",
        action: "Find remote interactive or network logons (LogonType 3, 10)",
        kql: `DeviceLogonEvents
| where Timestamp > ago(7d)
| where LogonType in (3, 10)          // Network, RemoteInteractive
| where ActionType == "LogonSuccess"
| project Timestamp, DeviceName, DeviceId, AccountUpn,
          AccountDomain, LogonType, LogonId, RemoteIP
| order by Timestamp desc`,
      },
      {
        table: "IdentityLogonEvents",
        action: "Correlate with Kerberos / NTLM events on the DC",
        kql: `IdentityLogonEvents
| where Timestamp > ago(7d)
| where AccountUpn =~ "<AccountUpn from DeviceLogonEvents>"
| where Protocol in ("Kerberos", "NTLM")
| project Timestamp, AccountUpn, DeviceName, IPAddress,
          LogonType, Protocol, ActionType, DestinationIPAddress`,
      },
      {
        table: "IdentityDirectoryEvents",
        action: "Check for suspicious ticket requests (TGS/TGT anomalies)",
        kql: `IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where AccountUpn =~ "<AccountUpn from IdentityLogonEvents>"
| where ActionType in (
    "Service Ticket Request",
    "TGT Request",
    "A Kerberos service ticket was requested")
| project Timestamp, AccountUpn, ActionType,
          TargetAccountUpn, Application, AdditionalFields`,
      },
      {
        table: "DeviceProcessEvents",
        action: "Look for remote execution tools: psexec, wmic, sc, schtasks",
        kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceId == "<DeviceId from DeviceLogonEvents>"
| where FileName in~ (
    "psexec.exe","psexesvc.exe","wmic.exe",
    "sc.exe","schtasks.exe","at.exe","net.exe")
| project Timestamp, DeviceName, FileName,
          ProcessCommandLine, ProcessId,
          InitiatingProcessFileName, AccountName`,
      },
      {
        table: "DeviceNetworkEvents",
        action: "Confirm SMB / RPC connections between hosts",
        kql: `DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessId == <ProcessId from DeviceProcessEvents>
| where DeviceId == "<DeviceId>"
| where RemotePort in (445, 135, 139)   // SMB, RPC, NetBIOS
| project Timestamp, DeviceName, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessId`,
      },
      {
        table: "DeviceFileEvents",
        action: "Find dropped tools or payloads on the lateral target",
        kql: `DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessId == <ProcessId from DeviceProcessEvents>
| where DeviceId == "<DeviceId>"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, FileName, FolderPath,
          SHA256, InitiatingProcessFileName, InitiatingProcessId`,
      },
      {
        table: "DeviceRegistryEvents",
        action: "Check persistence set on newly compromised host",
        kql: `DeviceRegistryEvents
| where Timestamp > ago(7d)
| where DeviceId == "<DeviceId from DeviceFileEvents>"
| where RegistryKey has_any (
    "CurrentVersion\\Run",
    "CurrentVersion\\RunOnce",
    "Services","Winlogon")
| project Timestamp, DeviceName, ActionType, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessFileName`,
      },
      {
        table: "AlertInfo",
        action: "Look for PTH/PTT, suspicious logon, or admin share alerts",
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where Category in ("LateralMovement","CredentialAccess")
    or Title has_any ("pass-the-hash","pass-the-ticket",
                      "admin share","suspicious logon")
| project Timestamp, AlertId, Title, Severity,
          Category, AttackTechniques
| join kind=inner AlertEvidence on AlertId
| where EntityType == "Machine"`,
      },
    ],
    links: [
      { from: "DeviceLogonEvents",       to: "IdentityLogonEvents",     col: "AccountUpn + IPAddress" },
      { from: "IdentityLogonEvents",     to: "IdentityDirectoryEvents", col: "AccountUpn" },
      { from: "DeviceLogonEvents",       to: "DeviceProcessEvents",     col: "DeviceId + LogonId" },
      { from: "DeviceProcessEvents",     to: "DeviceNetworkEvents",     col: "InitiatingProcessId" },
      { from: "DeviceNetworkEvents",     to: "DeviceLogonEvents",       col: "RemoteIP → DeviceName" },
      { from: "DeviceProcessEvents",     to: "DeviceFileEvents",        col: "InitiatingProcessId" },
      { from: "DeviceFileEvents",        to: "DeviceRegistryEvents",    col: "DeviceId" },
      { from: "AlertInfo",               to: "AlertEvidence",           col: "AlertId" },
    ],
  },
  {
    id: "persistence",
    name: "Persistence",
    icon: "🪝",
    tactic: "Persistence",
    color: "#ff4757",
    desc: "Hunt scheduled tasks, registry run keys, services, and startup folder modifications.",
    steps: [
      {
        table: "DeviceRegistryEvents",
        action: "Query Run/RunOnce keys, service entries, WMI subscriptions",
        kql: `DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any (
    "CurrentVersion\\Run","CurrentVersion\\RunOnce",
    "Image File Execution Options",
    "Classes\\CLSID","Winlogon")
| project Timestamp, DeviceName, DeviceId, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessId`,
      },
      {
        table: "DeviceProcessEvents",
        action: "Find the process that wrote the persistence mechanism",
        kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceId == "<DeviceId from DeviceRegistryEvents>"
| where ProcessId == <InitiatingProcessId from DeviceRegistryEvents>
| project Timestamp, DeviceName, FileName, ProcessId,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessId, AccountName`,
      },
      {
        table: "DeviceFileEvents",
        action: "Locate the payload file dropped for persistence",
        kql: `DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceId == "<DeviceId>"
| where InitiatingProcessId == <ProcessId from DeviceProcessEvents>
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, FileName, FolderPath,
          SHA256, InitiatingProcessFileName, InitiatingProcessId`,
      },
      {
        table: "DeviceFileCertificateInfo",
        action: "Check if the payload is signed (LOLbin abuse vs. malware)",
        kql: `DeviceFileCertificateInfo
| where Timestamp > ago(7d)
| where SHA256 == "<SHA256 from DeviceFileEvents>"
| project Timestamp, DeviceName, SHA256, SignerType, Signer,
          IsTrusted, IsRootSignerMicrosoft,
          CertificateSerialNumber, CertificateExpirationTime`,
      },
      {
        table: "DeviceEvents",
        action: "Look for scheduled task creation (ActionType: ScheduledTaskCreated)",
        kql: `DeviceEvents
| where Timestamp > ago(7d)
| where DeviceId == "<DeviceId>"
| where ActionType == "ScheduledTaskCreated"
| extend TaskDetails = parse_json(AdditionalFields)
| project Timestamp, DeviceName, DeviceId,
          InitiatingProcessFileName, InitiatingProcessId,
          TaskDetails.TaskName, TaskDetails.TaskContent`,
      },
      {
        table: "DeviceLogonEvents",
        action: "Identify any new service accounts or logon anomalies",
        kql: `DeviceLogonEvents
| where Timestamp > ago(7d)
| where DeviceId == "<DeviceId from DeviceProcessEvents>"
| where LogonType == 5                 // Service logon
| project Timestamp, DeviceName, AccountName, AccountDomain,
          AccountUpn, LogonType, LogonId`,
      },
      {
        table: "IdentityDirectoryEvents",
        action: "Check for new admin accounts or group membership changes",
        kql: `IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "Group Membership changed",
    "User Account created",
    "User Account enabled")
| where AccountUpn =~ "<AccountUpn from DeviceLogonEvents>"
    or TargetAccountUpn =~ "<AccountUpn from DeviceLogonEvents>"
| project Timestamp, AccountUpn, ActionType,
          TargetAccountUpn, TargetAccountDisplayName, AdditionalFields`,
      },
      {
        table: "AlertEvidence",
        action: "Validate against existing persistence-class detections",
        kql: `AlertEvidence
| where Timestamp > ago(7d)
| where SHA256 == "<SHA256 from DeviceFileCertificateInfo>"
    or FileName =~ "<FileName from DeviceFileEvents>"
| project Timestamp, AlertId, EntityType, EvidenceRole,
          FileName, SHA256, DeviceName`,
      },
    ],
    links: [
      { from: "DeviceRegistryEvents",    to: "DeviceProcessEvents",       col: "InitiatingProcessId" },
      { from: "DeviceProcessEvents",     to: "DeviceFileEvents",          col: "InitiatingProcessId" },
      { from: "DeviceFileEvents",        to: "DeviceFileCertificateInfo", col: "SHA256" },
      { from: "DeviceEvents",            to: "DeviceProcessEvents",       col: "InitiatingProcessId" },
      { from: "DeviceProcessEvents",     to: "DeviceLogonEvents",         col: "DeviceId + AccountName" },
      { from: "DeviceLogonEvents",       to: "IdentityDirectoryEvents",   col: "AccountUpn" },
      { from: "AlertEvidence",           to: "DeviceFileEvents",          col: "SHA256" },
    ],
  },
  {
    id: "credentialAccess",
    name: "Credential Access",
    icon: "🔐",
    tactic: "Credential Access",
    color: "#ffb347",
    desc: "Identify credential dumping, LSASS access, spray attacks, and Kerberoasting.",
    steps: [
      {
        table: "DeviceEvents",
        action: "Look for LSASS access events (ActionType: OpenProcessApiCall on lsass.exe)",
        kql: `DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| project Timestamp, DeviceName, DeviceId,
          InitiatingProcessFileName, InitiatingProcessId,
          InitiatingProcessCommandLine, AccountName`,
      },
      {
        table: "DeviceProcessEvents",
        action: "Find credential dumping tools: mimikatz, procdump, comsvcs.dll",
        kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ (
    "mimikatz.exe","procdump.exe","procdump64.exe")
    or ProcessCommandLine has_any (
      "sekurlsa","lsadump","minidump",
      "MiniDump","comsvcs","Invoke-Mimikatz")
| project Timestamp, DeviceName, DeviceId, FileName,
          ProcessId, ProcessCommandLine,
          InitiatingProcessFileName, AccountName`,
      },
      {
        table: "DeviceFileEvents",
        action: "Detect dump file creation (.dmp, .bin) in temp directories",
        kql: `DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FileName endswith ".dmp" or FileName endswith ".bin"
| where FolderPath has_any ("Temp","tmp","AppData\\Local")
| project Timestamp, DeviceName, FileName, FolderPath,
          SHA256, InitiatingProcessFileName, InitiatingProcessId`,
      },
      {
        table: "IdentityLogonEvents",
        action: "Look for Kerberoasting (abnormal TGS requests for SPNs)",
        kql: `IdentityLogonEvents
| where Timestamp > ago(7d)
| where Protocol == "Kerberos"
| where ActionType == "LogonSuccess"
| summarize RequestCount = count(),
            Targets = make_set(TargetAccountUpn)
    by AccountUpn, IPAddress, bin(Timestamp, 5m)
| where RequestCount > 10             // Bulk TGS = Kerberoasting signal
| order by RequestCount desc`,
      },
      {
        table: "IdentityDirectoryEvents",
        action: "LDAP queries enumerating SPNs or admin groups",
        kql: `IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "LDAP query"
| where AdditionalFields has_any (
    "servicePrincipalName","adminCount",
    "Domain Admins","ms-DS-MachineAccountQuota")
| project Timestamp, AccountUpn, IPAddress,
          ActionType, AdditionalFields`,
      },
      {
        table: "AADSignInEventsBeta",
        action: "Detect spray attacks: many failed sign-ins across accounts, same IP",
        kql: `AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ErrorCode != 0                // Failed sign-ins only
| summarize FailedCount = count(),
            DistinctAccounts = dcount(AccountUpn),
            Accounts = make_set(AccountUpn, 10)
    by IPAddress, bin(Timestamp, 10m)
| where DistinctAccounts > 5         // Same IP hitting many accounts
| order by FailedCount desc`,
      },
      {
        table: "IdentityLogonEvents",
        action: "Correlate with successful auth immediately after failures (spray success)",
        kql: `IdentityLogonEvents
| where Timestamp > ago(1d)
| where AccountUpn in ("<accounts from AADSignInEventsBeta>")
| where ActionType == "LogonSuccess"
| project Timestamp, AccountUpn, IPAddress,
          DeviceName, LogonType, Protocol`,
      },
      {
        table: "AlertInfo",
        action: "Check for credential-class alerts: NTLM relay, Kerberoast, spray",
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where Category == "CredentialAccess"
    or Title has_any (
      "Kerberoast","NTLM relay","credential dump",
      "password spray","LSASS","Mimikatz")
| project Timestamp, AlertId, Title, Severity,
          Category, AttackTechniques`,
      },
    ],
    links: [
      { from: "DeviceEvents",        to: "DeviceProcessEvents",     col: "InitiatingProcessId" },
      { from: "DeviceProcessEvents", to: "DeviceFileEvents",        col: "InitiatingProcessId" },
      { from: "IdentityLogonEvents", to: "IdentityDirectoryEvents", col: "AccountUpn" },
      { from: "AADSignInEventsBeta", to: "IdentityLogonEvents",     col: "IPAddress + AccountUpn" },
      { from: "IdentityLogonEvents", to: "DeviceLogonEvents",       col: "AccountUpn" },
      { from: "AlertInfo",           to: "AlertEvidence",           col: "AlertId" },
      { from: "AlertEvidence",       to: "IdentityLogonEvents",     col: "AccountUpn" },
    ],
  },
  {
    id: "cloudCompromise",
    name: "Cloud / Identity Compromise",
    icon: "☁️",
    tactic: "Initial Access + Collection",
    color: "#47ff8f",
    desc: "Trace token theft, OAuth abuse, and cloud-native data access post-compromise.",
    steps: [
      {
        table: "AADSignInEventsBeta",
        action: "Identify sign-in from impossible travel, new ASN, or legacy protocol",
        kql: `AADSignInEventsBeta
| where Timestamp > ago(7d)
| where AccountUpn =~ "<target UPN>"
| where RiskLevelDuringSignIn in ("high","medium")
    or IsManaged == false
    or AuthenticationProcessingDetails has "Legacy Auth"
| project Timestamp, AccountUpn, IPAddress, Country,
          City, DeviceName, Application, ErrorCode,
          RiskLevelDuringSignIn, AccountObjectId`,
      },
      {
        table: "CloudAppEvents",
        action: "Look for mass download, mail forwarding rules, or admin actions",
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where AccountObjectId == "<AccountObjectId from AADSignInEventsBeta>"
| where ActionType in (
    "FileDownloaded","FileSyncDownloadedFull",
    "Set-Mailbox","New-InboxRule",
    "Add member to role.")
| project Timestamp, AccountUpn, ActionType, Application,
          IPAddress, ObjectName, AdditionalFields`,
      },
      {
        table: "GraphApiAuditEvents",
        action: "Detect app registrations, consent grants, or mail read via Graph",
        kql: `GraphApiAuditEvents
| where Timestamp > ago(7d)
| where AccountId == "<AccountId from CloudAppEvents>"
| where ActionType in (
    "Add application.",
    "Add OAuth2PermissionGrant.",
    "Consent to application.",
    "Add service principal.")
| project Timestamp, AccountUpn, ActionType,
          IPAddress, TargetResources, AdditionalFields`,
      },
      {
        table: "IdentityDirectoryEvents",
        action: "Check for MFA modification or self-service password reset abuse",
        kql: `IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where AccountUpn =~ "<AccountUpn from AADSignInEventsBeta>"
| where ActionType in (
    "User registered for MFA",
    "MFA registration details modified",
    "Reset password (self-service)",
    "Admin registered security info for user")
| project Timestamp, AccountUpn, ActionType,
          TargetAccountUpn, IPAddress, AdditionalFields`,
      },
      {
        table: "IdentityInfo",
        action: "Enumerate the account's group membership and admin roles",
        kql: `IdentityInfo
| where AccountUpn =~ "<AccountUpn from IdentityDirectoryEvents>"
| project AccountUpn, AccountDisplayName, JobTitle,
          Department, GroupMembership, AssignedRoles,
          IsAccountEnabled, CloudSid`,
      },
      {
        table: "CloudAuditEvents",
        action: "Look for cloud resource creation or IAM changes (Defender for Cloud)",
        kql: `CloudAuditEvents
| where Timestamp > ago(7d)
| where AccountId == "<AccountId from CloudAppEvents>"
| where ActionType has_any (
    "roleAssignment","policyAssignment",
    "resourceCreated","storageAccountCreate")
| project Timestamp, AccountUpn, ActionType,
          ResourceId, ResourceType, AdditionalFields`,
      },
      {
        table: "DataSecurityEvents",
        action: "Purview: flag any sensitive data access or exfiltration signals",
        kql: `DataSecurityEvents
| where Timestamp > ago(7d)
| where AccountUpn =~ "<AccountUpn from CloudAppEvents>"
| where SensitivityLabel != "" or PolicyName != ""
| project Timestamp, AccountUpn, ActionType, FileName,
          SensitivityLabel, PolicyName, ActivityType`,
      },
      {
        table: "AlertInfo",
        action: "Check for impossible travel, risky sign-in, or BEC alerts",
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where Category in ("InitialAccess","Collection")
    or Title has_any (
      "impossible travel","risky sign-in","BEC",
      "forwarding rule","OAuth app","token theft")
| project Timestamp, AlertId, Title, Severity,
          Category, AttackTechniques`,
      },
    ],
    links: [
      { from: "AADSignInEventsBeta",     to: "CloudAppEvents",         col: "AccountObjectId" },
      { from: "CloudAppEvents",          to: "GraphApiAuditEvents",    col: "AccountId" },
      { from: "AADSignInEventsBeta",     to: "IdentityDirectoryEvents",col: "AccountUpn" },
      { from: "IdentityDirectoryEvents", to: "IdentityInfo",           col: "AccountUpn" },
      { from: "CloudAppEvents",          to: "CloudAuditEvents",       col: "AccountUpn" },
      { from: "CloudAppEvents",          to: "DataSecurityEvents",     col: "AccountUpn" },
      { from: "AlertInfo",               to: "AlertEvidence",          col: "AlertId" },
      { from: "AlertEvidence",           to: "AADSignInEventsBeta",    col: "AccountUpn" },
    ],
  },
  {
    id: "exfiltration",
    name: "Data Exfiltration",
    icon: "📤",
    tactic: "Exfiltration",
    color: "#ff47a3",
    desc: "Hunt large data movements: cloud downloads, email forwarding, DNS/HTTP tunneling, USB.",
    steps: [
      {
        table: "CloudAppEvents",
        action: "Detect mass file downloads or sync of sensitive SharePoint libraries",
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "FileDownloaded","FileSyncDownloadedFull",
    "FileSyncUploadedFull")
| summarize DownloadCount = count(),
            TotalBytes = sum(tolong(FileSize))
    by AccountUpn, Application, bin(Timestamp, 1h)
| where DownloadCount > 50
| order by DownloadCount desc`,
      },
      {
        table: "DeviceNetworkEvents",
        action: "Look for large outbound data transfers or connections to external file hosts",
        kql: `DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIPType == "Public"
| where RemotePort in (443, 80, 21, 22, 25, 587)
| summarize BytesSent = sum(SentBytes),
            ConnCount = count()
    by DeviceName, DeviceId, RemoteIP, RemoteUrl,
       InitiatingProcessFileName, bin(Timestamp, 1h)
| where BytesSent > 10000000           // > 10 MB
| order by BytesSent desc`,
      },
      {
        table: "DeviceFileEvents",
        action: "Find archive creation (.zip, .7z, .rar) before exfil",
        kql: `DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FileName endswith ".zip"
    or FileName endswith ".7z"
    or FileName endswith ".rar"
    or FileName endswith ".tar.gz"
| project Timestamp, DeviceName, FileName, FolderPath,
          SHA256, InitiatingProcessFileName, InitiatingProcessId`,
      },
      {
        table: "DeviceProcessEvents",
        action: "Detect compression tools or exfil utilities (rclone, wget, curl)",
        kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessId == <InitiatingProcessId from DeviceNetworkEvents>
| where FileName in~ (
    "rclone.exe","wget.exe","curl.exe",
    "winscp.exe","robocopy.exe","azcopy.exe")
    or ProcessCommandLine has_any (
      "--config","--drive-client-id","copy","sync")
| project Timestamp, DeviceName, FileName,
          ProcessCommandLine, AccountName`,
      },
      {
        table: "EmailEvents",
        action: "Hunt external forwarding rules or large attachment sends",
        kql: `EmailEvents
| where Timestamp > ago(7d)
| where SenderFromAddress has "<company.com>"
| where RecipientEmailAddress !has "<company.com>"  // External recipient
| where EmailDirection == "Outbound"
| where AttachmentCount > 0
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
          Subject, AttachmentCount, NetworkMessageId`,
      },
      {
        table: "DataSecurityEvents",
        action: "Purview: check for sensitive label access or DLP policy matches",
        kql: `DataSecurityEvents
| where Timestamp > ago(7d)
| where AccountUpn =~ "<AccountUpn from CloudAppEvents>"
| where PolicyName != ""
| project Timestamp, AccountUpn, ActionType, FileName,
          SensitivityLabel, PolicyName, ActivityType`,
      },
      {
        table: "AlertInfo",
        action: "Look for data exfil or anomalous upload volume alerts",
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where Category == "Exfiltration"
    or Title has_any (
      "exfiltration","anomalous upload",
      "data transfer","DLP","large download")
| project Timestamp, AlertId, Title, Severity,
          Category, AttackTechniques`,
      },
    ],
    links: [
      { from: "CloudAppEvents",      to: "DeviceNetworkEvents", col: "AccountUpn → DeviceId" },
      { from: "DeviceNetworkEvents", to: "DeviceProcessEvents", col: "InitiatingProcessId" },
      { from: "DeviceProcessEvents", to: "DeviceFileEvents",    col: "InitiatingProcessId" },
      { from: "DeviceNetworkEvents", to: "EmailEvents",         col: "AccountName" },
      { from: "CloudAppEvents",      to: "DataSecurityEvents",  col: "AccountUpn" },
      { from: "AlertInfo",           to: "AlertEvidence",       col: "AlertId" },
      { from: "AlertEvidence",       to: "CloudAppEvents",      col: "AccountUpn" },
    ],
  },
  {
    id: "vulnerabilityExploitation",
    name: "Vuln / Exploit in Wild",
    icon: "💥",
    tactic: "Initial Access / Execution",
    color: "#ff6b35",
    desc: "Correlate CVE exposure with behavioral signals of exploitation on the endpoint.",
    steps: [
      {
        table: "DeviceTvmSoftwareVulnerabilities",
        action: "Identify devices with the relevant CVE and vuln severity",
        kql: `DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-XXXX-XXXXX"     // Replace with target CVE
| where VulnerabilitySeverityLevel in ("Critical","High")
| project DeviceId, DeviceName, CveId, SoftwareName,
          SoftwareVersion, VulnerabilitySeverityLevel,
          RecommendedSecurityUpdate`,
      },
      {
        table: "DeviceTvmSoftwareInventory",
        action: "Confirm affected software version is installed",
        kql: `DeviceTvmSoftwareInventory
| where DeviceId in (
    "<DeviceIds from DeviceTvmSoftwareVulnerabilities>")
| where SoftwareName =~ "<SoftwareName from TVM>"
| project DeviceId, DeviceName, SoftwareName,
          SoftwareVersion, SoftwareVendor,
          EndOfSupportStatus, OSPlatform`,
      },
      {
        table: "DeviceTvmSecureConfigurationAssessment",
        action: "Check if mitigating controls (e.g., DEP, ASLR) are in place",
        kql: `DeviceTvmSecureConfigurationAssessment
| where DeviceId in ("<DeviceIds from TVM>")
| where ConfigurationId in (
    "scid-2000","scid-2010",   // DEP, ASLR
    "scid-2050","scid-2060")
| project DeviceId, DeviceName, ConfigurationId,
          ConfigurationName, IsApplicable, IsCompliant,
          OSPlatform`,
      },
      {
        table: "DeviceProcessEvents",
        action: "Hunt for exploitation-indicative child processes of vulnerable apps",
        kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceId in ("<exposed DeviceIds>")
| where InitiatingProcessFileName =~ "<vulnerable-app>.exe"
| where FileName in~ (
    "cmd.exe","powershell.exe","wscript.exe",
    "cscript.exe","mshta.exe","rundll32.exe")
| project Timestamp, DeviceName, FileName, ProcessId,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessId`,
      },
      {
        table: "DeviceFileEvents",
        action: "Look for shellcode drops or payloads written by the vulnerable process",
        kql: `DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "<vulnerable-app>.exe"
| where ActionType == "FileCreated"
| where FolderPath has_any (
    "Temp","AppData","ProgramData","Windows\\Temp")
| project Timestamp, DeviceName, FileName, FolderPath,
          SHA256, InitiatingProcessFileName, InitiatingProcessId`,
      },
      {
        table: "DeviceNetworkEvents",
        action: "Detect C2 connections initiated by the exploited process",
        kql: `DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessId == <ProcessId from DeviceProcessEvents>
| where DeviceId in ("<exposed DeviceIds>")
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, RemoteIP, RemoteUrl,
          RemotePort, InitiatingProcessFileName`,
      },
      {
        table: "DeviceEvents",
        action: "Check exploit protection events (ExploitGuardNetworkProtectionBlocked, etc.)",
        kql: `DeviceEvents
| where Timestamp > ago(7d)
| where DeviceId in ("<exposed DeviceIds>")
| where ActionType in (
    "ExploitGuardNetworkProtectionBlocked",
    "ExploitGuardNetworkProtectionAudited",
    "ExploitGuardShellcodeBlock",
    "ExploitGuardAuditMode")
| project Timestamp, DeviceName, ActionType,
          InitiatingProcessFileName, InitiatingProcessId,
          AdditionalFields`,
      },
      {
        table: "AlertInfo",
        action: "Correlate with exploit-class or shell-class alerts on affected devices",
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where Category in ("InitialAccess","Execution")
    or Title has_any (
      "exploit","shellcode","CVE",
      "buffer overflow","suspicious child process")
| project Timestamp, AlertId, Title, Severity,
          Category, AttackTechniques
| join kind=inner AlertEvidence on AlertId
| where DeviceId in ("<exposed DeviceIds>")`,
      },
    ],
    links: [
      { from: "DeviceTvmSoftwareVulnerabilities",       to: "DeviceTvmSoftwareInventory",            col: "DeviceId + SoftwareName" },
      { from: "DeviceTvmSoftwareInventory",             to: "DeviceInfo",                            col: "DeviceId" },
      { from: "DeviceInfo",                             to: "DeviceProcessEvents",                   col: "DeviceId" },
      { from: "DeviceProcessEvents",                    to: "DeviceFileEvents",                      col: "InitiatingProcessId" },
      { from: "DeviceProcessEvents",                    to: "DeviceNetworkEvents",                   col: "InitiatingProcessId" },
      { from: "DeviceProcessEvents",                    to: "DeviceEvents",                          col: "InitiatingProcessId" },
      { from: "AlertInfo",                              to: "AlertEvidence",                         col: "AlertId" },
      { from: "AlertEvidence",                          to: "DeviceInfo",                            col: "DeviceId" },
      { from: "DeviceTvmSecureConfigurationAssessment", to: "DeviceInfo",                            col: "DeviceId" },
    ],
  },
  {
    id: "insiderThreat",
    name: "Insider Threat",
    icon: "🕵️",
    tactic: "Collection / Exfiltration",
    color: "#ff47a3",
    desc: "Investigate suspicious data access, policy violations, and anomalous user behavior.",
    steps: [
      {
        table: "DataSecurityEvents",
        action: "Start with Purview policy violations — sensitive data access or DLP matches",
        kql: `DataSecurityEvents
| where Timestamp > ago(30d)
| where PolicyName != "" or SensitivityLabel != ""
| project Timestamp, AccountUpn, ActionType, FileName,
          SensitivityLabel, PolicyName, ActivityType
| order by Timestamp desc`,
      },
      {
        table: "CloudAppEvents",
        action: "Look for abnormal volume of downloads or access to sensitive SharePoint sites",
        kql: `CloudAppEvents
| where Timestamp > ago(30d)
| where AccountUpn =~ "<AccountUpn from DataSecurityEvents>"
| where ActionType in (
    "FileDownloaded","FileSyncDownloadedFull","FileAccessed")
| summarize Count = count()
    by AccountUpn, Application, bin(Timestamp, 1d)
| order by Count desc`,
      },
      {
        table: "IdentityLogonEvents",
        action: "Check auth patterns — off-hours, new locations, unusual devices",
        kql: `IdentityLogonEvents
| where Timestamp > ago(30d)
| where AccountUpn =~ "<AccountUpn from CloudAppEvents>"
| extend Hour = hourofday(Timestamp)
| where Hour !between (7 .. 19)       // Outside business hours
    or ActionType == "LogonFailed"
| project Timestamp, AccountUpn, IPAddress,
          DeviceName, LogonType, Protocol, Hour`,
      },
      {
        table: "AADSignInEventsBeta",
        action: "Review cloud sign-in risk score and location anomalies",
        kql: `AADSignInEventsBeta
| where Timestamp > ago(30d)
| where AccountUpn =~ "<AccountUpn from IdentityLogonEvents>"
| project Timestamp, AccountUpn, IPAddress, Country, City,
          DeviceName, Application, RiskLevelDuringSignIn,
          RiskState, ConditionalAccessStatus`,
      },
      {
        table: "DeviceFileEvents",
        action: "Hunt for archive creation and USB/removable media file writes",
        kql: `DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType == "FileCreated"
| where AccountUpn =~ "<AccountUpn from CloudAppEvents>"
| where FileName endswith ".zip" or FileName endswith ".7z"
    or FolderPath matches regex @"^[D-Z]:\\"   // Non-system drive
| project Timestamp, DeviceName, FileName, FolderPath,
          SHA256, InitiatingProcessFileName, InitiatingProcessId`,
      },
      {
        table: "DeviceProcessEvents",
        action: "Find file sync clients, cloud upload tools, or compression utilities",
        kql: `DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessId == <InitiatingProcessId from DeviceFileEvents>
| where FileName in~ (
    "onedrive.exe","dropbox.exe","googledrivesync.exe",
    "rclone.exe","winscp.exe","7z.exe","winrar.exe")
| project Timestamp, DeviceName, FileName,
          ProcessCommandLine, AccountName`,
      },
      {
        table: "EmailEvents",
        action: "Detect personal email forwarding or unusual attachment sends",
        kql: `EmailEvents
| where Timestamp > ago(30d)
| where SenderFromAddress =~ "<account from CloudAppEvents>"
| where RecipientEmailAddress has_any (
    "gmail.com","yahoo.com","hotmail.com",
    "outlook.com","protonmail.com")
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
          Subject, AttachmentCount, NetworkMessageId`,
      },
      {
        table: "AlertInfo",
        action: "Check Insider Risk Management and UEBA-based alerts",
        kql: `AlertInfo
| where Timestamp > ago(30d)
| where Category in ("Collection","Exfiltration")
    or Title has_any (
      "insider","anomalous activity","unusual",
      "sensitive data","DLP","mass download")
| project Timestamp, AlertId, Title, Severity,
          Category, AttackTechniques`,
      },
    ],
    links: [
      { from: "DataSecurityEvents",  to: "CloudAppEvents",     col: "AccountUpn" },
      { from: "CloudAppEvents",      to: "IdentityLogonEvents",col: "AccountUpn" },
      { from: "IdentityLogonEvents", to: "AADSignInEventsBeta",col: "AccountUpn" },
      { from: "CloudAppEvents",      to: "DeviceFileEvents",   col: "AccountUpn → DeviceId" },
      { from: "DeviceFileEvents",    to: "DeviceProcessEvents",col: "InitiatingProcessId" },
      { from: "CloudAppEvents",      to: "EmailEvents",        col: "AccountUpn" },
      { from: "AlertInfo",           to: "AlertEvidence",      col: "AlertId" },
    ],
  },
];

export function buildEdges(useCases) {
  const edgeMap = new Map();
  useCases.forEach(uc => {
    uc.links.forEach(link => {
      const key = [link.from, link.to].sort().join("||");
      if (!edgeMap.has(key)) {
        edgeMap.set(key, { source: link.from, target: link.to, cols: [], useCases: [] });
      }
      const e = edgeMap.get(key);
      if (!e.cols.includes(link.col)) e.cols.push(link.col);
      if (!e.useCases.includes(uc.id)) e.useCases.push(uc.id);
    });
  });
  return Array.from(edgeMap.values());
}

export const ALL_EDGES = buildEdges(USE_CASES);

import { PIVOT_EDGES } from "./pivots.js";

export const USE_CASES = [
  {
    id: "becFraud",
    name: "AiTM → BEC Fraud",
    icon: "💸",
    tactic: "Initial Access > Impact",
    color: "#f97316",
    desc: "AiTM proxy steals the session cookie, attacker creates inbox rules, reads pending invoices, then impersonates the vendor to redirect a wire transfer.",
    steps: [
      {
        table: "EmailEvents",
        action: "Find the AiTM phishing lure — finance-themed subjects or Microsoft auth prompts from non-Microsoft domains",
        kql: `EmailEvents
| where Timestamp > ago(14d)
| where DeliveryAction in ("Delivered","DeliveredAsSpam")
| where Subject has_any (
    "sign-in","verify","MFA","invoice","payment",
    "authentication","action required","review document")
  and SenderFromDomain !endswith "microsoft.com"
| project Timestamp, SenderFromAddress, SenderFromDomain,
          RecipientEmailAddress, Subject,
          DeliveryAction, ThreatTypes, NetworkMessageId`,
      },
      {
        table: "UrlClickEvents",
        action: "Confirm click through the AiTM proxy — UrlChain shows the relay redirect before the real Microsoft login",
        kql: `UrlClickEvents
| where Timestamp > ago(14d)
| where NetworkMessageId == "<NetworkMessageId from EmailEvents>"
    or Url has "<proxy_domain from EmailUrlInfo>"
| project Timestamp, AccountUpn, Url, UrlChain,
          ActionType, IsClickedThrough, IPAddress`,
      },
      {
        table: "EntraIdSignInEvents",
        action: "Find Login:Reprocess event — this is where the attacker receives the stolen session token. Capture SessionId as the primary pivot for all downstream steps",
        kql: `// Login:Reprocess = attacker's proxy receives the session token from Entra
EntraIdSignInEvents
| where Timestamp > ago(14d)
| where AccountUpn =~ "<AccountUpn from UrlClickEvents>"
| where ErrorCode == 0
| where EndPointCall == "Login:Reprocess"
| project
    TokenIssuedAt   = Timestamp,
    AccountUpn, AccountObjectId,
    SessionId,                      // The stolen token — use as AADSessionId downstream
    AttackerProxyIP = IPAddress,
    Country, Application
---
// Full sign-in history — spot victim IP vs attacker proxy IP
EntraIdSignInEvents
| where Timestamp > ago(14d)
| where AccountUpn =~ "<AccountUpn>"
| where ErrorCode == 0
| project Timestamp, AccountUpn, SessionId, IPAddress,
          Country, EndPointCall, IsManaged,
          RiskLevelAggregated, AccountObjectId
| sort by Timestamp asc`,
      },
      {
        table: "CloudAppEvents",
        action: "Attacker creates inbox rules to forward all mail — filter by stolen SessionId (AADSessionId in AppAccessContext), not IP address",
        kql: `// AADSessionId in AppAccessContext matches SessionId from Login:Reprocess event
CloudAppEvents
| where Timestamp > ago(14d)
| extend AADSessionId = tostring(parse_json(AppAccessContext).AADSessionId)
| where AADSessionId == "<SessionId from EntraIdSignInEvents>"
| where ActionType in (
    "New-InboxRule","Set-InboxRule",
    "Set-Mailbox","Add-MailboxPermission",
    "New-TransportRule")
| extend RuleDetails = parse_json(RawEventData)
| project Timestamp, AccountUpn, ActionType,
          IPAddress, AADSessionId, RuleDetails, RawEventData`,
      },
      {
        table: "CloudAppEvents",
        action: "Attacker reads the mailbox — MailItemsAccessed under the stolen session. Double mv-expand gives one row per email with FolderPath, InternetMessageId, and Subject (via EmailEvents join) as separate columns",
        kql: `// MailItemsAccessed: double mv-expand → one row per accessed email
CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType == "MailItemsAccessed"
// SaaS sessions route through Microsoft infra — filter by AADSessionId, not IP
| extend AADSessionId = tostring(parse_json(AppAccessContext).AADSessionId)
| where AADSessionId == "<SessionId from EntraIdSignInEvents>"
| extend raw = parse_json(RawEventData)
| mv-expand Folder = raw.Folders
| extend FolderPath = tostring(Folder.Path)
| mv-expand Item = Folder.FolderItems
| extend InternetMessageId = tostring(Item.InternetMessageId)
| extend SizeInBytes       = toint(Item.SizeInBytes)
// Subject not logged in MailItemsAccessed — recover it from EmailEvents
| join kind=leftouter (
    EmailEvents
    | where Timestamp > ago(14d)
    | project InternetMessageId, Subject, SenderFromAddress, RecipientEmailAddress
) on InternetMessageId
| project Timestamp, AccountUpn, AADSessionId, IPAddress,
          FolderPath, InternetMessageId,
          Subject, SenderFromAddress, SizeInBytes
| sort by Timestamp asc
---
// What search terms did the attacker run?
CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType == "SearchQueryInitiatedExchange"
| extend AADSessionId = tostring(parse_json(AppAccessContext).AADSessionId)
| where AADSessionId == "<SessionId from EntraIdSignInEvents>"
| extend raw = parse_json(RawEventData)
| extend SearchQuery = tostring(raw.SearchQuery)
| extend ResultCount = toint(raw.ItemCount)
| project Timestamp, AccountUpn, AADSessionId, IPAddress,
          SearchQuery, ResultCount
| sort by Timestamp asc`,
      },
      {
        table: "EmailEvents",
        action: "Find the BEC fraud email sent from the compromised mailbox or lookalike domain requesting fraudulent wire transfer or payment redirect",
        kql: `EmailEvents
| where Timestamp > ago(14d)
| where SenderFromAddress =~ "<compromised_account>"
    and EmailDirection == "Outbound"
| where Subject has_any (
    "invoice","payment","wire","bank account",
    "transfer","urgent","updated banking","remittance")
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
          Subject, DeliveryAction, NetworkMessageId
| sort by Timestamp desc`,
      },
      {
        table: "AlertInfo",
        action: "Correlate MDO/MDCA/MDI alerts — impossible travel, inbox rule creation, anomalous send volume, and BEC-pattern detections",
        kql: `AlertInfo
| where Timestamp > ago(14d)
| where Title has_any (
    "AiTM","impossible travel","token theft",
    "inbox rule","mail forwarding","BEC",
    "suspicious sign-in","anomalous")
    or Category in ("InitialAccess","Persistence","Collection","Exfiltration")
| project Timestamp, AlertId, Title, Severity,
          Category, AttackTechniques, ServiceSource`,
      },
      {
        table: "AlertEvidence",
        action: "Extract confirmed IOCs — attacker IP, compromised UPN, inbox rule name — to scope blast radius and support account recovery",
        kql: `AlertEvidence
| where Timestamp > ago(14d)
| where AlertId == "<AlertId from AlertInfo>"
| where EntityType in ("User","Ip","Mailbox","CloudApplication")
| project Timestamp, AlertId, EntityType, EvidenceRole,
          AccountUpn, AccountObjectId, RemoteIP, AdditionalFields`,
      },
    ],
    links: [
      { from: "EmailEvents",         to: "UrlClickEvents",       col: "NetworkMessageId" },
      { from: "UrlClickEvents",      to: "EntraIdSignInEvents",  col: "AccountUpn" },
      { from: "EntraIdSignInEvents", to: "CloudAppEvents",       col: "SessionId → AADSessionId" },
      { from: "CloudAppEvents",      to: "GraphApiAuditEvents",  col: "AccountId" },
      { from: "CloudAppEvents",      to: "EmailEvents",          col: "AccountUpn → SenderFromAddress" },
      { from: "AlertInfo",           to: "AlertEvidence",        col: "AlertId" },
      { from: "AlertEvidence",       to: "EntraIdSignInEvents",  col: "AccountUpn" },
    ],
  },
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
        table: "CampaignInfo",
        action: "Check if the email is part of a tracked MDO campaign — get campaign scope and threat type",
        kql: `CampaignInfo
| where CampaignId in ("<CampaignId from EmailEvents>")
| project CampaignId, CampaignName, CampaignType,
          LatestActivityTime, Detections, Description
// CampaignType examples: Phishing, Malware, BEC
// Detections shows how many messages MDO tied to this campaign`,
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
        table: "AlertInfo",
        action: "Check for phishing, malware delivery, and payload execution alerts generated by MDO and MDE across this chain",
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where Category in ("InitialAccess","Execution","Malware")
    or Title has_any (
      "phishing","malware","payload delivery",
      "suspicious email attachment","document exploit",
      "macro","suspicious download")
| project Timestamp, AlertId, Title, Severity,
          Category, AttackTechniques`,
      },
      {
        table: "AlertEvidence",
        action: "Extract file hashes, IPs, and recipient accounts from the alert — pivot back to email and file telemetry to verify scope",
        kql: `AlertEvidence
| where Timestamp > ago(7d)
| where AlertId == "<AlertId from AlertInfo>"
    or RemoteIP == "<RemoteIP from DeviceNetworkEvents>"
    or SHA256 == "<SHA256 from DeviceFileEvents>"
// EntityType "Email" → NetworkMessageId to pivot back to EmailEvents
// EntityType "File"  → SHA256 to find all devices where payload landed
// EntityType "User"  → AccountUpn to confirm victim scope
| project Timestamp, AlertId, EntityType, EvidenceRole,
          RemoteIP, SHA256, FileName, AccountUpn,
          NetworkMessageId, IPAddress`,
      },
    ],
    links: [
      { from: "EmailEvents",          to: "CampaignInfo",             col: "CampaignId" },
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
      { from: "AlertInfo",            to: "AlertEvidence",            col: "AlertId" },
      { from: "AlertEvidence",        to: "EmailEvents",              col: "NetworkMessageId" },
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
        table: "EntraIdSignInEvents",
        action: "Find the Login:Reprocess event — attacker's proxy IP receives the stolen session token. Capture SessionId — the reliable pivot for all downstream cloud activity, regardless of IP",
        kql: `// Isolate the token issuance: Login:Reprocess = attacker proxy receives the session
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where AccountUpn =~ "<AccountUpn from UrlClickEvents>"
| where ErrorCode == 0
| where EndPointCall == "Login:Reprocess"
| project
    TokenIssuedAt   = Timestamp,
    AccountUpn, AccountObjectId,
    SessionId,                      // The stolen token — pivot via AADSessionId downstream
    AttackerProxyIP = IPAddress,
    Country, Application
---
// Full sign-in history — compare victim IP vs attacker proxy IP side-by-side
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where AccountUpn =~ "<AccountUpn>"
| where ErrorCode == 0
| project Timestamp, AccountUpn, SessionId, IPAddress,
          Country, EndPointCall, IsManaged,
          RiskLevelAggregated, AccountObjectId
| sort by Timestamp asc`,
      },
      {
        table: "CloudAppEvents",
        action: "Attacker in Azure Portal — filter by stolen SessionId (AADSessionId in AppAccessContext). SaaS sessions route through Microsoft infra so IPAddress here will be Microsoft datacenter ranges, not the attacker's proxy IP — use AADSessionId",
        kql: `// AADSessionId in AppAccessContext matches SessionId from Login:Reprocess event
// IPAddress in CloudAppEvents = Microsoft datacenter ranges for stolen-session activity
// Attacker proxy IP is still valid for blocking / DeviceNetworkEvents / threat intel
CloudAppEvents
| where Timestamp > ago(7d)
| extend AADSessionId = tostring(parse_json(AppAccessContext).AADSessionId)
| where AADSessionId == "<SessionId from EntraIdSignInEvents>"
| where Application == "Microsoft Azure"
| where ActionType in (
    "ListVirtualMachines",
    "ListSubscriptions",
    "Get Virtual Machine",
    "List Role Assignments",
    "ListResourceGroups",
    "UserLoggedIn")
| project Timestamp, AccountUpn, ActionType, Application,
          IPAddress, ObjectName, ObjectId, AADSessionId
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
// Pivot: CloudAuditEvents.ResourceName == CloudProcessEvents.DeviceName (VM name)
| where DeviceName == "<ResourceName from CloudAuditEvents>"
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
          Category, AttackTechniques`,
      },
      {
        table: "AlertEvidence",
        action: "Extract the specific entities from the alert — user account, source IP, affected device — to pivot back into the sign-in chain",
        kql: `AlertEvidence
| where Timestamp > ago(7d)
| where AlertId == "<AlertId from AlertInfo>"
// EntityType "User" → AccountUpn pivots to EntraIdSignInEvents to find the session
// EntityType "Ip"   → IPAddress to identify attacker source vs. victim source
| where EntityType in ("User","Ip","Machine")
| project Timestamp, AlertId, EntityType, EvidenceRole,
          AccountUpn, IPAddress, DeviceName, DeviceId`,
      },
    ],
    links: [
      { from: "EmailEvents",       to: "UrlClickEvents",       col: "NetworkMessageId" },
      { from: "UrlClickEvents",    to: "EntraIdSignInEvents",  col: "AccountUpn" },
      { from: "EntraIdSignInEvents", to: "CloudAppEvents",     col: "SessionId → AADSessionId" },
      { from: "CloudAppEvents",    to: "GraphApiAuditEvents",  col: "AccountId" },
      { from: "CloudAppEvents",    to: "CloudAuditEvents",     col: "AccountUpn" },
      { from: "CloudAuditEvents",  to: "CloudProcessEvents",   col: "ResourceName → DeviceName" },
      { from: "AlertInfo",         to: "AlertEvidence",        col: "AlertId" },
      { from: "AlertEvidence",     to: "EntraIdSignInEvents",  col: "AccountUpn" },
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
        table: "DeviceNetworkInfo",
        action: "Resolve RemoteIP to a device name — identify the lateral movement target in your fleet",
        kql: `DeviceNetworkInfo
| where Timestamp > ago(7d)
// IPAddresses is a JSON array — use 'has' to search within it
| where IPAddresses has "<RemoteIP from DeviceNetworkEvents>"
| project Timestamp, DeviceName, DeviceId,
          IPAddresses, MacAddress, NetworkAdapterName,
          ConnectedNetworks, DefaultGateways
// DeviceName here is the lateral target — pivot into DeviceProcessEvents next`,
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
          Category, AttackTechniques`,
      },
      {
        table: "AlertEvidence",
        action: "Extract the compromised account and target device from the alert — pivot back into logon telemetry to verify the movement path",
        kql: `AlertEvidence
| where Timestamp > ago(7d)
| where AlertId == "<AlertId from AlertInfo>"
// EntityType "Machine" → DeviceId/DeviceName confirms which host was targeted
// EntityType "User"    → AccountUpn pivots back to DeviceLogonEvents for the full session
| where EntityType in ("Machine","User")
| project Timestamp, AlertId, EntityType, EvidenceRole,
          AccountUpn, DeviceName, DeviceId, IPAddress`,
      },
    ],
    links: [
      { from: "DeviceLogonEvents",       to: "IdentityLogonEvents",     col: "AccountUpn + RemoteIP → IPAddress" },
      { from: "IdentityLogonEvents",     to: "IdentityDirectoryEvents", col: "AccountUpn" },
      { from: "DeviceLogonEvents",       to: "DeviceProcessEvents",     col: "DeviceId + LogonId" },
      { from: "DeviceProcessEvents",     to: "DeviceNetworkEvents",     col: "InitiatingProcessId" },
      { from: "DeviceNetworkEvents",     to: "DeviceNetworkInfo",       col: "RemoteIP → IPAddresses" },
      { from: "DeviceNetworkInfo",       to: "DeviceLogonEvents",       col: "DeviceName" },
      { from: "DeviceProcessEvents",     to: "DeviceFileEvents",        col: "InitiatingProcessId" },
      { from: "DeviceFileEvents",        to: "DeviceRegistryEvents",    col: "DeviceId" },
      { from: "AlertInfo",               to: "AlertEvidence",           col: "AlertId" },
      { from: "AlertEvidence",           to: "DeviceLogonEvents",        col: "AccountUpn + DeviceId" },
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
        table: "DeviceImageLoadEvents",
        action: "Confirm the payload DLL was actually loaded into memory — and see what process loaded it",
        kql: `DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where DeviceId == "<DeviceId from DeviceFileEvents>"
| where SHA256 == "<SHA256 from DeviceFileCertificateInfo>"
    or FileName =~ "<FileName from DeviceFileEvents>"
| project Timestamp, DeviceName, FileName, FolderPath,
          SHA256, IsSigned, IsCodeIntegrityPolicyEnabled,
          InitiatingProcessFileName, InitiatingProcessId,
          InitiatingProcessCommandLine
// IsSigned=false on a newly dropped DLL loaded by a trusted process = strong malware signal`,
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
        table: "AlertInfo",
        action: "Look for persistence-class alerts: scheduled tasks, registry autoruns, service installs, DLL hijacking",
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where Category in ("Persistence","DefenseEvasion")
    or Title has_any (
      "scheduled task","registry persistence",
      "startup folder","service install",
      "DLL side-loading","hijack","autorun",
      "image file execution")
| project Timestamp, AlertId, Title, Severity,
          Category, AttackTechniques`,
      },
      {
        table: "AlertEvidence",
        action: "Extract the payload file from the alert and pivot back to where it appeared on disk",
        kql: `AlertEvidence
| where Timestamp > ago(7d)
| where AlertId == "<AlertId from AlertInfo>"
// EntityType "File" gives SHA256/FileName to pivot to DeviceFileEvents
// EntityType "Machine" confirms the persisted host
| where EntityType in ("File","Machine","Process")
| project Timestamp, AlertId, EntityType, EvidenceRole,
          FileName, SHA256, DeviceName, DeviceId,
          ProcessCommandLine`,
      },
    ],
    links: [
      { from: "DeviceRegistryEvents",    to: "DeviceProcessEvents",       col: "InitiatingProcessId" },
      { from: "DeviceProcessEvents",     to: "DeviceFileEvents",          col: "InitiatingProcessId" },
      { from: "DeviceFileEvents",        to: "DeviceFileCertificateInfo", col: "SHA256" },
      { from: "DeviceFileCertificateInfo", to: "DeviceImageLoadEvents",  col: "SHA256" },
      { from: "DeviceFileEvents",        to: "DeviceImageLoadEvents",    col: "FileName | FolderPath" },
      { from: "DeviceEvents",            to: "DeviceProcessEvents",       col: "InitiatingProcessId" },
      { from: "DeviceProcessEvents",     to: "DeviceLogonEvents",         col: "DeviceId + AccountName" },
      { from: "DeviceLogonEvents",       to: "IdentityDirectoryEvents",   col: "AccountUpn" },
      { from: "AlertInfo",              to: "AlertEvidence",              col: "AlertId" },
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
        table: "IdentityQueryEvents",
        action: "Raw LDAP/DNS queries — see exactly what attributes the attacker enumerated for Kerberoast target selection",
        kql: `IdentityQueryEvents
| where Timestamp > ago(7d)
| where AccountUpn =~ "<AccountUpn from IdentityDirectoryEvents>"
| where QueryType in ("Ldap","ActiveDirectory")
| where QueryTarget has_any (
    "servicePrincipalName","adminCount",
    "Domain Admins","krbtgt","ms-DS-MachineAccountQuota",
    "userAccountControl","password")
| project Timestamp, AccountUpn, DeviceName, IPAddress,
          Protocol, QueryType, QueryTarget
// High-volume repeated queries to the same QueryTarget = automated enumeration`,
      },
      {
        table: "EntraIdSignInEvents",
        action: "Detect spray attacks: many failed sign-ins across accounts, same IP",
        kql: `EntraIdSignInEvents
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
| where AccountUpn in ("<accounts from EntraIdSignInEvents>")
| where ActionType == "LogonSuccess"
| project Timestamp, AccountUpn, IPAddress,
          DeviceName, LogonType, Protocol`,
      },
      {
        table: "DeviceLogonEvents",
        action: "Identify which machine(s) the attacker actually authenticated to — DeviceId bridges to device-side dump activity",
        kql: `DeviceLogonEvents
| where Timestamp > ago(1d)
| where AccountUpn in ("<AccountUpn from IdentityLogonEvents>")
| where ActionType == "LogonSuccess"
| where LogonType in (2, 3, 10)         // Interactive, Network, RemoteInteractive
| project Timestamp, DeviceName, DeviceId,
          AccountUpn, AccountDomain, LogonType, LogonId, RemoteIP
// DeviceId → pivot to DeviceProcessEvents to find if dumping tools ran after this logon
// DeviceId → pivot to DeviceEvents to find LSASS access attempts on this host`,
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
      {
        table: "AlertEvidence",
        action: "Extract the compromised account and credential-dumping process from the alert — pivot to logon events to track credential reuse",
        kql: `AlertEvidence
| where Timestamp > ago(7d)
| where AlertId == "<AlertId from AlertInfo>"
// EntityType "User"    → AccountUpn to pivot to IdentityLogonEvents for reuse tracking
// EntityType "Process" → FileName/SHA256 of the dumping tool (mimikatz, procdump)
| where EntityType in ("User","Process","Machine")
| project Timestamp, AlertId, EntityType, EvidenceRole,
          AccountUpn, DeviceName, DeviceId,
          FileName, ProcessCommandLine, SHA256`,
      },
    ],
    links: [
      { from: "DeviceEvents",        to: "DeviceProcessEvents",     col: "InitiatingProcessId" },
      { from: "DeviceProcessEvents", to: "DeviceFileEvents",        col: "InitiatingProcessId" },
      { from: "IdentityLogonEvents", to: "IdentityDirectoryEvents", col: "AccountUpn" },
      { from: "IdentityDirectoryEvents", to: "IdentityQueryEvents", col: "AccountUpn" },
      { from: "EntraIdSignInEvents", to: "IdentityLogonEvents",     col: "IPAddress + AccountUpn" },
      { from: "IdentityLogonEvents",  to: "DeviceLogonEvents",       col: "AccountUpn" },
      { from: "DeviceLogonEvents",    to: "DeviceProcessEvents",     col: "DeviceId" },
      { from: "DeviceLogonEvents",    to: "DeviceEvents",            col: "DeviceId" },
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
        table: "EntraIdSignInEvents",
        action: "Identify sign-in from impossible travel, new ASN, or legacy protocol",
        kql: `EntraIdSignInEvents
| where Timestamp > ago(7d)
| where AccountUpn =~ "<target UPN>"
| where RiskLevelAggregated >= 10
    or IsManaged == false
    or AuthenticationProcessingDetails has "Legacy Auth"
| project Timestamp, AccountUpn, IPAddress, Country,
          City, DeviceName, Application, ErrorCode,
          RiskLevelAggregated, AccountObjectId`,
      },
      {
        table: "CloudAppEvents",
        action: "Look for mass download, mail forwarding rules, or admin actions",
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where AccountObjectId == "<AccountObjectId from EntraIdSignInEvents>"
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
| where AccountUpn =~ "<AccountUpn from EntraIdSignInEvents>"
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
        table: "IdentityAccountInfo",
        action: "Cross-reference on-prem SID with cloud account — confirm hybrid identity linkage and spot orphaned accounts",
        kql: `IdentityAccountInfo
| where AccountUpn =~ "<AccountUpn from IdentityInfo>"
| project AccountUpn, AccountDisplayName, OnPremSid,
          CloudAccountId, Type, GivenName, Surname,
          Department, JobTitle
// OnPremSid links back to AD; CloudAccountId links to AAD ObjectId
// A mismatch between IdentityInfo.CloudSid and OnPremSid indicates a broken sync`,
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
      {
        table: "AlertEvidence",
        action: "Extract the compromised user from the alert and pivot back to the sign-in chain to find the initial access point",
        kql: `AlertEvidence
| where Timestamp > ago(7d)
| where AlertId == "<AlertId from AlertInfo>"
// EntityType "User"             → AccountUpn to pivot to EntraIdSignInEvents
// EntityType "Ip"               → IPAddress of the attacker's sign-in source
// EntityType "CloudApplication" → shows which app the attacker abused
| where EntityType in ("User","Ip","CloudApplication")
| project Timestamp, AlertId, EntityType, EvidenceRole,
          AccountUpn, IPAddress, AdditionalFields`,
      },
    ],
    links: [
      { from: "EntraIdSignInEvents",     to: "CloudAppEvents",         col: "AccountObjectId" },
      { from: "CloudAppEvents",          to: "GraphApiAuditEvents",    col: "AccountId" },
      { from: "EntraIdSignInEvents",     to: "IdentityDirectoryEvents",col: "AccountUpn" },
      { from: "IdentityDirectoryEvents", to: "IdentityInfo",           col: "AccountUpn" },
      { from: "IdentityInfo",           to: "IdentityAccountInfo",    col: "AccountUpn" },
      { from: "CloudAppEvents",          to: "CloudAuditEvents",       col: "AccountUpn" },
      { from: "CloudAppEvents",          to: "DataSecurityEvents",     col: "AccountUpn" },
      { from: "AlertInfo",               to: "AlertEvidence",          col: "AlertId" },
      { from: "AlertEvidence",           to: "EntraIdSignInEvents",    col: "AccountUpn" },
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
| summarize ConnCount = count(),
            FirstSeen = min(Timestamp),
            LastSeen  = max(Timestamp)
    by DeviceName, DeviceId, RemoteIP, RemoteUrl,
       InitiatingProcessFileName, bin(Timestamp, 1h)
| where ConnCount > 50                 // High connection frequency = exfil or C2
| order by ConnCount desc`,
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
      {
        table: "AlertEvidence",
        action: "Extract the exfiltrating account and destination IP from the alert — pivot to CloudAppEvents to quantify what was taken",
        kql: `AlertEvidence
| where Timestamp > ago(7d)
| where AlertId == "<AlertId from AlertInfo>"
// EntityType "User" → AccountUpn to pivot to CloudAppEvents for download volume
// EntityType "Ip"   → RemoteIP destination of the exfil
// EntityType "File" → FileName/SHA256 of the specific file exfiltrated
| where EntityType in ("User","Ip","File","Machine")
| project Timestamp, AlertId, EntityType, EvidenceRole,
          AccountUpn, DeviceName, DeviceId,
          FileName, SHA256, RemoteIP`,
      },
    ],
    links: [
      { from: "CloudAppEvents",      to: "DeviceNetworkEvents", col: "AccountUpn → InitiatingProcessAccountUpn" },
      { from: "DeviceNetworkEvents", to: "DeviceProcessEvents", col: "InitiatingProcessId" },
      { from: "DeviceProcessEvents", to: "DeviceFileEvents",    col: "InitiatingProcessId" },
      { from: "DeviceNetworkEvents", to: "EmailEvents",         col: "InitiatingProcessAccountUpn → SenderFromAddress" },
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
        table: "DeviceInfo",
        action: "Get full device context for exposed machines — OS, sensor status, last logged-on user — before pivoting into behavioral events",
        kql: `DeviceInfo
| where DeviceId in ("<DeviceIds from DeviceTvmSoftwareInventory>")
// DeviceInfo logs periodically — use arg_max to get the latest snapshot per device
| summarize arg_max(Timestamp, *) by DeviceId
| project DeviceId, DeviceName, OSPlatform, OSVersion,
          LoggedOnUsers, JoinType, OnboardingStatus, MachineGroup
// OnboardingStatus confirms MDE coverage — if "CanBeOnboarded", sensor gap exists
// LoggedOnUsers shows who was active on the machine at last check-in`,
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
          Category, AttackTechniques`,
      },
      {
        table: "AlertEvidence",
        action: "Extract the exploited device from the alert — pivot back to DeviceInfo to confirm it was in your exposed fleet",
        kql: `AlertEvidence
| where Timestamp > ago(7d)
| where AlertId == "<AlertId from AlertInfo>"
// EntityType "Machine" → DeviceId confirms which exposed device was actually hit
// EntityType "Process" → FileName of the shellcode/spawned child process
// EntityType "File"    → SHA256 of the dropped payload for threat intel lookup
| where EntityType in ("Machine","Process","File")
| project Timestamp, AlertId, EntityType, EvidenceRole,
          DeviceName, DeviceId, FileName, SHA256,
          ProcessCommandLine`,
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
        table: "EntraIdSignInEvents",
        action: "Review cloud sign-in risk score and location anomalies",
        kql: `EntraIdSignInEvents
| where Timestamp > ago(30d)
| where AccountUpn =~ "<AccountUpn from IdentityLogonEvents>"
| project Timestamp, AccountUpn, IPAddress, Country, City,
          DeviceName, Application, RiskLevelAggregated,
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
      {
        table: "AlertEvidence",
        action: "Extract the user and sensitive files flagged in the alert — pivot back to CloudAppEvents to find the full scope of what they accessed",
        kql: `AlertEvidence
| where Timestamp > ago(30d)
| where AlertId == "<AlertId from AlertInfo>"
// EntityType "User" → AccountUpn to pivot to CloudAppEvents for download history
// EntityType "File" → FileName/SHA256 of the specific sensitive data touched
| where EntityType in ("User","File","Machine")
| project Timestamp, AlertId, EntityType, EvidenceRole,
          AccountUpn, DeviceName, FileName, SHA256`,
      },
    ],
    links: [
      { from: "DataSecurityEvents",  to: "CloudAppEvents",     col: "AccountUpn" },
      { from: "CloudAppEvents",      to: "IdentityLogonEvents",col: "AccountUpn" },
      { from: "IdentityLogonEvents", to: "EntraIdSignInEvents",col: "AccountUpn" },
      { from: "CloudAppEvents",      to: "DeviceFileEvents",   col: "AccountUpn → InitiatingProcessAccountUpn" },
      { from: "DeviceFileEvents",    to: "DeviceProcessEvents",col: "InitiatingProcessId" },
      { from: "CloudAppEvents",      to: "EmailEvents",        col: "AccountUpn" },
      { from: "AlertInfo",           to: "AlertEvidence",      col: "AlertId" },
      { from: "AlertEvidence",       to: "CloudAppEvents",     col: "AccountUpn" },
    ],
  },
  {
    id: "infoStealer",
    name: "Info Stealer Malware",
    icon: "🕵️",
    tactic: "Collection > Exfiltration",
    color: "#a78bfa",
    desc: "Malvertising or fake software drops Lumma/Redline/StealC. The stealer harvests browser credentials, session cookies, and crypto wallets then exfils via Telegram Bot API or Discord webhook.",
    steps: [
      {
        table: "DeviceProcessEvents",
        action: "Find the dropper or initial execution — fake installer from Temp/Downloads, browser-spawned LOLBin, or renamed executable with suspicious parent",
        kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FolderPath has_any (@"\Temp\",@"\AppData\Local\",@"\Downloads\")
    or InitiatingProcessFileName in~ (
        "chrome.exe","msedge.exe","firefox.exe",
        "explorer.exe","msiexec.exe")
| where FileName in~ (
    "powershell.exe","cmd.exe","mshta.exe",
    "wscript.exe","cscript.exe","regsvr32.exe","rundll32.exe")
    or SHA256 == "<known_stealer_hash>"
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
          SHA256, FolderPath, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AccountName`,
      },
      {
        table: "DeviceFileEvents",
        action: "Identify browser credential database reads by a non-browser process — Login Data, Local State, or Firefox profile access is the stealer fingerprint",
        kql: `DeviceFileEvents
| where Timestamp > ago(7d)
| where (ActionType == "FileCreated"
    and FolderPath has_any (@"\Temp\",@"\AppData\",@"\ProgramData\"))
    or (FolderPath has_any (
        @"Chrome\User Data\Default\Login Data",
        @"Chrome\User Data\Local State",
        @"Edge\User Data\Default\Login Data",
        @"Mozilla\Firefox\Profiles")
    and InitiatingProcessFileName !in~ (
        "chrome.exe","msedge.exe","firefox.exe"))
| project Timestamp, DeviceName, ActionType, FileName,
          FolderPath, SHA256, InitiatingProcessFileName,
          InitiatingProcessCommandLine`,
      },
      {
        table: "DeviceEvents",
        action: "DPAPI decryption by a non-browser process confirms the stealer is unwrapping the browser master key to decrypt stored credentials and cookies",
        kql: `DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "DpapiAccessed","OpenProcessApiCall")
| where InitiatingProcessFileName !in~ (
    "chrome.exe","msedge.exe","firefox.exe",
    "explorer.exe","lsass.exe","svchost.exe")
| project Timestamp, DeviceName, ActionType,
          InitiatingProcessFileName, InitiatingProcessId,
          InitiatingProcessCommandLine, FileName, AccountName`,
      },
      {
        table: "DeviceRegistryEvents",
        action: "Check Run key persistence — stealers often install a dropper or updater to persist between credential harvesting runs",
        kql: `DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has_any (
    @"Software\Microsoft\Windows\CurrentVersion\Run",
    @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    @"SOFTWARE\Classes\CLSID")
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where InitiatingProcessFileName !in~ (
    "msiexec.exe","svchost.exe","explorer.exe","system")
| project Timestamp, DeviceName, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessId`,
      },
      {
        table: "DeviceNetworkEvents",
        action: "Catch the exfil — stealers POST credential logs to Telegram Bot API, Discord webhooks, or a C2 panel. Non-browser processes calling these endpoints is a confirmed steal.",
        kql: `DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any (
    "api.telegram.org",
    "discord.com/api/webhooks","t.me")
    or (RemoteIPType == "Public"
        and InitiatingProcessFileName !in~ (
            "chrome.exe","msedge.exe","firefox.exe",
            "telegram.exe","discord.exe","slack.exe"))
| project Timestamp, DeviceName, RemoteIP, RemoteUrl,
          RemotePort, InitiatingProcessFileName,
          InitiatingProcessId`,
      },
      {
        table: "AlertInfo",
        action: "Check MDE alerts on browser credential theft, suspicious DPAPI access, Telegram/Discord C2, and known stealer family detections",
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where Category in ("Malware","SuspiciousActivity","CredentialAccess")
    or Title has_any (
        "stealer","credential","browser data","DPAPI",
        "Lumma","Redline","StealC","Vidar",
        "Telegram","Discord C2","infostealer")
| project Timestamp, AlertId, Title, Severity,
          Category, AttackTechniques, ServiceSource`,
      },
      {
        table: "AlertEvidence",
        action: "Extract the stealer binary hash — SHA256 lets you scope all devices where this payload landed across the entire environment",
        kql: `AlertEvidence
| where Timestamp > ago(7d)
| where AlertId == "<AlertId from AlertInfo>"
| where EntityType in ("File","Process","Ip","Machine")
| project Timestamp, AlertId, EntityType, EvidenceRole,
          FileName, SHA256, RemoteIP, DeviceName, ProcessCommandLine`,
      },
    ],
    links: [
      { from: "DeviceProcessEvents",  to: "DeviceFileEvents",      col: "InitiatingProcessId" },
      { from: "DeviceFileEvents",     to: "DeviceEvents",          col: "DeviceId + InitiatingProcessId" },
      { from: "DeviceEvents",         to: "DeviceProcessEvents",   col: "InitiatingProcessId" },
      { from: "DeviceProcessEvents",  to: "DeviceRegistryEvents",  col: "InitiatingProcessId" },
      { from: "DeviceProcessEvents",  to: "DeviceNetworkEvents",   col: "InitiatingProcessId" },
      { from: "AlertInfo",            to: "AlertEvidence",         col: "AlertId" },
      { from: "AlertEvidence",        to: "DeviceFileEvents",      col: "SHA256" },
    ],
  },
  {
    id: "clickFix",
    name: "ClickFix Social Eng.",
    icon: "📋",
    tactic: "Execution",
    color: "#22d3ee",
    desc: "Fake CAPTCHA or browser-error dialog silently writes an encoded PowerShell cradle to the clipboard, then instructs the user to paste it into the Windows Run dialog — no attachment, no macro.",
    steps: [
      {
        table: "EmailEvents",
        action: "Find the phishing email linking to a ClickFix page — fake CAPTCHAs, document viewer errors, or browser update prompts",
        kql: `EmailEvents
| where Timestamp > ago(7d)
| where DeliveryAction in ("Delivered","DeliveredAsSpam")
| where Subject has_any (
    "verify","captcha","browser","document",
    "access","update","error","fix","confirm")
  and SenderFromDomain !endswith "yourdomain.com"
| project Timestamp, SenderFromAddress, SenderFromDomain,
          RecipientEmailAddress, Subject, ThreatTypes, NetworkMessageId`,
      },
      {
        table: "DeviceNetworkEvents",
        action: "Identify the browser visiting the ClickFix landing page — the malicious JavaScript will silently overwrite the clipboard with a PowerShell cradle",
        kql: `DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (
    "chrome.exe","msedge.exe","firefox.exe","iexplore.exe")
| where RemoteUrl has_any (
    "captcha","verify","browser-fix","repair",
    "windows-update","document-view","access-denied")
    and RemoteIPType == "Public"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP,
          RemotePort, InitiatingProcessFileName`,
      },
      {
        table: "DeviceEvents",
        action: "Clipboard write from the browser process — this is the ClickFix fingerprint before any command executes",
        kql: `DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("SetClipboardText","ProcessMemoryAccess")
    and InitiatingProcessFileName in~ (
        "chrome.exe","msedge.exe","firefox.exe")
| project Timestamp, DeviceName, ActionType,
          InitiatingProcessFileName, InitiatingProcessId,
          AdditionalFields`,
      },
      {
        table: "DeviceProcessEvents",
        action: "The ClickFix tell: cmd.exe or PowerShell parented by explorer.exe with an encoded command — this is the user pasting from Windows+R. No Office, no macro, no download.",
        kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ (
    "powershell.exe","cmd.exe","mshta.exe","certutil.exe")
| where InitiatingProcessFileName in~ (
    "explorer.exe","userinit.exe","WinLogonUI.exe")
| where ProcessCommandLine has_any (
    "-EncodedCommand","-enc ",
    "IEX","Invoke-Expression","DownloadString",
    "WebClient","certutil","bitsadmin","mshta http")
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, SHA256, AccountName`,
      },
      {
        table: "DeviceFileEvents",
        action: "Payload written by the PowerShell cradle — executables or scripts in Temp/AppData immediately after the Run dialog command",
        kql: `DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (
    "powershell.exe","cmd.exe","mshta.exe","certutil.exe")
| where ActionType == "FileCreated"
| where FolderPath has_any (
    @"\Temp\",@"\AppData\",@"\ProgramData\",@"\Windows\Temp\")
    or FileName has_any (".exe",".dll",".ps1",".bat",".vbs")
| project Timestamp, DeviceName, FileName, FolderPath,
          SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine`,
      },
      {
        table: "DeviceRegistryEvents",
        action: "Persistence installed by the dropped payload — ClickFix commonly delivers AsyncRAT, DarkGate, or Lumma Stealer, all of which write Run key persistence",
        kql: `DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has_any (
    @"Software\Microsoft\Windows\CurrentVersion\Run",
    @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    @"SOFTWARE\Classes\CLSID")
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where InitiatingProcessFileName !in~ (
    "msiexec.exe","svchost.exe","explorer.exe")
| project Timestamp, DeviceName, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessFileName`,
      },
      {
        table: "AlertInfo",
        action: "Correlate MDE alerts on explorer-parented PowerShell, encoded commands, LOLBin abuse, and ClickFix-specific detections",
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where Category in ("Execution","InitialAccess","Persistence")
    or Title has_any (
        "ClickFix","encoded command","suspicious PowerShell",
        "mshta","certutil download","LOLBin",
        "clipboard","download cradle","suspicious process")
| project Timestamp, AlertId, Title, Severity,
          Category, AttackTechniques, ServiceSource`,
      },
      {
        table: "AlertEvidence",
        action: "Extract the payload hash and the LOLBin process — SHA256 scopes all devices hit by the same campaign payload",
        kql: `AlertEvidence
| where Timestamp > ago(7d)
| where AlertId == "<AlertId from AlertInfo>"
| where EntityType in ("Process","File","Machine","Ip")
| project Timestamp, AlertId, EntityType, EvidenceRole,
          FileName, SHA256, ProcessCommandLine,
          DeviceName, RemoteIP`,
      },
    ],
    links: [
      { from: "EmailEvents",          to: "DeviceNetworkEvents",  col: "RecipientEmailAddress → device browsing" },
      { from: "DeviceNetworkEvents",  to: "DeviceEvents",         col: "DeviceId + InitiatingProcessId" },
      { from: "DeviceEvents",         to: "DeviceProcessEvents",  col: "InitiatingProcessId" },
      { from: "DeviceProcessEvents",  to: "DeviceNetworkEvents",  col: "InitiatingProcessId" },
      { from: "DeviceProcessEvents",  to: "DeviceFileEvents",     col: "InitiatingProcessId" },
      { from: "DeviceFileEvents",     to: "DeviceRegistryEvents", col: "DeviceId" },
      { from: "AlertInfo",            to: "AlertEvidence",        col: "AlertId" },
      { from: "AlertEvidence",        to: "DeviceProcessEvents",  col: "SHA256" },
    ],
  },
];

export function buildEdges(useCases) {
  const edgeMap = new Map();

  // Seed with comprehensive schema-level pivots (tier comes from here)
  PIVOT_EDGES.forEach(pivot => {
    const key = [pivot.source, pivot.target].sort().join("||");
    edgeMap.set(key, {
      source: pivot.source,
      target: pivot.target,
      cols: [...pivot.cols],
      useCases: [],
      tier: pivot.tier,
    });
  });

  // Overlay use-case-specific edges (adds useCases tracking; cols merged in)
  useCases.forEach(uc => {
    uc.links.forEach(link => {
      const key = [link.from, link.to].sort().join("||");
      if (!edgeMap.has(key)) {
        // Edge not in PIVOT_EDGES — add with default tier
        edgeMap.set(key, { source: link.from, target: link.to, cols: [], useCases: [], tier: "mid" });
      }
      const e = edgeMap.get(key);
      if (!e.cols.includes(link.col)) e.cols.push(link.col);
      if (!e.useCases.includes(uc.id)) e.useCases.push(uc.id);
    });
  });

  return Array.from(edgeMap.values());
}

export const ALL_EDGES = buildEdges(USE_CASES);

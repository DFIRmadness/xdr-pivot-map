// Column definitions for Defender XDR Advanced Hunting schema.
// `docs`        — aligned with Microsoft Defender XDR Advanced Hunting schema documentation
// `plain`       — analyst-friendly plain English explanation
// `dfir`        — why this column matters in a DFIR / threat hunting scenario
// `docUrl`      — link to the Microsoft Learn schema reference for the most relevant table
// `crossTables` — other tables containing this column; `as` note if name differs

export const COLUMN_INFO = {

  // ── Identity ──────────────────────────────────────────────────────────────

  "AccountUpn": {
    docs: "User Principal Name (UPN) of the account in user@domain.com format, as recorded by the data source. May reflect the on-premises UPN or the cloud UPN depending on the table.",
    plain: "The user's login name in email format. The most consistent cross-table user identifier — works across device, identity, email, and cloud app tables.",
    dfir: "Your primary identity pivot. An attacker who compromises a single account will leave UPN breadcrumbs across EmailEvents, IdentityLogonEvents, DeviceLogonEvents, EntraIdSignInEvents, CloudAppEvents, and BehaviorInfo. Note: CloudAuditEvents and GraphApiAuditEvents do not have an AccountUpn column — use RawEventData['caller'] for CloudAuditEvents and AccountObjectId for GraphApiAuditEvents.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitylogonevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceLogonEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceEvents" },
      { table: "IdentityInfo" },
      { table: "IdentityAccountInfo" },
      { table: "IdentityLogonEvents" },
      { table: "IdentityQueryEvents" },
      { table: "IdentityDirectoryEvents" },
      { table: "EntraIdSignInEvents" },
      { table: "AADSignInEventsBeta" },
      { table: "CloudAppEvents" },
      { table: "UrlClickEvents" },
      { table: "AlertEvidence" },
      { table: "BehaviorInfo" },
      { table: "DataSecurityEvents" },
    ],
  },

  "AccountObjectId": {
    docs: "Unique object identifier for the account in Azure Active Directory (Entra ID). A stable GUID that persists even if the UPN or display name changes.",
    plain: "The AAD GUID for a user. More reliable than UPN for cloud pivots because it doesn't change when someone's email address changes.",
    dfir: "Essential for cloud investigations. When an attacker renames an account or changes UPN to cover tracks, the ObjectId stays the same. Use this to join EntraIdSignInEvents into CloudAppEvents to trace what a compromised account actually did in M365. Also present in BehaviorEntities for UEBA correlation.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table",
    crossTables: [
      { table: "IdentityInfo" },
      { table: "IdentityAccountInfo" },
      { table: "IdentityLogonEvents" },
      { table: "IdentityDirectoryEvents" },
      { table: "IdentityQueryEvents" },
      { table: "EntraIdSignInEvents" },
      { table: "AADSignInEventsBeta" },
      { table: "CloudAppEvents" },
      { table: "GraphApiAuditEvents" },
      { table: "EmailEvents", as: "SenderObjectId" },
      { table: "EmailAttachmentInfo", as: "SenderObjectId" },
      { table: "AlertEvidence" },
      { table: "BehaviorEntities" },
      { table: "DataSecurityEvents" },
    ],
  },

  "AccountId": {
    docs: "Identifier for the account as recorded in CloudAppEvents. May be an AAD ObjectId, SID, or email address depending on the application and event type.",
    plain: "The account identifier as the cloud app sees it — usually the same as AccountObjectId for Microsoft 365 apps.",
    dfir: "Use this to join CloudAppEvents activities to the user identity. Note: this column exists in CloudAppEvents but NOT in GraphApiAuditEvents (which uses AccountObjectId) or CloudAuditEvents (which embeds caller info in RawEventData).",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table",
    crossTables: [
      { table: "CloudAppEvents" },
    ],
  },

  "AccountName": {
    docs: "SAM account name (pre-Windows 2000 format) of the account, without the domain prefix. For local accounts this is simply the username; for domain accounts it omits the domain.",
    plain: "The short username without the domain — e.g. 'jsmith' rather than 'CORP\\jsmith' or 'jsmith@corp.com'.",
    dfir: "Useful for joining DeviceProcessEvents to DeviceLogonEvents on the same machine. Be aware it is not globally unique — two different domains can have the same AccountName. Always combine with AccountDomain or DeviceId to avoid false pivots.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceLogonEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceEvents" },
      { table: "CloudProcessEvents" },
      { table: "IdentityDirectoryEvents" },
    ],
  },

  "AccountDomain": {
    docs: "Domain of the account. For domain-joined machines this is the AD domain name; for local accounts it is the device name.",
    plain: "Which domain the account belongs to. Local accounts show the machine name as the domain.",
    dfir: "Critical for distinguishing local administrator abuse from domain account abuse. If AccountDomain equals DeviceName, the attacker is using a local account — often a sign of lateral movement using built-in admin accounts or freshly created local accounts.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table",
    crossTables: [
      { table: "DeviceLogonEvents" },
      { table: "DeviceProcessEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceEvents" },
    ],
  },

  "AccountDisplayName": {
    docs: "Display name of the account as stored in Azure Active Directory or the directory service. Typically the user's full name.",
    plain: "The human-readable name of the account — e.g. 'Jane Smith'. Not unique and not stable, but useful for human-readable reporting.",
    dfir: "Helpful for quick human readability in reports, but never use it as a join key — display names can be duplicated and changed. In cloud app events it can reveal service accounts or shared mailboxes being abused (e.g. 'Finance Shared Mailbox' accessing hundreds of emails).",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table",
    crossTables: [
      { table: "AADSignInEventsBeta" },
      { table: "CloudAppEvents" },
      { table: "IdentityDirectoryEvents" },
    ],
  },

  "TargetAccountUpn": {
    docs: "UPN of the account that was the target of the directory event — for example, the account that was created, modified, deleted, or added to a group.",
    plain: "The account that had something done to it, as opposed to AccountUpn which is who did it.",
    dfir: "Key for detecting privilege escalation and persistence. If TargetAccountUpn is a high-value account (admin, service account) and AccountUpn is a regular user, something is wrong. Also watch for TargetAccountUpn being added to privileged groups.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitydirectoryevents-table",
    crossTables: [
      { table: "IdentityDirectoryEvents" },
      { table: "IdentityQueryEvents", as: "QueryTarget" },
    ],
  },

  "LogonType": {
    docs: "Type of logon session. Common values: Interactive (2) — direct keyboard login; Network (3) — SMB/RPC; RemoteInteractive (10) — RDP; CachedInteractive (11) — cached domain credentials.",
    plain: "How the user logged on. Interactive means at the keyboard; Network means over the wire (SMB, WMI, etc.); RemoteInteractive means RDP.",
    dfir: "One of the most valuable lateral movement indicators. Network logons (type 3) from unusual sources = pass-the-hash or SMB relay. RemoteInteractive (type 10) = RDP. Batch and Service logons from unexpected accounts = scheduled task or service-based persistence.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table",
    crossTables: [
      { table: "DeviceLogonEvents" },
      { table: "IdentityLogonEvents" },
    ],
  },

  "RemoteDeviceName": {
    docs: "Name of the remote device that initiated or received the logon. Populated when the logon source is a network-accessible device that has been resolved.",
    plain: "The hostname of the machine on the other end of a network logon — who connected to this machine.",
    dfir: "Helps trace the source of lateral movement. If RemoteDeviceName is a workstation connecting to a server via RDP or SMB, it tells you where the attacker was before reaching the current machine. Cross-reference with that device's own logon and process events.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table",
    crossTables: [
      { table: "DeviceLogonEvents" },
    ],
  },

  "Protocol": {
    docs: "Network or authentication protocol used for the logon or query — e.g. Kerberos, NTLM, Ldap, Ldaps, Samr.",
    plain: "The authentication or query protocol. NTLM vs Kerberos matters; LDAP vs LDAPS matters.",
    dfir: "NTLM in environments that should be Kerberos-only is a major red flag — it is the signature of pass-the-hash and NTLM relay attacks. Unexpected LDAP (unencrypted) queries can indicate domain reconnaissance. LDAPS from unexpected hosts can indicate LDAP-based C2.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitylogonevents-table",
    crossTables: [
      { table: "IdentityLogonEvents" },
      { table: "IdentityQueryEvents" },
      { table: "IdentityDirectoryEvents" },
    ],
  },

  "IPAddress": {
    docs: "IP address associated with the account during the event. For identity events this is the source IP of the authentication request.",
    plain: "The source IP address of the user at the time of the event.",
    dfir: "The bridge between identity events and network/endpoint events. Match IPAddress from IdentityLogonEvents against DeviceNetworkInfo.IPAddresses to find the actual device making the authentication. Sudden changes in IPAddress (especially to TOR/VPN) mid-session are strong indicators of account takeover.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitylogonevents-table",
    crossTables: [
      { table: "IdentityLogonEvents" },
      { table: "IdentityQueryEvents" },
      { table: "IdentityDirectoryEvents" },
      { table: "EntraIdSignInEvents" },
      { table: "AADSignInEventsBeta" },
      { table: "CloudAppEvents" },
      { table: "CloudAuditEvents" },
      { table: "GraphApiAuditEvents" },
      { table: "UrlClickEvents" },
      { table: "DataSecurityEvents" },
      { table: "DeviceLogonEvents", as: "RemoteIP" },
    ],
  },

  "Country": {
    docs: "Country or region associated with the IP address of the event, resolved via geolocation. May be empty if the IP cannot be geolocated.",
    plain: "Where in the world the request came from, based on the source IP.",
    dfir: "Instant triage signal. A CFO whose account suddenly signs in from a country they have never been to — while they are sitting in the office — is account takeover until proven otherwise. Always baseline normal countries for high-value accounts.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table",
    crossTables: [
      { table: "EntraIdSignInEvents" },
      { table: "AADSignInEventsBeta" },
      { table: "IdentityLogonEvents" },
      { table: "CloudAppEvents" },
    ],
  },

  "IsAnonymousProxy": {
    docs: "Boolean indicating whether the sign-in IP address was identified as an anonymous proxy, VPN, or TOR exit node by Microsoft's threat intelligence.",
    plain: "True if the login came from a known anonymiser — VPN, TOR, or proxy service.",
    dfir: "Attackers use anonymisers to obscure their origin. A legitimate employee signing in through TOR is almost never valid. Combine with RiskLevelAggregated for high-confidence account compromise alerts.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table",
    crossTables: [
      { table: "EntraIdSignInEvents" },
      { table: "AADSignInEventsBeta" },
    ],
  },

  "RiskLevelAggregated": {
    docs: "Entra ID Protection risk level assessed at sign-in time. Integer values: 0=none, 1=low, 10=medium, 100=high. Factors include leaked credentials, impossible travel, anonymous IP, and unusual sign-in properties. Present in both AADSignInEventsBeta and EntraIdSignInEvents under this same column name.",
    plain: "Microsoft's real-time risk score for the sign-in — high means Entra thinks something is suspicious.",
    dfir: "A pre-computed threat signal you should always include in sign-in investigations. High risk + successful sign-in + no MFA challenge = Conditional Access gap. Cross-reference with IsAnonymousProxy and Country to understand what drove the risk score.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table",
    crossTables: [
      { table: "EntraIdSignInEvents" },
      { table: "AADSignInEventsBeta" },
    ],
  },

  "ErrorCode": {
    docs: "Entra ID sign-in error code. 0 = success. Common failure codes: 50126 = invalid credentials, 50053 = account locked, 50055 = expired password, 50074 = MFA required.",
    plain: "Whether the sign-in worked, and if not, why it failed. 0 means success.",
    dfir: "Crucial for brute-force and password spray detection. A spray shows many different accounts with error 50126, then a sudden 0 (success) on one. A targeted attack shows many failures on one account. ErrorCode 50074 (MFA required) followed by success can indicate MFA fatigue or bypass.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table",
    crossTables: [
      { table: "EntraIdSignInEvents" },
      { table: "AADSignInEventsBeta" },
    ],
  },

  "ConditionalAccessStatus": {
    docs: "Result of the Conditional Access policy evaluation for the sign-in. Values: success, failure, notApplied.",
    plain: "Whether Conditional Access policies passed, failed, or weren't evaluated for this sign-in.",
    dfir: "notApplied on a sensitive resource sign-in means no CA policy covered it — a gap in your Zero Trust posture. failure means the policy blocked it. success means it passed, but check what the policy actually required — MFA-optional policies can pass without MFA.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table",
    crossTables: [
      { table: "EntraIdSignInEvents" },
      { table: "AADSignInEventsBeta" },
    ],
  },

  "QueryType": {
    docs: "Type of LDAP or identity query made. Examples: AllUsers, AllGroups, User, Group, AllDomains, KerberosServiceTicketRequest.",
    plain: "What kind of Active Directory query was made — looking up all users, all groups, or requesting Kerberos service tickets.",
    dfir: "AllUsers and AllGroups queries from non-admin accounts or at unusual hours are classic pre-lateral-movement reconnaissance. KerberosServiceTicketRequest with high counts from a single account is the Kerberoasting signature.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityqueryevents-table",
    crossTables: [
      { table: "IdentityQueryEvents" },
    ],
  },

  "QueryTarget": {
    docs: "Target of the LDAP query or identity operation — for example, a distinguished name, username, group name, or SPN being queried.",
    plain: "What specifically was being looked up in Active Directory.",
    dfir: "Targeted queries for 'domain admins', 'enterprise admins', or specific service accounts reveal attacker intent. SPN queries (for Kerberoasting) show up here as queries for servicePrincipalName attributes. Combine with AccountUpn to see who is doing the reconnaissance.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityqueryevents-table",
    crossTables: [
      { table: "IdentityQueryEvents" },
      { table: "IdentityDirectoryEvents", as: "TargetAccountUpn" },
    ],
  },

  // ── Device / Endpoint ─────────────────────────────────────────────────────

  "DeviceId": {
    docs: "Unique identifier for a device in Microsoft Defender for Endpoint. A stable GUID assigned at onboarding that persists across renames and OS reinstalls if the device is re-enrolled.",
    plain: "The stable fingerprint of a device in MDE. More reliable than DeviceName for joining across tables because hostnames change.",
    dfir: "Your anchor for all endpoint pivots. DeviceName can change; DeviceId does not. Always use DeviceId when joining DeviceInfo → DeviceProcessEvents → DeviceNetworkEvents → DeviceLogonEvents to avoid mismatching events across a rename. Also present in BehaviorInfo/BehaviorEntities and DataSecurityEvents.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table",
    crossTables: [
      { table: "DeviceInfo" },
      { table: "DeviceProcessEvents" },
      { table: "DeviceNetworkEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceLogonEvents" },
      { table: "DeviceEvents" },
      { table: "DeviceImageLoadEvents" },
      { table: "DeviceNetworkInfo" },
      { table: "DeviceFileCertificateInfo" },
      { table: "DeviceTvmSoftwareVulnerabilities" },
      { table: "DeviceTvmSoftwareInventory" },
      { table: "DeviceTvmSecureConfigurationAssessment" },
      { table: "DeviceTvmHardwareFirmware" },
      { table: "DeviceTvmBrowserExtensions" },
      { table: "DeviceTvmCertificateInfo" },
      // CloudProcessEvents has no DeviceId — it uses pod/container identifiers
      { table: "AlertEvidence" },
      { table: "BehaviorInfo" },
      { table: "BehaviorEntities" },
      { table: "DataSecurityEvents" },
      { table: "CloudDnsEvents" },
    ],
  },

  "DeviceName": {
    docs: "Fully qualified domain name (FQDN) or hostname of the device as reported by the MDE sensor at time of the event.",
    plain: "The hostname of the machine. Easy to read, but can change — use DeviceId for reliable joins.",
    dfir: "Your first filter in most endpoint hunts. Key things to watch: processes with system-level parent processes on workstations, DeviceNames you don't recognise (potential rogue devices), and workstation names appearing in server-only event tables.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table",
    crossTables: [
      { table: "DeviceInfo" },
      { table: "DeviceProcessEvents" },
      { table: "DeviceNetworkEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceLogonEvents" },
      { table: "DeviceEvents" },
      { table: "IdentityLogonEvents" },
      { table: "IdentityQueryEvents" },
      { table: "AlertEvidence" },
    ],
  },

  "LogonId": {
    docs: "Identifier for a logon session on a device. Unique within a single device only, and only for the duration of the session. Recycled after the session ends.",
    plain: "Links a specific logon session to everything that ran under it — processes, network connections, file writes.",
    dfir: "Critical for lateral movement analysis. Tie a suspicious logon (from DeviceLogonEvents) to all the processes and activity in that session (DeviceProcessEvents). Always combine with DeviceId or it won't be unique across the fleet.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table",
    crossTables: [
      { table: "DeviceLogonEvents" },
      { table: "DeviceProcessEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceNetworkEvents" },
      { table: "DeviceEvents" },
    ],
  },

  "InitiatingProcessFileName": {
    docs: "File name of the process that initiated the event — i.e. the parent or triggering process. Does not include the full path.",
    plain: "The name of the process that caused this event to happen — the parent process.",
    dfir: "One of the most valuable columns for detecting LOLBin abuse, malware droppers, and process injection. cmd.exe spawned by winword.exe = macro execution. powershell.exe spawned by regsvr32.exe = LOLBin proxy. Always look at this column alongside FileName to understand the parent-child relationship.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceNetworkEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceEvents" },
      { table: "DeviceImageLoadEvents" },
    ],
  },

  "InitiatingProcessId": {
    docs: "Process ID (PID) of the process that initiated the event. PIDs are assigned by the OS, are only unique per device, and are recycled after a process terminates.",
    plain: "The PID of the parent or triggering process.",
    dfir: "Essential for building process trees, but always pair with DeviceId and narrow the Timestamp window — PIDs are reused. Use this to trace 'which browser spawned this suspicious child process' or 'which malware dropped this file'.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceNetworkEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceEvents" },
      { table: "DeviceImageLoadEvents" },
      // CloudProcessEvents has no InitiatingProcessId — parent is tracked via ParentProcessName
    ],
  },

  "InitiatingProcessCommandLine": {
    docs: "Full command line of the process that initiated the event, including the executable path and all arguments.",
    plain: "The full command the parent process was running when it triggered this event.",
    dfir: "Reveals the attacker's intent more than the filename alone. A regsvr32.exe calling a remote DLL, certutil decoding a base64 blob, or PowerShell with a download cradle — all visible here. Look for long base64 strings, URLs, and common LOLBIN switches.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceNetworkEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceEvents" },
      { table: "DeviceImageLoadEvents" },
    ],
  },

  "FileName": {
    docs: "Name of the file involved in the event — for process events this is the process executable name; for file events this is the file name. Does not include the full path.",
    plain: "The name of the file or executable involved in the event.",
    dfir: "Combine with FolderPath to detect masquerading — svchost.exe running from %TEMP% is malware. Combine with SHA256 to pivot to threat intelligence. Alone it is easy to spoof, so never rely on FileName without validating the path and hash.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceImageLoadEvents" },
      // CloudProcessEvents uses ProcessName, not FileName
      { table: "EmailAttachmentInfo" },
      { table: "AlertEvidence" },
    ],
  },

  "ProcessCommandLine": {
    docs: "Full command line used to create the process, including the path to the executable and all command-line arguments passed to it.",
    plain: "The exact command that was run — the executable plus all its arguments.",
    dfir: "The single most informative column for malicious execution detection. Encoded PowerShell, download cradles, LOLBIN abuse, credential dumping syntax, shadow copy deletion — all betray themselves in the command line. This is where you find the smoking gun.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "CloudProcessEvents" },
      { table: "AlertEvidence", as: "CommandLine" },
    ],
  },

  "FolderPath": {
    docs: "Full path of the folder containing the file involved in the event. For process events this is the directory the executable was launched from.",
    plain: "The directory where the file lives or ran from.",
    dfir: "Masquerading detection goldmine. Legitimate Windows processes run from C:\\Windows\\System32 or C:\\Windows\\SysWOW64. The same executable name running from %TEMP%, %APPDATA%, ProgramData, or Downloads is almost always malicious. Filter for FileName in known system binary names but FolderPath not matching expected paths.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceImageLoadEvents" },
      { table: "AlertEvidence" },
    ],
  },

  "ProcessIntegrityLevel": {
    docs: "Windows integrity level of the process. Values: Low, Medium, High, System. Reflects the token integrity level assigned by Windows when the process was created.",
    plain: "The privilege level of the process — System/High means elevated, Medium means normal user, Low means sandboxed.",
    dfir: "Key indicator for UAC bypass and privilege escalation. A process that is 'High' or 'System' whose parent was 'Medium' without a visible UAC prompt or explicit elevation has likely been privilege-escalated. Combine with InitiatingProcessFileName to see the escalation path.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
    ],
  },

  "ActionType": {
    docs: "Type of event or action captured by the record. The set of values varies by table — for example DeviceProcessEvents uses ProcessCreated; DeviceRegistryEvents uses RegistryValueSet; DeviceEvents uses hundreds of specific action types.",
    plain: "What specifically happened — the event type within a given table.",
    dfir: "Your primary event-type filter in any hunt. Always filter ActionType early — tables like DeviceEvents contain hundreds of distinct action types and querying without filtering it is extremely expensive. Also useful for anomaly hunting: unexpected ActionTypes from expected processes reveal living-off-the-land activity.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceNetworkEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceLogonEvents" },
      { table: "DeviceEvents" },
      { table: "DeviceImageLoadEvents" },
      { table: "IdentityLogonEvents" },
      { table: "IdentityQueryEvents" },
      { table: "IdentityDirectoryEvents" },
      { table: "CloudAppEvents" },
      { table: "CloudAuditEvents" },
      // CloudProcessEvents does not have an ActionType column
      { table: "BehaviorInfo" },
      { table: "BehaviorEntities" },
      { table: "DataSecurityEvents" },
    ],
  },

  "AdditionalFields": {
    docs: "JSON object containing additional event-specific properties that do not have dedicated columns in the schema. Content varies by ActionType.",
    plain: "A catch-all JSON blob containing extra event details. You need to parse it with parse_json() to extract specific values.",
    dfir: "Where the details hide for many high-value event types — scheduled task names, service paths, WMI filter contents, and injected process names all live here. Use parse_json(AdditionalFields).FieldName or extend with tostring(). Never overlook this column when investigating a suspicious ActionType.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceNetworkEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceLogonEvents" },
      { table: "DeviceEvents" },
      { table: "IdentityLogonEvents" },
      { table: "IdentityQueryEvents" },
      { table: "IdentityDirectoryEvents" },
      { table: "CloudAppEvents" },
    ],
  },

  // ── Files ─────────────────────────────────────────────────────────────────

  "SHA256": {
    docs: "SHA-256 cryptographic hash of a file. Computed at time of event and consistent across machines — the same binary always produces the same hash regardless of filename or path.",
    plain: "The fingerprint of a file's contents. The same binary always produces the same hash, regardless of what it's named or where it is.",
    dfir: "The most reliable file identity pivot in the schema. Look up SHA256 in threat intelligence (VirusTotal, MDE threat intel), join across EmailAttachmentInfo → DeviceFileEvents → AlertEvidence to find everywhere a known-bad file landed. Cannot be spoofed — two files with the same SHA256 are identical.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceEvents" },
      { table: "DeviceImageLoadEvents" },
      { table: "EmailAttachmentInfo" },
      { table: "AlertEvidence" },
      { table: "DeviceFileCertificateInfo" },
      { table: "BehaviorEntities" },
    ],
  },

  "FileType": {
    docs: "Extension or MIME-type category of the file as determined by content inspection, not just the file extension.",
    plain: "The file type — but determined by what the file actually is, not just its extension.",
    dfir: "Attackers rename malicious files with innocent extensions (.jpg, .txt) to bypass email filters. FileType reflects content inspection so a .jpg that is actually a PE executable will show as such. Critical for detecting file type mismatch attacks in email and web delivery.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailattachmentinfo-table",
    crossTables: [
      { table: "EmailAttachmentInfo" },
      { table: "DeviceFileEvents", as: "FileExtension" },
    ],
  },

  "FileSize": {
    docs: "Size of the file in bytes at the time of the event.",
    plain: "How big the file is in bytes.",
    dfir: "Useful for exfiltration and staging detection. Abnormally large archives created in user temp directories, or small executables (< 20KB) dropped by Office documents, are both worth investigating. FileSize alone is not a strong signal but combined with FolderPath, FileName, and ActionType it adds valuable context.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table",
    crossTables: [
      { table: "DeviceFileEvents" },
      { table: "EmailAttachmentInfo" },
    ],
  },

  // ── Network ───────────────────────────────────────────────────────────────

  "RemoteIP": {
    docs: "IP address of the remote endpoint in a network connection, as observed from the device. May be a public IP, private IP, or loopback depending on connection type.",
    plain: "The IP address the device was talking to.",
    dfir: "Pivot RemoteIP to AlertEvidence to check if Defender has tagged it as malicious C2 or threat actor infrastructure. For lateral movement, match RemoteIP against DeviceNetworkInfo.IPAddresses across your fleet to identify the target machine. Sudden connections to newly seen IPs from trusted processes warrant investigation.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table",
    crossTables: [
      { table: "DeviceNetworkEvents" },
      { table: "DeviceLogonEvents", as: "IPAddress" },
      { table: "AlertEvidence", as: "RemoteIP" },
    ],
  },

  "RemotePort": {
    docs: "TCP or UDP port number on the remote endpoint. Present in DeviceNetworkEvents (outbound/inbound connections), DeviceLogonEvents (port the authentication arrived on), and DeviceEvents.",
    plain: "The port number on the remote side of the connection or authentication.",
    dfir: "Non-standard ports for common protocols are a classic C2 indicator — HTTPS on port 4443, HTTP on 8080, or DNS on a non-53 port. In DeviceLogonEvents, RemotePort tells you which port the authentication came in on — useful for detecting unusual pass-the-hash or NTLM relay inbound on non-standard ports. Always combine with InitiatingProcessFileName.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table",
    crossTables: [
      { table: "DeviceNetworkEvents" },
      { table: "DeviceLogonEvents" },
      { table: "DeviceEvents" },
    ],
  },

  "LocalPort": {
    docs: "TCP or UDP port number on the local device side of the connection. Present in DeviceNetworkEvents and DeviceEvents.",
    plain: "The port number on this device's side of the connection.",
    dfir: "Useful for identifying listening services and inbound connections. Unexpected services listening on high ports (> 1024) on endpoints — especially those created by non-system processes — can indicate backdoors or reverse shells. Compare with expected service baseline.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table",
    crossTables: [
      { table: "DeviceNetworkEvents" },
      { table: "DeviceEvents" },
    ],
  },

  "RemoteUrl": {
    docs: "URL or fully qualified domain name (FQDN) of the remote endpoint that the device connected to, when available. May be empty if only an IP was used.",
    plain: "The domain name or URL the device connected to, if one was resolved.",
    dfir: "More informative than RemoteIP for C2 and exfiltration hunting — malware using DGA (Domain Generation Algorithms) shows up as high-entropy random-looking domains. Look for connections to newly registered domains, low-reputation TLDs, or known bad infrastructure. Also critical for DNS tunneling detection.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table",
    crossTables: [
      { table: "DeviceNetworkEvents" },
      { table: "EmailUrlInfo", as: "Url" },
      { table: "UrlClickEvents", as: "Url" },
    ],
  },

  "BytesSent": {
    docs: "Number of bytes sent by the local device to the remote endpoint. Note: DeviceNetworkEvents does NOT include SentBytes or ReceivedBytes columns — byte counts are not available in that table.",
    plain: "How much data this device sent to the remote endpoint. Not available in DeviceNetworkEvents — use connection count and timing patterns to infer exfiltration instead.",
    dfir: "DeviceNetworkEvents does not expose byte counts. To detect exfiltration via network telemetry, use connection frequency (Connections = count()), beaconing interval patterns, and remote IP/domain reputation instead. For actual data volume, check CloudAppEvents (file download/upload events) or DataSecurityEvents (Purview DLP triggers).",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table",
    crossTables: [],
  },

  // ── Registry ──────────────────────────────────────────────────────────────

  "RegistryKey": {
    docs: "Full path of the registry key involved in the event, including the hive prefix (e.g. HKEY_LOCAL_MACHINE\\...). Present in DeviceRegistryEvents, DeviceEvents (for registry actions captured as misc events), and AlertEvidence.",
    plain: "The full registry path — the folder that was created or accessed. Present in registry events, the catch-all device events table, and alert evidence.",
    dfir: "Persistence hunting 101. Run keys (HKCU/HKLM\\...\\Run, RunOnce), service keys (HKLM\\SYSTEM\\CurrentControlSet\\Services), and AppInit_DLLs are the most common attacker-modified keys. Filter for writes to these paths from non-system processes. AlertEvidence.RegistryKey surfaces the exact key associated with a detection — use it to jump straight to the registry context without hunting through DeviceRegistryEvents.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table",
    crossTables: [
      { table: "DeviceRegistryEvents" },
      { table: "DeviceEvents" },
      { table: "AlertEvidence" },
    ],
  },

  "RegistryValueName": {
    docs: "Name of the registry value that was created, modified, or deleted. Present in DeviceRegistryEvents, DeviceEvents, and AlertEvidence.",
    plain: "The name of the specific registry entry that was changed — like the filename within the folder.",
    dfir: "Identifies exactly which value was tampered with. ImagePath in a service key = service hijacking. Start = 2 (Auto) = automatic persistence. DisableAntiSpyware = 1 = Defender disablement. AlertEvidence carries RegistryValueName directly on the evidence row — no join to DeviceRegistryEvents needed for initial triage.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table",
    crossTables: [
      { table: "DeviceRegistryEvents" },
      { table: "DeviceEvents" },
      { table: "AlertEvidence" },
    ],
  },

  "RegistryValueData": {
    docs: "Data written to the registry value — the actual value stored. Present in DeviceRegistryEvents, DeviceEvents, and AlertEvidence.",
    plain: "The actual data stored in the registry value — the payload of the change.",
    dfir: "Where the actual malicious payload lives in registry-based persistence. Fileless malware often stores base64-encoded PowerShell or shellcode here. AlertEvidence surfaces the RegistryValueData directly on the evidence row for immediate inspection. Decode any base64 or hex you find here immediately.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table",
    crossTables: [
      { table: "DeviceRegistryEvents" },
      { table: "DeviceEvents" },
      { table: "AlertEvidence" },
    ],
  },

  // ── Email ─────────────────────────────────────────────────────────────────

  "NetworkMessageId": {
    docs: "Unique identifier for an email or Teams message assigned by Microsoft 365 during transport. Persists across all email-related and Teams message tables for the lifetime of the message.",
    plain: "The tracking number stamped on every email or Teams message as it flows through M365. Your primary join key across all email and Teams tables.",
    dfir: "The master pivot key for email and Teams attack chains. One NetworkMessageId ties together EmailEvents/MessageEvents (delivery), EmailAttachmentInfo (attachment hashes), EmailUrlInfo/MessageUrlInfo (extracted links), UrlClickEvents (user clicks), AlertEvidence, and DataSecurityEvents. Always start an email investigation with this column.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table",
    crossTables: [
      { table: "EmailEvents" },
      { table: "EmailAttachmentInfo" },
      { table: "EmailUrlInfo" },
      { table: "EmailPostDeliveryEvents" },
      { table: "UrlClickEvents" },
      { table: "MessageEvents" },
      { table: "MessagePostDeliveryEvents" },
      { table: "MessageUrlInfo" },
      { table: "AlertEvidence" },
      { table: "BehaviorEntities" },
      { table: "DataSecurityEvents" },
    ],
  },

  "SenderFromAddress": {
    docs: "Sender email address in the From header of the email message as displayed to the recipient. May differ from SenderMailFromAddress (the SMTP envelope sender) in spoofing scenarios.",
    plain: "The 'From' address the user sees in their email client. This can be spoofed.",
    dfir: "The display name and address visible to the user — not necessarily the real sender. Discrepancy between SenderFromAddress and SenderMailFromAddress is a spoofing indicator. Look for homoglyph attacks (rnicrosoft.com), legitimate domain abuse (reply-to mismatch), and display name spoofing with external domains.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table",
    crossTables: [
      { table: "EmailEvents" },
      { table: "EmailAttachmentInfo", as: "SenderFromAddress" },
      { table: "EmailUrlInfo", as: "SenderFromAddress" },
    ],
  },

  "RecipientEmailAddress": {
    docs: "Email address of the recipient as specified in the To header. For messages to multiple recipients, each recipient generates a separate row.",
    plain: "Who received the email. Each recipient gets their own row in the table.",
    dfir: "Essential for blast radius assessment in phishing campaigns. Aggregate by RecipientEmailAddress to see who was targeted. Pivot to UrlClickEvents on NetworkMessageId to identify who actually clicked — that narrows your incident scope from all recipients to the ones who took the bait.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table",
    crossTables: [
      { table: "EmailEvents" },
      { table: "EmailAttachmentInfo" },
      { table: "EmailUrlInfo" },
      { table: "EmailPostDeliveryEvents" },
    ],
  },

  "Subject": {
    docs: "Subject line of the email message, as delivered. May be truncated for very long subject lines.",
    plain: "The subject line of the email.",
    dfir: "Useful for campaign attribution and hunting lateral phishing. If you see a confirmed malicious email, search for other emails with the same or similar Subject across the organisation — attackers reuse lure subjects. Also useful for hunting thread hijacking (reply/forward chains with malicious content).",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table",
    crossTables: [
      { table: "EmailEvents" },
      { table: "EmailPostDeliveryEvents" },
    ],
  },

  "DeliveryAction": {
    docs: "Action taken on the email by Defender for Office 365. Values: Delivered, DeliveredToJunk, Blocked, Replaced, JunkFolder.",
    plain: "What happened to the email — was it delivered, junked, blocked, or had links replaced by Safe Links.",
    dfir: "Filter to Delivered for emails that actually reached users. DeliveredToJunk means it landed in junk — the user might still see it. Blocked means ATP stopped it. If you see Delivered for a known-malicious campaign IOC, those are your at-risk users needing immediate investigation.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table",
    crossTables: [
      { table: "EmailEvents" },
      { table: "EmailPostDeliveryEvents" },
    ],
  },

  "AttachmentCount": {
    docs: "Number of attachments in the email message.",
    plain: "How many attachments the email had.",
    dfir: "A quick pre-filter for phishing campaigns. Emails with AttachmentCount > 0 that were Delivered to non-junk are worth deeper investigation via EmailAttachmentInfo. Combine with SenderFromDomain not matching your organisation for external attachment delivery scoping.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table",
    crossTables: [
      { table: "EmailEvents" },
    ],
  },

  // MalwareDetectionMethod is NOT a column in EmailAttachmentInfo.
  // The correct columns for threat verdict data are ThreatTypes and DetectionMethods.
  // See: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailattachmentinfo-table

  "Url": {
    docs: "The full URL associated with an email body, attachment, or click event. Captured at the time of processing by Defender for Office 365.",
    plain: "The actual link extracted from an email or clicked by a user.",
    dfir: "Pivot from EmailUrlInfo to UrlClickEvents on this column to determine not just who received the link but who clicked it. Decode URL-shortened or Safe Links-wrapped URLs to get the real destination. Compare domain registration age and reputation against baseline.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailurlinfo-table",
    crossTables: [
      { table: "EmailUrlInfo" },
      { table: "UrlClickEvents" },
      { table: "DeviceNetworkEvents", as: "RemoteUrl" },
    ],
  },

  "IsClickedThrough": {
    docs: "Boolean indicating whether the user clicked through the Safe Links warning page to access the URL, or whether Safe Links blocked navigation.",
    plain: "True if the user saw a Safe Links warning and clicked through anyway.",
    dfir: "The difference between a near-miss and a confirmed compromise. IsClickedThrough = true means the user actively ignored a security warning to reach a malicious site. These users are your highest-priority responders — pivot immediately to their device events to look for post-exploitation activity.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table",
    crossTables: [
      { table: "UrlClickEvents" },
    ],
  },

  // ── Alerts ────────────────────────────────────────────────────────────────

  "AlertId": {
    docs: "Unique identifier for an alert generated by Microsoft Defender XDR. Links AlertInfo (title, severity, MITRE techniques) to AlertEvidence (specific entities associated with the alert).",
    plain: "The join key between two alert tables — AlertInfo tells you what the alert is, AlertEvidence tells you what entities it touched.",
    dfir: "Always join AlertInfo and AlertEvidence on AlertId to get the full picture. AlertInfo alone tells you the title; AlertEvidence tells you which files, IPs, users, and devices triggered it. Cross-reference AlertId with process/network/file events to reconstruct what the attacker actually did around the alert time.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table",
    crossTables: [
      { table: "AlertInfo" },
      { table: "AlertEvidence" },
    ],
  },

  "Title": {
    docs: "Name or title of the alert as generated by the Microsoft Defender XDR detection engine or a custom detection rule. AlertEvidence also carries the Title of the parent alert on each evidence row.",
    plain: "The human-readable name of the alert. Present in both AlertInfo (one row per alert) and AlertEvidence (repeated on every evidence row for that alert).",
    dfir: "Use Title with contains or has_any to hunt for clusters of related detections — e.g. all 'Credential dumping' or 'Ransomware' alerts across the estate. Because AlertEvidence also carries Title, you can filter evidence rows by title without first joining to AlertInfo, which makes ad-hoc hunting faster.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table",
    crossTables: [
      { table: "AlertInfo" },
      { table: "AlertEvidence" },
      { table: "BehaviorInfo" },
    ],
  },

  "Severity": {
    docs: "Severity of the alert as assessed by Defender XDR. Values: Informational, Low, Medium, High. Present in both AlertInfo and AlertEvidence.",
    plain: "How serious Microsoft considers the alert. Repeated on every AlertEvidence row so you can filter evidence by severity without a join.",
    dfir: "High severity alerts demand immediate triage. However, don't ignore Medium — advanced persistent threats often generate medium alerts early in the chain. Filter for High first, then pivot to related Medium alerts on the same device or account in the same timeframe to understand the full kill chain.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table",
    crossTables: [
      { table: "AlertInfo" },
      { table: "AlertEvidence" },
      { table: "BehaviorInfo" },
    ],
  },

  "Category": {
    docs: "Category of the attack activity, aligned to MITRE ATT&CK. In AlertEvidence the column is named Categories (plural). BehaviorInfo uses the same taxonomy for UEBA behaviors.",
    plain: "The type of attack technique — e.g. Ransomware, CredentialAccess, LateralMovement. Shared across alert and behavior tables.",
    dfir: "Enables fleet-wide hunting for attack categories before alerts are correlated into incidents. Group by Category across AlertInfo + AlertEvidence + BehaviorInfo to see whether a single attacker is generating noise across multiple detection engines simultaneously.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table",
    crossTables: [
      { table: "AlertInfo" },
      { table: "AlertEvidence", as: "Categories" },
      { table: "BehaviorInfo" },
      { table: "BehaviorEntities" },
    ],
  },

  "AttackTechniques": {
    docs: "MITRE ATT&CK technique IDs associated with the alert or behavior, as a JSON array or pipe-delimited string. Present in AlertInfo, AlertEvidence, BehaviorInfo, and BehaviorEntities.",
    plain: "Which MITRE ATT&CK technique IDs this detection maps to. Shared across alert and UEBA behavior tables.",
    dfir: "Direct mapping between Defender detections and the ATT&CK framework. Use has 'T1486' to find all ransomware-related alerts, or parse the array to look for multiple high-risk techniques on a single device. Cross-referencing AttackTechniques across AlertInfo + BehaviorInfo gives you a fuller picture of what the attacker's TTPs look like even when individual signals are below alert threshold.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table",
    crossTables: [
      { table: "AlertInfo" },
      { table: "AlertEvidence" },
      { table: "BehaviorInfo" },
      { table: "BehaviorEntities" },
    ],
  },

  // ── Cloud ─────────────────────────────────────────────────────────────────

  "Application": {
    docs: "Name of the cloud application that generated the event, as identified by Microsoft Defender for Cloud Apps. Examples: Microsoft Exchange Online, Microsoft Teams, Microsoft SharePoint Online.",
    plain: "Which Microsoft 365 or cloud app the event came from.",
    dfir: "Scopes cloud investigation to the affected service. An attacker who compromises an account may abuse Exchange (email collection), SharePoint (document exfiltration), and Teams (communication monitoring) — filter by Application to separate these activity streams. Unusual applications appearing for a compromised account (e.g. Power Automate, Graph Explorer) warrant immediate attention.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table",
    crossTables: [
      { table: "CloudAppEvents" },
      // GraphApiAuditEvents does not have an Application column
    ],
  },

  "ObjectName": {
    docs: "Name or identifier of the cloud object involved in the event — for example a file name, mailbox folder name, SharePoint document, or Teams channel.",
    plain: "The name of the specific file, document, or resource that was accessed or modified.",
    dfir: "Essential for data exfiltration scoping. Pivot on ObjectName to identify which files were accessed or downloaded during a compromise. Document names containing keywords like 'password', 'credential', 'VPN', 'salary', or 'merger' accessed in bulk are a major red flag.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table",
    crossTables: [
      { table: "CloudAppEvents" },
      // GraphApiAuditEvents does not have an ObjectName column
    ],
  },

  "ResourceId": {
    docs: "The full Azure Resource Manager (ARM) resource identifier of the Azure resource involved in the event, in the format /subscriptions/{id}/resourceGroups/{rg}/providers/{type}/{name}.",
    plain: "The unique full path to an Azure resource — think of it as the resource's absolute address inside Azure. It tells you which subscription, resource group, and specific resource (VM, storage account, Key Vault, etc.) was involved.",
    dfir: "In AiTM and Azure-targeting attacks, the ResourceId in CloudAuditEvents identifies exactly which VM received a Run Command or extension write. Parse the resource name from the end of the path to correlate with DeviceName in DeviceProcessEvents (requires Defender for Servers Plan 2 on the VM) for the full execution trail. Note: CloudProcessEvents uses AzureResourceId, not ResourceId — these are different columns.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudauditevents-table",
    crossTables: [
      { table: "CloudAuditEvents" },
      // CloudProcessEvents uses AzureResourceId, not ResourceId
    ],
  },

  "UrlChain": {
    docs: "An ordered list of URLs in the redirect chain, from the initial click URL through all redirect hops to the final destination.",
    plain: "The full trail of redirects a URL followed — from the link in the email all the way to where the user actually landed. AiTM proxies always show as a middle hop between the phishing email link and the legitimate Microsoft login page.",
    dfir: "The single most reliable AiTM detection signal in UrlClickEvents. A legitimate Microsoft auth flow has no redirect through a third-party domain. If UrlChain contains a non-Microsoft domain between the phishing link and login.microsoftonline.com, that intermediate domain is the AiTM proxy. Extract it to find all victims who used the same proxy.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table",
    crossTables: [
      { table: "UrlClickEvents" },
    ],
  },

  // ── Composite pivots ──────────────────────────────────────────────────────

  "DeviceId + LogonId": {
    docs: "Composite pivot combining DeviceId and LogonId. DeviceId scopes the logon to a specific machine; LogonId identifies the session within that machine.",
    plain: "Two columns used together. LogonId is meaningless across devices — combine both to trace a specific user session on a specific device.",
    dfir: "The correct way to trace everything that happened in a single logon session. After identifying a suspicious logon in DeviceLogonEvents, join on both DeviceId + LogonId to DeviceProcessEvents and DeviceFileEvents to see every process run and file touched in that session.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table",
    crossTables: [
      { table: "DeviceLogonEvents" },
      { table: "DeviceProcessEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceNetworkEvents" },
      { table: "DeviceEvents" },
    ],
  },

  "AccountUpn + IPAddress": {
    docs: "Composite pivot combining AccountUpn and IPAddress to correlate identity events with network source.",
    plain: "Two columns together to match the same user session across endpoint and identity provider events.",
    dfir: "Bridges the gap between Entra ID sign-in logs (which have UPN + IP) and device events (which have UPN + machine info). Match both to confirm the same authentication appears in both sources — critical for distinguishing legitimate access from token replay attacks.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitylogonevents-table",
    crossTables: [
      { table: "IdentityLogonEvents" },
      { table: "EntraIdSignInEvents" },
      { table: "AADSignInEventsBeta" },
      { table: "CloudAppEvents" },
    ],
  },

  "IPAddress + AccountUpn": {
    docs: "Composite pivot combining IPAddress and AccountUpn. Used to correlate identity sign-in telemetry with endpoint or cloud events from the same source.",
    plain: "Same as AccountUpn + IPAddress — both columns together map a sign-in event back to the source machine.",
    dfir: "Same as AccountUpn + IPAddress — the column order depends on the table, but the pivot logic is identical. Use it to confirm that what you see in cloud/identity logs corresponds to actual device activity.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-entraidsiginevents-table",
    crossTables: [
      { table: "EntraIdSignInEvents" },
      { table: "AADSignInEventsBeta" },
      { table: "IdentityLogonEvents" },
      { table: "CloudAppEvents" },
    ],
  },

  "AccountUpn → DeviceId": {
    docs: "Directional pivot: use AccountUpn from a cloud or identity table to find the DeviceId in DeviceLogonEvents, then continue pivoting through device tables.",
    plain: "Cloud and identity tables only have the user's UPN — look up the UPN in DeviceLogonEvents to find the DeviceId.",
    dfir: "The essential cloud-to-endpoint bridge. When you identify suspicious cloud activity (EntraIdSignInEvents, CloudAppEvents), pivot the UPN into DeviceLogonEvents to find which physical device was used. That DeviceId then unlocks the full endpoint telemetry chain.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table",
    crossTables: [
      { table: "DeviceLogonEvents" },
      { table: "DeviceProcessEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceNetworkEvents" },
    ],
  },

  "RemoteIP → DeviceName": {
    docs: "Directional pivot: use the RemoteIP from DeviceNetworkEvents to look up the DeviceName in DeviceInfo or DeviceNetworkInfo.",
    plain: "A directional lookup — you have an IP address, now find which device in your fleet owns it.",
    dfir: "Identifies the target of lateral movement. You see a connection going to RemoteIP — match it against DeviceNetworkInfo.IPAddresses to resolve it to a DeviceName in your fleet. That machine is the lateral movement target and needs immediate investigation.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkinfo-table",
    crossTables: [
      { table: "DeviceNetworkEvents" },
      { table: "DeviceNetworkInfo", as: "IPAddresses" },
      { table: "DeviceInfo" },
    ],
  },

  "DeviceId + SoftwareName": {
    docs: "Composite pivot combining DeviceId and SoftwareName across TVM tables. Confirms that a specific software package identified as vulnerable is present on a specific device.",
    plain: "Two TVM tables talking about the same thing — confirms a CVE applies to the exact version installed on a specific machine.",
    dfir: "Vulnerability exploitation scoping. Join DeviceTvmSoftwareVulnerabilities and DeviceTvmSoftwareInventory on both columns to avoid false positives where the CVE technically applies but the installed version is actually patched. Critical for prioritising patch urgency post-exploitation discovery.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvmsoftwarevulnerabilities-table",
    crossTables: [
      { table: "DeviceTvmSoftwareVulnerabilities" },
      { table: "DeviceTvmSoftwareInventory" },
    ],
  },

  // ── Email threat fields ───────────────────────────────────────────────────

  "ThreatTypes": {
    docs: "List of threat types identified by Defender for Office 365, such as Malware, Phish, or Spam. Present across the full email pipeline — delivery, attachment, post-delivery, and click events.",
    plain: "What Defender thinks the email or attachment is — malware delivery, phishing, spam, or clean. Consistent across all email tables so you can filter any stage of the pipeline.",
    dfir: "The fastest cross-email-pipeline triage signal. Because ThreatTypes appears in EmailEvents, EmailAttachmentInfo, EmailPostDeliveryEvents, and UrlClickEvents, you can see the verdict at every stage of an attack chain — delivery, content, post-delivery action, and click. Inconsistencies between stages (e.g., delivered without a threat verdict but post-delivery ZAP fired) reveal detection timing gaps.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table",
    crossTables: [
      { table: "EmailEvents" },
      { table: "EmailAttachmentInfo" },
      { table: "EmailPostDeliveryEvents" },
      { table: "UrlClickEvents" },
    ],
  },

  "ThreatNames": {
    docs: "Names of malware or other threats detected, as identified by Microsoft Defender antivirus and threat intelligence. Present in EmailEvents and EmailAttachmentInfo.",
    plain: "The specific malware family name — like 'TrojanDownloader:O97M/Donoff'. Available at both the email level and the attachment level.",
    dfir: "Ties detections directly to a known malware family across the email tables. When ThreatNames appears in EmailEvents it reflects the overall message verdict; in EmailAttachmentInfo it reflects the specific attachment. The same family name may appear in DeviceFileEvents if the file was scanned on an endpoint — use it to pivot from email delivery to endpoint execution.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailattachmentinfo-table",
    crossTables: [
      { table: "EmailEvents" },
      { table: "EmailAttachmentInfo" },
    ],
  },

  "SenderIPv4": {
    docs: "IPv4 address of the mail server that delivered the message to Microsoft 365. This is the last external hop — the IP of the sending MTA that connected to Microsoft's mail infrastructure.",
    plain: "The IP address of the server that actually sent the email into Microsoft 365. Not the attacker's workstation — the mail server, which may be a compromised host, a bulletproof hosting provider, or a legitimate ESP being abused.",
    dfir: "Cross-reference against threat intel blocklists and reputation services. If it matches known C2 or phishing infrastructure, you have strong confirmation the email is malicious. Pivot to DeviceNetworkEvents to see if any endpoint connected to this same IP.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table",
    crossTables: [
      { table: "EmailEvents" },
    ],
  },

  "UrlDomain": {
    docs: "The domain portion of the URL found in an email or Teams message, extracted by MDO during processing. Present in EmailUrlInfo and MessageUrlInfo.",
    plain: "Just the domain name from a link — e.g. 'malicious-site.example.com'. Available in both email and Teams URL tables.",
    dfir: "Useful for hunting by domain rather than full URL, since attackers rotate paths while reusing infrastructure. Because it's consistent across EmailUrlInfo and MessageUrlInfo, you can hunt a malicious domain across both email and Teams channels in a single query. Join UrlDomain against threat intel feeds or DNS query logs to see if any internal hosts resolved it.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailurlinfo-table",
    crossTables: [
      { table: "EmailUrlInfo" },
      { table: "MessageUrlInfo" },
    ],
  },

  // ── Authentication fields ─────────────────────────────────────────────────

  "FailureReason": {
    docs: "The reason an authentication attempt failed. In IdentityLogonEvents (AD/Kerberos/NTLM) this is a Kerberos or NTLM error string. In DeviceLogonEvents (local device logons) this is a Windows logon failure reason.",
    plain: "Why the login failed — wrong password, account locked, expired ticket, disabled account, etc. Present in both the identity-layer (AD) and device-layer (local logon) tables.",
    dfir: "Password spray attacks produce KDC_ERR_PREAUTH_FAILED in bulk across IdentityLogonEvents. On DeviceLogonEvents, FailureReason = 'SubStatus: 0xC000006A' (wrong password) or 'SubStatus: 0xC0000234' (account locked) are the local equivalents. Correlating both tables on AccountName + DeviceName + timewindow during a suspected spray gives you the full on-prem + device picture simultaneously.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitylogonevents-table",
    crossTables: [
      { table: "IdentityLogonEvents" },
      { table: "DeviceLogonEvents" },
    ],
  },

  "ApplicationId": {
    docs: "The unique identifier (GUID or app ID) of the Azure AD application involved in the event. Present across sign-in tables (both user and service principal), cloud app activity, and alert evidence.",
    plain: "Which app was involved — each Microsoft 365 app, third-party SaaS integration, service principal, and custom app has its own ID. The Microsoft Graph API is '00000003-0000-0000-c000-000000000000', for example.",
    dfir: "Identifies exactly which app an attacker accessed. In EntraIdSignInEvents it tells you which app a compromised user signed into. In EntraIdSpnSignInEvents it identifies which service principal or managed identity authenticated — critical for detecting compromised workload identities. In CloudAppEvents it shows which app generated the activity. Cross-reference against your approved app inventory for any unexpected values.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table",
    crossTables: [
      { table: "EntraIdSignInEvents" },
      { table: "EntraIdSpnSignInEvents" },
      { table: "AADSignInEventsBeta" },
      { table: "CloudAppEvents" },
      { table: "AlertEvidence" },
    ],
  },

  // ── Directory / identity change fields ───────────────────────────────────

  "TargetAccountDisplayName": {
    docs: "The display name of the account that was the target of an identity action — a directory modification (IdentityDirectoryEvents), an authentication attempt toward a destination account (IdentityLogonEvents), or a query target (IdentityQueryEvents).",
    plain: "The friendly name of the account that something was done to — the victim or target of the identity operation, not the account performing it.",
    dfir: "Critical for detecting privilege escalation and lateral movement targeting. In IdentityDirectoryEvents it shows whose account was modified. In IdentityLogonEvents it reveals which account an authentication was directed at — key for detecting pass-the-ticket or delegation abuse. In IdentityQueryEvents it shows which account was looked up — useful for detecting targeted LDAP reconnaissance.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitydirectoryevents-table",
    crossTables: [
      { table: "IdentityDirectoryEvents" },
      { table: "IdentityLogonEvents" },
      { table: "IdentityQueryEvents" },
    ],
  },

  "ModifiedProperties": {
    docs: "NOT a top-level column in IdentityDirectoryEvents. Attribute change details (old and new values) are stored inside the AdditionalFields JSON column, not as a standalone ModifiedProperties field. Access via: parse_json(AdditionalFields)[\"ModifiedProperties\"].",
    plain: "AD attribute change details live inside AdditionalFields (JSON), not as their own column. Use parse_json(AdditionalFields) to extract the modified properties.",
    dfir: "To get before/after values in IdentityDirectoryEvents, extend with parse_json(AdditionalFields). For group membership changes look for additions to 'Domain Admins', 'Enterprise Admins', or 'Protected Users'. For account changes, flag modifications to adminCount, userAccountControl, or servicePrincipalName. Example: | extend ChangedProps = parse_json(AdditionalFields) | where tostring(ChangedProps) has 'Domain Admins'",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitydirectoryevents-table",
    crossTables: [
      { table: "IdentityDirectoryEvents", as: "AdditionalFields (JSON)" },
    ],
  },

  // ── Alert fields ──────────────────────────────────────────────────────────

  "EntityType": {
    docs: "The type of entity represented by this row. In AlertEvidence: File, Ip, Url, User, Machine, MailMessage, MailCluster, MailBox, CloudApplication. In BehaviorEntities the same taxonomy is used for UEBA behavior entities.",
    plain: "What kind of thing this evidence/behavior row is about — a file, IP, user, device, email, etc. Present in both alert and UEBA behavior tables.",
    dfir: "Always filter by EntityType first. EntityType == 'File' gives you hashes to hunt across endpoints; 'Ip' gives you C2 addresses; 'User' gives you compromised accounts. In BehaviorEntities, filtering by EntityType lets you extract the specific entity types involved in a UEBA anomaly without manually parsing all behavior evidence rows.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertevidence-table",
    crossTables: [
      { table: "AlertEvidence" },
      { table: "BehaviorEntities" },
    ],
  },

  "EvidenceRole": {
    docs: "Role of the entity in the detection — whether it was the attacker-controlled asset (Attacker), the victim (Victim), or contextually related (Related, ContextualTarget). Shared between AlertEvidence and BehaviorEntities.",
    plain: "Defender's classification of why this entity is part of the detection. 'Attacker' = bad actor's asset; 'Victim' = targeted; 'Related' = involved but role unclear.",
    dfir: "Filter on EvidenceRole == 'Attacker' in both AlertEvidence and BehaviorEntities to extract highest-confidence attacker-controlled IOCs across both alert-based and UEBA-based detections simultaneously. 'Victim' entities define the blast radius.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertevidence-table",
    crossTables: [
      { table: "AlertEvidence" },
      { table: "BehaviorEntities" },
    ],
  },

  // ── Cloud / app fields ────────────────────────────────────────────────────

  "IPTags": {
    docs: "Tags associated with the IP address based on Microsoft Threat Intelligence categorization, such as 'anonymizer', 'tor', 'hosting', or 'vpn'.",
    plain: "Labels that Microsoft has applied to the IP based on its reputation and behavior — 'anonymizer' means it's a known proxy or VPN, 'tor' means it's a Tor exit node, 'hosting' means it's a cloud or data center IP.",
    dfir: "An 'anonymizer' or 'tor' tag on a sign-in IP is a strong signal the attacker is hiding their origin. Attackers using residential proxies may not trigger this, but datacenter IPs and known anonymizing services will. Use this to quickly triage sign-in risk without needing external threat intel.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table",
    crossTables: [
      { table: "CloudAppEvents" },
      { table: "EntraIdSignInEvents" },
      { table: "AADSignInEventsBeta" },
    ],
  },

  "IsManaged": {
    docs: "Indicates whether the device used to sign in is managed by the organization — enrolled in Intune or joined to an Entra ID / hybrid AD domain.",
    plain: "Was the device that completed this sign-in a company-managed machine? If False, the sign-in happened on a personal phone, home PC, or attacker-controlled machine — anything not under corporate control.",
    dfir: "In device code phishing, the victim authenticates via their browser at microsoft.com/devicelogin, which does NOT appear as a managed device sign-in. IsManaged = false combined with successful MFA completion is a key hunting indicator for this attack pattern. Also flags bring-your-own-device (BYOD) abuse.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table",
    crossTables: [
      { table: "EntraIdSignInEvents" },
      { table: "AADSignInEventsBeta" },
    ],
  },

  "SessionId": {
    docs: "Unique identifier for the authenticated session created by the sign-in event.",
    plain: "SessionId in EntraIdSignInEvents is the canonical session token. In CloudAppEvents and OfficeActivity the same value surfaces as AADSessionId — extracted from the AppAccessContext JSON column: parse_json(AppAccessContext).AADSessionId. One sign-in = one token = one SessionId/AADSessionId across every table that logs activity under it.",
    dfir: "The primary attacker-tracking pivot for SaaS activity in AiTM token theft. The Login:Reprocess event in EntraIdSignInEvents (EndPointCall == 'Login:Reprocess') is where the stolen session token is issued — the SessionId on that event is what the attacker holds. After token issuance, SaaS activity tables (CloudAppEvents, OfficeActivity) will show Microsoft datacenter IPs for the attacker's actions — not the attacker's real proxy IP — because stolen sessions route through Microsoft infrastructure. The attacker proxy IP is still a first-class IOC: block it in Conditional Access, hunt it in DeviceNetworkEvents, and search threat intel for campaign infrastructure. SessionId is the reliable thread for SaaS tables: match it to AADSessionId in CloudAppEvents and OfficeActivity. The two most reliable attacker trackers in AiTM: (1) known attacker proxy IP — valid for blocking, network tables, threat intel; (2) stolen SessionId — reliable for all SaaS activity tables where Microsoft infra IPs appear.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table",
    crossTables: [
      { table: "EntraIdSignInEvents" },
      { table: "AADSignInEventsBeta" },
      { table: "CloudAppEvents" },
      { table: "OfficeActivity" },
    ],
  },

  "DeviceId + AccountName": {
    docs: "Composite pivot combining DeviceId and AccountName to correlate process events with logon events on the same device for the same user.",
    plain: "Links what a process did to who was logged in when it happened on a specific machine.",
    dfir: "Confirms that suspicious process activity is tied to a specific user session. If malware runs under a user account name, this pivot connects it to the corresponding logon event — revealing whether it was an interactive session, a scheduled task, or a service.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceLogonEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
    ],
  },

  // ── File hashes ───────────────────────────────────────────────────────────────

  "SHA1": {
    docs: "SHA-1 cryptographic hash of a file. Less collision-resistant than SHA256, but the primary hash used by DeviceFileCertificateInfo for code-signing lookups.",
    plain: "The SHA-1 fingerprint of a file. Use SHA256 when available; use SHA1 to link to DeviceFileCertificateInfo to check whether a binary is legitimately signed.",
    dfir: "The essential bridge between file execution events and code-signing validation. Join SHA1 from DeviceProcessEvents or DeviceFileEvents to DeviceFileCertificateInfo to determine if a process ran as an unsigned binary, a self-signed binary, or one signed by a trusted certificate. Unsigned or self-signed binaries in system directories are high-confidence malware indicators.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceEvents" },
      { table: "DeviceImageLoadEvents" },
      { table: "DeviceFileCertificateInfo" },
      { table: "AlertEvidence" },
      { table: "BehaviorEntities" },
    ],
  },

  // ── Initiating process identity columns (present in ALL 7 device event tables) ─

  "InitiatingProcessAccountUpn": {
    docs: "UPN of the account that owns the initiating (parent) process. Shares format with AccountUpn and is populated from the process token at event time.",
    plain: "The user account whose session the triggering process was running under — the identity behind the parent process.",
    dfir: "Directly links process activity in device tables back to identity provider logs. If InitiatingProcessAccountUpn is a service account, a disabled account, or an account you don't recognise, that is an immediate red flag. Pivot this value into IdentityInfo, IdentityLogonEvents, or EntraIdSignInEvents to build a full picture of the account.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceNetworkEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceLogonEvents" },
      { table: "DeviceEvents" },
      { table: "DeviceImageLoadEvents" },
    ],
  },

  "InitiatingProcessAccountObjectId": {
    docs: "Entra ID ObjectId of the account that owns the initiating process — the cloud identity GUID linked to the process token.",
    plain: "The Entra ID GUID of the user running the parent process. Stable across UPN changes and links directly to cloud identity tables.",
    dfir: "Enables a direct device-to-cloud pivot without going through UPN. When a device process event carries this value, join it straight into EntraIdSignInEvents or IdentityInfo to understand the cloud-side risk posture of that account — even if the UPN has been changed to cover tracks.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceNetworkEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceLogonEvents" },
      { table: "DeviceEvents" },
      { table: "DeviceImageLoadEvents" },
    ],
  },

  "InitiatingProcessSHA1": {
    docs: "SHA-1 hash of the initiating (parent) process binary. Present across all seven core device event tables.",
    plain: "The hash of the parent process executable. Use it to check if the triggering process is a known-bad binary, even if it has been renamed.",
    dfir: "Hash-based IOC matching for the parent process — critical for detecting renamed malware being used as a dropper. Check this value against threat intelligence before trusting the InitiatingProcessFileName. Also join to DeviceFileCertificateInfo to validate whether the parent process is signed by a legitimate publisher.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceNetworkEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceLogonEvents" },
      { table: "DeviceEvents" },
      { table: "DeviceImageLoadEvents" },
      { table: "DeviceFileCertificateInfo", as: "SHA1" },
    ],
  },

  "InitiatingProcessSHA256": {
    docs: "SHA-256 hash of the initiating (parent) process binary. Present across all seven core device event tables.",
    plain: "The SHA-256 fingerprint of the parent process executable — more reliable than SHA1 for threat intel lookups.",
    dfir: "Higher-confidence hash-based IOC for the parent process. Use this for VirusTotal lookups or MDE threat intelligence queries. More resistant to hash collisions than SHA1. When combined with InitiatingProcessFileName, reveals masquerading: the same binary hash appearing under different process names is a process hollowing indicator.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceNetworkEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceLogonEvents" },
      { table: "DeviceEvents" },
      { table: "DeviceImageLoadEvents" },
    ],
  },

  "InitiatingProcessLogonId": {
    docs: "Logon session ID of the session in which the initiating process was running. Device-scoped identifier — only unique when combined with DeviceId.",
    plain: "The logon session that spawned the parent process. Use it to join back to the specific logon event that created the session.",
    dfir: "Ties the parent process lineage directly back to the originating logon event without needing AccountName. Join DeviceId + InitiatingProcessLogonId to DeviceLogonEvents to find the exact logon (interactive, network, RDP) that started the session chain that led to the suspicious activity.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceNetworkEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceEvents" },
      { table: "DeviceImageLoadEvents" },
      { table: "DeviceLogonEvents", as: "LogonId" },
    ],
  },

  // ── Process identity / stability columns ─────────────────────────────────────

  "ProcessUniqueId": {
    docs: "A stable unique identifier for a process derived from the process creation timestamp and PID. Unlike raw PIDs, ProcessUniqueId does not get recycled — it remains unique across the device's lifetime.",
    plain: "A collision-resistant process ID that won't be reused after the process exits. Use this instead of ProcessId when building process trees across wide time windows.",
    dfir: "Eliminates the false-positive risk of PID reuse in long-running hunts. When building process trees over days or weeks, PID values are recycled many times. ProcessUniqueId lets you reliably trace a parent-child chain from an initial infection event to lateral movement actions hours or days later.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceNetworkEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceEvents" },
      { table: "DeviceImageLoadEvents" },
    ],
  },

  "InitiatingProcessUniqueId": {
    docs: "A stable unique identifier for the initiating (parent) process, combining creation time and PID for collision-resistant process lineage tracking.",
    plain: "The collision-resistant unique ID of the parent process — pairs with ProcessUniqueId to build reliable process trees.",
    dfir: "The complementary field to ProcessUniqueId. Join InitiatingProcessUniqueId = ProcessUniqueId across all device event tables to traverse the full process tree from a leaf node all the way back to the original infection vector. Essential for long-dwell threat hunts where PID reuse would otherwise break the chain.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceNetworkEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceEvents" },
      { table: "DeviceImageLoadEvents" },
      { table: "DeviceLogonEvents" },
    ],
  },

  // ── RDP / remote session tracking columns ────────────────────────────────────

  "IsInitiatingProcessRemoteSession": {
    docs: "Boolean indicating whether the process that triggered the event was running inside a remote session (e.g. RDP, remote PowerShell, or similar remote access mechanism).",
    plain: "True if the parent process was running in an RDP or remote session — not a locally-initiated process.",
    dfir: "Instant lateral movement signal. If IsInitiatingProcessRemoteSession is true, the process chain originated from a remote session — not local keyboard input. Combine with InitiatingProcessRemoteSessionDeviceName and InitiatingProcessRemoteSessionIP to identify the source machine of the remote session.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceNetworkEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceEvents" },
      { table: "DeviceImageLoadEvents" },
    ],
  },

  "InitiatingProcessRemoteSessionDeviceName": {
    docs: "Device name (hostname) of the device from which the remote session — in which the initiating process was running — was established.",
    plain: "The source device of the remote session that the parent process was running in. Identifies where the remote connection came from.",
    dfir: "Pinpoints the lateral movement source device. When a process tree originates in a remote session, this field tells you the hostname of the machine the attacker used to connect. Cross-reference that hostname in DeviceInfo and DeviceLogonEvents to understand what happened on the source machine.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceNetworkEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceEvents" },
      { table: "DeviceImageLoadEvents" },
    ],
  },

  "InitiatingProcessRemoteSessionIP": {
    docs: "IP address of the device that established the remote session in which the initiating process was running.",
    plain: "The source IP of the remote session that spawned the parent process.",
    dfir: "Complements InitiatingProcessRemoteSessionDeviceName for lateral movement tracing. When the source device hostname isn't available (e.g. non-domain-joined machine), the IP is your fallback to identify the lateral movement source. Match against DeviceNetworkInfo.IPAddresses to resolve it to a managed device.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceNetworkEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceEvents" },
      { table: "DeviceImageLoadEvents" },
    ],
  },

  // ── Device exposure columns ───────────────────────────────────────────────────

  "IsInternetFacing": {
    docs: "Boolean indicating whether the device has been identified as internet-facing — i.e., has open ports accessible from the public internet as assessed by Microsoft's external attack surface management.",
    plain: "True if the device can be reached directly from the internet. Internet-facing devices are in your external attack surface.",
    dfir: "Critical for prioritising vulnerability and exploit detection. An internet-facing device with a critical CVE is a direct exploitation target, not just a theoretical risk. Filter DeviceTvmSoftwareVulnerabilities on DeviceId where IsInternetFacing is true and CvssScore >= 9.0 for your highest-priority patch targets.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table",
    crossTables: [
      { table: "DeviceInfo" },
    ],
  },

  "ExposureLevel": {
    docs: "Risk exposure level of the device as assessed by Microsoft Defender Vulnerability Management. Values: None, Low, Medium, High. Factors in CVE severity, exploit availability, device criticality, and internet exposure.",
    plain: "Microsoft's overall exposure risk score for the device. High means it has serious unpatched vulnerabilities that are likely exploitable.",
    dfir: "Use ExposureLevel as a rapid triage filter during active incidents. A device involved in suspicious activity that also has ExposureLevel=High has likely been targeted specifically for its vulnerabilities. Pivot from DeviceInfo to DeviceTvmSoftwareVulnerabilities on DeviceId to get the specific CVEs driving the score.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table",
    crossTables: [
      { table: "DeviceInfo" },
    ],
  },

  "AssetValue": {
    docs: "Business criticality value assigned to the device in Microsoft Defender Vulnerability Management. Values: Normal, Low, High. High-value assets receive elevated risk scoring.",
    plain: "How business-critical the device is — High means it's a key server or sensitive endpoint that should be prioritised for patching and monitoring.",
    dfir: "Combine with ExposureLevel for risk-based incident triage. A high-AssetValue device involved in suspicious lateral movement should be your first isolation candidate regardless of how mundane the initial alert seemed. Attackers deliberately target crown jewel systems — AssetValue flags which ones those are.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table",
    crossTables: [
      { table: "DeviceInfo" },
    ],
  },

  // ── Account on-premises SID ───────────────────────────────────────────────────

  "AccountSid": {
    docs: "Windows Security Identifier (SID) for the account. A stable binary identifier assigned by the domain controller or local system. Persists across account renames.",
    plain: "The Windows SID of the account — a unique binary identity that survives name changes. The on-premises equivalent of ObjectId.",
    dfir: "Bridges endpoint events (which use SID natively) with identity events. Useful in hybrid environments where on-prem AD events in IdentityLogonEvents and IdentityDirectoryEvents need to be correlated with DeviceProcessEvents and DeviceLogonEvents. Also useful for detecting well-known SID abuse: S-1-5-18 (SYSTEM), S-1-5-19/20 (Local Service/Network Service) running unexpected processes.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceLogonEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceEvents" },
      { table: "IdentityInfo", as: "OnPremSid" },
      { table: "IdentityLogonEvents" },
      { table: "IdentityDirectoryEvents" },
      { table: "AlertEvidence" },
      { table: "BehaviorEntities" },
    ],
  },

  // ── Email / identity bridge columns ──────────────────────────────────────────

  "InternetMessageId": {
    docs: "The RFC 5322 Message-ID header value of the email, which is set by the originating mail server. Unlike NetworkMessageId (which is Microsoft-assigned), InternetMessageId is set by the sending server and may appear in logs outside of Microsoft 365.",
    plain: "The external message ID the sending mail server stamped on the email — useful for correlating M365 email events with external mail logs or SIEM data from mail gateways.",
    dfir: "Enables cross-system email correlation. If your on-premises mail gateway, third-party SIEM, or external mail relay logs email by the RFC Message-ID header, you can use InternetMessageId to tie those logs back to the M365 investigation in EmailEvents and EmailPostDeliveryEvents.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table",
    crossTables: [
      { table: "EmailEvents" },
      { table: "EmailPostDeliveryEvents" },
    ],
  },

  "SenderObjectId": {
    docs: "The Entra ID ObjectId of the sender account, when the sender is an authenticated Microsoft 365 user. Links email events directly to the identity layer without needing to resolve a UPN.",
    plain: "The Entra ID GUID of who sent the email. Populated only for internal senders or authenticated relay — empty for external senders.",
    dfir: "Enables direct email-to-identity pivot without UPN matching. When investigating Business Email Compromise or internal phishing from a compromised account, join SenderObjectId to IdentityInfo and EntraIdSignInEvents to see the full account context — including risk level, MFA status, and concurrent sign-ins — without needing to look up the UPN first.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table",
    crossTables: [
      { table: "EmailEvents" },
      { table: "EmailAttachmentInfo" },
      { table: "IdentityInfo", as: "AccountObjectId" },
      { table: "EntraIdSignInEvents", as: "AccountObjectId" },
    ],
  },

  "RecipientObjectId": {
    docs: "The Entra ID ObjectId of the recipient account. Links email events directly to the identity and device layer for the recipient.",
    plain: "The Entra ID GUID of who received the email. Enables direct join to identity and device tables to understand the recipient's endpoint posture.",
    dfir: "Bypasses UPN resolution for pivoting from email recipient to device activity. Join RecipientObjectId to IdentityInfo (AccountObjectId) to get device memberships and risk level, then to DeviceLogonEvents to find which machine the recipient was on when the email arrived.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table",
    crossTables: [
      { table: "EmailEvents" },
      { table: "EmailAttachmentInfo" },
      { table: "EmailPostDeliveryEvents" },
      { table: "IdentityInfo", as: "AccountObjectId" },
    ],
  },

  "UrlLocation": {
    docs: "Location within an email or Teams message where the URL was found. Values include: Header, Body, Attachment, QRCode. The QRCode value indicates the URL was extracted from an embedded QR code image.",
    plain: "Where in the message the URL was found. QRCode is particularly notable — it means the link was hidden inside a QR code image, a technique used to bypass text-based URL scanning.",
    dfir: "The critical QR code phishing detection column. Filter EmailUrlInfo where UrlLocation == 'QRCode' to find all QR phishing attempts in your environment — standard URL scanning often misses these. Join to UrlClickEvents to find who actually scanned the QR code and clicked through. Volume of QRCode URLs in recent 30 days is a good baseline for detection rule tuning.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailurlinfo-table",
    crossTables: [
      { table: "EmailUrlInfo" },
      { table: "MessageUrlInfo" },
    ],
  },

  // ── Cloud App anomaly detection columns ──────────────────────────────────────

  "IsAdminOperation": {
    docs: "Boolean indicating whether the cloud app activity was performed using administrative privileges — for example, a global admin accessing another user's mailbox or an admin modifying tenant-wide settings.",
    plain: "True if the cloud action was performed as an admin operation, not a regular user action.",
    dfir: "High-value filter for privileged account abuse investigation. An attacker who has compromised a global admin will generate IsAdminOperation = true events. Filter CloudAppEvents for IsAdminOperation = true from accounts that don't normally perform admin actions — look for mass mailbox access, user account modifications, app consent changes, or conditional access policy modifications.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table",
    crossTables: [
      { table: "CloudAppEvents" },
    ],
  },

  "UncommonForUser": {
    docs: "A dynamic JSON array of fields in the event that are uncommon or anomalous compared to the user's historical baseline behaviour as computed by Defender for Cloud Apps UEBA.",
    plain: "A list of things in this event that are unusual for this particular user — Defender's built-in anomaly detection has flagged these specific fields as deviating from baseline.",
    dfir: "Pre-computed behavioural anomaly signal. Rather than building your own baseline queries, check this field for any non-empty value. If UncommonForUser contains 'IPAddress' it means the user is connecting from a new IP; 'Application' means a new app; 'UserAgent' means a new browser or client. Multiple fields flagged simultaneously is a strong account compromise signal.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table",
    crossTables: [
      { table: "CloudAppEvents" },
    ],
  },

  "OAuthAppId": {
    docs: "The application ID of the OAuth app that performed the cloud action, when the event was generated by an OAuth application acting on behalf of a user or service principal.",
    plain: "The OAuth app that did this action — distinct from the user's own app session. Populated when a third-party OAuth integration or service principal is acting as the agent.",
    dfir: "Critical for detecting OAuth app abuse and consent grant attacks. An attacker who tricks a user into granting consent to a malicious OAuth app will generate CloudAppEvents with suspicious OAuthAppId values performing data access on behalf of the user. Find all OAuthAppId values accessing sensitive data (email, files, directory) for users who recently granted new consent.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table",
    crossTables: [
      { table: "CloudAppEvents" },
      { table: "AlertEvidence", as: "OAuthApplicationId" },
    ],
  },

  // ── Entra ID sign-in columns ──────────────────────────────────────────────────

  "EntraIdDeviceId": {
    docs: "The Entra ID (Azure AD) device object identifier for the device used to sign in. This is the Entra-registered device ID, as distinct from the MDE DeviceId. Introduced in EntraIdSignInEvents to replace the deprecated AadDeviceId field.",
    plain: "The Entra ID registration ID of the device that signed in. Links the sign-in event to Entra device compliance and management status — different from the MDE device sensor ID.",
    dfir: "Essential for zero-trust gap analysis. A sign-in where EntraIdDeviceId is empty means the device is not Entra-registered — it has no device compliance policy. Combine with IsManaged and IsCompliant to find sign-ins from unmanaged devices accessing sensitive resources. In device code phishing, the legitimate user's device shows a valid EntraIdDeviceId but the attacker's token usage shows none.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-entraidsiginevents-table",
    crossTables: [
      { table: "EntraIdSignInEvents" },
    ],
  },

  "IsCompliant": {
    docs: "Boolean indicating whether the device used to sign in meets Intune or Entra ID compliance policies at the time of sign-in.",
    plain: "Was the device compliant with Intune device management policies when this sign-in happened?",
    dfir: "Zero Trust posture signal for device-based Conditional Access. A successful sign-in to a sensitive resource where IsCompliant = false means CA device compliance policies aren't enforced for that resource. In BYOD and AiTM scenarios, IsCompliant = false alongside IsManaged = false is strong evidence the authentication came from an attacker-controlled device.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table",
    crossTables: [
      { table: "EntraIdSignInEvents" },
      { table: "AADSignInEventsBeta" },
    ],
  },

  "IsExternalUser": {
    docs: "Boolean indicating whether the signing-in account is external to the tenant — i.e., a guest user from another organisation or a B2B collaboration account.",
    plain: "True if the sign-in is from a guest or external user, not a member of this tenant.",
    dfir: "Scopes external access investigations. Guest accounts have fewer controls and are often overlooked in security monitoring. Look for external users accessing sensitive SharePoint sites, Teams channels, or triggering IsAdminOperation events — guest accounts should almost never perform admin operations.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table",
    crossTables: [
      { table: "EntraIdSignInEvents" },
      { table: "AADSignInEventsBeta" },
      { table: "CloudAppEvents" },
    ],
  },

  // ── Data classification columns ───────────────────────────────────────────────

  "SensitivityLabelId": {
    docs: "The Microsoft Purview sensitivity label ID currently applied to the item. A string identifier (GUID) that maps to a label such as Confidential or Highly Confidential.",
    plain: "The GUID of the Purview sensitivity label on the file or item involved in the event.",
    dfir: "Use this to triage DLP violations by data sensitivity — a SensitivityLabelId corresponding to 'Highly Confidential' combined with an exfiltration ActionType is a critical insider threat signal. Join to your organisation's label registry to convert the GUID to a human-readable label name. Also present as PreviousSensitivityLabelId for label-downgrade detection.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-datasecurityevents-table",
    crossTables: [
      { table: "DataSecurityEvents" },
    ],
  },

  "SensitivityLabel": {
    docs: "The Microsoft Purview Information Protection sensitivity label applied to the file at the time of the event. Examples: Confidential, Highly Confidential, Public.",
    plain: "The data classification label on the file — tells you how sensitive the organisation considers this data.",
    dfir: "Data exfiltration severity multiplier. A file access or copy event where SensitivityLabel is 'Highly Confidential' or 'Confidential' is far more serious than the same action on an unlabelled file. Filter DeviceFileEvents by high SensitivityLabel to find bulk access of sensitive files. Note: DataSecurityEvents uses SensitivityLabelId (a string label ID), not SensitivityLabel.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table",
    crossTables: [
      { table: "DeviceFileEvents" },
      // DataSecurityEvents uses SensitivityLabelId, not SensitivityLabel
    ],
  },

  "FileOriginUrl": {
    docs: "The URL from which a file was downloaded onto the device. Captured when a file is downloaded via a browser or application that provides download origin metadata.",
    plain: "Where the file came from — the URL it was downloaded from. Only populated when MDE can attribute the file to a specific download event.",
    dfir: "Malware delivery hunting anchor. If you know a file is malicious (by SHA256), pivot on FileOriginUrl across DeviceFileEvents to find all devices where the same file was downloaded from the same URL — revealing the blast radius of a malware distribution campaign. Also check FileOriginUrl against your web proxy logs to correlate with category and reputation data.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table",
    crossTables: [
      { table: "DeviceFileEvents" },
      { table: "DeviceEvents" },
    ],
  },

  "FileOriginIP": {
    docs: "The IP address from which a file was downloaded onto the device, when the download source IP can be resolved.",
    plain: "The IP address the file was downloaded from — the server that delivered the malware.",
    dfir: "C2 and malware distribution infrastructure indicator. Cross-reference FileOriginIP against AlertEvidence and threat intelligence to confirm the download source is known-malicious infrastructure. Pivot this IP into DeviceNetworkEvents to see all endpoints that connected to it — beyond just those where the file was written.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table",
    crossTables: [
      { table: "DeviceFileEvents" },
      { table: "DeviceEvents" },
      { table: "DeviceNetworkEvents", as: "RemoteIP" },
    ],
  },

  // ── UEBA / Behaviors tables pivot key ────────────────────────────────────────

  "BehaviorId": {
    docs: "Unique identifier for a UEBA behavior record in BehaviorInfo. Links the high-level behavior description to all its associated entities in BehaviorEntities.",
    plain: "The join key between the two UEBA behavior tables — BehaviorInfo has the what and why; BehaviorEntities has the specific devices, users, and files involved.",
    dfir: "UEBA behaviors represent correlated anomaly detections that may not trigger individual alerts. Join BehaviorId from BehaviorInfo to BehaviorEntities to extract the exact accounts, devices, and files involved. Cross-reference BehaviorEntities DeviceId/AccountUpn with DeviceProcessEvents and IdentityLogonEvents around the behavior's StartTime/EndTime window.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-behaviorinfo-table",
    crossTables: [
      { table: "BehaviorInfo" },
      { table: "BehaviorEntities" },
    ],
  },

  // ── Exposure Graph pivot keys ─────────────────────────────────────────────────

  "NodeId": {
    docs: "Unique identifier for a node in the Security Exposure Management graph. Nodes represent entities in your attack surface — devices, identities, Azure resources, cloud workloads.",
    plain: "The unique ID of an entity in the attack surface graph. Use it to join ExposureGraphNodes to ExposureGraphEdges to traverse attack paths.",
    dfir: "Attack path analysis pivot. Join NodeId from ExposureGraphNodes to SourceNodeId or TargetNodeId in ExposureGraphEdges to map all attack paths leading to or from a critical asset. The EntityIds field in ExposureGraphNodes contains the DeviceId or AccountObjectId that links back to standard XDR tables.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-exposuregraphnodes-table",
    crossTables: [
      { table: "ExposureGraphNodes" },
      { table: "ExposureGraphEdges", as: "SourceNodeId" },
      { table: "ExposureGraphEdges", as: "TargetNodeId" },
    ],
  },

  // ── Composite pivots (additions) ─────────────────────────────────────────────

  "AccountSid → IdentityInfo": {
    docs: "Directional pivot: use AccountSid from a device event table to look up the account's full profile in IdentityInfo via OnPremSid.",
    plain: "On-premises AD SID from endpoint events → full account profile in IdentityInfo. Useful when UPN isn't available.",
    dfir: "Essential for hybrid environment investigations. Device event tables carry the Windows SID; IdentityInfo maps SIDs to UPNs, ObjectIds, group memberships, and risk levels. When investigating a suspicious local account (where AccountUpn is empty), the SID is the reliable link to the AD identity layer.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityinfo-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceLogonEvents" },
      { table: "DeviceEvents" },
      { table: "IdentityInfo" },
      { table: "IdentityLogonEvents" },
      { table: "IdentityDirectoryEvents" },
    ],
  },

  "InitiatingProcessUniqueId → ProcessUniqueId": {
    docs: "Directional composite pivot: join InitiatingProcessUniqueId in any device event table to ProcessUniqueId in DeviceProcessEvents to walk the process tree upward toward the root.",
    plain: "The stable parent-process key. Join child events back to parent process creation events to build an accurate, PID-collision-free process tree.",
    dfir: "The correct way to build process trees in long-running hunts. For each suspicious process execution in DeviceProcessEvents, join InitiatingProcessUniqueId = ProcessUniqueId repeatedly until you reach a trusted root process (services.exe, svchost.exe at expected paths) or until the chain terminates. Each step reveals another layer of the attack chain.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceNetworkEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceEvents" },
      { table: "DeviceImageLoadEvents" },
    ],
  },

  // ── Email campaign pivot ──────────────────────────────────────────────────────

  "CampaignId": {
    docs: "Unique identifier for an email campaign as tracked by Microsoft Defender for Office 365. Links individual email messages in EmailEvents to their parent campaign record in CampaignInfo.",
    plain: "The ID that groups individual phishing or malware emails into a single tracked campaign. Your join key from EmailEvents into CampaignInfo.",
    dfir: "Elevates single-email investigations to campaign-level scope. Once you have a NetworkMessageId for a suspicious email, extract its CampaignId and join to CampaignInfo to understand how many messages MDO has tied to this campaign, what threat type it is, and what other recipients were targeted. A CampaignId also appears on multiple EmailEvents rows — use it to find all deliveries in the same wave even if the email subject and sender varied.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table",
    crossTables: [
      { table: "EmailEvents" },
      { table: "CampaignInfo" },
    ],
  },

  // ── Cloud DNS pivot key ───────────────────────────────────────────────────────

  "DnsQueryType": {
    docs: "Type of DNS query made from a cloud workload, as recorded in CloudDnsEvents. Common values: A, AAAA, CNAME, MX, TXT, PTR. Unusual query types (TXT, NULL) are frequently used for DNS tunneling.",
    plain: "What kind of DNS lookup was made — A record (IPv4), CNAME (alias), TXT (text record), etc. TXT and NULL record queries are rarely used legitimately and are strong DNS tunneling indicators.",
    dfir: "Primary DNS tunneling detection column. Legitimate workloads almost never query TXT or NULL record types at high volume. Combine with high query frequency from a single DeviceId and unusually long query names (> 50 characters) to identify DNS exfiltration channels. Also watch for high entropy in the queried domain name — DGA and tunneling domains have very different entropy profiles from legitimate domains.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-clouddnsevents-table",
    crossTables: [
      { table: "CloudDnsEvents" },
    ],
  },

  "DnsQueryName": {
    docs: "The fully qualified domain name (FQDN) that was queried in the DNS request, as recorded in CloudDnsEvents.",
    plain: "The actual domain name that was looked up — e.g. 'api.malicious-c2.com'. For DNS tunneling this will contain unusually long or high-entropy subdomains encoding exfiltrated data.",
    dfir: "The core IOC in CloudDnsEvents. Long DnsQueryName values (> 50 chars) with high entropy subdomains are the signature of DNS tunneling. Compare DnsQueryName against threat intel blocklists and your baseline of expected cloud workload DNS queries. New domains first seen recently (< 30 days) queried heavily by cloud workloads are worth investigating.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-clouddnsevents-table",
    crossTables: [
      { table: "CloudDnsEvents" },
      { table: "DeviceNetworkEvents", as: "RemoteUrl" },
    ],
  },

  // ── Service principal sign-in pivot key ───────────────────────────────────────

  "ServicePrincipalId": {
    docs: "The unique identifier of the service principal (application or managed identity) that performed the authentication, as recorded in EntraIdSpnSignInEvents.",
    plain: "The ID of the app or managed identity that authenticated — like AccountObjectId but for workload identities instead of users.",
    dfir: "The primary pivot key for non-human identity investigation. When investigating suspicious cloud activity that might be a compromised service principal or managed identity, ServicePrincipalId links EntraIdSpnSignInEvents sign-ins to CloudAppEvents activity using the same identity. Unexpected service principals authenticating from unfamiliar IPs or to unusual resources are indicators of credential theft targeting workload identities.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-entraidsignineventsbeta-table",
    crossTables: [
      { table: "EntraIdSpnSignInEvents" },
      { table: "CloudAppEvents", as: "AccountId" },
    ],
  },

  // ── IdentityAccountInfo pivot key ─────────────────────────────────────────────

  "OnPremSid": {
    docs: "The on-premises Active Directory Security Identifier (SID) of an account, as stored in IdentityInfo and IdentityAccountInfo. Stable binary identity assigned by the domain controller.",
    plain: "The on-prem AD SID that links Entra ID cloud identities back to their Active Directory counterpart — the bridge between hybrid identity tables.",
    dfir: "Critical for hybrid environment correlation. IdentityInfo maps OnPremSid to AccountObjectId, AccountUpn, and cloud risk indicators — giving you a single lookup to connect a Windows SID from device events to the full Entra ID identity profile. Particularly important for lateral movement investigations where device events expose SIDs but you need the cloud identity context.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityinfo-table",
    crossTables: [
      { table: "IdentityInfo" },
      { table: "IdentityAccountInfo" },
      { table: "DeviceProcessEvents", as: "AccountSid" },
      { table: "DeviceLogonEvents", as: "AccountSid" },
      { table: "IdentityLogonEvents", as: "AccountSid" },
    ],
  },

  "NetworkMessageId (Teams)": {
    docs: "Teams messages use the same NetworkMessageId scheme as email. MessageEvents, MessagePostDeliveryEvents, and MessageUrlInfo all join on NetworkMessageId — identical pattern to email tables.",
    plain: "Teams messages use the same tracking ID format as email. The investigation pattern is the same: NetworkMessageId → delivery (MessageEvents) → URLs (MessageUrlInfo) → post-delivery actions (MessagePostDeliveryEvents).",
    dfir: "Expands the email phishing pivot chain to cover Teams-based phishing. Attackers increasingly use Teams for credential harvesting and malware delivery, especially after initial email compromise (send phishing from a compromised Teams account). The identical NetworkMessageId schema means your email hunting KQL translates directly to Teams hunting by swapping the table names.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-messageevents-table",
    crossTables: [
      { table: "MessageEvents" },
      { table: "MessagePostDeliveryEvents" },
      { table: "MessageUrlInfo" },
      { table: "UrlClickEvents" },
      { table: "EmailEvents" },
    ],
  },
};

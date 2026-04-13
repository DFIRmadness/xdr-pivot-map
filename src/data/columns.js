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
    dfir: "Your primary identity pivot. An attacker who compromises a single account will leave UPN breadcrumbs across EmailEvents, IdentityLogonEvents, DeviceLogonEvents, AADSignInEventsBeta, and CloudAppEvents. Correlating all of them paints the full picture of what they did after initial access.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitylogonevents-table",
    crossTables: [
      { table: "DeviceProcessEvents" },
      { table: "DeviceLogonEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceEvents" },
      { table: "IdentityLogonEvents" },
      { table: "IdentityQueryEvents" },
      { table: "IdentityDirectoryEvents" },
      { table: "AADSignInEventsBeta" },
      { table: "CloudAppEvents" },
      { table: "UrlClickEvents" },
    ],
  },

  "AccountObjectId": {
    docs: "Unique object identifier for the account in Azure Active Directory (Entra ID). A stable GUID that persists even if the UPN or display name changes.",
    plain: "The AAD GUID for a user. More reliable than UPN for cloud pivots because it doesn't change when someone's email address changes.",
    dfir: "Essential for cloud investigations. When an attacker renames an account or changes UPN to cover tracks, the ObjectId stays the same. Use this to join AADSignInEventsBeta into CloudAppEvents to trace what a compromised account actually did in M365.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table",
    crossTables: [
      { table: "AADSignInEventsBeta" },
      { table: "CloudAppEvents" },
      { table: "IdentityDirectoryEvents" },
      { table: "GraphApiAuditEvents" },
    ],
  },

  "AccountId": {
    docs: "Identifier for the account as recorded in CloudAppEvents. May be an AAD ObjectId, SID, or email address depending on the application and event type.",
    plain: "The account identifier as the cloud app sees it — usually the same as AccountObjectId for Microsoft 365 apps.",
    dfir: "Use this to join CloudAppEvents to GraphApiAuditEvents and CloudAuditEvents to trace what a compromised account actually did in the cloud after sign-in.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table",
    crossTables: [
      { table: "CloudAppEvents" },
      { table: "GraphApiAuditEvents" },
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
      { table: "GraphApiAuditEvents" },
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
      { table: "AADSignInEventsBeta" },
      { table: "CloudAppEvents" },
      { table: "DeviceLogonEvents", as: "RemoteIP" },
    ],
  },

  "Country": {
    docs: "Country or region associated with the IP address of the event, resolved via geolocation. May be empty if the IP cannot be geolocated.",
    plain: "Where in the world the request came from, based on the source IP.",
    dfir: "Instant triage signal. A CFO whose account suddenly signs in from a country they have never been to — while they are sitting in the office — is account takeover until proven otherwise. Always baseline normal countries for high-value accounts.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table",
    crossTables: [
      { table: "AADSignInEventsBeta" },
      { table: "IdentityLogonEvents" },
      { table: "CloudAppEvents" },
    ],
  },

  "IsAnonymousProxy": {
    docs: "Boolean indicating whether the sign-in IP address was identified as an anonymous proxy, VPN, or TOR exit node by Microsoft's threat intelligence.",
    plain: "True if the login came from a known anonymiser — VPN, TOR, or proxy service.",
    dfir: "Attackers use anonymisers to obscure their origin. A legitimate employee signing in through TOR is almost never valid. Combine with RiskLevelDuringSignIn for high-confidence account compromise alerts.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table",
    crossTables: [
      { table: "AADSignInEventsBeta" },
    ],
  },

  "RiskLevelDuringSignIn": {
    docs: "Entra ID Protection risk level assessed at sign-in time. Values: none, low, medium, high. Factors include leaked credentials, impossible travel, anonymous IP, and unusual sign-in properties.",
    plain: "Microsoft's real-time risk score for the sign-in — high means Entra thinks something is suspicious.",
    dfir: "A pre-computed threat signal you should always include in sign-in investigations. High risk + successful sign-in + no MFA challenge = Conditional Access gap. Cross-reference with IsAnonymousProxy and Country to understand what drove the risk score.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table",
    crossTables: [
      { table: "AADSignInEventsBeta" },
    ],
  },

  "ErrorCode": {
    docs: "Entra ID sign-in error code. 0 = success. Common failure codes: 50126 = invalid credentials, 50053 = account locked, 50055 = expired password, 50074 = MFA required.",
    plain: "Whether the sign-in worked, and if not, why it failed. 0 means success.",
    dfir: "Crucial for brute-force and password spray detection. A spray shows many different accounts with error 50126, then a sudden 0 (success) on one. A targeted attack shows many failures on one account. ErrorCode 50074 (MFA required) followed by success can indicate MFA fatigue or bypass.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table",
    crossTables: [
      { table: "AADSignInEventsBeta" },
    ],
  },

  "ConditionalAccessStatus": {
    docs: "Result of the Conditional Access policy evaluation for the sign-in. Values: success, failure, notApplied.",
    plain: "Whether Conditional Access policies passed, failed, or weren't evaluated for this sign-in.",
    dfir: "notApplied on a sensitive resource sign-in means no CA policy covered it — a gap in your Zero Trust posture. failure means the policy blocked it. success means it passed, but check what the policy actually required — MFA-optional policies can pass without MFA.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table",
    crossTables: [
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
    dfir: "Your anchor for all endpoint pivots. DeviceName can change; DeviceId does not. Always use DeviceId when joining DeviceInfo → DeviceProcessEvents → DeviceNetworkEvents → DeviceLogonEvents to avoid mismatching events across a rename.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table",
    crossTables: [
      { table: "DeviceInfo" },
      { table: "DeviceProcessEvents" },
      { table: "DeviceNetworkEvents" },
      { table: "DeviceFileEvents" },
      { table: "DeviceRegistryEvents" },
      { table: "DeviceLogonEvents" },
      { table: "DeviceEvents" },
      { table: "DeviceNetworkInfo" },
      { table: "DeviceTvmSoftwareVulnerabilities" },
      { table: "DeviceTvmSoftwareInventory" },
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
      { table: "IdentityLogonEvents" },
      { table: "IdentityQueryEvents" },
      { table: "IdentityDirectoryEvents" },
      { table: "CloudAppEvents" },
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
      { table: "EmailAttachmentInfo" },
      { table: "AlertEvidence" },
      { table: "DeviceFileCertificateInfo" },
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
    docs: "TCP or UDP port number on the remote endpoint that the device connected to or received a connection from.",
    plain: "The port number on the remote side of the connection.",
    dfir: "Non-standard ports for common protocols are a classic C2 indicator — HTTPS on port 4443, HTTP on 8080, or DNS on a non-53 port. Also useful for lateral movement: port 445 = SMB, 3389 = RDP, 5985/5986 = WinRM/PowerShell remoting. Always combine with InitiatingProcessFileName.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table",
    crossTables: [
      { table: "DeviceNetworkEvents" },
    ],
  },

  "LocalPort": {
    docs: "TCP or UDP port number on the local device side of the connection.",
    plain: "The port number on this device's side of the connection.",
    dfir: "Useful for identifying listening services and inbound connections. Unexpected services listening on high ports (> 1024) on endpoints — especially those created by non-system processes — can indicate backdoors or reverse shells. Compare with expected service baseline.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table",
    crossTables: [
      { table: "DeviceNetworkEvents" },
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
    docs: "Number of bytes sent by the local device to the remote endpoint during the connection. Also appears as SentBytes in some table versions.",
    plain: "How much data this device sent to the remote endpoint.",
    dfir: "Primary exfiltration detection signal. Large BytesSent values to external IPs from non-browser processes — especially outside business hours — are high-priority alerts. Also useful for DNS tunneling: DNS queries that send unusually large payloads indicate data being encoded in query names.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table",
    crossTables: [
      { table: "DeviceNetworkEvents", as: "SentBytes" },
    ],
  },

  // ── Registry ──────────────────────────────────────────────────────────────

  "RegistryKey": {
    docs: "Full path of the registry key involved in the event, including the hive prefix (e.g. HKEY_LOCAL_MACHINE\\...). Represents the container, not the individual value.",
    plain: "The full registry path — the folder that was created or accessed.",
    dfir: "Persistence hunting 101. Run keys (HKCU/HKLM\\...\\Run, RunOnce), service keys (HKLM\\SYSTEM\\CurrentControlSet\\Services), and AppInit_DLLs are the most common attacker-modified keys. Filter for writes to these paths from non-system processes.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table",
    crossTables: [
      { table: "DeviceRegistryEvents" },
    ],
  },

  "RegistryValueName": {
    docs: "Name of the registry value that was created, modified, or deleted within the registry key.",
    plain: "The name of the specific registry entry that was changed — like the filename within the folder.",
    dfir: "Identifies exactly which value was tampered with. ImagePath in a service key changed by a non-SCM process is service hijacking. Start in a service key changed to 2 (Auto) is automatic startup. DisableAntiSpyware set to 1 is Defender disablement.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table",
    crossTables: [
      { table: "DeviceRegistryEvents" },
    ],
  },

  "RegistryValueData": {
    docs: "Data written to the registry value — the actual value stored. For REG_SZ and REG_EXPAND_SZ types this is the string value; for REG_DWORD it is the integer.",
    plain: "The actual data stored in the registry value — the payload of the change.",
    dfir: "Where the actual malicious payload lives in registry-based persistence. Fileless malware often stores base64-encoded PowerShell or shellcode here. LOLBin execution paths, C2 URLs, and scheduled task commands can all be written to registry values. Decode any base64 or hex you find here immediately.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table",
    crossTables: [
      { table: "DeviceRegistryEvents" },
    ],
  },

  // ── Email ─────────────────────────────────────────────────────────────────

  "NetworkMessageId": {
    docs: "Unique identifier for an email message assigned by Microsoft 365 during transport. Persists across all email-related tables for the lifetime of the message.",
    plain: "The tracking number stamped on every email as it flows through Exchange Online. Your primary join key across all email tables.",
    dfir: "The master pivot key for email-based attack chains. One NetworkMessageId ties together EmailEvents (delivery), EmailAttachmentInfo (attachment hashes), EmailUrlInfo (extracted links), and UrlClickEvents (user clicks). Always start an email investigation with this column.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table",
    crossTables: [
      { table: "EmailEvents" },
      { table: "EmailAttachmentInfo" },
      { table: "EmailUrlInfo" },
      { table: "EmailPostDeliveryEvents" },
      { table: "UrlClickEvents" },
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

  "MalwareDetectionMethod": {
    docs: "Method used to detect malware in an email attachment. Examples include: ATP detonation, antivirus engine, file reputation, Zero-hour Auto Purge (ZAP).",
    plain: "How the malware in the attachment was detected — detonation sandbox, AV signature, or file reputation.",
    dfir: "Tells you how confident the detection is. ATP detonation = highest confidence (sandbox observed malicious behaviour). File reputation = hash-based, reliable. ZAP = detected after delivery and retroactively pulled. If MalwareDetectionMethod is empty but you have a suspicious attachment, check SHA256 in threat intel.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailattachmentinfo-table",
    crossTables: [
      { table: "EmailAttachmentInfo" },
    ],
  },

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
    docs: "Name or title of the alert as generated by the Microsoft Defender XDR detection engine or a custom detection rule.",
    plain: "The human-readable name of the alert.",
    dfir: "Use Title with contains or has_any to hunt for clusters of related detections — e.g. all 'Credential dumping' or 'Ransomware' alerts across the estate. Correlate with Severity and AttackTechniques to prioritise. Repeated alert titles on a single device in a short window suggest multi-stage attack progression.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table",
    crossTables: [
      { table: "AlertInfo" },
    ],
  },

  "Severity": {
    docs: "Severity of the alert as assessed by Defender XDR. Values: Informational, Low, Medium, High.",
    plain: "How serious Microsoft considers the alert.",
    dfir: "High severity alerts demand immediate triage. However, don't ignore Medium — advanced persistent threats often generate medium alerts early in the chain. Filter for High first, then pivot to related Medium alerts on the same device or account in the same timeframe to understand the full kill chain.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table",
    crossTables: [
      { table: "AlertInfo" },
    ],
  },

  "Category": {
    docs: "Category of the attack activity associated with the alert, aligned to the MITRE ATT&CK framework or Microsoft threat taxonomy.",
    plain: "The type of attack technique the alert relates to — e.g. Ransomware, CredentialAccess, LateralMovement.",
    dfir: "Enables fleet-wide hunting for attack categories before alerts are correlated into incidents. Group alerts by Category across all devices in a time window to identify whether a single attacker is operating across multiple machines. Ransomware category alerts should trigger immediate network isolation procedures.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table",
    crossTables: [
      { table: "AlertInfo" },
    ],
  },

  "AttackTechniques": {
    docs: "MITRE ATT&CK technique IDs associated with the alert, as a JSON array or pipe-delimited string. May contain multiple technique IDs.",
    plain: "Which MITRE ATT&CK technique IDs the alert maps to.",
    dfir: "Direct mapping between Defender alerts and the ATT&CK framework. Use has 'T1486' to find all ransomware-related alerts, or parse the array to look for multiple high-risk techniques on a single device. Cross-referencing AttackTechniques with your MITRE coverage gaps tells you whether you are detecting what you think you are detecting.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table",
    crossTables: [
      { table: "AlertInfo" },
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
      { table: "GraphApiAuditEvents" },
    ],
  },

  "ObjectName": {
    docs: "Name or identifier of the cloud object involved in the event — for example a file name, mailbox folder name, SharePoint document, or Teams channel.",
    plain: "The name of the specific file, document, or resource that was accessed or modified.",
    dfir: "Essential for data exfiltration scoping. Pivot on ObjectName to identify which files were accessed or downloaded during a compromise. Document names containing keywords like 'password', 'credential', 'VPN', 'salary', or 'merger' accessed in bulk are a major red flag.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table",
    crossTables: [
      { table: "CloudAppEvents" },
      { table: "GraphApiAuditEvents" },
    ],
  },

  "ResourceId": {
    docs: "The full Azure Resource Manager (ARM) resource identifier of the Azure resource involved in the event, in the format /subscriptions/{id}/resourceGroups/{rg}/providers/{type}/{name}.",
    plain: "The unique full path to an Azure resource — think of it as the resource's absolute address inside Azure. It tells you which subscription, resource group, and specific resource (VM, storage account, Key Vault, etc.) was involved.",
    dfir: "In AiTM and Azure-targeting attacks, the ResourceId in CloudAuditEvents identifies exactly which VM received a Run Command or extension write. Parse the resource name from the end of the path to correlate with DeviceName in CloudProcessEvents and DeviceNetworkEvents for the full execution trail.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudauditevents-table",
    crossTables: [
      { table: "CloudAuditEvents" },
      { table: "CloudProcessEvents" },
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
      { table: "AADSignInEventsBeta" },
      { table: "CloudAppEvents" },
    ],
  },

  "IPAddress + AccountUpn": {
    docs: "Composite pivot combining IPAddress and AccountUpn. Used to correlate identity sign-in telemetry with endpoint or cloud events from the same source.",
    plain: "Same as AccountUpn + IPAddress — both columns together map a sign-in event back to the source machine.",
    dfir: "Same as AccountUpn + IPAddress — the column order depends on the table, but the pivot logic is identical. Use it to confirm that what you see in cloud/identity logs corresponds to actual device activity.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table",
    crossTables: [
      { table: "AADSignInEventsBeta" },
      { table: "IdentityLogonEvents" },
      { table: "CloudAppEvents" },
    ],
  },

  "AccountUpn → DeviceId": {
    docs: "Directional pivot: use AccountUpn from a cloud or identity table to find the DeviceId in DeviceLogonEvents, then continue pivoting through device tables.",
    plain: "Cloud and identity tables only have the user's UPN — look up the UPN in DeviceLogonEvents to find the DeviceId.",
    dfir: "The essential cloud-to-endpoint bridge. When you identify suspicious cloud activity (AADSignInEventsBeta, CloudAppEvents), pivot the UPN into DeviceLogonEvents to find which physical device was used. That DeviceId then unlocks the full endpoint telemetry chain.",
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
    docs: "List of threat types identified in the email by Microsoft Defender for Office 365, such as Malware, Phish, or Spam.",
    plain: "What Defender thinks the email is — malware delivery, phishing, spam, or clean. Can be multiple values if the email has more than one threat indicator.",
    dfir: "The fastest triage signal for email investigations. A ThreatTypes value of 'Phish' or 'Malware' confirms the email was weaponized. Use it to filter EmailEvents to only confirmed threats and ignore noise.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table",
    crossTables: [
      { table: "EmailEvents" },
    ],
  },

  "ThreatNames": {
    docs: "Names of malware or other threats detected in email attachments, as identified by Microsoft Defender antivirus and threat intelligence.",
    plain: "The specific malware family name detected in the attachment, like 'TrojanDownloader:O97M/Donoff' or 'Phish:HTML/GenericPhish'.",
    dfir: "Ties the email attachment directly to a known malware family. Cross-reference the name against threat intel to understand the campaign, expected behavior, and MITRE techniques. The same family name may appear in DeviceFileEvents if the file was scanned on an endpoint.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailattachmentinfo-table",
    crossTables: [
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
    docs: "The domain portion of the URL found in the email, extracted by Microsoft Defender for Office 365 during email processing.",
    plain: "Just the domain name from a link in the email, without the path or query string — e.g. 'malicious-site.example.com'.",
    dfir: "Useful for hunting by domain rather than full URL, since attackers rotate paths while reusing infrastructure. Join UrlDomain against threat intel feeds or check against your DNS query logs to see if any internal hosts resolved it.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailurlinfo-table",
    crossTables: [
      { table: "EmailUrlInfo" },
    ],
  },

  // ── Authentication fields ─────────────────────────────────────────────────

  "FailureReason": {
    docs: "The reason an authentication attempt failed, as reported by the identity provider. For Kerberos and NTLM events in IdentityLogonEvents; for Azure AD events, maps to error codes.",
    plain: "Why the login failed — wrong password, account locked, expired ticket, disabled account, etc. Each value corresponds to a Kerberos or NTLM error code that tells you the exact failure mode.",
    dfir: "Password spray attacks produce KDC_ERR_PREAUTH_FAILED in bulk. Account lockouts generate KDC_ERR_CLIENT_REVOKED. A single account with many unique FailureReason values in a short window suggests a targeted attack trying different techniques to bypass authentication.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitylogonevents-table",
    crossTables: [
      { table: "IdentityLogonEvents" },
    ],
  },

  "ApplicationId": {
    docs: "The unique identifier (GUID or app ID) of the Azure AD application that the user signed into, as recorded in AADSignInEventsBeta.",
    plain: "Which app the user was signing into — each Microsoft 365 app, third-party SaaS integration, and custom app has its own ID. The Microsoft Graph API is '00000003-0000-0000-c000-000000000000', for example.",
    dfir: "Identifies exactly which app an attacker accessed after compromising credentials. Unexpected apps — especially the Graph API, Exchange Web Services, or third-party OAuth apps — indicate the attacker is programmatically harvesting data. Cross-reference against your approved app list.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table",
    crossTables: [
      { table: "AADSignInEventsBeta" },
      { table: "CloudAppEvents" },
    ],
  },

  // ── Directory / identity change fields ───────────────────────────────────

  "TargetAccountDisplayName": {
    docs: "The display name of the account that was the target of a directory action, such as a group membership change, password reset, or account modification recorded in IdentityDirectoryEvents.",
    plain: "The friendly name (first name + last name) of the account that was changed, not the account doing the changing. Tells you who was targeted by the directory modification.",
    dfir: "Critical for detecting privilege escalation. If an attacker resets a Domain Admin's password or adds themselves to a privileged group, this field shows whose account was modified. Pair with AccountUpn (the modifier) to map the full action.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitydirectoryevents-table",
    crossTables: [
      { table: "IdentityDirectoryEvents" },
    ],
  },

  "ModifiedProperties": {
    docs: "A JSON array describing what properties were changed on an Active Directory object, including the old and new values of each modified attribute, as recorded in IdentityDirectoryEvents.",
    plain: "The before-and-after values of whatever was changed — for example, a group membership change shows the old member list and the new one, or a password change logs which account attribute was touched.",
    dfir: "The most detail-rich field in IdentityDirectoryEvents. Parse the JSON to extract old and new values. For group changes, look for additions to 'Domain Admins', 'Enterprise Admins', or 'Protected Users'. For account changes, flag modifications to adminCount, userAccountControl, or servicePrincipalName.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitydirectoryevents-table",
    crossTables: [
      { table: "IdentityDirectoryEvents" },
    ],
  },

  // ── Alert fields ──────────────────────────────────────────────────────────

  "EntityType": {
    docs: "The type of entity represented by this row in AlertEvidence. Possible values include File, Ip, Url, User, Machine, MailMessage, MailCluster, MailBox, and CloudApplication.",
    plain: "What kind of thing this alert evidence row is about — a file, an IP address, a user account, a device, an email, etc. Each row in AlertEvidence describes one entity involved in the alert.",
    dfir: "Always filter by EntityType first to extract the right IOC type from an alert. EntityType == 'File' gives you hashes to hunt across endpoints; EntityType == 'Ip' gives you C2 addresses to check in network logs; EntityType == 'User' gives you compromised accounts. One alert can have dozens of evidence rows across all types.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertevidence-table",
    crossTables: [
      { table: "AlertEvidence" },
    ],
  },

  "EvidenceRole": {
    docs: "Describes the role of an entity in an alert — whether it was the attacker-controlled entity (Attacker), the victim (Victim), or contextually related (Related, ContextualTarget).",
    plain: "Defender's classification of why this entity is part of the alert. 'Attacker' means Defender thinks this is the bad actor's asset; 'Victim' means it was targeted; 'Related' means it was involved but its role is unclear.",
    dfir: "Filter on EvidenceRole == 'Attacker' to extract confirmed attacker-controlled IPs, files, and accounts from an alert — these are your highest-confidence IOCs. 'Victim' entities tell you the blast radius.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertevidence-table",
    crossTables: [
      { table: "AlertEvidence" },
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
      { table: "AADSignInEventsBeta" },
    ],
  },

  "IsManaged": {
    docs: "Indicates whether the device used to sign in is managed by the organization — enrolled in Intune or joined to an Entra ID / hybrid AD domain.",
    plain: "Was the device that completed this sign-in a company-managed machine? If False, the sign-in happened on a personal phone, home PC, or attacker-controlled machine — anything not under corporate control.",
    dfir: "In device code phishing, the victim authenticates via their browser at microsoft.com/devicelogin, which does NOT appear as a managed device sign-in. IsManaged = false combined with successful MFA completion is a key hunting indicator for this attack pattern. Also flags bring-your-own-device (BYOD) abuse.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table",
    crossTables: [
      { table: "AADSignInEventsBeta" },
    ],
  },

  "SessionId": {
    docs: "Unique identifier for the authenticated session created by the sign-in event.",
    plain: "A unique ID that ties this sign-in event to all activity performed during that browser or app session. One sign-in = one SessionId for everything that happens until the session expires or is revoked.",
    dfir: "Links a specific sign-in event to subsequent cloud and API activity from the same session token. In token theft scenarios, activity using the stolen token may share the original SessionId — revealing that actions taken from a different IP belong to the same stolen session.",
    docUrl: "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table",
    crossTables: [
      { table: "AADSignInEventsBeta" },
      { table: "CloudAppEvents" },
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
};

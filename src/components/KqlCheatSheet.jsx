import { useState } from "react";

// ── KQL Quick Reference data ──────────────────────────────────────────────────
const KQL_SECTIONS = [
  {
    id: "filtering",
    label: "Filtering & Selection",
    color: "#00d4ff",
    items: [
      { op: "where",          syntax: "| where Column == 'value'",                    desc: "Filter rows by exact match" },
      { op: "where =~",       syntax: "| where Column =~ 'value'",                    desc: "Case-insensitive equals" },
      { op: "where (time)",   syntax: "| where Timestamp > ago(7d)",                  desc: "Filter to last N days/hours/minutes" },
      { op: "where between",  syntax: "| where Timestamp between(ago(14d)..ago(7d))", desc: "Filter to a specific time window" },
      { op: "project",        syntax: "| project Col1, Col2, Col3",                   desc: "Select only named columns" },
      { op: "project-away",   syntax: "| project-away RawEventData, AdditionalFields",desc: "Drop named columns, keep the rest" },
      { op: "extend",         syntax: "| extend NewCol = expression",                 desc: "Add or overwrite a column" },
      { op: "distinct",       syntax: "| distinct AccountUpn, IPAddress",             desc: "Return unique combinations of columns" },
      { op: "top",            syntax: "| top 10 by Timestamp desc",                   desc: "Return the top N rows by a column" },
      { op: "limit / take",   syntax: "| limit 100",                                  desc: "Return at most N rows (same as take)" },
      { op: "sort / order",   syntax: "| sort by Timestamp desc",                     desc: "Sort rows (sort by and order by are identical)" },
    ],
  },
  {
    id: "strings",
    label: "String Operators",
    color: "#ffb347",
    items: [
      { op: "has",            syntax: "| where Col has 'word'",                        desc: "Whole-word match — fast, index-accelerated" },
      { op: "has_any",        syntax: "| where Col has_any ('a','b','c')",             desc: "Match any word from a list — fast" },
      { op: "contains",       syntax: "| where Col contains 'substr'",                 desc: "Substring match — slower than has" },
      { op: "startswith",     syntax: "| where Col startswith 'prefix'",               desc: "Match from beginning of string" },
      { op: "endswith",       syntax: "| where Col endswith '.exe'",                   desc: "Match end of string" },
      { op: "matches regex",  syntax: "| where Col matches regex @'\\d{3}-\\d{4}'",   desc: "Full regex match — slowest, use sparingly" },
      { op: "in",             syntax: "| where Col in ('a','b','c')",                  desc: "Exact membership — case-sensitive" },
      { op: "in~",            syntax: "| where Col in~ ('A','B','C')",                 desc: "Membership — case-insensitive" },
      { op: "!has / !in",     syntax: "| where Col !has 'word'",                       desc: "Negated versions of has / in" },
      { op: "tolower",        syntax: "| extend low = tolower(Column)",                desc: "Lowercase a string for normalised comparison" },
      { op: "strcat",         syntax: "| extend full = strcat(Col1, '-', Col2)",       desc: "Concatenate strings" },
      { op: "split",          syntax: "| extend parts = split(Path, '\\\\')",          desc: "Split string into an array on a delimiter" },
      { op: "extract",        syntax: "| extend ip = extract(@'(\\d+\\.\\d+\\.\\d+\\.\\d+)', 1, Col)", desc: "Extract substring matching a regex capture group" },
      { op: "strlen",         syntax: "| extend n = strlen(Column)",                   desc: "Length of a string" },
      { op: "trim",           syntax: "| extend t = trim(' ', Column)",                desc: "Remove leading/trailing characters" },
    ],
  },
  {
    id: "time",
    label: "Time & Bucketing",
    color: "#47ff8f",
    items: [
      { op: "ago()",          syntax: "ago(7d) | ago(4h) | ago(30m) | ago(90s)",      desc: "Relative time offset: d=days, h=hours, m=minutes, s=seconds" },
      { op: "now()",          syntax: "now()",                                          desc: "Current UTC datetime" },
      { op: "bin()",          syntax: "| summarize c=count() by bin(Timestamp, 1h)",   desc: "Bucket a datetime into fixed intervals" },
      { op: "startofday()",   syntax: "| where Timestamp >= startofday(now())",        desc: "Start of the current day (midnight UTC)" },
      { op: "startofweek()",  syntax: "startofweek(Timestamp)",                        desc: "Start of the week containing the given datetime" },
      { op: "format_datetime",syntax: "| extend d = format_datetime(Timestamp,'yyyy-MM-dd')", desc: "Format a datetime as a string" },
      { op: "datetime()",     syntax: "| where Timestamp > datetime(2025-01-01)",      desc: "Literal datetime constant" },
    ],
  },
  {
    id: "aggregation",
    label: "Aggregation & Grouping",
    color: "#a78bfa",
    items: [
      { op: "count()",        syntax: "| summarize count() by AccountUpn",             desc: "Count rows per group" },
      { op: "dcount()",       syntax: "| summarize dcount(IPAddress) by AccountUpn",   desc: "Distinct count of values per group" },
      { op: "make_set()",     syntax: "| summarize IPs=make_set(IPAddress) by AccountUpn", desc: "Collect distinct values into an array" },
      { op: "make_list()",    syntax: "| summarize Actions=make_list(ActionType)",     desc: "Collect all values (including duplicates) into an array" },
      { op: "arg_max()",      syntax: "| summarize arg_max(Timestamp, *) by AccountUpn", desc: "Return the row where a column is maximum — great for 'latest event per account'" },
      { op: "arg_min()",      syntax: "| summarize arg_min(Timestamp, *) by AccountUpn", desc: "Return the row where a column is minimum — first event per account" },
      { op: "sum()",          syntax: "| summarize TotalBytes=sum(SentBytes)",         desc: "Sum numeric column" },
      { op: "avg()",          syntax: "| summarize AvgSize=avg(FileSize)",             desc: "Average of numeric column" },
      { op: "min() / max()",  syntax: "| summarize min(Timestamp), max(Timestamp)",   desc: "Min and max values" },
      { op: "countif()",      syntax: "| summarize Fails=countif(ErrorCode != 0)",    desc: "Count only rows matching a condition" },
    ],
  },
  {
    id: "joins",
    label: "Joins & Unions",
    color: "#ff4757",
    items: [
      { op: "join inner",     syntax: "T1 | join kind=inner T2 on $left.Col == $right.Col", desc: "Only rows with matching keys in both tables" },
      { op: "join leftouter", syntax: "T1 | join kind=leftouter T2 on Col",            desc: "All left rows; null-fill right side where no match" },
      { op: "join leftanti",  syntax: "T1 | join kind=leftanti T2 on Col",             desc: "Rows in T1 with NO match in T2 — find events NOT in another table" },
      { op: "join rightsemi", syntax: "T1 | join kind=rightsemi T2 on Col",            desc: "Rows in T2 that DO have a match in T1" },
      { op: "union",          syntax: "union Table1, Table2 | where ...",              desc: "Stack multiple tables into one result set" },
      { op: "union withsource",syntax:"union withsource=TableName Table1, Table2",    desc: "Add a column identifying which table each row came from" },
      { op: "lookup",         syntax: "T1 | lookup T2 on Col",                         desc: "Enrichment join — like leftouter but T2 is treated as a lookup table (no duplicates)" },
    ],
  },
  {
    id: "multiquery",
    label: "Variables, Pipes & Multi-query",
    color: "#fb923c",
    items: [
      { op: "let (scalar)",   syntax: "let upn = 'user@corp.com';",                    desc: "Define a scalar variable — reuse it anywhere below" },
      { op: "let (tabular)",  syntax: "let suspects = EmailEvents | where ...;",       desc: "Define a tabular variable — pipe it into later queries" },
      { op: "let (function)", syntax: "let GetAlerts = (account:string) { AlertInfo | where ... };", desc: "Parameterised function — call with GetAlerts('upn')" },
      { op: "---",            syntax: "// query 1\n---\n// query 2",                   desc: "Separate multiple independent queries in the same editor pane" },
      { op: "// comment",     syntax: "// this is a comment",                          desc: "Single-line comment" },
      { op: "render",         syntax: "| render timechart",                            desc: "Visualise results: timechart, barchart, piechart, table" },
      { op: "print",          syntax: "print parse_json('{\"a\":1}').a",               desc: "Evaluate an expression inline — great for testing parse_json logic" },
    ],
  },
  {
    id: "types",
    label: "Type Casting",
    color: "#ffd700",
    items: [
      { op: "tostring()",     syntax: "| extend s = tostring(Column)",                 desc: "Cast any value to string" },
      { op: "toint()",        syntax: "| extend n = toint(Column)",                   desc: "Cast to 32-bit integer" },
      { op: "tolong()",       syntax: "| extend n = tolong(Column)",                  desc: "Cast to 64-bit integer" },
      { op: "tobool()",       syntax: "| extend b = tobool(Column)",                  desc: "Cast to boolean (true/false)" },
      { op: "todouble()",     syntax: "| extend d = todouble(Column)",                desc: "Cast to floating point" },
      { op: "todatetime()",   syntax: "| extend dt = todatetime(Column)",             desc: "Cast string to datetime" },
      { op: "isnull()",       syntax: "| where isnull(Column)",                       desc: "True if column is null — use after parse_json when field is absent" },
      { op: "isnotempty()",   syntax: "| where isnotempty(Column)",                   desc: "True if column is non-null and non-empty string" },
      { op: "iff()",          syntax: "| extend x = iff(Col > 0, 'positive','zero')", desc: "Inline conditional (ternary): iff(condition, true_val, false_val)" },
      { op: "case()",         syntax: "| extend level = case(Score > 90,'High', Score > 50,'Med','Low')", desc: "Multi-branch conditional — like a switch statement" },
    ],
  },
  {
    id: "mvexpand",
    label: "Arrays & mv-expand",
    color: "#38bdf8",
    items: [
      { op: "mv-expand",      syntax: "| mv-expand Item = ArrayColumn",               desc: "Explode an array column — each element becomes its own row. Essential for nested JSON arrays." },
      { op: "mv-apply",       syntax: "| mv-apply Item = ArrayColumn to typeof(string) on (...)", desc: "Apply a subquery to each array element without changing row count" },
      { op: "array_length()", syntax: "| extend n = array_length(ArrayColumn)",       desc: "Count elements in an array" },
      { op: "array_index_of",syntax: "| extend pos = array_index_of(arr, 'x')",      desc: "Find index of a value in an array (-1 if not found)" },
      { op: "pack_array()",   syntax: "| extend arr = pack_array(Col1, Col2)",        desc: "Create an array from scalar values" },
      { op: "set_union()",    syntax: "| extend combined = set_union(arr1, arr2)",    desc: "Merge two arrays, removing duplicates" },
    ],
  },
];

// ── JSON Parsing Patterns data ─────────────────────────────────────────────────
const JSON_PATTERNS = [
  {
    id: "app-access-context",
    title: "AppAccessContext — Session & Client",
    table: "CloudAppEvents",
    tableColor: "#fb923c",
    tags: ["AiTM", "session token", "AADSessionId"],
    desc: "Extract the stolen session token ID (AADSessionId) and client app details from every CloudAppEvents row. AADSessionId matches the SessionId on the Login:Reprocess event in EntraIdSignInEvents — use it to track attacker activity across all SaaS tables after token theft.",
    kql:
`CloudAppEvents
| where Timestamp > ago(14d)
| extend ctx           = parse_json(AppAccessContext)
| extend AADSessionId  = tostring(ctx.AADSessionId)
| extend ClientApp     = tostring(ctx.ClientAppName)
| extend IsInteractive = tobool(ctx.IsInteractive)
| extend AADTenantId   = tostring(ctx.AADTenantId)
// Filter by the stolen session token — not by IP (SaaS sessions route through Microsoft infra)
| where AADSessionId == "<SessionId from EntraIdSignInEvents Login:Reprocess>"
| project Timestamp, AccountUpn, ActionType, Application,
          IPAddress, AADSessionId, ClientApp, IsInteractive`,
  },
  {
    id: "mailitemsaccessed",
    title: "MailItemsAccessed — Separate Columns: AADSessionId, Folder, Item, Subject, MessageId",
    table: "CloudAppEvents",
    tableColor: "#fb923c",
    tags: ["BEC", "email recon", "inbox", "message id", "subject", "mv-expand"],
    desc: "MailItemsAccessed buries folder paths and message IDs inside nested JSON arrays in RawEventData. Two mv-expand calls flatten Folders[] → FolderItems[] so each accessed email becomes its own row with its own columns. MailItemsAccessed does NOT log Subject directly — join the InternetMessageId to EmailEvents to recover Subject, sender, and delivery details.",
    kql:
`CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType == "MailItemsAccessed"
// Step 1: extract AADSessionId — the stolen session token identifier
| extend ctx          = parse_json(AppAccessContext)
| extend AADSessionId = tostring(ctx.AADSessionId)
| where AADSessionId == "<SessionId from Login:Reprocess in EntraIdSignInEvents>"
// Step 2: first mv-expand — one row per folder the attacker accessed
| extend raw = parse_json(RawEventData)
| mv-expand Folder = raw.Folders
| extend FolderPath = tostring(Folder.Path)           // e.g. \\Inbox, \\Sent Items
// Step 3: second mv-expand — one row per individual email item inside each folder
| mv-expand Item = Folder.FolderItems
| extend InternetMessageId = tostring(Item.InternetMessageId)
| extend SizeInBytes       = toint(Item.SizeInBytes)
// Step 4: join EmailEvents on InternetMessageId to recover Subject + sender
// MailItemsAccessed does not log Subject — EmailEvents is the only source for it
| join kind=leftouter (
    EmailEvents
    | where Timestamp > ago(14d)
    | project InternetMessageId, Subject, SenderFromAddress,
              SenderDisplayName, RecipientEmailAddress, DeliveryAction
) on InternetMessageId
// Result: one row per email the attacker touched, with all context as separate columns
| project
    Timestamp,
    AccountUpn,
    AADSessionId,             // stolen session token — same across all attacker actions
    IPAddress,                // will be Microsoft datacenter IP, not attacker proxy IP
    FolderPath,               // which mailbox folder was accessed
    InternetMessageId,        // RFC message ID — joins to EmailEvents
    Subject,                  // recovered from EmailEvents join
    SenderFromAddress,        // who sent the email the attacker read
    SizeInBytes               // size of the accessed message
| sort by Timestamp asc`,
  },
  {
    id: "search-query",
    title: "SearchQueryInitiatedExchange — What the Attacker Searched",
    table: "CloudAppEvents",
    tableColor: "#fb923c",
    tags: ["BEC", "email recon", "search"],
    desc: "When an attacker uses Outlook search (or Graph API search), Defender logs SearchQueryInitiatedExchange. The search terms, folder path, and result count are in RawEventData. High result counts on queries for 'invoice', 'wire', 'payment' are a BEC recon signal.",
    kql:
`CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType == "SearchQueryInitiatedExchange"
| extend ctx          = parse_json(AppAccessContext)
| extend AADSessionId = tostring(ctx.AADSessionId)
| where AADSessionId == "<SessionId from Login:Reprocess>"
| extend raw = parse_json(RawEventData)
| extend
    SearchQuery   = tostring(raw.SearchQuery),
    ResultCount   = toint(raw.ItemCount),
    FolderPath    = tostring(raw.FolderPath),
    QuerySource   = tostring(raw.QuerySource)
| project Timestamp, AccountUpn, IPAddress, AADSessionId,
          SearchQuery, ResultCount, FolderPath
| sort by Timestamp asc`,
  },
  {
    id: "inbox-rules",
    title: "New-InboxRule / Set-Mailbox — Forwarding Rule Details",
    table: "CloudAppEvents",
    tableColor: "#fb923c",
    tags: ["BEC", "persistence", "forwarding", "inbox rule"],
    desc: "Inbox rule creation is the primary persistence mechanism in BEC attacks. The rule name, forwarding address, conditions, and flags are packed into RawEventData. Filter by the stolen AADSessionId — the IP will be Microsoft infrastructure, not the attacker.",
    kql:
`CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType has_any (
    "New-InboxRule","Set-InboxRule",
    "Set-Mailbox","UpdateInboxRules")
| extend ctx          = parse_json(AppAccessContext)
| extend AADSessionId = tostring(ctx.AADSessionId)
| where AADSessionId == "<SessionId from Login:Reprocess>"
| extend raw = parse_json(RawEventData)
| extend
    RuleName      = tostring(raw.Name),
    ForwardTo     = tostring(raw.ForwardTo),
    ForwardAsAtt  = tostring(raw.ForwardAsAttachmentTo),
    RedirectTo    = tostring(raw.RedirectTo),
    DeleteMsg     = tobool(raw.DeleteMessage),
    MarkAsRead    = tobool(raw.MarkAsRead),
    BodyContains  = tostring(raw.BodyContains),
    SubjectContains = tostring(raw.SubjectContains)
| project Timestamp, AccountUpn, IPAddress, AADSessionId,
          ActionType, RuleName, ForwardTo, RedirectTo,
          DeleteMsg, MarkAsRead, BodyContains, SubjectContains
| sort by Timestamp asc`,
  },
  {
    id: "mail-send",
    title: "Send / MailSend — Subject, Recipients & Message ID",
    table: "CloudAppEvents",
    tableColor: "#fb923c",
    tags: ["BEC", "fraud email", "outbound", "subject"],
    desc: "Outbound email sends from the compromised account appear in CloudAppEvents. Subject, recipients, InternetMessageId, and importance are inside RawEventData. Cross-reference InternetMessageId with EmailEvents to see delivery status and MDO verdicts.",
    kql:
`CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType in ("Send","MailSend","New-Message","SubmitMessage")
| extend ctx          = parse_json(AppAccessContext)
| extend AADSessionId = tostring(ctx.AADSessionId)
| where AADSessionId == "<SessionId from Login:Reprocess>"
| extend raw = parse_json(RawEventData)
| extend
    Subject             = tostring(raw.Subject),
    ToRecipients        = tostring(raw.ToRecipients),
    CcRecipients        = tostring(raw.CcRecipients),
    InternetMessageId   = tostring(raw.InternetMessageId),
    Importance          = tostring(raw.Importance),
    HasAttachments      = tobool(raw.HasAttachments),
    ConversationId      = tostring(raw.ConversationId)
| project Timestamp, AccountUpn, IPAddress, AADSessionId,
          Subject, ToRecipients, CcRecipients,
          InternetMessageId, HasAttachments
| sort by Timestamp asc`,
  },
  {
    id: "session-activity-map",
    title: "Full Session Activity Map — Everything the Attacker Did Under One SessionId",
    table: "CloudAppEvents",
    tableColor: "#fb923c",
    tags: ["AiTM", "BEC", "session token", "AADSessionId", "mv-expand", "full picture"],
    desc: "One query to surface everything the attacker did under a stolen session token. Handles MailItemsAccessed (double mv-expand for folder + message columns), SearchQueryInitiatedExchange (search terms), inbox rule creation (forwarding address), and Send (subject + recipients) — all with AADSessionId as the common thread. Subject for accessed emails is recovered via an EmailEvents join.",
    kql:
`// ── FULL SESSION ACTIVITY MAP ─────────────────────────────────────────────────
// Surfaces every meaningful action under a stolen session token in one pass.
// Replace <SessionId> with the value from the Login:Reprocess event.
// ─────────────────────────────────────────────────────────────────────────────

// Base: all CloudAppEvents under the stolen session
let StealSession = "<SessionId from Login:Reprocess in EntraIdSignInEvents>";
let SessionEvents = CloudAppEvents
| where Timestamp > ago(14d)
| extend ctx          = parse_json(AppAccessContext)
| extend AADSessionId = tostring(ctx.AADSessionId)
| where AADSessionId == StealSession;

// ── 1. Inbox rules created (persistence) ─────────────────────────────────────
SessionEvents
| where ActionType in ("New-InboxRule","Set-InboxRule","Set-Mailbox","UpdateInboxRules")
| extend raw = parse_json(RawEventData)
| extend
    RuleName   = tostring(raw.Name),
    ForwardTo  = tostring(raw.ForwardTo),
    DeleteMsg  = tobool(raw.DeleteMessage),
    BodyFilter = tostring(raw.BodyContains)
| project Timestamp, AccountUpn, AADSessionId, IPAddress,
          ActionType, RuleName, ForwardTo, DeleteMsg, BodyFilter
| sort by Timestamp asc
---
// ── 2. Emails accessed — one row per message with Subject via EmailEvents join ─
SessionEvents
| where ActionType == "MailItemsAccessed"
| extend raw = parse_json(RawEventData)
| mv-expand Folder = raw.Folders
| extend FolderPath = tostring(Folder.Path)
| mv-expand Item = Folder.FolderItems
| extend InternetMessageId = tostring(Item.InternetMessageId)
| extend SizeInBytes       = toint(Item.SizeInBytes)
| join kind=leftouter (
    EmailEvents
    | where Timestamp > ago(14d)
    | project InternetMessageId, Subject,
              SenderFromAddress, RecipientEmailAddress
) on InternetMessageId
| project Timestamp, AccountUpn, AADSessionId, IPAddress,
          FolderPath, InternetMessageId,
          Subject,           // from EmailEvents join — not in MailItemsAccessed itself
          SenderFromAddress, SizeInBytes
| sort by Timestamp asc
---
// ── 3. Search queries run by the attacker ─────────────────────────────────────
SessionEvents
| where ActionType == "SearchQueryInitiatedExchange"
| extend raw = parse_json(RawEventData)
| extend
    SearchQuery = tostring(raw.SearchQuery),
    ResultCount = toint(raw.ItemCount),
    FolderPath  = tostring(raw.FolderPath)
| project Timestamp, AccountUpn, AADSessionId, IPAddress,
          SearchQuery, ResultCount, FolderPath
| sort by Timestamp asc
---
// ── 4. Emails sent from the compromised account (BEC fraud email) ─────────────
SessionEvents
| where ActionType in ("Send","MailSend","New-Message","SubmitMessage")
| extend raw = parse_json(RawEventData)
| extend
    Subject           = tostring(raw.Subject),
    ToRecipients      = tostring(raw.ToRecipients),
    InternetMessageId = tostring(raw.InternetMessageId),
    HasAttachments    = tobool(raw.HasAttachments)
| project Timestamp, AccountUpn, AADSessionId, IPAddress,
          ActionType, Subject, ToRecipients,
          InternetMessageId, HasAttachments
| sort by Timestamp asc`,
  },
  {
    id: "sharepoint-file",
    title: "FileDownloaded / AnonymousLinkCreated — File Path & Site",
    table: "CloudAppEvents",
    tableColor: "#fb923c",
    tags: ["exfiltration", "SharePoint", "OneDrive", "file"],
    desc: "SharePoint and OneDrive file access events carry the file name, relative path, and site URL inside RawEventData. AnonymousLinkCreated means the attacker created a shareable link — a strong exfiltration signal.",
    kql:
`CloudAppEvents
| where Timestamp > ago(14d)
| where Application in ("Microsoft SharePoint Online","Microsoft OneDrive for Business")
| where ActionType has_any (
    "FileDownloaded","AnonymousLinkCreated",
    "SharingSet","FileSyncDownloadedFull","FileAccessed")
| extend ctx          = parse_json(AppAccessContext)
| extend AADSessionId = tostring(ctx.AADSessionId)
| where AADSessionId == "<SessionId from Login:Reprocess>"  // or remove to hunt broadly
| extend raw = parse_json(RawEventData)
| extend
    FileName          = tostring(raw.SourceFileName),
    FilePath          = tostring(raw.SourceRelativeUrl),
    SiteUrl           = tostring(raw.SiteUrl),
    SharingType       = tostring(raw.SharingType),
    ExpirationDate    = tostring(raw.ExpirationDate)
| project Timestamp, AccountUpn, IPAddress, AADSessionId,
          ActionType, FileName, FilePath, SiteUrl, SharingType
| sort by Timestamp asc`,
  },
  {
    id: "cloud-audit-caller",
    title: "CloudAuditEvents — Caller Identity & ARM Operation Details",
    table: "CloudAuditEvents",
    tableColor: "#00d4ff",
    tags: ["Azure", "ARM", "Run Command", "caller"],
    desc: "CloudAuditEvents has no top-level AccountUpn column — the caller identity is buried in RawEventData as the 'caller' field. The caller is a UPN or service principal objectId. Also extract HTTP method, operation status, and client IP from the nested structure.",
    kql:
`CloudAuditEvents
| where Timestamp > ago(14d)
| extend raw = parse_json(RawEventData)
| extend
    Caller        = tostring(raw["caller"]),
    StatusCode    = tostring(raw.status.value),
    HttpMethod    = tostring(raw.httpRequest.method),
    ClientIP      = tostring(raw.httpRequest.clientIpAddress),
    CorrelationId = tostring(raw.correlationId)
// AccountUpn confirmed via AADSessionId tracking in CloudAppEvents (previous step)
| where Caller =~ "<AccountUpn confirmed via AADSessionId>"
// Use OperationName for specific Azure ops — ActionType is only generic Create/Read/Update/Delete
| where OperationName has_any (
    "runCommand",
    "virtualMachines/runCommand",
    "virtualMachines/extensions/write",
    "roleAssignments/write",
    "secrets/read")
| project Timestamp, OperationName, ResourceId,
          Caller, ClientIP, StatusCode, HttpMethod, RawEventData
| sort by Timestamp asc`,
  },
  {
    id: "alert-evidence-fields",
    title: "AlertEvidence — AdditionalFields by EntityType",
    table: "AlertEvidence",
    tableColor: "#ff4757",
    tags: ["triage", "IOC", "evidence"],
    desc: "AdditionalFields in AlertEvidence is a JSON bag whose contents vary by EntityType. Parse it once and extract the fields relevant to each type. Url entities carry the phishing URL; File entities carry SHA256 and path; CloudLogonRequest carries the sign-in IP and app.",
    kql:
`AlertEvidence
| where AlertId in ("<AlertId1>","<AlertId2>")
| extend fields = parse_json(AdditionalFields)
// Entity-type-specific extractions — all from the same AdditionalFields column
| extend
    // Url entity
    UrlValue          = tostring(fields.Url),
    // File entity
    FileSHA256        = tostring(fields.Sha256),
    FilePath          = tostring(fields.FilePath),
    ProcessCmdLine    = tostring(fields.ProcessCommandLine),
    // CloudLogonRequest entity
    SignInIP          = tostring(fields.IpAddress),
    SignInApp         = tostring(fields.ApplicationId),
    // ThreatIntelligence entity
    ThreatName        = tostring(fields.ThreatName),
    ThreatFamily      = tostring(fields.ThreatFamily)
| project Timestamp, EntityType, EvidenceRole,
          AccountUpn, AccountObjectId, RemoteIP,
          UrlValue, FileSHA256, FilePath, ProcessCmdLine,
          SignInIP, ThreatName
| sort by EntityType asc`,
  },
  {
    id: "identity-logon-fields",
    title: "IdentityLogonEvents — AdditionalFields (Auth Protocol, NTLM)",
    table: "IdentityLogonEvents",
    tableColor: "#ffb347",
    tags: ["lateral movement", "NTLM", "Kerberos", "credential abuse"],
    desc: "IdentityLogonEvents AdditionalFields carries the granular auth protocol (NTLM vs Kerberos vs LDAP), target account, sub-status codes for failed logons, and MDI detection context. Essential for differentiating pass-the-hash (NTLM) from Kerberoast (Kerberos service tickets).",
    kql:
`IdentityLogonEvents
| where Timestamp > ago(14d)
| where AccountUpn =~ "<compromised_upn>" or IPAddress == "<attacker_ip>"
| extend fields = parse_json(AdditionalFields)
| extend
    AuthProtocol     = tostring(fields.AuthenticationProtocol),
    TargetAccount    = tostring(fields.TargetAccount),
    SubStatus        = tostring(fields.SubStatus),
    ServiceName      = tostring(fields.ServiceName),
    TicketEncType    = tostring(fields.TicketEncryptionType),
    MappedAccount    = tostring(fields.MappedAccount)
// Pass-the-hash signal: NTLM network logon with no interactive session
| where AuthProtocol == "NTLM" and LogonType == "Network"
| project Timestamp, AccountUpn, IPAddress, DeviceName,
          LogonType, AuthProtocol, SubStatus, ServiceName
| sort by Timestamp asc`,
  },
  {
    id: "device-network-fields",
    title: "DeviceNetworkEvents — AdditionalFields (DNS, Tunnel, Direction)",
    table: "DeviceNetworkEvents",
    tableColor: "#00d4ff",
    tags: ["C2", "exfiltration", "DNS", "beaconing"],
    desc: "DeviceNetworkEvents AdditionalFields carries connection direction, DNS queries resolved during the connection, tunnel type (common for C2 over DNS or HTTPS), and byte counts on some versions.",
    kql:
`DeviceNetworkEvents
| where Timestamp > ago(14d)
| where DeviceName == "<vm_or_device_name>"
| extend fields = parse_json(AdditionalFields)
| extend
    Direction     = tostring(fields.Direction),
    TunnelType    = tostring(fields.TunnelType),
    DnsQueries    = tostring(fields.DnsQueries),
    BytesSent     = tolong(fields.BytesSent),
    BytesReceived = tolong(fields.BytesReceived)
// Suspicious: outbound connections from Azure Guest Agent child processes
| where InitiatingProcessFileName has_any (
    "WindowsAzureGuestAgent","WaAppAgent",
    "powershell","cmd","wscript","cscript")
// Known attacker C2 IP — valid pivot here (DeviceNetworkEvents shows real endpoint IPs)
| where RemoteIP == "<attacker_c2_ip>" or RemoteUrl contains "<attacker_domain>"
| project Timestamp, DeviceName, InitiatingProcessFileName,
          RemoteIP, RemoteUrl, RemotePort,
          Direction, TunnelType, DnsQueries, BytesSent
| sort by Timestamp asc`,
  },
  {
    id: "office-activity-context",
    title: "OfficeActivity — AADSessionId from AppAccessContext (Sentinel)",
    table: "OfficeActivity",
    tableColor: "#fb923c",
    tags: ["AiTM", "BEC", "Sentinel", "session token"],
    desc: "OfficeActivity in Log Analytics / Sentinel covers the same Exchange, SharePoint, and OneDrive events as CloudAppEvents in XDR, but from the Log Analytics pipeline. The AADSessionId is extracted from AppAccessContext identically. Cross-referencing both tables against the same stolen SessionId gives a complete picture across both pipelines.",
    kql:
`// Run in Log Analytics workspace or Microsoft Sentinel
OfficeActivity
| where TimeGenerated > ago(14d)
| extend ctx          = parse_json(AppAccessContext)
| extend AADSessionId = tostring(ctx.AADSessionId)
// AADSessionId matches SessionId from Login:Reprocess in EntraIdSignInEvents
| where AADSessionId == "<SessionId from Login:Reprocess>"
| project TimeGenerated, UserId, Operation, Workload,
          ClientIP, ObjectId, SiteUrl, AADSessionId
| sort by TimeGenerated asc
---
// Inbox rule creation specifically
OfficeActivity
| where TimeGenerated > ago(14d)
| extend ctx          = parse_json(AppAccessContext)
| extend AADSessionId = tostring(ctx.AADSessionId)
| where AADSessionId == "<SessionId>"
| where Operation in ("New-InboxRule","Set-InboxRule","Set-MailboxAutoReplyConfiguration")
| extend raw = parse_json(Parameters)
| mv-expand Param = raw
| extend ParamName  = tostring(Param.Name)
| extend ParamValue = tostring(Param.Value)
| project TimeGenerated, UserId, Operation, ClientIP,
          AADSessionId, ParamName, ParamValue`,
  },
  {
    id: "graph-api-uri",
    title: "GraphApiAuditEvents — RequestUri Parsing",
    table: "GraphApiAuditEvents",
    tableColor: "#fb923c",
    tags: ["Graph API", "enumeration", "token abuse"],
    desc: "GraphApiAuditEvents has no AccountUpn or ActionType column — filter by AccountObjectId (from AlertEvidence) and parse RequestUri to determine what data was accessed. High call volume in a short window against /me/messages, /users, or /groups indicates automated enumeration.",
    kql:
`GraphApiAuditEvents
| where Timestamp > ago(14d)
| where AccountObjectId == "<ObjectId from AlertEvidence>"
// Parse the Graph endpoint being hit from RequestUri
| extend UriParts    = split(RequestUri, '/')
| extend ApiEndpoint = strcat(tostring(UriParts[3]), '/', tostring(UriParts[4]))
// Classify intent by endpoint
| extend Intent = case(
    RequestUri has "/me/messages",          "Mail read",
    RequestUri has "/messages",             "Mail read",
    RequestUri has "/me/drive",             "OneDrive",
    RequestUri has "/groups",               "Group enumeration",
    RequestUri has "/users",                "User enumeration",
    RequestUri has "/servicePrincipals",    "App/SP enumeration",
    RequestUri has "/directoryRoles",       "Role enumeration",
    RequestUri has "/subscriptions",        "Azure subscription enum",
    "Other")
| summarize
    CallCount   = count(),
    Methods     = make_set(RequestMethod),
    Endpoints   = make_set(ApiEndpoint)
  by bin(Timestamp, 5m), AccountObjectId, IPAddress, Intent
| sort by Timestamp asc`,
  },
];

// ── Helpers ────────────────────────────────────────────────────────────────────
function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1800);
        });
      }}
      style={{
        background: "transparent",
        border: "1px solid var(--bd-2)",
        color: copied ? "#47ff8f" : "var(--tx-5)",
        fontSize: 10,
        fontFamily: "inherit",
        letterSpacing: "0.08em",
        padding: "3px 8px",
        borderRadius: 3,
        cursor: "pointer",
        flexShrink: 0,
        transition: "color 0.15s, border-color 0.15s",
      }}
    >
      {copied ? "COPIED" : "COPY"}
    </button>
  );
}

function KqlBlock({ code }) {
  return (
    <div style={{ position: "relative", marginTop: 10 }}>
      <div style={{
        position: "absolute", top: 8, right: 8, zIndex: 1,
      }}>
        <CopyButton text={code} />
      </div>
      <pre style={{
        background: "var(--bg-1)",
        border: "1px solid var(--bd-3)",
        borderRadius: 4,
        padding: "12px 14px",
        paddingRight: 60,
        fontSize: 11,
        lineHeight: 1.65,
        color: "var(--tx-3)",
        overflowX: "auto",
        margin: 0,
        whiteSpace: "pre",
        fontFamily: "inherit",
      }}>
        <code>{code}</code>
      </pre>
    </div>
  );
}

// ── Quick Reference tab ────────────────────────────────────────────────────────
function QuickRefTab({ search }) {
  const q = search.toLowerCase();
  const filtered = KQL_SECTIONS.map(s => ({
    ...s,
    items: s.items.filter(i =>
      !q || i.op.toLowerCase().includes(q) ||
      i.syntax.toLowerCase().includes(q) ||
      i.desc.toLowerCase().includes(q)
    ),
  })).filter(s => s.items.length > 0);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 28 }}>
      {filtered.map(section => (
        <div key={section.id}>
          <div style={{
            fontSize: 10, letterSpacing: "0.18em", textTransform: "uppercase",
            color: section.color, marginBottom: 10, fontWeight: 700,
          }}>
            {section.label}
          </div>
          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(340px, 1fr))",
            gap: 6,
          }}>
            {section.items.map(item => (
              <div key={item.op} style={{
                background: "var(--bg-card)",
                border: "1px solid var(--bd-3)",
                borderLeft: `3px solid ${section.color}`,
                borderRadius: 4,
                padding: "10px 12px",
                display: "flex",
                flexDirection: "column",
                gap: 4,
              }}>
                <div style={{ display: "flex", alignItems: "baseline", gap: 10, justifyContent: "space-between" }}>
                  <span style={{
                    fontSize: 11, fontWeight: 700, color: section.color,
                    flexShrink: 0, minWidth: 90,
                  }}>{item.op}</span>
                  <CopyButton text={item.syntax} />
                </div>
                <code style={{
                  fontSize: 10.5, color: "var(--tx-2)",
                  background: "var(--bg-1)", borderRadius: 3,
                  padding: "3px 6px", display: "block",
                  whiteSpace: "pre-wrap", wordBreak: "break-all",
                  lineHeight: 1.5,
                }}>{item.syntax}</code>
                <span style={{ fontSize: 10.5, color: "var(--tx-4)", lineHeight: 1.5 }}>{item.desc}</span>
              </div>
            ))}
          </div>
        </div>
      ))}
      {filtered.length === 0 && (
        <div style={{ color: "var(--tx-5)", fontSize: 12, paddingTop: 24, textAlign: "center" }}>
          No matches for "{search}"
        </div>
      )}
    </div>
  );
}

// ── JSON Patterns tab ──────────────────────────────────────────────────────────
function JsonPatternsTab({ search }) {
  const [expanded, setExpanded] = useState({});
  const q = search.toLowerCase();

  const filtered = JSON_PATTERNS.filter(p =>
    !q ||
    p.title.toLowerCase().includes(q) ||
    p.table.toLowerCase().includes(q) ||
    p.desc.toLowerCase().includes(q) ||
    p.tags.some(t => t.toLowerCase().includes(q)) ||
    p.kql.toLowerCase().includes(q)
  );

  const toggle = id => setExpanded(e => ({ ...e, [id]: !e[id] }));

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      <div style={{ fontSize: 11, color: "var(--tx-5)", marginBottom: 8, lineHeight: 1.7 }}>
        These patterns extract fields from JSON columns (RawEventData, AppAccessContext, AdditionalFields) that contain nested data not exposed as top-level columns. Click any card to expand the full KQL.
      </div>
      {filtered.map(p => {
        const open = expanded[p.id];
        return (
          <div key={p.id} style={{
            background: "var(--bg-card)",
            border: "1px solid var(--bd-2)",
            borderLeft: `3px solid ${p.tableColor}`,
            borderRadius: 4,
            overflow: "hidden",
          }}>
            <button
              onClick={() => toggle(p.id)}
              style={{
                width: "100%", background: "transparent", border: "none",
                padding: "12px 14px", cursor: "pointer", textAlign: "left",
                display: "flex", alignItems: "center", gap: 12,
              }}
            >
              <span style={{
                fontSize: 11, color: open ? "#00d4ff" : "var(--tx-5)",
                flexShrink: 0, transition: "color 0.15s",
                transform: open ? "rotate(90deg)" : "none",
                display: "inline-block", transition: "transform 0.15s, color 0.15s",
              }}>▶</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                  <span style={{ fontSize: 12, fontWeight: 700, color: "var(--tx-1)" }}>{p.title}</span>
                  <span style={{
                    fontSize: 9.5, letterSpacing: "0.1em", textTransform: "uppercase",
                    color: p.tableColor,
                    border: `1px solid ${p.tableColor}`,
                    borderRadius: 3, padding: "1px 5px",
                    flexShrink: 0,
                  }}>{p.table}</span>
                  {p.tags.map(t => (
                    <span key={t} style={{
                      fontSize: 9, letterSpacing: "0.08em", textTransform: "uppercase",
                      color: "var(--tx-6)", border: "1px solid var(--bd-3)",
                      borderRadius: 3, padding: "1px 4px",
                    }}>{t}</span>
                  ))}
                </div>
                <div style={{ fontSize: 11, color: "var(--tx-4)", marginTop: 3, lineHeight: 1.5 }}>
                  {p.desc}
                </div>
              </div>
            </button>
            {open && (
              <div style={{ padding: "0 14px 14px" }}>
                <KqlBlock code={p.kql} />
              </div>
            )}
          </div>
        );
      })}
      {filtered.length === 0 && (
        <div style={{ color: "var(--tx-5)", fontSize: 12, paddingTop: 24, textAlign: "center" }}>
          No matches for "{search}"
        </div>
      )}
    </div>
  );
}

// ── Root component ─────────────────────────────────────────────────────────────
export default function KqlCheatSheet() {
  const [tab, setTab]       = useState("quickref");
  const [search, setSearch] = useState("");

  const tabs = [
    { id: "quickref",  label: "KQL Quick Reference" },
    { id: "jsonparse", label: "JSON Parsing Patterns" },
  ];

  return (
    <div style={{
      minHeight: "100vh",
      background: "var(--bg-0)",
      display: "flex",
      flexDirection: "column",
    }}>
      {/* Header */}
      <div style={{
        borderBottom: "1px solid var(--bd-1)",
        padding: "20px 28px 0",
        background: "var(--bg-1)",
      }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 14, marginBottom: 14, flexWrap: "wrap" }}>
          <a href="/xdr-pivot-map/" style={{
            fontSize: 10, letterSpacing: "0.18em", textTransform: "uppercase",
            color: "var(--tx-5)", textDecoration: "none",
          }}>← Home</a>
          <span style={{ color: "var(--bd-1)" }}>|</span>
          <span style={{ fontSize: 10, letterSpacing: "0.18em", textTransform: "uppercase", color: "var(--tx-5)" }}>
            KQL Cheat Sheet
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 14, flexWrap: "wrap" }}>
          <h1 style={{ fontSize: "1.1rem", fontWeight: 700, color: "var(--tx-1)", letterSpacing: "0.04em" }}>
            KQL Cheat Sheet
          </h1>
          <span style={{ fontSize: 10, color: "var(--tx-5)", letterSpacing: "0.1em" }}>
            Kusto Query Language · Defender XDR Advanced Hunting
          </span>
        </div>

        {/* Search bar */}
        <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 0, flexWrap: "wrap" }}>
          <input
            type="text"
            placeholder="Search operators, patterns, tables..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{
              background: "var(--bg-2)", border: "1px solid var(--bd-2)",
              borderRadius: 4, padding: "6px 12px",
              fontSize: 11, color: "var(--tx-2)", fontFamily: "inherit",
              width: 280, outline: "none",
            }}
          />
          {search && (
            <button
              onClick={() => setSearch("")}
              style={{
                background: "transparent", border: "none",
                color: "var(--tx-5)", fontSize: 11, cursor: "pointer",
                fontFamily: "inherit", padding: "4px 6px",
              }}
            >✕ Clear</button>
          )}
        </div>

        {/* Tabs */}
        <div style={{ display: "flex", gap: 0, marginTop: 14 }}>
          {tabs.map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              style={{
                background: "transparent",
                border: "none",
                borderBottom: tab === t.id ? "2px solid #00d4ff" : "2px solid transparent",
                color: tab === t.id ? "#00d4ff" : "var(--tx-5)",
                fontSize: 11, fontFamily: "inherit", letterSpacing: "0.06em",
                padding: "8px 16px 10px",
                cursor: "pointer",
                transition: "color 0.15s, border-color 0.15s",
              }}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div style={{ flex: 1, padding: "24px 28px", maxWidth: 1200, width: "100%" }}>
        {tab === "quickref"  && <QuickRefTab  search={search} />}
        {tab === "jsonparse" && <JsonPatternsTab search={search} />}
      </div>
    </div>
  );
}

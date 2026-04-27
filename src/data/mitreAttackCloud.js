// MITRE ATT&CK Cloud Matrix — Defender XDR crosswalk
// Aligned with ATT&CK v15 — IaaS, SaaS, Identity Provider, and Office Suite platforms
// Covers all cloud-applicable techniques from the Enterprise matrix (cloud platform filter).
// Each technique carries matrix: "cloud" so the component can distinguish
// it from Enterprise techniques when rendering the blended view.

export const CLOUD_TECHNIQUES = [

  // ─── INITIAL ACCESS ────────────────────────────────────────────────────────
  {
    id: "T1190",
    name: "Exploit Public-Facing Application",
    tacticIds: ["TA0001"],
    matrix: "cloud",
    description: "Adversaries exploit weaknesses in Internet-facing cloud applications — web apps hosted on Azure App Service, API Management, AKS ingress, or VMs with public IPs — to gain an initial foothold. Common vectors include SQL injection, SSRF, deserialization, and unpatched CVEs on exposed services.",
    xdrMappings: [
      {
        table: "DeviceEvents",
        columns: ["DeviceName", "ActionType", "RemoteIP", "LocalPort", "InitiatingProcessFileName"],
        kql: `DeviceEvents
| where Timestamp > ago(7d)
| where ActionType has_any (
    "ExploitGuardNetworkProtectionBlocked",
    "ExploitGuardNonMicrosoftSignedBlocked",
    "SmartScreenUrlWarning","NetworkProtectionUserBypassEvent")
| project Timestamp, DeviceName, ActionType, RemoteIP, LocalPort`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where AttackTechniques has "T1190"
    or Title has_any (
      "web shell","exploit","public-facing",
      "SQL injection","SSRF","RCE","remote code execution",
      "injection","deserialization","CVE-")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },

  {
    id: "T1566.002",
    name: "Phishing: Spearphishing Link",
    tacticIds: ["TA0001"],
    matrix: "cloud",
    description: "Adversaries send targeted spearphishing emails containing malicious URLs to cloud service users — Microsoft 365, Entra ID, Teams — to harvest credentials or deliver malware. AiTM reverse-proxy kits (Evilginx, Modlishka) are commonly delivered via this vector, capturing post-MFA session tokens.",
    xdrMappings: [
      {
        table: "EmailEvents",
        columns: ["SenderFromAddress", "RecipientEmailAddress", "Subject", "ThreatTypes", "DeliveryAction", "UrlCount"],
        kql: `EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has_any ("Phish","MaliciousUrl","Spam")
    or DeliveryAction == "Blocked"
| where UrlCount > 0
| project Timestamp, SenderFromAddress, RecipientEmailAddress,
          Subject, ThreatTypes, DeliveryAction, UrlCount`,
      },
      {
        table: "UrlClickEvents",
        columns: ["AccountUpn", "Url", "UrlChain", "IsClickedThrough", "ActionType", "IPAddress"],
        kql: `UrlClickEvents
| where Timestamp > ago(7d)
| where IsClickedThrough == true
| where ActionType in ("ClickBlocked","ClickAllowed")
| where Url !has "microsoft.com" and Url !has "office.com"
| project Timestamp, AccountUpn, Url, UrlChain,
          IsClickedThrough, ActionType, IPAddress`,
      },
    ],
  },

  {
    id: "T1566.004",
    name: "Phishing: Spearphishing Voice",
    tacticIds: ["TA0001"],
    matrix: "cloud",
    description: "Adversaries use phone calls (vishing) to socially engineer cloud service users — impersonating IT helpdesk, Microsoft support, or executives — to obtain credentials, MFA bypass codes, or trick victims into approving fraudulent MFA push notifications.",
    xdrMappings: [
      {
        table: "EntraIdSignInEvents",
        columns: ["AccountUpn", "IPAddress", "Country", "RiskLevelDuringSignIn", "ConditionalAccessStatus", "ErrorCode"],
        kql: `// MFA approval immediately following a period of repeated failed attempts
// suggests victim was socially engineered over phone
EntraIdSignInEvents
| where Timestamp > ago(1d)
| where ErrorCode == 0
| join kind=inner (
    EntraIdSignInEvents
    | where ErrorCode in (50097, 500121, 50074)
    | summarize FailedMFA = count() by AccountUpn, bin(Timestamp, 30m)
    | where FailedMFA >= 3
) on AccountUpn
| project Timestamp, AccountUpn, IPAddress, Country, RiskLevelDuringSignIn`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where Title has_any (
    "vishing","voice phishing","phone-based social engineering",
    "MFA approved after repeated failures","suspicious MFA")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },

  {
    id: "T1199",
    name: "Trusted Relationship",
    tacticIds: ["TA0001"],
    matrix: "cloud",
    description: "Adversaries gain access to cloud environments by compromising a trusted third party — MSPs, IT vendors, cloud consulting partners — that already has delegated admin access, CSP relationships, or privileged API integrations with the target tenant.",
    xdrMappings: [
      {
        table: "EntraIdSignInEvents",
        columns: ["AccountUpn", "IPAddress", "Country", "IsManaged", "Application", "RiskLevelDuringSignIn"],
        kql: `// Sign-ins from service provider tenants via cross-tenant delegation
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode == 0
// HomeTenantId != resource tenant = cross-tenant / partner sign-in
| where isnotempty(HomeTenantId) and HomeTenantId != TenantId
| project Timestamp, AccountUpn, IPAddress, Country,
          IsManaged, Application, HomeTenantId, RiskLevelDuringSignIn`,
      },
      {
        table: "CloudAuditEvents",
        columns: ["AccountUpn", "ActionType", "ResourceId", "IPAddress", "AdditionalFields"],
        kql: `// Activity by delegated admin (GDAP/DAP) partner accounts
CloudAuditEvents
| where Timestamp > ago(7d)
| extend Props = parse_json(AdditionalFields)
| where tostring(Props.delegatedAdmin) == "true"
    or ActionType has "delegatedAdminRelationship"
| project Timestamp, AccountUpn, ActionType,
          ResourceId, IPAddress, Props`,
      },
    ],
  },

  {
    id: "T1078.004",
    name: "Valid Accounts: Cloud Accounts",
    tacticIds: ["TA0001", "TA0003", "TA0004", "TA0005"],
    matrix: "cloud",
    description: "Adversaries obtain and abuse credentials for Entra ID users, service principals, or managed identities to gain initial access, persist, or evade defences via the cloud identity layer. MFA bypass is common via token theft or AiTM.",
    xdrMappings: [
      {
        table: "EntraIdSignInEvents",
        columns: ["AccountUpn", "IPAddress", "Country", "IsAnonymousProxy", "RiskLevelDuringSignIn", "ConditionalAccessStatus", "ErrorCode"],
        kql: `EntraIdSignInEvents
| where Timestamp > ago(1d)
| where ErrorCode == 0
| where IsAnonymousProxy == true
    or RiskLevelDuringSignIn in ("high","medium")
    or ConditionalAccessStatus == "notApplied"
| project Timestamp, AccountUpn, IPAddress, Country,
          IsAnonymousProxy, RiskLevelDuringSignIn, ConditionalAccessStatus`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountUpn", "ActionType", "IPAddress", "Application", "IPTags", "UncommonForUser"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where IPTags has_any ("anonymizer","tor","VPN")
    or UncommonForUser has "IPAddress"
| where ActionType in ("UserLoggedIn","MailboxLogin","FileAccessed")
| project Timestamp, AccountUpn, ActionType, IPAddress, Application, IPTags`,
      },
    ],
  },

  {
    id: "T1557",
    name: "Adversary-in-the-Middle (AiTM)",
    tacticIds: ["TA0006", "TA0009"],
    matrix: "cloud",
    description: "Adversaries deploy a reverse-proxy phishing kit between the victim and a legitimate cloud service to intercept credentials and post-MFA session cookies in real time — bypassing MFA without exploiting any vulnerability in the MFA mechanism itself.",
    xdrMappings: [
      {
        table: "UrlClickEvents",
        columns: ["AccountUpn", "Url", "UrlChain", "IsClickedThrough", "ActionType", "IPAddress"],
        kql: `UrlClickEvents
| where Timestamp > ago(7d)
| where IsClickedThrough == true
// AiTM proxy always sits between the phishing link and
// login.microsoftonline.com — it shows as a middle hop in UrlChain
| where UrlChain has_any (
    "login.microsoftonline.com",
    "login.microsoft.com")
| where Url !has "microsoft.com"
| project Timestamp, AccountUpn, Url, UrlChain, IPAddress`,
      },
      {
        table: "EntraIdSignInEvents",
        columns: ["AccountUpn", "IPAddress", "Country", "SessionId", "AuthenticationRequirement", "RiskLevelDuringSignIn"],
        kql: `// Stolen token replay: same SessionId used from two different IPs
EntraIdSignInEvents
| where Timestamp > ago(1d)
| where ErrorCode == 0
| summarize IPs      = make_set(IPAddress),
            Countries = make_set(Country),
            SignIns  = count()
    by AccountUpn, SessionId
| where array_length(IPs) > 1
| project AccountUpn, SessionId, SignIns, IPs, Countries`,
      },
    ],
  },

  // ─── EXECUTION ─────────────────────────────────────────────────────────────
  {
    id: "T1651",
    name: "Cloud Administration Command",
    tacticIds: ["TA0002"],
    matrix: "cloud",
    description: "Adversaries abuse cloud-native VM management features — Azure Run Command, AWS SSM Run Command, GCP OS Login — to execute arbitrary commands inside VMs without any network-layer visibility, authenticating entirely through the cloud control plane.",
    xdrMappings: [
      {
        table: "CloudAuditEvents",
        columns: ["AccountUpn", "ActionType", "ResourceId", "ResourceType", "IPAddress", "AdditionalFields"],
        kql: `CloudAuditEvents
| where Timestamp > ago(7d)
| where ActionType has_any (
    "Microsoft.Compute/virtualMachines/runCommand/action",
    "microsoft.compute/virtualmachines/runcommand",
    "Microsoft.Compute/virtualMachines/extensions/write",
    "CustomScriptExtension","RunPowerShellScript","RunShellScript")
| extend Details = parse_json(AdditionalFields)
| project Timestamp, AccountUpn, ActionType, ResourceId, IPAddress, Details`,
      },
      {
        table: "CloudProcessEvents",
        columns: ["DeviceName", "DeviceId", "FileName", "ProcessCommandLine", "InitiatingProcessFileName", "AccountName"],
        kql: `CloudProcessEvents
| where Timestamp > ago(7d)
// Run Command spawns through the Azure Guest Agent on the VM
| where InitiatingProcessFileName in~ (
    "WindowsAzureGuestAgent.exe","WaAppAgent.exe",
    "waagent","CustomScriptHandler","RunCommandExtension")
| where FileName in~ (
    "cmd.exe","powershell.exe","bash","sh",
    "python.exe","python3","whoami.exe","net.exe","curl","wget")
| project Timestamp, DeviceName, FileName,
          ProcessCommandLine, InitiatingProcessFileName, AccountName`,
      },
    ],
  },

  {
    id: "T1059.009",
    name: "Command and Scripting Interpreter: Cloud API",
    tacticIds: ["TA0002"],
    matrix: "cloud",
    description: "Adversaries use cloud management APIs (Azure REST API, Azure CLI, Azure PowerShell, Graph API) to execute commands against cloud resources — creating infrastructure, accessing data, or pivoting between services — all without touching a VM or endpoint.",
    xdrMappings: [
      {
        table: "CloudAuditEvents",
        columns: ["AccountUpn", "ActionType", "ResourceId", "ResourceType", "IPAddress", "AdditionalFields"],
        kql: `// Burst of API write/execute operations in short window = scripted API abuse
CloudAuditEvents
| where Timestamp > ago(7d)
| where ActionType !has "/read"
| summarize ApiCalls = count(),
            Actions = make_set(ActionType, 20),
            Resources = make_set(ResourceType, 10)
    by AccountUpn, IPAddress, bin(Timestamp, 10m)
| where ApiCalls > 30
| order by ApiCalls desc`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountUpn", "ActionType", "Application", "IPAddress", "UserAgent"],
        kql: `// Requests via Azure CLI or PowerShell user-agents rather than portal
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Azure"
| where UserAgent has_any (
    "AZURECLI","python-requests","PowerShell",
    "Go-http-client","Terraform","Pulumi","axios",
    "curl","libcurl","AzurePowerShell")
| summarize Calls = count(), Actions = make_set(ActionType, 20)
    by AccountUpn, IPAddress, UserAgent, bin(Timestamp, 1h)
| where Calls > 20
| order by Calls desc`,
      },
    ],
  },

  {
    id: "T1648",
    name: "Serverless Execution",
    tacticIds: ["TA0002"],
    matrix: "cloud",
    description: "Adversaries abuse serverless platforms — Azure Functions, Azure Logic Apps, Azure Automation Runbooks — to execute malicious code in the cloud without managing infrastructure, leveraging managed identities for lateral movement to storage, Key Vault, or other Azure services.",
    xdrMappings: [
      {
        table: "CloudAuditEvents",
        columns: ["AccountUpn", "ActionType", "ResourceId", "ResourceType", "IPAddress", "AdditionalFields"],
        kql: `CloudAuditEvents
| where Timestamp > ago(7d)
| where ActionType has_any (
    "Microsoft.Web/sites/functions/write",
    "Microsoft.Web/sites/functions/run/action",
    "Microsoft.Logic/workflows/write",
    "Microsoft.Logic/workflows/triggers/run/action",
    "Microsoft.Automation/automationAccounts/runbooks/write",
    "Microsoft.Automation/automationAccounts/jobs/write")
| project Timestamp, AccountUpn, ActionType,
          ResourceId, ResourceType, IPAddress`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where AttackTechniques has "T1648"
    or Title has_any (
      "Azure Function","Logic App","Automation Runbook",
      "serverless execution","suspicious function")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },

  // ─── PERSISTENCE ───────────────────────────────────────────────────────────
  {
    id: "T1098.001",
    name: "Account Manipulation: Additional Cloud Credentials",
    tacticIds: ["TA0003", "TA0004"],
    matrix: "cloud",
    description: "Adversaries add client secrets, certificates, or federated identity credentials to an Entra ID application registration or service principal — creating a persistent authentication path that survives password resets and is invisible to the affected user.",
    xdrMappings: [
      {
        table: "GraphApiAuditEvents",
        columns: ["AccountUpn", "ActionType", "IPAddress", "TargetResources", "AdditionalFields"],
        kql: `GraphApiAuditEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "Add service principal credentials.",
    "Update application – Certificates and secrets management",
    "Add application.",
    "Update service principal.")
| project Timestamp, AccountUpn, ActionType,
          IPAddress, TargetResources, AdditionalFields`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where AttackTechniques has "T1098"
    or Title has_any (
      "service principal","app credential",
      "certificate added","client secret","federated credential")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },

  {
    id: "T1098.002",
    name: "Account Manipulation: Additional Email Delegate Permissions",
    tacticIds: ["TA0003"],
    matrix: "cloud",
    description: "Adversaries grant mailbox delegate permissions (Full Access, SendAs, SendOnBehalf) to attacker-controlled accounts via Exchange Online — enabling continuous email reading without triggering forwarding-rule detections, and surviving password resets.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountUpn", "ActionType", "Application", "AdditionalFields"],
        kql: `CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "Microsoft Exchange Online"
| where ActionType in (
    "Add-MailboxPermission","Add-RecipientPermission",
    "Set-Mailbox","UpdateCalendarDelegation",
    "AddFolderPermissions")
| where AdditionalFields has_any (
    "FullAccess","SendAs","SendOnBehalf")
| project Timestamp, AccountUpn, ActionType, AdditionalFields`,
      },
    ],
  },

  {
    id: "T1098.003",
    name: "Account Manipulation: Additional Cloud Roles",
    tacticIds: ["TA0003", "TA0004"],
    matrix: "cloud",
    description: "Adversaries assign high-privilege Entra ID roles (Global Administrator, Privileged Role Administrator) or Azure RBAC roles to accounts they control — escalating privileges and creating a persistence mechanism that survives credential rotation.",
    xdrMappings: [
      {
        table: "GraphApiAuditEvents",
        columns: ["AccountUpn", "ActionType", "IPAddress", "TargetResources", "AdditionalFields"],
        kql: `GraphApiAuditEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "Add member to role.",
    "Add eligible member to role.",
    "Add scoped member to role.")
| where AdditionalFields has_any (
    "Global Administrator","Privileged Role Administrator",
    "Security Administrator","Exchange Administrator",
    "SharePoint Administrator","User Administrator",
    "Application Administrator","Cloud Application Administrator")
| project Timestamp, AccountUpn, ActionType,
          IPAddress, TargetResources, AdditionalFields`,
      },
      {
        table: "IdentityDirectoryEvents",
        columns: ["AccountUpn", "ActionType", "TargetAccountUpn", "ModifiedProperties"],
        kql: `IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "Group Membership changed"
| where AdditionalFields has_any (
    "Domain Admins","Enterprise Admins",
    "Schema Admins","Administrators",
    "Backup Operators")
| project Timestamp, AccountUpn, ActionType,
          TargetAccountUpn, AdditionalFields`,
      },
    ],
  },

  {
    id: "T1136.003",
    name: "Create Account: Cloud Account",
    tacticIds: ["TA0003"],
    matrix: "cloud",
    description: "Adversaries create new Entra ID users, guest accounts, service principals, or managed identities as backdoors — accounts that survive on-premises AD changes, are harder to audit, and often lack the monitoring of regular user accounts.",
    xdrMappings: [
      {
        table: "GraphApiAuditEvents",
        columns: ["AccountUpn", "ActionType", "IPAddress", "TargetResources"],
        kql: `GraphApiAuditEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "Add user.","Invite external user.",
    "Add application.","Add service principal.",
    "Create managed identity.")
| project Timestamp, AccountUpn, ActionType,
          IPAddress, TargetResources`,
      },
      {
        table: "IdentityDirectoryEvents",
        columns: ["AccountUpn", "ActionType", "TargetAccountUpn", "TargetAccountDisplayName"],
        kql: `IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType == "User Account created"
// Flag accounts created outside business hours by non-provisioning processes
| extend Hour = hourofday(Timestamp)
| where Hour !between (8 .. 18)
| project Timestamp, AccountUpn, TargetAccountUpn,
          TargetAccountDisplayName, Hour`,
      },
    ],
  },

  {
    id: "T1525",
    name: "Implant Internal Image",
    tacticIds: ["TA0003"],
    matrix: "cloud",
    description: "Adversaries modify or replace cloud VM images, container images, or Azure Shared Image Gallery entries with backdoored versions — ensuring malicious code executes on every new workload deployed from that image, providing persistent execution without touching running instances.",
    xdrMappings: [
      {
        table: "CloudAuditEvents",
        columns: ["AccountUpn", "ActionType", "ResourceId", "ResourceType", "IPAddress"],
        kql: `CloudAuditEvents
| where Timestamp > ago(7d)
| where ActionType has_any (
    "Microsoft.Compute/images/write",
    "Microsoft.Compute/galleries/images/versions/write",
    "Microsoft.ContainerRegistry/registries/push/write",
    "Microsoft.ContainerRegistry/registries/importImage/action",
    "Microsoft.Compute/disks/write")
| project Timestamp, AccountUpn, ActionType,
          ResourceId, ResourceType, IPAddress`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(30d)
| where AttackTechniques has "T1525"
    or Title has_any (
      "container image","VM image","backdoor image",
      "image registry","implant","shared image")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },

  {
    id: "T1484.002",
    name: "Domain or Tenant Policy Modification: Trust Modification",
    tacticIds: ["TA0003", "TA0004", "TA0005"],
    matrix: "cloud",
    description: "Adversaries modify Entra ID federation settings or add a new federated domain — injecting a malicious SAML identity provider that can issue tokens for any user in the tenant, creating a persistent, password-independent backdoor (SAML Golden Ticket / federation backdoor).",
    xdrMappings: [
      {
        table: "GraphApiAuditEvents",
        columns: ["AccountUpn", "ActionType", "IPAddress", "TargetResources", "AdditionalFields"],
        kql: `GraphApiAuditEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "Set domain authentication.",
    "Set federation settings on domain.",
    "Add unverified domain to company.",
    "Add verified domain to company.",
    "Set domain to be authenticated.",
    "Update domain.")
| project Timestamp, AccountUpn, ActionType,
          IPAddress, TargetResources, AdditionalFields`,
      },
      {
        table: "IdentityDirectoryEvents",
        columns: ["AccountUpn", "ActionType", "AdditionalFields"],
        kql: `IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType has_any (
    "Federation settings changed",
    "Domain federation","Set federation",
    "federated domain","trust modification",
    "Token signing cert","AD FS")
| project Timestamp, AccountUpn, ActionType, AdditionalFields`,
      },
    ],
  },

  // ─── DEFENSE EVASION ───────────────────────────────────────────────────────
  {
    id: "T1562.008",
    name: "Impair Defenses: Disable Cloud Logs",
    tacticIds: ["TA0005"],
    matrix: "cloud",
    description: "Adversaries disable or modify cloud audit logging — Azure Monitor diagnostic settings, Defender plans, M365 Unified Audit Log, or Log Analytics workspaces — to blind defenders before or during their main activity.",
    xdrMappings: [
      {
        table: "CloudAuditEvents",
        columns: ["AccountUpn", "ActionType", "ResourceId", "ResourceType", "IPAddress"],
        kql: `CloudAuditEvents
| where Timestamp > ago(7d)
| where ActionType has_any (
    "microsoft.insights/diagnosticSettings/delete",
    "microsoft.insights/diagnosticSettings/write",
    "Microsoft.Security/policies/write",
    "microsoft.operationalinsights/workspaces/delete",
    "Microsoft.Authorization/policyAssignments/delete")
| project Timestamp, AccountUpn, ActionType,
          ResourceId, ResourceType, IPAddress`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where AttackTechniques has "T1562"
    or Title has_any (
      "diagnostic settings","logging disabled",
      "Defender disabled","audit log cleared",
      "policy deleted","log analytics workspace")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },

  {
    id: "T1535",
    name: "Unused/Unsupported Cloud Regions",
    tacticIds: ["TA0005"],
    matrix: "cloud",
    description: "Adversaries operate in Azure regions outside the organization's approved set — regions with no monitoring, no policy enforcement, and no alerting configured — to evade detection while conducting their operations.",
    xdrMappings: [
      {
        table: "CloudAuditEvents",
        columns: ["AccountUpn", "ActionType", "ResourceId", "ResourceType", "IPAddress", "AdditionalFields"],
        kql: `CloudAuditEvents
| where Timestamp > ago(7d)
| where ActionType has_any (
    "Microsoft.Compute/virtualMachines/write",
    "Microsoft.Storage/storageAccounts/write",
    "Microsoft.Network/virtualNetworks/write",
    "Microsoft.ContainerService/managedClusters/write")
| extend Region = tostring(parse_json(AdditionalFields).location)
// Adjust to your organisation's approved regions
| where Region !in~ (
    "eastus","eastus2","westus","westus2","westus3",
    "centralus","northcentralus","southcentralus",
    "westeurope","northeurope","uksouth","ukwest",
    "australiaeast","australiasoutheast")
| project Timestamp, AccountUpn, ActionType, Region,
          ResourceId, IPAddress`,
      },
    ],
  },

  {
    id: "T1578.002",
    name: "Modify Cloud Compute Infrastructure: Create Cloud Instance",
    tacticIds: ["TA0005", "TA0003"],
    matrix: "cloud",
    description: "Adversaries create new cloud compute instances — VMs, containers, or scale sets — to establish staging infrastructure, pivot, or mine cryptocurrency. Unexpected VM creation outside the provisioning baseline is a strong indicator.",
    xdrMappings: [
      {
        table: "CloudAuditEvents",
        columns: ["AccountUpn", "ActionType", "ResourceId", "ResourceType", "IPAddress", "AdditionalFields"],
        kql: `CloudAuditEvents
| where Timestamp > ago(7d)
| where ActionType has_any (
    "Microsoft.Compute/virtualMachines/write",
    "Microsoft.Compute/virtualMachineScaleSets/write",
    "Microsoft.ContainerService/managedClusters/write",
    "Microsoft.ContainerInstance/containerGroups/write")
| summarize VMsCreated = count(),
            IPs = make_set(IPAddress, 5)
    by AccountUpn, bin(Timestamp, 1h)
| where VMsCreated > 3
| order by VMsCreated desc`,
      },
    ],
  },

  {
    id: "T1578.001",
    name: "Modify Cloud Compute Infrastructure: Create Snapshot",
    tacticIds: ["TA0005"],
    matrix: "cloud",
    description: "Adversaries create snapshots of VM disks or storage volumes to exfiltrate data or access credentials stored at rest — bypassing OS-level access controls by reading the raw disk offline, avoiding any log events generated by the running OS.",
    xdrMappings: [
      {
        table: "CloudAuditEvents",
        columns: ["AccountUpn", "ActionType", "ResourceId", "ResourceType", "IPAddress"],
        kql: `CloudAuditEvents
| where Timestamp > ago(7d)
| where ActionType has_any (
    "Microsoft.Compute/snapshots/write",
    "Microsoft.Compute/disks/beginGetAccess/action",
    "Microsoft.Compute/snapshots/beginGetAccess/action",
    "Microsoft.Compute/disks/download")
| project Timestamp, AccountUpn, ActionType,
          ResourceId, ResourceType, IPAddress`,
      },
    ],
  },

  {
    id: "T1578.003",
    name: "Modify Cloud Compute Infrastructure: Delete Cloud Instance",
    tacticIds: ["TA0005"],
    matrix: "cloud",
    description: "Adversaries delete cloud VM instances to destroy evidence of their activity — wiping process, network, and file telemetry that existed only in the running instance's memory and OS logs. Often performed after completing their objective or as part of a ransomware deployment.",
    xdrMappings: [
      {
        table: "CloudAuditEvents",
        columns: ["AccountUpn", "ActionType", "ResourceId", "ResourceType", "IPAddress"],
        kql: `CloudAuditEvents
| where Timestamp > ago(7d)
| where ActionType has_any (
    "Microsoft.Compute/virtualMachines/delete",
    "Microsoft.Compute/virtualMachineScaleSets/delete",
    "Microsoft.ContainerService/managedClusters/delete",
    "Microsoft.ContainerInstance/containerGroups/delete",
    "Microsoft.Compute/disks/delete")
| summarize Deletions = count(), IPs = make_set(IPAddress, 5)
    by AccountUpn, ResourceType, bin(Timestamp, 1h)
| order by Deletions desc`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where AttackTechniques has "T1578"
    or Title has_any (
      "VM deleted","instance deleted","compute destroyed",
      "mass deletion","bulk delete","resource deleted")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },

  {
    id: "T1564.008",
    name: "Hide Artifacts: Email Hiding Rules",
    tacticIds: ["TA0005"],
    matrix: "cloud",
    description: "Adversaries create Exchange Online inbox rules that move, delete, or mark-as-read security alerts, investigation notices, or suspicious reply threads — hiding evidence of compromise from the victim and preventing them from noticing attacker activity in their mailbox.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountUpn", "ActionType", "Application", "AdditionalFields"],
        kql: `CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "Microsoft Exchange Online"
| where ActionType in (
    "New-InboxRule","Set-InboxRule","UpdateInboxRules")
// Rules that hide items without forwarding (concealment, not exfil)
| where AdditionalFields has_any (
    "MoveToFolder","DeleteMessage","MarkAsRead",
    "MarkAllAsRead","PermanentlyDelete")
    and AdditionalFields !has_any (
    "ForwardTo","RedirectTo","ForwardAsAttachmentTo")
| project Timestamp, AccountUpn, ActionType, AdditionalFields`,
      },
    ],
  },

  {
    id: "T1550.004",
    name: "Use Alternate Authentication Material: Web Session Cookie",
    tacticIds: ["TA0005", "TA0008"],
    matrix: "cloud",
    description: "Adversaries replay stolen web session cookies to authenticate to cloud services without credentials or MFA. After AiTM phishing captures a post-MFA session token, the attacker uses it from a different IP — appearing as a legitimately authenticated session.",
    xdrMappings: [
      {
        table: "EntraIdSignInEvents",
        columns: ["AccountUpn", "IPAddress", "Country", "SessionId", "IsManaged", "RiskLevelDuringSignIn"],
        kql: `// Same session active from two different IPs = likely stolen token replay
EntraIdSignInEvents
| where Timestamp > ago(1d)
| where ErrorCode == 0
| summarize IPs       = make_set(IPAddress),
            Countries = make_set(Country),
            Sessions  = dcount(SessionId)
    by AccountUpn, bin(Timestamp, 30m)
| where array_length(IPs) > 1 or array_length(Countries) > 1
| project Timestamp, AccountUpn, IPs, Countries, Sessions`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountUpn", "ActionType", "IPAddress", "Application", "UncommonForUser"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where isnotempty(UncommonForUser)
| where UncommonForUser has "IPAddress"
| where ActionType in (
    "MailItemsAccessed","FileDownloaded",
    "FileSyncDownloadedFull","UserLoggedIn")
| project Timestamp, AccountUpn, ActionType,
          IPAddress, Application, UncommonForUser`,
      },
    ],
  },

  {
    id: "T1556.006",
    name: "Modify Authentication Process: MFA Method Modification",
    tacticIds: ["TA0005", "TA0006"],
    matrix: "cloud",
    description: "Adversaries modify MFA configuration for a cloud account — registering an attacker-controlled authenticator app, phone number, or FIDO key — to gain persistent MFA-capable access that survives password resets.",
    xdrMappings: [
      {
        table: "IdentityDirectoryEvents",
        columns: ["AccountUpn", "ActionType", "TargetAccountUpn", "AdditionalFields"],
        kql: `IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "User registered for MFA",
    "MFA registration details modified",
    "Admin registered security info for user",
    "MFA method added for user",
    "SSPR registration activity")
| project Timestamp, AccountUpn, ActionType,
          TargetAccountUpn, AdditionalFields`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where Title has_any (
    "MFA method registered","authenticator registered",
    "security info modified","MFA change",
    "suspicious MFA registration")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },

  // ─── CREDENTIAL ACCESS ─────────────────────────────────────────────────────
  {
    id: "T1528",
    name: "Steal Application Access Token",
    tacticIds: ["TA0006"],
    matrix: "cloud",
    description: "Adversaries steal OAuth access tokens via malicious consent grants (device code phishing, illicit consent), allowing them to authenticate as an app or user against Microsoft 365 and Azure APIs without credentials — and without triggering MFA.",
    xdrMappings: [
      {
        table: "GraphApiAuditEvents",
        columns: ["AccountUpn", "ActionType", "IPAddress", "TargetResources", "AdditionalFields"],
        kql: `GraphApiAuditEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "Add OAuth2PermissionGrant.",
    "Consent to application.",
    "Add application.",
    "Add service principal.")
| project Timestamp, AccountUpn, ActionType,
          IPAddress, TargetResources, AdditionalFields`,
      },
      {
        table: "EntraIdSignInEvents",
        columns: ["AccountUpn", "IPAddress", "IsManaged", "Application", "ApplicationId", "AuthenticationRequirement"],
        kql: `// Device code phishing: successful sign-in to unknown app from unmanaged device
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode == 0
| where IsManaged == false
// Flag app IDs not in your approved allowlist
| where ApplicationId !in (
    "00000002-0000-0ff1-ce00-000000000000",   // Exchange
    "00000003-0000-0000-c000-000000000000",   // Graph
    "00000004-0000-0ff1-ce00-000000000000")   // Lync
| project Timestamp, AccountUpn, ApplicationId, Application,
          IPAddress, IsManaged, AuthenticationRequirement`,
      },
    ],
  },

  {
    id: "T1539",
    name: "Steal Web Session Cookie",
    tacticIds: ["TA0006"],
    matrix: "cloud",
    description: "Adversaries steal browser session cookies from disk, memory, or via AiTM proxy capture to authenticate to cloud web applications. This covers the theft mechanism itself; T1550.004 covers the subsequent replay.",
    xdrMappings: [
      {
        table: "DeviceFileEvents",
        columns: ["DeviceName", "FileName", "FolderPath", "SHA256", "InitiatingProcessFileName"],
        kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileRead","FileCopied","FileRenamed")
| where FolderPath has_any (
    "\\Google\\Chrome\\User Data",
    "\\Microsoft\\Edge\\User Data",
    "\\Mozilla\\Firefox\\Profiles")
| where FileName in~ ("Cookies","Login Data","Web Data","Cookies.db")
| project Timestamp, DeviceName, FileName, FolderPath,
          InitiatingProcessFileName, SHA256`,
      },
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "InitiatingProcessFileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any (
    "Cookies","Login Data","ChromePass",
    "WebBrowserPassView","cookie dump",
    "\\User Data\\Default\\")
    or FileName in~ ("esentutl.exe","robocopy.exe","xcopy.exe")
        and ProcessCommandLine has_any ("Cookies","Login Data")
| project Timestamp, DeviceName, FileName,
          ProcessCommandLine, InitiatingProcessFileName`,
      },
    ],
  },

  {
    id: "T1621",
    name: "Multi-Factor Authentication Request Generation",
    tacticIds: ["TA0006"],
    matrix: "cloud",
    description: "Adversaries send a high volume of MFA push notifications to a target — MFA fatigue — hoping the user approves one to stop the noise. Often preceded by a successful password spray to confirm valid credentials before the bombing phase.",
    xdrMappings: [
      {
        table: "EntraIdSignInEvents",
        columns: ["AccountUpn", "IPAddress", "ErrorCode", "AuthenticationRequirement", "RiskLevelDuringSignIn"],
        kql: `// High-volume MFA prompts that fail — target account receiving repeated push requests
EntraIdSignInEvents
| where Timestamp > ago(1h)
// 50097 = MFA not completed; 500121 = auth strength policy; 50074 = MFA required
| where ErrorCode in (50097, 500121, 50074, 50158)
| summarize MFAAttempts = count()
    by AccountUpn, IPAddress, bin(Timestamp, 10m)
| where MFAAttempts > 5
| order by MFAAttempts desc`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where AttackTechniques has "T1621"
    or Title has_any (
      "MFA fatigue","MFA flood","authenticator spam",
      "suspicious MFA","MFA request generation")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },

  {
    id: "T1606.002",
    name: "Forge Web Credentials: SAML Tokens",
    tacticIds: ["TA0006"],
    matrix: "cloud",
    description: "Adversaries forge SAML assertions using a stolen AD FS token-signing certificate (Golden SAML attack), allowing them to authenticate as any federated user to cloud services including Entra ID, Azure, and Microsoft 365 — without needing user passwords.",
    xdrMappings: [
      {
        table: "EntraIdSignInEvents",
        columns: ["AccountUpn", "IPAddress", "Country", "IsManaged", "AuthenticationRequirement", "RiskLevelDuringSignIn"],
        kql: `// SAML token abuse: sign-ins with unusual auth method, no device registration
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode == 0
| where IsManaged == false
// Federated sign-ins that bypass conditional access
| where ConditionalAccessStatus == "notApplied"
| where AuthenticationRequirement == "singleFactorAuthentication"
// Flag accounts that normally require MFA
| where AccountUpn in ("<high-value-accounts>")
| project Timestamp, AccountUpn, IPAddress, Country,
          IsManaged, ConditionalAccessStatus, RiskLevelDuringSignIn`,
      },
      {
        table: "IdentityDirectoryEvents",
        columns: ["AccountUpn", "ActionType", "AdditionalFields"],
        kql: `// Detect access to AD FS signing certificate or token-signing key
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType has_any (
    "Certificate Services","Token signing","AD FS",
    "Federation settings","federated domain")
| project Timestamp, AccountUpn, ActionType, AdditionalFields`,
      },
    ],
  },

  {
    id: "T1110.003",
    name: "Brute Force: Password Spraying",
    tacticIds: ["TA0006"],
    matrix: "cloud",
    description: "Adversaries test a small number of common passwords against a large number of Entra ID accounts — avoiding per-account lockout thresholds. Sprays typically target legacy authentication protocols (IMAP, SMTP, EWS) that bypass MFA, or use credential stuffing lists from prior breaches.",
    xdrMappings: [
      {
        table: "EntraIdSignInEvents",
        columns: ["AccountUpn", "IPAddress", "Country", "ErrorCode", "AuthenticationRequirement", "RiskLevelDuringSignIn"],
        kql: `// Many different accounts failing from same IP in a short window = spray
EntraIdSignInEvents
| where Timestamp > ago(1h)
// 50126 = bad password, 50053 = account locked, 50055 = password expired
| where ErrorCode in (50126, 50053, 50055, 50056, 50064, 50144)
| summarize FailedAccounts = dcount(AccountUpn),
            Attempts = count()
    by IPAddress, Country, bin(Timestamp, 10m)
| where FailedAccounts > 5
| order by FailedAccounts desc`,
      },
      {
        table: "IdentityLogonEvents",
        columns: ["AccountName", "AccountUpn", "LogonType", "FailureReason", "IPAddress", "Protocol"],
        kql: `// Legacy protocol spray — IMAP/POP/SMTP bypass MFA
IdentityLogonEvents
| where Timestamp > ago(1h)
| where FailureReason == "WrongPassword"
| where Protocol in~ ("IMAP","POP3","SMTP","EWS","mapi")
| summarize FailedAccounts = dcount(AccountUpn), Attempts = count()
    by IPAddress, Protocol, bin(Timestamp, 10m)
| where FailedAccounts > 3
| order by FailedAccounts desc`,
      },
    ],
  },

  {
    id: "T1110.004",
    name: "Brute Force: Credential Stuffing",
    tacticIds: ["TA0006"],
    matrix: "cloud",
    description: "Adversaries use username-password pairs obtained from third-party data breaches to authenticate to Entra ID and Microsoft 365 services at scale. Because the credentials are valid elsewhere, success rates are higher than spraying and per-account lockout is not guaranteed to stop the attack.",
    xdrMappings: [
      {
        table: "EntraIdSignInEvents",
        columns: ["AccountUpn", "IPAddress", "Country", "IsAnonymousProxy", "RiskLevelDuringSignIn", "ErrorCode"],
        kql: `// High-risk successful logins from anonymizers — credential stuffing success
EntraIdSignInEvents
| where Timestamp > ago(7d)
| where ErrorCode == 0
| where IsAnonymousProxy == true
    or RiskLevelDuringSignIn in ("high","medium")
// Also look for logins from known breach/stuffing infrastructure
| project Timestamp, AccountUpn, IPAddress, Country,
          IsAnonymousProxy, RiskLevelDuringSignIn`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where AttackTechniques has "T1110"
    or Title has_any (
      "credential stuffing","brute force","password spray",
      "multiple failed","sign-in attempts","login flood")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },

  {
    id: "T1552.005",
    name: "Unsecured Credentials: Cloud Instance Metadata API",
    tacticIds: ["TA0006"],
    matrix: "cloud",
    description: "Adversaries running on a cloud VM query the Azure Instance Metadata Service (IMDS) endpoint to retrieve temporary credentials for the VM's managed identity — obtaining an access token for Azure resources without any stored credentials, often via SSRF from a web application.",
    xdrMappings: [
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteIP", "RemoteUrl", "LocalPort", "InitiatingProcessFileName", "InitiatingProcessCommandLine"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(7d)
// Azure IMDS is accessed at link-local 169.254.169.254
| where RemoteIP == "169.254.169.254"
    or RemoteUrl has "169.254.169.254"
    or RemoteUrl has "metadata.azure.internal"
| where InitiatingProcessFileName !in~ (
    "WindowsAzureGuestAgent.exe","WaAppAgent.exe",
    "azd.exe","az.cmd","AzureRM.dll")
| project Timestamp, DeviceName, RemoteIP, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine`,
      },
      {
        table: "DeviceProcessEvents",
        columns: ["DeviceName", "FileName", "ProcessCommandLine", "InitiatingProcessFileName"],
        kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any (
    "169.254.169.254","metadata.azure.internal",
    "metadata/identity","managed-identity",
    "imds","instance-metadata","client_credentials")
| project Timestamp, DeviceName, FileName,
          ProcessCommandLine, InitiatingProcessFileName`,
      },
    ],
  },

  {
    id: "T1552.008",
    name: "Unsecured Credentials: Chat Messages",
    tacticIds: ["TA0006"],
    matrix: "cloud",
    description: "Adversaries search Microsoft Teams, SharePoint, and email for credentials, secrets, and tokens shared insecurely by users — API keys, passwords, SAS tokens, and service account credentials pasted in chat messages, document comments, or email bodies.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountUpn", "ActionType", "Application", "ObjectName", "IPAddress"],
        kql: `// Keyword search in Teams/SharePoint for stored credentials
CloudAppEvents
| where Timestamp > ago(7d)
| where Application in (
    "Microsoft Teams","Microsoft SharePoint Online",
    "Microsoft OneDrive for Business")
| where ActionType in (
    "SearchQueryPerformed","FileAccessed","FileDownloaded")
// Look for searches targeting credential-like terms
| where ObjectName has_any (
    "password","passwd","secret","token","apikey",
    "api_key","credentials","private_key","SAS",
    "connection_string","access_key")
| project Timestamp, AccountUpn, Application,
          ActionType, ObjectName, IPAddress`,
      },
      {
        table: "DataSecurityEvents",
        columns: ["AccountUpn", "ActionType", "FileName", "SensitivityLabel", "PolicyName"],
        kql: `// DLP match on credential-pattern content in Teams/SharePoint
DataSecurityEvents
| where Timestamp > ago(7d)
| where PolicyName has_any (
    "credential","password","secret","token","API key")
| project Timestamp, AccountUpn, ActionType,
          FileName, SensitivityLabel, PolicyName`,
      },
    ],
  },

  {
    id: "T1555.006",
    name: "Credentials from Password Stores: Cloud Secrets Management Stores",
    tacticIds: ["TA0006"],
    matrix: "cloud",
    description: "Adversaries access Azure Key Vault, App Service application settings, or environment variables in containerized workloads to retrieve stored secrets — service account passwords, API keys, database connection strings, and certificates — leveraging compromised managed identities or service principals.",
    xdrMappings: [
      {
        table: "CloudAuditEvents",
        columns: ["AccountUpn", "ActionType", "ResourceId", "ResourceType", "IPAddress"],
        kql: `CloudAuditEvents
| where Timestamp > ago(7d)
| where ActionType has_any (
    "Microsoft.KeyVault/vaults/secrets/read",
    "Microsoft.KeyVault/vaults/secrets/getSecret/action",
    "Microsoft.KeyVault/vaults/keys/read",
    "Microsoft.KeyVault/vaults/certificates/read",
    "Microsoft.Web/sites/config/list/action",
    "listConnectionStrings")
| summarize SecretReads = count(), Vaults = dcount(ResourceId)
    by AccountUpn, IPAddress, bin(Timestamp, 1h)
| where SecretReads > 10
| order by SecretReads desc`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where AttackTechniques has "T1555"
    or Title has_any (
      "Key Vault","secret accessed","credentials retrieved",
      "secrets management","credential store")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },

  // ─── DISCOVERY ─────────────────────────────────────────────────────────────
  {
    id: "T1526",
    name: "Cloud Service Discovery",
    tacticIds: ["TA0007"],
    matrix: "cloud",
    description: "Adversaries enumerate Azure subscriptions, resource groups, VMs, storage accounts, Key Vaults, and IAM role assignments — mapping the tenant before lateral movement or data theft. Burst of read/list operations on the Azure management API is the signature.",
    xdrMappings: [
      {
        table: "CloudAuditEvents",
        columns: ["AccountUpn", "ActionType", "ResourceId", "ResourceType", "IPAddress"],
        kql: `CloudAuditEvents
| where Timestamp > ago(7d)
| where ActionType has_any (
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.Storage/storageAccounts/read",
    "Microsoft.Resources/subscriptions/read",
    "Microsoft.Resources/subscriptions/resourceGroups/read",
    "Microsoft.KeyVault/vaults/read",
    "ListKeys","listKeys",
    "Microsoft.Authorization/roleAssignments/read")
| summarize OpCount = count(),
            ResourceTypes = make_set(ResourceType, 20)
    by AccountUpn, IPAddress, bin(Timestamp, 1h)
| where OpCount > 20
| order by OpCount desc`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountUpn", "ActionType", "Application", "IPAddress", "ObjectName"],
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Azure"
| where ActionType in (
    "ListVirtualMachines","ListSubscriptions",
    "List Role Assignments","ListResourceGroups",
    "Get Virtual Machine","ListStorageAccounts")
| summarize Actions = count(),
            Resources = make_set(ObjectName, 20)
    by AccountUpn, IPAddress, bin(Timestamp, 1h)
| order by Actions desc`,
      },
    ],
  },

  {
    id: "T1580",
    name: "Cloud Infrastructure Discovery",
    tacticIds: ["TA0007"],
    matrix: "cloud",
    description: "Adversaries map the cloud infrastructure in detail — VM names, network topology, security controls, Key Vault contents, and service configurations — to identify pivot paths and targets for data collection or destructive impact.",
    xdrMappings: [
      {
        table: "CloudAuditEvents",
        columns: ["AccountUpn", "ActionType", "ResourceId", "ResourceType", "IPAddress"],
        kql: `CloudAuditEvents
| where Timestamp > ago(7d)
| where ActionType has_any (
    "Microsoft.Network/virtualNetworks/read",
    "Microsoft.Network/networkSecurityGroups/read",
    "Microsoft.KeyVault/vaults/read",
    "Microsoft.KeyVault/vaults/secrets/read",
    "Microsoft.Security/securityContacts/read",
    "Microsoft.Compute/disks/read",
    "Microsoft.Sql/servers/read")
| summarize OpCount = count(), ResourceTypes = make_set(ResourceType, 15)
    by AccountUpn, IPAddress, bin(Timestamp, 1h)
| where OpCount > 15
| order by OpCount desc`,
      },
    ],
  },

  {
    id: "T1538",
    name: "Cloud Service Dashboard",
    tacticIds: ["TA0007"],
    matrix: "cloud",
    description: "Adversaries use the Azure Portal, M365 Admin Center, or Exchange Admin Center browser interfaces for reconnaissance — listing users, reviewing security settings, and browsing resources — leveraging legitimate admin UI rather than APIs.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountUpn", "ActionType", "Application", "IPAddress", "UncommonForUser"],
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where Application in (
    "Microsoft Azure",
    "Microsoft 365 admin center",
    "Exchange Admin Center",
    "SharePoint Admin Center",
    "Microsoft Teams admin center",
    "Azure Active Directory")
// Access to admin centers from accounts that don't normally use them
| where UncommonForUser has "Application"
    or isnotempty(UncommonForUser)
| project Timestamp, AccountUpn, Application,
          ActionType, IPAddress, UncommonForUser`,
      },
    ],
  },

  {
    id: "T1619",
    name: "Cloud Storage Object Discovery",
    tacticIds: ["TA0007"],
    matrix: "cloud",
    description: "Adversaries enumerate SharePoint Online, OneDrive, and Teams document libraries — identifying file names, folder structures, and sensitivity labels to locate high-value data prior to collection.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountUpn", "ActionType", "Application", "ObjectName", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where Application in (
    "Microsoft SharePoint Online",
    "Microsoft OneDrive for Business",
    "Microsoft Teams")
| where ActionType in (
    "SearchQueryPerformed","FileAccessed",
    "PageViewed","SiteCollectionAdminAdded",
    "ListRetrieved")
| summarize Actions = count(), Files = dcount(ObjectName)
    by AccountUpn, IPAddress, Application, bin(Timestamp, 1h)
| where Files > 50
| order by Files desc`,
      },
      {
        table: "DataSecurityEvents",
        columns: ["AccountUpn", "ActionType", "FileName", "SensitivityLabel", "PolicyName"],
        kql: `DataSecurityEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileAccessed","FileViewed","SearchQueryPerformed")
| where SensitivityLabel in ("Highly Confidential","Confidential")
| summarize Count = count(), Files = make_set(FileName, 20)
    by AccountUpn, SensitivityLabel, bin(Timestamp, 1h)
| order by Count desc`,
      },
    ],
  },

  {
    id: "T1087.004",
    name: "Account Discovery: Cloud Account",
    tacticIds: ["TA0007"],
    matrix: "cloud",
    description: "Adversaries enumerate Entra ID users, service principals, guest accounts, groups, and managed identities via Graph API queries or Admin Center — identifying targets for credential stuffing, role escalation, or lateral movement.",
    xdrMappings: [
      {
        table: "GraphApiAuditEvents",
        columns: ["AccountUpn", "ActionType", "IPAddress", "TargetResources"],
        kql: `GraphApiAuditEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "Get member objects","Get user","List users",
    "List group members","Get service principal",
    "List service principals","List application",
    "Get group","List groups")
| summarize Queries = count(),
            QueryTypes = make_set(ActionType)
    by AccountUpn, IPAddress, bin(Timestamp, 1h)
| where Queries > 20
| order by Queries desc`,
      },
    ],
  },

  {
    id: "T1069.003",
    name: "Permission Groups Discovery: Cloud Groups",
    tacticIds: ["TA0007"],
    matrix: "cloud",
    description: "Adversaries enumerate Entra ID security groups, Microsoft 365 groups, Teams channels, and distribution lists to map which accounts have access to high-value resources — identifying targets for lateral movement and understanding the scope of permissions available under a compromised identity.",
    xdrMappings: [
      {
        table: "GraphApiAuditEvents",
        columns: ["AccountUpn", "ActionType", "IPAddress", "TargetResources"],
        kql: `GraphApiAuditEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "List groups","Get group","List group members",
    "List group owners","Get member objects",
    "List transitive member of","List app role assignments",
    "List role assignments")
| summarize Queries = count(), QueryTypes = make_set(ActionType)
    by AccountUpn, IPAddress, bin(Timestamp, 1h)
| where Queries > 15
| order by Queries desc`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountUpn", "ActionType", "Application", "ObjectName", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where Application in (
    "Azure Active Directory","Microsoft Teams",
    "Microsoft 365 admin center")
| where ActionType in (
    "ListGroups","GetGroupMembers","ListRoleAssignments",
    "ListTeamMembers","ListChannels","GetTeam")
| summarize Actions = count()
    by AccountUpn, IPAddress, bin(Timestamp, 1h)
| where Actions > 20
| order by Actions desc`,
      },
    ],
  },

  {
    id: "T1613",
    name: "Container and Resource Discovery",
    tacticIds: ["TA0007"],
    matrix: "cloud",
    description: "Adversaries enumerate container orchestration environments — Azure Kubernetes Service, Azure Container Instances, Azure Container Registry — to understand the workload topology, identify exposed service endpoints, and find containers with privileged access or sensitive environment variables.",
    xdrMappings: [
      {
        table: "CloudAuditEvents",
        columns: ["AccountUpn", "ActionType", "ResourceId", "ResourceType", "IPAddress"],
        kql: `CloudAuditEvents
| where Timestamp > ago(7d)
| where ResourceType has_any (
    "Microsoft.ContainerService",
    "Microsoft.ContainerRegistry",
    "Microsoft.ContainerInstance",
    "Microsoft.App/containerApps",
    "Microsoft.Web/sites")
| where ActionType has "/read"
| summarize OpCount = count(), ResourceTypes = make_set(ResourceType, 10)
    by AccountUpn, IPAddress, bin(Timestamp, 1h)
| where OpCount > 10
| order by OpCount desc`,
      },
      {
        table: "CloudProcessEvents",
        columns: ["DeviceName", "DeviceId", "FileName", "ProcessCommandLine", "AccountName"],
        kql: `// kubectl enumeration commands running inside cloud-connected workloads
CloudProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("kubectl","docker","crictl","ctr","nerdctl")
| where ProcessCommandLine has_any (
    "get pod","get service","get node","get deploy",
    "get secret","describe","list","exec","auth can-i")
| project Timestamp, DeviceName, FileName,
          ProcessCommandLine, AccountName`,
      },
    ],
  },

  {
    id: "T1654",
    name: "Log Enumeration",
    tacticIds: ["TA0007"],
    matrix: "cloud",
    description: "Adversaries read cloud audit and activity logs to understand the target environment — learning what monitoring is in place, identifying defenders' detection gaps, and understanding what actions were already recorded before they disable logging. Azure Monitor, Log Analytics, and the M365 Unified Audit Log are primary targets.",
    xdrMappings: [
      {
        table: "CloudAuditEvents",
        columns: ["AccountUpn", "ActionType", "ResourceId", "ResourceType", "IPAddress"],
        kql: `CloudAuditEvents
| where Timestamp > ago(7d)
| where ActionType has_any (
    "microsoft.insights/logs/read",
    "microsoft.operationalinsights/workspaces/query/read",
    "microsoft.operationalinsights/workspaces/read",
    "microsoft.operationalinsights/workspaces/sharedkeys/read",
    "Microsoft.Security/alerts/read",
    "microsoft.insights/activitylogs/read")
| summarize LogReads = count()
    by AccountUpn, IPAddress, bin(Timestamp, 1h)
| where LogReads > 10
| order by LogReads desc`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountUpn", "ActionType", "Application", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType has_any (
    "SearchAuditLog","eDiscoverySearch",
    "AuditLogSearched","AdminActivitySearch",
    "SearchComplianceCenterAuditLog")
| project Timestamp, AccountUpn, Application,
          ActionType, IPAddress`,
      },
    ],
  },

  // ─── LATERAL MOVEMENT ──────────────────────────────────────────────────────
  {
    id: "T1021.007",
    name: "Remote Services: Cloud Services",
    tacticIds: ["TA0008"],
    matrix: "cloud",
    description: "Adversaries move laterally through cloud environments by authenticating to cloud services (Azure, M365, Teams, SharePoint) using stolen credentials or tokens from a compromised account — pivoting between cloud resources without touching on-premises network paths.",
    xdrMappings: [
      {
        table: "EntraIdSignInEvents",
        columns: ["AccountUpn", "IPAddress", "Country", "Application", "ApplicationId", "RiskLevelDuringSignIn"],
        kql: `// New app or resource accessed by a compromised account after initial sign-in
EntraIdSignInEvents
| where Timestamp > ago(1d)
| where ErrorCode == 0
| where AccountUpn in ("<compromised accounts>")
| summarize Apps = make_set(Application, 20),
            IPs  = make_set(IPAddress, 10)
    by AccountUpn, bin(Timestamp, 1h)
// Flag accounts accessing more apps than their baseline
| where array_length(Apps) > 5
| project Timestamp, AccountUpn, Apps, IPs`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountUpn", "ActionType", "Application", "IPAddress", "OAuthAppId"],
        kql: `CloudAppEvents
| where Timestamp > ago(1d)
| where AccountUpn in ("<compromised accounts>")
// Look for access to services the user doesn't normally touch
| where UncommonForUser has "Application"
| project Timestamp, AccountUpn, ActionType,
          Application, IPAddress, UncommonForUser`,
      },
    ],
  },

  // ─── COLLECTION ────────────────────────────────────────────────────────────
  {
    id: "T1530",
    name: "Data from Cloud Storage",
    tacticIds: ["TA0009"],
    matrix: "cloud",
    description: "Adversaries access and collect data directly from Azure Blob Storage, SharePoint Online, OneDrive, and Teams — leveraging compromised user credentials or OAuth tokens, often via the Graph API to bypass UI-based controls.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountUpn", "ActionType", "Application", "ObjectName", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "FileDownloaded","FileSyncDownloadedFull",
    "FileAccessed","MailItemsAccessed")
| summarize Downloads = count(),
            TotalItems = dcount(ObjectName)
    by AccountUpn, Application, IPAddress, bin(Timestamp, 1h)
| where Downloads > 100 or TotalItems > 50
| order by Downloads desc`,
      },
      {
        table: "DataSecurityEvents",
        columns: ["AccountUpn", "ActionType", "FileName", "SensitivityLabel", "PolicyName"],
        kql: `DataSecurityEvents
| where Timestamp > ago(7d)
| where SensitivityLabel in ("Highly Confidential","Confidential")
| where ActionType in (
    "FileDownloaded","FileCopied","FileAccessed","FileShared")
| project Timestamp, AccountUpn, ActionType,
          FileName, SensitivityLabel, PolicyName`,
      },
    ],
  },

  {
    id: "T1213.002",
    name: "Data from Information Repositories: SharePoint",
    tacticIds: ["TA0009"],
    matrix: "cloud",
    description: "Adversaries search SharePoint Online and Teams wikis for stored credentials, network diagrams, financial data, and intellectual property — accessing a broad set of document libraries that the victim account normally does not visit.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountUpn", "ActionType", "Application", "ObjectName", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where Application in (
    "Microsoft SharePoint Online","Microsoft Teams")
| where ActionType in (
    "SearchQueryPerformed","FileAccessed",
    "PageViewed","FileDownloaded")
// Unusually broad access = adversary trawling
| summarize Sites = dcount(ObjectName), Actions = count()
    by AccountUpn, IPAddress, bin(Timestamp, 1h)
| where Sites > 20 or Actions > 100
| order by Actions desc`,
      },
    ],
  },

  {
    id: "T1114.003",
    name: "Email Collection: Email Forwarding Rule",
    tacticIds: ["TA0009"],
    matrix: "cloud",
    description: "Adversaries create Exchange Online inbox rules that silently forward or redirect all inbound messages to an external address — establishing a persistent mail exfiltration channel that survives password resets and generates no obvious user-visible indicators.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountUpn", "ActionType", "Application", "AdditionalFields"],
        kql: `CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "Microsoft Exchange Online"
| where ActionType in (
    "New-InboxRule","Set-InboxRule","Set-Mailbox",
    "UpdateInboxRules","Add-MailboxPermission")
// Rules that forward or delete incoming mail are always suspicious
| where AdditionalFields has_any (
    "ForwardTo","RedirectTo",
    "ForwardAsAttachmentTo","DeleteMessage",
    "MoveToFolder")
| project Timestamp, AccountUpn, ActionType, AdditionalFields`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(30d)
| where Title has_any (
    "forwarding rule","inbox rule","mail redirect",
    "suspicious inbox rule","email exfiltration")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },

  {
    id: "T1213.003",
    name: "Data from Information Repositories: Code Repositories",
    tacticIds: ["TA0009"],
    matrix: "cloud",
    description: "Adversaries access Azure DevOps, GitHub, or GitLab repositories connected to the Microsoft 365 tenant to steal source code, infrastructure-as-code configs, CI/CD secrets, hardcoded API keys, and deployment pipelines — high-value targets that often contain credentials embedded in code history.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountUpn", "ActionType", "Application", "ObjectName", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where Application in (
    "Azure DevOps","GitHub","GitLab",
    "Microsoft Azure DevOps","GitHub Enterprise")
| where ActionType in (
    "GitRepoCloned","RepoDownloaded","GitPull",
    "GetRepository","SearchRepository","FileAccessed",
    "DownloadFile","ListRepositories")
| summarize Downloads = count(), Repos = dcount(ObjectName)
    by AccountUpn, IPAddress, bin(Timestamp, 1h)
| where Downloads > 20 or Repos > 5
| order by Downloads desc`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where AttackTechniques has "T1213"
    or Title has_any (
      "repository","source code","DevOps","GitHub",
      "code repository","pipeline secret","CI/CD")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },

  // ─── EXFILTRATION ──────────────────────────────────────────────────────────
  {
    id: "T1537",
    name: "Transfer Data to Cloud Account",
    tacticIds: ["TA0010"],
    matrix: "cloud",
    description: "Adversaries exfiltrate data by moving it to cloud accounts they control — personal OneDrive, Dropbox, Google Drive, or an attacker-owned Azure Storage account — blending egress traffic with normal cloud-to-cloud activity.",
    xdrMappings: [
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountUpn", "ActionType", "Application", "IPAddress", "ObjectName"],
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where Application in (
    "Dropbox","Google Drive","Box",
    "Personal OneDrive","GitHub","Pastebin")
    or (ActionType == "SharingSet" and AdditionalFields has "External")
    or ActionType == "FileSyncUploadedFull"
| project Timestamp, AccountUpn, Application,
          ActionType, ObjectName, IPAddress`,
      },
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteUrl", "RemoteIP", "InitiatingProcessFileName"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any (
    "dropbox.com","drive.google.com","box.com",
    "wetransfer.com","mega.nz","anonfiles.com",
    "paste.ee","pastebin.com","gofile.io")
| where RemoteIPType == "Public"
| summarize TotalSent = sum(SentBytes), Sessions = count()
    by DeviceName, RemoteUrl, InitiatingProcessFileName
| where TotalSent > 5000000   // > 5 MB
| order by TotalSent desc`,
      },
    ],
  },

  {
    id: "T1567.002",
    name: "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
    tacticIds: ["TA0010"],
    matrix: "cloud",
    description: "Adversaries exfiltrate data to publicly accessible cloud storage — Azure Blob Storage (public containers), AWS S3 buckets, or third-party file hosts — using HTTP PUT/POST requests that blend with normal web traffic.",
    xdrMappings: [
      {
        table: "DeviceNetworkEvents",
        columns: ["DeviceName", "RemoteUrl", "RemoteIP", "RemotePort", "InitiatingProcessFileName"],
        kql: `DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any (
    "blob.core.windows.net","s3.amazonaws.com",
    "storage.googleapis.com","storageaccounts.net")
| where RemoteIPType == "Public"
| where InitiatingProcessFileName !in~ (
    "OneDrive.exe","MicrosoftEdgeUpdate.exe",
    "WindowsAzureGuestAgent.exe","WaAppAgent.exe")
| summarize TotalSent = sum(SentBytes), Sessions = count()
    by DeviceName, RemoteUrl, InitiatingProcessFileName
| where TotalSent > 10000000   // > 10 MB
| order by TotalSent desc`,
      },
      {
        table: "DataSecurityEvents",
        columns: ["AccountUpn", "ActionType", "FileName", "SensitivityLabel", "PolicyName"],
        kql: `DataSecurityEvents
| where Timestamp > ago(7d)
| where PolicyName != "" or SensitivityLabel != ""
| where ActionType in ("FileUploaded","FileCopied","FileShared")
| project Timestamp, AccountUpn, ActionType,
          FileName, SensitivityLabel, PolicyName`,
      },
    ],
  },

  // ─── IMPACT ────────────────────────────────────────────────────────────────
  {
    id: "T1496",
    name: "Resource Hijacking",
    tacticIds: ["TA0040"],
    matrix: "cloud",
    description: "Adversaries hijack cloud compute capacity for cryptomining — spinning up high-CPU VM SKUs or container clusters after compromising a service principal or cloud console account. Detection relies on sudden unexpected VM provisioning activity.",
    xdrMappings: [
      {
        table: "CloudAuditEvents",
        columns: ["AccountUpn", "ActionType", "ResourceId", "ResourceType", "IPAddress", "AdditionalFields"],
        kql: `CloudAuditEvents
| where Timestamp > ago(7d)
| where ActionType has_any (
    "Microsoft.Compute/virtualMachines/write",
    "Microsoft.Compute/virtualMachineScaleSets/write",
    "Microsoft.ContainerService/managedClusters/write",
    "Microsoft.ContainerInstance/containerGroups/write")
| summarize VMsCreated = count(),
            IPs = make_set(IPAddress, 5)
    by AccountUpn, bin(Timestamp, 1h)
| where VMsCreated > 3
| order by VMsCreated desc`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where AttackTechniques has "T1496"
    or Title has_any (
      "cryptomining","coin miner","resource hijack",
      "compute abuse","suspicious VM creation",
      "crypto","unauthorized subscription usage")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },

  {
    id: "T1531",
    name: "Account Access Removal",
    tacticIds: ["TA0040"],
    matrix: "cloud",
    description: "Adversaries delete or disable cloud accounts, revoke admin roles, or change passwords of legitimate users — locking out defenders and IT administrators as a final disruptive action or as cover during a ransomware deployment.",
    xdrMappings: [
      {
        table: "GraphApiAuditEvents",
        columns: ["AccountUpn", "ActionType", "IPAddress", "TargetResources"],
        kql: `GraphApiAuditEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "Delete user.","Block sign in.",
    "Remove member from role.",
    "Delete application.",
    "Remove service principal credentials.",
    "Update user.")
// Mass account changes = ransomware lockout pattern
| summarize Changes = count()
    by AccountUpn, ActionType, bin(Timestamp, 10m)
| where Changes > 5
| order by Changes desc`,
      },
      {
        table: "IdentityDirectoryEvents",
        columns: ["AccountUpn", "ActionType", "TargetAccountUpn"],
        kql: `IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "User Account disabled","User Account deleted",
    "Password of user account changed",
    "Reset user password")
| summarize Changes = count()
    by AccountUpn, ActionType, bin(Timestamp, 10m)
| where Changes > 5
| order by Changes desc`,
      },
    ],
  },

  {
    id: "T1485",
    name: "Data Destruction",
    tacticIds: ["TA0040"],
    matrix: "cloud",
    description: "Adversaries destroy data stored in Azure Blob Storage, SharePoint Online, Exchange Online, or Azure databases — deleting or overwriting files, mailboxes, and database records as a final disruptive act, often following data theft to prevent recovery and maximize ransom leverage.",
    xdrMappings: [
      {
        table: "CloudAuditEvents",
        columns: ["AccountUpn", "ActionType", "ResourceId", "ResourceType", "IPAddress"],
        kql: `CloudAuditEvents
| where Timestamp > ago(7d)
| where ActionType has_any (
    "Microsoft.Storage/storageAccounts/delete",
    "Microsoft.Storage/storageAccounts/blobServices/containers/delete",
    "Microsoft.Sql/servers/databases/delete",
    "Microsoft.DocumentDB/databaseAccounts/delete",
    "Microsoft.RecoveryServices/vaults/backupFabrics/delete")
| summarize Deletions = count(), Resources = make_set(ResourceId, 10)
    by AccountUpn, ResourceType, bin(Timestamp, 1h)
| order by Deletions desc`,
      },
      {
        table: "CloudAppEvents",
        columns: ["AccountObjectId", "AccountUpn", "ActionType", "Application", "ObjectName", "IPAddress"],
        kql: `CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in (
    "FileDeleted","FilePermanentlyDeleted",
    "SiteDeleted","FolderDeleted",
    "HardDelete","PurgedItems","MoveToDeletedItems")
| summarize Deletions = count(), Files = dcount(ObjectName)
    by AccountUpn, Application, IPAddress, bin(Timestamp, 1h)
| where Deletions > 50 or Files > 30
| order by Deletions desc`,
      },
    ],
  },

  {
    id: "T1486",
    name: "Data Encrypted for Impact",
    tacticIds: ["TA0040"],
    matrix: "cloud",
    description: "Adversaries encrypt data across Azure storage, virtual machine disks, databases, and Microsoft 365 workloads — rendering cloud resources inaccessible for ransom. Cloud-aware ransomware variants target Azure Blob Storage SAS tokens, SharePoint, and backup vaults to maximize impact.",
    xdrMappings: [
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where AttackTechniques has "T1486"
    or Title has_any (
      "ransomware","encrypt","ransom","data encrypted",
      "file encrypted","BitLocker","backup deleted",
      "recovery point deleted","vault deleted")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
      {
        table: "CloudAuditEvents",
        columns: ["AccountUpn", "ActionType", "ResourceId", "ResourceType", "IPAddress"],
        kql: `// Ransomware prep: deleting backups before encryption
CloudAuditEvents
| where Timestamp > ago(7d)
| where ActionType has_any (
    "Microsoft.RecoveryServices/vaults/delete",
    "Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems/delete",
    "Microsoft.RecoveryServices/vaults/backupPolicies/delete",
    "microsoft.backup/backupVaults/delete",
    "Microsoft.Compute/snapshots/delete")
| project Timestamp, AccountUpn, ActionType,
          ResourceId, ResourceType, IPAddress`,
      },
    ],
  },

  {
    id: "T1489",
    name: "Service Stop",
    tacticIds: ["TA0040"],
    matrix: "cloud",
    description: "Adversaries stop or disable cloud services — shutting down VMs, disabling Azure App Services, stopping Azure SQL databases, or pausing Logic Apps — to cause service outages, disrupt business operations, or remove defensive capabilities prior to a destructive action.",
    xdrMappings: [
      {
        table: "CloudAuditEvents",
        columns: ["AccountUpn", "ActionType", "ResourceId", "ResourceType", "IPAddress"],
        kql: `CloudAuditEvents
| where Timestamp > ago(7d)
| where ActionType has_any (
    "Microsoft.Compute/virtualMachines/deallocate/action",
    "Microsoft.Compute/virtualMachines/powerOff/action",
    "Microsoft.Web/sites/stop/action",
    "Microsoft.Sql/servers/databases/pause/action",
    "Microsoft.Logic/workflows/disable/action",
    "Microsoft.Automation/automationAccounts/webhooks/action",
    "Microsoft.Security/pricings/write")
| summarize Stops = count(), Services = make_set(ResourceType, 10)
    by AccountUpn, IPAddress, bin(Timestamp, 1h)
| where Stops > 3
| order by Stops desc`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where AttackTechniques has "T1489"
    or Title has_any (
      "service stopped","service disabled","VM stopped",
      "resource stopped","workload stopped","Defender disabled")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },

  {
    id: "T1491.002",
    name: "Defacement: External Defacement",
    tacticIds: ["TA0040"],
    matrix: "cloud",
    description: "Adversaries modify or replace publicly accessible cloud-hosted content — Azure Static Web Apps, Azure Blob Storage public containers, Azure App Service web apps — to display attacker-controlled messages, damaging the organisation's reputation or signaling a successful breach.",
    xdrMappings: [
      {
        table: "CloudAuditEvents",
        columns: ["AccountUpn", "ActionType", "ResourceId", "ResourceType", "IPAddress"],
        kql: `CloudAuditEvents
| where Timestamp > ago(7d)
| where ActionType has_any (
    "Microsoft.Web/sites/write",
    "Microsoft.Storage/storageAccounts/blobServices/containers/write",
    "Microsoft.Cdn/profiles/endpoints/write",
    "Microsoft.Network/frontDoors/write")
// Unexpected changes to web/CDN resources
| project Timestamp, AccountUpn, ActionType,
          ResourceId, ResourceType, IPAddress`,
      },
      {
        table: "AlertInfo",
        columns: ["AlertId", "Title", "Severity", "Category", "AttackTechniques"],
        kql: `AlertInfo
| where Timestamp > ago(7d)
| where AttackTechniques has "T1491"
    or Title has_any (
      "defacement","web content modified","page replaced",
      "static web app","CDN content")
| project Timestamp, AlertId, Title, Severity, Category`,
      },
    ],
  },

];

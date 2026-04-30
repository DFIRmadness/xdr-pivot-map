export const TABLES = [
  // ── Endpoint (MDE) ───────────────────────────────────────────────────────────
  { id: "DeviceInfo",                             domain: "endpoint",  desc: "Machine info, OS version, active users, internet exposure" },
  { id: "DeviceProcessEvents",                    domain: "endpoint",  desc: "Process creation and related events" },
  { id: "DeviceNetworkEvents",                    domain: "endpoint",  desc: "Network connections from endpoints" },
  { id: "DeviceFileEvents",                       domain: "endpoint",  desc: "File create / modify / delete events" },
  { id: "DeviceRegistryEvents",                   domain: "endpoint",  desc: "Registry key creates and modifications" },
  { id: "DeviceLogonEvents",                      domain: "endpoint",  desc: "Sign-ins and auth events on devices" },
  { id: "DeviceEvents",                           domain: "endpoint",  desc: "Misc: AV, exploit protection, ASR events" },
  { id: "DeviceImageLoadEvents",                  domain: "endpoint",  desc: "DLL / module load events" },
  { id: "DeviceFileCertificateInfo",              domain: "endpoint",  desc: "Cert info of signed files on endpoints" },
  { id: "DeviceNetworkInfo",                      domain: "endpoint",  desc: "NIC info, IPs, MACs, connected networks" },

  // ── Identity (MDI / Entra) ────────────────────────────────────────────────────
  { id: "IdentityInfo",                           domain: "identity",  desc: "Account info from Entra ID and other sources" },
  { id: "IdentityLogonEvents",                    domain: "identity",  desc: "Auth events on AD and Microsoft online services" },
  { id: "IdentityDirectoryEvents",                domain: "identity",  desc: "AD DC events: queries, object modifications" },
  { id: "IdentityQueryEvents",                    domain: "identity",  desc: "LDAP / AD object queries" },
  { id: "EntraIdSignInEvents",                    domain: "identity",  desc: "Entra interactive and non-interactive sign-ins (replaces AADSignInEventsBeta)" },
  { id: "EntraIdSpnSignInEvents",                 domain: "identity",  desc: "Service principal and managed identity sign-ins" },
  { id: "AADSignInEventsBeta",                    domain: "identity",  desc: "Legacy Entra interactive and non-interactive sign-in events.", deprecated: true, replacedBy: "EntraIdSignInEvents" },
  { id: "GraphApiAuditEvents",                    domain: "identity",  desc: "Graph API calls made against the tenant" },
  { id: "IdentityAccountInfo",                    domain: "identity",  desc: "Account info with link to owning identity" },

  // ── Email (MDO) ───────────────────────────────────────────────────────────────
  { id: "EmailEvents",                            domain: "email",     desc: "M365 email delivery and blocking events" },
  { id: "EmailAttachmentInfo",                    domain: "email",     desc: "File attachments associated with emails" },
  { id: "EmailUrlInfo",                           domain: "email",     desc: "URLs extracted from email bodies" },
  { id: "EmailPostDeliveryEvents",                domain: "email",     desc: "Post-delivery security events on emails" },
  { id: "UrlClickEvents",                         domain: "email",     desc: "Safe Links clicks from email, Teams, O365" },
  { id: "CampaignInfo",                           domain: "email",     desc: "Email campaigns identified by MDO", preview: true },

  // ── Teams (MDO) ───────────────────────────────────────────────────────────────
  { id: "MessageEvents",                          domain: "teams",     desc: "Teams messages at time of delivery — Teams equivalent of EmailEvents" },
  { id: "MessagePostDeliveryEvents",              domain: "teams",     desc: "Post-delivery security actions on Teams messages (ZAP etc.)" },
  { id: "MessageUrlInfo",                         domain: "teams",     desc: "URLs extracted from Teams messages" },

  // ── Cloud (MDCA / Defender for Cloud) ─────────────────────────────────────────
  { id: "CloudAppEvents",                         domain: "cloud",     desc: "Activity in O365 and other cloud apps" },
  { id: "CloudAuditEvents",                       domain: "cloud",     desc: "Cloud platform audit events (Defender for Cloud)", preview: true },
  { id: "CloudProcessEvents",                     domain: "cloud",     desc: "Process events in cloud container workloads (AKS/EKS/GKE)", preview: true },
  { id: "CloudDnsEvents",                         domain: "cloud",     desc: "DNS activity in cloud infrastructure", preview: true },

  // ── Alerts ────────────────────────────────────────────────────────────────────
  { id: "AlertInfo",                              domain: "alerts",    desc: "Alerts from MDE, MDO, MDCA, MDI with severity" },
  { id: "AlertEvidence",                          domain: "alerts",    desc: "Files, IPs, URLs, users, devices linked to alerts" },

  // ── Vulnerability Management (TVM) ───────────────────────────────────────────
  { id: "DeviceTvmSoftwareInventory",             domain: "tvm",       desc: "Installed software and version info" },
  { id: "DeviceTvmSoftwareVulnerabilities",       domain: "tvm",       desc: "CVEs found on devices" },
  { id: "DeviceTvmSecureConfigurationAssessment", domain: "tvm",       desc: "Security config status on devices" },
  { id: "DeviceTvmHardwareFirmware",              domain: "tvm",       desc: "Hardware and firmware inventory for supply chain risk" },
  { id: "DeviceTvmBrowserExtensions",             domain: "tvm",       desc: "Browser extension inventory — malicious extension persistence", preview: true },
  { id: "DeviceTvmCertificateInfo",               domain: "tvm",       desc: "Certificate inventory from TVM", preview: true },

  // ── Purview (IRM / DLP) ───────────────────────────────────────────────────────
  { id: "DataSecurityEvents",                     domain: "purview",   desc: "User activities violating Purview DLP / IRM policies", preview: true },

  // ── Behaviors / UEBA ─────────────────────────────────────────────────────────
  { id: "BehaviorInfo",                           domain: "behaviors", desc: "UEBA anomaly behaviors — correlated across multiple signals", preview: true },
  { id: "BehaviorEntities",                       domain: "behaviors", desc: "Entities (devices, users, files) linked to UEBA behaviors", preview: true },

  // ── Security Exposure Management ──────────────────────────────────────────────
  { id: "ExposureGraphNodes",                     domain: "exposure",  desc: "Attack surface entity nodes — devices, identities, cloud assets" },
  { id: "ExposureGraphEdges",                     domain: "exposure",  desc: "Attack path relationships between exposure graph entities" },

  // ── Azure Sentinel / Log Analytics ────────────────────────────────────────
  { id: "SigninLogs",                             domain: "azure",     azure: true, desc: "Entra ID sign-ins via Azure Monitor. AuthenticationProtocol == 'deviceCode' is the primary filter for device code phishing hunts." },
  { id: "OfficeActivity",                         domain: "azure",     azure: true, desc: "Exchange, SharePoint, OneDrive, and Teams audit logs from Azure Monitor. Pre-migration equivalent of CloudAppEvents for Sentinel-based environments." },
];

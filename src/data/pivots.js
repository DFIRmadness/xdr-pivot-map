// Complete schema-level pivot map for Microsoft Defender XDR Advanced Hunting.
// Every meaningful table-to-table join is listed here, regardless of whether
// it appears in a named use case.
//
// tier:
//   "high" — primary hunting pivots; core to most investigations
//   "mid"  — useful but more situational
//   "low"  — valid joins, narrow or low-frequency hunting scenarios

export const PIVOT_EDGES = [

  // ─── ALERT TABLES ─────────────────────────────────────────────────────────

  { source: "AlertInfo",        target: "AlertEvidence",          cols: ["AlertId"],                                    tier: "high" },
  { source: "AlertEvidence",    target: "DeviceInfo",             cols: ["DeviceId", "DeviceName"],                     tier: "high" },
  { source: "AlertEvidence",    target: "DeviceProcessEvents",    cols: ["SHA256", "SHA1", "FileName", "DeviceId"],     tier: "high" },
  { source: "AlertEvidence",    target: "DeviceFileEvents",       cols: ["SHA256", "SHA1", "DeviceId"],                 tier: "high" },
  { source: "AlertEvidence",    target: "DeviceNetworkEvents",    cols: ["RemoteIP"],                                   tier: "high" },
  { source: "AlertEvidence",    target: "EntraIdSignInEvents",    cols: ["AccountUpn", "AccountObjectId"],              tier: "high" },
  { source: "AlertEvidence",    target: "CloudAppEvents",         cols: ["AccountUpn", "AccountObjectId"],              tier: "high" },
  { source: "AlertEvidence",    target: "EmailEvents",            cols: ["NetworkMessageId"],                           tier: "high" },
  { source: "AlertEvidence",    target: "IdentityLogonEvents",    cols: ["AccountUpn", "DeviceId", "DeviceName"],       tier: "mid"  },
  { source: "AlertEvidence",    target: "IdentityInfo",           cols: ["AccountObjectId", "AccountUpn"],              tier: "mid"  },
  { source: "AlertEvidence",    target: "GraphApiAuditEvents",    cols: ["AccountUpn", "AccountObjectId"],              tier: "mid"  },
  { source: "AlertEvidence",    target: "IdentityDirectoryEvents",cols: ["AccountUpn"],                                 tier: "mid"  },
  { source: "AlertEvidence",    target: "DeviceLogonEvents",      cols: ["AccountUpn", "DeviceId"],                     tier: "mid"  },
  { source: "AlertEvidence",    target: "DeviceRegistryEvents",   cols: ["RegistryKey"],                                tier: "mid"  },
  { source: "AlertEvidence",    target: "DeviceEvents",           cols: ["DeviceId", "SHA1", "RegistryKey"],            tier: "mid"  },
  { source: "AlertEvidence",    target: "EmailAttachmentInfo",    cols: ["SHA256", "NetworkMessageId"],                 tier: "mid"  },
  { source: "AlertEvidence",    target: "UrlClickEvents",         cols: ["AccountUpn", "NetworkMessageId"],             tier: "mid"  },
  { source: "AlertEvidence",    target: "CloudAuditEvents",       cols: ["AccountUpn"],                                 tier: "mid"  },
  { source: "AlertEvidence",    target: "DataSecurityEvents",     cols: ["AccountUpn", "NetworkMessageId"],             tier: "low"  },
  { source: "AlertEvidence",    target: "BehaviorEntities",       cols: ["EntityType", "EvidenceRole", "SHA256"],       tier: "low"  },
  { source: "AlertEvidence",    target: "DeviceImageLoadEvents",  cols: ["SHA1", "DeviceId"],                           tier: "low"  },
  { source: "AlertInfo",        target: "BehaviorInfo",           cols: ["Title", "Category"],                          tier: "low"  },

  // ─── BEHAVIOR / UEBA TABLES ────────────────────────────────────────────────

  { source: "BehaviorInfo",     target: "BehaviorEntities",       cols: ["BehaviorId"],                                 tier: "high" },
  { source: "BehaviorEntities", target: "DeviceInfo",             cols: ["DeviceId"],                                   tier: "mid"  },
  { source: "BehaviorEntities", target: "DeviceProcessEvents",    cols: ["DeviceId"],                                   tier: "mid"  },
  { source: "BehaviorEntities", target: "IdentityInfo",           cols: ["AccountObjectId"],                            tier: "mid"  },
  { source: "BehaviorEntities", target: "EntraIdSignInEvents",    cols: ["AccountObjectId", "AccountUpn"],              tier: "mid"  },
  { source: "BehaviorEntities", target: "AlertEvidence",          cols: ["EntityType", "EvidenceRole"],                 tier: "low"  },

  // ─── CLOUD APP / AUDIT / PROCESS ──────────────────────────────────────────

  { source: "CloudAppEvents",   target: "EntraIdSignInEvents",    cols: ["AccountUpn", "AccountObjectId"],              tier: "high" },
  { source: "CloudAppEvents",   target: "GraphApiAuditEvents",    cols: ["AccountUpn", "AccountObjectId"],              tier: "high" },
  { source: "CloudAuditEvents", target: "CloudProcessEvents",     cols: ["ResourceId", "DeviceId"],                     tier: "high" },
  { source: "CloudAppEvents",   target: "CloudAuditEvents",       cols: ["AccountUpn", "AccountObjectId"],              tier: "mid"  },
  { source: "CloudAppEvents",   target: "IdentityInfo",           cols: ["AccountObjectId"],                            tier: "mid"  },
  { source: "CloudAppEvents",   target: "IdentityLogonEvents",    cols: ["AccountUpn", "IPAddress"],                    tier: "mid"  },
  { source: "CloudAppEvents",   target: "IdentityDirectoryEvents",cols: ["AccountUpn"],                                 tier: "mid"  },
  { source: "CloudAppEvents",   target: "DataSecurityEvents",     cols: ["AccountUpn", "NetworkMessageId"],             tier: "mid"  },
  { source: "CloudAuditEvents", target: "EntraIdSignInEvents",    cols: ["AccountUpn", "AccountObjectId"],              tier: "mid"  },
  { source: "CloudAuditEvents", target: "GraphApiAuditEvents",    cols: ["AccountUpn", "AccountObjectId"],              tier: "mid"  },
  { source: "CloudAuditEvents", target: "IdentityInfo",           cols: ["AccountObjectId"],                            tier: "mid"  },
  { source: "CloudProcessEvents",target: "DeviceNetworkEvents",   cols: ["DeviceId"],                                   tier: "mid"  },
  { source: "CloudProcessEvents",target: "DeviceProcessEvents",   cols: ["DeviceId"],                                   tier: "mid"  },
  { source: "CloudDnsEvents",   target: "DeviceNetworkEvents",    cols: ["DeviceId", "RemoteUrl"],                      tier: "mid"  },
  { source: "CloudAppEvents",   target: "DeviceLogonEvents",      cols: ["AccountUpn"],                                 tier: "low"  },
  { source: "CloudAuditEvents", target: "IdentityDirectoryEvents",cols: ["AccountUpn"],                                 tier: "low"  },
  { source: "EntraIdSpnSignInEvents", target: "CloudAppEvents",   cols: ["AccountObjectId"],                            tier: "mid"  },
  { source: "EntraIdSpnSignInEvents", target: "CloudAuditEvents", cols: ["AccountObjectId"],                            tier: "mid"  },
  { source: "EntraIdSpnSignInEvents", target: "EntraIdSignInEvents", cols: ["AccountObjectId", "ApplicationId"],        tier: "mid"  },

  // ─── DEVICE CORE EVENT TABLES ─────────────────────────────────────────────

  { source: "DeviceInfo",       target: "DeviceProcessEvents",    cols: ["DeviceId", "DeviceName"],                     tier: "high" },
  { source: "DeviceInfo",       target: "DeviceNetworkEvents",    cols: ["DeviceId", "DeviceName"],                     tier: "high" },
  { source: "DeviceInfo",       target: "DeviceFileEvents",       cols: ["DeviceId", "DeviceName"],                     tier: "high" },
  { source: "DeviceInfo",       target: "DeviceLogonEvents",      cols: ["DeviceId", "DeviceName"],                     tier: "high" },
  { source: "DeviceInfo",       target: "DeviceNetworkInfo",      cols: ["DeviceId", "DeviceName"],                     tier: "high" },
  { source: "DeviceInfo",       target: "DeviceTvmSoftwareVulnerabilities", cols: ["DeviceId"],                         tier: "high" },
  { source: "DeviceInfo",       target: "DeviceTvmSoftwareInventory",       cols: ["DeviceId"],                         tier: "mid"  },
  { source: "DeviceInfo",       target: "DeviceTvmSecureConfigurationAssessment", cols: ["DeviceId"],                   tier: "mid"  },
  { source: "DeviceInfo",       target: "DeviceRegistryEvents",   cols: ["DeviceId"],                                   tier: "mid"  },
  { source: "DeviceInfo",       target: "DeviceEvents",           cols: ["DeviceId"],                                   tier: "mid"  },
  { source: "DeviceInfo",       target: "DeviceImageLoadEvents",  cols: ["DeviceId"],                                   tier: "low"  },
  { source: "DeviceInfo",       target: "DeviceFileCertificateInfo", cols: ["DeviceId"],                                tier: "low"  },
  { source: "DeviceInfo",       target: "DeviceTvmBrowserExtensions", cols: ["DeviceId"],                              tier: "low"  },
  { source: "DeviceInfo",       target: "DeviceTvmHardwareFirmware",  cols: ["DeviceId"],                              tier: "low"  },
  { source: "DeviceInfo",       target: "DeviceTvmCertificateInfo",   cols: ["DeviceId"],                              tier: "low"  },
  { source: "DeviceInfo",       target: "ExposureGraphNodes",     cols: ["DeviceId"],                                   tier: "low"  },
  { source: "DeviceInfo",       target: "BehaviorInfo",           cols: ["DeviceId"],                                   tier: "low"  },

  { source: "DeviceProcessEvents", target: "DeviceNetworkEvents", cols: ["DeviceId", "LogonId"],                        tier: "high" },
  { source: "DeviceProcessEvents", target: "DeviceFileEvents",    cols: ["DeviceId", "LogonId", "SHA256"],              tier: "high" },
  { source: "DeviceProcessEvents", target: "DeviceLogonEvents",   cols: ["DeviceId", "LogonId"],                        tier: "high" },
  { source: "DeviceProcessEvents", target: "DeviceRegistryEvents",cols: ["DeviceId", "LogonId"],                        tier: "high" },
  { source: "DeviceProcessEvents", target: "DeviceFileCertificateInfo", cols: ["SHA1", "DeviceId"],                     tier: "high" },
  { source: "DeviceProcessEvents", target: "DeviceEvents",        cols: ["DeviceId", "LogonId"],                        tier: "mid"  },
  { source: "DeviceProcessEvents", target: "DeviceImageLoadEvents",cols: ["DeviceId", "LogonId"],                       tier: "mid"  },
  { source: "DeviceProcessEvents", target: "IdentityLogonEvents", cols: ["AccountUpn", "DeviceName"],                   tier: "mid"  },
  { source: "DeviceProcessEvents", target: "DeviceTvmSoftwareVulnerabilities", cols: ["DeviceId"],                      tier: "mid"  },
  { source: "DeviceProcessEvents", target: "CloudProcessEvents",  cols: ["DeviceId"],                                   tier: "mid"  },

  { source: "DeviceNetworkEvents", target: "DeviceNetworkInfo",   cols: ["DeviceId"],                                   tier: "high" },
  { source: "DeviceNetworkEvents", target: "DeviceLogonEvents",   cols: ["DeviceId", "LogonId"],                        tier: "high" },
  { source: "DeviceNetworkEvents", target: "DeviceFileEvents",    cols: ["DeviceId", "LogonId"],                        tier: "mid"  },
  { source: "DeviceNetworkEvents", target: "DeviceRegistryEvents",cols: ["DeviceId", "LogonId"],                        tier: "low"  },
  { source: "DeviceNetworkEvents", target: "DeviceEvents",        cols: ["DeviceId", "LogonId"],                        tier: "mid"  },
  { source: "DeviceNetworkEvents", target: "UrlClickEvents",      cols: ["RemoteUrl"],                                  tier: "mid"  },

  { source: "DeviceFileEvents", target: "DeviceLogonEvents",      cols: ["DeviceId", "LogonId"],                        tier: "high" },
  { source: "DeviceFileEvents", target: "DeviceFileCertificateInfo", cols: ["SHA1", "DeviceId"],                        tier: "high" },
  { source: "DeviceFileEvents", target: "EmailAttachmentInfo",    cols: ["SHA256"],                                     tier: "high" },
  { source: "DeviceFileEvents", target: "DeviceRegistryEvents",   cols: ["DeviceId", "LogonId"],                        tier: "mid"  },
  { source: "DeviceFileEvents", target: "DeviceEvents",           cols: ["DeviceId", "LogonId"],                        tier: "mid"  },
  { source: "DeviceFileEvents", target: "DeviceImageLoadEvents",  cols: ["DeviceId", "SHA1"],                           tier: "mid"  },
  { source: "DeviceFileEvents", target: "DataSecurityEvents",     cols: ["AccountUpn", "SensitivityLabel"],             tier: "mid"  },
  { source: "DeviceFileEvents", target: "DeviceTvmSoftwareVulnerabilities", cols: ["DeviceId"],                         tier: "low"  },

  { source: "DeviceLogonEvents", target: "IdentityLogonEvents",   cols: ["AccountUpn", "DeviceName"],                   tier: "high" },
  { source: "DeviceLogonEvents", target: "DeviceRegistryEvents",  cols: ["DeviceId", "LogonId"],                        tier: "mid"  },
  { source: "DeviceLogonEvents", target: "DeviceEvents",          cols: ["DeviceId", "LogonId"],                        tier: "mid"  },
  { source: "DeviceLogonEvents", target: "IdentityInfo",          cols: ["AccountUpn", "AccountObjectId"],              tier: "mid"  },
  { source: "DeviceLogonEvents", target: "EntraIdSignInEvents",   cols: ["AccountUpn", "IPAddress"],                    tier: "mid"  },

  { source: "DeviceRegistryEvents", target: "DeviceEvents",       cols: ["DeviceId", "LogonId"],                        tier: "mid"  },
  { source: "DeviceRegistryEvents", target: "DeviceImageLoadEvents", cols: ["DeviceId"],                                tier: "low"  },

  { source: "DeviceImageLoadEvents", target: "DeviceFileCertificateInfo", cols: ["SHA1", "DeviceId"],                   tier: "mid"  },

  { source: "DeviceNetworkInfo", target: "DeviceProcessEvents",   cols: ["DeviceId"],                                   tier: "mid"  },
  { source: "DeviceNetworkInfo", target: "DeviceLogonEvents",     cols: ["DeviceId"],                                   tier: "mid"  },

  // ─── TVM TABLES ────────────────────────────────────────────────────────────

  { source: "DeviceTvmSoftwareVulnerabilities", target: "DeviceTvmSoftwareInventory", cols: ["DeviceId", "SoftwareName"], tier: "high" },
  { source: "DeviceTvmSoftwareVulnerabilities", target: "DeviceTvmSecureConfigurationAssessment", cols: ["DeviceId"],   tier: "mid"  },
  { source: "DeviceTvmSoftwareInventory",       target: "DeviceTvmSecureConfigurationAssessment", cols: ["DeviceId"],   tier: "low"  },
  { source: "DeviceTvmBrowserExtensions",       target: "DeviceTvmSoftwareInventory",  cols: ["DeviceId"],              tier: "low"  },
  { source: "DeviceTvmCertificateInfo",         target: "DeviceFileCertificateInfo",   cols: ["DeviceId"],              tier: "low"  },

  // ─── EMAIL TABLES ──────────────────────────────────────────────────────────

  { source: "EmailEvents",          target: "EmailAttachmentInfo",    cols: ["NetworkMessageId"],                        tier: "high" },
  { source: "EmailEvents",          target: "EmailUrlInfo",           cols: ["NetworkMessageId"],                        tier: "high" },
  { source: "EmailEvents",          target: "EmailPostDeliveryEvents",cols: ["NetworkMessageId", "RecipientEmailAddress"],tier: "high" },
  { source: "EmailEvents",          target: "UrlClickEvents",         cols: ["NetworkMessageId", "AccountUpn"],          tier: "high" },
  { source: "EmailEvents",          target: "CampaignInfo",           cols: ["CampaignId"],                              tier: "high" },
  { source: "EmailEvents",          target: "IdentityInfo",           cols: ["SenderObjectId", "RecipientEmailAddress"], tier: "mid"  },
  { source: "EmailEvents",          target: "EntraIdSignInEvents",    cols: ["SenderObjectId"],                          tier: "mid"  },
  { source: "EmailAttachmentInfo",  target: "EmailUrlInfo",           cols: ["NetworkMessageId"],                        tier: "mid"  },
  { source: "EmailAttachmentInfo",  target: "EmailPostDeliveryEvents",cols: ["NetworkMessageId", "RecipientEmailAddress"],tier: "mid"  },
  { source: "EmailAttachmentInfo",  target: "UrlClickEvents",         cols: ["NetworkMessageId"],                        tier: "mid"  },
  { source: "EmailUrlInfo",         target: "UrlClickEvents",         cols: ["Url", "NetworkMessageId"],                 tier: "high" },
  { source: "EmailUrlInfo",         target: "EmailPostDeliveryEvents",cols: ["NetworkMessageId"],                        tier: "mid"  },
  { source: "EmailPostDeliveryEvents", target: "UrlClickEvents",      cols: ["NetworkMessageId"],                        tier: "mid"  },
  { source: "UrlClickEvents",       target: "EntraIdSignInEvents",    cols: ["AccountUpn"],                              tier: "high" },
  { source: "UrlClickEvents",       target: "DeviceNetworkEvents",    cols: ["Url"],                                     tier: "mid"  },
  { source: "UrlClickEvents",       target: "DeviceProcessEvents",    cols: ["AccountUpn"],                              tier: "mid"  },

  // ─── TEAMS TABLES ──────────────────────────────────────────────────────────

  { source: "MessageEvents",        target: "MessageUrlInfo",         cols: ["NetworkMessageId"],                        tier: "high" },
  { source: "MessageEvents",        target: "MessagePostDeliveryEvents", cols: ["NetworkMessageId"],                     tier: "high" },
  { source: "MessageUrlInfo",       target: "UrlClickEvents",         cols: ["Url", "NetworkMessageId"],                 tier: "high" },
  { source: "MessageUrlInfo",       target: "EmailUrlInfo",           cols: ["UrlDomain"],                               tier: "mid"  },
  { source: "MessagePostDeliveryEvents", target: "MessageUrlInfo",    cols: ["NetworkMessageId"],                        tier: "mid"  },
  { source: "MessageEvents",        target: "EmailEvents",            cols: ["NetworkMessageId"],                        tier: "mid"  },

  // ─── IDENTITY TABLES ───────────────────────────────────────────────────────

  { source: "EntraIdSignInEvents",  target: "IdentityLogonEvents",    cols: ["AccountUpn", "IPAddress"],                 tier: "high" },
  { source: "EntraIdSignInEvents",  target: "GraphApiAuditEvents",    cols: ["AccountUpn", "AccountObjectId"],           tier: "high" },
  { source: "EntraIdSignInEvents",  target: "IdentityInfo",           cols: ["AccountObjectId"],                         tier: "high" },
  { source: "EntraIdSignInEvents",  target: "IdentityDirectoryEvents",cols: ["AccountUpn"],                              tier: "mid"  },
  { source: "IdentityInfo",         target: "IdentityLogonEvents",    cols: ["AccountObjectId", "AccountUpn"],           tier: "high" },
  { source: "IdentityInfo",         target: "IdentityDirectoryEvents",cols: ["AccountObjectId", "AccountUpn"],           tier: "mid"  },
  { source: "IdentityInfo",         target: "IdentityQueryEvents",    cols: ["AccountUpn"],                              tier: "mid"  },
  { source: "IdentityInfo",         target: "GraphApiAuditEvents",    cols: ["AccountObjectId"],                         tier: "mid"  },
  { source: "IdentityInfo",         target: "IdentityAccountInfo",    cols: ["AccountObjectId", "OnPremSid"],            tier: "mid"  },
  { source: "IdentityInfo",         target: "DataSecurityEvents",     cols: ["AccountObjectId"],                         tier: "low"  },
  { source: "IdentityLogonEvents",  target: "IdentityDirectoryEvents",cols: ["AccountUpn"],                              tier: "high" },
  { source: "IdentityLogonEvents",  target: "IdentityQueryEvents",    cols: ["AccountUpn", "IPAddress"],                 tier: "high" },
  { source: "IdentityLogonEvents",  target: "GraphApiAuditEvents",    cols: ["AccountUpn"],                              tier: "mid"  },
  { source: "IdentityLogonEvents",  target: "DeviceProcessEvents",    cols: ["AccountUpn", "DeviceName"],                tier: "mid"  },
  { source: "IdentityDirectoryEvents", target: "IdentityQueryEvents", cols: ["AccountUpn", "Protocol"],                  tier: "mid"  },
  { source: "IdentityDirectoryEvents", target: "GraphApiAuditEvents", cols: ["AccountUpn"],                              tier: "high" },
  { source: "IdentityAccountInfo",  target: "IdentityLogonEvents",    cols: ["AccountObjectId", "AccountUpn"],           tier: "mid"  },
  { source: "IdentityAccountInfo",  target: "EntraIdSignInEvents",    cols: ["AccountObjectId"],                         tier: "mid"  },
  { source: "AADSignInEventsBeta",  target: "EntraIdSignInEvents",    cols: ["AccountUpn", "AccountObjectId"],           tier: "low"  },

  // ─── PURVIEW / DATA ────────────────────────────────────────────────────────

  { source: "DataSecurityEvents",   target: "EmailEvents",            cols: ["NetworkMessageId", "AccountUpn"],          tier: "mid"  },
  { source: "DataSecurityEvents",   target: "IdentityInfo",           cols: ["AccountObjectId"],                         tier: "low"  },

  // ─── EXPOSURE GRAPH ────────────────────────────────────────────────────────

  { source: "ExposureGraphNodes",   target: "ExposureGraphEdges",     cols: ["NodeId"],                                  tier: "high" },
  { source: "ExposureGraphNodes",   target: "DeviceInfo",             cols: ["DeviceId"],                                tier: "mid"  },
  { source: "ExposureGraphNodes",   target: "IdentityInfo",           cols: ["AccountObjectId"],                         tier: "mid"  },

];

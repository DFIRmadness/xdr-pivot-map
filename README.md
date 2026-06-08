# Microsoft Defender XDR Pivot Map

Claude and I created a thing. I prefer the term, "Compose Coded".

Interactive threat hunting and incident response reference tools for Microsoft Defender XDR. Built for security analysts who live in Advanced Hunting.

**Live site:** [dfirmadness.github.io/DefenderXDR-pivot-map](https://dfirmadness.github.io/DefenderXDR-pivot-map)

> **Disclaimer:** This project is not a Microsoft product and is not endorsed by, affiliated with, or supported by Microsoft in any way. Microsoft, Microsoft Defender, and Microsoft Defender XDR are trademarks of Microsoft Corporation. All schema and documentation references are sourced from publicly available Microsoft Learn documentation.

---

## Tools

### XDR Advanced Hunting Pivot Map
Force-directed graph of Defender XDR table relationships. Select a hunt scenario — phishing, lateral movement, credential access, AiTM, BEC fraud, and more — and the graph highlights the relevant table chain. Click investigation steps to spotlight individual tables and surface KQL queries for each pivot.

- 45 tables across 7 domains (endpoint, identity, email, cloud, alerts, TVM, Purview)
- 12 threat hunt scenarios
- Schema-level pivot edges tiered by hunting value (high / mid / low)
- Linkable node identifiers with animated rings for common pivot columns (AccountObjectId, SessionId, NetworkMessageId, etc.)

### Tables for Muggles
Plain-English guide to every Defender XDR table. Explains where each table's data comes from, what it means operationally, and which columns matter most for IR and threat hunting — without assuming you already know the schema.

- 47 tables with plain-English descriptions and IR context
- Full-schema column search: find any table that contains a column by name
- Key column annotations with DFIR notes
- Topic filters and alphabetical sort

### Incident Roadmaps
Ordered investigation paths for five pivot types (Email, Device, Identity, Malware, IP) and five attack scenarios (AiTM session hijacking, BEC wire fraud, OAuth device code phishing, info stealer, ClickFix clipboard hijack). Each stop shows what to look for, which columns to pivot on, and a ready-to-run KQL query.

- 10 roadmaps (5 pivot + 5 scenario)
- 70+ investigation stops
- Opening triage step (AlertInfo/AlertEvidence) and closing detection gap analysis on every scenario

### MITRE ATT&CK × Defender XDR Crosswalk
Browse Enterprise and Cloud tactics and techniques mapped to the Defender XDR tables and columns that surface them, with KQL hunting queries for each technique.

- 14 MITRE ATT&CK Enterprise tactics, 40+ techniques
- 53 ATT&CK Cloud techniques
- Every column and query verified against the published MS Learn schema

### KQL Cheat Sheet
Quick reference for Kusto operators, time functions, joins, type casting, and JSON parsing patterns. Includes MailItemsAccessed expand patterns for tracking attacker email recon and CloudAuditEvents RawEventData patterns for ARM/Azure pivots.

- 8 operator categories
- 12 JSON parsing patterns
- Copy-ready KQL

### Obsidian Canvas & Cheat Sheet Exports
Download the pivot map and investigation roadmaps as Obsidian Canvas (`.canvas`) files for offline use, annotation, and extension inside your vault.

---

## Running locally

```bash
npm install
npm run dev      # http://localhost:4321/DefenderXDR-pivot-map
npm run build    # static output to /dist
npm run preview  # preview production build
```

Requires Node 24+.

---

## Stack

- [Astro 6](https://astro.build) — static site framework and routing
- [React 19](https://react.dev) — interactive components (client:only islands)
- [D3 7](https://d3js.org) — force-directed graph rendering
- GitHub Actions + GitHub Pages — CI/CD and hosting

All data is static JS modules — no API calls, no backend, no telemetry.

---

## Data sources and accuracy

Schema column lists are sourced from [Microsoft Learn Advanced Hunting reference](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables). MITRE ATT&CK technique mappings follow the [ATT&CK Enterprise and Cloud matrices](https://attack.mitre.org). KQL queries use only verified columns from the published schema.

If you spot an inaccurate column name, fabricated field, or wrong table mapping — please open an issue.

---

## Contributing

Issues and PRs welcome. If you're adding or correcting KQL, please link to the MS Learn schema page that confirms the column exists.

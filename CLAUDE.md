# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run dev       # Start Astro dev server with HMR
npm run build     # Build static site to /dist
npm run preview   # Preview production build locally
npm run lint      # ESLint (React hooks plugin)
```

No test suite is configured.

## Architecture

**Stack:** Astro 6 (static output) + React 19 (interactive islands) + D3 7 (graph rendering). Deployed to GitHub Pages at `/xdr-pivot-map` base path — configured in `astro.config.mjs`.

**Pages → Components:** Astro pages in `src/pages/` are thin shells that mount React components with `client:only="react"`. All interactivity lives in React; Astro provides routing and the HTML shell.

```
src/pages/index.astro                        → landing page (static, links to all tools)
src/pages/tools/xdr-pivot.astro             → mounts <XDRPivotMap />
src/pages/tools/investigation-roadmap.astro → mounts <InvestigationRoadmap />
src/pages/tools/mitre-crosswalk.astro       → mounts <MitreCrosswalk />
src/pages/tools/tables-for-muggles.astro    → mounts <TablesForMuggles />
src/pages/tools/canvas-export.astro         → mounts <CanvasExport />
src/layouts/BaseLayout.astro                → global HTML + CSS variables for theme
```

## Tool: XDR Pivot Map (`/tools/xdr-pivot`)

**Component tree:**
```
XDRPivotMap       ← state owner: selected use case, domain filter, active step, theme, dimensions
├── Sidebar        ← domain filter + use case list + theme toggle
├── PivotGraph     ← D3 force-directed SVG graph
├── StepPanel      ← investigation steps + KQL snippets (collapsible)
└── Tooltips       ← NodeTooltip / EdgeTooltip on hover
```

**D3 + React boundary:** `PivotGraph.jsx` uses `useRef` to hand DOM elements directly to D3. D3 mutates SVG nodes via `nodeRefs`, `edgeRefs`, `edgeHitRefs`, `labelRefs` arrays — React does not manage these nodes after initial render. Zoom (`d3.zoom`) and drag with node-pinning (`d3.drag`) are set up in effects.

Critical pattern: always use `setAttribute` (never `removeAttribute`) in D3 imperative effects — React only re-asserts props that changed vdom-to-vdom; `removeAttribute` leaves attributes absent permanently since React won't re-assert unchanged props.

Edge tier styling: `high` = opacity 1.0, strokeWidth 2.5; `mid` = opacity 0.55, strokeWidth 2; `low` = opacity 0.25, strokeWidth 1. Baseline is set in JSX props so React owns it; imperative D3 effects only override when a filter is active.

## Tool: Investigation Roadmap (`/tools/investigation-roadmap`)

Ordered investigation paths rendered by `InvestigationRoadmap.jsx` from `src/data/roadmaps.js`.

**Roadmap types:**

| id | kind | Description |
|---|---|---|
| email | pivot | Trace email-borne threat from delivery through execution |
| device | pivot | Investigate suspicious endpoint activity |
| identity | pivot | Follow compromised account across cloud, identity, endpoint |
| malware | pivot | Hunt from a known hash through execution and C2 |
| ip | pivot | Pivot from a suspicious IP across all telemetry |
| devicecode | scenario | OAuth device code phishing → token theft |
| aitm | scenario | AiTM → Azure portal recon → VM Run Command execution |
| becfraud | scenario | AiTM → inbox rules → mailbox recon → wire fraud |
| infostealer | scenario | Malvertising → browser credential harvest → Telegram exfil |
| clickfix | scenario | Fake CAPTCHA clipboard hijack → Run dialog PowerShell cradle |

**Roadmap step pattern:** All roadmaps start with an AlertInfo/AlertEvidence triage step. Scenario roadmaps (not pivot roadmaps) also end with a closing AlertInfo step — this is intentional: the closing step is a **detection gap analysis** (which kill chain stages fired alerts vs. which didn't), not a repeat of the opening triage. The closing step goal text always leads with a `⚠ NOTE` annotation explaining this distinction.

## Tool: MITRE Crosswalk (`/tools/mitre-crosswalk`)

`MitreCrosswalk.jsx` from `src/data/mitreAttack.js` (Enterprise matrix) and `src/data/mitreAttackCloud.js` (Cloud matrix). 14 tactics, 53+ cloud techniques, 40+ Enterprise techniques, each mapped to Defender XDR tables and KQL queries.

## Tool: Tables for Muggles (`/tools/tables-for-muggles`)

`TablesForMuggles.jsx` from `src/data/tableDetails.js`. Plain-English guide to every Defender XDR table with key columns and IR context.

## Tool: Canvas Export (`/tools/canvas-export`)

`CanvasExport.jsx` — generates downloadable Obsidian Canvas (`.canvas`) JSON files for the pivot map and investigation roadmaps.

## Data layer (`src/data/`)

All data is static JS modules — no API calls.

| File | Contents |
|---|---|
| `tables.js` | 45 Microsoft Defender XDR tables, each assigned a domain |
| `domains.js` | 7 domains (endpoint, identity, email, cloud, alerts, tvm, purview) with display colors |
| `useCases.js` | 12 threat hunt use cases with ordered steps, KQL queries, and edge links; exports `USE_CASES`, `buildEdges()`, `ALL_EDGES` |
| `pivots.js` | Comprehensive schema-level pivot map — 149 table-to-table edges tiered by hunting value (high/mid/low); imported by `useCases.js` to seed `buildEdges()` |
| `columns.js` | Per-column metadata (plain English, DFIR context, cross-table refs, MS docs links) |
| `roadmaps.js` | 10 investigation roadmaps (5 pivot + 5 scenario) with ordered stops, goals, pivot columns, and KQL |
| `mitreAttack.js` | 14 MITRE ATT&CK Enterprise tactics + 40+ techniques mapped to XDR tables |
| `mitreAttackCloud.js` | 53 MITRE ATT&CK Cloud techniques mapped to XDR tables and KQL |
| `tableDetails.js` | Extended table descriptions for Tables for Muggles |

**`buildEdges()` logic:** Seeds the edge map from `PIVOT_EDGES` (schema-level, with tier), then overlays use-case-specific links (adds `useCases[]` tracking, merges column names). Result is `ALL_EDGES` — used by `PivotGraph.jsx` to render the graph.

## Use Case IDs (current)

`phishing`, `azurePortalBreach`, `lateralMovement`, `persistence`, `credentialAccess`, `cloudCompromise`, `exfiltration`, `vulnerabilityExploitation`, `insiderThreat`, `becFraud`, `infoStealer`, `clickFix`

## Theme

Light/dark via CSS custom properties defined in `BaseLayout.astro`. Theme state persisted to `localStorage` and toggled in `XDRPivotMap`. Domain colors are fixed constants (e.g., endpoint `#00d4ff`, identity `#ffb347`).

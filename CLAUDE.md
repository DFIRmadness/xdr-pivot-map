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
src/pages/index.astro                → landing page (static)
src/pages/tools/xdr-pivot.astro      → mounts <XDRPivotMap />
src/pages/tools/mitre-crosswalk.astro → mounts <MitreCrosswalk />
src/layouts/BaseLayout.astro         → global HTML + CSS variables for theme
```

**Component tree (XDR Pivot tool):**
```
XDRPivotMap       ← state owner: selected use case, hovered elements, active step, theme, dimensions
├── Sidebar        ← use case list + theme toggle
├── PivotGraph     ← D3 force-directed SVG graph
├── StepPanel      ← investigation steps + KQL snippets
└── Tooltips       ← NodeTooltip / EdgeTooltip on hover
```

**D3 + React boundary:** `PivotGraph.jsx` uses `useRef` to hand DOM elements directly to D3. D3 mutates SVG nodes via `nodeRefs`, `edgeRefs`, `edgeHitRefs`, `labelRefs` arrays — React does not manage these nodes after initial render. Zoom (`d3.zoom`) and drag with node-pinning (`d3.drag`) are set up in effects. When editing graph behavior, work inside D3's imperative layer, not React state.

**Data layer (`src/data/`):** All data is static JS modules — no API calls.
- `tables.js` — 32 Microsoft Defender XDR tables, each assigned a domain
- `domains.js` — 7 domains (endpoint, identity, email, cloud, alerts, tvm, purview) with display colors
- `useCases.js` — 8 threat hunt scenarios; each has ordered steps with KQL queries
- `columns.js` — per-column metadata (plain English, DFIR context, cross-table refs, MS docs links)
- `mitreAttack.js` — 14 MITRE ATT&CK tactics + 40+ techniques mapped to XDR tables

**Theme:** Light/dark via CSS custom properties defined in `BaseLayout.astro`. Theme state is persisted to `localStorage` and toggled in `XDRPivotMap`. Domain colors are fixed constants (e.g., endpoint `#00d4ff`, identity `#ffb347`).

import { useState } from "react";
import { TABLES } from "../data/tables.js";
import { DOMAINS } from "../data/domains.js";
import { ALL_EDGES, USE_CASES } from "../data/useCases.js";
import { ROADMAPS, ROADMAP_TYPES } from "../data/roadmaps.js";
import { TACTICS, TECHNIQUES } from "../data/mitreAttack.js";

// ── Layout constants ──────────────────────────────────────────────────────────
const PM_NODE_W  = 340;   // wide enough for longest table names
const PM_NODE_H  = 110;   // tall enough for 2-line content
const PM_V_GAP   = 28;    // breathing room between nodes
const PM_COL_W   = 460;   // column width including horizontal gap
const PM_ROW_GAP = 320;   // vertical gap between domain rows

const RM_NODE_W   = 560;   // wider for verbose goal text
const RM_HEADER_H = 140;   // taller header for long descriptions
const RM_STOP_H   = 360;   // tall enough for multi-sentence goals + pivot cols
const RM_V_GAP    = 60;

const MIT_COL_W      = 440;  // column pitch — wide enough for long technique names
const MIT_NODE_W     = 400;  // technique node width
const MIT_NODE_H     = 80;   // compact height: ID line + table line
const MIT_V_GAP      = 12;   // tight but distinct gap
const MIT_TACTIC_H   = 60;   // tactic header height
const MIT_TACTIC_GAP = 16;   // gap between tactic header and first technique
const MIT_ROW_GAP    = 280;  // vertical gap between tactic rows

// ── Domain column/row layout for Pivot Map canvas ────────────────────────────
const DOMAIN_POS = {
  endpoint: { col: 0, row: 0 },
  identity: { col: 1, row: 0 },
  email:    { col: 2, row: 0 },
  cloud:    { col: 3, row: 0 },
  alerts:   { col: 4, row: 0 },
  tvm:      { col: 0, row: 1 },
  purview:  { col: 1, row: 1 },
};

// ── Canvas generators ─────────────────────────────────────────────────────────

function generatePivotMapCanvas() {
  const nodes = [];
  const edges = [];

  // Group tables by domain
  const byDomain = {};
  TABLES.forEach(t => {
    if (!byDomain[t.domain]) byDomain[t.domain] = [];
    byDomain[t.domain].push(t);
  });

  // Calculate row 1 y offset based on max tables in row 0
  const row0Max = Math.max(
    ...Object.entries(DOMAIN_POS)
      .filter(([, v]) => v.row === 0)
      .map(([d]) => (byDomain[d] || []).length)
  );
  const row1Y = row0Max * (PM_NODE_H + PM_V_GAP) + PM_ROW_GAP;

  // Emit domain label nodes + table nodes
  const nodeIdMap = {};

  Object.entries(byDomain).forEach(([domain, tables]) => {
    const pos = DOMAIN_POS[domain];
    if (!pos) return;
    const x    = pos.col * PM_COL_W;
    const yBase = pos.row === 0 ? 0 : row1Y;
    const color = DOMAINS[domain].color;

    // Domain header pseudo-node (label above the column)
    nodes.push({
      id: `domain-label-${domain}`,
      type: "text",
      text: `**${DOMAINS[domain].label}**`,
      x,
      y: yBase - 58,
      width: PM_NODE_W,
      height: 42,
      color,
    });

    tables.forEach((table, i) => {
      const id = `node-${table.id}`;
      nodeIdMap[table.id] = id;
      nodes.push({
        id,
        type: "text",
        text: `## ${table.id}\n${table.desc}`,
        x,
        y: yBase + i * (PM_NODE_H + PM_V_GAP),
        width: PM_NODE_W,
        height: PM_NODE_H,
        color,
      });
    });
  });

  // Emit edges from ALL_EDGES
  ALL_EDGES.forEach((edge, i) => {
    const fromId = nodeIdMap[edge.source];
    const toId   = nodeIdMap[edge.target];
    if (!fromId || !toId) return;
    edges.push({
      id:       `edge-${i}`,
      fromNode: fromId,
      toNode:   toId,
      label:    edge.cols.join(", "),
    });
  });

  return { nodes, edges };
}

function generateRoadmapCanvas(typeId) {
  const type    = ROADMAP_TYPES.find(t => t.id === typeId);
  const roadmap = ROADMAPS[typeId];
  if (!type || !roadmap) return null;

  const nodes = [];
  const edges = [];
  const x = 0;

  // Header
  nodes.push({
    id:     "header",
    type:   "text",
    text:   `# ${type.icon} ${type.label} Investigation Roadmap\n\n${type.description}`,
    x,
    y:      0,
    width:  RM_NODE_W,
    height: RM_HEADER_H,
    color:  type.color,
  });

  let y = RM_HEADER_H + RM_V_GAP;

  roadmap.steps.forEach((step, i) => {
    const id        = `stop-${i}`;
    const tableObj  = TABLES.find(t => t.id === step.table);
    const domain    = tableObj?.domain || "endpoint";
    const color     = DOMAINS[domain]?.color || "#8890b8";
    const pivotMd   = step.pivotColumns.map(c => `\`${c}\``).join("  ·  ");

    const text =
      `## ${i + 1}. ${step.label}\n` +
      `> **${step.table}**\n\n` +
      `${step.goal}\n\n` +
      `**Pivot columns:** ${pivotMd}`;

    nodes.push({
      id,
      type:   "text",
      text,
      x,
      y,
      width:  RM_NODE_W,
      height: RM_STOP_H,
      color,
    });

    const prevId  = i === 0 ? "header" : `stop-${i - 1}`;
    const edgeCol = i === 0 ? "begin" : (step.pivotColumns[0] || "→");
    edges.push({
      id:       `edge-${i}`,
      fromNode: prevId,
      toNode:   id,
      label:    edgeCol,
    });

    y += RM_STOP_H + RM_V_GAP;
  });

  return { nodes, edges };
}

function generateMitreCanvas() {
  const nodes = [];

  // Index techniques by primary tactic (tacticIds[0])
  const byTactic = {};
  TACTICS.forEach(t => { byTactic[t.id] = []; });
  TECHNIQUES.forEach(tech => {
    const primary = tech.tacticIds[0];
    if (byTactic[primary]) byTactic[primary].push(tech);
  });

  // 14 tactics → 2 rows of 7
  const row1 = TACTICS.slice(0, 7);
  const row2 = TACTICS.slice(7);

  const row1Max  = Math.max(...row1.map(t => (byTactic[t.id] || []).length));
  const row1H    = MIT_TACTIC_H + MIT_TACTIC_GAP + row1Max * (MIT_NODE_H + MIT_V_GAP);
  const row2YBase = row1H + MIT_ROW_GAP;

  [row1, row2].forEach((row, rowIdx) => {
    const yBase = rowIdx === 0 ? 0 : row2YBase;

    row.forEach((tactic, colIdx) => {
      const x         = colIdx * MIT_COL_W;
      const techniques = byTactic[tactic.id] || [];

      // Tactic header
      nodes.push({
        id:     `tactic-${tactic.id}`,
        type:   "text",
        text:   `## ${tactic.icon} ${tactic.name}`,
        x,
        y:      yBase,
        width:  MIT_NODE_W,
        height: MIT_TACTIC_H,
        color:  tactic.color,
      });

      // Technique nodes
      techniques.forEach((tech, i) => {
        const tables = [...new Set(tech.xdrMappings.map(m => m.table))].join("  ·  ");
        nodes.push({
          id:     `tech-${tech.id}`,
          type:   "text",
          text:   `**${tech.id}** — ${tech.name}\n\`${tables}\``,
          x,
          y:      yBase + MIT_TACTIC_H + MIT_TACTIC_GAP + i * (MIT_NODE_H + MIT_V_GAP),
          width:  MIT_NODE_W,
          height: MIT_NODE_H,
          color:  tactic.color,
        });
      });
    });
  });

  return { nodes, edges: [] };
}

// ── Download helper ───────────────────────────────────────────────────────────

function download(filename, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ── UI ────────────────────────────────────────────────────────────────────────

function DownloadCard({ icon, title, subtitle, filename, generate, accentColor }) {
  const [downloaded, setDownloaded] = useState(false);

  function handleDownload() {
    const data = generate();
    if (!data) return;
    download(filename, data);
    setDownloaded(true);
    setTimeout(() => setDownloaded(false), 2000);
  }

  return (
    <div style={{
      display: "flex", alignItems: "center", gap: "1.4rem",
      padding: "1.25rem 1.5rem",
      background: "var(--bg-card)",
      border: "1px solid var(--bd-1)",
      borderLeft: `4px solid ${accentColor}`,
      boxShadow: "0 4px 24px rgba(0,0,0,0.5),inset 0 1px 0 rgba(255,255,255,0.06)",
    }}>
      <div style={{ fontSize: "1.5rem", flexShrink: 0 }}>{icon}</div>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: "0.8rem", fontWeight: 700, color: "var(--tx-1)", marginBottom: "0.3rem", letterSpacing: "0.04em" }}>
          {title}
        </div>
        <div style={{ fontSize: "0.7rem", color: "var(--tx-3)", lineHeight: 1.6 }}>{subtitle}</div>
        <div style={{ marginTop: "0.5rem", fontSize: "0.65rem", color: "var(--tx-5)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
          {filename}
        </div>
      </div>
      <button
        onClick={handleDownload}
        style={{
          flexShrink: 0,
          padding: "0.45rem 1rem",
          background: downloaded ? accentColor + "22" : "var(--bg-2)",
          border: `1px solid ${accentColor}${downloaded ? "88" : "44"}`,
          borderRadius: 3,
          color: downloaded ? accentColor : "var(--tx-3)",
          fontSize: "0.7rem",
          fontFamily: "inherit",
          letterSpacing: "0.08em",
          textTransform: "uppercase",
          cursor: "pointer",
          transition: "all 0.15s",
        }}
      >
        {downloaded ? "✓ Saved" : "↓ Download"}
      </button>
    </div>
  );
}

export default function CanvasExport() {
  // Theme
  const [isDark, setIsDark] = useState(() => {
    if (typeof window !== "undefined") {
      return (document.documentElement.dataset.theme || "dark") === "dark";
    }
    return true;
  });

  function toggleTheme() {
    const next = isDark ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    localStorage.setItem("theme", next);
    setIsDark(!isDark);
  }

  return (
    <div style={{ display: "flex", minHeight: "100vh", fontFamily: "inherit", background: "var(--bg-0)", color: "var(--tx-1)" }}>
      {/* ── Sidebar ── */}
      <aside style={{
        width: 220, flexShrink: 0,
        background: "var(--bg-1)", borderRight: "1px solid var(--bd-1)",
        padding: "1.5rem 1.25rem",
        display: "flex", flexDirection: "column", gap: "1.25rem",
      }}>
        <a href="/DefenderXDR-pivot-map/" style={{
          fontSize: "0.65rem", letterSpacing: "0.12em", textTransform: "uppercase",
          color: "var(--tx-5)", textDecoration: "none",
        }}>
          ← Home
        </a>

        <div>
          <div style={{ fontSize: "0.65rem", letterSpacing: "0.2em", color: "var(--tx-5)", textTransform: "uppercase", marginBottom: "0.5rem" }}>
            Tool
          </div>
          <div style={{ fontSize: "0.85rem", fontWeight: 700, color: "var(--tx-1)" }}>
            Obsidian Canvas Export
          </div>
        </div>

        <div style={{ fontSize: "0.72rem", color: "var(--tx-4)", lineHeight: 1.7 }}>
          Download <code style={{ fontSize: "0.65rem", color: "var(--tx-3)" }}>.canvas</code> files
          for Obsidian — import into your vault for an offline, editable
          reference of the pivot map and investigation roadmaps.
        </div>

        <div style={{ fontSize: "0.65rem", color: "var(--tx-6)", lineHeight: 1.7 }}>
          <strong style={{ color: "var(--tx-5)" }}>How to use:</strong><br/>
          1. Download a <code style={{ fontSize: "0.6rem" }}>.canvas</code> file<br/>
          2. Move it into your Obsidian vault<br/>
          3. Open with Obsidian (any version ≥ 1.1)
        </div>

        <button onClick={toggleTheme} style={{
          marginTop: "auto",
          background: "var(--bg-2)", border: "1px solid var(--bd-1)",
          color: "var(--tx-4)", fontFamily: "inherit", fontSize: "0.65rem",
          letterSpacing: "0.12em", textTransform: "uppercase",
          padding: "0.4rem 0.8rem", borderRadius: 3, cursor: "pointer",
        }}>
          {isDark ? "☀ Light" : "◐ Dark"}
        </button>
      </aside>

      {/* ── Main ── */}
      <main style={{ flex: 1, padding: "2.5rem 2.5rem", maxWidth: 680 }}>
        <p style={{ fontSize: "0.65rem", letterSpacing: "0.25em", color: "var(--tx-5)", textTransform: "uppercase", marginBottom: "1.25rem" }}>
          Obsidian Canvas Export
        </p>
        <h1 style={{ fontSize: "clamp(1.3rem,3vw,1.8rem)", fontWeight: 700, color: "var(--tx-1)", marginBottom: "0.75rem" }}>
          Download Canvas Maps
        </h1>
        <p style={{ fontSize: "0.8rem", color: "var(--tx-3)", lineHeight: 1.8, marginBottom: "2.5rem", maxWidth: 480 }}>
          Each file is valid Obsidian Canvas JSON — tables and stops as nodes,
          pivot relationships as labeled edges. Open in Obsidian to explore,
          annotate, and extend offline.
        </p>

        {/* Pivot Map section */}
        <div style={{ marginBottom: "2.5rem" }}>
          <div style={{
            fontSize: "0.65rem", letterSpacing: "0.2em", color: "var(--tx-5)",
            textTransform: "uppercase", marginBottom: "0.75rem",
            paddingBottom: "0.5rem", borderBottom: "1px solid var(--bd-2)",
          }}>
            Pivot Map
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
            <DownloadCard
              icon="🕸️"
              title="XDR Advanced Hunting Pivot Map"
              subtitle={`All ${TABLES.length} Defender XDR tables as nodes, grouped by domain. Every cross-table pivot relationship from the ${USE_CASES.length} use cases drawn as labeled edges.`}
              filename="defender-xdr-pivot-map.canvas"
              accentColor="#00d4ff"
              generate={generatePivotMapCanvas}
            />
          </div>
        </div>

        {/* MITRE ATT&CK section */}
        <div style={{ marginBottom: "2.5rem" }}>
          <div style={{
            fontSize: "0.65rem", letterSpacing: "0.2em", color: "var(--tx-5)",
            textTransform: "uppercase", marginBottom: "0.75rem",
            paddingBottom: "0.5rem", borderBottom: "1px solid var(--bd-2)",
          }}>
            MITRE ATT&CK Crosswalk
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
            <DownloadCard
              icon="🎯"
              title="MITRE ATT&CK × Defender XDR"
              subtitle={`${TECHNIQUES.length} techniques across ${TACTICS.length} tactics, each node showing the XDR tables that cover it. Arranged in two rows of 7 tactics — colour-coded by tactic.`}
              filename="mitre-attack-crosswalk.canvas"
              accentColor="#ff4757"
              generate={generateMitreCanvas}
            />
          </div>
        </div>

        {/* Roadmaps section */}
        <div>
          <div style={{
            fontSize: "0.65rem", letterSpacing: "0.2em", color: "var(--tx-5)",
            textTransform: "uppercase", marginBottom: "0.75rem",
            paddingBottom: "0.5rem", borderBottom: "1px solid var(--bd-2)",
          }}>
            Investigation Roadmaps
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 1 }}>
            {ROADMAP_TYPES.map(type => (
              <DownloadCard
                key={type.id}
                icon={type.icon}
                title={`${type.label} Investigation Roadmap`}
                subtitle={type.description}
                filename={`roadmap-${type.id}.canvas`}
                accentColor={type.color}
                generate={() => generateRoadmapCanvas(type.id)}
              />
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}

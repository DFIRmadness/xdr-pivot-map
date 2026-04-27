import { useEffect, useRef, useState } from "react";
import mermaid from "mermaid";
import * as d3 from "d3";
import { TABLES } from "../data/tables.js";
import { DOMAINS } from "../data/domains.js";

// Build a Mermaid flowchart definition from a use-case's links array.
// Nodes are styled by domain colour; edge labels show the pivot column.
function buildDef(useCase, isDark) {
  const lines = ["flowchart LR"];

  // Collect all table IDs referenced by this use case
  const tableIds = new Set(useCase.links.flatMap(l => [l.from, l.to]));

  // Group tables by domain so we can emit classDef + class assignments
  const domainMap = {};
  tableIds.forEach(id => {
    const t = TABLES.find(t => t.id === id);
    if (!t) return;
    (domainMap[t.domain] ??= []).push(id);
  });

  const textCol = isDark ? "#c8ceff" : "#1a1f3a";
  Object.keys(domainMap).forEach(domain => {
    const col = DOMAINS[domain].color;
    lines.push(
      `  classDef ${domain} fill:${col}28,stroke:${col},stroke-width:1.5px,color:${textCol}`
    );
  });

  lines.push(""); // blank line for readability

  // Edges — quote labels so slashes, arrows, and plus signs render correctly
  useCase.links.forEach(link => {
    const label = link.col.replace(/"/g, "'");
    lines.push(`  ${link.from} <-->|"${label}"| ${link.to}`);
  });

  lines.push(""); // blank line before class assignments

  // Assign domain classes to nodes
  Object.entries(domainMap).forEach(([domain, ids]) => {
    lines.push(`  class ${ids.join(",")} ${domain}`);
  });

  return lines.join("\n");
}

// Monotonically increasing ID avoids stale-element conflicts in mermaid's
// internal DOM scratch pad across re-renders.
let _uid = 0;

// ── Button style shared by zoom controls ─────────────────────────────────────
const ctrlBtn = {
  background: "var(--bg-2)",
  border: "1px solid var(--bd-1)",
  borderRadius: 3,
  color: "var(--tx-3)",
  fontFamily: "inherit",
  fontSize: 11,
  letterSpacing: "0.08em",
  padding: "3px 9px",
  cursor: "pointer",
  textTransform: "uppercase",
  transition: "background 0.12s, color 0.12s",
  lineHeight: 1.5,
};

export default function MermaidDiagram({ activeUC, isDark }) {
  const wrapRef      = useRef(null);   // overflow:hidden canvas wrapper
  const containerRef = useRef(null);   // SVG mount point (position:absolute fill)
  const zoomRef      = useRef(null);   // { zoom, svgSel } — set after each render
  const [zoomPct, setZoomPct] = useState(100);

  // ── Fit diagram to the visible canvas ──────────────────────────────────────
  function fitToView(animated = true) {
    if (!zoomRef.current || !wrapRef.current || !containerRef.current) return;
    const { zoom, svgSel } = zoomRef.current;
    const svgEl = containerRef.current.querySelector("svg");
    if (!svgEl) return;

    const vb  = svgEl.viewBox?.baseVal;
    const dgW = vb?.width  || 800;
    const dgH = vb?.height || 400;
    const cW  = wrapRef.current.clientWidth  || 800;
    const cH  = wrapRef.current.clientHeight || 400;
    const pad = 48;

    const scale = Math.min((cW - pad * 2) / dgW, (cH - pad * 2) / dgH, 1.5);
    const tx    = (cW - dgW * scale) / 2;
    const ty    = (cH - dgH * scale) / 2;

    const t = d3.zoomIdentity.translate(tx, ty).scale(scale);
    if (animated) {
      svgSel.transition().duration(350).call(zoom.transform, t);
    } else {
      svgSel.call(zoom.transform, t);
    }
  }

  function zoomBy(factor) {
    if (!zoomRef.current) return;
    const { zoom, svgSel } = zoomRef.current;
    svgSel.transition().duration(200).call(zoom.scaleBy, factor);
  }

  // ── Render + wire D3 zoom whenever use case or theme changes ───────────────
  useEffect(() => {
    if (!activeUC || !containerRef.current) return;

    zoomRef.current = null;
    setZoomPct(100);

    mermaid.initialize({
      startOnLoad: false,
      theme: isDark ? "dark" : "default",
      flowchart: { curve: "basis", padding: 24 },
      themeVariables: {
        fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
        fontSize: "12px",
        ...(isDark && {
          background:          "#0e0f1a",
          primaryColor:        "#161830",
          primaryBorderColor:  "#363a62",
          primaryTextColor:    "#c8ceff",
          lineColor:           "#555a8a",
          edgeLabelBackground: "#0e0f1a",
          clusterBkg:          "#1a1f3a",
        }),
      },
    });

    const id  = `mermaid-${++_uid}`;
    const def = buildDef(activeUC, isDark);

    mermaid.render(id, def)
      .then(({ svg }) => {
        if (!containerRef.current) return;
        containerRef.current.innerHTML = svg;

        const svgEl = containerRef.current.querySelector("svg");
        if (!svgEl) return;

        // Remove fixed dimensions so the SVG fills its container naturally
        svgEl.removeAttribute("width");
        svgEl.removeAttribute("height");
        Object.assign(svgEl.style, {
          display:  "block",
          width:    "100%",
          height:   "100%",
          overflow: "visible",
          cursor:   "grab",
        });

        const g = svgEl.querySelector("g");
        if (!g) return;

        // D3 zoom — all pan/zoom state is managed by D3
        const zoom = d3.zoom()
          .scaleExtent([0.05, 8])
          .on("zoom", e => {
            g.setAttribute("transform", e.transform.toString());
            setZoomPct(Math.round(e.transform.k * 100));
          });

        const svgSel = d3.select(svgEl);
        svgSel.call(zoom);

        // Cursor feedback during drag
        svgSel
          .on("mousedown.cur",              () => { svgEl.style.cursor = "grabbing"; })
          .on("mouseup.cur mouseleave.cur", () => { svgEl.style.cursor = "grab"; });

        zoomRef.current = { zoom, svgSel };

        // Auto-fit after the browser has laid out the container
        requestAnimationFrame(() => fitToView(false));
      })
      .catch(err => {
        console.error("Mermaid render error:", err);
        if (containerRef.current) {
          containerRef.current.innerHTML =
            `<pre style="color:#ff4757;padding:16px;font-size:12px">${err.message}</pre>`;
        }
      });
  }, [activeUC, isDark]);

  // ── Empty state ─────────────────────────────────────────────────────────────
  if (!activeUC) {
    return (
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "center",
        height: "100%", color: "var(--tx-4)", fontSize: 13,
        fontFamily: "inherit", textAlign: "center", padding: "0 32px",
        lineHeight: 1.7,
      }}>
        Select a hunt scenario from the sidebar<br />to generate its flow diagram.
      </div>
    );
  }

  // ── Diagram view ─────────────────────────────────────────────────────────────
  return (
    <div style={{
      position: "absolute", inset: 0,
      display: "flex", flexDirection: "column",
      background: "var(--bg-0)",
    }}>

      {/* ── Title strip ─────────────────────────────────────────────────── */}
      <div style={{
        display: "flex", alignItems: "center",
        padding: "7px 16px 6px",
        borderBottom: "1px solid var(--bd-2)",
        flexShrink: 0,
      }}>
        <span style={{
          fontSize: 11, letterSpacing: "0.12em", textTransform: "uppercase",
          color: "var(--tx-4)", fontFamily: "'JetBrains Mono', monospace",
        }}>
          {activeUC.icon} {activeUC.name} — flow diagram
        </span>
      </div>

      {/* ── Pan/zoom canvas ─────────────────────────────────────────────── */}
      <div
        ref={wrapRef}
        style={{ flex: 1, position: "relative", overflow: "hidden" }}
      >
        <div
          ref={containerRef}
          style={{ position: "absolute", inset: 0 }}
        />

        {/* ── Bottom-centre zoom controls (mirrors PivotGraph control bar) ── */}
        <div style={{
          position: "absolute", bottom: 20, left: "50%", transform: "translateX(-50%)",
          display: "flex", alignItems: "center", gap: 4, zIndex: 10,
        }}>
          <span style={{
            fontSize: 10, color: "var(--tx-6)", letterSpacing: "0.1em",
            marginRight: 4, userSelect: "none",
          }}>
            scroll · drag
          </span>

          <button style={ctrlBtn}
            onClick={() => zoomBy(1.3)}
            title="Zoom in  (scroll up)"
            onMouseEnter={e => { e.currentTarget.style.background = "var(--bg-3)"; e.currentTarget.style.color = "var(--tx-1)"; }}
            onMouseLeave={e => { e.currentTarget.style.background = "var(--bg-2)"; e.currentTarget.style.color = "var(--tx-3)"; }}
          >+</button>

          <span style={{
            fontSize: 11, color: "var(--tx-4)", fontFamily: "monospace",
            minWidth: 40, textAlign: "center", userSelect: "none",
          }}>
            {zoomPct}%
          </span>

          <button style={ctrlBtn}
            onClick={() => zoomBy(0.77)}
            title="Zoom out  (scroll down)"
            onMouseEnter={e => { e.currentTarget.style.background = "var(--bg-3)"; e.currentTarget.style.color = "var(--tx-1)"; }}
            onMouseLeave={e => { e.currentTarget.style.background = "var(--bg-2)"; e.currentTarget.style.color = "var(--tx-3)"; }}
          >−</button>

          <button style={{ ...ctrlBtn, marginLeft: 4 }}
            onClick={() => fitToView(true)}
            title="Fit diagram to view"
            onMouseEnter={e => { e.currentTarget.style.background = "var(--bg-3)"; e.currentTarget.style.color = "var(--tx-1)"; }}
            onMouseLeave={e => { e.currentTarget.style.background = "var(--bg-2)"; e.currentTarget.style.color = "var(--tx-3)"; }}
          >⊡ Fit</button>
        </div>
      </div>

    </div>
  );
}

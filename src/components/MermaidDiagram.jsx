import { useEffect, useRef } from "react";
import mermaid from "mermaid";
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
    lines.push(`  ${link.from} -->|"${label}"| ${link.to}`);
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

export default function MermaidDiagram({ activeUC, isDark }) {
  const containerRef = useRef(null);

  useEffect(() => {
    if (!activeUC || !containerRef.current) return;

    mermaid.initialize({
      startOnLoad: false,
      theme: isDark ? "dark" : "default",
      flowchart: { curve: "basis", padding: 24 },
      themeVariables: {
        fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
        fontSize: "12px",
        ...(isDark && {
          background:           "#0e0f1a",
          primaryColor:         "#161830",
          primaryBorderColor:   "#363a62",
          primaryTextColor:     "#c8ceff",
          lineColor:            "#555a8a",
          edgeLabelBackground:  "#0e0f1a",
          clusterBkg:           "#1a1f3a",
        }),
      },
    });

    const id  = `mermaid-${++_uid}`;
    const def = buildDef(activeUC, isDark);

    mermaid.render(id, def)
      .then(({ svg }) => {
        if (!containerRef.current) return;
        containerRef.current.innerHTML = svg;
        // Let the SVG stretch to fill the container width
        const svgEl = containerRef.current.querySelector("svg");
        if (svgEl) {
          svgEl.style.width    = "100%";
          svgEl.style.height   = "auto";
          svgEl.style.maxWidth = "100%";
        }
      })
      .catch(err => {
        console.error("Mermaid render error:", err);
        if (containerRef.current) {
          containerRef.current.innerHTML =
            `<pre style="color:#ff4757;padding:16px;font-size:12px">${err.message}</pre>`;
        }
      });
  }, [activeUC, isDark]);

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

  return (
    <div style={{
      position: "absolute", inset: 0,
      overflow: "auto",
      padding: "32px 28px 80px",   // bottom pad clears the control bar
      boxSizing: "border-box",
      background: "var(--bg-0)",
    }}>
      <div style={{
        fontSize: 11, letterSpacing: "0.12em", textTransform: "uppercase",
        color: "var(--tx-4)", marginBottom: 18,
        fontFamily: "'JetBrains Mono', monospace",
      }}>
        {activeUC.icon} {activeUC.name} — flow diagram
      </div>
      <div ref={containerRef} />
    </div>
  );
}

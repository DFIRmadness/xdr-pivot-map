import { useEffect, useRef, useState } from "react";
import * as d3 from "d3";
import { DOMAINS } from "../data/domains.js";
import { TABLES } from "../data/tables.js";
import { ALL_EDGES } from "../data/useCases.js";
import MermaidDiagram from "./MermaidDiagram.jsx";

export default function PivotGraph({
  activeUC,
  activeTableIds,
  activeEdgePairs,
  activeStep,
  dimensions,
  onNodeHover,
  onEdgeHover,
  svgRef,
  isDark,
  viewMode,
  onViewModeChange,
  highlightColor,
}) {
  const simRef     = useRef(null);
  const zoomRef    = useRef(null);
  const zoomGrpRef = useRef(null);
  const nodeRefs   = useRef({});
  const edgeRefs   = useRef([]);
  const edgeHitRefs= useRef([]);
  const labelRefs  = useRef({});
  const nodesRef   = useRef([]);   // live node objects with x/y/fx/fy
  const lockedRef  = useRef(true);
  const [isLocked, setIsLocked] = useState(true);

  // ── Simulation + zoom + drag ──────────────────────────────────────────────
  useEffect(() => {
    if (!svgRef.current || !zoomGrpRef.current) return;
    const { w, h } = dimensions;
    const nodes = TABLES.map(t => ({ ...t }));
    nodesRef.current = nodes;
    const edges = ALL_EDGES.map(e => ({ ...e }));

    if (simRef.current) simRef.current.stop();

    const sim = d3.forceSimulation(nodes)
      .force("link",      d3.forceLink(edges).id(d => d.id).distance(200).strength(0.35))
      .force("charge",    d3.forceManyBody().strength(-500))
      .force("center",    d3.forceCenter(w / 2, h / 2))
      .force("collision", d3.forceCollide(65))
      .force("x",         d3.forceX(w / 2).strength(0.03))
      .force("y",         d3.forceY(h / 2).strength(0.03));

    simRef.current = sim;

    // Zoom
    const zoom = d3.zoom()
      .scaleExtent([0.15, 4])
      .on("zoom", (event) => {
        if (zoomGrpRef.current) {
          zoomGrpRef.current.setAttribute("transform", event.transform.toString());
        }
      });
    zoomRef.current = zoom;
    d3.select(svgRef.current).call(zoom).on("dblclick.zoom", null);

    // Drag — bind each node datum so d3.drag can read/write x/y/fx/fy
    const drag = d3.drag()
      .on("start", function(event) {
        if (!event.active) sim.alphaTarget(0.3).restart();
        const node = d3.select(this).datum();
        node.fx = node.x;
        node.fy = node.y;
      })
      .on("drag", function(event) {
        const node = d3.select(this).datum();
        node.fx = event.x;
        node.fy = event.y;
      })
      .on("end", function(event) {
        if (!event.active) sim.alphaTarget(0);
        const node = d3.select(this).datum();
        if (lockedRef.current) {
          // Keep the node pinned at wherever it was dropped
          node.fx = node.x;
          node.fy = node.y;
        } else {
          node.fx = null;
          node.fy = null;
        }
      });

    nodes.forEach(node => {
      const el = nodeRefs.current[node.id];
      if (el) d3.select(el).datum(node).call(drag);
    });

    // Pin all nodes once simulation cools (respects lock state)
    sim.on("end", () => {
      if (lockedRef.current) {
        nodesRef.current.forEach(node => { node.fx = node.x; node.fy = node.y; });
      }
    });

    // Tick
    sim.on("tick", () => {
      nodes.forEach(node => {
        const el = nodeRefs.current[node.id];
        if (el) el.setAttribute("transform", `translate(${node.x},${node.y})`);
        const lel = labelRefs.current[node.id];
        if (lel) lel.setAttribute("transform", `translate(${node.x},${node.y})`);
      });
      edges.forEach((edge, i) => {
        if (edge.source.x == null) return;
        const coords = {
          x1: edge.source.x, y1: edge.source.y,
          x2: edge.target.x, y2: edge.target.y,
        };
        const el = edgeRefs.current[i];
        if (el) { el.setAttribute("x1", coords.x1); el.setAttribute("y1", coords.y1); el.setAttribute("x2", coords.x2); el.setAttribute("y2", coords.y2); }
        const hit = edgeHitRefs.current[i];
        if (hit) { hit.setAttribute("x1", coords.x1); hit.setAttribute("y1", coords.y1); hit.setAttribute("x2", coords.x2); hit.setAttribute("y2", coords.y2); }
      });
    });

    return () => sim.stop();
  }, [dimensions, svgRef]);

  // ── Visual state: use-case highlight + theme ──────────────────────────────
  useEffect(() => {
    const dimFill   = isDark ? "#0e0f1a" : "#dce0f0";
    const dimStroke = isDark ? "#363a62" : "#a8b0d0";
    const edgeDim   = isDark ? "#363a62" : "#a8b0d0";
    TABLES.forEach(table => {
      const el  = nodeRefs.current[table.id];
      const lel = labelRefs.current[table.id];
      if (!el) return;
      const isActive    = !activeTableIds || activeTableIds.has(table.id);
      const col         = DOMAINS[table.domain].color;
      const accentColor = activeUC ? activeUC.color : col;
      el.querySelector("circle").setAttribute("fill",         isActive ? accentColor + "22" : dimFill);
      el.querySelector("circle").setAttribute("stroke",       isActive ? (activeUC ? accentColor : col) : dimStroke);
      el.querySelector("circle").setAttribute("stroke-width", isActive ? "2" : "1");
      el.style.opacity = isActive ? "1" : "0.12";
      if (lel) lel.style.opacity = isActive ? "1" : "0.08";
    });

    ALL_EDGES.forEach((edge, i) => {
      const el = edgeRefs.current[i];
      if (!el) return;
      const key      = [edge.source.id || edge.source, edge.target.id || edge.target].sort().join("||");
      const isActive = !activeEdgePairs || activeEdgePairs.has(key);
      const tier     = edge.tier || "mid";

      if (activeEdgePairs) {
        // Filter active — override tier baseline with binary active/dim
        el.setAttribute("stroke", edgeDim);
        el.setAttribute("stroke-width", "2");
        el.style.opacity = isActive ? "1" : "0.06";
      } else {
        // No filter — restore tier baseline explicitly
        el.setAttribute("stroke", "var(--edge)");
        el.setAttribute("stroke-width", tier === "high" ? "2.5" : tier === "low" ? "1" : "2");
        el.style.opacity = tier === "high" ? "1" : tier === "low" ? "0.25" : "0.55";
      }
    });
  }, [activeUC, activeTableIds, activeEdgePairs, isDark, highlightColor]);

  // ── Spotlight active step node ────────────────────────────────────────────
  useEffect(() => {
    if (!activeUC || activeStep === null) return;
    const stepTable = activeUC.steps[activeStep]?.table;
    TABLES.forEach(table => {
      const el = nodeRefs.current[table.id];
      if (!el) return;
      const circle = el.querySelector("circle");
      if (table.id === stepTable) {
        circle.setAttribute("fill",         activeUC.color + "55");
        circle.setAttribute("stroke-width", "3");
        el.style.filter = "url(#glow)";
      } else {
        el.style.filter = "";
        if (activeTableIds?.has(table.id)) {
          circle.setAttribute("fill",         activeUC.color + "22");
          circle.setAttribute("stroke-width", "2");
        }
      }
    });
  }, [activeStep, activeUC, activeTableIds, isDark]);

  // ── Zoom helpers ──────────────────────────────────────────────────────────
  function zoomIn()    { d3.select(svgRef.current).transition().duration(220).call(zoomRef.current.scaleBy, 1.5); }
  function zoomOut()   { d3.select(svgRef.current).transition().duration(220).call(zoomRef.current.scaleBy, 1 / 1.5); }
  function zoomReset() { d3.select(svgRef.current).transition().duration(320).call(zoomRef.current.transform, d3.zoomIdentity); }

  // ── Lock toggle ───────────────────────────────────────────────────────────
  function toggleLock() {
    const next = !lockedRef.current;
    lockedRef.current = next;
    setIsLocked(next);
    if (next) {
      // Pin every node at its current position
      nodesRef.current.forEach(node => { node.fx = node.x; node.fy = node.y; });
      simRef.current?.alphaTarget(0);
    } else {
      // Release all nodes and let the sim breathe again briefly
      nodesRef.current.forEach(node => { node.fx = null; node.fy = null; });
      simRef.current?.alphaTarget(0.1).restart();
    }
  }

  // ── Button style ──────────────────────────────────────────────────────────
  const btnStyle = {
    width: 32, height: 32, display: "flex", alignItems: "center", justifyContent: "center",
    background: "var(--bg-2)", border: "1px solid var(--bd-1)", borderRadius: 3,
    color: "var(--tx-3)", fontSize: 16, cursor: "pointer",
    fontFamily: "inherit", lineHeight: 1, userSelect: "none",
    transition: "background 0.15s, color 0.15s",
  };

  // ── View toggle ───────────────────────────────────────────────────────────
  const tabStyle = (mode) => ({
    ...btnStyle,
    width: "auto",
    padding: "0 10px",
    fontSize: 11,
    letterSpacing: "0.06em",
    background: viewMode === mode ? "var(--bg-3)" : "var(--bg-2)",
    color:      viewMode === mode ? "var(--tx-1)" : "var(--tx-4)",
    border:     viewMode === mode ? "1px solid var(--bd-2)" : "1px solid var(--bd-1)",
    fontWeight: viewMode === mode ? "700" : "400",
    opacity:    mode === "diagram" && !activeUC ? 0.35 : 1,
    cursor:     mode === "diagram" && !activeUC ? "not-allowed" : "pointer",
  });

  return (
    <>
      {/* D3 SVG — kept mounted so the simulation survives view toggles */}
      <svg ref={svgRef} width={dimensions.w} height={dimensions.h}
        style={{ position: "absolute", inset: 0, cursor: "grab",
                 display: viewMode === "graph" ? undefined : "none" }}
      >
        <defs>
          <filter id="glow">
            <feGaussianBlur stdDeviation="4" result="coloredBlur"/>
            <feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
          <style>{`
            .edge-grp:hover .edge-vis {
              stroke: var(--tx-3);
              stroke-width: 3.5px;
            }
          `}</style>
        </defs>

        {/* Everything inside the zoom group */}
        <g ref={zoomGrpRef}>

          {/* Edges */}
          <g>
            {ALL_EDGES.map((edge, i) => {
              const srcId = edge.source.id || edge.source;
              const tgtId = edge.target.id || edge.target;
              const edgeKey = [srcId, tgtId].sort().join("||");
              const isEdgeActive = !activeEdgePairs || activeEdgePairs.has(edgeKey);
              return (
                <g key={i} className="edge-grp">
                  <line ref={el => edgeRefs.current[i] = el}
                    className="edge-vis"
                    stroke="var(--edge)"
                    strokeWidth={edge.tier === "high" ? "2.5" : edge.tier === "low" ? "1" : "2"}
                    strokeLinecap="round"
                    style={{
                      pointerEvents: "none",
                      opacity: edge.tier === "high" ? 1 : edge.tier === "low" ? 0.25 : 0.55,
                    }}
                  />
                  <line ref={el => edgeHitRefs.current[i] = el}
                    stroke="transparent"
                    strokeWidth={isEdgeActive ? "28" : "0"}
                    strokeLinecap="round"
                    style={{ cursor: isEdgeActive ? "pointer" : "default" }}
                    onMouseEnter={() => onEdgeHover(edge)}
                    onMouseLeave={() => onEdgeHover(null)}
                  />
                </g>
              );
            })}
          </g>

          {/* Node circles */}
          <g>
            {TABLES.map(table => {
              const col = DOMAINS[table.domain].color;
              const isNodeActive = !activeTableIds || activeTableIds.has(table.id);
              return (
                <g key={table.id} ref={el => nodeRefs.current[table.id] = el}
                  style={{ cursor: "grab" }}
                  onMouseEnter={() => { if (isNodeActive) onNodeHover(table.id); }}
                  onMouseLeave={() => { if (isNodeActive) onNodeHover(null); }}
                >
                  <circle r={22} fill={col + "22"} stroke={col} strokeWidth="1.5" />
                  {table.azure && (
                    <text
                      textAnchor="middle" dominantBaseline="central"
                      fontSize="13" fontFamily="'JetBrains Mono', monospace"
                      fontWeight="700" fill={col}
                      style={{ pointerEvents: "none", userSelect: "none" }}
                    >S</text>
                  )}
                </g>
              );
            })}
          </g>

          {/* Labels */}
          <g>
            {TABLES.map(table => {
              const words    = table.id.match(/[A-Z][a-z0-9]*/g) || [table.id];
              const midpoint = Math.ceil(words.length / 2);
              const line1    = words.slice(0, midpoint).join("");
              const line2    = words.slice(midpoint).join("");
              const twoLines = line2.length > 0;
              return (
                <g key={table.id + "_label"} ref={el => labelRefs.current[table.id] = el}
                  style={{ pointerEvents: "none" }}
                >
                  <text textAnchor="middle"
                    fontSize="11" fontFamily="'JetBrains Mono', monospace"
                    fontWeight="600" fill={DOMAINS[table.domain].color} letterSpacing="0.02em"
                  >
                    {twoLines ? (
                      <>
                        <tspan x="0" dy="30">{line1}</tspan>
                        <tspan x="0" dy="13">{line2}</tspan>
                      </>
                    ) : (
                      <tspan x="0" dy="32">{line1}</tspan>
                    )}
                  </text>
                </g>
              );
            })}
          </g>

        </g>
      </svg>

      {/* Mermaid diagram layer */}
      {viewMode === "diagram" && (
        <MermaidDiagram activeUC={activeUC} isDark={isDark} />
      )}

      {/* Controls bar */}
      <div style={{
        position: "absolute", bottom: 20, left: "50%", transform: "translateX(-50%)",
        display: "flex", gap: 4, zIndex: 10,
      }}>
        {/* View toggle — always visible */}
        <button style={tabStyle("graph")}
          onClick={() => onViewModeChange("graph")}
          title="Force-directed graph"
        >◈ Graph</button>
        <button style={tabStyle("diagram")}
          onClick={() => { if (activeUC) onViewModeChange("diagram"); }}
          title={activeUC ? "Flow diagram (Mermaid)" : "Select a use case first"}
        >⊡ Diagram</button>

        {/* Zoom + lock — only relevant in graph mode */}
        {viewMode === "graph" && (<>
          <div style={{ width: 1, background: "var(--bd-1)", margin: "4px 4px" }} />
          <button style={btnStyle} onClick={zoomIn}
            onMouseEnter={e => { e.currentTarget.style.background = "var(--bg-3)"; e.currentTarget.style.color = "var(--tx-1)"; }}
            onMouseLeave={e => { e.currentTarget.style.background = "var(--bg-2)"; e.currentTarget.style.color = "var(--tx-3)"; }}
            title="Zoom in"
          >+</button>
          <button style={btnStyle} onClick={zoomReset}
            onMouseEnter={e => { e.currentTarget.style.background = "var(--bg-3)"; e.currentTarget.style.color = "var(--tx-1)"; }}
            onMouseLeave={e => { e.currentTarget.style.background = "var(--bg-2)"; e.currentTarget.style.color = "var(--tx-3)"; }}
            title="Reset zoom"
          >⌂</button>
          <button style={btnStyle} onClick={zoomOut}
            onMouseEnter={e => { e.currentTarget.style.background = "var(--bg-3)"; e.currentTarget.style.color = "var(--tx-1)"; }}
            onMouseLeave={e => { e.currentTarget.style.background = "var(--bg-2)"; e.currentTarget.style.color = "var(--tx-3)"; }}
            title="Zoom out"
          >−</button>
          <button
            style={{
              ...btnStyle,
              marginLeft: 4,
              background: isLocked ? "#00d4ff22" : "var(--bg-2)",
              border: isLocked ? "1px solid #00d4ff66" : "1px solid var(--bd-1)",
              color: isLocked ? "#00d4ff" : "var(--tx-3)",
              fontSize: 14,
            }}
            onClick={toggleLock}
            title={isLocked ? "Unlock nodes" : "Lock nodes in place"}
          >{isLocked ? "🔒" : "🔓"}</button>
        </>)}
      </div>
    </>
  );
}

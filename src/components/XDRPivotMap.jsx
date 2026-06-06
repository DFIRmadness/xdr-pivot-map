import { useState, useEffect, useRef } from "react";
import { USE_CASES, ALL_EDGES } from "../data/useCases.js";
import { TABLES } from "../data/tables.js";
import { DOMAINS } from "../data/domains.js";
import Sidebar from "./Sidebar.jsx";
import PivotGraph from "./PivotGraph.jsx";
import StepPanel from "./StepPanel.jsx";
import { NodeTooltip, EdgeTooltip } from "./Tooltips.jsx";

export default function XDRPivotMap() {
  const svgRef = useRef(null);
  const [selectedUseCase, setSelectedUseCase] = useState(null);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [hoveredEdge, setHoveredEdge] = useState(null);
  const [dimensions, setDimensions] = useState({ w: 900, h: 600 });
  const [activeStep, setActiveStep] = useState(null);
  const [isDark, setIsDark] = useState(true);
  const [viewMode, setViewMode] = useState("graph");
  const [selectedDomain, setSelectedDomain] = useState(null);

  const activeUC = USE_CASES.find(u => u.id === selectedUseCase) ?? null;

  const ucTableIds = activeUC
    ? new Set(activeUC.links.flatMap(l => [l.from, l.to]))
    : null;
  const domainTableIds = selectedDomain
    ? new Set([
        ...TABLES.filter(t => t.domain === selectedDomain || t.extraDomains?.includes(selectedDomain)).map(t => t.id),
        "AlertInfo",
        "AlertEvidence",
      ])
    : null;

  // Combine UC + domain filters: intersect when both active, apply whichever is set
  const activeTableIds = (() => {
    if (!ucTableIds && !domainTableIds) return null;
    if (ucTableIds && domainTableIds) {
      return new Set([...ucTableIds].filter(id => domainTableIds.has(id)));
    }
    return ucTableIds ?? domainTableIds;
  })();

  // Single highlight color for both UC and domain isolation modes
  const highlightColor = activeUC
    ? activeUC.color
    : selectedDomain
    ? DOMAINS[selectedDomain].color
    : null;

  const activeEdgePairs = (() => {
    if (activeUC) {
      return new Set(activeUC.links.map(l => [l.from, l.to].sort().join("||")));
    }
    if (domainTableIds) {
      // Only highlight edges where both endpoints are in the selected domain
      return new Set(
        ALL_EDGES
          .filter(e => {
            const src = e.source.id || e.source;
            const tgt = e.target.id || e.target;
            return domainTableIds.has(src) && domainTableIds.has(tgt);
          })
          .map(e => {
            const src = e.source.id || e.source;
            const tgt = e.target.id || e.target;
            return [src, tgt].sort().join("||");
          })
      );
    }
    return null;
  })();

  // Read saved theme on mount
  useEffect(() => {
    const theme = localStorage.getItem('theme') || 'dark';
    setIsDark(theme !== 'light');
    document.documentElement.dataset.theme = theme;
  }, []);

  // Track container size
  useEffect(() => {
    const container = svgRef.current?.parentElement;
    if (!container) return;
    const ro = new ResizeObserver(entries => {
      for (const e of entries) setDimensions({ w: e.contentRect.width, h: e.contentRect.height });
    });
    ro.observe(container);
    return () => ro.disconnect();
  }, []);

  function toggleTheme() {
    const next = isDark ? 'light' : 'dark';
    setIsDark(!isDark);
    localStorage.setItem('theme', next);
    document.documentElement.dataset.theme = next;
  }

  function handleSelectUseCase(id) {
    setSelectedUseCase(id);
    setActiveStep(null);
    setViewMode("graph");
  }

  return (
    <div style={{
      display: "flex",
      height: "100vh",
      width: "100%",
      background: "var(--bg-0)",
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Courier New', monospace",
      color: "var(--tx-2)",
      overflow: "hidden",
    }}>
      <Sidebar
        selectedUseCase={selectedUseCase}
        onSelect={handleSelectUseCase}
        isDark={isDark}
        onToggleTheme={toggleTheme}
        selectedDomain={selectedDomain}
        onDomainSelect={d => setSelectedDomain(prev => prev === d ? null : d)}
      />

      {/* Graph canvas */}
      <div style={{ flex: 1, position: "relative", overflow: "hidden" }}>
        {/* Background grid */}
        <svg style={{ position: "absolute", inset: 0, pointerEvents: "none" }} width="100%" height="100%">
          <defs>
            <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="var(--grid)" strokeWidth="1"/>
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#grid)" />
        </svg>

        <PivotGraph
          svgRef={svgRef}
          activeUC={activeUC}
          activeTableIds={activeTableIds}
          activeEdgePairs={activeEdgePairs}
          activeStep={activeStep}
          dimensions={dimensions}
          onNodeHover={setHoveredNode}
          onEdgeHover={setHoveredEdge}
          isDark={isDark}
          viewMode={viewMode}
          onViewModeChange={setViewMode}
          highlightColor={highlightColor}
        />

        <StepPanel
          activeUC={activeUC}
          activeStep={activeStep}
          onStepClick={setActiveStep}
        />

        <NodeTooltip hoveredNode={hoveredNode} />
        <EdgeTooltip hoveredEdge={hoveredEdge} hoveredNode={hoveredNode} />

        {!selectedUseCase && !hoveredNode && (
          <div style={{
            position: "absolute", top: 16, right: 16,
            background: "var(--bg-float)", border: "1px solid var(--bd-1)", borderRadius: 4,
            padding: "14px 18px", maxWidth: 300, fontSize: 12, color: "var(--tx-4)", lineHeight: 1.7,
          }}>
            <div style={{ color: "#ffb34788", marginBottom: 8, fontSize: 11, letterSpacing: "0.15em", textTransform: "uppercase" }}>
              How to use
            </div>
            The XDR Map is the main focus of this tool. Use the map to see where an analyst may pivot with an IOC from one table to the next.<br/><br/>
            <strong style={{ color: "var(--tx-3)" }}>Categories</strong> will highlight tables relevant to the category.<br/><br/>
            <strong style={{ color: "var(--tx-3)" }}>Hunt Scenarios</strong> are rough sketches of how to pivot through the data. They should not be expected to be 100% accurate for every environment.
          </div>
        )}

        {/* Legend — always visible in graph mode */}
        {viewMode === "graph" && (
          <div style={{
            position: "absolute", bottom: 70, left: 16,
            background: "var(--bg-float)", border: "1px solid var(--bd-1)", borderRadius: 4,
            padding: "8px 12px", fontSize: 11, color: "var(--tx-5)", lineHeight: 1.9,
            pointerEvents: "none",
          }}>
            <div style={{ fontSize: 10, letterSpacing: "0.12em", color: "var(--tx-5)", textTransform: "uppercase", marginBottom: 4 }}>
              Table Source
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
              <span style={{
                display: "inline-flex", alignItems: "center", justifyContent: "center",
                width: 17, height: 17, borderRadius: "50%", flexShrink: 0,
                border: "1.5px solid var(--tx-5)",
              }} />
              Defender XDR
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
              <span style={{
                display: "inline-flex", alignItems: "center", justifyContent: "center",
                width: 17, height: 17, borderRadius: "50%", flexShrink: 0,
                border: "1.5px solid #fb923c", color: "#fb923c",
                fontSize: 10, fontWeight: 700, fontFamily: "inherit",
              }}>S</span>
              Azure Sentinel
            </div>

            <div style={{ borderTop: "1px solid var(--bd-2)", marginTop: 7, paddingTop: 7 }}>
              <div style={{ fontSize: 10, letterSpacing: "0.12em", color: "var(--tx-5)", textTransform: "uppercase", marginBottom: 5 }}>
                Token Tracking
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                <svg width="22" height="22" viewBox="-11 -11 22 22" style={{ flexShrink: 0, overflow: "visible" }}>
                  <circle r={5} fill="none" stroke="#f0c840" strokeWidth="1.2" strokeDasharray="2 2" strokeDashoffset="0" className="li-ring-inner" />
                  <circle r={8} fill="none" stroke="#f0c840" strokeWidth="0.9" strokeDasharray="3 1.5" strokeDashoffset="0" className="li-ring-outer"
                    style={{ filter: "drop-shadow(0 0 2px #f0c840)" }} />
                </svg>
                <span style={{ color: "#f0c840cc" }}>Linkable Identifiers</span>
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 7, marginTop: 1 }}>
                <svg width="22" height="4" style={{ flexShrink: 0, overflow: "visible" }}>
                  <line x1="0" y1="2" x2="22" y2="2" stroke="#f0c840" strokeWidth="1.5" strokeDasharray="5 4" className="li-edge-overlay" />
                </svg>
                <span style={{ color: "#f0c840cc" }}>Linkable ID edge</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

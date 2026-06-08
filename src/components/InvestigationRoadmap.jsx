import { useState, useEffect } from "react";
import { ROADMAP_TYPES, ROADMAPS } from "../data/roadmaps.js";
import { TABLES } from "../data/tables.js";
import { DOMAINS } from "../data/domains.js";
import { COLUMN_INFO } from "../data/columns.js";
import { ColumnTooltip } from "./Tooltips.jsx";

const PICERL_META = {
  identification: { label: "IDENTIFICATION", color: "#00d4ff" },
  containment:    { label: "CONTAINMENT",    color: "#f97316" },
  eradication:    { label: "ERADICATION",    color: "#ef4444" },
  recovery:       { label: "RECOVERY",       color: "#22c55e" },
  lessons:        { label: "LESSONS LEARNED", color: "#a78bfa" },
};

function tableColor(tableName) {
  const t = TABLES.find(t => t.id === tableName);
  return t ? DOMAINS[t.domain].color : "#8890b8";
}

function domainLabel(tableName) {
  const t = TABLES.find(t => t.id === tableName);
  return t ? DOMAINS[t.domain].label : "XDR";
}

function tablePreview(tableName) {
  const t = TABLES.find(t => t.id === tableName);
  return t?.preview ?? false;
}

function tableAzure(tableName) {
  const t = TABLES.find(t => t.id === tableName);
  return t?.azure ?? false;
}

function StopCard({ step, index, total, roadmapColor, hoveredCol, setHoveredCol }) {
  const [kqlOpen, setKqlOpen] = useState(false);
  const col = tableColor(step.table);
  const isPreview = tablePreview(step.table);
  const isAzure = tableAzure(step.table);
  const picerlMetas = step.picerl
    ? (Array.isArray(step.picerl) ? step.picerl : [step.picerl]).map(p => PICERL_META[p]).filter(Boolean)
    : [];
  const isLast = index === total - 1;

  return (
    <div style={{ display: "flex", gap: 0, position: "relative" }}>
      {/* Timeline spine + node */}
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", flexShrink: 0, width: 48, marginTop: 2 }}>
        {/* Circle */}
        <div style={{
          width: 32, height: 32, borderRadius: "50%",
          background: roadmapColor + "22",
          border: `2px solid ${roadmapColor}`,
          display: "flex", alignItems: "center", justifyContent: "center",
          fontSize: 13, fontWeight: 700, color: roadmapColor,
          flexShrink: 0, zIndex: 1,
          boxShadow: `0 0 12px ${roadmapColor}44`,
        }}>
          {index + 1}
        </div>
        {/* Line below */}
        {!isLast && (
          <div style={{
            width: 2,
            flex: 1,
            minHeight: 32,
            background: `linear-gradient(to bottom, ${roadmapColor}88, ${roadmapColor}22)`,
            marginTop: 4,
          }} />
        )}
      </div>

      {/* Card */}
      <div style={{
        flex: 1,
        marginLeft: 16,
        marginBottom: isLast ? 0 : 24,
        background: "var(--bg-float)",
        border: `1px solid ${col}33`,
        borderRadius: 4,
        overflow: "hidden",
      }}>
        {/* Card header */}
        <div style={{
          padding: "10px 14px",
          background: col + "0d",
          borderBottom: `1px solid ${col}22`,
          display: "flex", alignItems: "center", justifyContent: "space-between",
        }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 7, flexWrap: "wrap", marginBottom: 2 }}>
              <span style={{ fontSize: 13, fontWeight: 700, color: col, letterSpacing: "0.04em" }}>
                {step.table}
              </span>
              {isPreview && (
                <span style={{
                  fontSize: 10, padding: "1px 5px", borderRadius: 2,
                  background: "#a78bfa18", border: "1px solid #a78bfa55",
                  color: "#a78bfa", letterSpacing: "0.04em", whiteSpace: "nowrap",
                }}>
                  PREVIEW
                </span>
              )}
              {isAzure && (
                <span style={{
                  fontSize: 10, padding: "1px 5px", borderRadius: 2,
                  background: "#fb923c18", border: "1px solid #fb923c55",
                  color: "#fb923c", letterSpacing: "0.04em", whiteSpace: "nowrap",
                }}>
                  AZURE
                </span>
              )}
              {picerlMetas.map((meta, i) => (
                <span key={i} style={{
                  fontSize: 10, padding: "1px 5px", borderRadius: 2,
                  background: meta.color + "18",
                  border: `1px solid ${meta.color}55`,
                  color: meta.color,
                  letterSpacing: "0.04em", whiteSpace: "nowrap",
                }}>
                  {meta.label}
                </span>
              ))}
            </div>
            <div style={{ fontSize: 11, color: roadmapColor, fontWeight: 600, letterSpacing: "0.05em" }}>
              {step.label}
            </div>
          </div>
          <div style={{
            fontSize: 10, color: "var(--tx-4)", letterSpacing: "0.1em",
            textTransform: "uppercase", padding: "2px 6px", borderRadius: 2,
            background: "var(--bg-3)", border: "1px solid var(--bd-2)", flexShrink: 0,
          }}>
            {domainLabel(step.table)}
          </div>
        </div>

        {/* Goal */}
        <div style={{ padding: "12px 14px 8px" }}>
          <div style={{ fontSize: 10, color: "var(--tx-4)", letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 6 }}>
            What to look for
          </div>
          <div style={{ fontSize: 12, color: "var(--tx-3)", lineHeight: 1.7 }}>
            {step.goal}
          </div>
        </div>

        {/* Pivot columns */}
        <div style={{ padding: "0 14px 8px" }}>
          <div style={{ fontSize: 10, color: "var(--tx-4)", letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 6 }}>
            Pivot Columns
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
            {step.pivotColumns.map((colName, ci) => {
              const hasInfo = !!COLUMN_INFO[colName];
              const isHovered = hoveredCol?.name === colName;
              return (
                <span
                  key={ci}
                  onMouseEnter={() => hasInfo && setHoveredCol({ name: colName })}
                  onMouseLeave={() => setHoveredCol(null)}
                  onClick={() => { if (hasInfo && COLUMN_INFO[colName].docUrl) window.open(COLUMN_INFO[colName].docUrl, "_blank", "noopener"); }}
                  style={{
                    fontSize: 11, padding: "3px 8px", borderRadius: 2,
                    background: isHovered ? col + "22" : "var(--bg-3)",
                    border: `1px solid ${isHovered ? col + "88" : col + "33"}`,
                    color: isHovered ? col : col + "cc",
                    letterSpacing: "0.02em",
                    cursor: hasInfo ? "pointer" : "default",
                    transition: "all 0.15s",
                    userSelect: "none",
                  }}
                >
                  {colName}{hasInfo ? " ?" : ""}
                </span>
              );
            })}
          </div>
        </div>

        {/* KQL toggle */}
        <div
          onClick={() => setKqlOpen(o => !o)}
          style={{
            padding: "5px 14px 8px",
            cursor: "pointer", fontSize: 11,
            color: kqlOpen ? col : "var(--tx-3)",
            letterSpacing: "0.1em", textTransform: "uppercase",
            background: kqlOpen ? col + "08" : "transparent",
            transition: "all 0.15s", userSelect: "none",
          }}
        >
          {kqlOpen ? "▾ hide query" : "▸ show kql"}
        </div>

        {kqlOpen && (
          <div style={{ padding: "0 14px 14px" }}>
            <pre style={{
              margin: 0, fontSize: 12, lineHeight: 1.65,
              color: "var(--tx-2)",
              fontFamily: "'JetBrains Mono', 'Fira Code', 'Courier New', monospace",
              whiteSpace: "pre-wrap", wordBreak: "break-word",
              border: `1px solid ${col}22`, borderRadius: 3,
              padding: "10px 12px", background: "var(--bg-3)",
            }}>
              {step.kql}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}

function RoadmapTypeButton({ type, isSelected, onClick }) {
  return (
    <button
      onClick={onClick}
      style={{
        width: "100%",
        background: isSelected ? type.color + "11" : "transparent",
        border: "none",
        borderLeft: isSelected ? `3px solid ${type.color}` : "3px solid transparent",
        color: isSelected ? type.color : "var(--tx-3)",
        padding: "12px 18px",
        textAlign: "left", cursor: "pointer",
        display: "flex", alignItems: "center", gap: 12,
        transition: "all 0.15s", fontFamily: "inherit",
      }}
    >
      <span style={{ fontSize: 22, flexShrink: 0 }}>{type.icon}</span>
      <div>
        <div style={{ fontSize: 13, fontWeight: 600, letterSpacing: "0.02em" }}>
          {type.label}
        </div>
        <div style={{
          fontSize: 10, marginTop: 3, color: isSelected ? type.color + "99" : "var(--tx-4)",
          letterSpacing: "0.04em", lineHeight: 1.5,
        }}>
          {ROADMAPS[type.id].steps.length} stops
        </div>
      </div>
    </button>
  );
}

export default function InvestigationRoadmap() {
  const [selectedType, setSelectedType] = useState(null);
  const [isDark, setIsDark]             = useState(true);
  const [hoveredCol, setHoveredCol]     = useState(null);

  useEffect(() => {
    const theme = localStorage.getItem("theme") || "dark";
    setIsDark(theme !== "light");
    document.documentElement.dataset.theme = theme;
  }, []);

  function toggleTheme() {
    const next = isDark ? "light" : "dark";
    setIsDark(!isDark);
    localStorage.setItem("theme", next);
    document.documentElement.dataset.theme = next;
  }

  const activeType   = ROADMAP_TYPES.find(t => t.id === selectedType) ?? null;
  const activeRoadmap = activeType ? ROADMAPS[activeType.id] : null;

  return (
    <div style={{
      display: "flex", height: "100vh", width: "100%",
      background: "var(--bg-0)",
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Courier New', monospace",
      color: "var(--tx-2)", overflow: "hidden",
    }}>

      {/* ── Sidebar ────────────────────────────────────────────────────────── */}
      <div style={{
        width: 270, flexShrink: 0,
        borderRight: "1px solid var(--bd-1)",
        display: "flex", flexDirection: "column",
        background: "var(--bg-2)", overflow: "hidden",
      }}>
        {/* Header */}
        <div style={{ padding: "20px 18px 14px", borderBottom: "1px solid var(--bd-1)", position: "relative" }}>
          <button
            onClick={toggleTheme}
            style={{
              position: "absolute", top: 16, right: 14,
              background: "none", border: "none", fontSize: 11,
              color: "var(--tx-4)", cursor: "pointer",
              letterSpacing: "0.08em", fontFamily: "inherit", padding: "2px 4px",
            }}
            onMouseEnter={e => e.currentTarget.style.color = "var(--tx-1)"}
            onMouseLeave={e => e.currentTarget.style.color = "var(--tx-4)"}
          >
            {isDark ? "☀ Light" : "◐ Dark"}
          </button>
          <a href="/DefenderXDR-pivot-map/" style={{
            display: "inline-flex", alignItems: "center", gap: 5,
            fontSize: 11, color: "var(--tx-4)", textDecoration: "none",
            letterSpacing: "0.08em", marginBottom: 12, transition: "color 0.15s",
          }}
            onMouseEnter={e => e.currentTarget.style.color = "var(--tx-1)"}
            onMouseLeave={e => e.currentTarget.style.color = "var(--tx-4)"}
          >
            ← Home
          </a>
          <div style={{ fontSize: 11, letterSpacing: "0.2em", color: "var(--tx-4)", marginBottom: 6, textTransform: "uppercase" }}>
            Defender XDR
          </div>
          <div style={{ fontSize: 16, fontWeight: 700, color: "var(--tx-1)", lineHeight: 1.3 }}>
            Incident Roadmaps
          </div>
          <div style={{ fontSize: 11, color: "var(--tx-4)", marginTop: 10, letterSpacing: "0.06em" }}>
            IOC pivots and attack scenario walkthroughs
          </div>
        </div>

        {/* Investigation type list */}
        <div style={{ flex: 1, overflowY: "auto", padding: "6px 0" }}>
          {/* IOC Pivot section */}
          <div style={{
            fontSize: 9, letterSpacing: "0.18em", textTransform: "uppercase",
            color: "var(--tx-5)", padding: "10px 18px 4px",
          }}>
            IOC Pivots
          </div>
          {ROADMAP_TYPES.filter(t => t.kind === "pivot").map(type => (
            <RoadmapTypeButton
              key={type.id}
              type={type}
              isSelected={selectedType === type.id}
              onClick={() => setSelectedType(selectedType === type.id ? null : type.id)}
            />
          ))}

          {/* Attack Scenarios section */}
          <div style={{
            fontSize: 9, letterSpacing: "0.18em", textTransform: "uppercase",
            color: "var(--tx-5)", padding: "14px 18px 4px",
            borderTop: "1px solid var(--bd-2)", marginTop: 8,
          }}>
            Attack Scenarios
          </div>
          {ROADMAP_TYPES.filter(t => t.kind === "scenario").map(type => (
            <RoadmapTypeButton
              key={type.id}
              type={type}
              isSelected={selectedType === type.id}
              onClick={() => setSelectedType(selectedType === type.id ? null : type.id)}
            />
          ))}
        </div>

        {/* Footer */}
        <div style={{ padding: "12px 18px", borderTop: "1px solid var(--bd-1)" }}>
          <div style={{ fontSize: 10, color: "var(--tx-5)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
            Defender XDR · Advanced Hunting
          </div>
        </div>
      </div>

      {/* ── Main panel ─────────────────────────────────────────────────────── */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden", position: "relative" }}>

        {/* Background grid */}
        <svg style={{ position: "absolute", inset: 0, pointerEvents: "none", zIndex: 0 }} width="100%" height="100%">
          <defs>
            <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="var(--grid)" strokeWidth="1"/>
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#grid)" />
        </svg>

        {!activeType ? (
          <div style={{
            position: "absolute", top: "50%", left: "50%", transform: "translate(-50%,-50%)",
            background: "var(--bg-float)", border: "1px solid #00d4ff55", borderRadius: 4,
            padding: "28px 32px", maxWidth: 440, fontSize: 14, color: "var(--tx-1)", lineHeight: 1.8,
            zIndex: 1, textAlign: "center",
          }}>
            <div style={{ color: "#00d4ff", marginBottom: 12, fontSize: 12, letterSpacing: "0.15em", textTransform: "uppercase", fontWeight: 700 }}>
              How to use
            </div>
            Select an investigation type from the left panel.<br/><br/>
            Follow the ordered stops to trace the full table chain — each stop shows what to look for, which columns to pivot on, and a ready-to-run KQL query.<br/><br/>
            <span style={{ fontSize: 13, color: "var(--tx-2)", lineHeight: 1.8, display: "block", borderTop: "1px solid var(--bd-1)", paddingTop: 14, marginTop: 4 }}>
              <span style={{ display: "inline-block", transform: "scale(4.0)", transformOrigin: "center", marginRight: 24 }}>⚠</span> The investigation roadmaps are AI-driven rough sketches of how an investigation might look — meant to drive ideas, not prescribe exact steps. Treat them as a starting point, not a definitive playbook.
            </span>
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", height: "100%", zIndex: 1, position: "relative" }}>

            {/* Investigation header */}
            <div style={{
              background: activeType.color + "0d",
              borderBottom: `1px solid ${activeType.color}33`,
              padding: "20px 32px",
              flexShrink: 0,
              display: "flex", alignItems: "center", gap: 20,
            }}>
              <div style={{ fontSize: 48, lineHeight: 1, flexShrink: 0 }}>{activeType.icon}</div>
              <div>
                <div style={{ fontSize: 11, color: activeType.color + "88", letterSpacing: "0.2em", textTransform: "uppercase", marginBottom: 4 }}>
                  Investigation Roadmap
                </div>
                <div style={{ fontSize: 22, fontWeight: 700, color: activeType.color, marginBottom: 6 }}>
                  {activeType.label}
                </div>
                <div style={{ fontSize: 13, color: "var(--tx-3)", lineHeight: 1.6, maxWidth: 560 }}>
                  {activeType.description}
                </div>
              </div>
              <div style={{ marginLeft: "auto", flexShrink: 0, textAlign: "right" }}>
                <div style={{ fontSize: 28, fontWeight: 700, color: activeType.color }}>
                  {activeRoadmap.steps.length}
                </div>
                <div style={{ fontSize: 10, color: "var(--tx-4)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
                  stops
                </div>
              </div>
            </div>

            {/* Roadmap stops */}
            <div style={{ flex: 1, overflowY: "auto", padding: "32px 32px 48px" }}>
              {activeRoadmap.steps.map((step, i) => (
                <StopCard
                  key={i}
                  step={step}
                  index={i}
                  total={activeRoadmap.steps.length}
                  roadmapColor={activeType.color}
                  hoveredCol={hoveredCol}
                  setHoveredCol={setHoveredCol}
                />
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Column hover tooltip */}
      {hoveredCol && (
        <ColumnTooltip col={hoveredCol.name} />
      )}
    </div>
  );
}

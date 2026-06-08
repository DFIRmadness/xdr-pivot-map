import { useState, useEffect, useMemo } from "react";
import { TACTICS, TECHNIQUES } from "../data/mitreAttack.js";
import { CLOUD_TECHNIQUES } from "../data/mitreAttackCloud.js";
import { TABLES } from "../data/tables.js";
import { DOMAINS } from "../data/domains.js";
import { COLUMN_INFO } from "../data/columns.js";
import { ColumnTooltip } from "./Tooltips.jsx";

function tableColor(tableName) {
  const t = TABLES.find(t => t.id === tableName);
  return t ? DOMAINS[t.domain].color : "#8890b8";
}

function tableDeprecation(tableName) {
  const t = TABLES.find(t => t.id === tableName);
  return t?.deprecated ? { replacedBy: t.replacedBy } : null;
}

function tablePreview(tableName) {
  const t = TABLES.find(t => t.id === tableName);
  return t?.preview ?? false;
}

export default function MitreCrosswalk() {
  const [selectedTactic, setSelectedTactic] = useState(null);
  const [expandedTechnique, setExpandedTechnique] = useState(null);
  const [expandedKql, setExpandedKql] = useState(null); // "techId:mappingIndex"
  const [isDark, setIsDark] = useState(true);
  const [hoveredCol, setHoveredCol] = useState(null);
  const [matrixView, setMatrixView] = useState("enterprise"); // "enterprise" | "cloud" | "blended"

  const activeTechniques = useMemo(() => {
    if (matrixView === "enterprise") return TECHNIQUES;
    if (matrixView === "cloud") return CLOUD_TECHNIQUES;
    // Blended: merge by technique ID, deduplicate mappings
    const map = new Map();
    [...TECHNIQUES, ...CLOUD_TECHNIQUES].forEach(t => {
      if (!map.has(t.id)) {
        map.set(t.id, { ...t, _matrix: t.matrix ?? "enterprise" });
      } else {
        const existing = map.get(t.id);
        map.set(t.id, {
          ...existing,
          tacticIds: [...new Set([...existing.tacticIds, ...t.tacticIds])],
          xdrMappings: [...existing.xdrMappings, ...t.xdrMappings],
          _matrix: "both",
        });
      }
    });
    return Array.from(map.values());
  }, [matrixView]);

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

  const tactic = TACTICS.find(t => t.id === selectedTactic) ?? null;
  const techniques = tactic
    ? activeTechniques.filter(t => t.tacticIds.includes(tactic.id))
    : [];

  function toggleTechnique(id) {
    setExpandedTechnique(prev => prev === id ? null : id);
    setExpandedKql(null);
  }

  function toggleKql(key) {
    setExpandedKql(prev => prev === key ? null : key);
  }

  return (
    <div style={{
      display: "flex", height: "100vh", width: "100%",
      background: "var(--bg-0)",
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Courier New', monospace",
      color: "var(--tx-2)", overflow: "hidden",
    }}>

      {/* ── Sidebar ──────────────────────────────────────────────────────── */}
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
            letterSpacing: "0.08em", marginBottom: 12,
            transition: "color 0.15s",
          }}
            onMouseEnter={e => e.currentTarget.style.color = "var(--tx-1)"}
            onMouseLeave={e => e.currentTarget.style.color = "var(--tx-4)"}
          >
            ← Home
          </a>
          <div style={{ fontSize: 11, letterSpacing: "0.2em", color: "var(--tx-4)", marginBottom: 6, textTransform: "uppercase" }}>
            MITRE ATT&amp;CK
          </div>
          <div style={{ fontSize: 16, fontWeight: 700, color: "var(--tx-1)", lineHeight: 1.3, marginBottom: 12 }}>
            {matrixView === "enterprise" ? "Enterprise" : matrixView === "cloud" ? "Cloud" : "Blended"}<br/>Tactics
          </div>

          {/* Matrix toggle */}
          <div style={{
            display: "flex", borderRadius: 3, overflow: "hidden",
            border: "1px solid var(--bd-2)", fontSize: 10, letterSpacing: "0.08em",
          }}>
            {[
              { key: "enterprise", label: "ENTERPRISE" },
              { key: "cloud",      label: "CLOUD" },
              { key: "blended",    label: "BLENDED" },
            ].map(({ key, label }) => (
              <button
                key={key}
                onClick={() => { setMatrixView(key); setSelectedTactic(null); setExpandedTechnique(null); setExpandedKql(null); }}
                style={{
                  flex: 1, border: "none", padding: "5px 0",
                  cursor: "pointer", fontFamily: "inherit", fontSize: 10, letterSpacing: "0.07em",
                  background: matrixView === key ? "#ff475722" : "transparent",
                  color: matrixView === key ? "#ff4757" : "var(--tx-4)",
                  borderRight: key !== "blended" ? "1px solid var(--bd-2)" : "none",
                  fontWeight: matrixView === key ? 700 : 400,
                  transition: "all 0.15s",
                }}
              >
                {label}
              </button>
            ))}
          </div>

          <div style={{ fontSize: 11, color: "var(--tx-4)", marginTop: 10, letterSpacing: "0.06em" }}>
            Select a tactic to browse techniques
          </div>
        </div>

        {/* Tactic list */}
        <div style={{ flex: 1, overflowY: "auto", padding: "6px 0" }}>
          {TACTICS.map(t => {
            const isSelected = selectedTactic === t.id;
            const count = activeTechniques.filter(te => te.tacticIds.includes(t.id)).length;
            if (count === 0) return null;
            return (
              <button
                key={t.id}
                onClick={() => setSelectedTactic(isSelected ? null : t.id)}
                style={{
                  width: "100%", background: isSelected ? t.color + "11" : "transparent",
                  border: "none", borderLeft: isSelected ? `3px solid ${t.color}` : "3px solid transparent",
                  color: isSelected ? t.color : "var(--tx-3)",
                  padding: "10px 18px", textAlign: "left", cursor: "pointer",
                  display: "flex", alignItems: "flex-start", gap: 10,
                  transition: "all 0.15s", fontFamily: "inherit",
                }}
              >
                <span style={{ fontSize: 16, flexShrink: 0, marginTop: 1 }}>{t.icon}</span>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, letterSpacing: "0.02em", lineHeight: 1.4 }}>
                    {t.name}
                  </div>
                  <div style={{
                    fontSize: 10, marginTop: 3, padding: "1px 5px", borderRadius: 2, display: "inline-block",
                    background: isSelected ? t.color + "22" : "var(--bd-1)",
                    color: isSelected ? t.color : "var(--tx-4)",
                    letterSpacing: "0.06em",
                  }}>
                    {count} technique{count !== 1 ? "s" : ""}
                  </div>
                </div>
              </button>
            );
          })}
        </div>

        {/* Footer */}
        <div style={{ padding: "12px 18px", borderTop: "1px solid var(--bd-1)" }}>
          <div style={{ fontSize: 10, color: "var(--tx-5)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
            ATT&amp;CK v15 · {matrixView === "enterprise" ? "Enterprise" : matrixView === "cloud" ? "Cloud (IaaS/SaaS/IdP)" : "Enterprise + Cloud"}
          </div>
        </div>
      </div>

      {/* ── Main panel ───────────────────────────────────────────────────── */}
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

        {!tactic ? (
          // No selection hint
          <div style={{
            position: "absolute", top: "50%", left: "50%", transform: "translate(-50%,-50%)",
            background: "var(--bg-float)", border: "1px solid #ff475755", borderRadius: 4,
            padding: "28px 32px", maxWidth: 440, fontSize: 14, color: "var(--tx-1)", lineHeight: 1.8,
            zIndex: 1, textAlign: "center",
          }}>
            <div style={{ color: "#ff4757", marginBottom: 12, fontSize: 12, letterSpacing: "0.15em", textTransform: "uppercase", fontWeight: 700 }}>
              How to use
            </div>
            Select a tactic from the left panel.<br/><br/>
            Each technique shows the relevant Defender XDR tables, key columns, and ready-to-run KQL hunting queries.<br/><br/>
            <span style={{ fontSize: 13, color: "var(--tx-2)", lineHeight: 1.8, display: "block", borderTop: "1px solid var(--bd-1)", paddingTop: 14, marginTop: 4 }}>
              <span style={{ display: "inline-block", transform: "scale(2.8)", transformOrigin: "center", marginRight: 16 }}>⚠</span> The technique mappings and KQL queries are AI-driven and meant to drive ideas — they may not be 100% accurate for every environment. Treat them as a starting point, not a definitive reference.
            </span>
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", height: "100%", zIndex: 1, position: "relative" }}>

            {/* Tactic header */}
            <div style={{
              background: tactic.color + "0d", borderBottom: `1px solid ${tactic.color}33`,
              padding: "16px 24px", flexShrink: 0,
            }}>
              <div style={{ fontSize: 11, color: tactic.color + "88", letterSpacing: "0.18em", textTransform: "uppercase", marginBottom: 5 }}>
                {tactic.id}
              </div>
              <div style={{ fontSize: 20, fontWeight: 700, color: tactic.color, display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
                <span>{tactic.icon}</span>{tactic.name}
              </div>
              <div style={{ fontSize: 13, color: "var(--tx-3)", lineHeight: 1.6 }}>{tactic.description}</div>
              <div style={{ marginTop: 8, fontSize: 11, color: tactic.color + "77", letterSpacing: "0.08em" }}>
                {techniques.length} technique{techniques.length !== 1 ? "s" : ""} mapped to Defender XDR
              </div>
            </div>

            {/* Technique list */}
            <div style={{ flex: 1, overflowY: "auto" }}>
              {techniques.map(tech => {
                const isOpen = expandedTechnique === tech.id;
                return (
                  <div key={tech.id} style={{ borderBottom: "1px solid var(--bd-2)" }}>

                    {/* Technique row */}
                    <div
                      onClick={() => toggleTechnique(tech.id)}
                      style={{
                        padding: "14px 24px",
                        cursor: "pointer",
                        background: isOpen ? tactic.color + "0a" : "transparent",
                        borderLeft: isOpen ? `3px solid ${tactic.color}` : "3px solid transparent",
                        transition: "all 0.15s",
                        display: "flex", alignItems: "flex-start", gap: 16,
                      }}
                    >
                      {/* ID badge */}
                      <div style={{ flexShrink: 0, marginTop: 2, display: "flex", flexDirection: "column", gap: 3, alignItems: "flex-start" }}>
                        <div style={{
                          fontSize: 10, fontWeight: 700,
                          padding: "2px 6px", borderRadius: 2,
                          background: isOpen ? tactic.color + "22" : "var(--bg-3)",
                          border: `1px solid ${isOpen ? tactic.color + "55" : "var(--bd-2)"}`,
                          color: isOpen ? tactic.color : "var(--tx-4)",
                          letterSpacing: "0.06em",
                        }}>
                          {tech.id}
                        </div>
                        {matrixView === "blended" && tech._matrix && (
                          <div style={{
                            fontSize: 9, fontWeight: 700, padding: "1px 5px", borderRadius: 2,
                            letterSpacing: "0.06em",
                            background: tech._matrix === "cloud" ? "#00d4ff18" : tech._matrix === "both" ? "#a855f718" : "#ffb34718",
                            border: `1px solid ${tech._matrix === "cloud" ? "#00d4ff55" : tech._matrix === "both" ? "#a855f755" : "#ffb34755"}`,
                            color: tech._matrix === "cloud" ? "#00d4ff" : tech._matrix === "both" ? "#a855f7" : "#ffb347",
                          }}>
                            {tech._matrix === "cloud" ? "CLOUD" : tech._matrix === "both" ? "E+C" : "ENT"}
                          </div>
                        )}
                      </div>

                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 14, fontWeight: 700, color: isOpen ? tactic.color : "var(--tx-1)", marginBottom: 4 }}>
                          {tech.name}
                        </div>
                        <div style={{ fontSize: 12, color: "var(--tx-3)", lineHeight: 1.6 }}>
                          {isOpen ? tech.description : tech.description.slice(0, 120) + (tech.description.length > 120 ? "…" : "")}
                        </div>
                        {!isOpen && (
                          <div style={{ marginTop: 6, display: "flex", gap: 6, flexWrap: "wrap" }}>
                            {tech.xdrMappings.map((m, i) => {
                              const dep = tableDeprecation(m.table);
                              return (
                                <span key={i} style={{
                                  fontSize: 10, padding: "2px 7px", borderRadius: 2,
                                  background: "var(--bg-3)",
                                  border: `1px solid ${dep ? "#f59e0b55" : "var(--bd-2)"}`,
                                  color: dep ? "#f59e0b" : tableColor(m.table),
                                  letterSpacing: "0.04em",
                                }}>
                                  {m.table}{dep ? " ⚠" : ""}
                                </span>
                              );
                            })}
                          </div>
                        )}
                      </div>

                      {/* Expand chevron */}
                      <div style={{ fontSize: 11, color: isOpen ? tactic.color : "var(--tx-4)", flexShrink: 0, marginTop: 2 }}>
                        {isOpen ? "▾" : "▸"} {tech.xdrMappings.length} mapping{tech.xdrMappings.length !== 1 ? "s" : ""}
                      </div>
                    </div>

                    {/* Expanded: mapping cards */}
                    {isOpen && (
                      <div style={{ background: "var(--bg-3)", borderTop: `1px solid ${tactic.color}22` }}>
                        {tech.xdrMappings.map((mapping, mi) => {
                          const kqlKey = `${tech.id}:${mi}`;
                          const kqlOpen = expandedKql === kqlKey;
                          const col = tableColor(mapping.table);
                          const dep = tableDeprecation(mapping.table);
                          const isPreview = tablePreview(mapping.table);
                          return (
                            <div key={mi} style={{
                              margin: "12px 24px",
                              background: "var(--bg-float)",
                              border: `1px solid ${dep ? "#f59e0b44" : isPreview ? "#a78bfa33" : col + "33"}`,
                              borderRadius: 4, overflow: "hidden",
                            }}>
                              {/* Card header */}
                              <div style={{
                                padding: "10px 14px",
                                background: dep ? "#f59e0b0a" : isPreview ? "#a78bfa0a" : col + "0d",
                                borderBottom: `1px solid ${dep ? "#f59e0b22" : isPreview ? "#a78bfa22" : col + "22"}`,
                                display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, flexWrap: "wrap",
                              }}>
                                <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                                  <span style={{ fontSize: 13, fontWeight: 700, color: dep ? "#f59e0b" : col, letterSpacing: "0.04em" }}>
                                    {mapping.table}
                                  </span>
                                  {dep && (
                                    <span style={{
                                      fontSize: 10, padding: "1px 6px", borderRadius: 2,
                                      background: "#f59e0b18", border: "1px solid #f59e0b55",
                                      color: "#f59e0b", letterSpacing: "0.04em",
                                    }}>
                                      DEPRECATED → {dep.replacedBy}
                                    </span>
                                  )}
                                  {isPreview && !dep && (
                                    <span style={{
                                      fontSize: 10, padding: "1px 6px", borderRadius: 2,
                                      background: "#a78bfa18", border: "1px solid #a78bfa55",
                                      color: "#a78bfa", letterSpacing: "0.04em",
                                    }}>
                                      PREVIEW
                                    </span>
                                  )}
                                </div>
                                <div style={{
                                  fontSize: 10, color: "var(--tx-4)", letterSpacing: "0.1em",
                                  textTransform: "uppercase", padding: "2px 6px", borderRadius: 2,
                                  background: "var(--bg-3)", border: "1px solid var(--bd-2)",
                                }}>
                                  {(() => { const t = TABLES.find(t => t.id === mapping.table); return t ? DOMAINS[t.domain].label : "XDR"; })()}
                                </div>
                              </div>

                              {/* Columns */}
                              <div style={{ padding: "10px 14px 4px" }}>
                                <div style={{ fontSize: 10, color: "var(--tx-4)", letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 7 }}>
                                  Key Columns
                                </div>
                                <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginBottom: 10 }}>
                                  {mapping.columns.map((col2, ci) => {
                                    const hasInfo = !!COLUMN_INFO[col2];
                                    return (
                                      <span
                                        key={ci}
                                        onMouseEnter={() => hasInfo && setHoveredCol({ name: col2 })}
                                        onMouseLeave={() => setHoveredCol(null)}
                                        onClick={() => { if (hasInfo && COLUMN_INFO[col2].docUrl) window.open(COLUMN_INFO[col2].docUrl, "_blank", "noopener"); }}
                                        style={{
                                          fontSize: 11, padding: "3px 8px", borderRadius: 2,
                                          background: hoveredCol?.name === col2 ? col + "22" : "var(--bg-3)",
                                          border: `1px solid ${hoveredCol?.name === col2 ? col + "88" : col + "33"}`,
                                          color: hoveredCol?.name === col2 ? col : col + "cc",
                                          letterSpacing: "0.02em",
                                          cursor: hasInfo ? "pointer" : "default",
                                          transition: "all 0.15s",
                                          userSelect: "none",
                                        }}
                                      >
                                        {col2}{hasInfo ? " ?" : ""}
                                      </span>
                                    );
                                  })}
                                </div>
                              </div>

                              {/* KQL toggle */}
                              <div
                                onClick={() => toggleKql(kqlKey)}
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

                              {/* KQL block */}
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
                                    {mapping.kql}
                                  </pre>
                                </div>
                              )}
                            </div>
                          );
                        })}
                        <div style={{ height: 4 }} />
                      </div>
                    )}
                  </div>
                );
              })}
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

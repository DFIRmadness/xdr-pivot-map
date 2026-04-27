import { useState, useEffect } from "react";
import { DOMAINS } from "../data/domains.js";
import { TABLES } from "../data/tables.js";
import { COLUMN_INFO } from "../data/columns.js";

function tableDeprecation(tableId) {
  const t = TABLES.find(t => t.id === tableId);
  return t?.deprecated ? { replacedBy: t.replacedBy } : null;
}

export default function StepPanel({ activeUC, activeStep, onStepClick }) {
  const [expandedKql, setExpandedKql] = useState(null);
  const [expandedCol, setExpandedCol] = useState(null); // "stepIndex:colKey"
  const [minimized, setMinimized] = useState(false);

  useEffect(() => {
    setExpandedKql(null);
    setExpandedCol(null);
    setMinimized(false);
  }, [activeUC]);

  if (!activeUC) return null;

  function toggleKql(i) {
    setExpandedKql(prev => prev === i ? null : i);
  }

  function toggleCol(key) {
    setExpandedCol(prev => prev === key ? null : key);
  }

  return (
    <div style={{
      position: "absolute",
      top: 16,
      right: 16,
      width: minimized ? "auto" : 460,
      background: "var(--bg-float)",
      border: `1px solid ${activeUC.color}33`,
      borderRadius: 4,
      overflow: "hidden",
      maxHeight: minimized ? "none" : "calc(100vh - 32px)",
      display: "flex",
      flexDirection: "column",
    }}>
      {/* Header */}
      <div style={{ background: activeUC.color + "0a", borderBottom: minimized ? "none" : `1px solid ${activeUC.color}22`, padding: minimized ? "10px 14px" : "14px 18px", flexShrink: 0 }}>
        <div style={{ display: "flex", alignItems: minimized ? "center" : "flex-start", justifyContent: "space-between", gap: 10 }}>
          <div style={{ minWidth: 0 }}>
            {!minimized && (
              <div style={{ fontSize: 12, color: activeUC.color + "88", letterSpacing: "0.18em", textTransform: "uppercase", marginBottom: 6 }}>
                Hunt Scenario
              </div>
            )}
            <div style={{ fontSize: minimized ? 13 : 19, fontWeight: 700, color: activeUC.color, display: "flex", alignItems: "center", gap: 8, whiteSpace: minimized ? "nowrap" : "normal" }}>
              <span>{activeUC.icon}</span>
              <span style={minimized ? { maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis" } : {}}>
                {activeUC.name}
              </span>
            </div>
            {!minimized && (
              <>
                <div style={{ fontSize: 13, color: "var(--tx-3)", marginTop: 8, lineHeight: 1.65 }}>{activeUC.desc}</div>
                <div style={{ marginTop: 10, fontSize: 12, color: activeUC.color + "77", letterSpacing: "0.08em" }}>
                  MITRE: {activeUC.tactic}
                </div>
              </>
            )}
            {minimized && (
              <div style={{ fontSize: 11, color: activeUC.color + "77", letterSpacing: "0.06em", marginTop: 1 }}>
                {activeUC.steps.length} steps · {activeUC.tactic}
              </div>
            )}
          </div>
          <button
            onClick={() => setMinimized(m => !m)}
            title={minimized ? "Expand panel" : "Minimize panel"}
            style={{
              flexShrink: 0,
              background: "none",
              border: `1px solid ${activeUC.color}33`,
              borderRadius: 3,
              color: activeUC.color + "88",
              cursor: "pointer",
              fontSize: 13,
              width: 24,
              height: 24,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontFamily: "inherit",
              lineHeight: 1,
              transition: "all 0.15s",
              alignSelf: "flex-start",
            }}
            onMouseEnter={e => { e.currentTarget.style.color = activeUC.color; e.currentTarget.style.borderColor = activeUC.color + "66"; }}
            onMouseLeave={e => { e.currentTarget.style.color = activeUC.color + "88"; e.currentTarget.style.borderColor = activeUC.color + "33"; }}
          >
            {minimized ? "▲" : "▼"}
          </button>
        </div>
      </div>

      {/* Steps */}
      {!minimized && <div style={{ overflowY: "auto", flex: 1 }}>
        <div style={{ padding: "8px 18px 10px", fontSize: 12, color: "var(--tx-5)", letterSpacing: "0.12em", textTransform: "uppercase", borderBottom: "1px solid var(--bd-2)" }}>
          Investigation Steps
        </div>

        {activeUC.steps.map((step, i) => {
          const table = TABLES.find(t => t.id === step.table);
          const col = table ? DOMAINS[table.domain].color : "#fff";
          const isActive = activeStep === i;
          const kqlOpen = expandedKql === i;
          const dep = tableDeprecation(step.table);

          const outgoing = activeUC.links.filter(l => l.from === step.table);
          const incoming = activeUC.links.filter(l => l.to === step.table);

          return (
            <div key={i} style={{ borderBottom: "1px solid var(--bd-3)" }}>
              {/* Step row */}
              <div
                onClick={() => onStepClick(isActive ? null : i)}
                style={{
                  padding: "10px 18px 8px",
                  cursor: "pointer",
                  background: isActive ? activeUC.color + "0d" : "transparent",
                  borderLeft: isActive ? `3px solid ${activeUC.color}` : "3px solid transparent",
                  transition: "all 0.15s",
                  display: "flex",
                  gap: 12,
                  alignItems: "flex-start",
                }}
              >
                <div style={{
                  fontSize: 13, fontWeight: 700, flexShrink: 0,
                  color: isActive ? activeUC.color : "var(--tx-4)",
                  minWidth: 22, paddingTop: 1,
                }}>
                  {String(i + 1).padStart(2, "0")}
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 7, flexWrap: "wrap", marginBottom: 5 }}>
                    <span style={{ fontSize: 14, fontWeight: 700, color: dep ? "#f59e0b" : (isActive ? col : col + "99") }}>
                      {step.table}
                    </span>
                    {dep && (
                      <span style={{
                        fontSize: 10, padding: "1px 5px", borderRadius: 2,
                        background: "#f59e0b18", border: "1px solid #f59e0b55",
                        color: "#f59e0b", letterSpacing: "0.04em", whiteSpace: "nowrap",
                      }}>
                        DEPRECATED → {dep.replacedBy}
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: 12, color: "var(--tx-4)", lineHeight: 1.6 }}>{step.action}</div>

                  {/* Pivot column pills */}
                  {(incoming.length > 0 || outgoing.length > 0) && (
                    <div style={{ marginTop: 8, display: "flex", flexWrap: "wrap", gap: 4 }}>
                      {incoming.map((l, j) => {
                        const key = `${i}:in:${l.col}`;
                        const isOpen = expandedCol === key;
                        const info = COLUMN_INFO[l.col];
                        return (
                          <span key={"in" + j}>
                            <span
                              onClick={e => { e.stopPropagation(); if (info) toggleCol(key); }}
                              title={info ? "Click for column details" : ""}
                              style={{
                                fontSize: 11, padding: "3px 8px", borderRadius: 2,
                                background: "var(--bg-3)",
                                border: `1px solid ${isOpen ? "#47ff8f66" : "#47ff8f33"}`,
                                color: isOpen ? "#47ff8f" : "#47ff8f99",
                                fontFamily: "inherit",
                                cursor: info ? "pointer" : "default",
                                transition: "all 0.15s",
                                display: "inline-block",
                              }}
                            >
                              ← {l.col}
                            </span>
                          </span>
                        );
                      })}
                      {outgoing.map((l, j) => {
                        const key = `${i}:out:${l.col}`;
                        const isOpen = expandedCol === key;
                        const info = COLUMN_INFO[l.col];
                        return (
                          <span key={"out" + j}>
                            <span
                              onClick={e => { e.stopPropagation(); if (info) toggleCol(key); }}
                              title={info ? "Click for column details" : ""}
                              style={{
                                fontSize: 11, padding: "3px 8px", borderRadius: 2,
                                background: "var(--bg-3)",
                                border: `1px solid ${isOpen ? activeUC.color + "66" : activeUC.color + "33"}`,
                                color: isOpen ? activeUC.color : activeUC.color + "99",
                                fontFamily: "inherit",
                                cursor: info ? "pointer" : "default",
                                transition: "all 0.15s",
                                display: "inline-block",
                              }}
                            >
                              {l.col} →
                            </span>
                          </span>
                        );
                      })}
                    </div>
                  )}

                  {/* Column description panel — inline expand on pill click */}
                  {expandedCol && expandedCol.startsWith(`${i}:`) && (() => {
                    // Extract col name from key like "2:out:SHA256"
                    const colKey = expandedCol.split(":").slice(2).join(":");
                    const info = COLUMN_INFO[colKey];
                    if (!info) return null;
                    return (
                      <div style={{
                        marginTop: 8,
                        padding: "10px 12px",
                        background: "var(--bg-3)",
                        border: `1px solid ${activeUC.color}22`,
                        borderRadius: 3,
                      }}>
                        <div style={{ fontSize: 13, fontWeight: 700, color: activeUC.color, marginBottom: 7, letterSpacing: "0.04em" }}>
                          {colKey}
                        </div>
                        <div style={{ fontSize: 12, color: "var(--tx-3)", lineHeight: 1.65, marginBottom: 9 }}>
                          <span style={{ color: "var(--tx-5)", letterSpacing: "0.08em", textTransform: "uppercase", fontSize: 10, display: "block", marginBottom: 3 }}>
                            Microsoft Docs
                          </span>
                          {info.docs}
                        </div>
                        <div style={{ fontSize: 12, color: "var(--tx-3)", lineHeight: 1.65, borderTop: "1px solid var(--bd-2)", paddingTop: 9 }}>
                          <span style={{ color: "var(--tx-5)", letterSpacing: "0.08em", textTransform: "uppercase", fontSize: 10, display: "block", marginBottom: 3 }}>
                            Plain English
                          </span>
                          {info.plain}
                        </div>
                      </div>
                    );
                  })()}
                </div>
              </div>

              {/* KQL toggle */}
              {step.kql && (
                <div
                  onClick={() => toggleKql(i)}
                  style={{
                    padding: "5px 18px 5px 50px",
                    cursor: "pointer",
                    fontSize: 11,
                    color: kqlOpen ? activeUC.color : "var(--tx-3)",
                    letterSpacing: "0.1em",
                    textTransform: "uppercase",
                    background: kqlOpen ? activeUC.color + "08" : "transparent",
                    transition: "all 0.15s",
                    userSelect: "none",
                  }}
                >
                  {kqlOpen ? "▾ hide query" : "▸ show kql"}
                </div>
              )}

              {/* KQL block */}
              {kqlOpen && step.kql && (
                <div style={{ padding: "0 18px 12px 18px", background: "var(--bg-4)" }}>
                  <pre style={{
                    margin: 0,
                    fontSize: 12,
                    lineHeight: 1.65,
                    color: "var(--tx-2)",
                    fontFamily: "'JetBrains Mono', 'Fira Code', 'Courier New', monospace",
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-word",
                    border: `1px solid ${activeUC.color}22`,
                    borderRadius: 3,
                    padding: "10px 12px",
                    background: "var(--bg-3)",
                  }}>
                    {step.kql}
                  </pre>
                </div>
              )}
            </div>
          );
        })}
      </div>}
    </div>
  );
}

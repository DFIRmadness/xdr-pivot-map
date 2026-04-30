import { DOMAINS } from "../data/domains.js";
import { TABLES } from "../data/tables.js";
import { USE_CASES } from "../data/useCases.js";
import { COLUMN_INFO } from "../data/columns.js";

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

function DeprecatedBadge({ replacedBy, style = {} }) {
  return (
    <span style={{
      fontSize: 10, padding: "1px 6px", borderRadius: 2,
      background: "#f59e0b18", border: "1px solid #f59e0b55",
      color: "#f59e0b", letterSpacing: "0.04em",
      whiteSpace: "nowrap", flexShrink: 0,
      ...style,
    }}>
      DEPRECATED → {replacedBy}
    </span>
  );
}

function PreviewBadge({ style = {} }) {
  return (
    <span style={{
      fontSize: 10, padding: "1px 6px", borderRadius: 2,
      background: "#a78bfa18", border: "1px solid #a78bfa55",
      color: "#a78bfa", letterSpacing: "0.04em",
      whiteSpace: "nowrap", flexShrink: 0,
      ...style,
    }}>
      PREVIEW
    </span>
  );
}

export function ColumnTooltip({ col }) {
  if (!col) return null;
  const info = COLUMN_INFO[col];
  if (!info) return null;

  return (
    <div style={{
      position: "fixed",
      top: "50%", left: "50%",
      transform: "translate(-50%, -50%)",
      width: 460, maxHeight: "80vh", overflowY: "auto",
      background: "var(--bg-float)",
      border: "1px solid var(--bd-1)",
      borderRadius: 4, padding: "14px 16px",
      zIndex: 9999, pointerEvents: "none",
      boxShadow: "0 8px 40px rgba(0,0,0,0.6)",
    }}>
      <div style={{ fontSize: 14, fontWeight: 700, color: "var(--tx-1)", marginBottom: 10, letterSpacing: "0.04em" }}>
        {col}
      </div>
      <div style={{ marginBottom: 10 }}>
        <div style={{ fontSize: 10, color: "var(--tx-5)", letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 4 }}>
          Microsoft Definition
        </div>
        <div style={{ fontSize: 12, color: "var(--tx-3)", lineHeight: 1.6 }}>{info.docs}</div>
      </div>
      <div style={{ marginBottom: 10, paddingTop: 8, borderTop: "1px solid var(--bd-2)" }}>
        <div style={{ fontSize: 10, color: "var(--tx-5)", letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 4 }}>
          Plain English
        </div>
        <div style={{ fontSize: 12, color: "var(--tx-3)", lineHeight: 1.6 }}>{info.plain}</div>
      </div>
      <div style={{ marginBottom: 10, paddingTop: 8, borderTop: "1px solid var(--bd-2)" }}>
        <div style={{ fontSize: 10, color: "#ffb34788", letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 4 }}>
          DFIR Relevance
        </div>
        <div style={{ fontSize: 12, color: "var(--tx-3)", lineHeight: 1.6 }}>{info.dfir}</div>
      </div>
      {info.crossTables?.length > 0 && (
        <div style={{ paddingTop: 8, borderTop: "1px solid var(--bd-2)" }}>
          <div style={{ fontSize: 10, color: "#47ff8f88", letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 8 }}>
            Also found in
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
            {info.crossTables.map((entry, i) => {
              const c = tableColor(entry.table);
              const dep = tableDeprecation(entry.table);
              return (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                  <span style={{
                    fontSize: 11, padding: "2px 7px", borderRadius: 2,
                    background: dep ? "#f59e0b18" : c + "18",
                    border: `1px solid ${dep ? "#f59e0b55" : c + "44"}`,
                    color: dep ? "#f59e0b" : c,
                    letterSpacing: "0.03em", flexShrink: 0,
                  }}>
                    {entry.table}
                  </span>
                  {dep && <DeprecatedBadge replacedBy={dep.replacedBy} />}
                  {entry.as && (
                    <span style={{ fontSize: 11, color: "var(--tx-4)" }}>
                      as <span style={{ color: "var(--tx-2)", fontWeight: 600 }}>{entry.as}</span>
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
      {info.docUrl && (
        <div style={{ marginTop: 10, paddingTop: 8, borderTop: "1px solid var(--bd-2)", fontSize: 11, color: "#00d4ff", letterSpacing: "0.06em" }}>
          → Click column to open Microsoft Docs
        </div>
      )}
    </div>
  );
}

export function NodeTooltip({ hoveredNode }) {
  if (!hoveredNode) return null;
  const table = TABLES.find(t => t.id === hoveredNode);
  if (!table) return null;
  const col = DOMAINS[table.domain].color;
  const dep = tableDeprecation(hoveredNode);
  const isPreview = tablePreview(hoveredNode);

  return (
    <div style={{
      position: "absolute", top: 16, left: 16,
      background: "var(--bg-float)", border: `1px solid ${dep ? "#f59e0b55" : col + "44"}`, borderRadius: 4,
      padding: "12px 18px", minWidth: 300, pointerEvents: "none",
    }}>
      <div style={{ fontSize: 11, color: col + "88", letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 5 }}>
        {DOMAINS[table.domain].label}
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: (dep || isPreview) ? 6 : 0 }}>
        <span style={{ fontSize: 14, fontWeight: 700, color: dep ? "#f59e0b" : col }}>{table.id}</span>
        {dep && <DeprecatedBadge replacedBy={dep.replacedBy} />}
        {isPreview && !dep && <PreviewBadge />}
      </div>
      {dep && (
        <div style={{ fontSize: 11, color: "#f59e0b99", marginBottom: 6, lineHeight: 1.5 }}>
          This table was renamed to <span style={{ color: "#f59e0b", fontWeight: 600 }}>{dep.replacedBy}</span> in December 2025. Use the new name in all queries.
        </div>
      )}
      {isPreview && !dep && (
        <div style={{ fontSize: 11, color: "#a78bfa99", marginBottom: 6, lineHeight: 1.5 }}>
          This table is in public preview. Schema and availability may change before GA release.
        </div>
      )}
      <div style={{ fontSize: 12, color: "var(--tx-3)", marginTop: 5 }}>{table.desc}</div>
    </div>
  );
}

export function EdgeTooltip({ hoveredEdge, hoveredNode }) {
  if (!hoveredEdge || hoveredNode) return null;

  const srcId = hoveredEdge.source.id || hoveredEdge.source;
  const tgtId = hoveredEdge.target.id || hoveredEdge.target;
  const srcTable = TABLES.find(t => t.id === srcId);
  const tgtTable = TABLES.find(t => t.id === tgtId);

  const srcDep = tableDeprecation(srcId);
  const tgtDep = tableDeprecation(tgtId);

  return (
    <div style={{
      position: "absolute", top: 16, left: 16,
      background: "var(--bg-float)", border: "1px solid var(--bd-1)", borderRadius: 4,
      padding: "12px 18px", minWidth: 340, pointerEvents: "none",
    }}>
      <div style={{ fontSize: 11, color: "var(--tx-5)", letterSpacing: "0.15em", marginBottom: 8, textTransform: "uppercase" }}>
        Pivot Link
      </div>
      <div style={{ fontSize: 13, color: "var(--tx-2)", marginBottom: 6, display: "flex", alignItems: "center", flexWrap: "wrap", gap: 4 }}>
        <span style={{ color: srcDep ? "#f59e0b" : DOMAINS[srcTable?.domain]?.color }}>{srcId}</span>
        {srcDep && <DeprecatedBadge replacedBy={srcDep.replacedBy} />}
        <span style={{ color: "var(--tx-6)" }}> ↔ </span>
        <span style={{ color: tgtDep ? "#f59e0b" : DOMAINS[tgtTable?.domain]?.color }}>{tgtId}</span>
        {tgtDep && <DeprecatedBadge replacedBy={tgtDep.replacedBy} />}
      </div>
      <div style={{ fontSize: 11, color: "#00d4ff88", marginBottom: 5 }}>
        {hoveredEdge.cols.join(", ")}
      </div>
      <div style={{ fontSize: 11, color: "var(--tx-4)" }}>
        Used in: {hoveredEdge.useCases.map(id => USE_CASES.find(u => u.id === id)?.name).join(", ")}
      </div>
    </div>
  );
}

import { useState, useMemo } from "react";
import { TABLE_DETAILS, CATEGORIES } from "../data/tableDetails.js";
import { TABLES } from "../data/tables.js";
import { DOMAINS } from "../data/domains.js";

function domainColor(tableId) {
  const t = TABLES.find(t => t.id === tableId);
  return t ? DOMAINS[t.domain].color : "#8890b8";
}

function domainLabel(tableId) {
  const t = TABLES.find(t => t.id === tableId);
  return t ? DOMAINS[t.domain].label : "";
}

function isTablePreview(tableId) {
  const t = TABLES.find(t => t.id === tableId);
  return t?.preview ?? false;
}

function isTableAzure(tableId) {
  const t = TABLES.find(t => t.id === tableId);
  return t?.azure ?? false;
}

// ── Table card ────────────────────────────────────────────────────────────────

function TableCard({ detail, search }) {
  const [open, setOpen] = useState(false);
  const color = domainColor(detail.id);
  const domain = domainLabel(detail.id);
  const preview = isTablePreview(detail.id);
  const azure = isTableAzure(detail.id);

  const schemaMatches = useMemo(() => {
    if (!search || !detail.schemaColumns) return [];
    const topNames = new Set(detail.topColumns.map(c => c.name.toLowerCase()));
    return detail.schemaColumns.filter(col =>
      col.toLowerCase().includes(search) && !topNames.has(col.toLowerCase())
    );
  }, [search, detail]);

  return (
    <div style={{
      background: "var(--bg-card)",
      border: "1px solid var(--bd-1)",
      borderLeft: `4px solid ${color}`,
      boxShadow: "0 2px 12px rgba(0,0,0,0.35)",
    }}>
      {/* Header row — always visible */}
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          width: "100%", textAlign: "left",
          display: "flex", alignItems: "flex-start", gap: "1rem",
          padding: "1rem 1.25rem",
          background: "none", border: "none", cursor: "pointer", color: "inherit",
          fontFamily: "inherit",
        }}
      >
        <div style={{ flex: 1, minWidth: 0 }}>
          {/* Domain badge + table name */}
          <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", marginBottom: "0.35rem", flexWrap: "wrap" }}>
            <span style={{
              fontSize: "0.6rem", padding: "2px 7px", borderRadius: 2,
              background: color + "18", border: `1px solid ${color}44`,
              color, letterSpacing: "0.05em", textTransform: "uppercase", flexShrink: 0,
            }}>
              {domain}
            </span>
            <span style={{ fontSize: "0.85rem", fontWeight: 700, color: "var(--tx-1)", letterSpacing: "0.02em" }}>
              {detail.id}
            </span>
            {preview && (
              <span style={{
                fontSize: "0.6rem", padding: "2px 7px", borderRadius: 2,
                background: "#a78bfa18", border: "1px solid #a78bfa55",
                color: "#a78bfa", letterSpacing: "0.05em", textTransform: "uppercase", flexShrink: 0,
              }}>
                Preview
              </span>
            )}
            {azure && (
              <span style={{
                fontSize: "0.6rem", padding: "2px 7px", borderRadius: 2,
                background: "#fb923c18", border: "1px solid #fb923c55",
                color: "#fb923c", letterSpacing: "0.05em", textTransform: "uppercase", flexShrink: 0,
              }}>
                Azure
              </span>
            )}
          </div>
          {/* MS description — always visible */}
          <div style={{ fontSize: "0.72rem", color: "var(--tx-4)", lineHeight: 1.6 }}>
            {detail.msDesc}
          </div>
          {/* Schema match chips — shown when search hits a non-topColumn */}
          {schemaMatches.length > 0 && (
            <div style={{ marginTop: "0.4rem", display: "flex", flexWrap: "wrap", gap: "0.3rem", alignItems: "center" }}>
              <span style={{ fontSize: "0.58rem", color: "var(--tx-5)", letterSpacing: "0.1em", textTransform: "uppercase", flexShrink: 0 }}>
                Also in schema:
              </span>
              {schemaMatches.slice(0, 6).map((col, i) => (
                <code key={i} style={{
                  fontSize: "0.62rem", padding: "1px 5px", borderRadius: 2,
                  background: "var(--bg-3)", border: "1px solid var(--bd-1)",
                  color: "var(--tx-5)", letterSpacing: "0.02em", whiteSpace: "nowrap",
                }}>
                  {col}
                </code>
              ))}
              {schemaMatches.length > 6 && (
                <span style={{ fontSize: "0.6rem", color: "var(--tx-6)" }}>+{schemaMatches.length - 6} more</span>
              )}
            </div>
          )}
        </div>
        {/* Expand toggle */}
        <div style={{
          flexShrink: 0, fontSize: "0.7rem", color: "var(--tx-5)",
          letterSpacing: "0.08em", marginTop: 2,
          transform: open ? "rotate(180deg)" : "none",
          transition: "transform 0.15s",
        }}>
          ▾
        </div>
      </button>

      {/* Expanded detail */}
      {open && (
        <div style={{
          padding: "0 1.25rem 1.25rem",
          borderTop: "1px solid var(--bd-2)",
          paddingTop: "1rem",
          display: "flex", flexDirection: "column", gap: "1.25rem",
        }}>
          {/* Plain English */}
          <div>
            <div style={{ fontSize: "0.6rem", letterSpacing: "0.15em", textTransform: "uppercase", color: "var(--tx-5)", marginBottom: "0.4rem" }}>
              Plain English
            </div>
            <div style={{ fontSize: "0.75rem", color: "var(--tx-3)", lineHeight: 1.75 }}>
              {detail.plain}
            </div>
          </div>

          {/* Data sources */}
          <div>
            <div style={{ fontSize: "0.6rem", letterSpacing: "0.15em", textTransform: "uppercase", color: "var(--tx-5)", marginBottom: "0.5rem" }}>
              Data Sources
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "0.3rem" }}>
              {detail.sources.map((src, i) => (
                <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: "0.5rem" }}>
                  <span style={{ color: color, flexShrink: 0, marginTop: 2 }}>▸</span>
                  <span style={{ fontSize: "0.72rem", color: "var(--tx-3)", lineHeight: 1.5 }}>{src}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Top columns */}
          <div>
            <div style={{ fontSize: "0.6rem", letterSpacing: "0.15em", textTransform: "uppercase", color: "#ffb34788", marginBottom: "0.5rem" }}>
              Key Columns for IR / Threat Hunting
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
              {detail.topColumns.map((col, i) => (
                <div key={i} style={{ display: "flex", gap: "0.75rem", alignItems: "flex-start" }}>
                  <code style={{
                    flexShrink: 0, fontSize: "0.68rem",
                    padding: "2px 7px", borderRadius: 2,
                    background: color + "12", border: `1px solid ${color}33`,
                    color, letterSpacing: "0.02em",
                    whiteSpace: "nowrap",
                  }}>
                    {col.name}
                  </code>
                  <span style={{ fontSize: "0.7rem", color: "var(--tx-4)", lineHeight: 1.6, paddingTop: 1 }}>
                    {col.note}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function TablesForMuggles() {
  const [activeCategory, setActiveCategory] = useState(null); // null = All
  const [sortAlpha, setSortAlpha] = useState(false);
  const [search, setSearch] = useState("");
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

  const filtered = useMemo(() => {
    let list = TABLE_DETAILS;

    if (activeCategory) {
      list = list.filter(t => t.categories.includes(activeCategory));
    }

    if (search.trim()) {
      const q = search.trim().toLowerCase();
      list = list.filter(t =>
        t.id.toLowerCase().includes(q) ||
        t.msDesc.toLowerCase().includes(q) ||
        t.plain.toLowerCase().includes(q) ||
        t.topColumns.some(c => c.name.toLowerCase().includes(q) || c.note.toLowerCase().includes(q)) ||
        t.schemaColumns?.some(col => col.toLowerCase().includes(q))
      );
    }

    if (sortAlpha) {
      list = [...list].sort((a, b) => a.id.localeCompare(b.id));
    }

    return list;
  }, [activeCategory, sortAlpha, search]);

  const activeCatLabel = activeCategory
    ? CATEGORIES.find(c => c.id === activeCategory)?.label
    : "All Tables";

  return (
    <div style={{ display: "flex", minHeight: "100vh", fontFamily: "inherit", background: "var(--bg-0)", color: "var(--tx-1)" }}>

      {/* ── Sidebar ── */}
      <aside style={{
        width: 220, flexShrink: 0,
        background: "var(--bg-1)", borderRight: "1px solid var(--bd-1)",
        padding: "1.5rem 1.25rem",
        display: "flex", flexDirection: "column", gap: "1.5rem",
        position: "sticky", top: 0, height: "100vh", overflowY: "auto",
      }}>
        <a href="/xdr-pivot-map/" style={{
          fontSize: "0.65rem", letterSpacing: "0.12em", textTransform: "uppercase",
          color: "var(--tx-5)", textDecoration: "none",
        }}>
          ← Home
        </a>

        <div>
          <div style={{ fontSize: "0.65rem", letterSpacing: "0.2em", color: "var(--tx-5)", textTransform: "uppercase", marginBottom: "0.4rem" }}>
            Tool
          </div>
          <div style={{ fontSize: "0.85rem", fontWeight: 700, color: "var(--tx-1)" }}>
            Tables for Muggles
          </div>
        </div>

        {/* Sort toggle */}
        <div>
          <div style={{ fontSize: "0.6rem", letterSpacing: "0.15em", textTransform: "uppercase", color: "var(--tx-5)", marginBottom: "0.5rem" }}>
            Sort
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
            {[
              { label: "By Domain", value: false },
              { label: "A → Z", value: true },
            ].map(opt => (
              <button
                key={String(opt.value)}
                onClick={() => setSortAlpha(opt.value)}
                style={{
                  textAlign: "left", padding: "0.35rem 0.6rem",
                  background: sortAlpha === opt.value ? "var(--bg-3)" : "none",
                  border: `1px solid ${sortAlpha === opt.value ? "var(--bd-1)" : "transparent"}`,
                  borderRadius: 3,
                  color: sortAlpha === opt.value ? "var(--tx-1)" : "var(--tx-4)",
                  fontSize: "0.72rem", fontFamily: "inherit", cursor: "pointer",
                  letterSpacing: "0.03em",
                }}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>

        {/* Category filters */}
        <div>
          <div style={{ fontSize: "0.6rem", letterSpacing: "0.15em", textTransform: "uppercase", color: "var(--tx-5)", marginBottom: "0.5rem" }}>
            Filter by Topic
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
            <button
              onClick={() => setActiveCategory(null)}
              style={{
                textAlign: "left", padding: "0.35rem 0.6rem",
                background: activeCategory === null ? "var(--bg-3)" : "none",
                border: `1px solid ${activeCategory === null ? "var(--bd-1)" : "transparent"}`,
                borderRadius: 3,
                color: activeCategory === null ? "var(--tx-1)" : "var(--tx-4)",
                fontSize: "0.72rem", fontFamily: "inherit", cursor: "pointer",
                letterSpacing: "0.03em",
              }}
            >
              All Tables
            </button>
            {CATEGORIES.map(cat => (
              <button
                key={cat.id}
                onClick={() => setActiveCategory(cat.id === activeCategory ? null : cat.id)}
                style={{
                  textAlign: "left", padding: "0.35rem 0.6rem",
                  display: "flex", alignItems: "center", gap: "0.4rem",
                  background: activeCategory === cat.id ? "var(--bg-3)" : "none",
                  border: `1px solid ${activeCategory === cat.id ? "var(--bd-1)" : "transparent"}`,
                  borderRadius: 3,
                  color: activeCategory === cat.id ? "var(--tx-1)" : "var(--tx-4)",
                  fontSize: "0.72rem", fontFamily: "inherit", cursor: "pointer",
                  letterSpacing: "0.03em",
                }}
              >
                <span>{cat.icon}</span>
                <span>{cat.label}</span>
              </button>
            ))}
          </div>
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
      <main style={{ flex: 1, padding: "2.5rem", maxWidth: 820, minWidth: 0 }}>
        <p style={{ fontSize: "0.65rem", letterSpacing: "0.25em", color: "var(--tx-5)", textTransform: "uppercase", marginBottom: "1.25rem" }}>
          Schema Reference
        </p>
        <h1 style={{ fontSize: "clamp(1.3rem,3vw,1.8rem)", fontWeight: 700, color: "var(--tx-1)", marginBottom: "0.6rem" }}>
          Tables for Muggles
        </h1>
        <p style={{ fontSize: "0.8rem", color: "var(--tx-3)", lineHeight: 1.8, marginBottom: "2rem", maxWidth: 560 }}>
          Plain-English guide to every Microsoft Defender XDR table — what it contains,
          where the data comes from, and which columns matter most for incident response
          and threat hunting.
        </p>

        {/* Search */}
        <div style={{ marginBottom: "1.5rem" }}>
          <input
            type="text"
            placeholder="Search tables or columns…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{
              width: "100%", maxWidth: 400,
              padding: "0.5rem 0.8rem",
              background: "var(--bg-2)", border: "1px solid var(--bd-1)",
              borderRadius: 3, color: "var(--tx-1)",
              fontFamily: "inherit", fontSize: "0.75rem",
              outline: "none", boxSizing: "border-box",
            }}
          />
        </div>

        {/* Result count + active filter label */}
        <div style={{
          display: "flex", alignItems: "center", gap: "0.75rem",
          marginBottom: "1rem", fontSize: "0.65rem",
          color: "var(--tx-5)", letterSpacing: "0.1em", textTransform: "uppercase",
        }}>
          <span>{activeCatLabel}</span>
          <span style={{ color: "var(--bd-1)" }}>·</span>
          <span>{filtered.length} table{filtered.length !== 1 ? "s" : ""}</span>
        </div>

        {/* Cards */}
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          {filtered.length === 0 ? (
            <div style={{ fontSize: "0.8rem", color: "var(--tx-5)", padding: "2rem 0" }}>
              No tables match that filter.
            </div>
          ) : (
            filtered.map(detail => (
              <TableCard key={detail.id} detail={detail} search={search.trim().toLowerCase()} />
            ))
          )}
        </div>
      </main>
    </div>
  );
}

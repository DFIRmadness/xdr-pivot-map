import { DOMAINS } from "../data/domains.js";
import { USE_CASES } from "../data/useCases.js";

export default function Sidebar({ selectedUseCase, onSelect, isDark, onToggleTheme, selectedDomain, onDomainSelect }) {
  return (
    <div style={{
      width: 270,
      flexShrink: 0,
      borderRight: "1px solid var(--bd-1)",
      display: "flex",
      flexDirection: "column",
      background: "var(--bg-2)",
      overflow: "hidden",
    }}>
      <div style={{ padding: "20px 18px 14px", borderBottom: "1px solid var(--bd-1)", position: "relative" }}>
        <button
          onClick={onToggleTheme}
          style={{
            position: "absolute",
            top: 16,
            right: 14,
            background: "none",
            border: "none",
            fontSize: 11,
            color: "var(--tx-5)",
            cursor: "pointer",
            letterSpacing: "0.08em",
            fontFamily: "inherit",
            padding: "2px 4px",
          }}
          onMouseEnter={e => e.currentTarget.style.color = "var(--tx-2)"}
          onMouseLeave={e => e.currentTarget.style.color = "var(--tx-5)"}
        >
          {isDark ? "☀ Light" : "◐ Dark"}
        </button>
        <a href="/xdr-pivot-map/" style={{
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
        <div style={{ fontSize: 11, letterSpacing: "0.2em", color: "var(--tx-5)", marginBottom: 6, textTransform: "uppercase" }}>
          Defender XDR
        </div>
        <div style={{ fontSize: 16, fontWeight: 700, color: "var(--tx-1)", lineHeight: 1.3 }}>
          Hunt by<br/>Use Case
        </div>
        <div style={{ fontSize: 11, color: "var(--tx-5)", marginTop: 10, letterSpacing: "0.06em" }}>
          Select a scenario to map the table chain
        </div>
      </div>

      <div style={{ padding: "10px 18px 10px", borderBottom: "1px solid var(--bd-1)" }}>
        {/* All categories button */}
        <button
          onClick={() => onDomainSelect(null)}
          style={{
            width: "100%", marginBottom: 6, padding: "4px 8px",
            background: !selectedDomain ? "var(--bg-3)" : "transparent",
            border: !selectedDomain ? "1px solid var(--bd-2)" : "1px solid transparent",
            borderRadius: 3, cursor: "pointer", fontFamily: "inherit",
            display: "flex", alignItems: "center", gap: 7,
            transition: "all 0.15s",
          }}
          onMouseEnter={e => { if (selectedDomain) e.currentTarget.style.background = "var(--bg-3)"; }}
          onMouseLeave={e => { if (selectedDomain) e.currentTarget.style.background = "transparent"; }}
        >
          <div style={{
            width: 7, height: 7, borderRadius: "50%", flexShrink: 0,
            background: !selectedDomain ? "var(--tx-2)" : "var(--tx-5)",
          }} />
          <span style={{
            fontSize: 11,
            color: !selectedDomain ? "var(--tx-1)" : "var(--tx-5)",
            fontWeight: !selectedDomain ? 700 : 400,
            letterSpacing: "0.04em",
          }}>All Categories</span>
        </button>

        {Object.entries(DOMAINS).map(([key, { label, color }]) => {
          const isActive = selectedDomain === key;
          return (
            <button
              key={key}
              onClick={() => onDomainSelect(key)}
              style={{
                width: "100%", padding: "3px 8px",
                background: isActive ? color + "18" : "transparent",
                border: isActive ? `1px solid ${color}44` : "1px solid transparent",
                borderRadius: 3, cursor: "pointer", fontFamily: "inherit",
                display: "flex", alignItems: "center", gap: 7, marginBottom: 2,
                transition: "all 0.15s",
              }}
              onMouseEnter={e => { if (!isActive) e.currentTarget.style.background = "var(--bg-3)"; }}
              onMouseLeave={e => { if (!isActive) e.currentTarget.style.background = "transparent"; }}
            >
              <div style={{
                width: isActive ? 9 : 7, height: isActive ? 9 : 7,
                borderRadius: "50%", background: color, flexShrink: 0,
                boxShadow: isActive ? `0 0 6px ${color}99` : "none",
                transition: "all 0.15s",
              }} />
              <span style={{
                fontSize: 11,
                color: isActive ? color : "var(--tx-4)",
                fontWeight: isActive ? 700 : 400,
                letterSpacing: "0.04em",
              }}>{label}</span>
            </button>
          );
        })}
      </div>

      <div style={{ flex: 1, overflowY: "auto", padding: "6px 0" }}>
        {USE_CASES.map(uc => {
          const isSelected = selectedUseCase === uc.id;
          return (
            <button
              key={uc.id}
              onClick={() => onSelect(isSelected ? null : uc.id)}
              style={{
                width: "100%",
                background: isSelected ? uc.color + "11" : "transparent",
                border: "none",
                borderLeft: isSelected ? `3px solid ${uc.color}` : "3px solid transparent",
                color: isSelected ? uc.color : "var(--tx-3)",
                padding: "11px 18px",
                textAlign: "left",
                cursor: "pointer",
                display: "flex",
                alignItems: "flex-start",
                gap: 12,
                transition: "all 0.15s",
                fontFamily: "inherit",
              }}
            >
              <span style={{ fontSize: 18, flexShrink: 0, marginTop: 1 }}>{uc.icon}</span>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, letterSpacing: "0.02em", lineHeight: 1.4 }}>
                  {uc.name}
                </div>
                <div style={{
                  fontSize: 10,
                  marginTop: 4,
                  padding: "2px 6px",
                  borderRadius: 2,
                  background: isSelected ? uc.color + "22" : "var(--bd-1)",
                  color: isSelected ? uc.color : "var(--tx-4)",
                  display: "inline-block",
                  letterSpacing: "0.06em",
                }}>
                  {uc.tactic}
                </div>
              </div>
            </button>
          );
        })}
      </div>

    </div>
  );
}

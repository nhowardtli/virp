import { useState, useEffect, useCallback, useRef } from "react";

const FONT = "'Inter', -apple-system, 'Segoe UI', sans-serif";
const MONO = "'SF Mono', 'Cascadia Code', 'Consolas', monospace";

// ── UPDATE THIS to point at the FastAPI backend on CT 210 ──
const API_BASE = window.location.hostname === "localhost"
  ? "http://10.0.0.210:8080"
  : `${window.location.protocol}//${window.location.host}`;

const C = {
  sidebar: "#1e2a3a", sidebarHover: "#263548", sidebarActive: "#2d4a6f",
  sidebarBorder: "#2a3a4e", sidebarText: "#8899aa", sidebarTextActive: "#ffffff",
  bg: "#f4f6f8", card: "#ffffff", cardBorder: "#e4e8ec",
  text: "#1a2332", textSec: "#5a6a7a", textMuted: "#8899aa", divider: "#e8ecf0",
  green: "#00b894", greenBg: "#eafaf5", greenBorder: "#b8edd8",
  yellow: "#f0a030", yellowBg: "#fef8ec", yellowBorder: "#f0dca0",
  red: "#e74c3c", redBg: "#fdecea", redBorder: "#f0b8b0",
  orange: "#e67e22", orangeBg: "#fdf2e6",
  blue: "#3498db", blueBg: "#eaf4fc", blueBorder: "#b0d4f0",
  purple: "#8e44ad",
  headerBg: "#ffffff", headerBorder: "#dce0e4", accent: "#4a8fe7",
};

// ── Helpers ─────────────────────────────────────────────────────────────────

function TierDot({ tier, size = 10 }) {
  const colors = { GREEN: C.green, YELLOW: C.yellow, RED: C.red, TIMEOUT: C.yellow, BLACK: C.textMuted };
  const color = colors[tier] || C.textMuted;
  return (
    <span style={{
      display: "inline-block", width: size, height: size, borderRadius: "50%",
      background: color,
      boxShadow: tier === "GREEN" ? `0 0 6px ${C.green}60` : "none",
    }} />
  );
}

function TierLabel({ tier }) {
  const cfg = {
    GREEN: { bg: C.greenBg, color: C.green, border: C.greenBorder },
    YELLOW: { bg: C.yellowBg, color: C.yellow, border: C.yellowBorder },
    RED: { bg: C.redBg, color: C.red, border: C.redBorder },
    TIMEOUT: { bg: C.yellowBg, color: C.yellow, border: C.yellowBorder },
    BLACK: { bg: "#f0f0f0", color: C.textMuted, border: "#ddd" },
  };
  const c = cfg[tier];
  if (!c) return <span style={{ fontFamily: MONO, fontSize: 11, color: C.textMuted }}>—</span>;
  return (
    <span style={{
      fontFamily: MONO, fontSize: 10, fontWeight: 600, letterSpacing: 1,
      color: c.color, background: c.bg, border: `1px solid ${c.border}`,
      padding: "2px 8px", borderRadius: 3,
    }}>{tier}</span>
  );
}

function Widget({ title, children, span = 1, noPad = false, action = null }) {
  return (
    <div style={{
      background: C.card, border: `1px solid ${C.cardBorder}`,
      borderRadius: 6, gridColumn: `span ${span}`,
      boxShadow: "0 1px 3px rgba(0,0,0,0.04)", overflow: "hidden",
    }}>
      <div style={{
        padding: "10px 16px", borderBottom: `1px solid ${C.divider}`,
        display: "flex", alignItems: "center", justifyContent: "space-between",
      }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: C.text, letterSpacing: 0.3 }}>{title}</span>
        {action}
      </div>
      <div style={{ padding: noPad ? 0 : 16 }}>{children}</div>
    </div>
  );
}

function StatusSummary({ summary }) {
  const items = [
    { label: "Total", value: summary.total, color: C.text },
    { label: "Green", value: summary.green, color: C.green },
    { label: "Warning", value: summary.yellow, color: C.yellow },
    { label: "Critical", value: summary.red, color: C.red },
    { label: "Pending", value: summary.pending || 0, color: C.textMuted },
  ];
  return (
    <div style={{ display: "flex" }}>
      {items.map((it, i) => (
        <div key={i} style={{
          flex: 1, textAlign: "center", padding: "8px 0",
          borderRight: i < items.length - 1 ? `1px solid ${C.divider}` : "none",
        }}>
          <div style={{ fontSize: 22, fontWeight: 700, color: it.color, fontFamily: MONO }}>{it.value}</div>
          <div style={{ fontSize: 10, color: C.textMuted, marginTop: 2, letterSpacing: 0.5, textTransform: "uppercase" }}>{it.label}</div>
        </div>
      ))}
    </div>
  );
}

function DeviceRow({ device }) {
  return (
    <div style={{
      display: "flex", alignItems: "center", padding: "10px 16px",
      borderBottom: `1px solid ${C.divider}`, gap: 12, cursor: "default",
    }}
      onMouseOver={e => e.currentTarget.style.background = "#f8fafc"}
      onMouseOut={e => e.currentTarget.style.background = "transparent"}
    >
      <TierDot tier={device.tier} />
      <div style={{ flex: "0 0 90px" }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: C.text }}>{device.hostname}</div>
        <div style={{ fontSize: 10, color: C.textMuted }}>{device.ip}</div>
      </div>
      <div style={{ flex: "0 0 90px", fontSize: 11, color: C.textSec }}>{device.vendor}</div>
      <div style={{ flex: "0 0 65px" }}><TierLabel tier={device.tier} /></div>
      <div style={{ flex: "0 0 50px", fontFamily: MONO, fontSize: 12, color: C.text, textAlign: "center" }}>{device.bgp || "—"}</div>
      <div style={{ flex: 1, fontFamily: MONO, fontSize: 10, color: C.purple }}>
        {device.hmac ? `HMAC:${device.hmac} ✓` : "—"}
      </div>
      {device.alert && (
        <div style={{
          fontSize: 10, color: C.yellow, background: C.yellowBg,
          border: `1px solid ${C.yellowBorder}`, borderRadius: 3,
          padding: "2px 8px", maxWidth: 240, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis",
        }}>{device.alert}</div>
      )}
    </div>
  );
}

function SessionTable({ devices }) {
  const allSessions = (devices || []).flatMap(d => (d.sessions || []).map(s => ({ ...s, device: d.hostname })));
  if (!allSessions.length) return (
    <div style={{ padding: 20, textAlign: "center", color: C.textMuted, fontSize: 12, fontStyle: "italic" }}>No active sessions</div>
  );
  return (
    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
      <thead>
        <tr style={{ borderBottom: `1px solid ${C.divider}` }}>
          {["Device", "Neighbor", "Remote AS", "Type", "State", "Uptime", "Pfx"].map(h => (
            <th key={h} style={{
              padding: "8px 10px", textAlign: "left", fontSize: 10, fontWeight: 600,
              color: C.textMuted, letterSpacing: 0.5, textTransform: "uppercase",
            }}>{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {allSessions.map((s, i) => (
          <tr key={i} style={{ borderBottom: `1px solid ${C.divider}` }}
            onMouseOver={e => e.currentTarget.style.background = "#f8fafc"}
            onMouseOut={e => e.currentTarget.style.background = "transparent"}
          >
            <td style={{ padding: "8px 10px", fontWeight: 600, color: C.text }}>{s.device}</td>
            <td style={{ padding: "8px 10px", fontFamily: MONO, fontSize: 11, color: C.textSec }}>{s.neighbor}</td>
            <td style={{ padding: "8px 10px", fontFamily: MONO, fontSize: 11, color: C.textSec }}>{s.as}</td>
            <td style={{ padding: "8px 10px", color: C.textSec }}>{s.type}</td>
            <td style={{ padding: "8px 10px" }}>
              <span style={{
                fontSize: 10, fontWeight: 600,
                color: s.state === "Established" ? C.green : C.red,
                background: s.state === "Established" ? C.greenBg : C.redBg,
                border: `1px solid ${s.state === "Established" ? C.greenBorder : C.redBorder}`,
                padding: "1px 6px", borderRadius: 3,
              }}>{s.state}</span>
            </td>
            <td style={{ padding: "8px 10px", fontFamily: MONO, fontSize: 11, color: C.textMuted }}>{s.uptime}</td>
            <td style={{ padding: "8px 10px", fontFamily: MONO, fontSize: 11, color: C.text, textAlign: "center" }}>{s.pfx}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function LogFeed({ entries }) {
  const ref = useRef(null);
  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; }, [entries]);
  const typeStyles = {
    intent: { color: C.blue }, hmac: { color: C.purple }, onode: { color: C.green },
    device: { color: C.text }, result: { color: C.green }, warning: { color: C.yellow }, cage: { color: C.orange },
  };
  return (
    <div ref={ref} style={{ maxHeight: 220, overflowY: "auto", padding: entries.length ? 0 : 16 }}>
      {!entries.length && (
        <div style={{ textAlign: "center", color: C.textMuted, fontSize: 12, fontStyle: "italic" }}>Awaiting observations...</div>
      )}
      {entries.map((e, i) => (
        <div key={i} style={{
          display: "flex", gap: 10, padding: "5px 16px", fontSize: 11,
          borderBottom: `1px solid ${C.divider}`, fontFamily: MONO,
        }}>
          <span style={{ color: C.textMuted, whiteSpace: "nowrap", flexShrink: 0 }}>{e.time}</span>
          <span style={{ ...(typeStyles[e.type] || { color: C.textSec }) }}>{e.msg}</span>
        </div>
      ))}
    </div>
  );
}

function CageWidget({ cage }) {
  if (!cage) return null;
  return (
    <div>
      <div style={{
        background: C.redBg, border: `1px solid ${C.redBorder}`,
        borderRadius: 4, padding: "10px 14px", marginBottom: 14, fontFamily: MONO, fontSize: 12,
      }}>
        <span style={{ color: C.red, fontWeight: 700 }}>DENIED</span>
        <span style={{ color: C.textSec }}> → </span>
        <span style={{ color: C.text }}>{cage.command}</span>
        <span style={{ color: C.textMuted }}> on </span>
        <span style={{ color: C.blue, fontWeight: 600 }}>{cage.hostname}</span>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {(cage.walls || []).map((w, i) => (
          <div key={i} style={{
            display: "flex", alignItems: "center", gap: 12,
            background: "#fdf8f4", border: "1px solid #f0d8c0",
            borderRadius: 4, padding: "10px 14px",
          }}>
            <span style={{ fontSize: 16, flexShrink: 0 }}>{["🔒", "🛡", "⛔"][i] || "⬡"}</span>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: C.text }}>Wall {i + 1}: {w.name}</div>
              <div style={{ fontSize: 11, color: C.textSec, marginTop: 1 }}>{w.desc}</div>
            </div>
            <span style={{
              fontFamily: MONO, fontSize: 9, fontWeight: 700, letterSpacing: 1,
              color: C.red, background: C.redBg, border: `1px solid ${C.redBorder}`,
              padding: "2px 8px", borderRadius: 3,
            }}>BLOCKED</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Nav config ──────────────────────────────────────────────────────────────

const NAV_ITEMS = [
  { section: "MONITOR", items: [
    { key: "dashboard", icon: "◫", label: "Dashboard" },
    { key: "cage_test", icon: "⬡", label: "The Cage" },
  ]},
  { section: "VIRP", items: [
    { key: null, icon: "⬢", label: "Trust Tiers", disabled: true },
    { key: null, icon: "⎔", label: "Observations", disabled: true },
    { key: null, icon: "⏣", label: "Intent Chain", disabled: true },
  ]},
  { section: "SYSTEM", items: [
    { key: null, icon: "⚙", label: "O-Node Config", disabled: true },
    { key: null, icon: "⊞", label: "Devices", disabled: true },
  ]},
];

// ── Main Dashboard ──────────────────────────────────────────────────────────

export default function VIRPDashboard() {
  const [view, setView] = useState("dashboard");
  const [sweepData, setSweepData] = useState(null);
  const [cageData, setCageData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [onodeStatus, setOnodeStatus] = useState("checking");
  const [lastSweepTime, setLastSweepTime] = useState(null);
  const [error, setError] = useState(null);

  // Check O-Node health on mount
  useEffect(() => {
    fetch(`${API_BASE}/api/health`)
      .then(r => r.json())
      .then(d => setOnodeStatus(d.onode))
      .catch(() => setOnodeStatus("unreachable"));
  }, []);

  // Run sweep
  const runSweep = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/sweep`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setSweepData(data);
      setLastSweepTime(new Date().toLocaleTimeString());
    } catch (e) {
      setError(`Sweep failed: ${e.message}`);
    }
    setLoading(false);
  }, []);

  // Test The Cage
  const testCage = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/intent`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          hostname: "ASA-5525",
          command: "shutdown interface GigabitEthernet0/0",
        }),
      });
      const data = await res.json();
      setCageData(data);
    } catch (e) {
      setError(`Cage test failed: ${e.message}`);
    }
    setLoading(false);
  }, []);

  const devices = sweepData?.devices || [];
  const summary = sweepData?.summary || { total: 3, green: 0, yellow: 0, red: 0, pending: 3 };
  const log = view === "cage_test" && cageData?.log ? cageData.log : sweepData?.log || [];

  return (
    <div style={{ display: "flex", height: "100vh", fontFamily: FONT, background: C.bg, overflow: "hidden" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: ${C.cardBorder}; border-radius: 3px; }
      `}</style>

      {/* ── Sidebar ── */}
      <div style={{
        width: 200, background: C.sidebar, display: "flex", flexDirection: "column",
        borderRight: `1px solid ${C.sidebarBorder}`, flexShrink: 0,
      }}>
        <div style={{
          padding: "16px 16px 14px", borderBottom: `1px solid ${C.sidebarBorder}`,
          display: "flex", alignItems: "center", gap: 10,
        }}>
          <div style={{
            width: 28, height: 28, borderRadius: 5,
            background: "linear-gradient(135deg, #4a8fe7, #22c55e)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 12, fontWeight: 800, color: "#fff", fontFamily: MONO,
          }}>V</div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: "#fff", letterSpacing: 0.5 }}>VIRP</div>
            <div style={{ fontSize: 9, color: C.sidebarText, letterSpacing: 0.8 }}>IronClaw Ops Center</div>
          </div>
        </div>

        <div style={{ padding: "8px 0", flex: 1 }}>
          {NAV_ITEMS.map((section, si) => (
            <div key={si} style={{ marginBottom: 4 }}>
              <div style={{
                fontSize: 9, fontWeight: 700, color: C.sidebarText,
                letterSpacing: 1.5, textTransform: "uppercase", padding: "10px 16px 4px",
              }}>{section.section}</div>
              {section.items.map((item, ii) => {
                const active = item.key === view;
                return (
                  <div key={ii}
                    onClick={() => !item.disabled && item.key && setView(item.key)}
                    style={{
                      display: "flex", alignItems: "center", gap: 10,
                      padding: "8px 16px", cursor: item.disabled ? "default" : "pointer",
                      background: active ? C.sidebarActive : "transparent",
                      borderLeft: active ? `3px solid ${C.accent}` : "3px solid transparent",
                      opacity: item.disabled ? 0.35 : 1, transition: "all 0.15s",
                    }}
                    onMouseOver={e => { if (!item.disabled && !active) e.currentTarget.style.background = C.sidebarHover; }}
                    onMouseOut={e => { if (!active) e.currentTarget.style.background = "transparent"; }}
                  >
                    <span style={{ fontSize: 14, color: active ? C.accent : C.sidebarText, width: 18, textAlign: "center" }}>{item.icon}</span>
                    <span style={{ fontSize: 12, color: active ? C.sidebarTextActive : C.sidebarText, fontWeight: active ? 600 : 400 }}>{item.label}</span>
                  </div>
                );
              })}
            </div>
          ))}
        </div>

        <div style={{ padding: "12px 16px", borderTop: `1px solid ${C.sidebarBorder}`, fontSize: 10, color: C.sidebarText }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
            <span style={{
              width: 6, height: 6, borderRadius: "50%",
              background: onodeStatus === "online" ? C.green : C.red,
              boxShadow: onodeStatus === "online" ? `0 0 4px ${C.green}` : "none",
            }} />
            <span>O-Node {onodeStatus}</span>
          </div>
          <div style={{ color: "#4a5568" }}>10.0.0.211 · CT 211</div>
        </div>
      </div>

      {/* ── Main ── */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <div style={{
          background: C.headerBg, borderBottom: `1px solid ${C.headerBorder}`,
          padding: "10px 24px", display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0,
        }}>
          <div>
            <span style={{ fontSize: 15, fontWeight: 600, color: C.text }}>
              {view === "dashboard" ? "Dashboard" : "The Cage — Structural Enforcement"}
            </span>
            {lastSweepTime && (
              <span style={{ fontSize: 11, color: C.textMuted, marginLeft: 12 }}>
                Last sweep: {lastSweepTime}
                {sweepData?.duration_ms && ` (${sweepData.duration_ms}ms)`}
              </span>
            )}
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            {error && (
              <span style={{ fontSize: 10, color: C.red, background: C.redBg, padding: "3px 8px", borderRadius: 3 }}>
                {error}
              </span>
            )}
            <span style={{
              fontFamily: MONO, fontSize: 10, color: C.green,
              background: C.greenBg, border: `1px solid ${C.greenBorder}`,
              padding: "3px 8px", borderRadius: 3,
            }}>VIRP ACTIVE</span>
          </div>
        </div>

        <div style={{ flex: 1, overflowY: "auto", padding: 20 }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, maxWidth: 1100 }}>

            {/* ── Dashboard View ── */}
            {view === "dashboard" && (
              <>
                <Widget title="Security Fabric Status" span={2}
                  action={
                    <button onClick={runSweep} disabled={loading} style={{
                      fontFamily: FONT, fontSize: 11, fontWeight: 600,
                      color: "#fff", background: loading ? C.textMuted : C.accent,
                      border: "none", borderRadius: 4, padding: "5px 14px",
                      cursor: loading ? "default" : "pointer",
                      transition: "background 0.2s",
                    }}>
                      {loading ? "Sweeping..." : "Run BGP Sweep"}
                    </button>
                  }
                >
                  <StatusSummary summary={summary} />
                </Widget>

                <Widget title="Managed Devices" span={2} noPad>
                  <div>
                    <div style={{
                      display: "flex", alignItems: "center", padding: "6px 16px",
                      borderBottom: `1px solid ${C.divider}`, background: "#fafbfc",
                    }}>
                      <div style={{ width: 10 }} />
                      {["DEVICE", "VENDOR", "TIER", "BGP", "HMAC"].map((h, i) => (
                        <div key={h} style={{
                          flex: i === 0 ? "0 0 90px" : i === 1 ? "0 0 90px" : i === 2 ? "0 0 65px" : i === 3 ? "0 0 50px" : 1,
                          fontSize: 10, fontWeight: 600, color: C.textMuted, letterSpacing: 0.5,
                          marginLeft: i === 0 ? 12 : 0, textAlign: i === 3 ? "center" : "left",
                        }}>{h}</div>
                      ))}
                    </div>
                    {devices.length > 0
                      ? devices.map((d, i) => <DeviceRow key={i} device={d} />)
                      : [
                          { hostname: "R1", ip: "10.0.0.50", vendor: "Cisco IOS" },
                          { hostname: "ASA-5525", ip: "10.0.0.253", vendor: "Cisco ASA" },
                          { hostname: "pa-850", ip: "10.0.0.250", vendor: "PAN-OS" },
                        ].map((d, i) => <DeviceRow key={i} device={d} />)
                    }
                  </div>
                </Widget>

                <Widget title="BGP Peer Sessions" span={2} noPad>
                  <SessionTable devices={devices} />
                </Widget>

                <Widget title="Observation Log" span={2} noPad>
                  <LogFeed entries={log} />
                </Widget>
              </>
            )}

            {/* ── Cage View ── */}
            {view === "cage_test" && (
              <>
                <Widget title="Intent Filing" span={2}
                  action={
                    <button onClick={testCage} disabled={loading} style={{
                      fontFamily: FONT, fontSize: 11, fontWeight: 600,
                      color: "#fff", background: loading ? C.textMuted : C.orange,
                      border: "none", borderRadius: 4, padding: "5px 14px",
                      cursor: loading ? "default" : "pointer",
                    }}>
                      {loading ? "Filing..." : "Test: shutdown Gi0/0 on ASA-5525"}
                    </button>
                  }
                >
                  <div style={{ fontSize: 12, color: C.textSec, lineHeight: 1.6 }}>
                    File a RED-tier config change intent and watch The Cage deny it structurally.
                    Three walls must be breached — network isolation, device ACLs, and socket enforcement.
                    None are behavioral. All are architectural.
                  </div>
                </Widget>

                {cageData?.blocked && cageData?.cage && (
                  <Widget title="⛔ The Cage — Structural Enforcement" span={2}>
                    <CageWidget cage={cageData.cage} />
                  </Widget>
                )}

                <Widget title="Observation Log" span={2} noPad>
                  <LogFeed entries={cageData?.log || []} />
                </Widget>
              </>
            )}
          </div>

          <div style={{
            textAlign: "center", padding: "20px 0 8px",
            fontSize: 10, color: C.textMuted, letterSpacing: 0.5,
          }}>
            VIRP · Verified Infrastructure Response Protocol · Third Level IT LLC
          </div>
        </div>
      </div>
    </div>
  );
}

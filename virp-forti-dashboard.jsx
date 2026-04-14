import { useState, useEffect, useCallback, useRef } from "react";

const FONT = "'Inter', -apple-system, 'Segoe UI', sans-serif";
const MONO = "'SF Mono', 'Cascadia Code', 'Consolas', monospace";

const C = {
  sidebar: "#1e2a3a",
  sidebarHover: "#263548",
  sidebarActive: "#2d4a6f",
  sidebarBorder: "#2a3a4e",
  sidebarText: "#8899aa",
  sidebarTextActive: "#ffffff",
  bg: "#f4f6f8",
  card: "#ffffff",
  cardBorder: "#e4e8ec",
  text: "#1a2332",
  textSec: "#5a6a7a",
  textMuted: "#8899aa",
  divider: "#e8ecf0",
  green: "#00b894",
  greenBg: "#eafaf5",
  greenBorder: "#b8edd8",
  yellow: "#f0a030",
  yellowBg: "#fef8ec",
  yellowBorder: "#f0dca0",
  red: "#e74c3c",
  redBg: "#fdecea",
  redBorder: "#f0b8b0",
  orange: "#e67e22",
  orangeBg: "#fdf2e6",
  blue: "#3498db",
  blueBg: "#eaf4fc",
  blueBorder: "#b0d4f0",
  purple: "#8e44ad",
  purpleBg: "#f5eef8",
  headerBg: "#ffffff",
  headerBorder: "#dce0e4",
  accent: "#4a8fe7",
};

const DEMO_STATES = {
  dashboard: {
    devices: [
      { hostname: "R1", vendor: "Cisco IOS", as: "AS 100", ip: "10.0.0.50", tier: null, hmac: null, bgp: null, sessions: [], status: "standby" },
      { hostname: "ASA-5525", vendor: "Cisco ASA", as: "AS 65001", ip: "10.0.0.253", tier: null, hmac: null, bgp: null, sessions: [], status: "standby" },
      { hostname: "pa-850", vendor: "PAN-OS", as: "AS 65002", ip: "10.0.0.250", tier: null, hmac: null, bgp: null, sessions: [], status: "standby" },
    ],
    log: [],
    cage: null,
    summary: { total: 3, green: 0, yellow: 0, red: 0, pending: 3 },
    headline: "Awaiting sweep",
  },
  sweep: {
    devices: [
      {
        hostname: "R1", vendor: "Cisco IOS", as: "AS 100", ip: "10.0.0.50",
        tier: "GREEN", hmac: "698a2d", bgp: "3/3",
        sessions: [
          { neighbor: "2.2.2.2", as: "100", type: "iBGP", state: "Established", uptime: "05:44:32", pfx: 13 },
          { neighbor: "10.0.0.253", as: "65001", type: "eBGP", state: "Established", uptime: "02:23:01", pfx: 1 },
          { neighbor: "10.1.13.2", as: "200", type: "eBGP", state: "Established", uptime: "05:44:41", pfx: 10 },
        ],
        status: "verified"
      },
      {
        hostname: "ASA-5525", vendor: "Cisco ASA", as: "AS 65001", ip: "10.0.0.253",
        tier: "GREEN", hmac: "bbc2d8", bgp: "2/2",
        sessions: [
          { neighbor: "10.10.10.2", as: "65002", type: "eBGP", state: "Established", uptime: "07:42:09", pfx: 0 },
          { neighbor: "10.0.0.50", as: "100", type: "eBGP", state: "Established", uptime: "02:56:22", pfx: 14 },
        ],
        status: "verified"
      },
      {
        hostname: "pa-850", vendor: "PAN-OS", as: "AS 65002", ip: "10.0.0.250",
        tier: "GREEN", hmac: "969484", bgp: "1/1",
        sessions: [
          { neighbor: "ASA-5525", as: "65001", type: "eBGP", state: "Established", uptime: "08:04:11", pfx: 15 },
        ],
        status: "verified"
      },
    ],
    log: [
      { time: "17:17:01", type: "intent", msg: "Intent 054386a8 filed — BGP health sweep" },
      { time: "17:17:01", type: "hmac", msg: "HMAC verified ✓ seq 172" },
      { time: "17:17:02", type: "onode", msg: "O-Node batch_execute → 3 devices parallel" },
      { time: "17:17:03", type: "device", msg: "R1 — show ip bgp summary — 698a2d ✓" },
      { time: "17:17:03", type: "device", msg: "ASA-5525 — show bgp summary — bbc2d8 ✓" },
      { time: "17:17:04", type: "device", msg: "pa-850 — show routing protocol bgp — 969484 ✓" },
      { time: "17:17:04", type: "result", msg: "All GREEN — 3/3 HMAC-verified" },
    ],
    cage: null,
    summary: { total: 3, green: 3, yellow: 0, red: 0, pending: 0 },
    headline: "All systems verified",
  },
  device_down: {
    devices: [
      {
        hostname: "R1", vendor: "Cisco IOS", as: "AS 100", ip: "10.0.0.50",
        tier: "TIMEOUT", hmac: "a1c3f7", bgp: "—",
        sessions: [],
        status: "timeout",
        alert: "SSH read timeout — device unresponsive. Evidence degraded."
      },
      {
        hostname: "ASA-5525", vendor: "Cisco ASA", as: "AS 65001", ip: "10.0.0.253",
        tier: "YELLOW", hmac: "bbc2d8", bgp: "1/2",
        sessions: [
          { neighbor: "10.10.10.2", as: "65002", type: "eBGP", state: "Established", uptime: "08:04:09", pfx: 0 },
          { neighbor: "10.0.0.50", as: "100", type: "eBGP", state: "Idle", uptime: "—", pfx: 0 },
        ],
        status: "warning",
        alert: "SYN timeouts to 10.0.0.50:179 since 17:22 UTC"
      },
      {
        hostname: "pa-850", vendor: "PAN-OS", as: "AS 65002", ip: "10.0.0.250",
        tier: "GREEN", hmac: "969484", bgp: "1/1",
        sessions: [
          { neighbor: "ASA-5525", as: "65001", type: "eBGP", state: "Established", uptime: "08:04:11", pfx: 15 },
        ],
        status: "verified"
      },
    ],
    log: [
      { time: "17:36:28", type: "intent", msg: "Intent filed — BGP state query R1" },
      { time: "17:36:29", type: "onode", msg: "O-Node → R1 SSH connect..." },
      { time: "17:36:34", type: "warning", msg: "R1 — read timeout 5s — unresponsive" },
      { time: "17:36:34", type: "result", msg: "TIMEOUT — evidence degraded, refusing to conclude" },
      { time: "17:36:35", type: "device", msg: "ASA logs: SYN timeouts to 10.0.0.50:179" },
      { time: "17:36:35", type: "result", msg: "Root cause: R1 unreachable" },
    ],
    cage: null,
    summary: { total: 3, green: 1, yellow: 1, red: 1, pending: 0 },
    headline: "Evidence degraded — R1 timeout",
  },
  cage: {
    devices: [
      {
        hostname: "R1", vendor: "Cisco IOS", as: "AS 100", ip: "10.0.0.50",
        tier: "TIMEOUT", hmac: "a1c3f7", bgp: "—", sessions: [], status: "timeout",
      },
      {
        hostname: "ASA-5525", vendor: "Cisco ASA", as: "AS 65001", ip: "10.0.0.253",
        tier: "YELLOW", hmac: "bbc2d8", bgp: "1/2",
        sessions: [
          { neighbor: "10.10.10.2", as: "65002", type: "eBGP", state: "Established", uptime: "08:04:09", pfx: 0 },
          { neighbor: "10.0.0.50", as: "100", type: "eBGP", state: "Idle", uptime: "—", pfx: 0 },
        ],
        status: "warning",
      },
      {
        hostname: "pa-850", vendor: "PAN-OS", as: "AS 65002", ip: "10.0.0.250",
        tier: "GREEN", hmac: "969484", bgp: "1/1",
        sessions: [
          { neighbor: "ASA-5525", as: "65001", type: "eBGP", state: "Established", uptime: "08:04:11", pfx: 15 },
        ],
        status: "verified"
      },
    ],
    log: [
      { time: "17:37:01", type: "cage", msg: 'Intent: "shutdown Gi0/0 on ASA-5525"' },
      { time: "17:37:01", type: "cage", msg: "⛔ RED TIER — requires explicit approval" },
      { time: "17:37:02", type: "cage", msg: "Wall 1: Network isolation — AI has no route to devices" },
      { time: "17:37:02", type: "cage", msg: "Wall 2: Device ACLs — SSH locked to O-Node only" },
      { time: "17:37:02", type: "cage", msg: "Wall 3: Socket enforcement — writes rejected at GREEN" },
      { time: "17:37:03", type: "result", msg: "ACTION DENIED — structural, not behavioral" },
    ],
    cage: {
      command: "shutdown interface GigabitEthernet0/0",
      target: "ASA-5525",
      walls: [
        { name: "Network Isolation", desc: "CT 210 cannot route to device management", icon: "🔒" },
        { name: "Device ACLs", desc: "SSH access-class: O-Node IP only", icon: "🛡" },
        { name: "Socket Enforcement", desc: "O-Node rejects write ops at GREEN tier", icon: "⛔" },
      ],
    },
    summary: { total: 3, green: 1, yellow: 1, red: 1, pending: 0 },
    headline: "RED-tier action denied",
  },
};

const NAV_ITEMS = [
  { section: "MONITOR", items: [
    { key: "dashboard", icon: "◫", label: "Dashboard" },
    { key: "sweep", icon: "◉", label: "BGP Sweep" },
    { key: "device_down", icon: "△", label: "Device Down" },
    { key: "cage", icon: "⬡", label: "The Cage" },
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

function TierDot({ tier, size = 10 }) {
  const colors = {
    GREEN: C.green, YELLOW: C.yellow, RED: C.red,
    TIMEOUT: C.yellow, BLACK: C.textMuted, null: C.textMuted
  };
  return (
    <span style={{
      display: "inline-block", width: size, height: size, borderRadius: "50%",
      background: colors[tier] || C.textMuted,
      boxShadow: tier === "GREEN" ? `0 0 6px ${C.green}60` : tier === "RED" || tier === "TIMEOUT" ? `0 0 6px ${C.yellow}60` : "none",
    }} />
  );
}

function TierLabel({ tier }) {
  const cfg = {
    GREEN: { bg: C.greenBg, color: C.green, border: C.greenBorder, text: "GREEN" },
    YELLOW: { bg: C.yellowBg, color: C.yellow, border: C.yellowBorder, text: "YELLOW" },
    RED: { bg: C.redBg, color: C.red, border: C.redBorder, text: "RED" },
    TIMEOUT: { bg: C.yellowBg, color: C.yellow, border: C.yellowBorder, text: "TIMEOUT" },
  };
  const c = cfg[tier];
  if (!c) return <span style={{ fontFamily: MONO, fontSize: 11, color: C.textMuted }}>STANDBY</span>;
  return (
    <span style={{
      fontFamily: MONO, fontSize: 10, fontWeight: 600, letterSpacing: 1,
      color: c.color, background: c.bg, border: `1px solid ${c.border}`,
      padding: "2px 8px", borderRadius: 3, display: "inline-block",
    }}>{c.text}</span>
  );
}

function Widget({ title, children, span = 1, noPad = false }) {
  return (
    <div style={{
      background: C.card, border: `1px solid ${C.cardBorder}`,
      borderRadius: 6, gridColumn: `span ${span}`,
      boxShadow: "0 1px 3px rgba(0,0,0,0.04)",
      overflow: "hidden",
    }}>
      <div style={{
        padding: "10px 16px", borderBottom: `1px solid ${C.divider}`,
        display: "flex", alignItems: "center", justifyContent: "space-between",
      }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: C.text, letterSpacing: 0.3 }}>
          {title}
        </span>
      </div>
      <div style={{ padding: noPad ? 0 : 16 }}>
        {children}
      </div>
    </div>
  );
}

function StatusSummary({ summary }) {
  const items = [
    { label: "Total", value: summary.total, color: C.text },
    { label: "Green", value: summary.green, color: C.green },
    { label: "Warning", value: summary.yellow, color: C.yellow },
    { label: "Critical", value: summary.red, color: C.red },
    { label: "Pending", value: summary.pending, color: C.textMuted },
  ];
  return (
    <div style={{ display: "flex", gap: 0 }}>
      {items.map((it, i) => (
        <div key={i} style={{
          flex: 1, textAlign: "center", padding: "8px 0",
          borderRight: i < items.length - 1 ? `1px solid ${C.divider}` : "none",
        }}>
          <div style={{ fontSize: 22, fontWeight: 700, color: it.color, fontFamily: MONO }}>
            {it.value}
          </div>
          <div style={{ fontSize: 10, color: C.textMuted, marginTop: 2, letterSpacing: 0.5, textTransform: "uppercase" }}>
            {it.label}
          </div>
        </div>
      ))}
    </div>
  );
}

function DeviceRow({ device }) {
  return (
    <div style={{
      display: "flex", alignItems: "center", padding: "10px 16px",
      borderBottom: `1px solid ${C.divider}`, gap: 12,
      transition: "background 0.15s", cursor: "default",
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
      <div style={{ flex: "0 0 50px", fontFamily: MONO, fontSize: 12, color: C.text, textAlign: "center" }}>
        {device.bgp || "—"}
      </div>
      <div style={{ flex: 1, fontFamily: MONO, fontSize: 10, color: C.purple }}>
        {device.hmac ? `HMAC:${device.hmac} ✓` : "—"}
      </div>
      {device.alert && (
        <div style={{
          fontSize: 10, color: C.yellow, background: C.yellowBg,
          border: `1px solid ${C.yellowBorder}`, borderRadius: 3,
          padding: "2px 8px", maxWidth: 220, whiteSpace: "nowrap",
          overflow: "hidden", textOverflow: "ellipsis",
        }}>
          {device.alert}
        </div>
      )}
    </div>
  );
}

function SessionTable({ devices }) {
  const allSessions = devices.flatMap(d =>
    d.sessions.map(s => ({ ...s, device: d.hostname }))
  );
  if (allSessions.length === 0) return (
    <div style={{ padding: 20, textAlign: "center", color: C.textMuted, fontSize: 12, fontStyle: "italic" }}>
      No active sessions
    </div>
  );
  return (
    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
      <thead>
        <tr style={{ borderBottom: `1px solid ${C.divider}` }}>
          {["Device","Neighbor","Remote AS","Type","State","Uptime","Pfx Rcvd"].map(h => (
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
                fontSize: 10, fontWeight: 600, letterSpacing: 0.5,
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
    device: { color: C.text }, result: { color: C.green }, warning: { color: C.yellow },
    cage: { color: C.orange },
  };
  return (
    <div ref={ref} style={{ maxHeight: 200, overflowY: "auto", padding: entries.length ? 0 : 16 }}>
      {entries.length === 0 && (
        <div style={{ textAlign: "center", color: C.textMuted, fontSize: 12, fontStyle: "italic" }}>
          Awaiting observations...
        </div>
      )}
      {entries.map((e, i) => (
        <div key={i} style={{
          display: "flex", gap: 10, padding: "5px 16px", fontSize: 11,
          borderBottom: `1px solid ${C.divider}`,
          fontFamily: MONO,
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
        borderRadius: 4, padding: "10px 14px", marginBottom: 14,
        fontFamily: MONO, fontSize: 12,
      }}>
        <span style={{ color: C.red, fontWeight: 700 }}>DENIED</span>
        <span style={{ color: C.textSec }}> → </span>
        <span style={{ color: C.text }}>{cage.command}</span>
        <span style={{ color: C.textMuted }}> on </span>
        <span style={{ color: C.blue, fontWeight: 600 }}>{cage.target}</span>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {cage.walls.map((w, i) => (
          <div key={i} style={{
            display: "flex", alignItems: "center", gap: 12,
            background: "#fdf8f4", border: `1px solid #f0d8c0`,
            borderRadius: 4, padding: "10px 14px",
          }}>
            <span style={{ fontSize: 18, flexShrink: 0 }}>{w.icon}</span>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: C.text }}>
                Wall {i + 1}: {w.name}
              </div>
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

export default function VIRPDashboard() {
  const [view, setView] = useState("dashboard");
  const state = DEMO_STATES[view];

  return (
    <div style={{ display: "flex", height: "100vh", fontFamily: FONT, background: C.bg, overflow: "hidden" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: ${C.cardBorder}; border-radius: 3px; }
      `}</style>

      {/* Sidebar */}
      <div style={{
        width: 200, background: C.sidebar, display: "flex", flexDirection: "column",
        borderRight: `1px solid ${C.sidebarBorder}`, flexShrink: 0, overflowY: "auto",
      }}>
        {/* Logo */}
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
            <div style={{ fontSize: 9, color: C.sidebarText, letterSpacing: 0.8 }}>IronClaw v0.1</div>
          </div>
        </div>

        {/* Nav Sections */}
        <div style={{ padding: "8px 0", flex: 1 }}>
          {NAV_ITEMS.map((section, si) => (
            <div key={si} style={{ marginBottom: 4 }}>
              <div style={{
                fontSize: 9, fontWeight: 700, color: C.sidebarText,
                letterSpacing: 1.5, textTransform: "uppercase",
                padding: "10px 16px 4px",
              }}>{section.section}</div>
              {section.items.map((item, ii) => {
                const active = item.key === view;
                const disabled = item.disabled;
                return (
                  <div
                    key={ii}
                    onClick={() => !disabled && item.key && setView(item.key)}
                    style={{
                      display: "flex", alignItems: "center", gap: 10,
                      padding: "8px 16px", cursor: disabled ? "default" : "pointer",
                      background: active ? C.sidebarActive : "transparent",
                      borderLeft: active ? `3px solid ${C.accent}` : "3px solid transparent",
                      transition: "all 0.15s",
                      opacity: disabled ? 0.35 : 1,
                    }}
                    onMouseOver={e => { if (!disabled && !active) e.currentTarget.style.background = C.sidebarHover; }}
                    onMouseOut={e => { if (!active) e.currentTarget.style.background = "transparent"; }}
                  >
                    <span style={{ fontSize: 14, color: active ? C.accent : C.sidebarText, width: 18, textAlign: "center" }}>
                      {item.icon}
                    </span>
                    <span style={{
                      fontSize: 12, color: active ? C.sidebarTextActive : C.sidebarText,
                      fontWeight: active ? 600 : 400,
                    }}>{item.label}</span>
                    {item.key === "cage" && view === "cage" && (
                      <span style={{
                        marginLeft: "auto", fontSize: 8, fontWeight: 700,
                        color: C.red, background: C.redBg,
                        padding: "1px 5px", borderRadius: 3, letterSpacing: 0.5,
                      }}>!</span>
                    )}
                  </div>
                );
              })}
            </div>
          ))}
        </div>

        {/* Sidebar Footer */}
        <div style={{
          padding: "12px 16px", borderTop: `1px solid ${C.sidebarBorder}`,
          fontSize: 10, color: C.sidebarText,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
            <span style={{
              width: 6, height: 6, borderRadius: "50%", background: C.green,
              boxShadow: `0 0 4px ${C.green}`,
            }} />
            <span>O-Node Online</span>
          </div>
          <div style={{ color: "#4a5568" }}>10.0.0.211 · CT 211</div>
        </div>
      </div>

      {/* Main Content */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        {/* Top Header Bar */}
        <div style={{
          background: C.headerBg, borderBottom: `1px solid ${C.headerBorder}`,
          padding: "10px 24px", display: "flex", alignItems: "center", justifyContent: "space-between",
          flexShrink: 0,
        }}>
          <div>
            <span style={{ fontSize: 15, fontWeight: 600, color: C.text }}>
              {view === "dashboard" ? "Dashboard" : view === "sweep" ? "Act 1 — All Green" : view === "device_down" ? "Act 2 — Device Down" : "Act 3 — The Cage"}
            </span>
            <span style={{ fontSize: 12, color: C.textMuted, marginLeft: 12 }}>{state.headline}</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
            <span style={{ fontFamily: MONO, fontSize: 10, color: C.textMuted, letterSpacing: 0.5 }}>
              {new Date().toISOString().replace('T', ' ').substring(0, 19)} UTC
            </span>
            <span style={{
              fontFamily: MONO, fontSize: 10, color: C.green,
              background: C.greenBg, border: `1px solid ${C.greenBorder}`,
              padding: "3px 8px", borderRadius: 3, letterSpacing: 0.5,
            }}>VIRP ACTIVE</span>
          </div>
        </div>

        {/* Content Grid */}
        <div style={{ flex: 1, overflowY: "auto", padding: 20 }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, maxWidth: 1100 }}>

            {/* Status Summary — full width */}
            <Widget title="Security Fabric Status" span={2}>
              <StatusSummary summary={state.summary} />
            </Widget>

            {/* Device Inventory — full width */}
            <Widget title="Managed Devices" span={2} noPad>
              <div>
                {/* Table Header */}
                <div style={{
                  display: "flex", alignItems: "center", padding: "6px 16px",
                  borderBottom: `1px solid ${C.divider}`, background: "#fafbfc",
                }}>
                  <div style={{ width: 10 }} />
                  <div style={{ flex: "0 0 90px", fontSize: 10, fontWeight: 600, color: C.textMuted, letterSpacing: 0.5, marginLeft: 12 }}>DEVICE</div>
                  <div style={{ flex: "0 0 90px", fontSize: 10, fontWeight: 600, color: C.textMuted, letterSpacing: 0.5 }}>VENDOR</div>
                  <div style={{ flex: "0 0 65px", fontSize: 10, fontWeight: 600, color: C.textMuted, letterSpacing: 0.5 }}>TIER</div>
                  <div style={{ flex: "0 0 50px", fontSize: 10, fontWeight: 600, color: C.textMuted, letterSpacing: 0.5, textAlign: "center" }}>BGP</div>
                  <div style={{ flex: 1, fontSize: 10, fontWeight: 600, color: C.textMuted, letterSpacing: 0.5 }}>HMAC</div>
                </div>
                {state.devices.map((d, i) => <DeviceRow key={i} device={d} />)}
              </div>
            </Widget>

            {/* BGP Sessions */}
            <Widget title="BGP Peer Sessions" span={view === "cage" ? 1 : 2} noPad>
              <SessionTable devices={state.devices} />
            </Widget>

            {/* Cage Widget - only on cage view */}
            {view === "cage" && (
              <Widget title="⛔ The Cage — Structural Enforcement" span={1}>
                <CageWidget cage={state.cage} />
              </Widget>
            )}

            {/* Observation Log */}
            <Widget title="Observation Log" span={2} noPad>
              <LogFeed entries={state.log} />
            </Widget>
          </div>

          {/* Footer */}
          <div style={{
            textAlign: "center", padding: "20px 0 8px",
            fontSize: 10, color: C.textMuted, letterSpacing: 0.5,
          }}>
            VIRP · Verified Infrastructure Response Protocol · Third Level IT LLC · Every observation signed · Every action gated
          </div>
        </div>
      </div>
    </div>
  );
}

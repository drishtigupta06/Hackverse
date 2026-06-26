import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import * as api from "../api.js";

// ─── Mini SVG Donut Chart ────────────────────────────────────────────────────
function DonutChart({ data, size = 120 }) {
    const total = data.reduce((s, d) => s + d.value, 0) || 1;
    const r = 44, cx = 60, cy = 60, strokeW = 14;
    const circumference = 2 * Math.PI * r;
    let offset = 0;
    const segments = data.filter(d => d.value > 0).map(d => {
        const dash = (d.value / total) * circumference;
        const seg = { ...d, dash, offset };
        offset += dash;
        return seg;
    });

    return (
        <svg width={size} height={size} viewBox="0 0 120 120" style={{ transform: "rotate(-90deg)" }}>
            <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth={strokeW} />
            {segments.map((s, i) => (
                <circle key={i} cx={cx} cy={cy} r={r} fill="none"
                    stroke={s.color} strokeWidth={strokeW}
                    strokeDasharray={`${s.dash} ${circumference - s.dash}`}
                    strokeDashoffset={-s.offset} strokeLinecap="round"
                    style={{ transition: "all 0.5s ease" }} />
            ))}
        </svg>
    );
}

function StatCard({ icon, value, label, color = "#6366f1", onClick }) {
    return (
        <div className="stat-card" onClick={onClick} style={{ cursor: onClick ? "pointer" : "default" }}>
            <div className="stat-icon" style={{ background: `${color}18`, border: `1px solid ${color}30` }}>
                <span>{icon}</span>
            </div>
            <div>
                <div className="stat-value" style={{ color }}>{value}</div>
                <div className="stat-label">{label}</div>
            </div>
        </div>
    );
}

function ScanRow({ scan, onSelect, onDelete }) {
    const [deleting, setDeleting] = useState(false);
    async function handleDelete(e) {
        e.stopPropagation();
        if (!confirm(`Delete scan for ${scan.target}?`)) return;
        setDeleting(true);
        try { await api.deleteScan(scan.scan_id); onDelete(scan.scan_id); }
        catch (err) { alert(err.message); }
        finally { setDeleting(false); }
    }
    return (
        <tr onClick={() => onSelect(scan)} style={{ cursor: "pointer" }}>
            <td className="mono">{scan.scan_id?.slice(0, 8)}...</td>
            <td style={{ color: "var(--text-primary)", fontWeight: 500 }}>{scan.target}</td>
            <td>
                <span className={`status-pill status-${scan.status}`}>
                    {scan.status === "running" ? "⚡ " : scan.status === "completed" ? "✅ " : scan.status === "failed" ? "❌ " : "⏳ "}
                    {scan.status}
                </span>
            </td>
            <td style={{ color: scan.vuln_count > 0 ? "var(--accent-light)" : "var(--text-muted)" }}>{scan.vuln_count || 0}</td>
            <td style={{ color: "var(--text-muted)", fontSize: 12 }}>{scan.created_at ? new Date(scan.created_at).toLocaleString() : "—"}</td>
            <td>
                <button className="btn btn-danger btn-sm" onClick={handleDelete} disabled={deleting}
                    style={{ padding: "4px 8px", fontSize: 11 }}>
                    {deleting ? "..." : "🗑️"}
                </button>
            </td>
        </tr>
    );
}

export default function Dashboard({ user }) {
    const navigate = useNavigate();
    const [stats, setStats] = useState(null);
    const [scans, setScans] = useState([]);
    const [loading, setLoading] = useState(true);

    async function load() {
        try {
            const [s, sc] = await Promise.all([api.getStats(), api.listScans(10)]);
            setStats(s);
            setScans(sc.scans || []);
        } catch (e) { console.error(e); }
        finally { setLoading(false); }
    }

    useEffect(() => {
        load();
        const interval = setInterval(load, 15000);
        return () => clearInterval(interval);
    }, []);

    function removeScan(scanId) {
        setScans(prev => prev.filter(s => s.scan_id !== scanId));
        load();
    }

    const sevData = stats ? [
        { value: stats.critical_count, color: "#dc2626", label: "Critical" },
        { value: stats.high_count, color: "#ea580c", label: "High" },
        { value: stats.medium_count || 0, color: "#d97706", label: "Medium" },
        { value: stats.low_count || 0, color: "#65a30d", label: "Low" },
    ] : [];

    const riskLevel = stats?.risk_level
        ? { label: stats.risk_level.toUpperCase(), color: stats.risk_level === "Low" ? "var(--green)" : stats.risk_level === "Medium" ? "var(--yellow)" : stats.risk_level === "High" ? "var(--orange)" : "var(--red)" }
        : { label: "UNKNOWN", color: "var(--text-muted)" };

    if (loading) {
        return <div className="loading-center"><div className="spinner" style={{ width: 32, height: 32 }} /><span>Loading dashboard...</span></div>;
    }

    return (
        <div className="fade-in">
            <div className="page-header">
                <div>
                    <div className="page-title"><span>📊</span> Dashboard</div>
                    <div className="page-subtitle">
                        Welcome back, <strong style={{ color: "var(--accent-light)" }}>{user}</strong>
                    </div>
                </div>
                <div style={{ display: "flex", gap: 10 }}>
                    <button className="btn btn-secondary" onClick={() => navigate("/cvelookup")}>🔎 CVE Lookup</button>
                    <button className="btn btn-primary" onClick={() => navigate("/scan")}>+ New Scan</button>
                </div>
            </div>

            <div className="stats-grid">
                <StatCard icon="🔍" value={stats?.total_scans ?? 0} label="Total Scans" color="#6366f1" onClick={() => navigate("/results")} />
                <StatCard icon="🧠" value={stats?.intelligence_count ?? 0} label="Intelligence Base" color="#10b981" />
                <StatCard icon="⚡" value={stats?.running_scans ?? 0} label="Running" color="#06b6d4" />

                {/* Risk Score Gauge */}
                <div className="card hover-glow" style={{ background: "linear-gradient(45deg, rgba(15,23,42,0.9), rgba(30,41,59,0.9))", border: "1px solid var(--border)", position: "relative", overflow: "hidden" }}>
                    <div style={{ position: "absolute", top: 0, left: 0, width: "100%", height: "4px", background: riskLevel.color }} />
                    <div style={{ textAlign: "center", padding: "10px 0" }}>
                        <div style={{ fontSize: 32, fontWeight: 900, color: riskLevel.color, textShadow: `0 0 20px ${riskLevel.color}44` }}>
                            {stats?.security_score ?? 42} <span style={{ fontSize: 14, color: "var(--text-muted)" }}>/ 100</span>
                        </div>
                        <div style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: "2px", color: "var(--text-muted)", marginTop: -4 }}>Security Score</div>
                        <div style={{ marginTop: 8, fontSize: 13, fontWeight: 700, color: "var(--text-primary)" }}>
                            Risk Level: <span style={{ color: riskLevel.color }}>{riskLevel.label}</span>
                        </div>
                    </div>
                </div>

                {/* AI Hacker Mode Button */}
                <div className="card" style={{
                    gridColumn: "span 2",
                    background: "rgba(99, 102, 241, 0.05)",
                    border: "2px solid var(--accent)",
                    display: "flex",
                    flexDirection: "column",
                    justifyContent: "center",
                    alignItems: "center",
                    gap: 12,
                    position: "relative"
                }}>
                    <div style={{ position: "absolute", top: 10, right: 10, fontSize: 10, background: "var(--accent)", color: "#fff", padding: "2px 6px", borderRadius: 4, fontWeight: 800 }}>LIVE DEMO</div>
                    <div style={{ textAlign: "center" }}>
                        <div style={{ fontSize: 16, fontWeight: 800, color: "var(--text-primary)", marginBottom: 4 }}>Autonomous Pentest Mode</div>
                        <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 12 }}>One-click full autonomous reconnaissance and exploit path generation.</div>
                    </div>
                    <button className="btn btn-primary" style={{ padding: "12px 30px", fontSize: 14, fontWeight: 800, background: "linear-gradient(90deg, #6366f1, #a855f7)", border: "none", boxShadow: "0 0 20px rgba(99,102,241,0.4)" }}
                        onClick={async () => {
                            const target = prompt("Enter Target Domain (e.g. juice-shop.herokuapp.com):", "juice-shop.herokuapp.com");
                            if (target) {
                                try {
                                    const r = await api.startHackerMode(target);
                                    navigate("/task-monitor/" + r.scan_id);
                                } catch (err) { alert(err.message); }
                            }
                        }}>
                        ⚡ DEPLOY AI HACKER MODE
                    </button>
                </div>
            </div>

            {/* Middle row: Severity chart + Quick actions */}
            <div style={{ display: "grid", gridTemplateColumns: "260px 1fr", gap: 16, marginBottom: 24 }}>
                {/* Severity Donut */}
                <div className="card" style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
                    <div className="card-title" style={{ alignSelf: "flex-start" }}>📊 Severity Breakdown</div>
                    {stats?.total_vulnerabilities > 0 ? (
                        <div style={{ position: "relative", display: "flex", justifyContent: "center" }}>
                            <DonutChart data={sevData} size={140} />
                            <div style={{
                                position: "absolute", top: "50%", left: "50%",
                                transform: "translate(-50%, -50%)", textAlign: "center",
                            }}>
                                <div style={{ fontSize: 24, fontWeight: 800, color: "var(--text-primary)", lineHeight: 1 }}>
                                    {stats.total_vulnerabilities}
                                </div>
                                <div style={{ fontSize: 11, color: "var(--text-muted)" }}>total</div>
                            </div>
                        </div>
                    ) : (
                        <div style={{ padding: 20, textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>
                            🎉 No vulnerabilities found yet
                        </div>
                    )}
                    <div style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 8, width: "100%" }}>
                        {sevData.filter(d => d.value > 0).map(d => (
                            <div key={d.label} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                <div style={{ width: 10, height: 10, borderRadius: "50%", background: d.color, flexShrink: 0 }} />
                                <span style={{ fontSize: 12, color: "var(--text-secondary)", flex: 1 }}>{d.label}</span>
                                <span style={{ fontSize: 12, color: d.color, fontWeight: 700 }}>{d.value}</span>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Quick Actions */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                    {[
                        { icon: "🎯", title: "Launch Scan", desc: "Nmap or Acunetix scan on a target", page: "scan", color: "#6366f1" },
                        { icon: "🔎", title: "CVE Lookup", desc: "Search any CVE-ID in real time via NVD", page: "cvelookup", color: "#06b6d4" },
                        { icon: "💬", title: "AI Assistant", desc: "Ask CyberGuard AI about any vulnerability", page: "chat", color: "#10b981" },
                        { icon: "📄", title: "Reports", desc: "Download full PDF vulnerability reports", page: "reports", color: "#f59e0b" },
                    ].map(a => (
                        <div key={a.page} className="card" style={{
                            textAlign: "center", cursor: "pointer",
                            borderColor: "var(--border)",
                            transition: "var(--transition)",
                        }} onClick={() => navigate(`/${a.page}`)}>
                            <div style={{ fontSize: 36, marginBottom: 10 }}>{a.icon}</div>
                            <div style={{ fontWeight: 700, color: a.color, marginBottom: 4 }}>{a.title}</div>
                            <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>{a.desc}</div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Recent scans + Hacker Timeline Sidebar */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 280px", gap: 16 }}>
                <div className="card">
                    <div className="card-title" style={{ justifyContent: "space-between" }}>
                        🕐 Recent Activity
                    </div>
                    {scans.length === 0 ? (
                        <div className="empty-state">
                            <div className="empty-state-icon">🔍</div>
                            <div className="empty-state-title">No scans yet</div>
                        </div>
                    ) : (
                        <div className="table-container">
                            <table>
                                <thead><tr><th>ID</th><th>Target</th><th>Status</th><th>Findings</th><th>Started</th></tr></thead>
                                <tbody>
                                    {scans.map(s => (
                                        <ScanRow key={s.scan_id} scan={s}
                                            onSelect={() => navigate(`/results/${s.scan_id}`)}
                                            onDelete={removeScan} />
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>

                {/* Hacker Timeline Sidecar */}
                <div className="card" style={{ background: "rgba(0,0,0,0.2)", border: "1px solid var(--accent)", position: "relative" }}>
                    <div className="card-title" style={{ fontSize: 12 }}>⚡ Hacker Timeline</div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 12, padding: "10px 0" }}>
                        {[
                            { time: "00:01", event: "Reconnaissance", status: "completed", color: "var(--cyan)" },
                            { time: "00:03", event: "Asset Discovery", status: "completed", color: "var(--accent)" },
                            { time: "00:05", event: "Vuln Analysis", status: "in-progress", color: "var(--orange)" },
                            { time: "00:08", event: "Exploit Vectoring", status: "queued", color: "var(--text-muted)" },
                            { time: "00:10", event: "Impact Simulation", status: "queued", color: "var(--text-muted)" },
                        ].map((t, i) => (
                            <div key={i} style={{ display: "flex", gap: 10, alignItems: "center" }}>
                                <div style={{ fontSize: 10, color: "var(--text-muted)", width: 35 }}>{t.time}</div>
                                <div style={{ width: 8, height: 8, borderRadius: "50%", background: t.color, boxShadow: t.status === "in-progress" ? `0 0 8px ${t.color}` : "none" }} />
                                <div style={{ flex: 1 }}>
                                    <div style={{ fontSize: 11, fontWeight: 700, color: t.status === "queued" ? "var(--text-muted)" : "var(--text-primary)" }}>{t.event}</div>
                                    {t.status === "in-progress" && <div style={{ fontSize: 9, color: t.color }}>Pulsing active agent...</div>}
                                </div>
                            </div>
                        ))}
                    </div>
                    <div style={{ marginTop: 15, padding: 8, background: "rgba(99,102,241,0.1)", borderRadius: 6, fontSize: 10, color: "var(--text-secondary)" }}>
                        💡 Demo tip: Full timeline completes in 60s during AI Hacker Mode.
                    </div>
                </div>
            </div>

        </div >
    );
}

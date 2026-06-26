import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import * as api from "../api.js";

export default function ScanPage({ user }) {
    const navigate = useNavigate();
    const [target, setTarget] = useState("127.0.0.1");
    const [scanTypes, setScanTypes] = useState({ nmap: true, acunetix: false });
    const [description, setDescription] = useState("");
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState("");
    const [logs, setLogs] = useState([]);
    const wsRef = useRef(null);
    const logEndRef = useRef(null);

    useEffect(() => {
        logEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [logs]);

    useEffect(() => {
        return () => { wsRef.current?.close(); };
    }, []);

    function addLog(msg, type = "info") {
        setLogs(prev => [...prev, { msg, type, time: new Date().toLocaleTimeString() }]);
    }

    function connectWS(scanId) {
        const ws = api.connectScanWS(scanId, (msg) => {
            if (msg.type === "log") {
                addLog(msg.msg, msg.level || "info");
            } else if (msg.type === "done") {
                addLog(`✅ Scan complete! ${msg.vuln_count} vulnerabilities found.`, "success");
                setLoading(false);
                ws.close();
                // Refresh scan status
                api.getScan(scanId).then(s => setResult(s)).catch(() => { });
            } else if (msg.type === "error") {
                addLog(`❌ Error: ${msg.msg}`, "error");
                setLoading(false);
                ws.close();
            } else if (msg.type === "status") {
                if (["completed", "failed"].includes(msg.status)) {
                    setLoading(false);
                    ws.close();
                }
            }
        });
        wsRef.current = ws;
    }

    async function handleScan(e) {
        e.preventDefault();
        setError(""); setResult(null); setLogs([]);
        const types = Object.keys(scanTypes).filter(k => scanTypes[k]);
        if (!types.length) { setError("Select at least one scan type"); return; }

        setLoading(true);
        addLog(`🎯 Targeting: ${target}`);
        addLog(`📡 Scan types: ${types.join(", ")}`);

        try {
            let data;
            if (target === "127.0.0.1" || target === "localhost") {
                addLog("⚡ Starting background scan via FastAPI...");
                data = await api.runDemoScan();
            } else {
                addLog("📬 Queueing scan task...");
                data = await api.createScan(target, types, description);
            }

            addLog(`✅ Scan started! ID: ${data.scan_id}`, "success");
            addLog(`🔌 Connecting to live stream...`);
            setResult(prev => ({ ...prev, ...data }));

            // Connect WebSocket for real-time logs
            connectWS(data.scan_id);

            // Also poll as fallback
            let polls = 0;
            const pollInterval = setInterval(async () => {
                polls++;
                try {
                    const s = await api.getScan(data.scan_id);
                    setResult(s);
                    if (["completed", "failed"].includes(s.status)) {
                        clearInterval(pollInterval);
                        setLoading(false);
                    }
                } catch { }
                if (polls > 60) clearInterval(pollInterval);
            }, 5000);

        } catch (err) {
            setError(err.message);
            addLog(`❌ ${err.message}`, "error");
            setLoading(false);
        }
    }

    const statusColor = {
        completed: "var(--green)", running: "var(--cyan)",
        failed: "var(--red)", pending: "var(--text-muted)"
    };

    return (
        <div className="fade-in">
            <div className="page-header">
                <div>
                    <div className="page-title"><span>🔬</span> Launch Scan</div>
                    <div className="page-subtitle">Configure and run vulnerability scans — real-time progress via WebSocket</div>
                </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24 }}>
                {/* Config Panel */}
                <div className="card">
                    <div className="card-title">⚙️ Scan Configuration</div>
                    <form onSubmit={handleScan} style={{ display: "flex", flexDirection: "column", gap: 20 }}>
                        <div className="input-group">
                            <label className="input-label">Target (IP or URL)</label>
                            <input className="input" value={target} onChange={e => setTarget(e.target.value)}
                                placeholder="192.168.1.1 or https://example.com" required />
                            <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 4 }}>
                                💡 Use <code style={{ color: "var(--cyan)" }}>127.0.0.1</code> for a quick demo (runs instantly without Celery)
                            </div>
                        </div>

                        <div className="input-group">
                            <label className="input-label">Scan Engines</label>
                            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                                {[
                                    { key: "nmap", icon: "📡", label: "Nmap", desc: "Port scan + service detection + vulnerability scripts" },
                                    { key: "acunetix", icon: "🕷️", label: "Acunetix DAST", desc: "Web app vulnerability scan (requires API key)" },
                                ].map(({ key, icon, label, desc }) => (
                                    <label key={key} style={{
                                        display: "flex", alignItems: "center", gap: 12, padding: "12px 14px", cursor: "pointer",
                                        background: scanTypes[key] ? "rgba(99,102,241,0.1)" : "rgba(10,22,40,0.5)",
                                        border: `1px solid ${scanTypes[key] ? "var(--accent)" : "var(--border)"}`,
                                        borderRadius: "var(--radius-sm)", transition: "var(--transition)",
                                    }}>
                                        <input type="checkbox" checked={scanTypes[key]}
                                            onChange={e => setScanTypes(p => ({ ...p, [key]: e.target.checked }))}
                                            style={{ display: "none" }} />
                                        <span style={{ fontSize: 20 }}>{icon}</span>
                                        <div style={{ flex: 1 }}>
                                            <div style={{ fontWeight: 600, fontSize: 14, color: "var(--text-primary)" }}>{label}</div>
                                            <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>{desc}</div>
                                        </div>
                                        <div style={{
                                            width: 20, height: 20, borderRadius: 4, flexShrink: 0,
                                            background: scanTypes[key] ? "var(--accent)" : "transparent",
                                            border: `2px solid ${scanTypes[key] ? "var(--accent)" : "var(--border)"}`,
                                            display: "flex", alignItems: "center", justifyContent: "center",
                                            fontSize: 12, color: "white", transition: "var(--transition)",
                                        }}>{scanTypes[key] ? "✓" : ""}</div>
                                    </label>
                                ))}
                            </div>
                        </div>

                        <div className="input-group">
                            <label className="input-label">Description (optional)</label>
                            <input className="input" value={description} onChange={e => setDescription(e.target.value)}
                                placeholder="Q1 2026 security assessment..." />
                        </div>

                        {error && <div className="alert alert-error">⚠️ {error}</div>}

                        <button className="btn btn-primary btn-lg" type="submit" disabled={loading}
                            style={{ justifyContent: "center" }}>
                            {loading
                                ? <><div className="spinner" style={{ width: 18, height: 18 }} /> Scanning...</>
                                : "🚀 Launch Scan"}
                        </button>
                    </form>
                </div>

                {/* Right panel */}
                <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                    {/* Status Card */}
                    {result && (
                        <div className="card">
                            <div className="card-title">📊 Scan Status</div>
                            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 16 }}>
                                {[
                                    ["Scan ID", result.scan_id?.slice(0, 12) + "...", "var(--font-mono)"],
                                    ["Target", result.target, null],
                                    ["Status", result.status, statusColor[result.status] || "var(--text-primary)"],
                                    ["Findings", `${result.vuln_count || 0} vulnerabilities`, null],
                                ].map(([k, v, color]) => (
                                    <div key={k} style={{
                                        padding: "10px 14px", background: "rgba(10,22,40,0.6)",
                                        borderRadius: "var(--radius-sm)", border: "1px solid var(--border)",
                                    }}>
                                        <div style={{ fontSize: 11, color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase" }}>{k}</div>
                                        <div style={{
                                            fontSize: 14, fontWeight: 600, marginTop: 4,
                                            fontFamily: k === "Scan ID" ? "var(--font-mono)" : "inherit",
                                            color: color || "var(--text-primary)"
                                        }}>{v}</div>
                                    </div>
                                ))}
                            </div>
                            {result.status === "completed" && (
                                <div style={{ display: "flex", gap: 10 }}>
                                    <button className="btn btn-primary" style={{ flex: 1, justifyContent: "center" }}
                                        onClick={() => navigate(`/results/${result.scan_id}`)}>
                                        🔎 View Results →
                                    </button>
                                    <button className="btn btn-secondary" onClick={() => navigate(`/graph/${result.scan_id}`)}>
                                        🕸️ Graph
                                    </button>
                                </div>
                            )}
                        </div>
                    )}

                    {/* Live log terminal */}
                    <div className="card" style={{ flex: 1 }}>
                        <div className="card-title">
                            📋 Live Scan Log
                            {loading && <div className="spinner" style={{ width: 14, height: 14, marginLeft: "auto" }} />}
                        </div>
                        <div style={{
                            height: result ? 280 : 380, overflowY: "auto", padding: 12,
                            background: "rgba(5,10,20,0.9)", borderRadius: "var(--radius-sm)",
                            border: "1px solid var(--border)", fontFamily: "var(--font-mono)", fontSize: 12,
                        }}>
                            {logs.length === 0 ? (
                                <div style={{ color: "var(--text-muted)", textAlign: "center", paddingTop: 40 }}>
                                    Waiting for scan to start...
                                </div>
                            ) : logs.map((l, i) => (
                                <div key={i} style={{
                                    color: l.type === "error" ? "var(--red)" : l.type === "success" ? "var(--green)" : "var(--cyan)",
                                    marginBottom: 4, display: "flex", gap: 8,
                                }}>
                                    <span style={{ color: "var(--text-muted)", flexShrink: 0 }}>[{l.time}]</span>
                                    <span>{l.msg}</span>
                                </div>
                            ))}
                            <div ref={logEndRef} />
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

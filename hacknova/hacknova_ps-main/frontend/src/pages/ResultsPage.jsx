import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import * as api from "../api.js";

function SeverityBadge({ severity }) {
    return <span className={`badge badge-${severity}`}>{severity?.toUpperCase()}</span>;
}

export default function ResultsPage({ user }) {
    const { scanId: routeScanId } = useParams();
    const navigate = useNavigate();
    const [scans, setScans] = useState([]);
    const [selectedScan, setSelectedScan] = useState(routeScanId || null);
    const [vulns, setVulns] = useState([]);
    const [hosts, setHosts] = useState([]);
    const [tab, setTab] = useState("vulnerabilities");
    const [filters, setFilters] = useState({ severity: "", source: "" });
    const [loading, setLoading] = useState(false);
    const [search, setSearch] = useState("");

    useEffect(() => {
        api.listScans(50).then(r => {
            const done = (r.scans || []).filter(s => s.status === "completed");
            setScans(done);
            if (!selectedScan && !routeScanId && done.length > 0) setSelectedScan(done[0].scan_id);
        });
    }, []);

    useEffect(() => {
        if (routeScanId) {
            setSelectedScan(routeScanId);
        }
    }, [routeScanId]);

    useEffect(() => {
        if (!selectedScan) return;
        setLoading(true);
        const f = {};
        if (filters.severity) f.severity = filters.severity;
        if (filters.source) f.source = filters.source;
        Promise.all([
            api.getScanVulnerabilities(selectedScan, f),
            api.getScanHosts(selectedScan),
        ]).then(([vr, hr]) => {
            setVulns(vr.vulnerabilities || []);
            setHosts(hr.hosts || []);
        }).catch(console.error).finally(() => setLoading(false));
    }, [selectedScan, filters]);

    const filteredVulns = vulns.filter(v =>
        !search || JSON.stringify(v).toLowerCase().includes(search.toLowerCase())
    );

    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sorted = [...filteredVulns].sort((a, b) =>
        (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5)
    );

    return (
        <div className="fade-in">
            <div className="page-header">
                <div>
                    <div className="page-title"><span>🔍</span> Scan Results</div>
                    <div className="page-subtitle">{selectedScan ? `Viewing scan: ${selectedScan?.slice(0, 8)}...` : "Select a completed scan"}</div>
                </div>
                {selectedScan && (
                    <div style={{ display: "flex", gap: 12 }}>
                        <button className="btn btn-secondary" onClick={() => navigate(`/graph/${selectedScan}`)}>🕸️ Attack Graph</button>
                        <button className="btn btn-secondary" onClick={() => navigate(`/simulation/${selectedScan}`)}>🧠 AI Simulation</button>
                        <button className="btn btn-primary" onClick={() => navigate(`/chat/${selectedScan}`)}>💬 Ask AI</button>
                    </div>
                )}
            </div>

            {/* Scan selector */}
            <div className="card" style={{ marginBottom: 24 }}>
                <div className="card-title" style={{ marginBottom: 12 }}>📁 Select Scan</div>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                    {scans.length === 0 && <div style={{ color: "var(--text-muted)", fontSize: 14 }}>No completed scans yet. Run a scan first.</div>}
                    {scans.map(s => (
                        <button key={s.scan_id} onClick={() => navigate(`/results/${s.scan_id}`)}
                            className={`btn btn-sm ${selectedScan === s.scan_id ? "btn-primary" : "btn-secondary"}`}>
                            {s.target} ({s.vuln_count} findings)
                        </button>
                    ))}
                </div>
            </div>

            {selectedScan && (
                <>
                    {/* Tabs */}
                    <div style={{ display: "flex", gap: 4, marginBottom: 16, borderBottom: "1px solid var(--border)", paddingBottom: 0 }}>
                        {[
                            { id: "vulnerabilities", label: `🐛 Vulnerabilities (${vulns.length})` },
                            { id: "hosts", label: `🖥️ Hosts & Ports (${hosts.length})` },
                        ].map(t => (
                            <button key={t.id} onClick={() => setTab(t.id)} style={{
                                padding: "10px 20px", border: "none", background: "none", cursor: "pointer",
                                color: tab === t.id ? "var(--accent-light)" : "var(--text-muted)",
                                fontSize: 14, fontWeight: 600,
                                borderBottom: tab === t.id ? "2px solid var(--accent)" : "2px solid transparent",
                                transition: "var(--transition)",
                            }}>{t.label}</button>
                        ))}
                    </div>

                    {/* Filters */}
                    <div className="filters-bar">
                        <input className="input" placeholder="🔎 Search vulnerabilities..."
                            value={search} onChange={e => setSearch(e.target.value)}
                            style={{ maxWidth: 300 }} />
                        <select className="filter-select" value={filters.severity} onChange={e => setFilters(p => ({ ...p, severity: e.target.value }))}>
                            <option value="">All Severities</option>
                            {["critical", "high", "medium", "low", "info"].map(s =>
                                <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                            )}
                        </select>
                        <select className="filter-select" value={filters.source} onChange={e => setFilters(p => ({ ...p, source: e.target.value }))}>
                            <option value="">All Sources</option>
                            <option value="nmap">Nmap</option>
                            <option value="acunetix">Acunetix</option>
                        </select>
                    </div>

                    {loading ? (
                        <div className="loading-center"><div className="spinner" style={{ width: 28, height: 28 }} /><span>Loading results...</span></div>
                    ) : tab === "vulnerabilities" ? (
                        sorted.length === 0 ? (
                            <div className="empty-state">
                                <div className="empty-state-icon">🎉</div>
                                <div className="empty-state-title">No vulnerabilities found</div>
                                <div className="empty-state-desc">Great news — no issues matching your filters</div>
                            </div>
                        ) : (
                            <div className="table-container">
                                <table>
                                    <thead>
                                        <tr>
                                            <th>Host</th>
                                            <th>Port</th>
                                            <th>Service</th>
                                            <th>Vulnerability</th>
                                            <th>MITRE ATT&CK</th>
                                            <th>CVE ID</th>
                                            <th>Severity</th>
                                            <th>CVSS</th>
                                            <th>Source</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {sorted.map((v, i) => (
                                            <tr key={i}>
                                                <td className="mono">{v.host}</td>
                                                <td className="mono">{v.port || "—"}</td>
                                                <td style={{ color: "var(--text-secondary)" }}>{v.service || "—"}</td>
                                                <td style={{ maxWidth: 260, color: "var(--text-primary)", fontWeight: 500 }}>
                                                    <div style={{ fontWeight: 600 }}>{v.name}</div>
                                                    <div className="text-muted" style={{ fontSize: 11, marginTop: 4 }}>{v.description?.slice(0, 100)}...</div>
                                                </td>
                                                <td>
                                                    {v.mitre_tactic && v.mitre_tactic !== "Unknown" ? (
                                                        <div>
                                                            <div style={{ fontSize: 12, fontWeight: 700, color: "var(--cyan)" }}>{v.mitre_tactic}</div>
                                                            <div style={{ fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>{v.mitre_technique}</div>
                                                        </div>
                                                    ) : <span className="text-muted" style={{ fontSize: 11 }}>Unmapped</span>}
                                                </td>
                                                <td className="mono" style={{ color: "var(--accent-light)", fontSize: 12 }}>{v.cve_id || "-"}</td>
                                                <td><SeverityBadge severity={v.severity} /></td>
                                                <td style={{ fontWeight: 600 }}>{v.cvss_score ? v.cvss_score.toFixed(1) : "-"}</td>
                                                <td><span className="badge badge-info">{v.source?.toUpperCase()}</span></td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )
                    ) : (
                        /* Hosts tab */
                        hosts.length === 0 ? (
                            <div className="empty-state">
                                <div className="empty-state-icon">🖥️</div>
                                <div className="empty-state-title">No host data</div>
                            </div>
                        ) : hosts.map((h, hi) => (
                            <div key={hi} className="card" style={{ marginBottom: 16 }}>
                                <div className="card-title">🖥️ {h.host}</div>
                                <div className="table-container">
                                    <table>
                                        <thead><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Version</th></tr></thead>
                                        <tbody>
                                            {(h.ports || []).map((p, pi) => (
                                                <tr key={pi}>
                                                    <td className="mono">{p.port}</td>
                                                    <td className="mono">{p.protocol}</td>
                                                    <td><span className={`status-pill ${p.state === "open" ? "status-completed" : "status-pending"}`}>{p.state}</span></td>
                                                    <td style={{ color: "var(--text-primary)" }}>{p.service}</td>
                                                    <td style={{ color: "var(--text-secondary)", fontSize: 12 }}>{p.version}</td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        ))
                    )}
                </>
            )}
        </div>
    );
}

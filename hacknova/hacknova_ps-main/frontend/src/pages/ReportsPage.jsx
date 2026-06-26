import { useState, useEffect } from "react";
import * as api from "../api.js";

export default function ReportsPage() {
    const [scans, setScans] = useState([]);
    const [loading, setLoading] = useState(false);
    const [downloading, setDownloading] = useState(null);
    const [error, setError] = useState("");
    const [success, setSuccess] = useState("");

    useEffect(() => {
        Promise.all([
            api.listScans(50).then(r => r.scans || []),
            api.listLLMJobs(50).then(r => r.jobs || []),
            api.listMobileScans(50).then(r => r.jobs || [])
        ]).then(([nmapScans, llmJobs, mobileScans]) => {
            const doneNmap = nmapScans.filter(s => s.status === "completed").map(s => ({
                id: s.scan_id, target: s.target, type: "Network Scan", time: s.completed_at,
                vulns: s.vuln_count || 0, icon: "📋", downloadFn: api.downloadReport
            }));

            const doneLLM = llmJobs.filter(s => s.status === "completed").map(s => {
                const fails = (s.results || []).filter(r => r.status === "FAIL").length;
                return {
                    id: s.scan_id, target: s.model_name || "LLM Model", type: "LLM Scan", time: s.created_at || s.updated_at,
                    vulns: fails, icon: "🤖", downloadFn: api.downloadLLMReport
                };
            });

            const doneMobile = mobileScans.filter(s => s.status === "completed").map(s => {
                let fails = 0;
                for (const list of Object.values(s.report || {})) {
                    if (Array.isArray(list)) fails += list.length;
                }
                return {
                    id: s.scan_id, target: s.filename || "App", type: "Mobile Scan", time: s.created_at || s.updated_at,
                    vulns: fails, icon: "📱", downloadFn: api.downloadMobileReport
                };
            });

            const allScans = [...doneNmap, ...doneLLM, ...doneMobile].sort((a, b) => new Date(b.time) - new Date(a.time));
            setScans(allScans);
        }).catch(err => {
            console.error(err);
        });
    }, []);

    async function handleDownload(scan) {
        setError(""); setSuccess("");
        setDownloading(scan.id);
        try {
            const blob = await scan.downloadFn(scan.id);
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.style.display = "none";
            a.href = url;
            a.download = `cyberguard_${scan.type.replace(" ", "_").toLowerCase()}_${scan.id.slice(0, 8)}.pdf`;
            document.body.appendChild(a);
            a.click();

            setTimeout(() => {
                document.body.removeChild(a);
                window.URL.revokeObjectURL(url);
            }, 100);

            setSuccess(`✅ Report downloaded for ${scan.target}`);
        } catch (err) {
            setError(`Failed to download report: ${err.message}`);
        } finally {
            setDownloading(null);
        }
    }

    const sevMap = { critical: "var(--red)", high: "var(--orange)", medium: "var(--yellow)", low: "var(--green)", info: "var(--cyan)" };

    return (
        <div className="fade-in">
            <div className="page-header">
                <div>
                    <div className="page-title"><span>📄</span> Reports</div>
                    <div className="page-subtitle">Download PDF vulnerability reports for completed scans</div>
                </div>
            </div>

            {error && <div className="alert alert-error">⚠️ {error}</div>}
            {success && <div className="alert alert-success">{success}</div>}

            {scans.length === 0 ? (
                <div className="empty-state">
                    <div className="empty-state-icon">📄</div>
                    <div className="empty-state-title">No completed scans</div>
                    <div className="empty-state-desc">Complete a scan to generate a downloadable PDF report</div>
                </div>
            ) : (
                <div style={{ display: "grid", gap: 16 }}>
                    {scans.map(scan => (
                        <div key={scan.id} className="card" style={{ display: "grid", gridTemplateColumns: "1fr auto", alignItems: "center", gap: 24 }}>
                            <div style={{ display: "flex", gap: 20, alignItems: "center" }}>
                                {/* Icon */}
                                <div style={{
                                    width: 56, height: 56, borderRadius: "var(--radius)", flexShrink: 0,
                                    background: "linear-gradient(135deg, rgba(99,102,241,0.15), rgba(6,182,212,0.1))",
                                    border: "1px solid var(--border)",
                                    display: "flex", alignItems: "center", justifyContent: "center", fontSize: 26,
                                }}>{scan.icon}</div>

                                {/* Info */}
                                <div style={{ flex: 1 }}>
                                    <div style={{ fontWeight: 700, color: "var(--text-primary)", fontSize: 16, marginBottom: 4 }}>
                                        {scan.target}
                                    </div>
                                    <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
                                        <span style={{ fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--font-mono)", background: "var(--bg-secondary)", padding: "2px 6px", borderRadius: 4 }}>
                                            {scan.type}
                                        </span>
                                        <span style={{ fontSize: 12, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                                            ID: {scan.id?.slice(0, 12)}...
                                        </span>
                                        <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
                                            📅 {scan.time ? new Date(scan.time).toLocaleString() : "—"}
                                        </span>
                                    </div>

                                    {/* Vulnerability summary */}
                                    <div style={{ display: "flex", gap: 10, marginTop: 10, flexWrap: "wrap" }}>
                                        <span style={{ fontSize: 13, color: "var(--accent-light)", fontWeight: 600 }}>
                                            {scan.vulns} findings / issues
                                        </span>
                                    </div>
                                </div>
                            </div>

                            {/* Actions */}
                            <div style={{ display: "flex", gap: 10, flexDirection: "column", alignItems: "flex-end" }}>
                                <button
                                    className="btn btn-primary"
                                    onClick={() => handleDownload(scan)}
                                    disabled={downloading === scan.id}
                                >
                                    {downloading === scan.id ? (
                                        <><div className="spinner" style={{ width: 16, height: 16 }} /> Generating...</>
                                    ) : (
                                        "⬇️ Download PDF"
                                    )}
                                </button>
                                <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Consolidated executive summary</span>
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {/* Report contents legend */}
            {scans.length > 0 && (
                <div className="card" style={{ marginTop: 24 }}>
                    <div className="card-title">📋 Report Contents</div>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12 }}>
                        {[
                            { icon: "🎯", label: "Target Info" },
                            { icon: "🔍", label: "Executive Summary" },
                            { icon: "📊", label: "Vulnerability Table" },
                            { icon: "🐛", label: "Detailed Findings" },
                            { icon: "🕸️", label: "Attack Graph Analysis" },
                            { icon: "💊", label: "Remediation Advice" },
                            { icon: "📚", label: "CVE References" },
                            { icon: "🔒", label: "Security Recommendations" },
                        ].map(({ icon, label }) => (
                            <div key={label} style={{
                                display: "flex", alignItems: "center", gap: 8, padding: "8px 12px",
                                background: "rgba(99,102,241,0.06)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)"
                            }}>
                                <span>{icon}</span>
                                <span style={{ fontSize: 13, color: "var(--text-secondary)" }}>{label}</span>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}

import React, { useState, useEffect } from "react";
import * as api from "../api.js";

const CredentialLeaks = () => {
    const [targetDomain, setTargetDomain] = useState("");
    const [loading, setLoading] = useState(false);
    const [jobs, setJobs] = useState([]);
    const [selectedJob, setSelectedJob] = useState(null);
    const [findings, setFindings] = useState([]);
    const [error, setError] = useState(null);

    useEffect(() => {
        fetchJobs();
    }, []);

    const fetchJobs = async () => {
        try {
            const res = await api.get("/recon/leaks/jobs");
            setJobs(res.jobs || []);
        } catch (err) {
            console.error("Failed to fetch leak jobs", err);
        }
    };

    const handleScan = async (e) => {
        e.preventDefault();
        if (!targetDomain) return;
        setLoading(true);
        setError(null);
        try {
            await api.post("/recon/leaks/scan", { target_domain: targetDomain });
            setTargetDomain("");
            setTimeout(fetchJobs, 1000); // Wait for the background task to initialize
        } catch (err) {
            setError(err.response?.data?.detail || "Leak scan failed to start");
        } finally {
            setLoading(false);
        }
    };

    const viewResults = async (job) => {
        setSelectedJob(job);
        setLoading(true);
        try {
            const res = await api.get(`/recon/leaks/results/${job.scan_id}`);
            setFindings(res.report?.findings || []);
        } catch (err) {
            setError("Failed to fetch leak findings");
            setFindings([]);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="fade-in">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 30 }}>
                <div>
                    <h1 style={{ margin: 0, fontSize: "1.8rem", fontWeight: 800, letterSpacing: -0.5 }}>
                        Credential Leak Monitoring
                    </h1>
                    <p style={{ margin: "5px 0 0 0", color: "var(--text-muted)", fontSize: 14 }}>
                        OSINT intelligence gathering across Pastebin, GitHub, and dark web breach data
                    </p>
                </div>
                <button onClick={fetchJobs} className="btn btn-outline" style={{ fontSize: 12 }}>🔄 Refresh Status</button>
            </div>

            <div className="glass-card" style={{ padding: 24, marginBottom: 30, background: "rgba(255,42,133,0.05)", border: "1px solid rgba(255,42,133,0.2)" }}>
                <form onSubmit={handleScan} style={{ display: "flex", gap: 12 }}>
                    <div style={{ flex: 1 }}>
                        <input
                            type="text"
                            className="input-field"
                            placeholder="Enter organizational domain (e.g. corp.com)"
                            value={targetDomain}
                            onChange={(e) => setTargetDomain(e.target.value)}
                            style={{ width: "100%", borderColor: "rgba(255,42,133,0.3)" }}
                        />
                    </div>
                    <button type="submit" className="btn btn-primary" disabled={loading} style={{ minWidth: 160, background: "var(--red)" }}>
                        {loading ? "Searching..." : "Search Leaks"}
                    </button>
                </form>
                {error && <div style={{ marginTop: 15, color: "var(--red)", fontSize: 13, fontWeight: 600 }}>{error}</div>}
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "350px 1fr", gap: 30 }}>
                <div className="glass-card" style={{ padding: 20 }}>
                    <h3 style={{ marginTop: 0, marginBottom: 15, fontSize: 13, letterSpacing: 1, color: "var(--text-muted)", fontWeight: 800 }}>RECENT SCANS</h3>
                    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                        {jobs.length === 0 && <div className="text-muted" style={{ fontSize: 13 }}>No monitoring jobs yet</div>}
                        {jobs.map((job) => (
                            <div
                                key={job.scan_id}
                                onClick={() => viewResults(job)}
                                className={`glass-card ${selectedJob?.scan_id === job.scan_id ? 'active' : ''}`}
                                style={{
                                    padding: 12,
                                    cursor: "pointer",
                                    background: selectedJob?.scan_id === job.scan_id ? "rgba(255,42,133,0.1)" : "rgba(255,255,255,0.03)",
                                    border: selectedJob?.scan_id === job.scan_id ? "1px solid var(--red)" : "1px solid var(--border)",
                                    transition: "all 0.2s ease"
                                }}
                            >
                                <div style={{ fontWeight: 700, fontSize: 14 }}>{job.target_domain}</div>
                                <div style={{ display: "flex", justifyContent: "space-between", marginTop: 5, fontSize: 11 }}>
                                    <span style={{ color: "var(--text-muted)" }}>{new Date(job.created_at).toLocaleDateString()}</span>
                                    <span style={{
                                        color: job.status === "completed" ? "var(--green)" : job.status === "running" ? "var(--cyan)" : "var(--red)",
                                        textTransform: "uppercase",
                                        fontWeight: 800
                                    }}>
                                        {job.status}
                                    </span>
                                </div>
                                {job.status === "completed" && (
                                    <div style={{ marginTop: 8, fontSize: 10, fontWeight: 800, color: job.findings?.length > 0 ? "var(--red)" : "var(--green)" }}>
                                        {job.findings ? job.findings.length : 0} EXPOSURES FOUND
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                </div>

                <div className="glass-card" style={{ padding: 24 }}>
                    <h3 style={{ marginTop: 0, marginBottom: 20, fontSize: 15, letterSpacing: 1, fontWeight: 800 }}>
                        {selectedJob ? `FINDINGS FOR ${selectedJob.target_domain.toUpperCase()}` : "EXPOSURE INTELLIGENCE"}
                    </h3>

                    {!selectedJob && (
                        <div style={{ textAlign: "center", padding: 60, color: "var(--text-muted)" }}>
                            <div style={{ fontSize: 40, marginBottom: 15, opacity: 0.5 }}>🕵️‍♂️</div>
                            <div style={{ fontSize: 16, fontWeight: 600 }}>Select a scan to view intel</div>
                        </div>
                    )}

                    {selectedJob && loading && (
                        <div style={{ textAlign: "center", padding: 40, color: "var(--text-muted)" }}>
                            <div className="spinner" style={{ width: 30, height: 30, margin: "0 auto 15px" }}></div>
                            Loading findings...
                        </div>
                    )}

                    {selectedJob && !loading && findings.length === 0 && (
                        <div style={{ textAlign: "center", padding: 40, color: "var(--green)" }}>
                            <div style={{ fontSize: 40, marginBottom: 15 }}>🛡️</div>
                            <div style={{ fontSize: 16, fontWeight: 800 }}>No Leaks Detected</div>
                            <p style={{ color: "var(--text-muted)", fontSize: 13, marginTop: 10 }}>Target domain appears secure across monitored data sources.</p>
                        </div>
                    )}

                    {selectedJob && !loading && findings.length > 0 && (
                        <div style={{ display: "flex", flexDirection: "column", gap: 15 }}>
                            {findings.map((f, i) => (
                                <div key={i} className="glass-card" style={{ padding: 16, borderLeft: `4px solid ${f.severity === 'critical' ? 'var(--red)' : f.severity === 'high' ? 'var(--orange)' : 'var(--yellow)'}` }}>
                                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                                        <div>
                                            <div style={{ fontSize: 15, fontWeight: 800 }}>{f.title}</div>
                                            <div style={{ display: "flex", gap: 8, marginTop: 5, marginBottom: 10 }}>
                                                <span className="badge badge-info" style={{ fontSize: 9 }}>{f.source?.toUpperCase()}</span>
                                                <span className={`badge badge-${f.severity}`} style={{ fontSize: 9 }}>{f.severity?.toUpperCase()}</span>
                                            </div>
                                        </div>
                                        <div style={{ fontSize: 11, color: "var(--text-muted)", fontWeight: 600 }}>
                                            {new Date(f.date_found).toLocaleDateString()}
                                        </div>
                                    </div>
                                    <p style={{ margin: 0, fontSize: 13, color: "var(--text-muted)", lineHeight: 1.5 }}>
                                        {f.description}
                                    </p>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default CredentialLeaks;

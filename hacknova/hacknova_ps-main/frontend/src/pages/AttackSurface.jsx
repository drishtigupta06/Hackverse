import React, { useState, useEffect } from "react";
import * as api from "../api.js";

const AttackSurface = () => {
    const [targetDomain, setTargetDomain] = useState("");
    const [loading, setLoading] = useState(false);
    const [jobs, setJobs] = useState([]);
    const [selectedJob, setSelectedJob] = useState(null);
    const [assets, setAssets] = useState([]);
    const [error, setError] = useState(null);

    useEffect(() => {
        fetchJobs();
    }, []);

    const fetchJobs = async () => {
        try {
            const res = await api.get("/recon/jobs");
            setJobs(res.jobs);
        } catch (err) {
            console.error("Failed to fetch recon jobs", err);
        }
    };

    const handleDiscovery = async (e) => {
        e.preventDefault();
        if (!targetDomain) return;
        setLoading(true);
        setError(null);
        try {
            const res = await api.post("/recon/discovery", { target_domain: targetDomain });
            setTargetDomain("");
            fetchJobs();
        } catch (err) {
            setError(err.response?.data?.detail || "Discovery failed to start");
        } finally {
            setLoading(false);
        }
    };

    const viewResults = async (job) => {
        setSelectedJob(job);
        setLoading(true);
        try {
            const res = await api.get(`/recon/results/${job.recon_id}`);
            setAssets(res.assets);
        } catch (err) {
            setError("Failed to fetch assets");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="fade-in">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 30 }}>
                <div>
                    <h1 style={{ margin: 0, fontSize: "1.8rem", fontWeight: 800, letterSpacing: -0.5 }}>
                        Attack Surface Discovery
                    </h1>
                    <p style={{ margin: "5px 0 0 0", color: "var(--text-muted)", fontSize: 14 }}>
                        Reconnaissance engine using Amass & Subfinder
                    </p>
                </div>
            </div>

            <div className="glass-card" style={{ padding: 24, marginBottom: 30 }}>
                <form onSubmit={handleDiscovery} style={{ display: "flex", gap: 12 }}>
                    <div style={{ flex: 1 }}>
                        <input
                            type="text"
                            className="input-field"
                            placeholder="Enter domain (e.g. example.com)"
                            value={targetDomain}
                            onChange={(e) => setTargetDomain(e.target.value)}
                            style={{ width: "100%" }}
                        />
                    </div>
                    <button type="submit" className="btn btn-primary" disabled={loading} style={{ minWidth: 160 }}>
                        {loading ? "Discovering..." : "Start Discovery"}
                    </button>
                </form>
                {error && <div style={{ marginTop: 15, color: "var(--red)", fontSize: 13, fontWeight: 600 }}>{error}</div>}
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "350px 1fr", gap: 30 }}>
                <div className="glass-card" style={{ padding: 20 }}>
                    <h3 style={{ marginTop: 0, marginBottom: 15, fontSize: 15, letterSpacing: 1 }}>RECENT JOBS</h3>
                    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                        {jobs.length === 0 && <div className="text-muted">No discovery jobs yet</div>}
                        {jobs.map((job) => (
                            <div
                                key={job.recon_id}
                                onClick={() => viewResults(job)}
                                className={`glass-card ${selectedJob?.recon_id === job.recon_id ? 'active' : ''}`}
                                style={{
                                    padding: 12,
                                    cursor: "pointer",
                                    background: selectedJob?.recon_id === job.recon_id ? "rgba(0,163,255,0.15)" : "rgba(255,255,255,0.03)",
                                    border: selectedJob?.recon_id === job.recon_id ? "1px solid var(--cyan)" : "1px solid var(--border)",
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
                                <div style={{ marginTop: 5, fontSize: 10, fontWeight: 700, color: "var(--text-muted)" }}>
                                    {job.asset_count} ASSETS FOUND
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="glass-card" style={{ padding: 24 }}>
                    <h3 style={{ marginTop: 0, marginBottom: 20, fontSize: 15, letterSpacing: 1 }}>
                        {selectedJob ? `RESULTS FOR ${selectedJob.target_domain}` : "DISCOVERED ASSETS"}
                    </h3>
                    {selectedJob ? (
                        <div className="table-container">
                            <table className="data-table">
                                <thead>
                                    <tr>
                                        <th>SUBDOMAIN</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {assets.length === 0 && (
                                        <tr>
                                            <td style={{ textAlign: "center", padding: 40, color: "var(--text-muted)" }}>
                                                {loading ? "Loading assets..." : "No assets discovered for this target"}
                                            </td>
                                        </tr>
                                    )}
                                    {assets.map((asset, i) => (
                                        <tr key={i}>
                                            <td style={{ fontWeight: 600 }}>{asset.domain}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    ) : (
                        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-muted)", padding: 40 }}>
                            <div style={{ fontSize: 40, marginBottom: 20 }}>🔍</div>
                            <div>Select a job on the left to view discovered subdomains</div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

class ErrorBoundary extends React.Component {
    constructor(props) {
        super(props);
        this.state = { hasError: false, error: null };
    }
    static getDerivedStateFromError(error) {
        return { hasError: true, error };
    }
    render() {
        if (this.state.hasError) {
            return (
                <div style={{ padding: 40, color: 'red' }}>
                    <h2>React Crash Detected:</h2>
                    <pre>{this.state.error.toString()}</pre>
                </div>
            );
        }
        return this.props.children;
    }
}

export default function AttackSurfaceWrapper(props) {
    return (
        <ErrorBoundary>
            <AttackSurface {...props} />
        </ErrorBoundary>
    );
}

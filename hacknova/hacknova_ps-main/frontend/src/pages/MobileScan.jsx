import React, { useState, useEffect, useRef } from "react";
import * as api from "../api.js";

const MobileScan = () => {
    const [file, setFile] = useState(null);
    const [uploading, setUploading] = useState(false);
    const [jobs, setJobs] = useState([]);
    const [selectedJob, setSelectedJob] = useState(null);
    const [error, setError] = useState(null);
    const [activeTab, setActiveTab] = useState("findings");
    const fileInputRef = useRef(null);

    useEffect(() => {
        fetchJobs();
    }, []);

    const fetchJobs = async () => {
        try {
            const res = await api.get("/mobile/jobs");
            setJobs(res.jobs || []);
        } catch (err) {
            console.error("Failed to fetch mobile scan jobs", err);
        }
    };

    const handleFileChange = (e) => {
        if (e.target.files && e.target.files[0]) {
            setFile(e.target.files[0]);
        }
    };

    const handleUpload = async (e) => {
        e.preventDefault();
        if (!file) return;
        setUploading(true);
        setError(null);

        const formData = new FormData();
        formData.append("file", file);

        try {
            await api.post("/mobile/scan", formData);
            setFile(null);
            fetchJobs();
        } catch (err) {
            setError(err.response?.data?.detail || "Upload failed. Check if backend is running.");
        } finally {
            setUploading(false);
            if (fileInputRef.current) fileInputRef.current.value = "";
        }
    };

    const viewResults = async (job) => {
        setUploading(true);
        try {
            const res = await api.get(`/mobile/results/${job.scan_id}`);
            setSelectedJob(res.job);
        } catch (err) {
            setError("Failed to fetch job details");
        } finally {
            setUploading(false);
        }
    };

    const renderFindings = () => (
        <table className="data-table">
            <thead>
                <tr>
                    <th>APP COMPONENT</th>
                    <th>IDENTIFIED ISSUE</th>
                    <th>SEVERITY</th>
                </tr>
            </thead>
            <tbody>
                {selectedJob.results.vulnerabilities.length === 0 && (
                    <tr>
                        <td colSpan="3" style={{ textAlign: "center", padding: 30, color: "var(--text-muted)" }}>
                            No specific vulnerabilities identified in this scan.
                        </td>
                    </tr>
                )}
                {selectedJob.results.vulnerabilities.map((v, i) => (
                    <tr key={i}>
                        <td style={{ fontWeight: 600, color: "var(--cyan)", fontSize: 13 }}>{v.component || "Unknown"}</td>
                        <td>
                            <div style={{ fontWeight: 700, fontSize: 14 }}>{v.title}</div>
                            <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 6, lineHeight: 1.4 }}>{v.description}</div>
                        </td>
                        <td>
                            <span className={`badge badge-${v.severity.toLowerCase()}`} style={{ fontWeight: 800, fontSize: 11, padding: "4px 8px" }}>
                                {v.severity.toUpperCase()}
                            </span>
                        </td>
                    </tr>
                ))}
            </tbody>
        </table>
    );

    const renderUrls = () => (
        <div style={{ padding: 10 }}>
            <h4 style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 15 }}>EXTRACTED ENDPOINTS & URLS</h4>
            <div style={{ maxHeight: 400, overflowY: "auto", border: "1px solid var(--border)", borderRadius: 8, background: "rgba(0,0,0,0.2)" }}>
                {selectedJob.results.urls?.length > 0 ? (
                    selectedJob.results.urls.map((url, i) => (
                        <div key={i} style={{ padding: "10px 15px", borderBottom: "1px solid var(--border)", fontSize: 13, wordBreak: "break-all" }}>
                            <span style={{ color: "var(--cyan)", marginRight: 10 }}>#{i + 1}</span> {url}
                        </div>
                    ))
                ) : (
                    <div style={{ padding: 20, textAlign: "center", color: "var(--text-muted)" }}>No URLs extracted</div>
                )}
            </div>
        </div>
    );

    const renderEmails = () => (
        <div style={{ padding: 10 }}>
            <h4 style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 15 }}>EXTRACTED EMAILS</h4>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
                {selectedJob.results.emails?.length > 0 ? (
                    selectedJob.results.emails.map((email, i) => (
                        <div key={i} className="glass-card" style={{ padding: "8px 15px", fontSize: 13, background: "rgba(255,255,255,0.05)" }}>
                            {email}
                        </div>
                    ))
                ) : (
                    <div style={{ width: "100%", padding: 20, textAlign: "center", color: "var(--text-muted)" }}>No emails extracted</div>
                )}
            </div>
        </div>
    );

    return (
        <div className="fade-in">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 30 }}>
                <div>
                    <h1 style={{ margin: 0, fontSize: "1.8rem", fontWeight: 800, letterSpacing: -0.5 }}>
                        Mobile Application Security
                    </h1>
                    <p style={{ margin: "5px 0 0 0", color: "var(--text-muted)", fontSize: 14 }}>
                        Static & Dynamic Analysis via MobSF Engine
                    </p>
                </div>
            </div>

            {/* Upload Section */}
            <div className="glass-card" style={{ padding: 40, marginBottom: 30, textAlign: "center", border: "1px dashed rgba(255,255,255,0.2)", background: "rgba(255,255,255,0.01)" }}>
                <form onSubmit={handleUpload}>
                    <input
                        type="file"
                        ref={fileInputRef}
                        accept=".apk,.ipa,.zip"
                        onChange={handleFileChange}
                        style={{ display: "none" }}
                        id="mobile-upload"
                    />
                    <label htmlFor="mobile-upload" style={{
                        display: "inline-block",
                        padding: "20px 40px",
                        background: "rgba(99, 102, 241, 0.1)",
                        border: "1px solid var(--purple)",
                        borderRadius: 12,
                        cursor: "pointer",
                        color: "var(--purple)",
                        fontWeight: 700,
                        transition: "all 0.3s ease",
                        boxShadow: "0 4px 15px rgba(99,102,241,0.2)"
                    }}>
                        {file ? `📁 ${file.name}` : "Drop APK / IPA File Here or Browse"}
                    </label>

                    <div style={{ marginTop: 25 }}>
                        <button type="submit" className="btn btn-primary" disabled={!file || uploading} style={{ minWidth: 220, padding: "12px 24px" }}>
                            {uploading ? "Uploading & Analyzing..." : "Launch Mobile Scan"}
                        </button>
                    </div>
                </form>
                {error && <div style={{ marginTop: 15, color: "var(--red)", fontSize: 13, fontWeight: 600 }}>{error}</div>}
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "350px 1fr", gap: 30 }}>
                <div className="glass-card" style={{ padding: 20 }}>
                    <h3 style={{ marginTop: 0, marginBottom: 15, fontSize: 12, letterSpacing: 1, color: "var(--text-muted)" }}>RECENT SCANS</h3>
                    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                        {jobs.length === 0 && <div className="text-muted" style={{ fontSize: 13, textAlign: 'center', margin: '20px 0' }}>No mobile scans yet</div>}
                        {jobs.map((job) => (
                            <div
                                key={job.scan_id}
                                onClick={() => viewResults(job)}
                                className={`glass-card ${selectedJob?.scan_id === job.scan_id ? 'active' : ''}`}
                                style={{
                                    padding: 12,
                                    cursor: "pointer",
                                    background: selectedJob?.scan_id === job.scan_id ? "rgba(0,163,255,0.15)" : "rgba(255,255,255,0.03)",
                                    border: selectedJob?.scan_id === job.scan_id ? "1px solid var(--cyan)" : "1px solid var(--border)",
                                    transition: "all 0.2s ease"
                                }}
                            >
                                <div style={{ fontWeight: 700, fontSize: 14, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{job.filename}</div>
                                <div style={{ display: "flex", justifyContent: "space-between", marginTop: 5, fontSize: 11 }}>
                                    <span style={{ color: "var(--text-muted)" }}>{new Date(job.created_at).toLocaleDateString()}</span>
                                    <span style={{
                                        color: job.status === "completed" ? "var(--green)" : job.status === "scanning" ? "var(--cyan)" : "var(--red)",
                                        textTransform: "uppercase",
                                        fontWeight: 800
                                    }}>
                                        {job.status}
                                    </span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="glass-card" style={{ padding: 24, display: "flex", flexDirection: "column", minHeight: 600 }}>
                    {selectedJob && selectedJob.results ? (
                        <>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 25 }}>
                                <div>
                                    <h2 style={{ margin: 0, fontSize: "1.4rem", fontWeight: 800 }}>{selectedJob.results.app_info?.app_name || selectedJob.filename}</h2>
                                    <p style={{ margin: "4px 0 0 0", color: "var(--cyan)", fontSize: 12, fontWeight: 600 }}>{selectedJob.results.app_info?.package_name} • v{selectedJob.results.app_info?.version}</p>
                                </div>
                                <div style={{ textAlign: "right" }}>
                                    <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 1 }}>Security Score</div>
                                    <div style={{ fontSize: 24, fontWeight: 900, color: selectedJob.results.security_score > 70 ? "var(--green)" : "var(--red)" }}>
                                        {selectedJob.results.security_score}/100
                                    </div>
                                </div>
                            </div>

                            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 20, marginBottom: 30 }}>
                                <div className="glass-card" style={{ padding: 15, textAlign: "center", background: "rgba(255,42,133,0.05)", border: "1px solid rgba(255,42,133,0.2)" }}>
                                    <div style={{ fontSize: 28, fontWeight: 800, color: "var(--red)" }}>
                                        {selectedJob.results.vulnerabilities?.filter(v => v.severity === "High").length || 0}
                                    </div>
                                    <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 1, marginTop: 5 }}>High Risks</div>
                                </div>
                                <div className="glass-card" style={{ padding: 15, textAlign: "center", background: "rgba(0,163,255,0.05)", border: "1px solid rgba(0,163,255,0.2)" }}>
                                    <div style={{ fontSize: 28, fontWeight: 800, color: "var(--cyan)" }}>
                                        {selectedJob.results.permissions_analyzed || 0}
                                    </div>
                                    <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 1, marginTop: 5 }}>Permissions</div>
                                </div>
                                <div className="glass-card" style={{ padding: 15, textAlign: "center", background: "rgba(163,0,255,0.05)", border: "1px solid rgba(163,0,255,0.2)" }}>
                                    <div style={{ fontSize: 28, fontWeight: 800, color: "var(--purple)" }}>
                                        {selectedJob.results.trackers_count || 0}
                                    </div>
                                    <div style={{ fontSize: 10, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: 1, marginTop: 5 }}>Trackers</div>
                                </div>
                            </div>

                            <div style={{ display: "flex", borderBottom: "1px solid var(--border)", marginBottom: 20 }}>
                                {["findings", "urls", "emails"].map(tab => (
                                    <button
                                        key={tab}
                                        onClick={() => setActiveTab(tab)}
                                        style={{
                                            padding: "10px 20px",
                                            background: "none",
                                            border: "none",
                                            borderBottom: activeTab === tab ? "2px solid var(--cyan)" : "2px solid transparent",
                                            color: activeTab === tab ? "var(--cyan)" : "var(--text-muted)",
                                            cursor: "pointer",
                                            fontWeight: 700,
                                            fontSize: 12,
                                            textTransform: "uppercase",
                                            letterSpacing: 1,
                                            transition: "all 0.2s ease"
                                        }}
                                    >
                                        {tab}
                                    </button>
                                ))}
                            </div>

                            <div className="table-container" style={{ flex: 1 }}>
                                {activeTab === "findings" && renderFindings()}
                                {activeTab === "urls" && renderUrls()}
                                {activeTab === "emails" && renderEmails()}
                            </div>
                        </>
                    ) : (
                        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", flex: 1, color: "var(--text-muted)", padding: 40 }}>
                            <div style={{ fontSize: 48, marginBottom: 20 }}>📱</div>
                            <div style={{ fontSize: 14, fontWeight: 600 }}>{selectedJob ? "Analysis in progress... Data populating." : "Select a scan to review deep analysis results"}</div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default MobileScan;

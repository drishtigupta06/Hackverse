import React, { useState, useEffect } from "react";
import * as api from "../api.js";

const LLMScanner = () => {
    const [modelName, setModelName] = useState("");
    const [targetType, setTargetType] = useState("huggingface");

    // Dynamic Data
    const [availableModels, setAvailableModels] = useState([]);
    const [availableProbes, setAvailableProbes] = useState([]);

    // Scan Configuration
    const [selectedProbes, setSelectedProbes] = useState([]);

    // UI State
    const [loadingData, setLoadingData] = useState(false);
    const [loadingScan, setLoadingScan] = useState(false);
    const [jobs, setJobs] = useState([]);
    const [selectedJob, setSelectedJob] = useState(null);
    const [results, setResults] = useState([]);
    const [error, setError] = useState(null);

    const targetTypes = [
        { id: "huggingface", label: "Hugging Face (Local/Weight-based)", icon: "💻" },
        { id: "huggingface.InferenceAPI", label: "Hugging Face (API/Router)", icon: "🤗" },
        { id: "openai", label: "OpenAI", icon: "🤖" },
        { id: "nim", label: "NVIDIA NIM", icon: "🟩" },
        { id: "replicate", label: "Replicate", icon: "🌐" }
    ];

    useEffect(() => {
        fetchInitialData();
        fetchJobs();
    }, []);

    const fetchInitialData = async () => {
        setLoadingData(true);
        try {
            const [modelsRes, probesRes] = await Promise.all([
                api.request("GET", "/llm/models"),
                api.request("GET", "/llm/probes")
            ]);
            setAvailableModels(modelsRes.models || []);
            setAvailableProbes(probesRes.probes || []);

            // Set default selected probes to standard ones (mapped to Garak IDs)
            const initialProbes = probesRes.probes
                .filter(p => ["dan", "promptinject", "web_injection", "atkgen"].includes(p.id))
                .map(p => p.id);
            setSelectedProbes(initialProbes);

            // Set default model Name
            if (modelsRes.models && modelsRes.models.length > 0) {
                setModelName(modelsRes.models[0].id);
            }
        } catch (err) {
            console.error("Failed to fetch initial LLM config data", err);
            setError("Could not load latest HuggingFace models or Garak probes. Using defaults.");
        } finally {
            setLoadingData(false);
        }
    };

    const fetchJobs = async () => {
        try {
            const res = await api.request("GET", "/llm/jobs");
            setJobs(res.jobs);

            // Auto update selected job if it's running
            if (selectedJob && selectedJob.status === "running") {
                viewResults(selectedJob);
            }
        } catch (err) {
            console.error("Failed to fetch LLM scan jobs", err);
        }
    };

    // Poll running jobs
    useEffect(() => {
        let interval;
        if (selectedJob && selectedJob.status === "running") {
            interval = setInterval(() => {
                viewResults(selectedJob);
                fetchJobs(); // Update the sidebar too
            }, 3000);
        }
        return () => clearInterval(interval);
    }, [selectedJob]);

    const handleScan = async (e) => {
        e.preventDefault();
        if (!modelName || selectedProbes.length === 0) {
            setError("Please specify a target model and select at least one probe.");
            return;
        }
        setLoadingScan(true);
        setError(null);
        try {
            await api.request("POST", "/llm/scan", {
                model_name: modelName,
                target_type: targetType,
                probes: selectedProbes
            });
            setTimeout(fetchJobs, 1000);

            // Reset to top to see job list
            window.scrollTo({ top: 0, behavior: 'smooth' });
        } catch (err) {
            setError(err.response?.data?.detail || "LLM scan initialization failed");
        } finally {
            setLoadingScan(false);
        }
    };

    const viewResults = async (job) => {
        try {
            const res = await api.request("GET", `/llm/results/${job.scan_id}`);
            const updatedJob = res.job;
            setSelectedJob(updatedJob);
            setResults(updatedJob.results || []);

            // Update job list status locally
            setJobs(prev => prev.map(j => j.scan_id === updatedJob.scan_id ? updatedJob : j));
        } catch (err) {
            console.error("Failed to fetch job details", err);
        }
    };

    const toggleProbe = (probeId) => {
        if (selectedProbes.includes(probeId)) {
            setSelectedProbes(selectedProbes.filter(p => p !== probeId));
        } else {
            setSelectedProbes([...selectedProbes, probeId]);
        }
    };

    return (
        <div className="fade-in" style={{ paddingBottom: 60 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: 30 }}>
                <div>
                    <div style={{ display: "flex", alignItems: "center", gap: 15, marginBottom: 5 }}>
                        <div style={{ padding: "8px 12px", background: "rgba(111, 66, 193, 0.2)", borderRadius: 8, color: "var(--purple)", fontWeight: 800 }}>NVIDIA garak</div>
                        <h1 style={{ margin: 0, fontSize: "1.8rem", fontWeight: 800, letterSpacing: -0.5 }}>
                            AI Red-Teaming Scanner
                        </h1>
                    </div>
                    <p style={{ margin: "5px 0 0 0", color: "var(--text-muted)", fontSize: 14 }}>
                        Evaluate LLM interfaces against Prompt Injections, Jailbreaks, and Toxicity limits.
                    </p>
                </div>
                <button onClick={fetchJobs} className="btn btn-outline" style={{ fontSize: 12 }}>🔄 Refresh Dashboard</button>
            </div>

            {/* Scan Configuration Container */}
            <div className="glass-card" style={{ padding: 24, marginBottom: 30, background: "rgba(111, 66, 193, 0.05)", border: "1px solid rgba(111, 66, 193, 0.2)" }}>
                <form onSubmit={handleScan}>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 30 }}>

                        {/* Left Col: Target Config */}
                        <div>
                            <h3 style={{ fontSize: 14, color: "var(--text-secondary)", marginBottom: 15, fontWeight: 800 }}>TARGET CONFIGURATION</h3>

                            <label style={{ display: "block", marginBottom: 8, fontSize: 12, fontWeight: 700 }}>Provider / Interface Type</label>
                            <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 20 }}>
                                {targetTypes.map(t => (
                                    <div
                                        key={t.id}
                                        onClick={() => setTargetType(t.id)}
                                        style={{
                                            padding: "8px 12px",
                                            border: targetType === t.id ? "1px solid var(--purple)" : "1px solid rgba(255,255,255,0.1)",
                                            background: targetType === t.id ? "rgba(111,66,193,0.15)" : "rgba(0,0,0,0.2)",
                                            borderRadius: 6,
                                            cursor: "pointer",
                                            fontSize: 12,
                                            fontWeight: 700,
                                            transition: "all 0.2s"
                                        }}
                                    >
                                        <span style={{ marginRight: 6 }}>{t.icon}</span> {t.label}
                                    </div>
                                ))}
                            </div>

                            <label style={{ display: "block", marginBottom: 8, fontSize: 12, fontWeight: 700 }}>Target Model Name</label>

                            {targetType.includes("huggingface") ? (
                                <select
                                    className="input-field"
                                    value={modelName}
                                    onChange={(e) => setModelName(e.target.value)}
                                    style={{ width: "100%", borderColor: "rgba(111, 66, 193, 0.3)", marginBottom: 10, background: "rgba(0,0,0,0.3)", color: "#fff" }}
                                >
                                    <option value="" disabled>Select a Trending Model...</option>
                                    {availableModels.map(m => (
                                        <option key={m.id} value={m.id}>{m.id}</option>
                                    ))}
                                    <option value="CUSTOM">-- Enter Custom Model ID --</option>
                                </select>
                            ) : (
                                <input
                                    type="text"
                                    className="input-field"
                                    placeholder={targetType.includes("openai") ? "e.g. gpt-4-turbo" : "e.g. meta-llama/Llama-2-7b-chat-hf"}
                                    value={modelName}
                                    onChange={(e) => setModelName(e.target.value)}
                                    style={{ width: "100%", borderColor: "rgba(111, 66, 193, 0.3)", marginBottom: 10 }}
                                />
                            )}

                            {modelName === "CUSTOM" && targetType.includes("huggingface") && (
                                <input
                                    type="text"
                                    className="input-field"
                                    placeholder="Enter custom HuggingFace model ID (e.g. owner/repo)"
                                    value={modelName === "CUSTOM" ? "" : modelName}
                                    onChange={(e) => setModelName(e.target.value)}
                                    style={{ width: "100%", borderColor: "rgba(111, 66, 193, 0.3)", marginBottom: 10 }}
                                />
                            )}

                            {targetType.includes("huggingface") && (
                                <div style={{ fontSize: 11, color: "var(--text-muted)", background: "rgba(0,0,0,0.2)", padding: "8px 12px", borderRadius: 6, border: "1px dashed rgba(255,255,255,0.1)" }}>
                                    Selected Model Details: <span style={{ color: "var(--cyan)", fontWeight: 700 }}>{modelName || "None"}</span>
                                </div>
                            )}
                        </div>

                        {/* Right Col: Attack Probes */}
                        <div>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 15 }}>
                                <h3 style={{ fontSize: 14, color: "var(--text-secondary)", margin: 0, fontWeight: 800 }}>ATTACK PROBES ({selectedProbes.length})</h3>
                                <div style={{ fontSize: 11 }}>
                                    <span style={{ color: "var(--cyan)", cursor: "pointer", marginRight: 10 }} onClick={() => setSelectedProbes(availableProbes.map(p => p.id))}>Select All</span>
                                    <span style={{ color: "var(--text-muted)", cursor: "pointer" }} onClick={() => setSelectedProbes([])}>Clear</span>
                                </div>
                            </div>

                            <div style={{
                                display: "grid",
                                gridTemplateColumns: "1fr 1fr",
                                gap: 8,
                                maxHeight: "250px",
                                overflowY: "auto",
                                paddingRight: 10
                            }}>
                                {loadingData ? (
                                    <div style={{ color: "var(--text-muted)", fontSize: 12, gridColumn: "1 / -1", textAlign: "center", padding: 20 }}>
                                        Loading available garak probes from NVIDIA registry...
                                    </div>
                                ) : availableProbes.length > 0 ? (
                                    availableProbes.map(probe => (
                                        <div
                                            key={probe.id}
                                            onClick={() => toggleProbe(probe.id)}
                                            className="hover-glow"
                                            title={probe.desc}
                                            style={{
                                                padding: "10px 12px",
                                                border: selectedProbes.includes(probe.id) ? "1px solid var(--purple)" : "1px solid rgba(255,255,255,0.05)",
                                                background: selectedProbes.includes(probe.id) ? "rgba(111, 66, 193, 0.25)" : "rgba(255,255,255,0.02)",
                                                borderRadius: 8,
                                                cursor: "pointer",
                                                transition: "all 0.2s",
                                                display: "flex",
                                                flexDirection: "column",
                                                gap: 4
                                            }}
                                        >
                                            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                                                <div style={{
                                                    minWidth: 16, height: 16, borderRadius: 4,
                                                    border: "1px solid var(--purple)",
                                                    background: selectedProbes.includes(probe.id) ? "var(--purple)" : "transparent",
                                                    display: "flex", alignItems: "center", justifyContent: "center"
                                                }}>
                                                    {selectedProbes.includes(probe.id) && <span style={{ color: "#fff", fontSize: 10, fontWeight: 900 }}>✓</span>}
                                                </div>
                                                <div style={{ fontSize: 12, fontWeight: 800, color: selectedProbes.includes(probe.id) ? "#fff" : "var(--text-secondary)" }}>
                                                    {probe.name}
                                                </div>
                                            </div>
                                            <div style={{ fontSize: 10, color: "var(--text-muted)", lineHeight: 1.2 }}>
                                                {probe.desc || `garak.probes.${probe.id}`}
                                            </div>
                                        </div>
                                    ))
                                ) : (
                                    <div style={{ color: "var(--text-muted)", fontSize: 12, gridColumn: "1 / -1", textAlign: "center" }}>
                                        No probes available.
                                    </div>
                                )}
                            </div>
                        </div>

                    </div>

                    <div style={{ marginTop: 25, display: "flex", alignItems: "center", justifyContent: "space-between", borderTop: "1px solid rgba(111, 66, 193, 0.2)", paddingTop: 20 }}>
                        <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
                            <strong>Note:</strong> API keys for cloud providers must be set in the `.env` file of the CyberGuard backend.
                        </div>
                        <button type="submit" className="btn btn-primary" disabled={loadingScan || !modelName || selectedProbes.length === 0} style={{ minWidth: 200, background: "var(--purple)", height: 46 }}>
                            {loadingScan ? (
                                <span style={{ display: "flex", alignItems: "center", gap: 8, justifyContent: "center" }}>
                                    <div className="spinner" style={{ width: 14, height: 14 }}></div> Deploying...
                                </span>
                            ) : "Deploy AI Red-Team"}
                        </button>
                    </div>
                </form>
                {error && <div style={{ marginTop: 15, padding: 12, background: "rgba(255,51,102,0.1)", border: "1px solid var(--red)", borderRadius: 6, color: "var(--red)", fontSize: 13, fontWeight: 600 }}>⚠️ {error}</div>}
            </div>

            {/* Content Results Split */}
            <div style={{ display: "grid", gridTemplateColumns: "350px 1fr", gap: 30 }}>
                {/* Sidebar: Job List */}
                <div className="glass-card" style={{ padding: 20 }}>
                    <h3 style={{ marginTop: 0, marginBottom: 15, fontSize: 13, letterSpacing: 1, color: "var(--text-muted)", fontWeight: 800 }}>EVALUATION JOBS</h3>
                    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                        {jobs.length === 0 && <div className="text-muted" style={{ fontSize: 13 }}>No models scanned yet</div>}
                        {jobs.map((job) => (
                            <div
                                key={job.scan_id}
                                onClick={() => viewResults(job)}
                                className={`glass-card ${selectedJob?.scan_id === job.scan_id ? 'active' : ''}`}
                                style={{
                                    padding: 12,
                                    cursor: "pointer",
                                    background: selectedJob?.scan_id === job.scan_id ? "rgba(111, 66, 193, 0.1)" : "rgba(255,255,255,0.03)",
                                    border: selectedJob?.scan_id === job.scan_id ? "1px solid var(--purple)" : "1px solid var(--border)",
                                    transition: "all 0.2s ease"
                                }}
                            >
                                <div style={{ fontWeight: 700, fontSize: 14, wordBreak: "break-all" }}>{job.model_name}</div>
                                <div style={{ display: "flex", justifyContent: "space-between", marginTop: 8, fontSize: 11 }}>
                                    <span style={{ color: "var(--cyan)", background: "rgba(0,163,255,0.1)", padding: "2px 6px", borderRadius: 4 }}>
                                        {job.target_type.split(".")[0].toUpperCase()}
                                    </span>
                                    <span style={{
                                        color: job.status === "completed" ? "var(--green)" : job.status === "running" ? "var(--cyan)" : "var(--red)",
                                        textTransform: "uppercase",
                                        fontWeight: 800,
                                        display: "flex",
                                        alignItems: "center",
                                        gap: 5
                                    }}>
                                        {job.status === "running" && <div className="spinner" style={{ width: 8, height: 8, borderWidth: 2, borderLeftColor: "var(--cyan)" }}></div>}
                                        {job.status}
                                    </span>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Main Pane: Findings View */}
                <div className="glass-card" style={{ padding: 24, position: "relative", minHeight: 400 }}>
                    {selectedJob && (
                        <div style={{ position: "absolute", top: 24, right: 24, fontSize: 11, color: "var(--text-muted)", textAlign: "right", background: "rgba(0,0,0,0.5)", padding: 10, borderRadius: 8 }}>
                            <div style={{ fontWeight: 800, color: "#fff" }}>SCAN #{selectedJob.scan_id.split("-")[0].toUpperCase()}</div>
                            <div style={{ marginTop: 4 }}>Probes: {selectedJob.probes.length}</div>
                        </div>
                    )}

                    <h3 style={{ marginTop: 0, marginBottom: 20, fontSize: 16, letterSpacing: 1, fontWeight: 800, display: "flex", alignItems: "center", gap: 10 }}>
                        {selectedJob ? (
                            <>
                                <span style={{ background: "var(--purple)", width: 12, height: 12, borderRadius: "50%", display: "inline-block" }}></span>
                                garak REPORT: <span style={{ color: "var(--cyan)" }}>{selectedJob.model_name}</span>
                            </>
                        ) : "SCAN RESULTS"}
                    </h3>

                    {!selectedJob && (
                        <div style={{ textAlign: "center", marginTop: 80, color: "var(--text-muted)" }}>
                            <div style={{ fontSize: 60, marginBottom: 15, opacity: 0.5, filter: "grayscale(100%)" }}>🎯</div>
                            <div style={{ fontSize: 18, fontWeight: 700 }}>No Target Selected</div>
                            <p style={{ marginTop: 10, fontSize: 14 }}>Deploy a red-team agent above or select a historical scan to view telemetry.</p>
                        </div>
                    )}

                    {selectedJob && selectedJob.status === "running" && results.length === 0 && (
                        <div style={{ textAlign: "center", marginTop: 80, color: "var(--text-muted)" }}>
                            <div className="spinner" style={{ width: 50, height: 50, margin: "0 auto 20px", borderLeftColor: "var(--purple)", borderWidth: 4 }}></div>
                            <div style={{ fontSize: 18, fontWeight: 800, letterSpacing: 1, color: "var(--purple)" }}>INJECTING ADVERSARIAL PROBES...</div>
                            <p style={{ marginTop: 15, fontSize: 14, maxWidth: 400, margin: "15px auto 0", lineHeight: 1.6 }}>
                                The target model inference endpoint is actively being stress-tested locally by the python <span className="mono">garak</span> orchestration engine.
                            </p>
                            <div style={{ display: "flex", justifyContent: "center", gap: 10, marginTop: 25 }}>
                                {selectedJob.probes.slice(0, 5).map(p => (
                                    <span key={p} className="badge" style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", fontSize: 10 }}>{p}</span>
                                ))}
                                {selectedJob.probes.length > 5 && <span className="badge" style={{ background: "rgba(255,255,255,0.05)" }}>+{selectedJob.probes.length - 5} more</span>}
                            </div>
                        </div>
                    )}

                    {selectedJob && (selectedJob.status === "completed" || results.length > 0) && (
                        <>
                            {results.length === 0 ? (
                                <div style={{ textAlign: "center", marginTop: 80, color: "var(--text-muted)" }}>
                                    <div style={{ fontSize: 50, marginBottom: 15 }}>✓</div>
                                    <div style={{ fontSize: 18, fontWeight: 800, color: "var(--green)" }}>No Vulnerabilities Detected</div>
                                    <p style={{ marginTop: 10, fontSize: 14 }}>All executed probe categories gracefully handled by the endpoint.</p>
                                </div>
                            ) : (
                                <div className="table-container fade-in" style={{ marginTop: 20 }}>
                                    <table className="data-table">
                                        <thead>
                                            <tr>
                                                <th>PROBE SUITE</th>
                                                <th>EVALUATION DETECTOR</th>
                                                <th style={{ textAlign: "center", width: 120 }}>STATUS</th>
                                                <th style={{ textAlign: "left", width: 200 }}>VULNERABILITY METRIC</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {results.map((r, i) => {
                                                const failPct = Math.round((r.failed_attempts / Math.max(r.total_attempts, 1)) * 100) || 0;
                                                return (
                                                    <tr key={i} style={{ borderLeft: `3px solid ${r.status !== 'PASS' ? 'var(--red)' : 'transparent'}` }}>
                                                        <td style={{ fontWeight: 800 }}>{r.probe}</td>
                                                        <td className="mono" style={{ fontSize: 12, color: "var(--cyan)" }}>{r.detector}</td>
                                                        <td style={{ textAlign: "center" }}>
                                                            <span className={`badge badge-${r.severity}`}>
                                                                {r.status}
                                                            </span>
                                                        </td>
                                                        <td>
                                                            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                                                                <span style={{ fontSize: 12, fontWeight: 800, width: 35, textAlign: "right", color: r.status === "PASS" ? "var(--green)" : "var(--red)" }}>{failPct}%</span>
                                                                <div style={{ flex: 1, height: 8, background: "rgba(255,255,255,0.05)", borderRadius: 4, overflow: "hidden" }}>
                                                                    <div style={{ width: `${failPct}%`, height: "100%", background: r.status === "PASS" ? "var(--green)" : "var(--red)" }}></div>
                                                                </div>
                                                                <span style={{ fontSize: 10, color: "var(--text-muted)", width: 45 }}>{r.failed_attempts}/{r.total_attempts}</span>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                )
                                            })}
                                        </tbody>
                                        {selectedJob.status === "running" && (
                                            <tfoot>
                                                <tr>
                                                    <td colSpan="4" style={{ textAlign: "center", padding: 10, color: "var(--cyan)", fontSize: 12 }}>
                                                        <span className="spinner" style={{ width: 10, height: 10, marginRight: 8 }}></span>
                                                        Scan in progress... Data streams active.
                                                    </td>
                                                </tr>
                                            </tfoot>
                                        )}
                                    </table>
                                </div>
                            )}

                            {/* Terminal Log View */}
                            <div style={{ marginTop: 25, background: "#000", borderRadius: 8, border: "1px solid rgba(255,255,255,0.1)", overflow: "hidden" }}>
                                <div style={{ background: "rgba(255,255,255,0.1)", padding: "8px 15px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                                    <span style={{ fontSize: 11, fontWeight: 800, color: "var(--cyan)", textTransform: "uppercase", letterSpacing: 1 }}>
                                        Garak Scanner Terminal Logs
                                    </span>
                                    <div style={{ display: "flex", gap: 5 }}>
                                        <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#ff5f56" }}></div>
                                        <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#ffbd2e" }}></div>
                                        <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#27c93f" }}></div>
                                    </div>
                                </div>
                                <div style={{
                                    padding: 15,
                                    maxHeight: 300,
                                    overflowY: "auto",
                                    fontFamily: "'Fira Code', monospace",
                                    fontSize: 12,
                                    color: "#0f0",
                                    background: "#050505"
                                }}>
                                    {selectedJob.logs && selectedJob.logs.length > 0 ? (
                                        selectedJob.logs.map((log, li) => (
                                            <div key={li} style={{ marginBottom: 2 }}>
                                                <span style={{ color: "rgba(0,255,0,0.3)", marginRight: 8 }}>[{li}]</span>
                                                {log}
                                            </div>
                                        ))
                                    ) : (
                                        <div style={{ color: "var(--text-muted)", fontStyle: "italic" }}>
                                            {selectedJob.status === "running" ? "Waiting for garak output streams..." : "No logs available for this job."}
                                        </div>
                                    )}
                                </div>
                            </div>
                        </>
                    )}
                </div>
            </div>
        </div>
    );
};

export default LLMScanner;

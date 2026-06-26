import React, { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import * as api from "../api.js";

const AttackSimulationPage = ({ user }) => {
    const { scanId } = useParams();
    const [scan, setScan] = useState(null);
    const [simulation, setSimulation] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        fetchData();
    }, [scanId]);

    const fetchData = async () => {
        setLoading(true);
        setError(null);
        try {
            // Fetch basic scan details
            const scanRes = await api.get(`/scans/${scanId}`);
            setScan(scanRes.data);

            // Generate Simulation
            const simRes = await api.get(`/scans/${scanId}/simulation`);
            setSimulation(simRes.data.simulation);
        } catch (err) {
            console.error("Simulation failed", err);
            setError(err.response?.data?.detail || "Failed to generate attack simulation.");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="fade-in" style={{ paddingBottom: 60 }}>
            {/* Header */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: 30 }}>
                <div>
                    <Link to={`/results/${scanId}`} className="text-muted" style={{ display: "inline-block", marginBottom: 10, fontSize: 13, textDecoration: "none", fontWeight: 600 }}>
                        ← Back to Scan Results
                    </Link>
                    <h1 style={{ margin: 0, fontSize: "2rem", fontWeight: 800, letterSpacing: -0.5 }}>
                        AI Attack Simulation Engine
                    </h1>
                    <p style={{ margin: "5px 0 0 0", color: "var(--text-muted)", fontSize: 14 }}>
                        LLM Probabilistic Threat Model for <strong style={{ color: "#fff" }}>{scan?.target || scanId}</strong>
                    </p>
                </div>
                {simulation && (
                    <button onClick={fetchData} className="btn btn-outline" style={{ fontSize: 12 }}>
                        🔄 Regenerate Simulation
                    </button>
                )}
            </div>

            {loading && (
                <div style={{ padding: 80, textAlign: "center", color: "var(--text-muted)" }}>
                    <div style={{ fontSize: 60, marginBottom: 20, animation: "pulse 2s infinite" }}>🧠</div>
                    <div style={{ fontSize: 20, fontWeight: 800, color: "var(--cyan)", letterSpacing: -0.5 }}>Analyzing Vulnerabilities...</div>
                    <p style={{ marginTop: 10, maxWidth: 400, margin: "10px auto 0", lineHeight: 1.6 }}>The AI engine is constructing a step-by-step probabilistic attack chain based on identified weaknesses.</p>
                </div>
            )}

            {error && (
                <div className="glass-card fade-in" style={{ padding: 40, textAlign: "center", border: "1px solid rgba(255,42,133,0.3)", background: "rgba(255,42,133,0.02)" }}>
                    <div style={{ fontSize: 40 }}>⚠️</div>
                    <h3 style={{ color: "var(--red)", marginTop: 15 }}>Simulation Engine Error</h3>
                    <p style={{ color: "var(--text-muted)", maxWidth: 500, margin: "10px auto" }}>{error}</p>
                    <button onClick={fetchData} className="btn btn-outline" style={{ marginTop: 25 }}>Try Again</button>
                </div>
            )}

            {simulation && !loading && (
                <div className="fade-in" style={{ maxWidth: 800, margin: "0 auto", position: "relative", paddingTop: 20 }}>

                    {/* Vertical Line */}
                    <div style={{
                        position: "absolute",
                        left: 24,
                        top: 20,
                        bottom: 0,
                        width: 2,
                        background: "linear-gradient(to bottom, var(--cyan), var(--purple), var(--red))",
                        zIndex: 0
                    }}></div>

                    {simulation.map((step, idx) => (
                        <div key={idx} style={{ display: "flex", gap: 30, marginBottom: 40, position: "relative", zIndex: 1 }}>
                            {/* Number Circle */}
                            <div style={{
                                width: 50,
                                height: 50,
                                borderRadius: 25,
                                background: "var(--bg-dark)",
                                border: `2px solid ${idx === simulation.length - 1 ? "var(--red)" : (idx === 0 ? "var(--cyan)" : "var(--purple)")}`,
                                display: "flex",
                                alignItems: "center",
                                justifyContent: "center",
                                fontSize: 18,
                                fontWeight: 800,
                                color: "#fff",
                                boxShadow: `0 0 20px ${idx === simulation.length - 1 ? 'rgba(255,42,133,0.3)' : 'rgba(0,163,255,0.2)'}`,
                                flexShrink: 0
                            }}>
                                {step.step || (idx + 1)}
                            </div>

                            {/* Content Card */}
                            <div className="glass-card transition-all" style={{ flex: 1, padding: 24, transition: "transform 0.2sease, box-shadow 0.2s ease" }}
                                onMouseEnter={e => { e.currentTarget.style.transform = 'translateX(5px)'; e.currentTarget.style.boxShadow = '0 5px 25px rgba(0,0,0,0.5)' }}
                                onMouseLeave={e => { e.currentTarget.style.transform = 'none'; e.currentTarget.style.boxShadow = '0 4px 20px rgba(0,0,0,0.2)' }}
                            >
                                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 15 }}>
                                    <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: idx === simulation.length - 1 ? "var(--red)" : "#fff" }}>
                                        {step.title}
                                    </h3>
                                    {step.technique && (
                                        <span style={{
                                            fontSize: 10,
                                            background: "rgba(255,255,255,0.05)",
                                            padding: "4px 8px",
                                            borderRadius: 4,
                                            color: "var(--cyan)",
                                            fontWeight: 700,
                                            border: "1px solid rgba(0,163,255,0.2)"
                                        }}>
                                            {step.technique}
                                        </span>
                                    )}
                                </div>
                                <p style={{ margin: 0, fontSize: 14, color: "var(--text-muted)", lineHeight: 1.6 }}>
                                    {step.description}
                                </p>
                            </div>
                        </div>
                    ))}

                    {/* Final goal indicator */}
                    <div style={{ display: "flex", gap: 30, position: "relative", zIndex: 1 }}>
                        <div style={{
                            width: 50, height: 50, borderRadius: 25, background: "rgba(255,42,133,0.1)", border: "2px dashed var(--red)",
                            display: "flex", alignItems: "center", justifyContent: "center", fontSize: 24, flexShrink: 0,
                            boxShadow: "0 0 30px rgba(255,42,133,0.2)"
                        }}>💀</div>
                        <div style={{ flex: 1, display: "flex", alignItems: "center" }}>
                            <h3 style={{ margin: 0, color: "var(--red)", fontSize: 16, fontWeight: 800, letterSpacing: 1 }}>SIMULATION COMPLETE: SYSTEM COMPROMISED</h3>
                        </div>
                    </div>

                </div>
            )}
        </div>
    );
};

export default AttackSimulationPage;

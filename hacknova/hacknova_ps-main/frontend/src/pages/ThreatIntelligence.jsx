import React, { useState, useEffect } from "react";
import * as api from "../api.js";

const ThreatIntelligence = () => {
    const [feed, setFeed] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        fetchFeed();
    }, []);

    const fetchFeed = async () => {
        setLoading(true);
        setError(null);
        try {
            const res = await api.get("/intel/feed");
            setFeed(res.feed || []);
        } catch (err) {
            console.error("Failed to fetch threat intel", err);
            setError("Could not load the global threat intelligence feed. Ensure the backend API is reachable.");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="fade-in">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 30 }}>
                <div>
                    <h1 style={{ margin: 0, fontSize: "1.8rem", fontWeight: 800, letterSpacing: -0.5 }}>
                        Global Threat Intelligence
                    </h1>
                    <p style={{ margin: "5px 0 0 0", color: "var(--text-muted)", fontSize: 14 }}>
                        Live CVSS stream from NVD, Rapid7, and MITRE vulnerability databases
                    </p>
                </div>
                <button onClick={fetchFeed} className="btn btn-outline" style={{ fontSize: 12 }}>🔄 Synchronize Feed</button>
            </div>

            {loading ? (
                <div style={{ textAlign: "center", padding: 80, color: "var(--text-muted)" }}>
                    <div className="spinner" style={{ width: 40, height: 40, margin: "0 auto 20px" }}></div>
                    <div style={{ fontSize: 18, fontWeight: 700, letterSpacing: 1 }}>Aggregating Global Threats...</div>
                </div>
            ) : error ? (
                <div className="glass-card" style={{ padding: 40, color: "var(--red)", textAlign: "center", border: "1px solid var(--red)", background: "rgba(255,42,133,0.05)" }}>
                    <div style={{ fontSize: 30, marginBottom: 15 }}>⚠️</div>
                    <div style={{ fontWeight: 800 }}>{error}</div>
                </div>
            ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 15 }}>
                    {feed.map((item, idx) => (
                        <div key={idx} className="glass-card transition-all" style={{ padding: 24, borderLeft: `4px solid ${item.severity === 'critical' ? 'var(--red)' : item.severity === 'high' ? 'var(--orange)' : 'var(--yellow)'}` }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
                                <div>
                                    <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                                        <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800 }}>{item.title}</h3>
                                        {item.cve_id && (
                                            <span className="mono hover-glow" style={{ fontSize: 12, color: "var(--cyan)", background: "rgba(0,163,255,0.1)", padding: "4px 8px", borderRadius: 4, border: "1px solid rgba(0,163,255,0.2)" }}>
                                                {item.cve_id}
                                            </span>
                                        )}
                                    </div>
                                    <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
                                        <span className="badge badge-info" style={{ fontWeight: 800 }}>{item.source?.toUpperCase()}</span>
                                        <span className={`badge badge-${item.severity}`} style={{ fontWeight: 800 }}>{item.severity?.toUpperCase()}</span>
                                        <span style={{ fontSize: 11, fontWeight: 800, padding: "4px 10px", background: "rgba(255,255,255,0.05)", borderRadius: 10 }}>
                                            CVSS: <span style={{ color: item.cvss_score >= 9.0 ? 'var(--red)' : 'var(--orange)' }}>{item.cvss_score.toFixed(1)}</span>
                                        </span>
                                    </div>
                                </div>
                                <div style={{ textAlign: "right", fontSize: 12, color: "var(--text-muted)", fontWeight: 700 }}>
                                    Published: <span style={{ color: "var(--text-secondary)" }}>{new Date(item.published_date).toLocaleDateString()}</span>
                                </div>
                            </div>

                            <p style={{ margin: "15px 0 20px 0", fontSize: 14, color: "var(--text-muted)", lineHeight: 1.6 }}>
                                {item.description}
                            </p>

                            {(item.mitre_tactic || item.mitre_technique) && (
                                <div style={{ display: "inline-flex", gap: 12, alignItems: "center", background: "rgba(0,0,0,0.3)", padding: "10px 16px", borderRadius: 8, border: "1px solid rgba(255,255,255,0.05)" }}>
                                    <span style={{ fontSize: 18 }}>🎯</span>
                                    <div>
                                        <div style={{ fontSize: 10, color: "var(--text-muted)", fontWeight: 800, textTransform: "uppercase", letterSpacing: 0.5 }}>MITRE ATT&CK Mapping</div>
                                        <div style={{ fontSize: 13, color: "var(--cyan)", fontWeight: 700, marginTop: 2 }}>
                                            {item.mitre_tactic} <span style={{ color: "var(--text-muted)", margin: "0 5px" }}>→</span> <span style={{ color: "#fff" }}>{item.mitre_technique}</span>
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

export default ThreatIntelligence;

import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import * as api from "../api.js";

export default function SimulationPage() {
    const { scanId } = useParams();
    const navigate = useNavigate();
    const [scenario, setScenario] = useState([]);
    const [loading, setLoading] = useState(true);
    const [step, setStep] = useState(0);

    useEffect(() => {
        api.getAttackScenario(scanId).then(res => {
            setScenario(res.scenario || []);
        }).finally(() => setLoading(false));
    }, [scanId]);

    const playNext = () => {
        if (step < scenario.length) {
            setStep(s => s + 1);
        }
    };

    return (
        <div className="fade-in" style={{ maxWidth: 800, margin: "40px auto" }}>
            <div className="card" style={{ padding: 40, background: "rgba(10,10,20,0.8)", border: "2px solid var(--accent)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 30 }}>
                    <div style={{ fontSize: 20, fontWeight: 800, color: "var(--accent-light)" }}>🎬 Attack Narrative Simulator</div>
                    <button className="btn btn-secondary btn-sm" onClick={() => navigate(-1)}>Back to Results</button>
                </div>

                {loading ? (
                    <div className="loading-center">Generating cinematic scenario...</div>
                ) : (
                    <div style={{ minHeight: 300 }}>
                        {scenario.slice(0, step).map((line, i) => (
                            <div key={i} className="fade-in" style={{
                                padding: 15,
                                marginBottom: 15,
                                background: i === step - 1 ? "rgba(99,102,241,0.15)" : "transparent",
                                borderLeft: i === step - 1 ? "4px solid var(--accent)" : "4px solid var(--border)",
                                transition: "all 0.5s ease"
                            }}>
                                <div style={{ fontSize: 13, color: "var(--text-muted)", marginBottom: 4 }}>PHASE {i + 1}</div>
                                <div style={{ fontSize: 16, fontWeight: 600, color: i === step - 1 ? "var(--text-primary)" : "var(--text-secondary)" }}>{line}</div>
                            </div>
                        ))}

                        {step < scenario.length ? (
                            <button className="btn btn-primary" style={{ marginTop: 20, width: "100%", padding: 15 }} onClick={playNext}>
                                {step === 0 ? "START ATTACK SIMULATION" : "CONTINUE TO NEXT PHASE →"}
                            </button>
                        ) : (
                            <div className="fade-in" style={{ marginTop: 30, textAlign: "center", padding: 20, background: "rgba(16,185,129,0.1)", borderRadius: 8 }}>
                                <div style={{ fontSize: 24, marginBottom: 10 }}>💀 CRITICAL COMPROMISE</div>
                                <div style={{ color: "var(--text-secondary)" }}>The attacker has achieved all objectives. See full report for remediation steps.</div>
                                <button className="btn btn-primary" style={{ marginTop: 20 }} onClick={() => navigate("/reports")}>Go to Executive Report</button>
                            </div>
                        )}
                    </div>
                )}
            </div>

            <div style={{ textAlign: "center", marginTop: 20, color: "var(--text-muted)", fontSize: 13 }}>
                💡 Judges Note: This narrative is generated based on real vulnerabilities found in <b>scan {scanId.slice(0, 8)}</b>.
            </div>
        </div>
    );
}

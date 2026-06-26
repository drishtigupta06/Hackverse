import { useState } from "react";
import * as api from "../api.js";

export default function AuthPage({ onLogin }) {
    const [tab, setTab] = useState("login");
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [email, setEmail] = useState("");
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");
    const [success, setSuccess] = useState("");

    async function handleSubmit(e) {
        e.preventDefault();
        setError(""); setSuccess("");
        setLoading(true);
        try {
            if (tab === "login") {
                await api.login(username, password);
                onLogin();
            } else {
                await api.register(username, password, email);
                setSuccess("Account created! Please login.");
                setTab("login");
            }
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    }

    return (
        <div className="auth-page">
            {/* Background orbs */}
            <div style={{
                position: "fixed", top: "-20%", left: "-10%",
                width: "500px", height: "500px",
                background: "radial-gradient(circle, rgba(99,102,241,0.08) 0%, transparent 70%)",
                borderRadius: "50%", pointerEvents: "none"
            }} />
            <div style={{
                position: "fixed", bottom: "-20%", right: "-10%",
                width: "500px", height: "500px",
                background: "radial-gradient(circle, rgba(6,182,212,0.06) 0%, transparent 70%)",
                borderRadius: "50%", pointerEvents: "none"
            }} />

            <div className="auth-card fade-in">
                <div className="auth-logo">
                    <div className="auth-logo-icon">🛡️</div>
                    <div className="auth-logo-title">CyberGuard</div>
                    <div className="auth-logo-sub">AI-Assisted Vulnerability Platform</div>
                </div>

                <div className="auth-tabs">
                    <button className={`auth-tab ${tab === "login" ? "active" : ""}`} onClick={() => setTab("login")}>Login</button>
                    <button className={`auth-tab ${tab === "register" ? "active" : ""}`} onClick={() => setTab("register")}>Register</button>
                </div>

                {error && <div className="alert alert-error">⚠️ {error}</div>}
                {success && <div className="alert alert-success">✅ {success}</div>}

                <form className="auth-form" onSubmit={handleSubmit}>
                    <div className="input-group">
                        <label className="input-label">Username</label>
                        <input className="input" placeholder="analyst" value={username}
                            onChange={e => setUsername(e.target.value)} required autoFocus />
                    </div>

                    {tab === "register" && (
                        <div className="input-group">
                            <label className="input-label">Email (optional)</label>
                            <input className="input" type="email" placeholder="user@company.com" value={email}
                                onChange={e => setEmail(e.target.value)} />
                        </div>
                    )}

                    <div className="input-group">
                        <label className="input-label">Password</label>
                        <input className="input" type="password" placeholder="••••••••" value={password}
                            onChange={e => setPassword(e.target.value)} required />
                    </div>

                    <button className="btn btn-primary btn-lg" type="submit" disabled={loading}
                        style={{ width: "100%", justifyContent: "center", marginTop: 8 }}>
                        {loading ? <><div className="spinner" style={{ width: 16, height: 16 }} /> Processing...</>
                            : tab === "login" ? "🔐 Sign In" : "🚀 Create Account"}
                    </button>
                </form>
            </div>
        </div>
    );
}

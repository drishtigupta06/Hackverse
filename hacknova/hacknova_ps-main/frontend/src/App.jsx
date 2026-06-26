import { useState, useEffect } from "react";
import { BrowserRouter as Router, Routes, Route, NavLink, Navigate, useLocation } from "react-router-dom";
import "./index.css";
import * as api from "./api.js";

import AuthPage from "./pages/AuthPage.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import ScanPage from "./pages/ScanPage.jsx";
import ResultsPage from "./pages/ResultsPage.jsx";
import AttackGraphPage from "./pages/AttackGraphPage.jsx";
import ChatPage from "./pages/ChatPage.jsx";
import ChatHistoryPage from "./pages/ChatHistoryPage.jsx";
import CVELookupPage from "./pages/CVELookupPage.jsx";
import ReportsPage from "./pages/ReportsPage.jsx";
import TaskMonitor from "./pages/TaskMonitor.jsx";
import AttackSurface from "./pages/AttackSurface.jsx";
import MobileScan from "./pages/MobileScan.jsx";
import SimulationPage from "./pages/SimulationPage.jsx";
import CredentialLeaks from "./pages/CredentialLeaks.jsx";
import ThreatIntelligence from "./pages/ThreatIntelligence.jsx";
import LLMScanner from "./pages/LLMScanner.jsx";

const NAV_ITEMS = [
    { id: "dashboard", icon: "📊", label: "Dashboard", path: "/dashboard" },
    { id: "llm", icon: "🧠", label: "LLM Scanner", path: "/llm" },
    { id: "intel", icon: "🌎", label: "Threat Intel", path: "/intel" },
    { id: "recon", icon: "🌍", label: "Attack Surface", path: "/recon" },
    { id: "leaks", icon: "🕵️‍♂️", label: "Credential Leaks", path: "/leaks" },
    { id: "mobile", icon: "📱", label: "Mobile Scan", path: "/mobile" },
    { id: "results", icon: "📋", label: "Scan Results", path: "/results" },
    { id: "graph", icon: "🕸️", label: "Attack Graph", path: "/graph" },
    { id: "chat", icon: "💬", label: "AI Chat", path: "/chat" },
    { id: "cvelookup", icon: "🔎", label: "CVE Lookup", path: "/cvelookup" },
    { id: "reports", icon: "📄", label: "Reports", path: "/reports" },
    { id: "tasks", icon: "⚙️", label: "Task Monitor", path: "/tasks" },
];

function InternalApp({ user, onLogout }) {
    const location = useLocation();

    return (
        <div className="app-container">
            {/* Sidebar */}
            <div className="sidebar">
                <div className="sidebar-logo">
                    <div className="sidebar-logo-icon">🛡️</div>
                    <div className="sidebar-logo-text">CyberGuard</div>
                </div>

                <nav className="sidebar-nav">
                    {NAV_ITEMS.map(item => (
                        <NavLink
                            key={item.id}
                            to={item.path}
                            className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
                            style={{ textDecoration: 'none' }}
                        >
                            <span className="nav-icon">{item.icon}</span>
                            {item.label}
                        </NavLink>
                    ))}
                </nav>

                {/* Service status */}
                <div style={{ padding: "10px 20px", borderTop: "1px solid var(--border)", marginBottom: 6 }}>
                    <div style={{ fontSize: 10, color: "var(--text-muted)", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: 8 }}>
                        Services
                    </div>
                    {[
                        { label: "API", ok: true, detail: ":8002" },
                        { label: "Nmap", ok: true },
                        { label: "RAG Engine", ok: true },
                        { label: "Ollama LLM", ok: true, detail: "CUDA" },
                        { label: "Celery", ok: true, detail: "Worker + Flower" },
                    ].map(({ label, ok, detail }) => (
                        <div key={label} style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 3 }}>
                            <div style={{ width: 5, height: 5, borderRadius: "50%", background: ok ? "var(--green)" : "var(--text-muted)", flexShrink: 0 }} />
                            <span style={{ fontSize: 11, color: "var(--text-secondary)", flex: 1 }}>{label}</span>
                            <span style={{ fontSize: 10, color: ok ? "var(--green)" : "var(--text-muted)" }}>
                                {detail || (ok ? "✓" : "—")}
                            </span>
                        </div>
                    ))}
                </div>

                {/* User */}
                <div className="sidebar-footer">
                    <div className="user-info">
                        <div className="user-avatar">{user?.[0]?.toUpperCase() || "A"}</div>
                        <div>
                            <div className="user-name">{user}</div>
                            <div className="user-role">Security Analyst</div>
                        </div>
                        <button onClick={onLogout} title="Logout"
                            style={{ marginLeft: "auto", background: "none", border: "none", cursor: "pointer", fontSize: 14, color: "var(--text-muted)", padding: 4 }}>
                            ↩
                        </button>
                    </div>
                </div>
            </div>

            {/* Main */}
            <main className="main-content">
                <div style={{ position: "fixed", top: "10%", right: "-5%", width: 400, height: 400, background: "radial-gradient(circle, rgba(99,102,241,0.04) 0%, transparent 70%)", borderRadius: "50%", pointerEvents: "none", zIndex: 0 }} />
                <div style={{ position: "relative", zIndex: 1 }}>
                    <Routes>
                        <Route path="/" element={<Navigate to="/dashboard" replace />} />
                        <Route path="/dashboard" element={<Dashboard user={user} />} />
                        <Route path="/llm" element={<LLMScanner user={user} />} />
                        <Route path="/intel" element={<ThreatIntelligence user={user} />} />
                        <Route path="/scan" element={<ScanPage user={user} />} />
                        <Route path="/recon" element={<AttackSurface user={user} />} />
                        <Route path="/leaks" element={<CredentialLeaks user={user} />} />
                        <Route path="/mobile" element={<MobileScan user={user} />} />
                        <Route path="/results/:scanId?" element={<ResultsPage user={user} />} />
                        <Route path="/graph/:scanId?" element={<AttackGraphPage user={user} />} />
                        <Route path="/simulation/:scanId" element={<SimulationPage user={user} />} />
                        <Route path="/chat/:scanId?" element={<ChatPage user={user} />} />
                        <Route path="/chathistory" element={<ChatHistoryPage user={user} />} />
                        <Route path="/cvelookup" element={<CVELookupPage user={user} />} />
                        <Route path="/reports" element={<ReportsPage user={user} />} />
                        <Route path="/tasks" element={<TaskMonitor user={user} />} />
                        <Route path="*" element={<Navigate to="/dashboard" replace />} />
                    </Routes>
                </div>
            </main>
        </div>
    );
}

export default function App() {
    const [loggedIn, setLoggedIn] = useState(api.isLoggedIn());
    const [user, setUser] = useState("analyst");

    useEffect(() => {
        if (loggedIn) {
            api.getMe().then(u => setUser(u.username)).catch(() => {
                setLoggedIn(false);
            });
        }
    }, [loggedIn]);

    function handleLogout() {
        api.logout();
        setLoggedIn(false);
    }

    if (!loggedIn) return <AuthPage onLogin={() => setLoggedIn(true)} />;

    return (
        <Router>
            <InternalApp user={user} onLogout={handleLogout} />
        </Router>
    );
}

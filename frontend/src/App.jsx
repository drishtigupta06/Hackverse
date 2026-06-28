import { useState, useEffect } from "react";
import { BrowserRouter as Router, Routes, Route, NavLink, Navigate, useLocation } from "react-router-dom";
import "./index.css";
import * as api from "./api.js";
import {
    LayoutDashboard,
    Brain,
    Globe,
    Radar,
    Key,
    Smartphone,
    ClipboardList,
    GitBranch,
    MessageSquare,
    Search,
    FileText,
    Settings,
    Shield,
    LogOut,
    Users,
    User
} from "lucide-react";

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
import TeamManagement from "./pages/TeamManagement.jsx";
import ProfilePage from "./pages/ProfilePage.jsx";

const NAV_ITEMS = [
    { id: "dashboard", icon: LayoutDashboard, label: "Dashboard", path: "/dashboard" },
    { id: "llm", icon: Brain, label: "LLM Scanner", path: "/llm" },
    { id: "intel", icon: Globe, label: "Threat Intel", path: "/intel" },
    { id: "recon", icon: Radar, label: "Attack Surface", path: "/recon" },
    { id: "leaks", icon: Key, label: "Credential Leaks", path: "/leaks" },
    { id: "mobile", icon: Smartphone, label: "Mobile Scan", path: "/mobile" },
    { id: "results", icon: ClipboardList, label: "Scan Results", path: "/results" },
    { id: "graph", icon: GitBranch, label: "Attack Graph", path: "/graph" },
    { id: "chat", icon: MessageSquare, label: "AI Chat", path: "/chat" },
    { id: "cvelookup", icon: Search, label: "CVE Lookup", path: "/cvelookup" },
    { id: "reports", icon: FileText, label: "Reports", path: "/reports" },
    { id: "tasks", icon: Settings, label: "Task Monitor", path: "/tasks" },
    { id: "team", icon: Users, label: "Team", path: "/team" },
    { id: "profile", icon: User, label: "My Profile", path: "/profile" },
];

function InternalApp({ user, onLogout }) {
    const location = useLocation();

    return (
        <div className="app-container">
            {/* Sidebar */}
            <div className="sidebar">
                <div className="sidebar-logo">
                    <div className="sidebar-logo-icon" style={{ background: "none", display: "inline-flex", alignItems: "center" }}>
                        <Shield size={24} style={{ color: "var(--accent)" }} />
                    </div>
                    <div className="sidebar-logo-text">CyberGuard</div>
                </div>

                <nav className="sidebar-nav">
                    {NAV_ITEMS.map(item => {
                        const IconComponent = item.icon;
                        return (
                            <NavLink
                                key={item.id}
                                to={item.path}
                                className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
                                style={{ textDecoration: 'none' }}
                            >
                                <span className="nav-icon" style={{ display: "inline-flex", alignItems: "center" }}>
                                    <IconComponent size={16} />
                                </span>
                                {item.label}
                            </NavLink>
                        );
                    })}
                </nav>

                {/* Service status */}
                <div style={{ padding: "14px 20px", borderTop: "1px solid var(--border)", marginBottom: 6 }}>
                    <div style={{ fontSize: 10, color: "var(--text-muted)", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.8px", marginBottom: 12 }}>
                        System Services
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: 8 }}>
                        {[
                            { label: "API Gateway", ok: true, detail: "Port 8002" },
                            { label: "Nmap Engine", ok: true, detail: "Dockerized" },
                            { label: "RAG Pipeline", ok: true, detail: "Active" },
                            { label: "Ollama LLM", ok: true, detail: "CUDA Active" },
                            { label: "Celery Node", ok: true, detail: "Worker Pool" },
                        ].map(({ label, ok, detail }) => (
                            <div key={label} style={{
                                display: "flex",
                                flexDirection: "column",
                                padding: "8px 10px",
                                background: "var(--bg-secondary)",
                                border: "1px solid var(--border)",
                                borderRadius: 8,
                                gap: 4
                            }}>
                                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                                    <div style={{
                                        width: 6,
                                        height: 6,
                                        borderRadius: "50%",
                                        background: ok ? "var(--green)" : "var(--text-muted)",
                                        boxShadow: ok ? "0 0 6px var(--green)" : "none",
                                        flexShrink: 0
                                    }} />
                                    <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-primary)" }}>{label}</span>
                                </div>
                                <span style={{ fontSize: 9, color: "var(--text-muted)", marginLeft: 12 }}>{detail}</span>
                            </div>
                        ))}
                    </div>
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
                            style={{ marginLeft: "auto", background: "none", border: "none", cursor: "pointer", display: "inline-flex", alignItems: "center", justifyItems: "center", color: "var(--text-muted)", padding: 4 }}>
                            <LogOut size={16} />
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
                        <Route path="/team" element={<TeamManagement user={user} />} />
                        <Route path="/profile" element={<ProfilePage user={user} />} />
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

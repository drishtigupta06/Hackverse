import { useState, useEffect } from "react";
import * as api from "../api.js";

const NAV_ITEMS = [
    { id: "dashboard", icon: "📊", label: "Dashboard", url: "/dashboard.html" },
    { id: "scan", icon: "🔬", label: "Launch Scan", url: "/scan.html" },
    { id: "results", icon: "📋", label: "Results", url: "/results.html" },
    { id: "graph", icon: "🕸️", label: "Attack Graph", url: "/graph.html" },
    { id: "chat", icon: "💬", label: "AI Chat", url: "/chat.html" },
    { id: "chathistory", icon: "📜", label: "Chat History", url: "/chathistory.html" },
    { id: "cvelookup", icon: "🔎", label: "CVE Lookup", url: "/cvelookup.html" },
    { id: "reports", icon: "📄", label: "Reports", url: "/reports.html" },
    { id: "tasks", icon: "⚙️", label: "Task Monitor", url: "/tasks.html" },
];

export default function Layout({ children, activePage, user }) {
    function handleLogout() {
        api.logout();
        window.location.href = "/index.html";
    }

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
                        <a key={item.id}
                            href={item.url}
                            className={`nav-item ${activePage === item.id ? "active" : ""}`}
                            style={{ textDecoration: 'none' }}>
                            <span className="nav-icon">{item.icon}</span>
                            {item.label}
                        </a>
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
                        <button onClick={handleLogout} title="Logout"
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
                    {children}
                </div>
            </main>
        </div>
    );
}

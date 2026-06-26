import { useState, useEffect } from "react";
import * as api from "../api.js";
import ReactMarkdown from "react-markdown";

export default function ChatHistoryPage({ onNavigate }) {
    const [chats, setChats] = useState([]);
    const [loading, setLoading] = useState(true);
    const [search, setSearch] = useState("");
    const [expanded, setExpanded] = useState(null);

    useEffect(() => {
        api.getChatHistory(100)
            .then(r => setChats(r.chats || []))
            .catch(console.error)
            .finally(() => setLoading(false));
    }, []);

    const filtered = chats.filter(c =>
        !search || c.question?.toLowerCase().includes(search.toLowerCase()) ||
        c.answer?.toLowerCase().includes(search.toLowerCase())
    );

    return (
        <div className="fade-in">
            <div className="page-header">
                <div>
                    <div className="page-title"><span>📜</span> Chat History</div>
                    <div className="page-subtitle">All past conversations with CyberGuard AI</div>
                </div>
                <button className="btn btn-primary" onClick={() => onNavigate("chat")}>+ New Chat</button>
            </div>

            {/* Search */}
            <div style={{ marginBottom: 20 }}>
                <input className="input" placeholder="🔎 Search questions or answers..."
                    value={search} onChange={e => setSearch(e.target.value)}
                    style={{ maxWidth: 400 }} />
            </div>

            {loading ? (
                <div className="loading-center"><div className="spinner" style={{ width: 28, height: 28 }} /><span>Loading history...</span></div>
            ) : filtered.length === 0 ? (
                <div className="empty-state">
                    <div className="empty-state-icon">💬</div>
                    <div className="empty-state-title">No chat history</div>
                    <div className="empty-state-desc">Start a conversation with CyberGuard AI</div>
                    <button className="btn btn-primary" style={{ marginTop: 8 }} onClick={() => onNavigate("chat")}>Open Chat</button>
                </div>
            ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                    {filtered.map((c, i) => (
                        <div key={i} className="card" style={{ cursor: "pointer" }}
                            onClick={() => setExpanded(expanded === i ? null : i)}>
                            {/* Question header */}
                            <div style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
                                <div style={{
                                    width: 32, height: 32, borderRadius: "50%", flexShrink: 0,
                                    background: "linear-gradient(135deg, var(--green), var(--cyan))",
                                    display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14,
                                }}>👤</div>
                                <div style={{ flex: 1, minWidth: 0 }}>
                                    <div style={{ fontWeight: 600, color: "var(--text-primary)", fontSize: 14, marginBottom: 4 }}>
                                        {c.question}
                                    </div>
                                    <div style={{ display: "flex", gap: 12 }}>
                                        <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
                                            📅 {c.timestamp ? new Date(c.timestamp).toLocaleString() : "—"}
                                        </span>
                                        {c.scan_id && (
                                            <span style={{ fontSize: 11, color: "var(--accent-light)", fontFamily: "var(--font-mono)" }}>
                                                🔍 Scan: {c.scan_id?.slice(0, 8)}...
                                            </span>
                                        )}
                                    </div>
                                </div>
                                <span style={{ color: "var(--text-muted)", fontSize: 12 }}>
                                    {expanded === i ? "▲" : "▼"}
                                </span>
                            </div>

                            {/* Answer (expanded) */}
                            {expanded === i && c.answer && (
                                <div style={{ marginTop: 16, paddingTop: 16, borderTop: "1px solid var(--border)" }}>
                                    <div style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
                                        <div style={{
                                            width: 32, height: 32, borderRadius: "50%", flexShrink: 0,
                                            background: "linear-gradient(135deg, var(--accent), var(--cyan))",
                                            display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14,
                                        }}>🛡️</div>
                                        <div style={{
                                            flex: 1, padding: "12px 16px",
                                            background: "rgba(99,102,241,0.06)", border: "1px solid var(--border)",
                                            borderRadius: 12, fontSize: 14, lineHeight: 1.7, color: "var(--text-primary)",
                                        }}>
                                            <div className="markdown-body">
                                                <ReactMarkdown>{c.answer.slice(0, 600)}{c.answer.length > 600 ? "..." : ""}</ReactMarkdown>
                                            </div>
                                            {c.answer.length > 600 && (
                                                <button className="btn btn-secondary btn-sm" style={{ marginTop: 8 }}
                                                    onClick={(e) => { e.stopPropagation(); onNavigate("chat"); }}>
                                                    Continue in Chat →
                                                </button>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>
                    ))}
                </div>
            )}

            <style>{`
        .markdown-body p { margin: 4px 0; }
        .markdown-body ul, .markdown-body ol { margin: 6px 0; padding-left: 20px; }
        .markdown-body code { font-family: var(--font-mono); font-size: 12px; background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px; }
        .markdown-body strong { color: var(--accent-light); }
        .markdown-body h1, .markdown-body h2, .markdown-body h3 { font-size: 13px; font-weight: 700; margin: 6px 0 3px; color: var(--accent-light); }
      `}</style>
        </div>
    );
}

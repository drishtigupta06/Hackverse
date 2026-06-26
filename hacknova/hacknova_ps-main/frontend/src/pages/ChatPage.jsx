import { useState, useEffect, useRef } from "react";
import { useParams } from "react-router-dom";
import * as api from "../api.js";
import ReactMarkdown from "react-markdown";

function ChatMessage({ msg }) {
    const isUser = msg.role === "user";
    return (
        <div className={`chat-message ${isUser ? "user" : ""}`}>
            <div className={`chat-avatar ${isUser ? "user" : "ai"}`}>
                {isUser ? "👤" : "🛡️"}
            </div>
            <div className={`chat-bubble ${isUser ? "user" : "ai"}`}>
                {isUser ? msg.content : (
                    <div className="markdown-body">
                        <ReactMarkdown>{msg.content}</ReactMarkdown>
                    </div>
                )}
                <div style={{ fontSize: 10, color: isUser ? "rgba(255,255,255,0.5)" : "var(--text-muted)", marginTop: 6, textAlign: isUser ? "right" : "left" }}>
                    {msg.time}
                </div>
            </div>
        </div>
    );
}

const SUGGESTIONS = [
    "What is CVE-2021-44228 (Log4Shell)?",
    "Explain SQL injection and how to prevent it",
    "How can an open SSH port be exploited?",
    "What is CVSS score and how is it calculated?",
    "Explain the OWASP Top 10 briefly",
    "What does 'exploit available' for a CVE mean?",
];

export default function ChatPage({ user }) {
    const { scanId: routeScanId } = useParams();
    const [messages, setMessages] = useState([{
        role: "assistant",
        content: "👋 Hello! I'm **CyberGuard AI**, your cybersecurity expert assistant.\n\nI can explain vulnerabilities, CVEs, attack paths, and security concepts. Ask me anything — or select a scan to give me context about your findings.",
        time: new Date().toLocaleTimeString(),
    }]);
    const [input, setInput] = useState("");
    const [loading, setLoading] = useState(false);
    const [scans, setScans] = useState([]);
    const [selectedScan, setSelectedScan] = useState(routeScanId || null);
    const endRef = useRef(null);

    useEffect(() => {
        api.listScans(20).then(r => {
            const done = (r.scans || []).filter(s => s.status === "completed");
            setScans(done);
        });
    }, []);

    useEffect(() => {
        if (routeScanId) {
            setSelectedScan(routeScanId);
        }
    }, [routeScanId]);

    useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

    async function send(question) {
        const q = question || input.trim();
        if (!q || loading) return;
        setInput("");

        setMessages(prev => [...prev, { role: "user", content: q, time: new Date().toLocaleTimeString() }]);
        setLoading(true);

        try {
            const resp = await api.sendChat(q, selectedScan);
            setMessages(prev => [...prev, {
                role: "assistant",
                content: resp.answer,
                time: new Date().toLocaleTimeString(),
            }]);
        } catch (err) {
            setMessages(prev => [...prev, {
                role: "assistant",
                content: `⚠️ Error: ${err.message}`,
                time: new Date().toLocaleTimeString(),
            }]);
        } finally {
            setLoading(false);
        }
    }

    return (
        <div className="fade-in">
            <div className="page-header">
                <div>
                    <div className="page-title"><span>💬</span> CyberGuard AI Chat</div>
                    <div className="page-subtitle">Explain vulnerabilities and get remediation advice</div>
                </div>
                <select className="filter-select" value={selectedScan || ""}
                    onChange={e => setSelectedScan(e.target.value || null)}>
                    <option value="">No scan context</option>
                    {scans.map(s => <option key={s.scan_id} value={s.scan_id}>{s.target} ({s.vuln_count} findings)</option>)}
                </select>
            </div>

            {/* Suggestions */}
            {messages.length === 1 && (
                <div style={{ marginBottom: 20 }}>
                    <div style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 10, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.5px" }}>
                        Quick Questions
                    </div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                        {SUGGESTIONS.map(s => (
                            <button key={s} className="btn btn-secondary btn-sm" onClick={() => send(s)}>{s}</button>
                        ))}
                    </div>
                </div>
            )}

            <div className="chat-container">
                <div className="chat-messages">
                    {messages.map((m, i) => <ChatMessage key={i} msg={m} />)}

                    {loading && (
                        <div className="chat-message">
                            <div className="chat-avatar ai">🛡️</div>
                            <div className="chat-bubble ai">
                                <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                                    <div style={{ display: "flex", gap: 3 }}>
                                        {[0, 1, 2].map(i => (
                                            <div key={i} style={{
                                                width: 6, height: 6, borderRadius: "50%", background: "var(--accent)",
                                                animation: `bounce 1.2s ${i * 0.2}s ease-in-out infinite`,
                                            }} />
                                        ))}
                                    </div>
                                    <span style={{ fontSize: 12, color: "var(--text-muted)" }}>Analyzing with RAG pipeline...</span>
                                </div>
                            </div>
                        </div>
                    )}
                    <div ref={endRef} />
                </div>

                <div className="chat-input-bar">
                    <input className="input" placeholder="Ask about a CVE, vulnerability, or attack path..."
                        value={input} onChange={e => setInput(e.target.value)}
                        onKeyDown={e => e.key === "Enter" && !e.shiftKey && send()} disabled={loading} />
                    <button className="btn btn-primary" onClick={() => send()} disabled={loading || !input.trim()}
                        style={{ flexShrink: 0 }}>
                        {loading ? <div className="spinner" style={{ width: 16, height: 16 }} /> : "Send →"}
                    </button>
                </div>
            </div>

            <style>{`
        @keyframes bounce {
          0%, 80%, 100% { transform: scale(1); opacity: 0.5; }
          40% { transform: scale(1.3); opacity: 1; }
        }
        .markdown-body p { margin: 4px 0; }
        .markdown-body ul, .markdown-body ol { margin: 6px 0; padding-left: 20px; }
        .markdown-body code { font-family: var(--font-mono); font-size: 12px; background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px; }
        .markdown-body pre { background: rgba(0,0,0,0.3); padding: 10px; border-radius: var(--radius-sm); margin: 8px 0; overflow-x: auto; }
        .markdown-body h1, .markdown-body h2, .markdown-body h3 { font-size: 14px; font-weight: 700; margin: 8px 0 4px; color: var(--accent-light); }
        .markdown-body strong { color: var(--text-primary); }
        .markdown-body a { color: var(--accent-light); }
      `}</style>
        </div>
    );
}

import { useState } from "react";
import * as api from "../api.js";
import {
    SearchIcon,
    AlertCircleIcon,
    HistoryIcon,
    SettingsIcon
} from "../components/Icons.jsx";

const KNOWN_CVES = [
    "CVE-2021-44228", "CVE-2021-34527", "CVE-2022-30190",
    "CVE-2023-23397", "CVE-2021-26855", "CVE-2022-22965",
    "CVE-2023-44487",
];

function SeverityBar({ score }) {
    if (!score) return null;
    const color = score >= 9 ? "#dc2626" : score >= 7 ? "#ea580c" : score >= 4 ? "#d97706" : "#65a30d";
    const width = Math.round((score / 10) * 100);
    return (
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ flex: 1, height: 8, background: "var(--bg-secondary)", borderRadius: 4, overflow: "hidden" }}>
                <div style={{ width: `${width}%`, height: "100%", background: color, borderRadius: 4, transition: "width 0.5s ease" }} />
            </div>
            <span style={{ color, fontWeight: 700, fontSize: 18, minWidth: 40 }}>{score}</span>
        </div>
    );
}

export default function CVELookupPage() {
    const [query, setQuery] = useState("");
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");

    async function lookup(cveId) {
        const id = (cveId || query).trim().toUpperCase();
        if (!id) return;
        setError(""); setResult(null); setLoading(true);
        try {
            const data = await api.lookupCVE(id);
            setResult(data);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    }

    return (
        <div className="fade-in">
            <div className="page-header">
                <div>
                    <div className="page-title" style={{ display: "inline-flex", alignItems: "center", gap: 10 }}>
                        <SearchIcon size={24} style={{ color: "var(--accent)" }} /> CVE Lookup
                    </div>
                    <div className="page-subtitle">Search any CVE ID for details, CVSS score, and references (powered by NVD API)</div>
                </div>
            </div>

            {/* Search bar */}
            <div className="card" style={{ marginBottom: 24 }}>
                <div style={{ display: "flex", gap: 12 }}>
                    <input className="input" placeholder="CVE-2021-44228"
                        value={query} onChange={e => setQuery(e.target.value)}
                        onKeyDown={e => e.key === "Enter" && lookup()}
                        style={{ flex: 1, fontFamily: "var(--font-mono)", fontSize: 15 }} />
                    <button className="btn btn-primary" onClick={() => lookup()} disabled={loading || !query.trim()} style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                        <SearchIcon size={16} /> Search
                    </button>
                </div>

                {/* Quick picks */}
                <div style={{ marginTop: 14 }}>
                    <div style={{ fontSize: 11, color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: 8 }}>
                        Popular CVEs
                    </div>
                    <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                        {KNOWN_CVES.map(c => (
                            <button key={c} className="btn btn-secondary btn-sm"
                                style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}
                                onClick={() => { setQuery(c); lookup(c); }}>
                                {c}
                            </button>
                        ))}
                    </div>
                </div>
            </div>

            {/* Error */}
            {error && (
                <div className="alert alert-error" style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                    <AlertCircleIcon size={14} /> {error} — NVD API may be rate-limited or CVE not found
                </div>
            )}

            {/* Loading */}
            {loading && <div className="loading-center"><div className="spinner" style={{ width: 32, height: 32 }} /><span>Fetching from NVD API...</span></div>}

            {/* Result */}
            {result && (
                <div className="card fade-in">
                    <div style={{ display: "flex", alignItems: "flex-start", gap: 20, marginBottom: 24 }}>
                        <div>
                            <div style={{ fontFamily: "var(--font-mono)", fontSize: 24, fontWeight: 800, color: "var(--accent-light)", marginBottom: 6 }}>
                                {result.cve_id}
                            </div>
                            <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                                {result.published && (
                                    <span style={{ fontSize: 12, color: "var(--text-muted)", display: "inline-flex", alignItems: "center", gap: 4 }}>
                                        <HistoryIcon size={12} /> Published: {new Date(result.published).toLocaleDateString()}
                                    </span>
                                )}
                                {result.modified && (
                                    <span style={{ fontSize: 12, color: "var(--text-muted)", display: "inline-flex", alignItems: "center", gap: 4 }}>
                                        <SettingsIcon size={12} /> Modified: {new Date(result.modified).toLocaleDateString()}
                                    </span>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* CVSS Score */}
                    {result.cvss_score && (
                        <div style={{ marginBottom: 24 }}>
                            <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: 8 }}>
                                CVSS Score
                            </div>
                            <SeverityBar score={result.cvss_score} />
                            {result.cvss_vector && (
                                <div style={{ marginTop: 8, fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-muted)", wordBreak: "break-all" }}>
                                    {result.cvss_vector}
                                </div>
                            )}
                        </div>
                    )}

                    {/* Description */}
                    {result.description && (
                        <div style={{ marginBottom: 24 }}>
                            <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: 8 }}>
                                Description
                            </div>
                            <div style={{ fontSize: 14, lineHeight: 1.7, color: "var(--text-secondary)", background: "var(--bg-secondary)", padding: 16, borderRadius: "var(--radius-sm)", border: "1px solid var(--border)" }}>
                                {result.description}
                            </div>
                        </div>
                    )}

                    {/* Links */}
                    <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                        {result.nvd_url && (
                            <a href={result.nvd_url} target="_blank" rel="noreferrer" className="btn btn-secondary btn-sm" style={{ textDecoration: 'none' }}>
                                View on NVD
                            </a>
                        )}
                        {result.exploitdb_url && (
                            <a href={result.exploitdb_url} target="_blank" rel="noreferrer" className="btn btn-secondary btn-sm" style={{ textDecoration: 'none' }}>
                                Search Exploit-DB
                            </a>
                        )}
                    </div>

                    {/* References */}
                    {result.references?.length > 0 && (
                        <div style={{ marginTop: 20 }}>
                            <div style={{ fontSize: 12, fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.5px", marginBottom: 10 }}>
                                References
                            </div>
                            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                                {result.references.map((ref, i) => {
                                    let label = ref;
                                    try {
                                        const urlObj = new URL(ref);
                                        label = urlObj.hostname + (urlObj.pathname.length > 20 ? urlObj.pathname.substring(0, 18) + "..." : urlObj.pathname);
                                    } catch (_) { }
                                    return (
                                        <a key={i} href={ref} target="_blank" rel="noreferrer" className="btn btn-secondary btn-sm"
                                            style={{
                                                display: "inline-flex",
                                                alignItems: "center",
                                                textDecoration: 'none',
                                                fontFamily: "var(--font-mono)",
                                                fontSize: 11
                                            }}>
                                            {label}
                                        </a>
                                    );
                                })}
                            </div>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

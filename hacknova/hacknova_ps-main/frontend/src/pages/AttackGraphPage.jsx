import { useState, useEffect, useRef, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import * as api from "../api.js";

// D3-free force-directed graph using canvas/SVG
const NODE_COLORS = {
    attacker: "#ef4444",
    host: "#6366f1",
    service: "#06b6d4",
    vulnerability: { critical: "#dc2626", high: "#ea580c", medium: "#d97706", low: "#65a30d", info: "#0891b2" },
    exploit: "#dc2626",
};

function getNodeColor(node) {
    if (node.type === "vulnerability") {
        return NODE_COLORS.vulnerability[node.severity] || "#6366f1";
    }
    return NODE_COLORS[node.type] || "#6366f1";
}

function GraphCanvas({ graphData }) {
    const svgRef = useRef(null);
    const [positions, setPositions] = useState({});
    const [selectedNode, setSelectedNode] = useState(null);
    const [dragging, setDragging] = useState(null);
    const animRef = useRef(null);
    const posRef = useRef({});
    const velRef = useRef({});

    const nodes = graphData?.nodes || [];
    const edges = graphData?.edges || [];

    // Initialize positions in a circle layout
    useEffect(() => {
        if (!nodes.length) return;
        const centerX = 400, centerY = 250;
        const radius = Math.min(200, nodes.length * 15);
        const newPos = {};
        const newVel = {};

        nodes.forEach((n, i) => {
            if (posRef.current[n.id]) {
                newPos[n.id] = posRef.current[n.id];
            } else {
                const angle = (i / nodes.length) * 2 * Math.PI;
                newPos[n.id] = {
                    x: centerX + radius * Math.cos(angle) + (Math.random() - 0.5) * 40,
                    y: centerY + radius * Math.sin(angle) + (Math.random() - 0.5) * 40,
                };
            }
            newVel[n.id] = { vx: 0, vy: 0 };
        });

        posRef.current = newPos;
        velRef.current = newVel;
        setPositions({ ...newPos });
    }, [nodes.length]);

    // Simple spring simulation
    useEffect(() => {
        if (!nodes.length) return;

        let frame = 0;
        function tick() {
            frame++;
            const pos = posRef.current;
            const vel = velRef.current;
            const W = 800, H = 500;

            // Repulsion between all nodes
            nodes.forEach(a => {
                nodes.forEach(b => {
                    if (a.id === b.id) return;
                    const dx = (pos[a.id]?.x || 0) - (pos[b.id]?.x || 0);
                    const dy = (pos[a.id]?.y || 0) - (pos[b.id]?.y || 0);
                    const dist = Math.sqrt(dx * dx + dy * dy) || 1;
                    const force = 1200 / (dist * dist);
                    if (vel[a.id]) {
                        vel[a.id].vx += (dx / dist) * force;
                        vel[a.id].vy += (dy / dist) * force;
                    }
                });
            });

            // Attraction along edges
            edges.forEach(e => {
                const a = pos[e.source], b = pos[e.target];
                if (!a || !b) return;
                const dx = b.x - a.x, dy = b.y - a.y;
                const dist = Math.sqrt(dx * dx + dy * dy) || 1;
                const target = 120;
                const force = (dist - target) * 0.05;
                const fx = (dx / dist) * force, fy = (dy / dist) * force;
                if (vel[e.source]) { vel[e.source].vx += fx; vel[e.source].vy += fy; }
                if (vel[e.target]) { vel[e.target].vx -= fx; vel[e.target].vy -= fy; }
            });

            // Apply velocities with damping + boundary
            nodes.forEach(n => {
                if (!pos[n.id] || !vel[n.id]) return;
                const damping = 0.82;
                vel[n.id].vx *= damping;
                vel[n.id].vy *= damping;
                pos[n.id].x = Math.max(40, Math.min(W - 40, pos[n.id].x + vel[n.id].vx));
                pos[n.id].y = Math.max(40, Math.min(H - 40, pos[n.id].y + vel[n.id].vy));
            });

            if (frame % 3 === 0) setPositions({ ...pos });
            if (frame < 150) animRef.current = requestAnimationFrame(tick);
        }

        animRef.current = requestAnimationFrame(tick);
        return () => cancelAnimationFrame(animRef.current);
    }, [nodes.length, edges.length]);

    function handleMouseDown(e, nodeId) {
        e.stopPropagation();
        setDragging(nodeId);
        setSelectedNode(nodeId);
    }

    function handleMouseMove(e) {
        if (!dragging || !svgRef.current) return;
        const rect = svgRef.current.getBoundingClientRect();
        posRef.current[dragging] = { x: e.clientX - rect.left, y: e.clientY - rect.top };
        if (velRef.current[dragging]) { velRef.current[dragging] = { vx: 0, vy: 0 }; }
        setPositions({ ...posRef.current });
    }

    const selectedNodeData = selectedNode ? nodes.find(n => n.id === selectedNode) : null;

    return (
        <div style={{ position: "relative" }}>
            <svg ref={svgRef} width="100%" viewBox="0 0 800 500" style={{ background: "rgba(5,10,20,0.8)", borderRadius: "var(--radius)", border: "1px solid var(--border)", display: "block" }}
                onMouseMove={handleMouseMove} onMouseUp={() => setDragging(null)} onMouseLeave={() => setDragging(null)}>

                <defs>
                    <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
                        <polygon points="0 0, 8 3, 0 6" fill="rgba(99,102,241,0.5)" />
                    </marker>
                    {/* Glowing Filter for Node Impact */}
                    <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
                        <feGaussianBlur stdDeviation="3" result="blur" />
                        <feComposite in="SourceGraphic" in2="blur" operator="over" />
                    </filter>
                </defs>

                {/* Edges */}
                {edges.map((e, i) => {
                    const s = positions[e.source], t = positions[e.target];
                    if (!s || !t) return null;
                    const dx = t.x - s.x, dy = t.y - s.y;
                    const dist = Math.sqrt(dx * dx + dy * dy) || 1;
                    const r = 18;
                    const ex = t.x - (dx / dist) * r, ey = t.y - (dy / dist) * r;
                    return (
                        <g key={i}>
                            <line x1={s.x} y1={s.y} x2={ex} y2={ey}
                                stroke="rgba(99,102,241,0.3)" strokeWidth="1.5" markerEnd="url(#arrowhead)" />
                            <text x={(s.x + t.x) / 2} y={(s.y + t.y) / 2 - 4}
                                fontSize="9" fill="rgba(148,163,184,0.6)" textAnchor="middle">{e.label}</text>
                        </g>
                    );
                })}

                {/* Nodes */}
                {nodes.map(n => {
                    const p = positions[n.id];
                    if (!p) return null;
                    const color = getNodeColor(n);
                    const isSelected = selectedNode === n.id;
                    const r = n.type === "attacker" ? 22 : n.type === "exploit" ? 16 : 18;
                    return (
                        <g key={n.id} transform={`translate(${p.x},${p.y})`}
                            style={{ cursor: "pointer" }} onMouseDown={e => handleMouseDown(e, n.id)}>
                            {isSelected && <circle r={r + 8} fill={color} opacity="0.2" filter="url(#glow)" />}
                            <circle r={r} fill={`${color}22`} stroke={color} strokeWidth={isSelected ? 2.5 : 1.5} filter={isSelected ? "url(#glow)" : ""} />
                            <text textAnchor="middle" dominantBaseline="middle" fontSize={n.type === "attacker" ? 14 : 11}>{
                                n.type === "attacker" ? "👤" :
                                    n.type === "host" ? "🖥️" :
                                        n.type === "service" ? "⚙️" :
                                            n.type === "vulnerability" ? "🐛" : "💥"
                            }</text>
                            <text y={r + 14} textAnchor="middle" fontSize="9" fill="rgba(148,163,184,0.8)" style={{ pointerEvents: "none" }}>
                                {n.label?.slice(0, 20)}{n.label?.length > 20 ? "…" : ""}
                            </text>
                        </g>
                    );
                })}
            </svg>

            {/* Node detail panel */}
            {selectedNodeData && (
                <div style={{
                    position: "absolute", top: 12, right: 12,
                    background: "var(--bg-card)", border: "1px solid var(--border)",
                    borderRadius: "var(--radius-sm)", padding: 16, maxWidth: 260,
                    backdropFilter: "blur(12px)",
                }}>
                    <div style={{ fontWeight: 700, color: "var(--text-primary)", marginBottom: 8, display: "flex", justifyContent: "space-between" }}>
                        {selectedNodeData.label}
                        <button onClick={() => setSelectedNode(null)} style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer" }}>✕</button>
                    </div>
                    <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                        <div><b>Type:</b> {selectedNodeData.type}</div>
                        {selectedNodeData.severity && <div><b>Severity:</b> {selectedNodeData.severity}</div>}
                        {selectedNodeData.data?.cve_id && <div><b>CVE:</b> {selectedNodeData.data.cve_id}</div>}
                        {selectedNodeData.data?.description && (
                            <div style={{ marginTop: 6, color: "var(--text-muted)" }}>{selectedNodeData.data.description?.slice(0, 120)}...</div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}

export default function AttackGraphPage({ user }) {
    const { scanId: routeScanId } = useParams();
    const navigate = useNavigate();
    const [scans, setScans] = useState([]);
    const [selectedScan, setSelectedScan] = useState(routeScanId || null);
    const [graphData, setGraphData] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");

    useEffect(() => {
        api.listScans(50).then(r => {
            const done = (r.scans || []).filter(s => s.status === "completed");
            setScans(done);
            if (!selectedScan && !routeScanId && done.length > 0) setSelectedScan(done[0].scan_id);
        });
    }, []);

    useEffect(() => {
        if (routeScanId) {
            setSelectedScan(routeScanId);
        }
    }, [routeScanId]);

    useEffect(() => {
        if (!selectedScan) return;
        setLoading(true); setError("");
        api.getAttackGraph(selectedScan)
            .then(setGraphData)
            .catch(e => setError(e.message))
            .finally(() => setLoading(false));
    }, [selectedScan]);

    const nodesByType = graphData?.nodes?.reduce((acc, n) => {
        acc[n.type] = (acc[n.type] || 0) + 1; return acc;
    }, {}) || {};

    return (
        <div className="fade-in">
            <div className="page-header">
                <div>
                    <div className="page-title"><span>🕸️</span> Attack Graph</div>
                    <div className="page-subtitle">Visualize attack paths and compromise routes</div>
                </div>
            </div>

            <div className="card" style={{ marginBottom: 20 }}>
                <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
                    <span style={{ fontSize: 13, color: "var(--text-secondary)", fontWeight: 600 }}>Select scan:</span>
                    {scans.map(s => (
                        <button key={s.scan_id} onClick={() => navigate(`/graph/${s.scan_id}`)}
                            className={`btn btn-sm ${selectedScan === s.scan_id ? "btn-primary" : "btn-secondary"}`}>
                            {s.target}
                        </button>
                    ))}
                </div>
            </div>

            {/* Legend */}
            {graphData && (
                <div style={{ display: "flex", gap: 16, flexWrap: "wrap", marginBottom: 20 }}>
                    {[
                        { type: "attacker", icon: "👤", label: "Attacker", color: "#ef4444" },
                        { type: "host", icon: "🖥️", label: "Host", color: "#6366f1" },
                        { type: "service", icon: "⚙️", label: "Service/Port", color: "#06b6d4" },
                        { type: "vulnerability", icon: "🐛", label: "Vulnerability", color: "#d97706" },
                        { type: "exploit", icon: "💥", label: "Exploit", color: "#dc2626" },
                    ].map(({ type, icon, label, color }) => {
                        const count = nodesByType[type] || 0;
                        return count > 0 ? (
                            <div key={type} style={{
                                display: "flex", alignItems: "center", gap: 6, padding: "6px 12px",
                                background: `${color}11`, border: `1px solid ${color}30`, borderRadius: "var(--radius-sm)"
                            }}>
                                <span>{icon}</span>
                                <span style={{ fontSize: 12, color, fontWeight: 600 }}>{label}</span>
                                <span style={{ fontSize: 12, color: "var(--text-muted)" }}>×{count}</span>
                            </div>
                        ) : null;
                    })}
                </div>
            )}

            {loading ? (
                <div className="loading-center"><div className="spinner" style={{ width: 32, height: 32 }} /><span>Building attack graph...</span></div>
            ) : error ? (
                <div className="alert alert-error">⚠️ {error}</div>
            ) : !graphData ? (
                <div className="empty-state">
                    <div className="empty-state-icon">🕸️</div>
                    <div className="empty-state-title">No graph data</div>
                    <div className="empty-state-desc">Run a scan with discovered vulnerabilities to generate an attack graph</div>
                </div>
            ) : (
                <div className="card" style={{ padding: 16 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
                        <div style={{ fontSize: 13, color: "var(--text-secondary)" }}>
                            💡 <b>Tip:</b> Click nodes to view details. Drag to rearrange. Graph shows {graphData.nodes?.length} nodes.
                        </div>
                        <div style={{ display: "flex", gap: 10 }}>
                            <button className="btn btn-primary btn-sm" style={{ background: "linear-gradient(45deg, #f00, #ff00ff)", border: "none" }}
                                onClick={() => alert("Simulating attack path... Nodes will pulse based on exploit narrative.")}>
                                ⚡ Play Attack Simulation
                            </button>
                        </div>
                    </div>
                    <GraphCanvas graphData={graphData} />
                </div>
            )}
        </div>
    );
}

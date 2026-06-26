import { useState, useEffect } from 'react';
import * as api from '../api.js';

const TaskMonitor = () => {
    const [tasks, setTasks] = useState([]);
    const [workers, setWorkers] = useState({});
    const [broker, setBroker] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const fetchData = async () => {
        try {
            // Using Proxy to bypass CORS/Auth
            const data = await api.request("GET", `${api.FLOWER_BASE}/tasks?limit=20`);
            const workerData = await api.request("GET", `${api.FLOWER_BASE}/workers`);
            const brokerData = await api.request("GET", `${api.FLOWER_BASE}/broker`);

            if (data?.error) {
                setError(data.error);
                setTasks([]);
            } else {
                setTasks(Object.values(data || {}));
                setError(null);
            }
            setWorkers(workerData || {});
            setBroker(brokerData || null);
        } catch (err) {
            console.error("Task monitor polling error:", err);
            setError(err.message || "Could not connect to Flower service.");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 4000);
        return () => clearInterval(interval);
    }, []);

    const getStatusColor = (status) => {
        switch (status?.toUpperCase()) {
            case 'SUCCESS': return 'status-success';
            case 'STARTED': return 'status-running';
            case 'FAILURE': return 'status-failed';
            case 'RECEIVED': return 'status-pending';
            default: return 'status-info';
        }
    };

    return (
        <div className="fade-in">
            <div className="page-header">
                <div>
                    <div className="page-title"><span>📡</span> Task Monitor</div>
                    <div className="page-subtitle">Real-time background scanning orchestration & cluster health</div>
                </div>
                <div style={{ display: "flex", gap: 10 }}>
                    <div className="stat-card" style={{ padding: "10px 16px", minWidth: 160 }}>
                        <div className="stat-label" style={{ marginTop: 0 }}>Cluster Status</div>
                        <div className="stat-value" style={{ fontSize: 18, color: "var(--green)" }}>ONLINE</div>
                    </div>
                </div>
            </div>

            {error && (
                <div className="alert alert-error" style={{ marginBottom: 24 }}>
                    ⚠️ {error}
                </div>
            )}

            {/* Top Bar Stats */}
            <div className="stats-grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))" }}>
                <div className="stat-card">
                    <div className="stat-icon" style={{ background: "rgba(16, 185, 129, 0.1)", color: "var(--green)" }}>🔗</div>
                    <div>
                        <div className="stat-value">{broker?.active_queues?.length || 0}</div>
                        <div className="stat-label">Active Broker Pipes</div>
                    </div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon" style={{ background: "rgba(99, 102, 241, 0.1)", color: "var(--accent-light)" }}>⚙️</div>
                    <div>
                        <div className="stat-value">{Object.keys(workers).length}</div>
                        <div className="stat-label">Online Workers</div>
                    </div>
                </div>
                <div className="stat-card">
                    <div className="stat-icon" style={{ background: "rgba(6, 182, 212, 0.1)", color: "var(--cyan)" }}>📈</div>
                    <div>
                        <div className="stat-value">{tasks.length}</div>
                        <div className="stat-label">Tasks in Registry</div>
                    </div>
                </div>
            </div>

            {/* Task Table */}
            <div className="card" style={{ padding: 0, overflow: "hidden" }}>
                <div className="card-title" style={{ padding: "20px 24px", margin: 0, borderBottom: "1px solid var(--border)" }}>
                    🏃 Active & Recent Tasks
                </div>
                <div className="table-container" style={{ border: "none", borderRadius: 0 }}>
                    <table>
                        <thead>
                            <tr>
                                <th>Process Module</th>
                                <th>Reference ID</th>
                                <th>Status</th>
                                <th>Runtime Context</th>
                                <th>Started At</th>
                            </tr>
                        </thead>
                        <tbody>
                            {tasks.length === 0 && !loading && (
                                <tr>
                                    <td colSpan="5" style={{ textAlign: "center", padding: 60, color: "var(--text-muted)" }}>
                                        <div style={{ fontSize: 40, marginBottom: 12 }}>📡</div>
                                        Awaiting task dispatch...
                                    </td>
                                </tr>
                            )}
                            {tasks.map((task) => (
                                <tr key={task?.uuid || Math.random()}>
                                    <td style={{ fontWeight: 700, color: "var(--text-primary)" }}>
                                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                            <div style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--accent)" }}></div>
                                            {task?.name?.split('.').pop()?.toUpperCase() || 'TASK'}
                                        </div>
                                    </td>
                                    <td className="mono">{task?.uuid?.split('-')[0] || 'N/A'}</td>
                                    <td>
                                        <span className={`status-pill status-${task?.state?.toLowerCase() === 'success' ? 'completed' : task?.state?.toLowerCase() === 'failure' ? 'failed' : 'running'}`}>
                                            {task?.state || 'UNKNOWN'}
                                        </span>
                                    </td>
                                    <td>
                                        <div style={{
                                            fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--text-secondary)",
                                            background: "rgba(0,0,0,0.2)", padding: "4px 8px", borderRadius: 4,
                                            maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"
                                        }}>
                                            {task?.args || '[]'}
                                        </div>
                                    </td>
                                    <td className="mono" style={{ fontSize: 12 }}>
                                        {task.started ? new Date(task.started * 1000).toLocaleTimeString() : 'PENDING'}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
                <div style={{ padding: "16px 24px", background: "rgba(0,0,0,0.1)", borderTop: "1px solid var(--border)", display: "flex", gap: 20 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11, fontWeight: 700, color: "var(--green)" }}>
                        <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--green)" }}></span> SUCCESS
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11, fontWeight: 700, color: "var(--cyan)" }}>
                        <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--cyan)" }}></span> RUNNING
                    </div>
                    <div style={{ marginLeft: "auto", fontSize: 10, color: "var(--text-muted)", fontWeight: 700, letterSpacing: 1 }}>
                        SERVICE SYNCHRONIZATION ACTIVE
                    </div>
                </div>
            </div>
        </div>
    );
};

export default TaskMonitor;

import { useState, useEffect, useCallback } from "react";
import { Users, Shield, Eye, Pencil, Trash2, RefreshCw, Crown, UserCheck, UserX, Building2 } from "lucide-react";
import * as api from "../api.js";

const ROLE_META = {
    admin: {
        label: "Admin",
        icon: Crown,
        color: "#f59e0b",
        bg: "rgba(245,158,11,0.10)",
        desc: "Full access — can manage team, launch scans, view all data."
    },
    analyst: {
        label: "Analyst",
        icon: UserCheck,
        color: "#6366f1",
        bg: "rgba(99,102,241,0.10)",
        desc: "Can create and run scans, view results."
    },
    viewer: {
        label: "Viewer",
        icon: Eye,
        color: "#64748b",
        bg: "rgba(100,116,139,0.10)",
        desc: "Read-only access to all results."
    }
};

function RoleBadge({ role }) {
    const meta = ROLE_META[role] || ROLE_META.viewer;
    const IconComp = meta.icon;
    return (
        <span style={{
            display: "inline-flex", alignItems: "center", gap: 5,
            background: meta.bg, color: meta.color,
            borderRadius: 20, padding: "3px 10px", fontSize: 12, fontWeight: 600
        }}>
            <IconComp size={12} />
            {meta.label}
        </span>
    );
}

export default function TeamManagement({ user }) {
    const [members, setMembers] = useState([]);
    const [orgName, setOrgName] = useState("");
    const [myRole, setMyRole] = useState("analyst");
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [editingUser, setEditingUser] = useState(null);
    const [newRole, setNewRole] = useState("");
    const [saving, setSaving] = useState(false);
    const [notification, setNotification] = useState(null);

    // Add Member states
    const [addUsername, setAddUsername] = useState("");
    const [addRole, setAddRole] = useState("analyst");
    const [addingMember, setAddingMember] = useState(false);

    const notify = (msg, type = "success") => {
        setNotification({ msg, type });
        setTimeout(() => setNotification(null), 3500);
    };

    const fetchData = useCallback(async () => {
        setLoading(true);
        setError("");
        try {
            const [membersRes, meRes] = await Promise.all([
                api.get("/org/members"),
                api.get("/org/me")
            ]);
            setMembers(membersRes.members || []);
            setOrgName(membersRes.org_name || meRes.org_name || "Organization");
            setMyRole(meRes.role || "analyst");
        } catch (e) {
            setError(e.message || "Failed to load team data");
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { fetchData(); }, [fetchData]);

    const handleUpdateRole = async () => {
        if (!editingUser || !newRole) return;
        setSaving(true);
        try {
            await api.request("PUT", `/org/members/${editingUser}/role`, { role: newRole });
            notify(`Role updated to '${newRole}' for ${editingUser}`);
            setEditingUser(null);
            fetchData();
        } catch (e) {
            notify(e.message || "Failed to update role", "error");
        } finally {
            setSaving(false);
        }
    };

    const handleRemoveMember = async (username) => {
        if (!window.confirm(`Remove ${username} from the organization?`)) return;
        try {
            await api.request("DELETE", `/org/members/${username}`);
            notify(`${username} removed from organization`);
            fetchData();
        } catch (e) {
            notify(e.message || "Failed to remove member", "error");
        }
    };

    const handleAddMember = async () => {
        if (!addUsername.trim()) return;
        setAddingMember(true);
        try {
            await api.request("POST", "/org/members", { username: addUsername, role: addRole });
            notify(`Successfully added ${addUsername} to organization`);
            setAddUsername("");
            setAddRole("analyst");
            fetchData();
        } catch (e) {
            notify(e.message || "Failed to add member", "error");
        } finally {
            setAddingMember(false);
        }
    };

    const isAdmin = myRole === "admin";

    return (
        <div style={{ padding: "32px 40px", maxWidth: 860, margin: "0 auto" }}>
            {/* Header */}
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 28 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
                    <div style={{
                        width: 44, height: 44, background: "rgba(99,102,241,0.12)",
                        borderRadius: 12, display: "flex", alignItems: "center", justifyContent: "center"
                    }}>
                        <Users size={22} color="var(--accent)" />
                    </div>
                    <div>
                        <h1 style={{ margin: 0, fontSize: 22, fontWeight: 700, color: "var(--text-primary)" }}>
                            Team Management
                        </h1>
                        <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 3 }}>
                            <Building2 size={13} color="var(--text-muted)" />
                            <span style={{ fontSize: 13, color: "var(--text-secondary)" }}>{orgName}</span>
                            <span style={{ color: "var(--border)", margin: "0 4px" }}>•</span>
                            <RoleBadge role={myRole} />
                        </div>
                    </div>
                </div>
                <button
                    onClick={fetchData}
                    style={{
                        background: "var(--surface)", border: "1px solid var(--border)",
                        color: "var(--text-secondary)", borderRadius: 8, padding: "8px 14px",
                        cursor: "pointer", display: "flex", alignItems: "center", gap: 6, fontSize: 13
                    }}
                >
                    <RefreshCw size={14} /> Refresh
                </button>
            </div>

            {/* Toast notification */}
            {notification && (
                <div style={{
                    position: "fixed", top: 24, right: 24, zIndex: 9999,
                    background: notification.type === "error" ? "#dc2626" : "#16a34a",
                    color: "#fff", padding: "12px 20px", borderRadius: 10,
                    fontSize: 14, fontWeight: 500, boxShadow: "0 4px 20px rgba(0,0,0,0.15)",
                    display: "flex", alignItems: "center", gap: 8
                }}>
                    {notification.type === "error" ? <UserX size={16} /> : <UserCheck size={16} />}
                    {notification.msg}
                </div>
            )}

            {/* Role Legend */}
            <div style={{
                display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12, marginBottom: 28
            }}>
                {Object.entries(ROLE_META).map(([key, meta]) => {
                    const Icon = meta.icon;
                    return (
                        <div key={key} style={{
                            background: "var(--surface)", border: "1px solid var(--border)",
                            borderRadius: 10, padding: "14px 16px", display: "flex", alignItems: "flex-start", gap: 10
                        }}>
                            <div style={{
                                width: 32, height: 32, background: meta.bg, borderRadius: 8,
                                display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0
                            }}>
                                <Icon size={16} color={meta.color} />
                            </div>
                            <div>
                                <div style={{ fontWeight: 600, fontSize: 13, color: meta.color }}>{meta.label}</div>
                                <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2, lineHeight: 1.4 }}>{meta.desc}</div>
                            </div>
                        </div>
                    );
                })}
            </div>

            {/* Error */}
            {error && (
                <div style={{ background: "rgba(220,38,38,0.08)", border: "1px solid rgba(220,38,38,0.25)", borderRadius: 10, padding: "12px 16px", color: "#dc2626", marginBottom: 20, fontSize: 14 }}>
                    {error}
                </div>
            )}

            {/* Add Member Form (Admins only) */}
            {isAdmin && (
                <div style={{
                    background: "var(--surface)", border: "1px solid var(--border)",
                    borderRadius: 12, padding: "20px 24px", marginBottom: 28
                }}>
                    <h3 style={{ margin: "0 0 14px 0", fontSize: 15, fontWeight: 600, color: "var(--text-primary)", display: "flex", alignItems: "center", gap: 6 }}>
                        <Users size={16} color="var(--accent)" /> Add Team Member
                    </h3>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 12, alignItems: "flex-end" }}>
                        <div style={{ flex: 1, minWidth: 200 }}>
                            <label style={{ display: "block", fontSize: 11, fontWeight: 600, color: "var(--text-muted)", marginBottom: 6, textTransform: "uppercase" }}>Username</label>
                            <input
                                type="text"
                                placeholder="Enter username of registered user"
                                value={addUsername}
                                onChange={e => setAddUsername(e.target.value)}
                                style={{
                                    width: "100%", background: "var(--bg)", border: "1px solid var(--border)",
                                    borderRadius: 8, padding: "8px 12px", fontSize: 13, color: "var(--text-primary)",
                                    boxSizing: "border-box"
                                }}
                            />
                        </div>
                        <div style={{ width: 140 }}>
                            <label style={{ display: "block", fontSize: 11, fontWeight: 600, color: "var(--text-muted)", marginBottom: 6, textTransform: "uppercase" }}>Initial Role</label>
                            <select
                                value={addRole}
                                onChange={e => setAddRole(e.target.value)}
                                style={{
                                    width: "100%", background: "var(--bg)", border: "1px solid var(--border)",
                                    borderRadius: 8, padding: "8px 12px", fontSize: 13, color: "var(--text-primary)", cursor: "pointer",
                                    boxSizing: "border-box"
                                }}
                            >
                                <option value="analyst">Analyst</option>
                                <option value="viewer">Viewer</option>
                                <option value="admin">Admin</option>
                            </select>
                        </div>
                        <button
                            onClick={handleAddMember}
                            disabled={addingMember}
                            style={{
                                background: "var(--accent)", color: "#fff", border: "none",
                                borderRadius: 8, padding: "9px 20px", fontSize: 13, fontWeight: 600,
                                cursor: "pointer", height: 38
                            }}
                        >
                            {addingMember ? "Adding…" : "Add Member"}
                        </button>
                    </div>
                </div>
            )}

            {/* Member table */}
            <div style={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 12, overflow: "hidden" }}>
                <div style={{ padding: "14px 20px", borderBottom: "1px solid var(--border)", display: "flex", alignItems: "center", gap: 8 }}>
                    <Shield size={15} color="var(--text-muted)" />
                    <span style={{ fontSize: 13, fontWeight: 600, color: "var(--text-secondary)" }}>
                        {loading ? "Loading…" : `${members.length} member${members.length !== 1 ? "s" : ""}`}
                    </span>
                </div>

                {loading ? (
                    <div style={{ padding: 40, textAlign: "center", color: "var(--text-muted)", fontSize: 14 }}>
                        <RefreshCw size={20} style={{ animation: "spin 1s linear infinite", marginBottom: 10 }} />
                        <div>Loading team members…</div>
                    </div>
                ) : members.length === 0 ? (
                    <div style={{ padding: 40, textAlign: "center", color: "var(--text-muted)", fontSize: 14 }}>
                        <Users size={32} style={{ marginBottom: 10, opacity: 0.4 }} />
                        <div>No members found in your organization.</div>
                    </div>
                ) : (
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                        <thead>
                            <tr style={{ background: "rgba(0,0,0,0.02)" }}>
                                {["User", "Email", "Role", isAdmin && "Actions"].filter(Boolean).map(h => (
                                    <th key={h} style={{
                                        textAlign: "left", padding: "10px 20px",
                                        fontSize: 11, fontWeight: 700, textTransform: "uppercase",
                                        letterSpacing: "0.5px", color: "var(--text-muted)",
                                        borderBottom: "1px solid var(--border)"
                                    }}>{h}</th>
                                ))}
                            </tr>
                        </thead>
                        <tbody>
                            {members.map((m, i) => (
                                <tr key={m.username} style={{
                                    borderBottom: i < members.length - 1 ? "1px solid var(--border)" : "none",
                                    background: m.username === user ? "rgba(99,102,241,0.03)" : "transparent"
                                }}>
                                    <td style={{ padding: "14px 20px" }}>
                                        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                                            <div style={{
                                                width: 34, height: 34, borderRadius: "50%",
                                                background: "rgba(99,102,241,0.15)",
                                                display: "flex", alignItems: "center", justifyContent: "center",
                                                fontWeight: 700, fontSize: 14, color: "var(--accent)", flexShrink: 0
                                            }}>
                                                {m.username?.[0]?.toUpperCase() || "?"}
                                            </div>
                                            <div>
                                                <div style={{ fontSize: 14, fontWeight: 600, color: "var(--text-primary)" }}>
                                                    {m.username}
                                                    {m.username === user && (
                                                        <span style={{ fontSize: 10, marginLeft: 6, color: "var(--accent)", fontWeight: 500 }}>(you)</span>
                                                    )}
                                                </div>
                                            </div>
                                        </div>
                                    </td>
                                    <td style={{ padding: "14px 20px", fontSize: 13, color: "var(--text-secondary)" }}>
                                        {m.email || <span style={{ color: "var(--text-muted)" }}>—</span>}
                                    </td>
                                    <td style={{ padding: "14px 20px" }}>
                                        {editingUser === m.username ? (
                                            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                                <select
                                                    value={newRole}
                                                    onChange={e => setNewRole(e.target.value)}
                                                    style={{
                                                        background: "var(--bg)", border: "1px solid var(--border)",
                                                        borderRadius: 6, padding: "5px 8px", fontSize: 13,
                                                        color: "var(--text-primary)", cursor: "pointer"
                                                    }}
                                                >
                                                    <option value="admin">Admin</option>
                                                    <option value="analyst">Analyst</option>
                                                    <option value="viewer">Viewer</option>
                                                </select>
                                                <button
                                                    onClick={handleUpdateRole}
                                                    disabled={saving}
                                                    style={{
                                                        background: "var(--accent)", border: "none", color: "#fff",
                                                        borderRadius: 6, padding: "5px 10px", fontSize: 12,
                                                        cursor: "pointer", fontWeight: 600
                                                    }}
                                                >
                                                    {saving ? "…" : "Save"}
                                                </button>
                                                <button
                                                    onClick={() => setEditingUser(null)}
                                                    style={{
                                                        background: "transparent", border: "1px solid var(--border)",
                                                        color: "var(--text-muted)", borderRadius: 6,
                                                        padding: "5px 10px", fontSize: 12, cursor: "pointer"
                                                    }}
                                                >
                                                    Cancel
                                                </button>
                                            </div>
                                        ) : (
                                            <RoleBadge role={m.role} />
                                        )}
                                    </td>
                                    {isAdmin && (
                                        <td style={{ padding: "14px 20px" }}>
                                            {m.username !== user && editingUser !== m.username && (
                                                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                                    <button
                                                        onClick={() => { setEditingUser(m.username); setNewRole(m.role); }}
                                                        title="Change role"
                                                        style={{
                                                            background: "rgba(99,102,241,0.10)", border: "none",
                                                            color: "var(--accent)", borderRadius: 7, padding: "6px 10px",
                                                            cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 5, fontSize: 12, fontWeight: 500
                                                        }}
                                                    >
                                                        <Pencil size={12} /> Edit Role
                                                    </button>
                                                    <button
                                                        onClick={() => handleRemoveMember(m.username)}
                                                        title="Remove from org"
                                                        style={{
                                                            background: "rgba(220,38,38,0.08)", border: "none",
                                                            color: "#dc2626", borderRadius: 7, padding: "6px 10px",
                                                            cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 5, fontSize: 12, fontWeight: 500
                                                        }}
                                                    >
                                                        <Trash2 size={12} /> Remove
                                                    </button>
                                                </div>
                                            )}
                                            {m.username === user && (
                                                <span style={{ fontSize: 12, color: "var(--text-muted)", fontStyle: "italic" }}>—</span>
                                            )}
                                        </td>
                                    )}
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            {!isAdmin && (
                <div style={{ marginTop: 16, padding: "10px 16px", background: "rgba(99,102,241,0.06)", border: "1px solid rgba(99,102,241,0.15)", borderRadius: 8, fontSize: 13, color: "var(--text-secondary)" }}>
                    <Shield size={13} style={{ marginRight: 6, verticalAlign: "middle" }} />
                    Only <strong>Admins</strong> can modify team roles or remove members.
                </div>
            )}
        </div>
    );
}

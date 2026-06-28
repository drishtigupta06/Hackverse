import { useState, useEffect } from "react";
import * as api from "../api.js";
import { User, Lock, Shield, Building2, Mail, CheckCircle, AlertCircle } from "lucide-react";

export default function ProfilePage({ user }) {
    const [profile, setProfile] = useState(null);
    const [loading, setLoading] = useState(true);

    // Change password form state
    const [currentPwd, setCurrentPwd] = useState("");
    const [newPwd, setNewPwd] = useState("");
    const [confirmPwd, setConfirmPwd] = useState("");
    const [pwdLoading, setPwdLoading] = useState(false);
    const [success, setSuccess] = useState("");
    const [error, setError] = useState("");

    useEffect(() => {
        api.getMe().then(data => {
            setProfile(data);
            setLoading(false);
        }).catch(() => setLoading(false));
    }, []);

    const handleChangePassword = async (e) => {
        e.preventDefault();
        setSuccess("");
        setError("");

        if (newPwd !== confirmPwd) {
            setError("New passwords do not match.");
            return;
        }
        if (newPwd.length < 6) {
            setError("New password must be at least 6 characters.");
            return;
        }

        setPwdLoading(true);
        try {
            const res = await api.request("POST", "/auth/change-password", {
                current_password: currentPwd,
                new_password: newPwd,
            });
            setSuccess(res.message || "Password changed successfully!");
            setCurrentPwd(""); setNewPwd(""); setConfirmPwd("");
        } catch (err) {
            setError(err.message || "Failed to change password.");
        } finally {
            setPwdLoading(false);
        }
    };

    const ROLE_COLORS = { admin: "#f59e0b", analyst: "#6366f1", viewer: "#64748b" };
    const ROLE_LABELS = { admin: "Administrator", analyst: "Security Analyst", viewer: "Read-Only Viewer" };

    return (
        <div className="fade-in" style={{ maxWidth: 700, margin: "0 auto" }}>
            {/* Page header */}
            <div className="page-header" style={{ marginBottom: 32 }}>
                <div>
                    <div className="page-title">
                        <User size={24} style={{ color: "var(--accent)" }} />
                        My Profile
                    </div>
                    <div className="page-subtitle">Manage your account settings and security</div>
                </div>
            </div>

            {/* Profile Info Card */}
            <div className="card" style={{ marginBottom: 24 }}>
                <div className="card-title">
                    <User size={16} style={{ color: "var(--accent)" }} />
                    Account Information
                </div>
                {loading ? (
                    <div className="loading-center"><div className="spinner" /></div>
                ) : profile ? (
                    <div style={{ display: "grid", gap: 16 }}>
                        {/* Avatar + name row */}
                        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
                            <div style={{
                                width: 64, height: 64,
                                borderRadius: "50%",
                                background: "linear-gradient(135deg, var(--accent), var(--cyan))",
                                display: "flex", alignItems: "center", justifyContent: "center",
                                fontSize: 26, fontWeight: 800, color: "#fff",
                                flexShrink: 0
                            }}>
                                {profile.username?.[0]?.toUpperCase()}
                            </div>
                            <div>
                                <div style={{ fontSize: 20, fontWeight: 700, color: "var(--text-primary)" }}>
                                    {profile.username}
                                </div>
                                <div style={{
                                    display: "inline-flex", alignItems: "center", gap: 5, marginTop: 4,
                                    fontSize: 12, fontWeight: 700, padding: "3px 10px", borderRadius: 100,
                                    background: `${ROLE_COLORS[profile.role] || "#6366f1"}22`,
                                    color: ROLE_COLORS[profile.role] || "var(--accent)",
                                    border: `1px solid ${ROLE_COLORS[profile.role] || "var(--accent)"}44`
                                }}>
                                    <Shield size={11} />
                                    {ROLE_LABELS[profile.role] || profile.role}
                                </div>
                            </div>
                        </div>

                        {/* Details */}
                        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, paddingTop: 8, borderTop: "1px solid var(--border)" }}>
                            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                <Mail size={14} style={{ color: "var(--text-muted)" }} />
                                <div>
                                    <div style={{ fontSize: 10, color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.5px" }}>Email</div>
                                    <div style={{ fontSize: 13, color: "var(--text-secondary)", marginTop: 2 }}>{profile.email || "—"}</div>
                                </div>
                            </div>
                            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                <Building2 size={14} style={{ color: "var(--text-muted)" }} />
                                <div>
                                    <div style={{ fontSize: 10, color: "var(--text-muted)", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.5px" }}>Organization</div>
                                    <div style={{ fontSize: 13, color: "var(--text-secondary)", marginTop: 2 }}>{profile.org_name || "—"}</div>
                                </div>
                            </div>
                        </div>
                    </div>
                ) : (
                    <div className="empty-state">Could not load profile.</div>
                )}
            </div>

            {/* Change Password Card */}
            <div className="card">
                <div className="card-title">
                    <Lock size={16} style={{ color: "var(--accent)" }} />
                    Change Password
                </div>

                {success && (
                    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 14px", background: "rgba(16,185,129,0.08)", border: "1px solid rgba(16,185,129,0.25)", borderRadius: 8, color: "#047857", fontSize: 13, fontWeight: 500, marginBottom: 16 }}>
                        <CheckCircle size={15} /> {success}
                    </div>
                )}
                {error && (
                    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 14px", background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.25)", borderRadius: 8, color: "#b91c1c", fontSize: 13, fontWeight: 500, marginBottom: 16 }}>
                        <AlertCircle size={15} /> {error}
                    </div>
                )}

                <form onSubmit={handleChangePassword} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                    <div className="input-group">
                        <label className="input-label">Current Password</label>
                        <input
                            className="input"
                            type="password"
                            placeholder="Enter current password"
                            value={currentPwd}
                            onChange={e => setCurrentPwd(e.target.value)}
                            required
                        />
                    </div>
                    <div className="input-group">
                        <label className="input-label">New Password</label>
                        <input
                            className="input"
                            type="password"
                            placeholder="At least 6 characters"
                            value={newPwd}
                            onChange={e => setNewPwd(e.target.value)}
                            required
                        />
                    </div>
                    <div className="input-group">
                        <label className="input-label">Confirm New Password</label>
                        <input
                            className="input"
                            type="password"
                            placeholder="Re-enter new password"
                            value={confirmPwd}
                            onChange={e => setConfirmPwd(e.target.value)}
                            required
                        />
                    </div>
                    <button
                        type="submit"
                        className="btn btn-primary"
                        disabled={pwdLoading}
                        style={{ alignSelf: "flex-start", marginTop: 4 }}
                    >
                        <Lock size={14} />
                        {pwdLoading ? "Updating..." : "Change Password"}
                    </button>
                </form>
            </div>
        </div>
    );
}

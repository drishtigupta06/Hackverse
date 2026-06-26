const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8002";
const WS_BASE = API_BASE.replace(/^http/, "ws");
export const FLOWER_BASE = "/proxy/flower";

function getToken() {
    return localStorage.getItem("cg_token");
}

function authHeaders() {
    const token = getToken();
    return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function request(method, path, body = null, isBlob = false) {
    const isFormData = body instanceof FormData;
    const opts = {
        method,
        headers: { ...authHeaders() },
    };
    if (!isFormData) {
        opts.headers["Content-Type"] = "application/json";
    }
    if (body) {
        opts.body = isFormData ? body : JSON.stringify(body);
    }
    const resp = await fetch(`${API_BASE}${path}`, opts);
    if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        throw new Error(err.detail || `HTTP ${resp.status}`);
    }
    if (isBlob) return resp.blob();
    return resp.json();
}

export async function get(path, isBlob = false) {
    return request("GET", path, null, isBlob);
}

export async function post(path, body) {
    return request("POST", path, body);
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

export async function login(username, password) {
    const form = new URLSearchParams({ username, password });
    const resp = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form,
    });
    if (!resp.ok) {
        const e = await resp.json().catch(() => ({}));
        throw new Error(e.detail || "Login failed");
    }
    const data = await resp.json();
    localStorage.setItem("cg_token", data.access_token);
    return data;
}

export async function register(username, password, email = "") {
    return request("POST", "/auth/register", { username, password, email });
}

export function logout() {
    localStorage.removeItem("cg_token");
}

export function isLoggedIn() {
    return !!getToken();
}

export async function getMe() {
    return request("GET", "/auth/me");
}

// ─── Stats ────────────────────────────────────────────────────────────────────

export async function getStats() {
    return request("GET", "/stats");
}

// ─── Scans ────────────────────────────────────────────────────────────────────

export async function createScan(target, scan_types = ["nmap"], description = "") {
    return request("POST", "/scans", { target, scan_types, description });
}

export async function listScans(limit = 20, skip = 0) {
    return request("GET", `/scans?limit=${limit}&skip=${skip}`);
}

export async function getScan(scanId) {
    return request("GET", `/scans/${scanId}`);
}

export async function getScanHosts(scanId) {
    return request("GET", `/scans/${scanId}/hosts`);
}

export async function getScanVulnerabilities(scanId, filters = {}) {
    const params = new URLSearchParams({ limit: 200, ...filters });
    return request("GET", `/scans/${scanId}/vulnerabilities?${params}`);
}

export async function getAttackGraph(scanId) {
    return request("GET", `/scans/${scanId}/graph`);
}

export async function downloadReport(scanId) {
    return request("GET", `/scans/${scanId}/report`, null, true);
}

export async function listLLMJobs(limit = 20, skip = 0) {
    return request("GET", `/llm/jobs?limit=${limit}&skip=${skip}`);
}

export async function downloadLLMReport(scanId) {
    return request("GET", `/llm/${scanId}/report`, null, true);
}

export async function listMobileScans(limit = 20, skip = 0) {
    return request("GET", `/mobile/jobs?limit=${limit}&skip=${skip}`);
}

export async function downloadMobileReport(scanId) {
    return request("GET", `/mobile/${scanId}/report`, null, true);
}

export async function runDemoScan() {
    return request("POST", "/demo/scan-localhost");
}

// ─── Vulnerabilities ──────────────────────────────────────────────────────────

export async function listVulnerabilities(filters = {}) {
    const params = new URLSearchParams({ limit: 100, ...filters });
    return request("GET", `/vulnerabilities?${params}`);
}

// ─── Chat ─────────────────────────────────────────────────────────────────────

export async function sendChat(question, scan_id = null) {
    return request("POST", "/chat", { question, scan_id });
}

export async function getChatHistory(limit = 50) {
    return request("GET", `/chat/history?limit=${limit}`);
}

// ─── CVE Lookup ───────────────────────────────────────────────────────────────

export async function lookupCVE(cveId) {
    return request("GET", `/cve/${encodeURIComponent(cveId)}`);
}

// ─── Scan Management ──────────────────────────────────────────────────────────

export async function deleteScan(scanId) {
    const resp = await fetch(`${API_BASE}/scans/${scanId}`, {
        method: "DELETE",
        headers: { ...authHeaders() },
    });
    if (!resp.ok && resp.status !== 204) {
        const e = await resp.json().catch(() => ({}));
        throw new Error(e.detail || `HTTP ${resp.status}`);
    }
    return true;
}

// ─── WebSocket ────────────────────────────────────────────────────────────────

export function connectScanWS(scanId, onMessage) {
    const ws = new WebSocket(`${WS_BASE}/ws/scans/${scanId}`);
    ws.onopen = () => console.log(`[ws] Connected to scan ${scanId}`);
    ws.onmessage = (e) => {
        try { onMessage(JSON.parse(e.data)); } catch { }
    };
    ws.onerror = (e) => console.warn("[ws] error", e);
    return ws;
}

// ─── Hackathon Endpoints ───────────────────────────────────────────────────

export async function startHackerMode(target_domain) {
    return request("POST", "/api/v1/agent/hacker-mode", { target_domain });
}

export async function getAttackScenario(scanId) {
    return request("GET", `/api/v1/agent/simulator/${scanId}`);
}

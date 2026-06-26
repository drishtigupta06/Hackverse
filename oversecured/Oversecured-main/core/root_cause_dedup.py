"""
Root Cause Dedup — Group 1059 findings into ROOT-001, ROOT-002, ...
User sees one bug, not 25 symptoms.
"""

ROOT_CAUSES = [
    {
        "id": "ROOT-001",
        "title": "Exported Activity allows Intent Injection",
        "matches": ["MF-007", "ADV-001", "ADV-012", "ADV-016", "CG-003"],
        "severity": "CRITICAL",
        "impact": "Any app can launch this activity and inject malicious intents, leading to data theft or privilege escalation",
        "exploit_vector": "adb",
    },
    {
        "id": "ROOT-002",
        "title": "Exported Service without Permission",
        "matches": ["MF-008", "ADV-002", "CG-004"],
        "severity": "HIGH",
        "impact": "Any app can bind to or start this service, potentially accessing sensitive functionality",
        "exploit_vector": "adb",
    },
    {
        "id": "ROOT-003",
        "title": "Exported Broadcast Receiver without Permission",
        "matches": ["MF-009", "ADV-008", "ADV-011", "CG-005"],
        "severity": "HIGH",
        "impact": "Any app can send broadcasts to this receiver, potentially triggering unintended behavior",
        "exploit_vector": "adb",
    },
    {
        "id": "ROOT-004",
        "title": "Exported ContentProvider without Permission",
        "matches": ["MF-010", "MF-011", "ADV-037", "SRC-058"],
        "severity": "CRITICAL",
        "impact": "Any app can read/write provider data; SQL injection may allow data exfiltration",
        "exploit_vector": "drozer",
    },
    {
        "id": "ROOT-005",
        "title": "WebView with JavaScript and Untrusted Input",
        "matches": ["SRC-031", "SRC-032", "SRC-121", "ADV-005", "ADV-006"],
        "severity": "CRITICAL",
        "impact": "XSS or RCE via WebView; attacker can execute arbitrary JavaScript in app context",
        "exploit_vector": "frida",
    },
    {
        "id": "ROOT-006",
        "title": "Insecure Data Storage (SharedPrefs / SQLite / Files)",
        "matches": ["SRC-013", "SRC-014", "SRC-015", "SRC-129", "SRC-017"],
        "severity": "HIGH",
        "impact": "Sensitive data stored in world-readable locations; any app with file access can steal it",
        "exploit_vector": "adb",
    },
    {
        "id": "ROOT-007",
        "title": "Hardcoded Secrets (Keys / Tokens / Passwords)",
        "matches": ["SRC-001", "SRC-002", "SRC-009", "SRC-153", "SRC-155"],
        "severity": "CRITICAL",
        "impact": "Hardcoded credentials enable unauthorized access to backend services or encryption",
        "exploit_vector": "adb",
    },
    {
        "id": "ROOT-008",
        "title": "Debuggable Application with Backup Enabled",
        "matches": ["MF-001", "MF-004", "MF-036", "MF-063"],
        "severity": "HIGH",
        "impact": "ADB debugging and full backup allow data extraction and code injection",
        "exploit_vector": "adb",
    },
    {
        "id": "ROOT-009",
        "title": "Cleartext Network Traffic",
        "matches": ["MF-003", "SRC-022", "ADV-MITM-*"],
        "severity": "HIGH",
        "impact": "HTTP traffic can be intercepted via MITM; credentials and tokens exposed",
        "exploit_vector": "frida",
    },
    {
        "id": "ROOT-010",
        "title": "Command Injection via Runtime.exec",
        "matches": ["SRC-071", "SRC-167", "ADV-300"],
        "severity": "CRITICAL",
        "impact": "Untrusted input flows into shell execution; full device compromise possible",
        "exploit_vector": "adb",
    },
    {
        "id": "ROOT-011",
        "title": "Weak Cryptography (ECB / Hardcoded Key / Custom Crypto)",
        "matches": ["SRC-009", "ADV-CRYPTO-001", "ADV-CRYPTO-002", "ADV-CRYPTO-003"],
        "severity": "HIGH",
        "impact": "Encrypted data can be decrypted by attackers due to weak algorithm or key management",
        "exploit_vector": "frida",
    },
    {
        "id": "ROOT-012",
        "title": "PendingIntent Confusion (Mutable without Immutable)",
        "matches": ["SYS-004", "SYS-005", "SRC-051", "ADV-003"],
        "severity": "HIGH",
        "impact": "Malicious app can modify the PendingIntent's extras, redirecting to unintended component",
        "exploit_vector": "drozer",
    },
    {
        "id": "ROOT-013",
        "title": "DeepLink / URL Scheme without Validation",
        "matches": ["MF-040", "MF-041", "SRC-095", "SRC-151"],
        "severity": "HIGH",
        "impact": "Other apps can launch deep links with crafted data; path traversal or injection possible",
        "exploit_vector": "adb",
    },
    {
        "id": "ROOT-014",
        "title": "System / Signature Privilege Escalation",
        "matches": ["SYS-001", "SYS-002", "SYS-006", "SYS-009", "SYS-010"],
        "severity": "CRITICAL",
        "impact": "App holds system-level permissions without proper caller verification; privilege escalation",
        "exploit_vector": "drozer",
    },
    {
        "id": "ROOT-015",
        "title": "Task Affinity / Activity Hijacking",
        "matches": ["ADV-020", "ADV-024", "SYS-007"],
        "severity": "HIGH",
        "impact": "Malicious app can overlay or replace legitimate activities; credential phishing",
        "exploit_vector": "adb",
    },
    {
        "id": "ROOT-016",
        "title": "Fragment Injection via PreferenceActivity",
        "matches": ["SRC-178", "ADV-025"],
        "severity": "HIGH",
        "impact": "Attacker can inject arbitrary fragments via intent extras; UI manipulation",
        "exploit_vector": "adb",
    },
    {
        "id": "ROOT-017",
        "title": "Dynamic Code Loading (DexClassLoader / WebView RCE)",
        "matches": ["SRC-069", "SRC-121", "SRC-122", "SRC-132"],
        "severity": "CRITICAL",
        "impact": "App loads and executes external code; arbitrary code execution via malicious input",
        "exploit_vector": "frida",
    },
    {
        "id": "ROOT-018",
        "title": "Reflection-Based API Abuse",
        "matches": ["ADV-REFL-001", "ADV-REFL-002", "ADV-REFL-003", "ADV-REFL-101"],
        "severity": "HIGH",
        "impact": "Reflection used to access hidden/private APIs; may bypass platform restrictions",
        "exploit_vector": "frida",
    },
    {
        "id": "ROOT-019",
        "title": "Sensitive Data Leaked via Logging",
        "matches": ["SRC-017", "SRC-074", "ADV-LOG-002"],
        "severity": "MEDIUM",
        "impact": "Sensitive information written to system logs; any app with READ_LOGS can extract it",
        "exploit_vector": "adb",
    },
    {
        "id": "ROOT-020",
        "title": "No Root / Emulator Detection",
        "matches": ["SRC-078", "ADV-021", "ADV-022"],
        "severity": "MEDIUM",
        "impact": "App runs on rooted devices or emulators without detection; security controls bypassed",
        "exploit_vector": "frida",
    },
]


class RootCauseDedup:
    def __init__(self):
        self.roots = {}

    def analyze(self, findings, exploit_results=None, confidence_results=None):
        finding_ids = set()
        finding_map = {}
        for f in findings:
            fid = f.get("id", "")
            if fid:
                finding_ids.add(fid)
            finding_map.setdefault(fid, []).append(f)

        by_vector = {}
        validated_ids = set()
        if exploit_results:
            for er in exploit_results:
                eid = er.get("finding_id", "")
                vectors = er.get("vectors", {})
                by_vector[eid] = list(vectors.keys())
                for vec, vdata in vectors.items():
                    val = vdata.get("validation", {}) or {}
                    if val.get("validated") is True:
                        validated_ids.add(eid)

        confidence_map = {}
        if confidence_results:
            for cr in confidence_results:
                fid = cr.get("finding", {}).get("id", "")
                if fid:
                    confidence_map[fid] = cr["confidence"]["score"]

        output = []
        for rc in ROOT_CAUSES:
            matched = []
            for mid in rc["matches"]:
                for fid in finding_ids:
                    if mid.endswith("*"):
                        prefix = mid[:-1]
                        if fid.startswith(prefix):
                            matched.append(fid)
                    elif fid == mid:
                        matched.append(fid)

            if not matched:
                continue

            raw_confidence = max(confidence_map.get(f, 40) for f in matched)
            validated = any(f in validated_ids for f in matched)
            # Cap at raw_confidence — don't propagate C100 from one finding to the whole group
            if raw_confidence >= 85:
                confidence = 85
            elif raw_confidence >= 75:
                confidence = 75
            elif raw_confidence >= 70:
                confidence = 70
            elif raw_confidence >= 55:
                confidence = 55
            else:
                confidence = 40

            vectors = set()
            for f in matched:
                if f in by_vector:
                    vectors.update(by_vector[f])
            vector = rc["exploit_vector"] if not vectors else list(vectors)[0] if len(vectors) == 1 else "adb"

            entry = {
                "id": rc["id"],
                "title": rc["title"],
                "severity": rc["severity"],
                "impact": rc["impact"],
                "confidence": confidence,
                "validated": validated,
                "exploit_vector": vector,
                "evidence": matched,
                "finding_count": len(matched),
            }
            output.append(entry)

        output.sort(key=lambda x: (-x["confidence"], -x["finding_count"]))
        self.roots = {e["id"]: e for e in output}
        return output

    def get_summary(self):
        verified = sum(1 for r in self.roots.values() if r["validated"])
        total = len(self.roots)
        return {
            "root_causes": total,
            "verified": verified,
            "exploitable": total,
            "average_confidence": round(sum(r["confidence"] for r in self.roots.values()) / max(total, 1)),
        }

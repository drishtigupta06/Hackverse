"""
Root Cause Engine — Deduplicate Multiple Findings into Single Root Cause
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Problem: 1 bug → 5 findings (Exported Activity + Intent Redirection + Activity
         Injection + Attack Chain = actually same root cause)

Solution: Group findings by ROOT CAUSE, show all consequences.

Example:
  Root Cause: Exported Activity with Intent Extras
  └── Consequence 1: Exported Activity (MF-007)
  └── Consequence 2: Intent Redirection (ADV-001)
  └── Consequence 3: Activity Injection (ADV-012)
  └── Consequence 4: Attack Chain (CHAIN-001)
"""

from collections import defaultdict


ROOT_CAUSE_RULES = [
    {
        "root_cause": "Exported Component without Permission",
        "consequence_ids": ["MF-007", "MF-008", "MF-009", "MF-010", "CG-001"],
        "related_ids": ["ADV-001", "ADV-012", "ADV-008", "ADV-016", "MF-011", "MF-073"],
        "chain_ids": ["CHAIN-001", "CHAIN-002", "CHAIN-003", "CHAIN-007", "CHAIN-008", "CHAIN-009"],
        "severity": "CRITICAL",
        "description": "Component is exported without a permission guard, allowing any app to invoke it",
    },
    {
        "root_cause": "WebView with JavaScript Enabled and Untrusted Input",
        "consequence_ids": ["SRC-031", "SRC-032", "SRC-121"],
        "related_ids": ["ADV-005", "ADV-006", "ADV-007", "ADV-028", "CG-002"],
        "chain_ids": ["CHAIN-001", "CHAIN-005"],
        "severity": "CRITICAL",
        "description": "WebView has JavaScript enabled and accepts untrusted input via intent/data",
    },
    {
        "root_cause": "Intent Redirection / Injection",
        "consequence_ids": ["ADV-001", "ADV-002", "ADV-012", "ADV-016"],
        "related_ids": ["MF-007", "MF-008", "MF-009"],
        "chain_ids": ["CHAIN-001", "CHAIN-013"],
        "severity": "HIGH",
        "description": "Untrusted intent data is forwarded to another component without validation",
    },
    {
        "root_cause": "SQL Injection in ContentProvider",
        "consequence_ids": ["SRC-058", "ADV-037", "ADV-500"],
        "related_ids": ["MF-010", "MF-011", "MF-072", "MF-073"],
        "chain_ids": ["CHAIN-002"],
        "severity": "CRITICAL",
        "description": "User-supplied input is used in SQL queries without sanitization",
    },
    {
        "root_cause": "Insecure Data Storage",
        "consequence_ids": ["SRC-013", "SRC-014", "SRC-015", "SRC-129"],
        "related_ids": ["MF-004", "MF-063", "MF-001"],
        "chain_ids": ["CHAIN-006", "CHAIN-012"],
        "severity": "HIGH",
        "description": "Sensitive data stored insecurely (shared_prefs, external storage, world-readable files)",
    },
    {
        "root_cause": "Command Injection via Runtime.exec",
        "consequence_ids": ["SRC-071", "ADV-300", "ADV-301"],
        "related_ids": ["SRC-069"],
        "chain_ids": ["CHAIN-003"],
        "severity": "CRITICAL",
        "description": "Untrusted input flows into Runtime.exec() or ProcessBuilder",
    },
    {
        "root_cause": "PendingIntent with FLAG_MUTABLE",
        "consequence_ids": ["SYS-004", "SYS-005"],
        "related_ids": ["SRC-051", "ADV-003"],
        "chain_ids": ["CHAIN-004"],
        "severity": "HIGH",
        "description": "PendingIntent is mutable and can be hijacked by malicious apps",
    },
    {
        "root_cause": "DeepLink without Input Validation",
        "consequence_ids": ["MF-040", "MF-041", "CG-002"],
        "related_ids": ["SRC-031", "SRC-150"],
        "chain_ids": ["CHAIN-005"],
        "severity": "HIGH",
        "description": "Deep link handler does not validate incoming URIs or parameters",
    },
    {
        "root_cause": "System Privilege Abuse",
        "consequence_ids": ["SYS-001", "SYS-002", "SYS-006", "SYS-009", "SYS-010"],
        "related_ids": ["SYS-003", "SYS-007", "SYS-008"],
        "chain_ids": ["CHAIN-004", "CHAIN-011"],
        "severity": "CRITICAL",
        "description": "App uses system/signature-level privileges without proper caller verification",
    },
    {
        "root_cause": "Broadcast Injection",
        "consequence_ids": ["ADV-008", "ADV-009", "ADV-010", "ADV-011"],
        "related_ids": ["MF-009", "MF-012", "MF-076"],
        "chain_ids": ["CHAIN-007"],
        "severity": "HIGH",
        "description": "Untrusted data is sent as implicit broadcast or via exported receiver",
    },
]


class RootCauseEngine:
    def __init__(self):
        self.root_causes = {}

    def analyze(self, findings):
        self.root_causes = {}
        finding_ids = set()
        finding_map = {}

        for f in findings:
            fid = f.get("id", "")
            if fid:
                finding_ids.add(fid)
            name = f.get("name", "") or f.get("description", "") or ""
            finding_map[fid] = f

        for rule in ROOT_CAUSE_RULES:
            consequences = []
            for cid in rule["consequence_ids"]:
                for fid in finding_ids:
                    if fid.startswith(cid.replace("*", "")):
                        consequences.append(finding_map.get(fid, {"id": fid}))

            related = []
            for rid in rule["related_ids"]:
                for fid in finding_ids:
                    if fid.startswith(rid.replace("*", "")):
                        related.append(finding_map.get(fid, {"id": fid}))

            chains = []
            for chid in rule["chain_ids"]:
                for fid in finding_ids:
                    if fid.startswith(chid):
                        chains.append(finding_map.get(fid, {"id": fid}))

            if consequences or related:
                key = rule["root_cause"]
                if key not in self.root_causes:
                    self.root_causes[key] = {
                        "root_cause": key,
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "consequences": [],
                        "related": [],
                        "chains": [],
                        "total_findings": 0,
                    }
                self.root_causes[key]["consequences"].extend(consequences)
                self.root_causes[key]["related"].extend(related)
                self.root_causes[key]["chains"].extend(chains)
                self.root_causes[key]["total_findings"] = (
                    len(self.root_causes[key]["consequences"]) +
                    len(self.root_causes[key]["related"]) +
                    len(self.root_causes[key]["chains"])
                )

        return list(self.root_causes.values())

    def get_summary(self):
        total = len(self.root_causes)
        original_findings = sum(rc["total_findings"] for rc in self.root_causes.values())
        deduped = total
        reduction = ((original_findings - total) / original_findings * 100) if original_findings > 0 else 0
        return {
            "root_causes": total,
            "original_findings": original_findings,
            "after_dedup": total,
            "reduction_pct": round(reduction, 1),
        }
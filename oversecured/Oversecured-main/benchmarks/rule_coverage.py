"""
Rule Coverage Audit — OWASP Mobile Top 10 / MASVS / Bug Bounty Mapping
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Maps every scanner finding type to industry standards and identifies gaps.
"""

OWASP_MOBILE_TOP_10_2024 = {
    "M1": {"name": "Improper Credential Usage", "finding_ids": ["SRC-001", "SRC-*"]},
    "M2": {"name": "Inadequate Supply Chain Security", "finding_ids": []},
    "M3": {"name": "Insecure Authentication/Authorization", "finding_ids": ["MF-007", "MF-008", "MF-009", "MF-010", "MF-046", "ADV-001", "ADV-012"]},
    "M4": {"name": "Insufficient Input/Output Validation", "finding_ids": ["SRC-058", "SRC-031", "SRC-032", "SRC-071", "SRC-061"]},
    "M5": {"name": "Insecure Communication", "finding_ids": ["MF-003", "SRC-022", "SRC-023", "SRC-038"]},
    "M6": {"name": "Inadequate Privacy Controls", "finding_ids": ["ADV-400", "SRC-090", "SRC-*"]},
    "M7": {"name": "Insufficient Binary Protections", "finding_ids": ["MF-001", "SRC-078"]},
    "M8": {"name": "Security Misconfiguration", "finding_ids": ["MF-004", "MF-011", "MF-052", "MF-056", "MF-073", "MF-040"]},
    "M9": {"name": "Insecure Data Storage", "finding_ids": ["SRC-013", "SRC-014", "SRC-015", "SRC-129", "MF-063"]},
    "M10": {"name": "Insufficient Cryptography", "finding_ids": ["ADV-*"]},
}

MASVS_V2 = {
    "MSTG-STORAGE": {"name": "Data Storage", "finding_ids": ["SRC-013", "SRC-014", "SRC-015", "SRC-129", "MF-004", "MF-063"]},
    "MSTG-CRYPTO": {"name": "Cryptography", "finding_ids": ["ADV-*"]},
    "MSTG-AUTH": {"name": "Authentication/Authorization", "finding_ids": ["MF-007", "MF-008", "MF-009", "MF-010", "ADV-001"]},
    "MSTG-NETWORK": {"name": "Network Communication", "finding_ids": ["MF-003", "SRC-022", "SRC-023", "SRC-038"]},
    "MSTG-PLATFORM": {"name": "Platform Interaction", "finding_ids": ["MF-007", "MF-008", "MF-009", "MF-010", "MF-011", "MF-040", "MF-041", "MF-046", "MF-052", "MF-056", "MF-073", "ADV-005", "ADV-006", "ADV-007", "ADV-008", "ADV-009", "ADV-012", "ADV-016", "ADV-018", "ADV-200", "ADV-201"]},
    "MSTG-CODE": {"name": "Code Quality", "finding_ids": ["SRC-058", "SRC-071", "SRC-078", "SRC-001"]},
    "MSTG-RESILIENCE": {"name": "Resilience", "finding_ids": ["MF-001", "SRC-078"]},
}

ANDROID_BUG_BOUNTY_CLASSES = {
    "Account Takeover": ["SRC-001", "MF-007", "ADV-001"],
    "Data Exposure": ["SRC-013", "SRC-014", "SRC-015", "MF-010", "MF-011"],
    "Privilege Escalation": ["MF-007", "MF-008", "MF-009", "MF-052", "ADV-001", "ADV-012"],
    "Authentication Bypass": ["MF-007", "MF-040", "ADV-012"],
    "RCE via WebView": ["SRC-031", "SRC-032", "ADV-005"],
    "SQL Injection": ["SRC-058", "ADV-037"],
    "Insecure Deep Link": ["MF-040", "MF-041"],
    "Broadcast Injection": ["ADV-008", "ADV-009", "ADV-010", "ADV-011"],
    "Fragment Injection": ["ADV-018", "SRC-124"],
    "PendingIntent Abuse": ["SRC-051", "ADV-003", "SYS-004", "SYS-005"],
    "Task Hijacking": ["MF-037", "MF-038"],
    "SSLPinning Bypass": ["SRC-022", "SRC-023", "SRC-038"],
}


class RuleCoverageAudit:
    def __init__(self):
        self.gaps = {}

    def audit_all(self):
        coverage = {
            "owasp_mobile_top_10": self._audit_standard(OWASP_MOBILE_TOP_10_2024, "OWASP Mobile Top 10 2024"),
            "masvs": self._audit_standard(MASVS_V2, "MASVS v2"),
            "bug_bounty": self._audit_bounty_classes(),
        }
        return coverage

    def _audit_standard(self, standard, name):
        results = []
        covered = 0
        total = len(standard)
        for key, entry in standard.items():
            finding_ids = entry["finding_ids"]
            is_covered = len(finding_ids) > 0
            if is_covered:
                covered += 1
            results.append({
                "id": key,
                "name": entry["name"],
                "covered": is_covered,
                "finding_ids": finding_ids if is_covered else [],
                "gap": not is_covered,
            })
        return {
            "standard": name,
            "total_requirements": total,
            "covered": covered,
            "coverage_pct": round(covered / total * 100, 1) if total else 0,
            "gaps": [r for r in results if r["gap"]],
            "details": results,
        }

    def _audit_bounty_classes(self):
        results = []
        total = len(ANDROID_BUG_BOUNTY_CLASSES)
        covered = 0
        for cls_name, finding_ids in ANDROID_BUG_BOUNTY_CLASSES.items():
            is_covered = len(finding_ids) > 0
            if is_covered:
                covered += 1
            results.append({
                "class": cls_name,
                "covered": is_covered,
                "finding_ids": finding_ids if is_covered else [],
            })
        return {
            "standard": "Android Bug Bounty Classes",
            "total_classes": total,
            "total_requirements": total,
            "covered": covered,
            "coverage_pct": round(covered / total * 100, 1) if total else 0,
            "details": results,
        }

    def get_gap_analysis(self):
        audit = self.audit_all()
        all_gaps = []
        for std_key, std_data in audit.items():
            for gap in std_data.get("gaps", []):
                all_gaps.append({
                    "standard": std_data["standard"],
                    "requirement": gap["name"],
                    "finding_id": gap["id"],
                })
        return all_gaps

    def print_report(self):
        audit = self.audit_all()
        print("\n" + "=" * 80)
        print("RULE COVERAGE AUDIT")
        print("=" * 80)

        for std_key, std_data in audit.items():
            if std_key == "bug_bounty":
                continue
            print(f"\n{std_data['standard']}:")
            print(f"  Coverage: {std_data['covered']}/{std_data['total_requirements']} "
                  f"({std_data['coverage_pct']}%)")
            if std_data.get("gaps"):
                print(f"  GAPS ({len(std_data['gaps'])}):")
                for g in std_data["gaps"]:
                    print(f"    - {g['name']} ({g['id']})")
            print()

        bb = audit.get("bug_bounty", {})
        total_bb = bb.get("total_classes") if "total_classes" in bb else bb.get("total_requirements", 0)
        print(f"Android Bug Bounty Classes:")
        print(f"  Coverage: {bb.get('covered', 0)}/{total_bb} "
              f"({bb.get('coverage_pct', 0)}%)")
        for d in bb.get("details", []):
            status = "✅" if d["covered"] else "❌"
            print(f"  {status} {d['class']}")
        print("=" * 80)

    def get_summary(self):
        audit = self.audit_all()
        return {
            "owasp_coverage": audit["owasp_mobile_top_10"]["coverage_pct"],
            "masvs_coverage": audit["masvs"]["coverage_pct"],
            "bounty_coverage": audit["bug_bounty"]["coverage_pct"],
            "gaps_found": len(self.get_gap_analysis()),
        }


# ── Known Gaps that need new detectors ──
KNOWN_GAPS = [
    {
        "id": "GAP-PARCELABLE",
        "name": "Parcelable Injection",
        "owasp": "M4",
        "masvs": "MSTG-PLATFORM",
        "priority": "HIGH",
        "description": "Custom Parcelable classes without proper validation can lead to injection attacks",
    },
    {
        "id": "GAP-PENDINGINTENT",
        "name": "PendingIntent Confusion (FLAG_MUTABLE without IMMUTABLE)",
        "owasp": "M3",
        "masvs": "MSTG-PLATFORM",
        "priority": "CRITICAL",
        "description": "Partial coverage via SYS-004 but needs dedicated detector",
    },
    {
        "id": "GAP-TASK-AFFINITY",
        "name": "Task Affinity Hijacking",
        "owasp": "M8",
        "masvs": "MSTG-PLATFORM",
        "priority": "HIGH",
        "description": "Needs manifest analysis + CFG for taskAffinity + allowTaskReparenting",
    },
    {
        "id": "GAP-NOTIFICATION",
        "name": "Notification Redirection",
        "owasp": "M3",
        "masvs": "MSTG-PLATFORM",
        "priority": "MEDIUM",
        "description": "Tapping notifications can be redirected to arbitrary components",
    },
    {
        "id": "GAP-CHOOSER",
        "name": "Intent Chooser Abuse",
        "owasp": "M3",
        "masvs": "MSTG-PLATFORM",
        "priority": "MEDIUM",
        "description": "createChooser intents can leak app identity or be intercepted",
    },
    {
        "id": "GAP-DESERIALIZATION",
        "name": "Parcel/Serialization Deserialization Attack",
        "owasp": "M4",
        "masvs": "MSTG-CODE",
        "priority": "CRITICAL",
        "description": "Custom serialization without validation leads to code execution",
    },
    {
        "id": "GAP-CONTENTPROVIDER-SQLI-FULL",
        "name": "ContentProvider SQL Injection (Full Query Support)",
        "owasp": "M4",
        "masvs": "MSTG-CODE",
        "priority": "HIGH",
        "description": "Projection/slection-based SQLi in custom ContentProviders",
    },
    {
        "id": "GAP-JNI",
        "name": "JNI Native Code Vulnerabilities",
        "owasp": "M4",
        "masvs": "MSTG-CODE",
        "priority": "MEDIUM",
        "description": "Buffer overflows, format string bugs in native libraries via JNI",
    },
    {
        "id": "GAP-DYNAMIC-DEX",
        "name": "Dynamic DEX Loading (DexClassLoader without validation)",
        "owasp": "M4",
        "masvs": "MSTG-CODE",
        "priority": "HIGH",
        "description": "Partial coverage via ADV-020 but needs path validation checking",
    },
    {
        "id": "GAP-WEBVIEW-FILEACCESS",
        "name": "WebView File Access with UniversalAccessFromFileURLs",
        "owasp": "M4",
        "masvs": "MSTG-PLATFORM",
        "priority": "HIGH",
        "description": "AllowFileAccess + AllowUniversalAccessFromFileURLs = full file read",
    },
]
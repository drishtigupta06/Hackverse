import json
import os
import hashlib
import datetime


SEVERITY_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


class SarifExporter:
    def __init__(self, apk_path="", package_name="", app_name=""):
        self.apk_path = apk_path
        self.package_name = package_name
        self.app_name = app_name
        self.rules_cache = {}
        self.results = []

    def _rule_id(self, finding):
        rid = finding.get("id") or finding.get("name", "RULE-000")
        return rid

    def _rule_index(self, rule_id):
        if rule_id not in self.rules_cache:
            idx = len(self.rules_cache)
            self.rules_cache[rule_id] = idx
        return self.rules_cache[rule_id]

    def _level(self, severity):
        return SEVERITY_MAP.get(severity.upper(), "warning")

    def _message(self, finding):
        desc = finding.get("description") or finding.get("name", "")
        return {"text": desc}

    def _location(self, finding):
        locs = []
        matches = finding.get("matches", [])
        if matches:
            for m in matches:
                locs.append({
                    "physicalLocation": {
                        "artifactLocation": {"uri": m.split(":")[0] if ":" in m else m},
                        "region": {
                            "startLine": int(m.split(":")[1]) if ":" in m and m.split(":")[1].isdigit() else 1
                        } if ":" in m and len(m.split(":")) > 1 and m.split(":")[1].isdigit() else None
                    } if ":" in m else {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "AndroidManifest.xml"},
                            "region": {"startLine": 1}
                        }
                    }
                })
                break
        code_context = finding.get("_code_context", [])
        if code_context and isinstance(code_context, list):
            for cc in code_context:
                locs.append({
                    "physicalLocation": {
                        "artifactLocation": {"uri": cc.get("file", "source.java")},
                        "region": {
                            "startLine": cc.get("line", 1),
                            "snippet": {"text": cc.get("code", "")}
                        }
                    }
                })
                break
        location = finding.get("location")
        if location and not locs:
            locs.append({
                "physicalLocation": {
                    "artifactLocation": {"uri": location},
                    "region": {"startLine": 1}
                }
            })
        if not locs:
            locs.append({
                "physicalLocation": {
                    "artifactLocation": {"uri": self.apk_path or "unknown.apk"},
                    "region": {"startLine": 1}
                }
            })
        return locs

    def _add_manifest_findings(self, findings):
        for f in findings:
            rid = self._rule_id(f)
            self.results.append({
                "ruleId": rid,
                "ruleIndex": self._rule_index(rid),
                "level": self._level(f.get("severity", "MEDIUM")),
                "message": self._message(f),
                "locations": self._location(f),
                "properties": {
                    "category": "manifest",
                    "severity": f.get("severity", "MEDIUM"),
                    "recommendation": f.get("recommendation", ""),
                }
            })

    def _add_source_findings(self, findings):
        for f in findings:
            rid = self._rule_id(f)
            self.results.append({
                "ruleId": rid,
                "ruleIndex": self._rule_index(rid),
                "level": self._level(f.get("severity", "MEDIUM")),
                "message": self._message(f),
                "locations": self._location(f),
                "properties": {
                    "category": "source",
                    "severity": f.get("severity", "MEDIUM"),
                    "recommendation": f.get("recommendation", ""),
                }
            })

    def _add_phase2_findings(self, findings):
        for group in findings:
            for r in group.get("rules", []):
                rid = self._rule_id(r)
                self.results.append({
                    "ruleId": rid,
                    "ruleIndex": self._rule_index(rid),
                    "level": self._level(r.get("severity", "MEDIUM")),
                    "message": self._message(r),
                    "locations": self._location(r),
                    "properties": {
                        "category": group.get("category", "phase2"),
                        "severity": r.get("severity", "MEDIUM"),
                        "recommendation": r.get("recommendation", ""),
                    }
                })

    def _add_taint_findings(self, findings):
        for f in findings:
            rid = f.get("id", f"TAIN-{hashlib.md5(str(f.get('method', '')).encode()).hexdigest()[:8]}")
            self.results.append({
                "ruleId": rid,
                "ruleIndex": self._rule_index(rid),
                "level": self._level(f.get("severity", "HIGH")),
                "message": {"text": f.get("description", f"Taint flow: {f.get('sink_type', 'unknown')}")},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("method", "unknown")},
                        "region": {"startLine": f.get("sink_at_idx", 1) or 1}
                    }
                }],
                "properties": {
                    "category": "taint",
                    "severity": f.get("severity", "HIGH"),
                    "sink_type": f.get("sink_type", ""),
                    "sanitized": f.get("sanitized", False),
                }
            })

    def _add_component_graph_findings(self, findings):
        for f in findings:
            rid = self._rule_id(f)
            self.results.append({
                "ruleId": rid,
                "ruleIndex": self._rule_index(rid),
                "level": self._level(f.get("severity", "MEDIUM")),
                "message": self._message(f),
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("component_name", f.get("deep_link", self.apk_path))},
                        "region": {"startLine": 1}
                    }
                }],
                "properties": {
                    "category": "component_graph",
                    "severity": f.get("severity", "MEDIUM"),
                }
            })

    def _add_dynamic_findings(self, findings):
        for f in findings:
            rid = self._rule_id(f)
            self.results.append({
                "ruleId": rid,
                "ruleIndex": self._rule_index(rid),
                "level": self._level(f.get("severity", "MEDIUM")),
                "message": self._message(f),
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"dynamic://{self.package_name}"},
                        "region": {"startLine": 1}
                    }
                }],
                "properties": {
                    "category": "dynamic",
                    "severity": f.get("severity", "MEDIUM"),
                }
            })

    def _add_chain_findings(self, findings):
        for f in findings:
            rid = self._rule_id(f)
            self.results.append({
                "ruleId": rid,
                "ruleIndex": self._rule_index(rid),
                "level": self._level(f.get("severity", "CRITICAL")),
                "message": self._message(f),
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"chain://{self.package_name}"},
                        "region": {"startLine": 1}
                    }
                }],
                "properties": {
                    "category": "exploit_chain",
                    "severity": f.get("severity", "CRITICAL"),
                    "steps": f.get("steps", ""),
                    "all_steps_satisfied": f.get("all_steps_satisfied", False),
                }
            })

    def export(self, report_data, output_path):
        self.results = []
        self.rules_cache = {}

        self.apk_path = report_data.get("apk_path", self.apk_path)
        self.package_name = report_data.get("package_name", self.package_name)
        self.app_name = report_data.get("app_name", self.app_name)

        self._add_manifest_findings(report_data.get("manifest_findings", []))
        self._add_source_findings(report_data.get("source_findings", []))
        self._add_phase2_findings(report_data.get("phase2_findings", []))
        self._add_taint_findings(report_data.get("taint_findings", []))
        self._add_component_graph_findings(report_data.get("component_graph_findings", []))
        self._add_dynamic_findings(report_data.get("dynamic_findings", []))
        self._add_chain_findings(report_data.get("chain_findings", []))

        rules_list = []
        for rid, idx in sorted(self.rules_cache.items(), key=lambda x: x[1]):
            rules_list.append({
                "id": rid,
                "name": rid,
                "shortDescription": {"text": rid},
                "properties": {"category": "android-security"}
            })

        sarif_log = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "ManifestScanner",
                        "fullName": "Bug Bounty Android App Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/manifest-scanner",
                        "rules": rules_list,
                    }
                },
                "results": self.results,
                "artifacts": [{
                    "location": {"uri": self.apk_path},
                    "description": {"text": f"APK: {self.app_name} ({self.package_name})"}
                }],
                "invocations": [{
                    "executionSuccessful": True,
                    "startTime": datetime.datetime.now().isoformat(),
                    "endTime": datetime.datetime.now().isoformat(),
                }]
            }]
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif_log, f, indent=2, ensure_ascii=False)

        return output_path

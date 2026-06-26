import re


FRIDA_STATIC_MATCHERS = {
    "ssl_pinning": {
        "keywords": ["ssl", "tls", "certificate", "trustmanager", "hostnameverifier",
                      "network_security", "https", "sslsocket"],
        "static_ids": ["MF-003", "SRC-003", "ADV-003", "ADV-004"],
        "category": "SSL/TLS",
    },
    "root_detection": {
        "keywords": ["root", "detection", "su", "magisk", "superuser", "jailbreak",
                      "system/app", "test-keys", "mountinfo"],
        "static_ids": ["SRC-002", "ADV-002"],
        "category": "Root Detection",
    },
    "runtime_hooks": {
        "keywords": ["cipher", "encrypt", "decrypt", "rawquery", "execsql",
                      "loadurl", "evaluatejavascript", "webview", "sqli", "sqlite"],
        "static_ids": ["ADV-001", "TAIN-SQLI-001", "TAIN-WEBVIEW-001"],
        "category": "Runtime Security",
    },
    "api_monitor": {
        "keywords": ["network", "file_io", "content_resolver", "intent", "location",
                      "notification", "httpurlconnection", "okhttp", "fileoutput",
                      "contentresolver"],
        "static_ids": ["MF-002", "SRC-004", "MF-001"],
        "category": "API Monitoring",
    },
    "sharedprefs": {
        "keywords": ["sharedpreferences", "putstring", "getstring", "putint",
                      "world_readable", "world_writeable", "mode_private"],
        "static_ids": ["MF-007", "SRC-007", "ADV-007"],
        "category": "Data Storage",
    },
}

WEBVIEW_KEYWORDS = ["loadurl", "evaluatejavascript", "webview", "webviewclient",
                     "chromeclient", "javascriptinterface", "addjavascriptinterface"]
INTENT_KEYWORDS = ["intent", "putextra", "getstringextra", "exported", "intentfilter",
                    "scheme", "deep_link", "activity"]
SQLI_KEYWORDS = ["rawquery", "execsql", "sqlite", "sqli", "injection", "selectionargs"]


def _keyword_match(text, keywords):
    if not text or not keywords:
        return False
    text_lower = text.lower()
    return any(k.lower() in text_lower for k in keywords)


def _extract_methods_from_static(finding):
    methods = set()
    matches = finding.get("matches", [])
    for m in matches:
        if isinstance(m, str) and ":" in m:
            methods.add(m.split(":")[0])
    code_context = finding.get("_code_context", [])
    for cc in code_context if isinstance(code_context, list) else []:
        if isinstance(cc, dict) and cc.get("file"):
            methods.add(cc["file"])
    location = finding.get("location")
    if location:
        methods.add(location)
    return methods


def _extract_classes_from_frida(frida_entry):
    classes = set()
    clazz = frida_entry.get("clazz", "")
    if clazz:
        classes.add(clazz)
    method = frida_entry.get("method", "")
    if method:
        classes.add(method)
    detail = frida_entry.get("detail", "")
    if isinstance(detail, str):
        parts = re.findall(r'[a-zA-Z_][\w.]*\.[a-zA-Z_][\w]+', detail)
        classes.update(parts)
    return classes


class FridaStaticLinker:
    def __init__(self):
        self.linked_findings = []
        self.match_stats = {
            "total_frida_events": 0,
            "matched_events": 0,
            "unmatched_events": 0,
            "linked_findings": 0,
            "by_category": {},
        }

    def link(self, frida_findings, manifest_findings=None, source_findings=None,
             phase2_findings=None, taint_findings=None):
        self.linked_findings = []
        self.match_stats = {
            "total_frida_events": 0,
            "matched_events": 0,
            "unmatched_events": 0,
            "linked_findings": 0,
            "by_category": {},
        }

        all_static = []
        by_id = {}
        if manifest_findings:
            for f in manifest_findings:
                fid = f.get("id", "")
                all_static.append(f)
                if fid:
                    by_id[fid] = f
        if source_findings:
            for f in source_findings:
                fid = f.get("id", "")
                all_static.append(f)
                if fid:
                    by_id[fid] = f
        if phase2_findings:
            for group in phase2_findings:
                for r in group.get("rules", []):
                    fid = r.get("id", "")
                    all_static.append(r)
                    if fid:
                        by_id[fid] = r
        if taint_findings:
            for f in taint_findings:
                f["_source"] = "taint"
                all_static.append(f)

        for frida_category, events in frida_findings.items():
            if not isinstance(events, list):
                continue
            non_done = [e for e in events if not e.get("done")]
            self.match_stats["total_frida_events"] += len(non_done)
            matcher = FRIDA_STATIC_MATCHERS.get(frida_category, {})
            keywords = matcher.get("keywords", [])
            static_ids = matcher.get("static_ids", [])
            category_label = matcher.get("category", frida_category)

            for event in non_done:
                linked_static = []
                event_text = json_to_text(event)

                for sf in all_static:
                    score = 0
                    sf_text = json_to_text(sf)

                    if _keyword_match(event_text, keywords) and _keyword_match(sf_text, keywords):
                        score += 2

                    frida_classes = _extract_classes_from_frida(event)
                    static_methods = _extract_methods_from_static(sf)
                    if frida_classes & static_methods:
                        score += 3

                    sf_id = sf.get("id", "")
                    if sf_id in static_ids:
                        score += 2

                    if _keyword_match(event_text, WEBVIEW_KEYWORDS) and _keyword_match(sf_text, WEBVIEW_KEYWORDS):
                        score += 4
                    if _keyword_match(event_text, INTENT_KEYWORDS) and _keyword_match(sf_text, INTENT_KEYWORDS):
                        score += 4
                    if _keyword_match(event_text, SQLI_KEYWORDS) and _keyword_match(sf_text, SQLI_KEYWORDS):
                        score += 4

                    if score >= 3:
                        linked_static.append({
                            "finding_id": sf.get("id", ""),
                            "finding_name": sf.get("name", ""),
                            "score": score,
                        })

                if linked_static:
                    self.match_stats["matched_events"] += 1
                    linked_static.sort(key=lambda x: x["score"], reverse=True)
                    self.linked_findings.append({
                        "frida_category": frida_category,
                        "frida_event": event,
                        "matches": linked_static,
                        "match_count": len(linked_static),
                        "best_match": linked_static[0]["finding_id"] if linked_static else "",
                    })
                    self.match_stats["by_category"].setdefault(frida_category, 0)
                    self.match_stats["by_category"][frida_category] += 1
                else:
                    self.match_stats["unmatched_events"] += 1

        self.match_stats["linked_findings"] = len(self.linked_findings)
        return self.linked_findings

    def get_summary(self):
        return {
            "total_frida_events": self.match_stats["total_frida_events"],
            "matched_events": self.match_stats["matched_events"],
            "unmatched_events": self.match_stats["unmatched_events"],
            "linked_findings": self.match_stats["linked_findings"],
            "match_rate": round(
                self.match_stats["matched_events"] / max(self.match_stats["total_frida_events"], 1) * 100, 1
            ),
            "by_category": self.match_stats["by_category"],
        }


def json_to_text(obj):
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        parts = []
        for v in obj.values():
            if isinstance(v, (str, int, float, bool)):
                parts.append(str(v))
            elif isinstance(v, dict):
                parts.append(json_to_text(v))
            elif isinstance(v, list):
                for item in v:
                    parts.append(json_to_text(item))
        return " ".join(parts)
    if isinstance(obj, list):
        return " ".join(json_to_text(item) for item in obj)
    return str(obj)

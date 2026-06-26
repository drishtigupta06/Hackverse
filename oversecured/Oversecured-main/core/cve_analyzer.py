import json
import os
import re
import datetime
import urllib.request
import urllib.error
import time
from collections import defaultdict

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
AOSP_PATCH_URL = "https://android.googlesource.com/platform/{repo}/+/refs/heads/main/{path}"

# ── DISK CACHE SETTINGS ──
CACHE_FILE = os.path.join(os.path.dirname(__file__), "..", "rules", "cve_cache.json")
CACHE_EXPIRY_HOURS = 24

KNOWN_TAINT_SOURCES = [
    "getStringExtra", "getIntExtra", "getBooleanExtra", "getLongExtra",
    "getDoubleExtra", "getFloatExtra", "getSerializableExtra", "getParcelableExtra",
    "getStringArrayListExtra", "getIntegerArrayListExtra", "getParcelableArrayListExtra",
    "getCharSequenceExtra", "getCharArrayExtra", "getExtras", "getData", "getAction",
    "getScheme", "getHost", "getPath", "getQueryString", "getDataString",
    "getIntent", "getCallingPackage",
    "getQueryParameter", "getQueryParameters", "getPathSegments", "getLastPathSegment",
    "getText", "getUri",
    "readLine", "read", "openInputStream",
    "getDeviceId", "getLine1Number", "getSubscriberId",
]

KNOWN_TAINT_SINKS = [
    "rawQuery", "execSQL", "compileStatement",
    "loadUrl", "loadData", "loadDataWithBaseURL", "evaluateJavascript",
    "addJavascriptInterface",
    "File", "FileInputStream", "FileOutputStream",
    "Runtime.exec", "ProcessBuilder.start",
    "Method.invoke", "Class.forName",
    "startActivity", "startService", "bindService", "sendBroadcast",
    "setComponent", "setClassName", "setClass", "setData",
    "readObject", "readUnshared",
    "openFile", "openAssetFile",
    "transact",
]

METHOD_PATTERNS = {
    "intent": r"get(Parcelable|Serializable|String|Int|Boolean|Long|Double|Float|CharSequence|CharArray|StringArrayList|IntegerArrayList|ParcelableArrayList)Extra",
    "uri": r"(getQueryParameter|getData|getPath|getHost|getScheme|getQueryString)",
    "webview": r"(loadUrl|loadData|loadDataWithBaseURL|evaluateJavascript|addJavascriptInterface)",
    "sql": r"(rawQuery|execSQL|compileStatement)",
    "file": r"(openFile|openAssetFile|File(InputStream|OutputStream|Reader|Writer))",
    "exec": r"(Runtime\.exec|ProcessBuilder)",
    "reflection": r"(Class\.forName|Method\.invoke|DexClassLoader)",
    "intent_sink": r"(startActivity|startService|sendBroadcast|setComponent|setData)",
    "binder": r"(transact|onTransact)",
    "serial": r"(readObject|readUnshared|readObjectOverride)",
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  DISK CACHE HELPERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _load_disk_cache():
    """Load CVE cache from disk. Returns empty dict if missing or expired."""
    cache_path = os.path.abspath(CACHE_FILE)
    if not os.path.exists(cache_path):
        return {}
    try:
        age_hours = (time.time() - os.path.getmtime(cache_path)) / 3600
        if age_hours > CACHE_EXPIRY_HOURS:
            print(f"[*] CVE cache expired ({age_hours:.1f}h old), will refresh.")
            return {}
        with open(cache_path, "r") as f:
            data = json.load(f)
        print(f"[+] Loaded CVE cache ({len(data)} entries, {age_hours:.1f}h old)")
        return data
    except Exception as e:
        print(f"[-] Could not load CVE cache: {e}")
        return {}


def _save_disk_cache(cache_data):
    """Persist CVE cache to disk."""
    cache_path = os.path.abspath(CACHE_FILE)
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    try:
        with open(cache_path, "w") as f:
            json.dump(cache_data, f, indent=2)
        print(f"[+] CVE cache saved ({len(cache_data)} entries) → {cache_path}")
    except Exception as e:
        print(f"[-] Could not save CVE cache: {e}")


class CVEAnalyzer:
    def __init__(self, rules_dir="rules/cve"):
        self.rules_dir = rules_dir
        # In-memory + disk cache: { cve_id: normalized_vuln_dict }
        self._disk_cache = _load_disk_cache()
        self.cve_cache = dict(self._disk_cache)   # working copy
        self.generated_rules = []
        self._last_nvd_request = 0.0
        self._cache_dirty = False
        os.makedirs(self.rules_dir, exist_ok=True)

    # ── NVD NETWORK ────────────────────────────────────────────────────────

    def _nvd_request(self, params, retries=3):
        self._rate_limit()
        query = "&".join(f"{k}={urllib.request.quote(str(v))}" for k, v in params.items() if v)
        url = f"{NVD_API}?{query}"
        for attempt in range(retries):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "CVERuleGenerator/1.0"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return json.loads(resp.read())
            except urllib.error.HTTPError as e:
                if e.code == 403 and attempt < retries - 1:
                    time.sleep(5 * (attempt + 1))
                    continue
                print(f"[-] NVD HTTP {e.code}: {e.reason} (attempt {attempt+1}/{retries})")
                return None
            except Exception as e:
                print(f"[-] NVD request failed: {e}")
                return None

    def _rate_limit(self):
        elapsed = time.time() - self._last_nvd_request
        if elapsed < 0.7:
            time.sleep(0.7 - elapsed)
        self._last_nvd_request = time.time()

    # ── CVE LOOKUP (cache-first) ───────────────────────────────────────────

    def query_nvd_by_cve(self, cve_id):
        cve_id = cve_id.upper()
        # 1. Return from cache if available
        if cve_id in self.cve_cache:
            return self.cve_cache[cve_id]

        # 2. Fetch from NVD
        result = self._nvd_request({"cveId": cve_id})
        if result and "vulnerabilities" in result:
            vulns = result["vulnerabilities"]
            if vulns:
                normalized = self._normalize_nvd_cve(vulns[0]["cve"])
                self.cve_cache[cve_id] = normalized
                self._cache_dirty = True
                return normalized
        return None

    def flush_cache(self):
        """Write in-memory cache to disk if it has new entries."""
        if self._cache_dirty:
            _save_disk_cache(self.cve_cache)
            self._cache_dirty = False

    # ── SEARCH ────────────────────────────────────────────────────────────

    def search_nvd(self, keyword=None, pub_start_date=None, pub_end_date=None,
                   cpe_name=None, results_per_page=50, max_results=100):
        params = {"resultsPerPage": min(results_per_page, 200)}
        if keyword:
            params["keywordSearch"] = keyword
        if pub_start_date:
            params["pubStartDate"] = pub_start_date
        if pub_end_date:
            params["pubEndDate"] = pub_end_date
        if cpe_name:
            params["cpeName"] = cpe_name

        result = self._nvd_request(params)
        if not result or "vulnerabilities" not in result:
            return []

        vulns = result["vulnerabilities"]
        total_results = result.get("totalResults", 0)
        if total_results > results_per_page:
            for start_idx in range(results_per_page, min(total_results, max_results), results_per_page):
                params["startIndex"] = start_idx
                next_result = self._nvd_request(params)
                if next_result and "vulnerabilities" in next_result:
                    vulns.extend(next_result["vulnerabilities"])

        normalized = []
        for v in vulns[:max_results]:
            cve_data = v.get("cve", v)
            cve_id = cve_data.get("id", "CVE-UNKNOWN").upper()
            if cve_id in self.cve_cache:
                normalized.append(self.cve_cache[cve_id])
            else:
                n = self._normalize_nvd_cve(cve_data)
                self.cve_cache[cve_id] = n
                self._cache_dirty = True
                normalized.append(n)
        return normalized

    # ── NORMALISATION ─────────────────────────────────────────────────────

    def _normalize_nvd_cve(self, cve_data):
        cve_id = cve_data.get("id", "CVE-UNKNOWN")
        descriptions = cve_data.get("descriptions", [])
        summary = ""
        details = ""
        for desc in descriptions:
            if desc.get("lang", "") == "en":
                text = desc.get("value", "")
                if not summary:
                    summary = text[:500]
                else:
                    details = text[:1000]

        metrics = cve_data.get("metrics", {})
        severity = "MEDIUM"
        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if metric_key in metrics:
                ms = metrics[metric_key]
                if ms:
                    bs = ms[0].get("cvssData", {}).get("baseSeverity", "")
                    if bs:
                        severity = bs
                        break

        references = []
        for ref in cve_data.get("references", []):
            url = ref.get("url", "")
            tags = ref.get("tags", [])
            references.append({
                "url": url,
                "type": ",".join(tags) if tags else (
                    "Patch" if "commit" in url or "googlesource" in url else "Vendor Advisory"
                ),
            })

        affected = []
        for vdict in cve_data.get("affected", []):
            vendor = vdict.get("vendor", "")
            product = vdict.get("product", "")
            for ver in vdict.get("versions", []):
                affected.append(f"{vendor}:{product}:{ver.get('version','')}")

        published = cve_data.get("published", "")
        return {
            "id": cve_id,
            "summary": summary,
            "details": details or summary,
            "severity": severity,
            "published": published,
            "lastModified": cve_data.get("lastModified", ""),
            "references": references,
            "affected": affected,
            "aliases": [cve_id],
            "source": "NVD",
        }

    # ── PATCH / PATTERN EXTRACTION ────────────────────────────────────────

    def extract_android_patches(self, vuln):
        patches = []
        for ref in vuln.get("references", []):
            url = ref.get("url", "")
            if "android.googlesource.com" in url:
                patches.append({
                    "url": url,
                    "type": ref.get("type", "Patch"),
                    "source": self._identify_patch_source(url),
                })
        return {
            "patches": patches,
            "severity": vuln.get("severity", "MEDIUM"),
            "affected_versions": vuln.get("affected", []),
            "aliases": vuln.get("aliases", []),
            "summary": vuln.get("summary", ""),
            "details": vuln.get("details", ""),
        }

    def _identify_patch_source(self, url):
        if "platform/framework" in url or "platform/frameworks" in url:
            return "framework"
        if "platform/packages" in url:
            return "packages"
        if "platform/system" in url:
            return "system"
        if "platform/vendor" in url:
            return "vendor"
        if "kernel" in url:
            return "kernel"
        return "other"

    def analyze_patch_diff(self, vuln_data):
        patterns = []
        details = vuln_data.get("details", "") or ""
        summary = vuln_data.get("summary", "") or ""
        combined = f"{details} {summary}".lower()
        cve_id = vuln_data.get("id", "CVE-UNKNOWN")
        severity_v = vuln_data.get("severity", "MEDIUM")

        sources_found = self._extract_sources(combined)
        sinks_found = self._extract_sinks(combined)
        vuln_type = self._classify_vulnerability(combined, sources_found, sinks_found)

        for src in sources_found:
            for sink in sinks_found:
                patterns.append({
                    "cve": cve_id,
                    "source": src,
                    "sink": sink,
                    "type": vuln_type,
                    "severity": severity_v,
                    "confidence": self._compute_confidence(src, sink, vuln_type),
                })

        refs = vuln_data.get("references", [])
        for ref in refs:
            desc = ref.get("type", "") or ""
            patch_sources = self._extract_sources(desc.lower())
            patch_sinks = self._extract_sinks(desc.lower())
            existing_pairs = {(p["source"], p["sink"]) for p in patterns}
            for src in patch_sources:
                for sink in patch_sinks:
                    if (src, sink) not in existing_pairs:
                        patterns.append({
                            "cve": cve_id,
                            "source": src,
                            "sink": sink,
                            "type": vuln_type,
                            "severity": severity_v,
                            "confidence": "medium",
                        })
        return patterns

    def _extract_sources(self, text):
        found = set()
        text_lower = text.lower()
        for src in KNOWN_TAINT_SOURCES:
            if src.lower() in text_lower:
                found.add(src)
        for name, pattern in METHOD_PATTERNS.items():
            if name in ("webview", "sql", "file", "exec", "reflection", "intent_sink", "binder", "serial"):
                continue
            if re.search(pattern, text, re.IGNORECASE):
                found.add(pattern.replace("\\\\(", "("))
        for kw in ["Parcelable", "Serializable", "Intent", "Bundle", "Uri", "ClipData",
                   "SharedPreferences", "ContentResolver", "InputStream", "Reader",
                   "URL", "HttpURLConnection", "Location", "TelephonyManager",
                   "AccountManager", "NdefMessage", "ClipboardManager", "EditText"]:
            if kw.lower() in text_lower:
                found.add(kw)
        return list(found)

    def _extract_sinks(self, text):
        found = set()
        text_lower = text.lower()
        for sink in KNOWN_TAINT_SINKS:
            if sink.lower() in text_lower:
                found.add(sink)
        for kw in ["WebView", "SQLiteDatabase", "File", "Runtime", "ProcessBuilder",
                   "Method", "Class", "DexClassLoader", "Context.startActivity",
                   "Context.startService", "Context.sendBroadcast", "Context.bindService",
                   "Intent.setComponent", "ObjectInputStream", "ContentProvider",
                   "IBinder", "NotificationManager", "ClipboardManager", "DevicePolicyManager"]:
            if kw.lower() in text_lower:
                found.add(kw)
        return list(found)

    def _classify_vulnerability(self, text, sources, sinks):
        checks = [
            (["rce", "remote code execution", "code execution"], "remote_code_execution"),
            (["eop", "elevation of privilege", "privilege escalation"], "privilege_escalation"),
            (["information disclosure", "info leak", "information leak"], "information_disclosure"),
            (["sql injection", "sqli"], "sql_injection"),
            (["xss", "cross-site scripting", "cross site scripting"], "xss"),
            (["dos", "denial of service", "denial-of-service"], "denial_of_service"),
            (["bypass", "security bypass"], "security_bypass"),
            (["spoofing"], "spoofing"),
            (["injection"], "injection"),
            (["path traversal", "directory traversal"], "path_traversal"),
            (["deserialization"], "deserialization"),
        ]
        for keywords, vtype in checks:
            if any(k in text for k in keywords):
                return vtype
        return "unknown"

    def _compute_confidence(self, source, sink, vuln_type):
        known_pairs = [
            ("getParcelableExtra", "loadUrl"),
            ("getStringExtra", "rawQuery"),
            ("getSerializableExtra", "readObject"),
            ("getIntent", "startActivity"),
            ("getStringExtra", "Runtime.exec"),
            ("getData", "loadUrl"),
            ("getQueryParameter", "loadUrl"),
        ]
        if (source, sink) in known_pairs:
            return "high"
        if vuln_type != "unknown":
            return "medium"
        return "low"

    # ── RULE GENERATION ───────────────────────────────────────────────────

    def generate_rule_yaml(self, pattern):
        cve_id = pattern["cve"]
        source = pattern["source"]
        sink = pattern["sink"]
        vuln_type = pattern["type"]
        severity = pattern["severity"]
        confidence = pattern["confidence"]
        safe_id = cve_id.replace("-", "")
        return {
            "id": f"CVE-{safe_id}-{source}-{sink}"[:64],
            "name": f"[CVE] {cve_id} — {source} → {sink} ({vuln_type.replace('_',' ').title()})",
            "description": (
                f"CVE-derived rule: {cve_id}. Source '{source}' may flow to sink '{sink}' "
                f"enabling {vuln_type.replace('_',' ').title()}. Confidence: {confidence}."
            ),
            "severity": severity,
            "category": f"CVE Auto-Gen: {vuln_type.replace('_',' ').title()}",
            "cve": cve_id,
            "confidence": confidence,
            "source": source,
            "sink": sink,
            "vulnerability_type": vuln_type,
            "condition": "code",
            "pattern": f"{source}.*{sink}",
            "recommendation": (
                f"Review CVE {cve_id}. Ensure '{source}' data is validated before reaching '{sink}'."
            ),
        }

    # ── BATCH PROCESSING ──────────────────────────────────────────────────

    def process_cve_list(self, cve_ids):
        print(f"[*] Processing {len(cve_ids)} CVE IDs...")
        all_rules = []
        for cve_id in cve_ids:
            vuln = self.query_nvd_by_cve(cve_id)
            if not vuln:
                continue
            patterns = self.analyze_patch_diff(vuln)
            for pat in patterns:
                all_rules.append(self.generate_rule_yaml(pat))
            if patterns:
                print(f"  [+] {cve_id}: {len(patterns)} pattern(s)")
            else:
                print(f"  [-] {cve_id}: no patterns extracted")
        # Flush cache to disk after batch processing
        self.flush_cache()
        return all_rules

    def auto_discover_android_cves(self, days_back=90):
        print(f"[*] Auto-discovering Android CVEs from last {days_back} days...")
        end_date = datetime.datetime.utcnow()
        start_date = end_date - datetime.timedelta(days=days_back)
        fmt = "%Y-%m-%dT%H:%M:%S.000"
        vulns = self.search_nvd(
            keyword="android",
            pub_start_date=start_date.strftime(fmt),
            pub_end_date=end_date.strftime(fmt),
            cpe_name="cpe:2.3:o:google:android:*",
            max_results=50,
        )
        cve_ids = [v["id"] for v in vulns if v.get("id")]
        print(f"[+] Found {len(cve_ids)} Android CVEs")
        self.flush_cache()
        return cve_ids

    def batch_analyze(self, cve_ids=None, auto_discover=False, days_back=90):
        if auto_discover:
            cve_ids = self.auto_discover_android_cves(days_back)
            print(f"[+] Auto-discovered {len(cve_ids)} CVEs")

        if not cve_ids:
            print("[-] No CVE IDs to process")
            return []

        all_rules = self.process_cve_list(cve_ids)
        self.generated_rules = all_rules

        if all_rules:
            self._save_rules(all_rules)
            self._save_aggregated_report(all_rules)

        return all_rules

    def _save_rules(self, rules):
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(self.rules_dir, f"cve_rules_{timestamp}.yaml")
        lines = ["rules:\n"]
        for r in rules:
            for key in ["id", "name", "description", "severity", "category",
                        "cve", "confidence", "condition", "pattern", "recommendation"]:
                lines.append(f'  {key}: "{r[key]}"\n')
            lines.append("\n")
        with open(filepath, "w") as f:
            f.writelines(lines)
        print(f"[+] Saved {len(rules)} CVE rules to {filepath}")
        return filepath

    def _save_aggregated_report(self, rules):
        vuln_types = defaultdict(list)
        for r in rules:
            vuln_types[r["vulnerability_type"]].append(r)
        report_path = os.path.join(self.rules_dir, "cve_aggregated_report.txt")
        with open(report_path, "w") as f:
            f.write("CVE Analysis Aggregated Report\n")
            f.write(f"Generated: {datetime.datetime.utcnow().isoformat()}\n")
            f.write(f"Total CVEs processed: {len(rules)}\n\n")
            for vtype, vlist in sorted(vuln_types.items()):
                f.write(f"\n{'='*60}\n")
                f.write(f"TYPE: {vtype.upper()} ({len(vlist)} rules)\n")
                f.write(f"{'='*60}\n")
                for v in vlist[:10]:
                    f.write(f"  CVE: {v['cve']}\n")
                    f.write(f"  Source: {v['source']} → Sink: {v['sink']}\n")
                    f.write(f"  Severity: {v['severity']} | Confidence: {v['confidence']}\n\n")
        print(f"[+] Aggregated report saved to {report_path}")

    def get_known_cve_sources_sinks(self):
        known = {}
        for r in self.generated_rules:
            cve = r["cve"]
            if cve not in known:
                known[cve] = {"sources": set(), "sinks": set(), "severity": r["severity"]}
            known[cve]["sources"].add(r["source"])
            known[cve]["sinks"].add(r["sink"])
        return known

    def update_existing_rules(self):
        print("[*] Merging CVE rules into existing taint rules...")
        if not self.generated_rules:
            print("[-] No CVE rules generated yet")
            return set(), set()
        taint_sources = set(KNOWN_TAINT_SOURCES)
        taint_sinks = set(KNOWN_TAINT_SINKS)
        for r in self.generated_rules:
            taint_sources.add(r["source"])
            taint_sinks.add(r["sink"])
        print(f"[+] Updated taint sources: {len(taint_sources)}")
        print(f"[+] Updated taint sinks: {len(taint_sinks)}")
        return taint_sources, taint_sinks

    def search_cve_by_keyword(self, keyword, max_results=20):
        print(f"[*] Searching NVD for '{keyword}'...")
        vulns = self.search_nvd(keyword=keyword, max_results=max_results)
        self.flush_cache()
        print(f"[+] Found {len(vulns)} CVEs")
        return vulns

    def get_cache_stats(self):
        """Return stats about the current cache state."""
        cache_path = os.path.abspath(CACHE_FILE)
        age_str = "N/A"
        if os.path.exists(cache_path):
            age_h = (time.time() - os.path.getmtime(cache_path)) / 3600
            age_str = f"{age_h:.1f}h"
        return {
            "entries": len(self.cve_cache),
            "cache_file": cache_path,
            "cache_age": age_str,
            "dirty": self._cache_dirty,
        }


class PatchDiffParser:
    def __init__(self):
        self.source_patterns = [
            (r'(get|set)(String|Int|Long|Boolean|Double|Float|CharSequence|Serializable|Parcelable)Extra',
             "Intent.get{}Extra"),
            (r'getQueryParameter[s]?\(', "Uri.getQueryParameter"),
            (r'getData\(\)', "Intent.getData"),
            (r'getAction\(\)', "Intent.getAction"),
            (r'getExtras\(\)', "Intent.getExtras"),
            (r'openInputStream\(', "ContentResolver.openInputStream"),
            (r'readLine\(\)', "BufferedReader.readLine"),
            (r'getDeviceId\(\)', "TelephonyManager.getDeviceId"),
            (r'getLine1Number\(\)', "TelephonyManager.getLine1Number"),
        ]
        self.sink_patterns = [
            (r'rawQuery\(', "SQLiteDatabase.rawQuery"),
            (r'execSQL\(', "SQLiteDatabase.execSQL"),
            (r'loadUrl\(', "WebView.loadUrl"),
            (r'loadDataWithBaseURL\(', "WebView.loadDataWithBaseURL"),
            (r'evaluateJavascript\(', "WebView.evaluateJavascript"),
            (r'addJavascriptInterface\(', "WebView.addJavascriptInterface"),
            (r'Runtime\.exec\(', "Runtime.exec"),
            (r'ProcessBuilder\(', "ProcessBuilder"),
            (r'Class\.forName\(', "Class.forName"),
            (r'Method\.invoke\(', "Method.invoke"),
            (r'readObject\(\)', "ObjectInputStream.readObject"),
            (r'DexClassLoader\(', "DexClassLoader"),
            (r'startActivity\(', "Context.startActivity"),
            (r'startService\(', "Context.startService"),
            (r'sendBroadcast\(', "Context.sendBroadcast"),
            (r'transact\(', "IBinder.transact"),
        ]

    def parse_diff(self, diff_text):
        findings = []
        added_lines = [line[1:] for line in diff_text.split("\n")
                       if line.startswith("+") and not line.startswith("+++")]
        combined = "\n".join(added_lines)
        sources = [name for pat, name in self.source_patterns if re.search(pat, combined)]
        sinks = [name for pat, name in self.sink_patterns if re.search(pat, combined)]
        if sources or sinks:
            findings.append({"added_lines": len(added_lines), "sources": sources, "sinks": sinks})
        return findings

    def parse_aosp_commit_diff(self, commit_url):
        try:
            diff_url = commit_url if "diff" in commit_url else commit_url
            req = urllib.request.Request(diff_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                content = resp.read().decode("utf-8", errors="replace")
                return self.parse_diff(content)
        except Exception as e:
            print(f"[-] Failed to fetch diff from {commit_url}: {e}")
            return []

#!/usr/bin/env python3
"""
IPC Fuzzer — DAST-style intent/broadcast/provider/deeplink fuzzing

Supports single-ADB-device workflows:
  - Exported activity fuzzing (explicit + implicit intents)
  - Broadcast injection fuzzing (custom + system actions)
  - ContentProvider fuzzing (SQLi, path traversal, type confusion)
  - Deep-link fuzzing (XSS, protocol abuse, host spoofing)
  - PendingIntent hijacking heuristics via exported receivers

Output integrates with scanner finding schema (id/name/severity/category/recommendation/description).
"""
import json
import os
import re
import shutil
import subprocess
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class IPCFinding:
    id: str
    name: str
    severity: str
    category: str
    component: str
    payload: str
    description: str
    recommendation: str
    evidence: str = ""
    metadata: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "id": self.id,
            "name": self.name,
            "severity": self.severity,
            "category": self.category,
            "component": self.component,
            "payload": self.payload,
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }
        if self.metadata:
            d["metadata"] = self.metadata
        return d


class IPCFuzzer:
    def __init__(self, adb_path: str = "adb", device_serial: Optional[str] = None, pkg_name: Optional[str] = None):
        self.adb = adb_path
        self.device = device_serial
        self.pkg = pkg_name or ""
        self._findings: List[IPCFinding] = []
        self._crashes: List[Dict[str, Any]] = []
        self._adb_prefix = [adb_path]
        if device_serial:
            self._adb_prefix += ["-s", device_serial]

    def run_all(self, *, activities: List[str], services: List[str], receivers: List[str],
                providers: List[Dict[str, Any]], deep_links: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        self._findings = []
        try:
            if activities:
                self.fuzz_activities(activities)
            if receivers:
                self.fuzz_receivers(receivers)
            if providers:
                self.fuzz_providers(providers)
            if deep_links:
                self.fuzz_deep_links(deep_links)
            self._detect_crashes()
        except Exception as e:
            print(f"[-] IPC fuzzing error: {e}")
        return [f.to_dict() for f in self._findings]

    def findings(self) -> List[Dict[str, Any]]:
        return [f.to_dict() for f in self._findings]

    # ── Activity / Intent Fuzzing ────────────────────────────────────────────

    def fuzz_activities(self, activities: List[str]):
        for act in activities:
            try:
                self._fuzz_single_activity(act)
            except Exception as e:
                print(f"[!] activity fuzz failed for {act}: {e}")

    def _fuzz_single_activity(self, activity_name: str):
        base = _resolve_component(self.pkg, activity_name)

        # Explicit launch (baseline)
        rc, out, err = self._shell(["am", "start", "-n", base])
        if rc == 0:
            self._log_finding(IPCFinding(
                id="DAST-ACT-001",
                name="Exported Activity Launchable",
                severity="MEDIUM",
                category="dast_ipc",
                component=base,
                payload="am start -n {base}",
                description=f"Activity {activity_name} is directly launchable via explicit intent",
                recommendation="Restrict exported=true with permission or set exported=false",
                evidence=out.strip(),
            ))
            time.sleep(0.8)

        # Data URI abuse
        for scheme, host, path in [
            ("https", "evil.example", "/<script>alert(1)</script>"),
            ("file", "", "/sdcard/evil.html"),
            ("javascript", "", "alert(1)"),
        ]:
            uri = f"{scheme}://{host}{path}"
            rc, out, err = self._shell([
                "am", "start", "-a", "android.intent.action.VIEW",
                "-d", uri, "-n", base,
            ])
            if rc == 0:
                self._log_finding(IPCFinding(
                    id="DAST-ACT-002",
                    name="Activity Accepts Malicious Data URI",
                    severity="HIGH",
                    category="dast_ipc",
                    component=base,
                    payload=uri,
                    description=f"Activity accepts suspicious scheme/data URI without validation",
                    recommendation="Validate scheme/host/path in onCreate/onNewIntent",
                    evidence=out.strip(),
                ))
                time.sleep(0.5)

        # Intent extras fuzzing
        for extra_key, extra_val in [
            ("url", "javascript:alert(document.cookie)"),
            ("redirect", "https://evil.example/phish"),
            ("input", "' OR '1'='1"),
            ("cmd", "reboot"),
            ("debug", "true"),
        ]:
            rc, out, err = self._shell([
                "am", "start", "-n", base,
                "--es", extra_key, extra_val,
                "-a", "android.intent.action.VIEW",
            ])
            if rc == 0:
                self._log_finding(IPCFinding(
                    id="DAST-ACT-003",
                    name="Activity Accepts Untrusted Intent Extras",
                    severity="HIGH",
                    category="dast_ipc",
                    component=base,
                    payload=f"extra[{extra_key}]={extra_val}",
                    description="Activity processes unvalidated intent extras",
                    recommendation="Validate and sanitize all extras from external intents",
                    evidence=out.strip(),
                ))
                time.sleep(0.3)

        # PendingIntent confusion heuristic (FLAG_MUTABLE)
        rc, out, err = self._shell([
            "am", "start", "-n", base,
            "-p", self.pkg,
        ])
        if rc == 0:
            self._capture_crash_info(base, "activity")
            time.sleep(0.3)

    # ── Broadcast Fuzzing ────────────────────────────────────────────────────

    def fuzz_receivers(self, receivers: List[str]):
        for recv in receivers:
            try:
                self._fuzz_single_receiver(recv)
            except Exception as e:
                print(f"[!] receiver fuzz failed for {recv}: {e}")

    def _fuzz_single_receiver(self, receiver_name: str):
        base = _resolve_component(self.pkg, receiver_name)

        # Custom action broadcast (permission bypass)
        for action, extras in [
            ("com.target.CUSTOM_ACTION", {"key": "payload", "cmd": "reboot"}),
            ("android.intent.action.BOOT_COMPLETED", {}),
        ]:
            cmd = ["am", "broadcast", "-a", action, "-n", base, "-p", self.pkg]
            for k, v in extras.items():
                cmd += ["--es", k, v]
            rc, out, err = self._shell(cmd)
            if rc == 0:
                self._log_finding(IPCFinding(
                    id="DAST-BRC-001",
                    name="Broadcast Receiver Accepts Unprotected Custom Action",
                    severity="HIGH",
                    category="dast_ipc",
                    component=base,
                    payload=action,
                    description="Custom broadcast action accepted without signature-level protection",
                    recommendation="Use android:exported=false or signature-level permission",
                    evidence=out.strip(),
                ))
                time.sleep(0.3)

        # Ordered broadcast hijacking
        rc, out, err = self._shell([
            "am", "broadcast", "-a", "android.intent.action.PACKAGE_REPLACED",
            "-n", base, "--receiver-foreground",
        ])
        if rc == 0:
            self._log_finding(IPCFinding(
                id="DAST-BRC-002",
                name="Broadcast Receiver Handles High-Privilege Action",
                severity="HIGH",
                category="dast_ipc",
                component=base,
                payload="android.intent.action.PACKAGE_REPLACED",
                description="Receiver registered for system-level broadcast",
                recommendation="Add android:permission or restrict receiver",
                evidence=out.strip(),
            ))
            time.sleep(0.3)

        # Sticky broadcast persistence test
        rc, out, err = self._shell([
            "am", "broadcast", "-a", "com.target.STATUS_UPDATE",
            "--receiver-foreground", "-n", base,
        ])
        if rc == 0:
            self._log_finding(IPCFinding(
                id="DAST-BRC-003",
                name="Sticky Broadcast May Persist Sensitive Data",
                severity="MEDIUM",
                category="dast_ipc",
                component=base,
                payload="com.target.STATUS_UPDATE",
                description="Receiver accepts broadcast without sender validation",
                recommendation="Validate sender getCallingPackage() or use signature permission",
            ))
            self._capture_crash_info(base, "receiver")
            time.sleep(0.3)

    # ── ContentProvider Fuzzing ──────────────────────────────────────────────

    def fuzz_providers(self, providers: List[Dict[str, Any]]):
        for prov in providers:
            try:
                uri = prov.get("authority") or prov.get("name", "")
                if not uri:
                    continue
                self._fuzz_single_provider(uri, prov)
            except Exception as e:
                print(f"[!] provider fuzz failed for {prov}: {e}")

    def _fuzz_single_provider(self, uri: str, prov: Dict[str, Any]):
        base_uri = f"content://{uri}"

        # Generic query
        rc, out, err = self._shell(["content", "query", "--uri", base_uri])
        if rc == 0:
            self._log_finding(IPCFinding(
                id="DAST-CP-001",
                name="ContentProvider Leaks Data Without Permission",
                severity="HIGH",
                category="dast_ipc",
                component=base_uri,
                payload="adb shell content query",
                description="Provider returns data without requiring caller-level permission",
                recommendation="Add android:readPermission and android:writePermission, enforce in code",
                evidence=out.strip()[:2000],
            ))
            time.sleep(0.3)

        # SQL injection via projection
        for proj in ["*", "* FROM sqlite_master;--", "1 UNION SELECT"]:
            rc, out, err = self._shell([
                "content", "query", "--uri", base_uri,
                "--projection", proj,
            ])
            if rc == 0 and ("sqlite_master" in (out + err).lower() or "sqlite" in (out + err).lower()):
                self._log_finding(IPCFinding(
                    id="DAST-CP-002",
                    name="ContentProvider SQL Injection via Projection",
                    severity="CRITICAL",
                    category="dast_ipc",
                    component=base_uri,
                    payload=proj,
                    description="SQL injection confirmed in provider projection argument",
                    recommendation="Use parameterized queries and whitelist projection columns",
                    evidence=(out + err).strip()[:2000],
                ))
                time.sleep(0.3)
                break

        # SQL injection via selection
        injection_payloads = ["1=1", "1=0", "' OR '1'='1", "1; DROP TABLE users"]
        for sel in injection_payloads:
            rc, out, err = self._shell([
                "content", "query", "--uri", base_uri,
                "--selection", sel,
            ])
            combined = (out + err).lower()
            if rc == 0 and ("sqlite" in combined or "error" in combined or "syntax" in combined):
                self._log_finding(IPCFinding(
                    id="DAST-CP-003",
                    name="ContentProvider SQL Injection via Selection",
                    severity="CRITICAL",
                    category="dast_ipc",
                    component=base_uri,
                    payload=sel,
                    description="Unsantized selection clause passed to SQLite",
                    recommendation="Use ? placeholders and selectionArgs, never raw selection strings",
                ))
                time.sleep(0.3)
                break

        # Path traversal
        for trav in ["../../../../../../etc/passwd", "../../data/data/", "../shared_prefs/"]:
            rc, out, err = self._shell([
                "content", "query", "--uri", f"{base_uri}/{trav}",
            ])
            if rc == 0:
                self._log_finding(IPCFinding(
                    id="DAST-CP-004",
                    name="ContentProvider Path Traversal",
                    severity="HIGH",
                    category="dast_ipc",
                    component=base_uri,
                    payload=trav,
                    description="Provider path segments not sanitized, allows traversal outside intended scope",
                    recommendation="Validate and canonicalize URI path segments",
                    evidence=(out + err).strip()[:1500],
                ))
                time.sleep(0.3)
                break

        # Insert / update abuse
        rc, out, err = self._shell([
            "content", "insert", "--uri", base_uri,
            "--bind", "name:s:exploit", "--bind", "value:s:pwned",
        ])
        if rc == 0:
            self._log_finding(IPCFinding(
                id="DAST-CP-005",
                name="ContentProvider Allows Unrestricted Write",
                severity="HIGH",
                category="dast_ipc",
                component=base_uri,
                payload="content insert --bind name:s:exploit",
                description="Provider allows arbitrary data insertion without write permission",
                recommendation="Enforce writePermission and validate inserted columns",
            ))
            time.sleep(0.3)

        self._capture_crash_info(base_uri, "provider")

    # ── Deep Link Fuzzing ────────────────────────────────────────────────────

    def fuzz_deep_links(self, deep_links: List[Dict[str, Any]]):
        for dl in deep_links:
            try:
                uri = dl.get("uri", "")
                if not uri:
                    continue
                self._fuzz_single_deep_link(uri, dl)
            except Exception as e:
                print(f"[!] deeplink fuzz failed for {dl}: {e}")

    def _fuzz_single_deep_link(self, uri: str, dl: Dict[str, Any]):
        # Basic deep link injection
        for payload in [
            "<script>alert(document.cookie)</script>",
            "javascript:alert(1)",
            "?cmd=reboot&debug=true",
            "?url=https://evil.example",
        ]:
            test_uri = uri
            if "?" in uri:
                test_uri = uri + "&extra=" + payload
            else:
                test_uri = uri + "?" + payload
            rc, out, err = self._shell([
                "am", "start", "-a", "android.intent.action.VIEW",
                "-d", test_uri,
            ])
            if rc == 0:
                self._log_finding(IPCFinding(
                    id="DAST-DL-001",
                    name="Deep Link Accepts Untrusted Input",
                    severity="HIGH",
                    category="dast_ipc",
                    component=uri,
                    payload=payload,
                    description="Deep link handler does not validate query parameters",
                    recommendation="Use StrictMode, whitelist parameters, validate host + path",
                ))
                time.sleep(0.3)
                break

        # Host spoofing (Android < 12 / unverified)
        parts = uri.split("://", 1)
        if len(parts) == 2:
            scheme, rest = parts
            host_path = rest.split("/", 1)
            spoofed = f"{scheme}://evil.example/{host_path[1] if len(host_path) > 1 else ''}"
            rc, out, err = self._shell([
                "am", "start", "-a", "android.intent.action.VIEW",
                "-d", spoofed,
            ])
            if rc == 0:
                self._log_finding(IPCFinding(
                    id="DAST-DL-002",
                    name="Deep Link Host Not Verified",
                    severity="HIGH",
                    category="dast_ipc",
                    component=uri,
                    payload=spoofed,
                    description="Deep link triggered with attacker-controlled host",
                    recommendation="Verify host against appLinkHosts or explicit intent filter host checks",
                ))
                time.sleep(0.3)

        self._capture_crash_info(uri, "deeplink")

    # ── Crash & Anomaly Detection ────────────────────────────────────────────

    def _detect_crashes(self):
        try:
            rc, out, err = self._shell(["logcat", "-d", "-s", "AndroidRuntime:F"])
            if "FATAL" in out or "FATAL" in err:
                self._findings.append(IPCFinding(
                    id="DAST-CRASH-001",
                    name="App Crash During IPC Fuzzing",
                    severity="HIGH",
                    category="dast_ipc",
                    component=self.pkg,
                    payload="Various",
                    description="Application crashed during fuzzing, indicating input validation bug",
                    recommendation="Add try/catch and input validation in IPC entry points",
                    evidence=(out + err).strip()[:3000],
                ))
        except Exception:
            pass

    def _capture_crash_info(self, component: str, comp_type: str):
        try:
            rc, out, err = self._shell(["logcat", "-d", "-s", "AndroidRuntime:E"])
            if "FATAL" in (out + err):
                self._crashes.append({
                    "component": component,
                    "type": comp_type,
                    "log": (out + err).strip()[:3000],
                    "timestamp": time.time(),
                })
        except Exception:
            pass

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _log_finding(self, finding: IPCFinding):
        self._findings.append(finding)
        print(f"[+] {finding.component}: {finding.name} [{finding.severity}]")

    def _shell(self, cmd: List[str]) -> Tuple[int, str, str]:
        full = self._adb_prefix + cmd
        try:
            proc = subprocess.run(full, capture_output=True, text=True, timeout=30)
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "timeout"
        except Exception as e:
            return -1, "", str(e)


def _resolve_component(pkg: str, name: str) -> str:
    if not name:
        return pkg
    if name.startswith(".") or not name.startswith(pkg):
        return f"{pkg}/{name}"
    if "/" not in name:
        return f"{pkg}/{name}"
    return name

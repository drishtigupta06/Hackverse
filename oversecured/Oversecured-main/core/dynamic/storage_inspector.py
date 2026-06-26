#!/usr/bin/env python3
"""
Storage Inspector — Runtime data storage analysis

Runs on single device via ADB:
  - Internal storage (run-as) inspection
  - External storage inspection
  - SQLite database dump
  - SharedPrefs / XML config parse
  - Cache directory analysis
"""
import os
import re
import glob
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class StorageFinding:
    id: str
    name: str
    severity: str
    category: str
    path: str
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
            "path": self.path,
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }
        if self.metadata:
            d["metadata"] = self.metadata
        return d


class StorageInspector:
    SENSITIVE_KEYWORDS = {
        "password", "passwd", "pin", "otp", "token", "secret", "key",
        "credential", "jwt", "bearer", "auth", "access_token", "refresh_token",
        "api_key", "apikey", "private_key", "session", "ssn", "credit",
        "card", "cvv", "account", "routing", "mfa", "2fa", "security_code",
    }

    def __init__(self, adb_path="adb", device_serial=None, pkg_name="",
                 use_root_fallback=True):
        self.adb = adb_path
        self.device_serial = device_serial
        self.pkg = pkg_name or ""
        self._findings: List[StorageFinding] = []
        self._adb_prefix = [adb_path]
        self._has_root = False
        if device_serial:
            self._adb_prefix += ["-s", device_serial]

        # Check if device has root access (su root style)
        if use_root_fallback:
            r = subprocess.run(
                self._adb_prefix + ["shell", "su", "root", "id"],
                capture_output=True, text=True, timeout=5,
            )
            self._has_root = r.returncode == 0 and "uid=0(root)" in r.stdout

    def _su(self, cmd: List[str]) -> tuple:
        """Run a command via `su root` on the device (Toybox su syntax)."""
        full = self._adb_prefix + ["shell", "su", "root"] + cmd
        try:
            p = subprocess.run(full, capture_output=True, text=True, timeout=40)
            return p.stdout, p.stderr
        except subprocess.TimeoutExpired:
            return "", "timeout"
        except Exception as e:
            return "", str(e)

    def inspect_all(self) -> List[Dict[str, Any]]:
        self._findings = []
        if not self.pkg:
            return []
        try:
            if self._has_root:
                print(f"[Storage] Root available, using su fallback")
            self._check_debuggable()
            self._inspect_shared_prefs()
            self._inspect_databases()
            self._inspect_external_storage()
            self._inspect_cache()
            self._inspect_files_dir()
        except Exception as e:
            print(f"[-] Storage inspection error: {e}")
        return [f.to_dict() for f in self._findings]

    def summary(self) -> Dict[str, int]:
        by_sev = defaultdict(int)
        for f in self._findings:
            by_sev[f.severity] += 1
        return {
            "total_findings": len(self._findings),
            "critical": by_sev.get("CRITICAL", 0),
            "high": by_sev.get("HIGH", 0),
            "medium": by_sev.get("MEDIUM", 0),
            "low": by_sev.get("LOW", 0),
            "info": by_sev.get("INFO", 0),
        }

    # ── Debuggable Check ─────────────────────────────────────────────────────

    def _check_debuggable(self):
        if self._has_root:
            # Root access — always can access
            out, err = self._su(["ls", "-la", f"/data/data/{self.pkg}"])
            if out:
                self._findings.append(StorageFinding(
                    id="DAST-STO-002",
                    name="App Data Accessible via Root",
                    severity="HIGH",
                    category="dast_storage",
                    path=f"/data/data/{self.pkg}",
                    description="Internal app data accessible via root (su). All files readable.",
                    recommendation="Implement root detection; encrypt sensitive data at rest",
                ))
                return

        out, err = self._shell(["shell", "run-as", self.pkg, "ls", "-la"])
        if not out:
            self._findings.append(StorageFinding(
                id="DAST-STO-001",
                name="App Cannot Be Accessed via run-as",
                severity="INFO",
                category="dast_storage",
                path=f"/data/data/{self.pkg}",
                description="run-as does not grant access (likely debuggable=false)",
                recommendation="Ensure consistent debuggable state across builds",
            ))
            return

        self._findings.append(StorageFinding(
            id="DAST-STO-002",
            name="App Data Accessible via run-as",
            severity="MEDIUM" if self._is_debuggable() else "INFO",
            category="dast_storage",
            path=f"/data/data/{self.pkg}",
            description="Internal app data can be listed via run-as on debuggable builds",
            recommendation="Strip debuggable=true from release builds; encrypt sensitive stored data",
        ))

    def _is_debuggable(self) -> bool:
        out, _ = self._shell([
            "shell", "run-as", self.pkg, "ls", "/data/data/", self.pkg
        ])
        if out:
            return True
        return False

    def _run_as_or_su(self, cmd: List[str]) -> Tuple[str, str]:
        """Try `run-as pkg ...`, fall back to `su root ...` if root available."""
        if self._has_root:
            out, err = self._su(cmd)
            if out or "No such file" not in err:
                return out, err
        # Try run-as
        full_cmd = ["shell", "run-as", self.pkg] + cmd
        return self._shell(full_cmd)

    # ── SharedPreferences ─────────────────────────────────────────────────────

    def _inspect_shared_prefs(self):
        out, _ = self._run_as_or_su([
            "ls", "-la", f"/data/data/{self.pkg}/shared_prefs/"
        ])
        if not out:
            return
        files = [x.strip() for x in out.splitlines() if x.strip() and not x.startswith("total")]
        for fname in files:
            if fname.endswith(".xml"):
                path = f"/data/data/{self.pkg}/shared_prefs/{fname}"
                content, _ = self._run_as_or_su(["cat", path])
                if content:
                    self._scan_file_content(path, content, source="shared_prefs")

    # ── Databases ─────────────────────────────────────────────────────────────

    def _inspect_databases(self):
        out, _ = self._run_as_or_su([
            "ls", "-la", f"/data/data/{self.pkg}/databases/"
        ])
        if not out:
            return
        files = [x.strip() for x in out.splitlines() if x.strip() and not x.startswith("total")]
        for fname in files:
            if "-journal" in fname or fname.startswith("."):
                continue
            path = f"/data/data/{self.pkg}/databases/{fname}"
            size_kb = self._parse_size_from_ls(out, fname)
            if size_kb is not None and size_kb > 5:
                self._findings.append(StorageFinding(
                    id="DAST-STO-010",
                    name="SQLite Database Detected",
                    severity="MEDIUM",
                    category="dast_storage",
                    path=path,
                    description=f"Database {fname} ({size_kb} KB) found without encryption",
                    recommendation="Use SQLCipher or encrypted SharedPreferences for sensitive data",
                ))
            self._dump_sqlite(path)

    def _dump_sqlite(self, db_path: str):
        _, err = self._run_as_or_su([
            "sqlite3", db_path, "SELECT name FROM sqlite_master WHERE type='table';"
        ])
        if err and "cannot open" in (err or "").lower():
            return
        dump_out, _ = self._run_as_or_su(["sqlite3", db_path, ".dump"])
        if dump_out:
            self._scan_file_content(db_path, dump_out, source="sqlite_dump")

    # ── External Storage ──────────────────────────────────────────────────────

    def _inspect_external_storage(self):
        candidates = [
            f"/sdcard/Android/data/{self.pkg}",
            f"/sdcard/Android/media/{self.pkg}",
            f"/sdcard/{self.pkg}",
        ]
        for d in candidates:
            out, _ = self._shell(["shell", "ls", "-la", d])
            if not out:
                continue
            files = [x.strip() for x in out.splitlines() if x.strip() and not x.startswith("total")]
            for fname in files:
                path = f"{d}/{fname}"
                if fname.endswith(".json") or fname.endswith(".xml") or fname.endswith(".txt"):
                    content, _ = self._shell(["shell", "cat", path])
                    if content:
                        self._scan_file_content(path, content, source="external_storage")

    # ── Cache / Files Dir ─────────────────────────────────────────────────────

    def _inspect_cache(self):
        cache_dir = f"/data/data/{self.pkg}/cache"
        out, _ = self._run_as_or_su(["ls", "-la", cache_dir])
        if out:
            files = [x.strip() for x in out.splitlines() if x.strip() and not x.startswith("total")]
            if files:
                self._findings.append(StorageFinding(
                    id="DAST-STO-020",
                    name="Cache Directory Contains Files",
                    severity="LOW",
                    category="dast_storage",
                    path=cache_dir,
                    description=f"{len(files)} entries in cache; these may persist sensitive data across sessions",
                    recommendation="Clear cache on logout; avoid caching sensitive data; use getCacheDir() responsibly",
                ))

    def _inspect_files_dir(self):
        files_dir = f"/data/data/{self.pkg}/files"
        out, _ = self._run_as_or_su(["ls", "-la", files_dir])
        if not out:
            return
        files = [x.strip() for x in out.splitlines() if x.strip() and not x.startswith("total")]
        for fname in files:
            path = f"{files_dir}/{fname}"
            if any(fname.endswith(ext) for ext in [".json", ".xml", ".txt", ".db", ".dat"]):
                content, _ = self._run_as_or_su(["cat", path])
                if content:
                    self._scan_file_content(path, content, source="files_dir")
                    continue
            if "." not in fname and len(fname) < 64:
                content, _ = self._run_as_or_su(["cat", path])
                if content:
                    self._scan_file_content(path, content, source="files_dir")

    # ── Sensitive Data Detection ──────────────────────────────────────────────

    def _scan_file_content(self, path: str, content: str, source: str):
        lowered = content.lower()
        matched_keywords = [kw for kw in self.SENSITIVE_KEYWORDS if kw in lowered]
        if matched_keywords:
            self._findings.append(StorageFinding(
                id="DAST-STO-030",
                name="Sensitive Data Found in File",
                severity="HIGH" if any(k in lowered for k in ["password", "secret", "private_key", "api_key"]) else "MEDIUM",
                category="dast_storage",
                path=path,
                description=f"File in {source} contains keywords: {', '.join(sorted(set(matched_keywords))[:8])}",
                recommendation="Encrypt data at rest; avoid plaintext secrets in SharedPrefs/files",
                evidence=content[:1200],
            ))

    # ── ADB Helpers ──────────────────────────────────────────────────────────

    def _shell(self, cmd: List[str]) -> tuple:
        full = self._adb_prefix + cmd
        try:
            p = subprocess.run(full, capture_output=True, text=True, timeout=40)
            return p.stdout, p.stderr
        except subprocess.TimeoutExpired:
            return "", "timeout"
        except Exception as e:
            return "", str(e)

    @staticmethod
    def _parse_size_from_ls(ls_output: str, filename: str) -> Optional[int]:
        for line in ls_output.splitlines():
            if filename in line:
                p = line.split()
                if len(p) >= 5:
                    try:
                        return int(p[3])
                    except Exception:
                        pass
        return None

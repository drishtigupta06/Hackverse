#!/usr/bin/env python3
"""
Clean-App False Positive Benchmark

Measures FPR (False Positive Rate) by scanning APKs known to be clean/benign.

Usage:
    runner = CleanAppBenchmark(fp_analyzer=FPAnalyzer())
    runner.add_clean_apk("clean_app_1.apk", package="com.example.clean1")
    runner.add_clean_apk("clean_app_2.apk", package="com.example.clean2")
    results = runner.run(dynamic=False)

Produces:
  - Per-rule FPR (zero hits = clean rule)
  - Overall scanner FPR
  - Exportable suppression manifest
"""
import os
import sys
import time
import subprocess
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional


class CleanAppBenchmark:
    def __init__(self, fp_analyzer=None, storage_dir=".fp_analysis", scanner_script="scanner.py"):
        self.fp = fp_analyzer
        self.storage = Path(storage_dir)
        self.storage.mkdir(exist_ok=True)
        self.scanner = scanner_script
        self.clean_apks: List[Dict[str, str]] = []
        self.results: Dict[str, Dict] = {}

    def add_clean_apk(self, apk_path: str, package: str = "", notes: str = ""):
        if os.path.exists(apk_path):
            self.clean_apks.append({
                "path": apk_path,
                "package": package,
                "notes": notes,
            })

    def run(self, *, dynamic=False, max_time=120) -> Dict:
        if not self.fp:
            from core.fp_analyzer import FPAnalyzer
            self.fp = FPAnalyzer(storage_dir=str(self.storage))

        if not self.clean_apks:
            return {"error": "no clean APKs registered"}

        t0 = time.time()
        total_findings = 0
        total_rules_triggered = set()

        for apk_info in self.clean_apks:
            apk = apk_info["path"]
            pkg = apk_info["package"]
            print(f"[FP] Scanning clean APK: {apk}")
            scan_start = time.time()
            flags = [
                sys.executable, self.scanner, apk,
                "--skip-jadx", "--skip-phase2",
                "-o", str(self.storage / "fp_clean_report.html"),
            ]
            if dynamic:
                flags += ["--dynamic", "--dynamic-mode", "basic", "--dynamic-time", "60"]
            try:
                proc = subprocess.run(
                    flags, capture_output=True, text=True,
                    timeout=max_time,
                )
                scan_elapsed = time.time() - scan_start
                findings = self._parse_findings_from_stdout(proc.stdout, proc.stderr)
                total_findings += len(findings)
                total_rules_triggered.update(self._extract_rule_ids(findings))
                self.fp.record_scan(
                    app_package=pkg,
                    findings=findings,
                    is_clean_baseline=True,
                )
                self.results[apk] = {
                    "findings": findings,
                    "elapsed": round(scan_elapsed, 2),
                    "returncode": proc.returncode,
                    "finding_count": len(findings),
                }
                print(f"  -> {len(findings)} findings in {scan_elapsed:.1f}s")
            except subprocess.TimeoutExpired:
                self.results[apk] = {"error": "timeout", "elapsed": time.time() - scan_start}
                print(f"  -> timeout after {max_time}s")
            except Exception as e:
                self.results[apk] = {"error": str(e)}
                print(f"  -> error: {e}")

        elapsed = time.time() - t0
        fpr_summary = self.fp.measure_fpr()
        high_fpr = self.fp.get_high_fpr_rules(min_fpr=0.10)
        suppressed = self.fp.get_suppressed_rules()

        out = {
            "clean_apks_scanned": len(self.clean_apks),
            "total_clean_findings": total_findings,
            "unique_rules_triggered": len(total_rules_triggered),
            "elapsed_seconds": round(elapsed, 2),
            "fpr_summary": fpr_summary,
            "high_fpr_rules": high_fpr,
            "suppressed_rules": suppressed,
            "per_apk": self.results,
            "manifest_path": "",
        }
        manifest_path = self.storage / "clean_app_fpr_report.json"
        manifest_path.write_text(json.dumps(out, indent=2))
        out["manifest_path"] = str(manifest_path)
        return out

    def export_suppression_manifest(self, path: str) -> str:
        return self.fp.export_suppression_manifest(path)

    def print_report(self):
        summary = self.fp.measure_fpr()
        print("\n" + "=" * 80)
        print("FALSE POSITIVE ANALYSIS")
        print("=" * 80)
        print(f"Rules tracked:        {summary.get('total_rules', 0)}")
        print(f"Suppressed rules:     {summary.get('suppressed', 0)}")
        print(f"FPR threshold:        {summary.get('fpr_threshold', 0.3):.1%}")
        print(f"Clean scans recorded: {summary.get('clean_baseline_scans', 0)}")
        by_level = summary.get("by_level", {})
        if by_level:
            print(f"Clean rules:          {by_level.get('clean', 0)}")
            print(f"Low FPR rules:        {by_level.get('low_fpr', 0)}")
            print(f"High FPR rules:       {by_level.get('high_fpr', 0)}")
            print(f"Already suppressed:   {by_level.get('suppressed', 0)}")
        print()

        print("Top High-FPR Rules (potential FPs):")
        print(f"  {'Rule':12} {'FPR':8} {'Clean Hits':12} {'Placeholder':12} {'Gen Code':10}")
        print(f"  {'-'*12} {'-'*8} {'-'*12} {'-'*12} {'-'*10}")
        for r in self.fp.get_high_fpr_rules(min_fpr=0.10)[:20]:
            print(f"  {r['rule_id']:12} {r['empirical_fpr']:7.1%} "
                  f"{r['clean_app_hits']:12} {r['placeholder_hits']:12} "
                  f"{r['generated_code_hits']:10}")
        print("=" * 80)

    # ── Stdout / Stderr Parsing ──────────────────────────────────────────────

    def _parse_findings_from_stdout(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        findings = []
        seen_ids = set()
        combined = stdout + "\n" + stderr
        for raw_line in combined.splitlines():
            if "Finding IDs:" in raw_line:
                parts = raw_line.split("Finding IDs:", 1)[1].strip().split()
                for pid in parts:
                    pid = pid.strip()
                    if pid and pid not in seen_ids:
                        seen_ids.add(pid)
                        findings.append({"id": pid})
                break
        if not findings:
            import re as _re
            ids = _re.findall(
                r'(MF-\d+|SRC-\d+|ADV-\d+|TAIN-\d+|IPA-\d+|CG-\d+|SYS-\d+|UI-\d+|DYN-\d+|CHAIN-\d+|DAST-[A-Z]+-\d+)',
                combined
            )
            for pid in ids:
                pid = pid.strip()
                if pid not in seen_ids:
                    seen_ids.add(pid)
                    findings.append({"id": pid})
        return findings

    def _extract_rule_ids(self, findings: List[Dict[str, Any]]) -> Set[str]:
        out = set()
        for f in findings:
            rid = f.get("id", "")
            if rid:
                out.add(rid)
        return out


def run_clean_app_fpr_benchmark(apk_dirs: List[str], dynamic=False, max_apks=20):
    """
    Convenience: scan all APKs in given directories as clean baselines.
    Assumes ALL APKs in these dirs are clean (no known vulns).
    """
    bm = CleanAppBenchmark()
    apks_found = 0
    for d in apk_dirs:
        if not os.path.isdir(d):
            continue
        for f in os.listdir(d):
            if f.endswith(".apk") and apks_found < max_apks:
                bm.add_clean_apk(
                    os.path.join(d, f),
                    package="",
                    notes=f"clean baseline from {d}",
                )
                apks_found += 1

    if not bm.clean_apks:
        print("[-] No clean APKs found in specified directories.")
        return {"error": "no clean APKs"}

    results = bm.run(dynamic=dynamic)
    bm.print_report()
    return results

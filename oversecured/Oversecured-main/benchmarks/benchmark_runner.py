"""
Benchmark Runner — Compare scanner output against Gold Standards
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Usage:
    runner = BenchmarkRunner("benchmarks/")
    results = runner.run_all()  # Scans all available APKs
    runner.print_matrix()

    # Or scan a single APK:
    results = runner.scan_apk("diva.apk")
"""

import os
import sys
import json
import re
import time
import subprocess
from collections import defaultdict

from benchmarks.gold_standards import GOLD_STANDARDS, get_gold_standard


class BenchmarkRunner:
    def __init__(self, benchmarks_dir="benchmarks", scanner_script="scanner.py"):
        self.benchmarks_dir = benchmarks_dir
        self.scanner_script = scanner_script
        self.results = {}
        self.matrix = {}

    def find_apks(self):
        apks = []
        for root, dirs, files in os.walk(self.benchmarks_dir):
            for f in files:
                if f.endswith(".apk"):
                    apks.append(os.path.join(root, f))
        return apks

    def scan_apk(self, apk_path, full_scan=False):
        if not os.path.exists(apk_path):
            return {"error": f"APK not found: {apk_path}"}

        print(f"[*] Scanning: {apk_path}")
        start = time.time()
        flags = [
            sys.executable, self.scanner_script, apk_path,
            "--skip-jadx", "--skip-phase2",
            "-o", "/dev/null",
        ]
        if full_scan:
            flags = [
                sys.executable, self.scanner_script, apk_path,
                "--taint", "--component-graph",
                "--chains", "--exploit",
                "-o", "/tmp/benchmark_report.html",
            ]
        try:
            result = subprocess.run(
                flags, capture_output=True, text=True,
                timeout=180 if full_scan else 120,
            )
            elapsed = time.time() - start
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "elapsed": elapsed,
                "success": result.returncode == 0,
            }
        except subprocess.TimeoutExpired:
            return {"error": "timeout", "elapsed": time.time() - start}
        except Exception as e:
            return {"error": str(e), "elapsed": time.time() - start}

    def parse_findings_from_output(self, output):
        for line in output.split("\n"):
            if "Finding IDs:" in line:
                return line.split("Finding IDs:")[1].strip().split()
        return list(set(re.findall(r'(MF-\d+|SRC-\d+|ADV-\d+|TAIN-\d+|IPA-\d+|CG-\d+|SYS-\d+|UI-\d+|DYN-\d+|CHAIN-\d+)', output)))

    def analyze_results_v2(self, apk_name, scan_result, gold_standard, manifest_only=True):
        """v2 analysis: match expected challenges instead of raw finding IDs."""
        if not gold_standard:
            return {"error": "No gold standard for this APK"}

        detected_ids = self.parse_findings_from_output(
            scan_result.get("stdout", "")
        )
        detected_set = set(detected_ids)

        if "challenges" in gold_standard:
            tp_challenges = []
            fn_challenges = []
            skipped = []
            for ch in gold_standard["challenges"]:
                ch_id = ch.get("id")
                if not ch_id:
                    skipped.append(ch)
                    continue
                found = any(fid.startswith(ch_id.replace("*", "")) for fid in detected_set)
                if found:
                    tp_challenges.append(ch)
                else:
                    fn_challenges.append(ch)

            expected_vulns = gold_standard.get("all_vulns", [])
            matched = []
            missed = []
            for exp in expected_vulns:
                exp_id = exp["id"]
                found = any(fid.startswith(exp_id.replace("*", "")) for fid in detected_set)
                if found:
                    matched.append(exp)
                else:
                    missed.append(exp)

            manifest_exp = gold_standard.get("manifest_vulns", [])
            mm = []
            mm_missed = []
            for me in manifest_exp:
                me_id = me["id"]
                found = any(fid.startswith(me_id.replace("*", "")) for fid in detected_set)
                if found:
                    mm.append(me)
                else:
                    mm_missed.append(me)

            tp = len(tp_challenges)
            fn = len(fn_challenges)
            total_found = len(detected_set)
            recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
            return {
                "true_positives": tp,
                "false_negatives": fn,
                "skipped": len(skipped),
                "total_findings": total_found,
                "recall": round(recall, 1),
                "matched": [c["name"] for c in tp_challenges],
                "missed": [c["name"] for c in fn_challenges],
                "detected_ids": sorted(detected_set),
                "elapsed_seconds": round(scan_result.get("elapsed", 0), 1),
            }

        expected = gold_standard["manifest_vulns"] if manifest_only else gold_standard["all_vulns"]
        matched = []
        missed = []
        for exp in expected:
            exp_id = exp["id"]
            found = any(fid.startswith(exp_id.replace("*", "")) for fid in detected_set)
            if found:
                matched.append(exp)
            else:
                missed.append(exp)

        tp = len(matched)
        fn = len(missed)
        total_found = len(detected_set)
        recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
        return {
            "true_positives": tp,
            "false_negatives": fn,
            "total_findings": total_found,
            "recall": round(recall, 1),
            "matched": [e.get("name", "") for e in matched],
            "missed": [e.get("name", "") for e in missed],
            "detected_ids": sorted(detected_set),
            "elapsed_seconds": round(scan_result.get("elapsed", 0), 1),
        }

    def analyze_results(self, apk_name, scan_result, gold_standard, manifest_only=True):
        if not gold_standard:
            return {"error": "No gold standard for this APK"}

        detected_ids = self.parse_findings_from_output(
            scan_result.get("stdout", "")
        )
        detected_set = set(detected_ids)

        expected = gold_standard["manifest_vulns"] if manifest_only else gold_standard["all_vulns"]
        matched = []
        missed = []

        for exp in expected:
            exp_id = exp["id"]
            found = any(fid.startswith(exp_id.replace("*", "")) for fid in detected_set)
            if found:
                matched.append(exp)
            else:
                missed.append(exp)

        tp = len(matched)
        fn = len(missed)
        total_found = len(detected_set)

        recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0

        return {
            "true_positives": tp,
            "false_negatives": fn,
            "total_findings": total_found,
            "recall": round(recall, 1),
            "matched": [e.get("name", "") for e in matched],
            "missed": [e.get("name", "") for e in missed],
            "detected_ids": sorted(detected_set),
            "elapsed_seconds": round(scan_result.get("elapsed", 0), 1),
        }

    def run_all(self, manifest_only=True):
        apks = self.find_apks()
        if not apks:
            print("[-] No APK files found in benchmarks/")
            return {}

        for apk_path in apks:
            apk_name = os.path.basename(apk_path).replace(".apk", "").lower()
            gs = get_gold_standard(apk_name)
            scan_result = self.scan_apk(apk_path, full_scan=not manifest_only)
            if gs and "challenges" in gs and apk_name in ("diva", "oversecured", "insecurebank"):
                analysis = self.analyze_results_v2(apk_name, scan_result, gs, manifest_only=manifest_only)
            else:
                analysis = self.analyze_results(apk_name, scan_result, gs, manifest_only=manifest_only)
            self.results[apk_name] = {
                "apk": apk_path,
                "scan": scan_result,
                "gold_standard": gs["name"] if gs else "unknown",
                "gold_standard_data": gs,
                "analysis": analysis,
            }

        self._build_matrix(manifest_only=manifest_only)
        return self.results

    def _build_matrix(self, manifest_only=True):
        rows = []
        for apk_name, data in self.results.items():
            a = data.get("analysis", {})
            if "error" in a:
                continue
            gs = data.get("gold_standard_data", {})
            exp_min = gs.get("expected_min_manifest", "?") if manifest_only else gs.get("expected_min_all", "?")
            exp_max = gs.get("expected_max_manifest", "?") if manifest_only else gs.get("expected_max_all", "?")
            total_challenges = gs.get("total_challenges", "?")
            rows.append({
                "apk": apk_name,
                "gold_standard": data.get("gold_standard", "?"),
                "expected_min": exp_min,
                "expected_max": exp_max,
                "tp": a.get("true_positives", 0),
                "fn": a.get("false_negatives", 0),
                "total_findings": a.get("total_findings", 0),
                "recall": a.get("recall", 0),
                "time": a.get("elapsed_seconds", 0),
                "total_challenges": total_challenges,
                "raw_findings": a.get("total_findings", 0),
                "fp_estimate": max(0, a.get("total_findings", 0) - a.get("true_positives", 0)),
            })

        self.matrix = {
            "rows": rows,
            "average_recall": round(
                sum(r["recall"] for r in rows) / len(rows), 1
            ) if rows else 0,
            "total_tp": sum(r["tp"] for r in rows),
            "total_fn": sum(r["fn"] for r in rows),
        }

    def print_matrix(self):
        matrix = self.matrix
        if not matrix:
            print("[-] No benchmark results. Run run_all() first.")
            return

        print("\n" + "=" * 120)
        print("BENCHMARK RESULTS MATRIX")
        print("=" * 120)
        print(f"{'APK':<22} {'TP':<5} {'FN':<5} {'Recall':<8} {'Findings':<10} {'Chall':<7} {'Est.FP':<8} {'Time(s)':<8}")
        print("-" * 75)
        for r in matrix["rows"]:
            fp_est = r.get("fp_estimate", 0)
            chall = r.get("total_challenges", "?")
            print(f"{r['apk']:<22} {r['tp']:<5} {r['fn']:<5} "
                  f"{r['recall']:<7}% {r['total_findings']:<10} {str(chall):<7} {fp_est:<8} {r['time']:<8}")
        print("-" * 75)
        print(f"{'AVERAGE':<22} {'':<5} {'':<5} "
              f"{matrix['average_recall']:<7}%")
        total_fp = sum(r.get("fp_estimate", 0) for r in matrix["rows"])
        print(f"Total True Positives:  {matrix['total_tp']}")
        print(f"Total False Negatives: {matrix['total_fn']}")
        print(f"Total Est. FPs:        {total_fp}")
        print(f"Goal: Recall > 80%, FPs < findings")
        print("=" * 120)

    def export_json(self, path="benchmark_results.json"):
        with open(path, "w") as f:
            json.dump(self.matrix, f, indent=2)
        print(f"[+] Results exported to {path}")
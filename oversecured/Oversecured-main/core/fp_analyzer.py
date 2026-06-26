#!/usr/bin/env python3
"""
False Positive Analyzer — Track, measure, and suppress false positives

Features:
  - Per-rule hit tracking across scans
  - Clean-app baseline FPR (False Positive Rate) measurement
  - Auto-suppress rules above configurable FPR threshold
  - Cross-finding correlation (same root cause → group, don't double-count FP)
  - Evidence-based FP reasoning (library code, placeholder values, benign patterns)
  - Export suppression manifests compatible with scanner --fp-filter

Usage:
    analyzer = FPAnalyzer()
    analyzer.record_scan("com.app", scan_findings)
    analyzer.measure_fpr(clean_app_findings)
    suppressed = analyzer.suppress_findings(raw_findings)
"""
import json
import os
import re
import subprocess
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ── Known benign / library patterns that inflate FP counts ──────────────────
BENIGN_PATTERNS = {
    "androidx.", "com.google.", "org.apache.", "org.json.",
    "kotlin.", "kotlinx.", "com.squareup.", "io.reactivex.",
    "com.fasterxml.", "org.slf4j.", "okhttp3.", "okio.",
    "com.google.android.material.", "com.google.common.",
    "com.google.firebase.", "com.android.", "android.",
    "dalvik.", "javax.", "com.sun.", "org.w3c.",
    "R$", "R.", "Manifest$", "BuildConfig",
}

# Placeholder / test-value patterns that cause secret-detection FPs
PLACEHOLDER_PATTERNS = [
    r"AKIAIOSFODNN7EXAMPLE",
    r"AIzaSy[A-Za-z0-9_-]{35}",  # Google API key placeholder/test format
    r"changeme", r"password123", r"dummy", r"test",
    r"\$\{.*\}",                  # Template placeholder
    r"\{\{.*\}\}",               # Mustache/template placeholder
    r"example\.com", r"test\.com",
    r"0{16}", r"1{16}",           # Repetitive digit placeholders
    r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",  # UUID placeholder
]

# Patterns that indicate a finding is in generated / auto-generated code
GENERATED_CODE_PATTERNS = [
    r"/build/", r"/generated/", r"\.R\.", r"\.BuildConfig$",
    r"DataBinding", r"ViewBinding", r"BR\.",
]


@dataclass
class RuleStats:
    """Per-rule false positive statistics."""
    rule_id: str
    total_hits: int = 0
    app_specific_hits: int = 0
    library_hits: int = 0
    clean_app_hits: int = 0
    suppressed: bool = False
    suppression_reason: str = ""
    empirical_fpr: float = 0.0
    confidence: float = 0.0  # 0..1
    # Evidence buckets
    placeholder_hits: int = 0
    generated_code_hits: int = 0
    benign_pattern_hits: int = 0
    app_code_hits: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "total_hits": self.total_hits,
            "app_specific_hits": self.app_specific_hits,
            "library_hits": self.library_hits,
            "clean_app_hits": self.clean_app_hits,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
            "empirical_fpr": round(self.empirical_fpr, 4),
            "confidence": round(self.confidence, 4),
            "placeholder_hits": self.placeholder_hits,
            "generated_code_hits": self.generated_code_hits,
            "benign_pattern_hits": self.benign_pattern_hits,
            "app_code_hits": self.app_code_hits,
        }


@dataclass
class ScanRecord:
    """One scan's contribution to FP analysis."""
    app_package: str
    is_clean_baseline: bool
    findings: List[Dict[str, Any]]
    timestamp: float = field(default_factory=time.time)


class FPAnalyzer:
    """
    Central false positive tracking and suppression engine.

    Workflow:
      1. record_scan() — ingest each scan's findings
      2. measure_fpr() — run baseline clean-app scans to compute per-rule FPR
      3. suppress_findings() — filter findings using accumulated FP knowledge
      4. export_suppression_manifest() — save/load reusable suppression rules
    """

    def __init__(self, storage_dir: str = ".fp_analysis"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True)
        self._rule_stats: Dict[str, RuleStats] = {}
        self._scan_records: List[ScanRecord] = []
        self._fpr_threshold: float = 0.30  # suppress rules above 30% FPR by default
        self._min_samples: int = 3         # need >=3 clean-app hits to trust FPR
        self._load_persisted()

    # ── Ingestion ────────────────────────────────────────────────────────────

    def record_scan(self, app_package: str, findings: List[Dict[str, Any]],
                    is_clean_baseline: bool = False):
        rec = ScanRecord(
            app_package=app_package,
            is_clean_baseline=is_clean_baseline,
            findings=findings,
        )
        self._scan_records.append(rec)
        for f in findings:
            rid = self._extract_rule_id(f)
            if not rid:
                continue
            if rid not in self._rule_stats:
                self._rule_stats[rid] = RuleStats(rule_id=rid)
            stats = self._rule_stats[rid]
            stats.total_hits += 1
            if is_clean_baseline:
                stats.clean_app_hits += 1
                self._classify_fp_evidence(f, stats)
            else:
                if self._is_app_code_finding(f, app_package):
                    stats.app_code_hits += 1
                else:
                    stats.library_hits += 1
                if self._is_placeholder_finding(f):
                    stats.placeholder_hits += 1
                if self._is_generated_code_finding(f):
                    stats.generated_code_hits += 1
                if self._is_benign_pattern_finding(f):
                    stats.benign_pattern_hits += 1
        self._persist()

    # ── FPR Measurement ──────────────────────────────────────────────────────

    def measure_fpr(self) -> Dict[str, Any]:
        total_clean = sum(1 for r in self._scan_records if r.is_clean_baseline)
        if total_clean == 0:
            return {"error": "no clean baseline scans recorded"}

        suppressed = 0
        for rid, stats in self._rule_stats.items():
            if stats.clean_app_hits == 0:
                stats.empirical_fpr = 0.0
                stats.confidence = 0.0
                continue
            denom = max(stats.clean_app_hits + stats.app_code_hits, 1)
            stats.empirical_fpr = stats.clean_app_hits / denom
            stats.confidence = min(
                stats.clean_app_hits / self._min_samples, 1.0
            )
            if (stats.empirical_fpr >= self._fpr_threshold
                    and stats.clean_app_hits >= self._min_samples):
                stats.suppressed = True
                stats.suppression_reason = (
                    f"FPR {stats.empirical_fpr:.1%} above threshold "
                    f"{self._fpr_threshold:.1%} "
                    f"({stats.clean_app_hits} clean hits)"
                )
                suppressed += 1

        by_level = defaultdict(int)
        for s in self._rule_stats.values():
            if s.suppressed:
                by_level["suppressed"] += 1
            elif s.empirical_fpr >= 0.15:
                by_level["high_fpr"] += 1
            elif s.empirical_fpr > 0:
                by_level["low_fpr"] += 1
            else:
                by_level["clean"] += 1

        return {
            "total_rules": len(self._rule_stats),
            "suppressed": suppressed,
            "by_level": dict(by_level),
            "fpr_threshold": self._fpr_threshold,
            "min_samples": self._min_samples,
            "clean_baseline_scans": total_clean,
        }

    def get_high_fpr_rules(self, min_fpr: float = 0.15) -> List[Dict[str, Any]]:
        out = []
        for rid, s in self._rule_stats.items():
            if s.empirical_fpr >= min_fpr and not s.suppressed:
                out.append(s.to_dict())
        out.sort(key=lambda x: -x["empirical_fpr"])
        return out

    def get_suppressed_rules(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self._rule_stats.values() if s.suppressed]

    # ── Finding Suppression ──────────────────────────────────────────────────

    def suppress_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out = []
        for f in findings:
            rid = self._extract_rule_id(f)
            if rid and rid in self._rule_stats:
                stats = self._rule_stats[rid]
                if stats.suppressed:
                    f["_fp_suppressed"] = True
                    f["_fp_reason"] = stats.suppression_reason
                    continue
                if self._is_placeholder_finding(f):
                    f["_fp_risk"] = "placeholder"
                if self._is_generated_code_finding(f):
                    f["_fp_risk"] = "generated_code"
                if self._is_benign_pattern_finding(f):
                    f["_fp_risk"] = "benign_pattern"
            out.append(f)
        return out

    # ── Correlation / Dedup ──────────────────────────────────────────────────

    def correlate_with_dynamic(self, static_findings: List[Dict[str, Any]],
                                dynamic_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Mark static findings as validated if dynamic findings reference same
        root cause. Reduces FP by upgrading STATIC → DYNAMIC confidence.
        """
        dyn_keys = set()
        for df in dynamic_findings:
            rid = self._extract_rule_id(df)
            if rid:
                dyn_keys.add(rid)

        updated = 0
        for f in static_findings:
            rid = self._extract_rule_id(f)
            if rid and rid in dyn_keys:
                f["dynamic_correlated"] = True
                f.setdefault("confidence", {})
                f["confidence"]["dynamic_correlated"] = True
                updated += 1
        return static_findings

    # ── Export / Import ──────────────────────────────────────────────────────

    def export_suppression_manifest(self, path: str) -> str:
        manifest = {
            "version": "1.0",
            "generated_at": time.time(),
            "fpr_threshold": self._fpr_threshold,
            "min_samples": self._min_samples,
            "suppressed_rules": {
                rid: {
                    "reason": s.suppression_reason,
                    "empirical_fpr": s.empirical_fpr,
                    "clean_hits": s.clean_app_hits,
                }
                for rid, s in self._rule_stats.items() if s.suppressed
            },
            "high_fpr_rules": {
                rid: {"empirical_fpr": s.empirical_fpr}
                for rid, s in self._rule_stats.items()
                if not s.suppressed and s.empirical_fpr >= 0.15
            },
        }
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(manifest, indent=2))
        return str(p)

    def import_suppression_manifest(self, path: str):
        p = Path(path)
        if not p.exists():
            return
        data = json.loads(p.read_text())
        threshold = data.get("fpr_threshold")
        if threshold is not None:
            self._fpr_threshold = float(threshold)
        min_samples = data.get("min_samples")
        if min_samples is not None:
            self._min_samples = int(min_samples)
        for rid, info in data.get("suppressed_rules", {}).items():
            if rid not in self._rule_stats:
                self._rule_stats[rid] = RuleStats(rule_id=rid)
            s = self._rule_stats[rid]
            s.suppressed = True
            s.suppression_reason = info.get("reason", "imported")
            s.empirical_fpr = info.get("empirical_fpr", 1.0)

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _extract_rule_id(self, finding: Dict[str, Any]) -> Optional[str]:
        return finding.get("id", "") or finding.get("rule_id", "")

    def _is_app_code_finding(self, f: Dict[str, Any], app_pkg: str) -> bool:
        cls = (f.get("class_name") or f.get("source") or f.get("file")
               or f.get("location") or "")
        if not cls or not app_pkg:
            return True
        normalized = cls.replace("/", ".").replace("\\", ".")
        if normalized.startswith("L") and ";" in normalized:
            normalized = normalized[1:].split(";")[0]
        if ";->" in normalized:
            normalized = normalized.split(";->")[0]
        if normalized.startswith(app_pkg):
            return True
        for pat in BENIGN_PATTERNS:
            if normalized.startswith(pat):
                return False
        return True

    def _is_placeholder_finding(self, f: Dict[str, Any]) -> bool:
        if not f:
            return False
        evidence = " ".join(str(v) for v in f.values())
        for pat in PLACEHOLDER_PATTERNS:
            if re.search(pat, evidence, re.IGNORECASE):
                return True
        return False

    def _is_generated_code_finding(self, f: Dict[str, Any]) -> bool:
        if not f:
            return False
        loc = str(f.get("location", "")) + str(f.get("file", ""))
        for pat in GENERATED_CODE_PATTERNS:
            if re.search(pat, loc):
                return True
        return False

    def _is_benign_pattern_finding(self, f: Dict[str, Any]) -> bool:
        if not f:
            return False
        loc = str(f.get("location", "")) + str(f.get("file", ""))
        for pat in BENIGN_PATTERNS:
            if pat in loc:
                return True
        return False

    @staticmethod
    def _classify_fp_evidence(f: Dict[str, Any], stats: RuleStats):
        if FPAnalyzer._placeholder_check(f):
            stats.placeholder_hits += 1
        if FPAnalyzer._generated_code_check(f):
            stats.generated_code_hits += 1
        if FPAnalyzer._benign_pattern_check(f):
            stats.benign_pattern_hits += 1

    @staticmethod
    def _placeholder_check(f) -> bool:
        if not f:
            return False
        evidence = " ".join(str(v) for v in f.values())
        for pat in PLACEHOLDER_PATTERNS:
            if re.search(pat, evidence, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def _generated_code_check(f) -> bool:
        if not f:
            return False
        loc = str(f.get("location", "")) + str(f.get("file", ""))
        for pat in GENERATED_CODE_PATTERNS:
            if re.search(pat, loc):
                return True
        return False

    @staticmethod
    def _benign_pattern_check(f) -> bool:
        if not f:
            return False
        loc = str(f.get("location", "")) + str(f.get("file", ""))
        for pat in BENIGN_PATTERNS:
            if pat in loc:
                return True
        return False

    # ── Persistence ──────────────────────────────────────────────────────────

    def _persist(self):
        try:
            data = {
                rid: s.to_dict() for rid, s in self._rule_stats.items()
            }
            (self.storage_dir / "rule_stats.json").write_text(
                json.dumps(data, indent=2)
            )
        except Exception:
            pass

    def _load_persisted(self):
        try:
            p = self.storage_dir / "rule_stats.json"
            if not p.exists():
                return
            data = json.loads(p.read_text())
            for rid, info in data.items():
                self._rule_stats[rid] = RuleStats(
                    rule_id=rid,
                    total_hits=info.get("total_hits", 0),
                    app_specific_hits=info.get("app_specific_hits", 0),
                    library_hits=info.get("library_hits", 0),
                    clean_app_hits=info.get("clean_app_hits", 0),
                    suppressed=info.get("suppressed", False),
                    suppression_reason=info.get("suppression_reason", ""),
                    empirical_fpr=info.get("empirical_fpr", 0.0),
                    confidence=info.get("confidence", 0.0),
                    placeholder_hits=info.get("placeholder_hits", 0),
                    generated_code_hits=info.get("generated_code_hits", 0),
                    benign_pattern_hits=info.get("benign_pattern_hits", 0),
                    app_code_hits=info.get("app_code_hits", 0),
                )
        except Exception:
            pass

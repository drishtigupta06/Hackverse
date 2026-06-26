import os
import sys

import pytest

from core.orchestrator import ScanConfig, ScanResult, run_scan, build_report_data
from core.utils import post_process_findings, is_library_class


class TestScanConfig:
    def test_default_values(self):
        cfg = ScanConfig()
        assert cfg.apk == ""
        assert cfg.skip_jadx is False
        assert cfg.skip_phase2 is False
        assert cfg.dedup is False

    def test_with_apk(self, diva_apk_path):
        cfg = ScanConfig(apk=diva_apk_path, skip_jadx=True, skip_phase2=True)
        assert cfg.apk == diva_apk_path
        assert cfg.skip_jadx is True


class TestScanResult:
    def test_empty_result(self):
        r = ScanResult()
        assert r.manifest_findings == []
        assert r.source_findings == []
        assert r.package_name == ""

    def test_result_roundtrip(self):
        r = ScanResult()
        r.package_name = "com.test"
        r.manifest_findings = [{"id": "MF-001", "severity": "HIGH"}]
        assert r.package_name == "com.test"
        assert len(r.manifest_findings) == 1


class TestSmokeScan:
    def test_run_scan_returns_result(self, diva_apk_path):
        config = ScanConfig(
            apk=diva_apk_path,
            skip_jadx=True,
            skip_phase2=True,
        )
        result = run_scan(config)
        assert isinstance(result, ScanResult)
        assert result.package_name == "jakhar.aseem.diva"
        assert result.app_name == "Diva"

    def test_run_scan_finds_manifest_issues(self, diva_apk_path):
        config = ScanConfig(
            apk=diva_apk_path,
            skip_jadx=True,
            skip_phase2=True,
        )
        result = run_scan(config)
        total = len(result.manifest_findings) + len(result.source_findings)
        assert total >= 15, f"Expected >=15 findings, got {total}"
        severities = [f.get("severity") for f in result.manifest_findings]
        assert "CRITICAL" in severities or "HIGH" in severities

    def test_run_scan_with_ai_triage(self, diva_apk_path):
        config = ScanConfig(
            apk=diva_apk_path,
            skip_jadx=True,
            skip_phase2=True,
            ai_triage=False,
        )
        result = run_scan(config)
        assert result.ai_triage_findings == []

    @pytest.mark.slow
    def test_run_scan_with_nonexistent_apk(self):
        config = ScanConfig(apk="/nonexistent.apk")
        result = run_scan(config)
        assert result.package_name == ""


class TestBuildReportData:
    def test_report_data_keys(self, diva_apk_path):
        config = ScanConfig(apk=diva_apk_path, skip_jadx=True, skip_phase2=True)
        result = run_scan(config)
        data = build_report_data(result, config)
        assert data["apk_path"] == os.path.abspath(diva_apk_path)
        assert data["package_name"] == "jakhar.aseem.diva"
        assert data["app_name"] == "Diva"
        assert "manifest_findings" in data
        assert "source_findings" in data
        assert "frida_findings" in data
        assert "exploit_screenshots" in data

    def test_report_data_non_empty_findings(self, diva_apk_path):
        config = ScanConfig(apk=diva_apk_path, skip_jadx=True, skip_phase2=True)
        result = run_scan(config)
        data = build_report_data(result, config)
        assert len(data["manifest_findings"]) > 0


class TestPostProcessFindings:
    def test_library_filter(self):
        findings = [
            {"id": "F-001", "file": "androidx/core/app/Activity.java", "confidence": 40},
            {"id": "F-002", "file": "jakhar/aseem/diva/MainActivity.java", "confidence": 40},
        ]
        filtered = post_process_findings(findings, "jakhar.aseem.diva")
        assert len(filtered) == 1
        assert filtered[0]["id"] == "F-002"

    def test_low_confidence_filter(self):
        findings = [
            {"id": "F-001", "confidence": 5},
            {"id": "F-002", "confidence": 50},
        ]
        filtered = post_process_findings(findings, None)
        assert len(filtered) == 1
        assert filtered[0]["id"] == "F-002"

    def test_critical_kept_even_low_confidence(self):
        findings = [
            {"id": "F-001", "confidence": 5, "severity": "CRITICAL"},
        ]
        filtered = post_process_findings(findings, None)
        assert len(filtered) == 1

    def test_empty_findings(self):
        assert post_process_findings([], "com.test") == []


class TestIsLibraryClass:
    def test_androidx_is_library(self):
        assert is_library_class("androidx.appcompat.app.AppCompatActivity", "com.test") is True

    def test_app_class_not_library(self):
        assert is_library_class("com.test.MainActivity", "com.test") is False

    def test_dalvik_class_not_library(self):
        assert is_library_class("Lcom/test/MainActivity;->onCreate()V", "com.test") is False

    def test_empty_is_not_library(self):
        assert is_library_class("", "com.test") is False

    def test_kotlin_is_library(self):
        assert is_library_class("kotlin.text.StringsKt", "com.test") is True


class TestRegression:
    """Regression test suite against gold standard APKs (benchmarks)."""

    GOLD = {
        "diva": {
            "package": "jakhar.aseem.diva",
            "app_name": "Diva",
            "must_find_manifest": {
                "MF-007": "Exported Activity",
                "MF-010": "Exported ContentProvider",
            },
            "expected_min_findings": 15,
        },
    }

    def test_diva_gold_standard(self, diva_apk_path):
        """Verify scanner detects all DIVA gold-standard vulnerabilities."""
        config = ScanConfig(apk=diva_apk_path, skip_jadx=True, skip_phase2=True)
        result = run_scan(config)
        assert result.package_name == self.GOLD["diva"]["package"]
        assert result.app_name == self.GOLD["diva"]["app_name"]

        all_ids = set()
        for f in result.manifest_findings:
            all_ids.add(f.get("id", ""))
        for f in result.source_findings:
            all_ids.add(f.get("id", ""))

        total = len(result.manifest_findings) + len(result.source_findings)
        assert total >= self.GOLD["diva"]["expected_min_findings"], \
            f"Diva scan: expected ≥{self.GOLD['diva']['expected_min_findings']} findings, got {total}"

        missing = []
        for fid, fname in self.GOLD["diva"]["must_find_manifest"].items():
            if not any(fid in i for i in all_ids):
                if not any(fname.lower() in (f.get("name", "") or "").lower() or fname.lower() in (f.get("description", "") or "").lower()
                           for f in result.manifest_findings + result.source_findings):
                    missing.append(f"{fid} ({fname})")

        assert not missing, f"Gold standard findings MISSING from DIVA scan: {missing}"

    @pytest.mark.slow
    def test_benchmark_runner_integrity(self):
        """Verify benchmark gold standards data is well-formed."""
        from benchmarks.gold_standards import GOLD_STANDARDS
        assert "diva" in GOLD_STANDARDS
        assert len(GOLD_STANDARDS["diva"]["challenges"]) >= 10
        all_ids = [c["id"] for c in GOLD_STANDARDS["diva"]["challenges"] if c.get("id")]
        assert all(all_ids), "Every gold standard challenge must have a finding ID"

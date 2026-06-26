import os
import uuid
import json
import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from services.db import async_session
from services.queue import publish_log, publish_event
from services.apk_store import ensure_report_dir, get_report_path
from models.scan import Scan
from models.finding import Finding
from models.exploit_chain import ExploitChain
from models.scan_log import ScanLog

logger = logging.getLogger(__name__)

SCANNER_PATH = os.getenv("SCANNER_PATH", "/scanner/scanner.py")
DATA_DIR = os.getenv("DATA_DIR", "/data")
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "7200"))

_running_processes: dict[str, dict] = {}

SEVERITY_MAP = {
    "error": "HIGH",
    "warning": "MEDIUM",
    "note": "LOW",
    "none": "INFO",
}

SCANNER_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
}

ALLOWED_SCAN_MODES = {"fast", "standard", "thorough", "bb"}
ALLOWED_FP_FILTERS = {"basic", "aggressive", "off"}
ALLOWED_MIN_CONFIDENCE = {"low", "medium", "high"}
ALLOWED_AI_CONFIDENCE = {"Low", "Medium", "High"}
ALLOWED_EXPLOIT_VECTORS = {"adb", "drozer", "frida"}
ALLOWED_FRIDA_MODES = {"spawn", "attach"}

LOG_COMMIT_INTERVAL = 50


def _clamp(val, lo, hi):
    return max(lo, min(hi, val))


def _sanitize_config(config: dict) -> dict:
    safe = dict(config)

    mode = safe.get("scan_mode", "standard")
    safe["scan_mode"] = mode if mode in ALLOWED_SCAN_MODES else "standard"

    fp_f = safe.get("fp_filter", "basic")
    safe["fp_filter"] = fp_f if fp_f in ALLOWED_FP_FILTERS else "basic"

    mc = safe.get("min_confidence", "low")
    safe["min_confidence"] = mc if mc in ALLOWED_MIN_CONFIDENCE else "low"

    ai_c = safe.get("ai_confidence", "Medium")
    safe["ai_confidence"] = ai_c if ai_c in ALLOWED_AI_CONFIDENCE else "Medium"

    ev = safe.get("exploit_vector", "adb")
    safe["exploit_vector"] = ev if ev in ALLOWED_EXPLOIT_VECTORS else "adb"

    fm = safe.get("frida_mode", "spawn")
    safe["frida_mode"] = fm if fm in ALLOWED_FRIDA_MODES else "spawn"

    safe["cve_days"] = _clamp(int(safe.get("cve_days", 30)), 1, 365)
    safe["frida_timeout"] = _clamp(int(safe.get("frida_timeout", 30)), 5, 300)
    safe["emulator_ram"] = _clamp(int(safe.get("emulator_ram", 2048)), 512, 16384)
    safe["screenrecord_duration"] = _clamp(int(safe.get("screenrecord_duration", 60)), 5, 600)
    safe["screenrecord_bitrate"] = _clamp(int(safe.get("screenrecord_bitrate", 4000000)), 100000, 20000000)
    fp_t = safe.get("fp_threshold", 0.30)
    safe["fp_threshold"] = _clamp(float(fp_t), 0.0, 1.0)

    for key in ("exploit_pkg", "cve_list", "cve_search", "ai_model", "emulator_avd", "frida_device"):
        val = safe.get(key)
        if val is not None:
            val = str(val)[:256]
            safe[key] = val.replace("\n", " ").replace("\r", " ").replace("\0", "")
    safe["frida_package"] = (safe.get("frida_package") or "")[:256]

    for key in (
        "skip_jadx", "skip_phase2", "ai_triage", "cve_update", "taint",
        "component_graph", "chains", "root_cause", "dedup", "confidence",
        "frida_enabled", "frida_ssl", "frida_root", "frida_hooks", "frida_api",
        "frida_prefs", "frida_all", "exploit", "exploit_validate",
        "emulator_enabled", "no_emulator_cleanup", "screenrecord", "emulator_test",
        "fp_measure", "fp_report", "coverage_audit", "sarif", "history_save",
    ):
        raw = safe.get(key, False)
        if not isinstance(raw, bool):
            raw = str(raw).lower() in ("true", "1", "yes")
        safe[key] = raw

    return safe


def _build_cli(apk_path: str, config: dict, scan_id: str) -> list:
    config = _sanitize_config(config)

    cmd = ["python", SCANNER_PATH, apk_path]
    report_dir = ensure_report_dir(scan_id)
    html_path = str(report_dir / "report.html")
    sarif_path = str(report_dir / "report.sarif")
    cmd.extend(["--template", str(Path(SCANNER_PATH).parent / "templates/report.html")])
    cmd.extend(["--output", html_path])
    cmd.extend(["--sarif", sarif_path])

    mode = config["scan_mode"]
    if mode == "bb":
        cmd.append("--bb")
    elif mode == "fast":
        cmd.append("--skip-jadx")
        cmd.append("--skip-phase2")
    elif mode == "thorough":
        cmd.append("--chains")
        cmd.append("--root-cause")
        cmd.append("--confidence")
        cmd.append("--component-graph")

    fp_filter = config["fp_filter"]
    if fp_filter != "basic":
        cmd.extend(["--fp-filter", fp_filter])

    min_conf = config["min_confidence"]
    if min_conf != "low":
        cmd.extend(["--min-confidence", min_conf])

    if config["skip_jadx"]:
        cmd.append("--skip-jadx")
    if config["skip_phase2"]:
        cmd.append("--skip-phase2")

    if config["ai_triage"]:
        cmd.append("--ai-triage")
        cmd.extend(["--ai-model", config["ai_model"]])
        cmd.extend(["--ai-confidence", config["ai_confidence"]])

    if config["cve_update"]:
        cmd.append("--cve-update")
    cmd.extend(["--cve-days", str(config["cve_days"])])
    if config.get("cve_list"):
        cmd.extend(["--cve-list", config["cve_list"]])
    if config.get("cve_search"):
        cmd.extend(["--cve-search", config["cve_search"]])

    if config["frida_enabled"]:
        frida_mode = config["frida_mode"]
        pkg = config.get("frida_package", "")
        if frida_mode == "attach" and pkg:
            cmd.extend(["--frida", pkg])
        elif frida_mode == "spawn" and pkg:
            cmd.extend(["--frida-spawn", pkg])
        if config.get("frida_device"):
            cmd.extend(["--frida-device", config["frida_device"]])
        if config["frida_ssl"]:
            cmd.append("--frida-ssl")
        if config["frida_root"]:
            cmd.append("--frida-root")
        if config["frida_hooks"]:
            cmd.append("--frida-hooks")
        if config["frida_api"]:
            cmd.append("--frida-api")
        if config["frida_prefs"]:
            cmd.append("--frida-prefs")
        if config["frida_all"]:
            cmd.append("--frida-all")
        cmd.extend(["--frida-timeout", str(config["frida_timeout"])])

    if config["exploit"]:
        cmd.append("--exploit")
        if config["exploit_validate"]:
            cmd.append("--exploit-validate")
        cmd.extend(["--exploit-vector", config["exploit_vector"]])
        cmd.extend(["--exploit-pkg", config["exploit_pkg"]])

    if config["emulator_enabled"]:
        cmd.append("--emulator")
        cmd.extend(["--emulator-avd", config["emulator_avd"]])
        cmd.extend(["--emulator-ram", str(config["emulator_ram"])])
        if config["no_emulator_cleanup"]:
            cmd.append("--no-emulator-cleanup")
        if config["screenrecord"]:
            cmd.append("--screenrecord")
            cmd.extend(["--screenrecord-duration", str(config["screenrecord_duration"])])
            cmd.extend(["--screenrecord-bitrate", str(config["screenrecord_bitrate"])])
        if config["emulator_test"]:
            cmd.append("--emulator-test")

    if config["taint"]:
        cmd.append("--taint")
    if config["component_graph"]:
        cmd.append("--component-graph")
    if config["chains"]:
        cmd.append("--chains")
    if config["root_cause"]:
        cmd.append("--root-cause")
    if config["dedup"]:
        cmd.append("--dedup")
    if config["confidence"]:
        cmd.append("--confidence")

    if config["fp_measure"]:
        cmd.append("--fp-measure")
    if config["fp_report"]:
        cmd.append("--fp-report")
    cmd.extend(["--fp-threshold", str(config["fp_threshold"])])

    return cmd


async def _parse_sarif(sarif_path: str) -> tuple[list[dict], list[dict]]:
    findings = []
    chains = []
    try:
        import aiofiles
        async with aiofiles.open(sarif_path, "r") as f:
            content = await f.read()
        sarif = await asyncio.to_thread(json.loads, content)
    except (FileNotFoundError, json.JSONDecodeError, Exception):
        return findings, chains

    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            finding = {
                "rule_id": result.get("ruleId", "UNKNOWN"),
                "title": result.get("message", {}).get("text", ""),
                "description": result.get("message", {}).get("text", ""),
                "severity": SEVERITY_MAP.get(result.get("level", "warning"), "MEDIUM"),
                "location": "",
                "confidence": 50,
                "validated": False,
                "category": result.get("properties", {}).get("category", ""),
                "source": result.get("properties", {}).get("source", ""),
                "original_sev": result.get("properties", {}).get("original_sev", ""),
                "impact": result.get("properties", {}).get("impact", ""),
                "recommendation": result.get("properties", {}).get("recommendation", ""),
                "escalation_rule": result.get("properties", {}).get("escalation_rule", ""),
                "rule_group": result.get("properties", {}).get("rule_group", ""),
                "poc_command": result.get("properties", {}).get("poc_command", ""),
                "poc_vector": result.get("properties", {}).get("poc_vector", ""),
                "sectors": result.get("properties", {}).get("sectors", []),
                "raw_data": result,
            }

            sev_raw = result.get("properties", {}).get("severity", "")
            if sev_raw in SCANNER_SEVERITY_MAP:
                finding["severity"] = sev_raw

            conf_raw = result.get("properties", {}).get("confidence")
            if conf_raw is not None:
                try:
                    finding["confidence"] = int(conf_raw)
                except (ValueError, TypeError):
                    pass

            validated_raw = result.get("properties", {}).get("validated", False)
            if isinstance(validated_raw, bool):
                finding["validated"] = validated_raw

            locations = result.get("locations", [])
            location_str = finding.get("location", "")
            if locations and len(locations) > 0:
                try:
                    loc = locations[0].get("physicalLocation", {}) or {}
                    art_loc = loc.get("artifactLocation", {}) or {}
                    uri = art_loc.get("uri", "") or ""
                    region = loc.get("region")
                    rline = ""
                    if region:
                        rline = str(region.get("startLine", ""))
                    if uri and rline:
                        location_str = f"{uri}:{rline}"
                    elif uri:
                        location_str = uri
                except Exception:
                    pass
            finding["location"] = location_str

            findings.append(finding)

    return findings, chains


async def _insert_findings(db: AsyncSession, scan_id_uuid, app_id_uuid, findings: list[dict]):
    for f in findings:
        db.add(Finding(
            scan_id=scan_id_uuid,
            app_id=app_id_uuid,
            rule_id=f["rule_id"],
            rule_group=f.get("rule_group", ""),
            title=f["title"],
            description=f.get("description", ""),
            severity=f["severity"],
            original_sev=f.get("original_sev", ""),
            category=f.get("category", ""),
            source=f.get("source", ""),
            confidence=f.get("confidence", 50),
            validated=f.get("validated", False),
            poc_command=f.get("poc_command", ""),
            poc_vector=f.get("poc_vector", ""),
            impact=f.get("impact", ""),
            recommendation=f.get("recommendation", ""),
            location=f.get("location", ""),
            escalation_rule=f.get("escalation_rule", ""),
            sectors=f.get("sectors", []),
            raw_data=f.get("raw_data"),
        ))
    await db.commit()


async def _log_output(db: AsyncSession, scan_id_uuid, line: str):
    level = "info"
    stripped = line.strip()
    if not stripped:
        return
    if stripped.startswith("ERROR") or stripped.startswith("CRITICAL"):
        level = "error"
    elif stripped.startswith("WARN") or stripped.startswith("WARNING"):
        level = "warn"
    elif stripped.startswith("DEBUG"):
        level = "debug"

    log_entry = ScanLog(scan_id=scan_id_uuid, level=level, message=stripped[:2000])
    db.add(log_entry)


async def _update_scan_status(db: AsyncSession, scan_id_uuid, **kwargs):
    result = await db.execute(select(Scan).where(Scan.id == scan_id_uuid))
    scan = result.scalar_one_or_none()
    if scan:
        for k, v in kwargs.items():
            setattr(scan, k, v)
        await db.commit()


async def run_scan(scan_id: str, app_id: str, config: dict):
    from services.apk_store import get_apk_path

    scan_uuid = uuid.UUID(scan_id) if isinstance(scan_id, str) else scan_id
    app_uuid = uuid.UUID(app_id) if isinstance(app_id, str) else app_id
    scan_id_str = str(scan_uuid)

    async with async_session() as db:
        process = None
        try:
            apk_path = await get_apk_path(app_uuid, db)
            cmd = _build_cli(apk_path, config, scan_id_str)
            report_dir = get_report_path(scan_id_str)
            html_path = str(report_dir / "report.html")
            sarif_path = str(report_dir / "report.sarif")

            await _update_scan_status(
                db, scan_uuid,
                status="running",
                started_at=datetime.now(timezone.utc),
            )

            start_time = datetime.now(timezone.utc)

            await publish_log(scan_id_str, "info", f"Starting scan: scan_id={scan_id_str}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

            _running_processes[scan_id_str] = {"process": process, "started_at": start_time}

            if not process.stdout:
                raise RuntimeError("Subprocess stdout is None")

            line_count = 0
            async for line in process.stdout:
                line = line.decode("utf-8", errors="replace").rstrip()
                await _log_output(db, scan_uuid, line)
                level = "info"
                stripped = line.strip()
                if stripped.startswith("ERROR") or stripped.startswith("CRITICAL"):
                    level = "error"
                elif stripped.startswith("WARN") or stripped.startswith("WARNING"):
                    level = "warn"
                elif stripped.startswith("DEBUG"):
                    level = "debug"
                await publish_log(scan_id_str, level, line)
                line_count += 1
                if line_count % LOG_COMMIT_INTERVAL == 0:
                    await db.commit()

            await db.commit()

            try:
                return_code = await asyncio.wait_for(process.wait(), timeout=30)
            except asyncio.TimeoutError:
                process.kill()
                return_code = await process.wait()

            _running_processes.pop(scan_id_str, None)
            completed_at = datetime.now(timezone.utc)
            duration = int((completed_at - start_time).total_seconds())

            if return_code == 0:
                findings, chains = await _parse_sarif(sarif_path)
                if findings:
                    await _insert_findings(db, scan_uuid, app_uuid, findings)

                await _update_scan_status(
                    db, scan_uuid,
                    status="completed",
                    completed_at=completed_at,
                    duration_secs=duration,
                    html_report_path=html_path if Path(html_path).exists() else None,
                    sarif_path=sarif_path if Path(sarif_path).exists() else None,
                )
                await publish_log(
                    scan_id_str, "info",
                    f"Scan completed: {len(findings)} findings, {duration}s"
                )
                await publish_event(scan_id_str, "scan_complete", {
                    "status": "completed",
                    "findings_count": len(findings),
                })
            else:
                await _update_scan_status(
                    db, scan_uuid,
                    status="failed",
                    completed_at=completed_at,
                    duration_secs=duration,
                    error_message=f"Scanner exited with code {return_code}",
                )
                await publish_log(scan_id_str, "error", f"Scanner failed with code {return_code}")
                await publish_event(scan_id_str, "scan_complete", {
                    "status": "failed",
                    "error": f"Exit code {return_code}",
                })

        except asyncio.TimeoutError:
            _running_processes.pop(scan_id_str, None)
            if process and process.returncode is None:
                try:
                    process.kill()
                except Exception:
                    pass
            await _safe_update_status(db, scan_uuid, status="failed", error_message="Scan timed out")
            await publish_log(scan_id_str, "error", "Scan timed out")
            await publish_event(scan_id_str, "scan_complete", {"status": "failed", "error": "timeout"})

        except Exception as e:
            _running_processes.pop(scan_id_str, None)
            if process and process.returncode is None:
                try:
                    process.kill()
                except Exception:
                    pass
            logger.exception(f"Scan {scan_id_str} failed")
            await _safe_update_status(db, scan_uuid, status="failed", error_message=str(e))
            await _safe_publish_log(scan_id_str, "error", f"Scan failed: {str(e)}")
            await _safe_publish_event(scan_id_str, "scan_complete", {"status": "failed", "error": str(e)})


async def _safe_update_status(db, scan_uuid, **kwargs):
    try:
        await _update_scan_status(db, scan_uuid, **kwargs)
    except Exception as e:
        logger.error(f"Failed to update scan status: {e}")


async def _safe_publish_log(scan_id, level, message):
    try:
        await publish_log(scan_id, level, message)
    except Exception as e:
        logger.error(f"Failed to publish log: {e}")


async def _safe_publish_event(scan_id, event, data):
    try:
        await publish_event(scan_id, event, data)
    except Exception as e:
        logger.error(f"Failed to publish event: {e}")

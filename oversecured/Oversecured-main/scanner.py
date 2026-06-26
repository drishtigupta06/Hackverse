#!/usr/bin/env python3
import sys
import os
import argparse

from core.utils import (
    IGNORED_LIBRARIES, APP_INTERNAL_PACKAGES_WHITELIST,
    is_library_class, is_library_file,
    extract_class_name_from_finding, post_process_findings,
)
from core.orchestrator import ScanConfig, run_scan, build_report_data

def parse_args():
    parser = argparse.ArgumentParser(description="Bug Bounty Android App Scanner - Find exploitable vulnerabilities in Android apps")
    parser.add_argument("apk", nargs="?", help="Path to the APK file to scan")
    parser.add_argument("-r", "--rules", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules"), help="Path to folder containing YAML rules")
    parser.add_argument("-t", "--template", default="templates/report.html", help="Path to HTML template")
    parser.add_argument("-o", "--output", default="report.html", help="Path to output HTML report")

    # ── Bug Bounty 1-Click Mode ──
    parser.add_argument("-bb", "--bb", action="store_true", dest="bug_bounty_oneclick",
                        help="ONE-CLICK BUG BOUNTY: full scan + auto PoC + chains + dedup + screenshots (1hr target)")
    parser.add_argument("--fp-filter", choices=["off", "basic", "aggressive"], default="basic",
                        help="False positive filter level (default: basic)")

    parser.add_argument("--skip-jadx", action="store_true", help="Skip decompilation and source code analysis")
    parser.add_argument("--jadx-dir", type=str, default=None, help="Use existing JADX output directory instead of decompiling")
    parser.add_argument("--skip-phase2", action="store_true", help="Skip Phase 2 advanced static analysis")
    parser.add_argument("--cve-update", action="store_true", help="Auto-download latest Android CVEs and generate detection rules")
    parser.add_argument("--cve-list", nargs="+", help="Specific CVE IDs to analyze (e.g., CVE-2025-XXXX)")
    parser.add_argument("--cve-days", type=int, default=90, help="Days back to search for CVEs (default: 90)")
    parser.add_argument("--cve-search", type=str, help="Keyword search for CVEs (e.g., 'WebView RCE')")
    parser.add_argument("--frida", type=str, metavar="PACKAGE", help="Run Frida dynamic analysis on a running app (package name)")
    parser.add_argument("--frida-spawn", type=str, metavar="PACKAGE", help="Spawn and run Frida dynamic analysis on an app")
    parser.add_argument("--frida-device", default="usb", help="Frida device ID (default: usb)")
    parser.add_argument("--frida-ssl", action="store_true", help="Frida: SSL Pinning detection only")
    parser.add_argument("--frida-root", action="store_true", help="Frida: Root detection detection only")
    parser.add_argument("--frida-hooks", action="store_true", help="Frida: Runtime hooks only")
    parser.add_argument("--frida-api", action="store_true", help="Frida: API monitoring only")
    parser.add_argument("--frida-prefs", action="store_true", help="Frida: SharedPrefs monitoring only")
    parser.add_argument("--frida-all", action="store_true", help="Frida: Run all dynamic analysis modules")
    parser.add_argument("--frida-timeout", type=int, default=30, help="Frida timeout in seconds (default: 30)")
    parser.add_argument("--exploit", action="store_true", help="Enable automatic exploit generation (Finding → PoC → Validation)")
    parser.add_argument("--exploit-vector", nargs="+", default=["adb", "drozer", "frida"],
                        choices=["adb", "drozer", "frida"],
                        help="Exploit vectors to use (default: all)")
    parser.add_argument("--exploit-validate", action="store_true",
                        help="Run automatic validation of generated exploits (requires device-connected ADB)")
    parser.add_argument("--exploit-pkg", type=str,
                        help="Target package name for exploit generation (defaults to APK package)")
    parser.add_argument("--taint", action="store_true",
                        help="Run real inter-procedural taint analysis (cross-file, cross-method)")
    parser.add_argument("--component-graph", action="store_true",
                        help="Build Android component attack surface graph with attack paths")
    parser.add_argument("--dynamic", action="store_true",
                        help="Run auto UI exploration + input fuzzing + deep link/provider fuzzing (requires device)")
    parser.add_argument("--dynamic-mode", choices=["basic", "complete", "dast"], default="basic",
                        help="Dynamic analysis mode: basic (adb uiautomator), complete (uiautomator2 + WebView + Frida), dast (IPC fuzz + UI + storage)")
    parser.add_argument("--dynamic-pkg", type=str,
                        help="Package name for dynamic analysis (defaults to APK package)")
    parser.add_argument("--dynamic-max-screens", type=int, default=20,
                        help="Max screens to explore in UI traversal (default: 20)")
    parser.add_argument("--dynamic-time", type=int, default=300,
                        help="Max seconds for dynamic phase (default: 300)")
    parser.add_argument("--ipc-only", action="store_true",
                        help="Run only IPC fuzzing (intents/broadcasts/providers/deeplinks)")
    parser.add_argument("--storage-only", action="store_true",
                        help="Run only runtime storage inspection")
    parser.add_argument("--chains", action="store_true",
                        help="Build exploit chains from findings (e.g., ExportedActivity + IntentRedirection + WebView = CRITICAL)")
    parser.add_argument("--benchmark", action="store_true",
                        help="Run benchmark suite against gold standards (requires APKs in benchmarks/<name>/)")
    parser.add_argument("--root-cause", action="store_true",
                        help="Deduplicate findings into root cause groups")
    parser.add_argument("--dedup", action="store_true",
                        help="Root cause dedup: compress findings into ROOT-001..ROOT-020")
    parser.add_argument("--confidence", action="store_true",
                        help="Score findings by confidence (STATIC/DATAFLOW/TAINT/DYNAMIC/EXPLOIT)")
    parser.add_argument("--coverage-audit", action="store_true",
                        help="Audit rule coverage against OWASP Mobile Top 10 / MASVS / Bug Bounty classes")
    parser.add_argument("--ai-triage", action="store_true",
                        help="Use Ollama AI to triage findings for exploitability (requires Ollama)")
    parser.add_argument("--ai-model", type=str, default="llama2",
                        help="Ollama model to use for AI triage (default: llama2)")
    parser.add_argument("--ai-confidence", type=str, default="Medium",
                        choices=["Low", "Medium", "High"],
                        help="Minimum AI confidence level for findings (default: Medium)")
    parser.add_argument("--bug-bounty", action="store_true", default=True,
                        help="Enable bug bounty focused workflow (prioritizes exploitable findings)")

    # ── False Positive Analysis ───────────────────────────────────────────
    parser.add_argument("--fp-measure", action="store_true",
                        help="Run with FP analysis: record findings for empirical FPR measurement")
    parser.add_argument("--fp-report", action="store_true",
                        help="Print FP analysis report after scan (requires prior --fp-measure runs)")
    parser.add_argument("--fp-export", type=str, default="", metavar="MANIFEST.json",
                        help="Export suppression manifest to JSON file")
    parser.add_argument("--fp-import", type=str, default="", metavar="MANIFEST.json",
                        help="Import suppression manifest from JSON file")
    parser.add_argument("--fp-threshold", type=float, default=0.30,
                        help="FPR threshold for auto-suppression (default: 0.30 = 30 percent)")
    parser.add_argument("--fp-clean-dir", type=str, default="", metavar="DIR",
                        help="Directory of known-clean APKs to use as FP baseline")

    parser.add_argument("--confirmed", action="store_true",
                        help="Enable confirmed-findings mode: only include validated exploits in report")
    parser.add_argument("--confirmed-min-confidence", type=str, default="medium",
                        choices=["low", "medium", "high"],
                        help="Minimum confidence for confirmed findings (default: medium)")
    parser.add_argument("--confirmed-export", type=str, default="", metavar="JSON",
                        help="Export confirmed findings as standalone JSON")

    # ── Inbuilt Emulator (Bug Bounty One-Click) ─────────────────────
    parser.add_argument("--emulator", action="store_true", dest="emulator_mode",
                        help="ONE-CLICK EMULATOR: auto-launch AVD, install APK+frida, validate exploits, capture screenshots, auto-cleanup")
    parser.add_argument("--emulator-avd", type=str, default="",
                        help="AVD name to use (default: auto-detect first available)")
    parser.add_argument("--emulator-ram", type=str, default="2048",
                        help="Emulator RAM in MB (default: 2048)")
    parser.add_argument("--no-emulator-cleanup", action="store_false", dest="emulator_cleanup", default=True,
                        help="Keep emulator running after scan (default: shutdown)")
    parser.add_argument("--screenrecord", action="store_true",
                        help="Record MP4 video of each exploit PoC execution (saved alongside HTML report)")
    parser.add_argument("--screenrecord-duration", type=int, default=8,
                        help="Max seconds per screen recording (default: 8)")
    parser.add_argument("--screenrecord-bitrate", type=int, default=1000000,
                        help="Bitrate for screen recording in bps (default: 1Mbps)")

    parser.add_argument("--emulator-test", action="store_true",
                        help="(Deprecated) Use --emulator instead")

    # ── SARIF Output ──
    parser.add_argument("--sarif", type=str, default="", metavar="OUTPUT.sarif",
                        help="Export findings in SARIF v2.1.0 format (e.g., results.sarif)")

    # ── Scan History ──
    parser.add_argument("--history-save", action="store_true",
                        help="Save scan to SQLite history database")
    parser.add_argument("--history-list", action="store_true",
                        help="List recent scans from history database")
    parser.add_argument("--history-show", type=int, default=None, metavar="ID",
                        help="Show details of a specific scan by ID")
    parser.add_argument("--history-compare", nargs=2, type=int, default=None, metavar=("ID1", "ID2"),
                        help="Compare two scans by their IDs")
    parser.add_argument("--history-stats", action="store_true",
                        help="Show aggregate statistics from scan history")

    # ── Frida ↔ Static Linking ──
    parser.add_argument("--frida-link", action="store_true",
                        help="Link Frida runtime findings to static analysis findings")
    return parser.parse_args()

def generate_report(template_path, output_path, data):
    template_dir = os.path.dirname(template_path) or "."
    template_file = os.path.basename(template_path)
    
    try:
        from jinja2 import Environment, FileSystemLoader
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template(template_file)
        
        with open(output_path, "w", encoding='utf-8') as f:
            f.write(template.render(data))
            
        print(f"[+] HTML Report generated successfully at: {output_path}")
    except Exception as e:
        print(f"[-] Error generating HTML report: {e}")

def main():
    args = parse_args()
    
    # ── Emulator Mode ──
    if args.emulator_mode:
        print("[*] ═══════════════════════════════════════════")
        print("[*]  INBUILT EMULATOR MODE")
        print("[*]  Auto-enabling: emulator, exploit-validate,")
        print("[*]  dynamic, screenshots, auto-cleanup")
        print("[*] ═══════════════════════════════════════════")
        args.exploit = True
        args.exploit_validate = True
        args.dynamic = True
        if args.fp_filter == "off":
            args.fp_filter = "basic"

    # ── Bug Bounty 1-Click Mode ──
    if args.bug_bounty_oneclick:
        print("[*] ═══════════════════════════════════════════")
        print("[*]  BUG BOUNTY 1-CLICK MODE")
        print("[*]  Auto-enabling: exploit, chains, dedup,")
        print("[*]  confidence, taint, component-graph,")
        print("[*]  frida-hooks, emulator, screenrecord,")
        print("[*]  exploit-validate, dynamic")
        print("[*] ═══════════════════════════════════════════")
        args.exploit = True
        args.chains = True
        args.dedup = True
        args.confidence = True
        args.taint = True
        args.component_graph = True
        args.frida_hooks = True
        args.exploit_validate = True
        args.dynamic = True
        args.emulator_mode = True
        args.screenrecord = True
        if args.fp_filter == "off":
            args.fp_filter = "basic"
    
    # ── Bug Bounty Workflow ──
    print("[*] Bug Bounty Scanner - Optimizing for exploitable findings")
    if args.bug_bounty or args.bug_bounty_oneclick:
        print("[*] Bug bounty mode enabled - prioritizing critical and exploitable vulnerabilities")

    # ── Benchmark Mode ──
    if args.benchmark:
        print("[*] ── Benchmark Suite ──")
        from benchmarks.benchmark_runner import BenchmarkRunner
        from benchmarks.rule_coverage import RuleCoverageAudit
        runner = BenchmarkRunner()
        manifest_only = not (args.taint or args.component_graph)
        runner.run_all(manifest_only=manifest_only)
        runner.print_matrix()
        print("\n[*] Rule Coverage Audit:")
        try:
            RuleCoverageAudit().print_report()
        except Exception as e:
            print(f"[-] Rule coverage audit error (non-fatal): {e}")
        return

    if args.coverage_audit:
        from benchmarks.rule_coverage import RuleCoverageAudit
        RuleCoverageAudit().print_report()
        return

    # ── Scan History Standalone Commands ──
    from core.scan_history import ScanHistory
    history = ScanHistory()
    if args.history_list:
        scans = history.list_scans()
        if not scans:
            print("[*] No scans in history.")
            return
        print(f"{'ID':<5} {'Date':<22} {'Package':<30} {'App':<25} {'Findings':<10} {'Crit':<6} {'High':<6} {'Expl':<6}")
        print("-" * 110)
        for s in scans:
            print(f"{s['id']:<5} {s['scan_date'][:19]:<22} {s['package_name'][:29]:<30} {s['app_name'][:24]:<25} "
                  f"{s['total_findings']:<10} {s['critical_count']:<6} {s['high_count']:<6} {s['exploitable_count']:<6}")
        return
    if args.history_show:
        s = history.get_scan(args.history_show)
        if not s:
            print(f"[-] Scan #{args.history_show} not found.")
            return
        print(f"[*] Scan #{s['id']} — {s['app_name'] or s['package_name']}")
        print(f"    APK: {s['apk_path']}")
        print(f"    Package: {s['package_name']}")
        print(f"    Date: {s['scan_date']}")
        print(f"    Duration: {s['duration_seconds']}s")
        print(f"    Total findings: {s['total_findings']}")
        print(f"    Critical: {s['critical_count']}  High: {s['high_count']}  Medium: {s['medium_count']}  Low: {s['low_count']}")
        print(f"    Exploitable: {s['exploitable_count']}  Validated: {s['validated_count']}")
        if s.get('sarif_path'):
            print(f"    SARIF: {s['sarif_path']}")
        return
    if args.history_compare:
        result = history.compare_scans(args.history_compare[0], args.history_compare[1])
        if "error" in result:
            print(f"[-] {result['error']}")
            return
        print(f"[*] Scan Comparison: {result['app']}")
        print(f"    {'Metric':<25} {'Scan #1':<12} {'Scan #2':<12} {'Diff':<12}")
        print(f"    {'-'*25} {'-'*12} {'-'*12} {'-'*12}")
        diff = result["diff"]
        s1, s2 = result["scan_1"], result["scan_2"]
        for key, label in [("total_findings", "Total Findings"), ("critical_count", "Critical"),
                           ("high_count", "High"), ("exploitable_count", "Exploitable"),
                           ("validated_count", "Validated")]:
            v1, v2 = s1[key], s2[key]
            d = diff[key]
            sign = "+" if d > 0 else ""
            print(f"    {label:<25} {v1:<12} {v2:<12} {sign}{d:<11}")
        return
    if args.history_stats:
        stats = history.stats()
        print("[*] Scan History Statistics")
        print(f"    Total scans: {stats['total_scans']}")
        print(f"    Total findings: {stats['total_findings']}")
        print(f"    Total critical: {stats['total_critical']}")
        print(f"    Total high: {stats['total_high']}")
        print(f"    Total exploitable: {stats['total_exploitable']}")
        print(f"    Avg critical/high per scan: {stats['avg_critical_high_per_scan']}")
        return

    if not args.apk:
        print("[-] Error: APK file path is required (unless --benchmark is used)")
        sys.exit(1)

    if not os.path.isfile(args.apk):
        print(f"[-] Error: APK file '{args.apk}' not found!")
        sys.exit(1)

    min_confidence = {"off": 10, "basic": 25, "aggressive": 40}.get(args.fp_filter, 25)
    config = ScanConfig(
        apk=args.apk,
        rules=args.rules,
        template=args.template,
        output=args.output,
        skip_jadx=args.skip_jadx,
        jadx_dir=args.jadx_dir,
        skip_phase2=args.skip_phase2,
        cve_update=args.cve_update,
        cve_list=args.cve_list,
        cve_days=args.cve_days,
        cve_search=args.cve_search,
        frida=args.frida,
        frida_spawn=args.frida_spawn,
        frida_device=args.frida_device,
        frida_ssl=args.frida_ssl,
        frida_root=args.frida_root,
        frida_hooks=args.frida_hooks,
        frida_api=args.frida_api,
        frida_prefs=args.frida_prefs,
        frida_all=args.frida_all,
        frida_timeout=args.frida_timeout,
        exploit=args.exploit,
        exploit_vector=args.exploit_vector,
        exploit_validate=args.exploit_validate,
        exploit_pkg=args.exploit_pkg,
        taint=args.taint,
        component_graph=args.component_graph,
        dynamic=args.dynamic,
        dynamic_mode=args.dynamic_mode,
        dynamic_pkg=args.dynamic_pkg,
        dynamic_max_screens=args.dynamic_max_screens,
        dynamic_time=args.dynamic_time,
        ipc_only=args.ipc_only,
        storage_only=args.storage_only,
        chains=args.chains,
        root_cause=args.root_cause,
        dedup=args.dedup,
        confidence=args.confidence,
        ai_triage=args.ai_triage,
        ai_model=args.ai_model,
        ai_confidence=args.ai_confidence,
        bug_bounty=args.bug_bounty or args.bug_bounty_oneclick,
        sarif=args.sarif,
        history_save=args.history_save,
        frida_link=args.frida_link,
        min_confidence=min_confidence,
        confirmed=args.confirmed,
        confirmed_min_confidence=args.confirmed_min_confidence,
        confirmed_export=args.confirmed_export,
        emulator_mode=args.emulator_mode,
        emulator_avd=args.emulator_avd,
        emulator_ram=args.emulator_ram,
        emulator_cleanup=args.emulator_cleanup if hasattr(args, 'emulator_cleanup') else True,
        emulator_test=args.emulator_test,
    )

    # ── Emulator lifecycle (start before scan) ──────────────────────
    _emulator_mgr = None
    if args.emulator_mode:
        print("[*] ═══════════════════════════════════════════")
        print("[*]  Starting inbuilt emulator...")
        print("[*] ═══════════════════════════════════════════")
        from core.emulator import EmulatorManager
        avd = args.emulator_avd or None
        _emulator_mgr = EmulatorManager(
            avd_name=avd,
            emulator_ram=args.emulator_ram,
        )
        serial = _emulator_mgr.ensure_running()
        config.device_serial = serial
        _emulator_mgr.install_apk(args.apk)
        _emulator_mgr.ensure_frida()
        print(f"[+] Emulator ready on {serial}")

    result = run_scan(config)

    # ── Emulator screenshots from validated exploits ────────────────
    _emulator_ss = {}
    _MAX_SS_FINDINGS = 20  # cap to avoid multi-minute screenshot loops
    if _emulator_mgr and result.exploit_results and result.package_name:
        print("[*] ── Emulator Exploit Screenshots ──")
        import time as _time
        import re as _re

        # Build a map of finding_id → finding data for manifest + source findings
        _findings_map = {}
        for f in (result.manifest_findings or []) + (result.source_findings or []):
            _findings_map[f.get("id", "")] = f

        _ss_findings = result.exploit_results[:_MAX_SS_FINDINGS]
        if len(result.exploit_results) > _MAX_SS_FINDINGS:
            print(f"  [SS] Limiting to {_MAX_SS_FINDINGS}/{len(result.exploit_results)} exploit screenshots")
        for er in _ss_findings:
            fid = er.get("finding_id", "")
            if not fid or fid in _emulator_ss:
                continue
            fdata = _findings_map.get(fid, {})
            ftype = er.get("finding_adb_key", "") or er.get("finding_type", fdata.get("type", ""))
            matches = fdata.get("matches", [])
            pkg = result.package_name

            # Determine the exploit command to run based on finding data
            cmd = None
            has_actual_launch = False

            # Extract schemes, hosts, components from matches
            exported_components = []
            exported_authorities = []
            scheme = fdata.get("scheme", "")
            host = fdata.get("host", "")
            deep_link_path = fdata.get("deep_link_path", "")
            is_provider = "Provider" in fdata.get("name", "") or "provider" in ftype.lower()

            for m in matches:
                if not isinstance(m, str):
                    continue
                for a in _re.findall(r"android:name='([^']*)'", m):
                    if a and a != "N/A":
                        exported_components.append(a)
                for a in _re.findall(r"android:scheme='([^']*)'", m):
                    if a and not scheme:
                        scheme = a
                for a in _re.findall(r"android:host='([^']*)'", m):
                    if a and not host:
                        host = a
                for a in _re.findall(r"android:authority='([^']*)'", m):
                    if a:
                        exported_authorities.append(a)
                # Extract parent activity from match text
                for a in _re.findall(r"parent='([^']*)'", m):
                    if a and a not in exported_components:
                        exported_components.append(a)

            # 1. Deep link → try targeting specific activity with -n (avoids browser intercept)
            if ftype in ("deep_link", "custom_scheme", "deeplink"):
                if exported_components:
                    comp = exported_components[0]
                    if comp.startswith("."):
                        comp = f"{pkg}/{comp}"
                    elif not comp.startswith(pkg):
                        comp = f"{pkg}/{comp}"
                    if scheme and scheme not in ("http", "https"):
                        target_uri = f"{scheme}://{host or 'open'}"
                        if deep_link_path:
                            target_uri += deep_link_path
                        cmd = f"am start -n {comp} -d '{target_uri}/?url=https://attacker.com/poc'"
                    else:
                        cmd = f"am start -n {comp} --es url 'https://attacker.com/poc'"
                    has_actual_launch = True
                elif scheme and scheme not in ("http", "https"):
                    target_uri = f"{scheme}://{host or 'open'}"
                    if deep_link_path:
                        target_uri += deep_link_path
                    cmd = f"am start -a android.intent.action.VIEW -d '{target_uri}/?url=https://attacker.com/poc'"
                    has_actual_launch = True
                elif scheme == "https" and host:
                    cmd = f"am start -a android.intent.action.VIEW -d 'https://{host}/?url=https://attacker.com/poc'"
                    has_actual_launch = True

            # 3. Provider
            elif is_provider and exported_authorities:
                uri = f"content://{exported_authorities[0]}"
                cmd = f"content query --uri {uri}"
                has_actual_launch = True

            # 4. Exported component (activity/service/receiver)
            elif exported_components:
                comp = exported_components[0]
                for c in exported_components:
                    if "Main" not in c and "Launcher" not in c:
                        comp = c
                        break
                if comp.startswith("."):
                    comp = f"{pkg}/{comp}"
                elif comp.startswith(pkg):
                    short = comp[len(pkg):]
                    if not short.startswith("."):
                        short = "." + short
                    comp = f"{pkg}/{short}"
                else:
                    comp = f"{pkg}/{comp}"
                cmd = f"am start -n {comp}"
                has_actual_launch = True
            else:
                # 5. Try poc_steps from exploit result
                for vec, vdata in er.get("vectors", {}).items():
                    if not isinstance(vdata, dict):
                        continue
                    steps = vdata.get("poc_steps", [])
                    for step in steps:
                        if not isinstance(step, str):
                            continue
                        if "am start" in step:
                            s = step.replace("adb shell ", "", 1)
                            cmd = s.replace("adb ", "", 1)
                            has_actual_launch = True
                            break
                        elif "content query" in step:
                            s = step.replace("adb shell ", "", 1)
                            cmd = s.replace("adb ", "", 1)
                            break
                    if cmd:
                        break
                if not cmd:
                    cmd = f"monkey -p {pkg} 1"

            before = _emulator_mgr.capture_screenshot(f"ss_{fid}_before")

            # Build ADB command list
            cmd_list = None
            if has_actual_launch and cmd:
                cmd_list = _emulator_mgr.cmd_prefix() + ["shell", cmd]

            # Screen recording (runs exploit command DURING recording)
            video_b64 = None
            if args.screenrecord:
                print(f"  [SS] Recording video for {fid} ({args.screenrecord_duration}s)...")
                video_b64 = _emulator_mgr.capture_video(
                    name=f"rec_{fid}",
                    duration=args.screenrecord_duration,
                    bit_rate=args.screenrecord_bitrate,
                    cmd_text=f"$ {cmd}",
                    run_cmd=cmd_list,
                )
            elif has_actual_launch and cmd_list:
                _emulator_mgr._run_cmd(cmd_list, timeout=10)
                _time.sleep(2)

            after = _emulator_mgr.capture_screenshot(f"ss_{fid}_after")

            # Check which app actually handled the intent
            fg_pkg = ""
            if has_actual_launch:
                _time.sleep(1.5)
                fg_pkg = _emulator_mgr._get_foreground_package()
                if fg_pkg and fg_pkg != pkg:
                    print(f"  [SS] ⚠ {fid}: intent handled by {fg_pkg}, NOT {pkg}")

            _emulator_ss[fid] = {
                "before_b64": before or "",
                "after_b64": after or "",
                "video_b64": video_b64 or "",
                "cmd": cmd or "",
                "has_actual_launch": has_actual_launch,
                "foreground_pkg": fg_pkg,
            }
            print(f"  [SS] {fid}: before={'y' if before else 'n'} after={'y' if after else 'n'}"
                  f" video={'y' if video_b64 else 'n'}"
                  f"{' (launch)' if has_actual_launch else ' (verify)'}"
                  f"{f' → {fg_pkg}' if fg_pkg and fg_pkg != pkg else ''}")

        if _emulator_ss:
            launches = sum(1 for v in _emulator_ss.values() if v.get("has_actual_launch"))
            videos = sum(1 for v in _emulator_ss.values() if v.get("video_b64"))
            print(f"[+] Captured {len(_emulator_ss)} exploit screenshot pairs "
                  f"({launches} with actual component launch, {videos} with video recording)")

    # ── Screenshot diffing (before vs after) ─────────────────────────
    _ss_diffs = {}
    if _emulator_ss and _emulator_mgr:
        print("[*] ── Screenshot Diff Analysis ──")
        for fid, sdata in _emulator_ss.items():
            diff = _emulator_mgr.diff_screenshots(
                sdata.get("before_b64"), sdata.get("after_b64")
            )
            _ss_diffs[fid] = diff
            flag = "✓ CHANGED" if diff["diff_score"] > 0.01 else "✗ SAME"
            print(f"  [Diff] {fid}: score={diff['diff_score']:.4f} {flag}")
        changed = sum(1 for d in _ss_diffs.values() if d["diff_score"] > 0.01)
        print(f"[+] Screenshot diffs: {changed}/{len(_ss_diffs)} show actual UI change")

    # ── Frida Runtime Hooks ──────────────────────────────────────────
    _frida_findings = []
    if _emulator_mgr and result.package_name and (args.frida_hooks or args.frida_all or args.bug_bounty_oneclick):
        print("[*] ── Frida Runtime Hooks ──")
        _frida_findings = _emulator_mgr.run_frida_hooks(
            pkg=result.package_name,
            timeout=args.frida_timeout if hasattr(args, 'frida_timeout') else 20,
        )
        # Group findings by type
        from collections import Counter
        type_counts = Counter(f.get("type", "?") for f in _frida_findings)
        sev_counts = Counter(f.get("severity", "?") for f in _frida_findings)
        print(f"[Frida] {len(_frida_findings)} total events: "
              f"{dict(type_counts)}, severity: {dict(sev_counts)}")

    # ── Bug Bounty Report Summary ──
    p1 = len(result.manifest_findings) + len(result.source_findings)
    p2 = sum(len(g["rules"]) for g in result.phase2_findings)
    critical_count = sum(
        1 for f in result.manifest_findings + result.source_findings
        if f.get('severity') in ['CRITICAL', 'HIGH']
    )
    exploitable_count = len(result.exploit_results) if result.exploit_results else 0

    print(f"[*] === BUG BOUNTY REPORT ===")
    print(f"[+] Total issues: {p1 + p2} (Phase 1: {p1}, Phase 2: {p2})")
    print(f"[+] Critical/High severity: {critical_count}")
    print(f"[+] Exploitable findings: {exploitable_count}")
    if args.chains:
        print(f"[+] Attack chains found: {result.chain_summary.get('total_chains', 0)}")
    if args.confidence:
        print(f"[+] Verified exploits: {result.confidence_summary.get('verified', 0)}")
    if result.confirmed_summary:
        cs = result.confirmed_summary
        print(f"[+] CONFIRMED FINDINGS: {cs['total_confirmed']} "
              f"(validated: {cs['validated']}, critical+high: {cs['critical_high']})")

    all_f_ids = []
    for f in result.manifest_findings:
        all_f_ids.append(f.get("id", "") or f.get("name", "")[:20])
    for f in result.source_findings:
        all_f_ids.append(f.get("id", "") or f.get("name", "")[:20])
    for g in result.phase2_findings:
        for r in g.get("rules", []):
            all_f_ids.append(r.get("id", "") or r.get("name", "")[:30])
    if all_f_ids:
        print(f"[+] Finding IDs: {' '.join(all_f_ids)}")

    report_data = build_report_data(result, config)

    if _emulator_ss:
        if "exploit_screenshots" not in report_data:
            report_data["exploit_screenshots"] = {}
        report_data["exploit_screenshots"]["emulator_before_after"] = _emulator_ss
        ss = report_data["exploit_screenshots"]
        eba = ss.get("emulator_before_after", {})
        ind_count = len(ss.get("individual", {}))
        has_global = bool(ss.get("before_b64") and ss.get("after_b64", False))
        print(f"[+] Emulator screenshots: {len(eba)} before/after pairs, {ind_count} individual, global={has_global}")

    if _ss_diffs:
        report_data["screenshot_diffs"] = _ss_diffs

    if _frida_findings:
        report_data["frida_findings"] = _frida_findings

    # ── Generate HTML Report ──
    if not os.path.exists(args.template):
        print(f"[-] Template file not found: {args.template}")
    else:
        generate_report(args.template, args.output, report_data)

    # ── SARIF Export ──
    if args.sarif:
        print(f"[*] ── SARIF Export ──")
        try:
            from core.sarif_exporter import SarifExporter
            sarif_exporter = SarifExporter(
                apk_path=result.apk_path,
                package_name=result.package_name,
                app_name=result.app_name,
            )
            sarif_path = sarif_exporter.export(report_data, args.sarif)
            print(f"[+] SARIF report generated: {sarif_path}")
        except Exception as e:
            print(f"[-] SARIF export failed: {e}")
            import traceback; traceback.print_exc()

    # ── Scan History Save ──
    if args.history_save:
        try:
            from core.scan_history import ScanHistory
            history = ScanHistory()
            total_f_all = len(result.manifest_findings) + len(result.source_findings)
            for g in result.phase2_findings:
                total_f_all += len(g.get("rules", []))
            critical_count = sum(
                1 for f in result.manifest_findings + result.source_findings
                if f.get("severity") in ("CRITICAL",)
            )
            high_count = sum(
                1 for f in result.manifest_findings + result.source_findings
                if f.get("severity") == "HIGH"
            )
            medium_count = sum(
                1 for f in result.manifest_findings + result.source_findings
                if f.get("severity") == "MEDIUM"
            )
            low_count = sum(
                1 for f in result.manifest_findings + result.source_findings
                if f.get("severity") in ("LOW", "INFO")
            )
            exploitable_count = len(result.exploit_results) if result.exploit_results else 0
            validated_count = result.exploit_summary.get("validated", 0) if result.exploit_summary else 0

            scan_id = history.save_scan(
                apk_path=result.apk_path,
                package_name=result.package_name,
                app_name=result.app_name,
                duration_seconds=0,
                total_findings=total_f_all,
                critical_count=critical_count,
                high_count=high_count,
                medium_count=medium_count,
                low_count=low_count,
                exploitable_count=exploitable_count,
                validated_count=validated_count,
                sarif_path=args.sarif if args.sarif else "",
                args_list=sys.argv,
            )
            print(f"[+] Scan saved to history (ID: {scan_id})")
        except Exception as e:
            print(f"[-] Failed to save scan history: {e}")

    print("[*] Scan complete.")

    # ── Confirmed Findings Export ──────────────────────────────────────
    if args.confirmed_export and result.confirmed_findings:
        try:
            path = args.confirmed_export
            with open(path, "w") as f:
                json.dump(result.confirmed_findings, f, indent=2)
            print(f"[+] Confirmed findings exported: {path}")
        except Exception as e:
            print(f"[-] Confirmed export failed: {e}")

    # ── Emulator Cleanup ───────────────────────────────────────────────
    if _emulator_mgr is not None:
        if args.emulator_cleanup:
            print("[*] Emulator cleanup: stopping emulator...")
            _emulator_mgr.stop()
        else:
            print(f"[*] Emulator left running on {_emulator_mgr.serial}")

    # ── Emulator-based Testing (deprecated) ──────────────────────
    if args.emulator_test:
        try:
            from core.exploit.emulator_harness import EmulatorHarness
            print("[*] ── Emulator Testing ──")
            findings_to_test = []
            for cf in result.confirmed_findings or []:
                findings_to_test.append({
                    "id": cf.get("finding_id"),
                    "type": cf.get("category", "generic"),
                    "severity": cf.get("severity"),
                    "finding_name": cf.get("finding_name"),
                })
            if not findings_to_test:
                print("[!] No confirmed findings to test in emulator. Run with --exploit --confirmed first.")
            else:
                with EmulatorHarness(
                    apk_path=args.apk,
                    avd_name=args.emulator_avd or "",
                    android_home=args.emulator_android_home or None,
                ) as harness:
                    emulator_results = harness.run_tests(findings_to_test)
                    report_path = args.emulator_report or "/tmp/emulator_test_report.json"
                    saved = harness.export_report(emulator_results, report_path)
                    passed = sum(1 for r in emulator_results if r.success)
                    failed = sum(1 for r in emulator_results if not r.success)
                    print(f"[+] Emulator tests: {passed} passed, {failed} failed")
                    print(f"[+] Report saved: {saved}")
                    for r in emulator_results:
                        status = "PASS" if r.success else "FAIL"
                        print(f"  [{status}] {r.test_name}: {r.finding_type} ({r.duration_seconds:.1f}s)")
        except Exception as e:
            print(f"[-] Emulator testing failed: {e}")
            import traceback; traceback.print_exc()

    return
        
if __name__ == "__main__":
    main()

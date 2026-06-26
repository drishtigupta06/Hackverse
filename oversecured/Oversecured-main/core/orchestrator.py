"""
Scan Orchestrator — programmatic API for running multi-phase Android APK analysis
"""
import os
import sys
import re
import base64
import zipfile
import subprocess
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

from core.analyzer import ManifestAnalyzer
from core.source_analyzer import SourceAnalyzer
from core.jadx_manager import JadxManager
from core.static_analyzer import StaticAnalyzer
from core.cve_analyzer import CVEAnalyzer
from core.frida_analyzer import FridaAnalyzer, check_frida_availability
from core.exploit.exploit_engine import ExploitEngine
from core.exploit.validated_chain_engine import ValidatedChainEngine
from core.taint_engine import InterproceduralTaintTracker
from core.component_graph import AndroidComponentGraph
from core.dynamic.dynamic_engine import DynamicEngine
from core.exploit_chain_engine import ExploitChainEngine
from benchmarks.root_cause_engine import RootCauseEngine
from core.root_cause_dedup import RootCauseDedup
from benchmarks.confidence_scorer import ConfidenceScorer
from core.ai_triage import AITriageEngine
from core.sarif_exporter import SarifExporter
from core.scan_history import ScanHistory
from core.frida_static_linker import FridaStaticLinker
from core.fp_analyzer import FPAnalyzer
from core.exploit.confirmed_findings import ConfirmedFindingsEngine, build_confirmed_section
from core.escalation_engine import EscalationEngine


@dataclass
class ScanConfig:
    apk: str = ""
    rules: str = "rules"
    template: str = "templates/report.html"
    output: str = "report.html"
    skip_jadx: bool = False
    jadx_dir: Optional[str] = None
    skip_phase2: bool = False
    cve_update: bool = False
    cve_list: Optional[List[str]] = None
    cve_days: int = 90
    cve_search: Optional[str] = None
    frida: Optional[str] = None
    frida_spawn: Optional[str] = None
    frida_device: str = "usb"
    frida_ssl: bool = False
    frida_root: bool = False
    frida_hooks: bool = False
    frida_api: bool = False
    frida_prefs: bool = False
    frida_all: bool = False
    frida_timeout: int = 30
    exploit: bool = False
    exploit_vector: List[str] = field(default_factory=lambda: ["adb", "drozer", "frida"])
    exploit_validate: bool = False
    exploit_pkg: Optional[str] = None
    taint: bool = False
    component_graph: bool = False
    dynamic: bool = False
    dynamic_mode: str = "basic"
    dynamic_pkg: Optional[str] = None
    dynamic_max_screens: int = 20
    dynamic_time: int = 300
    ipc_only: bool = False
    storage_only: bool = False
    chains: bool = False
    root_cause: bool = False
    dedup: bool = False
    confidence: bool = False
    coverage_audit: bool = False
    ai_triage: bool = False
    ai_model: str = "llama2"
    ai_confidence: str = "Medium"
    bug_bounty: bool = True
    sarif: str = ""
    history_save: bool = False
    frida_link: bool = False
    benchmark: bool = False
    fp_measure: bool = False
    fp_report: bool = False
    fp_export: str = ""
    min_confidence: int = 25
    fp_import: str = ""
    fp_threshold: float = 0.30
    fp_clean_dir: str = ""
    confirmed: bool = False
    confirmed_min_confidence: str = "medium"
    confirmed_export: str = ""
    emulator_mode: bool = False
    emulator_avd: str = ""
    emulator_ram: str = "2048"
    emulator_cleanup: bool = True
    emulator_test: bool = False
    emulator_android_home: str = ""
    device_serial: Optional[str] = None


@dataclass
class ScanResult:
    """Holds all findings and analysis results from a scan."""
    apk_path: str = ""
    package_name: str = ""
    app_name: str = ""
    manifest_findings: List = field(default_factory=list)
    source_findings: List = field(default_factory=list)
    ai_triage_findings: List = field(default_factory=list)
    ai_triage_summary: dict = field(default_factory=dict)
    phase2_findings: List = field(default_factory=list)
    phase2_summary: dict = field(default_factory=dict)
    cve_data: dict = field(default_factory=dict)
    frida_findings: dict = field(default_factory=dict)
    frida_summary: dict = field(default_factory=dict)
    exploit_results: List = field(default_factory=list)
    exploit_summary: dict = field(default_factory=dict)
    taint_findings: List = field(default_factory=list)
    taint_summary: dict = field(default_factory=dict)
    component_graph_findings: List = field(default_factory=list)
    component_graph_summary: dict = field(default_factory=dict)
    dynamic_findings: List = field(default_factory=list)
    dynamic_summary: dict = field(default_factory=dict)
    chain_findings: List = field(default_factory=list)
    chain_summary: dict = field(default_factory=dict)
    validated_chain_results: List = field(default_factory=list)
    validated_chain_summary: dict = field(default_factory=dict)
    root_cause_results: List = field(default_factory=list)
    root_cause_summary: dict = field(default_factory=dict)
    dedup_results: List = field(default_factory=list)
    dedup_summary: dict = field(default_factory=dict)
    confidence_results: List = field(default_factory=list)
    confidence_summary: dict = field(default_factory=dict)
    frida_link_results: List = field(default_factory=list)
    frida_link_summary: dict = field(default_factory=dict)
    confirmed_findings: List = field(default_factory=list)
    confirmed_summary: dict = field(default_factory=dict)
    escalation_results: List = field(default_factory=list)
    escalation_summary: dict = field(default_factory=dict)


class ScanOrchestrator:
    """Orchestrates multi-phase Android APK analysis."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.result = ScanResult()
        self._source_dir = None

    @staticmethod
    def _fallback_apk_parse(apk_path: str) -> Optional[Dict[str, Any]]:
        """Try to extract APK metadata when androguard's AXML parser chokes
        on newer binary XML formats (e.g. API 36+)."""
        info: Dict[str, Any] = {"package": "", "app_name": "", "permissions": [], "manifest_xml": None}

        # Method 1: aapt2 dump badging
        for tool in ["aapt2", "aapt"]:
            try:
                r = subprocess.run(
                    [tool, "dump", "badging", apk_path],
                    capture_output=True, text=True, timeout=30,
                )
                if r.returncode != 0:
                    continue
                m_pkg = re.search(r"package: name='([^']+)'", r.stdout)
                if m_pkg:
                    info["package"] = m_pkg.group(1)
                m_app = re.search(r"application-label:'([^']*)'", r.stdout)
                if m_app:
                    info["app_name"] = m_app.group(1)
                info["permissions"] = re.findall(r"uses-permission: name='([^']+)'", r.stdout)
                break
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

        # Method 2: extract raw AndroidManifest.xml from ZIP
        try:
            with zipfile.ZipFile(apk_path) as zf:
                raw_axml = zf.read("AndroidManifest.xml")
                # Try androguard's AXMLPrinter (may work even if APK ctor fails)
                try:
                    from androguard.core.bytecodes.axml import AXMLPrinter
                    from lxml import etree as lxml_etree
                    printer = AXMLPrinter(raw_axml)
                    xml_str = printer.get_xml()
                    if xml_str:
                        # get_xml() returns bytes or str depending on androguard version
                        if isinstance(xml_str, bytes):
                            info["manifest_xml"] = lxml_etree.fromstring(xml_str)
                        else:
                            info["manifest_xml"] = lxml_etree.fromstring(xml_str.encode("utf-8"))
                        if not info["package"]:
                            pkg_attr = info["manifest_xml"].get("package", "")
                            if pkg_attr:
                                info["package"] = pkg_attr
                        if not info["app_name"] and info["manifest_xml"] is not None:
                            ns = "http://schemas.android.com/apk/res/android"
                            app_elem = info["manifest_xml"].find(f"{{{ns}}}application")
                            if app_elem is not None:
                                label = app_elem.get(f"{{{ns}}}label", "")
                                if label and label.startswith("@"):
                                    info["app_name"] = info["package"].split(".")[-1].capitalize()
                                elif label:
                                    info["app_name"] = label
                except Exception:
                    # Last resort: aapt2 dump xmltree
                    for tool in ["aapt2", "aapt"]:
                        try:
                            r = subprocess.run(
                                [tool, "dump", "xmltree", apk_path, "--file", "AndroidManifest.xml"],
                                capture_output=True, text=True, timeout=30,
                            )
                            if r.returncode == 0 and r.stdout.strip():
                                m = re.search(r'A: android:package\(0x[0-9a-f]+\)="([^"]+)"', r.stdout)
                                if m and not info["package"]:
                                    info["package"] = m.group(1)
                                break
                        except (FileNotFoundError, subprocess.TimeoutExpired):
                            continue
        except Exception:
            pass

        if not info["package"]:
            base = os.path.basename(apk_path)
            info["package"] = os.path.splitext(base)[0]
        if not info["app_name"]:
            info["app_name"] = info["package"].split(".")[-1].capitalize()
        return info

    def run(self) -> ScanResult:
        cfg = self.config
        apk_path = os.path.abspath(cfg.apk) if cfg.apk else ""

        if not apk_path or not os.path.isfile(apk_path):
            print(f"[-] Error: APK file '{apk_path}' not found!")
            return self.result

        apk_obj = None
        pkg = ""
        app_name = ""

        print(f"[*] Analyzing APK via Androguard: {apk_path}")
        try:
            from androguard.core.bytecodes.apk import APK
            apk_obj = APK(apk_path)
            pkg = apk_obj.get_package()
            app_name = apk_obj.get_app_name()
            print(f"[+] Extracted Package: {pkg}")
            print(f"[+] Extracted App Name: {app_name}")
        except Exception as e:
            print(f"[-] Androguard APK parsing failed: {e}")
            print("[*] Trying fallback APK parser (aapt2 + raw ZIP)...")
            fb = self._fallback_apk_parse(apk_path)
            if fb and fb["package"]:
                pkg = fb["package"]
                app_name = fb["app_name"]
                print(f"[+] Fallback extracted Package: {pkg}")
                print(f"[+] Fallback extracted App Name: {app_name}")
                # Build minimal apk_obj duck-type for downstream use
                class _FallbackAPK:
                    def __init__(self, info, path):
                        self._info = info
                        self._path = path
                    def get_package(self): return self._info["package"]
                    def get_app_name(self): return self._info["app_name"]
                    def get_permissions(self): return self._info.get("permissions", [])
                    def get_android_manifest_xml(self): return self._info.get("manifest_xml")
                    def get_android_manifest_axml(self): return None
                    def get_dex(self): return None
                    def get_files(self): return []
                    def get_file(self, path): return None
                    def is_valid(self): return True
                apk_obj = _FallbackAPK(fb, apk_path)
            else:
                print("[-] All APK parsing methods failed. Aborting.")
                return self.result

        self.result.apk_path = apk_path
        self.result.package_name = pkg
        self.result.app_name = app_name

        self._phase1_manifest_source(apk_obj, pkg)
        self._ai_triage(pkg)
        self._phase2_static(pkg)
        self._cve_analysis()
        self._taint_analysis(apk_obj, pkg)
        self._component_graph(apk_obj, pkg)
        self._dynamic_analysis(apk_obj, pkg)
        self._exploit_generation(pkg)
        self._validated_chains()
        self._frida_analysis(pkg)
        self._frida_linking()
        self._exploit_chains(pkg)
        self._root_cause(pkg)
        self._post_process(pkg)
        self._escalation_analysis(apk_obj, pkg)
        self._confidence_scoring(pkg)
        self._root_cause_dedup(pkg)
        self._confirmed_findings(pkg)
        return self.result



    # ═══════════════════════════════════════════════════════════════
    # Phase 1: Manifest + Source Analysis
    # ═══════════════════════════════════════════════════════════════
    def _phase1_manifest_source(self, apk_obj, pkg):
        cfg = self.config
        print(f"[*] Loading rules from '{cfg.rules}'...")
        manifest_analyzer = ManifestAnalyzer(cfg.rules)
        print("[*] Evaluating Manifest...")
        self.result.manifest_findings = manifest_analyzer.analyze(apk_obj)

        if cfg.jadx_dir:
            self._source_dir = cfg.jadx_dir
            print(f"[*] Using existing JADX directory: {self._source_dir}")
            source_analyzer = SourceAnalyzer(cfg.rules)
            print("[*] Evaluating Source Code...")
            self.result.source_findings = source_analyzer.analyze(self._source_dir)
        elif not cfg.skip_jadx:
            jadx_manager = JadxManager(cfg.apk)
            try:
                self._source_dir = jadx_manager.decompile()
                source_analyzer = SourceAnalyzer(cfg.rules)
                print("[*] Evaluating Source Code...")
                self.result.source_findings = source_analyzer.analyze(self._source_dir)
            except Exception as e:
                print(f"[-] Source analysis failed: {e}")
                self._source_dir = None
            finally:
                if self._source_dir and os.path.exists(self._source_dir):
                    pass  # keep for phase 2
                else:
                    jadx_manager.cleanup()
        else:
            self._source_dir = None
            print("[*] Skipping JADX decompilation.")

    # ═══════════════════════════════════════════════════════════════
    # AI Triage
    # ═══════════════════════════════════════════════════════════════
    def _ai_triage(self, pkg):
        cfg = self.config
        if not cfg.ai_triage:
            return
        if not (self.result.manifest_findings or self.result.source_findings):
            return
        print("[*] ── AI Triage Analysis ──")
        try:
            triage_engine = AITriageEngine(model=cfg.ai_model)
            all_f = self.result.manifest_findings + self.result.source_findings
            print(f"[*] AI Triage: Analyzing {len(all_f)} findings with model '{cfg.ai_model}'...")
            self.result.ai_triage_findings = triage_engine.filter_findings(all_f, min_confidence=cfg.ai_confidence)
            self.result.ai_triage_summary = triage_engine.get_summary(self.result.ai_triage_findings)
            print(f"[+] AI Triage: {self.result.ai_triage_summary['exploitable']} exploitable")
            self.result.manifest_findings = [f for f in self.result.ai_triage_findings if f.get('type') in ['manifest', 'Manifest']]
            self.result.source_findings = [f for f in self.result.ai_triage_findings if f.get('type') not in ['manifest', 'Manifest']]
        except Exception as e:
            print(f"[-] AI Triage failed: {e}")

    # ═══════════════════════════════════════════════════════════════
    # Phase 2: Advanced Static Analysis
    # ═══════════════════════════════════════════════════════════════
    def _phase2_static(self, pkg):
        cfg = self.config
        if cfg.skip_phase2:
            print("[*] Skipping Phase 2.")
            return
        print("[*] ── Phase 2: Advanced Static Analysis ──")
        try:
            static_analyzer = StaticAnalyzer(cfg.apk, source_dir=self._source_dir)
            self.result.phase2_findings = static_analyzer.analyze(timeout_total=300, detector_timeout=30)
            self.result.phase2_summary = static_analyzer.get_summary()
            s = self.result.phase2_summary
            print(f"[+] Phase 2: {s['total']} issues, {s['call_graph_nodes']} nodes, {s['call_graph_edges']} edges")
        except Exception as e:
            print(f"[-] Phase 2 failed: {e}")

    # ═══════════════════════════════════════════════════════════════
    # CVE Analysis
    # ═══════════════════════════════════════════════════════════════
    def _cve_analysis(self):
        cfg = self.config
        if not (cfg.cve_update or cfg.cve_list or cfg.cve_search):
            return
        print("[*] ── CVE Analysis ──")
        cve_analyzer = CVEAnalyzer()
        cve_rules = []
        if cfg.cve_list:
            cve_rules = cve_analyzer.batch_analyze(cve_ids=cfg.cve_list)
        elif cfg.cve_search:
            vulns = cve_analyzer.search_cve_by_keyword(cfg.cve_search)
            cve_ids = [v.get("id", "") for v in vulns if v.get("id")]
            cve_rules = cve_analyzer.process_cve_list(cve_ids)
        else:
            cve_rules = cve_analyzer.batch_analyze(auto_discover=True, days_back=cfg.cve_days)
            upd_s, upd_k = cve_analyzer.update_existing_rules()
            self.result.cve_data["updated_sources_count"] = len(upd_s) if upd_s else 0
            self.result.cve_data["updated_sinks_count"] = len(upd_k) if upd_k else 0
        self.result.cve_data["rules_generated"] = len(cve_rules)

    # ═══════════════════════════════════════════════════════════════
    # Taint Engine
    # ═══════════════════════════════════════════════════════════════
    def _taint_analysis(self, apk_obj, pkg):
        cfg = self.config
        if not cfg.taint or cfg.skip_phase2:
            return
        print("[*] ── Taint Engine ──")
        try:
            from androguard.core.bytecodes.dvm import DalvikVMFormat
            from androguard.core.analysis.analysis import Analysis
            vm = DalvikVMFormat(apk_obj.get_dex())
            vmx = Analysis(vm)
            vmx.create_xref()
            cg = vmx.get_call_graph()
            tracker = InterproceduralTaintTracker(vm, vmx, cg)
            self.result.taint_findings = tracker.analyze()
            self.result.taint_summary = tracker.get_summary()
            cross = tracker.find_cross_file_flows(self.result.taint_findings)
            print(f"[+] Taint: {self.result.taint_summary['analyzed']}/{self.result.taint_summary['total_methods']} methods, {len(self.result.taint_findings)} flows, {len(cross)} cross-file")
        except Exception as e:
            print(f"[-] Taint engine failed: {e}")

    # ═══════════════════════════════════════════════════════════════
    # Component Graph
    # ═══════════════════════════════════════════════════════════════
    def _component_graph(self, apk_obj, pkg):
        cfg = self.config
        if not cfg.component_graph:
            return
        print("[*] ── Component Graph ──")
        try:
            from androguard.core.bytecodes.dvm import DalvikVMFormat
            from androguard.core.analysis.analysis import Analysis
            vm = DalvikVMFormat(apk_obj.get_dex())
            vmx = Analysis(vm)
            vmx.create_xref()
            cg = AndroidComponentGraph(apk_obj, vm, vmx)
            cg.find_attack_paths(max_depth=5)
            self.result.component_graph_summary = cg.get_summary()
            self.result.component_graph_findings = cg.get_findings()
            s = self.result.component_graph_summary
            print(f"[+] Components: {s['total_components']}, paths: {s['attack_paths_found']}, findings: {len(self.result.component_graph_findings)}")
        except Exception as e:
            print(f"[-] Component graph failed: {e}")

    # ═══════════════════════════════════════════════════════════════
    # Dynamic Analysis
    # ═══════════════════════════════════════════════════════════════
    def _dynamic_analysis(self, apk_obj, pkg):
        cfg = self.config
        if not (cfg.dynamic or cfg.ipc_only or cfg.storage_only):
            return
        print("[*] ── Dynamic Analysis ──")
        dynamic_pkg = cfg.dynamic_pkg or pkg

        if cfg.dynamic_mode == "complete":
            self._dynamic_complete(dynamic_pkg)
            return

        try:
            comp_list = {"activities": [], "services": [], "receivers": [], "providers": [],
                         "deep_links": [], "authorities": []}
            try:
                xml = apk_obj.get_android_manifest_xml().to_xml()
                comp_list["activities"] = list(set(re.findall(r'android:name="([^"]*)"', xml)))
                comp_list["deep_links"] = list(set(
                    f"{s}://{h or '*'}{p or '/*'}"
                    for s in re.findall(r'android:scheme="([^"]+)"', xml)
                    for h in [re.findall(r'android:host="([^"]+)"', xml)]
                    for p in [re.findall(r'android:path(?:Pattern)?="([^"]+)"', xml)]
                ))
                comp_list["authorities"] = list(set(re.findall(r'android:authority="([^"]+)"', xml)))
                providers = []
                for m in re.findall(r'<provider[^>]*>', xml):
                    name_m = re.search(r'android:name="([^"]+)"', m)
                    auth_m = re.search(r'android:authority="([^"]+)"', m)
                    providers.append({
                        "name": name_m.group(1) if name_m else "",
                        "authority": auth_m.group(1) if auth_m else "",
                        "exported": 'android:exported="true"' in m,
                    })
                comp_list["providers"] = providers
                services = []
                for m in re.findall(r'<service[^>]*>', xml):
                    name_m = re.search(r'android:name="([^"]+)"', m)
                    services.append(name_m.group(1) if name_m else "")
                comp_list["services"] = services
                receivers = []
                for m in re.findall(r'<receiver[^>]*>', xml):
                    name_m = re.search(r'android:name="([^"]+)"', m)
                    receivers.append(name_m.group(1) if name_m else "")
                comp_list["receivers"] = receivers
            except Exception:
                pass

            from core.dynamic.dynamic_engine import DynamicEngine
            dyn = DynamicEngine(
                adb_path="adb",
                device_serial=cfg.device_serial,
                pkg_name=dynamic_pkg,
                apk_path=cfg.apk,
                apk_obj=apk_obj,
                max_time=cfg.dynamic_time,
            )
            dyn.run(**comp_list)
            self.result.dynamic_findings = dyn.get_findings()
            self.result.dynamic_summary = dyn.get_summary()
            s = self.result.dynamic_summary
            print(f"[+] Dynamic: {s.get('total_findings', 0)} findings")
        except Exception as e:
            print(f"[-] Dynamic analysis failed: {e}")

    def _dynamic_complete(self, dynamic_pkg):
        cfg = self.config
        try:
            from core.dynamic.complete_engine import CompleteDynamicEngine
            engine = CompleteDynamicEngine(
                package=dynamic_pkg,
                apk_path=cfg.apk,
                output_dir="dynamic_analysis"
            )
            result = engine.run_complete_analysis(
                max_screens=cfg.dynamic_max_screens,
                max_time=300,
                use_frida=True
            )
            self.result.dynamic_findings = [f.__dict__ if hasattr(f, '__dict__') else f for f in result.ui_findings]
            self.result.dynamic_summary = {
                'screens_explored': result.screens_taken,
                'ui_findings': len(result.ui_findings),
                'webview_findings': len(result.webview_findings),
                'frida_findings': len(result.frida_findings),
                'total_findings': result.total_findings,
                'confidence_score': result.confidence_score,
                'exploit_paths': len(result.exploit_paths),
            }
            s = self.result.dynamic_summary
            print(f"[+] Complete dynamic: {s['screens_explored']} screens, {s['ui_findings']} findings, "
                  f"{s['webview_findings']} webview, {s['frida_findings']} frida")
        except ImportError:
            print("[-] CompleteDynamicEngine requires uiautomator2. Use basic mode (--dynamic-mode basic).")
        except Exception as e:
            print(f"[-] Complete dynamic analysis failed: {e}")

    # ═══════════════════════════════════════════════════════════════
    # Exploit Generation
    # ═══════════════════════════════════════════════════════════════
    def _exploit_generation(self, pkg):
        cfg = self.config
        if not cfg.exploit:
            return
        print("[*] ── Exploit Generation ──")
        exploit_pkg = cfg.exploit_pkg or pkg
        all_f = self.result.manifest_findings + self.result.source_findings
        for g in self.result.phase2_findings:
            all_f.extend(g.get("rules", []))
        print(f"[*] Generating PoCs for {len(all_f)} findings...")
        engine = ExploitEngine(pkg_name=exploit_pkg, device_serial=cfg.device_serial)
        self.result.exploit_results = engine.exploit_findings(all_f, vectors=cfg.exploit_vector, auto_validate=cfg.exploit_validate)
        self.result.exploit_summary = engine.results_summary()
        s = self.result.exploit_summary
        print(f"[+] Exploits: {s['total_findings_with_exploits']} findings, {s['validated']} validated")

    # ═══════════════════════════════════════════════════════════════
    # Validated Chains
    # ═══════════════════════════════════════════════════════════════
    def _validated_chains(self):
        cfg = self.config
        if not cfg.exploit or not self.result.exploit_results:
            return
        print("[*] ── Validated Chains ──")
        try:
            vc = ValidatedChainEngine()
            self.result.validated_chain_results = vc.analyze(self.result.exploit_results)
            self.result.validated_chain_summary = vc.get_summary(self.result.validated_chain_results)
            print(f"[+] Validated chains: {self.result.validated_chain_summary['total_chains']}")
        except Exception as e:
            print(f"[-] Validated chains failed: {e}")

    # ═══════════════════════════════════════════════════════════════
    # Frida Analysis
    # ═══════════════════════════════════════════════════════════════
    def _frida_analysis(self, pkg):
        cfg = self.config
        frida_pkg = cfg.frida or cfg.frida_spawn
        if not (frida_pkg or cfg.frida_all or cfg.frida_ssl or cfg.frida_root or cfg.frida_hooks or cfg.frida_api or cfg.frida_prefs):
            return
        print("[*] ── Frida Dynamic Analysis ──")
        if not check_frida_availability():
            print("[-] frida-tools not installed.")
            return
        attach = bool(cfg.frida)
        fa = FridaAnalyzer(target_package=frida_pkg, device_id=cfg.frida_device, attach=attach)
        if not fa.connect():
            print("[-] No Frida device found.")
            return
        try:
            if cfg.frida_all or not (cfg.frida_ssl or cfg.frida_root or cfg.frida_hooks or cfg.frida_api or cfg.frida_prefs):
                fa.run_all(timeout=cfg.frida_timeout)
            else:
                if cfg.frida_ssl:
                    fa.run_ssl_pinning_detection(timeout=cfg.frida_timeout)
                if cfg.frida_root:
                    fa.run_root_detection_detection(timeout=cfg.frida_timeout)
                if cfg.frida_hooks:
                    fa.run_runtime_hooks(timeout=cfg.frida_timeout)
                if cfg.frida_api:
                    fa.run_api_monitor(timeout=cfg.frida_timeout)
                if cfg.frida_prefs:
                    fa.run_sharedprefs_monitor(timeout=cfg.frida_timeout)
            self.result.frida_findings = fa.results
            self.result.frida_summary = fa.get_summary()
            for feature, s in self.result.frida_summary.items():
                print(f"  [+] {feature}: {s['findings']} findings, {s['total_events']} events")
        finally:
            fa.cleanup()

    # ═══════════════════════════════════════════════════════════════
    # Frida ↔ Static Linking
    # ═══════════════════════════════════════════════════════════════
    def _frida_linking(self):
        cfg = self.config
        if not cfg.frida_link or not self.result.frida_findings:
            return
        if not any(v for v in self.result.frida_findings.values() if isinstance(v, list) and v):
            return
        print("[*] ── Frida ↔ Static Linking ──")
        try:
            linker = FridaStaticLinker()
            self.result.frida_link_results = linker.link(
                frida_findings=self.result.frida_findings,
                manifest_findings=self.result.manifest_findings,
                source_findings=self.result.source_findings,
                phase2_findings=self.result.phase2_findings,
                taint_findings=self.result.taint_findings if cfg.taint else None,
            )
            self.result.frida_link_summary = linker.get_summary()
            s = self.result.frida_link_summary
            print(f"[+] Frida link: {s['match_rate']}% match rate, {s['linked_findings']} linked")
        except Exception as e:
            print(f"[-] Frida linking failed: {e}")

    # ═══════════════════════════════════════════════════════════════
    # Exploit Chains
    # ═══════════════════════════════════════════════════════════════
    def _exploit_chains(self, pkg):
        cfg = self.config
        if not cfg.chains:
            return
        print("[*] ── Exploit Chains ──")
        try:
            engine = ExploitChainEngine()
            self.result.chain_findings = engine.analyze(
                findings=self.result.manifest_findings + self.result.source_findings,
                component_graph_findings=self.result.component_graph_findings if cfg.component_graph else None,
                taint_findings=self.result.taint_findings if cfg.taint else None,
                dynamic_findings=self.result.dynamic_findings if cfg.dynamic else None,
                manifest_findings=self.result.manifest_findings,
            )
            self.result.chain_summary = engine.get_summary()
            s = self.result.chain_summary
            print(f"[+] Chains: {s['critical_full']} critical, {s['high_full']} high, {s['partial_chains']} partial")
        except Exception as e:
            print(f"[-] Chains failed: {e}")

    # ═══════════════════════════════════════════════════════════════
    # Root Cause Analysis
    # ═══════════════════════════════════════════════════════════════
    def _root_cause(self, pkg):
        cfg = self.config
        if not cfg.root_cause:
            return
        print("[*] ── Root Cause Analysis ──")
        try:
            all_f = self.result.manifest_findings + self.result.source_findings
            for g in self.result.phase2_findings:
                all_f.extend(g.get("rules", []))
            all_f.extend(self.result.taint_findings)
            all_f.extend(self.result.component_graph_findings)
            all_f.extend(self.result.dynamic_findings)
            all_f.extend(self.result.chain_findings)
            engine = RootCauseEngine()
            self.result.root_cause_results = engine.analyze(all_f)
            self.result.root_cause_summary = engine.get_summary()
            print(f"[+] Root causes: {self.result.root_cause_summary['root_causes']}")
        except Exception as e:
            print(f"[-] Root cause analysis failed: {e}")

    # ═══════════════════════════════════════════════════════════════
    # Post-Process: Noise Filter
    # ═══════════════════════════════════════════════════════════════
    def _post_process(self, pkg):
        from core.utils import post_process_findings
        min_conf = self.config.min_confidence
        self.result.manifest_findings = post_process_findings(self.result.manifest_findings, pkg, min_confidence=min_conf)
        self.result.source_findings = post_process_findings(self.result.source_findings, pkg, min_confidence=min_conf)
        filtered_phase2 = []
        for g in self.result.phase2_findings:
            rules = post_process_findings(g.get("rules", []), pkg, min_confidence=min_conf)
            if rules:
                g["rules"] = rules
                filtered_phase2.append(g)
        self.result.phase2_findings = filtered_phase2
        p1 = len(self.result.manifest_findings) + len(self.result.source_findings)
        p2 = sum(len(g["rules"]) for g in self.result.phase2_findings)
        print(f"[*] Post-process: Phase 1={p1}, Phase 2={p2} findings after noise filter")

        # FP feedback loop: auto-suppress findings matching known FP patterns
        if self.config.fp_measure:
            try:
                fp = FPAnalyzer()
                all_f = self.result.manifest_findings + self.result.source_findings
                for g in self.result.phase2_findings:
                    all_f.extend(g.get("rules", []))
                before = len(all_f)
                all_f = fp.suppress_findings(all_f, threshold=self.config.fp_threshold)
                if len(all_f) < before:
                    print(f"[+] FP filter removed {before - len(all_f)} findings (threshold={self.config.fp_threshold})")
            except Exception as e:
                print(f"[-] FP analysis failed: {e}")

    # ═══════════════════════════════════════════════════════════════
    # Confidence Scoring
    # ═══════════════════════════════════════════════════════════════
    def _confidence_scoring(self, pkg):
        cfg = self.config
        if not cfg.confidence:
            return
        print("[*] ── Confidence Scoring ──")
        try:
            scorer = ConfidenceScorer(app_package=pkg)
            all_f = self.result.manifest_findings + self.result.source_findings
            for g in self.result.phase2_findings:
                all_f.extend(g.get("rules", []))
            self.result.confidence_results = scorer.score_all_findings(
                findings=all_f,
                taint_findings=self.result.taint_findings,
                dynamic_findings=self.result.dynamic_findings,
                exploit_results=self.result.exploit_results,
                bb_mode=cfg.bug_bounty,
            )
            self.result.confidence_summary = scorer.get_summary(self.result.confidence_results)
            s = self.result.confidence_summary
            print(f"[+] Confidence: avg {s['average_confidence']}%, verified {s.get('verified', 0)}")
        except Exception as e:
            print(f"[-] Confidence scoring failed: {e}")

    # ═══════════════════════════════════════════════════════════════
    # Confirmed Findings (Validated Exploits Only)
    # ═══════════════════════════════════════════════════════════════
    def _confirmed_findings(self, pkg):
        cfg = self.config
        if not cfg.exploit and not cfg.confirmed:
            return
        print("[*] ── Confirmed Findings ──")
        try:
            engine = ConfirmedFindingsEngine(min_confidence=cfg.confirmed_min_confidence)
            self.result.confirmed_findings = engine.analyze(
                exploit_results=self.result.exploit_results or [],
                dynamic_findings=self.result.dynamic_findings or [],
            )
            self.result.confirmed_summary = engine.get_summary()
            s = self.result.confirmed_summary
            print(f"[+] Confirmed: {s['total_confirmed']} findings "
                  f"(validated: {s['validated']}, critical+high: {s['critical_high']})")
        except Exception as e:
            print(f"[-] Confirmed findings analysis failed: {e}")

    # ═══════════════════════════════════════════════════════════════
    # Escalation Analysis (Context-Aware Severity Upgrade)
    # ═══════════════════════════════════════════════════════════════
    def _escalation_analysis(self, apk_obj, pkg):
        print("[*] ── Escalation Analysis ──")
        try:
            permissions = []
            try:
                permissions = apk_obj.get_permissions() or []
            except Exception:
                pass
            target_sdk = None
            try:
                target_sdk = apk_obj.get_target_sdk_version()
            except Exception:
                pass
            engine = EscalationEngine()
            self.result.manifest_findings = engine.analyze(
                manifest_findings=self.result.manifest_findings,
                source_findings=self.result.source_findings,
                pkg=pkg,
                app_name=self.result.app_name,
                permissions=permissions,
                target_sdk_version=target_sdk,
            )
            self.result.escalation_summary = engine.get_summary()
            s = self.result.escalation_summary
            if s["total_escalations"]:
                print(f"[+] Upgraded {s['total_escalations']} findings based on context")
            else:
                print("[*] No severity escalations applied")
        except Exception as e:
            import traceback; traceback.print_exc()
            print(f"[-] Escalation analysis failed: {e}")

    # ═══════════════════════════════════════════════════════════════
    # Root Cause Dedup
    # ═══════════════════════════════════════════════════════════════
    def _root_cause_dedup(self, pkg):
        cfg = self.config
        if not cfg.dedup:
            return
        print("[*] ── Root Cause Dedup ──")
        try:
            all_f = self.result.manifest_findings + self.result.source_findings
            for g in self.result.phase2_findings:
                all_f.extend(g.get("rules", []))
            deduper = RootCauseDedup()
            safe_exploit = self.result.exploit_results if isinstance(self.result.exploit_results, list) else None
            safe_confidence = self.result.confidence_results if isinstance(self.result.confidence_results, list) and self.result.confidence_results else None
            self.result.dedup_results = deduper.analyze(
                findings=all_f,
                exploit_results=safe_exploit,
                confidence_results=safe_confidence,
            )
            self.result.dedup_summary = deduper.get_summary()
            raw = len(all_f)
            rc = len(self.result.dedup_results)
            print(f"[+] Dedup: {raw} → {rc} root causes ({round((1-rc/max(raw,1))*100,1)}% reduction)")
        except Exception as e:
            print(f"[-] Dedup failed: {e}")


def run_scan(config: ScanConfig) -> ScanResult:
    """Convenience function to run a full scan programmatically."""
    orchestrator = ScanOrchestrator(config)
    return orchestrator.run()


def build_report_data(result: ScanResult, config: ScanConfig) -> dict:
    """Build the report_data dict for HTML template rendering."""
    pre_validated_ids = []
    for er in result.exploit_results or []:
        for vec, vdata in er.get("vectors", {}).items():
            val = vdata.get("validation") if isinstance(vdata, dict) else None
            if isinstance(val, dict) and val.get("validated") is True:
                pre_validated_ids.append(er.get("finding_id", ""))
    pre_findings_map = {}
    for f in (result.manifest_findings or []) + (result.source_findings or []):
        fid = f.get("id", "")
        if fid:
            pre_findings_map[fid] = f

    exploit_screenshots = {}
    for shot_name in ("before", "after"):
        shot_path = f"/tmp/adb_exploit_{shot_name}.png"
        if os.path.exists(shot_path):
            try:
                with open(shot_path, "rb") as sf:
                    exploit_screenshots[f"{shot_name}_b64"] = base64.b64encode(sf.read()).decode()
            except Exception:
                pass
    individual_screenshots = {}
    for er in result.exploit_results or []:
        finding_id = er.get("finding_id", "")
        if not finding_id:
            continue
        for vec, vdata in er.get("vectors", {}).items():
            if not isinstance(vdata, dict):
                continue
            val = vdata.get("validation")
            if isinstance(val, dict):
                sb64 = val.get("screenshot_b64")
                if sb64:
                    individual_screenshots.setdefault(finding_id, {})["exploit_b64"] = sb64
                    break
        if finding_id:
            for shot_type in ("before", "after"):
                shot_path = f"/tmp/adb_exploit_{finding_id}_{shot_type}.png"
                if os.path.exists(shot_path):
                    try:
                        with open(shot_path, "rb") as sf:
                            individual_screenshots.setdefault(finding_id, {})[f"{shot_type}_b64"] = base64.b64encode(sf.read()).decode()
                    except Exception:
                        pass
    if individual_screenshots:
        exploit_screenshots["individual"] = individual_screenshots
    if exploit_screenshots:
        validated_count = result.exploit_summary.get("validated", 0) if result.exploit_summary else 0
        validated_ids = []
        for er in result.exploit_results or []:
            for vec, vdata in er.get("vectors", {}).items():
                val = vdata.get("validation") if isinstance(vdata, dict) else None
                if isinstance(val, dict) and val.get("validated") is True:
                    validated_ids.append(er.get("finding_id", "?"))
        exploit_screenshots["_meta"] = {
            "package": result.package_name,
            "app_name": result.app_name,
            "validated": validated_count,
            "total_exploits": result.exploit_summary.get("exploitable", 0) if result.exploit_summary else 0,
            "validated_ids": validated_ids[:5],
            "apk": os.path.basename(result.apk_path),
            "individual_count": len(individual_screenshots),
        }

    return {
        "apk_path": result.apk_path,
        "package_name": result.package_name,
        "app_name": result.app_name,
        "exploit_screenshots": exploit_screenshots,
        "manifest_findings": result.manifest_findings,
        "source_findings": result.source_findings,
        "ai_triage_findings": result.ai_triage_findings,
        "ai_triage_summary": result.ai_triage_summary,
        "phase2_findings": result.phase2_findings,
        "phase2_summary": result.phase2_summary,
        "cve_data": result.cve_data,
        "frida_findings": result.frida_findings,
        "frida_summary": result.frida_summary,
        "exploit_results": result.exploit_results,
        "exploit_summary": result.exploit_summary,
        "taint_findings": result.taint_findings,
        "taint_summary": result.taint_summary,
        "component_graph_findings": result.component_graph_findings,
        "component_graph_summary": result.component_graph_summary,
        "dynamic_findings": result.dynamic_findings,
        "dynamic_summary": result.dynamic_summary,
        "chain_findings": result.chain_findings,
        "chain_summary": result.chain_summary,
        "validated_chain_results": result.validated_chain_results,
        "validated_chain_summary": result.validated_chain_summary,
        "root_cause_results": result.root_cause_results,
        "root_cause_summary": result.root_cause_summary if config.root_cause else {},
        "dedup_results": result.dedup_results if config.dedup else [],
        "dedup_summary": result.dedup_summary if config.dedup else {},
        "confidence_results": result.confidence_results,
        "confidence_summary": result.confidence_summary,
        "validated_ids": pre_validated_ids,
        "findings_by_id": pre_findings_map,
        "frida_link_results": result.frida_link_results,
        "frida_link_summary": result.frida_link_summary,
        "confirmed_findings": result.confirmed_findings,
        "confirmed_summary": result.confirmed_summary,
        "escalation_results": result.escalation_results if config.bug_bounty else [],
        "escalation_summary": result.escalation_summary if config.bug_bounty else {},
    }

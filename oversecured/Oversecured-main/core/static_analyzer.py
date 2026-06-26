import os
import re
from collections import defaultdict

from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis

from core.cfg import MethodCFG
from core.dataflow import ReachingDefinitions, LivenessAnalysis, ConstantPropagation
from core.interprocedural import (
    InterproceduralAnalyzer, BinderPermissionAnalyzer, FlowAnalyzer,
    MultiHopTaintPropagator, BINDER_SERVICES, SYSTEM_SERVICES, SETTINGS_PROVIDER,
    VENDOR_SERVICES, PRIVILEGED_ACTIONS, CALLBACK_TYPES, ASYNC_PATTERNS, LIFECYCLE_METHODS,
)

from core.taint_config import TAINT_SOURCES, TAINT_SINKS
import logging
logger = logging.getLogger(__name__)

# ════════════════════════════════════════════════════════════════
# DALVIK INSTRUCTION GROUPINGS
# ════════════════════════════════════════════════════════════════

MOVE_INSTRS = {"move", "move-object", "move-result", "move-result-object",
               "move-wide", "move-exception", "move-result-wide"}
CONST_INSTRS = {"const", "const/4", "const/16", "const-wide/16", "const-wide/32",
                "const-wide", "const-string", "const-string/jumbo", "const-class",
                "const/high16", "const-wide/high16"}
BRANCH_INSTRS = {"if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le",
                  "if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez",
                  "if-eq-object", "if-ne-object"}
RETURN_INSTRS = {"return-void", "return", "return-wide", "return-object"}
SWITCH_INSTRS = {"packed-switch", "sparse-switch"}

# ════════════════════════════════════════════════════════════════
# TAINT ENGINE — Source → Propagation → Sink
# ════════════════════════════════════════════════════════════════

class TaintEngine:
    def __init__(self, vm, vmx, call_graph):
        self.vm = vm
        self.vmx = vmx
        self.call_graph = call_graph
        self.source_methods = TAINT_SOURCES
        self.sink_defs = TAINT_SINKS
        self._build_method_map()

    def _build_method_map(self):
        self.method_map = {}
        for cls in self.vm.get_classes():
            for method in cls.get_methods():
                sig = f"{cls.name}->{method.name}{method.descriptor}"
                self.method_map[sig] = method

    def analyze_taint_flow(self, max_depth=3):
        findings_by_type = defaultdict(list)

        for cls in self.vm.get_classes():
            for method in cls.get_methods():
                code = method.get_code()
                if code is None:
                    continue
                try:
                    instructions = list(code.get_bc().get_instructions())
                except Exception:
                    continue

                reg_taint = {}
                reg_values = {}
                last_invoke_tainted = False
                last_invoke_sig = None
                method_sig = f"{cls.name}->{method.name}{method.descriptor}"
                method_params = self._get_method_parameters(method)

                for p in method_params:
                    reg_taint[p] = True

                cp = ConstantPropagation(instructions)

                for idx, ins in enumerate(instructions):
                    try:
                        name = ins.get_name()
                        output = ins.get_output()
                    except Exception:
                        continue

                    if name in MOVE_INSTRS:
                        self._handle_move(ins, reg_taint, reg_values)

                    elif name in CONST_INSTRS:
                        self._handle_const(ins, name, reg_taint, reg_values)

                    elif name.startswith("invoke"):
                        last_invoke_tainted, last_invoke_sig = self._check_invoke(
                            ins, reg_taint, reg_values, findings_by_type,
                            method_sig, idx, instructions, cp)

                    elif name in ("move-result", "move-result-object", "move-result-wide"):
                        dest = self._get_dest_reg(ins)
                        if dest is not None:
                            if last_invoke_tainted:
                                reg_taint[dest] = True
                            if last_invoke_sig:
                                reg_values[dest] = ("invoke_result", last_invoke_sig)
                            last_invoke_tainted = False
                            last_invoke_sig = None

                    elif name in ("aget", "aget-object", "aget-wide"):
                        dest, arr, idx_reg = self._get_aget_regs(ins)
                        if dest is not None and arr in reg_taint:
                            reg_taint[dest] = reg_taint[arr]

                    elif name in ("aput", "aput-object", "aput-wide"):
                        val, arr, idx_reg = self._get_aput_regs(ins)
                        if val is not None and val in reg_taint:
                            reg_taint[arr] = True

                    elif name in ("iput", "iput-object", "iput-wide", "iput-boolean", "iput-byte", "iput-char", "iput-short"):
                        val, obj, field = self._get_iput_regs(ins, output)
                        if val is not None and val in reg_taint and reg_taint[val]:
                            field_id = f"{obj}:{field}" if obj else field
                            reg_taint[field_id] = True

                    elif name in ("iget", "iget-object", "iget-wide", "iget-boolean", "iget-byte", "iget-char", "iget-short"):
                        dest, obj, field = self._get_iget_regs(ins, output)
                        field_id = f"{obj}:{field}" if obj is not None and field else None
                        if dest is not None and field_id and field_id in reg_taint:
                            reg_taint[dest] = True

                    elif name == "new-instance":
                        if len(output.replace(",", "").split()) >= 1:
                            dest = output.replace(",", "").split()[-1]
                            reg_taint[dest] = False

                    elif name == "check-cast":
                        parts = output.replace(",", "").split()
                        dest = parts[-1] if parts else None
                        if dest and dest in reg_taint:
                            pass

        return dict(findings_by_type)

    def _get_method_parameters(self, method):
        params = []
        try:
            proto = method.get_descriptor()
            if proto:
                reg_idx = 1
                for i, c in enumerate(proto):
                    if c == 'L':
                        reg_name = f"p{reg_idx}" if reg_idx > 0 else "v0"
                        params.append(reg_name)
                        reg_idx += 1
                        while i + 1 < len(proto) and proto[i + 1] != ';':
                            i += 1
                    elif c in ('B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z'):
                        reg_name = f"p{reg_idx}" if reg_idx > 0 else "v0"
                        params.append(reg_name)
                        reg_idx += 1
                    elif c == '[':
                        pass
                    elif c == ')':
                        break
        except Exception:
            pass
        return params

    def _handle_move(self, ins, reg_taint, reg_values):
        try:
            output = ins.get_output()
            parts = output.replace(",", "").split()
            if len(parts) >= 2:
                dest = parts[0]
                src = parts[-1]
                if src in reg_taint:
                    reg_taint[dest] = reg_taint[src]
                elif dest in reg_taint:
                    del reg_taint[dest]
                if src in reg_values:
                    reg_values[dest] = reg_values[src]
                elif dest in reg_values:
                    del reg_values[dest]
        except Exception:
            pass

    def _handle_const(self, ins, name, reg_taint, reg_values):
        try:
            output = ins.get_output()
            parts = output.replace(",", "").split()
            if not parts:
                return
            dest = parts[0]
            reg_taint[dest] = False
            if "const-string" in name:
                rest = output[output.find(dest) + len(dest):].strip()
                if rest.startswith('"') and rest.endswith('"'):
                    reg_values[dest] = ("literal", rest[1:-1])
                else:
                    rest2 = rest.strip('"')
                    reg_values[dest] = ("literal", rest2)
        except Exception:
            pass

    def _get_dest_reg(self, ins):
        try:
            output = ins.get_output()
            parts = output.replace(",", "").split()
            return parts[0] if parts else None
        except Exception:
            return None

    def _get_aget_regs(self, ins):
        try:
            output = ins.get_output()
            parts = output.replace(",", "").split()
            if len(parts) >= 3:
                return parts[0], parts[1], parts[2]
        except Exception:
            pass
        return None, None, None

    def _get_aput_regs(self, ins):
        try:
            output = ins.get_output()
            parts = output.replace(",", "").split()
            if len(parts) >= 3:
                return parts[0], parts[1], parts[2]
        except Exception:
            pass
        return None, None, None

    def _get_iput_regs(self, ins, output):
        try:
            parts = output.replace(",", "").split()
            if len(parts) >= 3:
                return parts[0], parts[1], parts[2]
        except Exception:
            pass
        return None, None, None

    def _get_iget_regs(self, ins, output):
        try:
            parts = output.replace(",", "").split()
            if len(parts) >= 3:
                return parts[0], parts[-2], parts[-1]
        except Exception:
            pass
        return None, None, None

    def _get_invoke_details(self, ins):
        try:
            output = ins.get_output()
            name = ins.get_name()
            if name.startswith("invoke"):
                if ";->" in output:
                    parts = output.split("->", 1)
                    cls_part = parts[0].split()[-1] if " " in parts[0] else parts[0]
                    rest = parts[1]
                    method_end = rest.find("(")
                    if method_end == -1:
                        method_end = len(rest)
                    method_name = rest[:method_end]
                    full_sig = f"{cls_part}->{method_name}"
                    args = []
                    if "(" in rest:
                        bracket = rest[rest.find("("):]
                        if ")" in bracket:
                            arg_content = bracket[1:bracket.find(")")]
                            if arg_content:
                                for arg in arg_content.split(","):
                                    arg = arg.strip()
                                    if arg:
                                        args.append(arg)
                    return full_sig, args
        except Exception:
            pass
        return None, []

    def _check_invoke(self, ins, reg_taint, reg_values, findings_by_type, method_sig, idx, instructions, cp):
        full_sig, args = self._get_invoke_details(ins)
        if full_sig is None:
            return False, None

        tainted_result = False

        for src_sig in self.source_methods:
            if src_sig in full_sig:
                tainted_result = True
                break

        tainted_args = [i for i, a in enumerate(args) if a in reg_taint and reg_taint[a]]

        for vuln_type, sink_def in self.sink_defs.items():
            for sink_method in sink_def["methods"]:
                if sink_method not in full_sig:
                    continue

                param_indices = sink_def["param_index"].get(sink_method, tuple())
                is_tainted = False
                specific_param = None

                if param_indices:
                    for pi in param_indices:
                        if pi < len(args) and args[pi] in reg_taint:
                            if reg_taint[args[pi]]:
                                is_tainted = True
                                specific_param = pi
                                break
                else:
                    if tainted_args:
                        is_tainted = True
                        specific_param = tainted_args[0]

                if is_tainted:
                    source_desc = self._find_nearby_source(instructions, idx, reg_taint, reg_values)
                    findings_by_type[vuln_type].append({
                        "id": f"TAIN-{vuln_type.upper()}-001",
                        "type": vuln_type,
                        "method": method_sig,
                        "instruction_index": idx,
                        "sink": full_sig,
                        "sink_param": specific_param,
                        "location": f"{method_sig} @ instr:{idx} [{full_sig}]",
                        "source_hint": source_desc,
                        "tainted_args": tainted_args,
                    })

        return tainted_result, full_sig

    def _find_nearby_source(self, instructions, sink_idx, reg_taint, reg_values):
        for i in range(max(0, sink_idx - 20), sink_idx):
            try:
                name = instructions[i].get_name()
                output = instructions[i].get_output()
                if name.startswith("invoke"):
                    for src in self.source_methods:
                        norm_src = src.replace("Landroid/", "").replace("Landroidx/", "").replace("Ljava/", "").replace("Lcom/", "")
                        norm_out = output.replace("->", ";->")
                        if norm_src in norm_out:
                            return output.strip()
            except Exception:
                pass
        return None

    def trace_source_path(self, findings, max_depth=3):
        enriched = []
        for f in findings:
            f["source_path"] = self._backtrack_to_source(f, max_depth)
            enriched.append(f)
        return enriched

    def _backtrack_to_source(self, finding, max_depth):
        method_sig = finding["method"]
        method = self.method_map.get(method_sig)
        if method is None:
            return []
        path = []
        visited = set()
        queue = [(method_sig, 0)]
        visited.add(method_sig)
        while queue:
            current_sig, depth = queue.pop(0)
            if depth >= max_depth:
                continue
            for edge in self.call_graph.get("edges", []):
                if edge.get("target") == current_sig:
                    caller = edge.get("source")
                    if caller not in visited:
                        visited.add(caller)
                        for src in self.source_methods:
                            norm_src = src.replace("Landroid/", "").replace("Landroidx/", "").replace("Ljava/", "").replace("Lcom/", "")
                            norm_caller = caller.replace("->", ";->")
                            if norm_src in norm_caller:
                                path.append(caller)
                                break
                        queue.append((caller, depth + 1))
        return list(set(path))


# ════════════════════════════════════════════════════════════════
# STATIC ANALYZER — Phase 2
# ════════════════════════════════════════════════════════════════

SENSITIVE_KEYWORDS = {"password","passwd","pin","otp","token","secret","key","credential",
                      "jwt","bearer","auth","access_token","refresh_token","api_key",
                      "apikey","private_key","session","ssn","ssnumber","social",
                      "credit","card","cvv","cvc","expiry","iban","account_no",
                      "routing","pin","tac","mfa","2fa","security_code"}


class StaticAnalyzer:
    def __init__(self, apk_path, source_dir=None):
        self.apk_path = apk_path
        self.source_dir = source_dir
        self.apk = None
        self.vm = None
        self.vmx = None
        self.classes = []
        self.methods = []
        self.strings = []
        self.cfg = {}
        self.call_graph = {}
        self.xrefs = {}
        self.findings = []
        self.method_cfgs = {}
        self._method_strs = {}
        self._invoke_index = {}
        self._analysis_cache = {}
        self.manifest_components = {}

    def analyze(self, detector_timeout=5, timeout_total=60):
        import time
        t0 = time.time()
        print("[*] Phase 2: Loading APK for deep analysis...")
        self.apk = APK(self.apk_path)
        dex = self.apk.get_dex()
        if dex is None:
            raise Exception("No DEX data found in APK.")
        self.vm = DalvikVMFormat(dex)
        self.vmx = Analysis(self.vm)
        print(f"  ({time.time()-t0:.1f}s)")

        t1 = time.time()
        print("[*] Building cross-references...")
        self.vmx.create_xref()
        print(f"  ({time.time()-t1:.1f}s)")

        t1 = time.time()
        print("[*] Building call graph...")
        self._build_call_graph()
        print(f"  ({time.time()-t1:.1f}s)")

        t1 = time.time()
        print("[*] Extracting strings and constants...")
        self._collect_strings()
        print(f"  ({time.time()-t1:.1f}s)")

        t1 = time.time()
        print("[*] Building CFGs for all methods...")
        self._build_all_cfgs()
        print(f"  ({time.time()-t1:.1f}s)")

        t1 = time.time()
        print("[*] Building method string index...")
        self._build_method_strs()
        print(f"  ({time.time()-t1:.1f}s)")

        t1 = time.time()
        print("[*] Building invoke index...")
        self._build_invoke_index()
        print(f"  ({time.time()-t1:.1f}s)")

        t1 = time.time()
        print("[*] Extracting APK features...")
        self._extract_features()
        print(f"  ({time.time()-t1:.1f}s)")

        t1 = time.time()
        print("[*] Extracting manifest components...")
        self._extract_manifest_components()
        print(f"  ({time.time()-t1:.1f}s)")

        t1 = time.time()
        print("[*] Initializing Taint Engine...")
        self.taint_engine = TaintEngine(self.vm, self.vmx, self.call_graph)
        self.taint_findings = self.taint_engine.analyze_taint_flow()
        print(f"  ({time.time()-t1:.1f}s)")

        t1 = time.time()
        print("[*] Initializing Interprocedural Analysis...")
        self._init_interprocedural()
        self.ipa_findings = {
            "binder_bypass": getattr(self, 'binder_perm_bypass', []),
            "system_service_abuse": self.ipa_system_service_abuse if hasattr(self, 'ipa_system_service_abuse') else [],
            "settings_abuse": self.ipa_settings_abuse if hasattr(self, 'ipa_settings_abuse') else [],
            "vendor_abuse": self.ipa_vendor_abuse if hasattr(self, 'ipa_vendor_abuse') else [],
            "privileged_intent": self.ipa_privileged_intent if hasattr(self, 'ipa_privileged_intent') else [],
            "callback_flow": self.callback_flows if hasattr(self, 'callback_flows') else [],
        }
        print(f"  ({time.time()-t1:.1f}s)")

        t1 = time.time()
        print("[*] Running Phase 2 detectors...")
        from core.detectors import run_detectors, _DETECTOR_MODULE
        class_methods = {m for m in dir(self) if m.startswith('_detect_') and callable(getattr(self, m))}
        all_detectors = list(class_methods | set(_DETECTOR_MODULE.keys()))
        det_run = [d for d in all_detectors if "ipa" not in d.lower()]
        if not det_run:
            det_run = all_detectors
        det_run = self._relevant_detectors(det_run)
        s = len(det_run)
        print(f"  {s} relevant detectors (of {len([d for d in all_detectors if 'ipa' not in d.lower()])})")
        for i, d in enumerate(det_run):
            remaining = timeout_total - (time.time() - t0)
            if remaining < 0:
                print(f"  ⏱️ Phase 2 budget exhausted after {time.time()-t0:.0f}s")
                break
            dt = time.time()
            try:
                run_detectors(self, [d])
                elapsed = time.time() - dt
                if elapsed > 2:
                    print(f"  [{i+1}/{len(det_run)}] {d} ({elapsed:.1f}s)")
            except Exception as e:
                elapsed = time.time() - dt
                print(f"  [!] {d} failed: {e} ({elapsed:.1f}s)")
        print(f"  All detectors done ({time.time()-t1:.1f}s)")
        print(f"[+] Phase 2 total: {time.time()-t0:.1f}s")

        # Attach CFG Mermaid diagrams to findings where method sig is available
        import re as _re
        for group in self.findings:
            for rule in group.get("rules", []):
                loc = rule.get("location", "")
                if not loc:
                    continue
                m_sig_match = _re.search(r'(L[^;]+;->[^(]+\([^)]*\)[^|\s]*)', loc)
                if m_sig_match:
                    m_sig = m_sig_match.group(1).strip()
                    info = self.method_cfgs.get(m_sig)
                    if info and info.get("cfg"):
                        rule["_cfg_mermaid"] = info["cfg"].to_mermaid(max_blocks=15)

        return self.findings

    def _collect_strings(self):
        self.strings = [str(s) for s in self.vm.get_strings()]

    def _build_call_graph(self):
        graph = {"nodes": [], "edges": []}
        seen = set()
        try:
            nx_graph = self.vmx.get_call_graph()
            for edge in nx_graph.edges():
                src, tgt = edge
                m_sig = f"{src.class_name}->{src.name}{src.descriptor}"
                c_sig = f"{tgt.class_name}->{tgt.name}{tgt.descriptor}"
                if m_sig not in seen:
                    graph["nodes"].append({"id": m_sig, "class": src.class_name, "name": src.name})
                    seen.add(m_sig)
                if c_sig not in seen:
                    graph["nodes"].append({"id": c_sig, "class": tgt.class_name, "name": tgt.name})
                    seen.add(c_sig)
                graph["edges"].append({"source": m_sig, "target": c_sig})
        except Exception as e:
            print(f"[!] Could not build call graph: {e}")
        self.call_graph = graph

    def _build_all_cfgs(self):
        reachable = set()
        for n in self.call_graph.get("nodes", []):
            reachable.add(n.get("id", ""))
        for cls in self.vm.get_classes():
            for method in cls.get_methods():
                sig = f"{cls.name}->{method.name}{method.descriptor}"
                if sig not in reachable:
                    continue
                code = method.get_code()
                if code is None:
                    continue
                try:
                    instructions = list(code.get_bc().get_instructions())
                    cfg = MethodCFG(method, instructions)
                    self.method_cfgs[sig] = {
                        "cfg": cfg,
                        "instructions": instructions,
                        "method": method,
                    }
                except Exception:
                    pass

    def _build_method_strs(self):
        for sig, info in self.method_cfgs.items():
            try:
                outputs = " ".join(
                    instr.get_output()
                    for instr in info["instructions"]
                    if instr.get_output() is not None
                )
                self._method_strs[sig] = outputs
            except Exception:
                pass

    def _build_invoke_index(self):
        for cls in self.vm.get_classes():
            for method in cls.get_methods():
                code = method.get_code()
                if code is None:
                    continue
                try:
                    bc = code.get_bc()
                    instructions = list(bc.get_instructions())
                except Exception:
                    continue
                sig = f"{cls.name}->{method.name}{method.descriptor}"
                invokes = []
                for instr in instructions:
                    iname = instr.get_name()
                    if iname in ("invoke-virtual", "invoke-direct", "invoke-static", "invoke-interface"):
                        try:
                            invokes.append((iname, instr.get_output()))
                        except Exception:
                            pass
                if invokes:
                    self._invoke_index[sig] = invokes

    def _init_interprocedural(self):
        self.binder_flow = []
        self.binder_perm_bypass = []
        self.lifecycle_flows = []
        self.callback_flows = []
        self.concurrent_flows = []
        self.cross_class_flows = []
        self.cross_activity_flows = []
        self.ipa_settings_abuse = []
        self.ipa_vendor_abuse = []
        self.ipa_privileged_intent = []
        try:
            ipa = InterproceduralAnalyzer(
                self.vm, self.vmx, self.call_graph, self.method_cfgs, self.taint_engine
            )
            findings = ipa.analyze(max_iterations=3, time_limit=30)
            for f in findings:
                ftype = f.get("type", "")
                if ftype == "binder_flow":
                    self.binder_flow.append(f)
                elif ftype == "binder_perm_bypass":
                    self.binder_perm_bypass.append(f)
                elif ftype == "lifecycle_flow":
                    self.lifecycle_flows.append(f)
                elif ftype == "callback_flow":
                    self.callback_flows.append(f)
                elif ftype == "concurrent_flow":
                    self.concurrent_flows.append(f)
                elif ftype == "cross_class_flow":
                    self.cross_class_flows.append(f)
                elif ftype == "cross_activity_flow":
                    self.cross_activity_flows.append(f)
                elif ftype == "settings_abuse":
                    self.ipa_settings_abuse.append(f)
                elif ftype == "vendor_abuse":
                    self.ipa_vendor_abuse.append(f)
                elif ftype == "privileged_intent":
                    self.ipa_privileged_intent.append(f)
        except Exception as e:
            print(f"[!] IPA init warning (non-fatal): {e}")

    FEATURE_APIS = {
        "webview": ["Landroid/webkit/WebView"],
        "webview_js": ["Landroid/webkit/WebSettings;->setJavaScriptEnabled"],
        "webview_js_interface": ["Landroid/webkit/WebView;->addJavascriptInterface"],
        "webview_loadurl": ["Landroid/webkit/WebView;->loadUrl"],
        "sqlite": ["Landroid/database/sqlite/SQLiteDatabase"],
        "content_provider": ["Landroid/content/ContentProvider"],
        "runtime_exec": ["Ljava/lang/Runtime;->exec"],
        "dex_class_loader": ["Ldalvik/system/DexClassLoader;-><init>"],
        "pending_intent": ["Landroid/app/PendingIntent"],
        "reflection": ["Ljava/lang/reflect/Method;->invoke", "Ljava/lang/Class;->forName"],
        "native_code": ["Ljava/lang/System;->loadLibrary", "Ljava/lang/System;->load"],
        "cipher": ["Ljavax/crypto/Cipher"],
        "broadcast": ["Landroid/content/Context;->sendBroadcast"],
        "bind_service": ["Landroid/content/Context;->bindService"],
        "clipboard": ["Landroid/content/ClipboardManager;->setPrimaryClip"],
        "file_provider": ["Landroidx/core/content/FileProvider;->getUriForFile"],
        "fragment": ["Landroid/app/Fragment;->instantiate"],
        "notification": ["Landroid/app/Notification$Builder"],
        "preference": ["Landroid/preference/PreferenceActivity"],
        "device_admin": ["Landroid/app/admin/DevicePolicyManager"],
        "account_manager": ["Landroid/accounts/AccountManager"],
        "ssl_pinning": ["Lokhttp3/CertificatePinner"],
        "zip": ["Ljava/util/zip/ZipInputStream"],
        "sms": ["Landroid/telephony/SmsManager"],
        "serialization": ["Ljava/io/ObjectInputStream;->readObject"],
        "key_store": ["Ljava/security/KeyStore;->getInstance"],
    }

    DETECTOR_FEATURES = {
        "webview_advanced": ["webview"],
        "webview_chains": ["webview", "webview_loadurl"],
        "webview_file_access": ["webview"],
        "command_injection_advanced": ["runtime_exec"],
        "taint_command_execution": ["runtime_exec"],
        "cp_advanced": ["content_provider"],
        "sql_injection_provider": ["sqlite"],
        "pendingintent_advanced": ["pending_intent"],
        "reflection_advanced": ["reflection"],
        "reflection_abuse": ["reflection"],
        "reflection_and_native": ["reflection"],
        "dynamic_code_loading": ["dex_class_loader"],
        "native_code_loading": ["native_code"],
        "crypto_issues": ["cipher"],
        "broadcast_abuse": ["broadcast"],
        "broadcast_notification_advanced": ["broadcast"],
        "insecure_bound_services": ["bind_service"],
        "clipboard_abuse": ["clipboard"],
        "fileprovider_usage": ["file_provider"],
        "fragment_injection": ["fragment"],
        "notification_security": ["notification"],
        "exported_preference_activities": ["preference"],
        "device_admin_abuse": ["device_admin"],
        "zip_path_traversal": ["zip"],
        "deserialization": ["serialization"],
        "android_keystore_usage": ["key_store"],
        "ssl_pinning_config": ["ssl_pinning"],
        "network_mitm": True,
        "filesystem_advanced": True,
        "unsafe_external_storage": True,
        "sensitive_data_leakage": True,
        "unencrypted_database": True,
        "intents_advanced": True,
        "intent_redirection": True,
        "intent_interception": True,
        "confused_deputy": True,
        "arbitrary_intent_launch": True,
        "deeplink_advanced": True,
        "deep_link_hijacking": True,
        "auth_bypass": True,
        "auth_authorization_gaps": True,
        "account_takeover": True,
        "permission_redelegation": True,
        "privilege_escalation": True,
        "system_app_bugs": True,
        "missing_permission_checks": True,
        "jobscheduler_security": True,
        "ssl_pinning_bypass": True,
        "obfuscation_gaps": True,
    }

    def _extract_features(self):
        features = {k: False for k in self.FEATURE_APIS}
        for sig, invokes in self._invoke_index.items():
            for _, output in invokes:
                for fname, apis in self.FEATURE_APIS.items():
                    if features[fname]:
                        continue
                    for api in apis:
                        if api in output:
                            features[fname] = True
                            break
        self._features = features

    def _relevant_detectors(self, all_detectors):
        relevant = []
        for d in sorted(all_detectors):
            key = d.replace("_detect_", "")
            req = self.DETECTOR_FEATURES.get(key, True)
            if req is True:
                relevant.append(d)
            elif isinstance(req, list):
                if any(self._features.get(f, False) for f in req):
                    relevant.append(d)
        return relevant

    def _ensure_analysis(self, sig):
        cached = self._analysis_cache.get(sig)
        if cached:
            return cached
        info = self.method_cfgs.get(sig)
        if not info:
            return None
        cfg = info.get("cfg")
        if cfg is None:
            return None
        entry = {"cfg": cfg, "instructions": info["instructions"], "method": info["method"]}
        try:
            entry["rd"] = ReachingDefinitions(cfg)
        except Exception:
            entry["rd"] = None
        try:
            entry["la"] = LivenessAnalysis(cfg)
        except Exception:
            entry["la"] = None
        try:
            entry["cp"] = ConstantPropagation(info["instructions"])
        except Exception:
            entry["cp"] = None
        self._analysis_cache[sig] = entry
        return entry

    def _extract_manifest_components(self):
        try:
            manifest = self.apk.get_android_manifest_xml()
            if manifest is None:
                return
            ns = {'android': 'http://schemas.android.com/apk/res/android'}
            activities = manifest.xpath("//activity", namespaces=ns)
            services = manifest.xpath("//service", namespaces=ns)
            receivers = manifest.xpath("//receiver", namespaces=ns)
            providers = manifest.xpath("//provider", namespaces=ns)
            self.manifest_components = {
                "activities": [{"name": a.get(f"{{{ns['android']}}}name", ""),
                                "exported": a.get(f"{{{ns['android']}}}exported", "false"),
                                "permission": a.get(f"{{{ns['android']}}}permission", "")} for a in activities],
                "services": [{"name": s.get(f"{{{ns['android']}}}name", ""),
                              "exported": s.get(f"{{{ns['android']}}}exported", "false"),
                              "permission": s.get(f"{{{ns['android']}}}permission", "")} for s in services],
                "receivers": [{"name": r.get(f"{{{ns['android']}}}name", ""),
                               "exported": r.get(f"{{{ns['android']}}}exported", "false"),
                               "permission": r.get(f"{{{ns['android']}}}permission", "")} for r in receivers],
                "providers": [{"name": p.get(f"{{{ns['android']}}}name", ""),
                               "exported": p.get(f"{{{ns['android']}}}exported", "false"),
                               "permission": p.get(f"{{{ns['android']}}}permission", "")} for p in providers],
            }
        except Exception as e:
            print(f"[!] Could not read manifest: {e}")

    def _string_in_source(self, pattern, path_pattern=None):
        if not self.source_dir:
            return []
        matches = []
        for root, _, files in os.walk(self.source_dir):
            for f in files:
                if path_pattern and path_pattern not in root:
                    continue
                if not f.endswith(".java"):
                    continue
                fp = os.path.join(root, f)
                try:
                    with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                        for i, line in enumerate(fh, 1):
                            if re.search(pattern, line):
                                rel = os.path.relpath(fp, self.source_dir)
                                matches.append(f"{rel}:{i}: {line.strip()}")
                except Exception:
                    pass
        return matches

    def _find_methods_by_string(self, search_str):
        matches = []
        strings_pool = set()
        for s in self.vm.get_strings():
            if search_str in str(s):
                strings_pool.add(str(s))
        if not strings_pool:
            return matches
        for cls in self.vm.get_classes():
            for method in cls.get_methods():
                code = method.get_code()
                if code is None:
                    continue
                try:
                    instructions = list(code.get_bc().get_instructions())
                except Exception:
                    continue
                for instr in instructions:
                    try:
                        output = instr.get_output()
                        if any(ref in output for ref in strings_pool):
                            m_sig = f"{cls.name}->{method.name}{method.descriptor}"
                            matches.append(m_sig)
                            break
                    except Exception:
                        pass
        return matches

    def _find_methods_by_invoke(self, target_class, target_name=None):
        matches = []
        for sig, invokes in self._invoke_index.items():
            for iname, output in invokes:
                try:
                    if target_class in output:
                        if target_name is None or target_name in output:
                            matches.append(sig)
                            break
                except Exception:
                    pass
        return matches

    def _find_methods_by_regex(self, pattern):
        matches = []
        try:
            compiled = re.compile(pattern)
        except Exception:
            return matches
        for sig, output_str in self._method_strs.items():
            try:
                if compiled.search(output_str):
                    matches.append(sig)
            except Exception:
                pass
        return matches

    def _has_sensitive_strings(self, search_area):
        for kw in SENSITIVE_KEYWORDS:
            if kw.lower() in search_area.lower():
                return True
        return False

    def _sensitive_strings_in_method(self, instructions):
        found = []
        for ins in instructions:
            try:
                text = ins.get_output()
                for kw in SENSITIVE_KEYWORDS:
                    if kw in text.lower():
                        found.append(kw)
                        break
            except Exception:
                pass
        return found

    def _format_location(self, method_sig, details=""):
        if details:
            return f"{method_sig} | {details}"
        return method_sig

    def _add_finding(self, category, id_, name, description, severity, recommendation, location):
        self.findings.append({
            "category": category,
            "rules": [{
                "id": id_, "name": name, "description": description,
                "severity": severity, "recommendation": recommendation,
                "location": location,
            }]
        })

    # ══════════════════════════════════════════════════════════
    # SUMMARY — All _detect_* methods in core/detectors/
    # ══════════════════════════════════════════════════════════

    def get_summary(self):
        total = sum(len(g["rules"]) for g in self.findings)
        by_category = {g["category"]: len(g["rules"]) for g in self.findings}
        return {
            "total": total,
            "categories": len(self.findings),
            "by_category": by_category,
            "call_graph_nodes": len(self.call_graph.get("nodes", [])),
            "call_graph_edges": len(self.call_graph.get("edges", [])),
            "classes_analyzed": len(list(self.vm.get_classes())) if self.vm else 0,
            "methods_analyzed": len(list(self.vm.get_methods())) if self.vm else 0,
            "ipa_binder_flows": len(self.binder_flow) if hasattr(self, 'binder_flow') else 0,
            "ipa_binder_bypass": len(self.binder_perm_bypass) if hasattr(self, 'binder_perm_bypass') else 0,
            "ipa_lifecycle_flows": len(self.lifecycle_flows) if hasattr(self, 'lifecycle_flows') else 0,
            "ipa_callback_flows": len(self.callback_flows) if hasattr(self, 'callback_flows') else 0,
            "ipa_concurrent_flows": len(self.concurrent_flows) if hasattr(self, 'concurrent_flows') else 0,
            "ipa_cross_class_flows": len(self.cross_class_flows) if hasattr(self, 'cross_class_flows') else 0,
            "ipa_cross_activity_flows": len(self.cross_activity_flows) if hasattr(self, 'cross_activity_flows') else 0,
        }

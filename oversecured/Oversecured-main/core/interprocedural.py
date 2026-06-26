import re
from collections import defaultdict, deque

from core.cfg import MethodCFG
from core.dataflow import ReachingDefinitions, LivenessAnalysis, ConstantPropagation
import logging
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════
# INVOKE / BINDER / IPC PATTERNS
# ═══════════════════════════════════════════════════════════════

BINDER_SERVICES = {
    "Landroid/os/IBinder;->transact",
    "Landroid/os/Binder;->transact",
    "Landroid/os/Binder;->execTransact",
    "Landroid/os/Binder;->getCallingUid",
    "Landroid/os/Binder;->getCallingPid",
    "Landroid/os/Binder;->clearCallingIdentity",
    "Landroid/os/Binder;->restoreCallingIdentity",
}

SYSTEM_SERVICES = {
    "Landroid/content/Context;->getSystemService",
    "Landroid/content/Context;->getSystemServiceName",
    "Landroid/os/ServiceManager;->getService",
    "Landroid/os/ServiceManager;->addService",
    "Landroid/os/ServiceManager;->checkService",
    "Landroid/os/ServiceManager;->listServices",
}

SETTINGS_PROVIDER = {
    "Landroid/provider/Settings$Secure;->putString",
    "Landroid/provider/Settings$Secure;->getString",
    "Landroid/provider/Settings$Secure;->putInt",
    "Landroid/provider/Settings$Secure;->getInt",
    "Landroid/provider/Settings$System;->putString",
    "Landroid/provider/Settings$System;->getString",
    "Landroid/provider/Settings$Global;->putString",
    "Landroid/provider/Settings$Global;->getString",
    "Landroid/provider/Settings;->putString",
    "Landroid/provider/Settings;->getString",
}

VENDOR_SERVICES = [
    "com.huawei", "com.xiaomi", "com.oneplus", "com.samsung",
    "com.google.android", "com.qualcomm", "com.mediatek",
    "vendor.", "oem.", "system/vendor",
]

# Callback interfaces known in Android framework
CALLBACK_TYPES = {
    "Landroid/view/View$OnClickListener",
    "Landroid/view/View$OnLongClickListener",
    "Landroid/view/View$OnTouchListener",
    "Landroid/widget/AdapterView$OnItemClickListener",
    "Landroid/content/DialogInterface$OnClickListener",
    "Landroid/content/BroadcastReceiver",
    "Landroid/app/Service",
    "Landroid/app/IntentService",
    "Landroid/os/Handler$Callback",
    "Landroid/os/AsyncTask",
    "Ljava/lang/Runnable",
    "Ljava/util/concurrent/Callable",
    "Landroid/animation/Animator$AnimatorListener",
    "Landroid/text/TextWatcher",
    "Lcom/google/android/material/textfield/TextInputLayout$OnEditTextAttachedListener",
}

LIFECYCLE_METHODS = {
    "onCreate", "onStart", "onResume", "onPause", "onStop", "onDestroy",
    "onRestart", "onSaveInstanceState", "onRestoreInstanceState",
    "onActivityResult", "onNewIntent", "onBackPressed",
    "onConfigurationChanged", "onLowMemory", "onTrimMemory",
}

ASYNC_PATTERNS = {
    "Landroid/os/AsyncTask;->execute",
    "Landroid/os/AsyncTask;->executeOnExecutor",
    "Landroid/os/AsyncTask;->doInBackground",
    "Landroid/os/AsyncTask;->onPreExecute",
    "Landroid/os/AsyncTask;->onPostExecute",
    "Landroid/os/AsyncTask;->onProgressUpdate",
    "Ljava/lang/Thread;->start",
    "Ljava/util/concurrent/ThreadPoolExecutor;->execute",
    "Ljava/util/concurrent/ExecutorService;->submit",
    "Landroid/os/Handler;->post",
    "Landroid/os/Handler;->sendMessage",
    "Landroid/os/Handler;->handleMessage",
    "Landroid/os/Handler;->obtainMessage",
    "Landroid/os/Message;->sendToTarget",
    "Lkotlinx/coroutines/BuildersKt;->launch",
    "Lkotlinx/coroutines/BuildersKt;->async",
}

# Known privilege escalation patterns
PRIVILEGED_ACTIONS = {
    "android.intent.action.INSTALL_PACKAGE",
    "android.intent.action.UNINSTALL_PACKAGE",
    "android.intent.action.MASTER_CLEAR",
    "android.intent.action.FACTORY_RESET",
    "android.intent.action.SET_WALLPAPER",
    "android.intent.action.SET_PREFERRED_APPLICATION",
    "android.intent.action.ACCESS_NETWORK_STATE",
    "android.provider.Telephony.SMS_RECEIVED",
    "android.provider.Telephony.WAP_PUSH_RECEIVED",
    "android.intent.action.NEW_OUTGOING_CALL",
    "android.intent.action.CLOSE_SYSTEM_DIALOGS",
    "android.intent.action.SCREEN_OFF",
    "android.intent.action.SCREEN_ON",
    "android.intent.action.USER_PRESENT",
    "android.intent.action.TIME_SET",
    "android.intent.action.TIMEZONE_CHANGED",
}


# ═══════════════════════════════════════════════════════════════
# INTERPROCEDURAL ANALYSIS ENGINE
# ═══════════════════════════════════════════════════════════════

class CallContext:
    __slots__ = ('method_sig', 'param_taint', 'return_taint', 'sink_hits', 'callers', 'callees')

    def __init__(self, method_sig):
        self.method_sig = method_sig
        self.param_taint = {}
        self.return_taint = False
        self.sink_hits = []
        self.callers = set()
        self.callees = set()


class InterproceduralAnalyzer:
    def __init__(self, vm, vmx, call_graph, method_cfgs, taint_engine):
        self.vm = vm
        self.vmx = vmx
        self.call_graph = call_graph
        self.method_cfgs = method_cfgs
        self.taint_engine = taint_engine
        self._param_flow_cache = {}
        self._cp_cache = {}
        self.ctx = self._build_contexts()

    def _build_contexts(self):
        ctx = {}
        for edge in self.call_graph.get("edges", []):
            src = edge.get("source", "")
            tgt = edge.get("target", "")
            if src not in ctx:
                ctx[src] = CallContext(src)
            if tgt not in ctx:
                ctx[tgt] = CallContext(tgt)
            ctx[src].callees.add(tgt)
            ctx[tgt].callers.add(src)
        for sig in self.method_cfgs:
            if sig not in ctx:
                ctx[sig] = CallContext(sig)
        return ctx

    def _get_cached_cp(self, caller_sig):
        cp = self._cp_cache.get(caller_sig)
        if cp is None:
            info = self.method_cfgs.get(caller_sig)
            if info:
                cp = ConstantPropagation(info["instructions"])
                self._cp_cache[caller_sig] = cp
        return cp

    def _get_cached_param_flow(self, caller_sig, callee_sig):
        key = (caller_sig, callee_sig)
        cached = self._param_flow_cache.get(key)
        if cached is not None:
            return cached
        flow = self._compute_param_flow_impl(caller_sig, callee_sig)
        self._param_flow_cache[key] = flow
        return flow

    def analyze(self, max_iterations=3, time_limit=30):
        import time
        t0 = time.time()
        changed = True
        iteration = 0
        while changed and iteration < max_iterations and time.time() - t0 < time_limit:
            changed = False
            iteration += 1
            for sig, ctx in self.ctx.items():
                if time.time() - t0 > time_limit:
                    break
                if not ctx.callers:
                    continue
                caller_taint_flow = False
                for caller_sig in ctx.callers:
                    flow = self._get_cached_param_flow(caller_sig, sig) if sig in self.ctx else {}
                    for param_idx, is_tainted in flow.items():
                        old = ctx.param_taint.get(param_idx, False)
                        if is_tainted and not old:
                            ctx.param_taint[param_idx] = True
                            changed = True
                            caller_taint_flow = True
                if caller_taint_flow:
                    self._propagate_to_callees(sig)

        for sig, ctx in self.ctx.items():
            self._detect_method_sinks(sig, ctx)

        return self._collect_findings()

    def _compute_param_flow_impl(self, caller_sig, callee_sig):
        flow = {}
        caller_info = self.method_cfgs.get(caller_sig)
        if not caller_info:
            return flow
        instructions = caller_info["instructions"]
        cp = self._get_cached_cp(caller_sig)
        if cp is None:
            return flow
        reg_taint = self.taint_engine.reg_taint if hasattr(self.taint_engine, 'reg_taint') else {}
        callee_match = callee_sig.replace("->", ";->")
        for idx, ins in enumerate(instructions):
            try:
                output = ins.get_output()
                name = ins.get_name()
                if not name.startswith("invoke"):
                    continue
                if callee_match not in output and callee_sig not in output:
                    continue
                parts = output.replace(",", "").split()
                arg_regs = [p for p in parts if p.startswith('v') or p.startswith('p')]
                for pi, reg in enumerate(arg_regs):
                    is_tainted = reg in reg_taint
                    flow[pi] = is_tainted
            except Exception:
                logger.debug("Silent exception caught", exc_info=True)
        return flow

    def _propagate_to_callees(self, sig):
        ctx = self.ctx.get(sig)
        if not ctx:
            return
        for callee in ctx.callees:
            callee_ctx = self.ctx.get(callee)
            if callee_ctx and not callee_ctx.return_taint:
                callee_ctx.return_taint = any(ctx.param_taint.values()) or ctx.return_taint

    def _detect_method_sinks(self, sig, ctx):
        info = self.method_cfgs.get(sig)
        if not info:
            return
        instructions = info["instructions"]
        for idx, ins in enumerate(instructions):
            try:
                name = ins.get_name()
                if not name.startswith("invoke"):
                    continue
                output = ins.get_output()
                if ";->" not in output:
                    continue
                parts = output.split("->", 1)
                cls_part = parts[0].split()[-1] if " " in parts[0] else parts[0]
                rest = parts[1]
                method_end = rest.find("(")
                full_sig = f"{cls_part}->{rest[:method_end]}" if method_end >= 0 else f"{cls_part}->{rest}"
                self._check_binder_sinks(full_sig, output, sig, idx, ctx)
                self._check_system_service_sinks(full_sig, output, sig, idx, ctx)
                self._check_settings_sinks(full_sig, output, sig, idx, ctx)
                self._check_privileged_intent_sinks(full_sig, output, sig, idx, ctx)
                self._check_vendor_service_sinks(full_sig, output, sig, idx, ctx)
                self._check_broadcast_to_service(full_sig, output, sig, idx, ctx)
                self._check_callback_registration(full_sig, output, sig, idx, ctx)
            except Exception:
                logger.debug("Silent exception caught", exc_info=True)

    def _extract_invoke_sig(self, output):
        if ";->" in output:
            parts = output.split("->", 1)
            cls_part = parts[0].split()[-1] if " " in parts[0] else parts[0]
            rest = parts[1]
            method_end = rest.find("(")
            if method_end == -1:
                method_end = len(rest)
            return f"{cls_part}->{rest[:method_end]}"
        return None

    def _check_binder_sinks(self, full_sig, output, method_sig, idx, ctx):
        for bs in BINDER_SERVICES:
            if bs in full_sig:
                ctx.sink_hits.append({
                    "type": "binder_bypass",
                    "severity": "CRITICAL",
                    "sink": full_sig,
                    "method": method_sig,
                    "instruction": idx,
                    "detail": "Binder transaction without permission check",
                })

    def _check_system_service_sinks(self, full_sig, output, method_sig, idx, ctx):
        for ss in SYSTEM_SERVICES:
            if ss in full_sig:
                ctx.sink_hits.append({
                    "type": "system_service_abuse",
                    "severity": "HIGH",
                    "sink": full_sig,
                    "method": method_sig,
                    "instruction": idx,
                    "detail": "System service accessed - verify permission checks",
                })

    def _check_settings_sinks(self, full_sig, output, method_sig, idx, ctx):
        for sp in SETTINGS_PROVIDER:
            if sp in full_sig:
                put_op = "put" in sp
                ctx.sink_hits.append({
                    "type": "settings_provider_abuse",
                    "severity": "HIGH" if put_op else "MEDIUM",
                    "sink": full_sig,
                    "method": method_sig,
                    "instruction": idx,
                    "detail": f"Settings provider {'write' if put_op else 'read'} detected - may require WRITE_SECURE_SETTINGS",
                })

    def _check_privileged_intent_sinks(self, full_sig, output, method_sig, idx, ctx):
        for action in PRIVILEGED_ACTIONS:
            if action in output:
                ctx.sink_hits.append({
                    "type": "privileged_intent_abuse",
                    "severity": "HIGH",
                    "sink": full_sig,
                    "method": method_sig,
                    "instruction": idx,
                    "detail": f"Privileged action '{action}' used without system permission check",
                })

    def _check_vendor_service_sinks(self, full_sig, output, method_sig, idx, ctx):
        for vendor in VENDOR_SERVICES:
            if vendor.replace(".", "/") in full_sig or vendor in full_sig:
                ctx.sink_hits.append({
                    "type": "vendor_service_abuse",
                    "severity": "MEDIUM",
                    "sink": full_sig,
                    "method": method_sig,
                    "instruction": idx,
                    "detail": f"Vendor/OEM service '{full_sig}' accessed - verify behavior",
                })
                break

    def _check_broadcast_to_service(self, full_sig, output, method_sig, idx, ctx):
        if "Landroid/content/Context;->startService" in full_sig:
            nearby = self._find_nearby_strings(output, 5)
            for s in nearby:
                if any(kw in s for kw in ["SMS_RECEIVED", "BOOT_COMPLETED", "CONNECTIVITY", "BATTERY", "PACKAGE_"]):
                    ctx.sink_hits.append({
                        "type": "broadcast_to_service",
                        "severity": "HIGH",
                        "sink": full_sig,
                        "method": method_sig,
                        "instruction": idx,
                        "detail": f"Broadcast receiver starts service via {full_sig}",
                    })
                    break

    def _check_callback_registration(self, full_sig, output, method_sig, idx, ctx):
        for cb in CALLBACK_TYPES:
            if cb in output:
                ctx.sink_hits.append({
                    "type": "callback_flow",
                    "severity": "INFO",
                    "sink": full_sig,
                    "method": method_sig,
                    "instruction": idx,
                    "detail": f"Callback type '{cb}' registered - data may flow through callback",
                })
                break

    def _find_nearby_strings(self, output, window):
        strings = []
        for s in self.taint_engine.vm.get_strings() if hasattr(self.taint_engine, 'vm') else []:
            try:
                if str(s) in output:
                    strings.append(str(s))
            except Exception:
                logger.debug("Silent exception caught", exc_info=True)
        return strings[:window]

    def _collect_findings(self):
        findings = defaultdict(list)
        for sig, ctx in self.ctx.items():
            for hit in ctx.sink_hits:
                findings[hit["type"]].append(hit)
        return dict(findings)

    def trace_source_chain(self, sink_method_sig, max_hops=5):
        chain = [sink_method_sig]
        visited = {sink_method_sig}
        queue = deque([(sink_method_sig, 0)])
        while queue:
            current, depth = queue.popleft()
            if depth >= max_hops:
                continue
            ctx = self.ctx.get(current)
            if not ctx:
                continue
            for caller in ctx.callers:
                if caller not in visited:
                    visited.add(caller)
                    chain.append(caller)
                    queue.append((caller, depth + 1))
        return chain

    def compute_binder_flow(self):
        binder_findings = []
        for cls in self.vm.get_classes():
            for method in cls.get_methods():
                code = method.get_code()
                if code is None:
                    continue
                try:
                    instructions = list(code.get_bc().get_instructions())
                except Exception:
                    continue
                method_sig = f"{cls.name}->{method.name}{method.descriptor}"
                for idx, ins in enumerate(instructions):
                    try:
                        output = ins.get_output()
                        name = ins.get_name()
                        if not name.startswith("invoke"):
                            continue
                        if "Landroid/os/IBinder;->transact" in output:
                            has_callinguid = False
                            has_callingpid = False
                            for j in range(max(0, idx - 20), idx):
                                try:
                                    io = instructions[j].get_output()
                                    if "getCallingUid" in io:
                                        has_callinguid = True
                                    if "getCallingPid" in io:
                                        has_callingpid = True
                                except Exception:
                                    logger.debug("Silent exception caught", exc_info=True)
                            if not has_callinguid and not has_callingpid:
                                binder_findings.append({
                                    "method": method_sig,
                                    "instruction": idx,
                                    "detail": "IBinder.transact called without getCallingUid/getCallingPid check",
                                })
                    except Exception:
                        logger.debug("Silent exception caught", exc_info=True)
        return binder_findings


# ═══════════════════════════════════════════════════════════════
# BINDER PERMISSION BYPASS DETECTOR
# ═══════════════════════════════════════════════════════════════

class BinderPermissionAnalyzer:
    def __init__(self, vm, method_cfgs):
        self.vm = vm
        self.method_cfgs = method_cfgs

    def analyze(self):
        findings = []
        for sig, info in self.method_cfgs.items():
            if not self._is_binder_service(sig):
                continue
            instructions = info["instructions"]
            has_enforce = False
            has_callinguid = False
            has_permission_check = False
            for ins in instructions:
                try:
                    output = ins.get_output()
                    if "enforceCallingPermission" in output or "enforceCallingOrSelfPermission" in output:
                        has_enforce = True
                    if "getCallingUid" in output:
                        has_callinguid = True
                    if "checkCallingPermission" in output or "checkCallingOrSelfPermission" in output:
                        has_permission_check = True
                except Exception:
                    logger.debug("Silent exception caught", exc_info=True)
            if not has_enforce and not has_callinguid and not has_permission_check:
                findings.append({
                    "method": sig,
                    "has_enforce": has_enforce,
                    "has_callinguid": has_callinguid,
                    "has_permission_check": has_permission_check,
                })
        return findings

    def _is_binder_service(self, sig):
        if "onTransact" in sig or "onBind" in sig:
            return True
        if "Binder" in sig or "IInterface" in sig:
            return True
        if "Stub" in sig or "Proxy" in sig:
            return True
        return False


# ═══════════════════════════════════════════════════════════════
# LIFECYCLE / CALLBACK / CONCURRENT FLOW ANALYZER
# ═══════════════════════════════════════════════════════════════

class FlowAnalyzer:
    def __init__(self, vm, method_cfgs, call_graph):
        self.vm = vm
        self.method_cfgs = method_cfgs
        self.call_graph = call_graph

    def analyze_lifecycle_flows(self):
        findings = []
        lifecycle_map = defaultdict(set)
        for sig in self.method_cfgs:
            for lm in LIFECYCLE_METHODS:
                if f"->{lm}" in sig:
                    lifecycle_map[lm].add(sig)

        chain = ["onCreate", "onStart", "onResume", "onPause", "onStop", "onDestroy"]
        for i in range(len(chain) - 1):
            curr = chain[i]
            nxt = chain[i + 1]
            for csig in lifecycle_map.get(curr, set()):
                for nsig in lifecycle_map.get(nxt, set()):
                    base_class = csig.split("->")[0]
                    if base_class and base_class == nsig.split("->")[0]:
                        findings.append({
                            "type": "lifecycle_flow",
                            "from": csig,
                            "to": nsig,
                            "classes": [base_class],
                        })
        return findings

    def analyze_callback_flows(self):
        findings = []
        for sig in self.method_cfgs:
            for ct in CALLBACK_TYPES:
                className = ct.replace("L", "").replace(";", "").replace("/", ".")
                if className in sig:
                    findings.append({
                        "type": "callback_flow",
                        "method": sig,
                        "callback_type": className,
                    })
        return findings

    def analyze_concurrent_flows(self):
        findings = []
        for sig, info in self.method_cfgs.items():
            instructions = info["instructions"]
            for ins in instructions:
                try:
                    output = ins.get_output()
                    for ap in ASYNC_PATTERNS:
                        if ap in output:
                            findings.append({
                                "type": "concurrent_flow",
                                "method": sig,
                                "sink": ap,
                                "detail": f"Async/concurrent operation via {ap}",
                            })
                            break
                except Exception:
                    logger.debug("Silent exception caught", exc_info=True)
        return findings

    def analyze_handler_flows(self):
        findings = []
        handler_methods = set()
        for sig, info in self.method_cfgs.items():
            if "handleMessage" in sig or "Handler" in sig:
                handler_methods.add(sig)

        for sig, info in self.method_cfgs.items():
            instructions = info["instructions"]
            for ins in instructions:
                try:
                    output = ins.get_output()
                    if "Landroid/os/Handler;->sendMessage" in output or "Landroid/os/Handler;->post" in output:
                        findings.append({
                            "type": "handler_flow",
                            "sender": sig,
                            "receivers": list(handler_methods),
                            "detail": "Handler message flow from sender to one or more receivers",
                        })
                        break
                except Exception:
                    logger.debug("Silent exception caught", exc_info=True)
        return findings

    def find_cross_activity_flows(self):
        findings = []
        intent_put = set()
        intent_get = set()
        for sig in self.method_cfgs:
            for ins in self.method_cfgs[sig]["instructions"]:
                try:
                    output = ins.get_output()
                    if "Intent;->putExtra" in output or "Intent;->putStringArrayListExtra" in output:
                        intent_put.add(sig)
                    if "getStringExtra" in output or "getIntExtra" in output or "getSerializableExtra" in output:
                        intent_get.add(sig)
                except Exception:
                    logger.debug("Silent exception caught", exc_info=True)

        for put_sig in intent_put:
            for get_sig in intent_get:
                findings.append({
                    "type": "cross_activity_flow",
                    "sender": put_sig,
                    "receiver": get_sig,
                })
        return findings

    def find_cross_class_flows(self, time_limit=10):
        import time
        findings = []
        class_flows = defaultdict(set)
        t0 = time.time()
        edges_list = self.call_graph.get("edges", [])
        for sig in self.method_cfgs:
            if time.time() - t0 > time_limit:
                break
            cls_name = sig.split("->")[0]
            for edge in edges_list:
                if edge.get("source") == sig:
                    tgt = edge.get("target", "")
                    tgt_cls = tgt.split("->")[0]
                    if tgt_cls and tgt_cls != cls_name:
                        class_flows[(cls_name, tgt_cls)].add((sig, tgt))

        for (from_cls, to_cls), edges in class_flows.items():
            findings.append({
                "type": "cross_class_flow",
                "from_class": from_cls,
                "to_class": to_cls,
                "edges": list(edges)[:5],
            })
        return findings


# ═══════════════════════════════════════════════════════════════
# MULTI-HOP TAINT PROPAGATOR
# ═══════════════════════════════════════════════════════════════

class MultiHopTaintPropagator:
    def __init__(self, vm, method_cfgs, call_graph, taint_findings):
        self.vm = vm
        self.method_cfgs = method_cfgs
        self.call_graph = call_graph
        self.taint_findings = taint_findings

    def propagate(self, max_hops=5):
        results = defaultdict(list)
        visited = set()

        def follow(value_sig, depth, path):
            if depth > max_hops or value_sig in visited:
                return
            visited.add(value_sig)
            path = path + [value_sig]

            for sink_type, sinks in self.taint_findings.items():
                for s in sinks:
                    if s.get("method") == value_sig or value_sig in str(s):
                        results[sink_type].append({
                            "path": list(path),
                            "depth": depth,
                            "sink": s,
                        })

            for edge in self.call_graph.get("edges", []):
                if edge.get("source") == value_sig:
                    follow(edge["target"], depth + 1, path)

        for sink_type, sinks in self.taint_findings.items():
            for s in sinks:
                method_sig = s.get("method", "")
                if method_sig:
                    follow(method_sig, 0, [])

        return dict(results)

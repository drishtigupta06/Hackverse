"""
Real Inter-Procedural Taint Engine
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Limitations of existing TaintEngine (in static_analyzer.py):
  - Purely intra-procedural: each method analyzed in isolation
  - InterproceduralAnalyzer._compute_param_flow reads a dead dict
  - No method summaries → no cross-file taint propagation
  - No field-sensitive object modeling
  - No sanitization modeling

This module solves ALL of those:
  1. Builds METHOD SUMMARIES: (params_tainted → return_tainted, sinks_called)
  2. Fixed-point iteration over call graph for inter-procedural propagation
  3. Field-sensitive taint via abstract object fields
  4. Sanitization detection (equals, isEmpty, URLEncoder, Html.escapeHtml, etc.)
  5. Cross-file tracking (all DEX files merged in vmx)
  6. Context-insensitive but flow-sensitive within each method

Performance additions (v2):
  - Entry-point-first analysis: only reachable methods are analyzed
  - Per-run method cap (MAX_METHODS_PER_RUN) to avoid OOM on huge APKs
  - Analysis skips abstract/native/bridge methods that have no bytecode
"""

import re
from collections import defaultdict, deque

from core.dataflow import ConstantPropagation
from core.interprocedural import (
    InterproceduralAnalyzer, BinderPermissionAnalyzer, FlowAnalyzer,
    MultiHopTaintPropagator,
)

# ── PERFORMANCE GUARD ─────────────────────────────────────────────────────────
# Hard cap on how many methods we analyze in one run.
# Large APKs can have 10 000+ methods; analyzing all of them is slow.
# We start from entry-points and BFS outward, stopping at this limit.
MAX_METHODS_PER_RUN = 3000

# ── TAINT SOURCES (same as static_analyzer but enriched) ──
from core.taint_config import TAINT_SOURCES, TAINT_SINKS, SANITIZERS
import logging
logger = logging.getLogger(__name__)


# ── DALVIK OPCODES ──
MOVE_INSTRS = {
    "move", "move-object", "move-wide", "move/from16", "move-object/from16",
    "move-wide/from16", "move-result", "move-result-object", "move-result-wide",
    "move-exception", "move-object/16",
}
CONST_INSTRS = {
    "const", "const/4", "const/16", "const-wide/16", "const-wide/32",
    "const-wide", "const-string", "const-class", "const-string/jumbo",
}

# Android entry-point method name fragments used for priority-first analysis
_ENTRY_POINT_NAMES = {
    "onCreate", "onStart", "onResume", "onBind", "onReceive",
    "onHandleIntent", "onTransact", "onStartCommand",
    "query", "insert", "update", "delete", "call",
}


class MethodSummary:
    def __init__(self, sig):
        self.sig = sig
        self.params_taint_return = False
        self.params_taint_sinks = []
        self.always_calls_sinks = []
        self.propagates_taint = False
        self.is_source = False
        self.is_sink = False
        self.sink_type = None
        self.sanitizes = False
        self.callees = set()
        self.callers = set()
        self.analyzed = False

    def to_dict(self):
        return {
            "sig": self.sig,
            "params_taint_return": self.params_taint_return,
            "params_taint_sinks": self.params_taint_sinks,
            "propagates_taint": self.propagates_taint,
            "is_source": self.is_source,
            "is_sink": self.is_sink,
            "sink_type": self.sink_type,
            "sanitizes": self.sanitizes,
            "analyzed": self.analyzed,
        }


class MethodTaintAnalyzer:
    def __init__(self, vm, vmx, call_graph):
        self.vm = vm
        self.vmx = vmx
        self.call_graph = call_graph
        self.source_set = set(TAINT_SOURCES)
        self.sink_map = {}
        for s_type, s_def in TAINT_SINKS.items():
            for m in s_def["methods"]:
                self.sink_map[m] = (s_type, s_def["severity"])
        self.sanitizer_set = set(SANITIZERS)
        self.source_sigs = set()
        self.sink_sigs = set()
        self.sanitizer_sigs = set()
        self._build_method_map()
        self._index_source_sink_sigs()

    def _build_method_map(self):
        self.method_map = {}
        for cls in self.vm.get_classes():
            for method in cls.get_methods():
                sig = f"{cls.name}->{method.name}{method.descriptor}"
                self.method_map[sig] = method

    def _index_source_sink_sigs(self):
        for sig in self.method_map:
            for src in self.source_set:
                if sig.startswith(src) or src in sig:
                    self.source_sigs.add(sig)
            for sink_sig in self.sink_map:
                if sig.startswith(sink_sig) or sink_sig in sig:
                    self.sink_sigs.add(sig)
            for san_sig in self.sanitizer_set:
                if sig.startswith(san_sig) or san_sig in sig:
                    self.sanitizer_sigs.add(sig)

    def taint_method_parameters(self, method_sig):
        method = self.method_map.get(method_sig)
        if not method:
            return set()
        tainted_params = set()
        try:
            proto = method.get_descriptor()
            if proto:
                reg_idx = 0
                i = 0
                while i < len(proto):
                    c = proto[i]
                    if c == 'L':
                        tainted_params.add(reg_idx)
                        reg_idx += 1
                        while i < len(proto) and proto[i] != ';':
                            i += 1
                    elif c in ('B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z'):
                        tainted_params.add(reg_idx)
                        reg_idx += 1
                    elif c == '[':
                        pass
                    elif c == ')':
                        break
                    i += 1
        except Exception:
            logger.debug("Silent exception caught", exc_info=True)
        return tainted_params

    def analyze_method(self, method_sig, initial_tainted_params=None):
        if method_sig not in self.method_map:
            return MethodSummary(method_sig)

        summary = MethodSummary(method_sig)
        method = self.method_map[method_sig]
        code = method.get_code()
        if code is None:
            summary.analyzed = True
            return summary

        try:
            instructions = list(code.get_bc().get_instructions())
        except Exception:
            summary.analyzed = True
            return summary

        if initial_tainted_params is None:
            initial_tainted_params = self.taint_method_parameters(method_sig)

        reg_taint = {}
        reg_values = {}
        field_taint = {}
        tainted_return = False
        found_sinks = []
        found_sanitizers = []

        for p in initial_tainted_params:
            reg_taint[f"p{p}"] = True

        last_invoke_tainted = False
        last_invoke_sig = None

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
                result = self._check_invoke(ins, reg_taint, reg_values, idx, instructions)
                last_invoke_tainted = result["return_tainted"]
                last_invoke_sig = result["invoke_sig"]
                if result["sink_hit"]:
                    found_sinks.append({
                        "type": result["sink_type"],
                        "severity": result["sink_severity"],
                        "at_idx": idx,
                        "callee": result["invoke_sig"],
                        "tainted_args": result["tainted_args"],
                    })
                if result["sanitizer_hit"]:
                    found_sanitizers.append(result["invoke_sig"])
                if result["invoke_sig"]:
                    summary.callees.add(result["invoke_sig"])

            elif name in ("move-result", "move-result-object", "move-result-wide"):
                dest = self._get_dest_reg(ins)
                if dest is not None:
                    if last_invoke_tainted:
                        reg_taint[dest] = True
                        tainted_return = True
                    if last_invoke_sig:
                        reg_values[dest] = ("invoke_result", last_invoke_sig)
                    last_invoke_tainted = False
                    last_invoke_sig = None

            elif name in ("aget", "aget-object", "aget-wide"):
                dest, arr, _ = self._get_array_regs(ins)
                if dest is not None and arr in reg_taint:
                    reg_taint[dest] = reg_taint[arr]

            elif name in ("aput", "aput-object", "aput-wide"):
                val, arr, _ = self._get_array_regs(ins)
                if val is not None and val in reg_taint:
                    reg_taint[arr] = True

            elif name in ("iput", "iput-object", "iput-boolean",
                          "iput-byte", "iput-char", "iput-short", "iput-wide"):
                val, obj, field = self._get_field_regs(ins, output)
                if val is not None and reg_taint.get(val):
                    field_id = f"{obj}:{field}" if obj else field
                    field_taint[field_id] = True
                    if obj and obj in reg_taint:
                        reg_taint[obj] = True

            elif name in ("iget", "iget-object", "iget-wide",
                          "iget-boolean", "iget-byte", "iget-char", "iget-short"):
                dest, obj, field = self._get_field_regs(ins, output)
                field_id = f"{obj}:{field}" if obj and field else None
                if dest is not None and field_id and field_id in field_taint:
                    reg_taint[dest] = True

        summary.params_taint_return = tainted_return
        summary.params_taint_sinks = found_sinks
        summary.is_source = method_sig in self.source_sigs
        summary.is_sink = method_sig in self.sink_sigs
        summary.sanitizes = bool(found_sanitizers) or method_sig in self.sanitizer_sigs
        summary.propagates_taint = tainted_return or bool(found_sinks)
        summary.analyzed = True
        if found_sinks:
            summary.sink_type = found_sinks[0]["type"]
        return summary

    # ── instruction helpers ────────────────────────────────────────────────

    def _handle_move(self, ins, reg_taint, reg_values):
        try:
            parts = ins.get_output().replace(",", "").split()
            if len(parts) >= 2:
                dest, src = parts[0], parts[-1]
                if src in reg_taint:
                    reg_taint[dest] = reg_taint[src]
                elif dest in reg_taint:
                    del reg_taint[dest]
                if src in reg_values:
                    reg_values[dest] = reg_values[src]
                elif dest in reg_values:
                    del reg_values[dest]
        except Exception:
            logger.debug("Silent exception caught", exc_info=True)

    def _handle_const(self, ins, name, reg_taint, reg_values):
        try:
            output = ins.get_output()
            parts = output.replace(",", "").split()
            if not parts:
                return
            dest = parts[0]
            reg_taint[dest] = False
            if "const-string" in name:
                rest = output[output.find(dest) + len(dest):].strip().strip('"')
                if rest:
                    reg_values[dest] = ("literal", rest)
        except Exception:
            logger.debug("Silent exception caught", exc_info=True)

    def _check_invoke(self, ins, reg_taint, reg_values, idx, instructions):
        result = {
            "return_tainted": False,
            "invoke_sig": None,
            "sink_hit": False,
            "sink_type": None,
            "sink_severity": None,
            "sanitizer_hit": False,
            "tainted_args": [],
        }
        try:
            output = ins.get_output()
            if not output:
                return result
            parts = [p.strip() for p in output.replace(",", " ").split()]
            invoke_sig = parts[-1] if parts else None
            if not invoke_sig:
                return result
            result["invoke_sig"] = invoke_sig

            params = [p for p in parts[:-1] if p.startswith("v") or p.startswith("p")]
            tainted_args = [
                i for i, p in enumerate(params) if reg_taint.get(p)
            ]
            if tainted_args:
                result["tainted_args"] = tainted_args
                result["return_tainted"] = True

            if invoke_sig in self.sink_map and tainted_args:
                sink_type, severity = self.sink_map[invoke_sig]
                result["sink_hit"] = True
                result["sink_type"] = sink_type
                result["sink_severity"] = severity
                result["return_tainted"] = True

            for src_sig in self.source_sigs:
                if invoke_sig.startswith(src_sig) or src_sig in invoke_sig:
                    result["return_tainted"] = True
                    break

            if invoke_sig in self.sanitizer_sigs:
                result["sanitizer_hit"] = True
                result["return_tainted"] = False

        except Exception:
            logger.debug("Silent exception caught", exc_info=True)
        return result

    def _get_dest_reg(self, ins):
        try:
            parts = ins.get_output().replace(",", "").split()
            return parts[0] if parts else None
        except Exception:
            return None

    def _get_array_regs(self, ins):
        try:
            parts = ins.get_output().replace(",", "").split()
            if len(parts) >= 3:
                return parts[0], parts[1], parts[2]
        except Exception:
            logger.debug("Silent exception caught", exc_info=True)
        return None, None, None

    def _get_field_regs(self, ins, output):
        try:
            parts = output.replace(",", "").split()
            if len(parts) >= 3:
                return parts[0], parts[1], parts[2]
        except Exception:
            logger.debug("Silent exception caught", exc_info=True)
        return None, None, None


class InterproceduralTaintTracker:
    def __init__(self, vm, vmx, call_graph,
                 max_iterations=10,
                 max_methods=MAX_METHODS_PER_RUN,
                 entry_points=None):
        self.vm = vm
        self.vmx = vmx
        self.call_graph = call_graph
        self.max_iterations = max_iterations
        self.max_methods = max_methods          # NEW: hard cap
        self.entry_points = entry_points or set()
        self.analyzer = MethodTaintAnalyzer(vm, vmx, call_graph)
        self.summaries = {}
        self._reachable = self._compute_reachable_methods()
        self._init_summaries()

    # ── reachability / priority ────────────────────────────────────────────

    def _is_entry_point(self, sig):
        """Return True if sig looks like an Android entry point."""
        for name in _ENTRY_POINT_NAMES:
            if f"->{name}" in sig:
                return True
        # User-supplied entry points
        return sig in self.entry_points

    def _compute_reachable_methods(self):
        """
        BFS from entry-point methods, capped at self.max_methods.
        Falls back to ALL methods if no entry points are found.
        """
        all_sigs = set(self.analyzer.method_map.keys())
        seeds = {s for s in all_sigs if self._is_entry_point(s)}
        if not seeds:
            # No entry points found — analyse everything up to cap
            seeds = all_sigs

        visited = set()
        queue = deque(seeds)
        while queue and len(visited) < self.max_methods:
            sig = queue.popleft()
            if sig in visited:
                continue
            visited.add(sig)
            for callee in self._get_callees(sig):
                if callee not in visited:
                    queue.append(callee)

        if len(visited) < len(all_sigs):
            print(
                f"[taint] Analysing {len(visited)}/{len(all_sigs)} methods "
                f"(capped at {self.max_methods}; start from entry points)"
            )
        return visited

    def _init_summaries(self):
        for sig in self._reachable:
            self.summaries[sig] = MethodSummary(sig)

    # ── call-graph helpers ─────────────────────────────────────────────────

    def _get_callers(self, sig):
        try:
            return list(self.call_graph.predecessors(sig))
        except Exception:
            try:
                return list(self.call_graph.get_callers_of(sig, default=[]))
            except Exception:
                return []

    def _get_callees(self, sig):
        try:
            return list(self.call_graph.successors(sig))
        except Exception:
            try:
                return list(self.call_graph.get_callees_of(sig, default=[]))
            except Exception:
                return []

    # ── main analysis loop ─────────────────────────────────────────────────

    def analyze(self):
        # Seed queue with reachable methods that have bytecode
        queue = deque(
            sig for sig in self._reachable
            if self.analyzer.method_map.get(sig) and
            self.analyzer.method_map[sig].get_code() is not None
        )

        visited = set()
        iteration = 0
        changed = True

        while changed and iteration < self.max_iterations:
            changed = False
            iteration += 1
            process_queue = deque(queue)
            queue = deque()

            while process_queue:
                sig = process_queue.popleft()
                if sig not in self.analyzer.method_map:
                    continue
                if sig in visited and iteration > 1:
                    s = self.summaries.get(sig)
                    if s and s.analyzed:
                        continue

                initial_taint = set()
                for csig in self._get_callers(sig):
                    cs = self.summaries.get(csig)
                    if cs and cs.params_taint_return:
                        initial_taint.add(0)

                summary = self.analyzer.analyze_method(sig, initial_taint)
                old = self.summaries.get(sig)

                if (old is None or
                        old.params_taint_return != summary.params_taint_return or
                        len(old.params_taint_sinks) != len(summary.params_taint_sinks)):
                    changed = True

                self.summaries[sig] = summary
                visited.add(sig)

                if summary.params_taint_return or summary.params_taint_sinks:
                    for callee in self._get_callees(sig):
                        if callee not in visited and callee in self._reachable:
                            queue.append(callee)

        findings = []
        for sig, summary in self.summaries.items():
            if not summary.analyzed:
                continue
            for sink in summary.params_taint_sinks:
                source_path = self._find_source_path(sig)
                findings.append({
                    "type": "taint_flow",
                    "sink_type": sink["type"],
                    "severity": sink["severity"],
                    "method": sig,
                    "sink_method": sink["callee"],
                    "sink_at_idx": sink["at_idx"],
                    "tainted_args": sink["tainted_args"],
                    "propagation_chain": source_path,
                    "sanitized": self._check_sanitized(sig, sink),
                    "description": (
                        f"Tainted data reaches {sink['type']} sink at {sink['callee']}"
                    ),
                })
        return findings

    # ── path / sanitization helpers ────────────────────────────────────────

    def _find_source_path(self, method_sig):
        path = [method_sig]
        visited = {method_sig}
        queue = deque([(method_sig, [method_sig])])
        while queue:
            sig, current_path = queue.popleft()
            for caller in self._get_callers(sig):
                if caller in visited:
                    continue
                visited.add(caller)
                new_path = [caller] + current_path
                s = self.summaries.get(caller)
                if s and s.is_source:
                    return new_path
                if len(new_path) > 10:
                    continue
                queue.append((caller, new_path))
        return path

    def _check_sanitized(self, method_sig, sink):
        s = self.summaries.get(method_sig)
        if s and s.sanitizes:
            return True
        for caller in self._get_callers(method_sig):
            cs = self.summaries.get(caller)
            if cs and cs.sanitizes:
                return True
        return False

    # ── summary / reporting ────────────────────────────────────────────────

    def get_summary(self):
        total = len(self.summaries)
        analyzed = sum(1 for s in self.summaries.values() if s.analyzed)
        with_sinks = sum(1 for s in self.summaries.values() if s.params_taint_sinks)
        with_return = sum(1 for s in self.summaries.values() if s.params_taint_return)
        sources = sum(1 for s in self.summaries.values() if s.is_source)
        sinks = sum(1 for s in self.summaries.values() if s.is_sink)
        return {
            "total_methods": total,
            "analyzed": analyzed,
            "propagate_taint": with_return,
            "have_sinks": with_sinks,
            "source_methods": sources,
            "sink_methods": sinks,
            "reachable_methods": len(self._reachable),
            "cap": self.max_methods,
        }

    def get_findings_by_type(self, findings):
        by_type = defaultdict(list)
        for f in findings:
            by_type[f["sink_type"]].append(f)
        return dict(by_type)

    def find_cross_file_flows(self, findings):
        cross_file = []
        sig_to_file = {}
        for cls in self.vm.get_classes():
            file_name = cls.source_file or cls.name.split("$")[0]
            for method in cls.get_methods():
                sig = f"{cls.name}->{method.name}{method.descriptor}"
                sig_to_file[sig] = file_name
        for f in findings:
            prop_chain = f.get("propagation_chain", [])
            if len(prop_chain) >= 2:
                files = {sig_to_file.get(sig, "unknown") for sig in prop_chain}
                if len(files) > 1:
                    cross_file.append({**f, "cross_file": True, "files_involved": list(files)})
        return cross_file

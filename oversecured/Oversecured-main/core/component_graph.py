"""
Android Component Graph — Attack Surface Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Nodes:
  - Activity (exported/internal)
  - Service (exported/internal)
  - BroadcastReceiver (exported/internal)
  - ContentProvider (exported/internal)
  - DeepLink (intent-filter with data URI)
  - Permission (custom permission)

Edges:
  - startActivity(Intent) → Activity
  - startService(Intent) → Service
  - sendBroadcast(Intent) → Receiver
  - query(Uri) → Provider
  - bindService(Intent) → Service
  - requires permission → Permission node

Attack Paths:
  - Exported Component → Internal Component → Privileged Component
  - Deep Link → WebView → RCE
  - Exported Provider → SQLi / Path Traversal
  - Exported Receiver → Service → Privileged API
"""

import re
from collections import defaultdict, deque
import logging
logger = logging.getLogger(__name__)

COMPONENT_TYPES = {"activity", "service", "receiver", "provider"}

INVOKE_SIGS = {
    "start_activity": [
        "Landroid/app/Activity;->startActivity",
        "Landroid/app/Activity;->startActivityForResult",
        "Landroid/content/Context;->startActivity",
        "Landroid/content/Context;->startActivities",
    ],
    "start_service": [
        "Landroid/content/Context;->startService",
        "Landroid/content/Context;->bindService",
        "Landroid/app/Service;->startService",
    ],
    "send_broadcast": [
        "Landroid/content/Context;->sendBroadcast",
        "Landroid/content/Context;->sendOrderedBroadcast",
        "Landroid/content/Context;->sendStickyBroadcast",
        "Landroid/app/Activity;->sendBroadcast",
    ],
    "query_provider": [
        "Landroid/content/ContentResolver;->query",
        "Landroid/content/ContentResolver;->insert",
        "Landroid/content/ContentResolver;->update",
        "Landroid/content/ContentResolver;->delete",
        "Landroid/content/ContentResolver;->openInputStream",
        "Landroid/content/ContentResolver;->openFileDescriptor",
    ],
}

SENSITIVE_COMPONENT_PATTERNS = [
    "admin", "administrator", "root", "superuser", "su",
    "settings", "config", "configuration",
    "debug", "dev", "test", "hidden", "internal",
    "backup", "restore", "reset", "wipe", "factory",
    "payment", "billing", "purchase", "checkout",
    "password", "pin", "auth", "login", "token",
    "webview", "browser", "chrome", "print",
    "install", "update", "download", "upload",
    "vpn", "device_admin", "admin_receiver",
]


class ComponentNode:
    def __init__(self, name, comp_type, exported=False, permission=None,
                 intent_filters=None, deep_links=None):
        self.name = name
        self.comp_type = comp_type
        self.exported = exported
        self.permission = permission
        self.intent_filters = intent_filters or []
        self.deep_links = deep_links or []
        self.metadata = {}

    def __repr__(self):
        export_str = "E" if self.exported else "I"
        return f"{export_str}:{self.comp_type}:{self.name.split('.')[-1]}"


class ComponentEdge:
    def __init__(self, source, target, edge_type, action=None,
                 permission=None, data_uri=None, method_sig=None):
        self.source = source
        self.target = target
        self.edge_type = edge_type
        self.action = action
        self.permission = permission
        self.data_uri = data_uri
        self.method_sig = method_sig

    def __repr__(self):
        return f"{self.source} --[{self.edge_type}]--> {self.target}"


class AndroidComponentGraph:
    def __init__(self, apk_obj, vm, vmx):
        self.apk = apk_obj
        self.vm = vm
        self.vmx = vmx
        self.nodes = {}
        self.edges = []
        self._build()

    def _build(self):
        self._extract_manifest_components()
        self._extract_intent_connections()
        self._build_call_graph_connections()
        self._link_deep_links()

    def _extract_manifest_components(self):
        try:
            manifest = self.apk.get_android_manifest_xml()
        except Exception:
            return

        root = manifest if hasattr(manifest, 'tag') else None
        if root is None:
            try:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(self.apk.get_android_manifest_xml().to_xml())
            except Exception:
                return

        app_node = None
        for child in (list(root) if hasattr(root, '__iter__') else []):
            try:
                if child.tag.endswith('application'):
                    app_node = child
                    break
            except Exception:
                continue

        if app_node is None:
            return

        for child in (list(app_node) if hasattr(app_node, '__iter__') else []):
            try:
                tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                name = child.get(
                    '{http://schemas.android.com/apk/res/android}name',
                    child.get('name', '')
                )
                if not name:
                    continue

                exported_str = child.get(
                    '{http://schemas.android.com/apk/res/android}exported',
                    child.get('exported', 'false')
                )
                exported = exported_str.lower() == 'true'

                permission = child.get(
                    '{http://schemas.android.com/apk/res/android}permission',
                    child.get('permission', None)
                )

                comp_type = None
                if tag == 'activity':
                    comp_type = 'activity'
                elif tag == 'service':
                    comp_type = 'service'
                elif tag == 'receiver':
                    comp_type = 'receiver'
                elif tag == 'provider':
                    comp_type = 'provider'
                    authority = child.get(
                        '{http://schemas.android.com/apk/res/android}authority',
                        child.get('authority', '')
                    )
                    if authority and not name:
                        name = authority

                if not comp_type:
                    continue

                intent_filters = []
                deep_links = []
                for intent_child in (list(child) if hasattr(child, '__iter__') else []):
                    try:
                        ictag = intent_child.tag.split('}')[-1] if '}' in intent_child.tag else intent_child.tag
                    except Exception:
                        continue

                    if ictag == 'intent-filter':
                        actions = []
                        data_schemes = []
                        data_hosts = []
                        data_paths = []

                        for filter_child in (list(intent_child) if hasattr(intent_child, '__iter__') else []):
                            try:
                                ftag = filter_child.tag.split('}')[-1] if '}' in filter_child.tag else filter_child.tag
                            except Exception:
                                continue

                            if ftag == 'action':
                                a = filter_child.get(
                                    '{http://schemas.android.com/apk/res/android}name',
                                    filter_child.get('name', '')
                                )
                                if a:
                                    actions.append(a)
                            elif ftag == 'data':
                                scheme = filter_child.get(
                                    '{http://schemas.android.com/apk/res/android}scheme',
                                    filter_child.get('scheme', '')
                                )
                                host = filter_child.get(
                                    '{http://schemas.android.com/apk/res/android}host',
                                    filter_child.get('host', '')
                                )
                                path = filter_child.get(
                                    '{http://schemas.android.com/apk/res/android}path',
                                    filter_child.get('path', '')
                                )
                                pathPattern = filter_child.get(
                                    '{http://schemas.android.com/apk/res/android}pathPattern',
                                    filter_child.get('pathPattern', '')
                                )
                                if scheme:
                                    data_schemes.append(scheme)
                                if host:
                                    data_hosts.append(host)
                                if path or pathPattern:
                                    data_paths.append(path or pathPattern)

                        intent_filter = {
                            "actions": actions,
                            "schemes": data_schemes,
                            "hosts": data_hosts,
                            "paths": data_paths,
                        }
                        intent_filters.append(intent_filter)

                        for scheme in data_schemes:
                            for host in (data_hosts or ["*"]):
                                for path in (data_paths or ["/*"]):
                                    uri = f"{scheme}://{host}{path}"
                                    deep_links.append({
                                        "uri": uri,
                                        "action": actions[0] if actions else "android.intent.action.VIEW",
                                    })

                node = ComponentNode(
                    name=name,
                    comp_type=comp_type,
                    exported=exported,
                    permission=permission,
                    intent_filters=intent_filters,
                    deep_links=deep_links,
                )

                node_id = f"{comp_type}:{name}"
                self.nodes[node_id] = node

            except Exception:
                continue

    def _extract_intent_connections(self):
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

                for ins in instructions:
                    try:
                        name = ins.get_name()
                        if not name or not name.startswith("invoke"):
                            continue
                        output = ins.get_output()
                        if not output:
                            continue
                        parts = [p.strip() for p in output.replace(",", " ").split()]
                        invoke_sig = parts[-1] if parts else ""
                    except Exception:
                        continue

                    edge_type = None
                    for etype, sigs in INVOKE_SIGS.items():
                        for sig in sigs:
                            if invoke_sig.startswith(sig) or sig in invoke_sig:
                                edge_type = etype
                                break
                        if edge_type:
                            break

                    if edge_type is None:
                        continue

                    self._add_invoke_edge(method_sig, edge_type, cls.name, ins)

    def _add_invoke_edge(self, source_sig, edge_type, source_cls, ins):
        try:
            output = ins.get_output()
            parts = [p.strip() for p in output.replace(",", " ").split()]
            invoke_sig = parts[-1] if parts else ""

            possible_targets = []
            for node_id, node in self.nodes.items():
                if node.comp_type == "activity" and edge_type in ("start_activity",):
                    possible_targets.append(node_id)
                elif node.comp_type == "service" and edge_type in ("start_service",):
                    possible_targets.append(node_id)
                elif node.comp_type == "receiver" and edge_type in ("send_broadcast",):
                    possible_targets.append(node_id)
                elif node.comp_type == "provider" and edge_type in ("query_provider",):
                    possible_targets.append(node_id)

            for target_id in possible_targets:
                edge = ComponentEdge(
                    source=source_sig,
                    target=target_id,
                    edge_type=edge_type,
                    method_sig=invoke_sig,
                )
                if edge not in self.edges:
                    self.edges.append(edge)

        except Exception:
            logger.debug("Silent exception caught", exc_info=True)

    def _build_call_graph_connections(self):
        try:
            analysis = self.vmx
            cg = analysis.get_call_graph()
        except Exception:
            return

        try:
            if hasattr(cg, 'edges'):
                edges_iter = [(src, dst) for src, dst in cg.edges()]
            else:
                edges_iter = [(src, dst) for src, dst_list in cg.items() for dst in (dst_list if isinstance(dst_list, list) else [dst_list])]
        except Exception:
            return

        for source_sig, callee_sig in edges_iter:
            src_str = str(source_sig)
            dst_str = str(callee_sig)
            for node_id, node in self.nodes.items():
                comp_name = node.name.replace(".", "/")
                if comp_name in dst_str or comp_name in src_str:
                    cls_invoke = any(
                        invoke_sig in dst_str
                        for invokes in INVOKE_SIGS.values()
                        for invoke_sig in invokes
                    )
                    if cls_invoke:
                        edge_type = "internal"
                        for etype, sigs in INVOKE_SIGS.items():
                            for sig in sigs:
                                if sig in dst_str:
                                    edge_type = etype
                                    break
                        edge = ComponentEdge(
                                source=src_str,
                                target=node_id,
                                edge_type=edge_type,
                                method_sig=dst_str,
                            )
                        if edge not in self.edges:
                            self.edges.append(edge)
        for node_id, node in self.nodes.items():
            if node.permission:
                perm_node_id = f"permission:{node.permission}"
                if perm_node_id not in self.nodes:
                    perm_node = ComponentNode(
                        name=node.permission,
                        comp_type="permission",
                        exported=True,
                    )
                    self.nodes[perm_node_id] = perm_node

                edge = ComponentEdge(
                    source=node_id,
                    target=perm_node_id,
                    edge_type="requires_permission",
                    permission=node.permission,
                )
                if edge not in self.edges:
                    self.edges.append(edge)

    def _link_deep_links(self):
        for node_id, node in self.nodes.items():
            for dl in node.deep_links:
                uri = dl["uri"]
                action = dl["action"]
                dl_node_id = f"deeplink:{uri}"
                if dl_node_id not in self.nodes:
                    dl_node = ComponentNode(
                        name=uri,
                        comp_type="deeplink",
                        exported=True,
                        intent_filters=[{"actions": [action], "data": [uri]}],
                        deep_links=[uri],
                    )
                    self.nodes[dl_node_id] = dl_node

                edge = ComponentEdge(
                    source=dl_node_id,
                    target=node_id,
                    edge_type="deep_link_target",
                    action=action,
                    data_uri=uri,
                )
                if edge not in self.edges:
                    self.edges.append(edge)

    def find_attack_paths(self, max_depth=5):
        exported_nodes = []
        for nid, node in self.nodes.items():
            if node.exported:
                exported_nodes.append(nid)

        sensitive_pattern = re.compile(
            "|".join(SENSITIVE_COMPONENT_PATTERNS), re.IGNORECASE
        )

        sensitive_nodes = []
        for nid, node in self.nodes.items():
            if sensitive_pattern.search(node.name):
                sensitive_nodes.append(nid)

        self.attack_paths = []
        for start in exported_nodes:
            for end in sensitive_nodes:
                if start == end:
                    continue
                paths = self._bfs_shortest_paths(start, end, max_depth)
                for path in paths:
                    path_info = self._describe_path(path)
                    self.attack_paths.append(path_info)
        return self.attack_paths

    def _bfs_shortest_paths(self, start, end, max_depth=5):
        queue = deque([(start, [start])])
        visited = {start}
        found_paths = []

        while queue:
            node, path = queue.popleft()
            if len(path) > max_depth:
                continue
            if node == end:
                found_paths.append(path)
                continue

            for edge in self.edges:
                if not hasattr(edge, 'source') or not hasattr(edge, 'target'):
                    continue
                src = edge.source if isinstance(edge.source, str) else None
                tgt = edge.target if isinstance(edge.target, str) else None
                if not src or not tgt:
                    continue

                if src == node and tgt not in visited:
                    visited.add(tgt)
                    queue.append((tgt, path + [tgt]))

        return found_paths[:5]

    def _describe_path(self, path):
        steps = []
        for i in range(len(path) - 1):
            src = path[i]
            tgt = path[i + 1]
            matching_edges = [e for e in self.edges
                              if e.source == src and e.target == tgt]
            edge_info = matching_edges[0] if matching_edges else None
            edge_type = edge_info.edge_type if edge_info else "unknown"
            src_node = self.nodes.get(src)
            tgt_node = self.nodes.get(tgt)
            steps.append({
                "from": src,
                "from_type": src_node.comp_type if src_node else "unknown",
                "from_exported": src_node.exported if src_node else False,
                "to": tgt,
                "to_type": tgt_node.comp_type if tgt_node else "unknown",
                "to_exported": tgt_node.exported if tgt_node else False,
                "edge_type": edge_type,
                "action": edge_info.action if edge_info else None,
                "permission": edge_info.permission if edge_info else None,
                "data_uri": edge_info.data_uri if edge_info else None,
            })
        return {
            "path_length": len(path),
            "source": path[0],
            "target": path[-1],
            "steps": steps,
            "risk": self._assess_path_risk(steps),
        }

    def _assess_path_risk(self, steps):
        risk_score = 0
        reasons = []
        for step in steps:
            if step["from_exported"] and not step["to_exported"]:
                risk_score += 3
                reasons.append(f"Exported {step['from_type']} → Internal {step['to_type']}")
            if "admin" in step["to"].lower() or "privilege" in step["to"].lower():
                risk_score += 2
                reasons.append(f"Privileged target: {step['to']}")
            if "webview" in step["to"].lower():
                risk_score += 2
                reasons.append("WebView component reachable")
            if "provider" in step["to_type"]:
                risk_score += 1
                reasons.append("Provider reachable (SQLi/traversal risk)")

        if risk_score >= 5:
            severity = "CRITICAL"
        elif risk_score >= 3:
            severity = "HIGH"
        elif risk_score >= 1:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {"score": risk_score, "severity": severity, "reasons": reasons}

    def get_summary(self):
        comps = defaultdict(int)
        exported = 0
        for node in self.nodes.values():
            comps[node.comp_type] += 1
            if node.exported:
                exported += 1

        deeplinks = sum(1 for n in self.nodes.values() if n.comp_type == "deeplink")
        attack_paths = len(getattr(self, 'attack_paths', []))

        edge_types = defaultdict(int)
        for edge in self.edges:
            edge_types[edge.edge_type] += 1

        return {
            "total_components": len(self.nodes),
            "by_type": dict(comps),
            "exported": exported,
            "deep_links": deeplinks,
            "total_edges": len(self.edges),
            "by_edge_type": dict(edge_types),
            "attack_paths_found": attack_paths,
        }

    def get_findings(self):
        findings = []

        for node_id, node in self.nodes.items():
            if node.comp_type in COMPONENT_TYPES and node.exported:
                if not node.permission:
                    findings.append({
                        "id": f"CG-001",
                        "name": f"Unprotected Exported {node.comp_type.title()}",
                        "severity": "HIGH",
                        "category": "component_graph",
                        "component_name": node.name,
                        "component_type": node.comp_type,
                        "description": f"{node.comp_type.title()} {node.name} is exported without permission",
                        "recommendation": "Add android:permission or set android:exported=false",
                    })

        for node_id, node in self.nodes.items():
            if node.deep_links:
                for dl in node.deep_links:
                    findings.append({
                        "id": f"CG-002",
                        "name": f"Deep Link: {dl['uri']}",
                        "severity": "MEDIUM",
                        "category": "component_graph",
                        "component_name": node.name,
                        "deep_link": dl['uri'],
                        "description": f"Deep link {dl['uri']} registered on {node.comp_type} {node.name}",
                        "recommendation": "Validate all deep link inputs",
                    })

        attack_paths = getattr(self, 'attack_paths', [])
        for path in attack_paths:
            risk = path.get("risk", {})
            if risk.get("score", 0) >= 3:
                step_desc = " → ".join(
                    f"{s['from_type']}:{s['to'].split(':')[-1] if ':' in s['to'] else s['to']}"
                    for s in path.get("steps", [])
                )
                findings.append({
                    "id": f"CG-003",
                    "name": f"Attack Path: {step_desc}",
                    "severity": risk.get("severity", "MEDIUM"),
                    "category": "component_graph",
                    "path": path,
                    "description": f"Attack path from {path['source']} to {path['target']}: {', '.join(risk.get('reasons', []))}",
                    "recommendation": "Review component permissions and reduce attack surface",
                })

        return findings

    def to_mermaid(self, max_attack_paths=5):
        lines = ["```mermaid", "flowchart LR"]
        node_ids = {}
        counter = [0]
        def _id(label):
            n = counter[0]
            counter[0] += 1
            node_ids[label] = f"N{n}"
            return f"N{n}"

        for nid, node in self.nodes.items():
            label = node.name.split(".")[-1] if "." in node.name else node.name
            style = "exported" if node.exported else "internal"
            shape = "([\"   " if node.exported else "[\"   "
            lines.append(f"    {_id(nid)}{shape}{label} ({node.comp_type[:3]})")
            dl_hint = ""
            if node.deep_links:
                for dl in node.deep_links:
                    dl_hint = dl['uri'][:30]
                    break
            if dl_hint:
                lines.append(f"    {_id(nid + '_dl')}[[\"{dl_hint}\"]]")
                lines.append(f"    {node_ids[nid]} --> {node_ids[nid + '_dl']}")

        edge_count = 0
        for (f, t), edges in self.edges.items():
            if edge_count >= 20:
                break
            if f in node_ids and t in node_ids:
                for etype in edges:
                    label = etype.replace("_", " ").title()
                    lines.append(f"    {node_ids[f]} -->|\"{label}\"| {node_ids[t]}")
                    edge_count += 1
                    break

        attack_paths = getattr(self, 'attack_paths', [])
        for i, path in enumerate(attack_paths[:max_attack_paths]):
            risk = path.get("risk", {})
            steps = path.get("steps", [])
            sev = risk.get("severity", "MEDIUM")
            color = {"CRITICAL": "#ff0000", "HIGH": "#ff6600", "MEDIUM": "#ffaa00", "LOW": "#88cc00"}.get(sev, "#fff")
            style_cls = f"fill:{color},color:#fff"
            prev_nid = None
            for step in steps:
                sid = step.get("to", step.get("from", ""))
                label = sid.split(":")[-1] if ":" in sid else sid
                nid = f"ap_{i}_{label}"
                lines.append(f"    {_id(nid)}[\"{label}\"]")
                lines.append(f"    style {node_ids[nid]} {style_cls}")
                if prev_nid:
                    lines.append(f"    {prev_nid} -.->|attack| {node_ids[nid]}")
                prev_nid = node_ids[nid]

        lines.append("```")
        return "\n".join(lines)
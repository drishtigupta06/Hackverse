import logging
logger = logging.getLogger(__name__)


def detect_ipa_binder_bypass(sa):
    findings = []
    for hit in sa.ipa_findings.get("binder_bypass", []):
        findings.append({
            "id": "IPA-BINDER-001",
            "name": "Binder Transaction Without Permission Check",
            "description": f"Binder transaction via {hit.get('sink','?')} in {hit.get('method','?')} lacks getCallingUid/getCallingPid. Any client can invoke this service method without identity verification.",
            "severity": "CRITICAL",
            "location": f"{hit.get('method','?')} @ instr:{hit.get('instruction','?')}",
            "recommendation": "Always call getCallingUid() and enforce permissions at the beginning of Binder/onTransact methods.",
        })
    for bf in sa.binder_flow:
        findings.append({
            "id": "IPA-BINDER-002",
            "name": "IBinder.transact Without Identity Check",
            "description": f"IBinder.transact in {bf.get('method','?')} does not check caller identity. {bf.get('detail','')}",
            "severity": "CRITICAL",
            "location": f"{bf.get('method','?')} @ instr:{bf.get('instruction','?')}",
            "recommendation": "Verify getCallingUid/getCallingPid before processing Binder transactions.",
        })
    for bp in sa.binder_perm_bypass:
        findings.append({
            "id": "IPA-BINDER-003",
            "name": "Binder Service Missing Permission Enforcement",
            "description": f"Binder service method {bp.get('method','?')} does not enforce any permission check (enforceCallingPermission/checkCallingPermission/getCallingUid).",
            "severity": "CRITICAL",
            "location": bp.get('method','?'),
            "recommendation": "Implement enforceCallingPermission() or checkCallingPermission() in all binder service entry points.",
        })
    if findings:
        sa.findings.append({"category": "19. Binder / System Service Abuse (IPA)", "rules": findings})


def detect_ipa_system_service_abuse(sa):
    findings = []
    for hit in sa.ipa_findings.get("system_service_abuse", []):
        findings.append({
            "id": "IPA-SVC-001",
            "name": "System Service Accessed Without Permission Context",
            "description": f"System service {hit.get('sink','?')} accessed in {hit.get('method','?')}. Verify that the caller has appropriate permissions.",
            "severity": "HIGH",
            "location": f"{hit.get('method','?')} @ instr:{hit.get('instruction','?')}",
            "recommendation": "Check that the calling package has the required system-level permissions before accessing system services.",
        })
    if findings:
        sa.findings.append({"category": "19. System Service Abuse (IPA)", "rules": findings})


def detect_ipa_settings_abuse(sa):
    findings = []
    for hit in sa.ipa_findings.get("settings_provider_abuse", []):
        is_write = "put" in hit.get("sink","")
        findings.append({
            "id": "IPA-SETT-001" if is_write else "IPA-SETT-002",
            "name": f"Settings Provider {'Write' if is_write else 'Read'} Detected",
            "description": f"Settings provider operation {hit.get('sink','?')} in {hit.get('method','?')}. {'WRITE_SECURE_SETTINGS permission may be required.' if is_write else 'Sensitive system settings are being read.'}",
            "severity": hit.get("severity", "MEDIUM"),
            "location": f"{hit.get('method','?')} @ instr:{hit.get('instruction','?')}",
            "recommendation": "Avoid writing to Settings.Secure/System/Global. Use scoped APIs instead of direct settings provider access.",
        })
    if findings:
        sa.findings.append({"category": "19. Settings Provider Abuse (IPA)", "rules": findings})


def detect_ipa_vendor_service_abuse(sa):
    findings = []
    for hit in sa.ipa_findings.get("vendor_service_abuse", []):
        findings.append({
            "id": "IPA-VENDOR-001",
            "name": "Vendor/OEM Service Accessed",
            "description": f"Vendor-specific service {hit.get('sink','?')} accessed in {hit.get('method','?')}. Vendor services may have undocumented behavior or security implications.",
            "severity": "MEDIUM",
            "location": f"{hit.get('method','?')} @ instr:{hit.get('instruction','?')}",
            "recommendation": "Audit all vendor/OEM service interactions. These services may behave differently across devices and OEMs.",
        })
    if findings:
        sa.findings.append({"category": "19. Vendor/OEM Service Abuse (IPA)", "rules": findings})


def detect_ipa_privileged_intent(sa):
    findings = []
    for hit in sa.ipa_findings.get("privileged_intent_abuse", []):
        findings.append({
            "id": "IPA-PRIV-001",
            "name": "Privileged System Intent Action Used",
            "description": f"Privileged action {hit.get('sink','?')} in {hit.get('method','?')}. {hit.get('detail','')}",
            "severity": hit.get("severity", "HIGH"),
            "location": f"{hit.get('method','?')} @ instr:{hit.get('instruction','?')}",
            "recommendation": "Ensure the app holds the required system-level permissions before sending privileged intents. Use signature-level permissions to protect receivers.",
        })
    if findings:
        sa.findings.append({"category": "19. Privileged Intent Abuse (IPA)", "rules": findings})


def detect_ipa_broadcast_service_chain(sa):
    findings = []
    for hit in sa.ipa_findings.get("broadcast_to_service", []):
        findings.append({
            "id": "IPA-CHAIN-001",
            "name": "Broadcast Receiver Starts Service",
            "description": f"A broadcast receiver in {hit.get('method','?')} starts a service via {hit.get('sink','?')}. This creates a broadcast→service chain that may bypass background execution limits.",
            "severity": "HIGH",
            "location": f"{hit.get('method','?')} @ instr:{hit.get('instruction','?')}",
            "recommendation": "Prefer JobScheduler or WorkManager over starting services from broadcast receivers. On Android 8+, background start restrictions apply.",
        })
    if findings:
        sa.findings.append({"category": "19. Broadcast → Service Chains (IPA)", "rules": findings})


def detect_ipa_lifecycle_flow(sa):
    findings = []
    seen = set()
    for lf in sa.lifecycle_flows:
        key = (lf.get("from",""), lf.get("to",""))
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "id": "IPA-LIFE-001",
            "name": "Inter-Lifecycle Data Flow",
            "description": f"Data flows from {lf.get('from','?')} to {lf.get('to','?')} within {lf.get('classes',['?'])[0]}. Lifecycle transitions may expose intermediate state to other apps.",
            "severity": "MEDIUM",
            "location": f"{lf.get('classes',['?'])[0]} lifecycle: {lf.get('from','?')} → {lf.get('to','?')}",
            "recommendation": "Ensure sensitive state is cleared in onPause/onStop before transitioning to background. Use onSaveInstanceState for critical state.",
        })
    if findings:
        sa.findings.append({"category": "19. Lifecycle Flow Issues (IPA)", "rules": findings})


def detect_ipa_cross_class_flow(sa):
    findings = []
    seen = set()
    for cf in sa.cross_class_flows:
        key = (cf.get("from_class",""), cf.get("to_class",""))
        if key in seen:
            continue
        seen.add(key)
        edges_sample = cf.get("edges", [])
        findings.append({
            "id": "IPA-CROSS-001",
            "name": "Cross-Class Data Flow",
            "description": f"Data flows from {cf.get('from_class','?')} to {cf.get('to_class','?')} ({len(edges_sample)} edge(s)). Taint may propagate across class boundaries without validation.",
            "severity": "HIGH",
            "location": f"{cf.get('from_class','?')} → {cf.get('to_class','?')} via {', '.join([f'{s}→{t}' for s,t in edges_sample])}",
            "recommendation": "Validate data at each class boundary. Ensure that data crossing component boundaries is sanitized.",
        })
    for caf in sa.cross_activity_flows:
        findings.append({
            "id": "IPA-CROSS-002",
            "name": "Cross-Activity Intent Data Flow",
            "description": f"Data flows from {caf.get('sender','?')} (putExtra) to {caf.get('receiver','?')} (getExtra). This creates an inter-activity data channel for tainted data.",
            "severity": "HIGH",
            "location": f"{caf.get('sender','?')} → {caf.get('receiver','?')}",
            "recommendation": "Use explicit intents with setPackage() for cross-activity communication. Validate all extras at the receiving end.",
        })
    if findings:
        sa.findings.append({"category": "19. Cross-Class / Cross-Activity Flows (IPA)", "rules": findings})


def detect_ipa_callback_flow(sa):
    findings = []
    seen = set()
    for cb in sa.callback_flows:
        ct = cb.get("callback_type","")
        if ct in seen:
            continue
        seen.add(ct)
        findings.append({
            "id": "IPA-CALLBACK-001",
            "name": f"Callback Flow via {ct.split('.')[-1] if '.' in ct else ct}",
            "description": f"A callback of type '{ct}' is registered in {cb.get('method','?')}. Data may flow asynchronously through the callback, making taint paths harder to track.",
            "severity": "MEDIUM",
            "location": f"{cb.get('method','?')} type:{ct}",
            "recommendation": "Ensure callbacks do not propagate tainted data to security-sensitive sinks. Review callback chains for race conditions.",
        })
    for cof in sa.concurrent_flows:
        findings.append({
            "id": "IPA-CONCUR-001",
            "name": f"Async/Concurrent Operation via {cof.get('sink','?').split(';->')[-1] if ';->' in cof.get('sink','') else cof.get('sink','?')}",
            "description": f"Concurrent/async operation in {cof.get('method','?')} via {cof.get('sink','?')}. Asynchronous execution can lead to TOCTOU vulnerabilities and makes data flow analysis incomplete.",
            "severity": "MEDIUM",
            "location": f"{cof.get('method','?')} sink:{cof.get('sink','?')}",
            "recommendation": "Synchronize access to shared mutable state. Avoid passing tainted data across thread boundaries without validation.",
        })
    for hf in sa.handler_flows:
        findings.append({
            "id": "IPA-HANDLER-001",
            "name": "Handler Message Flow (Looper-based IPC)",
            "description": f"Handler messages are sent in {hf.get('sender','?')}. Receivers: {', '.join(hf.get('receivers',['?']))}. Messages may carry tainted data across threads.",
            "severity": "MEDIUM",
            "location": f"sender:{hf.get('sender','?')}",
            "recommendation": "Validate all Handler messages at the receiving end. Use Handler.Callback with strict message.what filtering.",
        })
    if findings:
        sa.findings.append({"category": "19. Callback / Concurrent Flows (IPA)", "rules": findings})


def detect_ipa_multi_hop_taint(sa):
    findings = []
    for sink_type, sinks in sa.multi_hop_findings.items():
        for s in sinks[:3]:
            path = s.get("path", [])
            depth = s.get("depth", 0)
            if depth < 2:
                continue
            findings.append({
                "id": "IPA-MHOP-001",
                "name": f"Multi-Hop Taint Chain ({sink_type})",
                "description": f"Taint propagates through {depth} hop(s): {' → '.join(path[:4])}{'...' if len(path) > 4 else ''}. Deep taint chains indicate complex data flow that may bypass single-method detectors.",
                "severity": "HIGH",
                "location": f"{depth}-hop chain ending at {path[-1] if path else '?'}",
                "recommendation": "Trace the full data flow path. Validate and sanitize data at each hop. Consider whether intermediate methods are properly validating inputs.",
            })
    if findings:
        sa.findings.append({"category": "19. Multi-Hop Taint Propagation (IPA)", "rules": findings})

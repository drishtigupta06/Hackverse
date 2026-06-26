import logging
logger = logging.getLogger(__name__)


def detect_privilege_escalation(sa):
    findings = []
    for comp_type in ["activities","services","receivers","providers"]:
        for comp in sa.manifest_components.get(comp_type, []):
            if comp["exported"] in ("true", None, ""):
                findings.append({"id":"ADV-PRIV-001","name":"Privilege Escalation via Exported Component",
                    "description":f"Exported {comp_type[:-2]} '{comp['name']}' allows any app to invoke it without permission, enabling privilege escalation.",
                    "severity":"HIGH","location":f"AndroidManifest: {comp['name']}",
                    "recommendation":"Restrict exported components with signature-level permissions. Never expose dangerous functionality without authorization."})
                break
    caller_checks = sa._find_methods_by_invoke("Landroid/app/Activity;->getCallingPackage")
    if caller_checks:
        for dm in caller_checks[:3]:
            findings.append({"id":"ADV-PRIV-002","name":"Caller Verification Present - Review",
                "description":"getCallingPackage() is used. Verify that the calling package is validated against an allowlist.",
                "severity":"INFO","location":dm,
                "recommendation":"Always validate getCallingPackage() against a known allowlist of package names."})
    if findings:
        sa.findings.append({"category":"2. Privilege Escalation","rules":findings})


def detect_confused_deputy(sa):
    findings = []
    cb = sa._find_methods_by_invoke("Landroid/content/Context;->sendBroadcast")
    start = sa._find_methods_by_invoke("Landroid/content/Context;->startActivity")
    if cb:
        for dm in cb[:3]:
            findings.append({"id":"ADV-CDEP-001","name":"Confused Deputy - Broadcast Sent Without Package Restriction",
                "description":"An unprotected broadcast is sent which can be received by any app. A malicious receiver can trigger the sending app to perform privileged operations.",
                "severity":"HIGH","location":dm,
                "recommendation":"Use setPackage() on outgoing broadcasts to restrict delivery. Require permissions for sensitive broadcast receivers."})
    if findings:
        sa.findings.append({"category":"2. Confused Deputy","rules":findings})


def detect_permission_redelegation(sa):
    findings = []
    grant_uri = sa._find_methods_by_invoke("Landroid/content/Context;->grantUriPermission")
    if grant_uri:
        for dm in grant_uri[:3]:
            findings.append({"id":"ADV-REDEL-001","name":"Permission Re-delegation - URI Permissions Granted",
                "description":"URI permissions are granted to other apps, potentially re-delegating permissions beyond what was intended.",
                "severity":"HIGH","location":dm,
                "recommendation":"Revoke URI permissions when no longer needed. Use FLAG_GRANT_READ_URI_PERMISSION carefully and scope grants."})
    if findings:
        sa.findings.append({"category":"2. Permission Re-delegation","rules":findings})


def detect_missing_permission_checks(sa):
    findings = []
    enforce = sa._find_methods_by_invoke("Landroid/app/Activity;->enforceCallingPermission")
    check_perm = sa._find_methods_by_invoke("Landroid/content/Context;->checkCallingPermission")
    if not enforce and not check_perm:
        exported = [c for comp_type in ["activities","services","receivers","providers"]
                    for c in sa.manifest_components.get(comp_type, []) if c["exported"] in ("true", None, "")]
        if exported:
            findings.append({"id":"ADV-MISS-001","name":"Missing Permission Checks in Exported Components",
                "description":"Exported components exist but enforceCallingPermission() or checkCallingPermission() is not used. Callers are not verified.",
                "severity":"HIGH","location":"bytecode analysis",
                "recommendation":"Use enforceCallingPermission() or checkCallingPermission() at the beginning of all exported component entry points."})
    if findings:
        sa.findings.append({"category":"2. Missing Permission Checks","rules":findings})


def detect_broadcast_abuse(sa):
    findings = []
    send = sa._find_methods_by_invoke("Landroid/content/Context;->sendBroadcast")
    send_sticky = sa._find_methods_by_invoke("Landroid/content/Context;->sendStickyBroadcast")
    reg = sa._find_methods_by_invoke("Landroid/content/Context;->registerReceiver")

    if send:
        for dm in send[:5]:
            findings.append({"id":"ADV-008","name":"Broadcast Sent Without Package Restriction",
                "description":"sendBroadcast() is called. If the broadcast is implicit (no specific package), any app can receive it.",
                "severity":"MEDIUM","location":dm,
                "recommendation":"Use setPackage() on outgoing broadcasts or require a permission via sendBroadcast(intent, permission)."})

    if send_sticky:
        for dm in send_sticky[:3]:
            findings.append({"id":"ADV-009","name":"Sticky Broadcast Used (Deprecated)",
                "description":"sendStickyBroadcast() persists the broadcast Intent for later reading by any app.",
                "severity":"HIGH","location":dm,
                "recommendation":"Replace with sendBroadcast() and use LocalBroadcastManager for internal communication."})

    if reg:
        for dm in reg[:5]:
            findings.append({"id":"ADV-010","name":"Dynamic BroadcastReceiver Without Permission",
                "description":"registerReceiver() is called without specifying a broadcast permission, allowing any app to send to it.",
                "severity":"MEDIUM","location":dm,
                "recommendation":"Pass a permission string to registerReceiver() to restrict which apps can send broadcasts."})

    if findings:
        sa.findings.append({"category":"14. Broadcast Vulnerabilities","rules":findings})


def detect_notification_security(sa):
    findings = []
    taint_notif = sa.taint_findings.get("notification", [])
    for f in taint_notif[:5]:
        findings.append({"id":"ADV-NOTIF-001","name":"Tainted Data in Notification Content",
            "description":f"Tainted data appears in a notification sink ({f.get('sink','?')}). Sensitive data in notifications may be visible on the lock screen or captured by notification listeners.",
            "severity":"HIGH","location":f.get("location","unknown"),
            "recommendation":"Set setVisibility(VISIBILITY_PRIVATE) on notification channels with sensitive content. Redact personal data from notifications."})
    fs_intent = sa._find_methods_by_invoke("Landroid/app/Notification$Builder;->setFullScreenIntent")
    if fs_intent and not findings:
        for dm in fs_intent[:3]:
            findings.append({"id":"ADV-NOTIF-002","name":"Full-Screen Intent Notification Without User Control",
                "description":"Full-screen intents can be abused for UI spoofing and clickjacking.",
                "severity":"HIGH","location":dm,
                "recommendation":"Use fullScreenIntent sparingly. On Android 14+, users must grant permission for full-screen notifications."})
    if findings:
        sa.findings.append({"category":"13. Notification Vulnerabilities","rules":findings})


def detect_exported_preference_activities(sa):
    findings = []
    pref = sa._find_methods_by_invoke("Landroid/preference/PreferenceActivity")
    if pref:
        findings.append({"id":"ADV-018","name":"Exported PreferenceActivity (Fragment Injection)",
            "description":"PreferenceActivity is a known fragment injection vector.",
            "severity":"HIGH","location":"bytecode analysis",
            "recommendation":"Ensure PreferenceActivity is not exported. Override isValidFragment() to whitelist fragments."})
    if findings:
        sa.findings.append({"category":"Exported Preference Activities","rules":findings})


def detect_get_calling_package_null_bypass(sa):
    findings = []
    calling_pkg = sa._find_methods_by_invoke(
        "Landroid/app/Activity;->getCallingPackage"
    )
    if calling_pkg:
        direct_launch = sa._find_methods_by_invoke(
            "Landroid/app/Activity;->startActivity"
        )
        for_result = sa._find_methods_by_invoke(
            "Landroid/app/Activity;->startActivityForResult"
        )
        if direct_launch and not for_result:
            for dm in calling_pkg[:3]:
                findings.append({
                    "id": "ADV-PERM-050",
                    "name": "getCallingPackage() Returns Null for startActivity() — Permission Bypass via Caller Identity Check",
                    "description": f"getCallingPackage() is used in {dm} but the component can be launched via startActivity() (not startActivityForResult). getCallingPackage() returns null for startActivity() calls, null for direct launcher starts, and null for system-originated intents. Any security check based on getCallingPackage() is completely bypassed when the caller uses startActivity() — the null value may pass contains() checks, equals() checks against null, or null-safety checks with unintended results. This was a real vulnerability in Google Pixel's Camera app: an app could request location access via startActivity() causing getCallingPackage() to return null, bypassing the permission check entirely.",
                    "severity": "CRITICAL",
                    "location": dm,
                    "recommendation": "Never rely on getCallingPackage() for security decisions. Use startActivityForResult() + getCallingPackage() or pass the caller identity as an Intent extra. Validate extras against an allowlist instead of relying on getCallingPackage()."
                })
        null_check_bypass = sa._find_methods_by_regex(
            r'getCallingPackage\(\)\s*!=\s*null|getCallingPackage\(\)\s*==\s*null|getCallingPackage\s*!=\s*null'
        )
        if null_check_bypass:
            for dm in null_check_bypass[:3]:
                findings.append({
                    "id": "ADV-PERM-051",
                    "name": "getCallingPackage() Null Check — Incomplete Security Boundary",
                    "description": f"getCallingPackage() null check found in {dm}. Checking getCallingPackage() != null is insufficient: null means 'I don't know' not 'safe'. Both startActivity() and direct launcher starts return null, while startActivityForResult() returns the caller's package. An attacker can choose startActivity() specifically to make getCallingPackage() return null and bypass caller verification.",
                    "severity": "HIGH",
                    "location": dm,
                    "recommendation": "Replace null checks with explicit allowlist validation. Always use startActivityForResult() when the target needs to identify the caller. For security-critical operations, require a permission rather than relying on caller identity."
                })
    if findings:
        sa.findings.append({"category": "37. getCallingPackage() Null Bypass — Caller Identity Verification Gaps", "rules": findings})


def detect_broadcast_notification_advanced(sa):
    findings = []
    local_bc = sa._find_methods_by_invoke("Landroidx/localbroadcastmanager/LocalBroadcastManager")
    if not local_bc:
        send = sa._find_methods_by_invoke("Landroid/content/Context;->sendBroadcast")
        if send:
            findings.append({"id":"ADV-BRNOT-001","name":"Global Broadcast Sent Without LocalBroadcastManager — Internal Broadcast Leakage",
                "description":"sendBroadcast() is used without LocalBroadcastManager. Internal broadcasts can be intercepted by any app on the device.",
                "severity":"HIGH","location":"bytecode analysis",
                "recommendation":"Use LocalBroadcastManager for app-internal broadcasts. For global broadcasts, use setPackage() to restrict delivery."})
    ordered = sa._find_methods_by_invoke("Landroid/content/Context;->sendOrderedBroadcast")
    if ordered:
        for dm in ordered[:3]:
            findings.append({"id":"ADV-BRNOT-002","name":"sendOrderedBroadcast() Used — Result Interception Risk",
                "description":f"sendOrderedBroadcast() in {dm} delivers broadcasts sequentially. A malicious receiver with higher priority can intercept, modify, or abort the broadcast.",
                "severity":"HIGH","location":dm,
                "recommendation":"Avoid ordered broadcasts for sensitive data. Use setPackage() and require permissions on ordered broadcasts."})
    abort = sa._find_methods_by_invoke("Landroid/content/BroadcastReceiver;->abortBroadcast")
    if abort:
        for dm in abort[:3]:
            findings.append({"id":"ADV-BRNOT-003","name":"abortBroadcast() Called — Broadcast Sink/DoS Risk",
                "description":f"abortBroadcast() in {dm} prevents the broadcast from reaching other receivers. Malicious receivers can block system broadcasts.",
                "severity":"MEDIUM","location":dm,
                "recommendation":"Audit abortBroadcast() usage. Never abort broadcasts based on untrusted data."})
    notif_listener = sa._find_methods_by_invoke("Landroid/service/notification/NotificationListenerService")
    if notif_listener:
        findings.append({"id":"ADV-BRNOT-004","name":"NotificationListenerService — Notification Access Service",
            "description":"NotificationListenerService allows reading all notifications from other apps, including sensitive content.",
            "severity":"CRITICAL","location":"bytecode analysis",
            "recommendation":"Disclose notification access usage in privacy policy. Only read notifications necessary for app functionality."})
    if findings:
        sa.findings.append({"category":"35. Broadcast & Notification Advanced — LocalBroadcastManager / Ordered / NotificationListener","rules":findings})

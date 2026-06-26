import logging
logger = logging.getLogger(__name__)


def detect_intent_redirection(sa):
    findings = []
    src = sa._string_in_source(r'getIntent\(\)\.(getStringExtra|getSerializableExtra|getParcelableExtra|getData|getAction|getExtras)')
    if src:
        for sm in src[:10]:
            findings.append({"id":"ADV-001","name":"Intent Redirection - External Intent Data Used",
                "description":"The application receives external Intent data and uses it directly. Attackers can craft malicious intents to redirect the app's internal flow.",
                "severity":"HIGH","location":sm,
                "recommendation":"Validate the source of all Intent extras. Use getCallingPackage() to verify the caller."})
    dex = sa._find_methods_by_invoke("Landroid/content/Intent;->setComponent")
    for dm in dex[:10]:
        findings.append({"id":"ADV-002","name":"Intent Redirection - setComponent from External Input",
            "description":"setComponent() is called which can redirect intents to arbitrary components based on external input.",
            "severity":"CRITICAL","location":dm,
            "recommendation":"Never allow setComponent() with values from untrusted sources. Whitelist allowed target components."})
    if findings:
        sa.findings.append({"category":"1. Intent Redirection","rules":findings})


def detect_intent_spoofing(sa):
    findings = []
    for comp_type in ["activities","services","receivers"]:
        for comp in sa.manifest_components.get(comp_type, []):
            if comp["exported"] in ("true", None, "") and not comp["permission"]:
                findings.append({"id":"ADV-INT-001","name":"Intent Spoofing - Component Accepts External Intents",
                    "description":f"Exported {comp_type[:-2]} '{comp['name']}' has no permission protection, allowing any app to send spoofed intents to it.",
                    "severity":"HIGH","location":f"AndroidManifest: {comp['name']}",
                    "recommendation":f"Set android:exported='false' or add a signature-level permission on {comp['name']}."})
    if findings:
        sa.findings.append({"category":"1. Intent Spoofing","rules":findings})


def detect_arbitrary_intent_launch(sa):
    findings = []
    start_act = sa._find_methods_by_invoke("Landroid/content/Context;->startActivity")
    start_for_result = sa._find_methods_by_invoke("Landroid/app/Activity;->startActivityForResult")
    for dm in start_act[:5]:
        findings.append({"id":"ADV-INT-002","name":"Arbitrary Intent Launch - startActivity Without Package Restriction",
            "description":"startActivity() is called. If the Intent is implicit or constructed from tainted data, any app can intercept or receive it.",
            "severity":"HIGH","location":dm,
            "recommendation":"Use explicit intents with setPackage() to restrict delivery. Validate all intent extras."})
    if findings:
        sa.findings.append({"category":"1. Arbitrary Intent Launch","rules":findings})


def detect_pending_intent_abuse(sa):
    findings = []
    src = sa._string_in_source(r'PendingIntent\.(getActivity|getBroadcast|getService|getForegroundService)\s*\(')
    mutable = sa._string_in_source(r'FLAG_MUTABLE')
    for sm in src[:15]:
        if 'FLAG_IMMUTABLE' not in sm:
            findings.append({"id":"ADV-003","name":"PendingIntent Without FLAG_IMMUTABLE",
                "description":"A PendingIntent is created without FLAG_IMMUTABLE, allowing the receiver to modify the Intent. On Android 12+, mutable PendingIntents require explicit justification.",
                "severity":"HIGH","location":sm,
                "recommendation":"Add PendingIntent.FLAG_IMMUTABLE to all PendingIntents. Only use FLAG_MUTABLE when absolutely required."})
    if not findings and src:
        findings.append({"id":"ADV-004","name":"PendingIntent Usage Detected",
            "description":"The application uses PendingIntents. Review all usages for security.",
            "severity":"INFO","location":"detected in source",
            "recommendation":"Audit all PendingIntent.create() calls for FLAG_IMMUTABLE usage."})
    if findings:
        sa.findings.append({"category":"1. Unsafe PendingIntent","rules":findings})


def detect_exported_components(sa):
    findings = []
    for comp_type in ["activities","services","receivers","providers"]:
        for comp in sa.manifest_components.get(comp_type, []):
            if comp["exported"] in ("true", None, ""):
                label = comp_type.capitalize()
                findings.append({"id":f"ADV-EXP-{comp_type[0].upper()}",
                    "name":f"Exported {label[:-1]} Without Protection",
                    "description":f"The {label[:-1].lower()} '{comp['name']}' is exported without a permission requirement. Any app can interact with it.",
                    "severity":"MEDIUM","location":f"AndroidManifest: {comp['name']}",
                    "recommendation":f"Set android:exported='false' on {comp['name']} if internal. If export is required, add a signature-level permission."})
    if findings:
        sa.findings.append({"category":"1. Exported Components","rules":findings})


def detect_task_hijacking(sa):
    findings = []
    prev_affinities = set()
    activities = sa.manifest_components.get("activities", [])
    for act in activities:
        if act["exported"] in ("true", None, ""):
            findings.append({"id":"ADV-TASK-001","name":"Task Hijacking Risk - Exported Activity Without Unique taskAffinity",
                "description":"An exported activity may inherit the default taskAffinity, enabling StrandHogg-style task hijacking where a malicious app can overlay its own activity.",
                "severity":"HIGH","location":f"AndroidManifest: {act['name']}",
                "recommendation":"Set a unique android:taskAffinity on exported activities. Consider android:launchMode='standard'."})
            break
    if findings:
        sa.findings.append({"category":"1. Task Hijacking / StrandHogg","rules":findings})


def detect_deep_link_hijacking(sa):
    findings = []
    deep_link_methods = sa._find_methods_by_regex(r'getData|getScheme|getHost|getPath')
    no_validation = sa._find_methods_by_regex(r'getData.*loadUrl|getData.*startActivity')
    if deep_link_methods and no_validation:
        for dm in no_validation[:5]:
            findings.append({"id":"ADV-DEEPLINK-001","name":"Deep Link Hijacking - URI Data Used Without Validation",
                "description":"Deep link data (URI) is processed without verifying the scheme, host, or path. Attackers can craft malicious deep links to inject data.",
                "severity":"CRITICAL","location":dm,
                "recommendation":"Validate scheme (must be https), host, and path against an allowlist before processing deep link data."})
    custom_schemes = sa._find_methods_by_regex(r'intent-filter.*<data.*android:scheme')
    if custom_schemes and not findings:
        findings.append({"id":"ADV-DEEPLINK-002","name":"Custom Scheme Deep Link - No autoVerify",
            "description":"Custom URI schemes cannot be verified via Digital Asset Links, making them susceptible to hijacking by any app claiming the same scheme.",
            "severity":"MEDIUM","location":"AndroidManifest analysis",
            "recommendation":"Prefer https:// schemes for deep links and enable autoVerify. Custom schemes should only be used for legacy compatibility."})
    if findings:
        sa.findings.append({"category":"1. Deep Link / Custom Scheme Abuse","rules":findings})


def detect_intent_interception(sa):
    findings = []
    implicit = sa._find_methods_by_invoke("Landroid/content/Context;->sendBroadcast")
    strings = [s for s in sa.strings if any(kw in s for kw in ["intent.action", ".ACTION_"])]
    if implicit and strings:
        for dm in implicit[:3]:
            findings.append({"id":"ADV-011","name":"Intent Interception - Implicit Broadcast",
                "description":"An implicit broadcast is sent. Any app with a matching intent-filter can intercept it.",
                "severity":"HIGH","location":dm,
                "recommendation":"Use explicit broadcasts with setPackage()."})
    start_act = sa._find_methods_by_invoke("Landroid/content/Context;->startActivity")
    action_s = [s for s in sa.strings if any(kw in s for kw in ["intent.action", ".ACTION_", ".action."])]
    if start_act and action_s:
        for dm in start_act[:3]:
            findings.append({"id":"ADV-012","name":"Intent Interception - Implicit Activity Start",
                "description":"An implicit Intent starts an Activity. A malicious app could intercept it.",
                "severity":"MEDIUM","location":dm,
                "recommendation":"Use explicit intents (setComponent()/setPackage()) for activities carrying sensitive data."})
    if findings:
        sa.findings.append({"category":"Intent Interception","rules":findings})


def detect_intents_advanced(sa):
    findings = []
    nested_intent = sa._find_methods_by_regex(r'Intent.*getParcelableExtra|Intent.*getSerializableExtra|Intent.*getParcelableArrayListExtra')
    for dm in nested_intent[:5]:
        findings.append({"id":"ADV-INT-100","name":"Nested Intent Extraction — Parcelable/Serializable Intent Injection Risk",
            "description":f"A nested Intent is extracted from getParcelableExtra/getSerializableExtra in {dm}. The extracted Intent may be used to start components, leading to nested intent redirection.",
            "severity":"CRITICAL","location":dm,
            "recommendation":"Validate nested intents before use. Ensure the extracted Intent's action, component, and data are from a trusted source."})
    parcelable_injection = sa._find_methods_by_regex(r'Parcelable\.CREATOR|CREATOR\.createFromParcel|readFromParcel|newArray.*Parcelable')
    if parcelable_injection:
        for dm in parcelable_injection[:3]:
            findings.append({"id":"ADV-INT-101","name":"Custom Parcelable Implementation — Parcelable Injection Risk",
                "description":f"Custom Parcelable implementation detected in {dm}. If the app reads Parcelable objects from intents without strict class validation, attackers can inject malicious Parcelable objects.",
                "severity":"HIGH","location":dm,
                "recommendation":"Validate the class of all deserialized Parcelable objects. Use allowlist-based class filtering in custom Parcelable readers."})
    get_bundle = sa._find_methods_by_invoke("Landroid/os/Bundle;->getBundle")
    if get_bundle:
        for dm in get_bundle[:3]:
            findings.append({"id":"ADV-INT-102","name":"Bundle.getBundle() — Nested Bundle Injection Risk",
                "description":f"getBundle() extracts a nested Bundle from another Bundle in {dm}. Nested Bundles can contain arbitrary data, leading to injection attacks if used without validation.",
                "severity":"HIGH","location":dm,
                "recommendation":"Validate the contents of nested bundles. Never pass trust decisions based on nested bundle values from untrusted sources."})
    intent_uri_abuse = sa._find_methods_by_regex(r'Intent\.parseUri|Intent\.getIntentOld')
    if intent_uri_abuse:
        for dm in intent_uri_abuse[:3]:
            findings.append({"id":"ADV-INT-103","name":"Intent.parseUri() — Arbitrary Intent Creation from Untrusted URI",
                "description":f"Intent.parseUri() is used in {dm}. This creates an Intent from a URI string. If the URI comes from an untrusted source, attackers can craft arbitrary intents to launch any component.",
                "severity":"CRITICAL","location":dm,
                "recommendation":"Never use Intent.parseUri() with URIs from untrusted sources. Wrap in try/catch and validate the resulting Intent's component."})
    if findings:
        sa.findings.append({"category":"28. Intents Advanced — Nested Redirection / Parcelable Injection / Bundle Injection","rules":findings})


def detect_setresult_data_leakage(sa):
    findings = []
    set_result = sa._find_methods_by_regex(
        r'setResult\([^)]*,\s*new\s+Intent|setResult\([^)]*,\s*intent|setResult\(-?\d+,\s*\w+\)'
    )
    get_extras_forward = sa._find_methods_by_regex(
        r'setResult[\s\S]{0,200}getIntent\(\)\.getExtras|setResult[\s\S]{0,200}getIntent\(\)\.getData|'
        r'setResult[\s\S]{0,200}getIntent\(\)\.getStringExtra|setResult[\s\S]{0,200}getIntent\(\)\.getParcelable'
    )
    if get_extras_forward:
        for dm in get_extras_forward[:5]:
            findings.append({
                "id": "ADV-INT-110",
                "name": "setResult() Forwards Incoming Intent Extras — Data Leakage via Payload Injection (PayPal/NextCloud Pattern)",
                "description": f"setResult() forwards getIntent().getExtras()/getData() to the caller in {dm}. An attacker can inject a ParcelableJsonWrapper or other serialized object that, when deserialized by the system during setResult/getExtras processing, initializes fields with sensitive data from the app's runtime state (account info, auth tokens, user data). The attacker reads the returned data via onActivityResult(). This was the exact vulnerability pattern in PayPal (AuthRememberedStateManager data leakage via ParcelableJsonWrapper) and in NextCloud (arbitrary file theft via setResult with file URI).",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Never forward incoming Intent extras/setResult() directly. Create a clean Intent with only the data that needs to be returned. Validate all outgoing Intent extras. Consider using a fixed result contract with minimal data passing."
            })
    if set_result and not get_extras_forward:
        for dm in set_result[:3]:
            findings.append({
                "id": "ADV-INT-111",
                "name": "setResult() Used — Review Returned Data for Sensitive Content",
                "description": f"setResult() is called in {dm}. Ensure returned Intent extras do not include sensitive data that was passed in by the caller or derived from internal state. Activities launched via startActivityForResult() return data to the calling app, which may be malicious.",
                "severity": "MEDIUM",
                "location": dm,
                "recommendation": "Review all setResult() call sites. Never return sensitive data or forward caller-provided extras. Return minimal data needed for the result contract."
            })
    if findings:
        sa.findings.append({"category": "28. setResult Data Leakage — Incoming Extras Forwarded / Payload Injection (PayPal style)", "rules": findings})


def detect_intent_uri_perm_manipulation(sa):
    findings = []
    setresult_getintent = sa._find_methods_by_regex(
        r'setResult\([^)]*getIntent\(\)|setResult\(\s*-?1\s*,\s*intent|'
        r'setResult\(\s*-?1[\s,]*\w+\)[\s\S]{0,200}getIntent\(\)'
    )
    uri_flag = sa._find_methods_by_regex(
        r'FLAG_GRANT_READ_URI_PERMISSION|FLAG_GRANT_WRITE_URI_PERMISSION|'
        r'GRANT_READ_URI|GRANT_WRITE_URI'
    )
    if setresult_getintent:
        for dm in setresult_getintent[:5]:
            findings.append({
                "id": "ADV-URI-PERM-001",
                "name": "Intent URI Permission Manipulation — setResult Reflects getIntent (CWE-266)",
                "description": f"setResult() is called using getIntent() data in {dm}. An attacker can craft an Intent with URI permission flags (FLAG_GRANT_READ_URI_PERMISSION / FLAG_GRANT_WRITE_URI_PERMISSION) and send it to this exported component. When the vulnerable component reflects the Intent back via setResult(), the URI permissions take effect, granting the attacker access to the app's content providers. This is the CWE-266 Intent URI Permission Manipulation pattern.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Never return getIntent() via setResult(). Create a clean new Intent with only required data. If the incoming Intent must be used, remove URI permission flags with intent.removeFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION)."
            })
    if uri_flag and setresult_getintent:
        findings.append({
            "id": "ADV-URI-PERM-002",
            "name": "URI Permission Flags Present + setResult(getIntent) — Active URI Permission Manipulation Risk",
            "description": "The app uses URI permission flags (FLAG_GRANT_READ_URI_PERMISSION / FLAG_GRANT_WRITE_URI_PERMISSION) and also reflects getIntent() via setResult(). This combination enables Intent URI permission manipulation: an attacker can send an intent with URI permission flags to a vulnerable exported component, and the reflected setResult will grant the attacker persistent access to the app's content providers.",
            "severity": "CRITICAL",
            "location": "bytecode analysis",
            "recommendation": "Sanitize all incoming Intents before passing them to setResult(). Use intent.removeFlags() to strip URI permission flags, or create a new Intent for results."
        })
    if findings:
        sa.findings.append({"category": "40. Intent URI Permission Manipulation (CWE-266)", "rules": findings})

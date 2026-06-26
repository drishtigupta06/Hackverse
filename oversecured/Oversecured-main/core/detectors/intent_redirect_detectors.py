import logging
logger = logging.getLogger(__name__)


def detect_proxy_activity(sa):
    findings = []
    proxy = sa._find_methods_by_regex(
        r'getParcelableExtra.*Intent.*startActivity|getParcelableExtra.*Intent.*sendBroadcast|getParcelableExtra.*Intent.*startService'
    )
    for dm in proxy[:8]:
        findings.append({
            "id": "ADV-REDIR-001",
            "name": "Proxy Activity — Parcelable Intent Redirect to startActivity/sendBroadcast/startService",
            "description": f"An Intent is extracted via getParcelableExtra() and forwarded to startActivity/sendBroadcast/startService in {dm}. An attacker can embed a malicious Intent to launch any component, including non-exported ones, bypassing Android's access controls.",
            "severity": "CRITICAL",
            "location": dm,
            "recommendation": "Never forward embedded Intents directly. Validate the target component, action, and data. Use setComponent(null) and setSelector(null) to strip dangerous fields, or extract only the needed data instead of forwarding the entire Intent."
        })
    if findings:
        sa.findings.append({"category": "38. Intent Redirect — Proxy Components / Open Redirect", "rules": findings})


def detect_intent_setresult_redirect(sa):
    findings = []
    setresult = sa._find_methods_by_regex(
        r'setResult\([^,]*,\s*getIntent\(\)\s*\)|setResult\(-?\d+,\s*getIntent\(\)\)'
    )
    for dm in setresult[:5]:
        findings.append({
            "id": "ADV-REDIR-010",
            "name": "setResult(getIntent()) — Full Intent Redirect Leaks Content Provider Access",
            "description": f"Activity calls setResult(-1, getIntent()) in {dm}, returning the full incoming Intent to the caller. An attacker can use this to gain access to the app's Content Providers by passing a content:// URI with FLAG_GRANT_READ_URI_PERMISSION, allowing theft of arbitrary provider data.",
            "severity": "CRITICAL",
            "location": dm,
            "recommendation": "Never return getIntent() directly via setResult(). Extract only the data you need (e.g., getStringExtra) into a new Intent. Strip FLAG_GRANT_READ_URI_PERMISSION / FLAG_GRANT_WRITE_URI_PERMISSION flags from returned Intents."
        })
    if findings:
        sa.findings.append({"category": "38. Intent Redirect — setResult(getIntent()) Provider Access Leak", "rules": findings})


def detect_intent_parse_uri(sa):
    findings = []
    parse_uri = sa._find_methods_by_invoke(
        "Landroid/content/Intent;->parseUri"
    )
    if parse_uri:
        for dm in parse_uri[:5]:
            findings.append({
                "id": "ADV-REDIR-020",
                "name": "Intent.parseUri() — Intent Creation from Untrusted String URI",
                "description": f"Intent.parseUri() is called in {dm}, which constructs an Intent object from a URI string. If the URI originates from user input, deep links, or WebView content, an attacker can craft a malicious intent:// scheme URI to launch arbitrary components, including non-exported ones.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Never use Intent.parseUri() with untrusted URI strings. If parsing intent:// URIs in WebView, clear setComponent(null) and setSelector(null) after parsing, and only allow BROWSABLE category intents."
            })
    parse_uri_unsafe = sa._find_methods_by_regex(
        r'Intent\.parseUri.*URI_ALLOW_UNSAFE|parseUri.*URI_INTENT_SCHEME.*URI_ALLOW_UNSAFE'
    )
    if parse_uri_unsafe:
        for dm in parse_uri_unsafe[:3]:
            findings.append({
                "id": "ADV-REDIR-021",
                "name": "Intent.parseUri() with URI_ALLOW_UNSAFE — Unsafe Flags Allowed",
                "description": f"Intent.parseUri() is called with URI_ALLOW_UNSAFE flag in {dm}, which allows FLAG_GRANT_READ_URI_PERMISSION and FLAG_GRANT_WRITE_URI_PERMISSION in parsed intents. This enables content:// URI permission escalation through intent URIs.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Remove URI_ALLOW_UNSAFE flag. Never grant URI permissions via intent:// scheme URIs."
            })
    if findings:
        sa.findings.append({"category": "38. Intent Redirect — Intent.parseUri() ACE via Intent Scheme", "rules": findings})


def detect_intent_selector(sa):
    findings = []
    selector = sa._find_methods_by_invoke(
        "Landroid/content/Intent;->setSelector"
    )
    if selector:
        for dm in selector[:5]:
            findings.append({
                "id": "ADV-REDIR-030",
                "name": "setSelector() Used — Intent Selector May Bypass Component Filters",
                "description": f"Intent.setSelector() is used in {dm}. Selectors allow an Intent to specify an alternative target component that can bypass setComponent(null) filtering. Attackers can use selectors to launch non-exported components even when the primary Intent's component is cleared.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "After calling setComponent(null), also call setSelector(null) to fully clear the target. Never accept Intents with selectors from untrusted sources."
            })
    if findings:
        sa.findings.append({"category": "38. Intent Redirect — setSelector() Bypass", "rules": findings})


def detect_parcel_unmarshall_intent(sa):
    findings = []
    unmarshall = sa._find_methods_by_invoke(
        "Landroid/os/Parcel;->unmarshall"
    )
    read_parcelable = sa._find_methods_by_invoke(
        "Landroid/os/Parcel;->readParcelable"
    )
    intent_from_bytes = sa._find_methods_by_regex(
        r'Parcel\.obtain.*unmarshall.*[Ii]ntent|unmarshall.*readParcelable.*Intent|marshall.*Intent.*unmarshall'
    )
    if unmarshall and read_parcelable and intent_from_bytes:
        for dm in intent_from_bytes[:3]:
            findings.append({
                "id": "ADV-REDIR-040",
                "name": "Parcel.unmarshall() → Intent — Low-Level Intent Reconstruction from Bytes",
                "description": f"An Intent is reconstructed from raw bytes via Parcel.unmarshall() + readParcelable() in {dm}. If the byte array originates from untrusted input (deep link params, push messages, JSON), this bypasses all Intent validation and can launch arbitrary components.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Avoid reconstructing Intents from byte arrays. Use explicit Intent constructors with validated fields. If Parcel deserialization is necessary, validate the final Intent's component and action before use."
            })
    if findings:
        sa.findings.append({"category": "38. Intent Redirect — Parcel.unmarshall() Low-Level Intent Deserialization", "rules": findings})


def detect_provider_access_via_proxy(sa):
    findings = []
    proxy_flags = sa._find_methods_by_regex(
        r'FLAG_GRANT_READ_URI_PERMISSION.*getParcelableExtra|FLAG_GRANT_WRITE_URI_PERMISSION.*getParcelableExtra|'
        r'getParcelableExtra.*FLAG_GRANT_READ_URI_PERMISSION'
    )
    for dm in proxy_flags[:5]:
        findings.append({
            "id": "ADV-REDIR-050",
            "name": "Content Provider URI Permission Bypass via Proxy Component",
            "description": f"A proxy component in {dm} receives an Intent with URI permission flags (FLAG_GRANT_READ_URI_PERMISSION/FLAG_GRANT_WRITE_URI_PERMISSION) and forwards it to startActivity. An attacker can abuse this to gain access to protected Content Providers.",
            "severity": "CRITICAL",
            "location": dm,
            "recommendation": "Strip or clear URI permission flags before forwarding Intents. Use setFlags(0) to clear all flags on forwarded Intents."
        })
    if findings:
        sa.findings.append({"category": "38. Intent Redirect — Content Provider Permission Leak via Proxy", "rules": findings})

import logging
logger = logging.getLogger(__name__)


def detect_local_oauth_server(sa):
    findings = []
    server_socket = sa._find_methods_by_invoke(
        "Ljava/net/ServerSocket"
    )
    server_socket_accept = sa._find_methods_by_invoke(
        "Ljava/net/ServerSocket;->accept"
    )
    oauth_keywords = ["oauth", "callback", "redirect_uri", "localhost", "127.0.0.1", "authorization_code", "token"]
    oauth_strings = [s for s in sa.strings if any(kw in str(s).lower() for kw in oauth_keywords)]
    localhost_strs = [s for s in sa.strings if "localhost" in str(s) or "127.0.0.1" in str(s)]
    has_nanohttpd = sa._find_methods_by_invoke("Lfi/iki/elonen/NanoHTTPD")
    if (server_socket or has_nanohttpd) and oauth_strings:
        for dm in (server_socket_accept or has_nanohttpd or [])[:3]:
            findings.append({
                "id": "ADV-AUTH-001",
                "name": "Local HTTP Server for OAuth Callback — Token Interception via Loopback",
                "description": f"A local server (ServerSocket/NanoHTTPD) is used to handle OAuth callbacks in {dm}. Android does not isolate loopback ports between apps — any app on the same device can connect to 127.0.0.1:{'?'}. A malicious app can race to intercept the authorization code from the callback, potentially exchanging it for access tokens.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Use Android's intent-based OAuth redirect flow (Custom Tabs with PKCE) instead of localhost servers. PKCE ensures intercepted authorization codes cannot be exchanged without the code verifier."
            })
    if findings:
        sa.findings.append({"category": "41. Account Takeover — OAuth Localhost Callback / Token Interception", "rules": findings})


def detect_biometric_without_crypto(sa):
    findings = []
    bp = sa._find_methods_by_invoke(
        "Landroidx/biometric/BiometricPrompt"
    )
    bp_old = sa._find_methods_by_invoke(
        "Landroid/hardware/biometrics/BiometricPrompt"
    )
    crypto = sa._find_methods_by_invoke(
        "Landroidx/biometric/BiometricPrompt$CryptoObject"
    )
    if (bp or bp_old) and not crypto:
        findings.append({
            "id": "ADV-AUTH-010",
            "name": "Biometric Authentication Without CryptoObject — One-Time Gate Bypass",
            "description": "BiometricPrompt is used without a CryptoObject. Without CryptoObject, biometric authentication acts as a one-time gate: once passed, subsequent sensitive operations are not re-authenticated. An attacker who gains access to the device after biometric unlock can perform all privileged operations. Additionally, new biometric enrollment does not invalidate the session.",
            "severity": "HIGH",
            "location": "bytecode analysis",
            "recommendation": "Always use BiometricPrompt with a CryptoObject (e.g., Signature or Cipher). This binds the key to biometric auth, requiring re-authentication per operation and invalidating keys on biometric enrollment changes."
        })
    if findings:
        sa.findings.append({"category": "41. Insecure Biometric Authentication — Missing CryptoObject Binding", "rules": findings})


def detect_aidl_auth_abuse(sa):
    findings = []
    aidl = sa._find_methods_by_invoke("Landroid/os/IInterface")
    calling_uid = sa._find_methods_by_invoke(
        "Landroid/os/Binder;->getCallingUid"
    )
    if aidl and not calling_uid:
        findings.append({
            "id": "ADV-AUTH-020",
            "name": "AIDL Service Without Calling UID Check — Unauthenticated IPC Access",
            "description": "An AIDL interface is used without calling getCallingUid() or checking the caller's package. Any app on the device can bind to this service and invoke auth-related operations (token generation, credential access, privileged actions).",
            "severity": "CRITICAL",
            "location": "bytecode analysis",
            "recommendation": "Always call getCallingUid() at the beginning of AIDL interface methods and verify the caller's identity against an allowlist. Use checkCallingPermission() for permission enforcement."
        })
    if findings:
        sa.findings.append({"category": "41. Account Takeover — AIDL Service / IPC Auth Abuse", "rules": findings})


def detect_custom_scheme_oauth(sa):
    findings = []
    oauth_intents = sa._find_methods_by_regex(
        r'oauth|OAuth|OAuth2|authorization_code|access_token|id_token|code_challenge|PKCE'
    )
    custom_scheme = sa._find_methods_by_regex(
        r'intent-filter.*scheme.*://?[a-z]+|register.*scheme|CustomTabsIntent'
    )
    has_applinks = False
    for s in sa.strings:
        try:
            s_str = str(s)
            if 'assetlinks.json' in s_str or 'digital_asset_links' in s_str or '.well-known/assetlinks' in s_str:
                has_applinks = True
                break
        except Exception:
            pass
    if oauth_intents and custom_scheme and not has_applinks:
        findings.append({
            "id": "ADV-AUTH-030",
            "name": "Custom URI Scheme for OAuth Callback — Scheme Hijacking Risk (Use App Links)",
            "description": "The app uses a custom URI scheme for OAuth callbacks without HTTPS App Links verification. Any other app on the device can register the same custom scheme, intercept the OAuth authorization code, and potentially exchange it for tokens. PKCE mitigates this but is not universally implemented.",
            "severity": "HIGH",
            "location": "bytecode analysis",
            "recommendation": "Use HTTPS App Links (with assetlinks.json) instead of custom URI schemes for OAuth callbacks. Always implement PKCE (Proof Key for Code Exchange) in all OAuth flows."
        })
    if findings:
        sa.findings.append({"category": "41. Account Takeover — Custom Scheme OAuth Hijacking / App Links Missing", "rules": findings})


def detect_token_in_external_storage(sa):
    findings = []
    ext_storage = sa._find_methods_by_invoke(
        "Landroid/content/Context;->getExternalFilesDir"
    )
    ext_storage2 = sa._find_methods_by_invoke(
        "Landroid/os/Environment;->getExternalStorageDirectory"
    )
    sensitive_patterns = r'(token|jwt|session|auth|credential|password|secret|key).*(write|save|store|put|export)'
    ext_with_sensitive = sa._find_methods_by_regex(
        r'(getExternalFilesDir|getExternalStorageDirectory|getExternalCacheDir).{0,200}(token|jwt|session|auth|credential)'
    )
    if ext_with_sensitive:
        for dm in ext_with_sensitive[:5]:
            findings.append({
                "id": "ADV-AUTH-040",
                "name": "Authentication Token Written to External Storage — Token Theft via Any App",
                "description": f"Authentication tokens or credentials appear to be written to external storage in {dm}. External (SD card) storage is readable by any app with READ_EXTERNAL_STORAGE permission. On older Android versions (pre-API 24), no permission is needed. Tokens leaked this way enable full account takeover.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Never store authentication tokens in external storage. Use EncryptedSharedPreferences or Android Keystore for token storage. Tokens should only exist in app-private internal storage."
            })
    if findings:
        sa.findings.append({"category": "41. Account Takeover — Token Storage / Credential Exposure", "rules": findings})


def detect_magic_link_interception(sa):
    findings = []
    intent_filters = sa.manifest_components
    all_intents = []
    for comp_type in ["activities", "services", "receivers"]:
        for comp in intent_filters.get(comp_type, []):
            for intent_f in comp.get("intent_filters", []):
                all_intents.append(intent_f)
    has_https_deeplink = False
    missing_auto_verify = False
    has_auth_keywords = False
    for intent_f in all_intents:
        action_view = any(a.get("name") == "android.intent.action.VIEW" for a in intent_f.get("actions", []))
        category_browsable = any(c.get("name") == "android.intent.category.BROWSABLE" for c in intent_f.get("categories", []))
        if not (action_view and category_browsable):
            continue
        for data in intent_f.get("data", []):
            scheme = data.get("scheme", "")
            host = data.get("host", "")
            if scheme == "https" or scheme == "http":
                has_https_deeplink = True
                auto_verify = data.get("autoVerify", intent_f.get("autoVerify", None))
                if auto_verify is None:
                    has_https_deeplink = True
                    missing_auto_verify = True
    auth_link_strings = sa._find_methods_by_regex(
        r'magic.?link|magic_link|login.?token|auth.?token|access.?token|session.?token|'
        r'passwordless|one.?time.?link|signin.?link|email.?link|'
        r'Branch\.io|branch\.io|app\.link|bnc_lt|bnc_sdk'
    )
    if auth_link_strings:
        has_auth_keywords = True
    if has_https_deeplink and missing_auto_verify and has_auth_keywords:
        findings.append({
            "id": "ADV-AUTH-050",
            "name": "HTTPS Deep Link Without autoVerify — Magic Link Token Interception via Intent Hijacking",
            "description": "The app uses HTTPS deep links with auth-related operations (magic link, login token, auth token) but does NOT set android:autoVerify=\"true\" on the intent-filter. Without autoVerify, the deep link domain is NOT cryptographically bound to this app. Any malicious app on the device can register the same HTTPS host in its intent-filter and intercept the incoming deep link. If the deep link URL contains auth tokens (magic link tokens, OAuth codes, session tokens), the attacker extracts them and achieves full account takeover. This was the root cause of CVE-2023-36612 (Shopify Arrive): Branch.io app.link domain was used for magic link login without App Links verification, allowing any app to intercept the login token.",
            "severity": "CRITICAL",
            "location": "AndroidManifest: intent-filter with https scheme (autoVerify missing)",
            "recommendation": "Always add android:autoVerify=\"true\" to all HTTPS deep link intent-filters. Deploy a valid assetlinks.json file at https://DOMAIN/.well-known/assetlinks.json. Never pass auth tokens in deep link URLs — use a server-side session exchange pattern instead. Implement PKCE for all OAuth flows. Use Custom Tabs for auth flows instead of deep link redirects."
        })
    deep_link_activities = []
    for comp_type in ["activities", "services", "receivers"]:
        for comp in intent_filters.get(comp_type, []):
            for intent_f in comp.get("intent_filters", []):
                action_view = any(a.get("name") == "android.intent.action.VIEW" for a in intent_f.get("actions", []))
                browsable = any(c.get("name") == "android.intent.category.BROWSABLE" for c in intent_f.get("categories", []))
                if action_view and browsable:
                    deep_link_activities.append(comp.get("name", "?"))
    if deep_link_activities:
        token_in_deeplink = sa._find_methods_by_regex(
            r'(token|secret|access|jwt|session)\s*=\s*getQueryParameter|'
            r'getQueryParameter\(.*(token|secret|access|jwt|session)|'
            r'getData\(\).*toString.*contains.*(token|secret|key|auth|magic|link|signin|signup)'
        )
        if token_in_deeplink:
            for dm in token_in_deeplink[:5]:
                findings.append({
                    "id": "ADV-AUTH-051",
                    "name": "Auth Token/Secret Extracted From Deep Link URL — Token Leakage via Query Parameter",
                    "description": f"Auth tokens, secrets, or session identifiers are extracted from deep link query parameters in {dm}. Deep link URLs appear in Android's system logs (logcat), are visible to other apps with READ_LOGS permission (pre-API 24), are included in referrer headers, and can be intercepted by any app that registers the same intent filter. Tokens should never travel in deep link URLs.",
                    "severity": "CRITICAL",
                    "location": dm,
                    "recommendation": "Never pass auth tokens in deep link URLs (query parameters or fragments). Use a temporary exchange code pattern: the deep link contains a one-time code that the app exchanges for a token via server-side authentication. This prevents token leakage from logcat, referrer headers, and intent interception."
                })
    if findings:
        sa.findings.append({"category": "41. Account Takeover — Magic Link / Deep Link Token Interception (autoVerify Missing)", "rules": findings})

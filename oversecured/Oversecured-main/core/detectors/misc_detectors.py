import logging
logger = logging.getLogger(__name__)


def detect_deserialization(sa):
    findings = []
    ois = sa._find_methods_by_invoke("Ljava/io/ObjectInputStream;->readObject")
    bundle_serializable = sa._find_methods_by_regex(r'getSerializable|getParcelable')
    for dm in ois[:3]:
        findings.append({"id":"ADV-DESER-001","name":"Java Deserialization (ObjectInputStream.readObject)",
            "description":"ObjectInputStream.readObject() is used, which can execute arbitrary code during deserialization of attacker-controlled data.",
            "severity":"CRITICAL","location":dm,
            "recommendation":"Avoid Java serialization entirely. Use JSON with validation. If serialization is required, implement ObjectInputFilter (Java 9+) to whitelist allowed classes."})
    if bundle_serializable:
        for dm in bundle_serializable[:3]:
            findings.append({"id":"ADV-DESER-002","name":"Bundle Serialization - getSerializable/getParcelable",
                "description":"Serializable or Parcelable objects are extracted from Bundles. Malicious serialized objects can cause unexpected behavior.",
                "severity":"MEDIUM","location":dm,
                "recommendation":"Validate the class of deserialized objects. Use allowlist-based class filtering."})
    if findings:
        sa.findings.append({"category":"8. Deserialization Vulnerabilities","rules":findings})


def detect_uri_handling(sa):
    findings = []
    taint_uri = sa.taint_findings.get("uri_handling", [])
    for f in taint_uri[:5]:
        findings.append({"id":"ADV-URI-001","name":"Tainted URI Used in URI Operation",
            "description":f"Tainted data reaches a URI handling sink ({f.get('sink','?')}). Malformed or malicious URIs can trigger SSRF, file disclosure, or content:// abuse.",
            "severity":"HIGH","location":f.get("location","unknown"),
            "recommendation":"Validate all URIs against an allowlist. Parse and check the scheme, host, and path. Reject unrecognized schemes."})
    file_uri = sa._find_methods_by_regex(r'Uri\.parse.*file://|Uri\.fromFile')
    if file_uri:
        for dm in file_uri[:3]:
            findings.append({"id":"ADV-URI-002","name":"File URI Constructed (file://)",
                "description":"File URIs are constructed, which can expose local files when passed to other components.",
                "severity":"HIGH","location":dm,
                "recommendation":"Avoid file:// URIs. Use FileProvider for sharing files between apps."})
    if findings:
        sa.findings.append({"category":"15. URI Handling Vulnerabilities","rules":findings})


def detect_data_leaking_activities(sa):
    findings = []
    src = sa._string_in_source(r'(getIntent\(\)\.(getStringExtra|getData|getExtras)).{0,100}(startActivity|startService|setResult)')
    if src:
        for sm in src[:10]:
            findings.append({"id":"ADV-016","name":"Activity Leaking Data - Intent Forwarding",
                "description":"An activity forwards incoming Intent data to another component without validation.",
                "severity":"HIGH","location":sm,
                "recommendation":"Validate and sanitize all forwarded Intent data."})
    if findings:
        sa.findings.append({"category":"Activities Leaking Data","rules":findings})


def detect_root_emulator_debug(sa):
    findings = []
    root_s = [s for s in sa.strings if any(kw in s.lower() for kw in ["su ","superuser","magisk","busybox","testkeys"])]
    emu_s = [s for s in sa.strings if any(kw in s.lower() for kw in ["goldfish","ranchu","generic","sdk_google","emulator"])]
    debug_s = [s for s in sa.strings if any(kw in s.lower() for kw in ["isDebuggerConnected","waitForDebugger","ro.debuggable"])]
    if root_s:
        findings.append({"id":"ADV-021","name":"Root Detection References Found",
            "severity":"INFO","location":"bytecode strings",
            "recommendation":"Ensure root detection is a genuine security control."})
    if emu_s:
        findings.append({"id":"ADV-022","name":"Emulator Detection References Found",
            "severity":"INFO","location":"bytecode strings",
            "recommendation":"Review emulator detection logic for correctness."})
    if debug_s:
        findings.append({"id":"ADV-023","name":"Debug Detection References Found",
            "severity":"LOW","location":"bytecode strings",
            "recommendation":"Verify debug detection is enforced across all entry points."})
    if findings:
        sa.findings.append({"category":"Root/Emulator/Debug Detection","rules":findings})


def detect_screen_capture_vulnerability(sa):
    findings = []
    flag_secure = sa._find_methods_by_string("FLAG_SECURE")
    if not flag_secure:
        src = sa._string_in_source(r'(Login|Password|Pin|Otp|Payment|Checkout).*Activity')
        if src:
            for sm in src[:5]:
                findings.append({"id":"ADV-024","name":"Potential Screen Capture Vulnerability",
                    "description":"Sensitive activities may not set FLAG_SECURE, allowing screenshots.",
                    "severity":"HIGH","location":sm,
                    "recommendation":"Call getWindow().setFlags(FLAG_SECURE, FLAG_SECURE) in onCreate()."})
    if findings:
        sa.findings.append({"category":"Screen Capture Protection","rules":findings})


def detect_obfuscation_gaps(sa):
    findings = []
    all_classes = list(sa.vm.get_classes())
    total = len(all_classes)
    if total < 5:
        return
    unrenamed = [cn for cn in [c.name.split("/")[-1] for c in all_classes]
                 if any(indicator in (cn if isinstance(cn, str) else cn.decode()) for indicator in ["Activity","Fragment","Service","Receiver","Provider","Helper","Utils","Manager","Database"])]
    ratio = 1.0 - (len(unrenamed) / max(total, 1))
    if ratio < 0.3 and len(unrenamed) > 10:
        findings.append({"id":"ADV-051","name":"Limited Obfuscation Detected",
            "description":f"{len(unrenamed)} identifiable class names out of {total} ({ratio:.0%} obfuscation).",
            "severity":"LOW","location":"bytecode analysis",
            "recommendation":"Enable ProGuard/R8 obfuscation in release builds."})
    if findings:
        sa.findings.append({"category":"Obfuscation & Anti-Tamper","rules":findings})


def detect_zip_path_traversal(sa):
    findings = []
    ze = sa._find_methods_by_invoke("Ljava/util/zip/ZipEntry;->getName")
    zi = sa._find_methods_by_invoke("Ljava/util/zip/ZipInputStream")
    if ze and zi:
        findings.append({"id":"ADV-052","name":"Zip Entry Path Traversal Risk (Zip Slip)",
            "description":"The app reads zip files and may be vulnerable to Zip Slip.",
            "severity":"CRITICAL","location":"bytecode analysis",
            "recommendation":"Validate zip entry names against '../' patterns."})
    if findings:
        sa.findings.append({"category":"Zip Path Traversal","rules":findings})


def detect_fragment_injection(sa):
    findings = []
    fi = sa._find_methods_by_invoke("Landroid/app/Fragment;->instantiate")
    fm = sa._find_methods_by_invoke("Landroid/app/FragmentManager;->beginTransaction")
    if fi and fm:
        findings.append({"id":"ADV-053","name":"Fragment Injection - Dynamic Fragment Loading",
            "severity":"HIGH","location":"bytecode analysis",
            "recommendation":"Whitelist allowed fragment classes before instantiation."})
    if findings:
        sa.findings.append({"category":"Fragment Injection","rules":findings})


def detect_jobscheduler_security(sa):
    findings = []
    js = sa._find_methods_by_invoke("Landroid/app/job/JobService")
    if js:
        findings.append({"id":"ADV-055","name":"JobScheduler/JobService Used",
            "severity":"LOW","location":"bytecode analysis",
            "recommendation":"Avoid storing sensitive parameters in JobInfo extras."})
    if findings:
        sa.findings.append({"category":"JobScheduler Security","rules":findings})


def detect_device_admin_abuse(sa):
    findings = []
    dpm = sa._find_methods_by_invoke("Landroid/app/admin/DevicePolicyManager")
    if dpm:
        findings.append({"id":"ADV-039","name":"Device Admin Usage Detected",
            "severity":"HIGH","location":"bytecode analysis",
            "recommendation":"Disclose device admin usage in privacy policy."})
    wipe = sa._find_methods_by_invoke("Landroid/app/admin/DevicePolicyManager;->wipeData")
    if wipe:
        for dm in wipe[:3]:
            findings.append({"id":"ADV-040","name":"Remote Wipe (wipeData) Capability",
                "severity":"CRITICAL","location":dm,
                "recommendation":"Restrict remote wipe triggers to authenticated server commands."})
    if findings:
        sa.findings.append({"category":"Device Admin","rules":findings})


def detect_insecure_bound_services(sa):
    findings = []
    bind_svc = sa._find_methods_by_invoke("Landroid/content/Context;->bindService")
    aidl = sa._find_methods_by_invoke("Landroid/os/IInterface")
    binder_svc = [c for c in sa.manifest_components.get("services", [])
                   if c.get("exported") in ("true", None, "")]
    if bind_svc and not binder_svc:
        for dm in bind_svc[:3]:
            findings.append({"id":"ADV-IPC-001","name":"Bound Service Without Permission Protection",
                "description":f"bindService() used in {dm}. Bound services without permissions allow any app to connect.",
                "severity":"HIGH","location":dm,
                "recommendation":"Add permission check in onBind(). Use checkCallingPermission() before returning IBinder."})
    if aidl:
        findings.append({"id":"ADV-IPC-002","name":"AIDL Interface Detected",
            "description":"AIDL interface enables cross-process IPC. Unprotected AIDL interfaces expose app functionality to all apps.",
            "severity":"HIGH","location":"bytecode analysis",
            "recommendation":"Protect AIDL interfaces with permissions. Validate caller identity in all AIDL methods."})
    exported_with_binder = []
    for svc in binder_svc:
        exported_with_binder.append(svc["name"])
    if exported_with_binder:
        findings.append({"id":"ADV-IPC-003","name":"Exported Service With Potential Binder Exposure",
            "description":f"Exported service(s) may expose Binder: {', '.join(exported_with_binder[:3])}. Binder services without permission checks allow arbitrary apps to invoke service methods.",
            "severity":"CRITICAL","location":"AndroidManifest analysis",
            "recommendation":"Add android:permission to exported services. Implement checkCallingPermission() in onTransact()."})
    if findings:
        sa.findings.append({"category":"20. Insecure IPC (Bound Services / AIDL / Binder)","rules":findings})


def detect_pendingintent_advanced(sa):
    findings = []
    fill_in = sa._find_methods_by_invoke("Landroid/app/PendingIntent;->fillIn")
    send = sa._find_methods_by_invoke("Landroid/app/PendingIntent;->send")
    get_act = sa._find_methods_by_invoke("Landroid/app/PendingIntent;->getActivity")
    get_brd = sa._find_methods_by_invoke("Landroid/app/PendingIntent;->getBroadcast")
    get_svc = sa._find_methods_by_invoke("Landroid/app/PendingIntent;->getService")
    if fill_in:
        for dm in fill_in[:3]:
            findings.append({"id":"ADV-PI-001","name":"PendingIntent.fillIn() Used — Intent Fields Can Be Overwritten",
                "description":f"PendingIntent.fillIn() in {dm} allows the caller to overwrite Intent fields. Combined with FLAG_MUTABLE, this enables PendingIntent hijacking.",
                "severity":"CRITICAL","location":dm,
                "recommendation":"Avoid fillIn() with mutable PendingIntents. Use FLAG_IMMUTABLE and validate all incoming fields."})
    if send:
        for dm in send[:3]:
            findings.append({"id":"ADV-PI-002","name":"PendingIntent.send() Used — Check OnFinished Callback",
                "description":f"PendingIntent.send() in {dm} may leak execution results to untrusted callers.",
                "severity":"MEDIUM","location":dm,
                "recommendation":"Use null OnFinished callback or validate the caller's identity in send()."})
    pi_usage = bool(get_act or get_brd or get_svc)
    mutable_strs = [s for s in sa.strings if "FLAG_MUTABLE" in str(s)]
    immutable_strs = [s for s in sa.strings if "FLAG_IMMUTABLE" in str(s)]
    if pi_usage and mutable_strs and not immutable_strs:
        findings.append({"id":"ADV-PI-003","name":"Mutable PendingIntent Without FLAG_IMMUTABLE Usage — Hijacking Risk",
            "description":"App uses FLAG_MUTABLE but may not use FLAG_IMMUTABLE elsewhere. Mutable PendingIntents allow the receiver to modify the Intent, enabling privilege escalation.",
            "severity":"CRITICAL","location":"bytecode analysis",
            "recommendation":"Always use FLAG_IMMUTABLE unless mutation is absolutely required (Android 12+) and document the reason."})
    no_immutable = pi_usage and not immutable_strs and not mutable_strs
    if no_immutable:
        findings.append({"id":"ADV-PI-004","name":"PendingIntent Without FLAG_IMMUTABLE (Default Mutable on Older Android)",
            "description":"PendingIntents are used without FLAG_IMMUTABLE. On Android <12, all PendingIntents are mutable by default.",
            "severity":"HIGH","location":"bytecode analysis",
            "recommendation":"Add PendingIntent.FLAG_IMMUTABLE to all PendingIntent.getActivity/getBroadcast/getService calls for Android 12+ compatibility and security."})
    if findings:
        sa.findings.append({"category":"21. PendingIntent Advanced — Hijacking / Injection / Escalation","rules":findings})


def detect_deeplink_advanced(sa):
    findings = []
    url_redirect = sa._find_methods_by_regex(r'loadUrl.*getData|getQueryParameter.*loadUrl|getStringExtra.*loadUrl')
    for dm in url_redirect[:5]:
        findings.append({"id":"ADV-DL-001","name":"Open Redirect via Deep Link — LoadUrl with Tainted URI",
            "description":f"Deep link data (getData/getQueryParameter) flows to loadUrl() in {dm}. Attackers can craft a deep link that redirects to a malicious website.",
            "severity":"CRITICAL","location":dm,
            "recommendation":"Validate all URLs loaded from deep link data against an allowlist. Never load unvalidated URLs from intents in WebView."})
    token_to_uri = sa._find_methods_by_regex(r'getQueryParameter.*token|getQueryParameter.*access|getQueryParameter.*auth|getQueryParameter.*jwt')
    for dm in token_to_uri[:5]:
        findings.append({"id":"ADV-DL-002","name":"Token/Authorization Parameter Extracted From Deep Link URI",
            "description":f"Auth tokens or credentials are extracted from deep link URI query parameters in {dm}. Tokens in URIs are leaked via referrer headers, browser history, and logs.",
            "severity":"CRITICAL","location":dm,
            "recommendation":"Never pass auth tokens in URI query parameters. Use the authorization code flow (PKCE) instead."})
    result_to_browser = sa._find_methods_by_regex(r'setResult.*Intent|startActivity.*Intent')
    deep_link_sig_patterns = ["Landroid/app/Activity;->onNewIntent", "Landroid/app/Activity;->onActivityResult",
                               "Landroid/app/Activity;->setResult"]
    for sig_pat in deep_link_sig_patterns:
        dl_methods = sa._find_methods_by_invoke(sig_pat)
        if dl_methods and result_to_browser:
            findings.append({"id":"ADV-DL-003","name":"Authentication Bypass via Deep Link — setResult/startActivity Chain",
                "description":f"Deep link handler can setResult or startActivity via {sig_pat} in {', '.join(dl_methods[:2])}. This may allow bypassing authentication by directly invoking deep link handlers.",
                "severity":"CRITICAL","location":"bytecode analysis",
                "recommendation":"Ensure deep link handlers verify the user's authentication state before processing. Require authentication for all deep link entry points."})
    if findings:
        sa.findings.append({"category":"22. Deep Link Advanced — Open Redirect / Auth Bypass / Token Leakage","rules":findings})


def detect_deeplink_path_traversal(sa):
    findings = []
    dl_file_write = sa._find_methods_by_regex(
        r'getQueryParameter[\s\S]{0,200}(?:FileOutputStream|write\(|file\.getName|saveFile|downloadFile|createNewFile|mkdir|renameTo|file\.getAbsolutePath)'
    )
    if dl_file_write:
        for dm in dl_file_write[:5]:
            findings.append({
                "id": "ADV-DL-004",
                "name": "Deep Link Query Parameter Used in File Write — Path Traversal to Arbitrary File Write",
                "description": f"Deep link query parameter value is used to construct a file write operation in {dm}. Attackers can craft a deep link with path traversal sequences (e.g., 'bc3://handle?file=../../shared_prefs/config.xml' or 'bc3://handle?name=../../databases/leak.db') to overwrite arbitrary files in the app's private directory. This was the core vulnerability in CVE-2023-36612 (Basecamp): a deep link query parameter allowed writing session tokens to attacker-controlled paths, and combined with a malicious intent, could then leak server responses to third-party apps.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Validate and canonicalize all file paths derived from deep link query parameters. Reject paths containing '../' or any non-alphanumeric characters. Use a fixed subdirectory with no user-controlled path components. Never construct file paths directly from query parameter values."
            })
    dl_file_path = sa._find_methods_by_regex(
        r'Uri\.parse.*getQueryParameter[\s\S]{0,300}new File\(|Uri\.getQueryParameter[\s\S]{0,300}File\.|'
        r'getQueryParameter[\s\S]{0,300}getFilesDir[\s\S]{0,300}\+|getQueryParameter[\s\S]{0,300}getCacheDir[\s\S]{0,300}\+'
    )
    if dl_file_path:
        for dm in dl_file_path[:5]:
            findings.append({
                "id": "ADV-DL-005",
                "name": "Deep Link Query Parameter + getFilesDir Concat — Path Traversal via String Concatenation",
                "description": f"A file path is constructed by concatenating getFilesDir() or getCacheDir() with a deep link query parameter in {dm}. Even if the base directory is safe, string concatenation with user-controlled data allows path traversal. An attacker can craft: 'myapp://action?name=../../databases/webview.db' to write to arbitrary locations.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Never concatenate user-controlled values with directory paths. Use File constructor with a user-controlled filename validated against an allowlist. Use getCanonicalPath().startsWith() to verify the final path is within the intended directory."
            })
    if findings:
        sa.findings.append({"category": "37. Deep Link Path Traversal — File Write via Query Parameter (CVE-2023-36612 style)", "rules": findings})


def detect_deeplink_response_redirect(sa):
    findings = []
    fetch_then_intent = sa._find_methods_by_regex(
        r'(?:HttpURLConnection|OkHttp|volley|Retrofit|HttpClient)[\s\S]{0,500}(?:startActivity|setResult|sendBroadcast|PendingIntent)'
    )
    if fetch_then_intent:
        param_in_both = sa._find_methods_by_regex(
            r'getQueryParameter[\s\S]{0,200}(?:HttpURLConnection|OkHttp|\.url\(|\.load\(|openConnection)[\s\S]{0,500}(?:startActivity|setResult|PendingIntent\.get)'
        )
        if param_in_both:
            for dm in param_in_both[:5]:
                findings.append({
                    "id": "ADV-DL-006",
                    "name": "Deep Link — Server Response Redirected to Third-Party via Intent",
                    "description": f"A deep link query parameter controls both a network request URL and the destination of a resulting Intent or PendingIntent in {dm}. This enables an attacker to make the app fetch data from its own server (containing user session tokens, private info) and then redirect that response to an attacker-controlled app via a crafted Intent. This was the second stage of CVE-2023-36612 (Basecamp): after using path traversal to write files, the attacker could redirect server responses to third-party apps using a malicious deeplink scheme.",
                    "severity": "CRITICAL",
                    "location": dm,
                    "recommendation": "Never allow deep link parameters to control both a network request destination and an Intent destination. Restrict Intent destinations from deep link handlers to specific package names. Use fixed URLs for network requests in deep link flows."
                })
    server_resp_redirect = sa._find_methods_by_regex(
        r'onResponse[\s\S]{0,200}startActivity|onResponse[\s\S]{0,200}setResult|'
        r'onResponse[\s\S]{0,200}sendBroadcast|onSuccess[\s\S]{0,200}startActivity'
    )
    if server_resp_redirect:
        for dm in server_resp_redirect[:3]:
            findings.append({
                "id": "ADV-DL-007",
                "name": "Server Response Handler Starts Activity — Response Content Redirected via Intent",
                "description": f"A network response callback (onResponse/onSuccess) starts an activity or sends a broadcast in {dm}. If the Intent or its data is derived from the response content (e.g., response body, redirect URL), an attacker who can intercept or spoof the server response can redirect sensitive data to a malicious app. In deep link flows, the attacker crafts a deeplink that triggers a network request and controls where the response is forwarded.",
                "severity": "HIGH",
                "location": dm,
                "recommendation": "Validate the destination package and component in startActivity() calls from network response handlers. Do not dynamically construct Intent URIs from response content. Use fixed, known destination components only."
            })
    if findings:
        sa.findings.append({"category": "37. Deep Link Server Response Redirection — Data Leak via Intent (CVE-2023-36612 style)", "rules": findings})


def detect_system_app_bugs(sa):
    findings = []
    shared_uid = [s for s in sa.strings if "android.uid.system" in str(s) or "android.uid.shared" in str(s) or "android.uid.phone" in str(s)]
    if shared_uid:
        for s in shared_uid[:3]:
            findings.append({"id":"ADV-SYS-001","name":"System/Shared UID Reference Found — System UI Privilege Escalation Risk",
                "description":f"System UID reference '{s}' found. Apps running with system UID have elevated privileges. A vulnerability in an app with android:sharedUserId='android.uid.system' can lead to system-level compromise.",
                "severity":"CRITICAL","location":f"string: '{s}'",
                "recommendation":"Avoid using sharedUserId with system UID. If required, minimize the attack surface by reducing exported components."})
    sig_perm = sa._find_methods_by_invoke("Landroid/content/Context;->enforceCallingOrSelfPermission")
    sig_perm_sig = sa._find_methods_by_invoke("Landroid/content/Context;->enforceCallingPermission")
    if sig_perm or sig_perm_sig:
        dangerous_sigs = sa._find_methods_by_regex(r'signatureOrSystem|signature.*permission|permission.*signature')
        if dangerous_sigs:
            findings.append({"id":"ADV-SYS-002","name":"Signature-Level Permission Enforced — Review Permission Scope",
                "description":"Signature-level permissions are enforced. Apps signed with the same platform key can access these protected components. Review whether all platform-signed apps should have access.",
                "severity":"HIGH","location":"bytecode analysis",
                "recommendation":"Use 'signature' protection level (not 'signatureOrSystem'). Review which apps share the platform signature."})
    platform_key = [s for s in sa.strings if any(kw in str(s) for kw in ["platform.*key", "testkey", "releasekey", "android.uid.system"])]
    if platform_key:
        findings.append({"id":"ADV-SYS-003","name":"Platform/System Key References — System App Privilege Escalation Risk",
            "description":f"Platform key references found in strings: {', '.join(platform_key[:3])}. Apps signed with platform keys run with system-level privileges.",
            "severity":"CRITICAL","location":"bytecode analysis",
            "recommendation":"Never use platform-level sharedUserId. If required, restrict exported components to the absolute minimum."})
    if findings:
        sa.findings.append({"category":"29. System App Vulnerabilities — Shared UID / Platform Key Abuse / Signature Permission Issues","rules":findings})


def detect_hardcoded_secrets(sa):
    findings = []
    api_key_patterns = [
        (r'["\'](?:api[_-]?key|apikey|api_key)["\']\s*[:=]\s*["\'][A-Za-z0-9+/=]{16,}["\']', "API Key"),
        (r'["\'](?:secret|client_secret)["\']\s*[:=]\s*["\'][A-Za-z0-9+/=]{8,}["\']', "Client Secret"),
        (r'["\'](?:access_token|accesstoken)["\']\s*[:=]\s*["\'][A-Za-z0-9_-]{20,}["\']', "Access Token"),
        (r'["\'](?:bearer|token)["\']\s*[:=]\s*["\'][A-Za-z0-9._-]{20,}["\']', "Bearer Token"),
        (r'["\'](?:password|passwd)["\']\s*[:=]\s*["\'][^"\']{6,}["\']', "Hardcoded Password"),
        (r'["\'](?:jwt|JWT)["\']\s*[:=]\s*["\'][A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+["\']', "JWT Token"),
        (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', "Private Key (PEM)"),
    ]
    for pattern, label in api_key_patterns:
        matches = sa._string_in_source(pattern)
        for m in matches[:3]:
            findings.append({"id":"ADV-SECRET-001","name":f"Potential {label} Hardcoded in Source",
                "description":f"A potential {label.lower()} was found in source code: {m[:120]}.",
                "severity":"CRITICAL","location":m,
                "recommendation":"Remove hardcoded secrets from source code. Use Android Keystore, BuildConfig with Gradle, or a secrets management service. Never commit secrets to version control."})
    if findings:
        sa.findings.append({"category":"30. Hardcoded Secrets — API Keys / Tokens / Passwords / Private Keys","rules":findings})


def detect_sensitive_data_leakage(sa):
    findings = []
    logger_methods = sa._find_methods_by_regex(r'Log\.(d|v|i|w|e)\([^)]*(password|token|secret|key|credential|pin|otp|jwt|bearer|auth|ssn|social|credit|card|cvv|cvc|expiry|iban)')
    for dm in logger_methods[:5]:
        findings.append({"id":"ADV-LEAK-001","name":"Sensitive Data Logged — PII/Credentials in Logcat",
            "description":f"Sensitive keywords logged in {dm}. Logcat is readable by any app with READ_LOGS permission (pre-API 24) and via ADB.",
            "severity":"HIGH","location":dm,
            "recommendation":"Never log PII, credentials, or tokens. Remove all debug logging in release builds using ProGuard."})
    intent_leak = sa._find_methods_by_regex(r'putExtra.*(password|token|secret|key|credential|pin|otp|jwt|bearer|auth)')
    if intent_leak:
        for dm in intent_leak[:5]:
            findings.append({"id":"ADV-LEAK-002","name":"Sensitive Data in Intent Extras — Data Leakage via IPC",
                "description":f"Sensitive data put into Intent extras in {dm}. Intent data is visible to receiving components and logged by the system.",
                "severity":"HIGH","location":dm,
                "recommendation":"Use setPackage() on intents containing sensitive data. Consider using a secure channel like EncryptedSharedPreferences + a reference ID instead of passing sensitive values in Intent extras."})
    notification_leak = sa._find_methods_by_regex(r'Notification\.Builder.*setContentText.*(password|token|secret|key|credential|pin|otp|jwt|bearer|auth|ssn|credit|card)')
    if notification_leak:
        for dm in notification_leak[:3]:
            findings.append({"id":"ADV-LEAK-003","name":"Sensitive Data in Notification — Visible on Lock Screen",
                "description":f"Sensitive data appears in notification in {dm}. Notifications are visible on the lock screen and can be read by accessibility services.",
                "severity":"HIGH","location":dm,
                "recommendation":"Set setVisibility(VISIBILITY_PRIVATE) on notifications with sensitive content. Redact personal data from notification text."})
    if findings:
        sa.findings.append({"category":"31. Sensitive Data Leakage — Logcat / Intent / Notification / File","rules":findings})


def detect_command_injection_advanced(sa):
    findings = []
    proc_builder = sa._find_methods_by_invoke("Ljava/lang/ProcessBuilder;-><init>")
    if proc_builder:
        for dm in proc_builder[:3]:
            findings.append({"id":"ADV-CMD-010","name":"ProcessBuilder Used — Command Injection Surface",
                "description":f"ProcessBuilder in {dm}. If any argument contains user-controlled input, command injection is possible.",
                "severity":"CRITICAL","location":dm,
                "recommendation":"Avoid ProcessBuilder with user input. If required, validate and sanitize each argument against a strict allowlist. Use array-based arguments, never string concatenation."})
    proc_builder_redirect = sa._find_methods_by_invoke("Ljava/lang/ProcessBuilder;->redirectErrorStream")
    redirect = sa._find_methods_by_regex(r'ProcessBuilder.*redirect|Runtime\.exec.*2>&1|Runtime\.exec.*redirect')
    if redirect and proc_builder:
        findings.append({"id":"ADV-CMD-011","name":"ProcessBuilder with Error Stream Redirect — Information Leakage",
            "description":"ProcessBuilder redirects error stream to standard output. Error messages may contain paths, stack traces, or other information useful to attackers.",
            "severity":"MEDIUM","location":"bytecode analysis",
            "recommendation":"Handle error and output streams separately. Do not merge stderr into stdout if error messages contain sensitive information."})
    shell_exec = sa._find_methods_by_regex(r'Runtime\.exec\([^)]*(sh\s+-c|bash\s+-c|/system/bin/sh|cmd\s+/c)')
    if shell_exec:
        for dm in shell_exec[:3]:
            findings.append({"id":"ADV-CMD-012","name":"Shell Execution via Runtime.exec(sh -c ...) — Full Shell Injection Risk",
                "description":f"Shell execution via sh/bash in {dm}. Shell metacharacters in user input lead to full command injection.",
                "severity":"CRITICAL","location":dm,
                "recommendation":"Never use sh -c with Runtime.exec(). Use ProcessBuilder with individual arguments instead."})
    if findings:
        sa.findings.append({"category":"36. Command Injection Advanced — ProcessBuilder / Shell / Redirect","rules":findings})


def detect_shell_command_injection_receiver(sa):
    findings = []
    exported_receivers = [r for r in sa.manifest_components.get("receivers", [])
                          if r.get("exported") in ("true", None, "")]
    if exported_receivers:
        exec_in_receiver = sa._find_methods_by_regex(
            r'onReceive.*Runtime\.exec|onReceive.*ProcessBuilder|'
            r'onReceive.*getStringExtra.*exec|onReceive.*getData.*exec|'
            r'onReceive.*getStringExtra.*Runtime|onReceive.*getData.*Runtime'
        )
        if exec_in_receiver:
            for dm in exec_in_receiver[:5]:
                findings.append({
                    "id": "ADV-CMD-020",
                    "name": "Shell Command Injection via Exported BroadcastReceiver — Intent Data to Runtime.exec",
                    "description": f"Exported BroadcastReceiver calls Runtime.exec() or ProcessBuilder with Intent data in {dm}. An attacker can send a malicious broadcast with shell metacharacters in Intent extras (e.g., ';id>/data/data/pkg/cmd.txt;') to execute arbitrary commands as the app process. This was a real vulnerability in Xiaomi system apps where an exported receiver invoked 'sh' with intent data, allowing command injection as the system UID.",
                    "severity": "CRITICAL",
                    "location": dm,
                    "recommendation": "Never pass Intent data directly to Runtime.exec() or ProcessBuilder. Use array-based ProcessBuilder arguments (never string concatenation). Validate and sanitize all input before shell execution. Consider removing exported status from receivers that execute shell commands."
                })
    receiver_exec = sa._find_methods_by_invoke(
        "Landroid/content/BroadcastReceiver;->onReceive"
    )
    if receiver_exec:
        cmd_from_intent = sa._find_methods_by_regex(
            r'onReceive.*getStringExtra[\s\S]{0,200}sh\s+-c|onReceive.*getData[\s\S]{0,200}sh\s+-c'
        )
        if cmd_from_intent:
            for dm in cmd_from_intent[:3]:
                findings.append({
                    "id": "ADV-CMD-021",
                    "name": "Shell Command via 'sh -c' in BroadcastReceiver — Full Shell Injection",
                    "description": f"BroadcastReceiver executes 'sh -c' with Intent-derived data in {dm}. When 'sh -c' is used, shell metacharacters (';', '|', '`', '$()') in user-controlled input achieve arbitrary command execution with the app's UID.",
                    "severity": "CRITICAL",
                    "location": dm,
                    "recommendation": "Never use 'sh -c' with Runtime.exec(). Replace with ProcessBuilder and array arguments. Validate all input against an allowlist of safe characters."
                })
    if findings:
        sa.findings.append({"category": "37. Shell Command Injection via BroadcastReceiver — Xiaomi-Style System App Abuse", "rules": findings})


def detect_spanned_html_injection(sa):
    findings = []
    from_html = sa._find_methods_by_invoke(
        "Landroid/text/Html;->fromHtml"
    )
    if from_html:
        intent_to_html = sa._find_methods_by_regex(
            r'Html\.fromHtml.*getStringExtra|Html\.fromHtml.*getData|'
            r'Html\.fromHtml.*getQueryParameter|Html\.fromHtml.*EXTRA_'
        )
        if intent_to_html:
            for dm in intent_to_html[:5]:
                findings.append({
                    "id": "ADV-UI-001",
                    "name": "HTML Injection via Spanned/fromHtml with Intent Data — UI Manipulation",
                    "description": f"Html.fromHtml() is called with Intent-derived data in {dm}. When untrusted HTML is rendered in UI elements (TextView, Notification, AlertDialog), attackers can inject arbitrary HTML tags including <a> (open URLs), <img> (leak IP), <script> (ignored in TextView but not web-based renderers), and <font> (phishing). This was a real vulnerability in Google Pixel's Device Admin Settings screen: an attacker with root access could inject HTML via the admin description field, enabling phishing and UI redressing.",
                    "severity": "HIGH",
                    "location": dm,
                    "recommendation": "Never pass untrusted data to Html.fromHtml(). Use TextUtils.htmlEncode() to escape HTML entities. For user-displayed text, use setText() without HTML formatting. If HTML rendering is required, allow only safe tags (<b>, <i>, <u>) with Html.fromHtml(source, flags, handler, ImageGetter)."
                })
        spanned_in_textview = sa._find_methods_by_regex(
            r'setText.*fromHtml|fromHtml.*append|fromHtml.*setText'
        )
        if spanned_in_textview:
            for dm in spanned_in_textview[:5]:
                findings.append({
                    "id": "ADV-UI-002",
                    "name": "Spanned HTML Rendered in TextView — Click Injection / URL Spoofing Risk",
                    "description": f"Html.fromHtml() output is set on a TextView in {dm}. HTML <a> tags create clickable links that open in the default browser. An attacker controlling the HTML content can create phishing links that appear as legitimate buttons or text, redirecting users to malicious sites.",
                    "severity": "MEDIUM",
                    "location": dm,
                    "recommendation": "Remove or sanitize <a> tags from HTML before rendering in TextView. Use LinkMovementMethod with custom URL handling to validate all clicked URLs against an allowlist."
                })
    if findings:
        sa.findings.append({"category": "37. HTML/Spanned Injection — fromHtml UI Manipulation / Click Injection", "rules": findings})


def detect_gson_deserialization(sa):
    findings = []
    gson_from_json = sa._find_methods_by_invoke(
        "Lcom/google/gson/Gson;->fromJson"
    )
    if gson_from_json:
        for dm in gson_from_json[:3]:
            findings.append({
                "id": "ADV-SERIAL-010",
                "name": "Gson.fromJson() — Deserialization of Untrusted JSON",
                "description": f"Gson.fromJson() is used in {dm}. When deserializing JSON from untrusted sources (Intent extras, network responses, broadcast data), Gson can instantiate arbitrary classes with attacker-controlled fields if the target type is too broad (Object, Map, JsonElement, or parameterized types). This was exploited in Xiaomi's LiveEventBus where Gson deserialization with a broad type led to memory corruption via crafted JSON that triggered unexpected object instantiation patterns in the Android runtime.",
                "severity": "HIGH",
                "location": dm,
                "recommendation": "Always specify the exact class type for Gson deserialization. Never use Object.class, Map.class, or JsonElement.class as the target type for untrusted data. Use @SerializedName annotations and validate all deserialized fields. Consider using a type adapter whitelist for security-critical deserialization."
            })
        json_element = sa._find_methods_by_regex(
            r'fromJson.*JsonElement\.class|fromJson.*Object\.class|fromJson.*Map\.class|fromJson.*List\.class'
        )
        if json_element:
            for dm in json_element[:3]:
                findings.append({
                    "id": "ADV-SERIAL-011",
                    "name": "Gson.fromJson() with Broad Type — Arbitrary Object Instantiation",
                    "description": f"Gson.fromJson() uses a broad type (JsonElement, Object, Map, List) in {dm}. This allows the JSON payload to control the concrete types instantiated during deserialization. Attackers can force the creation of classes with dangerous constructors, finalize() methods, or classes that trigger side effects during deserialization, potentially leading to memory corruption or denial of service.",
                    "severity": "CRITICAL",
                    "location": dm,
                    "recommendation": "Always specify the exact target class for Gson deserialization. Use a custom TypeAdapterFactory or @JsonAdapter to restrict which types can be deserialized. For security-sensitive contexts, validate the JSON structure before deserialization."
                })
    if findings:
        sa.findings.append({"category": "37. Gson Deserialization — Untrusted JSON / Arbitrary Object Instantiation", "rules": findings})


def detect_arbitrary_service_binding(sa):
    findings = []
    bind_svc = sa._find_methods_by_invoke(
        "Landroid/content/Context;->bindService"
    )
    create_pkg_context = sa._find_methods_by_invoke(
        "Landroid/content/Context;->createPackageContext"
    )
    if bind_svc and create_pkg_context:
        svc_from_intent = sa._find_methods_by_regex(
            r'bindService.*getStringExtra|bindService.*getData|'
            r'createPackageContext.*getStringExtra|createPackageContext.*getData'
        )
        if svc_from_intent:
            for dm in svc_from_intent[:5]:
                findings.append({
                    "id": "ADV-SERVICE-010",
                    "name": "Arbitrary Service Binding via createPackageContext + bindService — System Privilege Escalation",
                    "description": f"App uses createPackageContext() with CONTEXT_INCLUDE_CODE and bindService() using Intent data in {dm}. When a system app provides an SDK that accepts service names from calling apps, the calling app can request binding to any service in the system app's process. If the system app runs with sharedUserId='android.uid.system', the caller achieves arbitrary service binding with system privileges. This was a real vulnerability in Xiaomi's system SDK where a proxy service in a system-privileged app bound to arbitrary services requested by third-party apps, enabling privilege escalation.",
                    "severity": "CRITICAL",
                    "location": dm,
                    "recommendation": "Never bind to services based on caller-controlled Intent data when running with elevated privileges. Maintain an allowlist of permitted services or Intent actions. Do not use createPackageContext(CONTEXT_INCLUDE_CODE) when the target package runs with system privileges."
                })
    system_uid_svc = [s for s in sa.manifest_components.get("services", [])
                      if s.get("exported") in ("true", None, "")]
    intent_forwarding = sa._find_methods_by_regex(
        r'onStart.*getIntent.*startService|onBind.*getIntent.*startService|'
        r'onStartCommand.*getIntent.*startService|onStart.*getIntent.*bindService'
    )
    if system_uid_svc and intent_forwarding:
        for dm in intent_forwarding[:3]:
            findings.append({
                "id": "ADV-SERVICE-011",
                "name": "Service Intent Forwarding — Proxy Service Abuse",
                "description": f"An exported service forwards incoming Intents to startService()/bindService() in {dm}. This creates a proxy service pattern: any app can call startService() on the exported proxy, which then starts/binds arbitrary services with the proxy app's privileges. If the proxy app has system or signature-level permissions, this is a privilege escalation vector.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Do not forward incoming Intents from exported services to startService()/bindService(). If forwarding is required, validate the target Intent action against an allowlist and never allow the caller to control the target package or class name."
            })
    if findings:
        sa.findings.append({"category": "37. Arbitrary Service Binding — System Privilege Escalation via Proxy Service", "rules": findings})


def detect_exported_component_abuse(sa):
    findings = []
    activities = sa.manifest_components.get("activities", [])
    services = sa.manifest_components.get("services", [])
    receivers = sa.manifest_components.get("receivers", [])
    providers = sa.manifest_components.get("providers", [])

    exported_activities = [a for a in activities if a.get("exported") in ("true", None, "")]
    exported_services = [s for s in services if s.get("exported") in ("true", None, "")]
    exported_receivers = [r for r in receivers if r.get("exported") in ("true", None, "")]
    exported_providers = [p for p in providers if p.get("exported") in ("true", None, "")]

    for act in exported_activities[:5]:
        findings.append({"id":"ADV-EXP-101","name":f"Exported Activity — {act['name']}",
            "description":f"Activity '{act['name']}' is exported without protection. Any app can launch it, potentially bypassing authentication or accessing sensitive functionality.",
            "severity":"HIGH","location":f"AndroidManifest: {act['name']}",
            "recommendation":"Set android:exported='false' if internal. Implement permission checks in exported Activity entry points."})
    if len(exported_services) >= 3:
        findings.append({"id":"ADV-EXP-102","name":f"Multiple Exported Services ({len(exported_services)}) — Service Abuse Risk",
            "description":f"{len(exported_services)} services are exported. Malicious apps can start/bind exported services indefinitely, draining battery and resources.",
            "severity":"MEDIUM","location":"AndroidManifest analysis",
            "recommendation":"Add permissions to exported services. Implement rate limiting in service onCreate()."})
    if findings:
        sa.findings.append({"category":"36. Exported Component Abuse Advanced — Arbitrary Component Invocation","rules":findings})


def detect_manifest_allow_backup(sa):
    findings = []
    try:
        manifest = sa.apk.get_android_manifest_xml()
        if manifest is not None:
            ns = {'android': 'http://schemas.android.com/apk/res/android'}
            app_el = manifest.find("application")
            if app_el is not None:
                backup_val = app_el.get(f"{{{ns['android']}}}allowBackup")
                if backup_val is None:
                    findings.append({
                        "id": "ADV-MANIFEST-001",
                        "name": "Android:allowBackup Not Explicitly Set — Default Enabled",
                        "description": "android:allowBackup is not set in the <application> tag, defaulting to 'true'. Any app with ADB access can use 'adb backup' to extract all app data (databases, shared preferences, files) to an external device, including encrypted databases if the attacker has the password.",
                        "severity": "HIGH",
                        "location": "AndroidManifest.xml <application>",
                        "recommendation": "Set android:allowBackup='false' for production. If backup is needed, use android:fullBackupContent to restrict which data is backed up."
                    })
                elif backup_val.lower() == "true":
                    findings.append({
                        "id": "ADV-MANIFEST-002",
                        "name": "Android:allowBackup Enabled — Data Theft via ADB Backup",
                        "description": "android:allowBackup='true' enables full app data backup via ADB. An attacker with USB access or on a compromised workstation can run 'adb backup com.example.app' to extract all app data, including session tokens, encryption keys, and user credentials.",
                        "severity": "HIGH",
                        "location": "AndroidManifest.xml <application>",
                        "recommendation": "Set android:allowBackup='false' for production builds. If backup is essential, use android:fullBackupContent to specify a restricted set of data to back up."
                    })
    except Exception:
        pass
    if findings:
        sa.findings.append({"category": "38. Manifest Configuration — Backup & Debug Flags", "rules": findings})


def detect_manifest_debuggable(sa):
    findings = []
    try:
        manifest = sa.apk.get_android_manifest_xml()
        if manifest is not None:
            ns = {'android': 'http://schemas.android.com/apk/res/android'}
            app_el = manifest.find("application")
            if app_el is not None:
                debuggable_val = app_el.get(f"{{{ns['android']}}}debuggable")
                if debuggable_val is not None and debuggable_val.lower() == "true":
                    findings.append({
                        "id": "ADV-MANIFEST-003",
                        "name": "Android:debuggable Enabled — Arbitrary Code Execution via ADB",
                        "description": "android:debuggable='true' allows any ADB-connected user to run 'run-as com.example.app' and execute arbitrary code in the app's context, read/write all app-private data, install arbitrary APKs, and access all protected app components. This completely bypasses Android's sandbox.",
                        "severity": "CRITICAL",
                        "location": "AndroidManifest.xml <application>",
                        "recommendation": "Set android:debuggable='false' for all production releases. Debug builds should never be distributed to users."
                    })
    except Exception:
        pass
    if findings:
        sa.findings.append({"category": "38. Manifest Configuration — Backup & Debug Flags", "rules": findings})


def detect_keyboard_cache(sa):
    findings = []
    has_sensitive_fields = bool(
        sa._find_methods_by_regex(r'password|pin|otp|credit.*card|cvv|cvc|ssn|security.*code')
        or sa._find_methods_by_regex(r'(Login|SignIn|Payment|Checkout|PinEntry|Otp).*(Activity|Fragment)')
    )
    has_keyboard_cache_protection = bool(
        sa._find_methods_by_string("textNoSuggestions")
        or sa._find_methods_by_string("TYPE_TEXT_FLAG_NO_SUGGESTIONS")
        or sa._find_methods_by_invoke("Landroid/text/InputType;->TYPE_TEXT_FLAG_NO_SUGGESTIONS")
        or sa._find_methods_by_invoke("Landroid/text/InputType;->TYPE_TEXT_VARIATION_VISIBLE_PASSWORD")
    )
    if has_sensitive_fields and not has_keyboard_cache_protection:
        findings.append({
            "id": "ADV-KEYCACHE-001",
            "name": "Keyboard Cache/Suggestions Not Disabled on Sensitive Input — MASVS-STORAGE-2",
            "description": "The app accepts sensitive input (passwords, PINs, credit card numbers, OTPs) but does not disable keyboard suggestions/caching. The device keyboard may store entered text in its dictionary cache, making it accessible to other apps on the device or recoverable from keyboard app data.",
            "severity": "HIGH",
            "location": "bytecode analysis",
            "recommendation": "Set android:inputType='textNoSuggestions' on all sensitive EditText fields, or use InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS / TYPE_TEXT_VARIATION_VISIBLE_PASSWORD programmatically. Never allow keyboard caching on password, PIN, OTP, credit card, or other credential fields."
        })
    if findings:
        sa.findings.append({"category": "39. Keyboard Cache & Input Type Security (MASVS-STORAGE-2)", "rules": findings})


def detect_stepup_authentication(sa):
    findings = []
    has_biometric = bool(
        sa._find_methods_by_invoke("Landroid/hardware/biometrics/BiometricPrompt")
        or sa._find_methods_by_invoke("Landroid/hardware/fingerprint/FingerprintManager")
        or sa._find_methods_by_invoke("Landroid/app/KeyguardManager;->createConfirmDeviceCredentialIntent")
        or sa._find_methods_by_invoke("Landroidx/biometric/BiometricPrompt")
        or sa._find_methods_by_regex(r'BiometricPrompt|FingerprintManager|createConfirmDeviceCredential')
    )
    exported_deeplink_activities = []
    for act in sa.manifest_components.get("activities", []):
        if act.get("exported") in ("true", None, ""):
            intent_filters = act.get("intent_filters", [])
            for filt in intent_filters:
                actions = filt.get("actions", [])
                if any("VIEW" in a for a in actions):
                    exported_deeplink_activities.append(act["name"])
                    break
    if exported_deeplink_activities and not has_biometric:
        for act_name in exported_deeplink_activities[:3]:
            findings.append({
                "id": "ADV-AUTH-010",
                "name": f"No Step-Up Authentication on Exported Deep Link Activity — MASVS-AUTH-3",
                "description": f"Activity '{act_name}' is exported with a VIEW intent filter (deep link) but the app does not use biometric or step-up authentication. If the app handles sensitive data (payments, account settings, personal info), deep link entry points should be protected by step-up authentication to prevent bypass of login/biometric locks via direct deep link invocation.",
                "severity": "HIGH",
                "location": f"AndroidManifest: {act_name}",
                "recommendation": "Implement step-up authentication (BiometricPrompt, KeyguardManager.createConfirmDeviceCredentialIntent) in all exported deep link handler activities. Require re-authentication before processing sensitive actions from deep links."
            })
    if has_biometric and exported_deeplink_activities:
        findings.append({
            "id": "ADV-AUTH-011",
            "name": f"Biometric Auth Present but {len(exported_deeplink_activities)} Exported Deep Link Activities — Potential Auth Bypass",
            "description": f"The app implements biometric authentication but has {len(exported_deeplink_activities)} exported activities with deep link intent filters. If the biometric check is only in the launcher/home activity, deep link handlers may bypass authentication entirely. This was the pattern in HackerOne #637194 (Shopify biometric bypass).",
            "severity": "CRITICAL",
            "location": "AndroidManifest analysis",
            "recommendation": "Ensure every exported deep link activity independently verifies the user's authentication state. Consider using setConfirmCredential or a centralized auth check in each activity's onCreate()."
        })
    if findings:
        sa.findings.append({"category": "39. Step-Up Authentication & Biometric Bypass (MASVS-AUTH-3)", "rules": findings})


def detect_min_sdk_version(sa):
    findings = []
    try:
        min_sdk = sa.apk.get_min_sdk_version()
    except Exception:
        min_sdk = None
    if min_sdk is not None:
        min_sdk = int(min_sdk)
        if min_sdk < 21:
            findings.append({
                "id": "ADV-MANIFEST-010",
                "name": f"Minimum SDK Version ({min_sdk}) Below 21 — No ART Security Features",
                "description": f"minSdkVersion={min_sdk} is below API 21 (Android 5.0). Versions below 21 lack ART runtime security improvements, the modern permission model, and receive no security patches. Apps supporting these versions must support the legacy security model.",
                "severity": "CRITICAL",
                "location": "AndroidManifest.xml <uses-sdk>",
                "recommendation": "Set minSdkVersion to at least 21 (Android 5.0). For better security, target 23+ for runtime permissions or 26+ for background execution limits."
            })
        elif min_sdk < 23:
            findings.append({
                "id": "ADV-MANIFEST-011",
                "name": f"Minimum SDK Version ({min_sdk}) Below 23 — No Runtime Permission Model",
                "description": f"minSdkVersion={min_sdk} is below API 23 (Android 6.0). Apps supporting these versions must use the install-time permission model, which grants all permissions at install time without user consent. Runtime permission enforcement is unavailable.",
                "severity": "HIGH",
                "location": "AndroidManifest.xml <uses-sdk>",
                "recommendation": "Raise minSdkVersion to at least 23 (Android 6.0) to enforce the runtime permission model, allowing users to grant/revoke permissions individually."
            })
        else:
            findings.append({
                "id": "ADV-MANIFEST-012",
                "name": f"Minimum SDK Version ({min_sdk}) — Acceptable (API 23+)",
                "description": f"minSdkVersion={min_sdk} is at least API 23, meaning the runtime permission model is available.",
                "severity": "INFO",
                "location": "AndroidManifest.xml <uses-sdk>",
                "recommendation": "Monitor for new API level requirements. Consider increasing to API 26+ for background execution limits and API 29+ for scoped storage."
            })
    try:
        target_sdk = sa.apk.get_target_sdk_version()
    except Exception:
        target_sdk = None
    if target_sdk is not None:
        target_sdk = int(target_sdk)
        if target_sdk < 31:
            findings.append({
                "id": "ADV-MANIFEST-013",
                "name": f"Target SDK Version ({target_sdk}) Below 31 — Missing Android 12+ Security Enhancements",
                "description": f"targetSdkVersion={target_sdk} is below API 31 (Android 12). Apps targeting below 31 opt out of Android 12+ security features including: exported component defaults becoming safer, PendingIntent mutability requirements, and safer intent handling.",
                "severity": "MEDIUM",
                "location": "AndroidManifest.xml <uses-sdk>",
                "recommendation": "Update targetSdkVersion to at least 31 (Android 12) to benefit from the latest platform security improvements and mandatory PendingIntent mutability requirements."
            })
    if findings:
        sa.findings.append({"category": "39. SDK Version Configuration (MASVS-CODE-1)", "rules": findings})


def detect_enforced_updating(sa):
    findings = []
    has_update_checking = bool(
        sa._find_methods_by_invoke("Lcom/google/android/play/core/appupdate/AppUpdateManager")
        or sa._find_methods_by_invoke("Lcom/google/android/play/core/appupdate/AppUpdateManagerFactory")
        or sa._find_methods_by_invoke("Lcom/google/android/gms/common/GooglePlayServicesUtil")
        or sa._find_methods_by_regex(r'getPackageInfo.*versionCode')
        or sa._find_methods_by_regex(r'getPackageInfo.*GET_SIGNATURES')
        or sa._find_methods_by_regex(r'versionCode.*BuildConfig|BuildConfig.*versionCode')
        or sa._find_methods_by_regex(r'versionCode|VERSION_CODE|version_name|VERSION_NAME')
    )
    if not has_update_checking:
        findings.append({
            "id": "ADV-UPDATE-001",
            "name": "No In-App Update Checking Detected — MASVS-CODE-2",
            "description": "The app does not appear to check for updates at runtime. Without enforced updating, users may run outdated versions with known vulnerabilities, including publicly disclosed CVEs. Active attackers can serve malicious payloads targeting known platform or library vulnerabilities in older app versions.",
            "severity": "MEDIUM",
            "location": "bytecode analysis",
            "recommendation": "Implement in-app update checking using Play Core's AppUpdateManager (in-app updates API) or a custom update server. For critical security fixes, consider requiring the latest version to proceed, with a grace period for user convenience."
        })
    if findings:
        sa.findings.append({"category": "39. Enforced Updating (MASVS-CODE-2)", "rules": findings})


def detect_runtime_integrity(sa):
    findings = []
    has_integrity_checking = bool(
        sa._find_methods_by_invoke("Landroid/content/pm/PackageManager;->checkSignatures")
        or sa._find_methods_by_invoke("Landroid/content/pm/PackageManager;->getPackageInfo")
        or sa._find_methods_by_regex(r'GET_SIGNATURES|GET_SIGNING_CERTIFICATES')
        or sa._find_methods_by_regex(r'PackageInfo.*signatures|signatures.*PackageInfo')
        or sa._find_methods_by_regex(r'Signature\[\].*signatures|signatures.*Signature')
        or sa._find_methods_by_string("signatures")
        or sa._find_methods_by_regex(r'apkSignature|signingCertificate|certificate.*chain')
        or sa._find_methods_by_invoke("Landroid/content/pm/Signature")
        or sa._find_methods_by_regex(r'SigningInfo|getSigningCertificateHistory')
    )
    has_signature_verification = bool(
        sa._find_methods_by_invoke("Landroid/content/pm/PackageManager;->checkSignatures")
        or sa._find_methods_by_regex(r'checkSignatures|verifySignature|verify.*signature')
    )
    if not has_integrity_checking:
        findings.append({
            "id": "ADV-INTEGRITY-001",
            "name": "No Runtime Integrity / Code Signing Verification — MASVS-RESILIENCE-2",
            "description": "The app does not verify its own code signature or integrity at runtime. A repackaged or tampered version of the APK (e.g., modified by an attacker to remove security checks, inject ads, or steal data) will not be detected. This is a fundamental weakness against repackaging attacks.",
            "severity": "HIGH",
            "location": "bytecode analysis",
            "recommendation": "Implement runtime integrity checks: verify the APK signature using PackageManager.GET_SIGNATURES + PackageManager.checkSignatures(), or use SafetyNet Attestation / Play Integrity API. Compare the installed app's signature against the expected developer signature."
        })
    else:
        if not has_signature_verification:
            findings.append({
                "id": "ADV-INTEGRITY-002",
                "name": "Partial Integrity Checking — Signature References Found But No Signature Comparison",
                "description": "The app references signature or integrity related APIs but may not perform actual signature comparison. Simply calling getPackageInfo(GET_SIGNATURES) without comparing the result against a known-good signature does not provide tamper protection.",
                "severity": "MEDIUM",
                "location": "bytecode analysis",
                "recommendation": "Ensure signature verification includes a comparison step: call checkSignatures() or compare each signature element against a hardcoded certificate hash. Consider using the Play Integrity API as a stronger alternative."
            })
    if findings:
        sa.findings.append({"category": "39. Runtime Integrity / Code Signing (MASVS-RESILIENCE-2)", "rules": findings})


def detect_anti_debugging(sa):
    findings = []
    has_anti_debugging = bool(
        sa._find_methods_by_string("isDebuggerConnected")
        or sa._find_methods_by_string("waitForDebugger")
        or sa._find_methods_by_string("TracerPid")
        or sa._find_methods_by_string("ro.debuggable")
        or sa._find_methods_by_invoke("Landroid/os/Debug;->isDebuggerConnected")
        or sa._find_methods_by_invoke("Landroid/os/Debug;->waitForDebugger")
        or sa._find_methods_by_regex(r'TracerPid|/proc/self/status|/proc/self/cmdline')
    )
    if not has_anti_debugging:
        sensitive_activities = sa._find_methods_by_regex(
            r'(Login|SignIn|Payment|Checkout|Pin|Otp|Banking|Wallet|Transaction|Secure).*(Activity|Fragment)'
        )
        if sensitive_activities:
            findings.append({
                "id": "ADV-ANTIDBG-001",
                "name": "No Anti-Debugging Protection on Sensitive App — MASVS-RESILIENCE-4",
                "description": "The app handles sensitive data but lacks anti-debugging protections. An attacker with USB debugging access (ADB) can attach a debugger (jdwp) to the app process, inspect variables, modify memory, bypass authentication checks, and extract sensitive data at runtime. Even on production devices, an attacker with physical access or a compromised workstation can enable debugging.",
                "severity": "HIGH",
                "location": "bytecode analysis",
                "recommendation": "Implement anti-debugging checks using android.os.Debug.isDebuggerConnected(), check /proc/self/status for TracerPid != 0, and verify ro.debuggable system property. Note: these are anti-tampering controls and should be layered with obfuscation to prevent trivial bypass."
            })
    if findings:
        sa.findings.append({"category": "39. Anti-Debugging Protections (MASVS-RESILIENCE-4)", "rules": findings})


def detect_overlay_tapjacking(sa):
    findings = []
    has_tapjacking_protection = bool(
        sa._find_methods_by_string("FLAG_WATCH_OUTSIDE_TOUCH")
        or sa._find_methods_by_string("setFilterTouchesWhenObscured")
        or sa._find_methods_by_string("filterTouchesWhenObscured")
        or sa._find_methods_by_invoke("Landroid/view/WindowManager$LayoutParams;->FLAG_WATCH_OUTSIDE_TOUCH")
        or sa._find_methods_by_regex(r'setFilterTouchesWhenObscured\(.*true|setFlags.*FLAG_WATCH_OUTSIDE_TOUCH')
    )
    sensitive_activities = sa._find_methods_by_regex(
        r'(Login|SignIn|Payment|Checkout|Pin|Otp|Password|Secure|Confirm).*(Activity|Fragment)'
    )
    if sensitive_activities and not has_tapjacking_protection:
        findings.append({
            "id": "ADV-TAPJACK-001",
            "name": "No Tapjacking/Overlay Protection on Sensitive Activities — MASVS-PLATFORM-3",
            "description": "The app has sensitive activities (login, payment, PIN entry) but does not implement tapjacking/overlay protection. A malicious app can draw a transparent overlay on top of the victim app, intercepting taps and clicks. The user thinks they are tapping a legitimate button but actually taps on a malicious overlay element controlled by the attacker, enabling click hijacking and credential theft.",
            "severity": "HIGH",
            "location": "bytecode analysis",
            "recommendation": "For sensitive activities, add android:filterTouchesWhenObscured='true' to the root layout in XML, or call getWindow().setFlags(WindowManager.LayoutParams.FLAG_WATCH_OUTSIDE_TOUCH, WindowManager.LayoutParams.FLAG_WATCH_OUTSIDE_TOUCH) in onCreate(), combined with setFilterTouchesWhenObscured(true)."
        })
    if findings:
        sa.findings.append({"category": "39. Tapjacking/Overlay Protection (MASVS-PLATFORM-3)", "rules": findings})


def detect_nfe_dos(sa):
    findings = []
    nfe_sinks = [
        r'Integer\.parseInt\([^)]*getStringExtra',
        r'Integer\.parseInt\([^)]*getData\b',
        r'Integer\.valueOf\([^)]*getStringExtra',
        r'Long\.parseLong\([^)]*getStringExtra',
        r'Long\.valueOf\([^)]*getStringExtra',
        r'Double\.parseDouble\([^)]*getStringExtra',
        r'Float\.parseFloat\([^)]*getStringExtra',
        r'Short\.parseShort\([^)]*getStringExtra',
        r'Byte\.parseByte\([^)]*getStringExtra',
    ]
    for pat in nfe_sinks:
        matches = sa._find_methods_by_regex(pat)
        for dm in matches[:3]:
            findings.append({
                "id": "ADV-NFE-001",
                "name": "NumberFormatException DoS — parseInt/parseLong on Intent Extra (CWE-755)",
                "description": f"Number parsing called on untrusted intent extra in {dm}. A malicious app can send an intent with a non-numeric string extra, causing an unhandled NumberFormatException that crashes the app (Local Denial of Service). This is a CWE-755 pattern from real vulnerabilities in multiple Android apps.",
                "severity": "HIGH",
                "location": dm,
                "recommendation": "Wrap number parsing from intent extras in try/catch(NumberFormatException). Use TextUtils.isDigitsOnly() or a regex check before parsing. Consider using getIntExtra() with a default value instead of parsing getStringExtra()."
            })
    if findings:
        sa.findings.append({"category": "40. NumberFormatException DoS via Intent (CWE-755)", "rules": findings})


def detect_mitd_external_cache(sa):
    findings = []
    ext_cache = sa._find_methods_by_invoke("Landroid/content/Context;->getExternalCacheDir")
    if ext_cache:
        sensitive_in_ext_cache = sa._find_methods_by_regex(
            r'getExternalCacheDir[\s\S]{0,300}(?:session|ssl|tls|cache|psk|master.?secret'
            r'|session.?ticket|key.?material|cryptographic|cipher|keystore|watls)'
        )
        ssl_session_cache = sa._find_methods_by_invoke(
            "Landroid/net/SSLSessionCache"
        )
        ssl_ext_cache = sa._find_methods_by_regex(
            r'SSLSessionCache[\s\S]{0,200}getExternalCacheDir'
            r'|getExternalCacheDir[\s\S]{0,200}SSLSessionCache'
        )
        if sensitive_in_ext_cache:
            for dm in sensitive_in_ext_cache[:5]:
                findings.append({
                    "id": "ADV-MITD-001",
                    "name": "Sensitive Data Stored in External Cache — Man-in-the-Disk Risk (CVE-2021-24027 style)",
                    "description": f"getExternalCacheDir() is used to store sensitive/cryptographic data in {dm}. External cache (/sdcard/Android/data/<pkg>/cache/) is world-readable on Android ≤ 10 and indexed by the MediaStore content provider on Android ≤ 9. Any malicious app with READ_EXTERNAL_STORAGE can read this data. This was the exact pattern in CVE-2021-24027 (WhatsApp) where TLS 1.3 PSK keys and TLS 1.2 Master Secrets stored in external cache enabled full man-in-the-middle attacks on WhatsApp communications.",
                    "severity": "CRITICAL",
                    "location": dm,
                    "recommendation": "Never store cryptographic material, session tokens, or sensitive data in getExternalCacheDir(). Use getCacheDir() (internal storage) or EncryptedSharedPreferences. For TLS session caching, use internal storage paths only."
                })
        if ssl_ext_cache or (ssl_session_cache and ext_cache):
            if ssl_ext_cache:
                loc = ssl_ext_cache[0] if ssl_ext_cache else "bytecode analysis"
            else:
                loc = "bytecode analysis"
            findings.append({
                "id": "ADV-MITD-002",
                "name": "SSLSessionCache Configured on External Storage — TLS Session Material Leakage (CVE-2021-24027)",
                "description": f"SSLSessionCache is configured with a file in external cache in {loc}. TLS session identifiers and master secrets are written to world-readable external storage. An attacker with READ_EXTERNAL_STORAGE or via MediaStore content URI (Android ≤ 9) can steal TLS session keys and perform man-in-the-middle attacks on the app's TLS connections, bypassing certificate validation entirely during session resumption. This is the exact CVE-2021-24027 vulnerability pattern.",
                "severity": "CRITICAL",
                "location": loc,
                "recommendation": "Create SSLSessionCache with an internal storage File (e.g., new File(context.getCacheDir(), 'SSLSessionCache')) instead of external storage. Internal cache is sandboxed per-app and not accessible to other applications."
            })
        if not sensitive_in_ext_cache and not ssl_ext_cache and ext_cache:
            for dm in ext_cache[:3]:
                findings.append({
                    "id": "ADV-MITD-003",
                    "name": "getExternalCacheDir() Used — Verify No Sensitive Data Cached Externally",
                    "description": f"getExternalCacheDir() is used in {dm}. The external cache directory is world-readable (Android ≤ 10) and indexed by MediaStore (Android ≤ 9). While the current usage may not involve sensitive data, all uses of this directory should be audited to ensure no TLS sessions, cryptographic keys, tokens, or PII are stored there.",
                    "severity": "MEDIUM",
                    "location": dm,
                    "recommendation": "Prefer getCacheDir() over getExternalCacheDir(). If external cache is required, never write sensitive/cryptographic data there. Consider using scoped storage APIs on Android 10+."
                })
    if findings:
        sa.findings.append({"category": "40. Man-in-the-Disk (MitD) — External Cache Sensitive Data (CVE-2021-24027 style)", "rules": findings})


def detect_notification_spoofing(sa):
    findings = []
    notif_builder = sa._find_methods_by_invoke(
        "Landroid/app/Notification$Builder;->setContentText"
    ) or sa._find_methods_by_invoke(
        "Landroid/app/Notification$Builder;->setContentTitle"
    ) or sa._find_methods_by_invoke(
        "Landroid/app/Notification$Builder;->setTicker"
    ) or sa._find_methods_by_invoke(
        "Landroid/app/Notification$Builder;->setSubText"
    )
    if notif_builder:
        intent_in_notif = sa._find_methods_by_regex(
            r'(?:setContentText|setContentTitle|setTicker|setSubText).{0,100}'
            r'(?:getStringExtra|getData|getExtras|getQueryParameter)'
        )
        if intent_in_notif:
            for dm in intent_in_notif[:5]:
                findings.append({
                    "id": "OVS-NOTIF-001",
                    "name": "Notification Content Spoofing — Intent Extra Set on Notification Builder",
                    "description": f"Notification.Builder.setContentText/setContentTitle is called with data from Intent extras in {dm}. An attacker can send a crafted intent with spoofed notification text, title, or icon. This was identified by Oversecured as a vulnerability class in the AOSP platform: notifications displaying attacker-controlled content enable phishing attacks where the user is tricked into thinking the notification comes from a legitimate source or contains legitimate content.",
                    "severity": "HIGH",
                    "location": dm,
                    "recommendation": "Never set notification content directly from untrusted Intent extras. Validate and sanitize all data displayed in notifications. Use fixed notification templates with placeholder substitution for dynamic content."
                })
    if findings:
        sa.findings.append({"category": "42. Notification Spoofing — Intent Extra in Notification Content (Oversecured)", "rules": findings})


def detect_serialization_leakage(sa):
    findings = []
    parcelable_write = sa._find_methods_by_regex(
        r'writeToParcel|writeToParcelable|writeToBundle'
    )
    device_id_read = sa._find_methods_by_regex(
        r'(?:TelephonyManager|getDeviceId|getImei|getMeid|getSimSerialNumber|'
        r'getSubscriberId|getHardwareAddress|getMacAddress|'
        r'android\.os\.Build\.SERIAL|Build\.getSerial)'
    )
    if parcelable_write and device_id_read:
        leakage = sa._find_methods_by_regex(
            r'writeToParcel[\s\S]{0,500}(?:getDeviceId|getImei|getMeid|getSimSerialNumber|'
            r'getSubscriberId|getHardwareAddress|getMacAddress|Build\.SERIAL|Build\.getSerial)'
        )
        if leakage:
            for dm in leakage[:5]:
                findings.append({
                    "id": "OVS-SER-001",
                    "name": "Information Leakage via Serialization — Device Identifiers Written to Parcel",
                    "description": f"writeToParcel() includes device identifiers (IMEI, device ID, serial number) in {dm}. When a Parcelable object containing device identifiers is serialized and passed via IPC (Intent, Bundle, Binder), any receiving app can extract the device identifiers from the Parcel data. This is the Oversecured 'Information leakage via serialization' class: sensitive device information becomes available to any component that receives the serialized object.",
                    "severity": "HIGH",
                    "location": dm,
                    "recommendation": "Remove device identifiers (IMEI, device ID, serial, MAC) from Parcelable/Serializable objects passed via IPC. Use Android ID (Settings.Secure.ANDROID_ID) instead of hardware identifiers. If identifiers must be passed, encrypt them before serialization."
                })
    if findings:
        sa.findings.append({"category": "42. Information Leakage via Serialization — Device IDs in Parcel (Oversecured)", "rules": findings})


def detect_password_storage(sa):
    findings = []
    db_password = sa._find_methods_by_regex(
        r'(?:execSQL|rawQuery|ContentValues|insert|update|query|replace).{0,100}'
        r'["\']password["\']'
    )
    if db_password:
        for dm in db_password[:5]:
            findings.append({
                "id": "OVS-STOR-001",
                "name": "Password Stored in Database Column — Cleartext Credential Storage",
                "description": f"A database operation uses 'password' as a column name in {dm}. Oversecured identified this as a vulnerability pattern where passwords are stored directly in SQLite databases. Unless the column value is encrypted (not just the database), passwords are stored in cleartext on the device filesystem and can be read via backup, root, or ADB.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Never store passwords in plaintext. Use password hashing (bcrypt/scrypt/argon2) for verification. If encrypted storage is required, use EncryptedSharedPreferences or SQLCipher. Audit all database schemas for 'password' columns."
            })
    prefs_password = sa._find_methods_by_regex(
        r'(?:SharedPreferences|Editor).{0,100}["\']password["\']'
    )
    if prefs_password:
        for dm in prefs_password[:3]:
            findings.append({
                "id": "OVS-STOR-002",
                "name": "Password Stored in SharedPreferences — Cleartext Credential Storage",
                "description": f"SharedPreferences uses 'password' as a key in {dm}. Storing passwords in SharedPreferences stores them in cleartext XML in /data/data/<pkg>/shared_prefs/, accessible via root, ADB backup, or any app with READ_EXTERNAL_STORAGE (on older Android versions).",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Never store passwords in SharedPreferences. Use the Android Keystore + EncryptedSharedPreferences for credential storage. Consider biometric authentication instead of storing passwords locally."
            })
    if findings:
        sa.findings.append({"category": "42. Password Storage on Device — Cleartext Credentials in DB/Settings (Oversecured)", "rules": findings})


def detect_undeclared_permissions(sa):
    findings = []
    declared_perms = set()
    try:
        manifest = sa.apk.get_android_manifest_xml()
        if manifest is not None:
            ns = {'android': 'http://schemas.android.com/apk/res/android'}
            uses_perms = manifest.xpath("//uses-permission", namespaces=ns)
            for up in uses_perms:
                pname = up.get(f"{{{ns['android']}}}name", "")
                if pname:
                    declared_perms.add(pname)
            custom_perms = manifest.xpath("//permission", namespaces=ns)
            for cp in custom_perms:
                pname = cp.get(f"{{{ns['android']}}}name", "")
                if pname:
                    declared_perms.add(pname)
    except Exception:
        pass
    enforce_calls = sa._find_methods_by_regex(
        r'(?:enforceCallingPermission|enforceCallingOrSelfPermission|'
        r'enforcePermission)\(\s*["\']([^"\']+)["\']'
    )
    if enforce_calls:
        for dm in enforce_calls[:10]:
            import re
            m = re.search(r'enforce(?:Calling|CallingOrSelf)?Permission\(\s*["\']([^"\']+)["\']', dm)
            if m:
                perm_name = m.group(1)
                if perm_name not in declared_perms:
                    findings.append({
                        "id": "OVS-PERM-001",
                        "name": f"Undeclared Permission Enforced — '{perm_name}' Not in Manifest",
                        "description": f"enforceCallingPermission(\"{perm_name}\") is used in {dm} but '{perm_name}' is not declared in AndroidManifest.xml via <uses-permission> or <permission>. The permission check may always pass because the system does not know about this permission, or the permission might be misspelled. This was identified by Oversecured as 'Use of undeclared permissions': developers often use enforceCallingPermission with permission strings that are either typo'd or belong to libraries, making the permission check ineffective.",
                        "severity": "CRITICAL",
                        "location": dm,
                        "recommendation": "Ensure all permissions used in enforceCallingPermission() are declared in AndroidManifest.xml via <uses-permission>. Use constants from Manifest.permission class instead of hardcoded strings to avoid typos. For custom permissions, declare them with <permission> and the appropriate protectionLevel."
                    })
    if findings:
        sa.findings.append({"category": "42. Undeclared Permissions — enforceCallingPermission with Missing Manifest Declarations (Oversecured)", "rules": findings})


def detect_content_injection(sa):
    findings = []
    settext_from_intent = sa._find_methods_by_regex(
        r'setText.{0,50}(?:getStringExtra|getData|getQueryParameter|EXTRA_TEXT|EXTRA_HTML_TEXT)'
    )
    if settext_from_intent:
        for dm in settext_from_intent[:5]:
            findings.append({
                "id": "OVS-UI-003",
                "name": "Content Injection — setText() Called with Intent Extra Data",
                "description": f"TextView.setText() is called with data derived from Intent extras in {dm}. An attacker can craft a malicious intent that injects arbitrary text into the UI. While this is primarily a UI spoofing/phishing issue (rather than code execution), it enables attackers to display fake error messages, phishing prompts, or misleading content that tricks users into revealing credentials or performing sensitive actions. Oversecured identified this as 'Content injection' in their AOSP analysis.",
                "severity": "MEDIUM",
                "location": dm,
                "recommendation": "Never set UI text directly from untrusted Intent extras. Validate and sanitize all text displayed in UI elements from external sources. Use string resources with format placeholders for dynamic content. Consider the user's context — show warnings when displaying external content in security-sensitive UI surfaces."
            })
    if findings:
        sa.findings.append({"category": "42. Content Injection — setText from Intent Extra (Oversecured)", "rules": findings})


def detect_log_injection(sa):
    findings = []
    log_with_intent = sa._find_methods_by_regex(
        r'Log\.(?:d|v|i|w|e)\s*\([^)]*(?:getStringExtra|getData|getQueryParameter|EXTRA_TEXT|intent\.getStringExtra)'
    )
    if log_with_intent:
        for dm in log_with_intent[:5]:
            findings.append({
                "id": "OVS-LEAK-004",
                "name": "Log Injection — Logging User-Controlled Data from Intent",
                "description": f"Log.*() is called with data from an Intent extra in {dm}. An attacker can send a crafted intent that injects fake log entries containing misleading information. When logs are reviewed for debugging or forensics, fake entries can mask malicious activity or implicate innocent users. Oversecured identified this as 'Substitution of log data': user-controlled data written to logs enables log poisoning — an attacker can forge log entries appearing to come from legitimate operations, complicating incident response.",
                "severity": "MEDIUM",
                "location": dm,
                "recommendation": "Never log user-controlled data directly. If logging is required for debugging, sanitize the input (remove newlines, control characters, truncate length). Use structured logging with separate fields for user input. In production builds, strip all debug logging with ProGuard."
            })
    if findings:
        sa.findings.append({"category": "42. Log Injection — Intent Extra Data Written to Logcat (Oversecured)", "rules": findings})


def detect_local_addresses(sa):
    findings = []
    local_ip_patterns = [
        (r'127\.0\.0\.1', 'localhost (127.0.0.1)'),
        (r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'private network (10.x.x.x)'),
        (r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}', 'private network (172.16-31.x.x)'),
        (r'192\.168\.\d{1,3}\.\d{1,3}', 'private network (192.168.x.x)'),
        (r'169\.254\.\d{1,3}\.\d{1,3}', 'link-local (169.254.x.x)'),
    ]
    for pat, label in local_ip_patterns:
        matches = sa._find_methods_by_regex(pat)
        for dm in matches[:3]:
            findings.append({
                "id": "OVS-CONF-001",
                "name": f"Local/Private IP Address in Bytecode — {label}",
                "description": f"A local/private IP address ({label}) was found in bytecode strings in {dm}. Oversecured identified this as 'Local address in release build': hardcoded local IP addresses in release APKs indicate development/staging configurations were shipped. These addresses may expose internal network topology, reveal staging credentials, or allow an attacker on the local network to identify potential targets behind NAT. In release builds, no hardcoded IP addresses should point to internal infrastructure.",
                "severity": "MEDIUM",
                "location": dm,
                "recommendation": "Remove all hardcoded local/private IP addresses from release builds. Use a configuration server or DNS names instead of IP addresses. If local addresses are required for development builds, use BuildConfig.DEBUG to exclude them from release builds. Consider using Android's network service discovery instead of hardcoded IPs."
            })
    if findings:
        sa.findings.append({"category": "42. Local/Private IP Address in Release Build (Oversecured)", "rules": findings})


def detect_missing_protection_level(sa):
    findings = []
    try:
        manifest = sa.apk.get_android_manifest_xml()
        if manifest is not None:
            ns = {'android': 'http://schemas.android.com/apk/res/android'}
            perms = manifest.xpath("//permission", namespaces=ns)
            for perm in perms:
                name = perm.get(f"{{{ns['android']}}}name", "unknown")
                prot_level = perm.get(f"{{{ns['android']}}}protectionLevel")
                if prot_level is None:
                    findings.append({
                        "id": "ADV-PERM-001",
                        "name": f"Custom Permission '{name}' Missing protectionLevel — Defaults to 'normal' (CVE-2021-25410 style)",
                        "description": f"Custom permission '{name}' is declared without android:protectionLevel, defaulting to 'normal'. Any app can acquire this permission without user consent at install time. This was the root cause of CVE-2021-25410 (Samsung): a system app defined custom permissions without protectionLevel, allowing third-party apps to access sensitive functionality by simply declaring the permission in their own manifest. For signature-level permissions intended to restrict access to apps signed with the same key, the missing protectionLevel means any app can request and obtain the permission, completely defeating the access control purpose.",
                        "severity": "CRITICAL",
                        "location": f"AndroidManifest.xml <permission android:name='{name}'>",
                        "recommendation": "Always set android:protectionLevel on custom <permission> elements. Use 'signature' for permissions that should only be granted to apps signed with the same certificate. Use 'dangerous' for runtime-consented permissions. Never rely on the default 'normal' protection level for security-sensitive permissions."
                    })
    except Exception:
        pass
    if findings:
        sa.findings.append({"category": "41. Missing protectionLevel on Custom Permissions (CVE-2021-25410)", "rules": findings})

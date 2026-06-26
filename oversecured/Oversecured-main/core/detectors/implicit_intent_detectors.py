import logging
logger = logging.getLogger(__name__)


def detect_implicit_start_activity_for_result(sa):
    findings = []
    safr = sa._find_methods_by_invoke(
        "Landroid/app/Activity;->startActivityForResult"
    )
    implicit_safr = sa._find_methods_by_regex(
        r'startActivityForResult.*[Ii]ntent\(|startActivityForResult.*new Intent\b'
    )
    sensitive_implicit = sa._find_methods_by_regex(
        r'startActivityForResult.*(putExtra.*password|putExtra.*token|putExtra.*credit|putExtra.*secret)'
    )
    if implicit_safr:
        for dm in implicit_safr[:3]:
            findings.append({
                "id": "ADV-IMP-001",
                "name": "startActivityForResult() with Implicit Intent — Interception and Result Injection",
                "description": f"startActivityForResult() with an implicit Intent in {dm}. Any app with a matching intent-filter can intercept the activity launch, read the extras (potentially containing sensitive data), and return a crafted result via setResult(). This enables data theft and result injection.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Use explicit intents (setComponent/setPackage) for startActivityForResult(). If implicit is required, validate the caller identity via getCallingPackage() in onActivityResult()."
            })
    if sensitive_implicit:
        for dm in sensitive_implicit[:3]:
            findings.append({
                "id": "ADV-IMP-002",
                "name": "Sensitive Data Passed via Implicit startActivityForResult() — Data Theft via Interception",
                "description": f"Sensitive data (passwords, tokens, credit card info) is passed via implicit Intent extras in startActivityForResult() in {dm}. A malicious app with a matching intent-filter can intercept this data.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Use setPackage() to restrict the Intent to your app only. Never pass sensitive data via implicit intents."
            })
    if findings:
        sa.findings.append({"category": "39. Implicit Intent Interception — Activity / Broadcast / Service", "rules": findings})


def detect_query_intent_activities(sa):
    findings = []
    qia = sa._find_methods_by_invoke(
        "Landroid/content/pm/PackageManager;->queryIntentActivities"
    )
    qis = sa._find_methods_by_invoke(
        "Landroid/content/pm/PackageManager;->queryIntentServices"
    )
    if qia:
        for dm in qia[:5]:
            findings.append({
                "id": "ADV-IMP-010",
                "name": "queryIntentActivities() — Dynamic Activity Resolution to First Match",
                "description": f"queryIntentActivities() is called in {dm} to dynamically resolve an Intent target. If the first matching activity is selected and invoked via setClassName(), an attacker's app with a higher priority intent-filter can intercept the Intent and receive sensitive data.",
                "severity": "HIGH",
                "location": dm,
                "recommendation": "Avoid dynamic resolution of Intent targets. Use explicit intents targeting specific known components. If dynamic resolution is required, verify the resolved package name against an allowlist."
            })
    if qis:
        for dm in qis[:3]:
            findings.append({
                "id": "ADV-IMP-011",
                "name": "queryIntentServices() — Dynamic Service Resolution to First Match",
                "description": f"queryIntentServices() is called in {dm}. An attacker's app with a matching intent-filter can intercept service bindings.",
                "severity": "HIGH",
                "location": dm,
                "recommendation": "Use explicit intents for service binding. Validate resolved component against an allowlist."
            })
    if findings:
        sa.findings.append({"category": "39. Dynamic Intent Resolution — queryIntentActivities / queryIntentServices", "rules": findings})


def detect_standard_action_interception(sa):
    findings = []
    action_pick = sa._find_methods_by_regex(
        r'Intent\.ACTION_PICK|ACTION_PICK["\']|"android\.intent\.action\.PICK"'
    )
    action_get_content = sa._find_methods_by_regex(
        r'Intent\.ACTION_GET_CONTENT|ACTION_GET_CONTENT["\']|"android\.intent\.action\.GET_CONTENT"'
    )
    action_image_capture = sa._find_methods_by_regex(
        r'MediaStore\.ACTION_IMAGE_CAPTURE|ACTION_IMAGE_CAPTURE["\']|"android\.media\.action\.IMAGE_CAPTURE"'
    )
    if action_pick:
        for dm in action_pick[:3]:
            findings.append({
                "id": "ADV-IMP-020",
                "name": "ACTION_PICK Used — File Theft via Interception",
                "description": f"ACTION_PICK is used in startActivityForResult() in {dm}. A malicious app with a higher-priority intent-filter can intercept this intent and return a file:// URI pointing to any file in the app's private directory, enabling theft of arbitrary files (databases, shared preferences, cookies).",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Use a custom ContentProvider with scoped URI permissions instead of ACTION_PICK for file selection. If ACTION_PICK is required, validate the returned data URI's scheme, host, and path against an allowlist."
            })
    if action_get_content:
        for dm in action_get_content[:3]:
            findings.append({
                "id": "ADV-IMP-021",
                "name": "ACTION_GET_CONTENT Used — File Disclosure via Intent Interception",
                "description": f"ACTION_GET_CONTENT is used in {dm}. Similar to ACTION_PICK, this allows an intercepting app to return arbitrary file:// URIs, leading to theft of private app files.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Prefer FileProvider with scoped URIs. Validate returned content:// URIs for expected authority and path patterns."
            })
    if action_image_capture:
        for dm in action_image_capture[:3]:
            findings.append({
                "id": "ADV-IMP-022",
                "name": "ACTION_IMAGE_CAPTURE Used — Potential File Theft via Interception",
                "description": f"ACTION_IMAGE_CAPTURE is used in {dm}. An intercepting app can return arbitrary file:// URIs or content:// URIs pointing to sensitive files, enabling file theft.",
                "severity": "HIGH",
                "location": dm,
                "recommendation": "Validate the returned data URI in onActivityResult(). Use FileProvider with a temporary URI if saving the captured image."
            })
    if findings:
        sa.findings.append({"category": "39. Standard Action Interception — ACTION_PICK / GET_CONTENT / IMAGE_CAPTURE", "rules": findings})


def detect_implicit_pending_intent_broadcast(sa):
    findings = []
    pi_broadcast = sa._find_methods_by_regex(
        r'PendingIntent\.getBroadcast.*FLAG_MUTABLE|PendingIntent\.getBroadcast[^)]*\)'
    )
    implicit_pi = sa._find_methods_by_regex(
        r'PendingIntent\.(getActivity|getBroadcast|getService|getForegroundService).*new Intent\([^)]*\)'
    )
    if implicit_pi:
        for dm in implicit_pi[:5]:
            findings.append({
                "id": "ADV-IMP-030",
                "name": "Implicit Intent in PendingIntent — Interception of Delayed Intents",
                "description": f"A PendingIntent wraps an implicit Intent in {dm}. When the PendingIntent is fired, the implicit Intent can be intercepted by any app with a matching intent-filter. This delays the interception risk and makes it harder to trace.",
                "severity": "HIGH",
                "location": dm,
                "recommendation": "Always use explicit Intents (setPackage/setComponent) in PendingIntents. Add FLAG_IMMUTABLE to prevent the receiver from modifying the Intent."
            })
    if findings:
        sa.findings.append({"category": "39. Implicit PendingIntent — Delayed Intent Interception", "rules": findings})


def detect_on_activity_result_uri_validation(sa):
    findings = []
    oar_uri = sa._find_methods_by_regex(
        r'onActivityResult.*getData|onActivityResult.*getDataString'
    )
    uri_copy = sa._find_methods_by_regex(
        r'onActivityResult.*openInputStream|onActivityResult.*copy|getData\(\)[\s\S]{0,200}copy\(|'
        r'getData\(\)[\s\S]{0,200}openFileInput'
    )
    if oar_uri and uri_copy:
        for dm in uri_copy[:5]:
            findings.append({
                "id": "ADV-IMP-040",
                "name": "URI from onActivityResult Copied to Local File — Potential File Theft",
                "description": f"A URI received in onActivityResult() is copied to a local file in {dm}. If the URI originates from an intercepting app (via ACTION_PICK/ACTION_GET_CONTENT/startActivityForResult), the file contents are written to the victim app's storage. The attacker can control which file is copied by returning a file:// or content:// URI pointing to sensitive files.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Validate the URI scheme (reject file://), authority, and path before copying. Never copy content:// URIs from untrusted callers. Verify the calling package via getCallingPackage()."
            })
    if findings:
        sa.findings.append({"category": "39. onActivityResult — URI Validation / File Theft via ContentResolver", "rules": findings})


def detect_display_name_path_traversal(sa):
    findings = []
    display_name = sa._find_methods_by_regex(
        r'_display_name|DISPLAY_NAME|MediaColumns\.DISPLAY_NAME'
    )
    path_construct = sa._find_methods_by_regex(
        r'_display_name.*File\(|DISPLAY_NAME[\s\S]{0,100}new File|DISPLAY_NAME[\s\S]{0,100}\.html?[\s\S]{0,20}\.so'
    )
    if display_name and path_construct:
        for dm in path_construct[:5]:
            findings.append({
                "id": "ADV-IMP-050",
                "name": "_display_name from ContentProvider Used to Construct File Path — Path Traversal via Malicious Provider",
                "description": f"The _display_name column value from a ContentProvider query is used to construct a file path in {dm}. A malicious ContentProvider can return a _display_name with '../' path traversal sequences (e.g., '../lib-main/lib.so') to write files outside the intended directory, enabling arbitrary code execution via native library overwrite or config file manipulation.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Sanitize _display_name values by removing all path separators ('/', '..'). Use File.getName() to extract only the filename component. Never use _display_name directly in file path construction."
            })
    if findings:
        sa.findings.append({"category": "39. Path Traversal via _display_name — Malicious ContentProvider File Overwrite", "rules": findings})


def detect_symlink_file_theft(sa):
    findings = []
    symlink_cmds = sa._find_methods_by_regex(
        r'Runtime\.exec.*ln\s+-s|Runtime\.exec.*symlink|exec.*"ln"'
    )
    chmod_chrome = sa._find_methods_by_regex(
        r'Runtime\.exec.*chmod\s+-R\s+777'
    )
    if symlink_cmds:
        for dm in symlink_cmds[:3]:
            findings.append({
                "id": "ADV-IMP-060",
                "name": "Symlink Created via Runtime.exec(ln -s) — Cookie/File Theft via WebView",
                "description": f"A symbolic link is created via Runtime.exec() in {dm}, pointing to another app's internal file (e.g., WebView Cookies database). Combined with WebView loading the symlink, this enables theft of cookies, session tokens, and arbitrary files.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Avoid Runtime.exec() for file operations. Use Java symlink APIs (Files.createSymbolicLink) with proper permission checks. Never create symlinks to other apps' private directories."
            })
    if symlink_cmds and chmod_chrome:
        for dm in symlink_cmds[:3]:
            findings.append({
                "id": "ADV-IMP-061",
                "name": "Symlink + chmod 777 — Full File System Access for Cookie/Session Theft",
                "description": f"Symlink creation is combined with chmod 777 in {dm}. This pattern enables an app to make another app's private files (Cookies database, shared preferences) world-readable and accessible, typically used for session hijacking.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Never use chmod 777 on app-private directories. This removes all Android file system protections for your app's data."
            })
    if findings:
        sa.findings.append({"category": "39. Symlink Abuse — Cookie Theft / Private File Access", "rules": findings})

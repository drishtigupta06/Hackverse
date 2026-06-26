import logging
logger = logging.getLogger(__name__)


def detect_fileprovider_broad_paths(sa):
    findings = []
    fp_roots = []
    for s in sa.strings:
        try:
            s_str = str(s)
        except Exception:
            continue
        if 'root-path' in s_str and ('path=""' in s_str or "path=''" in s_str):
            fp_roots.append(s_str)
        if 'files-path' in s_str and ('path="."' in s_str or "path='.'" in s_str):
            fp_roots.append(s_str)
        if 'cache-path' in s_str and ('path=""' in s_str or "path=''" in s_str):
            fp_roots.append(s_str)
        if 'external-path' in s_str and ('path=""' in s_str or "path=''" in s_str):
            fp_roots.append(s_str)
    if fp_roots:
        for entry in fp_roots[:5]:
            findings.append({
                "id": "ADV-CP-300",
                "name": "FileProvider with Broad/Dangerous Path — Full Filesystem or Directory Exposure",
                "description": f"FileProvider XML config defines a path wildcard ('root-path', 'files-path' with '.', etc.): '{entry[:80]}...'. Any app that can obtain a URI grant can read/write files in the entire matching directory (or entire filesystem for root-path). Combined with intent redirect vulnerabilities, this enables arbitrary file access and code execution.",
                "severity": "CRITICAL",
                "location": "FileProvider paths.xml resource",
                "recommendation": "Restrict FileProvider paths to specific subdirectories (e.g., 'my_images/' not '.'). Never use root-path with empty path. Each FileProvider should serve a single, specific purpose."
            })
    if findings:
        sa.findings.append({"category": "40. Content Provider — FileProvider / Path Traversal / Permission Issues", "rules": findings})


def detect_provider_path_traversal(sa):
    findings = []
    last_seg = sa._find_methods_by_regex(
        r'Uri\.(getLastPathSegment|getPathSegments)'
    )
    path_construct = sa._find_methods_by_regex(
        r'getLastPathSegment[\s\S]{0,100}new File\(|getPathSegments[\s\S]{0,100}new File\('
    )
    if last_seg:
        for dm in path_construct[:5]:
            findings.append({
                "id": "ADV-CP-310",
                "name": "Uri.getLastPathSegment() Used in File Construction — Path Traversal via URL Encoding",
                "description": f"Uri.getLastPathSegment() is used to construct a file path in {dm}. This method returns a decoded value, so '%2F' becomes '/'. An attacker can use path traversal sequences like '..%2Fshared_prefs%2Fsecrets.xml' in the URI to access files outside the intended directory.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Never use decoded URI segments in file path construction. Canonicalize the final path and verify it starts with the intended directory. Use Uri.encode() on the segment before using it, or validate against canonical paths only."
            })
    if findings:
        sa.findings.append({"category": "40. Content Provider — Path Traversal via getLastPathSegment / URI Decoding", "rules": findings})


def detect_provider_permission_mismatch(sa):
    findings = []
    for p in sa.manifest_components.get("providers", []):
        has_read_perm = bool(p.get("readpermission", ""))
        has_write_perm = bool(p.get("writepermission", ""))
        has_perm = bool(p.get("permission", ""))
        exported = p.get("exported") in ("true", None, "")
        if exported and has_read_perm and not has_write_perm:
            findings.append({
                "id": "ADV-CP-320",
                "name": f"ContentProvider '{p.get('name','?')}' — writePermission Missing (read-only Permission Defined Only)",
                "description": f"ContentProvider '{p.get('name','?')}' has android:readPermission set but no android:writePermission. If the provider supports write operations (insert/update/delete/openFile with 'w' mode), any app can write without permission. The mode check in ContentResolver only validates against the mode string, not the actual operation.",
                "severity": "HIGH",
                "location": f"AndroidManifest: {p['name']}",
                "recommendation": "Always define both android:readPermission AND android:writePermission for exported providers. If unsure, use androd:permission which covers both read and write access."
            })
        if exported and not has_perm and not has_read_perm and not has_write_perm:
            if p.get("granturipersissions") not in ("true",):
                findings.append({
                    "id": "ADV-CP-321",
                    "name": f"Exported ContentProvider Without Any Permission — {p.get('name','?')}",
                    "description": f"ContentProvider '{p.get('name','?')}' is exported with no permission protection. Any app on the device can perform all CRUD operations (query, insert, update, delete) and open files via this provider.",
                    "severity": "CRITICAL",
                    "location": f"AndroidManifest: {p['name']}",
                    "recommendation": "Set android:exported='false' if provider is internal. If sharing is required, add signature-level permissions."
                })
    if findings:
        sa.findings.append({"category": "40. Content Provider — Permission Mismatch / Missing writePermission", "rules": findings})


def detect_provider_proxy_abuse(sa):
    findings = []
    proxy_provider = sa._find_methods_by_regex(
        r'ContentResolver\.query\(.*uri.*getQueryParameter|getQueryParameter.*uri.*ContentResolver\.query|'
        r'ContentResolver\.query\(.*Uri\.parse\(\s*getQueryParameter'
    )
    if proxy_provider:
        for dm in proxy_provider[:5]:
            findings.append({
                "id": "ADV-CP-330",
                "name": "ContentProvider Proxies Requests to Dynamic URI — SSRF/Provider Access Escalation",
                "description": f"A ContentProvider proxies queries to a URI parsed from dynamic parameters in {dm}. An attacker can pass any content:// URI to query arbitrary providers the app has access to, including system providers (contacts, SMS) and ecosystem providers with higher privilege levels.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Never proxy ContentProvider requests to dynamic URIs. Use a fixed set of known URIs with an allowlist. If proxying is required, validate the target authority and URI against a strict whitelist."
            })
    if findings:
        sa.findings.append({"category": "40. Content Provider — Dynamic Proxy / SSRF via ContentResolver", "rules": findings})


def detect_provider_debug_action(sa):
    findings = []
    debug_provider = sa._find_methods_by_regex(
        r'debug.*dump|debug.*copy|debug.*delete|debug.*move|ContentProvider.*debug|call\(.*debug'
    )
    if debug_provider:
        for dm in debug_provider[:5]:
            findings.append({
                "id": "ADV-CP-340",
                "name": "Debug/Dangerous Action in ContentProvider — Sensitive Operations via Provider",
                "description": f"A ContentProvider in {dm} contains debug or dangerous actions (data dump, file copy, delete). Even if the provider is non-exported, any component in the app that calls ContentResolver.query() with attacker-controlled URIs can trigger these actions, leading to data theft or file system manipulation.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Remove all debug functionality from ContentProviders before release. Never implement data dump, file copy, or destructive operations in ContentProvider methods."
            })
    if findings:
        sa.findings.append({"category": "40. Content Provider — Debug/Destructive Actions in Provider Logic", "rules": findings})


def detect_provider_openfile_no_validation(sa):
    findings = []
    open_file = sa._find_methods_by_invoke(
        "Landroid/content/ContentProvider;->openFile"
    )
    if open_file:
        for dm in open_file[:5]:
            findings.append({
                "id": "ADV-CP-350",
                "name": "ContentProvider.openFile() — File Access Without Path Validation",
                "description": f"ContentProvider.openFile() in {dm} returns files based on URI paths. If the file path is constructed from URI segments without canonicalization, attackers can use ../ path traversal to read/write files outside the intended directory.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Canonicalize the requested file path and verify it starts with the intended root directory. Use getCanonicalPath() and check with startsWith(). Reject paths containing '..' sequences."
            })
    content_uri_base = sa._find_methods_by_regex(
        r'content://.*openFile|openFile.*content://|ContentProvider;->openFile'
    )
    if findings:
        sa.findings.append({"category": "40. Content Provider — openFile/openAssetFile Path Traversal", "rules": findings})


def detect_local_webserver_path_traversal(sa):
    findings = []
    nanohttpd = sa._find_methods_by_invoke("Lfi/iki/elonen/NanoHTTPD")
    if nanohttpd:
        serve_method = sa._find_methods_by_regex(
            r'NanoHTTPD.*serve\(|NanoHTTPD.*serve |IHTTPSession.*getUri'
        )
        path_traversal = sa._find_methods_by_regex(
            r'getUri.*substring|getUri.*new File|getUri.*openStream'
        )
        if serve_method and path_traversal:
            for dm in path_traversal[:3]:
                findings.append({
                    "id": "ADV-CP-360",
                    "name": "Local Web Server (NanoHTTPD) — Path Traversal via HTTP Request URI",
                    "description": f"A local web server (NanoHTTPD) in {dm} uses the HTTP request URI to construct file paths. Any app on the same device (or local network) can send HTTP requests with '../' path traversal to read arbitrary files from the app's private directory, including databases, shared preferences, and tokens.",
                    "severity": "CRITICAL",
                    "location": dm,
                    "recommendation": "Canonicalize and validate all file paths derived from HTTP request URIs. Never use request URI segments directly in file path construction. Restrict file access to a specific subdirectory with validated paths."
                })
        if nanohttpd and not serve_method:
            findings.append({
                "id": "ADV-CP-361",
                "name": "Local Web Server (NanoHTTPD) — Potential File Disclosure via HTTP",
                "description": "NanoHTTPD library is detected running a local web server. Local web servers bind to all network interfaces by default, making them accessible from the local network. Any misconfiguration can expose app files to arbitrary apps or network attackers.",
                "severity": "HIGH",
                "location": "bytecode analysis",
                "recommendation": "Avoid local web servers entirely. If required, bind to localhost only, validate all incoming request paths, and restrict file access to a dedicated subdirectory."
            })
    if findings:
        sa.findings.append({"category": "40. Local Web Server — NanoHTTPD / HTTP File Disclosure", "rules": findings})


def detect_provider_same_database_cross_table(sa):
    findings = []
    shared_helper = sa._find_methods_by_regex(
        r'SQLiteOpenHelper.*SENSITIVE|SQLiteOpenHelper.*INSENSITIVE|'
        r'SQLiteOpenHelper.*getReadableDatabase.*Sensitive|SQLiteOpenHelper.*getReadableDatabase.*Insensitive'
    )
    cross_provider = sa._find_methods_by_regex(
        r'UNION.*SELECT.*FROM.*Sensitive|UNION.*SELECT.*FROM.*secret|'
        r'UNION.*SELECT.*FROM.*private'
    )
    if shared_helper:
        findings.append({
            "id": "ADV-CP-370",
            "name": "Sensitive and Non-Sensitive Data in Same Database — Cross-Provider SQL Injection",
            "description": "Multiple ContentProviders share the same SQLite database file, with different permission levels. An attacker with access to the lower-privilege provider can use SQL injection (UNION SELECT) to read sensitive data from tables belonging to the higher-privilege provider.",
            "severity": "HIGH",
            "location": "bytecode analysis",
            "recommendation": "Use separate database files for each ContentProvider. Never mix sensitive and non-sensitive data in the same database file when providers have different permission levels."
        })
    if findings:
        sa.findings.append({"category": "40. Content Provider — Shared Database / Cross-Provider SQL Injection", "rules": findings})


def detect_opencontenturi_bypass(sa):
    findings = []
    open_content_uri = sa._find_methods_by_invoke(
        "Landroid/app/IActivityManager;->openContentUri"
    )
    if open_content_uri:
        for dm in open_content_uri[:3]:
            findings.append({
                "id": "ADV-CP-380",
                "name": "IActivityManager.openContentUri() — ContentProvider Permission Bypass via Internal API",
                "description": f"IActivityManager.openContentUri() is invoked in {dm}. This internal system API opens a content URI for reading bypassing the ContentProvider's normal permission checks. Unlike ContentResolver.openInputStream(), openContentUri() does not enforce URI permissions (FLAG_GRANT_READ_URI_PERMISSION), does not check the calling package's permissions, and does not validate that the caller has the right to access the provider. Apps with system privileges or access to ActivityManagerService internals can read any ContentProvider data without permission checks.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Never use IActivityManager.openContentUri() for accessing ContentProviders. Use standard ContentResolver APIs with proper URI permission grants. If the provider must be accessed internally, implement custom permission checks in the provider's query() method regardless of how it was called."
            })
    content_resolver_open = sa._find_methods_by_invoke(
        "Landroid/content/ContentResolver;->openInputStream"
    )
    ams_open = sa._find_methods_by_regex(
        r'ActivityManagerNative|ActivityManagerService.*openContentUri|IActivityManager.*openContentUri'
    )
    if ams_open:
        for dm in ams_open[:3]:
            findings.append({
                "id": "ADV-CP-381",
                "name": "ContentResolver Bypass via ActivityManagerService — Direct Content URI Access",
                "description": f"ActivityManagerService.openContentUri() reference in {dm} allows direct content URI access that bypasses ContentProvider permission checks. The system server's openContentUri() method opens the URI through the package manager without verifying URI grants or caller permissions. Any content:// URI accessible to the system UID can be read.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Audit all uses of ActivityManagerService/IActivityManager.openContentUri(). Replace with ContentResolver calls. For system apps, add explicit permission checks in ContentProvider.query() as a defense-in-depth measure."
            })
    if findings:
        sa.findings.append({"category": "40. Content Provider — IActivityManager.openContentUri Permission Bypass", "rules": findings})

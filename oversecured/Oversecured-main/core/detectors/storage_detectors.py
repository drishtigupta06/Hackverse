import logging
logger = logging.getLogger(__name__)


def detect_cp_unauthorized_access(sa):
    findings = []
    for p in sa.manifest_components.get("providers", []):
        if p["exported"] in ("true", None, ""):
            findings.append({"id":"ADV-CP-001","name":"ContentProvider Exposed Without Protection",
                "description":f"ContentProvider '{p['name']}' is exported without permission. Any app can read or write provider data.",
                "severity":"HIGH","location":f"AndroidManifest: {p['name']}",
                "recommendation":"Set android:readPermission and android:writePermission with signature-level permissions."})
            break
    if findings:
        sa.findings.append({"category":"6. ContentProvider Unauthorized Access","rules":findings})


def detect_world_readable_files(sa):
    findings = []
    src = sa._string_in_source(r'(MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|Context\.MODE_WORLD)')
    if src:
        for sm in src[:10]:
            findings.append({"id":"ADV-019","name":"World-Readable/Writeable File Created",
                "description":"Files created with MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE are accessible to all apps. These modes throw SecurityException on API 24+.",
                "severity":"CRITICAL","location":sm,
                "recommendation":"Use MODE_PRIVATE exclusively. For sharing, use FileProvider with scoped URI grants."})
    if findings:
        sa.findings.append({"category":"4. World-Readable/Writeable Files","rules":findings})


def detect_unsafe_external_storage(sa):
    findings = []
    ext = sa._find_methods_by_invoke("Landroid/content/Context;->getExternalFilesDir")
    ext2 = sa._find_methods_by_invoke("Landroid/os/Environment;->getExternalStorageDirectory")
    if ext:
        for dm in ext[:3]:
            findings.append({"id":"ADV-FS-001","name":"Unsafe External Storage Usage",
                "description":"Files are written to external storage, which is readable by any app with READ_EXTERNAL_STORAGE permission.",
                "severity":"HIGH","location":dm,
                "recommendation":"Store sensitive data in internal storage or EncryptedSharedPreferences. If external storage is required, encrypt all data before writing."})
    if findings:
        sa.findings.append({"category":"4. Unsafe External Storage","rules":findings})


def detect_clipboard_abuse(sa):
    findings = []
    clip = sa._find_methods_by_invoke("Landroid/content/ClipboardManager;->setPrimaryClip")
    if clip:
        sensitive = any(s for s in sa.strings if any(kw in s.lower() for kw in ["password","pin","otp","token","secret"]))
        if sensitive:
            findings.append({"id":"ADV-034","name":"Sensitive Data Copied to Clipboard",
                "severity":"HIGH","location":"bytecode analysis",
                "recommendation":"Avoid copying passwords/OTPs to the clipboard."})
    if findings:
        sa.findings.append({"category":"Clipboard Security","rules":findings})


def detect_unencrypted_database(sa):
    findings = []
    rb = sa._find_methods_by_invoke("Landroidx/room/RoomDatabase;->build")
    sql = sa._find_methods_by_invoke("Landroid/database/sqlite/SQLiteDatabase;->openOrCreateDatabase")
    enc = sa._find_methods_by_invoke("Lnet/sqlcipher/database/SQLiteDatabase")
    if (rb or sql) and not enc:
        findings.append({"id":"ADV-056","name":"Unencrypted Local Database",
            "severity":"MEDIUM","location":"bytecode analysis",
            "recommendation":"Use SQLCipher for encrypting SQLite databases at rest."})
    if findings:
        sa.findings.append({"category":"Database Encryption","rules":findings})


def detect_sql_injection_provider(sa):
    findings = []
    raw_q = sa._find_methods_by_invoke("Landroid/database/sqlite/SQLiteDatabase;->rawQuery")
    if raw_q:
        concat_strs = [s for s in sa.strings if "+" in s or "WHERE" in s]
        if concat_strs:
            for dm in raw_q[:3]:
                findings.append({"id":"ADV-037","name":"Potential SQL Injection in rawQuery()",
                    "severity":"CRITICAL","location":dm,
                    "recommendation":"Use parameterized queries with ? placeholders."})
    if findings:
        sa.findings.append({"category":"SQL Injection (rawQuery)","rules":findings})


def detect_fileprovider_usage(sa):
    findings = []
    fp = sa._find_methods_by_invoke("Landroidx/core/content/FileProvider;->getUriForFile")
    sfp = sa._find_methods_by_invoke("Landroid/support/v4/content/FileProvider;->getUriForFile")
    if fp or sfp:
        findings.append({"id":"ADV-031","name":"FileProvider URI Granted",
            "severity":"MEDIUM","location":"bytecode analysis",
            "recommendation":"Audit the FileProvider paths.xml to ensure minimal directory exposure."})
    if findings:
        sa.findings.append({"category":"FileProvider & URI Permissions","rules":findings})


def detect_cp_advanced(sa):
    findings = []
    cp_open = sa._find_methods_by_invoke("Landroid/content/ContentProvider;->openFile")
    cp_open_asset = sa._find_methods_by_invoke("Landroid/content/ContentProvider;->openAssetFile")
    for dm in (cp_open or [])[:3]:
        findings.append({"id":"ADV-CP-200","name":"ContentProvider.openFile() — Path Traversal Risk",
            "description":f"ContentProvider.openFile() in {dm} may expose arbitrary files if the 'file' parameter is not validated for ../ patterns.",
            "severity":"CRITICAL","location":dm,
            "recommendation":"Canonicalize and validate all file paths in openFile(). Reject paths containing '..' or symbolic links."})
    for dm in (cp_open_asset or [])[:3]:
        findings.append({"id":"ADV-CP-201","name":"ContentProvider.openAssetFile() — Path Traversal in Assets",
            "description":f"ContentProvider.openAssetFile() in {dm} may expose arbitrary asset files.",
            "severity":"HIGH","location":dm,
            "recommendation":"Validate paths in openAssetFile() to prevent access to unauthorized asset files."})
    grant_uri = sa._find_methods_by_invoke("Landroid/content/Context;->grantUriPermission")
    revoke_uri = sa._find_methods_by_invoke("Landroid/content/Context;->revokeUriPermission")
    if grant_uri:
        for dm in grant_uri[:3]:
            findings.append({"id":"ADV-CP-202","name":"grantUriPermission() Used — URI Permission Abuse Risk",
                "description":f"grantUriPermission() in {dm} allows another app to access specific content URIs. If not revoked, URI permissions can be abused for data access.",
                "severity":"HIGH","location":dm,
                "recommendation":"Always pair grantUriPermission() with revokeUriPermission() in a finally block. Use FLAG_GRANT_READ_URI_PERMISSION on intents instead."})
    if grant_uri and not revoke_uri:
        findings.append({"id":"ADV-CP-203","name":"grantUriPermission() Without Revoke — Permanent URI Grant",
            "description":"grantUriPermission() is called but revokeUriPermission() is not found. URI permissions may persist indefinitely.",
            "severity":"HIGH","location":"bytecode analysis",
            "recommendation":"Always revoke URI permissions after use. Use try/finally to ensure revocation."})
    take_persistable = sa._find_methods_by_invoke("Landroid/content/ContentResolver;->takePersistableUriPermission")
    if take_persistable:
        for dm in take_persistable[:3]:
            findings.append({"id":"ADV-CP-204","name":"Persistable URI Permission Taken — Persistent Data Access",
                "description":f"takePersistableUriPermission() in {dm} grants persistent access to content URIs across reboots. This URI access persists until explicitly revoked.",
                "severity":"HIGH","location":dm,
                "recommendation":"Only take persistable URI permissions when absolutely necessary. Document and audit all persisted URI grants."})
    if findings:
        sa.findings.append({"category":"24. Content Provider Advanced — Path Traversal / URI Permission Abuse","rules":findings})


def detect_filesystem_advanced(sa):
    findings = []
    mkdirs = sa._find_methods_by_invoke("Ljava/io/File;->mkdirs")
    create_temp = sa._find_methods_by_invoke("Ljava/io/File;->createTempFile")
    if mkdirs:
        world_writable = sa._find_methods_by_regex(r'mkdirs.*0[0-7][0-7][0-7]|setReadable.*true.*true|setWritable.*true.*true')
        if world_writable:
            for dm in world_writable[:3]:
                findings.append({"id":"ADV-FS-010","name":"World-Writable Directory Created — Symlink Attack Vector",
                    "description":f"World-writable directory created in {dm}. A malicious app can place symlinks in this directory to redirect file operations to arbitrary locations.",
                    "severity":"CRITICAL","location":dm,
                    "recommendation":"Use MODE_PRIVATE for all directories. Never create world-writable directories in internal storage."})
    if create_temp:
        for dm in create_temp[:3]:
            findings.append({"id":"ADV-FS-011","name":"createTempFile() Used — Temporary File Leakage Risk",
                "description":f"createTempFile() in {dm} creates temporary files. If temporary files contain sensitive data, they may leak via other apps with storage access.",
                "severity":"MEDIUM","location":dm,
                "recommendation":"Clean up temporary files immediately after use. Store sensitive data in memory or encrypted storage instead."})
    cache_dir = sa._find_methods_by_invoke("Landroid/content/Context;->getCacheDir")
    code_cache = sa._find_methods_by_invoke("Landroid/content/Context;->getCodeCacheDir")
    if cache_dir:
        sensitive_in_cache = sa._find_methods_by_regex(r'getCacheDir.*(token|password|secret|key|session|credential|jwt)')
        if sensitive_in_cache:
            for dm in sensitive_in_cache[:3]:
                findings.append({"id":"ADV-FS-012","name":"Sensitive Data Written to Cache Directory",
                    "description":f"Sensitive data is written to the app cache directory in {dm}. Cache data can be accessed via storage permissions or ADB backups.",
                    "severity":"HIGH","location":dm,
                    "recommendation":"Never store tokens, passwords, or PII in the cache directory. Use EncryptedSharedPreferences or Android Keystore."})
    shared_prefs_exposure = sa._find_methods_by_regex(r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|getSharedPreferences.*[0-3]')
    if shared_prefs_exposure:
        for dm in shared_prefs_exposure[:3]:
            findings.append({"id":"ADV-FS-013","name":"SharedPreferences with World-Readable Mode — Preference Exposure",
                "description":f"SharedPreferences created with world-readable mode in {dm}. Any app can read all key-value pairs stored in these preferences.",
                "severity":"CRITICAL","location":dm,
                "recommendation":"Use MODE_PRIVATE for all SharedPreferences. Use EncryptedSharedPreferences for sensitive data."})
    db_exposure = sa._find_methods_by_regex(r'openOrCreateDatabase.*MODE_WORLD|Context\.openOrCreateDatabase.*[0-3]')
    if db_exposure:
        for dm in db_exposure[:3]:
            findings.append({"id":"ADV-FS-014","name":"Database Created With World-Readable Mode — Database Exposure",
                "description":f"SQLite database created with world-readable mode in {dm}. Any app can read the database contents.",
                "severity":"CRITICAL","location":dm,
                "recommendation":"Use MODE_PRIVATE for all databases. Use SQLCipher for encrypting database contents."})
    if findings:
        sa.findings.append({"category":"25. File System Advanced — Symlink / Cache / SharedPrefs / Temp Files","rules":findings})


def detect_sharedprefs_cleartext(sa):
    findings = []
    has_putstring = bool(
        sa._find_methods_by_invoke("Landroid/content/SharedPreferences$Editor;->putString")
        or sa._find_methods_by_regex(r'SharedPreferences.*Editor.*putString|edit\(\)\.putString')
    )
    has_encrypted = bool(
        sa._find_methods_by_invoke("Landroidx/security/crypto/EncryptedSharedPreferences")
        or sa._find_methods_by_string("EncryptedSharedPreferences")
        or sa._find_methods_by_regex(r'EncryptedSharedPreferences|MasterKey|encrypt.*preference')
    )
    sensitive_keystr = sa._find_methods_by_regex(
        r'putString\(["\'](password|token|secret|key|credential|pin|otp|jwt|bearer|auth|'
        r'ssn|credit|card|cvv|cvc|api_key|apikey|session)["\']'
    )
    sensitive_var = sa._find_methods_by_regex(
        r'putString\([^,]+,\s*(password|token|secret|credential|pin|otp|jwt)'
    )
    if has_putstring and not has_encrypted and (sensitive_keystr or sensitive_var):
        for dm in (sensitive_keystr or sensitive_var)[:5]:
            findings.append({
                "id": "ADV-STORAGE-100",
                "name": "Sensitive Data Stored in SharedPreferences Without Encryption (CWE-312)",
                "description": f"SharedPreferences.Editor.putString() stores potentially sensitive data in {dm}. SharedPreferences files are stored as cleartext XML in the app's private directory. On rooted devices, any app with root access can read these files. Additionally, via ADB backup or exposed components, the cleartext data is accessible. This is the CWE-312 pattern from real vulnerabilities in multiple Android apps.",
                "severity": "HIGH",
                "location": dm,
                "recommendation": "Use EncryptedSharedPreferences (from AndroidX Security) for all sensitive data. The MasterKey + EncryptedSharedPreferences ensures both keys and values are encrypted using AES256-GCM. Alternatively, encrypt values before storing using a custom encryption wrapper."
            })
    if findings:
        sa.findings.append({"category": "40. Cleartext SharedPreferences (CWE-312)", "rules": findings})

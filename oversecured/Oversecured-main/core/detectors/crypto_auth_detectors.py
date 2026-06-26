import logging
from core.dataflow import ReachingDefinitions, LivenessAnalysis

BRANCH_INSTRS = {"if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le",
                  "if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez",
                  "if-eq-object", "if-ne-object"}

logger = logging.getLogger(__name__)


def detect_crypto_issues(sa):
    findings = []
    ecb = sa._find_methods_by_regex(r'AES/ECB|DES/ECB|Blowfish/ECB|Cipher\.getInstance\s*\(\s*"AES"\s*\)|Cipher\.getInstance\s*\(\s*"DES"|Cipher\.getInstance\s*\(\s*"Blowfish"')
    if ecb:
        for dm in ecb[:3]:
            findings.append({"id":"ADV-CRYPTO-001","name":"ECB Mode Encryption Used",
                "description":"ECB mode is deterministic and reveals data patterns. Identical plaintext blocks produce identical ciphertext.",
                "severity":"CRITICAL","location":dm,
                "recommendation":"Replace ECB with AES/GCM/NoPadding which provides authenticated encryption."})

    des = sa._find_methods_by_regex(r'DES/|RC4|ARC4')
    if des:
        for dm in des[:3]:
            findings.append({"id":"ADV-CRYPTO-002","name":"Broken Cipher (DES/RC4) Used",
                "description":"DES/RC4 are broken and can be cracked with consumer hardware.",
                "severity":"CRITICAL","location":dm,
                "recommendation":"Use AES-256-GCM for all symmetric encryption."})

    md5 = sa._find_methods_by_regex(r'MessageDigest.*MD5')
    sha1 = sa._find_methods_by_regex(r'MessageDigest.*SHA-1|MessageDigest.*SHA1')
    if md5:
        for dm in md5[:3]:
            findings.append({"id":"ADV-CRYPTO-003","name":"MD5 Hash Used (Collision Vulnerable)",
                "severity":"HIGH","location":dm,
                "recommendation":"Use SHA-256 or SHA-512 for hashing."})
    if sha1:
        for dm in sha1[:3]:
            findings.append({"id":"ADV-CRYPTO-004","name":"SHA-1 Hash Used (Collision Vulnerable)",
                "severity":"HIGH","location":dm,
                "recommendation":"Use SHA-256 or SHA-512 instead of SHA-1."})

    rsa_no_oaep = sa._find_methods_by_regex(r'RSA/ECB/PKCS1Padding')
    if rsa_no_oaep:
        for dm in rsa_no_oaep[:3]:
            findings.append({"id":"ADV-CRYPTO-005","name":"RSA Without OAEP Padding - Bleichenbacher Vulnerable",
                "description":"RSA with PKCS1Padding is vulnerable to padding oracle attacks.",
                "severity":"HIGH","location":dm,
                "recommendation":"Use RSA/ECB/OAEPWithSHA-256AndMGF1Padding."})

    static_iv = sa._find_methods_by_regex(r'IvParameterSpec\s*\(new byte\[\d+\]|new byte\s*\[\s*1[0-6]\s*\]')
    if static_iv:
        for dm in static_iv[:3]:
            findings.append({"id":"ADV-CRYPTO-006","name":"Static IV Used for Encryption",
                "description":"A static IV breaks the semantic security of CBC/GCM encryption.",
                "severity":"CRITICAL","location":dm,
                "recommendation":"Generate a random IV using SecureRandom for each encryption operation."})

    weak_random = sa._find_methods_by_regex(r'new Random\(|Math\.random\(\)')
    if weak_random:
        for dm in weak_random[:3]:
            findings.append({"id":"ADV-CRYPTO-007","name":"Weak Random Number Generator Used",
                "description":"java.util.Random or Math.random() are predictable. Use SecureRandom for security-sensitive values.",
                "severity":"MEDIUM","location":dm,
                "recommendation":"Use java.security.SecureRandom for all security-relevant random values."})

    if findings:
        sa.findings.append({"category":"9. Cryptography Issues","rules":findings})


def detect_auth_bypass(sa):
    findings = []
    AUTH_KWS = ["isAdmin","isAuthenticated","isLoggedIn","isUser","checkAuth","isAuthorized",
                 "hasPermission","canAccess","isOwner","isVerified","isValid"]
    for sig, info in sa.method_cfgs.items():
        ins = info["instructions"]
        has_kw = False
        for instr in ins:
            try:
                output = instr.get_output()
                for kw in AUTH_KWS:
                    if kw in output:
                        has_kw = True
                        break
            except Exception:
                pass
            if has_kw:
                break
        if not has_kw:
            continue
        cfg = info["cfg"]
        try:
            rd = ReachingDefinitions(cfg)
            la = LivenessAnalysis(cfg)
        except Exception:
            continue
        for bi, bb in enumerate(cfg.blocks):
            for idx in range(bb.start_idx, bb.end_idx):
                    try:
                        output = ins[idx].get_output()
                        name = ins[idx].get_name()
                        if name in BRANCH_INSTRS:
                            cond_text = output
                            for kw in AUTH_KWS:
                                if kw in cond_text:
                                    if sa._auth_check_has_no_else(cfg, bi):
                                        findings.append({"id":"ADV-AUTH-001",
                                            "name":"Authentication Check Without Else Branch",
                                            "description":f"An authentication check '{kw}' at {sig} may be bypassable. Path analysis shows no else/fallback branch for the failure case.",
                                            "severity":"HIGH",
                                            "location":f"{sig} @ BB:{bb.label} [{cond_text[:100]}]",
                                            "recommendation":"Always implement both auth-success and auth-failure paths. Ensure the failure path explicitly denies access and does not fall through."})
                                        break
                    except Exception:
                        pass

    client_side_only = sa._find_methods_by_regex(r'if.*password.*equals|if.*pin.*equals|if.*token.*equals')
    if client_side_only:
        for dm in client_side_only[:3]:
            findings.append({"id":"ADV-AUTH-002","name":"Client-Side Authentication Check Only",
                "description":"Authentication appears to be performed entirely on the client side, which can be bypassed by decompiling the APK.",
                "severity":"CRITICAL","location":dm,
                "recommendation":"Perform all authentication checks on the server side. Client-side checks are cosmetic and easily bypassed."})
    if findings:
        sa.findings.append({"category":"10. Authentication Issues","rules":findings})


def detect_x509_validation(sa):
    findings = []
    src = sa._string_in_source(r'(TrustManager|checkServerTrusted|checkClientTrusted).{0,200}(catch|return null|true)')
    if src:
        for sm in src[:5]:
            findings.append({"id":"ADV-013","name":"Improper X.509 Certificate Validation",
                "description":"Custom TrustManager may bypass TLS/SSL certificate validation, enabling MITM attacks.",
                "severity":"CRITICAL","location":sm,
                "recommendation":"Remove custom TrustManager implementations. Use system default trust store. Implement certificate pinning via Network Security Config."})
    allow_all = sa._find_methods_by_string("ALLOW_ALL_HOSTNAME_VERIFIER")
    if allow_all:
        for dm in allow_all[:3]:
            findings.append({"id":"ADV-014","name":"ALLOW_ALL_HOSTNAME_VERIFIER Used",
                "description":"Hostname verification is completely disabled.",
                "severity":"CRITICAL","location":dm,
                "recommendation":"Never use ALLOW_ALL_HOSTNAME_VERIFIER."})
    http_usage = sa._find_methods_by_regex(r'http://.*url|http://.*api')
    if http_usage and not findings:
        for dm in http_usage[:3]:
            findings.append({"id":"ADV-NET-001","name":"HTTP URL Used (Cleartext Traffic)",
                "description":"HTTP URLs are used, transmitting data in plaintext. On API 28+, cleartext is blocked by default.",
                "severity":"MEDIUM","location":dm,
                "recommendation":"Use HTTPS for all network communications."})
    if findings:
        sa.findings.append({"category":"16. Network Security Issues","rules":findings})


def detect_android_keystore_usage(sa):
    findings = []
    ks = sa._find_methods_by_invoke("Ljava/security/KeyStore;->getInstance")
    if ks is None:
        findings.append({"id":"ADV-033","name":"Android Keystore Not Used",
            "description":"Cryptographic operations may not use the Android Keystore.",
            "severity":"MEDIUM","location":"bytecode analysis",
            "recommendation":"Use the Android Keystore for key generation and storage."})
    if findings:
        sa.findings.append({"category":"Android Keystore","rules":findings})


def detect_ssl_pinning_config(sa):
    findings = []
    cp = sa._find_methods_by_invoke("Lokhttp3/CertificatePinner")
    nsc = sa._string_in_source(r"network_security_config|networkSecurityConfig")
    if sa.strings and not cp and not nsc:
        https = any("https://" in str(s) for s in sa.strings)
        if https:
            findings.append({"id":"ADV-054","name":"SSL/TLS Pinning Not Implemented",
                "severity":"MEDIUM","location":"bytecode analysis",
                "recommendation":"Implement certificate pinning via OkHttp CertificatePinner or Network Security Config."})
    if findings:
        sa.findings.append({"category":"SSL/TLS Pinning","rules":findings})


def detect_account_takeover(sa):
    findings = []
    token_in_uri = sa._find_methods_by_regex(r'Uri\.parse.*token|Uri\.parse.*access_token|Uri\.parse.*auth|Uri\.parse.*jwt|getQueryParameter.*token|getQueryParameter.*auth')
    for dm in token_in_uri[:5]:
        findings.append({"id":"ADV-ATO-001","name":"Auth Token Passed in URI — Token Theft via Referrer/Logs",
            "description":f"Auth tokens appear in URI strings in {dm}. Tokens in URIs are leaked through browser referrer headers, server logs, and can be captured by other apps reading the clipboard or logs.",
            "severity":"CRITICAL","location":dm,
            "recommendation":"Use authorization code flow with PKCE for OAuth. Never pass tokens in URLs, fragments, or query parameters."})
    oauth_implicit = sa._find_methods_by_regex(r'response_type.*token|implicit.*grant|#access_token|#token')
    if oauth_implicit:
        for dm in oauth_implicit[:3]:
            findings.append({"id":"ADV-ATO-002","name":"OAuth Implicit Flow Detected — Token in URL Fragment Risk",
                "description":f"OAuth implicit grant flow detected in {dm}. The access_token is returned in the URL fragment (#), which is visible to other apps on the device and captured in browser history.",
                "severity":"CRITICAL","location":dm,
                "recommendation":"Migrate to authorization code flow with PKCE (Proof Key for Code Exchange). The implicit flow is deprecated by OAuth 2.1."})
    magic_link = sa._find_methods_by_regex(r'magic.*link|magiclink|magic_link|email.*link.*login|passwordless.*link')
    if magic_link:
        for dm in magic_link[:3]:
            findings.append({"id":"ADV-ATO-003","name":"Magic Link / Passwordless Login Detected — Link Interception Risk",
                "description":f"Magic link or passwordless login mechanism detected in {dm}. If the magic link contains a token in the URL, it can be intercepted via referrer headers, clipboard access, or notification access.",
                "severity":"HIGH","location":dm,
                "recommendation":"Ensure magic links require the user to be on the same device. Use universal links with associated domains. Never include session tokens directly in magic link URLs."})
    password_reset_weak = sa._find_methods_by_regex(r'password.*reset.*link|forgot.*password.*send|resetPassword.*email|sendPasswordReset')
    if password_reset_weak:
        for dm in password_reset_weak[:3]:
            findings.append({"id":"ADV-ATO-004","name":"Password Reset Over Email — Reset Link Token Exposure",
                "description":f"Password reset via email link in {dm}. If the reset token is in the URL, it may be leaked via referrer headers, logged by analytics, or intercepted by a malicious app registered for the same deep link scheme.",
                "severity":"HIGH","location":dm,
                "recommendation":"Send reset tokens via out-of-band channels (e.g., in-app notification). Validate reset token binding to device. Use short expiration times for reset tokens."})
    account_linking = sa._find_methods_by_regex(r'account.*link|link.*account|social.*login.*link|oauth.*link')
    if account_linking:
        findings.append({"id":"ADV-ATO-005","name":"Account Linking / Social Login — Account Takeover via OAuth Misconfiguration",
            "description":"Account linking or social login functionality detected. Vulnerabilities in account linking (e.g., not verifying email ownership) can lead to account takeover.",
            "severity":"CRITICAL","location":"bytecode analysis",
            "recommendation":"Verify the user owns both accounts before linking. Require re-authentication for account linking operations. Validate email verification status."})
    session_from_wv = sa._find_methods_by_regex(r'CookieManager.*getCookie|CookieManager.*setCookie|CookieSyncManager')
    if session_from_wv:
        findings.append({"id":"ADV-ATO-006","name":"Session/Token Accessed via WebView CookieManager",
            "description":"WebView CookieManager is used to access or set cookies. Session tokens in WebView cookies can be stolen by JavaScript injection or via the JavaScript bridge.",
            "severity":"CRITICAL","location":"bytecode analysis",
            "recommendation":"Avoid storing session tokens in WebView cookies when JavaScript is enabled. Use Authorization headers instead of cookies for API auth."})
    if findings:
        sa.findings.append({"category":"26. Account Takeover — Token Theft / Session Hijacking / OAuth / Password Reset","rules":findings})


def detect_auth_authorization_gaps(sa):
    findings = []
    client_side_auth = sa._find_methods_by_regex(r'if.*password.*equals|local.*auth.*check|isAuthenticated.*true|isAuthorized.*return.*true')
    for dm in client_side_auth[:5]:
        findings.append({"id":"ADV-AUTH-010","name":"Client-Side Authorization Check — Easily Bypassed",
            "description":f"Authorization appears to be checked entirely on the client side in {dm}. Client-side checks can be bypassed by decompiling and patching the APK.",
            "severity":"CRITICAL","location":dm,
            "recommendation":"Perform all authorization decisions on the server. Client-side checks are cosmetic only and provide no real security."})
    session_validation = sa._find_methods_by_regex(r'session.*null|session.*==.*null|token.*==.*null|isLoggedIn.*return|getSession.*null')
    if session_validation:
        for dm in session_validation[:3]:
            findings.append({"id":"ADV-AUTH-011","name":"Local Session Validation Only — Token Stored Locally With No Server Verification",
                "description":f"Session/token validation appears to check only local storage in {dm}. If the session is not verified with the server on each request, old/stolen tokens can be replayed.",
                "severity":"HIGH","location":dm,
                "recommendation":"Validate session tokens with the server on every sensitive operation. Implement token rotation and blacklist compromised tokens server-side."})
    mfa_bypass = sa._find_methods_by_regex(r'MFA.*skip|bypass.*MFA|otp.*skip|skip.*verification|isMFA.*false')
    if mfa_bypass:
        for dm in mfa_bypass[:3]:
            findings.append({"id":"ADV-AUTH-012","name":"MFA Bypass Logic Detected — Multi-Factor Authentication Can Be Skipped",
                "description":f"MFA bypass logic found in {dm}. If MFA can be skipped via a client-side flag or by calling a different API endpoint, attackers can bypass 2FA.",
                "severity":"CRITICAL","location":dm,
                "recommendation":"Enforce MFA server-side. Never allow client-side flags to control MFA requirements."})
    email_verify_bypass = sa._find_methods_by_regex(r'email.*skip|skip.*email.*verify|isEmailVerified.*false.*return.*true|emailVerified.*true')
    if email_verify_bypass:
        for dm in email_verify_bypass[:3]:
            findings.append({"id":"ADV-AUTH-013","name":"Email Verification Bypass — Client-Side Email Verification Check",
                "description":f"Email verification can be bypassed client-side in {dm}. If the isEmailVerified flag is set locally without server confirmation, users can access features without verified emails.",
                "severity":"HIGH","location":dm,
                "recommendation":"Enforce email verification server-side. Never trust client-side email verification status for sensitive operations."})
    admin_check = sa._find_methods_by_regex(r'isAdmin.*return.*true|isAdmin.*false.*else|role.*admin.*if|admin.*check.*local')
    if admin_check:
        for dm in admin_check[:3]:
            findings.append({"id":"ADV-AUTH-014","name":"Admin Role Check on Client Side — Privilege Escalation Risk",
                "description":f"Admin role verification is done client-side in {dm}. An attacker can patch the APK to bypass admin checks and access admin functionality.",
                "severity":"CRITICAL","location":dm,
                "recommendation":"Enforce admin role checks exclusively on the server. Client-side admin checks provide no security."})
    if findings:
        sa.findings.append({"category":"27. Authentication / Authorization Gaps — Client-Side Auth / MFA Bypass / Session Validation","rules":findings})


def detect_network_mitm(sa):
    findings = []
    custom_ca = sa._find_methods_by_invoke("Ljavax/net/ssl/SSLContext;->init")
    if custom_ca:
        findings.append({"id":"ADV-MITM-001","name":"Custom SSLContext Used — Potential MITM via Custom Trust",
            "description":"A custom SSLContext is initialized. If a custom TrustManager is used without proper certificate validation, all TLS connections are vulnerable to MITM attacks.",
            "severity":"CRITICAL","location":"bytecode analysis",
            "recommendation":"Use the default SSLContext. Avoid custom TrustManager implementations. Use certificate pinning via Network Security Config."})
    hostname_verifier = sa._find_methods_by_invoke("Ljavax/net/ssl/HttpsURLConnection;->setDefaultHostnameVerifier")
    if hostname_verifier:
        for dm in hostname_verifier[:3]:
            findings.append({"id":"ADV-MITM-002","name":"Custom HostnameVerifier Set Globally — MITM Risk",
                "description":f"setDefaultHostnameVerifier() in {dm} sets a custom hostname verifier globally for all HTTPS connections. A permissive verifier disables hostname validation.",
                "severity":"CRITICAL","location":dm,
                "recommendation":"Avoid setDefaultHostnameVerifier(). Use per-connection hostname verification or certificate pinning instead."})
    domain_fronting = sa._find_methods_by_regex(r'x-amz-cf-.*domain|X-Forwarded-Host|alt.*host|fallback.*host|cdn.*host[^.]*\.com')
    if domain_fronting:
        for dm in domain_fronting[:3]:
            findings.append({"id":"ADV-MITM-003","name":"Potential Domain Fronting — CDN/Proxy Hostname Manipulation",
                "description":f"Domain fronting indicators in {dm}. Domain fronting can bypass network security controls and CORS policies.",
                "severity":"MEDIUM","location":dm,
                "recommendation":"Audit custom CDN/proxy hostname logic. Ensure TLS connections validate the correct server hostname."})
    if findings:
        sa.findings.append({"category":"33. Network MITM — SSLContext / HostnameVerifier / Domain Fronting","rules":findings})

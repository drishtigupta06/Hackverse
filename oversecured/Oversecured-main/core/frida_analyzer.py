import json
import os
import sys
import subprocess
import threading
import time
import re
try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

SSL_PINNING_SCRIPT = r"""
Java.perform(function () {
    var results = [];

    function logResult(category, detail, status) {
        var msg = JSON.stringify({type: 'ssl_pinning', category: category, detail: detail, status: status});
        results.push(JSON.parse(msg));
        send(msg);
    }

    // TrustManager (custom)
    try {
        var TrustManager = Java.use('javax.net.ssl.TrustManager');
        logResult('TrustManager', 'javax.net.ssl.TrustManager found', 'info');
    } catch (e) {}

    // X509TrustManager (custom implementations = pinning bypass)
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        X509TrustManager.checkClientTrusted.implementation = function (chain, authType) {
            logResult('X509TrustManager', 'checkClientTrusted called  auth=' + authType, 'bypass');
        };
        X509TrustManager.checkServerTrusted.implementation = function (chain, authType) {
            logResult('X509TrustManager', 'checkServerTrusted called  auth=' + authType, 'bypass');
        };
    } catch (e) {}

    // HostnameVerifier (allow all = bypass)
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        HostnameVerifier.verify.implementation = function (hostname, session) {
            logResult('HostnameVerifier', 'verify called  hostname=' + hostname, 'bypass');
            return true;
        };
    } catch (e) {}

    // SSLSocketFactory
    try {
        var SSLSocketFactory = Java.use('javax.net.ssl.SSLSocketFactory');
        SSLSocketFactory.createSocket.overload('[Ljava.net.Socket;', 'java.lang.String', 'int', 'boolean').implementation = function (socket, host, port, autoClose) {
            logResult('SSLSocketFactory', 'createSocket  host=' + host + ' port=' + port, 'info');
            return this.createSocket(socket, host, port, autoClose);
        };
    } catch (e) {}

    // HttpsURLConnection.setHostnameVerifier (custom = bypass)
    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setHostnameVerifier.implementation = function (verifier) {
            logResult('HttpsURLConnection', 'setHostnameVerifier called', 'bypass_set');
        };
    } catch (e) {}

    // OkHttp CertificatePinner / HostnameVerifier
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        OkHttpClient.newBuilder.implementation = function () {
            logResult('OkHttp', 'OkHttpClient.newBuilder called', 'info');
            return this.newBuilder();
        };
    } catch (e) {}
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.implementation = function (hostname, peerCertificates) {
            logResult('OkHttp CertificatePinner', 'check called  hostname=' + hostname, 'pinned');
            return this.check(hostname, peerCertificates);
        };
    } catch (e) {}
    try {
        var OkHttpHostnameVerifier = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
        OkHttpHostnameVerifier.verify.implementation = function (hostname, session) {
            logResult('OkHttp HostnameVerifier', 'verify  hostname=' + hostname, 'bypass');
            return true;
        };
    } catch (e) {}

    // NetworkSecurityManager (Android N+)
    try {
        var NetworkSecurityManager = Java.use('android.security.NetworkSecurityPolicy');
        NetworkSecurityManager.isCleartextTrafficPermitted.implementation = function () {
            logResult('NetworkSecurityPolicy', 'isCleartextTrafficPermitted', 'cleartext');
            return true;
        };
    } catch (e) {}

    // Apache HttpClient (legacy)
    try {
        var SchemeRegistry = Java.use('org.apache.http.conn.SchemeRegistry');
        SchemeRegistry.register.implementation = function (scheme) {
            logResult('Apache HttpClient', 'SchemeRegistry.register', 'info');
            return this.register(scheme);
        };
    } catch (e) {}

    send(JSON.stringify({type: 'ssl_pinning', done: true, results: results}));
});
"""

ROOT_DETECTION_SCRIPT = r"""
Java.perform(function () {
    var results = [];

    function logResult(method, clazz, status) {
        var msg = JSON.stringify({type: 'root_detection', method: method, clazz: clazz, status: status});
        results.push(JSON.parse(msg));
        send(msg);
    }

    var rootMethods = [
        // File-based checks
        ['java.io.File', '.+'],
        // Runtime.exec checks
        ['java.lang.Runtime', 'exec'],
        // Build tags
        ['android.os.Build', 'TAGS'],
        // SystemProperties
        ['android.os.SystemProperties', 'get'],
        // PackageManager
        ['android.content.pm.PackageManager', 'getPackageInfo'],
        // ProcessBuilder
        ['java.lang.ProcessBuilder', 'start'],
        // SELinux
        ['android.os.SELinux', 'isSELinuxEnabled'],
        // Superuser
        ['java.lang.System', 'getProperty'],
    ];

    // Hook common root detection file paths
    var File = Java.use('java.io.File');
    var rootPaths = [
        '/system/app/Superuser.apk', '/sbin/su', '/system/bin/su',
        '/system/xbin/su', '/data/local/xbin/su', '/data/local/bin/su',
        '/system/sd/xbin/su', '/system/bin/failsafe/su', '/data/local/su',
        '/su/bin/su', '/magisk', '/sbin/magisk', '/data/adb/magisk',
        '/data/adb/modules', '/system/lib/libsu.so', '/system/lib64/libsu.so'
    ];
    File.exists.implementation = function () {
        var path = this.getPath();
        if (rootPaths.indexOf(path) !== -1) {
            logResult('File.exists', path, 'detected_root_path');
        }
        return this.exists();
    };

    // Hook Runtime.exec
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmdarray) {
            var cmdStr = JSON.stringify(cmdarray);
            logResult('Runtime.exec', cmdStr, 'exec_called');
            return this.exec(cmdarray);
        };
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            logResult('Runtime.exec', cmd, 'exec_called');
            return this.exec(cmd);
        };
    } catch (e) {}

    // Hook ProcessBuilder
    try {
        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        ProcessBuilder.start.implementation = function () {
            logResult('ProcessBuilder.start', 'process started', 'exec_called');
            return this.start();
        };
    } catch (e) {}

    // Hook PackageManager.getPackageInfo for root apps
    try {
        var PackageManager = Java.use('android.content.pm.PackageManager');
        PackageManager.getPackageInfo.implementation = function (pkgName, flags) {
            var rootPkgs = ['com.noshufou.android.su', 'com.thirdparty.superuser',
                'eu.chainfire.supersu', 'com.koushikdutta.superuser',
                'com.topjohnwu.magisk', 'io.defuse.rootchecker'];
            if (rootPkgs.indexOf(pkgName) !== -1) {
                logResult('PackageManager.getPackageInfo', pkgName, 'detected_root_app');
            }
            return this.getPackageInfo(pkgName, flags);
        };
    } catch (e) {}

    // Hook Build.TAGS for test-keys
    try {
        var Build = Java.use('android.os.Build');
        var tagsField = Build.TAGS.value;
        if (tagsField && tagsField.indexOf('test-keys') !== -1) {
            logResult('Build.TAGS', 'test-keys found', 'detected_test_keys');
        }
    } catch (e) {}

    // Hook SystemProperties (MagiskHide)
    try {
        var SystemProperties = Java.use('android.os.SystemProperties');
        SystemProperties.get.overload('java.lang.String').implementation = function (key) {
            var val = this.get(key);
            if (key.indexOf('ro.') === 0) {
                logResult('SystemProperties.get', key + '=' + val, 'prop_read');
            }
            return val;
        };
    } catch (e) {}

    // Hook System.getProperty
    try {
        var System = Java.use('java.lang.System');
        System.getProperty.overload('java.lang.String').implementation = function (key) {
            var val = this.getProperty(key);
            logResult('System.getProperty', key + '=' + val, 'prop_read');
            return val;
        };
    } catch (e) {}

    // Check /proc/1/mountinfo for magisk mounts
    try {
        var FileReader = Java.use('java.io.FileReader');
        var BufferedReader = Java.use('java.io.BufferedReader');
    } catch (e) {}

    send(JSON.stringify({type: 'root_detection', done: true, results: results}));
});
"""

RUNTIME_HOOKS_SCRIPT = r"""
Java.perform(function () {
    var results = [];

    function logResult(method, clazz, args, retval) {
        var msg = JSON.stringify({type: 'runtime_hook', method: method, clazz: clazz, args: args, retval: retval});
        results.push(JSON.parse(msg));
        send(msg);
    }

    // Crypto operations
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.doFinal.overload('[B').implementation = function (input) {
            logResult('Cipher.doFinal', 'javax.crypto.Cipher', bytesToHex(input), null);
            return this.doFinal(input);
        };
        Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
            logResult('Cipher.init', 'javax.crypto.Cipher', mode === 1 ? 'ENCRYPT' : 'DECRYPT', null);
            return this.init(mode, key);
        };
    } catch (e) {}

    // SharedPreferences (hooked in SharedPrefsMonitor instead)

    // SQLiteDatabase
    try {
        var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
        SQLiteDatabase.rawQuery.implementation = function (sql, selectionArgs) {
            logResult('rawQuery', 'SQLiteDatabase', sql, null);
            return this.rawQuery(sql, selectionArgs);
        };
        SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function (sql) {
            logResult('execSQL', 'SQLiteDatabase', sql, null);
            return this.execSQL(sql);
        };
    } catch (e) {}

    // WebView
    try {
        var WebView = Java.use('android.webkit.WebView');
        WebView.loadUrl.implementation = function (url) {
            logResult('loadUrl', 'WebView', url, null);
            return this.loadUrl(url);
        };
        WebView.evaluateJavascript.implementation = function (script, callback) {
            logResult('evaluateJavascript', 'WebView', script, null);
            return this.evaluateJavascript(script, callback);
        };
    } catch (e) {}

    // Toast (commonly used for root/detection feedback)
    try {
        var Toast = Java.use('android.widget.Toast');
        Toast.show.implementation = function () {
            logResult('Toast.show', 'android.widget.Toast', this.getText(), null);
            return this.show();
        };
    } catch (e) {}

    // Log
    try {
        var Log = Java.use('android.util.Log');
        Log.d.implementation = function (tag, msg) {
            logResult('Log.d', 'android.util.Log', tag + ': ' + msg, null);
            return Log.d(tag, msg);
        };
        Log.e.implementation = function (tag, msg) {
            logResult('Log.e', 'android.util.Log', tag + ': ' + msg, null);
            return Log.e(tag, msg);
        };
    } catch (e) {}

    function bytesToHex(bytes) {
        if (!bytes) return 'null';
        var hex = '';
        for (var i = 0; i < Math.min(bytes.length, 32); i++) {
            hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
        }
        if (bytes.length > 32) hex += '...';
        return hex;
    }

    send(JSON.stringify({type: 'runtime_hook', done: true, results: results}));
});
"""

API_MONITOR_SCRIPT = r"""
Java.perform(function () {
    var results = [];
    var categoryMap = {};

    function logResult(category, method, detail) {
        var msg = JSON.stringify({type: 'api_monitor', category: category, method: method, detail: detail});
        results.push(JSON.parse(msg));
        if (!categoryMap[category]) categoryMap[category] = 0;
        categoryMap[category]++;
        send(msg);
    }

    // ── Network API Monitoring ──
    try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.connect.implementation = function () {
            var url = this.getURL();
            logResult('network', 'HttpURLConnection.connect', url ? url.toString() : 'unknown');
            return this.connect();
        };
        var URL = Java.use('java.net.URL');
        URL.openConnection.implementation = function () {
            logResult('network', 'URL.openConnection', this.toString());
            return this.openConnection();
        };
    } catch (e) {}
    try {
        var OkHttpCall = Java.use('okhttp3.Call');
        OkHttpCall.execute.implementation = function () {
            logResult('network', 'OkHttp.execute', 'request');
            return this.execute();
        };
        OkHttpCall.enqueue.implementation = function (callback) {
            logResult('network', 'OkHttp.enqueue', 'async request');
            return this.enqueue(callback);
        };
    } catch (e) {}

    // ── File I/O Monitoring ──
    try {
        var FileOutputStream = Java.use('java.io.FileOutputStream');
        FileOutputStream.write.overload('[B').implementation = function (b) {
            var path = this.getFD() ? this.getFD().toString() : 'unknown';
            logResult('file_io', 'FileOutputStream.write', path + '  size=' + b.length);
            return this.write(b);
        };
        var FileInputStream = Java.use('java.io.FileInputStream');
        FileInputStream.read.overload('[B').implementation = function (b) {
            var path = this.getFD() ? this.getFD().toString() : 'unknown';
            logResult('file_io', 'FileInputStream.read', path + '  size=' + b.length);
            return this.read(b);
        };
    } catch (e) {}

    // ── ContentResolver / URI operations ──
    try {
        var ContentResolver = Java.use('android.content.ContentResolver');
        ContentResolver.query.implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
            logResult('content_resolver', 'ContentResolver.query', uri ? uri.toString() : 'unknown');
            return this.query(uri, projection, selection, selectionArgs, sortOrder);
        };
        ContentResolver.insert.implementation = function (uri, values) {
            logResult('content_resolver', 'ContentResolver.insert', uri ? uri.toString() : 'unknown');
            return this.insert(uri, values);
        };
        ContentResolver.openInputStream.implementation = function (uri) {
            logResult('content_resolver', 'ContentResolver.openInputStream', uri ? uri.toString() : 'unknown');
            return this.openInputStream(uri);
        };
    } catch (e) {}

    // ── Intent operations ──
    try {
        var Intent = Java.use('android.content.Intent');
        Intent.putExtra.overload('java.lang.String', 'java.lang.String').implementation = function (key, value) {
            logResult('intent', 'Intent.putExtra(String)', key + '=' + value);
            return this.putExtra(key, value);
        };
        Intent.getStringExtra.implementation = function (key) {
            var val = this.getStringExtra(key);
            logResult('intent', 'Intent.getStringExtra', key + '=' + (val || 'null'));
            return val;
        };
    } catch (e) {}

    // ── Notification Manager ──
    try {
        var NotificationManager = Java.use('android.app.NotificationManager');
        NotificationManager.notify.overload('int', 'android.app.Notification').implementation = function (id, notification) {
            logResult('notification', 'NotificationManager.notify', 'id=' + id);
            return this.notify(id, notification);
        };
    } catch (e) {}

    // ── Location ──
    try {
        var LocationManager = Java.use('android.location.LocationManager');
        LocationManager.getLastKnownLocation.implementation = function (provider) {
            logResult('location', 'getLastKnownLocation', provider);
            return this.getLastKnownLocation(provider);
        };
        LocationManager.requestLocationUpdates.overload('java.lang.String', 'long', 'float', 'android.location.LocationListener').implementation = function (provider, minTime, minDistance, listener) {
            logResult('location', 'requestLocationUpdates', provider + ' minTime=' + minTime);
            return this.requestLocationUpdates(provider, minTime, minDistance, listener);
        };
    } catch (e) {}

    send(JSON.stringify({type: 'api_monitor', done: true, results: results, categoryMap: categoryMap}));
});
"""

SHAREDPREFS_MONITOR_SCRIPT = r"""
Java.perform(function () {
    var results = [];

    function logResult(method, detail, clazz) {
        var msg = JSON.stringify({type: 'sharedprefs', method: method, detail: detail, clazz: clazz || 'SharedPreferences'});
        results.push(JSON.parse(msg));
        send(msg);
    }

    // Hook SharedPreferences.Editor
    try {
        var Editor = Java.use('android.content.SharedPreferences$Editor');

        Editor.putString.implementation = function (key, value) {
            logResult('putString', key + ' = ' + value, 'SharedPreferences.Editor');
            return this.putString(key, value);
        };
        Editor.putInt.implementation = function (key, value) {
            logResult('putInt', key + ' = ' + value, 'SharedPreferences.Editor');
            return this.putInt(key, value);
        };
        Editor.putLong.implementation = function (key, value) {
            logResult('putLong', key + ' = ' + value, 'SharedPreferences.Editor');
            return this.putLong(key, value);
        };
        Editor.putFloat.implementation = function (key, value) {
            logResult('putFloat', key + ' = ' + value, 'SharedPreferences.Editor');
            return this.putFloat(key, value);
        };
        Editor.putBoolean.implementation = function (key, value) {
            logResult('putBoolean', key + ' = ' + value, 'SharedPreferences.Editor');
            return this.putBoolean(key, value);
        };
        Editor.putStringSet.implementation = function (key, value) {
            logResult('putStringSet', key + ' = ' + JSON.stringify(value), 'SharedPreferences.Editor');
            return this.putStringSet(key, value);
        };
        Editor.remove.implementation = function (key) {
            logResult('remove', key, 'SharedPreferences.Editor');
            return this.remove(key);
        };
        Editor.clear.implementation = function () {
            logResult('clear', 'all keys', 'SharedPreferences.Editor');
            return this.clear();
        };
        Editor.commit.implementation = function () {
            logResult('commit', 'changes committed', 'SharedPreferences.Editor');
            return this.commit();
        };
        Editor.apply.implementation = function () {
            logResult('apply', 'changes applied (async)', 'SharedPreferences.Editor');
            this.apply();
        };
    } catch (e) {}

    // Hook SharedPreferences read methods
    try {
        var SharedPrefs = Java.use('android.content.SharedPreferences');

        SharedPrefs.getString.implementation = function (key, defValue) {
            var val = this.getString(key, defValue);
            logResult('getString', key + ' = ' + (val != null ? val : 'null'), 'SharedPreferences');
            return val;
        };
        SharedPrefs.getInt.implementation = function (key, defValue) {
            var val = this.getInt(key, defValue);
            logResult('getInt', key + ' = ' + val, 'SharedPreferences');
            return val;
        };
        SharedPrefs.getLong.implementation = function (key, defValue) {
            var val = this.getLong(key, defValue);
            logResult('getLong', key + ' = ' + val, 'SharedPreferences');
            return val;
        };
        SharedPrefs.getFloat.implementation = function (key, defValue) {
            var val = this.getFloat(key, defValue);
            logResult('getFloat', key + ' = ' + val, 'SharedPreferences');
            return val;
        };
        SharedPrefs.getBoolean.implementation = function (key, defValue) {
            var val = this.getBoolean(key, defValue);
            logResult('getBoolean', key + ' = ' + val, 'SharedPreferences');
            return val;
        };
        SharedPrefs.getStringSet.implementation = function (key, defValues) {
            var val = this.getStringSet(key, defValues);
            logResult('getStringSet', key + ' = ' + (val ? JSON.stringify(val) : 'null'), 'SharedPreferences');
            return val;
        };
        SharedPrefs.contains.implementation = function (key) {
            var val = this.contains(key);
            logResult('contains', key + ' = ' + val, 'SharedPreferences');
            return val;
        };
        SharedPrefs.getAll.implementation = function () {
            var all = this.getAll();
            logResult('getAll', all ? JSON.stringify(all) : 'empty/null', 'SharedPreferences');
            return all;
        };
    } catch (e) {}

    // Hook Context.getSharedPreferences to log file names
    try {
        var Context = Java.use('android.content.Context');
        Context.getSharedPreferences.implementation = function (name, mode) {
            var modeStr = mode === 0 ? 'MODE_PRIVATE' : mode === 1 ? 'MODE_WORLD_READABLE' : mode === 2 ? 'MODE_WORLD_WRITEABLE' : 'MODE_' + mode;
            logResult('getSharedPreferences', 'name=' + name + ' mode=' + modeStr, 'Context');
            return this.getSharedPreferences(name, mode);
        };
    } catch (e) {}

    // Hook PreferenceManager.getDefaultSharedPreferences
    try {
        var PreferenceManager = Java.use('android.preference.PreferenceManager');
        PreferenceManager.getDefaultSharedPreferences.implementation = function (context) {
            logResult('getDefaultSharedPreferences', 'called', 'PreferenceManager');
            return PreferenceManager.getDefaultSharedPreferences(context);
        };
    } catch (e) {}

    // Hook Activity.getPreferences
    try {
        var Activity = Java.use('android.app.Activity');
        Activity.getPreferences.implementation = function (mode) {
            logResult('getPreferences', 'mode=' + mode, 'Activity');
            return this.getPreferences(mode);
        };
        Activity.getSharedPreferences.implementation = function (name, mode) {
            logResult('getSharedPreferences(Activity)', 'name=' + name + ' mode=' + mode, 'Activity');
            return this.getSharedPreferences(name, mode);
        };
    } catch (e) {}

    send(JSON.stringify({type: 'sharedprefs', done: true, results: results}));
});
"""


class FridaAnalyzer:
    def __init__(self, target_package=None, device_id="usb", attach=False):
        self.target_package = target_package
        self.device_id = device_id
        self.attach_mode = attach
        self.session = None
        self.device = None
        self.results = {
            "ssl_pinning": [],
            "root_detection": [],
            "runtime_hooks": [],
            "api_monitor": [],
            "sharedprefs": [],
        }
        self._message_callbacks = {}

    def _on_message(self, feature, message, data):
        if message.get("type") == "send":
            payload = message.get("payload", {})
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except json.JSONDecodeError:
                    pass
            if isinstance(payload, dict):
                ptype = payload.get("type", "unknown")
                if ptype == "ssl_pinning":
                    self.results["ssl_pinning"].append(payload)
                elif ptype == "root_detection":
                    self.results["root_detection"].append(payload)
                elif ptype == "runtime_hook":
                    self.results["runtime_hooks"].append(payload)
                elif ptype == "api_monitor":
                    self.results["api_monitor"].append(payload)
                elif ptype == "sharedprefs":
                    self.results["sharedprefs"].append(payload)
        elif message.get("type") == "error":
            print(f"[-] Frida error: {message.get('description', '')}")

    def _get_device(self):
        try:
            self.device = frida.get_device(self.device_id, timeout=10)
            return self.device
        except Exception:
            try:
                self.device = frida.get_usb_device(timeout=10)
                return self.device
            except Exception:
                try:
                    self.device = frida.get_remote_device()
                    return self.device
                except Exception as e:
                    print(f"[-] Cannot connect to Frida device: {e}")
                    return None

    def _spawn_or_attach(self):
        if not self.device:
            return None
        try:
            if self.attach_mode or not self.target_package:
                self.session = self.device.attach(self.target_package)
                print(f"[+] Attached to {self.target_package} (PID: {self.session.pid})")
            else:
                pid = self.device.spawn([self.target_package])
                self.session = self.device.attach(pid)
                print(f"[+] Spawned {self.target_package} (PID: {pid})")
                self.device.resume(pid)
            return self.session
        except Exception as e:
            print(f"[-] Failed to spawn/attach: {e}")
            return None

    def connect(self):
        """Public API: discover device and spawn/attach session in one call."""
        self._get_device()
        if self.device:
            self._spawn_or_attach()
        return self.session is not None

    def load_script(self, source_code, script_name="unnamed"):
        if not self.session:
            print(f"[-] No session for script '{script_name}'")
            return None
        try:
            script = self.session.create_script(source_code)
            script.on("message", self._on_message)
            script.load()
            print(f"[+] Loaded Frida script: {script_name}")
            return script
        except Exception as e:
            print(f"[-] Script '{script_name}' failed: {e}")
            return None

    def run_ssl_pinning_detection(self, timeout=15):
        print("[*] Frida SSL Pinning Detection...")
        script = self.load_script(SSL_PINNING_SCRIPT, "ssl_pinning")
        if not script:
            return []
        time.sleep(min(timeout, 5))
        return self.results["ssl_pinning"]

    def run_root_detection_detection(self, timeout=15):
        print("[*] Frida Root Detection Detection...")
        script = self.load_script(ROOT_DETECTION_SCRIPT, "root_detection")
        if not script:
            return []
        time.sleep(min(timeout, 5))
        return self.results["root_detection"]

    def run_runtime_hooks(self, timeout=15):
        print("[*] Frida Runtime Hooks...")
        script = self.load_script(RUNTIME_HOOKS_SCRIPT, "runtime_hooks")
        if not script:
            return []
        time.sleep(min(timeout, 5))
        return self.results["runtime_hooks"]

    def run_api_monitor(self, timeout=20):
        print("[*] Frida API Monitoring (network, file, content, intent, location)...")
        script = self.load_script(API_MONITOR_SCRIPT, "api_monitor")
        if not script:
            return []
        time.sleep(min(timeout, 10))
        return self.results["api_monitor"]

    def run_sharedprefs_monitor(self, timeout=15):
        print("[*] Frida SharedPrefs Monitoring...")
        script = self.load_script(SHAREDPREFS_MONITOR_SCRIPT, "sharedprefs_monitor")
        if not script:
            return []
        time.sleep(min(timeout, 5))
        return self.results["sharedprefs"]

    def run_all(self, timeout=30):
        print("[*] Frida: Running all dynamic analysis modules...")
        self.run_ssl_pinning_detection(timeout)
        self.run_root_detection_detection(timeout)
        self.run_runtime_hooks(timeout)
        self.run_api_monitor(timeout)
        self.run_sharedprefs_monitor(timeout)
        return self.get_summary()

    def get_summary(self):
        summary = {}
        for feature, items in self.results.items():
            done_items = [i for i in items if i.get("done")]
            data_items = [i for i in items if not i.get("done")]
            summary[feature] = {
                "total_events": len(items),
                "findings": len(data_items),
                "has_completed": len(done_items) > 0,
            }
        return summary

    def cleanup(self):
        if self.session:
            try:
                self.session.detach()
            except Exception:
                pass
            self.session = None


def check_frida_availability():
    return FRIDA_AVAILABLE

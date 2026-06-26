/**
 * Runtime Data Tracker — Frida script
 *
 * Traces sensitive data flowing through IPC boundaries:
 *   - Intent extras (getStringExtra, getParcelableExtra, getSerializableExtra)
 *   - Bundle data
 *   - SharedPreferences writes
 *   - SQLite writes
 *   - Clipboard access
 *   - Logcat leakage
 *
 * Hooks Java-level APIs; emits structured events readable by Python.
 */
'use strict';

const SENSITIVE_KEYS = new Set([
  'password', 'passwd', 'pin', 'otp', 'token', 'secret', 'key',
  'credential', 'jwt', 'bearer', 'auth', 'access_token', 'refresh_token',
  'api_key', 'apikey', 'private_key', 'session', 'ssn', 'credit',
  'card', 'cvv', 'account', 'routing', 'mfa', '2fa', 'security_code'
]);

const SENSITIVE_CLASSES = new Set([
  'Landroid/content/Intent;',
  'Landroid/os/Bundle;',
  'Landroid/content/pm/ParceledListSlice;'
]);

Java.perform(function () {
  const findings = [];
  const seen = new Set();

  function classifyKey(k) {
    if (!k || typeof k !== 'string') return null;
    const lower = k.toLowerCase();
    for (const kw of SENSITIVE_KEYS) {
      if (lower.includes(kw)) return kw;
    }
    return null;
  }

  function recordFinding(event) {
    const sig = event.klass + '::' + event.method + '::' + event.key;
    if (seen.has(sig)) return;
    seen.add(sig);
    send(JSON.stringify({type: 'storage_leak', event}));
  }

  // Intent / Bundle extra reads
  const intentCls = Java.use('android.content.Intent');
  intentCls.getStringExtra.overload('java.lang.String').implementation = function (key) {
    const v = this.getStringExtra(key);
    const kw = classifyKey(key);
    if (kw) {
      send(JSON.stringify({
        type: 'ipc_data', klass: 'Intent', method: 'getStringExtra',
        key, keyword: kw, value: v, src: this.toString()
      }));
    }
    return v;
  };
  intentCls.getBundleExtra.overload('java.lang.String').implementation = function (key) {
    const v = this.getBundleExtra(key);
    const kw = classifyKey(key);
    if (kw) {
      send(JSON.stringify({
        type: 'ipc_data', klass: 'Intent', method: 'getBundleExtra',
        key, keyword: kw, src: this.toString()
      }));
    }
    return v;
  };
  intentCls.getParcelableExtra.overload('java.lang.String').implementation = function (key) {
    const v = this.getParcelableExtra(key);
    const kw = classifyKey(key);
    if (kw) {
      send(JSON.stringify({
        type: 'ipc_data', klass: 'Intent', method: 'getParcelableExtra',
        key, keyword: kw, src: this.toString()
      }));
    }
    return v;
  };
  intentCls.getSerializableExtra.overload('java.lang.String').implementation = function (key) {
    const v = this.getSerializableExtra(key);
    const kw = classifyKey(key);
    if (kw) {
      send(JSON.stringify({
        type: 'ipc_data', klass: 'Intent', method: 'getSerializableExtra',
        key, keyword: kw, src: this.toString()
      }));
    }
    return v;
  };

  // Bundle access
  const bundleCls = Java.use('android.os.BaseBundle');
  bundleCls.getString.overload('java.lang.String').implementation = function (key) {
    const v = this.getString(key);
    const kw = classifyKey(key);
    if (kw) {
      send(JSON.stringify({
        type: 'ipc_data', klass: 'Bundle', method: 'getString',
        key, keyword: kw, value: v
      }));
    }
    return v;
  };

  // SharedPreferences write monitor
  try {
    const sp = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
    sp.putString.overload('java.lang.String', 'java.lang.String').implementation = function (k, v) {
      const kw = classifyKey(k);
      if (kw) {
        send(JSON.stringify({
          type: 'storage_write', klass: 'SharedPreferences', method: 'putString',
          key: k, keyword: kw, value: v
        }));
      }
      return this.putString(k, v);
    };
  } catch (e) {
    send(JSON.stringify({type: 'debug', msg: 'SP hook failed: ' + e}));
  }

  // Logcat leakage
  try {
    const log = Java.use('android.util.Log');
    ['d', 'i', 'w', 'e', 'v'].forEach(function (lvl) {
      log[lvl].overload('java.lang.String', 'java.lang.String').implementation = function (tag, msg) {
        if (msg && typeof msg === 'string' && SENSITIVE_KEYS.has(msg.toLowerCase())) {
          send(JSON.stringify({
            type: 'log_leak', klass: 'Log', method: 'Log.' + lvl,
            tag, msg, snippet: msg.substring(0, 120)
          }));
        }
        return this[lvl](tag, msg);
      };
    });
  } catch (e) {
    send(JSON.stringify({type: 'debug', msg: 'Log hook failed: ' + e}));
  }

  // SQLite openDatabase hook to detect plaintext DBs
  try {
    const sqlite = Java.use('android.database.sqlite.SQLiteDatabase');
    sqlite.openDatabase.implementation = function (path, factory, flags) {
      const s = String(path || '');
      if (s.endsWith('.db') || s.endsWith('.sqlite')) {
        send(JSON.stringify({
          type: 'db_open', path: s, flags: flags
        }));
      }
      return this.openDatabase(path, factory, flags);
    };
  } catch (e) {
    send(JSON.stringify({type: 'debug', msg: 'SQLite hook failed: ' + e}));
  }

  send(JSON.stringify({type: 'ready', msg: 'runtime_data_tracker loaded'}));
});

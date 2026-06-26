"""
Shared Taint Analysis Configuration
Single source of truth for taint sources, sinks, and sanitizers.
"""
# ── TAINT SOURCES ──────────────────────────────────────────────────────
TAINT_SOURCES = [
    # Intent / Bundle
    "Landroid/content/Intent;->getStringExtra", "Landroid/content/Intent;->getIntExtra",
    "Landroid/content/Intent;->getBooleanExtra", "Landroid/content/Intent;->getLongExtra",
    "Landroid/content/Intent;->getDoubleExtra", "Landroid/content/Intent;->getFloatExtra",
    "Landroid/content/Intent;->getSerializableExtra", "Landroid/content/Intent;->getParcelableExtra",
    "Landroid/content/Intent;->getStringArrayListExtra", "Landroid/content/Intent;->getIntegerArrayListExtra",
    "Landroid/content/Intent;->getParcelableArrayListExtra", "Landroid/content/Intent;->getCharSequenceExtra",
    "Landroid/content/Intent;->getCharArrayExtra", "Landroid/content/Intent;->getExtras",
    "Landroid/content/Intent;->getData", "Landroid/content/Intent;->getAction",
    "Landroid/content/Intent;->getScheme", "Landroid/content/Intent;->getHost",
    "Landroid/content/Intent;->getPath", "Landroid/content/Intent;->getQueryString",
    "Landroid/content/Intent;->getDataString",
    "Landroid/app/Activity;->getIntent", "Landroid/app/Activity;->getCallingPackage",
    # Uri
    "Landroid/net/Uri;->getQueryParameter", "Landroid/net/Uri;->getQueryParameters",
    "Landroid/net/Uri;->getPathSegments", "Landroid/net/Uri;->getLastPathSegment",
    "Landroid/net/Uri;->parse",
    # Bundle
    "Landroid/os/Bundle;->getString", "Landroid/os/Bundle;->getInt",
    "Landroid/os/Bundle;->getSerializable", "Landroid/os/Bundle;->getParcelable",
    "Landroid/os/Bundle;->getStringArrayList",
    # Clip / Clipboard
    "Landroid/content/ClipData$Item;->getText", "Landroid/content/ClipData$Item;->getUri",
    "Landroid/content/ClipboardManager;->getPrimaryClip",
    # Content Resolver
    "Landroid/content/ContentResolver;->openInputStream", "Landroid/content/ContentResolver;->openOutputStream",
    "Landroid/content/ContentResolver;->query",
    # IO
    "Ljava/io/BufferedReader;->readLine", "Ljava/io/BufferedReader;->read",
    "Ljava/io/InputStream;->read",
    # Network
    "Ljava/net/URL;->openConnection", "Ljava/net/HttpURLConnection;->getInputStream",
    "Ljava/net/HttpURLConnection;->getResponseCode",
    # Shared Preferences
    "Landroid/content/SharedPreferences;->getString", "Landroid/content/SharedPreferences;->getInt",
    "Landroid/content/SharedPreferences;->getBoolean",
    # EditText / View input
    "Landroid/widget/EditText;->getText", "Landroid/widget/TextView;->getText",
    "Landroid/widget/TextView;->toString",
    # Location / Sensors
    "Landroid/location/Location;->getLatitude", "Landroid/location/Location;->getLongitude",
    "Landroid/location/Location;->getProvider",
    # Telephony
    "Landroid/telephony/TelephonyManager;->getDeviceId",
    "Landroid/telephony/TelephonyManager;->getLine1Number",
    "Landroid/telephony/TelephonyManager;->getSimSerialNumber",
    "Landroid/telephony/TelephonyManager;->getSubscriberId",
    # Account Manager
    "Landroid/accounts/AccountManager;->getAccounts", "Landroid/accounts/AccountManager;->getUserData",
    "Landroid/accounts/AccountManager;->getAuthToken", "Landroid/accounts/AccountManager;->peekAuthToken",
    # Firebase / Remote Config
    "Lcom/google/firebase/remoteconfig/FirebaseRemoteConfig;->getString",
    "Lcom/google/firebase/remoteconfig/FirebaseRemoteConfig;->getLong",
    # NFC
    "Landroid/nfc/NdefMessage;->getRecords", "Landroid/nfc/NdefRecord;->getPayload",
    "Landroid/nfc/Tag;->getId",
]

# ── TAINT SINKS (grouped by vulnerability class) ────────────────────────
TAINT_SINKS = {
    "sqli": {
        "methods": [
            "Landroid/database/sqlite/SQLiteDatabase;->rawQuery",
            "Landroid/database/sqlite/SQLiteDatabase;->execSQL",
            "Landroid/database/sqlite/SQLiteDatabase;->compileStatement",
            "Landroid/database/sqlite/SQLiteDatabase;->query",
            "Landroid/database/sqlite/SQLiteDatabase;->delete",
            "Landroid/database/sqlite/SQLiteDatabase;->update",
        ],
        "param_index": {"Landroid/database/sqlite/SQLiteDatabase;->rawQuery": (1,)},
        "severity": "CRITICAL",
    },
    "webview_injection": {
        "methods": [
            "Landroid/webkit/WebView;->loadUrl", "Landroid/webkit/WebView;->loadData",
            "Landroid/webkit/WebView;->loadDataWithBaseURL",
            "Landroid/webkit/WebView;->evaluateJavascript",
            "Landroid/webkit/WebView;->addJavascriptInterface",
            "Landroid/webkit/WebView;->postUrl",
        ],
        "param_index": {m: (0,) for m in [
            "Landroid/webkit/WebView;->loadUrl", "Landroid/webkit/WebView;->loadData",
            "Landroid/webkit/WebView;->loadDataWithBaseURL",
            "Landroid/webkit/WebView;->evaluateJavascript",
            "Landroid/webkit/WebView;->postUrl",
        ]},
        "severity": "CRITICAL",
    },
    "path_traversal": {
        "methods": [
            "Ljava/io/File;-><init>", "Ljava/io/FileInputStream;-><init>",
            "Ljava/io/FileOutputStream;-><init>", "Ljava/io/FileReader;-><init>",
            "Ljava/io/FileWriter;-><init>",
            "Landroid/content/Context;->openFileInput", "Landroid/content/Context;->openFileOutput",
            "Landroid/content/Context;->getDatabasePath", "Landroid/content/Context;->getDir",
            "Ldalvik/system/DexClassLoader;-><init>", "Ldalvik/system/PathClassLoader;-><init>",
            "Ljava/util/zip/ZipFile;-><init>", "Ljava/util/jar/JarFile;-><init>",
            "Ljava/io/RandomAccessFile;-><init>",
        ],
        "param_index": {m: (0,) for m in [
            "Ljava/io/File;-><init>", "Ljava/io/FileInputStream;-><init>",
            "Ljava/io/FileOutputStream;-><init>", "Ljava/io/FileReader;-><init>",
            "Ljava/io/FileWriter;-><init>",
            "Landroid/content/Context;->openFileInput", "Landroid/content/Context;->openFileOutput",
        ]},
        "severity": "HIGH",
    },
    "file_disclosure": {
        "methods": [
            "Landroid/content/ContentResolver;->openInputStream",
            "Landroid/content/ContentResolver;->openOutputStream",
            "Landroid/content/ContentResolver;->openFileDescriptor",
            "Landroidx/core/content/FileProvider;->getUriForFile",
            "Landroid/support/v4/content/FileProvider;->getUriForFile",
            "Landroid/content/Context;->grantUriPermission",
            "Landroid/webkit/WebView;->loadUrl",
            "Landroid/webkit/WebView;->loadDataWithBaseURL",
            "Landroid/app/Activity;->setResult",
        ],
        "param_index": {},
        "severity": "HIGH",
    },
    "intent_injection": {
        "methods": [
            "Landroid/content/Intent;->setComponent", "Landroid/content/Intent;->setClassName",
            "Landroid/content/Intent;->setClass", "Landroid/content/Intent;->setPackage",
            "Landroid/content/Intent;->setData", "Landroid/content/Intent;->putExtra",
            "Landroid/content/Context;->startActivity", "Landroid/content/Context;->startService",
            "Landroid/content/Context;->bindService", "Landroid/content/Context;->sendBroadcast",
            "Landroid/content/Context;->sendOrderedBroadcast",
            "Landroid/app/Activity;->startActivityForResult", "Landroid/app/Activity;->setResult",
            "Landroid/app/PendingIntent;->getActivity",
            "Landroid/app/PendingIntent;->getService",
            "Landroid/app/PendingIntent;->getBroadcast",
        ],
        "param_index": {
            "Landroid/content/Intent;->setComponent": (0,), "Landroid/content/Intent;->setClassName": (0,),
            "Landroid/content/Intent;->setClass": (0,), "Landroid/content/Intent;->setPackage": (0,),
            "Landroid/content/Intent;->setData": (0,),
        },
        "severity": "CRITICAL",
    },
    "content_provider_abuse": {
        "methods": [
            "Landroid/content/ContentProvider;->query", "Landroid/content/ContentProvider;->insert",
            "Landroid/content/ContentProvider;->update", "Landroid/content/ContentProvider;->delete",
            "Landroid/content/ContentProvider;->openFile", "Landroid/content/ContentProvider;->openAssetFile",
        ],
        "param_index": {
            "Landroid/content/ContentProvider;->query": (1,), "Landroid/content/ContentProvider;->insert": (0,),
            "Landroid/content/ContentProvider;->update": (2,), "Landroid/content/ContentProvider;->delete": (1,),
        },
        "severity": "HIGH",
    },
    "command_execution": {
        "methods": [
            "Ljava/lang/Runtime;->exec", "Ljava/lang/ProcessBuilder;->start",
            "Ljava/lang/ProcessBuilder;-><init>",
            "Ljava/lang/Runtime;->loadLibrary", "Ljava/lang/Runtime;->load",
            "Ljava/lang/System;->loadLibrary", "Ljava/lang/System;->load",
        ],
        "param_index": {
            "Ljava/lang/Runtime;->exec": (0,), "Ljava/lang/ProcessBuilder;-><init>": (0,),
            "Ljava/lang/Runtime;->load": (0,), "Ljava/lang/System;->load": (0,),
            "Ljava/lang/System;->loadLibrary": (0,),
        },
        "severity": "CRITICAL",
    },
    "serialization": {
        "methods": [
            "Ljava/io/ObjectInputStream;->readObject", "Ljava/io/ObjectInputStream;->readUnshared",
            "Ljava/io/ObjectInputStream;->readObjectOverride",
            "Ljava/beans/XMLDecoder;->readObject",
            "Ljava/io/ObjectOutputStream;->writeObject",
        ],
        "param_index": {},
        "severity": "CRITICAL",
    },
    "logging": {
        "methods": [
            "Landroid/util/Log;->d", "Landroid/util/Log;->v", "Landroid/util/Log;->i",
            "Landroid/util/Log;->w", "Landroid/util/Log;->e", "Landroid/util/Log;->wtf",
            "Ljava/io/PrintStream;->print", "Ljava/io/PrintStream;->println",
            "Ljava/io/PrintStream;->printf",
            "Ljava/lang/System;->out",
            "Ljava/lang/Throwable;->printStackTrace",
            "Landroid/util/Log;->println",
        ],
        "param_index": {"Landroid/util/Log;->d": (1,2), "Landroid/util/Log;->v": (1,2),
                         "Landroid/util/Log;->i": (1,2), "Landroid/util/Log;->w": (1,2),
                         "Landroid/util/Log;->e": (1,2)},
        "severity": "MEDIUM",
    },
    "crypto": {
        "methods": [
            "Ljavax/crypto/Cipher;->doFinal",
            "Ljavax/crypto/Cipher;->update",
            "Ljavax/crypto/spec/SecretKeySpec;-><init>",
        ],
        "severity": "HIGH",
    },
    "nfc": {
        "methods": [
            "Landroid/nfc/NfcAdapter;->enableForegroundDispatch",
            "Landroid/nfc/Tag;->getId",
        ],
        "severity": "LOW",
    },
    "notification": {
        "methods": [
            "Landroid/app/NotificationManager;->notify",
            "Landroid/app/Notification$Builder;->setContentText",
            "Landroid/app/Notification$Builder;->setContentTitle",
            "Landroid/app/Notification$Builder;->setSubText",
            "Landroid/app/Notification$Builder;->setTicker",
            "Landroid/app/Notification$Builder;->setContentIntent",
            "Landroid/app/Notification$Builder;->setFullScreenIntent",
        ],
        "param_index": {
            "Landroid/app/Notification$Builder;->setContentText": (0,),
            "Landroid/app/Notification$Builder;->setContentTitle": (0,),
        },
        "severity": "HIGH",
    },
    "broadcast": {
        "methods": [
            "Landroid/content/Context;->sendBroadcast",
            "Landroid/content/Context;->sendOrderedBroadcast",
            "Landroid/content/Context;->sendStickyBroadcast",
            "Landroid/content/Context;->sendBroadcastWithMultiplePermissions",
        ],
        "param_index": {},
        "severity": "HIGH",
    },
    "uri_handling": {
        "methods": [
            "Landroid/net/Uri;->parse", "Landroid/content/Intent;->setData",
            "Landroid/content/Intent;->setDataAndNormalize",
            "Landroid/webkit/WebView;->loadUrl",
            "Landroid/app/Activity;->startActivity",
            "Landroid/content/Context;->startActivity",
            "Landroid/content/ContentResolver;->openInputStream",
        ],
        "param_index": {"Landroid/net/Uri;->parse": (0,), "Landroid/content/Intent;->setData": (0,)},
        "severity": "HIGH",
    },
    "sensitive_data_exposure": {
        "methods": [
            "Landroid/widget/Toast;->makeText",
            "Landroid/util/Log;->d", "Landroid/util/Log;->v", "Landroid/util/Log;->i", "Landroid/util/Log;->w", "Landroid/util/Log;->e",
            "Ljava/io/PrintStream;->println",
            "Landroid/widget/TextView;->setText",
            "Ljava/lang/System;->out",
        ],
        "param_index": {
            "Landroid/widget/Toast;->makeText": (1,),
            "Landroid/widget/TextView;->setText": (0,),
        },
        "severity": "HIGH",
    },
    "reflection": {
        "methods": [
            "Ljava/lang/reflect/Method;->invoke",
            "Ljava/lang/reflect/Constructor;->newInstance",
            "Ljava/lang/Class;->forName",
            "Ljava/lang/Class;->newInstance",
            "Ldalvik/system/DexClassLoader;-><init>",
            "Ldalvik/system/PathClassLoader;-><init>",
        ],
        "param_index": {
            "Ljava/lang/Class;->forName": (0,),
        },
        "severity": "CRITICAL",
    },
}

# ── SANITIZERS — methods that remove/neutralize taint ──
SANITIZERS = [
    "Ljava/lang/String;->equals",
    "Ljava/lang/String;->equalsIgnoreCase",
    "Ljava/lang/String;->isEmpty",
    "Ljava/lang/String;->length",
    "Ljava/lang/String;->trim",
    "Ljava/lang/String;->replaceAll",
    "Ljava/lang/String;->replace",
    "Ljava/lang/String;->matches",
    "Ljava/lang/String;->contains",
    "Ljava/lang/String;->startsWith",
    "Ljava/lang/String;->endsWith",
    "Ljava/lang/String;->substring",
    "Ljava/lang/String;->toLowerCase",
    "Ljava/lang/String;->toUpperCase",
    "Ljava/lang/String;->valueOf",
    "Ljava/lang/String;->format",
    "Ljava/net/URLEncoder;->encode",
    "Ljava/net/URLDecoder;->decode",
    "Landroid/text/TextUtils;->isEmpty",
    "Landroid/text/TextUtils;->isBlank",
    "Landroid/text/Html;->escapeHtml",
    "Landroid/text/Html;->toHtml",
    "Landroid/text/Html;->fromHtml",
    "Ljava/util/regex/Pattern;->matches",
    "Ljava/util/regex/Pattern;->compile",
    "Ljava/util/regex/Matcher;->matches",
    "Ljava/util/regex/Matcher;->find",
    "Landroid/webkit/URLUtil;->isValidUrl",
    "Landroid/webkit/URLUtil;->isNetworkUrl",
    "Landroid/content/Intent;->parseUri",
    "Landroid/net/Uri;->parse",
    "Lorg/apache/commons/text/StringEscapeUtils;->escapeHtml4",
    "Lorg/apache/commons/text/StringEscapeUtils;->escapeJava",
]

#!/usr/bin/env python3
"""Shared utility functions for the APK scanner."""

IGNORED_LIBRARIES = [
    "androidx.", "com.google.", "org.apache.", "org.json.",
    "kotlin.", "kotlinx.", "com.squareup.", "io.reactivex.",
    "com.fasterxml.", "com.google.gson.", "org.slf4j.",
    "com.squareup.okhttp", "org.bouncycastle.", "com.google.protobuf",
    "com.sun.", "javax.", "org.w3c.", "org.xml.", "org.joda.",
    "com.airbnb.", "org.jetbrains.", "com.google.android.",
    "com.android.", "dalvik.", "okhttp3.", "okio.",
    "android.", "com.google.android.material.",
    "org.apache.http.", "org.apache.commons.",
    "com.google.common.", "com.google.firebase.",
    # Additional noise sources for bug bounty
    "butterknife.", "com.facebook.", "com.tencent.", "com.umeng.",
    "com.alipay.", "com.baidu.", "com.huawei.", "com.xiaomi.",
    "com.adjust.", "com.amplitude.", "com.appsflyer.", "com.bugsnag.",
    "com.crashlytics.", "com.deltadna.", "com.flurry.", "com.google.analytics.",
    "com.google.tagmanager.", "com.localytics.", "com.mixpanel.",
    "com.newrelic.", "com.onesignal.", "com.optimizely.", "com.segment.",
    "com.snowplow.", "com.tapjoy.", "com.tencent.", "com.twitter.",
    "com.unity3d.", "com.vungle.", "com.yandex.", "com.zendesk.",
    "io.sentry.", "net.hockeyapp.", "org.acra.",
    "android.arch.", "android.animation.", "android.annotation.",
    "android.app.admin.", "android.app.assist.", "android.app.backup.",
    "android.content.pm.", "android.content.res.",
    "android.database.sqlite.", "android.graphics.",
    "android.hardware.", "android.location.", "android.media.",
    "android.net.", "android.nfc.", "android.os.",
    "android.preference.", "android.print.", "android.provider.",
    "android.security.", "android.telephony.", "android.text.",
    "android.view.", "android.webkit.", "android.widget.",
    "apache.", "ch.qos.logback.", "com.auth0.", "com.bumptech.glide.",
    "com.chartboost.", "com.crashlytics.", "com.daimajia.",
    "com.digits.", "com.facebook.", "com.github.", "com.google.ads.",
    "com.google.android.gms.", "com.google.firebase.",
    "com.google.zxing.", "com.heyzap.", "com.inmobi.",
    "com.jakewharton.", "com.loopj.", "com.nostra13.",
    "com.parse.", "com.path.", "com.paypal.", "com.squareup.leakcanary.",
    "com.squareup.picasso.", "com.stripe.", "com.takisoft.",
    "com.theartofdev.", "com.turbomanage.", "com.yalantis.",
    "commons-codec.", "de.greenrobot.", "edu.umd.",
    "io.fabric.", "io.flutter.", "io.realm.", "io.socket.",
    "javassist.", "jp.co.", "junit.", "net.danlew.",
    "net.sqlcipher.", "oauth.signpost.", "org.acra.",
    "org.apache.commons.", "org.apache.http.", "org.codehaus.",
    "org.jdom.", "org.jsoup.", "org.ksoap2.", "org.mockito.",
    "org.simpleframework.", "org.xwalk.", "retrofit.",
    "twitter4j.", "uk.co.chrisjenx.",
]
APP_INTERNAL_PACKAGES_WHITELIST = [
    "R$", "R.", "Manifest$", "BuildConfig",
]


def is_library_class(class_name, app_package):
    """Check if a class belongs to a third-party library (not app code)."""
    if not class_name:
        return False
    for internal in APP_INTERNAL_PACKAGES_WHITELIST:
        if internal in class_name:
            return False
    if app_package and app_package in class_name:
        return False
    normalized = class_name.replace("/", ".").replace("\\", ".")
    if normalized.startswith("L") and ";" in normalized:
        normalized = normalized[1:].split(";")[0]
    if ";->" in normalized:
        normalized = normalized.split(";->")[0]
    for lib in IGNORED_LIBRARIES:
        if normalized.startswith(lib):
            return True
    return False


def is_library_file(path, app_package):
    """Check if a source file path points to library (not app) code."""
    if not path:
        return False
    pkg_path = app_package.replace(".", "/") if app_package else ""
    if pkg_path and pkg_path in path:
        return False
    for lib in IGNORED_LIBRARIES:
        lib_path = lib.replace(".", "/")
        if lib_path in path:
            return True
    return False


def extract_class_name_from_finding(finding):
    """Extract class/package info from a finding, checking all possible field locations."""
    for key in ("file", "source", "class_name", "path", "location"):
        val = finding.get(key, "")
        if val:
            return val
    cc = finding.get("_code_context", [])
    if isinstance(cc, list):
        for entry in cc:
            if isinstance(entry, dict):
                f = entry.get("file", "")
                if f:
                    return f
    elif isinstance(cc, dict):
        f = cc.get("file", "")
        if f:
            return f
    return ""


_AGGRESSIVE_FP_SEVERITY_DOWNGRADE = {
    "MF-004", "MF-005", "MF-006", "MF-024", "MF-025", "MF-043", "MF-044",
    "MF-048", "MF-049", "MF-050", "MF-054", "MF-060", "MF-061", "MF-062",
    "MF-063", "MF-068", "MF-070", "MF-071", "MF-109", "MF-120", "MF-122",
    "MF-139", "MF-157", "MF-161", "MF-169", "MF-171", "MF-172", "MF-173",
    "MF-185", "MF-198", "MF-200", "MF-205", "MF-210",
}

_LOW_VALUE_SOURCE_RULES = {
    "SRC-014", "SRC-016", "SRC-067", "SRC-074", "SRC-079", "SRC-080",
    "SRC-086", "SRC-098", "SRC-099", "SRC-147", "SRC-149", "SRC-159", "SRC-172",
}

_PHASE2_NOISE_DETECTORS = {
    "ADV-ANTIDBG", "ADV-MANIFEST", "ADV-MISS", "ADV-NATIVE",
    "ADV-KEYCACHE", "ADV-INTEGRITY", "ADV-EXP-P", "ADV-FS",
    "OVS-STOR", "ADV-UPDATE", "ADV-PI",
}


def post_process_findings(findings, app_package, min_confidence=25):
    """Filter noise: remove library-code findings and very low-confidence ones.
    Higher min_confidence = fewer FPs (used by --bb mode).
    """
    filtered = []
    for f in findings:
        fid = f.get("id", "")
        class_info = extract_class_name_from_finding(f)
        if is_library_class(class_info, app_package) or is_library_file(class_info, app_package):
            continue

        if min_confidence >= 40:
            if fid in _AGGRESSIVE_FP_SEVERITY_DOWNGRADE:
                continue
            if fid in _LOW_VALUE_SOURCE_RULES:
                continue

        severity = f.get("severity", "INFO")
        if fid.startswith("MF-") and severity in ("LOW", "INFO") and min_confidence >= 25:
            continue

        for noise_prefix in _PHASE2_NOISE_DETECTORS:
            if fid.startswith(noise_prefix) and min_confidence >= 25:
                break
        else:
            pass
        if any(fid.startswith(np) for np in _PHASE2_NOISE_DETECTORS) and min_confidence >= 25:
            continue

        confidence = f.get("confidence", {}).get("score", 0) if isinstance(f.get("confidence"), dict) else f.get("confidence", 40)
        if isinstance(confidence, str):
            confidence = 40
        f["confidence"] = confidence
        if confidence < min_confidence and severity not in ("CRITICAL", "HIGH"):
            continue
        filtered.append(f)
    return filtered

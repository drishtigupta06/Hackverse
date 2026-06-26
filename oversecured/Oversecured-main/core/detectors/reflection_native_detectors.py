import logging
logger = logging.getLogger(__name__)


def detect_reflection_abuse(sa):
    findings = []
    reflect = sa._find_methods_by_invoke("Ljava/lang/reflect/Method;->invoke")
    if reflect:
        tainted_reflect = [f for f in sa.taint_findings.get("reflection", [])]
        if tainted_reflect:
            for f in tainted_reflect[:3]:
                findings.append({"id":"ADV-REFL-001","name":"Reflection with Potentially Tainted Input",
                    "description":f"Reflection is used with data reaching Class.forName or Method.invoke. Dynamic class loading from untrusted sources can lead to arbitrary code execution.",
                    "severity":"CRITICAL","location":f.get("location","unknown"),
                    "recommendation":"Avoid reflection with user-controllable class/method names. Use a strict allowlist."})
        else:
            for dm in reflect[:3]:
                findings.append({"id":"ADV-REFL-002","name":"Reflection Usage Detected",
                    "description":"Java reflection (Method.invoke) is used. Reflection can bypass access controls and is commonly used by malware.",
                    "severity":"MEDIUM","location":dm,
                    "recommendation":"Minimize reflection usage. Never invoke methods with arguments from untrusted sources."})
    dex_loader = sa._find_methods_by_invoke("Ldalvik/system/DexClassLoader;-><init>")
    if dex_loader:
        for dm in dex_loader[:3]:
            findings.append({"id":"ADV-REFL-003","name":"DexClassLoader Used - Dynamic Code Loading",
                "description":"DexClassLoader loads DEX files from external paths. This can execute arbitrary code if the loaded DEX is tampered with.",
                "severity":"CRITICAL","location":dm,
                "recommendation":"Verify the integrity of dynamically loaded DEX files using cryptographic signatures."})
    if findings:
        sa.findings.append({"category":"17. Reflection Vulnerabilities","rules":findings})


def detect_native_code_loading(sa):
    findings = []
    load_lib = sa._find_methods_by_invoke("Ljava/lang/System;->loadLibrary")
    load = sa._find_methods_by_invoke("Ljava/lang/System;->load")
    runtime_load = sa._find_methods_by_invoke("Ljava/lang/Runtime;->load")
    runtime_load_lib = sa._find_methods_by_invoke("Ljava/lang/Runtime;->loadLibrary")

    if load_lib:
        for dm in load_lib[:3]:
            findings.append({"id":"ADV-NATIVE-001","name":"System.loadLibrary() Used",
                "description":"Native libraries are loaded via System.loadLibrary(). Native code bypasses Java security controls.",
                "severity":"MEDIUM","location":dm,
                "recommendation":"Audit native libraries for memory safety (buffer overflows, use-after-free). Compile with RELRO, NX, and ASLR."})

    native_methods = []
    for cls in sa.vm.get_classes():
        for method in cls.get_methods():
            try:
                if method.get_access_flags_string() and "NATIVE" in method.get_access_flags_string():
                    native_methods.append(f"{cls.name}->{method.name}{method.descriptor}")
            except Exception:
                pass
    if native_methods:
        findings.append({"id":"ADV-NATIVE-002","name":f"Native Methods Declared ({len(native_methods)} found)",
            "description":"The app declares JNI native methods. Example: " + native_methods[0],
            "severity":"MEDIUM","location":"bytecode analysis",
            "recommendation":"Audit all .so libraries for security vulnerabilities."})

    cmd_exec = sa._find_methods_by_invoke("Ljava/lang/Runtime;->exec")
    if cmd_exec and not findings:
        pass

    if findings:
        sa.findings.append({"category":"18. Native Code Loading","rules":findings})


def detect_dynamic_code_loading(sa):
    findings = []
    dex = sa._find_methods_by_invoke("Ldalvik/system/DexClassLoader;-><init>")
    if dex:
        for dm in dex[:5]:
            findings.append({"id":"ADV-020","name":"Dynamic Code Loading via DexClassLoader",
                "description":"DexClassLoader loads DEX files from non-standard locations.",
                "severity":"CRITICAL","location":dm,
                "recommendation":"Verify integrity of loaded DEX files using cryptographic signatures."})
    if findings:
        sa.findings.append({"category":"Dynamic Code Loading","rules":findings})


def detect_reflection_and_native(sa):
    findings = []
    reflect = sa._find_methods_by_invoke("Ljava/lang/reflect/Method;->invoke")
    native_methods = []
    for cls in sa.vm.get_classes():
        for method in cls.get_methods():
            try:
                if method.get_access_flags_string() and "NATIVE" in method.get_access_flags_string():
                    native_methods.append(f"{cls.name}->{method.name}{method.descriptor}")
            except Exception:
                pass
    if reflect:
        for dm in reflect[:3]:
            findings.append({"id":"ADV-025","name":"Reflection Used",
                "severity":"MEDIUM","location":dm,
                "recommendation":"Minimize reflection usage."})
    if native_methods:
        findings.append({"id":"ADV-026","name":f"Native Methods ({len(native_methods)} found)",
            "severity":"MEDIUM","location":", ".join(native_methods[:3]),
            "recommendation":"Audit native libraries for memory safety."})
    if findings:
        sa.findings.append({"category":"Reflection & Native Code","rules":findings})


def detect_playcore_unprotected_receiver(sa):
    findings = []
    play_core_receiver = sa._find_methods_by_invoke(
        "Lcom/google/android/play/core/splitinstall/SplitInstallSessionState"
    )
    split_receiver_action = sa._find_methods_by_regex(
        r'SplitInstallUpdateIntentService|split_file_intents|split_id|unverified-splits|verified-splits|splitcompat'
    )
    unprotected_receiver = sa._find_methods_by_invoke(
        "Landroid/content/Context;->registerReceiver"
    )
    if play_core_receiver and split_receiver_action and unprotected_receiver:
        findings.append({
            "id": "ADV-DCL-020",
            "name": "Google Play Core Library — Unprotected Broadcast Receiver (CVE-2020-8913)",
            "description": "The app uses Google Play Core library which registers an unprotected broadcast receiver for action 'com.google.android.play.core.splitinstall.receiver.SplitInstallUpdateIntentService'. Any app on the device can send crafted intents to this receiver. The receiver processes 'split_file_intents' and 'split_id' parameters to copy files to the 'unverified-splits' directory. The 'split_id' parameter is vulnerable to path traversal, allowing writing files to arbitrary locations including 'verified-splits/config.test.apk' which gets automatically loaded into the app's ClassLoader on next restart, achieving persistent code execution (CVE-2020-8913).",
            "severity": "CRITICAL",
            "location": "bytecode analysis",
            "recommendation": "Update Google Play Core library to version 1.8.2 or later which fixes CVE-2020-8913. The fix validates the 'split_id' parameter against path traversal and restricts file writes to the intended directory. Monitor for Google Play Core security advisories and update promptly."
        })
    if findings:
        sa.findings.append({"category": "42. Google Play Core — Unprotected Receiver / Persistent Code Execution (CVE-2020-8913)", "rules": findings})


def detect_playcore_splitcompat_path_traversal(sa):
    findings = []
    splitcompat_paths = sa._find_methods_by_regex(
        r'splitcompat|verified-splits|unverified-splits|config\.\w+\.apk|split_file_intents|split_id'
    )
    provider_openfile = sa._find_methods_by_invoke(
        "Landroid/content/ContentProvider;->openFile"
    )
    provider_openfile_asset = sa._find_methods_by_invoke(
        "Landroid/content/ContentProvider;->openAssetFile"
    )
    get_last_segment = sa._find_methods_by_invoke(
        "Landroid/net/Uri;->getLastPathSegment"
    )
    if splitcompat_paths and (provider_openfile or provider_openfile_asset) and get_last_segment:
        findings.append({
            "id": "ADV-DCL-021",
            "name": "ContentProvider openFile + Play Core splitcompat Path — Persistent Code Execution via Provider Write",
            "description": "The app uses a ContentProvider with openFile() that uses getLastPathSegment() (which is vulnerable to path traversal via URL-encoded '/../') AND also uses the Google Play Core library which auto-loads APK files from its 'verified-splits' directory. An attacker can chain these: (1) exploit intent redirection to reach the ContentProvider, (2) use URL-encoded path traversal to write a malicious APK to 'splitcompat/{version}/verified-splits/config.evil.apk', (3) the Play Core library loads the malicious module on next restart, achieving persistent code execution. This was the exact chain used against the Google app in May 2021.",
            "severity": "CRITICAL",
            "location": "bytecode analysis",
            "recommendation": "Fix the path traversal in openFile/getLastPathSegment. Update Google Play Core library to the latest version. Consider whether dynamic code loading via Play Core is necessary for the app's functionality."
        })
    if findings:
        sa.findings.append({"category": "42. Play Core — ContentProvider Path Traversal to Persistent Code Execution", "rules": findings})


def detect_parcelable_deserialization_rce(sa):
    findings = []
    parcelable_classes = []
    for cls in sa.vm.get_classes():
        try:
            cls_name = cls.name
            for iface in cls.get_interfaces():
                if 'Parcelable' in str(iface):
                    parcelable_classes.append(cls_name)
                    break
        except Exception:
            pass
    if parcelable_classes:
        dangerous_parcelable = sa._find_methods_by_regex(
            r'createFromParcel[\s\S]{0,300}(?:Runtime\.exec|ProcessBuilder|chmod|mount|rm\s+-rf|cp\s+|mv\s+|'
            r'su\s+-c|sh\s+-c|bash\s+-c|dexClassLoader|loadDex|loadClass|System\.load)'
        )
        if dangerous_parcelable:
            for dm in dangerous_parcelable[:5]:
                findings.append({
                    "id": "ADV-DCL-030",
                    "name": "Parcelable Deserialization Code Execution (EvilParcelable Pattern) — RCE via createFromParcel",
                    "description": f"Custom Parcelable class contains dangerous code execution in createFromParcel() or newArray() in {dm}. When Android deserializes a Parcelable from an Intent extra (e.g., via bundle.getParcelable()), the createFromParcel() method is automatically called in the receiving app's process. An attacker who can send intents to any exported component triggers arbitrary code execution with the target app's privileges. This was the payload delivery mechanism in CVE-2020-8913 (Play Core) and Google app DCL exploit: after writing a malicious APK to verified-splits, the attacker sent an EvilParcelable that executed 'chmod -R 777' on deserialization.",
                    "severity": "CRITICAL",
                    "location": dm,
                    "recommendation": "Review all custom Parcelable implementations. Never execute shell commands or load dynamic code in createFromParcel()/newArray(). These methods should only perform simple data marshaling. Validate the source of incoming Parcelable objects and restrict which classes can be deserialized via Bundle.getClassLoader() restrictions."
                })
    intent_has_parcelable = sa._find_methods_by_regex(
        r'Intent\.hasExtra|Bundle\.hasExtra|Intent\.getParcelableExtra|Bundle\.getParcelable'
    )
    if parcelable_classes and intent_has_parcelable:
        exported_comps = []
        for comp_type in ["activities", "services", "receivers"]:
            for comp in sa.manifest_components.get(comp_type, []):
                if comp.get("exported") in ("true", None, ""):
                    exported_comps.append(comp["name"])
        if exported_comps:
            findings.append({
                "id": "ADV-DCL-031",
                "name": f"Exported Component + Parcelable Deserialization — Remote Parcel Injection Attack Surface",
                "description": f"The app has {len(exported_comps)} exported components AND uses Parcelable objects in Intent extras. Any app can send intents to exported components with crafted Parcelable extras. If any Parcelable class has dangerous operations in createFromParcel() or newArray(), this is a remote code execution vector.",
                "severity": "CRITICAL",
                "location": f"exported: {', '.join(exported_comps[:3])}...",
                "recommendation": "Audit all exported components for Parcelable extra handling. Restrict Parcelable deserialization to known-safe classes. Remove exported status from components that don't need it."
            })
    if findings:
        sa.findings.append({"category": "42. Parcelable Deserialization — EvilParcelable RCE (CVE-2020-8913 style)", "rules": findings})


def detect_conditional_system_load(sa):
    findings = []
    system_load = sa._find_methods_by_invoke("Ljava/lang/System;->load")
    file_exists = sa._find_methods_by_invoke("Ljava/io/File;->exists")
    if system_load and file_exists:
        conditional_load = sa._find_methods_by_regex(
            r'File\.exists\(\)[\s\S]{0,200}System\.load\(|exists[\s\S]{0,200}System\.load\('
        )
        if conditional_load:
            for dm in conditional_load[:5]:
                findings.append({
                    "id": "ADV-DCL-040",
                    "name": "Conditional System.load() After File.exists() — Native Library Injection via Predictable Path",
                    "description": f"System.load() is called only after File.exists() on a predictable library path in {dm}. If an attacker can write a malicious .so file to the checked path (via intent redirect + FileProvider, content provider path traversal, or AIDL file download), the app will load attacker-controlled native code on next restart. This was the core of TikTok's persistent code execution vulnerabilities: the app checked for libraries at predictable paths like '/data/user/0/pkg/lib-main/libimagepipeline.so' or '/data/user/0/pkg/app_librarian/version/libAkeva.so' without integrity verification, allowing pre-written malicious .so files to be loaded as native code.",
                    "severity": "CRITICAL",
                    "location": dm,
                    "recommendation": "Replace conditional System.load() with verified integrity checks. Use signature verification for all loaded native libraries. Store libraries in app's protected resources (not writable paths). Consider using Android's modern in-App Update API instead of dynamic library loading."
                })
        path_like_load = sa._find_methods_by_regex(
            r'System\.load\([^)]*(?:getFilesDir|getCacheDir|getExternal|getDir|files/|cache/|lib-main|app_lib|app_librarian)'
        )
        if path_like_load:
            for dm in path_like_load[:3]:
                findings.append({
                    "id": "ADV-DCL-041",
                    "name": "System.load() with Dynamic/App-Private Path — Library Injection Risk (TikTok-Style DCL)",
                    "description": f"System.load() uses a path constructed from the app's private directory or a user-modifiable location in {dm}. Since the app's private directory can be written to via intent redirect + FileProvider, content provider openFile path traversal, or AIDL file download, an attacker can replace or inject a malicious library at this path, achieving native code execution with the app's privileges.",
                    "severity": "CRITICAL",
                    "location": dm,
                    "recommendation": "Do not load native libraries from app-private writable directories. Bundle necessary libraries in the APK's lib/ directory where they are read-only (owned by system). If dynamic loading is unavoidable, verify the library's cryptographic signature before loading."
                })
    if findings:
        sa.findings.append({"category": "42. Dynamic Code Loading — Conditional System.load + File.exists (TikTok-Style Native Injection)", "rules": findings})


def detect_serializable_memory_corruption(sa):
    findings = []
    serializable_classes = []
    for cls in sa.vm.get_classes():
        try:
            if any(k in str(cls.get_super()) for k in ["Serializable", "java.io.Serializable"]):
                serializable_classes.append(cls.name)
        except Exception:
            pass
    if serializable_classes:
        native_ptr = sa._find_methods_by_regex(
            r'(long\s+ptr|long\s+nativePtr|long\s+mNativePtr|long\s+NativePtr|long\s+native_ptr|'
            r'private\s+transient\s+long|private\s+long\s+(ptr|nativePtr|address|mPtr))'
        )
        finalize_with_native = sa._find_methods_by_regex(
            r'finalize[\s\S]{0,200}(?:freePtr|native_free|nFree|release|nativeRelease|closeNative|nativeClose)'
        )
        if native_ptr and finalize_with_native:
            for dm in finalize_with_native[:5]:
                findings.append({
                    "id": "ADV-MEM-001",
                    "name": "Serializable Class With Native Pointer (long ptr) — Memory Corruption via Arbitrary Address Dereference",
                    "description": f"A Serializable class stores a native pointer as a 'long' field in {dm}. The finalize() method calls a native function to free/release this pointer. When this object is deserialized from an Intent extra (via getSerializableExtra), an attacker can set 'ptr' to any 64-bit value. On finalization, the native code dereferences the attacker-controlled address, causing arbitrary memory corruption (write-what-where, read of arbitrary memory, or code execution via vtable/function pointer overwrite). This is the classic OpenSSLX509Certificate/MemoryCorruptionSerializable pattern found in PayPal and other Android apps.",
                    "severity": "CRITICAL",
                    "location": dm,
                    "recommendation": "Mark native pointer fields as 'transient' so they are excluded from serialization. Never store native pointers in Serializable classes. Use Android Keystore or safe object wrappers instead of direct native pointer management."
                })
    if findings:
        sa.findings.append({"category": "42. Serializable Memory Corruption — Native Pointer Overwrite via Arbitrary Address", "rules": findings})


def detect_parcelable_json_wrapper(sa):
    findings = []
    gson_from_json = sa._find_methods_by_invoke("Lcom/google/gson/Gson;->fromJson")
    jackson = sa._find_methods_by_invoke("Lcom/fasterxml/jackson/databind/ObjectMapper")
    fastjson = sa._find_methods_by_invoke("Lcom/alibaba/fastjson/JSON")
    any_json_parser = bool(gson_from_json or jackson or fastjson)
    parcelable_with_json = sa._find_methods_by_regex(
        r'class\s+\w+\s+implements\s+Parcelable[\s\S]{0,500}(?:fromJson|parseObject|readValue|JSON\.parse|gson\.from)'
    )
    classname_in_parcel = sa._find_methods_by_regex(
        r'readString[\s\S]{0,200}(?:className|class_name|clazz|type|jsonClassName|json_class)'
    )
    if any_json_parser and (parcelable_with_json or classname_in_parcel):
        findings.append({
            "id": "ADV-MEM-010",
            "name": "Parcelable + JSON Parser + Class Name Control — Arbitrary Object Instantiation (ParcelableJsonWrapper Pattern)",
            "description": "The app defines a Parcelable class that reads a 'className' string and a 'jsonData' string during deserialization (createFromParcel), then uses Gson/Jackson/Fastjson to deserialize 'jsonData' into an instance of 'className'. An attacker controls both the class name and the JSON payload by sending a crafted Parcelable extra. This enables instantiation of arbitrary classes with attacker-controlled field values. Using Android internal classes like VirtualRefBasePtr (which has a long mNativePtr field set via JSON), the attacker can trigger memory corruption by controlling native pointers. This was the vulnerability in PayPal's ParcelableJsonWrapper class (HackerOne).",
            "severity": "CRITICAL",
            "location": "bytecode analysis",
            "recommendation": "Never combine Parcelable deserialization with dynamic JSON parsing where the class name is user-controlled. Restrict the set of allowed classes for JSON deserialization. Consider using predefined JSON models instead of dynamic class name resolution. Validate that className is from a predefined allowlist before deserialization."
        })
    parcel_json_extras = sa._find_methods_by_regex(
        r'getParcelableExtra|getParcelableArrayListExtra[\s\S]{0,200}(?:Json|json|Gson|gson|Jackson|jackson|Fastjson|fastjson)'
    )
    if parcel_json_extras and classname_in_parcel:
        for dm in parcel_json_extras[:5]:
            findings.append({
                "id": "ADV-MEM-011",
                "name": "Parcelable Extra Contains JSON Deserialization — Dynamic Object Creation from Intent",
                "description": f"An Intent extra containing a Parcelable with class name + JSON data is received in {dm}. When this Parcelable is deserialized, it creates arbitrary objects using a JSON parser with attacker-controlled class name. This allows the attacker to instantiate any class available in the app's classpath and set its fields via JSON, potentially leading to memory corruption, data leakage, or denial of service.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Validate all incoming Parcelable objects. Restrict Parcelable deserialization to known-safe class types. Never use Parcelable objects from intents to create dynamic class instances via JSON parsers."
            })
    if findings:
        sa.findings.append({"category": "42. ParcelableJsonWrapper — Arbitrary Object Creation via Class Name + JSON (PayPal Memory Corruption)", "rules": findings})


def detect_reflection_advanced(sa):
    findings = []
    forName = sa._find_methods_by_invoke("Ljava/lang/Class;->forName")
    if forName:
        tainted_forName = [f for f in sa.taint_findings.get("reflection", []) if "forName" in f.get("sink","")]
        if tainted_forName:
            for f in tainted_forName[:3]:
                findings.append({"id":"ADV-REFL-100","name":"Class.forName() with Tainted Input — Dynamic Class Loading RCE",
                    "description":f"Class.forName() is called with tainted data ({f.get('sink','?')}) in {f.get('location','?')}. Attackers can load arbitrary classes, potentially leading to RCE via static initializers.",
                    "severity":"CRITICAL","location":f.get("location","unknown"),
                    "recommendation":"Never pass untrusted input to Class.forName(). Maintain a strict allowlist of permitted class names."})
        else:
            for dm in forName[:3]:
                findings.append({"id":"ADV-REFL-101","name":"Class.forName() Used — Dynamic Class Loading Review",
                    "description":f"Class.forName() used in {dm}. Dynamic class loading can bypass security controls.",
                    "severity":"MEDIUM","location":dm,
                    "recommendation":"Avoid Class.forName() with variable class names. Use compile-time references when possible."})
    method_get = sa._find_methods_by_invoke("Ljava/lang/Class;->getMethod")
    if method_get:
        for dm in method_get[:3]:
            findings.append({"id":"ADV-REFL-102","name":"getMethod() Used — Reflection Method Resolution",
                "description":f"getMethod() used in {dm}. Combined with invoke(), this allows calling arbitrary methods.",
                "severity":"MEDIUM","location":dm,
                "recommendation":"Restrict reflection to specific known methods. Validate method names against an allowlist."})
    proxy = sa._find_methods_by_invoke("Ljava/lang/reflect/Proxy;->newProxyInstance")
    if proxy:
        for dm in proxy[:3]:
            findings.append({"id":"ADV-REFL-103","name":"Dynamic Proxy Created — Method Interception Risk",
                "description":f"Dynamic proxy via Proxy.newProxyInstance() in {dm}. Proxies intercept method calls and can modify behavior.",
                "severity":"MEDIUM","location":dm,
                "recommendation":"Audit dynamic proxy usage. Ensure proxies do not bypass security checks."})
    if findings:
        sa.findings.append({"category":"34. Reflection Advanced — forName / getMethod / Proxy Injection","rules":findings})

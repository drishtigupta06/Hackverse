import logging
logger = logging.getLogger(__name__)


CONTEXT_INCLUDE_CODE = 1


def detect_create_package_context(sa):
    findings = []
    ctx = sa._find_methods_by_invoke(
        "Landroid/content/Context;->createPackageContext"
    )
    if ctx:
        for dm in ctx[:5]:
            findings.append({
                "id": "ADV-PKG-001",
                "name": "createPackageContext() — Third-Party Code Loaded in App Context",
                "description": f"createPackageContext() in {dm} can load code from another installed app via CONTEXT_INCLUDE_CODE. If the target package is not signature-verified, any app with a matching package name can execute arbitrary code in this app's context.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Always verify the target package signature via PackageManager.checkSignatures() before calling createPackageContext(). Never use CONTEXT_INCLUDE_CODE with unverified packages."
            })
    ctx_include = sa._find_methods_by_regex(r'CONTEXT_INCLUDE_CODE|createPackageContext.*CONTEXT_INCLUDE')
    if not ctx and ctx_include:
        for dm in ctx_include[:3]:
            findings.append({
                "id": "ADV-PKG-002",
                "name": "CONTEXT_INCLUDE_CODE Flag Used — Arbitrary Code Execution via Package Context",
                "description": f"CONTEXT_INCLUDE_CODE flag is used in {dm}. This allows loading and executing DEX code from another installed app's package. Without signature verification, an attacker's app with a matching package name can execute arbitrary code in this app's process.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Remove CONTEXT_INCLUDE_CODE if not essential. If required, verify the target app's signature matches your app's certificate."
            })
    if findings:
        sa.findings.append({"category": "37. Third-Party Package Context (ACE via Package Contexts)", "rules": findings})


def detect_installed_packages_enumeration(sa):
    findings = []
    get_installed = sa._find_methods_by_invoke(
        "Landroid/content/pm/PackageManager;->getInstalledPackages"
    )
    get_installed_apps = sa._find_methods_by_invoke(
        "Landroid/content/pm/PackageManager;->getInstalledApplications"
    )
    if get_installed:
        for dm in get_installed[:3]:
            findings.append({
                "id": "ADV-PKG-010",
                "name": "getInstalledPackages() — App Inventory Enumeration",
                "description": f"getInstalledPackages() in {dm} enumerates all installed apps on the device. If results are used to load code from third-party packages without signature verification, this enables arbitrary code execution.",
                "severity": "HIGH",
                "location": dm,
                "recommendation": "Restrict enumeration to specific known packages. Always verify package signatures via checkSignatures() before processing discovered packages. Never load code from unverified packages."
            })
    if get_installed_apps:
        for dm in get_installed_apps[:3]:
            findings.append({
                "id": "ADV-PKG-011",
                "name": "getInstalledApplications() — App Inventory Enumeration",
                "description": f"getInstalledApplications() in {dm} enumerates all installed apps. Third-party module discovery without signature verification enables malicious module loading.",
                "severity": "HIGH",
                "location": dm,
                "recommendation": "Verify signatures of discovered packages before processing them as modules."
            })
    if findings:
        sa.findings.append({"category": "37. Package Context Enumeration — Third-Party Module Discovery", "rules": findings})


def detect_missing_signature_verification(sa):
    findings = []
    check_sig = sa._find_methods_by_invoke(
        "Landroid/content/pm/PackageManager;->checkSignatures"
    )
    get_pkg_info = sa._find_methods_by_invoke(
        "Landroid/content/pm/PackageManager;->getPackageInfo"
    )
    client_pkg_str = sa._find_methods_by_invoke(
        "Landroid/content/Context;->getPackageName"
    )
    has_module_discovery = bool(
        sa._find_methods_by_invoke("Landroid/content/pm/PackageManager;->getInstalledPackages")
        or sa._find_methods_by_invoke("Landroid/content/pm/PackageManager;->getInstalledApplications")
    )
    has_context_loading = bool(
        sa._find_methods_by_invoke("Landroid/content/Context;->createPackageContext")
    )

    if has_module_discovery and not check_sig:
        findings.append({
            "id": "ADV-PKG-020",
            "name": "Missing Signature Verification — Module Discovery Without checkSignatures()",
            "description": "The app discovers or processes third-party packages but does not call PackageManager.checkSignatures(). An attacker's app with a matching package name prefix can impersonate a legitimate module and execute arbitrary code in the app's context.",
            "severity": "CRITICAL",
            "location": "bytecode analysis",
            "recommendation": "Always call checkSignatures(yourPackage, discoveredPackage) and verify the result is SIGNATURE_MATCH before loading code from discovered packages."
        })
    if has_context_loading and not check_sig and not client_pkg_str:
        findings.append({
            "id": "ADV-PKG-021",
            "name": "createPackageContext() Without Signature Verification — Arbitrary Code Loading",
            "description": "createPackageContext() is used to load code from other packages, but PackageManager.checkSignatures() is never called. Any app with the target package name can inject arbitrary code into this app.",
            "severity": "CRITICAL",
            "location": "bytecode analysis",
            "recommendation": "Always verify the target package signature matches your app's signature before calling createPackageContext(). Use checkSignatures() with SIGNATURE_MATCH comparison."
        })
    if check_sig:
        for dm in check_sig[:3]:
            findings.append({
                "id": "ADV-PKG-022",
                "name": "checkSignatures() Used — Signature Verification Present",
                "description": f"PackageManager.checkSignatures() is called in {dm}. Verify that the result is compared against PackageManager.SIGNATURE_MATCH and not just checked for non-zero.",
                "severity": "INFO",
                "location": dm,
                "recommendation": "Ensure the result of checkSignatures() is compared to PackageManager.SIGNATURE_MATCH. A non-zero check is insufficient as different signers return different non-zero values."
            })
    if findings:
        sa.findings.append({"category": "37. Missing Signature Verification — Package Context Security", "rules": findings})


def detect_inmemory_dex_classloader(sa):
    findings = []
    im_dex = sa._find_methods_by_invoke(
        "Ldalvik/system/InMemoryDexClassLoader"
    )
    if im_dex:
        for dm in im_dex[:3]:
            findings.append({
                "id": "ADV-PKG-030",
                "name": "InMemoryDexClassLoader — Dynamic Code Loading from ByteBuffer",
                "description": f"InMemoryDexClassLoader in {dm} loads DEX files directly from memory (ByteBuffer). If the byte buffer is populated from untrusted data (network, intents, files), this enables arbitrary code execution without any disk artifacts.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Ensure the ByteBuffer passed to InMemoryDexClassLoader contains only trusted, verified DEX data. Never load DEX from untrusted sources via InMemoryDexClassLoader."
            })
    if findings:
        sa.findings.append({"category": "37. In-Memory DEX Loading — InMemoryDexClassLoader", "rules": findings})


def detect_dex_file_loading(sa):
    findings = []
    dex_file = sa._find_methods_by_invoke(
        "Ldalvik/system/DexFile"
    )
    dex_load = sa._find_methods_by_invoke(
        "Ldalvik/system/DexFile;->loadDex"
    )
    if dex_file and dex_load:
        for dm in dex_load[:3]:
            findings.append({
                "id": "ADV-PKG-031",
                "name": "DexFile.loadDex() — Legacy Dynamic Code Loading",
                "description": f"DexFile.loadDex() in {dm} loads DEX/ODEX files from external paths. This legacy API executes code from the loaded DEX and is vulnerable to code injection if the file path is untrusted.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Prefer DexClassLoader over DexFile. Verify integrity of loaded DEX files via cryptographic signature verification."
            })
    if dex_file and not dex_load:
        for dm in dex_file[:3]:
            findings.append({
                "id": "ADV-PKG-032",
                "name": "DexFile API Used — Potential Dynamic Code Loading",
                "description": f"DexFile class used in {dm}. This API can load and execute DEX code. Review for untrusted DEX loading patterns.",
                "severity": "HIGH",
                "location": dm,
                "recommendation": "Audit all DexFile usage. Verify that loaded DEX files come from trusted, verified sources."
            })
    if findings:
        sa.findings.append({"category": "37. Legacy DEX Loading — DexFile API", "rules": findings})


def detect_unverified_classloader_usage(sa):
    findings = []
    get_cl = sa._find_methods_by_invoke(
        "Landroid/content/Context;->getClassLoader"
    )
    load_cl_from_ctx = sa._find_methods_by_regex(
        r'createPackageContext.*getClassLoader|getClassLoader.*loadClass'
    )
    load_class = sa._find_methods_by_invoke(
        "Ljava/lang/ClassLoader;->loadClass"
    )
    if load_cl_from_ctx:
        for dm in load_cl_from_ctx[:5]:
            findings.append({
                "id": "ADV-PKG-040",
                "name": "ClassLoader from Package Context — Dynamic Class Loading Without Verification",
                "description": f"A ClassLoader is obtained from a package context and used to load classes in {dm}. If the package context was created without signature verification, an attacker can control which class is loaded, leading to arbitrary code execution via static initializers or reflection.",
                "severity": "CRITICAL",
                "location": dm,
                "recommendation": "Never load classes from ClassLoaders obtained from unverified package contexts. Verify the target app's signature before using its ClassLoader."
            })
    if findings:
        sa.findings.append({"category": "37. Unverified ClassLoader — Class Loading from Untrusted Packages", "rules": findings})

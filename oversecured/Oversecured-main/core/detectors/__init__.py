import importlib
import logging
logger = logging.getLogger(__name__)

_DETECTOR_MODULE = {}

def _build_map():
    mods = {
        "package_context_detectors": [
            "create_package_context", "installed_packages_enumeration",
            "missing_signature_verification", "inmemory_dex_classloader",
            "dex_file_loading", "unverified_classloader_usage",
        ],
        "intent_redirect_detectors": [
            "proxy_activity", "intent_setresult_redirect", "intent_parse_uri",
            "intent_selector", "parcel_unmarshall_intent", "provider_access_via_proxy",
        ],
        "implicit_intent_detectors": [
            "implicit_start_activity_for_result", "query_intent_activities",
            "standard_action_interception", "implicit_pending_intent_broadcast",
            "on_activity_result_uri_validation", "display_name_path_traversal",
            "symlink_file_theft",
        ],
        "content_provider_detectors": [
            "fileprovider_broad_paths", "provider_path_traversal",
            "provider_permission_mismatch", "provider_proxy_abuse",
            "provider_debug_action", "provider_openfile_no_validation",
            "local_webserver_path_traversal", "provider_same_database_cross_table",
            "opencontenturi_bypass",
        ],
        "auth_account_detectors": [
            "local_oauth_server", "biometric_without_crypto",
            "aidl_auth_abuse", "custom_scheme_oauth", "token_in_external_storage",
            "magic_link_interception",
        ],
        "intent_detectors": [
            "intent_redirection", "intent_spoofing", "arbitrary_intent_launch",
            "pending_intent_abuse", "exported_components", "task_hijacking",
            "deep_link_hijacking", "intent_interception", "intents_advanced",
            "setresult_data_leakage", "intent_uri_perm_manipulation",
        ],
        "webview_detectors": [
            "webview_intent_abuse", "webview_chains", "webview_file_access",
            "taint_webview_injection", "webview_advanced",
            "webview_loaddatawithbaseurl", "webview_webresourceresponse",
            "webview_url_validation_bypass", "webview_onnewintent_xss",
            "webview_js_injection", "webview_file_chooser_interception",
            "webview_cookie_injection", "deeplink_webview_info_disclosure",
        ],
        "permission_detectors": [
            "privilege_escalation", "confused_deputy", "permission_redelegation",
            "missing_permission_checks", "broadcast_abuse", "notification_security",
            "exported_preference_activities", "broadcast_notification_advanced",
            "get_calling_package_null_bypass",
        ],
        "taint_detectors": [
            "taint_sqli", "taint_content_provider_abuse", "taint_command_execution",
            "taint_sensitive_data_exposure", "taint_logging", "taint_path_traversal",
            "taint_file_disclosure", "taint_intent_injection", "taint_serialization",
            "taint_broadcast", "taint_native",
        ],
        "storage_detectors": [
            "cp_unauthorized_access", "world_readable_files", "unsafe_external_storage",
            "clipboard_abuse", "unencrypted_database", "sql_injection_provider",
            "fileprovider_usage", "cp_advanced", "filesystem_advanced",
            "sharedprefs_cleartext",
        ],
        "crypto_auth_detectors": [
            "crypto_issues", "auth_bypass", "x509_validation", "android_keystore_usage",
            "ssl_pinning_config", "account_takeover", "auth_authorization_gaps",
            "network_mitm",
        ],
        "reflection_native_detectors": [
            "reflection_abuse", "native_code_loading", "dynamic_code_loading",
            "reflection_and_native", "reflection_advanced",
            "playcore_unprotected_receiver", "playcore_splitcompat_path_traversal",
            "parcelable_deserialization_rce", "conditional_system_load",
            "serializable_memory_corruption", "parcelable_json_wrapper",
        ],
        "ipa_detectors": [
            "ipa_binder_bypass", "ipa_system_service_abuse", "ipa_settings_abuse",
            "ipa_vendor_service_abuse", "ipa_privileged_intent",
            "ipa_broadcast_service_chain", "ipa_lifecycle_flow",
            "ipa_cross_class_flow", "ipa_callback_flow", "ipa_multi_hop_taint",
        ],
        "misc_detectors": [
            "deserialization", "uri_handling", "data_leaking_activities",
            "root_emulator_debug", "screen_capture_vulnerability", "obfuscation_gaps",
            "zip_path_traversal", "fragment_injection", "jobscheduler_security",
            "device_admin_abuse", "insecure_bound_services", "pendingintent_advanced",
            "deeplink_advanced", "system_app_bugs", "hardcoded_secrets",
            "sensitive_data_leakage", "command_injection_advanced",
            "exported_component_abuse", "shell_command_injection_receiver",
            "spanned_html_injection", "gson_deserialization",
            "arbitrary_service_binding", "deeplink_path_traversal",
            "deeplink_response_redirect",
            "manifest_allow_backup", "manifest_debuggable",
            "keyboard_cache", "stepup_authentication", "min_sdk_version",
            "enforced_updating", "runtime_integrity", "anti_debugging",
            "overlay_tapjacking", "nfe_dos", "mitd_external_cache",
            "notification_spoofing", "serialization_leakage",
            "password_storage", "undeclared_permissions",
            "content_injection", "log_injection", "local_addresses",
            "missing_protection_level",
        ],
    }
    for mod, funcs in mods.items():
        for f in funcs:
            _DETECTOR_MODULE[f"_detect_{f}"] = f"core.detectors.{mod}"

_build_map()

def run_detectors(sa, detector_names):
    for name in detector_names:
        module_path = _DETECTOR_MODULE.get(name)
        if not module_path:
            logger.debug(f"No module mapping for {name}, skipping")
            continue
        try:
            mod = importlib.import_module(module_path)
            func_name = name.replace("_detect_", "detect_", 1)
            func = getattr(mod, func_name, None)
            if func:
                func(sa)
            else:
                logger.warning(f"Function {func_name} not found in {module_path}")
        except Exception as e:
            logger.warning(f"{name} failed: {e}")

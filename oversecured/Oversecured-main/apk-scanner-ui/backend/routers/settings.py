import os
import json
import asyncio
import logging
from fastapi import APIRouter
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/settings", tags=["settings"])

SETTINGS_PATH = os.getenv("SETTINGS_PATH", "/data/settings.json")

SETTINGS_DIR = os.path.dirname(SETTINGS_PATH) or "."

DEFAULT_SETTINGS = {
    "scannerPath": "/scanner/scanner.py",
    "jadxPath": "jadx",
    "adbPath": "adb",
    "fridaPath": "frida",
    "fridaServerPath": "/opt/frida-server-x86_64",
    "emulatorPath": "emulator",
    "ollamaUrl": "http://ollama:11434",
    "defaultScanMode": "standard",
    "defaultFridaTimeout": 30,
}


class SettingsModel(BaseModel):
    scannerPath: str = DEFAULT_SETTINGS["scannerPath"]
    jadxPath: str = DEFAULT_SETTINGS["jadxPath"]
    adbPath: str = DEFAULT_SETTINGS["adbPath"]
    fridaPath: str = DEFAULT_SETTINGS["fridaPath"]
    fridaServerPath: str = DEFAULT_SETTINGS["fridaServerPath"]
    emulatorPath: str = DEFAULT_SETTINGS["emulatorPath"]
    ollamaUrl: str = DEFAULT_SETTINGS["ollamaUrl"]
    defaultScanMode: str = DEFAULT_SETTINGS["defaultScanMode"]
    defaultFridaTimeout: int = DEFAULT_SETTINGS["defaultFridaTimeout"]


async def _load() -> dict:
    try:
        if os.path.exists(SETTINGS_PATH):
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, _read_settings)
    except Exception as e:
        logger.warning("Failed to load settings: %s", e)
    return dict(DEFAULT_SETTINGS)


def _read_settings() -> dict:
    with open(SETTINGS_PATH) as f:
        return json.load(f)


async def _save(data: dict):
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _write_settings, data)


def _write_settings(data: dict):
    os.makedirs(SETTINGS_DIR, exist_ok=True)
    with open(SETTINGS_PATH, "w") as f:
        json.dump(data, f, indent=2)


@router.get("")
async def get_settings():
    return await _load()


@router.put("")
async def update_settings(settings: SettingsModel):
    data = settings.model_dump()
    await _save(data)
    return {"status": "saved", "settings": data}

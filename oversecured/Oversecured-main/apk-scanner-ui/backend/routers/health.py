import os
import asyncio
import logging
from fastapi import APIRouter
import httpx
from services.emulator_service import get_emulator_status, get_frida_server_info

logger = logging.getLogger(__name__)
router = APIRouter(tags=["health"])

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")


@router.get("/health")
async def health():
    return {"status": "ok"}


async def _run_cmd(*args, timeout=5):
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        raise TimeoutError(f"Command timed out after {timeout}s: {' '.join(args)}")


@router.get("/api/v1/health/adb")
async def adb_health():
    try:
        try:
            await _run_cmd("adb", "start-server", timeout=5)
        except Exception:
            pass
        stdout, _ = await _run_cmd("adb", "devices", timeout=5)
        output = stdout
        devices = [l for l in output.split("\n") if l.strip() and "List" not in l and "device" in l]
        connected = any("device" in l and "offline" not in l for l in devices)
        return {"status": "connected" if connected else "offline", "devices": len(devices)}
    except Exception as e:
        return {"status": "offline", "error": str(e)}


@router.get("/api/v1/health/frida")
async def frida_health():
    try:
        stdout, _ = await _run_cmd("frida", "--version", timeout=5)
        version = stdout.strip()
        return {"status": "available", "version": version}
    except Exception as e:
        return {"status": "unavailable", "error": str(e)}


@router.get("/api/v1/health/frida-server")
async def frida_server_health():
    return get_frida_server_info()


@router.get("/api/v1/health/emulator")
async def emulator_health():
    return get_emulator_status()


@router.get("/api/v1/health/ollama")
async def ollama_health():
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{OLLAMA_URL}/api/tags")
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                return {"status": "connected", "models": [m["name"] for m in models]}
            return {"status": "error", "detail": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"status": "unavailable", "error": str(e)}

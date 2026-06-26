import os
import sys
import re
import shutil
import subprocess
import asyncio
import logging
import time
import signal
from typing import Optional

SCANNER_PATH = os.getenv("SCANNER_PATH", "/scanner/scanner.py")
SCANNER_DIR = os.path.dirname(SCANNER_PATH)
if SCANNER_DIR not in sys.path:
    sys.path.insert(0, SCANNER_DIR)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

_emulator_proc: Optional[subprocess.Popen] = None
_emulator_serial: Optional[str] = None
_emulator_status = "not_initialized"
_boot_task: Optional[asyncio.Task] = None
_last_error: Optional[str] = None
_stderr_lines: list[str] = []

ANDROID_HOME = os.environ.get("ANDROID_HOME", "/opt/android-sdk")
EMULATOR_BIN = os.path.join(ANDROID_HOME, "emulator", "emulator")
ADB_BIN = shutil.which("adb") or os.path.join(ANDROID_HOME, "platform-tools", "adb")
AVD_NAME = os.environ.get("AVD_NAME", "Pixel_6_API_33")
AVD_PORT = 5554
AVD_SERIAL = f"emulator-{AVD_PORT}"
BOOT_TIMEOUT = int(os.environ.get("EMULATOR_BOOT_TIMEOUT", "300"))

EXTERNAL_ADB_HOST = os.environ.get("ADB_DEVICE_HOST", "")
EXTERNAL_ADB_PORT = os.environ.get("ADB_DEVICE_PORT", "5555")

_CRASH_PATTERNS = [
    r"cannnot unmap ptr",
    r"detected a hanging thread.*QEMU2",
    r"Segmentation fault",
    r"signal 11",
    r"signal 6",
    r"Aborted",
    r"panic:",
]


def _is_external_backend() -> bool:
    return bool(EXTERNAL_ADB_HOST)


def _adb_serial() -> str:
    if _is_external_backend():
        return f"{EXTERNAL_ADB_HOST}:{EXTERNAL_ADB_PORT}"
    return AVD_SERIAL


def _emulator_env() -> dict:
    env = os.environ.copy()
    lib64 = os.path.join(os.path.dirname(EMULATOR_BIN), "lib64")
    qt_lib = os.path.join(lib64, "qt", "lib")
    existing = env.get("LD_LIBRARY_PATH", "")
    env["LD_LIBRARY_PATH"] = f"{lib64}:{qt_lib}" + (f":{existing}" if existing else "")
    return env


def _adb(args: list[str], timeout: int = 10) -> tuple[int, str, str]:
    serial = _adb_serial()
    try:
        r = subprocess.run(
            [ADB_BIN, "-s", serial] + args,
            capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -2, "", "adb not found"


async def _create_avd(name: str = "Pixel_6_API_33", pkg: str = "system-images;android-33;google_apis;x86_64") -> bool:
    avdmanager = shutil.which("avdmanager") or os.path.join(
        ANDROID_HOME, "cmdline-tools", "latest", "bin", "avdmanager"
    )
    if not os.path.exists(avdmanager):
        logger.error("avdmanager not found at %s", avdmanager)
        return False
    try:
        proc = await asyncio.create_subprocess_exec(
            avdmanager, "create", "avd", "-n", name, "-k", pkg, "-f",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        if proc.returncode != 0:
            logger.error("avdmanager failed: %s", stderr.decode())
            return False
        logger.info("AVD '%s' created successfully", name)
        return True
    except asyncio.TimeoutError:
        logger.error("avdmanager timed out creating AVD '%s'", name)
        return False
    except Exception as e:
        logger.error("avdmanager error: %s", e)
        return False


def _is_avd_created(name: str) -> bool:
    avd_dir = os.path.expanduser(f"~/.android/avd/{name}.avd")
    return os.path.isdir(avd_dir)


def _remove_stale_lock(name: str):
    lock_file = os.path.expanduser(f"~/.android/avd/{name}.avd/hardware-qemu.ini.lock")
    if os.path.exists(lock_file):
        try:
            os.remove(lock_file)
            logger.info("Removed stale AVD lock: %s", lock_file)
        except Exception as e:
            logger.warning("Could not remove lock %s: %s", lock_file, e)


def _detect_crash_in_stderr() -> Optional[str]:
    for line in _stderr_lines:
        for pattern in _CRASH_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                return f"QEMU crash detected: {line[:200]}"
    return None


def _start_emulator_process(name: str, ram: int) -> Optional[subprocess.Popen]:
    _remove_stale_lock(name)
    cmd = [
        EMULATOR_BIN,
        "-avd", name,
        "-port", str(AVD_PORT),
        "-no-window",
        "-no-audio",
        "-gpu", "swiftshader_indirect",
        "-no-metrics",
        "-memory", str(ram),
        "-no-boot-anim",
    ]
    logger.info("Launching emulator: %s", " ".join(cmd))
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=_emulator_env(),
        )
        import threading
        def _drain_stderr(p):
            try:
                for bline in iter(p.stderr.readline, b""):
                    line = bline.decode("utf-8", errors="replace").rstrip()
                    if line:
                        _stderr_lines.append(line)
                        if len(_stderr_lines) > 500:
                            _stderr_lines.pop(0)
                        logger.debug("[emu] %s", line)
            except ValueError:
                pass
        t = threading.Thread(target=_drain_stderr, args=(proc,), daemon=True)
        t.start()
        return proc
    except FileNotFoundError:
        logger.error("Emulator binary not found: %s", EMULATOR_BIN)
        return None
    except Exception as e:
        logger.error("Failed to launch emulator: %s", e)
        return None


def _wait_for_boot(timeout: int = BOOT_TIMEOUT) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        rc, out, _ = _adb(["shell", "getprop", "sys.boot_completed"])
        if rc == 0 and out.strip() == "1":
            logger.info("sys.boot_completed=1, waiting for package manager...")
            pm_deadline = time.time() + 30
            while time.time() < pm_deadline:
                rc2, out2, _ = _adb(["shell", "pm", "path", "android"])
                if rc2 == 0 and "package:" in out2:
                    return True
                time.sleep(2)
            return True
        time.sleep(5)
    return False


async def _boot_emulator(name: str, ram: int):
    global _emulator_proc, _emulator_serial, _emulator_status, _last_error, _stderr_lines

    try:
        _emulator_status = "starting"
        _stderr_lines = []

        proc = _start_emulator_process(name, ram)
        if proc is None:
            _emulator_status = "error"
            _last_error = "Failed to start emulator process"
            return

        _emulator_proc = proc
        _emulator_serial = AVD_SERIAL
        _emulator_status = "booting"

        adb_deadline = time.time() + 30
        device_ready = False
        while time.time() < adb_deadline:
            crash = _detect_crash_in_stderr()
            if crash:
                _emulator_status = "error"
                _last_error = f"Emulator QEMU engine crashed: {crash}"
                logger.error("Emulator QEMU crash detected during boot: %s", crash)
                proc.kill()
                return

            rc = proc.poll()
            if rc is not None:
                crash_info = _detect_crash_in_stderr() or f"exit code {rc}"
                logger.error("Emulator died (exit=%d) before ADB connection: %s", rc, crash_info)
                _emulator_status = "error"
                _last_error = f"Emulator exited with code {rc} before ADB connection. {crash_info}"
                return

            r = subprocess.run(
                [ADB_BIN, "devices"], capture_output=True, text=True, timeout=5,
            )
            for line in r.stdout.splitlines():
                if AVD_SERIAL in line:
                    device_ready = True
                    break
            if device_ready:
                break
            await asyncio.sleep(2)

        if not device_ready:
            rc = proc.poll()
            if rc is not None:
                crash_info = _detect_crash_in_stderr() or f"exit code {rc}"
                logger.error("Emulator died (exit=%d) before ADB connection: %s", rc, crash_info)
                _emulator_status = "error"
                _last_error = f"Emulator exited with code {rc} before ADB connection. {crash_info}"
                return
            logger.error("ADB did not detect emulator within 30s")
            _emulator_status = "error"
            _last_error = "ADB did not detect emulator device within 30s"
            return

        booted = await asyncio.to_thread(_wait_for_boot, BOOT_TIMEOUT)

        crash = _detect_crash_in_stderr()
        if crash:
            _emulator_status = "error"
            _last_error = f"Emulator QEMU engine crashed: {crash}"
            logger.error("Emulator QEMU crash detected after boot wait: %s", crash)
            proc.kill()
            return

        if booted:
            _emulator_status = "running"
            logger.info("Emulator boot complete on %s", AVD_SERIAL)

            try:
                from core.emulator import EmulatorManager
                mgr = EmulatorManager()
                mgr.device_serial = AVD_SERIAL
                mgr._emulator_process = proc
                mgr._started_by_us = True
            except ImportError:
                pass
        else:
            logger.error("Emulator boot timeout")
            _emulator_status = "error"
            _last_error = f"Emulator did not boot within {BOOT_TIMEOUT}s"
    except Exception as e:
        _emulator_status = "error"
        _last_error = str(e)
        logger.error("Emulator boot task failed: %s", e)


async def _connect_external_device():
    global _emulator_serial, _emulator_status, _last_error
    serial = _adb_serial()
    _emulator_serial = serial
    _emulator_status = "connecting"
    logger.info("Connecting to external ADB device at %s", serial)

    try:
        r = subprocess.run(
            [ADB_BIN, "connect", serial],
            capture_output=True, text=True, timeout=10,
        )
        output = (r.stdout + r.stderr).lower()
        if "failed" in output or "cannot" in output:
            _emulator_status = "error"
            _last_error = f"ADB connect failed: {r.stdout.strip()} {r.stderr.strip()}"
            logger.error("ADB connect to %s failed: %s", serial, _last_error)
            return
        logger.info("ADB connect to %s: %s", serial, r.stdout.strip())
    except Exception as e:
        _emulator_status = "error"
        _last_error = f"ADB connect exception: {e}"
        logger.error("ADB connect to %s failed: %s", serial, _last_error)
        return

    deadline = time.time() + 30
    device_ready = False
    while time.time() < deadline:
        r = subprocess.run(
            [ADB_BIN, "devices"], capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.splitlines():
            if serial in line and "device" in line:
                device_ready = True
                break
        if device_ready:
            break
        await asyncio.sleep(2)

    if not device_ready:
        _emulator_status = "error"
        _last_error = f"External ADB device {serial} not detected after connect"
        logger.error(_last_error)
        return

    _emulator_status = "booting"
    booted = await asyncio.to_thread(_wait_for_boot, BOOT_TIMEOUT)

    if booted:
        _emulator_status = "running"
        logger.info("External ADB device %s boot complete", serial)
    else:
        _emulator_status = "running"
        logger.warning("External ADB device %s did not report boot_completed=1, assuming ready", serial)


def find_running_device() -> Optional[str]:
    if _is_external_backend():
        serial = _adb_serial()
        try:
            r = subprocess.run(
                [ADB_BIN, "devices"], capture_output=True, text=True, timeout=5,
            )
            for line in r.stdout.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("List") or stripped.startswith("*"):
                    continue
                parts = stripped.split("\t", 1)
                if len(parts) == 2 and parts[0] == serial and parts[1] == "device":
                    return parts[0]
        except Exception:
            pass
        return None

    if _emulator_proc is not None and _emulator_proc.poll() is None:
        try:
            r = subprocess.run(
                [ADB_BIN, "devices"], capture_output=True, text=True, timeout=5,
            )
            for line in r.stdout.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("List") or stripped.startswith("*"):
                    continue
                parts = stripped.split("\t", 1)
                if len(parts) == 2 and "emulator" in parts[0] and parts[1] == "device":
                    return parts[0]
        except Exception:
            pass
    return None


FRIDA_SERVER_PATH = "/opt/frida-server-x86_64"


def get_frida_server_info() -> dict:
    if os.path.exists(FRIDA_SERVER_PATH):
        size = os.path.getsize(FRIDA_SERVER_PATH)
        return {"installed": True, "path": FRIDA_SERVER_PATH, "size": size}
    return {"installed": False, "path": FRIDA_SERVER_PATH}


def get_emulator_status() -> dict:
    if _is_external_backend():
        serial = find_running_device()
        _emulator_serial = serial
        if serial:
            return {"status": "running", "serial": serial, "started_by_us": True, "backend": "external"}
        return {"status": "stopped", "started_by_us": True, "backend": "external"}
    if _emulator_status == "running":
        serial = find_running_device()
        if serial:
            return {"status": "running", "serial": serial, "started_by_us": True, "backend": "qemu"}
        return {"status": "stopped", "started_by_us": True, "backend": "qemu"}
    if _emulator_status == "error":
        return {"status": "error", "error": _last_error, "backend": "qemu"}
    if _boot_task and not _boot_task.done():
        return {"status": "booting", "message": "Emulator is starting up", "backend": "qemu"}
    return {"status": _emulator_status, "backend": "qemu" if not _is_external_backend() else "external"}


async def ensure_emulator(avd_name: Optional[str] = None, ram: int = 2048) -> dict:
    global _boot_task, _emulator_status, _last_error

    if _is_external_backend():
        serial = find_running_device()
        if serial:
            return {"serial": serial, "started_by_us": True, "status": "running", "backend": "external"}
        await _connect_external_device()
        serial = find_running_device()
        if serial:
            return {"serial": serial, "started_by_us": True, "status": "running", "backend": "external"}
        return {"serial": None, "started_by_us": False, "status": _emulator_status, "error": _last_error, "backend": "external"}

    name = avd_name or AVD_NAME

    serial = find_running_device()
    if serial:
        return {"serial": serial, "started_by_us": True, "status": "running", "backend": "qemu"}

    if _boot_task and not _boot_task.done():
        return {"serial": None, "started_by_us": False, "status": "booting", "message": "Emulator starting in background", "backend": "qemu"}

    if not _is_avd_created(name):
        logger.info("Creating AVD '%s' (first boot may take 2-3 min)...", name)
        created = await _create_avd(name)
        if not created:
            _last_error = "Failed to create AVD"
            _emulator_status = "error"
            return {"serial": None, "started_by_us": False, "status": "error", "error": _last_error, "backend": "qemu"}

    if not os.path.exists(EMULATOR_BIN):
        _emulator_status = "unavailable"
        _last_error = f"Emulator binary not found: {EMULATOR_BIN}"
        return {"serial": None, "started_by_us": False, "status": "unavailable", "error": _last_error, "backend": "qemu"}

    _boot_task = asyncio.create_task(_boot_emulator(name, ram))
    return {"serial": None, "started_by_us": False, "status": "booting", "message": "Emulator starting in background (takes 1-3 min)", "backend": "qemu"}


async def stop_emulator():
    global _emulator_proc, _boot_task, _emulator_status, _last_error

    if _is_external_backend():
        serial = _adb_serial()
        try:
            subprocess.run(
                [ADB_BIN, "disconnect", serial],
                capture_output=True, text=True, timeout=5,
            )
        except Exception:
            pass
        _emulator_status = "stopped"
        logger.info("Disconnected from external ADB device %s", serial)
        return

    if _boot_task and not _boot_task.done():
        _boot_task.cancel()
        try:
            await asyncio.wait_for(_boot_task, timeout=5)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass

    if _emulator_proc is not None and _emulator_proc.poll() is None:
        _emulator_proc.send_signal(signal.SIGTERM)
        try:
            _emulator_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _emulator_proc.kill()
            _emulator_proc.wait(timeout=5)
        logger.info("Emulator process stopped")

    _emulator_proc = None
    _emulator_status = "stopped"
    _boot_task = None

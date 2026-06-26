#!/usr/bin/env python3
"""Batch scan all APKs under a directory, reusing the emulator."""
import os
import sys
import glob
import time
import subprocess
from pathlib import Path

APK_DIR = "/home/kali/Desktop/tatamotor"
OUTPUT_DIR = "/home/kali/Desktop/tatamotor/output_folder"
os.makedirs(OUTPUT_DIR, exist_ok=True)

apks = sorted(glob.glob(os.path.join(APK_DIR, "*.apk")))
print(f"[*] Found {len(apks)} APKs to scan")

results = []
for i, apk in enumerate(apks):
    name = os.path.splitext(os.path.basename(apk))[0]
    out = os.path.join(OUTPUT_DIR, f"{name}.html")
    print(f"\n{'='*60}")
    print(f"[{i+1}/{len(apks)}] Scanning: {os.path.basename(apk)}")
    print(f"{'='*60}")

    cleanup = "--no-emulator-cleanup" if i < len(apks) - 1 else ""
    cmd = (
        f"python3 scanner.py \"{apk}\" "
        f"--bb --emulator --fp-filter aggressive --skip-jadx "
        f"-o \"{out}\" {cleanup}"
    )
    start = time.time()
    rc = os.system(cmd)
    elapsed = time.time() - start
    status = "OK" if rc == 0 else "FAIL"
    results.append({"apk": os.path.basename(apk), "status": status, "time": elapsed, "output": out})
    print(f"[{status}] {os.path.basename(apk)} -> {elapsed:.0f}s")

print(f"\n{'='*60}")
print(f"[*] BATCH COMPLETE: {len(results)} APKs scanned")
for r in results:
    print(f"  [{r['status']}] {r['apk']:50s} {r['time']:.0f}s -> {r['output']}")

#!/usr/bin/env python3
"""
Validation Lab — Orchestrator

Manages device profiles across multiple validation targets.
Each lab has a device_profile.json scraped from a live device.

Usage:
  python3 labs/lab.py list                  # List all labs
  python3 labs/lab.py scrape <lab-name>      # Scrape device into lab
  python3 labs/lab.py upload <lab-name>      # Upload profile to platform
  python3 labs/lab.py validate <lab-name>    # Run scanner --require-device-profile
"""

import sys, os, json, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

BASE = os.path.dirname(__file__)

LABS = {
    "aosp_r30": {"sdk": 30, "type": "emulator", "apk_corpus": "aosp_30"},
    "pixel_r30": {"sdk": 33, "type": "physical", "apk_corpus": "realworld"},
    "samsung_oneui": {"sdk": 33, "type": "physical", "apk_corpus": "realworld"},
    "lineageos": {"sdk": 33, "type": "physical", "apk_corpus": "realworld"},
}


def cmd_list():
    print(f"\n{'Lab':20s} {'SDK':5s} {'Type':10s} {'Profile':10s} {'APK Corpus':15s}")
    print("-" * 65)
    for name, cfg in LABS.items():
        prof_path = os.path.join(BASE, name, "device_profile.json")
        has_profile = "✓" if os.path.isfile(prof_path) else "—"
        size = os.path.getsize(prof_path) if os.path.isfile(prof_path) else 0
        print(f"{name:20s} {cfg['sdk']:<5d} {cfg['type']:10s} {has_profile:10s} {cfg['apk_corpus']:15s}")
        if size:
            print(f"{'':20s}  profile: {size:,} bytes")
    print()


def cmd_scrape(lab_name: str):
    if lab_name not in LABS:
        print(f"Unknown lab: {lab_name}. Options: {list(LABS.keys())}")
        sys.exit(1)
    from device_profiles.scraper import DeviceProfileScraper
    scraper = DeviceProfileScraper()
    profile = scraper.scrape()
    out_path = os.path.join(BASE, lab_name, "device_profile.json")
    with open(out_path, "w") as f:
        json.dump(profile, f, indent=2)
    print(f"Scraped device profile -> {out_path}")
    print(f"  Packages: {len(profile.get('packages', []))}")
    print(f"  Providers: {len(profile.get('providers', []))}")


def cmd_upload(lab_name: str):
    prof_path = os.path.join(BASE, lab_name, "device_profile.json")
    if not os.path.isfile(prof_path):
        print(f"No profile found at {prof_path}. Run 'scrape' first.")
        sys.exit(1)
    with open(prof_path) as f:
        data = json.load(f)
    import urllib.request
    req = urllib.request.Request(
        "http://localhost:8000/api/v1/profiles",
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req)
        print(f"Uploaded: {resp.status} {resp.read().decode()}")
    except Exception as e:
        print(f"Upload failed (platform running?): {e}")


def cmd_validate(lab_name: str):
    print(f"Validate {lab_name} — requires ADB + scanner")
    print("  python3 scanner.py <apk> --require-device-profile")


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ("list", "scrape", "upload", "validate"):
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1]
    if command == "list":
        cmd_list()
    elif command == "scrape" and len(sys.argv) >= 3:
        cmd_scrape(sys.argv[2])
    elif command == "upload" and len(sys.argv) >= 3:
        cmd_upload(sys.argv[2])
    elif command == "validate" and len(sys.argv) >= 3:
        cmd_validate(sys.argv[2])
    else:
        print(__doc__)

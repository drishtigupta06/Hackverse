# Google Pixel 6 / Android 13 (pixel_r30)

## ADB Connection

```bash
adb devices
# If USB:
#   adb kill-server && adb start-server && adb devices
# If network:
adb connect <pixel_ip>:5555
```

## Device Info

- **Fingerprint:** google/pixel_6/oriole:13/TQ3A.230901.001/10717786:userdebug/release-keys
- **Build ID:** TQ3A.230901.001
- **SDK:** 33 (Android 13)
- **Arch:** arm64-v8a
- **Type:** userdebug (recommended for replay)
- **System image:** `system-images;android-33;google_apis;arm64-v8a`

## Setup

```bash
# Scrape device profile
python3 -c "
from device_profiles.scraper import DeviceProfileScraper
scraper = DeviceProfileScraper()
profile = scraper.scrape()
import json; json.dump(profile, open('labs/pixel_r30/device_profile.json', 'w'), indent=2)
"

# Upload to platform
curl -X POST http://localhost:8000/api/v1/profiles -H 'Content-Type: application/json' \
  -d @labs/pixel_r30/device_profile.json
```

## Validation Workflow

```bash
# 1. Run scanner with device profile
python3 scanner.py <apk> --require-device-profile

# 2. Replay bundles
python3 -c "
from core.system.reproduction_bundle import run_with_evidence, ReproductionBundle
import json
b = ReproductionBundle.from_dict(json.load(open('exploit/settings_bundles.json'))[0])
report, artifacts, pkg = run_with_evidence(b)
print(f'Replay: {report.successful_steps}/{report.total_steps} steps')
"

# 3. Check research package
ls -la /tmp/opencode/evidence/research_*.zip
```

## Known Issues

- Enable USB debugging and "Stay awake" in Developer Options
- Keep screen on during replay for screenshot evidence
- Grant `android.permission.READ_EXTERNAL_STORAGE` for logcat capture

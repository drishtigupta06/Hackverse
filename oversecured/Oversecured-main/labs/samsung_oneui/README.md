# Samsung Galaxy S21 / OneUI 5 (samsung_oneui)

## ADB Connection

```bash
adb devices
# Samsung requires USB debugging enabled in Developer Options
# On first connection, authorize the RSA key on device screen
```

## Device Info

- **Fingerprint:** samsung/o1q/o1q:13/TP1A.220624.014/O1QVSG2:user/release-keys
- **Build ID:** TP1A.220624.014
- **SDK:** 33 (Android 13)
- **Arch:** arm64-v8a
- **Type:** user (not userdebug — may limit replay)

## Setup

```bash
# Enable Developer Options: Settings → About → Tap Build Number 7x
# Enable USB Debugging
# Set USB configuration to "PTP" (some Samsung models need this)

# Scrape profile
python3 -c "
from device_profiles.scraper import DeviceProfileScraper
scraper = DeviceProfileScraper()
profile = scraper.scrape()
import json; json.dump(profile, open('labs/samsung_oneui/device_profile.json', 'w'), indent=2)
"

# Upload to platform
curl -X POST http://localhost:8000/api/v1/profiles -H 'Content-Type: application/json' \
  -d @labs/samsung_oneui/device_profile.json
```

## Samsung-Specific Notes

- OneUI has heavily modified SystemUI — bundle steps may differ from AOSP
- Knox security may block some `am start` / `service call` commands
- `pm list packages` output differs from AOSP (includes Knox containers)
- Some providers are Samsung-specific and may not exist on AOSP

## Validation Targets

- Settings bundles (com.android.settings is heavily customized)
- SystemUI bundles (OneUI QuickPanel, Edge panel differ)

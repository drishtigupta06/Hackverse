# LineageOS 20 / Android 13 (lineageos)

## ADB Connection

```bash
adb devices
# LineageOS has USB debugging enabled by default on userdebug builds
adb root   # if device is userdebug
```

## Device Info

- **Fingerprint:** lineageos/beryllium/beryllium:13/TQ3A.230801.001/20231001:userdebug/release-keys
- **Build ID:** TQ3A.230801.001
- **SDK:** 33 (Android 13)
- **Arch:** arm64-v8a
- **Type:** userdebug
- **Device:** POCO F1 (beryllium)

## Setup

```bash
# Scrape profile
python3 -c "
from device_profiles.scraper import DeviceProfileScraper
scraper = DeviceProfileScraper()
profile = scraper.scrape()
import json; json.dump(profile, open('labs/lineageos/device_profile.json', 'w'), indent=2)
"

# Upload to platform
curl -X POST http://localhost:8000/api/v1/profiles -H 'Content-Type: application/json' \
  -d @labs/lineageos/device_profile.json
```

## LineageOS-Specific Notes

- Closer to AOSP than OneUI — SystemUI bundles should work with fewer modifications
- Trust: LineageOS has signature spoofing support (MicroG) which may affect permission boundaries
- SELinux is enforcing by default — may block some replay commands
- Bundles generated for AOSP SDK 30 may need SDK-adjusted commands for SDK 33

## Validation Targets

- All bundle files: settings, systemui, bluetooth
- Best candidate for cross-version bundle compatibility testing (AOSP 11 → LineageOS 13)

# AOSP SDK 30 Emulator (aosp_r30)

## ADB Connection

```bash
# Emulator should auto-connect via localhost
adb devices
# If not found:
adb connect localhost:5555
```

## Device Info

- **Fingerprint:** Android/sdk_phone_x86_64/generic_x86_64:11/RSR1.210722.013.A2/10067904:userdebug/test-keys
- **Build ID:** RSR1.210722.013.A2
- **SDK:** 30 (Android 11)
- **Arch:** x86_64
- **Type:** userdebug
- **System image:** `system-images;android-30;google_apis;x86_64`

## Profile State

- [x] Scraped via `DeviceProfileScraper`
- [x] 169 packages, 97 providers
- [x] Matches Settings APK corpus (AOSP SDK 30)
- [ ] Validated chain > 0

## Replay Setup

```bash
python3 scanner.py <apk> --require-device-profile
```

## Known Limitations

- Headless emulator has no `ActivityManager` service — `am start` fails
- Need display for screenshot capture in evidence
- No Bluetooth hardware for BT bundle replay

# MASVS v2 → Manifest Scanner Coverage Matrix

| MASVS Category | Requirement ID | Description | Covered? | Scanner Detector(s) / Rule ID(s) |
|---|---|---|---|---|
| **MASVS-STORAGE** | MASVS-STORAGE-1 | Secure storage of sensitive data (minimise, avoid insecure storage) | **PARTIAL** | `ADV-019`, `ADV-FS-001`, `ADV-FS-010`, `ADV-FS-011`, `ADV-FS-012`, `ADV-FS-013`, `ADV-FS-014`, `ADV-031`, `ADV-034`, `ADV-056`, `ADV-CP-001`, `ADV-CP-320`, `ADV-CP-321`, `MF-024`, `MF-025`, `MF-026` |
| **MASVS-STORAGE** | MASVS-STORAGE-2 | Sensitive data excluded from backups | **PARTIAL** | `MF-004`, `MF-005`, `MF-006`, `MF-155`, `MF-181`, `MF-182`, `MF-063`, `MANIFEST-BACKUP-002`, `ADV-MANIFEST-001`, `ADV-MANIFEST-002` |
| **MASVS-CRYPTO** | MASVS-CRYPTO-1 | Cryptography uses secure algorithms and modes, keys managed safely | **YES** | `ADV-CRYPTO-001`, `ADV-CRYPTO-002`, `ADV-CRYPTO-003`, `ADV-CRYPTO-004`, `ADV-CRYPTO-005`, `ADV-CRYPTO-006`, `ADV-CRYPTO-007`, `ADV-033`, `MF-061`, `MF-062` |
| **MASVS-CRYPTO** | MASVS-CRYPTO-2 | Secure random number generation, key lifecycle management | **PARTIAL** | `ADV-CRYPTO-007` (weak RNG), `ADV-033` (keystore usage), `ADV-SECRET-001` (hardcoded secrets), `MF-061`, `MF-062` |
| **MASVS-AUTH** | MASVS-AUTH-1 | Biometric and local authentication properly implemented | **YES** | `ADV-AUTH-001`, `ADV-AUTH-002`, `ADV-AUTH-010`, `ADV-AUTH-010` (biometric w/o crypto), `ADV-PERM-050`, `ADV-PERM-051`, `MF-033` |
| **MASVS-AUTH** | MASVS-AUTH-2 | Server-side authentication, token management, session security | **YES** | `ADV-AUTH-001` (local OAuth), `ADV-AUTH-010` (auth gaps), `ADV-AUTH-011`, `ADV-AUTH-012`, `ADV-AUTH-013`, `ADV-AUTH-014`, `ADV-AUTH-020`, `ADV-AUTH-030`, `ADV-AUTH-040`, `ADV-AUTH-050`, `ADV-AUTH-051`, `ADV-ATO-001` through `ADV-ATO-006`, `MF-137`, `MF-138` |
| **MASVS-AUTH** | MASVS-AUTH-3 | Authorization decisions enforced on server, client-side checks prevented | **YES** | `ADV-AUTH-010` (client-side auth), `ADV-AUTH-014` (admin role client-side), `ADV-PRIV-001`, `ADV-PRIV-002`, `ADV-CDEP-001`, `ADV-MISS-001`, `ADV-REDEL-001` |
| **MASVS-NETWORK** | MASVS-NETWORK-1 | Network communications secured with TLS, proper certificate validation | **YES** | `ADV-013`, `ADV-014`, `ADV-MITM-001`, `ADV-MITM-002`, `ADV-MITM-003`, `ADV-NET-001`, `ADV-054`, `MF-003`, `MF-034`, `MF-035`, `MF-036`, `MF-171` |
| **MASVS-NETWORK** | MASVS-NETWORK-2 | Certificate pinning, network security config, secure protocols | **PARTIAL** | `ADV-054` (pinning check), `ADV-MITM-002`, `ADV-MITM-003`, `MF-034`, `MF-035`, `MF-171` (no network security config) |
| **MASVS-PLATFORM** | MASVS-PLATFORM-1 | Platform APIs used correctly (intents, IPC, WebViews, permissions) | **YES** | `ADV-001`, `ADV-002`, `ADV-005`, `ADV-006`, `ADV-007`, `ADV-008`, `ADV-009`, `ADV-010`, `ADV-011`, `ADV-012`, `ADV-016`, `ADV-018`, `ADV-025`, `ADV-026`, `ADV-028`, `ADV-029`, `ADV-030`, `ADV-INT-001`, `ADV-INT-002`, `ADV-INT-100`–`ADV-INT-103`, `ADV-INT-110`, `ADV-INT-111`, `ADV-DEEPLINK-001`, `ADV-DEEPLINK-002`, `ADV-TASK-001`, `ADV-WEBINT-001`, `ADV-WV-001`–`ADV-WV-007`, `ADV-WEB-020`, `ADV-WEB-021`, `ADV-WEB-030`, `ADV-WEB-031`, `ADV-WEB-040`, `ADV-WEB-050`, `ADV-WEB-060`, `ADV-WEB-070`, `ADV-WEB-080`, `ADV-WEB-081`, `ADV-WEB-090`, `ADV-IMP-001`–`ADV-IMP-061`, `ADV-REDIR-001`–`ADV-REDIR-050`, `ADV-MANIFEST-003`, `MF-007`–`MF-012`, `MF-037`–`MF-042`, `MF-046`–`MF-048`, `MF-056`, `MF-064`–`MF-066`, `MF-072–MF-075`, `MF-082`–`MF-086`, `MF-151`–`MF-152`, `MF-161`–`MF-170`, `MF-174`–`MF-178`, `MF-196`–`MF-202` |
| **MASVS-PLATFORM** | MASVS-PLATFORM-2 | Sensitive data not leaked via platform mechanisms (notifications, clipboard, UI) | **YES** | `ADV-034` (clipboard), `ADV-LEAK-001` (logging), `ADV-LEAK-002` (intent extras), `ADV-LEAK-003` (notifications), `ADV-NOTIF-001`, `ADV-NOTIF-002`, `ADV-BRNOT-004`, `ADV-024` (screen capture), `MF-043`, `MF-044`, `MF-045`, `MF-114`, `MF-115`, `MF-151`, `MF-152`, `MF-185`, `MF-209`, `MF-210` |
| **MASVS-PLATFORM** | MASVS-PLATFORM-3 | UI security (overlay protection, tapjacking, screenshot blocking) | **PARTIAL** | `ADV-024` (FLAG_SECURE check), `MF-043`, `MF-151` (filterTouchesWhenObscured), `MF-152` (FLAG_SECURE), `MF-114`, `MF-115`, `MF-196`, `MF-209`, `MF-210`, `MF-023` (SYSTEM_ALERT_WINDOW) |
| **MASVS-CODE** | MASVS-CODE-1 | Input validation and sanitisation (injection prevention) | **YES** | `ADV-037`, `TAIN-SQLI-001`, `TAIN-CP-001`, `TAIN-CMD-001`, `ADV-CMD-001`, `ADV-CMD-010`, `ADV-CMD-011`, `ADV-CMD-012`, `ADV-CMD-020`, `ADV-CMD-021`, `ADV-CP-310` (path traversal), `TAIN-PATH-001`, `TAIN-FILE-001`, `ADV-052` (zip slip), `ADV-UI-001`, `ADV-UI-002`, `ADV-SERIAL-010`, `ADV-SERIAL-011`, `TAIN-SER-001` |
| **MASVS-CODE** | MASVS-CODE-2 | Compiler features and build settings for security (debuggable, ProGuard, minSdk) | **YES** | `MF-001`, `MF-002`, `MF-049`, `MF-050`, `MF-051`, `MF-055`, `MF-107`, `MF-108`, `MF-109`, `MF-153`, `MF-172`, `MF-173`, `MF-186`, `MF-187`, `ADV-MANIFEST-003`, `ADV-051` (obfuscation), `ADV-MANIFEST-003` (debuggable) |
| **MASVS-CODE** | MASVS-CODE-3 | Memory safety, native code security, transitive dependencies | **PARTIAL** | `ADV-NATIVE-001`, `ADV-NATIVE-002`, `ADV-MEM-001` (serializable native ptr), `ADV-MEM-010`, `ADV-MEM-011` (ParcelableJsonWrapper), `ADV-REFL-100`, `ADV-DCL-030` (Parcelable RCE), `ADV-DCL-040`, `ADV-DCL-041` (conditional system load) |
| **MASVS-CODE** | MASVS-CODE-4 | App resilience via update mechanism, integrity checks | **NO** | No direct coverage for MASVS-CODE-4 (enforced updating, app integrity at install/update time). Partial: `ADV-021` (root detection), `MF-068` (Play Services), `MF-157` (Play Integrity) |
| **MASVS-RESILIENCE** | MASVS-RESILIENCE-1 | Reverse engineering protection (obfuscation, anti-tamper) | **PARTIAL** | `ADV-051` (limited obfuscation detection), `ADV-NATIVE-001`, `ADV-NATIVE-002`, `ADV-REFL-002`, `ADV-REFL-101`, `ADV-REFL-103`, `MF-107` (ProGuard absent), `MF-108` (extractNativeLibs) |
| **MASVS-RESILIENCE** | MASVS-RESILIENCE-2 | Integrity checks, code signing verification | **PARTIAL** | `ADV-021` (root detection), `MF-109` (signature verification), `MF-157` (Play Integrity), `MANIFEST-SIG-002` (V1 signing), `ADV-PKG-020` (missing signature verification) |
| **MASVS-RESILIENCE** | MASVS-RESILIENCE-3 | Runtime protection (debugger detection, emulator detection, tamper detection) | **PARTIAL** | `ADV-021` (root detection), `ADV-022` (emulator detection), `ADV-023` (debug detection), `IPA-CHAIN-001`, `IPA-CONCUR-001`, `IPA-CROSS-001`, `IPA-CROSS-002` (lifecycle flows) |
| **MASVS-RESILIENCE** | MASVS-RESILIENCE-4 | Device binding, attestation, RASP | **NO** | No direct coverage. Partial: `MF-068` (Play Services), `MF-157` (Play Integrity API), `ADV-SYS-001`–`ADV-SYS-003` (system UID) |
| **MASVS-PRIVACY** | MASVS-PRIVACY-1 | Data minimisation and collection transparency | **PARTIAL** | `MF-087`–`MF-094` (privacy permissions), `MF-126`–`MF-132` (third-party SDKs), `MF-139` (privacy policy), `MF-160` (Health Connect), `MF-140` (Health Connect), `MF-203`–`MF-208` (SDK detection) |
| **MASVS-PRIVACY** | MASVS-PRIVACY-2 | User consent and data subject rights | **NO** | No direct coverage. Partial: `MF-069`, `MF-070`, `MF-071` (Firebase collection settings) |
| **MASVS-PRIVACY** | MASVS-PRIVACY-3 | Data processing transparency and SDK data collection | **PARTIAL** | `MF-126`–`MF-132` (third-party SDK detection: Facebook, AdMob, MoPub, Adjust, Braze, AppsFlyer, generic analytics), `MF-207`, `MF-208` (vendor SDKs) |
| **MASVS-PRIVACY** | MASVS-PRIVACY-4 | Secure data disposal and access controls | **NO** | No direct coverage. Partial: `ADV-LEAK-001`–`ADV-LEAK-003` (data leakage detection), `ADV-MANIFEST-001`, `ADV-MANIFEST-002` (backup) |

## Legend

- **YES** — Most aspects of the MASVS requirement are covered by at least one detector or rule
- **PARTIAL** — Some aspects are covered but significant gaps remain
- **NO** — No detector or rule covers this requirement

## Summary Statistics

| Metric | Count |
|--------|-------|
| Total MASVS requirements | 22 |
| Covered (YES) | 11 |
| Partial coverage | 9 |
| Not covered (NO) | 2 |
| Coverage rate (YES + PARTIAL) | 90.9% |
| Full coverage rate (YES) | 50.0% |

## Key Gaps

1. **MASVS-CODE-4** (enforced updating / app integrity at install time) — No detector checks for enforced update mechanisms or Play Integrity API integration for install-time verification.
2. **MASVS-RESILIENCE-4** (device binding / attestation / RASP) — No runtime application self-protection (RASP) checks; no device binding verification.
3. **MASVS-PRIVACY-2** (user consent / data subject rights) — No analysis of consent flow UX or data deletion capabilities.
4. **MASVS-PRIVACY-4** (secure data disposal) — No detection of data purge routines or secure deletion practices.

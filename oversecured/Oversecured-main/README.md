# Manifest Scanner

**Android Bug Bounty APK Scanner** — multi-phase static + dynamic analysis for finding exploitable vulnerabilities in Android applications.

```
./scan.sh target.apk -bb -o report.html
```

## Quick Start

```bash
# One-click bug bounty mode (everything: taint, exploit, chains, emulator, screenrecord)
./scan.sh target.apk -bb -o report.html

# Same via Python directly
ANDROID_SDK_ROOT=/usr/lib/android-sdk ./venv/bin/python scanner.py app.apk -bb -o report.html

# Basic scan (manifest + source analysis only)
./scan.sh target.apk --skip-jadx
```

## Features

### Phase 1 — Manifest & Source Analysis
- **Manifest analysis** — 222 XPath-based rules (MF-001..MF-222) against `AndroidManifest.xml`
- **Source analysis** — 198 regex rules (SRC-001..SRC-198) on decompiled Java/Kotlin
- Shannon entropy filtering (≥3.2) for secret detection; known-placeholder blacklist
- JADX decompilation (auto-downloaded if missing)

### Phase 2 — Advanced Static Analysis
- **Dalvik bytecode analysis** (via Androguard) — CFGs, call graphs, xrefs, string/invoke indices
- **136 feature-gated detectors**: intent redirection, WebView RCE, command injection, SQL injection, content provider abuse, path traversal, fragment injection, reflection abuse, SSL pinning state, obfuscation gaps, dynamic code loading, notification security, exposed IPC

### Taint Engine
- Inter-procedural taint tracking with method summaries and fixed-point iteration
- BFS entry-point-first analysis (capped at 3000 methods)
- 60+ source types, 10 sink categories
- Field-sensitive tracking via abstract object fields
- Sanitization detection (`equals`, `isEmpty`, `URLEncoder`, `Html.escapeHtml`, `Pattern.matches`, etc.)

### Component Graph
- Builds attack surface graph from manifest components
- Discovers activities, services, receivers, providers, deep links, authorities
- Attack path discovery (max depth 5)

### CVE Detection
- NVD API integration — auto-downloads Android CVEs, generates detection rules
- CPE-based + keyword search; AOSP patch diff extraction
- Disk cache (24h expiry) at `rules/cve_cache.json`

### Dynamic Analysis
- **Storage inspection** — checks world-readable files, shared preferences, databases
- **IPC fuzzing** — intents, broadcasts, providers, deep links
- **UI exploration** — UIAutomator2-based UI traversal + input fuzzing (complete mode)

### Exploit Generation & Validation
- **Automatic PoC generation** from findings via ADB, Drozer, or Frida vectors
- **Validation** on live ADB-connected device or emulator
- **Exploit Chain Engine** — 14 attack chain templates (CHAIN-001..CHAIN-014)
- **Screenshot capture** (before/after per finding) with pixel-diff analysis
- **Screen recording** — MP4 video of exploit PoC execution with command overlay

### Emulator Integration
- Auto-launch AVD with `--emulator` flag
- Automatic APK install, Frida-server deploy, permissions grant
- Snapshot-based boot (~30s cold boot)
- Screenshot diffing and screen recording
- Auto-cleanup on scan completion

### Frida Dynamic Analysis
- **Inline scripts** — SSL pinning bypass, root detection bypass, runtime hooks, API monitor, SharedPrefs monitor
- **13 standalone scripts** in `frida_scripts/`: enhanced bypasses, intent/file/webview monitors, secret scanners
- `--frida` / `--frida-spawn` attach or spawn modes
- Frida↔Static linking cross-references runtime findings with static analysis

### AI Triage
- Ollama integration (`http://localhost:11434`) for per-finding exploitability analysis
- Attack vector, impact, difficulty, priority classification
- Configurable model and minimum confidence threshold

### Post-Processing & Scoring
- **Confidence scoring** — 6-level system: `STATIC` (40) → `DATAFLOW` (55) → `TAINT` (70) → `POC_GEN` (75) → `DYNAMIC` (85) → `EXPLOIT` (100), with library-filtering and boost heuristics
- **Root cause dedup** — 20 root cause categories (ROOT-001..ROOT-020): groups findings by underlying vulnerability class, confidence-weighted
- **Escalation analysis** — context-based severity upgrades
- **Confirmed findings** — validated-only filtered subset

### Benchmarking & Coverage
- Gold-standard recall testing against **6 benchmark APK sets**: DIVA, GoatDroid, InsecureBank, MSTG, Oversecured, VulnLab
- **Rule coverage audit** — maps findings to OWASP Mobile Top 10 2024, MASVS v2, and 13 Android Bug Bounty classes
- Gap analysis with 10+ known coverage gaps

### Output Formats
- **HTML report** — Jinja2-rendered via `templates/report.html` (includes screenshots, videos, diff analysis)
- **SARIF v2.1.0** — compatible with GitHub Advanced Security, VS Code, Azure DevOps
- **Scan history** — SQLite database (`~/.manifest_scanner/history.db`) with list/show/compare/stats

## Architecture

```
scanner.py                       ← Entry point + CLI args
├── args parsed → ScanConfig
├── EmulatorManager              ← AVD lifecycle (boot, install, frida, cleanup)
├── ScanOrchestrator.run()
│   ├── Phase 1 — Manifest (rules/manifest.yaml)     core/analyzer.py
│   │              Source  (rules/source.yaml)        core/source_analyzer.py
│   │              JADX decompile                     core/jadx_manager.py
│   ├── AI Triage                                     core/ai_triage.py
│   ├── Phase 2 — Dalvik bytecode                     core/static_analyzer.py
│   │              Detectors                          core/detectors/
│   ├── CVE analysis                                  core/cve_analyzer.py
│   ├── Taint engine                                  core/taint_engine.py
│   │              Interprocedural                     core/interprocedural.py
│   │              Dataflow                            core/dataflow.py
│   │              Config                              core/taint_config.py
│   ├── Component graph                               core/component_graph.py
│   ├── Dynamic — Storage/IPC/UI                      core/dynamic/
│   ├── Exploit — PoC generation                      core/exploit/
│   │              Validators                         core/exploit/validators.py
│   │              Chain engine                       core/exploit_chain_engine.py
│   │              Validated chains                   core/exploit/validated_chain_engine.py
│   ├── Frida analysis                                core/frida/
│   │              Static linker                      core/frida_static_linker.py
│   ├── Root cause analysis                           core/root_cause_dedup.py
│   ├── Post-process — noise filter + FP suppression  core/fp_analyzer.py
│   ├── Escalation analysis                           core/escalation_engine.py
│   ├── Confidence scoring                            benchmarks/confidence_scorer.py
│   └── Confirmed findings                            —
├── Emulator exploit screenshots + video recording
├── Screenshot diff analysis (PIL pixel comparison)
└── Output — HTML (templates/report.html)
         — SARIF (core/sarif_exporter.py)
         — History (core/scan_history.py)
```

## Tools & Libraries Used

### Python Packages (`requirements.txt`)

| Package | Purpose |
|---------|---------|
| `androguard==3.4.0a1` | APK parsing, Dalvik bytecode, CFGs, call graphs |
| `PyYAML` | Rule file parsing (manifest.yaml, source.yaml) |
| `Jinja2` | HTML report rendering |
| `colorama` | Terminal output colors |
| `requests` | HTTP client (NVD CVE updates, Ollama AI) |
| `Pillow` | Screenshot diff analysis (pixel comparison) |
| `frida` | Dynamic instrumentation (runtime hook injection) |

### System Dependencies

| Tool | Required for | Install |
|------|-------------|---------|
| **JADX** (`jadx`) | Phase 1 — Java/Kotlin decompilation | `apt install jadx` |
| **ADB** | Device communication, exploit validation, screenshots | `apt install adb` |
| **Frida** + **frida-tools** | Runtime hooking, SSL bypass, API monitoring | `pip install frida-tools` |
| **Emulator** (`emulator`) | Android Virtual Device for dynamic testing | Android SDK |
| **aapt2** | APK resource parsing (fallback) | `apt install aapt2` |
| **FFmpeg** (`ffmpeg`) | Screen recording (command overlay) | `apt install ffmpeg` |
| **Ollama** | AI triage (localhost:11434) | [ollama.ai](https://ollama.ai) |

## Rule System

### Manifest Rules (`rules/manifest.yaml`) — 222 Rules

XPath-based rules evaluated against `AndroidManifest.xml`. Categories:

| Category | Count | Description |
|----------|-------|-------------|
| Component Exposure | 27 | Exported activities, services, receivers, providers |
| Dangerous Permissions | 21 | SMS, camera, location, microphone, etc. |
| Intent Security | 12 | Implicit intents, PendingIntent confusion |
| Broadcast Receiver | 10 | Exported receivers, ordered broadcasts |
| Build Configuration | 9 | Debuggable, testOnly, cleartext traffic |
| Compliance | 9 | Target SDK, min SDK, Google Play policies |
| Privacy | 9 | PII access, clipboard access, screen capture |
| UI Security | 9 | Tapjacking, overlay, window flags |
| Third-Party SDKs | 7 | Firebase, Facebook, Google Maps, etc. |
| Data Exposure | 6 | Backup, allowBackup, fullBackupContent |
| Distribution Security | 6 | APK expansion, install location |
| Telephony | 6 | Read phone state, call log, IMEI |
| Accessibility | 5 | Accessibility service, explore by touch |
| Cloud Integrations | 5 | Firebase, AWS, GCP configuration |
| Persistence | 5 | Boot completed, alarms, services |
| SDK Targeting | 5 | minSdk, targetSdk, compileSdk |
| Network Security | 4 | Cleartext, network security config |
| Platform-Specific | 4 | Android TV, Wear OS, Auto |
| Others | 40+ | Crypto, WebView, NFC, DCL, hardware features |

### Source Rules (`rules/source.yaml`) — 198 Rules

Regex-based rules evaluated against decompiled Java/Kotlin source. Categories:

| Category | Count | Description |
|----------|-------|-------------|
| Cryptography | 19 | Weak ciphers, ECB mode, hardcoded keys, static IVs |
| WebView Security | 16 | JS enable, file access, addJavascriptInterface |
| Hardcoded Secrets | 14 | Passwords, tokens, API keys, JWT, private keys |
| Insecure Data Storage | 11 | SharedPrefs, SQLite, external storage, cache |
| Insecure Networking | 11 | HTTP, cleartext, self-signed certs, SSL pinning gaps |
| Intent Security | 11 | Implicit intents, PendingIntent, intent redirection |
| Authentication | 9 | Weak auth, local auth bypass, biometric gaps |
| Component Security | 9 | Exported components, permission checks |
| Logging | 7 | Log.d, Log.v, System.out, printStackTrace |
| Hardcoded Production Secrets | 3 | Production API keys, prod URLs, prod credentials |
| Memory Security | 5 | Mmap, direct buffer, insecure memory |
| Supply Chain | 6 | Library loading, dynamic code loading, reflection |
| SQL Injection | 3 | Raw queries, content:// injection |
| Path Traversal | 3 | File path manipulation, zip slip |
| Others | 60+ | Deep links, IPC, clipboard, runtime protection |

### Phase 2 Detectors (`core/detectors/`) — 150 Detectors

Bytecode-level detectors analyzing Dalvik instructions:

| Detector Type | Examples |
|---------------|----------|
| Intent Redirection | ADV-IPC-001, ADV-IPC-002 |
| WebView RCE | ADV-WV-001, ADV-WV-002, ADV-WV-005 |
| Content Provider | ADV-CP-001, ADV-CP-321 |
| Privilege Escalation | ADV-PRIV-001 |
| Command Injection | ADV-022 |
| Path Traversal | ADV-037 |
| SQL Injection | ADV-SQL-* |
| Fragment Injection | ADV-FRAG-* |
| Reflection Abuse | ADV-REFLECT-* |
| Dynamic Code Loading | ADV-DCL-* |
| SSL Pinning | ADV-SSL-* |
| Obfuscation Gaps | ADV-OBF-* |
| Notification Security | ADV-NOTIFY-* |

## CLI Reference

| Flag | Description |
|------|-------------|
| `apk` | Path to APK file |
| `-bb` | **One-click bug bounty:** enables exploit, chains, dedup, confidence, taint, component-graph, frida-hooks, emulator, screenrecord, exploit-validate, dynamic |
| `-o, --output` | Output HTML report path |
| `-r, --rules` | Rules directory (default: `rules/`) |
| `--skip-jadx` | Skip JADX decompilation |
| `--jadx-dir` | Use existing JADX output directory |
| `--skip-phase2` | Skip Phase 2 advanced static analysis |
| `--taint` | Inter-procedural taint analysis |
| `--component-graph` | Component attack surface graph |
| `--exploit` | Automatic exploit generation |
| `--exploit-validate` | Validate exploits on ADB device |
| `--exploit-vector` | Exploit vectors: adb, drozer, frida (default: all) |
| `--chains` | Build exploit chains |
| `--dedup` | Compress findings into ROOT-* groups |
| `--confidence` | Score findings by confidence level |
| `--emulator` | Auto-launch AVD, install APK, frida, screenshots |
| `--emulator-avd` | AVD name (default: auto-detect) |
| `--screenrecord` | Record MP4 video of exploit PoC execution |
| `--screenrecord-duration` | Max seconds per recording (default: 8) |
| `--screenrecord-bitrate` | Bitrate in bps (default: 1Mbps) |
| `--dynamic` | Auto UI exploration + input fuzzing |
| `--frida` | Attach Frida to running app |
| `--frida-spawn` | Spawn app with Frida |
| `--frida-hooks` | Runtime hooks |
| `--frida-link` | Link Frida ↔ static findings |
| `--cve-update` | Download latest Android CVEs |
| `--ai-triage` | AI exploitability triage via Ollama |
| `--sarif` | Export SARIF v2.1.0 |
| `--benchmark` | Run benchmark suite |
| `--history-save/list/show/compare/stats` | Scan history management |
| `--fp-filter` | False positive filter: off, basic, aggressive |
| `--confirmed` | Confirmed-findings only mode |
| `--coverage-audit` | Audit rule coverage |

## Confidence Scoring

| Level | Score | Description |
|-------|-------|-------------|
| `STATIC` | 40 | Pattern/regex match |
| `DATAFLOW` | 55 | Dataflow confirms path |
| `TAINT` | 70 | Taint flow confirmed |
| `POC_GEN` | 75 | PoC generated |
| `DYNAMIC` | 85 | Frida/dynamic analysis confirmed |
| `EXPLOIT` | 100 | Exploit validated on device |

Boosts: app-owned code +10%, exported component +5%.

## Root Cause Categories

| ID | Category |
|----|----------|
| ROOT-001 | Exported Activity Intent Injection |
| ROOT-002 | Exported Service/Receiver/Provider |
| ROOT-003 | WebView RCE |
| ROOT-004 | Insecure Data Storage |
| ROOT-005 | Hardcoded Secrets |
| ROOT-006 | Debuggable + Backup |
| ROOT-007 | Cleartext Traffic |
| ROOT-008 | Command Injection |
| ROOT-009 | Weak Crypto |
| ROOT-010 | PendingIntent Confusion |
| ROOT-011 | Deep Link Security |
| ROOT-012 | Privilege Escalation |
| ROOT-013 | Task Hijacking |
| ROOT-014 | Fragment Injection |
| ROOT-015 | Dynamic Code Loading |
| ROOT-016 | Reflection Abuse |
| ROOT-017 | Data Leaking via Logs |
| ROOT-018 | Root Detection Bypass |
| ROOT-019 | SSL Pinning Bypass |
| ROOT-020 | Content Provider Leak |

## Attack Chains

| Chain | Path |
|-------|------|
| CHAIN-001 | WebView RCE ← Exported Activity + Intent Injection |
| CHAIN-002 | Data Exfil ← Exported Provider + SQL Injection + No Permission |
| CHAIN-003 | Privilege Escalation ← Exported Service + Command Injection |
| CHAIN-004 | PendingIntent Hijacking → Privileged API Access |
| CHAIN-005 | Deep Link → WebView XSS → Cookie/Token Theft |
| CHAIN-006 | Backup + Debuggable → Full Data Exfiltration |
| CHAIN-007 | Broadcast Injection → Privilege Escalation |
| CHAIN-008 | FileProvider Path Traversal → Arbitrary File Read |
| CHAIN-009 | Fragment Injection → UI Spoofing |
| CHAIN-010 | Cleartext Traffic + SSL Pinning Bypass → MITM |
| CHAIN-011 | Cross-User Intent Poisoning |
| CHAIN-012 | Task Hijacking → Credential Theft |
| CHAIN-013 | Crypto Weakness → Key Extraction |
| CHAIN-014 | Deep Link → Arbitrary App Launch |

## Project Structure

```
scanner.py                 # Entry point
scan.sh                    # Wrapper script (auto-detects Android SDK)
core/                      # Core analysis engine
├── orchestrator.py        # Scan orchestration (phase pipeline)
├── analyzer.py            # Manifest XPath analyzer
├── source_analyzer.py     # Source regex analyzer
├── static_analyzer.py     # Phase 2 Dalvik bytecode analyzer
├── jadx_manager.py        # JADX decompilation manager
├── taint_engine.py        # Intra-procedural taint engine
├── interprocedural.py     # Inter-procedural taint analysis
├── dataflow.py            # Dataflow tracking
├── taint_config.py        # Taint source/sink configuration
├── component_graph.py     # Component attack surface graph
├── cve_analyzer.py        # CVE detection and NVD integration
├── escalation_engine.py   # Severity escalation analysis
├── exploit_chain_engine.py    # Attack chain engine
├── root_cause_dedup.py    # Root cause deduplication
├── sarif_exporter.py      # SARIF v2.1.0 export
├── scan_history.py        # SQLite scan history
├── fp_analyzer.py         # False positive analysis
├── ai_triage.py           # Ollama AI integration
├── frida_static_linker.py # Frida ↔ static linking
├── utils.py               # Shared utilities
├── detectors/             # Phase 2 bytecode detectors (136+)
│   └── ...
├── dynamic/               # Dynamic analysis engine
│   ├── __init__.py
│   ├── engine.py          # Main dynamic engine
│   ├── storage.py         # Runtime storage inspection
│   ├── ui_exploiter.py    # UIAutomator2 UI traversal
│   └── webview_exploiter.py # WebView vulnerability detection
├── emulator/              # Emulator management
│   ├── __init__.py
│   └── emulator_manager.py # AVD lifecycle, screenshot, screenrecord
├── exploit/               # Exploit generation
│   ├── __init__.py
│   ├── engine.py          # PoC generation
│   ├── validators.py      # ADB-based exploit validation
│   └── validated_chain_engine.py # Validated chain builder
└── frida/                 # Frida analysis
    ├── __init__.py
    └── ...

benchmarks/                # Benchmark suite
├── benchmark_runner.py    # Gold-standard recall testing
├── gold_standards.py      # Known vulnerability mappings
├── confidence_scorer.py   # Confidence scoring
├── rule_coverage.py       # OWASP/MASVS coverage audit
├── clean_app_benchmark.py # FP rate measurement
└── diva/ goatdroid/ insecurebank/ mstg/ oversecured/ vulnlab/  # Benchmark APKs

rules/                     # YAML detection rules
├── manifest.yaml          # 222 XPath manifest rules (MF-001..MF-222)
├── source.yaml            # 198 regex source rules (SRC-001..SRC-198)
└── cve_cache.json         # NVD CVE cache (24h expiry)

templates/                 # Jinja2 HTML templates
└── report.html            # Main report template

frida_scripts/             # Frida injection scripts
├── master_hook.js         # Master hook script
├── ssl_bypass.js          # SSL pinning bypass
├── root_bypass.js         # Root detection bypass
└── ... (13 total)

tests/                     # Test suite
screenshots/               # Benchmark screenshots
reports/                   # Generated scan reports
exploit/                   # Exploit chain bundles
labs/                      # Device profiling tools
apk-scanner-ui/            # GUI wrapper (optional)
manifest_scanner/          # Python package
```

## Requirements

### Python
```bash
venv/bin/pip install -r requirements.txt
```

### System
```bash
apt install adb jadx ffmpeg
pip install frida-tools
# Android SDK (emulator) — optional, for dynamic analysis
```

## Environment

The wrapper script `scan.sh` auto-detects Android SDK. Otherwise:

```bash
export ANDROID_SDK_ROOT=/usr/lib/android-sdk
export ANDROID_HOME=/usr/lib/android-sdk
```

## License

MIT

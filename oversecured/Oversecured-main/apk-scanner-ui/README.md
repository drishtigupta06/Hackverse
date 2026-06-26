# APK Scanner UI

A web-based control panel and results dashboard for the existing `manifest_scanner` Python engine.

## Architecture

```
┌─────────┐    ┌──────────┐    ┌──────────────┐
│  Nginx   │──▶│ FastAPI   │──▶│  PostgreSQL   │
│  :80     │   │  :8000    │   │  :5432        │
└─────────┘   └──────────┘   └──────────────┘
     │              │                │
     │              ├── Redis :6379   │
     ▼              │   (queue/pubsub)│
┌─────────┐        │                │
│  Vite    │        │                │
│  :5173  │        ▼                │
└─────────┘   ┌──────────────┐     │
              │  scanner.py   │     │
              │  (subprocess) │     │
              └──────────────┘     │
                                    │
              ┌──────────────┐     │
              │  /data/apks   │◀────┘
              │  /data/reports│
              └──────────────┘
```

## Prerequisites

- Docker 24+ and docker-compose v2
- Linux: KVM (`/dev/kvm`) for Android emulator support
- The existing `manifest_scanner` repository (cloned locally)

## Quick Start

```bash
git clone <this-repo>
cd apk-scanner-ui

# Copy and edit .env
cp .env.example .env
# Edit SCANNER_PATH to point to your manifest_scanner folder
# e.g., SCANNER_PATH=/home/user/manifest_scanner

docker compose up

# Open http://localhost
```

## ADB Setup (USB Device Passthrough)

For USB ADB devices on Linux:

```bash
# Install usbip on host
sudo apt install usbip

# Share ADB device
sudo usbip bind -b <bus-id>

# Or use TCP mode (easier):
adb tcpip 5555
adb connect <device-ip>:5555
```

## Frida Setup

Frida-server must run on the target Android device:

```bash
# On device/emulator
adb root && adb remount
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# The container runs frida CLI commands over ADB
```

## Emulator Setup

Emulator inside Docker requires KVM acceleration:

```bash
# Verify KVM is available
ls -la /dev/kvm

# Create an AVD (if none exists)
docker compose exec backend avdmanager create avd \
  -n Pixel_6_API_33 \
  -k "system-images;android-33;google_apis;x86_64" \
  -d "pixel_6"
```

## Ollama Setup

Install Ollama locally (not in Docker) and pull a model:

```bash
# Install Ollama: https://ollama.ai/download
ollama pull llama2

# The container connects to host Ollama via host.docker.internal:11434
```

## Configuration

All configuration is via environment variables (see `.env.example`):

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_PASSWORD` | `scannerpass` | PostgreSQL password |
| `SCANNER_PATH` | `../manifest_scanner` | Path to scanner engine |
| `OLLAMA_URL` | `http://host.docker.internal:11434` | Ollama API URL |
| `DATA_DIR` | `/data` | Data storage directory |
| `ALLOWED_ORIGINS` | `*` | CORS allowed origins |

## CLI Flags → UI Mapping

Every `scanner.py` CLI flag is exposed in the New Scan form:

| CLI Flag | UI Section | UI Control |
|---|---|---|
| `--bb` | Scan Mode | Bug Bounty button |
| `--skip-jadx` | Scan Mode | Fast mode (implied) |
| `--fp-filter` | Analysis Modules | FP Filter toggle + level |
| `--ai-triage` | Analysis Modules | AI Triage toggle |
| `--ai-model` | AI Triage sub-options | Model name input |
| `--cve-update` | Analysis Modules | CVE Analysis toggle |
| `--cve-days` | CVE sub-options | Days back input |
| `--frida-spawn` | Frida section | Spawn app radio |
| `--frida-ssl` | Frida sub-modules | SSL Pinning checkbox |
| `--exploit` | Exploit section | Generate Exploits toggle |
| `--exploit-validate` | Exploit sub-options | Validate via device toggle |
| `--emulator` | Emulator section | Enable Emulator toggle |
| `--taint` | Analysis Modules | Taint Analysis toggle |
| `--chains` | Analysis Modules | Exploit Chains toggle |

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `GET` | `/api/v1/health/adb` | ADB status |
| `GET` | `/api/v1/health/frida` | Frida status |
| `POST` | `/api/v1/apps/upload` | Upload APK |
| `GET` | `/api/v1/apps` | List apps |
| `POST` | `/api/v1/scans` | Create scan |
| `GET` | `/api/v1/scans` | List scans |
| `GET` | `/api/v1/scans/{id}` | Scan detail |
| `GET` | `/api/v1/findings` | List findings |
| `GET` | `/api/v1/findings/summary` | Finding aggregates |
| `GET` | `/api/v1/reports/{id}/html` | Download HTML report |
| `GET` | `/api/v1/reports/{id}/sarif` | Download SARIF |
| `GET` | `/api/v1/reports/{id}/json` | Download JSON |
| `WS` | `/ws/scans/{id}/logs` | Live scan logs |

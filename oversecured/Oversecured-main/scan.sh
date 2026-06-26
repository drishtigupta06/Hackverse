#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"

show_help() {
    echo "Usage: $(basename "$0") [OPTIONS] APK_FILE"
    echo ""
    echo "Android APK Vulnerability Scanner — one-command wrapper"
    echo ""
    echo "Examples:"
    echo "  $(basename "$0") app.apk -bb -o report.html"
    echo "  $(basename "$0") app.apk --taint --exploit --output report.html"
    echo "  $(basename "$0") app.apk -bb -o /tmp/report.html"
    echo ""
    echo "Note: ANDROID_SDK_ROOT auto-detected if not set."
    echo "      Uses venv Python from project directory."
    echo ""
    echo "--- Scanner help ---"
    "$DIR/venv/bin/python" "$DIR/scanner.py" --help
    exit 0
}

# Handle help
case "${1:-}" in
    -h|--help|help) show_help ;;
esac

# Auto-detect Android SDK
if [ -z "${ANDROID_SDK_ROOT}" ]; then
    for sdk in /usr/lib/android-sdk ~/Android/Sdk ~/.android/Sdk /opt/android-sdk; do
        if [ -f "$sdk/platform-tools/adb" ]; then
            export ANDROID_SDK_ROOT="$sdk"
            export ANDROID_HOME="$sdk"
            break
        fi
    done
fi

export PATH="$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/emulator:$PATH"

exec "$DIR/venv/bin/python" "$DIR/scanner.py" "$@"
#!/bin/bash
# Emulator lifecycle helper for Android vulnerability scanner
# Usage: ./emulator.sh start|stop|check|status
set -e

EMULATOR="$(dirname "$(dirname "$0")")/.emulator"
mkdir -p "$EMULATOR"

ADB=${ANDROID_SDK_ROOT:-/usr/lib/android-sdk}/platform-tools/adb
EMU=${ANDROID_SDK_ROOT:-/usr/lib/android-sdk}/emulator/emulator
AVD="${AVD:-test_device}"
MEMORY="${MEMORY:-2048}"

check() {
    if $ADB get-state 2>/dev/null | grep -q device; then
        local serial=$($ADB devices -l 2>/dev/null | awk '/device$/ {print $1; exit}')
        local model=$($ADB shell getprop ro.product.model 2>/dev/null | tr -d '\r')
        local release=$($ADB shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')
        local sdk=$($ADB shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')
        echo "ONLINE - $serial ($model, Android $release, API $sdk)"
        return 0
    else
        echo "OFFLINE"
        return 1
    fi
}

case "${1:-check}" in
    start)
        if check >/dev/null 2>&1; then
            echo "Already running: $(check)"
            exit 0
        fi
        echo "Starting emulator ($AVD)..."
        nohup "$EMU" -avd "$AVD" -no-window -no-audio -no-boot-anim \
            -gpu off -memory "$MEMORY" -no-snapshot -wipe-data \
            > "$EMULATOR/log.txt" 2>&1 &
        PID=$!
        echo "$PID" > "$EMULATOR/pid.txt"
        echo "PID $PID, waiting for boot..."
        for i in $(seq 1 60); do
            if check >/dev/null 2>&1; then
                echo "Boot complete after ~${i}s"
                check
                exit 0
            fi
            sleep 3
        done
        echo "Timeout waiting for boot (180s). Check $EMULATOR/log.txt"
        exit 1
        ;;
    stop)
        if [ -f "$EMULATOR/pid.txt" ]; then
            kill "$(cat "$EMULATOR/pid.txt")" 2>/dev/null || true
            rm -f "$EMULATOR/pid.txt"
        fi
        # Also kill any running emulator
        pkill -f "emulator.*-avd.*$AVD" 2>/dev/null || true
        $ADB kill-server 2>/dev/null || true
        echo "Stopped"
        ;;
    check|status)
        check
        ;;
    *)
        echo "Usage: $0 {start|stop|check|status}"
        exit 1
        ;;
esac

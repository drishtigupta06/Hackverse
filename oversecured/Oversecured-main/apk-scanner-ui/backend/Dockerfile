FROM python:3.11-slim

# ── System dependencies ─────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    adb \
    openjdk-21-jre-headless \
    wget \
    unzip \
    xz-utils \
    libgl1 \
    libpulse0 \
    libx11-6 \
    libx11-xcb1 \
    libxcb1 \
    libxext6 \
    libxi6 \
    libxrender1 \
    libxtst6 \
    libpng16-16t64 \
    libxkbfile1 \
    libxcvt0 \
    && rm -rf /var/lib/apt/lists/*

# ── Android SDK ─────────────────────────────────────────────────
ENV ANDROID_HOME=/opt/android-sdk
ENV PATH=$ANDROID_HOME/emulator:$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH

RUN mkdir -p $ANDROID_HOME && \
    wget -q https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -O /tmp/cmdline-tools.zip && \
    unzip -q /tmp/cmdline-tools.zip -d /tmp/cmdline-tools && \
    mkdir -p $ANDROID_HOME/cmdline-tools && \
    mv /tmp/cmdline-tools/cmdline-tools $ANDROID_HOME/cmdline-tools/latest && \
    rm /tmp/cmdline-tools.zip && \
    yes | $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager --licenses > /dev/null 2>&1 && \
    # SDK emulator + platform tools
    $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager \
      "emulator" \
      "platform-tools" \
      "platforms;android-33" > /dev/null 2>&1 && \
    # Google APIs system image (required by google_apis AVDs)
    echo "y" | $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager \
      "system-images;android-33;google_apis;x86_64" > /dev/null 2>&1 && \
    # AOSP ATD system image (lighter, more stable for automation)
    echo "y" | $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager \
      "system-images;android-33;aosp_atd;x86_64" > /dev/null 2>&1

# ── jadx (decompiler) ───────────────────────────────────────────
RUN wget -q https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip -O /tmp/jadx.zip \
    && unzip /tmp/jadx.zip -d /usr/local/jadx \
    && ln -s /usr/local/jadx/bin/jadx /usr/local/bin/jadx \
    && rm /tmp/jadx.zip

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Scanner engine dependencies (imported at module level)
RUN pip install --no-cache-dir \
    uiautomator2 \
    lxml \
    frida \
    frida-tools

# ── frida-server (pushed to Android devices for dynamic hooking) ─
# Must run AFTER pip install frida so that $FRIDA_VER is available
RUN FRIDA_VER=$(pip show frida 2>/dev/null | grep ^Version: | cut -d' ' -f2) && \
    wget -q "https://github.com/frida/frida/releases/download/${FRIDA_VER}/frida-server-${FRIDA_VER}-android-x86_64.xz" -O /tmp/frida-server.xz && \
    xz -d /tmp/frida-server.xz -f && \
    mv /tmp/frida-server /opt/frida-server-x86_64 && \
    chmod +x /opt/frida-server-x86_64 && \
    rm -f /tmp/frida-server.xz

COPY . .

# Use tini as init to properly reap zombie processes (critical for
# emulator subprocess management)
RUN apt-get update && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

Java.perform(function () {
    send("[Clipboard Monitor] Active");

    try {
        var ClipData = Java.use("android.content.ClipData");
        var ClipboardManager = Java.use("android.content.ClipboardManager");

        ClipboardManager.setPrimaryClip.implementation = function (clip) {
            var text = "";
            if (clip) {
                try {
                    var item = clip.getItemAt(0);
                    if (item) {
                        text = item.getText() ? item.getText().toString() : "(non-text)";
                    }
                } catch (e) { text = "(error reading)"; }
            }
            send("[Clipboard] SET: " + text);
            return this.setPrimaryClip(clip);
        };

        ClipboardManager.setPrimaryClipAsUser.implementation = function (clip, user) {
            var text = "";
            if (clip) {
                try {
                    var item = clip.getItemAt(0);
                    if (item) {
                        text = item.getText() ? item.getText().toString() : "(non-text)";
                    }
                } catch (e) { text = "(error reading)"; }
            }
            send("[Clipboard] SET (as user): " + text);
            return this.setPrimaryClipAsUser(clip, user);
        };

        ClipboardManager.getPrimaryClip.implementation = function () {
            send("[Clipboard] READ");
            return this.getPrimaryClip();
        };

        ClipboardManager.getPrimaryClipDescription.implementation = function () {
            send("[Clipboard] READ description");
            return this.getPrimaryClipDescription();
        };

        ClipboardManager.hasPrimaryClip.implementation = function () {
            send("[Clipboard] CHECK hasPrimaryClip");
            return this.hasPrimaryClip();
        };

        // Android 10+ ClipboardManager (OnPrimaryClipChangedListener)
        var ClipboardManagerListener = Java.use("android.content.ClipboardManager$OnPrimaryClipChangedListener");
        ClipboardManagerListener.onPrimaryClipChanged.implementation = function () {
            send("[Clipboard] Listener: clip changed");
            return this.onPrimaryClipChanged();
        };

        // Legacy clipboard
        try {
            var ClipboardManagerOld = Java.use("android.text.ClipboardManager");
            ClipboardManagerOld.getText.implementation = function () {
                send("[Clipboard] LEGACY read");
                return this.getText();
            };
            ClipboardManagerOld.setText.implementation = function (text) {
                send("[Clipboard] LEGACY set: " + (text ? text.toString() : "null"));
                return this.setText(text);
            };
        } catch (e) { /* legacy API not available on this device */ }

        send("[Clipboard Monitor] All hooks installed");

    } catch (e) {
        send("[Clipboard Monitor] Error: " + e);
    }
});

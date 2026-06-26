
Java.perform(function() {
    var WebView = Java.use('android.webkit.WebView');
    var WebSettings = Java.use('android.webkit.WebSettings');
    WebView.loadUrl.implementation = function(url) {
        console.log('[WebView] loadUrl: ' + url);
        return this.loadUrl(url);
    };
    WebView.loadDataWithBaseURL.implementation = function(baseUrl, data, mimeType, encoding, historyUrl) {
        console.log('[WebView] loadDataWithBaseURL: ' + baseUrl);
        console.log('[WebView] Data: ' + (data ? data.substring(0, 200) : 'null'));
        return this.loadDataWithBaseURL(baseUrl, data, mimeType, encoding, historyUrl);
    };
    WebView.addJavascriptInterface.implementation = function(obj, name) {
        console.log('[WebView] addJavascriptInterface: ' + name);
        return this.addJavascriptInterface(obj, name);
    };
    WebView.evaluateJavascript.implementation = function(script, callback) {
        console.log('[WebView] evaluateJavascript: ' + script.substring(0, 100));
        return this.evaluateJavascript(script, callback);
    };
    WebSettings.setJavaScriptEnabled.implementation = function(enabled) {
        console.log('[WebView] setJavaScriptEnabled: ' + enabled);
        return this.setJavaScriptEnabled(enabled);
    };
    if (WebSettings.setAllowFileAccess) {
        WebSettings.setAllowFileAccess.implementation = function(access) {
            console.log('[WebView] setAllowFileAccess: ' + access);
            return this.setAllowFileAccess(access);
        };
    }
    console.log('[WebView Monitor] Active');
});

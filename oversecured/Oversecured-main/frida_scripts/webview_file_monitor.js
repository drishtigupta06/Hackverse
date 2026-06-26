
Java.perform(function() {
    var WebSettings = Java.use('android.webkit.WebSettings');
    WebSettings.setAllowFileAccess.implementation = function(access) {
        console.log('[WebView] setAllowFileAccess(' + access + ')');
        return this.setAllowFileAccess(access);
    };
    WebSettings.setAllowFileAccessFromFileURLs.implementation = function(access) {
        console.log('[WebView] setAllowFileAccessFromFileURLs(' + access + ')');
        return this.setAllowFileAccessFromFileURLs(access);
    };
    WebSettings.setAllowUniversalAccessFromFileURLs.implementation = function(access) {
        console.log('[WebView] setAllowUniversalAccessFromFileURLs(' + access + ')');
        return this.setAllowUniversalAccessFromFileURLs(access);
    };
    console.log('[WebView File Access Monitor] Active');
});

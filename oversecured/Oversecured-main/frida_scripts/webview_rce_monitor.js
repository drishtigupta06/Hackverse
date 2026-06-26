
Java.perform(function() {
    var WebView = Java.use('android.webkit.WebView');
    WebView.addJavascriptInterface.implementation = function(obj, name) {
        console.log('[WebView RCE] JS Interface added: ' + name);
        var cls = obj.getClass();
        console.log('[WebView RCE] Interface class: ' + cls.getName());
        var methods = cls.getDeclaredMethods();
        for (var i = 0; i < methods.length; i++) {
            console.log('[WebView RCE]   Method: ' + methods[i].getName());
        }
        return this.addJavascriptInterface(obj, name);
    };
    WebView.loadUrl.implementation = function(url) {
        console.log('[WebView RCE] loadUrl: ' + url);
        if (url.indexOf('javascript:') >= 0) {
            console.log('[WebView RCE] JavaScript URL detected: ' + url.substring(0, 150));
        }
        return this.loadUrl(url);
    };
    var Runtime = Java.use('java.lang.Runtime');
    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
    console.log('[WebView RCE Monitor] Active - check for addJavascriptInterface usage');
});

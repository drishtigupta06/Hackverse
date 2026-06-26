
Java.perform(function() {
    var ArrayList = Java.use('java.util.ArrayList');
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.checkTrustedRecursive.implementation = function(certs, host, clientAuth, untrusted, trustAnchor, used) {
        return false;
    };
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    X509TrustManager.checkServerTrusted.implementation = function(chain, authType) {
        console.log('[SSL] Bypassed cert chain: ' + chain.length + ' certs');
        return;
    };
    X509TrustManager.checkClientTrusted.implementation = function(chain, authType) { return; };
    var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
    HostnameVerifier.verify.implementation = function(hostname, session) {
        console.log('[SSL] Hostname verification bypassed: ' + hostname);
        return true;
    };
    var SSLSocketFactory = Java.use('javax.net.ssl.SSLSocketFactory');
    SSLSocketFactory.createSocket.overload('[Ljava.net.InetAddress;', 'int').implementation = function() {
        console.log('[SSL] Socket created');
        return this.createSocket.apply(this, arguments);
    };
    console.log('[SSL Pinning Bypass] All checks disabled');
});

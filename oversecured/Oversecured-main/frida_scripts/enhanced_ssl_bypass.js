// Enhanced SSL Pinning Bypass Script
// Supports OkHttp3, Conscrypt, Network Security Config bypass

Java.perform(function() {
    console.log("[+] SSL Bypass Script Loaded");
    
    // ======== OKHTTP3 BYPASS ========
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("[+] OkHttp3 SSL Pinning Bypass: " + hostname);
            send({
                type: 'ssl_bypass',
                library: 'okhttp3',
                hostname: hostname,
                status: 'success'
            });
            return;
        };
        
        CertificatePinner.check.overload('java.lang.String', 'java.util.List', 'java.lang.String').implementation = function(hostname, peerCertificates, pinType) {
            console.log("[+] OkHttp3 SSL Pinning Bypass: " + hostname);
            send({
                type: 'ssl_bypass',
                library: 'okhttp3',
                hostname: hostname,
                pinType: pinType,
                status: 'success'
            });
            return;
        };
        
        // OkHttp3 Certificate Chain Cleaner bypass
        try {
            var CertificateChainCleaner = Java.use("okhttp3.internal.tls.CertificateChainCleaner");
            CertificateChainCleaner.clean.implementation = function(chain, hostname) {
                send({
                    type: 'ssl_bypass',
                    library: 'okhttp3_certificate_chain',
                    hostname: hostname,
                    status: 'success'
                });
                return chain;
            };
        } catch(e) {}
        
    } catch(e) {
        console.log("[-] OkHttp3 not found");
    }
    
    // ======== CONSCRYPT BYPASS ========
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocsp, certPin) {
            console.log("[+] Conscrypt SSL Bypass");
            send({
                type: 'ssl_bypass',
                library: 'conscrypt',
                host: host,
                certPin: certPin ? 'present' : 'none',
                status: 'success'
            });
            return untrustedChain;
        };
        
    } catch(e) {
        console.log("[-] Conscrypt TrustManager not found");
    }
    
    // ======== NETWORK SECURITY CONFIG BYPASS ========
    try {
        // NetworkSecurityConfig TrustManager bypass
        var NetworkSecurityConfig = Java.use("android.security.NetworkSecurityConfig");
        
        // Override default SSLContext
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        
        var CustomTrustManager = Java.registerClass({
            name: 'com.scanner.ssl.CustomTrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {
                    // Always trust client certificates
                },
                checkServerTrusted: function(chain, authType) {
                    // Always trust server certificates
                    send({
                        type: 'ssl_bypass',
                        library: 'network_security_config',
                        certCount: chain ? chain.length : 0,
                        authType: authType,
                        status: 'trust_bypassed'
                    });
                },
                getAcceptedIssuers: function() {
                    return []; // Return empty array
                }
            }
        });
        
    } catch(e) {
        console.log("[-] Network Security Config bypass failed");
    }
    
    // ======== APACHE HTTPCLIENT BYPASS ========
    try {
        var AbstractVerifier = Java.use("org.apache.http.conn.ssl.AbstractVerifier");
        
        AbstractVerifier.verify.overload('java.lang.String', 'java.lang.String[]', 'java.lang.String[]', 'boolean').implementation = function(host, cn, cns, strict) {
            console.log("[+] Apache HttpClient SSL Bypass: " + host);
            send({
                type: 'ssl_bypass',
                library: 'apache_httpclient',
                host: host,
                status: 'success'
            });
            return;
        };
        
    } catch(e) {
        console.log("[-] Apache HttpClient not found");
    }
    
    // ======== TRUSTKIT BYPASS ========
    try {
        var TrustKit = Java.use("com.datatheorem.android.trustkit.TrustKit");
        
        TrustKit.initializeWithNetworkSecurityConfig.implementation = function(context, resId) {
            console.log("[+] TrustKit SSL Bypass");
            send({
                type: 'ssl_bypass',
                library: 'trustkit',
                resId: resId,
                status: 'bypassed'
            });
            return;
        };
        
    } catch(e) {
        console.log("[-] TrustKit not found");
    }
    
    // ======== WEBVIEW SSL BYPASS ========
    try {
        var WebViewClient = Java.use("android.webkit.WebViewClient");
        
        WebViewClient.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function(view, handler, error) {
            console.log("[+] WebView SSL Error Bypass");
            send({
                type: 'ssl_bypass',
                library: 'webview',
                error: error.toString(),
                url: view.getUrl(),
                status: 'bypassed'
            });
            handler.proceed();
        };
        
    } catch(e) {
        console.log("[-] WebView SSL bypass failed");
    }
    
    // ======== CERTIFICATE TRANSPARENCY BYPASS ========
    try {
        var CTVerifications = Java.use("android.net.ssl.CTVerifications");
        
        CTVerifications.verify.implementation = function(hostname, untrustedChain) {
            console.log("[+] Certificate Transparency Bypass");
            send({
                type: 'ssl_bypass',
                library: 'certificate_transparency',
                hostname: hostname,
                status: 'bypassed'
            });
            return true;
        };
        
    } catch(e) {
        console.log("[-] Certificate Transparency not found");
    }
    
    // ======== UNIVERSAL SSL CONTEXT BYPASS ========
    try {
        var SSLCertificateSocketFactory = Java.use("org.apache.http.conn.ssl.SSLCertificateSocketFactory");
        
        SSLCertificateSocketFactory.createSocket.implementation = function(socket, host, port, autoClose) {
            console.log("[+] Universal SSL Socket Bypass: " + host);
            send({
                type: 'ssl_bypass',
                library: 'universal_ssl_socket',
                host: host,
                port: port,
                status: 'bypassed'
            });
            return this.createSocket(socket, host, port, autoClose);
        };
        
    } catch(e) {
        console.log("[-] Universal SSL bypass failed");
    }
    
    console.log("[+] SSL Bypass Script Complete");
    send({
        type: 'ssl_bypass',
        status: 'loaded_complete',
        libraries: ['okhttp3', 'conscrypt', 'webview', 'apache_httpclient', 'trustkit', 'network_security_config']
    });
});
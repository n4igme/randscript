/**
 * ssl_pinning_bypass.js — Universal SSL Pinning Bypass for Android
 * 
 * Covers:
 * - OkHttp3 CertificatePinner
 * - TrustManagerImpl (Android system)
 * - X509TrustManager custom implementations
 * - SSLContext with custom TrustManagers
 * - Conscrypt (modern Android TLS)
 * - Apache HTTP client (legacy)
 * - WebViewClient SSL errors
 * 
 * Usage: frida -U -f <package> -l ssl_pinning_bypass.js
 * 
 * NOTE: Does NOT work for Flutter apps (use flutter_ssl_bypass.js instead).
 * Flutter uses BoringSSL in libflutter.so which ignores all Java-layer hooks.
 */

'use strict';

Java.perform(function () {
    console.log('[*] SSL Pinning Bypass — loading hooks...');

    // ==========================================
    // 1. OkHttp3 CertificatePinner
    // ==========================================
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCertificates) {
            console.log('[+] OkHttp3 CertificatePinner.check() bypassed for: ' + hostname);
        };
    } catch (e) {
        console.log('[-] OkHttp3 CertificatePinner not found (not using OkHttp3)');
    }

    // OkHttp3 CertificatePinner$Builder — prevent pins from being added
    try {
        var CertificatePinnerBuilder = Java.use('okhttp3.CertificatePinner$Builder');
        CertificatePinnerBuilder.add.overload('java.lang.String', '[Ljava.lang.String;').implementation = function (hostname, pins) {
            console.log('[+] OkHttp3 CertificatePinner.Builder.add() neutralized for: ' + hostname);
            return this;
        };
    } catch (e) { }

    // ==========================================
    // 2. TrustManagerImpl (Android system verifier)
    // ==========================================
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] TrustManagerImpl.verifyChain() bypassed for: ' + host);
            return untrustedChain;
        };
    } catch (e) {
        console.log('[-] TrustManagerImpl not found (older Android or custom impl)');
    }

    // ==========================================
    // 3. X509TrustManager — hook all implementations
    // ==========================================
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        // Create a TrustManager that trusts everything
        var TrustAllManager = Java.registerClass({
            name: 'com.mtest.TrustAllManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) { },
                checkServerTrusted: function (chain, authType) { },
                getAcceptedIssuers: function () { return []; }
            }
        });

        // Hook SSLContext.init() to inject our TrustManager
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function (keyManagers, trustManagers, secureRandom) {
            console.log('[+] SSLContext.init() — injecting TrustAll manager');
            var trustAllArray = Java.array('javax.net.ssl.TrustManager', [TrustAllManager.$new()]);
            this.init(keyManagers, trustAllArray, secureRandom);
        };
    } catch (e) {
        console.log('[-] SSLContext hook failed: ' + e);
    }

    // ==========================================
    // 4. Conscrypt (modern Android TLS provider)
    // ==========================================
    try {
        var ConscryptPlatform = Java.use('org.conscrypt.Platform');
        ConscryptPlatform.checkServerTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'org.conscrypt.AbstractConscryptSocket').implementation = function (tm, chain, authType, socket) {
            console.log('[+] Conscrypt Platform.checkServerTrusted() bypassed');
        };
    } catch (e) { }

    try {
        var ConscryptPlatformDuck = Java.use('org.conscrypt.Platform');
        ConscryptPlatformDuck.checkServerTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'org.conscrypt.ConscryptEngine').implementation = function (tm, chain, authType, engine) {
            console.log('[+] Conscrypt Platform.checkServerTrusted(engine) bypassed');
        };
    } catch (e) { }

    // ==========================================
    // 5. Network Security Config (Android 7+)
    // ==========================================
    try {
        var NetworkSecurityTrustManager = Java.use('android.security.net.config.NetworkSecurityTrustManager');
        NetworkSecurityTrustManager.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function (certs, authType) {
            console.log('[+] NetworkSecurityTrustManager.checkServerTrusted() bypassed');
        };
    } catch (e) { }

    // ==========================================
    // 6. WebViewClient — accept all SSL errors
    // ==========================================
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            console.log('[+] WebViewClient SSL error bypassed — proceeding');
            handler.proceed();
        };
    } catch (e) { }

    // ==========================================
    // 7. Apache HTTP client (legacy apps)
    // ==========================================
    try {
        var AbstractVerifier = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
        AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean').implementation = function (host, cns, subjectAlts, strictWithSubDomains) {
            console.log('[+] Apache AbstractVerifier.verify() bypassed for: ' + host);
        };
    } catch (e) { }

    // ==========================================
    // 8. HostnameVerifier — accept all hostnames
    // ==========================================
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var SSLSession = Java.use('javax.net.ssl.SSLSession');

        // Find and hook all HostnameVerifier implementations
        Java.enumerateLoadedClasses({
            onMatch: function (className) {
                try {
                    var cls = Java.use(className);
                    if (cls.verify && cls.class.getInterfaces().length > 0) {
                        var interfaces = cls.class.getInterfaces();
                        for (var i = 0; i < interfaces.length; i++) {
                            if (interfaces[i].getName() === 'javax.net.ssl.HostnameVerifier') {
                                cls.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (hostname, session) {
                                    console.log('[+] HostnameVerifier.verify() bypassed for: ' + hostname);
                                    return true;
                                };
                                break;
                            }
                        }
                    }
                } catch (e) { }
            },
            onComplete: function () { }
        });
    } catch (e) { }

    // ==========================================
    // 9. OkHttp3 internal TLS check (newer versions)
    // ==========================================
    try {
        var RealConnection = Java.use('okhttp3.internal.connection.RealConnection');
        RealConnection.connectTls.implementation = function (connectionSpecSelector) {
            // Call original but suppress pin check exceptions
            try {
                this.connectTls(connectionSpecSelector);
            } catch (e) {
                console.log('[+] OkHttp3 RealConnection.connectTls() exception suppressed');
            }
        };
    } catch (e) { }

    console.log('[*] SSL Pinning Bypass — all hooks installed');
    console.log('[*] NOTE: If app uses Flutter, use flutter_ssl_bypass.js instead');
});

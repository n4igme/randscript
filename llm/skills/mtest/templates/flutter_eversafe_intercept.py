#!/usr/bin/env python3
"""
Flutter + Eversafe app interceptor template.
Combines: hluda connection, Eversafe bypass, SSL bypass, connect() redirect.

PREFERRED SETUP (Unix socket — invisible to /proc/net/tcp):
  1. On device: su -c 'rm -f /data/local/tmp/.es_sock; nohup /data/local/tmp/hluda-server -l unix:/data/local/tmp/.es_sock &'
  2. Host: adb forward tcp:38291 localfilesystem:/data/local/tmp/.es_sock
  3. Host: adb reverse tcp:8443 tcp:8443
  4. Ensure TLS proxy running on host :8443
  5. Edit PACKAGE_ID below
  6. Run: python3 -u flutter_eversafe_intercept.py

FALLBACK SETUP (TCP custom port — shows in /proc/net/tcp, may trigger detection):
  1. On device: su -c 'nohup /data/local/tmp/hluda-server -l 0.0.0.0:38291 &'
  2. Host: adb forward tcp:38291 tcp:38291 && adb reverse tcp:8443 tcp:8443
  3. Same as above from step 4
"""
import frida
import time
import sys
import os

PACKAGE_ID = "com.example.app"  # EDIT THIS
FRIDA_PORT = 38291
PROXY_PORT = 8443

EVERSAFE_BYPASS = """
(function() {
    "use strict";
    // Native: filter /proc/net/tcp to hide frida port (belt)
    var FRIDA_PORT_HEX = "9593"; // 38291
    var sensitiveFDs = {};
    var openatPtr = Module.findExportByName("libc.so", "openat");
    if (openatPtr) {
        Interceptor.attach(openatPtr, {
            onEnter: function(args) { this.path = args[1].readCString(); },
            onLeave: function(retval) {
                var fd = retval.toInt32();
                if (fd > 0 && this.path && this.path.indexOf("/proc/net/tcp") !== -1)
                    sensitiveFDs[fd] = true;
            }
        });
    }
    var readPtr = Module.findExportByName("libc.so", "read");
    if (readPtr) {
        Interceptor.attach(readPtr, {
            onEnter: function(args) { this.fd = args[0].toInt32(); this.buf = args[1]; },
            onLeave: function(retval) {
                if (!sensitiveFDs[this.fd]) return;
                var n = retval.toInt32();
                if (n <= 0) return;
                try {
                    var content = this.buf.readUtf8String(n);
                    if (content && content.toUpperCase().indexOf(FRIDA_PORT_HEX.toUpperCase()) !== -1) {
                        var lines = content.split("\\n");
                        var filtered = lines.filter(function(l) {
                            return l.toUpperCase().indexOf(FRIDA_PORT_HEX.toUpperCase()) === -1;
                        });
                        var nc = filtered.join("\\n");
                        this.buf.writeUtf8String(nc);
                        retval.replace(ptr(nc.length));
                    }
                } catch(e) {}
            }
        });
    }
    send("[+] Native /proc/net/tcp filter active");
})();

Java.perform(function() {
    // PRIMARY: Suppress Handler msg 84 (MESSAGE_THREATS_FOUND)
    // This is the proven reliable bypass — catches ALL detection paths
    try {
        var Handler = Java.use("android.os.Handler");
        Handler.dispatchMessage.implementation = function(msg) {
            if (msg.what.value === 84) {
                send("[Eversafe] SUPPRESSED msg 84 (THREATS_FOUND): " + msg.obj);
                return;
            }
            return this.dispatchMessage(msg);
        };
        send("[+] Handler.dispatchMessage hooked (msg 84 suppression)");
    } catch(e) { send("[-] Handler: " + e); }

    // SECONDARY: Block EversafeService bind (insurance)
    try {
        var ContextWrapper = Java.use("android.content.ContextWrapper");
        ContextWrapper.bindService.overload("android.content.Intent", "android.content.ServiceConnection", "int").implementation = function(intent, conn, flags) {
            var compStr = intent.getComponent() ? intent.getComponent().toString() : "";
            if (compStr.indexOf("EversafeService") !== -1) {
                send("[Eversafe] BLOCKED bindService");
                return false;
            }
            return this.bindService(intent, conn, flags);
        };
        send("[+] bindService hooked");
    } catch(e) {}

    // Spoof ADB/dev settings
    try {
        var Settings = Java.use("android.provider.Settings$Global");
        Settings.getInt.overload("android.content.ContentResolver", "java.lang.String", "int").implementation = function(cr, name, def) {
            if (name === "adb_enabled" || name === "development_settings_enabled") return 0;
            return this.getInt(cr, name, def);
        };
        Settings.getInt.overload("android.content.ContentResolver", "java.lang.String").implementation = function(cr, name) {
            if (name === "adb_enabled" || name === "development_settings_enabled") return 0;
            return this.getInt(cr, name);
        };
        send("[+] Settings.Global hooked");
    } catch(e) {}

    send("[+] Eversafe bypass v7 loaded (Handler msg 84 suppression)");
});
"""

def on_message(tag):
    def handler(msg, data):
        payload = msg.get('payload', msg)
        print(f'[{tag}] {payload}', flush=True)
    return handler

def main():
    print(f"[*] Connecting to hluda on 127.0.0.1:{FRIDA_PORT}...", flush=True)
    device = frida.get_device_manager().add_remote_device(f'127.0.0.1:{FRIDA_PORT}')

    pid = device.spawn([PACKAGE_ID])
    print(f"[*] Spawned PID: {pid}", flush=True)
    session = device.attach(pid)

    # Load Eversafe bypass FIRST (before resume, before libs load)
    s_es = session.create_script(EVERSAFE_BYPASS)
    s_es.on('message', on_message('ES'))
    s_es.load()
    print("[+] Eversafe bypass loaded (pre-resume)", flush=True)

    # Load traffic capture script (if exists in cwd)
    traffic_script = os.path.join(os.path.dirname(__file__), 'jago_traffic_capture.js')
    if not os.path.exists(traffic_script):
        traffic_script = 'jago_traffic_capture.js'
    try:
        with open(traffic_script) as f:
            s_tc = session.create_script(f.read())
        s_tc.on('message', on_message('TC'))
        s_tc.load()
        print("[+] Traffic capture loaded", flush=True)
    except FileNotFoundError:
        print("[!] No traffic capture script found, skipping", flush=True)

    device.resume(pid)
    print("[+] App resumed - interception active", flush=True)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Detaching...", flush=True)
        session.detach()

if __name__ == '__main__':
    main()

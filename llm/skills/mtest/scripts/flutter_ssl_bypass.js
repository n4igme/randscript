// Flutter SSL Pinning Bypass (Modern Builds - ARM64)
// Works for Flutter 3.19+ where standard patterns fail
// Scans only executable ranges to avoid access violations on unmapped pages
// Hooks all candidates matching the verify function prologue

function bypass() {
    var m = Process.findModuleByName('libflutter.so');
    if (!m) {
        console.log('[!] libflutter.so not loaded yet, retrying...');
        setTimeout(bypass, 500);
        return;
    }
    console.log('[*] libflutter.so: ' + m.base + ' size: ' + m.size);

    // Get only executable ranges within libflutter.so
    var ranges = Process.enumerateRanges('r-x');
    var flutterRanges = [];
    var mEnd = m.base.add(m.size);
    for (var i = 0; i < ranges.length; i++) {
        if (ranges[i].base.compare(m.base) >= 0 && ranges[i].base.compare(mEnd) < 0) {
            flutterRanges.push(ranges[i]);
        }
    }
    console.log('[*] Found ' + flutterRanges.length + ' executable ranges');

    // Patterns ordered by Flutter version (newest first)
    // Each is: sub sp, #N + stp x29, x30, [sp, #offset]
    var patterns = [
        'FF 03 05 D1 FD 7B 0F A9',  // Flutter 3.22-3.24 (sub sp, #0x140)
        'FF 83 04 D1 FD 7B 0F A9',  // Flutter 3.19-3.21 (sub sp, #0x120)
        'FF C3 03 D1 FD 7B 0E A9',  // Flutter 3.13-3.18 (sub sp, #0xF0)
        'FF 43 03 D1 FD 7B 0C A9',  // Flutter 3.10-3.12
        'FF 43 04 D1 FD 7B 0F A9',  // Alternative
        'FF C3 04 D1 FD 7B 0F A9',  // Alternative
    ];

    var hooked = false;
    for (var p = 0; p < patterns.length && !hooked; p++) {
        var allMatches = [];
        for (var r = 0; r < flutterRanges.length; r++) {
            try {
                var matches = Memory.scanSync(flutterRanges[r].base, flutterRanges[r].size, patterns[p]);
                for (var j = 0; j < matches.length; j++) {
                    allMatches.push(matches[j].address);
                }
            } catch(e) {}
        }

        // Good candidate: 1-5 matches (too many = wrong pattern)
        if (allMatches.length > 0 && allMatches.length <= 5) {
            for (var i = 0; i < allMatches.length; i++) {
                (function(addr) {
                    Interceptor.attach(addr, {
                        onLeave: function(retval) {
                            retval.replace(0x1);
                        }
                    });
                })(allMatches[i]);
                console.log('[+] Hooked at ' + allMatches[i]);
            }
            console.log('[+] SSL bypass active (' + allMatches.length + ' hooks, pattern ' + p + ')');
            hooked = true;
        } else if (allMatches.length > 5) {
            console.log('[*] Pattern ' + p + ': too many matches (' + allMatches.length + '), skipping');
        }
    }

    if (!hooked) {
        console.log('[-] No pattern matched. Try manual analysis of libflutter.so');
        console.log('[*] Verify BoringSSL presence:');
        // Check for CERTIFICATE_VERIFY_FAILED string
        var readRanges = Process.enumerateRanges('r--');
        for (var i = 0; i < readRanges.length; i++) {
            if (readRanges[i].base.compare(m.base) >= 0 && readRanges[i].base.compare(mEnd) < 0) {
                try {
                    var found = Memory.scanSync(readRanges[i].base, readRanges[i].size,
                        '43 45 52 54 49 46 49 43 41 54 45 5F 56 45 52 49 46 59 5F 46 41 49 4C 45 44');
                    if (found.length > 0) {
                        console.log('[*] CERTIFICATE_VERIFY_FAILED at: ' + found[0].address);
                    }
                } catch(e) {}
            }
        }
    }
}

setTimeout(bypass, 500);

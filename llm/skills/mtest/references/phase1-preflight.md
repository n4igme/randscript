# Phase 1: Preflight

### Gate: scope.md exists, target app identified, tools verified

**Steps:**

1. Define scope:
   - Platform(s): Android / iOS / Both
   - App name and package/bundle ID
   - Version(s) to test
   - Testing type: black-box / grey-box / white-box
   - Device requirements: rooted/jailbroken, emulator acceptable?
   - Rules of engagement: what's off-limits

2. Acquire target app:
   ```bash
   # Android — from device
   adb shell pm list packages | grep -i <keyword>
   adb shell pm path <package>
   adb pull <path> target.apk

   # If split APK (base + split_config.*.apk), merge before analysis:
   java -jar APKEditor-1.4.7.jar m -i <dir_with_splits> -o merged.apk -f
   # This produces a single APK with all DEX files, native libs, and resources combined.
   # Always analyze the merged APK — split analysis misses cross-module references.

   # If APKEditor unavailable — zip overlay method:
   cp base.apk merged.apk
   for split in split_config.*.apk; do
     unzip -o "$split" -d split_tmp && cd split_tmp && zip -r ../merged.apk . && cd .. && rm -rf split_tmp
   done
   # NOTE: zip overlay overwrites AndroidManifest.xml with the last split's manifest.
   # For JADX analysis, open base.apk directly — it has all DEX + correct manifest.
   # The merged APK is useful for full native lib + resource analysis.

   # Android — from APKMirror/APKPure (black-box)
   # Download manually or use apkeep
   pip install apkeep
   apkeep -a <package_name> .

   # iOS — from jailbroken device (decrypted)
   python frida-ios-dump/dump.py <bundle_id>

   # iOS — from App Store (encrypted, limited use)
   ipatool download -b <bundle_id> -o target.ipa
   ```

3. Verify tooling:
   ```bash
   # Core tools check
   which jadx apktool frida objection adb 2>/dev/null
   frida --version
   objection version

   # Android emulator or device
   adb devices

   # Proxy (Burp/Caido) running
   curl -x http://127.0.0.1:8080 http://example.com
   ```

4. Create output directory and scope.md

**Reference:** `preflight-checklist.md`

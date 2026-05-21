# Preflight Checklist

## Scope Definition Template

```markdown
# Mobile Pentest Scope

## Target Application
- App Name: 
- Package (Android): 
- Bundle ID (iOS): 
- Version(s): 
- Download source: [Play Store / App Store / APKMirror / Client-provided]

## Platform(s)
- [ ] Android
- [ ] iOS

## Testing Type
- [ ] Black-box (no source, no credentials)
- [ ] Grey-box (credentials provided, no source)
- [ ] White-box (source code + credentials)

## Device Requirements
- [ ] Rooted Android device/emulator
- [ ] Jailbroken iOS device
- [ ] Emulator acceptable: Yes / No

## Test Accounts
- Account 1: [phone/email] / [role: regular user]
- Account 2: [phone/email] / [role: admin/premium]
- OTP delivery: [real SMS / test OTP / bypass code]

## Rules of Engagement
- Testing window: [dates/times]
- Off-limits: [production data modification / specific features]
- Notification: [who to contact if issues found]
- Data handling: [can we create test data? use real accounts?]

## Environment
- Production API: 
- Staging API (if available): 
- Backend documentation (if provided): 

## Deliverables
- [ ] Technical report
- [ ] Executive summary
- [ ] Retest after fixes
```

---

## Tool Installation (macOS)

### Core Tools

```bash
# Package managers
brew install --cask android-platform-tools  # adb, fastboot
brew install jadx                           # DEX decompiler
brew install apktool                        # APK disassembly

# Python tools
pip install frida-tools                     # Frida CLI
pip install objection                       # Frida-powered exploration
pip install apkleaks                        # APK secret scanner

# Optional but useful
brew install class-dump                     # iOS header extraction (x86 only)
pip install qark                            # Android static analysis
brew install ideviceinstaller               # iOS device management
brew install libimobiledevice               # iOS communication
```

### MobSF (Automated Scanner)

```bash
# Docker (recommended)
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Access at http://localhost:8000
# API key shown in terminal output
```

### Frida Server Setup

```bash
# Check Frida version (must match server version exactly)
frida --version

# Download server for target architecture
# Android: https://github.com/frida/frida/releases
# Look for: frida-server-<version>-android-<arch>.xz
# arch: arm64 (most modern phones), arm (older), x86_64 (emulator)

# iOS: install via Cydia/Sileo repo: https://build.frida.re
```

### Proxy Setup

```bash
# Burp Suite (recommended for mobile)
# Download: https://portswigger.net/burp/releases
# Configure: Proxy > Options > Add listener on all interfaces

# Caido (alternative, faster)
# Download: https://caido.io
# Similar proxy configuration

# Export CA certificate for device installation
# Burp: Proxy > Options > Import/Export CA Certificate > DER format
```

---

## Device Preparation

### Android Emulator (Quick Start)

```bash
# Using Android Studio AVD
# Create: API 30+, Google APIs (NOT Google Play), x86_64
# Start with writable system:
emulator -avd <name> -writable-system -no-snapshot

# Root the emulator
adb root
adb remount

# Install Frida server
FRIDA_VER=$(frida --version)
wget "https://github.com/frida/frida/releases/download/${FRIDA_VER}/frida-server-${FRIDA_VER}-android-x86_64.xz"
xz -d frida-server-*.xz
adb push frida-server-* /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

# Verify
frida-ps -U
```

### Android Physical Device (Recommended for Banking Apps)

```bash
# Requirements:
# - Unlocked bootloader
# - Magisk installed (systemless root)
# - USB debugging enabled

# Verify
adb devices
adb shell su -c "id"  # should show uid=0

# Install Frida server (match device arch)
adb shell getprop ro.product.cpu.abi  # arm64-v8a typically
# Download and push matching frida-server

# For apps with emulator detection:
# Physical device is the only reliable option
```

### iOS Device

```bash
# Requirements:
# - Jailbroken device (checkra1n, palera1n, Dopamine)
# - SSH access (default: root/alpine — CHANGE PASSWORD)
# - Frida installed via package manager

# Verify
ssh root@<device_ip> "frida-server --version"
frida-ps -U  # from host machine

# If no jailbreak available:
# - Static analysis only (IPA from ipatool)
# - Network traffic via VPN-based proxy (limited)
# - Corellium cloud (paid, full jailbreak emulation)
```

---

## APK/IPA Acquisition

### Android APK Sources

```bash
# 1. From device (best — exact version installed)
adb shell pm list packages | grep -i <keyword>
adb shell pm path <package>
adb pull <path> target.apk

# 2. APKMirror (trusted, multiple versions)
# https://www.apkmirror.com/
# Search by package name or app name

# 3. APKPure
# https://apkpure.com/

# 4. apkeep (CLI tool)
pip install apkeep
apkeep -a <package_name> -d google .

# 5. Google Play (requires auth)
# Use aurora store or gplaycli
```

### iOS IPA Sources

```bash
# 1. From jailbroken device (decrypted — BEST)
# frida-ios-dump extracts decrypted binary
cd frida-ios-dump/
python dump.py <bundle_id>

# 2. ipatool (encrypted, limited analysis)
ipatool auth login -e <apple_id>
ipatool download -b <bundle_id> -o target.ipa
# Note: encrypted IPA — class-dump and strings won't work well
# Need to decrypt on-device first

# 3. From client (white-box engagement)
# Request IPA/xcarchive directly
```

---

## Verification Checklist (Phase 1 Gate)

Before proceeding to Phase 2 (Static Analysis):

- [ ] Scope document created and saved to `mtest-output/scope.md`
- [ ] Target APK/IPA acquired
- [ ] Core tools installed and working (`frida --version`, `jadx --version`, `apktool --version`)
- [ ] Device/emulator ready (if dynamic testing planned)
- [ ] Proxy configured and CA cert ready for installation
- [ ] Test accounts available (if grey-box)
- [ ] Output directory structure created
- [ ] Rules of engagement confirmed with client/team

```bash
# Create output directory
mkdir -p mtest-output/{phase1-preflight,phase2-static/{android,ios},phase3-dynamic-setup/scripts,phase4-traffic,phase5-runtime/{screenshots,frida-output},phase6-api,findings}
```

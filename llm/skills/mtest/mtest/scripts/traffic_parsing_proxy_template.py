#!/usr/bin/env python3
"""
Traffic Parsing Proxy Template (Flask)
Transparent forward proxy that captures sessions, tokens, IDOR candidates.
Configure as Burp upstream proxy (destination=*, host=127.0.0.1, port=5556).

PITFALL: Use destination=* (wildcard) in Burp upstream config because
redsocks sends CONNECT with IP address, not hostname.

Admin endpoints:
  /proxy-admin/sessions   - captured auth sessions
  /proxy-admin/tokens     - captured access/refresh tokens
  /proxy-admin/log        - request log (last 500)
  /proxy-admin/idor       - IDOR candidates
  /proxy-admin/sensitive  - flagged sensitive responses
  /proxy-admin/export     - dump all data

Customize:
  - REAL_API: target base URL
  - auth_paths: paths that return tokens
  - IDOR patterns: regex for ID params in paths
"""
import json, time, uuid, re, logging
from datetime import datetime
from flask import Flask, request, jsonify, Response
from functools import wraps
import requests as http_requests

app = Flask(__name__)

# ---- CONFIG (edit per engagement) ----
REAL_API = "https://api.example.com"  # Target API base
LISTEN_PORT = 5556
LOG_FILE = "traffic_sessions.log"
MAX_LOG = 500

# Paths that return auth tokens (parsed automatically)
AUTH_PATHS = ['/auth/mobile/v1/login', '/auth/mobile/v1/refresh',
              '/auth/v1/juniors/login', '/auth/v1/access-token']

# IDOR detection patterns
IDOR_PATTERNS = [
    r'/accounts/(\d+)',
    r'/participants/([a-zA-Z0-9-]+)',
    r'/payment-instructions/([a-zA-Z0-9-]+)',
    r'/customers/([a-zA-Z0-9-]+)',
    r'/orders/([a-zA-Z0-9-]+)',
]

# Sensitive response keys
SENSITIVE_KEYS = ['cvv', 'pin', 'password', 'secret', 'privateKey', 'ssn']

# ---- STORAGE ----
captured_sessions = {}
captured_tokens = {}
captured_requests = []
auth_events = []
idor_candidates = []
captured_responses = []

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s',
                    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()])
log = logging.getLogger('proxy')

# ---- PARSERS ----
def parse_auth_response(path, resp_json, req_headers):
    if not resp_json:
        return
    access = resp_json.get('accessToken', '')
    refresh = resp_json.get('refreshToken', '')
    session_id = resp_json.get('sessionId', '')
    if access:
        captured_tokens[access[:32]] = {
            'type': 'access', 'full': access, 'session': session_id,
            'issued': datetime.now().isoformat(), 'path': path,
            'device_id': req_headers.get('x-device-id', ''),
        }
        log.info(f"[TOKEN] Access: {access[:16]}... session={session_id}")
    if refresh:
        captured_tokens[refresh[:32]] = {
            'type': 'refresh', 'full': refresh, 'session': session_id,
            'issued': datetime.now().isoformat(),
        }
    if session_id:
        captured_sessions[session_id] = {
            'id': session_id, 'created': datetime.now().isoformat(),
            'device_id': req_headers.get('x-device-id', ''),
            'access_token': access[:32], 'refresh_token': refresh[:32],
        }

def detect_idor(path, method, headers):
    for pat in IDOR_PATTERNS:
        match = re.search(pat, path)
        if match:
            idor_candidates.append({
                'path': path, 'method': method,
                'param': match.group(1),
                'token': headers.get('Authorization', '')[:30],
                'timestamp': datetime.now().isoformat(),
            })

def parse_sensitive(path, resp_json):
    if not resp_json:
        return
    resp_str = json.dumps(resp_json).lower()
    for key in SENSITIVE_KEYS:
        if key in resp_str:
            captured_responses.append({
                'path': path, 'key': key,
                'timestamp': datetime.now().isoformat(),
            })
            log.info(f"[SENSITIVE] {key} in {path}")

# ---- PROXY ----
@app.route('/', defaults={'path': ''}, methods=['GET','POST','PUT','DELETE','PATCH'])
@app.route('/<path:path>', methods=['GET','POST','PUT','DELETE','PATCH'])
def proxy(path):
    if path.startswith('proxy-admin'):
        return handle_admin(path)
    target = f"{REAL_API}/{path}"
    if request.query_string:
        target += f"?{request.query_string.decode()}"
    req_body = request.get_data(as_text=True)
    req_headers = dict(request.headers)
    entry = {'timestamp': datetime.now().isoformat(), 'method': request.method,
             'path': f"/{path}", 'body_preview': req_body[:300]}
    detect_idor(f"/{path}", request.method, req_headers)
    fwd = {k: v for k, v in req_headers.items() if k.lower() not in ('host','content-length')}
    try:
        resp = http_requests.request(method=request.method, url=target,
            headers=fwd, data=req_body or None, timeout=30, verify=False,
            allow_redirects=False)
        resp_json = None
        try: resp_json = resp.json()
        except: pass
        for ap in AUTH_PATHS:
            if ap in path:
                parse_auth_response(f"/{path}", resp_json, req_headers)
                auth_events.append({'path': f"/{path}", 'status': resp.status_code,
                                    'timestamp': datetime.now().isoformat()})
                break
        parse_sensitive(f"/{path}", resp_json)
        entry['response_status'] = resp.status_code
        entry['response_size'] = len(resp.content)
        captured_requests.append(entry)
        if len(captured_requests) > MAX_LOG: captured_requests.pop(0)
        log.info(f"{request.method} /{path} -> {resp.status_code}")
        excl = ['content-encoding','transfer-encoding','content-length']
        rh = [(k,v) for k,v in resp.headers.items() if k.lower() not in excl]
        return Response(resp.content, resp.status_code, rh)
    except Exception as e:
        entry['error'] = str(e)
        captured_requests.append(entry)
        return jsonify({'error': 'proxy_error', 'detail': str(e)}), 502

def handle_admin(path):
    p = path.replace('proxy-admin/', '').replace('proxy-admin', '')
    if p == 'sessions': return jsonify({'sessions': captured_sessions})
    if p == 'tokens': return jsonify({'tokens': captured_tokens})
    if p == 'log': return jsonify({'log': captured_requests[-50:], 'total': len(captured_requests)})
    if p == 'idor': return jsonify({'candidates': idor_candidates})
    if p == 'sensitive': return jsonify({'responses': captured_responses})
    if p == 'export': return jsonify({'sessions': captured_sessions, 'tokens': captured_tokens,
        'auth_events': auth_events, 'idor': idor_candidates, 'sensitive': captured_responses})
    return jsonify({'error': 'unknown admin path'})

if __name__ == '__main__':
    import urllib3; urllib3.disable_warnings()
    log.info(f"Traffic Proxy on 0.0.0.0:{LISTEN_PORT} -> {REAL_API}")
    app.run(host='0.0.0.0', port=LISTEN_PORT, debug=False)

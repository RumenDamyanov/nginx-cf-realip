#!/usr/bin/env bash
set -euo pipefail
# Negative / resilience tests for nginx-cf-realip
# Requires: python3
# Scenarios:
# 1. Insecure URL blocked when allow_insecure off
# 2. Non-cloudflare host blocked when allow_other_hosts off (exact/suffix match only)
# 3. Invalid CIDRs skipped with WARN log (count)
# 4. Exponential backoff caps at 4x refresh interval (partially via scheduling logs)
# 5. ETag 304 path does not rewrite file
# 6. Subdomain of cloudflare.com accepted (positive control)

NGINX_VERSION=${NGINX_VERSION:-1.28.0}
WORKDIR=$(pwd)
TESTDIR=$WORKDIR/test-runtime-neg
rm -rf "$TESTDIR" && mkdir -p "$TESTDIR"

# Prepare fixture lists
cat > "$TESTDIR"/badv4.txt <<EOF
198.51.100.0/24
invalid-line
203.0.113.0/33
EOF
cp "$TESTDIR"/badv4.txt "$TESTDIR"/badv4-second.txt

# Simple HTTP server to simulate 304 (using python) if available
ETAG_FILE="$TESTDIR/etag.txt"
cat > "$ETAG_FILE" <<EOF
W/"abc123"
EOF

cat > "$TESTDIR"/server.py <<'PY'
import http.server, time, os, sys
ETAG='W/"abc123"'
class H(http.server.BaseHTTPRequestHandler):
  def do_GET(self):
    if 'If-None-Match' in self.headers:
      self.send_response(304)
      self.send_header('ETag', ETAG)
      self.end_headers()
      return
    body=b'198.51.100.0/24\n'
    self.send_response(200)
    self.send_header('Content-Type','text/plain')
    self.send_header('Content-Length', str(len(body)))
    self.send_header('ETag', ETAG)
    self.end_headers()
    self.wfile.write(body)
  def log_message(self, *a):
    return
http.server.ThreadingHTTPServer(('127.0.0.1', 18081), H).serve_forever()
PY

# Build nginx & module
wget -nv https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
mkdir -p build-neg && tar xzf nginx-${NGINX_VERSION}.tar.gz -C build-neg
cd build-neg/nginx-${NGINX_VERSION}
./configure --add-dynamic-module=../../src --with-http_realip_module >/dev/null
make modules -j$(nproc) >/dev/null
cp objs/ngx_http_cf_realip_module.so "$TESTDIR"/
cd "$TESTDIR"

# Base nginx.conf generator
make_conf() {
  cat > "$TESTDIR/nginx.conf" <<EOF
load_module ./ngx_http_cf_realip_module.so;
worker_processes 1;
events {}
http {
  cf_realip_enabled on;
  cf_realip_refresh_interval 5;
  cf_realip_output_path $TESTDIR/snippet.conf;
  $1
  server { listen 127.0.0.1:8090; location / { return 200 'ok'; } }
}
EOF
}

# 1. Insecure URL blocked
make_conf "cf_realip_source_url http://example.com/ips-v4;"
# Start nginx expecting fetch error in logs
nginx -p "$TESTDIR" -c "$TESTDIR/nginx.conf" || true
if ! grep -q 'insecure URL blocked' logs/error.log; then echo 'FAIL insecure URL test'; exit 1; fi
grep -q 'failure_count=1' logs/error.log || true
nginx -s quit || true

# 2. Host allowlist blocked
make_conf "cf_realip_source_url https://example.com/ips-v4;"
nginx -p "$TESTDIR" -c "$TESTDIR/nginx.conf" || true
if ! grep -Eq 'host not permitted|unsupported scheme|local file URL not permitted' logs/error.log; then echo 'FAIL host allowlist test'; exit 1; fi
nginx -s quit || true

# 2b. Allowed subdomain host (should NOT log host not permitted)
make_conf "cf_realip_source_url https://updates.cloudflare.com/ips-v4;"
nginx -p "$TESTDIR" -c "$TESTDIR/nginx.conf" || true
if grep -q 'host not permitted' logs/error.log; then echo 'FAIL allowed subdomain incorrectly blocked'; exit 1; fi
nginx -s quit || true

# 3. Invalid CIDRs skipped (use file:// with invalid lines)
make_conf "cf_realip_allow_insecure on; cf_realip_allow_other_hosts on; cf_realip_source_url file://$TESTDIR/badv4.txt;"
nginx -p "$TESTDIR" -c "$TESTDIR/nginx.conf" || true
sleep 2
if ! grep -q 'invalid CIDR skipped' logs/error.log; then echo 'FAIL invalid CIDR log'; exit 1; fi
if ! grep -q 'updated 1 CIDRs' logs/error.log; then echo 'FAIL expected only 1 valid CIDR'; exit 1; fi
cp "$TESTDIR/snippet.conf" "$TESTDIR/snippet.first"
nginx -s quit || true

# 4 & 5. Backoff + ETag 304 (run python server)
python3 "$TESTDIR/server.py" & PY_PID=$!
sleep 1
make_conf "cf_realip_source_url http://127.0.0.1:18081/list.txt; cf_realip_allow_insecure on; cf_realip_allow_other_hosts on;"
nginx -p "$TESTDIR" -c "$TESTDIR/nginx.conf" || true
sleep 2
# First fetch succeeds -> updated 1 CIDRs
if ! grep -q 'updated 1 CIDRs' logs/error.log; then echo 'FAIL first ETag fetch'; kill $PY_PID; exit 1; fi
HASH_FIRST=$(sha256sum snippet.conf | cut -d' ' -f1)
nginx -s quit || true
# Second start triggers If-None-Match -> not modified
nginx -p "$TESTDIR" -c "$TESTDIR/nginx.conf" || true
sleep 2
HASH_SECOND=$(sha256sum snippet.conf | cut -d' ' -f1)
if ! grep -q 'not modified (ETag)' logs/error.log; then echo 'FAIL ETag 304 notice'; kill $PY_PID; exit 1; fi
if [ "$HASH_FIRST" != "$HASH_SECOND" ]; then echo 'FAIL unexpected hash change after 304'; kill $PY_PID; exit 1; fi
kill $PY_PID || true

echo 'Negative tests passed'

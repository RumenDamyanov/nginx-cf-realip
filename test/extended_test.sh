#!/usr/bin/env bash
set -euo pipefail
# Extended tests: IPv6 fetch + unchanged hash skip
# Verifies IPv6 inclusion and stable hash on unchanged data (invoked in CI)

NGINX_VERSION=${NGINX_VERSION:-1.28.0}
WORKDIR=$(pwd)
TESTDIR=$WORKDIR/test-runtime-ext
rm -rf "$TESTDIR" && mkdir -p "$TESTDIR"
mkdir -p "$TESTDIR/logs" "$TESTDIR/conf" "$TESTDIR/temp"
cp test/fixtures/nginx.conf.template "$TESTDIR/nginx.conf"
cp test/fixtures/v6.txt "$TESTDIR/v6.txt"
# Provide v4 list
cat > "$TESTDIR/v4.txt" <<EOF
203.0.113.0/24
198.51.100.0/24
EOF
sed -i "s#__TESTDIR__#${TESTDIR}#g" "$TESTDIR/nginx.conf"

# Build nginx & module locally (assumes deps installed)
wget -nv https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
mkdir -p build-ext && tar xzf nginx-${NGINX_VERSION}.tar.gz -C build-ext
cd build-ext/nginx-${NGINX_VERSION}
./configure --add-dynamic-module=../../src --with-http_realip_module
# Build full nginx to obtain nginx binary (tests need to run it)
make -j$(nproc)
cp objs/ngx_http_cf_realip_module.so "$TESTDIR"/

# Adjust nginx.conf to enable IPv6 (must stay inside http { } block)
# Ensure fetch_ipv6 on and add v6 source directive within the block, not appended after closing brace.
if grep -q 'cf_realip_fetch_ipv6 off;' "$TESTDIR/nginx.conf"; then
  sed -i 's/cf_realip_fetch_ipv6 off;/cf_realip_fetch_ipv6 on;/' "$TESTDIR/nginx.conf"
elif ! grep -q 'cf_realip_fetch_ipv6' "$TESTDIR/nginx.conf"; then
  # insert after opening http {
  sed -i '/^http {/a \	cf_realip_fetch_ipv6 on;' "$TESTDIR/nginx.conf"
fi
if ! grep -q 'cf_realip_source_url_v6' "$TESTDIR/nginx.conf"; then
  sed -i "/^http {/a \	cf_realip_source_url_v6 file://$TESTDIR/v6.txt;" "$TESTDIR/nginx.conf"
fi

# Run nginx
mkdir -p "$TESTDIR/logs"
CF_REALIP_TEST_MIN_REFRESH=1 ./objs/nginx -p "$TESTDIR" -c "$TESTDIR/nginx.conf" || { echo 'Failed to start nginx'; cat "$TESTDIR/logs/error.log" 2>/dev/null || true; exit 1; }

# Wait (up to 12s) for first timer-driven fetch to produce snippet
FOUND=0
for i in {1..12}; do
  if [ -f "$TESTDIR/snippet.conf" ]; then FOUND=1; break; fi
  sleep 1
done
if [ $FOUND -ne 1 ]; then
  echo 'snippet.conf not created in time' >&2
  cat "$TESTDIR/logs/error.log" 2>/dev/null || true
  exit 1
fi
if ! grep -q '2400:cb00::/32' "$TESTDIR/snippet.conf"; then
  echo 'IPv6 CIDR missing' >&2
  cat "$TESTDIR/logs/error.log" 2>/dev/null || true
  exit 1
fi
COUNT_FIRST=$(grep -c '^set_real_ip_from' "$TESTDIR/snippet.conf" || true)
# Capture mod time and hash
HASH_FIRST=$(sha256sum "$TESTDIR/snippet.conf" | cut -d' ' -f1)
# Restart nginx to confirm unchanged hash path
if [ -f "$TESTDIR/logs/nginx.pid" ]; then
  OLD_PID=$(cat "$TESTDIR/logs/nginx.pid" || true)
  CF_REALIP_TEST_MIN_REFRESH=1 ./objs/nginx -p "$TESTDIR" -c "$TESTDIR/nginx.conf" -s quit || true
  # Wait for process exit (max 5s)
  for i in {1..10}; do
    if [ -n "${OLD_PID:-}" ] && kill -0 "$OLD_PID" 2>/dev/null; then sleep 0.5; else break; fi
  done
  if [ -n "${OLD_PID:-}" ] && kill -0 "$OLD_PID" 2>/dev/null; then echo 'Old nginx process still running; forcing kill' >&2; kill -9 "$OLD_PID" || true; fi
fi
CF_REALIP_TEST_MIN_REFRESH=1 ./objs/nginx -p "$TESTDIR" -c "$TESTDIR/nginx.conf"
sleep 3
HASH_SECOND=$(sha256sum "$TESTDIR/snippet.conf" | cut -d' ' -f1)
if [ "$HASH_FIRST" != "$HASH_SECOND" ]; then
  echo 'Hash changed unexpectedly for identical lists' >&2; exit 1; fi
COUNT_SECOND=$(grep -c '^set_real_ip_from' "$TESTDIR/snippet.conf" || true)
if [ "$COUNT_FIRST" -ne "$COUNT_SECOND" ]; then
  echo 'Entry count mismatch after unchanged fetch' >&2; exit 1; fi

echo 'Extended tests passed (IPv6 + unchanged hash)'

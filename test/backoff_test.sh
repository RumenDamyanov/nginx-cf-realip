#!/usr/bin/env bash
set -euo pipefail
# Backoff interval verification test
# Forces repeated failures to observe scheduling notice logs and ensure cap at 4x

NGINX_VERSION=${NGINX_VERSION:-1.28.0}
WORKDIR=$(pwd)
TESTDIR=$WORKDIR/test-runtime-backoff
rm -rf "$TESTDIR" && mkdir -p "$TESTDIR"
export CF_REALIP_TEST_MIN_REFRESH=1

# Intentionally point to an unreachable URL (fast failure) using https to trigger network error / timeout quickly
cat > "$TESTDIR/nginx.conf" <<EOF
load_module ./ngx_http_cf_realip_module.so;
worker_processes 1;
events {}
http {
  cf_realip_enabled on;
  cf_realip_refresh_interval 1;
  cf_realip_source_url https://127.0.0.1:59999/nowhere;
  cf_realip_output_path $TESTDIR/snippet.conf;
  server { listen 127.0.0.1:8181; location / { return 200 'ok'; } }
}
EOF

# Build nginx & module
wget -nv https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
mkdir -p build-back && tar xzf nginx-${NGINX_VERSION}.tar.gz -C build-back
cd build-back/nginx-${NGINX_VERSION}
./configure --add-dynamic-module=../../src --with-http_realip_module >/dev/null
make modules -j$(nproc) >/dev/null
cp objs/ngx_http_cf_realip_module.so "$TESTDIR"/
cd "$TESTDIR"

# Start nginx (it will schedule first fetch after 2s) – capture logs for ~12 seconds
nginx -p "$TESTDIR" -c "$TESTDIR/nginx.conf" || true
sleep 12
nginx -s quit || true

# Extract intervals from logs
mapfile -t intervals < <(grep 'scheduling next fetch in' logs/error.log | sed -E 's/.*in ([0-9]+) s.*/\1/')
# We expect a non-decreasing sequence capped at 4 (1,2,3,4,4,... depending on failures)
prev=0
cap_ok=1
for v in "${intervals[@]}"; do
  if [ "$v" -lt "$prev" ]; then echo "FAIL backoff decreased ($v < $prev)"; exit 1; fi
  if [ "$v" -gt 4 ]; then echo "FAIL backoff exceeded cap (v=$v)"; cap_ok=0; break; fi
  prev=$v
done
[ $cap_ok -eq 1 ] || exit 1

echo 'Backoff test passed'

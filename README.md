# nginx-cf-realip

Automatic Cloudflare edge IP list fetcher for NGINX real client IP restoration.

This dynamic HTTP module periodically downloads the authoritative Cloudflare IPv4 + IPv6 CIDR ranges, validates them, and writes an atomic include file that you reference from standard `ngx_http_realip_module` directives (`set_real_ip_from`). It focuses on being:

* Safe (HTTPS enforced, host allowlist, size limits, atomic write)
* Efficient (hash-based change detection, optional IPv6 fetch, exponential backoff)
* Simple to operate (no embedded reload logic: you decide when/how to reload)
* Portable (pure dynamic module – no external daemons / cron required inside the container)

Why not just curl a list via cron? This module keeps the logic inside the NGINX lifecycle so builds, logging, and configuration remain co-located. You reduce external moving parts, get consistent logging context, and avoid partial writes or race conditions during updates.

## Key Features

* Periodic fetch of Cloudflare IPv4 + IPv6 CIDRs (separate URLs) with HTTPS enforcement
* CIDR validation (invalid lines skipped with WARN log)
* Atomic snippet updates (temp + fsync + rename) only when content hash changes (SHA256)
* Exponential backoff (up to 4x interval) on repeated failures
* Configurable refresh interval, output path, source URLs, and security controls
* IPv6 toggle / custom v6 URL
* Hostname whitelisting (restricts to cloudflare.com unless overridden)
* Minimal logging footprint; structured NOTICE/ERROR/WARN messages

## Directives

Directive | Arguments | Default | Description
--------- | --------- | ------- | -----------
cf_realip_enabled | on / off | off | Enable module logic
cf_realip_source_url | URL | Cloudflare IPv4 list | IPv4 list URL (HTTPS required unless cf_realip_allow_insecure)
cf_realip_source_url_v6 | URL | Cloudflare IPv6 list | IPv6 list URL
cf_realip_fetch_ipv6 | on / off | on | Enable/disable IPv6 list fetching
cf_realip_refresh_interval | seconds | 86400 | Refresh cadence (>=300; backoff to 4x on failures)
cf_realip_output_path | path | /etc/nginx/cloudflare-ips.conf | Destination snippet file
cf_realip_allow_insecure | on / off | off | Permit non-HTTPS URLs
cf_realip_allow_other_hosts | on / off | off | Allow non-cloudflare hosts for source URLs

Notes:

* `cf_realip_refresh_interval` enforces a minimum of 300 seconds (5 minutes) to avoid abusive polling.
* When unchanged (SHA256 identical) the file is left untouched (mtime stable) – your reload automation can key off mtime changes or NOTICE logs.
* ETag conditional fetch is partially implemented (future optimization to skip body transfer when provider sends 304 Not Modified).

### Real IP Integration

The module only produces the *trusted proxy list*. You still configure `ngx_http_realip_module`:

```nginx
http {
  # 1. Include generated trusted proxy list
  include /etc/nginx/cloudflare-ips.conf;

  # 2. Declare header Cloudflare sets
  real_ip_header CF-Connecting-IP;
  real_ip_recursive on;

  # Optionally log original & restored IP
  log_format main '$remote_addr (orig $http_cf_connecting_ip) - $request';
}
```

## Build (Manual)

```bash
git clone https://github.com/RumenDamyanov/nginx-cf-realip.git
cd nginx-cf-realip
wget https://nginx.org/download/nginx-1.28.0.tar.gz
tar xzf nginx-1.28.0.tar.gz
cd nginx-1.28.0
./configure --add-dynamic-module=../src --with-http_realip_module
make modules
cp objs/ngx_http_cf_realip_module.so /etc/nginx/modules/
```

Load at top of `nginx.conf` (main context):

```nginx
load_module modules/ngx_http_cf_realip_module.so;
```

## Minimal Configuration

```nginx
http {
    include /etc/nginx/cloudflare-ips.conf;  # generated file
    cf_realip_enabled on;
    cf_realip_refresh_interval 86400;
    # optional overrides:
    # cf_realip_source_url https://www.cloudflare.com/ips-v4;
    # cf_realip_source_url_v6 https://www.cloudflare.com/ips-v6;
}
```

## How It Works

1. On worker process init, schedules first fetch (2s delay).
2. Fetches IPv4 (and optionally IPv6) lists via libcurl.
3. Validates each line as CIDR; discards invalid entries.
4. Builds unified snippet; computes SHA256.
5. If changed, atomically replaces `cf_realip_output_path`.
6. Logs NOTICE with counts; callers decide when to run `nginx -s reload`.
7. On errors, retains previous file; applies backoff.

## Suggested Reload Automation

```bash
if nginx -t; then
  nginx -s reload
fi
```
(Only after a logged cf_realip NOTICE indicating an update.)


## Security Notes

* HTTPS enforced unless explicitly allowed.
* Hostname restricted to *cloudflare.com* (exact or subdomain suffix) unless `cf_realip_allow_other_hosts on;`.
* Output file overwritten atomically to avoid partial read during reload.
* No runtime modification of realip trusted proxies; relies on reload semantics.

## Logs (Examples)

```text
NOTICE cf_realip: updated 42 CIDRs (size=1234) -> /etc/nginx/cloudflare-ips.conf
NOTICE cf_realip: IP list unchanged (42 entries)
ERROR  cf_realip: fetch failed (https://www.cloudflare.com/ips-v4) res=28 http=0
WARN   cf_realip: invalid CIDR skipped (badline)
```


## Example Configurations

### 1. Minimal (defaults)

```nginx
load_module modules/ngx_http_cf_realip_module.so;
http {
  include /etc/nginx/cloudflare-ips.conf;
  cf_realip_enabled on;
  # All other directives use defaults
  real_ip_header CF-Connecting-IP;
  real_ip_recursive on;
}
```

### 2. Custom Output Path & Faster Refresh

```nginx
http {
  cf_realip_enabled on;
  cf_realip_output_path /var/cache/nginx/cloudflare-trusted.conf;
  cf_realip_refresh_interval 7200; # 2h (>=300s constraint)
  include /var/cache/nginx/cloudflare-trusted.conf;
  real_ip_header CF-Connecting-IP;
}
```

### 3. Disable IPv6 Fetch (IPv4 only)

```nginx
http {
  cf_realip_enabled on;
  cf_realip_fetch_ipv6 off;
  include /etc/nginx/cloudflare-ips.conf;
}
```

### 4. Allow Non-Cloudflare Host (Testing / Mirror)

```nginx
http {
  cf_realip_enabled on;
  cf_realip_allow_other_hosts on;   # relax host allowlist
  cf_realip_source_url https://example.com/custom-v4.txt;
  cf_realip_source_url_v6 https://example.com/custom-v6.txt;
}
```

## Limitations / Roadmap

* No built-in automatic reload (intentional separation of concerns).
* Single combined snippet (does not separate v4/v6 sections—could be extended).
* Future: conditional fetch (ETag / If-Modified-Since), signed list verification.

## Development (Local Docker Build)

Use `.development/build-module.sh` to build against multiple NGINX versions inside a container; artifacts named `ngx_http_cf_realip_module-<version>.so`.

## Release Artifacts

Tagged releases publish prebuilt dynamic module tarballs for matrix:

* Ubuntu: jammy, noble, plucky
* Architectures: amd64, arm64
* NGINX versions: 1.27.0, 1.28.0

Each artifact filename pattern:

```text
nginx-cf-realip_<moduleVersion>_nginx<nginxVersion>_<ubuntuCodename>_<arch>.tar.gz
```

Tarball contents:

* `ngx_http_cf_realip_module-nginx<nginxVersion>-ubuntu-<ubuntuCodename>-<arch>.so`
* `README.md`, `LICENSE.md`, `CHANGELOG.md`
* `BUILDINFO.json` (metadata: versions, commit, timestamp, toolchain)

Integrity:

1. Download desired tarball + `SHA256SUMS` from release assets.
2. Verify:

```bash
grep "$(basename <tarball>)" SHA256SUMS | sha256sum -c -
```

Install:

1. Extract `.so` into `/etc/nginx/modules/` (or preferred modules dir).
2. Add `load_module` directive referencing the copied filename (you may rename locally if desired).
3. Include generated snippet path (default `/etc/nginx/cloudflare-ips.conf`) in `http` context.

Reproducibility:

`BUILDINFO.json` records build inputs enabling deterministic rebuild attempts; rebuild locally by matching NGINX version, Ubuntu base image, and architecture.

## Compatibility

Tested in CI (dynamic builds) against:

* Ubuntu: jammy, noble, plucky
* Architectures: amd64, arm64
* NGINX: 1.27.0, 1.28.0

Other versions may work; rebuild the module for the exact runtime NGINX version to avoid ABI mismatches.

## Upgrading

Rebuild the module against the exact NGINX version in production. ABI differences across versions may break older builds.

## Contributing

Contributions welcome – see [CONTRIBUTING.md](CONTRIBUTING.md) for workflow, coding style, and PR checklist.

## Code of Conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Please review the [Security Policy](SECURITY.md) for supported versions and coordinated disclosure process.

## Funding

Support ongoing development via the options in [FUNDING](FUNDING.md).

## License

BSD-style – see [LICENSE.md](LICENSE.md).

---

Questions / feedback? Open an issue or start a discussion in the repository.

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-01-16

### Changed
- **BREAKING**: Replaced libcurl with native NGINX async HTTP fetching
  - Module now uses NGINX's built-in resolver, event loop, and SSL support
  - Removed external libcurl dependency
  - **Requires `resolver` directive in http{} block** (e.g., `resolver 1.1.1.1;`)
- Refresh interval now uses milliseconds internally (config still accepts seconds)
- Version bumped to 0.3.0

### Added
- Native NGINX DNS resolution via `ngx_resolver`
- Native NGINX SSL/TLS support for HTTPS fetching
- Proper async I/O with non-blocking read/write handlers
- Connection timeout and retry handling

### Removed
- libcurl dependency - no longer required
- Blocking HTTP operations - all fetches are now async

### Fixed
- Memory management improved with proper pool allocation
- SSL function naming corrected (`ngx_ssl_write` instead of `ngx_ssl_send`)

## [0.2.0] - 2026-01-16

### Changed
- **BREAKING**: Refactored module configuration context structure
  - Global settings (URLs, interval, output path, security flags) now only valid in `http {}` block
  - Only `cf_realip_enabled` can be set per-server or per-location
- Module version bumped to 0.2.0
- Improved code organization with proper main_conf/loc_conf separation
- Updated GitHub Actions to latest versions
- Added plucky (Ubuntu 25.04) to build matrix

### Added
- Comprehensive documentation and wiki pages
- Scripts directory with development helpers
- OBS packaging infrastructure
- Proper `create_main_conf` and `init_main_conf` functions
- Memory leak fix for curl headers slist

### Fixed
- CONTRIBUTING.md now references correct module name
- Configuration directives now follow NGINX module best practices
- Timer event data now properly references main configuration

## [0.1.0] - 2024-10-06

### Added
- Initial release of nginx-cf-realip module
- Automatic fetching of Cloudflare IPv4 and IPv6 CIDR ranges
- Configurable refresh interval with 5-minute minimum
- Atomic file updates with SHA256 change detection
- Exponential backoff on fetch failures (up to 4x interval)
- HTTPS-only fetching with cloudflare.com host allowlist
- Security controls: `cf_realip_allow_insecure`, `cf_realip_allow_other_hosts`
- IPv6 toggle via `cf_realip_fetch_ipv6`
- Configurable output path via `cf_realip_output_path`
- ETag support for conditional fetching (partial implementation)
- CIDR validation with warning logs for invalid entries
- Test suite: backoff test, extended test, negative tests

### Directives
- `cf_realip_enabled` - Enable/disable module (on/off)
- `cf_realip_source_url` - IPv4 list URL
- `cf_realip_source_url_v6` - IPv6 list URL  
- `cf_realip_fetch_ipv6` - Enable IPv6 fetching (on/off)
- `cf_realip_refresh_interval` - Refresh cadence in seconds (min 300)
- `cf_realip_output_path` - Destination snippet file path
- `cf_realip_allow_insecure` - Allow HTTP URLs (on/off)
- `cf_realip_allow_other_hosts` - Allow non-Cloudflare hosts (on/off)

### Dependencies
- libcurl for HTTPS fetching
- OpenSSL for SHA256 hashing

[Unreleased]: https://github.com/RumenDamyanov/nginx-cf-realip/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/RumenDamyanov/nginx-cf-realip/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/RumenDamyanov/nginx-cf-realip/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/RumenDamyanov/nginx-cf-realip/releases/tag/v0.1.0

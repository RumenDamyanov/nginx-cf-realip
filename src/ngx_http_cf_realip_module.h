#ifndef _NGX_HTTP_CF_REALIP_MODULE_H_INCLUDED_
#define _NGX_HTTP_CF_REALIP_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_flag_t  enabled;
    ngx_str_t  source_url;
    ngx_str_t  source_url_v6;      // IPv6 list URL
    ngx_uint_t refresh_interval;
    time_t     last_update;
    ngx_flag_t update_pending;
    ngx_str_t  output_path;        // configurable output snippet path
    ngx_flag_t allow_insecure;     // allow http (default off)
    unsigned   prev_hash_valid:1;
    unsigned char prev_hash[32];   // SHA256 of last written file
    ngx_flag_t fetch_ipv6;         // fetch IPv6 list (default on)
    ngx_flag_t allow_other_hosts;  // permit non-cloudflare domains
    ngx_uint_t failure_count;      // consecutive failures for backoff
    ngx_str_t  etag_v4;            // last ETag for IPv4 list (only used when IPv6 disabled for now)
    ngx_str_t  etag_v6;            // placeholder for future IPv6 ETag support
} ngx_http_cf_realip_conf_t;

#define CF_REALIP_MODULE_VERSION "0.1.0"

// Exposed for potential future introspection (optional)
extern const char *ngx_http_cf_realip_version_string;


extern ngx_module_t ngx_http_cf_realip_module;

#endif /* _NGX_HTTP_CF_REALIP_MODULE_H_INCLUDED_ */

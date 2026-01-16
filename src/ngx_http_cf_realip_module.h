#ifndef _NGX_HTTP_CF_REALIP_MODULE_H_INCLUDED_
#define _NGX_HTTP_CF_REALIP_MODULE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_HTTP_SSL)
#include <ngx_event_openssl.h>
#endif

#define CF_REALIP_MODULE_VERSION "0.3.0"

/* Default values */
#define CF_REALIP_DEFAULT_URL_V4    "https://www.cloudflare.com/ips-v4"
#define CF_REALIP_DEFAULT_URL_V6    "https://www.cloudflare.com/ips-v6"
#define CF_REALIP_DEFAULT_REFRESH   86400000   /* 24 hours in ms */
#define CF_REALIP_DEFAULT_OUTPUT    "/etc/nginx/cloudflare-ips.conf"
#define CF_REALIP_MIN_REFRESH       300000     /* 5 minutes minimum in ms */
#define CF_REALIP_RESPONSE_SIZE     131072     /* 128KB max response */

/*
 * Main configuration - global settings for the module
 * These settings apply once per http{} block
 */
typedef struct {
    ngx_str_t           source_url;          /* IPv4 list URL */
    ngx_str_t           source_url_v6;       /* IPv6 list URL */
    ngx_msec_t          refresh_interval;    /* Refresh interval in ms */
    ngx_str_t           output_path;         /* Output file path */
    ngx_flag_t          allow_insecure;      /* Allow HTTP (default off) */
    ngx_flag_t          fetch_ipv6;          /* Fetch IPv6 list (default on) */
    ngx_flag_t          allow_other_hosts;   /* Permit non-Cloudflare domains */

    /* Runtime state */
    time_t              last_update;         /* Last update timestamp */
    ngx_uint_t          failure_count;       /* Consecutive failures for backoff */
    unsigned            prev_hash_valid:1;   /* Whether prev_hash is valid */
    unsigned char       prev_hash[32];       /* SHA256 of last written file */

    /* Event and resolver references */
    ngx_event_t         update_event;        /* Timer event for updates */
    ngx_log_t          *log;                 /* Log for events */
    ngx_resolver_t     *resolver;            /* DNS resolver reference */
    unsigned            initialized:1;       /* Whether module is initialized */
    unsigned            updating:1;          /* Whether update is in progress */

#if (NGX_HTTP_SSL)
    ngx_ssl_t          *ssl;                 /* SSL context for HTTPS */
#endif
} ngx_http_cf_realip_main_conf_t;

/*
 * Location configuration - per-location settings
 * These settings can vary per server{} or location{} block
 */
typedef struct {
    ngx_flag_t          enabled;             /* Enable/disable the module */
} ngx_http_cf_realip_loc_conf_t;

/*
 * Fetch context - holds state for async HTTP fetch operations
 */
typedef struct ngx_http_cf_realip_fetch_ctx_s ngx_http_cf_realip_fetch_ctx_t;

struct ngx_http_cf_realip_fetch_ctx_s {
    ngx_http_cf_realip_main_conf_t *mcf;
    ngx_pool_t                     *pool;
    ngx_peer_connection_t           peer;
    ngx_buf_t                      *request;
    ngx_buf_t                      *response;
    ngx_str_t                       host;
    ngx_str_t                       uri;
    in_port_t                       port;
    unsigned                        ssl:1;
    unsigned                        ssl_handshake_done:1;
    unsigned                        is_v6:1;         /* Whether fetching IPv6 list */
    unsigned                        v4_done:1;       /* IPv4 fetch completed */
    ngx_array_t                    *ips;             /* Collected IPs */
#if (NGX_HTTP_SSL)
    ngx_ssl_connection_t           *ssl_conn;
#endif
};

/* Exposed for potential future introspection */
extern const char *ngx_http_cf_realip_version_string;
extern ngx_module_t ngx_http_cf_realip_module;

#endif /* _NGX_HTTP_CF_REALIP_MODULE_H_INCLUDED_ */

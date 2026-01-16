/*
 * ngx_http_cf_realip_module.c
 * Cloudflare Real IP Auto-Updater for NGINX
 *
 * Automatically fetches Cloudflare IP ranges and generates set_real_ip_from
 * directives for use with ngx_http_realip_module.
 *
 * Uses native NGINX async I/O for HTTP fetching (no external dependencies).
 *
 * Copyright (c) 2024-2026 Rumen Damyanov
 * Licensed under BSD License
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_inet.h>

#include "ngx_http_cf_realip_module.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>

const char *ngx_http_cf_realip_version_string = CF_REALIP_MODULE_VERSION;

/* Global reference for process init */
static ngx_http_cf_realip_main_conf_t *ngx_http_cf_realip_main_conf = NULL;

/* Forward declarations */
static void *ngx_http_cf_realip_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_cf_realip_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_cf_realip_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_cf_realip_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_cf_realip_postconfig(ngx_conf_t *cf);
static ngx_int_t ngx_http_cf_realip_init_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_cf_realip_handler(ngx_http_request_t *r);
static char *ngx_http_cf_realip_set_output(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* Fetch handlers */
static void ngx_http_cf_realip_update_handler(ngx_event_t *ev);
static void ngx_http_cf_realip_resolve_handler(ngx_resolver_ctx_t *rctx);
static void ngx_http_cf_realip_connect_handler(ngx_event_t *wev);
static void ngx_http_cf_realip_write_handler(ngx_event_t *wev);
static void ngx_http_cf_realip_read_handler(ngx_event_t *rev);
static void ngx_http_cf_realip_send_request(ngx_http_cf_realip_fetch_ctx_t *ctx);
static void ngx_http_cf_realip_process_response(ngx_http_cf_realip_fetch_ctx_t *ctx);
static void ngx_http_cf_realip_close_connection(ngx_http_cf_realip_fetch_ctx_t *ctx);
static void ngx_http_cf_realip_schedule_retry(ngx_http_cf_realip_main_conf_t *mcf);
static ngx_int_t ngx_http_cf_realip_start_fetch(ngx_http_cf_realip_main_conf_t *mcf,
    ngx_str_t *url, ngx_flag_t is_v6, ngx_array_t *ips);
static ngx_int_t ngx_http_cf_realip_write_file(ngx_http_cf_realip_main_conf_t *mcf,
    ngx_array_t *ips);
static ngx_int_t ngx_http_cf_realip_parse_list(ngx_http_cf_realip_fetch_ctx_t *ctx,
    u_char *data, size_t len);

#if (NGX_HTTP_SSL)
static void ngx_http_cf_realip_ssl_handshake_handler(ngx_connection_t *c);
static ngx_int_t ngx_http_cf_realip_ssl_init(ngx_http_cf_realip_main_conf_t *mcf,
    ngx_conf_t *cf);
#endif

/* Custom setter for output path with validation */
static char *
ngx_http_cf_realip_set_output(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_cf_realip_main_conf_t *mcf = conf;
    ngx_str_t *value = cf->args->elts;

    (void) cmd;

    if (value[1].len == 0 || value[1].data[0] != '/') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "cf_realip_output_path must be an absolute path");
        return NGX_CONF_ERROR;
    }

    mcf->output_path = value[1];
    return NGX_CONF_OK;
}

/* Module directives */
static ngx_command_t ngx_http_cf_realip_commands[] = {

    /* Per-location directive - can be set in main/server/location */
    { ngx_string("cf_realip_enabled"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cf_realip_loc_conf_t, enabled),
      NULL },

    /* Main configuration directives - only in http{} block */
    { ngx_string("cf_realip_source_url"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_cf_realip_main_conf_t, source_url),
      NULL },

    { ngx_string("cf_realip_source_url_v6"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_cf_realip_main_conf_t, source_url_v6),
      NULL },

    { ngx_string("cf_realip_refresh_interval"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_cf_realip_main_conf_t, refresh_interval),
      NULL },

    { ngx_string("cf_realip_output_path"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_cf_realip_set_output,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("cf_realip_allow_insecure"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_cf_realip_main_conf_t, allow_insecure),
      NULL },

    { ngx_string("cf_realip_fetch_ipv6"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_cf_realip_main_conf_t, fetch_ipv6),
      NULL },

    { ngx_string("cf_realip_allow_other_hosts"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_cf_realip_main_conf_t, allow_other_hosts),
      NULL },

    ngx_null_command
};

/* Module context */
static ngx_http_module_t ngx_http_cf_realip_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_cf_realip_postconfig,          /* postconfiguration */
    ngx_http_cf_realip_create_main_conf,    /* create main configuration */
    ngx_http_cf_realip_init_main_conf,      /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_http_cf_realip_create_loc_conf,     /* create location configuration */
    ngx_http_cf_realip_merge_loc_conf       /* merge location configuration */
};

/* Module definition */
ngx_module_t ngx_http_cf_realip_module = {
    NGX_MODULE_V1,
    &ngx_http_cf_realip_module_ctx,     /* module context */
    ngx_http_cf_realip_commands,        /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    ngx_http_cf_realip_init_process,    /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};

/*
 * Create main configuration
 */
static void *
ngx_http_cf_realip_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_cf_realip_main_conf_t *mcf;

    mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cf_realip_main_conf_t));
    if (mcf == NULL) {
        return NULL;
    }

    /* Set unset markers for proper default handling */
    mcf->refresh_interval = NGX_CONF_UNSET_MSEC;
    mcf->allow_insecure = NGX_CONF_UNSET;
    mcf->fetch_ipv6 = NGX_CONF_UNSET;
    mcf->allow_other_hosts = NGX_CONF_UNSET;

    /* Runtime state initialization */
    mcf->last_update = 0;
    mcf->failure_count = 0;
    mcf->prev_hash_valid = 0;
    mcf->initialized = 0;
    mcf->updating = 0;
    mcf->log = cf->log;
    mcf->resolver = NULL;

#if (NGX_HTTP_SSL)
    mcf->ssl = NULL;
#endif

    return mcf;
}

/*
 * Initialize main configuration with defaults
 */
static char *
ngx_http_cf_realip_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_cf_realip_main_conf_t *mcf = conf;

    /* Set default URLs if not configured */
    if (mcf->source_url.len == 0) {
        ngx_str_set(&mcf->source_url, CF_REALIP_DEFAULT_URL_V4);
    }

    if (mcf->source_url_v6.len == 0) {
        ngx_str_set(&mcf->source_url_v6, CF_REALIP_DEFAULT_URL_V6);
    }

    if (mcf->output_path.len == 0) {
        ngx_str_set(&mcf->output_path, CF_REALIP_DEFAULT_OUTPUT);
    }

    /* Apply defaults for unset values */
    ngx_conf_init_msec_value(mcf->refresh_interval, CF_REALIP_DEFAULT_REFRESH);
    ngx_conf_init_value(mcf->allow_insecure, 0);
    ngx_conf_init_value(mcf->fetch_ipv6, 1);
    ngx_conf_init_value(mcf->allow_other_hosts, 0);

    /* Validate refresh interval */
    if (mcf->refresh_interval < CF_REALIP_MIN_REFRESH) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "cf_realip: refresh_interval too low (%M < %M); clamping",
            mcf->refresh_interval, (ngx_msec_t)CF_REALIP_MIN_REFRESH);
        mcf->refresh_interval = CF_REALIP_MIN_REFRESH;
    }

    /* Store global reference for process init */
    ngx_http_cf_realip_main_conf = mcf;

#if (NGX_HTTP_SSL)
    /* Initialize SSL context if URL is HTTPS */
    if (ngx_strncasecmp(mcf->source_url.data, (u_char *)"https://", 8) == 0) {
        if (ngx_http_cf_realip_ssl_init(mcf, cf) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }
#endif

    return NGX_CONF_OK;
}

#if (NGX_HTTP_SSL)
/*
 * Initialize SSL context for HTTPS fetching
 */
static ngx_int_t
ngx_http_cf_realip_ssl_init(ngx_http_cf_realip_main_conf_t *mcf, ngx_conf_t *cf)
{
    mcf->ssl = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
    if (mcf->ssl == NULL) {
        return NGX_ERROR;
    }

    mcf->ssl->log = cf->log;

    if (ngx_ssl_create(mcf->ssl,
                       NGX_SSL_SSLv2|NGX_SSL_SSLv3|NGX_SSL_TLSv1
                       |NGX_SSL_TLSv1_1|NGX_SSL_TLSv1_2|NGX_SSL_TLSv1_3,
                       NULL) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, cf->log, 0,
                  "cf_realip: SSL context initialized for HTTPS fetching");

    return NGX_OK;
}
#endif

/*
 * Create location configuration
 */
static void *
ngx_http_cf_realip_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_cf_realip_loc_conf_t *lcf;

    lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cf_realip_loc_conf_t));
    if (lcf == NULL) {
        return NULL;
    }

    lcf->enabled = NGX_CONF_UNSET;

    return lcf;
}

/*
 * Merge location configuration
 */
static char *
ngx_http_cf_realip_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_cf_realip_loc_conf_t *prev = parent;
    ngx_http_cf_realip_loc_conf_t *conf = child;

    (void)cf;  /* unused */

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);

    return NGX_CONF_OK;
}

/*
 * Post-configuration - register access phase handler and capture resolver
 */
static ngx_int_t
ngx_http_cf_realip_postconfig(ngx_conf_t *cf)
{
    ngx_http_handler_pt             *h;
    ngx_http_core_main_conf_t       *cmcf;
    ngx_http_core_loc_conf_t        *clcf;
    ngx_http_cf_realip_main_conf_t  *mcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_cf_realip_handler;

    /* Capture resolver reference from core loc conf */
    mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_cf_realip_module);
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    if (mcf != NULL && clcf != NULL && clcf->resolver != NULL) {
        mcf->resolver = clcf->resolver;
    }

    return NGX_OK;
}

/*
 * Access phase handler (module operates via background timer only)
 */
static ngx_int_t
ngx_http_cf_realip_handler(ngx_http_request_t *r)
{
    ngx_http_cf_realip_loc_conf_t *lcf;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_cf_realip_module);

    if (lcf == NULL || !lcf->enabled) {
        return NGX_DECLINED;
    }

    return NGX_DECLINED;
}

/*
 * Process initialization - start the update timer
 */
static ngx_int_t
ngx_http_cf_realip_init_process(ngx_cycle_t *cycle)
{
    ngx_http_cf_realip_main_conf_t *mcf;

    mcf = ngx_http_cf_realip_main_conf;
    if (mcf == NULL) {
        return NGX_OK;
    }

    mcf->log = cycle->log;

    /* Initialize the update event */
    ngx_memzero(&mcf->update_event, sizeof(ngx_event_t));
    mcf->update_event.handler = ngx_http_cf_realip_update_handler;
    mcf->update_event.data = mcf;
    mcf->update_event.log = cycle->log;

    /* Trigger initial update after 1 second */
    ngx_add_timer(&mcf->update_event, 1000);

    mcf->initialized = 1;

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "cf_realip: initialized (v%s), will fetch from \"%V\"",
                  CF_REALIP_MODULE_VERSION, &mcf->source_url);

    return NGX_OK;
}

/* ----------------------------------------------------------------
 * Native NGINX HTTP Fetching
 * ---------------------------------------------------------------- */

/*
 * Close connection and cleanup
 */
static void
ngx_http_cf_realip_close_connection(ngx_http_cf_realip_fetch_ctx_t *ctx)
{
    if (ctx->peer.connection) {
#if (NGX_HTTP_SSL)
        if (ctx->peer.connection->ssl) {
            ngx_ssl_shutdown(ctx->peer.connection);
        }
#endif
        ngx_close_connection(ctx->peer.connection);
    }

    ctx->mcf->updating = 0;
    ngx_destroy_pool(ctx->pool);
}

/*
 * Schedule retry after interval (with backoff)
 */
static void
ngx_http_cf_realip_schedule_retry(ngx_http_cf_realip_main_conf_t *mcf)
{
    ngx_msec_t interval = mcf->refresh_interval;

    if (mcf->failure_count > 0) {
        /* Exponential backoff up to 4x */
        ngx_msec_t backoff = mcf->refresh_interval * (mcf->failure_count + 1);
        if (backoff > mcf->refresh_interval * 4) {
            backoff = mcf->refresh_interval * 4;
        }
        interval = backoff;
    }

    ngx_log_error(NGX_LOG_NOTICE, mcf->log, 0,
                  "cf_realip: scheduling next fetch in %M ms (failures=%ui)",
                  interval, mcf->failure_count);

    ngx_add_timer(&mcf->update_event, interval);
}

/*
 * Parse IP list from HTTP response body
 */
static ngx_int_t
ngx_http_cf_realip_parse_list(ngx_http_cf_realip_fetch_ctx_t *ctx,
    u_char *data, size_t len)
{
    u_char     *p, *end, *line, *line_end;
    ngx_str_t   cidr_text;
    ngx_cidr_t  parsed;
    ngx_str_t  *elt;

    p = data;
    end = data + len;

    while (p < end) {
        line = p;

        /* Find end of line */
        while (p < end && *p != '\n' && *p != '\r') {
            p++;
        }
        line_end = p;

        /* Skip line endings */
        while (p < end && (*p == '\n' || *p == '\r')) {
            p++;
        }

        if (line_end <= line) {
            continue;
        }

        /* Trim whitespace */
        while (line < line_end && (*line == ' ' || *line == '\t')) {
            line++;
        }
        while (line_end > line && (line_end[-1] == ' ' || line_end[-1] == '\t')) {
            line_end--;
        }

        if (line_end <= line) {
            continue;
        }

        /* Skip comments */
        if (*line == '#') {
            continue;
        }

        cidr_text.data = line;
        cidr_text.len = line_end - line;

        /* Validate CIDR */
        if (ngx_ptocidr(&cidr_text, &parsed) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, ctx->mcf->log, 0,
                "cf_realip: invalid CIDR skipped (%*s)",
                (int)cidr_text.len, cidr_text.data);
            continue;
        }

        /* Add to array */
        elt = ngx_array_push(ctx->ips);
        if (elt == NULL) {
            continue;
        }

        elt->len = cidr_text.len;
        elt->data = ngx_pnalloc(ctx->pool, elt->len);
        if (elt->data == NULL) {
            elt->len = 0;
            continue;
        }
        ngx_memcpy(elt->data, cidr_text.data, elt->len);
    }

    return NGX_OK;
}

/*
 * Process the HTTP response
 */
static void
ngx_http_cf_realip_process_response(ngx_http_cf_realip_fetch_ctx_t *ctx)
{
    u_char     *p, *body;
    size_t      body_len;
    ngx_int_t   rc;

    /* Find body (after \r\n\r\n) */
    body = NULL;
    for (p = ctx->response->pos; p < ctx->response->last - 3; p++) {
        if (p[0] == '\r' && p[1] == '\n' && p[2] == '\r' && p[3] == '\n') {
            body = p + 4;
            break;
        }
    }

    if (body == NULL) {
        ngx_log_error(NGX_LOG_ERR, ctx->mcf->log, 0,
                      "cf_realip: invalid HTTP response (no body found)");
        ctx->mcf->failure_count++;
        ngx_http_cf_realip_close_connection(ctx);
        ngx_http_cf_realip_schedule_retry(ctx->mcf);
        return;
    }

    body_len = ctx->response->last - body;

    /* Check for HTTP 200 OK */
    if (ngx_strncmp(ctx->response->pos, "HTTP/1.1 200", 12) != 0 &&
        ngx_strncmp(ctx->response->pos, "HTTP/1.0 200", 12) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, ctx->mcf->log, 0,
                      "cf_realip: HTTP request failed (non-200 response)");
        ctx->mcf->failure_count++;
        ngx_http_cf_realip_close_connection(ctx);
        ngx_http_cf_realip_schedule_retry(ctx->mcf);
        return;
    }

    /* Parse the IP list */
    if (ngx_http_cf_realip_parse_list(ctx, body, body_len) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ctx->mcf->log, 0,
                      "cf_realip: failed to parse IP list");
        ctx->mcf->failure_count++;
        ngx_http_cf_realip_close_connection(ctx);
        ngx_http_cf_realip_schedule_retry(ctx->mcf);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, ctx->mcf->log, 0,
                  "cf_realip: fetched %s list (%ui entries)",
                  ctx->is_v6 ? "IPv6" : "IPv4", ctx->ips->nelts);

    ngx_http_cf_realip_close_connection(ctx);

    /* If this was IPv4 and we need IPv6, start that fetch */
    if (!ctx->is_v6 && ctx->mcf->fetch_ipv6 && ctx->mcf->source_url_v6.len > 0) {
        rc = ngx_http_cf_realip_start_fetch(ctx->mcf, &ctx->mcf->source_url_v6,
                                             1, ctx->ips);
        if (rc != NGX_OK) {
            /* Write what we have */
            ngx_http_cf_realip_write_file(ctx->mcf, ctx->ips);
            ngx_http_cf_realip_schedule_retry(ctx->mcf);
        }
        return;
    }

    /* Write the collected IPs to file */
    rc = ngx_http_cf_realip_write_file(ctx->mcf, ctx->ips);
    if (rc == NGX_OK) {
        ctx->mcf->failure_count = 0;
        ctx->mcf->last_update = ngx_time();
    } else {
        ctx->mcf->failure_count++;
    }

    ngx_http_cf_realip_schedule_retry(ctx->mcf);
}

/*
 * Read handler
 */
static void
ngx_http_cf_realip_read_handler(ngx_event_t *rev)
{
    ngx_http_cf_realip_fetch_ctx_t *ctx;
    ngx_connection_t               *c;
    ssize_t                         n;

    c = rev->data;
    ctx = c->data;

#if (NGX_HTTP_SSL)
    if (ctx->ssl && c->ssl) {
        n = ngx_ssl_recv(c, ctx->response->last,
                         ctx->response->end - ctx->response->last);
    } else {
        n = ngx_recv(c, ctx->response->last,
                     ctx->response->end - ctx->response->last);
    }
#else
    n = ngx_recv(c, ctx->response->last,
                 ctx->response->end - ctx->response->last);
#endif

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ctx->mcf->failure_count++;
            ngx_http_cf_realip_close_connection(ctx);
            ngx_http_cf_realip_schedule_retry(ctx->mcf);
        }
        return;
    }

    if (n == NGX_ERROR || n == 0) {
        /* Connection closed - process what we have */
        ngx_http_cf_realip_process_response(ctx);
        return;
    }

    ctx->response->last += n;

    if (ctx->response->last >= ctx->response->end) {
        ngx_http_cf_realip_process_response(ctx);
        return;
    }

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ctx->mcf->failure_count++;
        ngx_http_cf_realip_close_connection(ctx);
        ngx_http_cf_realip_schedule_retry(ctx->mcf);
    }
}

/*
 * Send HTTP request
 */
static void
ngx_http_cf_realip_send_request(ngx_http_cf_realip_fetch_ctx_t *ctx)
{
    ngx_connection_t *c;
    ssize_t           n;

    c = ctx->peer.connection;

#if (NGX_HTTP_SSL)
    if (ctx->ssl && c->ssl) {
        n = ngx_ssl_write(c, ctx->request->pos,
                          ctx->request->last - ctx->request->pos);
    } else {
        n = ngx_send(c, ctx->request->pos,
                     ctx->request->last - ctx->request->pos);
    }
#else
    n = ngx_send(c, ctx->request->pos,
                 ctx->request->last - ctx->request->pos);
#endif

    if (n == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, ctx->mcf->log, 0,
                      "cf_realip: failed to send HTTP request");
        ctx->mcf->failure_count++;
        ngx_http_cf_realip_close_connection(ctx);
        ngx_http_cf_realip_schedule_retry(ctx->mcf);
        return;
    }

    if (n == NGX_AGAIN) {
        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            ctx->mcf->failure_count++;
            ngx_http_cf_realip_close_connection(ctx);
            ngx_http_cf_realip_schedule_retry(ctx->mcf);
        }
        return;
    }

    ctx->request->pos += n;

    if (ctx->request->pos < ctx->request->last) {
        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            ctx->mcf->failure_count++;
            ngx_http_cf_realip_close_connection(ctx);
            ngx_http_cf_realip_schedule_retry(ctx->mcf);
        }
        return;
    }

    /* Request sent, wait for response */
    c->read->handler = ngx_http_cf_realip_read_handler;

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ctx->mcf->failure_count++;
        ngx_http_cf_realip_close_connection(ctx);
        ngx_http_cf_realip_schedule_retry(ctx->mcf);
    }
}

/*
 * Write handler
 */
static void
ngx_http_cf_realip_write_handler(ngx_event_t *wev)
{
    ngx_http_cf_realip_fetch_ctx_t *ctx;
    ngx_connection_t               *c;

    c = wev->data;
    ctx = c->data;

    ngx_http_cf_realip_send_request(ctx);
}

#if (NGX_HTTP_SSL)
/*
 * SSL handshake handler
 */
static void
ngx_http_cf_realip_ssl_handshake_handler(ngx_connection_t *c)
{
    ngx_http_cf_realip_fetch_ctx_t *ctx;

    ctx = c->data;

    if (c->ssl->handshaked) {
        ngx_log_error(NGX_LOG_INFO, ctx->mcf->log, 0,
                      "cf_realip: SSL handshake completed");

        ctx->ssl_handshake_done = 1;

        c->read->handler = ngx_http_cf_realip_read_handler;
        c->write->handler = ngx_http_cf_realip_write_handler;

        /* Send the HTTP request */
        ngx_http_cf_realip_send_request(ctx);
        return;
    }

    ngx_log_error(NGX_LOG_ERR, ctx->mcf->log, 0,
                  "cf_realip: SSL handshake failed");

    ctx->mcf->failure_count++;
    ngx_http_cf_realip_close_connection(ctx);
    ngx_http_cf_realip_schedule_retry(ctx->mcf);
}
#endif

/*
 * Connection established handler
 */
static void
ngx_http_cf_realip_connect_handler(ngx_event_t *wev)
{
    ngx_http_cf_realip_fetch_ctx_t *ctx;
    ngx_connection_t               *c;
    int                             err;
    socklen_t                       len;
#if (NGX_HTTP_SSL)
    ngx_int_t                       rc;
#endif

    c = wev->data;
    ctx = c->data;

    err = 0;
    len = sizeof(int);

    if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *)&err, &len) == -1) {
        err = ngx_socket_errno;
    }

    if (err) {
        ngx_log_error(NGX_LOG_ERR, ctx->mcf->log, err,
                      "cf_realip: connect() failed");
        ctx->mcf->failure_count++;
        ngx_http_cf_realip_close_connection(ctx);
        ngx_http_cf_realip_schedule_retry(ctx->mcf);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, ctx->mcf->log, 0,
                  "cf_realip: connected to %V:%d",
                  &ctx->host, ctx->port);

#if (NGX_HTTP_SSL)
    if (ctx->ssl && ctx->mcf->ssl) {
        /* Start SSL handshake */
        rc = ngx_ssl_create_connection(ctx->mcf->ssl, c,
                                       NGX_SSL_BUFFER|NGX_SSL_CLIENT);
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, ctx->mcf->log, 0,
                          "cf_realip: SSL connection creation failed");
            ctx->mcf->failure_count++;
            ngx_http_cf_realip_close_connection(ctx);
            ngx_http_cf_realip_schedule_retry(ctx->mcf);
            return;
        }

        /* Set SNI hostname */
        if (ngx_ssl_set_session(c, NULL) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, ctx->mcf->log, 0,
                          "cf_realip: failed to set SSL session");
        }

#ifdef SSL_set_tlsext_host_name
        SSL_set_tlsext_host_name(c->ssl->connection, (char *)ctx->host.data);
#endif

        c->sendfile = 0;

        rc = ngx_ssl_handshake(c);

        if (rc == NGX_AGAIN) {
            c->ssl->handler = ngx_http_cf_realip_ssl_handshake_handler;
            return;
        }

        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, ctx->mcf->log, 0,
                          "cf_realip: SSL handshake failed");
            ctx->mcf->failure_count++;
            ngx_http_cf_realip_close_connection(ctx);
            ngx_http_cf_realip_schedule_retry(ctx->mcf);
            return;
        }

        /* Handshake completed immediately */
        ctx->ssl_handshake_done = 1;
    }
#endif

    /* Send HTTP request */
    c->write->handler = ngx_http_cf_realip_write_handler;
    ngx_http_cf_realip_send_request(ctx);
}

/*
 * DNS resolve handler
 */
static void
ngx_http_cf_realip_resolve_handler(ngx_resolver_ctx_t *rctx)
{
    ngx_http_cf_realip_fetch_ctx_t *ctx;
    ngx_http_cf_realip_main_conf_t *mcf;
    ngx_connection_t               *c;
    ngx_int_t                       rc;
    struct sockaddr_in             *sin;
    u_char                         *p;
    u_char                          text[NGX_SOCKADDR_STRLEN];
    ngx_str_t                       addr_str;

    ctx = rctx->data;
    mcf = ctx->mcf;

    if (rctx->state) {
        ngx_log_error(NGX_LOG_ERR, mcf->log, 0,
                      "cf_realip: DNS resolve failed for \"%V\": %s",
                      &ctx->host, ngx_resolver_strerror(rctx->state));
        mcf->updating = 0;
        mcf->failure_count++;
        ngx_resolve_name_done(rctx);
        ngx_destroy_pool(ctx->pool);
        ngx_http_cf_realip_schedule_retry(mcf);
        return;
    }

    /* Log resolved address */
    addr_str.data = text;
    addr_str.len = ngx_sock_ntop(rctx->addrs[0].sockaddr, rctx->addrs[0].socklen,
                                  text, NGX_SOCKADDR_STRLEN, 0);

    ngx_log_error(NGX_LOG_INFO, mcf->log, 0,
                  "cf_realip: resolved %V to %V",
                  &ctx->host, &addr_str);

    /* Set up peer connection */
    ctx->peer.sockaddr = ngx_pcalloc(ctx->pool, rctx->addrs[0].socklen);
    if (ctx->peer.sockaddr == NULL) {
        mcf->updating = 0;
        mcf->failure_count++;
        ngx_resolve_name_done(rctx);
        ngx_destroy_pool(ctx->pool);
        ngx_http_cf_realip_schedule_retry(mcf);
        return;
    }

    ngx_memcpy(ctx->peer.sockaddr, rctx->addrs[0].sockaddr, rctx->addrs[0].socklen);

    /* Set the port */
    sin = (struct sockaddr_in *)ctx->peer.sockaddr;
    sin->sin_port = htons(ctx->port);

    ctx->peer.socklen = rctx->addrs[0].socklen;
    ctx->peer.name = &ctx->host;
    ctx->peer.get = ngx_event_get_peer;
    ctx->peer.log = mcf->log;
    ctx->peer.log_error = NGX_ERROR_ERR;

    ngx_resolve_name_done(rctx);

    /* Build HTTP request */
    ctx->request = ngx_create_temp_buf(ctx->pool, 1024);
    if (ctx->request == NULL) {
        mcf->updating = 0;
        mcf->failure_count++;
        ngx_destroy_pool(ctx->pool);
        ngx_http_cf_realip_schedule_retry(mcf);
        return;
    }

    p = ctx->request->last;
    p = ngx_sprintf(p, "GET %V HTTP/1.1\r\n", &ctx->uri);
    p = ngx_sprintf(p, "Host: %V\r\n", &ctx->host);
    p = ngx_sprintf(p, "User-Agent: nginx-cf-realip/%s\r\n", CF_REALIP_MODULE_VERSION);
    p = ngx_sprintf(p, "Accept: */*\r\n");
    p = ngx_sprintf(p, "Connection: close\r\n");
    p = ngx_sprintf(p, "\r\n");
    ctx->request->last = p;

    /* Allocate response buffer */
    ctx->response = ngx_create_temp_buf(ctx->pool, CF_REALIP_RESPONSE_SIZE);
    if (ctx->response == NULL) {
        mcf->updating = 0;
        mcf->failure_count++;
        ngx_destroy_pool(ctx->pool);
        ngx_http_cf_realip_schedule_retry(mcf);
        return;
    }

    /* Connect to server */
    rc = ngx_event_connect_peer(&ctx->peer);

    if (rc == NGX_ERROR || rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_ERR, mcf->log, 0,
                      "cf_realip: connect failed");
        mcf->updating = 0;
        mcf->failure_count++;
        ngx_destroy_pool(ctx->pool);
        ngx_http_cf_realip_schedule_retry(mcf);
        return;
    }

    c = ctx->peer.connection;
    c->data = ctx;
    c->read->handler = ngx_http_cf_realip_read_handler;
    c->write->handler = ngx_http_cf_realip_connect_handler;

    if (rc == NGX_OK) {
        ngx_http_cf_realip_connect_handler(c->write);
        return;
    }

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        mcf->updating = 0;
        mcf->failure_count++;
        ngx_close_connection(c);
        ngx_destroy_pool(ctx->pool);
        ngx_http_cf_realip_schedule_retry(mcf);
    }
}

/*
 * Validate URL scheme and host
 */
static ngx_int_t
ngx_http_cf_realip_validate_url(ngx_http_cf_realip_main_conf_t *mcf,
    ngx_str_t *url)
{
    u_char     *p, *host_start, *host_end, *colon;
    size_t      hlen, blen;
    const char *base = "cloudflare.com";

    if (url->len == 0) {
        return NGX_OK;
    }

    /* Check HTTPS requirement */
    if (!mcf->allow_insecure) {
        if (url->len < 8 || ngx_strncasecmp(url->data, (u_char *)"https://", 8) != 0) {
            ngx_log_error(NGX_LOG_ERR, mcf->log, 0,
                "cf_realip: insecure URL blocked (%V)", url);
            return NGX_ERROR;
        }
    }

    /* Check host restriction */
    if (!mcf->allow_other_hosts) {
        p = (u_char *)ngx_strstr(url->data, "://");
        if (p == NULL) {
            return NGX_ERROR;
        }

        p += 3;
        host_start = p;

        while (p < url->data + url->len && *p != '/' && *p != '?' && *p != '#') {
            p++;
        }
        host_end = p;

        /* Strip port */
        colon = host_start;
        while (colon < host_end && *colon != ':') {
            colon++;
        }
        if (colon < host_end) {
            host_end = colon;
        }

        hlen = host_end - host_start;
        blen = ngx_strlen(base);

        if (hlen == blen) {
            if (ngx_strncasecmp(host_start, (u_char *)base, blen) != 0) {
                ngx_log_error(NGX_LOG_ERR, mcf->log, 0,
                    "cf_realip: host not permitted (%V)", url);
                return NGX_ERROR;
            }
        } else if (hlen > blen) {
            if (ngx_strncasecmp(host_start + hlen - blen, (u_char *)base, blen) != 0
                || host_start[hlen - blen - 1] != '.')
            {
                ngx_log_error(NGX_LOG_ERR, mcf->log, 0,
                    "cf_realip: host not permitted (%V)", url);
                return NGX_ERROR;
            }
        } else {
            ngx_log_error(NGX_LOG_ERR, mcf->log, 0,
                "cf_realip: host not permitted (%V)", url);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/*
 * Start an HTTP fetch for a URL
 */
static ngx_int_t
ngx_http_cf_realip_start_fetch(ngx_http_cf_realip_main_conf_t *mcf,
    ngx_str_t *url, ngx_flag_t is_v6, ngx_array_t *ips)
{
    ngx_http_cf_realip_fetch_ctx_t *ctx;
    ngx_pool_t                     *pool;
    ngx_resolver_ctx_t             *rctx;
    u_char                         *p, *host_start;
    size_t                          len;

    if (ngx_http_cf_realip_validate_url(mcf, url) != NGX_OK) {
        return NGX_ERROR;
    }

    mcf->updating = 1;

    pool = ngx_create_pool(4096, mcf->log);
    if (pool == NULL) {
        mcf->updating = 0;
        return NGX_ERROR;
    }

    ctx = ngx_pcalloc(pool, sizeof(ngx_http_cf_realip_fetch_ctx_t));
    if (ctx == NULL) {
        mcf->updating = 0;
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    ctx->mcf = mcf;
    ctx->pool = pool;
    ctx->is_v6 = is_v6;

    /* Use provided IPs array or create new one */
    if (ips != NULL) {
        ctx->ips = ips;
    } else {
        ctx->ips = ngx_array_create(pool, 32, sizeof(ngx_str_t));
        if (ctx->ips == NULL) {
            mcf->updating = 0;
            ngx_destroy_pool(pool);
            return NGX_ERROR;
        }
    }

    /* Parse URL */
    p = url->data;
    len = url->len;

    if (ngx_strncasecmp(p, (u_char *)"https://", 8) == 0) {
        ctx->ssl = 1;
        ctx->port = 443;
        p += 8;
        len -= 8;
    } else if (ngx_strncasecmp(p, (u_char *)"http://", 7) == 0) {
        ctx->ssl = 0;
        ctx->port = 80;
        p += 7;
        len -= 7;
    } else {
        ngx_log_error(NGX_LOG_ERR, mcf->log, 0,
                      "cf_realip: invalid URL scheme in \"%V\"", url);
        mcf->updating = 0;
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

#if !(NGX_HTTP_SSL)
    if (ctx->ssl) {
        ngx_log_error(NGX_LOG_ERR, mcf->log, 0,
                      "cf_realip: HTTPS requires nginx with SSL support");
        mcf->updating = 0;
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }
#endif

    /* Extract host */
    host_start = p;
    while (len > 0 && *p != '/' && *p != ':') {
        p++;
        len--;
    }

    ctx->host.len = p - host_start;
    ctx->host.data = ngx_pnalloc(pool, ctx->host.len + 1);
    if (ctx->host.data == NULL) {
        mcf->updating = 0;
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }
    ngx_memcpy(ctx->host.data, host_start, ctx->host.len);
    ctx->host.data[ctx->host.len] = '\0';

    /* Extract URI */
    if (len > 0 && *p == '/') {
        ctx->uri.data = ngx_pnalloc(pool, len + 1);
        if (ctx->uri.data == NULL) {
            mcf->updating = 0;
            ngx_destroy_pool(pool);
            return NGX_ERROR;
        }
        ngx_memcpy(ctx->uri.data, p, len);
        ctx->uri.len = len;
        ctx->uri.data[len] = '\0';
    } else {
        ngx_str_set(&ctx->uri, "/");
    }

    if (ctx->host.len == 0) {
        ngx_log_error(NGX_LOG_ERR, mcf->log, 0,
                      "cf_realip: no host in URL \"%V\"", url);
        mcf->updating = 0;
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, mcf->log, 0,
                  "cf_realip: fetching %s list from \"%V\"",
                  is_v6 ? "IPv6" : "IPv4", url);

    /* Check if resolver is available */
    if (mcf->resolver == NULL) {
        ngx_log_error(NGX_LOG_ERR, mcf->log, 0,
                      "cf_realip: no resolver configured. "
                      "Add 'resolver 1.1.1.1;' or similar to http block");
        mcf->updating = 0;
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    rctx = ngx_resolve_start(mcf->resolver, NULL);
    if (rctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, mcf->log, 0,
                      "cf_realip: failed to start DNS resolve");
        mcf->updating = 0;
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    if (rctx == NGX_NO_RESOLVER) {
        ngx_log_error(NGX_LOG_ERR, mcf->log, 0,
                      "cf_realip: no resolver defined");
        mcf->updating = 0;
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    rctx->name = ctx->host;
    rctx->handler = ngx_http_cf_realip_resolve_handler;
    rctx->data = ctx;
    rctx->timeout = 10000;

    if (ngx_resolve_name(rctx) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, mcf->log, 0,
                      "cf_realip: failed to resolve \"%V\"",
                      &ctx->host);
        mcf->updating = 0;
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * Write IP list to config file (atomic)
 */
static ngx_int_t
ngx_http_cf_realip_write_file(ngx_http_cf_realip_main_conf_t *mcf,
    ngx_array_t *ips)
{
    u_char          tmp_path[NGX_MAX_PATH];
    u_char         *buf, *p;
    size_t          est, off;
    int             fd;
    ssize_t         wr;
    ngx_str_t      *ip;
    ngx_uint_t      i;
    unsigned char   hash[32];

    if (ips->nelts == 0) {
        ngx_log_error(NGX_LOG_WARN, mcf->log, 0,
                      "cf_realip: no IPs to write");
        return NGX_ERROR;
    }

    ngx_snprintf(tmp_path, NGX_MAX_PATH, "%V.tmp%Z", &mcf->output_path);

    fd = open((char *)tmp_path, O_CREAT|O_TRUNC|O_WRONLY, 0644);
    if (fd == -1) {
        ngx_log_error(NGX_LOG_ERR, mcf->log, ngx_errno,
                      "cf_realip: open temp failed %s", tmp_path);
        return NGX_ERROR;
    }

    /* Build content in memory */
    est = ips->nelts * 64;
    buf = ngx_alloc(est + 1, mcf->log);
    if (buf == NULL) {
        close(fd);
        unlink((char *)tmp_path);
        return NGX_ERROR;
    }

    ip = ips->elts;
    off = 0;

    for (i = 0; i < ips->nelts; i++) {
        if (ip[i].len == 0) {
            continue;
        }

        if (off + ip[i].len + 32 > est) {
            est *= 2;
            p = ngx_alloc(est + 1, mcf->log);
            if (p == NULL) {
                ngx_free(buf);
                close(fd);
                unlink((char *)tmp_path);
                return NGX_ERROR;
            }
            ngx_memcpy(p, buf, off);
            ngx_free(buf);
            buf = p;
        }

        off += ngx_sprintf(buf + off, "set_real_ip_from %V;\n", &ip[i]) - (buf + off);
    }
    buf[off] = '\0';

    /* Hash new content */
    SHA256(buf, off, hash);

    if (mcf->prev_hash_valid && ngx_memcmp(hash, mcf->prev_hash, 32) == 0) {
        ngx_free(buf);
        close(fd);
        unlink((char *)tmp_path);
        ngx_log_error(NGX_LOG_NOTICE, mcf->log, 0,
                      "cf_realip: IP list unchanged (%ui entries)", ips->nelts);
        return NGX_OK;
    }

    /* Write new content */
    wr = write(fd, buf, off);
    if (wr != (ssize_t)off) {
        ngx_log_error(NGX_LOG_ERR, mcf->log, ngx_errno,
                      "cf_realip: short write");
        ngx_free(buf);
        close(fd);
        unlink((char *)tmp_path);
        return NGX_ERROR;
    }

    fsync(fd);
    close(fd);

    if (rename((char *)tmp_path, (char *)mcf->output_path.data) != 0) {
        ngx_log_error(NGX_LOG_ERR, mcf->log, ngx_errno,
                      "cf_realip: rename to output failed");
        ngx_free(buf);
        unlink((char *)tmp_path);
        return NGX_ERROR;
    }

    ngx_memcpy(mcf->prev_hash, hash, 32);
    mcf->prev_hash_valid = 1;

    ngx_log_error(NGX_LOG_NOTICE, mcf->log, 0,
                  "cf_realip: updated %ui CIDRs (size=%uz) -> %V",
                  ips->nelts, off, &mcf->output_path);

    ngx_free(buf);
    return NGX_OK;
}

/*
 * Timer handler for periodic updates
 */
static void
ngx_http_cf_realip_update_handler(ngx_event_t *ev)
{
    ngx_http_cf_realip_main_conf_t *mcf;

    mcf = ev->data;

    if (mcf->updating) {
        ngx_log_error(NGX_LOG_WARN, mcf->log, 0,
                      "cf_realip: update already in progress, skipping");
        ngx_http_cf_realip_schedule_retry(mcf);
        return;
    }

    /* Start with IPv4 fetch */
    if (ngx_http_cf_realip_start_fetch(mcf, &mcf->source_url, 0, NULL) != NGX_OK) {
        mcf->failure_count++;
        ngx_http_cf_realip_schedule_retry(mcf);
    }
}

// ngx_http_cf_realip_module.c
// Cloudflare Real IP Auto-Updater for NGINX
// Production-hardening phase: implements periodic fetch of Cloudflare IP ranges
// Writes atomic snippet of set_real_ip_from directives consumed by ngx_http_realip_module
// Version: CF_REALIP_MODULE_VERSION

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <time.h>
#include <stdio.h>
#include "ngx_http_cf_realip_module.h"
#include <curl/curl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>

// Default values
#define CF_REALIP_DEFAULT_URL "https://www.cloudflare.com/ips-v4"
#define CF_REALIP_DEFAULT_REFRESH 86400
#define CF_REALIP_DEFAULT_OUTPUT "/etc/nginx/cloudflare-ips.conf"
#define CF_REALIP_MIN_REFRESH 300

const char *ngx_http_cf_realip_version_string = CF_REALIP_MODULE_VERSION;

typedef struct {
    ngx_event_t   timer;
    ngx_cycle_t  *cycle;
} ngx_http_cf_realip_global_t;

static ngx_http_cf_realip_global_t *cf_realip_global = NULL;
static ngx_uint_t cf_realip_curl_initialized = 0;

// Forward declarations
static ngx_int_t ngx_http_cf_realip_init_process(ngx_cycle_t *cycle);
static void ngx_http_cf_realip_exit_process(ngx_cycle_t *cycle);
static void ngx_http_cf_realip_timer_handler(ngx_event_t *ev);
static ngx_int_t ngx_http_cf_realip_fetch_and_write(ngx_cycle_t *cycle, ngx_http_cf_realip_conf_t *conf);

// Configuration directive handlers
static void *ngx_http_cf_realip_create_conf(ngx_conf_t *cf) {
    ngx_http_cf_realip_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cf_realip_conf_t));
    if (conf == NULL) return NULL;
    conf->enabled = NGX_CONF_UNSET;
    conf->refresh_interval = NGX_CONF_UNSET_UINT;
    conf->source_url.len = 0;
    conf->source_url.data = NULL;
    conf->source_url_v6.len = 0;
    conf->source_url_v6.data = NULL;
    conf->last_update = 0;
    conf->update_pending = 0;
    conf->output_path.len = 0;
    conf->output_path.data = NULL;
    conf->allow_insecure = NGX_CONF_UNSET;
    conf->fetch_ipv6 = NGX_CONF_UNSET;
    conf->allow_other_hosts = NGX_CONF_UNSET;
    conf->failure_count = 0;
    conf->etag_v4.len = 0; conf->etag_v4.data = NULL;
    conf->etag_v6.len = 0; conf->etag_v6.data = NULL;
    return conf;
}

static char *ngx_http_cf_realip_set_url_v6(ngx_conf_t *cf, ngx_command_t *cmd, void *conf_ptr) {
    ngx_http_cf_realip_conf_t *conf = conf_ptr;
    ngx_str_t *value = cf->args->elts;
    conf->source_url_v6 = value[1];
    return NGX_CONF_OK;
}

static char *ngx_http_cf_realip_merge_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_cf_realip_conf_t *prev = parent;
    ngx_http_cf_realip_conf_t *conf = child;
    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_str_value(conf->source_url, prev->source_url, CF_REALIP_DEFAULT_URL);
    ngx_conf_merge_str_value(conf->source_url_v6, prev->source_url_v6, (u_char*)"https://www.cloudflare.com/ips-v6");
    ngx_conf_merge_uint_value(conf->refresh_interval, prev->refresh_interval, CF_REALIP_DEFAULT_REFRESH);
    ngx_conf_merge_str_value(conf->output_path, prev->output_path, CF_REALIP_DEFAULT_OUTPUT);
    ngx_conf_merge_value(conf->allow_insecure, prev->allow_insecure, 0);
    ngx_conf_merge_value(conf->fetch_ipv6, prev->fetch_ipv6, 1);
    ngx_conf_merge_value(conf->allow_other_hosts, prev->allow_other_hosts, 0);
    if (conf->refresh_interval < CF_REALIP_MIN_REFRESH) {
        /* Allow a development/testing override via environment variable CF_REALIP_TEST_MIN_REFRESH (1-10) */
        char *ov = getenv("CF_REALIP_TEST_MIN_REFRESH");
        ngx_uint_t min_override = 0;
        if (ov) {
            long v = strtol(ov, NULL, 10);
            if (v >= 1 && v <= 10) {
                min_override = (ngx_uint_t)v;
            }
        }
        if (min_override && conf->refresh_interval >= min_override) {
            /* Use provided shorter minimum for tests (no clamp) */
        } else {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "cf_realip: refresh_interval too low (%ui < %d); clamping", conf->refresh_interval, CF_REALIP_MIN_REFRESH);
            conf->refresh_interval = CF_REALIP_MIN_REFRESH;
        }
    }
    return NGX_CONF_OK;
}

static char *ngx_http_cf_realip_set_output(ngx_conf_t *cf, ngx_command_t *cmd, void *conf_ptr) {
        ngx_http_cf_realip_conf_t *conf = conf_ptr;
        ngx_str_t *value = cf->args->elts;
        if (value[1].len == 0 || value[1].data[0] != '/') {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "cf_realip_output_path must be absolute");
                return (char*)NGX_CONF_ERROR;
        }
        conf->output_path = value[1];
        return NGX_CONF_OK;
}

static ngx_command_t ngx_http_cf_realip_commands[] = {
    { ngx_string("cf_realip_enabled"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cf_realip_conf_t, enabled),
      NULL },
    { ngx_string("cf_realip_source_url"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cf_realip_conf_t, source_url),
      NULL },
        { ngx_string("cf_realip_source_url_v6"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
            ngx_http_cf_realip_set_url_v6,
            NGX_HTTP_LOC_CONF_OFFSET,
            0,
            NULL },
    { ngx_string("cf_realip_refresh_interval"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_cf_realip_conf_t, refresh_interval),
      NULL },
        { ngx_string("cf_realip_output_path"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
            ngx_http_cf_realip_set_output,
            NGX_HTTP_LOC_CONF_OFFSET,
            0,
            NULL },
        { ngx_string("cf_realip_allow_insecure"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
            ngx_conf_set_flag_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_cf_realip_conf_t, allow_insecure),
            NULL },
            { ngx_string("cf_realip_fetch_ipv6"),
                NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
                ngx_conf_set_flag_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_cf_realip_conf_t, fetch_ipv6),
                NULL },
            { ngx_string("cf_realip_allow_other_hosts"),
                NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
                ngx_conf_set_flag_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_cf_realip_conf_t, allow_other_hosts),
                NULL },
    ngx_null_command
};

// Check for ngx_http_realip_module at config time
static ngx_int_t __attribute__((unused)) ngx_http_cf_realip_init(ngx_conf_t *cf) {
    ngx_uint_t i;
    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type == NGX_HTTP_MODULE && ngx_strcmp(ngx_modules[i]->name, "ngx_http_realip_module") == 0) {
            return NGX_OK;
        }
    }
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ngx_http_realip_module is required for nginx-cf-realip");
    return NGX_ERROR;
}

// Minimal postconfiguration to register access phase handler (early exit) and schedule timer init in process init
static ngx_int_t ngx_http_cf_realip_postconfig(ngx_conf_t *cf) {
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_cf_realip_handler;
    return NGX_OK;
}

// Minimal access phase handler (module operates via background timer only)
static ngx_int_t ngx_http_cf_realip_handler(ngx_http_request_t *r) {
    ngx_http_cf_realip_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_cf_realip_module);
    if (conf == NULL || !conf->enabled) return NGX_DECLINED;
    return NGX_DECLINED;
}

// Timer, subrequest, and config file update logic
// (Removed legacy runtime modification helper)

// Helper: write trusted proxies to config file for include
static ngx_int_t ngx_http_cf_realip_atomic_write(ngx_cycle_t *cycle, ngx_http_cf_realip_conf_t *conf, ngx_array_t *ips) {
    u_char tmp_path[NGX_MAX_PATH];
    ngx_snprintf(tmp_path, NGX_MAX_PATH, "%V.tmp%Z", &conf->output_path);
    size_t tmp_len = ngx_strlen(tmp_path);
    int fd = open((char*)tmp_path, O_CREAT|O_TRUNC|O_WRONLY, 0644);
    if (fd == -1) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno, "cf_realip: open temp failed %s", tmp_path);
        return NGX_ERROR;
    }
    // Build content in memory to compute hash
    ngx_str_t *ip = ips->elts;
    ngx_uint_t i;
    size_t est = ips->nelts * 64; // rough
    u_char *buf = ngx_pnalloc(cycle->pool, est + 1);
    if (!buf) { close(fd); return NGX_ERROR; }
    size_t off = 0;
    for (i=0;i<ips->nelts;i++) {
        if (ip[i].len == 0) continue;
        if (off + ip[i].len + 32 > est) { // realloc
            est *=2; u_char *nb = ngx_pnalloc(cycle->pool, est+1); if(!nb){close(fd);return NGX_ERROR;} ngx_memcpy(nb, buf, off); buf = nb; }
        off += ngx_sprintf(buf+off, "set_real_ip_from %V;\n", &ip[i]) - (buf+off);
    }
    buf[off] = '\0';
    // Hash new content
    unsigned char hash[32];
    SHA256(buf, off, hash);
    if (conf->prev_hash_valid && ngx_memcmp(hash, conf->prev_hash, 32) == 0) {
        close(fd);
        unlink((char*)tmp_path);
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "cf_realip: IP list unchanged (%ui entries)", ips->nelts);
        return NGX_OK;
    }
    // Write new content
    ssize_t wr = write(fd, buf, off);
    if (wr != (ssize_t)off) { close(fd); unlink((char*)tmp_path); ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno, "cf_realip: short write"); return NGX_ERROR; }
    fsync(fd);
    close(fd);
    if (rename((char*)tmp_path, (char*)conf->output_path.data) != 0) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno, "cf_realip: rename to output failed");
        return NGX_ERROR;
    }
    ngx_memcpy(conf->prev_hash, hash, 32);
    conf->prev_hash_valid = 1;
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "cf_realip: updated %ui CIDRs (size=%uz) -> %V", ips->nelts, off, &conf->output_path);
    return NGX_OK;
}

// (Removed legacy subrequest post handler)

// Timer, subrequest, and internal handler logic
// libcurl write callback accumulating into ngx dynamic array of u_char
typedef struct {
    ngx_pool_t *pool;
    u_char     *data;
    size_t      len;
    size_t      cap;
} cf_buf_t;

typedef struct {
    ngx_http_cf_realip_conf_t *conf;
    ngx_str_t                 *url;
    ngx_str_t                 *etag_slot; // where to store or read ETag
    ngx_pool_t                *pool;
    ngx_flag_t                 got_not_modified;
} cf_fetch_ctx_t;

static size_t cf_curl_write(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total = size * nmemb;
    cf_buf_t *b = userdata;
    if (b->len + total + 1 > b->cap) {
        size_t ncap = (b->cap ? b->cap * 2 : 8192);
        while (ncap < b->len + total + 1) ncap *= 2;
        u_char *n = ngx_pnalloc(b->pool, ncap);
        if (!n) return 0;
        if (b->data) ngx_memcpy(n, b->data, b->len);
        b->data = n;
        b->cap = ncap;
    }
    ngx_memcpy(b->data + b->len, ptr, total);
    b->len += total;
    b->data[b->len] = '\0';
    return total;
}

static size_t cf_curl_header(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total = size * nmemb;
    cf_fetch_ctx_t *ctx = userdata;
    // Simple ETag capture: case-insensitive match for 'ETag:'
    if (total > 6 && (ptr[0]=='E' || ptr[0]=='e') && (ptr[1]=='T' || ptr[1]=='t') && (ptr[2]=='a' || ptr[2]=='A') && (ptr[3]=='g' || ptr[3]=='G') && ptr[4]==':') {
        // Skip 'ETag:' and whitespace
        char *p = ptr + 5;
        while (p < ptr + total && (*p==' ' || *p=='\t')) p++;
        char *end = ptr + total;
        while (end>p && (end[-1]=='\r' || end[-1]=='\n')) end--;
        size_t len = end - p;
        if (len > 0) {
            ctx->etag_slot->data = ngx_pnalloc(ctx->pool, len);
            if (ctx->etag_slot->data) {
                ngx_memcpy(ctx->etag_slot->data, p, len);
                ctx->etag_slot->len = len;
            }
        }
    }
    return total;
}

static ngx_int_t cf_fetch_list(ngx_cycle_t *cycle, ngx_http_cf_realip_conf_t *conf, ngx_str_t *url, ngx_array_t *ips) {
    if (url->len == 0) return NGX_OK;
    if (!conf->allow_insecure) {
        if (url->len < 8 || ngx_strncasecmp(url->data, (u_char*)"https://", 8) != 0) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "cf_realip: insecure URL blocked (%V)", url);
            return NGX_ERROR;
        }
    }
    if (!conf->allow_other_hosts) {
        /* Stricter host validation:
         * Allow only exact or subdomain suffix of cloudflare.com when scheme is http/https.
         * Reject userinfo (@) and unexpected hosts.
         */
        if (url->len >= 7 && (ngx_strncasecmp(url->data, (u_char*)"http://", 7) == 0 || ngx_strncasecmp(url->data, (u_char*)"https://", 8) == 0)) {
            u_char *p = (u_char*)ngx_strstr(url->data, "://");
            if (p) {
                p += 3; // move past scheme
                u_char *host_start = p;
                u_char *end = url->data + url->len;
                /* host ends at first '/', '?', '#', or end */
                while (p < end && *p != '/' && *p != '?' && *p != '#') p++;
                u_char *host_end = p;
                /* Disallow userinfo (presence of '@') */
                u_char *at = host_start;
                while (at < host_end && *at != '@') at++;
                if (at < host_end && *at == '@') {
                    ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "cf_realip: userinfo not permitted in URL (%V)", url);
                    return NGX_ERROR;
                }
                /* Strip port if present */
                u_char *colon = host_start;
                while (colon < host_end && *colon != ':') colon++;
                u_char *effective_end = colon < host_end ? colon : host_end;
                size_t hlen = effective_end - host_start;
                const char *base = "cloudflare.com";
                size_t blen = ngx_strlen(base);
                ngx_flag_t ok = 0;
                if (hlen == blen) {
                    ok = (ngx_strncasecmp(host_start, (u_char*)base, blen) == 0);
                } else if (hlen > blen) {
                    /* must end with .cloudflare.com */
                    if (ngx_strncasecmp(host_start + hlen - blen, (u_char*)base, blen) == 0 && host_start[hlen - blen - 1] == '.') {
                        ok = 1;
                    }
                }
                if (!ok) {
                    ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "cf_realip: host not permitted (host=%*s url=%V)", (int)hlen, host_start, url);
                    return NGX_ERROR;
                }
            } else {
                ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "cf_realip: malformed URL (no scheme sep) (%V)", url);
                return NGX_ERROR;
            }
        } else if (url->len >= 7 && ngx_strncasecmp(url->data, (u_char*)"file://", 7) == 0) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "cf_realip: local file URL not permitted without cf_realip_allow_other_hosts (%V)", url);
            return NGX_ERROR;
        } else {
            /* Unknown scheme -> reject */
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "cf_realip: unsupported scheme (%V)", url);
            return NGX_ERROR;
        }
    }
    CURL *curl = curl_easy_init();
    if (!curl) { ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "cf_realip: curl init failed"); return NGX_ERROR; }
    cf_buf_t buf = { cycle->pool, NULL, 0, 0 };
    cf_fetch_ctx_t fctx; ngx_memzero(&fctx, sizeof(fctx));
    fctx.conf = conf; fctx.url = url; fctx.pool = cycle->pool; fctx.etag_slot = (url == &conf->source_url) ? &conf->etag_v4 : &conf->etag_v6;
    char c_url[1024];
    ngx_snprintf((u_char*)c_url, sizeof(c_url), "%V%Z", url);
    curl_easy_setopt(curl, CURLOPT_URL, c_url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ngx-cf-realip/" CF_REALIP_MODULE_VERSION);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 100L); // bytes/sec
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 5L);    // seconds
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cf_curl_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, cf_curl_header);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &fctx);
    // Conditional fetch with If-None-Match if we have prior ETag
    if (fctx.etag_slot->len) {
        // Build header list
        char cond[2048];
        size_t l = ngx_min(sizeof(cond)-1, (size_t)fctx.etag_slot->len + sizeof("If-None-Match: ") - 1);
        ngx_memcpy(cond, "If-None-Match: ", sizeof("If-None-Match: ") - 1);
        ngx_memcpy(cond + sizeof("If-None-Match: ") - 1, fctx.etag_slot->data, l - (sizeof("If-None-Match: ") - 1));
        cond[l] = '\0';
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, cond);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }
    CURLcode res = curl_easy_perform(curl);
    long code = 0; curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(curl);
    if (res == CURLE_OK && code == 304) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "cf_realip: not modified (ETag) %V", url);
        return NGX_OK; // unchanged
    }
    if (res != CURLE_OK || code != 200) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "cf_realip: fetch failed (%V) res=%d http=%ld", url, (int)res, code);
        return NGX_ERROR;
    }
    if (buf.len > 128*1024) { ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "cf_realip: list too large (%uz)", buf.len); return NGX_ERROR; }
    // Parse lines
    u_char *p = buf.data; u_char *end = buf.data + buf.len;
    while (p < end) {
        u_char *line = p;
        while (p < end && *p != '\n' && *p != '\r') p++;
        u_char *line_end = p;
        while (p < end && (*p == '\n' || *p == '\r')) p++;
        if (line_end <= line) continue;
        while (line < line_end && (*line==' '||*line=='\t')) line++;
        while (line_end > line && (line_end[-1]==' '||line_end[-1]=='\t')) line_end--;
        if (line_end <= line) continue;
        ngx_str_t cidr;
        cidr.len = line_end - line;
        cidr.data = line;
        ngx_cidr_t parsed;
        if (ngx_parse_addr_cidr(cycle->pool, &parsed, &cidr) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "cf_realip: invalid CIDR skipped (%*s)", (int)cidr.len, cidr.data);
            continue;
        }
        ngx_str_t *elt = ngx_array_push(ips); if (!elt) continue;
        elt->len = cidr.len;
        elt->data = ngx_pnalloc(cycle->pool, elt->len);
        if (!elt->data) { elt->len=0; continue; }
        ngx_memcpy(elt->data, cidr.data, elt->len);
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_cf_realip_fetch_and_write(ngx_cycle_t *cycle, ngx_http_cf_realip_conf_t *conf) {
    if (!conf->enabled) return NGX_OK;
    ngx_array_t *ips = ngx_array_create(cycle->pool, 64, sizeof(ngx_str_t));
    if (!ips) return NGX_ERROR;
    ngx_int_t rc4 = cf_fetch_list(cycle, conf, &conf->source_url, ips);
    ngx_int_t rc6 = NGX_OK;
    if (conf->fetch_ipv6) rc6 = cf_fetch_list(cycle, conf, &conf->source_url_v6, ips);
    if (rc4 != NGX_OK && (!conf->fetch_ipv6 || rc6 != NGX_OK)) {
        conf->failure_count++;
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "cf_realip: all fetch attempts failed (failure_count=%ui)", conf->failure_count);
        return NGX_ERROR;
    }
    ngx_int_t rc = ngx_http_cf_realip_atomic_write(cycle, conf, ips);
    if (rc == NGX_OK) { conf->last_update = ngx_time(); conf->failure_count = 0; }
    else { conf->failure_count++; }
    return rc;
}

static void ngx_http_cf_realip_timer_handler(ngx_event_t *ev) {
    ngx_cycle_t *cycle = (ngx_cycle_t*)ev->data;
    ngx_http_cf_realip_conf_t *conf = ngx_http_cycle_get_module_loc_conf(cycle, ngx_http_cf_realip_module);
    if (conf) {
        ngx_http_cf_realip_fetch_and_write(cycle, conf);
        ngx_uint_t interval = conf->refresh_interval;
        if (conf->failure_count) {
            ngx_uint_t backoff = conf->refresh_interval * (conf->failure_count + 1);
            if (backoff > conf->refresh_interval * 4) backoff = conf->refresh_interval * 4;
            interval = backoff;
        }
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "cf_realip: scheduling next fetch in %ui s (failure_count=%ui)", interval, conf->failure_count);
        ngx_add_timer(&cf_realip_global->timer, interval * 1000);
    }
}

// Module context and definition for NGINX
static ngx_http_module_t ngx_http_cf_realip_module_ctx = {
    NULL,                   // preconfiguration
    ngx_http_cf_realip_postconfig, // postconfiguration
    NULL,                   // create main conf
    NULL,                   // init main conf
    NULL,                   // create server conf
    NULL,                   // merge server conf
    ngx_http_cf_realip_create_conf, // create location conf
    ngx_http_cf_realip_merge_conf   // merge location conf
};

ngx_module_t ngx_http_cf_realip_module = {
    NGX_MODULE_V1,
    &ngx_http_cf_realip_module_ctx, // module context
    ngx_http_cf_realip_commands,    // module directives
    NGX_HTTP_MODULE,                // module type
    NULL,                           // init master
    NULL,                           // init module
    ngx_http_cf_realip_init_process,// init process
    NULL,                           // init thread
    NULL,                           // exit thread
    ngx_http_cf_realip_exit_process,// exit process
    NULL,                           // exit master
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_cf_realip_init_process(ngx_cycle_t *cycle) {
    if (cf_realip_global == NULL) {
        cf_realip_global = ngx_pcalloc(cycle->pool, sizeof(ngx_http_cf_realip_global_t));
        if (!cf_realip_global) return NGX_ERROR;
    }
    if (!cf_realip_curl_initialized) {
        if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "cf_realip: curl_global_init failed");
            return NGX_ERROR;
        }
        cf_realip_curl_initialized = 1;
    }
    cf_realip_global->cycle = cycle;
    ngx_memzero(&cf_realip_global->timer, sizeof(ngx_event_t));
    cf_realip_global->timer.handler = ngx_http_cf_realip_timer_handler;
    cf_realip_global->timer.data = cycle;
    cf_realip_global->timer.log = cycle->log;
    ngx_add_timer(&cf_realip_global->timer, 2000); // initial delay 2s
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "cf_realip: process init, scheduling first fetch");
    return NGX_OK;
}

static void ngx_http_cf_realip_exit_process(ngx_cycle_t *cycle) {
    if (cf_realip_global && cf_realip_global->timer.timer_set) {
        ngx_del_timer(&cf_realip_global->timer);
    }
    if (cf_realip_curl_initialized) {
        curl_global_cleanup();
        cf_realip_curl_initialized = 0;
    }
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "cf_realip: process exit");
}

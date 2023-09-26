/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 *
 * Based on the ngx_image_filter_module
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <gd.h>

#define NGX_HTTP_IMG_OFF       0
#define NGX_HTTP_IMG_TEST      1
#define NGX_HTTP_IMG_SIZE      2
#define NGX_HTTP_IMG_RESIZE    3
#define NGX_HTTP_IMG_CROP      4
#define NGX_HTTP_IMG_ROTATE    5


#define NGX_HTTP_IMG_START     0
#define NGX_HTTP_IMG_READ      1
#define NGX_HTTP_IMG_PROCESS   2
#define NGX_HTTP_IMG_PASS      3
#define NGX_HTTP_IMG_DONE      4


#define NGX_HTTP_IMG_NONE      0
#define NGX_HTTP_IMG_JPEG      1
#define NGX_HTTP_IMG_GIF       2
#define NGX_HTTP_IMG_PNG       3
#define NGX_HTTP_IMG_WEBP      4


#define NGX_HTTP_IMG_BUFFERED  0x08

#define NGX_HTTP_IMG_MIME_TYPE_IDX_JPEG   NGX_HTTP_IMG_JPEG - 1
#define NGX_HTTP_IMG_MIME_TYPE_IDX_GIF    NGX_HTTP_IMG_GIF - 1
#define NGX_HTTP_IMG_MIME_TYPE_IDX_PNG    NGX_HTTP_IMG_PNG - 1 
#define NGX_HTTP_IMG_MIME_TYPE_IDX_WEBP   NGX_HTTP_IMG_WEBP - 1

typedef struct {
    ngx_uint_t                   filter;
    ngx_uint_t                   width;
    ngx_uint_t                   height;
    ngx_uint_t                   angle;
    ngx_uint_t                   jpeg_quality;
    ngx_uint_t                   webp_quality;
    ngx_int_t                    png_quality;
    ngx_uint_t                   sharpen;

    ngx_flag_t                   transparency;
    ngx_flag_t                   interlace;

    ngx_http_complex_value_t    *wcv;
    ngx_http_complex_value_t    *hcv;
    ngx_http_complex_value_t    *acv;
    ngx_http_complex_value_t    *jqcv;
    ngx_http_complex_value_t    *wqcv;
    ngx_http_complex_value_t    *pqcv;
    ngx_http_complex_value_t    *shcv;

    size_t                       buffer_size;

    ngx_flag_t                   convert_webp;
    ngx_flag_t                   convert_allow_only_quality;
} ngx_http_img_filter_conf_t;


typedef struct {
    u_char                      *image;
    u_char                      *last;

    size_t                       length;

    ngx_uint_t                   width;
    ngx_uint_t                   height;
    ngx_uint_t                   max_width;
    ngx_uint_t                   max_height;
    ngx_uint_t                   angle;

    ngx_uint_t                   phase;
    ngx_uint_t                   type;
    ngx_uint_t                   force;
} ngx_http_img_filter_ctx_t;


static ngx_int_t ngx_http_img_send(ngx_http_request_t *r, ngx_http_img_filter_ctx_t *ctx, ngx_chain_t *in);
static ngx_uint_t ngx_http_img_test(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_img_read(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_buf_t *ngx_http_img_process(ngx_http_request_t *r);
static ngx_buf_t *ngx_http_img_json(ngx_http_request_t *r, ngx_http_img_filter_ctx_t *ctx);
static ngx_buf_t *ngx_http_img_asis(ngx_http_request_t *r, ngx_http_img_filter_ctx_t *ctx);
static void ngx_http_img_length(ngx_http_request_t *r, ngx_buf_t *b);
static ngx_int_t ngx_http_img_size(ngx_http_request_t *r, ngx_http_img_filter_ctx_t *ctx);

static ngx_buf_t *ngx_http_img_resize(ngx_http_request_t *r, ngx_http_img_filter_ctx_t *ctx);
static gdImagePtr ngx_http_img_source(ngx_http_request_t *r, ngx_http_img_filter_ctx_t *ctx);
static gdImagePtr ngx_http_img_new(ngx_http_request_t *r, int w, int h, int colors);
static u_char *ngx_http_img_out(ngx_http_request_t *r, ngx_uint_t type, gdImagePtr img, int *size);
static void ngx_http_img_cleanup(void *data);
static ngx_int_t ngx_http_img_filter_get_value(ngx_http_request_t *r, ngx_http_complex_value_t *cv, ngx_uint_t v);
static ngx_uint_t ngx_http_img_filter_value(ngx_str_t *value);

static void *ngx_http_img_filter_create_conf(ngx_conf_t *cf);
static char *ngx_http_img_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_img_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_img_filter_jpeg_quality(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_img_filter_webp_quality(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_img_filter_png_quality(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_img_filter_sharpen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_img_filter_init(ngx_conf_t *cf);

static ngx_command_t  ngx_http_img_filter_commands[] = {

    { ngx_string("img_filter"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_http_img_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("img_filter_jpeg_quality"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_img_filter_jpeg_quality,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("img_filter_webp_quality"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_img_filter_webp_quality,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("img_filter_png_quality"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_img_filter_png_quality,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("img_filter_sharpen"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_img_filter_sharpen,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("img_filter_transparency"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_img_filter_conf_t, transparency),
      NULL },

    { ngx_string("img_filter_interlace"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_img_filter_conf_t, interlace),
      NULL },

    { ngx_string("img_filter_buffer"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_img_filter_conf_t, buffer_size),
      NULL },

    { ngx_string("img_filter_convert_webp"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_img_filter_conf_t, convert_webp),
      NULL },

    { ngx_string("img_filter_convert_allow_only_quality"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_img_filter_conf_t, convert_allow_only_quality),
      NULL },


      ngx_null_command
};


static ngx_http_module_t  ngx_http_img_filter_module_ctx = {
    NULL,                                /* preconfiguration */
    ngx_http_img_filter_init,            /* postconfiguration */

    NULL,                                /* create main configuration */
    NULL,                                /* init main configuration */

    NULL,                                /* create server configuration */
    NULL,                                /* merge server configuration */

    ngx_http_img_filter_create_conf,     /* create location configuration */
    ngx_http_img_filter_merge_conf       /* merge location configuration */
};


ngx_module_t  ngx_http_img_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_img_filter_module_ctx,     /* module context */
    ngx_http_img_filter_commands,        /* module directives */
    NGX_HTTP_MODULE,                     /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static ngx_str_t  ngx_http_img_types[] = {
    ngx_string("image/jpeg"),
    ngx_string("image/gif"),
    ngx_string("image/png"),
    ngx_string("image/webp")
};


static ngx_int_t ngx_http_img_header_filter(ngx_http_request_t *r) {

    off_t                        len;
    ngx_http_img_filter_ctx_t   *ctx;
    ngx_http_img_filter_conf_t  *conf;

    if (r->headers_out.status == NGX_HTTP_NOT_MODIFIED || r->headers_out.content_length_n == 0) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_img_filter_module);

    if (ctx) {
        ngx_http_set_ctx(r, NULL, ngx_http_img_filter_module);
        return ngx_http_next_header_filter(r);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_img_filter_module);

    if (conf->filter == NGX_HTTP_IMG_OFF) {
        return ngx_http_next_header_filter(r);
    }

    if (r->headers_out.content_type.len >= sizeof("multipart/x-mixed-replace") - 1
        && ngx_strncasecmp(r->headers_out.content_type.data, (u_char *) "multipart/x-mixed-replace", sizeof("multipart/x-mixed-replace") - 1) == 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[=] img filter: multipart/x-mixed-replace response");

        return NGX_ERROR;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_img_filter_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_img_filter_module);

    len = r->headers_out.content_length_n;

    if (len != -1 && len > (off_t) conf->buffer_size) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[=] img filter: too big response: %O", len); 
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    if (len == -1) {
        ctx->length = conf->buffer_size;

    } else {
        ctx->length = (size_t) len;
    }

    if (r->headers_out.refresh) {
        r->headers_out.refresh->hash = 0;
    }

    r->main_filter_need_in_memory = 1;
    r->allow_ranges = 0;

    return NGX_OK;
}


static ngx_int_t ngx_http_img_body_filter(ngx_http_request_t *r, ngx_chain_t *in) {

    ngx_int_t                      rc;
    ngx_str_t                     *ct;
    ngx_chain_t                    out;
    ngx_http_img_filter_ctx_t   *ctx;
    ngx_http_img_filter_conf_t  *conf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[=] img filter - body");

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_img_filter_module);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    switch (ctx->phase) {

    case NGX_HTTP_IMG_START:

        ctx->type = ngx_http_img_test(r, in);

        conf = ngx_http_get_module_loc_conf(r, ngx_http_img_filter_module);

        if (ctx->type == NGX_HTTP_IMG_NONE) {

            if (conf->filter == NGX_HTTP_IMG_SIZE) {
                out.buf = ngx_http_img_json(r, NULL);

                if (out.buf) {
                    out.next = NULL;
                    ctx->phase = NGX_HTTP_IMG_DONE;

                    return ngx_http_img_send(r, ctx, &out);
                }
            }

            return ngx_http_filter_finalize_request(r, &ngx_http_img_filter_module, NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        /* override content type */

        if (conf->convert_webp == 1) {
            ct = &ngx_http_img_types[NGX_HTTP_IMG_MIME_TYPE_IDX_WEBP];
        } else {
            ct = &ngx_http_img_types[ctx->type - 1];
        }
        r->headers_out.content_type_len = ct->len;
        r->headers_out.content_type = *ct;
        r->headers_out.content_type_lowcase = NULL;

        if (conf->filter == NGX_HTTP_IMG_TEST) {
            ctx->phase = NGX_HTTP_IMG_PASS;

            return ngx_http_img_send(r, ctx, in);
        }

        ctx->phase = NGX_HTTP_IMG_READ;

        /* fall through */

    case NGX_HTTP_IMG_READ:

        rc = ngx_http_img_read(r, in);

        if (rc == NGX_AGAIN) {
            return NGX_OK;
        }

        if (rc == NGX_ERROR) {
            return ngx_http_filter_finalize_request(r, &ngx_http_img_filter_module, NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        /* fall through */

    case NGX_HTTP_IMG_PROCESS:

        out.buf = ngx_http_img_process(r);

        if (out.buf == NULL) {
            return ngx_http_filter_finalize_request(r, &ngx_http_img_filter_module, NGX_HTTP_UNSUPPORTED_MEDIA_TYPE);
        }

        out.next = NULL;
        ctx->phase = NGX_HTTP_IMG_PASS;

        return ngx_http_img_send(r, ctx, &out);

    case NGX_HTTP_IMG_PASS:

        return ngx_http_next_body_filter(r, in);

    default: /* NGX_HTTP_IMG_DONE */

        rc = ngx_http_next_body_filter(r, NULL);

        /* NGX_ERROR resets any pending data */
        return (rc == NGX_OK) ? NGX_ERROR : rc;
    }
}


static ngx_int_t ngx_http_img_send(ngx_http_request_t *r, ngx_http_img_filter_ctx_t *ctx, ngx_chain_t *in) {

    ngx_int_t  rc;

    rc = ngx_http_next_header_filter(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return NGX_ERROR;
    }

    rc = ngx_http_next_body_filter(r, in);

    if (ctx->phase == NGX_HTTP_IMG_DONE) {
        /* NGX_ERROR resets any pending data */
        return (rc == NGX_OK) ? NGX_ERROR : rc;
    }

    return rc;
}


static ngx_uint_t ngx_http_img_test(ngx_http_request_t *r, ngx_chain_t *in) {

    u_char  *p;

    p = in->buf->pos;

    if (in->buf->last - p < 16) {
        return NGX_HTTP_IMG_NONE;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[=] img filter: \"%c%c\"", p[0], p[1]);

    if (p[0] == 0xff && p[1] == 0xd8) {

        /* JPEG */
        return NGX_HTTP_IMG_JPEG;

    } else if (p[0] == 'G' && p[1] == 'I' && p[2] == 'F' && p[3] == '8' && p[5] == 'a') {

        if (p[4] == '9' || p[4] == '7') {

            /* GIF */
            return NGX_HTTP_IMG_GIF;
        }

    } else if (p[0] == 0x89 && p[1] == 'P' && p[2] == 'N' && p[3] == 'G' && p[4] == 0x0d && p[5] == 0x0a && p[6] == 0x1a && p[7] == 0x0a) {

        /* PNG */
        return NGX_HTTP_IMG_PNG;

    } else if (p[0] == 'R' && p[1] == 'I' && p[2] == 'F' && p[3] == 'F' && p[8] == 'W' && p[9] == 'E' && p[10] == 'B' && p[11] == 'P') {

        /* WebP */
        return NGX_HTTP_IMG_WEBP;
    }

    return NGX_HTTP_IMG_NONE;
}


static ngx_int_t ngx_http_img_read(ngx_http_request_t *r, ngx_chain_t *in) {

    u_char                       *p;
    size_t                        size, rest;
    ngx_buf_t                    *b;
    ngx_chain_t                  *cl;
    ngx_http_img_filter_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_img_filter_module);
    if (ctx->image == NULL) {
        ctx->image = ngx_palloc(r->pool, ctx->length);
        if (ctx->image == NULL) {
            return NGX_ERROR;
        }

        ctx->last = ctx->image;
    }

    p = ctx->last;

    for (cl = in; cl; cl = cl->next) {

        b = cl->buf;
        size = b->last - b->pos;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[=] image buf: %uz", size);

        rest = ctx->image + ctx->length - p;

        if (size > rest) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[=] img filter: too big response");
            return NGX_ERROR;
        }

        p = ngx_cpymem(p, b->pos, size);
        b->pos += size;

        if (b->last_buf) {
            ctx->last = p;
            return NGX_OK;
        }
    }

    ctx->last = p;
    r->connection->buffered |= NGX_HTTP_IMG_BUFFERED;

    return NGX_AGAIN;
}


static ngx_buf_t *ngx_http_img_process(ngx_http_request_t *r) {

    ngx_int_t                      rc;
    ngx_http_img_filter_ctx_t   *ctx;
    ngx_http_img_filter_conf_t  *conf;

    r->connection->buffered &= ~NGX_HTTP_IMG_BUFFERED;

    ctx = ngx_http_get_module_ctx(r, ngx_http_img_filter_module);

    rc = ngx_http_img_size(r, ctx);

    conf = ngx_http_get_module_loc_conf(r, ngx_http_img_filter_module);

    if (conf->filter == NGX_HTTP_IMG_SIZE) {
        return ngx_http_img_json(r, rc == NGX_OK ? ctx : NULL);
    }

    ctx->angle = ngx_http_img_filter_get_value(r, conf->acv, conf->angle);

    if (conf->filter == NGX_HTTP_IMG_ROTATE) {

        if (ctx->angle != 90 && ctx->angle != 180 && ctx->angle != 270) {
            return NULL;
        }

        return ngx_http_img_resize(r, ctx);
    }


   ctx->max_width = ngx_http_img_filter_get_value(r, conf->wcv, conf->width);
    if (ctx->max_width == 0) {
        return NULL;
    }

    ctx->max_height = ngx_http_img_filter_get_value(r, conf->hcv, conf->height);
    if (ctx->max_height == 0) {
        return NULL;
    }

    //obtain source image x/y
    gdImagePtr src = ngx_http_img_source(r, ctx);
    if (src == NULL) {
        return NULL;
    }


    if (ctx->max_width == NGX_CONF_UNSET_UINT) { //same as : -
        ctx->max_width = gdImageSX(src);
    }

    if (ctx->max_height == NGX_CONF_UNSET_UINT) { //same as : -
        ctx->max_height = gdImageSY(src);
    }

    //destory
    gdImageDestroy(src);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[*] ctx->max_width  : %d / ctx->width : %d", ctx->max_width, ctx->width);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[*] ctx->max_height : %d / ctx->height : %d", ctx->max_height, ctx->height);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[*] ctx->angle : %d", ctx->angle);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[*] ctx->force : %d", ctx->force);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[*] conf->png_quality : %d", conf->png_quality);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[*] conf->convert_webp : %d", conf->convert_webp);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[*] conf->convert_allow_only_quality : %d", conf->convert_allow_only_quality);


    if (rc == NGX_OK
        && ctx->width <= ctx->max_width
        && ctx->height <= ctx->max_height
        && ctx->angle == 0
        && !ctx->force
        && conf->convert_allow_only_quality == 0)
    {

        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[*] asis image");
        return ngx_http_img_asis(r, ctx);
    }

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[*] resizing");

    return ngx_http_img_resize(r, ctx);
}


static ngx_buf_t *ngx_http_img_json(ngx_http_request_t *r, ngx_http_img_filter_ctx_t *ctx) {

    size_t                          len;
    ngx_buf_t                       *b;
    int                             typeidx = ctx->type - 1;
    ngx_http_img_filter_conf_t    *conf;

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NULL;
    }

    b->memory = 1;
    b->last_buf = 1;

    ngx_http_clean_header(r);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_type_len = sizeof("application/json") - 1;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_type_lowcase = NULL;

    if (ctx == NULL) {
        b->pos = (u_char *) "{}" CRLF;
        b->last = b->pos + sizeof("{}" CRLF) - 1;

        ngx_http_img_length(r, b);

        return b;
    }

    len = sizeof("{ \"img\" : "
                 "{ \"width\": , \"height\": , \"type\": \"jpeg\" } }" CRLF) - 1 + 2 * NGX_SIZE_T_LEN;

    b->pos = ngx_pnalloc(r->pool, len);
    if (b->pos == NULL) {
        return NULL;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_img_filter_module);
    if (conf->convert_webp == 1) {
        typeidx = NGX_HTTP_IMG_MIME_TYPE_IDX_PNG;
    }

    b->last = ngx_sprintf(b->pos,
                          "{ \"img\" : "
                                       "{ \"width\": %uz,"
                                        " \"height\": %uz,"
                                        " \"type\": \"%s\" } }" CRLF,
                          ctx->width, ctx->height,
                          ngx_http_img_types[typeidx].data + 6);

    ngx_http_img_length(r, b);

    return b;
}


static ngx_buf_t *ngx_http_img_asis(ngx_http_request_t *r, ngx_http_img_filter_ctx_t *ctx) {

    ngx_buf_t  *b;

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NULL;
    }

    b->pos = ctx->image;
    b->last = ctx->last;
    b->memory = 1;
    b->last_buf = 1;

    ngx_http_img_length(r, b);

    return b;
}


static void ngx_http_img_length(ngx_http_request_t *r, ngx_buf_t *b) {

    r->headers_out.content_length_n = b->last - b->pos;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
    }

    r->headers_out.content_length = NULL;
}


static ngx_int_t ngx_http_img_size(ngx_http_request_t *r, ngx_http_img_filter_ctx_t *ctx) {

    u_char      *p, *last;
    size_t       len, app;
    ngx_uint_t   width, height;

    p = ctx->image;

    switch (ctx->type) {

    case NGX_HTTP_IMG_JPEG:

        p += 2;
        last = ctx->image + ctx->length - 10;
        width = 0;
        height = 0;
        app = 0;

        while (p < last) {

            if (p[0] == 0xff && p[1] != 0xff) {

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[=] JPEG: %02xd %02xd", p[0], p[1]);

                p++;

                if ((*p == 0xc0 || *p == 0xc1 || *p == 0xc2 || *p == 0xc3 || *p == 0xc9 || *p == 0xca || *p == 0xcb) && (width == 0 || height == 0)) {
                    width = p[6] * 256 + p[7];
                    height = p[4] * 256 + p[5];
                }

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[=] JPEG: %02xd %02xd", p[1], p[2]);

                len = p[1] * 256 + p[2];

                if (*p >= 0xe1 && *p <= 0xef) {
                    /* application data, e.g., EXIF, Adobe XMP, etc. */
                    app += len;
                }

                p += len;

                continue;
            }

            p++;
        }

        if (width == 0 || height == 0) {
            return NGX_DECLINED;
        }

        if (ctx->length / 20 < app) {
            /* force conversion if application data consume more than 5% */
            ctx->force = 1;
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[=] app data size: %uz", app);
        }

        break;

    case NGX_HTTP_IMG_GIF:

        if (ctx->length < 10) {
            return NGX_DECLINED;
        }

        width = p[7] * 256 + p[6];
        height = p[9] * 256 + p[8];

        break;

    case NGX_HTTP_IMG_PNG:

        if (ctx->length < 24) {
            return NGX_DECLINED;
        }

        width = p[18] * 256 + p[19];
        height = p[22] * 256 + p[23];

        break;

    case NGX_HTTP_IMG_WEBP:

        if (ctx->length < 30) {
            return NGX_DECLINED;
        }

        if (p[12] != 'V' || p[13] != 'P' || p[14] != '8') {
            return NGX_DECLINED;
        }

        switch (p[15]) {

        case ' ':
            if (p[20] & 1) {
                /* not a key frame */
                return NGX_DECLINED;
            }

            if (p[23] != 0x9d || p[24] != 0x01 || p[25] != 0x2a) {
                /* invalid start code */
                return NGX_DECLINED;
            }

            width = (p[26] | p[27] << 8) & 0x3fff;
            height = (p[28] | p[29] << 8) & 0x3fff;

            break;

        case 'L':
            if (p[20] != 0x2f) {
                /* invalid signature */
                return NGX_DECLINED;
            }

            width = ((p[21] | p[22] << 8) & 0x3fff) + 1;
            height = ((p[22] >> 6 | p[23] << 2 | p[24] << 10) & 0x3fff) + 1;

            break;

        case 'X':
            width = (p[24] | p[25] << 8 | p[26] << 16) + 1;
            height = (p[27] | p[28] << 8 | p[29] << 16) + 1;
            break;

        default:
            return NGX_DECLINED;
        }

        break;

    default:

        return NGX_DECLINED;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[=] image size: %d x %d", (int) width, (int) height);

    ctx->width = width;
    ctx->height = height;

    return NGX_OK;
}


static ngx_buf_t *ngx_http_img_resize(ngx_http_request_t *r, ngx_http_img_filter_ctx_t *ctx) {
    int                            sx, sy, dx, dy, ox, oy, ax, ay, size,
                                   colors, palette, transparent, sharpen,
                                   t;
    u_char                        *out;
    ngx_buf_t                     *b;
    ngx_uint_t                     resize;
    gdImagePtr                     src, dst;
    ngx_pool_cleanup_t            *cln;
    ngx_http_img_filter_conf_t  *conf;

    src = ngx_http_img_source(r, ctx);

    if (src == NULL) {
        return NULL;
    }

    sx = gdImageSX(src);
    sy = gdImageSY(src);

    conf = ngx_http_get_module_loc_conf(r, ngx_http_img_filter_module);

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[+] gd version : %s / extra version : %s", gdVersionString(), gdExtraVersion());
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[+] ctx->force : %d", ctx->force);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[+] ctx->force : %d", ctx->angle);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[+] sx :%d", sx);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[+] sy :%d", sy);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[+] ctx->max_width : %d", ctx->max_width);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[+] ctx->max_height : %d", ctx->max_height);

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[+] conf->convert_webp : %d", conf->convert_webp);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[+] conf->convert_allow_only_quality : %d", conf->convert_allow_only_quality);

    if (!ctx->force
        && ctx->angle == 0
        && (ngx_uint_t) sx <= ctx->max_width
        && (ngx_uint_t) sy <= ctx->max_height
        && conf->convert_allow_only_quality == 0)
    {

        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[+] asis");
        gdImageDestroy(src);
        return ngx_http_img_asis(r, ctx);
    }

    colors = gdImageColorsTotal(src);

    if (colors && conf->transparency) {
        transparent = gdImageGetTransparent(src);

        if (transparent != -1) {
            palette = colors;
            goto transparent;
        }
    }

    palette = 0;
    transparent = -1;

transparent:

    gdImageColorTransparent(src, -1);

    dx = sx;
    dy = sy;

    if (conf->filter == NGX_HTTP_IMG_RESIZE) {

        if ((ngx_uint_t) dx > ctx->max_width) {
            dy = dy * ctx->max_width / dx;
            dy = dy ? dy : 1;
            dx = ctx->max_width;
        }

        if ((ngx_uint_t) dy > ctx->max_height) {
            dx = dx * ctx->max_height / dy;
            dx = dx ? dx : 1;
            dy = ctx->max_height;
        }

        resize = 1;

    } else if (conf->filter == NGX_HTTP_IMG_ROTATE) {

        resize = 0;

    } else { /* NGX_HTTP_IMG_CROP */

        resize = 0;

        if ((double) dx / dy < (double) ctx->max_width / ctx->max_height) {
            if ((ngx_uint_t) dx > ctx->max_width) {
                dy = dy * ctx->max_width / dx;
                dy = dy ? dy : 1;
                dx = ctx->max_width;
                resize = 1;
            }

        } else {
            if ((ngx_uint_t) dy > ctx->max_height) {
                dx = dx * ctx->max_height / dy;
                dx = dx ? dx : 1;
                dy = ctx->max_height;
                resize = 1;
            }
        }
    }

    if (resize) {
        dst = ngx_http_img_new(r, dx, dy, palette);
        if (dst == NULL) {
            gdImageDestroy(src);
            return NULL;
        }

        if (colors == 0) {
            gdImageSaveAlpha(dst, 1);
            gdImageAlphaBlending(dst, 0);
        }

        if (transparent != -1) {
            gdImageAlphaBlending(dst, 0);
            gdImageSaveAlpha(dst, 1);
            gdImageFill(dst, 0,0, gdImageColorAllocateAlpha(dst, 255, 255, 255, 127));
            gdImageColorTransparent(dst, gdImageColorExactAlpha(dst, 255, 255, 255, 127));
        }

        gdImageCopyResampled(dst, src, 0, 0, 0, 0, dx, dy, sx, sy);

        if (colors) {
            gdImageTrueColorToPalette(dst, 1, 256);
        }

        gdImageDestroy(src);

    } else {
        dst = src;
    }

    if (ctx->angle) {
        src = dst;

        ax = (dx % 2 == 0) ? 1 : 0;
        ay = (dy % 2 == 0) ? 1 : 0;

        switch (ctx->angle) {

        case 90:
        case 270:
            dst = ngx_http_img_new(r, dy, dx, palette);
            if (dst == NULL) {
                gdImageDestroy(src);
                return NULL;
            }
            if (ctx->angle == 90) {
                ox = dy / 2 + ay;
                oy = dx / 2 - ax;

            } else {
                ox = dy / 2 - ay;
                oy = dx / 2 + ax;
            }

            gdImageCopyRotated(dst, src, ox, oy, 0, 0,
                               dx + ax, dy + ay, ctx->angle);
            gdImageDestroy(src);

            t = dx;
            dx = dy;
            dy = t;
            break;

        case 180:
            dst = ngx_http_img_new(r, dx, dy, palette);
            if (dst == NULL) {
                gdImageDestroy(src);
                return NULL;
            }
            gdImageCopyRotated(dst, src, dx / 2 - ax, dy / 2 - ay, 0, 0,
                               dx + ax, dy + ay, ctx->angle);
            gdImageDestroy(src);
            break;
        }
    }

    if (conf->filter == NGX_HTTP_IMG_CROP) {

        src = dst;

        if ((ngx_uint_t) dx > ctx->max_width) {
            ox = dx - ctx->max_width;

        } else {
            ox = 0;
        }

        if ((ngx_uint_t) dy > ctx->max_height) {
            oy = dy - ctx->max_height;

        } else {
            oy = 0;
        }

        if (ox || oy) {

            dst = ngx_http_img_new(r, dx - ox, dy - oy, colors);

            if (dst == NULL) {
                gdImageDestroy(src);
                return NULL;
            }

            ox /= 2;
            oy /= 2;

            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[=] image crop: %d x %d @ %d x %d", dx, dy, ox, oy);

            if (colors == 0) {
                gdImageSaveAlpha(dst, 1);
                gdImageAlphaBlending(dst, 0);
            }

            gdImageCopy(dst, src, 0, 0, ox, oy, dx - ox, dy - oy);

            if (colors) {
                gdImageTrueColorToPalette(dst, 1, 256);
            }

            gdImageDestroy(src);
        }
    }

    sharpen = ngx_http_img_filter_get_value(r, conf->shcv, conf->sharpen);
    if (sharpen > 0) {
        gdImageSharpen(dst, sharpen);
    }

    gdImageInterlace(dst, (int) conf->interlace);

    out = ngx_http_img_out(r, ctx->type, dst, &size);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[=] image: %d x %d %d", sx, sy, colors);

    gdImageDestroy(dst);
    ngx_pfree(r->pool, ctx->image);

    if (out == NULL) {
        return NULL;
    }

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        gdFree(out);
        return NULL;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        gdFree(out);
        return NULL;
    }

    cln->handler = ngx_http_img_cleanup;
    cln->data = out;

    b->pos = out;
    b->last = out + size;
    b->memory = 1;
    b->last_buf = 1;

    ngx_http_img_length(r, b);
    ngx_http_weak_etag(r);

    return b;
}


static gdImagePtr ngx_http_img_source(ngx_http_request_t *r, ngx_http_img_filter_ctx_t *ctx) {

    char        *failed;
    gdImagePtr   img;

    img = NULL;

    switch (ctx->type) {

    case NGX_HTTP_IMG_JPEG:
        img = gdImageCreateFromJpegPtr(ctx->length, ctx->image);
        failed = "[=] gdImageCreateFromJpegPtr() failed";
        break;

    case NGX_HTTP_IMG_GIF:
        img = gdImageCreateFromGifPtr(ctx->length, ctx->image);
        failed = "[=] gdImageCreateFromGifPtr() failed";
        break;

    case NGX_HTTP_IMG_PNG:
        img = gdImageCreateFromPngPtr(ctx->length, ctx->image);
        failed = "[=] gdImageCreateFromPngPtr() failed";
        break;

    case NGX_HTTP_IMG_WEBP:
#if (NGX_HAVE_GD_WEBP)
        img = gdImageCreateFromWebpPtr(ctx->length, ctx->image);
        failed = "[=] gdImageCreateFromWebpPtr() failed";
#else
        failed = "[=] nginx was built without GD WebP support";
#endif
        break;

    default:
        failed = "[=] unknown image type";
        break;
    }

    if (img == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, failed);
    }

    return img;
}


static gdImagePtr ngx_http_img_new(ngx_http_request_t *r, int w, int h, int colors) {

    gdImagePtr  img;

    if (colors == 0) {
        img = gdImageCreateTrueColor(w, h);

        if (img == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[=] gdImageCreateTrueColor() failed");
            return NULL;
        }

    } else {
        img = gdImageCreate(w, h);

        if (img == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "[=] gdImageCreate() failed");
            return NULL;
        }
    }

    return img;
}


static u_char *ngx_http_img_webp_out(ngx_http_request_t *r, ngx_uint_t type, gdImagePtr img, int *size) {

    char                          *failed;
    u_char                        *out = NULL;
#if (NGX_HAVE_GD_WEBP)
    ngx_int_t                     q,retval;
    ngx_http_img_filter_conf_t    *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_img_filter_module);
    q = ngx_http_img_filter_get_value(r, conf->wqcv, conf->webp_quality);
    if (q <= 0) {
        return NULL;
    }

    retval = gdImagePaletteToTrueColor(img);
    failed = "[=] gdImagePaletteToTrueColor() failed from PNG";
    if (retval == 0) {
        return NULL;
    }

    out = gdImageWebpPtrEx(img, size, q);
    failed = "[=] gdImageWebpPtrEx() failed from PNG";

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,  "[=] [png to webp] webp size : %d / quality : %d", size, q);
#else
    failed = "[=] nginx was built without GD WebP support";
#endif

    if (out == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, failed);
    }

    return out;
}

static u_char *ngx_http_img_out(ngx_http_request_t *r, ngx_uint_t type, gdImagePtr img, int *size) {

    char                            *failed;
    u_char                          *out;
    ngx_int_t                       q = 0;
    ngx_http_img_filter_conf_t      *conf;

    failed = NULL;
    out = NULL;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_img_filter_module);

    if (conf->convert_webp == 1) {
#if (NGX_HAVE_GD_WEBP)
        out = ngx_http_img_webp_out(r, type, img, size);
#else
        failed = "[=] nginx was built without GD WebP support";
#endif

    } else {

        switch (type) {

            case NGX_HTTP_IMG_JPEG:
                q = ngx_http_img_filter_get_value(r, conf->jqcv, conf->jpeg_quality);
                if (q <= 0) {
                    return NULL;
                }

                out = gdImageJpegPtr(img, size, (int)q);
                failed = "[=] gdImageJpegPtr() failed";
                break;

            case NGX_HTTP_IMG_GIF:
                out = gdImageGifPtr(img, size);
                failed = "[=] gdImageGifPtr() failed";
                break;

            case NGX_HTTP_IMG_PNG:
                q = ngx_http_img_filter_get_value(r, conf->pqcv, conf->png_quality);
                if (q < -1 || q > 9) {
                    failed = "[=] invalid png quality value (-1 ~ 9)";
                    return NULL;
                }

                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,  "[-] png quality : %d", q);

                out = gdImagePngPtrEx(img, size, (int)q);
                failed = "[=] gdImagePngPtr() failed";
                break;

            case NGX_HTTP_IMG_WEBP:
#if (NGX_HAVE_GD_WEBP)
                q = ngx_http_img_filter_get_value(r, conf->wqcv, conf->webp_quality);
                if (q <= 0) {
                    return NULL;
                }

                out = gdImageWebpPtrEx(img, size, (int)q);
                failed = "[=] gdImageWebpPtrEx() failed";
#else
                failed = "[=] nginx was built without GD WebP support";
#endif
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,  "[-] webp size : %d / quality : %d", size, q);

                break;

            default:
                failed = "[=] unknown image type";
                break;
        }
    }

    if (out == NULL && failed != NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, failed);
    }

    return out;
}


static void ngx_http_img_cleanup(void *data) {

    gdFree(data);
}


static ngx_int_t ngx_http_img_filter_get_value(ngx_http_request_t *r, ngx_http_complex_value_t *cv, ngx_uint_t v) {

    ngx_str_t  val;

    if (cv == NULL) {
        return v;
    }

    if (ngx_http_complex_value(r, cv, &val) != NGX_OK) {
        return 0;
    }

    return ngx_http_img_filter_value(&val);
}


static ngx_uint_t ngx_http_img_filter_value(ngx_str_t *value) {

    ngx_int_t  n;

    if (value->len == 1 && value->data[0] == '-') {
        return (ngx_uint_t) -1;
    }

    n = ngx_atoi(value->data, value->len);

    if (n > 0) {
        return (ngx_uint_t) n;
    }

    return 0;
}

static void *ngx_http_img_filter_create_conf(ngx_conf_t *cf) {

    ngx_http_img_filter_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_img_filter_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->width = 0;
     *     conf->height = 0;
     *     conf->angle = 0;
     *     conf->wcv = NULL;
     *     conf->hcv = NULL;
     *     conf->acv = NULL;
     *     conf->jqcv = NULL;
     *     conf->wqcv = NULL;
     *     conf->pqcv = -1;
     *     conf->shcv = NULL;
     */

    conf->filter = NGX_CONF_UNSET_UINT;
    conf->jpeg_quality = NGX_CONF_UNSET_UINT;
    conf->webp_quality = NGX_CONF_UNSET_UINT;
    conf->png_quality = -1;
    conf->sharpen = NGX_CONF_UNSET_UINT;
    conf->transparency = NGX_CONF_UNSET;
    conf->interlace = NGX_CONF_UNSET;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->convert_webp = NGX_CONF_UNSET;
    conf->convert_allow_only_quality = NGX_CONF_UNSET;

    return conf;
}


static char *ngx_http_img_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child) {

    ngx_http_img_filter_conf_t *prev = parent;
    ngx_http_img_filter_conf_t *conf = child;

    if (conf->filter == NGX_CONF_UNSET_UINT) {

        if (prev->filter == NGX_CONF_UNSET_UINT) {
            conf->filter = NGX_HTTP_IMG_OFF;

        } else {
            conf->filter = prev->filter;
            conf->width = prev->width;
            conf->height = prev->height;
            conf->angle = prev->angle;
            conf->wcv = prev->wcv;
            conf->hcv = prev->hcv;
            conf->acv = prev->acv;
        }
    }

    if (conf->jpeg_quality == NGX_CONF_UNSET_UINT) {

        /* 75 is libjpeg default quality */
        ngx_conf_merge_uint_value(conf->jpeg_quality, prev->jpeg_quality, 75);

        if (conf->jqcv == NULL) {
            conf->jqcv = prev->jqcv;
        }
    }

    if (conf->webp_quality == NGX_CONF_UNSET_UINT) {

        /* 80 is libwebp default quality */
        ngx_conf_merge_uint_value(conf->webp_quality, prev->webp_quality, 80);

        if (conf->wqcv == NULL) {
            conf->wqcv = prev->wqcv;
        }
    }

    if (conf->png_quality == -1) {

        /* 0 is libpng default quality */
        /* 0 -> none, 1-9 -> level, -1 -> default */
        ngx_conf_merge_value(conf->png_quality, prev->png_quality, -1);

        if (conf->pqcv == NULL) {
            conf->pqcv = prev->pqcv;
        }
    }


    if (conf->sharpen == NGX_CONF_UNSET_UINT) {
        ngx_conf_merge_uint_value(conf->sharpen, prev->sharpen, 0);

        if (conf->shcv == NULL) {
            conf->shcv = prev->shcv;
        }
    }

    ngx_conf_merge_value(conf->transparency, prev->transparency, 1); 
    ngx_conf_merge_value(conf->interlace, prev->interlace, 0); 
    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size, 1 * 1024 * 1024); 
    ngx_conf_merge_value(conf->convert_webp, prev->convert_webp, 0);
    ngx_conf_merge_value(conf->convert_allow_only_quality, prev->convert_allow_only_quality, 0);

    return NGX_CONF_OK;
}


static char *ngx_http_img_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    ngx_http_img_filter_conf_t *imcf = conf;

    ngx_str_t                         *value;
    ngx_int_t                          n;
    ngx_uint_t                         i;
    ngx_http_complex_value_t           cv;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    i = 1;

    if (cf->args->nelts == 2) {
        if (ngx_strcmp(value[i].data, "off") == 0) {
            imcf->filter = NGX_HTTP_IMG_OFF;

        } else if (ngx_strcmp(value[i].data, "test") == 0) {
            imcf->filter = NGX_HTTP_IMG_TEST;

        } else if (ngx_strcmp(value[i].data, "size") == 0) {
            imcf->filter = NGX_HTTP_IMG_SIZE;

        } else {
            goto failed;
        }

        return NGX_CONF_OK;

    } else if (cf->args->nelts == 3) {

        if (ngx_strcmp(value[i].data, "rotate") == 0) {
            if (imcf->filter != NGX_HTTP_IMG_RESIZE
                && imcf->filter != NGX_HTTP_IMG_CROP)
            {
                imcf->filter = NGX_HTTP_IMG_ROTATE;
            }

            ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

            ccv.cf = cf;
            ccv.value = &value[++i];
            ccv.complex_value = &cv;

            if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
                return NGX_CONF_ERROR;
            }

            if (cv.lengths == NULL) {
                n = ngx_http_img_filter_value(&value[i]);

                if (n != 90 && n != 180 && n != 270) {
                    goto failed;
                }

                imcf->angle = (ngx_uint_t) n;

            } else {
                imcf->acv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
                if (imcf->acv == NULL) {
                    return NGX_CONF_ERROR;
                }

                *imcf->acv = cv;
            }

            return NGX_CONF_OK;

        } else {
            goto failed;
        }
    }

    if (ngx_strcmp(value[i].data, "resize") == 0) {
        imcf->filter = NGX_HTTP_IMG_RESIZE;

    } else if (ngx_strcmp(value[i].data, "crop") == 0) {
        imcf->filter = NGX_HTTP_IMG_CROP;

    } else {
        goto failed;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[++i];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = ngx_http_img_filter_value(&value[i]);

        if (n == 0) {
            goto failed;
        }

        imcf->width = (ngx_uint_t) n;

    } else {
        imcf->wcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (imcf->wcv == NULL) {
            return NGX_CONF_ERROR;
        }

        *imcf->wcv = cv;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[++i];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = ngx_http_img_filter_value(&value[i]);

        if (n == 0) {
            goto failed;
        }

        imcf->height = (ngx_uint_t) n;

    } else {
        imcf->hcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (imcf->hcv == NULL) {

            return NGX_CONF_ERROR;
        }

        *imcf->hcv = cv;
    }

    return NGX_CONF_OK;

failed:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[=] invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}


static char *ngx_http_img_filter_jpeg_quality(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    ngx_http_img_filter_conf_t *imcf = conf;

    ngx_str_t                         *value;
    ngx_int_t                          n;
    ngx_http_complex_value_t           cv;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = ngx_http_img_filter_value(&value[1]);

        if (n <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[=] invalid value \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        imcf->jpeg_quality = (ngx_uint_t) n;

    } else {
        imcf->jqcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (imcf->jqcv == NULL) {
            return NGX_CONF_ERROR;
        }

        *imcf->jqcv = cv;
    }

    return NGX_CONF_OK;
}


static char *ngx_http_img_filter_webp_quality(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    ngx_http_img_filter_conf_t *imcf = conf;

    ngx_str_t                         *value;
    ngx_int_t                          n;
    ngx_http_complex_value_t           cv;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = ngx_http_img_filter_value(&value[1]);

        if (n <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[=] invalid value \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        imcf->webp_quality = (ngx_uint_t) n;

    } else {
        imcf->wqcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (imcf->wqcv == NULL) {
            return NGX_CONF_ERROR;
        }

        *imcf->wqcv = cv;
    }

    return NGX_CONF_OK;
}


static char *ngx_http_img_filter_png_quality(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    ngx_http_img_filter_conf_t *imcf = conf;

    ngx_str_t                         *value;
    ngx_int_t                          n;
    ngx_http_complex_value_t           cv;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = atoi((const char *)(&value[1])->data);
        if (n < -1 || n > 9) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[=] invalid value \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        imcf->png_quality = (ngx_int_t) n;

    } else {
        imcf->pqcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (imcf->pqcv == NULL) {
            return NGX_CONF_ERROR;
        }

        *imcf->pqcv = cv;
    }

    return NGX_CONF_OK;
}


static char *ngx_http_img_filter_sharpen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    ngx_http_img_filter_conf_t *imcf = conf;

    ngx_str_t                         *value;
    ngx_int_t                          n;
    ngx_http_complex_value_t           cv;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (cv.lengths == NULL) {
        n = ngx_http_img_filter_value(&value[1]);

        if (n < 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[=] invalid value \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        imcf->sharpen = (ngx_uint_t) n;

    } else {
        imcf->shcv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (imcf->shcv == NULL) {
            return NGX_CONF_ERROR;
        }

        *imcf->shcv = cv;
    }

    return NGX_CONF_OK;
}


static ngx_int_t ngx_http_img_filter_init(ngx_conf_t *cf) {

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_img_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_img_body_filter;

    return NGX_OK;
}

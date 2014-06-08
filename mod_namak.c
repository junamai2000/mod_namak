#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "ap_config.h"

#include "apr_hash.h"
#include "apr_strings.h"

#include <riak.h>

FILE *DEBUG__fp;
#define DEBUGF(...) DEBUG__fp=fopen("/tmp/log", "a+"); fprintf(DEBUG__fp,__VA_ARGS__); fclose(DEBUG__fp);

typedef struct {
    const char *riak_server;
    const char *riak_port;
} namak_svr_cfg;

extern module AP_MODULE_DECLARE_DATA namak_module;

static int namak_handler(request_rec *r)
{
    if (strcmp(r->handler, "namak")) {
        return DECLINED;
    }

    // a riak_config serves as your per-thread state to interact with Riak
    riak_config *cfg;

    // use the default configuration
    riak_error err = riak_config_new_default(&cfg);
    if (err) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server, "error2");
        return DECLINED;
    }

    apr_table_t *params = apr_table_make(r->pool, 5);
    int it;

    if (r->method_number != M_GET)
        return DECLINED;

    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server, r->args);
    if (r->args) {
        char *args = apr_pstrdup(r->pool, r->args);
        if (args == NULL) {
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server, "Can not allocate memory pool");
            return HTTP_BAD_REQUEST;
        }
        char *tok, *val;
        while (args && *args) {
            if ((val = ap_strchr(args, '='))) {
                *val++ = '\0';
                if ((tok = ap_strchr(val, '&')))
                    *tok++ = '\0';
            
                apr_table_setn(params, args, val);
                args = tok;
            }
            else
                return HTTP_BAD_REQUEST;
        }
    }

    const char *bucket = apr_table_get(params, "bucket");
    const char *key = apr_table_get(params, "key");
    if (bucket == NULL || key == NULL)
        return DECLINED;

    riak_binary *bucket_type_bin = riak_binary_copy_from_string(cfg, "default");
    riak_binary *bucket_bin   = riak_binary_copy_from_string(cfg, bucket); // Not copied
    riak_binary *key_bin      = riak_binary_copy_from_string(cfg, key);   // Not copied

    // check for memory allocation problems
    if (bucket_bin == NULL || key_bin    == NULL) {
        return DECLINED;
    }

    // Supporting Options and outputs
    riak_get_options *get_options;
    // Every possible message response type
    riak_get_response *get_response = NULL;
    riak_connection  *cxn   = NULL;
    // Create a connection with the default address resolver
    namak_svr_cfg* svr = ap_get_module_config(r->per_dir_config, &namak_module);
    if (svr->riak_server == NULL || svr->riak_port == NULL)
        return DECLINED;

    err = riak_connection_new(cfg, &cxn, svr->riak_server, svr->riak_port, NULL);
    if (err) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server, "error3");
        return DECLINED;
    }

    // handle possible operations from the command line
    get_options = riak_get_options_new(cfg);
    if (get_options == NULL) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server, "error4");
        return DECLINED;
    }
    riak_get_options_set_basic_quorum(get_options, RIAK_TRUE);
    riak_get_options_set_r(get_options, 1);
    err = riak_get(cxn, bucket_type_bin, bucket_bin, key_bin, get_options, &get_response);
    if (err == ERIAK_OK) {
        riak_object **objects = riak_get_get_content(get_response);
        int i = 0;
        for(i = 0; i < riak_get_get_n_content(get_response); i++) {
            riak_object *obj = objects[i];
            r->content_type = riak_binary_data(riak_object_get_content_type(obj));
            ap_rprintf(r,"%s\n",riak_binary_data(riak_object_get_value(obj)));
            break;
        }
    }
    riak_get_response_free(cfg, &get_response);
    riak_get_options_free(cfg, &get_options);
    if (err) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server, "error5");
        return DECLINED;
    }

    // cleanup
    riak_binary_free(cfg, &bucket_type_bin);
    riak_binary_free(cfg, &bucket_bin);
    riak_binary_free(cfg, &key_bin);
    riak_config_free(&cfg);

    return OK;
}

typedef enum { cmd_riak_server, cmd_riak_port } cmd_parts;
static const char *set_server(cmd_parms *cmd, void *dbconf, const char* val)
{
    namak_svr_cfg* entry = (namak_svr_cfg*)dbconf;
    switch ((long) cmd->info) {
        case cmd_riak_server:
            entry->riak_server = val;
            break;
        case cmd_riak_port:
            entry->riak_port = val;
            break;
    }
    return NULL;
}

static const command_rec namak_cmds[] =
{
    AP_INIT_TAKE1("RiakServer", set_server, (void*)cmd_riak_server, ACCESS_CONF, "riak server host name error"),
    AP_INIT_TAKE1("RiakPort", set_server, (void*)cmd_riak_port, ACCESS_CONF, "riak server pb port error"),
    {NULL}
};

static void namak_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(namak_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static void *create_namak_config(apr_pool_t *pool, server_rec *s)
{
    namak_svr_cfg* svr = apr_pcalloc(pool, sizeof(namak_svr_cfg));
    svr->riak_server = "localhost";
    svr->riak_port = "8087";
    return (void*)svr;
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA namak_module = {
    STANDARD20_MODULE_STUFF, 
    create_namak_config,   /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    namak_cmds,            /* table of config file commands       */
    namak_register_hooks   /* register hooks                      */
};


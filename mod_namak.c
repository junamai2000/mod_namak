// apache headers
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "ap_config.h"
// apr headers
#include "apr_hash.h"
#include "apr_strings.h"
// riak headers
#include <riak.h>
// FILE *DEBUG__fp;
// #define DEBUGF(...) DEBUG__fp=fopen("/tmp/log", "a+"); fprintf(DEBUG__fp,__VA_ARGS__); fclose(DEBUG__fp);

// configuration data structure
typedef struct {
    // riak kvs hostname
    const char *riak_server;
    // riak protocol buffers port
    const char *riak_port;
} namak_svr_cfg;

extern module AP_MODULE_DECLARE_DATA namak_module;

// main function that retrieves data from riak kvs 
static int namak_handler(request_rec *r)
{
    // check handler name
    if (strcmp(r->handler, "namak")) {
        return DECLINED;
    }
    // if method is not GET do not process
    if (r->method_number != M_GET)
        return DECLINED;
    // a riak_config serves as your per-thread state to interact with Riak
    riak_config *cfg;
    // use the default configuration
    riak_error err = riak_config_new_default(&cfg);
    if (err) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server, "failed to initailize default config");
        return DECLINED;
    }
    // make a table to store GET requests
    apr_table_t *params = apr_table_make(r->pool, 5);
    // debug code
    // ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server, r->args);
    // parse request parameters
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
    // get params to send them to Riak
    const char *bucket = apr_table_get(params, "bucket");
    const char *key = apr_table_get(params, "key");
    if (bucket == NULL || key == NULL)
        return DECLINED;
    riak_binary *bucket_type_bin = riak_binary_copy_from_string(cfg, "default"); // only for Riak 2.0?
    riak_binary *bucket_bin   = riak_binary_copy_from_string(cfg, bucket);
    riak_binary *key_bin      = riak_binary_copy_from_string(cfg, key);
    // check for memory allocation problems
    if (bucket_bin == NULL || key_bin    == NULL) {
        riak_config_free(&cfg);
        return DECLINED;
    }
    // Supporting Options and outputs
    riak_get_options *get_options;
    // Every possible message response type
    riak_get_response *get_response = NULL;
    riak_connection  *cxn   = NULL;
    // get Riak host and port from httpd.conf
    namak_svr_cfg* svr = ap_get_module_config(r->per_dir_config, &namak_module);
    if (svr->riak_server == NULL || svr->riak_port == NULL)
    {
        riak_binary_free(cfg, &bucket_type_bin);
        riak_binary_free(cfg, &bucket_bin);
        riak_binary_free(cfg, &key_bin);
        riak_config_free(&cfg);
        return DECLINED;
    }
    // Create a connection with the default address resolver
    err = riak_connection_new(cfg, &cxn, svr->riak_server, svr->riak_port, NULL);
    if (err) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server,
                "failed to connect Riak(%s:%s)", svr->riak_server, svr->riak_port);
        riak_binary_free(cfg, &bucket_type_bin);
        riak_binary_free(cfg, &bucket_bin);
        riak_binary_free(cfg, &key_bin);
        riak_config_free(&cfg);
        return HTTP_SERVICE_UNAVAILABLE;
    }
    // handle possible operations from the command line
    get_options = riak_get_options_new(cfg);
    if (get_options == NULL) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_NOTICE, 0, r->server, "failed to initailize option config");
        riak_binary_free(cfg, &bucket_type_bin);
        riak_binary_free(cfg, &bucket_bin);
        riak_binary_free(cfg, &key_bin);
        riak_config_free(&cfg);
        return DECLINED;
    }
    riak_get_options_set_basic_quorum(get_options, RIAK_TRUE);
    riak_get_options_set_r(get_options, 1);
    // get data from Riak kvs
    err = riak_get(cxn, bucket_type_bin, bucket_bin, key_bin, get_options, &get_response);
    if (err == ERIAK_OK) {
        // if response does not have at least one object, just return 404
        if (riak_get_get_n_content(get_response) < 1)
        {
            riak_binary_free(cfg, &bucket_type_bin);
            riak_binary_free(cfg, &bucket_bin);
            riak_binary_free(cfg, &key_bin);
            riak_config_free(&cfg);
            return HTTP_NOT_FOUND;
        }
        // get the first object
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
        riak_binary_free(cfg, &bucket_type_bin);
        riak_binary_free(cfg, &bucket_bin);
        riak_binary_free(cfg, &key_bin);
        riak_config_free(&cfg);
        return HTTP_SERVICE_UNAVAILABLE;
    }
    // cleanup
    riak_binary_free(cfg, &bucket_type_bin);
    riak_binary_free(cfg, &bucket_bin);
    riak_binary_free(cfg, &key_bin);
    riak_config_free(&cfg);
    return OK;
}

// config entries
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
// define config names 
static const command_rec namak_cmds[] =
{
    AP_INIT_TAKE1("RiakServer", set_server, (void*)cmd_riak_server, ACCESS_CONF, "riak server host name error"),
    AP_INIT_TAKE1("RiakPort", set_server, (void*)cmd_riak_port, ACCESS_CONF, "riak server pb port error"),
    {NULL}
};
// add hooks into apache2
static void namak_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(namak_handler, NULL, NULL, APR_HOOK_MIDDLE);
}
// allocate memory for config object
static void *create_namak_config(apr_pool_t *pool, server_rec *s)
{
    namak_svr_cfg* svr = apr_pcalloc(pool, sizeof(namak_svr_cfg));
    svr->riak_server = "localhost";
    svr->riak_port = "8087";
    return (void*)svr;
}
// api entry
module AP_MODULE_DECLARE_DATA namak_module = {
    STANDARD20_MODULE_STUFF, 
    create_namak_config,   /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    namak_cmds,            /* table of config file commands       */
    namak_register_hooks   /* register hooks                      */
};

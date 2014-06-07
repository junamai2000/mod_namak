/* 
**  mod_namak.c -- Apache sample namak module
**  [Autogenerated via ``apxs -n namak -g'']
**
**  To play with this sample module first compile it into a
**  DSO file and install it into Apache's modules directory 
**  by running:
**
**    $ apxs -c -i mod_namak.c
**
**  Then activate it in Apache's apache2.conf file for instance
**  for the URL /namak in as follows:
**
**    #   apache2.conf
**    LoadModule namak_module modules/mod_namak.so
**    <Location /namak>
**    SetHandler namak
**    </Location>
**
**  Then after restarting Apache via
**
**    $ apachectl restart
**
**  you immediately can request the URL /namak and watch for the
**  output of this module. This can be achieved for instance via:
**
**    $ lynx -mime_header http://localhost/namak 
**
**  The output should be similar to the following one:
**
**    HTTP/1.1 200 OK
**    Date: Tue, 31 Mar 1998 14:42:22 GMT
**    Server: Apache/1.3.4 (Unix)
**    Connection: close
**    Content-Type: text/html
**  
**    The sample page from mod_namak.c
*/ 

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "ap_config.h"

#include "apr_hash.h"
#include "apr_strings.h"

#include <riak.h>

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
    riak_get_options    *get_options;
    // Every possible message response type
    riak_get_response               *get_response = NULL;
    riak_connection  *cxn   = NULL;
    // Create a connection with the default address resolver
    err = riak_connection_new(cfg, &cxn, "192.168.10.80", "8087", NULL);
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

static void namak_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(namak_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA namak_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL,                  /* table of config file commands       */
    namak_register_hooks  /* register hooks                      */
};

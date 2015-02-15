/* Include the required headers from httpd */
#include <httpd.h>
#include <http_core.h>
#include <http_protocol.h>
#include <http_request.h>
#include <string.h>
#include "apr_base64.h"

/* Define prototypes of our functions in this module */
static void register_hooks(apr_pool_t *pool);
static int privcon_handler(request_rec *r);

/* Define our module as an entity and assign a function for registering hooks  */

module AP_MODULE_DECLARE_DATA   mod_auth_privcon_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,            // Per-directory configuration handler
    NULL,            // Merge handler for per-directory configurations
    NULL,            // Per-server configuration handler
    NULL,            // Merge handler for per-server configurations
    NULL,            // Any directives we may have for httpd
    register_hooks   // Our hook registering function
};


/* register_hooks: Adds a hook to the httpd process */
static void register_hooks(apr_pool_t *pool) 
{
    
    /* Hook the request handler */
    ap_hook_handler(privcon_handler, NULL, NULL, APR_HOOK_LAST);
}

/* The handler function for our module.
 * This is where all the fun happens!
 */

static int privcon_handler(request_rec *r)
{
    /* First off, we need to check if this is a call for the "example" handler.
     * If it is, we accept it and do our things, it not, we simply return DECLINED,
     * and Apache will try somewhere else.
     */
    if (!r->handler || strcmp(r->handler, "privcon-handler")) return (DECLINED);
    
    // The first thing we will do is write a simple "Hello, world!" back to the client.
    ap_rputs("Hello, world!<br/>", r);
    ap_rputs(r->useragent_ip, r);

    char decoded[1024];
    apr_base64_decode(decoded, r->args);

    ap_rputs(decoded, r);

    return OK;
}
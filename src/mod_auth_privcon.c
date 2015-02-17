/* Include the required headers from httpd */
#include <httpd.h>
#include <http_core.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>
#include <string.h>
#include "apr_base64.h"
#include "apr_strings.h"


struct Policy
{
    char url[1024];
    char sourceIp[15];
    char dateLessThan[20];
    char dateGreaterThan[20];
};

struct QueryStringParameters
{
    char policy[1024];
    char signiture[1024];
};

enum JsonDataType {
    JSONSTRING,
    JSONEPOCHDATETIME,
    JSONINTEGER,
    JSONIPADDRESS
};

/* Define prototypes of our functions in this module */
static void register_hooks(apr_pool_t *pool);
static int privcon_handler(request_rec *r);
static void decodeUrlSafeString(char string[]);
static struct QueryStringParameters extractQueryStringParameters(char querystring[]);
static void populatePolicyParameters(char policyJson[], struct Policy *policy);
static void extractJsonPropertyValue(char src[], char propertyName[], char propertyValue[], enum JsonDataType type);
static int strSearchPosition(char src[], char str[], int start);

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

    struct Policy policy;

    struct QueryStringParameters params = extractQueryStringParameters(r->args);

    // Check required querystring orameters are present
    if (params.policy[0]=='\0' || params.signiture[0]=='\0') {
        return HTTP_FORBIDDEN;
    }

    // Extract policy json from base 64 encoded policy from querystring
    char policyJson[1024];
    apr_base64_decode(policyJson, params.policy);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "policy Json %s.", policyJson);

    // Populate policy from policy json
    populatePolicyParameters(policyJson, &policy);

    extractJsonPropertyValue(policyJson, "Resource", policy.url, JSONSTRING);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "policy url %s.", policy.url);

    extractJsonPropertyValue(policyJson, "DateLessThan", policy.dateLessThan, JSONEPOCHDATETIME);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "policy DateLessThan %s.", policy.dateLessThan);

    extractJsonPropertyValue(policyJson, "DateGreaterThan", policy.dateGreaterThan, JSONEPOCHDATETIME);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "policy DateGreaterThan %s.", policy.dateGreaterThan);

    extractJsonPropertyValue(policyJson, "IpAddress", policy.sourceIp, JSONIPADDRESS);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "policy Source IP %s.", policy.sourceIp);

    // Let apache continue to process the request
    return DECLINED;
}

static struct QueryStringParameters extractQueryStringParameters(char querystring[]) {
    struct QueryStringParameters params;
    params.policy[0] = '\0';
    params.signiture[0] = '\0';

    char *a, *next, *last, *pnext, *plast;
    next = apr_strtok(querystring, "&", &last);

    while (next) {
        pnext = apr_strtok(next, "=", &plast);

        if (strcmp(pnext, "policy")==0) {
            if (strlen(plast) > 0) { // Check a parameter value was provided in the url
                pnext = apr_strtok(NULL, "=", &plast);
                strcpy(params.policy, pnext);
            }
            
        } else if (strcmp(pnext, "signiture")==0) {
            if (strlen(plast) > 0) { // Check a parameter value was provided in the url
                pnext = apr_strtok(NULL, "=", &plast);
                strcpy(params.signiture, pnext);
            }
        }

        next = apr_strtok(NULL, "&", &last);
    }

    return params;
}

static void populatePolicyParameters(char policyJson[], struct Policy *policy) {
    strcpy(policy->url, "http://www.google.com");

}

static void decodeUrlSafeString(char string[]) {
    const char safe[] = {'-', '_', '~'};
    const char unsafe[] = {'+', '=', '/'}; 

    for (int x = 0; x < strlen(string); x++) {
        for (int y = 0; y < sizeof(safe); y++) {
            if (string[x] == safe[y]) {
                string[x]=unsafe[y];
            }
        }
    }
}

static void extractJsonPropertyValue(char src[], char propertyName[], char propertyValue[], enum JsonDataType type) {
    // Create the pattern to match in the format of "propertyname":"
    char *propertyNamePattern;
    int propertyNamePosition;
    char *propertyEndPattern;

    switch (type) {
        case JSONSTRING:
            propertyNamePattern = malloc(strlen(propertyName) + 4);
            sprintf(propertyNamePattern, "\"%s\":\"", propertyName);
            propertyNamePosition = strSearchPosition(src, propertyNamePattern, 0);
            propertyEndPattern = "\"";
        break;
        case JSONEPOCHDATETIME:
            propertyNamePattern = malloc(strlen(propertyName) + 23);
            sprintf(propertyNamePattern, "\"%s\":{\"Apache:EpochTime\":", propertyName);
            propertyNamePosition = strSearchPosition(src, propertyNamePattern, 0);
            propertyEndPattern = "}";
        break;
        case JSONIPADDRESS:
            propertyNamePattern = malloc(strlen(propertyName) + 23);
            sprintf(propertyNamePattern, "\"%s\":{\"Apache:SourceIp\":\"", propertyName);
            propertyNamePosition = strSearchPosition(src, propertyNamePattern, 0);
            propertyEndPattern = "\"";
        break;
        case JSONINTEGER:

        break;
    }
   
    // Get the value start position , end position , and length
    int valueStartPosition = propertyNamePosition + strlen(propertyNamePattern);
    int valueEndPosition = strSearchPosition(src, propertyEndPattern, valueStartPosition);
    int valueLength = valueEndPosition - valueStartPosition;

    // Copy the property value
    memcpy(propertyValue, &src[valueStartPosition], valueLength);

    // Add trailing null after the last chatacter
    propertyValue[valueLength] = '\0'; 
}

static int strSearchPosition(char src[], char str[], int start) {
   int i, j, firstOcc;
   i = start, j = 0;
 
   while (src[i] != '\0') {
 
      while (src[i] != str[0] && src[i] != '\0')
         i++;
 
      if (src[i] == '\0')
         return (-1);
 
      firstOcc = i;
 
      while (src[i] == str[j] && src[i] != '\0' && str[j] != '\0') {
         i++;
         j++;
      }
 
      if (str[j] == '\0')
         return (firstOcc);
      if (src[i] == '\0')
         return (-1);
 
      i = firstOcc + 1;
      j = 0;
   }

   return (-1);
}

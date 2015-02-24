/* Include the required headers from httpd */
#include <httpd.h>
#include <http_core.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>
#include <string.h>
#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "apr.h"
#include "apr_base64.h"
#include "apr_strings.h"
#include "apr_random.h"
#include "apr_pools.h"
#include "apr_tables.h"
#include "util_script.h"
#include <time.h>

struct Configuration
{
    const char *publicKey;
    const char *publicKeyPath;
};

static struct Configuration configuration;

struct Policy
{
    char *url;
    char *sourceIp;
    char *dateLessThan;
    char *dateGreaterThan;
};

enum JsonDataType {
    JSONSTRING,
    JSONEPOCHDATETIME,
    JSONINTEGER,
    JSONIPADDRESS
};

/* Define prototypes of our functions in this module */
static void register_hooks(apr_pool_t *pool);
static int signedurl_handler(request_rec *r);
static char* decodeUrlSafeString(const char *string, request_rec *r);
static void extractJsonPropertyValue(char src[], char propertyName[], char **propertyValue, enum JsonDataType type, request_rec *r);
static int strSearchPosition(char src[], char str[], int start);
static int VerifySignature(char data[], size_t dataLength, unsigned char signature[], size_t signatureLength, request_rec *r);
static void sha256_init(apr_crypto_hash_t *h);
static void sha256_add(apr_crypto_hash_t *h,const void *data, apr_size_t bytes);
static void sha256_finish(apr_crypto_hash_t *h,unsigned char *result);

const char *signedurl_set_publickey(cmd_parms *cmd, void *cfg, const char *arg)
{
    configuration.publicKey = arg;
    return NULL;
}

const char *signedurl_set_publickeypath(cmd_parms *cmd, void *cfg, const char *arg)
{
    configuration.publicKeyPath = arg;
    return NULL;
}

static const command_rec signedurl_directives[] =
{
    AP_INIT_TAKE1("signedUrlPublicKey", signedurl_set_publickey, NULL, OR_ALL, "Set the public key"),
    AP_INIT_TAKE1("signedUrlPublicKeyPath", signedurl_set_publickeypath, NULL, OR_ALL, "Set the path to a public key"),
    { NULL }
};

/* Define our module as an entity and assign a function for registering hooks  */
module AP_MODULE_DECLARE_DATA   mod_authz_signedurl_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,               // Per-directory configuration handler
    NULL,               // Merge handler for per-directory configurations
    NULL,               // Per-server configuration handler
    NULL,               // Merge handler for per-server configurations
    signedurl_directives, // Any directives we may have for httpd
    register_hooks      // Our hook registering function
};

/* register_hooks: Adds a hook to the httpd process */
static void register_hooks(apr_pool_t *pool) 
{
    
    /* Hook the request handler */
    ap_hook_handler(signedurl_handler, NULL, NULL, APR_HOOK_LAST);
}

/* The handler function for our module.
 * This is where all the fun happens!
 */

static int signedurl_handler(request_rec *r)
{
    /* First off, we need to check if this is a call for the "example" handler.
     * If it is, we accept it and do our things, it not, we simply return DECLINED,
     * and Apache will try somewhere else.
     */
    if (!r->handler || strcmp(r->handler, "signedurl-handler")) return (DECLINED);

    struct Policy policy;

    // Get the querystring parameters
    apr_table_t *GET;
    ap_args_to_table(r, &GET);
    const char *base64Policy = decodeUrlSafeString(apr_table_get(GET, "policy"), r);
    const char *base64Signature = decodeUrlSafeString(apr_table_get(GET, "signature"), r);

    // Check required querystring orameters are present
    if (!base64Policy || !base64Signature) {
        return HTTP_FORBIDDEN;
    }

    // Extract policy json from base 64 encoded policy from querystring
    char policyJson[apr_base64_decode_len(base64Policy)];
    size_t policyJsonLength = apr_base64_decode(policyJson, base64Policy);

    unsigned char policySignature[apr_base64_decode_len(base64Signature)];
    size_t signatureLength = apr_base64_decode_binary(policySignature, base64Signature);

    // Verify the signature matches the json data
    int signatureOk = VerifySignature(policyJson, policyJsonLength, policySignature, signatureLength, r);
    if (1 != signatureOk) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "Request signature does not match policy document %s.", policySignature);
        return HTTP_FORBIDDEN;
    }

    // Populate policy from policy json
    extractJsonPropertyValue(policyJson, "Resource", &policy.url, JSONSTRING, r);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "policy url %s.", policy.url);

    extractJsonPropertyValue(policyJson, "DateLessThan", &policy.dateLessThan, JSONEPOCHDATETIME, r);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "policy DateLessThan %s.", policy.dateLessThan);

    extractJsonPropertyValue(policyJson, "DateGreaterThan", &policy.dateGreaterThan, JSONEPOCHDATETIME, r);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "policy DateGreaterThan %s.", policy.dateGreaterThan);

    extractJsonPropertyValue(policyJson, "IpAddress", &policy.sourceIp, JSONIPADDRESS, r);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "policy Source IP %s.", policy.sourceIp);

    // Check date time policy requirment
    time_t *sec = apr_palloc(r->pool, sizeof(time_t));
    *sec = time(NULL);

    // Check the request is before the less then policy requirement
    long int *policy_datelessthan = apr_palloc(r->pool, sizeof(long int));
    sscanf(policy.dateLessThan, "%ld", policy_datelessthan);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "checking less than policy %ld < %ld.", *sec, *policy_datelessthan);

    if (*sec > *policy_datelessthan) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "Request does not fulfill datetime less than policy %ld != %ld.", *sec, *policy_datelessthan);
        return HTTP_FORBIDDEN;
    }

    // Check the request is after the greater than policy requirment
    long int *policy_dategreaterthan = apr_palloc(r->pool, sizeof(long int));
    sscanf(policy.dateGreaterThan, "%ld", policy_dategreaterthan);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "checking greater than policy %ld < %ld.", *sec, *policy_dategreaterthan);

    if (*sec < *policy_dategreaterthan) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "Request does not fulfill datetime greater than policy %ld != %ld.", *sec, *policy_dategreaterthan);
        return HTTP_FORBIDDEN;
    }

    // Check ip address matched policy requirement
    if (strcmp(r->useragent_ip, policy.sourceIp)!=0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "Source IP address does not match policy %s != %s.", r->useragent_ip, policy.sourceIp);
        return HTTP_FORBIDDEN;   
    }

    // Check url matches policy
    apr_uri_t *uptr = apr_palloc(r->pool, sizeof(apr_uri_t));
    apr_uri_parse(r->pool, policy.url, uptr);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "Comparing requested url to policy url.");
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "policy url %s://%s:%d%s.", uptr->scheme, uptr->hostname, uptr->port, uptr->path);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "requested url %s://%s:%d%s.", r->parsed_uri.scheme, r->hostname, r->parsed_uri.port, r->parsed_uri.path);

    // Check protocol (http/https..)
    if (uptr->scheme!=NULL) {
        if (r->parsed_uri.scheme == NULL || strcmp(uptr->scheme, r->parsed_uri.scheme) != 0) {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "requested protocol %s does not match policy protocol %s.", r->parsed_uri.scheme, uptr->scheme);
            return HTTP_FORBIDDEN;           
        }
    }

    // Check port
    if (uptr->port != r->parsed_uri.port) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "requested port %d does not match policy port %d.", r->parsed_uri.port, uptr->port);
        return HTTP_FORBIDDEN; 
    }

    // Check hostname
    if (uptr->hostname == NULL || r->hostname == NULL || strcmp(uptr->hostname, r->hostname) != 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "requested hostname %s does not match policy hostname %s.", r->hostname, uptr->hostname);
        return HTTP_FORBIDDEN; 
    }

    // Check path
    if (uptr->path == NULL || r->parsed_uri.path == NULL || strcmp(uptr->path, r->parsed_uri.path) != 0) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "requested path %s does not match policy path %s.", r->parsed_uri.path, uptr->path);
        return HTTP_FORBIDDEN; 
    }

    // Let apache continue to process the request
    return DECLINED;
}

static char* decodeUrlSafeString(const char *string, request_rec *r) {
    const char safe[] = {'-', '_', '~'};
    const char unsafe[] = {'+', '=', '/'};

    //char *decoded = malloc(strlen(string)+1);
    char *decoded;
    decoded = apr_palloc(r->pool, strlen(string)+1);

    apr_cpystrn(decoded, string, strlen(string)+1);
 
    for (int x = 0; x < strlen(decoded); x++) {
        for (int y = 0; y < sizeof(safe); y++) {
            if (decoded[x] == safe[y]) {
                decoded[x] = unsafe[y];
            }
        }
    }
 
    return decoded;
}

static void extractJsonPropertyValue(char src[], char propertyName[], char **propertyValue, enum JsonDataType type, request_rec *r) {
    // Create the pattern to match in the format of "propertyname":"
    char *propertyNamePattern, *propertyEndPattern;
    int *propertyNamePosition = apr_palloc(r->pool, sizeof(int));

    switch (type) {
        case JSONSTRING:
            propertyNamePattern = apr_palloc(r->pool, strlen(propertyName)+4);
            sprintf(propertyNamePattern, "\"%s\":\"", propertyName);
            *propertyNamePosition = strSearchPosition(src, propertyNamePattern, 0);
            propertyEndPattern = apr_palloc(r->pool, sizeof(char)*3);
            propertyEndPattern = "\"";
        break;
        case JSONEPOCHDATETIME:
            propertyNamePattern = apr_palloc(r->pool, strlen(propertyName)+23);
            sprintf(propertyNamePattern, "\"%s\":{\"Apache:EpochTime\":", propertyName);
            *propertyNamePosition = strSearchPosition(src, propertyNamePattern, 0);
            propertyEndPattern = apr_palloc(r->pool, sizeof(char)*2);
            propertyEndPattern = "}";
        break;
        case JSONIPADDRESS:
            propertyNamePattern = apr_palloc(r->pool, strlen(propertyName)+23);
            sprintf(propertyNamePattern, "\"%s\":{\"Apache:SourceIp\":\"", propertyName);
            *propertyNamePosition = strSearchPosition(src, propertyNamePattern, 0);
            propertyEndPattern = apr_palloc(r->pool, sizeof(char)*3);
            propertyEndPattern = "\"";
        break;
        case JSONINTEGER:

        break;
    }
   
    // Get the value start position , end position , and length
    int *valueStartPosition = apr_palloc(r->pool, sizeof(int));
    *valueStartPosition = *propertyNamePosition + strlen(propertyNamePattern);
    int *valueEndPosition = apr_palloc(r->pool, sizeof(int));
    *valueEndPosition = strSearchPosition(src, propertyEndPattern, *valueStartPosition);
    int *valueLength = apr_palloc(r->pool, sizeof(int));
    *valueLength = *valueEndPosition - *valueStartPosition;

    // Copy the property value
    // Allocate 1 extera char set to \0
    *propertyValue = apr_pcalloc(r->pool, *valueLength+1);
    memcpy(*propertyValue, &src[*valueStartPosition], *valueLength);
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

static int VerifySignature(char data[], size_t dataLength, unsigned char signature[], size_t signatureLength, request_rec *r) {
    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "Starting signature verification");

    //ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "Reading public key from %s", configuration.publicKeyPath);
    //FILE *keyfile = fopen(configuration.publicKeyPath, "r");
    //RSA rsa_pubkey = *PEM_read_RSA_PUBKEY(keyfile, NULL, NULL, NULL);

    char publicKey[apr_base64_decode_len(configuration.publicKey)];
    size_t publicKeyLength = apr_base64_decode(publicKey, configuration.publicKey);
    BIO* bio = BIO_new_mem_buf( publicKey, publicKeyLength);
    RSA rsa_pubkey = *PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);


    // Create a digent of the data
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "Starting apr SHA256 hash");
    apr_crypto_hash_t *h = apr_crypto_sha256_new(r->pool);
    unsigned char digest2[SHA256_DIGEST_LENGTH];
    sha256_init(h);
    sha256_add(h, data, dataLength);
    sha256_finish(h, digest2);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "Starting apr digest %s", digest2);

    int rc = RSA_verify(NID_sha256, digest2, SHA256_DIGEST_LENGTH, signature, signatureLength, &rsa_pubkey);
    if (1 != rc) {
        int rsa_error = ERR_get_error();
        char rsa_error_str[1024];
        ERR_error_string(rsa_error, rsa_error_str);
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "RSA_verify error %d %s", rsa_error, rsa_error_str);
        return 0;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "RSA_verify OK");

    return 1;
}

static void sha256_init(apr_crypto_hash_t *h)
{
    apr__SHA256_Init(h->data);
}

static void sha256_add(apr_crypto_hash_t *h,const void *data, apr_size_t bytes)
{
    apr__SHA256_Update(h->data,data,bytes);
}

static void sha256_finish(apr_crypto_hash_t *h,unsigned char *result)
{
    apr__SHA256_Final(result,h->data);
}

APR_DECLARE(apr_crypto_hash_t *) apr_crypto_sha256_new(apr_pool_t *p)
{
    apr_crypto_hash_t *h=apr_palloc(p,sizeof *h);

    h->data=apr_palloc(p,sizeof(SHA256_CTX));
    h->init=sha256_init;
    h->add=sha256_add;
    h->finish=sha256_finish;
    h->size=256/8;

    return h;
}

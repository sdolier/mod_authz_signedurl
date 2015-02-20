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

struct Configuration
{
    const char *publicKey;
    const char *publicKeyPath;
};

static struct Configuration configuration;

struct Policy
{
    char url[1024];
    char sourceIp[15];
    char dateLessThan[20];
    char dateGreaterThan[20];
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
static char* decodeUrlSafeString(const char *string, request_rec *r);
static void populatePolicyParameters(char policyJson[], struct Policy *policy);
static void extractJsonPropertyValue(char src[], char propertyName[], char propertyValue[], enum JsonDataType type);
static int strSearchPosition(char src[], char str[], int start);
static int VerifySignature(char data[], size_t dataLength, unsigned char signature[], size_t signatureLength, request_rec *r);
static void sha256_init(apr_crypto_hash_t *h);
static void sha256_add(apr_crypto_hash_t *h,const void *data, apr_size_t bytes);
static void sha256_finish(apr_crypto_hash_t *h,unsigned char *result);

const char *privcon_set_publickey(cmd_parms *cmd, void *cfg, const char *arg)
{
    configuration.publicKey = arg;
    return NULL;
}

const char *privcon_set_publickeypath(cmd_parms *cmd, void *cfg, const char *arg)
{
    configuration.publicKeyPath = arg;
    return NULL;
}

static const command_rec privcon_directives[] =
{
    AP_INIT_TAKE1("privConPublicKey", privcon_set_publickey, NULL, OR_ALL, "Set the public key"),
    AP_INIT_TAKE1("privConPublicKeyPath", privcon_set_publickeypath, NULL, OR_ALL, "Set the path to a public key"),
    { NULL }
};

/* Define our module as an entity and assign a function for registering hooks  */
module AP_MODULE_DECLARE_DATA   mod_auth_privcon_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,               // Per-directory configuration handler
    NULL,               // Merge handler for per-directory configurations
    NULL,               // Per-server configuration handler
    NULL,               // Merge handler for per-server configurations
    privcon_directives, // Any directives we may have for httpd
    register_hooks      // Our hook registering function
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
        return HTTP_FORBIDDEN;
    }

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

static void populatePolicyParameters(char policyJson[], struct Policy *policy) {
    strcpy(policy->url, "http://www.google.com");

}

static char* decodeUrlSafeString(const char *string, request_rec *r) {
    const char safe[] = {'-', '_', '~'};
    const char unsafe[] = {'+', '=', '/'};

    char *decoded = malloc(strlen(string)+1);
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

static void sha256_add(apr_crypto_hash_t *h,const void *data,
              apr_size_t bytes)
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

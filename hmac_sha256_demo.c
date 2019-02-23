//
// Created by root on 2/23/19.
//
#include "util.h"
void main(){
    unsigned char * api_secret="123456";
    unsigned char * context="888888";


    HMAC256(api_secret, strlen(api_secret), context, strlen(context));

}

void HMAC256(const unsigned char * secret, size_t secretLen,
             const unsigned char * context, size_t contextLen)
{
    mbedtls_md_context_t md;
    const mbedtls_md_info_t* info;
    uint8_t digest[MBEDTLS_MD_MAX_SIZE];
    int ret;

    mbedtls_md_init(&md);

    /*
     * Extract
     */
    info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    ret = mbedtls_md_setup(&md, info, 1);
    if (ret != 0) {
        goto Exit;
    }
    ret = mbedtls_md_hmac_starts(&md, secret, secretLen);
    if (ret != 0) {
        goto Exit;
    }
    ret = mbedtls_md_hmac_update(&md, context, contextLen);
    if (ret != 0) {
        goto Exit;
    }
    ret = mbedtls_md_hmac_finish(&md, digest);
    if (ret != 0) {
        goto Exit;
    }

    printf("%s", bytes_to_hex(digest, 32));
    Exit:
    mbedtls_md_free(&md);

}

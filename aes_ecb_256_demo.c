//
// Created by root on 2/23/19.
//
#include "util.h"

int main(){
    unsigned char key[32];
    unsigned char buf[16];
    unsigned char buf2[16];

    unsigned char outbuf[16];
    unsigned char outbuf2[16];
    unsigned char decbuf[16];
    unsigned char decbuf2[16];

    mbedtls_aes_context ctx;

    memset( key, 0, 32 );
    mbedtls_aes_init( &ctx );
    memset( buf, 1, 16 );
    memset( buf2, 2, 16 );
    memset( outbuf, 0, 16 );
    memset( outbuf2, 0, 16 );
    memset( decbuf, 0, 16 );
    memset( decbuf2, 0, 16 );

    mbedtls_aes_setkey_enc( &ctx, key, 256 );  //set key, 256bit

    mbedtls_aes_crypt_ecb( &ctx, MBEDTLS_AES_ENCRYPT, buf, outbuf ); //ecb mode
    mbedtls_aes_crypt_ecb( &ctx, MBEDTLS_AES_ENCRYPT, buf2, outbuf2 );

    mbedtls_aes_setkey_dec( &ctx, key, 256 );
    mbedtls_aes_crypt_ecb( &ctx, MBEDTLS_AES_DECRYPT, outbuf, decbuf );
    mbedtls_aes_crypt_ecb( &ctx, MBEDTLS_AES_DECRYPT, outbuf2, decbuf2 );

    for (int i = 0; i < 16; ++i) {
        printf("%2x", buf[i]);
    }
    printf("\n");

    for (int i = 0; i < 16; ++i) {
        printf("%2x", buf2[i]);
    }
    printf("\n");
    for (int i = 0; i < 16; ++i) {
        printf("%02x", outbuf[i]);
    }
    printf("\n");
    for (int i = 0; i < 16; ++i) {
        printf("%02x", outbuf2[i]);
    }

    printf("\n");
    for (int i = 0; i < 16; ++i) {
        printf("%2x", decbuf[i]);
    }

    printf("\n");

    for (int i = 0; i < 16; ++i) {
        printf("%2x", decbuf2[i]);
    }

}

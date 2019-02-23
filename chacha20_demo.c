//
// Created by root on 2/23/19.
//
#include "util.h"

int main(){
    unsigned char output[32];
    static const char hello_str[] = "Hello, world!";
    static const unsigned char *hello_buffer = (const unsigned char *) hello_str;
    static const size_t hello_len = sizeof hello_str - 1;
    const unsigned char key[32];
    const unsigned char nonce[12];
    unsigned char output_chacha20_enc[32];
    unsigned char output_chacha20_dec[32];
    int32_t counter;

    memset(key, 'A', 32);
    memset(nonce, 1, 12);
    mbedtls_chacha20_context mbedtlsChacha20Context;
    mbedtls_chacha20_init(&mbedtlsChacha20Context);
    mbedtls_chacha20_setkey(&mbedtlsChacha20Context, key);
    mbedtls_chacha20_starts(&mbedtlsChacha20Context, &nonce, counter);
    mbedtls_chacha20_update(&mbedtlsChacha20Context, hello_len, hello_buffer, output_chacha20_enc);
    print_hex("chacha20 encryption:", output_chacha20_enc, sizeof(output_chacha20_enc));

    mbedtls_chacha20_starts(&mbedtlsChacha20Context, &nonce, counter);
    mbedtls_chacha20_update(&mbedtlsChacha20Context, hello_len, output_chacha20_enc, output_chacha20_dec);
    printf("chacha20 decrytion: %s", output_chacha20_dec);
    mbedtls_chacha20_free(&mbedtlsChacha20Context);

}

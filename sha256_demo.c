//
// Created by root on 2/23/19.
//
#include "util.h"

int main(){
    unsigned char output[32];
    static const char hello_str[] = "Hello, world!";
    static const unsigned char *hello_buffer = (const unsigned char *) hello_str;
    static const size_t hello_len = sizeof hello_str - 1;

    mbedtls_sha256_context mbedtlsSha256Context;
    mbedtls_sha256_init(&mbedtlsSha256Context);
    mbedtls_sha256_starts(&mbedtlsSha256Context, 0);
    mbedtls_sha256_update(&mbedtlsSha256Context, hello_buffer, hello_len);
    mbedtls_sha256_finish(&mbedtlsSha256Context, output);

    print_hex("sha256", output, sizeof(output));
    mbedtls_sha256_free(&mbedtlsSha256Context);
}

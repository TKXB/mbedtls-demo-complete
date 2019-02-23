//
// Created by root on 2/23/19.
//
#include "util.h"

void print_hex(const char *title, const unsigned char buf[], size_t len)
{
    printf("%s: ", title);

    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);

    printf("\r\n");
}

char *bytes_to_hex( const uint8_t bin[], size_t len ) {
    static const char hexchars[16] = "0123456789abcdef";
    static char hex[512];
    size_t i;

    for( i = 0; i < len; ++i ) {
        hex[2 * i] = hexchars[bin[i] / 16];
        hex[2 * i + 1] = hexchars[bin[i] % 16];
    }
    hex[2 * len] = '\0';
    return hex;
}
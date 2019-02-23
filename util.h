//
// Created by root on 2/23/19.
//

#ifndef MBEDTLS_DEMO_COMPLETE_UTIL_H
#define MBEDTLS_DEMO_COMPLETE_UTIL_H
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "mbedtls/config.h"
#include "mbedtls/sha256.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/pk.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/aes.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"
#include "mbedtls/md.h"
#include "mbedtls/ecdh.h"

#define mbedtls_free       free
#define mbedtls_printf          printf


void print_hex(const char *title, const unsigned char buf[], size_t len);
char *bytes_to_hex( const uint8_t bin[], size_t len );

#endif //MBEDTLS_DEMO_COMPLETE_UTIL_H

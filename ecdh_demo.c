//
// Created by root on 2/23/19.
//

//
// Created by root on 2/22/19.
//
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf          printf
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if !defined(MBEDTLS_ECDH_C) || \
    !defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf( "MBEDTLS_ECDH_C and/or "
                    "MBEDTLS_ECP_DP_CURVE25519_ENABLED and/or "
                    "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C "
                    "not defined\n" );
    return( 0 );
}
#else

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"

#include "util.h"

//Using MBEDTLS_ECP_DP_SECP256R1
int main(int argc, char *argv[]) {
    //First method: Generate keypair each time
    size_t olen, olen2;
    unsigned char buf[256];
    unsigned char buf2[256];

    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_ecdh_context ctx_cli, ctx_srv;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char cli_to_srv[32], srv_to_cli[32];
    const char pers[] = "ecdh";
    ((void) argc);
    ((void) argv);

    memset(buf, 0, sizeof(buf));
    mbedtls_ecdh_init( &ctx_cli );
    mbedtls_ecdh_init( &ctx_srv );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    mbedtls_printf( "  . Seeding the random number generator..." );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                       (const unsigned char *) pers,
                                       sizeof pers ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
    }

    mbedtls_printf( " ok\n" );

    ret = mbedtls_ecdh_setup(&ctx_cli, MBEDTLS_ECP_DP_SECP256R1);
    ret = mbedtls_ecdh_setup(&ctx_srv, MBEDTLS_ECP_DP_SECP256R1);
    ret = mbedtls_ecdh_make_params(&ctx_srv, &olen, buf, sizeof buf, mbedtls_ctr_drbg_random, &ctr_drbg);
    printf("ret make params = %x\n", -ret);
    printf("client read params\n");
    // client read params and make public params
    const unsigned char * buf_ptr = buf;
    ret = mbedtls_ecdh_read_params(&ctx_cli, &buf_ptr, buf_ptr+olen);

    printf("ret read params = %x\n", -ret);
    printf("client make public\n");
    ret = mbedtls_ecdh_make_public(&ctx_cli, &olen, buf, 256, mbedtls_ctr_drbg_random, &ctr_drbg);
    ret = mbedtls_ecdh_calc_secret(&ctx_cli, &olen2, buf2, 256, mbedtls_ctr_drbg_random, &ctr_drbg);
    printf("ret make public = %x\n", -ret);
    // server read public and calc secret
    printf("server read and calc\n");
    ret = mbedtls_ecdh_read_public(&ctx_srv, buf, olen);
    for(size_t i = 0; i < 5; i++)
        ret = mbedtls_ecdh_calc_secret(&ctx_srv, &olen, buf, 256, mbedtls_ctr_drbg_random, &ctr_drbg);

    printf("server secret key: 0x");
    for(size_t i = 0; i < olen; i++) {
        printf("%x", buf[i]);
    }
    printf("\n");
    printf("client secret key: 0x");
    for(size_t i = 0; i < olen2; i++) {
        printf("%x", buf2[i]);
    }
    printf("\n");
    printf("\n");


    //Another method: load keypair from file
    //note: Use ecc_key_gen to generate keypair file first
    unsigned char buf_file[256];
    unsigned char buf_file2[256];
    mbedtls_pk_context pk, pk_cli;
    memset(buf_file, 0, sizeof(buf_file));
    memset(buf_file2, 0, sizeof(buf_file2));
    mbedtls_pk_init( &pk );
    mbedtls_pk_init( &pk_cli );
    mbedtls_pk_parse_keyfile( &pk, "privatekey.txt", NULL );
    mbedtls_pk_parse_public_keyfile( &pk, "publickey.txt" );
    mbedtls_pk_parse_keyfile( &pk_cli, "privatekey_cli.txt", NULL );
    mbedtls_pk_parse_public_keyfile( &pk_cli, "publickey_cli.txt" );
    mbedtls_ecdh_context ctx_cli_file, ctx_srv_file;
    mbedtls_ecdh_init( &ctx_cli_file );
    mbedtls_ecdh_init( &ctx_srv_file );
    ret = mbedtls_ecdh_setup(&ctx_cli_file, MBEDTLS_ECP_DP_SECP256R1);
    ret = mbedtls_ecdh_setup(&ctx_srv_file, MBEDTLS_ECP_DP_SECP256R1);
    ret = mbedtls_ecdh_get_params(&ctx_srv_file, mbedtls_pk_ec(pk), MBEDTLS_ECDH_OURS);
    ret = mbedtls_ecdh_get_params(&ctx_srv_file, mbedtls_pk_ec(pk_cli), MBEDTLS_ECDH_THEIRS);

    ret = mbedtls_ecdh_get_params(&ctx_cli_file, mbedtls_pk_ec(pk_cli), MBEDTLS_ECDH_OURS);
    ret = mbedtls_ecdh_get_params(&ctx_cli_file, mbedtls_pk_ec(pk), MBEDTLS_ECDH_THEIRS);
    ret = mbedtls_ecdh_calc_secret(&ctx_cli_file, &olen2, buf_file2, 256, mbedtls_ctr_drbg_random, &ctr_drbg);
    ret = mbedtls_ecdh_calc_secret(&ctx_srv_file, &olen, buf_file, 256, mbedtls_ctr_drbg_random, &ctr_drbg);

    printf("Using this method, the generated key is the same\n");
    printf("server secret key: 0x");
    for(size_t i = 0; i < olen; i++) {
        printf("%x", buf_file[i]);
    }
    printf("\n");
    printf("client secret key: 0x");
    for(size_t i = 0; i < olen2; i++) {
        printf("%x", buf_file2[i]);
    }
    return 0;
}

#endif /* MBEDTLS_ECDH_C && MBEDTLS_ECP_DP_CURVE25519_ENABLED &&
          MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C */

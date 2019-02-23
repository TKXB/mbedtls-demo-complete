//
// Created by root on 2/23/19.
//
#include "util.h"

static int myrand( void *rng_state, unsigned char *output, size_t len )
{
    size_t use_len;
    int rnd;

    if( rng_state != NULL )
        rng_state  = NULL;

    while( len > 0 )
    {
        use_len = len;
        if( use_len > sizeof(int) )
            use_len = sizeof(int);

        rnd = rand();
        memcpy( output, &rnd, use_len );
        output += use_len;
        len -= use_len;
    }

    return( 0 );
}

void ecp_clear_precomputed( mbedtls_ecp_group *grp )
{
    if( grp->T != NULL )
    {
        size_t i;
        for( i = 0; i < grp->T_size; i++ )
            mbedtls_ecp_point_free( &grp->T[i] );
        mbedtls_free( grp->T );
    }
    grp->T = NULL;
    grp->T_size = 0;
}

//Use ecc_key_gen to generate keypair file first
int main(){
    //the same curve as ecc_key_gen use
    const mbedtls_ecp_curve_info *curve_info;
    curve_info = mbedtls_ecp_curve_info_from_grp_id(MBEDTLS_ECP_DP_SECP256R1);

    //load key
    mbedtls_pk_context pk;
    mbedtls_pk_init( &pk );
    mbedtls_pk_parse_keyfile( &pk, "privatekey.txt", NULL );
    mbedtls_pk_parse_public_keyfile( &pk, "publickey.txt" );

    //ecdsa
    mbedtls_ecdsa_context mbedtlsEcdsaContext;
    size_t sig_len;
    unsigned char tmp[200];
    unsigned char buf[64];
    memset(buf, 0x2A, sizeof(buf));
    strcpy((char *)buf, "hello world"); //just fill with something other than 0x2A
    mbedtls_ecdsa_init(&mbedtlsEcdsaContext);
    mbedtls_ecdsa_from_keypair(&mbedtlsEcdsaContext, mbedtls_pk_ec(pk));

    int ret_write_sign = mbedtls_ecdsa_write_signature(&mbedtlsEcdsaContext, MBEDTLS_MD_SHA256, buf, curve_info->bit_size, tmp, &sig_len, myrand, NULL);
    ecp_clear_precomputed( &mbedtlsEcdsaContext.grp );
    int ret_verify = mbedtls_ecdsa_read_signature(&mbedtlsEcdsaContext, buf, curve_info->bit_size, tmp, sig_len);
    printf("ret_verify = %d\n", ret_verify);
    return 0;
}


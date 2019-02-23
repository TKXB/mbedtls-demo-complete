//
// Created by root on 2/23/19.
//
#include "util.h"

static int write_private_key_pem( mbedtls_pk_context *key, const char *output_file )
{
    int ret;
    FILE *f;
    unsigned char output_buf[16000];
    unsigned char *c = output_buf;
    size_t len = 0;

    memset(output_buf, 0, 16000);
    if( ( ret = mbedtls_pk_write_key_pem( key, output_buf, 16000 ) ) != 0 )
        return( ret );

    len = strlen( (char *) output_buf );

    if( ( f = fopen( output_file, "wb" ) ) == NULL )
        return( -1 );

    if( fwrite( c, 1, len, f ) != len )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );

    return( 0 );
}

static int write_public_key_pem( mbedtls_pk_context *key, const char *output_file )
{
    int ret;
    FILE *f;
    unsigned char output_buf[16000];
    unsigned char *c = output_buf;
    size_t len = 0;

    memset(output_buf, 0, 16000);

    if( ( ret = mbedtls_pk_write_pubkey_pem( key, output_buf, 16000 ) ) != 0 )
        return( ret );

    len = strlen( (char *) output_buf );


    if( ( f = fopen( output_file, "w" ) ) == NULL )
        return( -1 );

    if( fwrite( c, 1, len, f ) != len )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );

    return( 0 );
}

int main(){
    int ret;
    mbedtls_pk_context mbedtlsPkContext;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    const mbedtls_ecp_curve_info *curve_info;

    //initialization
    mbedtls_pk_init(&mbedtlsPkContext);
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init(&entropy);
    const char *pers = "gen_key";
    mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,(const unsigned char *) pers,
                           strlen( pers ) );
    //use curve SECP256R1
    curve_info = mbedtls_ecp_curve_info_from_grp_id(MBEDTLS_ECP_DP_SECP256R1);

    //generate ECC key pair
    ret = mbedtls_pk_setup(&mbedtlsPkContext, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    ret = mbedtls_ecp_gen_key(curve_info->grp_id, mbedtls_pk_ec(mbedtlsPkContext), mbedtls_ctr_drbg_random, &ctr_drbg);
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_ecp_gen_key returned -0x%04x", -ret );
    }

    //print key pair
    mbedtls_ecp_keypair *ecp = mbedtls_pk_ec( mbedtlsPkContext );
    mbedtls_printf( "curve: %s\n",
                    mbedtls_ecp_curve_info_from_grp_id( ecp->grp.id )->name );
    mbedtls_mpi_write_file( "X_Q:   ", &ecp->Q.X, 16, NULL );
    mbedtls_mpi_write_file( "Y_Q:   ", &ecp->Q.Y, 16, NULL );
    mbedtls_mpi_write_file( "D:     ", &ecp->d  , 16, NULL );

    //write key pair to file using pem format
    write_public_key_pem(&mbedtlsPkContext, "publickey.txt");
    write_private_key_pem(&mbedtlsPkContext, "privatekey.txt");
}


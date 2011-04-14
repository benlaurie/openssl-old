/* ====================================================================
 * Copyright (c) 2003 The OpenSSL Project.  All rights reserved.
 *
 *
 * This command is intended as a test driver for the FIPS-140 testing
 * lab performing FIPS-140 validation.  It demonstrates the use of the
 * OpenSSL library ito perform a variety of common cryptographic
 * functions.  A power-up self test is demonstrated by deliberately
 * pointing to an invalid executable hash
 *
 * Contributed by Steve Marquess.
 *
 */

#define OPENSSL_FIPSAPI

#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include <openssl/bn.h>
#include <openssl/rand.h>

#ifndef OPENSSL_FIPS
int main(int argc, char *argv[])
    {
    printf("No FIPS support\n");
    return(0);
    }
#else

#define ERR_clear_error() while(0)

#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>

#include <openssl/fips.h>
#include "fips_utl.h"

/* AES: encrypt and decrypt known plaintext, verify result matches original plaintext
*/
static int FIPS_aes_test(void)
	{
	int ret = 0;
	unsigned char pltmp[16];
	unsigned char citmp[16];
	unsigned char key[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
	unsigned char plaintext[16] = "etaonrishdlcu";
	EVP_CIPHER_CTX ctx;
	FIPS_cipher_ctx_init(&ctx);
	if (FIPS_cipherinit(&ctx, EVP_aes_128_ecb(), key, NULL, 1) <= 0)
		goto err;
	FIPS_cipher(&ctx, citmp, plaintext, 16);
	if (FIPS_cipherinit(&ctx, EVP_aes_128_ecb(), key, NULL, 0) <= 0)
		goto err;
	FIPS_cipher(&ctx, pltmp, citmp, 16);
	if (memcmp(pltmp, plaintext, 16))
		goto err;
	ret = 1;
	err:
	FIPS_cipher_ctx_cleanup(&ctx);
	return ret;
	}

static int FIPS_aes_gcm_test(void)
	{
	int ret = 0;
	unsigned char pltmp[16];
	unsigned char citmp[16];
	unsigned char tagtmp[16];
	unsigned char key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
	unsigned char iv[16] = {21,22,23,24,25,26,27,28,29,30,31,32};
	unsigned char aad[] = "Some text AAD";
	unsigned char plaintext[16] = "etaonrishdlcu";
	EVP_CIPHER_CTX ctx;
	FIPS_cipher_ctx_init(&ctx);
	if (FIPS_cipherinit(&ctx, EVP_aes_128_gcm(), key, iv, 1) <= 0)
		goto err;
	FIPS_cipher(&ctx, NULL, aad, sizeof(aad));
	FIPS_cipher(&ctx, citmp, plaintext, 16);
	FIPS_cipher(&ctx, NULL, NULL, 0);
	if (!FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_GCM_GET_TAG, 16, tagtmp))
		goto err;

	if (FIPS_cipherinit(&ctx, EVP_aes_128_gcm(), key, iv, 0) <= 0)
		goto err;
	if (!FIPS_cipher_ctx_ctrl(&ctx, EVP_CTRL_GCM_SET_TAG, 16, tagtmp))
		goto err;

	FIPS_cipher(&ctx, NULL, aad, sizeof(aad));

	FIPS_cipher(&ctx, pltmp, citmp, 16);

	if (FIPS_cipher(&ctx, NULL, NULL, 0) < 0)
		goto err;

	if (memcmp(pltmp, plaintext, 16))
		goto err;

	ret = 1;
	err:
	FIPS_cipher_ctx_cleanup(&ctx);
	return ret;
	}

static int FIPS_des3_test(void)
	{
	int ret = 0;
	unsigned char pltmp[8];
	unsigned char citmp[8];
    	unsigned char key[] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,
		              19,20,21,22,23,24};
    	unsigned char plaintext[] = { 'e', 't', 'a', 'o', 'n', 'r', 'i', 's' };
	EVP_CIPHER_CTX ctx;
	FIPS_cipher_ctx_init(&ctx);
	if (FIPS_cipherinit(&ctx, EVP_des_ede3_ecb(), key, NULL, 1) <= 0)
		goto err;
	FIPS_cipher(&ctx, citmp, plaintext, 8);
	if (FIPS_cipherinit(&ctx, EVP_des_ede3_ecb(), key, NULL, 0) <= 0)
		goto err;
	FIPS_cipher(&ctx, pltmp, citmp, 8);
	if (memcmp(pltmp, plaintext, 8))
		goto err;
	ret = 1;
	err:
	FIPS_cipher_ctx_cleanup(&ctx);
	return ret;
	}

/*
 * DSA: generate keys and sign, verify input plaintext.
 */
static int FIPS_dsa_test(int bad)
    {
    DSA *dsa = NULL;
    unsigned char dgst[] = "etaonrishdlc";
    int r = 0;
    EVP_MD_CTX mctx;
    DSA_SIG *sig = NULL;

    ERR_clear_error();
    FIPS_md_ctx_init(&mctx);
    dsa = FIPS_dsa_new();
    if (!dsa)
	goto end;
    if (!DSA_generate_parameters_ex(dsa, 1024,NULL,0,NULL,NULL,NULL))
	goto end;
    if (!DSA_generate_key(dsa))
	goto end;
    if (bad)
	    BN_add_word(dsa->pub_key, 1);

    if (!FIPS_digestinit(&mctx, EVP_sha256()))
	goto end;
    if (!FIPS_digestupdate(&mctx, dgst, sizeof(dgst) - 1))
	goto end;
    sig = FIPS_dsa_sign_ctx(dsa, &mctx);
    if (!sig)
	goto end;

    if (!FIPS_digestinit(&mctx, EVP_sha256()))
	goto end;
    if (!FIPS_digestupdate(&mctx, dgst, sizeof(dgst) - 1))
	goto end;
    r = FIPS_dsa_verify_ctx(dsa, &mctx, sig);
    end:
    if (sig)
	FIPS_dsa_sig_free(sig);
    FIPS_md_ctx_cleanup(&mctx);
    if (dsa)
  	  FIPS_dsa_free(dsa);
    if (r != 1)
	return 0;
    return 1;
    }

/*
 * RSA: generate keys and sign, verify input plaintext.
 */
static int FIPS_rsa_test(int bad)
    {
    RSA *key;
    unsigned char input_ptext[] = "etaonrishdlc";
    unsigned char buf[256];
    unsigned int slen;
    BIGNUM *bn;
    EVP_MD_CTX mctx;
    int r = 0;

    ERR_clear_error();
    FIPS_md_ctx_init(&mctx);
    key = FIPS_rsa_new();
    bn = BN_new();
    if (!key || !bn)
	return 0;
    BN_set_word(bn, 65537);
    if (!RSA_generate_key_ex(key, 2048,bn,NULL))
	return 0;
    BN_free(bn);
    if (bad)
	    BN_add_word(key->n, 1);

    if (!FIPS_digestinit(&mctx, EVP_sha256()))
	goto end;
    if (!FIPS_digestupdate(&mctx, input_ptext, sizeof(input_ptext) - 1))
	goto end;
    if (!FIPS_rsa_sign_ctx(key, &mctx, RSA_PKCS1_PADDING, 0, NULL, buf, &slen))
	goto end;

    if (!FIPS_digestinit(&mctx, EVP_sha256()))
	goto end;
    if (!FIPS_digestupdate(&mctx, input_ptext, sizeof(input_ptext) - 1))
	goto end;
    r = FIPS_rsa_verify_ctx(key, &mctx, RSA_PKCS1_PADDING, 0, NULL, buf, slen);
    end:
    FIPS_md_ctx_cleanup(&mctx);
    if (key)
  	  FIPS_rsa_free(key);
    if (r != 1)
	return 0;
    return 1;
    }

/* SHA1: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_sha1_test()
    {
    unsigned char digest[SHA_DIGEST_LENGTH] =
        { 0x11, 0xf1, 0x9a, 0x3a, 0xec, 0x1a, 0x1e, 0x8e, 0x65, 0xd4, 0x9a, 0x38, 0x0c, 0x8b, 0x1e, 0x2c, 0xe8, 0xb3, 0xc5, 0x18 };
    unsigned char str[] = "etaonrishd";

    unsigned char md[SHA_DIGEST_LENGTH];

    ERR_clear_error();
    if (!FIPS_digest(str,sizeof(str) - 1,md, NULL, EVP_sha1())) return 0;
    if (memcmp(md,digest,sizeof(md)))
        return 0;
    return 1;
    }

/* SHA256: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_sha256_test()
    {
    unsigned char digest[SHA256_DIGEST_LENGTH] =
	{0xf5, 0x53, 0xcd, 0xb8, 0xcf, 0x1, 0xee, 0x17, 0x9b, 0x93, 0xc9, 0x68, 0xc0, 0xea, 0x40, 0x91,
	 0x6, 0xec, 0x8e, 0x11, 0x96, 0xc8, 0x5d, 0x1c, 0xaf, 0x64, 0x22, 0xe6, 0x50, 0x4f, 0x47, 0x57};
    unsigned char str[] = "etaonrishd";

    unsigned char md[SHA256_DIGEST_LENGTH];

    ERR_clear_error();
    if (!FIPS_digest(str,sizeof(str) - 1,md, NULL, EVP_sha256())) return 0;
    if (memcmp(md,digest,sizeof(md)))
        return 0;
    return 1;
    }

/* SHA512: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_sha512_test()
    {
    unsigned char digest[SHA512_DIGEST_LENGTH] =
	{0x99, 0xc9, 0xe9, 0x5b, 0x88, 0xd4, 0x78, 0x88, 0xdf, 0x88, 0x5f, 0x94, 0x71, 0x64, 0x28, 0xca,
	 0x16, 0x1f, 0x3d, 0xf4, 0x1f, 0xf3, 0x0f, 0xc5, 0x03, 0x99, 0xb2, 0xd0, 0xe7, 0x0b, 0x94, 0x4a,
	 0x45, 0xd2, 0x6c, 0x4f, 0x20, 0x06, 0xef, 0x71, 0xa9, 0x25, 0x7f, 0x24, 0xb1, 0xd9, 0x40, 0x22,
	 0x49, 0x54, 0x10, 0xc2, 0x22, 0x9d, 0x27, 0xfe, 0xbd, 0xd6, 0xd6, 0xeb, 0x2d, 0x42, 0x1d, 0xa3};
    unsigned char str[] = "etaonrishd";

    unsigned char md[SHA512_DIGEST_LENGTH];

    ERR_clear_error();
    if (!FIPS_digest(str,sizeof(str) - 1,md, NULL, EVP_sha512())) return 0;
    if (memcmp(md,digest,sizeof(md)))
        return 0;
    return 1;
    }

/* HMAC-SHA1: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_hmac_sha1_test()
    {
    unsigned char key[] = "etaonrishd";
    unsigned char iv[] = "Sample text";
    unsigned char kaval[EVP_MAX_MD_SIZE] =
	{0x73, 0xf7, 0xa0, 0x48, 0xf8, 0x94, 0xed, 0xdd, 0x0a, 0xea, 0xea, 0x56, 0x1b, 0x61, 0x2e, 0x70,
	 0xb2, 0xfb, 0xec, 0xc6};

    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen;

    ERR_clear_error();
    if (!HMAC(EVP_sha1(),key,sizeof(key)-1,iv,sizeof(iv)-1,out,&outlen)) return 0;
    if (memcmp(out,kaval,outlen))
        return 0;
    return 1;
    }

/* HMAC-SHA224: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_hmac_sha224_test()
    {
    unsigned char key[] = "etaonrishd";
    unsigned char iv[] = "Sample text";
    unsigned char kaval[EVP_MAX_MD_SIZE] =
	{0x75, 0x58, 0xd5, 0xbd, 0x55, 0x6d, 0x87, 0x0f, 0x75, 0xff, 0xbe, 0x1c, 0xb2, 0xf0, 0x20, 0x35,
	 0xe5, 0x62, 0x49, 0xb6, 0x94, 0xb9, 0xfc, 0x65, 0x34, 0x33, 0x3a, 0x19};

    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen;

    ERR_clear_error();
    if (!HMAC(EVP_sha224(),key,sizeof(key)-1,iv,sizeof(iv)-1,out,&outlen)) return 0;
    if (memcmp(out,kaval,outlen))
        return 0;
    return 1;
    }

/* HMAC-SHA256: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_hmac_sha256_test()
    {
    unsigned char key[] = "etaonrishd";
    unsigned char iv[] = "Sample text";
    unsigned char kaval[EVP_MAX_MD_SIZE] =
	{0xe9, 0x17, 0xc1, 0x7b, 0x4c, 0x6b, 0x77, 0xda, 0xd2, 0x30, 0x36, 0x02, 0xf5, 0x72, 0x33, 0x87,
	 0x9f, 0xc6, 0x6e, 0x7b, 0x7e, 0xa8, 0xea, 0xaa, 0x9f, 0xba, 0xee, 0x51, 0xff, 0xda, 0x24, 0xf4};

    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen;

    ERR_clear_error();
    if (!HMAC(EVP_sha256(),key,sizeof(key)-1,iv,sizeof(iv)-1,out,&outlen)) return 0;
    if (memcmp(out,kaval,outlen))
        return 0;
    return 1;
    }

/* HMAC-SHA384: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_hmac_sha384_test()
    {
    unsigned char key[] = "etaonrishd";
    unsigned char iv[] = "Sample text";
    unsigned char kaval[EVP_MAX_MD_SIZE] =
	{0xb2, 0x9d, 0x40, 0x58, 0x32, 0xc4, 0xe3, 0x31, 0xb6, 0x63, 0x08, 0x26, 0x99, 0xef, 0x3b, 0x10,
	 0xe2, 0xdf, 0xf8, 0xff, 0xc6, 0xe1, 0x03, 0x29, 0x81, 0x2a, 0x1b, 0xac, 0xb0, 0x07, 0x39, 0x08,
	 0xf3, 0x91, 0x35, 0x11, 0x76, 0xd6, 0x4c, 0x20, 0xfb, 0x4d, 0xc3, 0xf3, 0xb8, 0x9b, 0x88, 0x1c};

    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen;

    ERR_clear_error();
    if (!HMAC(EVP_sha384(),key,sizeof(key)-1,iv,sizeof(iv)-1,out,&outlen)) return 0;
    if (memcmp(out,kaval,outlen))
        return 0;
    return 1;
    }

/* HMAC-SHA512: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_hmac_sha512_test()
    {
    unsigned char key[] = "etaonrishd";
    unsigned char iv[] = "Sample text";
    unsigned char kaval[EVP_MAX_MD_SIZE] =
	{0xcd, 0x3e, 0xb9, 0x51, 0xb8, 0xbc, 0x7f, 0x9a, 0x23, 0xaf, 0xf3, 0x77, 0x59, 0x85, 0xa9, 0xe6,
	 0xf7, 0xd1, 0x51, 0x96, 0x17, 0xe0, 0x92, 0xd8, 0xa6, 0x3b, 0xc1, 0xad, 0x7e, 0x24, 0xca, 0xb1,
	 0xd7, 0x79, 0x0a, 0xa5, 0xea, 0x2c, 0x02, 0x58, 0x0b, 0xa6, 0x52, 0x6b, 0x61, 0x7f, 0xeb, 0x9c,
	 0x47, 0x86, 0x5d, 0x74, 0x2b, 0x88, 0xdf, 0xee, 0x46, 0x69, 0x96, 0x3d, 0xa6, 0xd9, 0x2a, 0x53};

    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen;

    ERR_clear_error();
    if (!HMAC(EVP_sha512(),key,sizeof(key)-1,iv,sizeof(iv)-1,out,&outlen)) return 0;
    if (memcmp(out,kaval,outlen))
        return 0;
    return 1;
    }

/* CMAC-AES128: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_cmac_aes128_test()
    {
    unsigned char key[16] = { 0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
			      0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c, };
    unsigned char data[] = "Sample text";
    unsigned char kaval[EVP_MAX_MD_SIZE] =
	    { 0x16,0x83,0xfe,0xac, 0x52,0x9b,0xae,0x23,
	      0xd7,0xd5,0x66,0xf5, 0xd2,0x8d,0xbd,0x2a, };

    unsigned char *out = NULL;
    size_t outlen;
    CMAC_CTX *ctx = CMAC_CTX_new();
    int r = 0;

    ERR_clear_error();

    if (!ctx)
	    goto end;
    if (!CMAC_Init(ctx,key,sizeof(key),EVP_aes_128_cbc(),NULL))
	    goto end;
    if (!CMAC_Update(ctx,data,sizeof(data)-1))
	    goto end;
    /* This should return 1.  If not, there's a programming error... */
    if (!CMAC_Final(ctx, out, &outlen))
	    goto end;
    out = OPENSSL_malloc(outlen);
    if (!CMAC_Final(ctx, out, &outlen))
	    goto end;
#if 0
    {
    char *hexout = OPENSSL_malloc(outlen * 2 + 1);
    bin2hex(out, outlen, hexout);
    printf("CMAC-AES128: res = %s\n", hexout);
    OPENSSL_free(hexout);
    }
    r = 1;
#else
    if (!memcmp(out,kaval,outlen))
	    r = 1;
#endif
    end:
    CMAC_CTX_free(ctx);
    if (out)
  	  OPENSSL_free(out);
    return r;
    }

/* CMAC-AES192: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_cmac_aes192_test()
    {
    unsigned char key[] = { 0x8e,0x73,0xb0,0xf7, 0xda,0x0e,0x64,0x52,
			    0xc8,0x10,0xf3,0x2b, 0x80,0x90,0x79,0xe5,
			    0x62,0xf8,0xea,0xd2, 0x52,0x2c,0x6b,0x7b, };
    unsigned char data[] = "Sample text";
    unsigned char kaval[] =
	    { 0xd6,0x99,0x19,0x25, 0xe5,0x1d,0x95,0x48,
	      0xb1,0x4a,0x0b,0xf2, 0xc6,0x3c,0x47,0x1f, };

    unsigned char *out = NULL;
    size_t outlen;
    CMAC_CTX *ctx = CMAC_CTX_new();
    int r = 0;

    ERR_clear_error();

    if (!ctx)
	    goto end;
    if (!CMAC_Init(ctx,key,sizeof(key),EVP_aes_192_cbc(),NULL))
	    goto end;
    if (!CMAC_Update(ctx,data,sizeof(data)-1))
	    goto end;
    /* This should return 1.  If not, there's a programming error... */
    if (!CMAC_Final(ctx, out, &outlen))
	    goto end;
    out = OPENSSL_malloc(outlen);
    if (!CMAC_Final(ctx, out, &outlen))
	    goto end;
#if 0
    {
    char *hexout = OPENSSL_malloc(outlen * 2 + 1);
    bin2hex(out, outlen, hexout);
    printf("CMAC-AES192: res = %s\n", hexout);
    OPENSSL_free(hexout);
    }
    r = 1;
#else
    if (!memcmp(out,kaval,outlen))
	    r = 1;
#endif
    end:
    CMAC_CTX_free(ctx);
    if (out)
  	  OPENSSL_free(out);
    return r;
    }

/* CMAC-AES256: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_cmac_aes256_test()
    {
    unsigned char key[] = { 0x60,0x3d,0xeb,0x10, 0x15,0xca,0x71,0xbe,
			    0x2b,0x73,0xae,0xf0, 0x85,0x7d,0x77,0x81,
			    0x1f,0x35,0x2c,0x07, 0x3b,0x61,0x08,0xd7,
			    0x2d,0x98,0x10,0xa3, 0x09,0x14,0xdf,0xf4, };
    unsigned char data[] = "Sample text";
    unsigned char kaval[] =
	    { 0xec,0xc2,0xcf,0x63, 0xc7,0xce,0xfc,0xa4,
	      0xb0,0x86,0x37,0x5f, 0x15,0x60,0xba,0x1f, };

    unsigned char *out = NULL;
    size_t outlen;
    CMAC_CTX *ctx = CMAC_CTX_new();
    int r = 0;

    ERR_clear_error();

    if (!ctx)
	    goto end;
    if (!CMAC_Init(ctx,key,sizeof(key),EVP_aes_256_cbc(),NULL))
	    goto end;
    if (!CMAC_Update(ctx,data,sizeof(data)-1))
	    goto end;
    /* This should return 1.  If not, there's a programming error... */
    if (!CMAC_Final(ctx, out, &outlen))
	    goto end;
    out = OPENSSL_malloc(outlen);
    if (!CMAC_Final(ctx, out, &outlen))
	    goto end;
#if 0
    {
    char *hexout = OPENSSL_malloc(outlen * 2 + 1);
    bin2hex(out, outlen, hexout);
    printf("CMAC-AES256: res = %s\n", hexout);
    OPENSSL_free(hexout);
    }
    r = 1;
#else
    if (!memcmp(out,kaval,outlen))
	    r = 1;
#endif
    end:
    CMAC_CTX_free(ctx);
    if (out)
  	  OPENSSL_free(out);
    return r;
    }

/* CMAC-TDEA3: generate hash of known digest value and compare to known
   precomputed correct hash
*/
static int FIPS_cmac_tdea3_test()
    {
    unsigned char key[] = { 0x8a,0xa8,0x3b,0xf8, 0xcb,0xda,0x10,0x62,
			    0x0b,0xc1,0xbf,0x19, 0xfb,0xb6,0xcd,0x58,
			    0xbc,0x31,0x3d,0x4a, 0x37,0x1c,0xa8,0xb5, };
    unsigned char data[] = "Sample text";
    unsigned char kaval[EVP_MAX_MD_SIZE] =
	    { 0xb4,0x06,0x4e,0xbf, 0x59,0x89,0xba,0x68, };

    unsigned char *out = NULL;
    size_t outlen;
    CMAC_CTX *ctx = CMAC_CTX_new();
    int r = 0;

    ERR_clear_error();

    if (!ctx)
	    goto end;
    if (!CMAC_Init(ctx,key,sizeof(key),EVP_des_ede3_cbc(),NULL))
	    goto end;
    if (!CMAC_Update(ctx,data,sizeof(data)-1))
	    goto end;
    /* This should return 1.  If not, there's a programming error... */
    if (!CMAC_Final(ctx, out, &outlen))
	    goto end;
    out = OPENSSL_malloc(outlen);
    if (!CMAC_Final(ctx, out, &outlen))
	    goto end;
#if 0
    {
    char *hexout = OPENSSL_malloc(outlen * 2 + 1);
    bin2hex(out, outlen, hexout);
    printf("CMAC-TDEA3: res = %s\n", hexout);
    OPENSSL_free(hexout);
    }
    r = 1;
#else
    if (!memcmp(out,kaval,outlen))
	    r = 1;
#endif
    end:
    CMAC_CTX_free(ctx);
    if (out)
  	  OPENSSL_free(out);
    return r;
    }


/* DH: generate shared parameters
*/
static int dh_test()
    {
    DH *dh;
    ERR_clear_error();
    dh = FIPS_dh_new();
    if (!dh)
	return 0;
    if (!DH_generate_parameters_ex(dh, 1024, 2, NULL))
	return 0;
    FIPS_dh_free(dh);
    return 1;
    }

/* Zeroize
*/
static int Zeroize()
    {
    RSA *key;
    BIGNUM *bn;
    unsigned char userkey[16] = 
	{ 0x48, 0x50, 0xf0, 0xa3, 0x3a, 0xed, 0xd3, 0xaf, 0x6e, 0x47, 0x7f, 0x83, 0x02, 0xb1, 0x09, 0x68 };
    size_t i;
    int n;

    key = FIPS_rsa_new();
    bn = BN_new();
    if (!key || !bn)
	return 0;
    BN_set_word(bn, 65537);
    if (!RSA_generate_key_ex(key, 1024,bn,NULL))
	return 0;
    BN_free(bn);
    
    n = BN_num_bytes(key->d);
    printf(" Generated %d byte RSA private key\n", n);
    printf("\tBN key before overwriting:\n");
    do_bn_print(stdout, key->d);
    BN_rand(key->d,n*8,-1,0);
    printf("\tBN key after overwriting:\n");
    do_bn_print(stdout, key->d);

    printf("\tchar buffer key before overwriting: \n\t\t");
    for(i = 0; i < sizeof(userkey); i++) printf("%02x", userkey[i]);
        printf("\n");
    RAND_bytes(userkey, sizeof userkey);
    printf("\tchar buffer key after overwriting: \n\t\t");
    for(i = 0; i < sizeof(userkey); i++) printf("%02x", userkey[i]);
        printf("\n");

    return 1;
    }

static int Error;
static const char * Fail(const char *msg)
    {
    Error++;
    return msg; 
    }

static void test_msg(const char *msg, int result)
	{
	printf("%s...%s\n", msg, result ? "successful" : Fail("Failed!"));
	}

static const char *post_get_sig(int id)
	{
	switch (id)
		{
		case EVP_PKEY_RSA:
		return " (RSA)";

		case EVP_PKEY_DSA:
		return " (DSA)";

		case EVP_PKEY_EC:
		return " (ECDSA)";

		default:
		return " (UNKNOWN)";

		}
	}

static const char *post_get_cipher(int id)
	{
	static char out[128];
	switch(id)
		{

		case NID_aes_128_ecb:
		return " (AES-128-ECB)";

		case NID_des_ede3_ecb:
		return " (DES-EDE3-ECB)";
		
		default:
		sprintf(out, " (NID=%d)", id);
		return out;

		}
	}

static int fail_id = -1;
static int fail_sub = -1;
static int fail_key = -1;

static int post_cb(int op, int id, int subid, void *ex)
	{
	const char *idstr, *exstr = "";
	int keytype = -1;
	switch(id)
		{
		case FIPS_TEST_INTEGRITY:
		idstr = "Integrity";
		break;

		case FIPS_TEST_DIGEST:
		idstr = "Digest";
		if (subid == NID_sha1)
			exstr = " (SHA1)";
		break;

		case FIPS_TEST_CIPHER:
		exstr = post_get_cipher(subid);
		idstr = "Cipher";
		break;

		case FIPS_TEST_SIGNATURE:
		if (ex)
			{
			EVP_PKEY *pkey = ex;
			keytype = pkey->type;
			exstr = post_get_sig(keytype);
			}
		idstr = "Signature";
		break;

		case FIPS_TEST_HMAC:
		idstr = "HMAC";
		break;

		case FIPS_TEST_CMAC:
		idstr = "CMAC";
		break;

		case FIPS_TEST_GCM:
		idstr = "HMAC";
		break;

		case FIPS_TEST_CCM:
		idstr = "HMAC";
		break;

		case FIPS_TEST_XTS:
		idstr = "HMAC";
		break;

		case FIPS_TEST_X931:
		idstr = "X9.31 PRNG";
		break;

		case FIPS_TEST_DRBG:
		idstr = "DRBG";
		break;

		case FIPS_TEST_PAIRWISE:
		if (ex)
			{
			EVP_PKEY *pkey = ex;
			keytype = pkey->type;
			exstr = post_get_sig(keytype);
			}
		idstr = "Pairwise Consistency";
		break;

		case FIPS_TEST_CONTINUOUS:
		idstr = "Continuous PRNG";
		break;

		default:
		idstr = "Unknown";
		break;

		}

	switch(op)
		{
		case FIPS_POST_BEGIN:
		printf("\tPOST started\n");
		break;

		case FIPS_POST_END:
		printf("\tPOST %s\n", id ? "Success" : "Failed");
		break;

		case FIPS_POST_STARTED:
		printf("\t\t%s%s test started\n", idstr, exstr);
		break;

		case FIPS_POST_SUCCESS:
		printf("\t\t%s%s test OK\n", idstr, exstr);
		break;

		case FIPS_POST_FAIL:
		printf("\t\t%s%s test FAILED!!\n", idstr, exstr);
		break;

		case FIPS_POST_CORRUPT:
		if (fail_id == id
			&& (fail_key == -1 || fail_key == keytype)
			&& (fail_sub == -1 || fail_sub == subid))
			{
			printf("\t\t%s%s test failure induced\n", idstr, exstr);
			return 0;
			}
		break;

		}
	return 1;
	}



int main(int argc,char **argv)
    {
    int bad_rsa = 0, bad_dsa = 0;
    int do_rng_stick = 0;
    int do_drbg_stick = 0;
    int no_exit = 0;

    fips_algtest_init_nofips();

    FIPS_post_set_callback(post_cb);

    printf("\tFIPS-mode test application\n\n");

    if (argv[1]) {
        /* Corrupted KAT tests */
        if (!strcmp(argv[1], "integrity")) {
	    fail_id = FIPS_TEST_INTEGRITY;
        } else if (!strcmp(argv[1], "aes")) {
	    fail_id = FIPS_TEST_CIPHER;
	    fail_sub = NID_aes_128_ecb;	
        } else if (!strcmp(argv[1], "aes-gcm")) {
	    fail_id = FIPS_TEST_GCM;
        } else if (!strcmp(argv[1], "des")) {
	    fail_id = FIPS_TEST_CIPHER;
	    fail_sub = NID_des_ede3_ecb;	
        } else if (!strcmp(argv[1], "dsa")) {
	    fail_id = FIPS_TEST_SIGNATURE;
	    fail_key = EVP_PKEY_DSA;	
        } else if (!strcmp(argv[1], "ecdsa")) {
	    fail_id = FIPS_TEST_SIGNATURE;
	    fail_key = EVP_PKEY_EC;	
        } else if (!strcmp(argv[1], "rsa")) {
	    fail_id = FIPS_TEST_SIGNATURE;
	    fail_key = EVP_PKEY_RSA;	
        } else if (!strcmp(argv[1], "rsakey")) {
            printf("RSA key generation and signature validation with corrupted key...\n");
	    bad_rsa = 1;
	    no_exit = 1;
        } else if (!strcmp(argv[1], "rsakeygen")) {
	    fail_id = FIPS_TEST_PAIRWISE;
	    fail_key = EVP_PKEY_RSA;
	    no_exit = 1;
        } else if (!strcmp(argv[1], "dsakey")) {
            printf("DSA key generation and signature validation with corrupted key...\n");
	    bad_dsa = 1;
	    no_exit = 1;
        } else if (!strcmp(argv[1], "dsakeygen")) {
	    fail_id = FIPS_TEST_PAIRWISE;
	    fail_key = EVP_PKEY_DSA;
	    no_exit = 1;
        } else if (!strcmp(argv[1], "sha1")) {
	    fail_id = FIPS_TEST_DIGEST;
        } else if (!strcmp(argv[1], "hmac")) {
	    fail_id = FIPS_TEST_HMAC;
	} else if (!strcmp(argv[1], "drbg")) {
	    FIPS_corrupt_drbg();
	} else if (!strcmp(argv[1], "rng")) {
	    FIPS_corrupt_x931();
	} else if (!strcmp(argv[1], "rngstick")) {
	    do_rng_stick = 1;
	    no_exit = 1;
	    printf("RNG test with stuck continuous test...\n");
	} else if (!strcmp(argv[1], "drbgstick")) {
	    do_drbg_stick = 1;
	    no_exit = 1;
	    printf("DRBG test with stuck continuous test...\n");
        } else {
            printf("Bad argument \"%s\"\n", argv[1]);
            exit(1);
        }
	if (!no_exit) {
        	if (!FIPS_mode_set(1)) {
        	    printf("Power-up self test failed\n");
		    exit(1);
		}
        	printf("Power-up self test successful\n");
        	exit(0);
	}
    }

    /* Non-Approved cryptographic operation
    */
    printf("1. Non-Approved cryptographic operation test...\n");
    test_msg("\ta. Included algorithm (D-H)...", dh_test());

    /* Power-up self test
    */
    ERR_clear_error();
    test_msg("2. Automatic power-up self test", FIPS_mode_set(1));
    if (!FIPS_mode())
	exit(1);
    if (do_drbg_stick)
            FIPS_drbg_stick();
    if (do_rng_stick)
            FIPS_x931_stick();

    /* AES encryption/decryption
    */
    test_msg("3a. AES encryption/decryption", FIPS_aes_test());
    /* AES GCM encryption/decryption
    */
    test_msg("3b. AES-GCM encryption/decryption", FIPS_aes_gcm_test());

    /* RSA key generation and encryption/decryption
    */
    test_msg("4. RSA key generation and encryption/decryption",
						FIPS_rsa_test(bad_rsa));

    /* DES-CBC encryption/decryption
    */
    test_msg("5. DES-ECB encryption/decryption", FIPS_des3_test());

    /* DSA key generation and signature validation
    */
    test_msg("6. DSA key generation and signature validation",
    						FIPS_dsa_test(bad_dsa));

    /* SHA-1 hash
    */
    test_msg("7a. SHA-1 hash", FIPS_sha1_test());

    /* SHA-256 hash
    */
    test_msg("7b. SHA-256 hash", FIPS_sha256_test());

    /* SHA-512 hash
    */
    test_msg("7c. SHA-512 hash", FIPS_sha512_test());

    /* HMAC-SHA-1 hash
    */
    test_msg("7d. HMAC-SHA-1 hash", FIPS_hmac_sha1_test());

    /* HMAC-SHA-224 hash
    */
    test_msg("7e. HMAC-SHA-224 hash", FIPS_hmac_sha224_test());

    /* HMAC-SHA-256 hash
    */
    test_msg("7f. HMAC-SHA-256 hash", FIPS_hmac_sha256_test());

    /* HMAC-SHA-384 hash
    */
    test_msg("7g. HMAC-SHA-384 hash", FIPS_hmac_sha384_test());

    /* HMAC-SHA-512 hash
    */
    test_msg("7h. HMAC-SHA-512 hash", FIPS_hmac_sha512_test());

    /* CMAC-AES-128 hash
    */
    test_msg("8a. CMAC-AES-128 hash", FIPS_cmac_aes128_test());

    /* CMAC-AES-192 hash
    */
    test_msg("8b. CMAC-AES-192 hash", FIPS_cmac_aes192_test());

    /* CMAC-AES-256 hash
    */
    test_msg("8c. CMAC-AES-256 hash", FIPS_cmac_aes256_test());

# if 0				/* Not a FIPS algorithm */
    /* CMAC-TDEA-2 hash
    */
    test_msg("8d. CMAC-TDEA-2 hash", FIPS_cmac_tdea2_test());
#endif

    /* CMAC-TDEA-3 hash
    */
    test_msg("8e. CMAC-TDEA-3 hash", FIPS_cmac_tdea3_test());

    /* Non-Approved cryptographic operation
    */
    printf("9. Non-Approved cryptographic operation test...\n");
    printf("\ta. Included algorithm (D-H)...%s\n",
    		dh_test() ? "successful as expected"
	    					: Fail("failed INCORRECTLY!") );

    /* Zeroization
    */
    printf("10. Zero-ization...\n\t%s\n",
    		Zeroize() ? "successful as expected"
					: Fail("failed INCORRECTLY!") );

    printf("\nAll tests completed with %d errors\n", Error);
    return Error ? 1 : 0;
    }

#endif

/* ====================================================================
 * Copyright (c) 2011 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#define OPENSSL_FIPSAPI

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/fips_rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ecdsa.h>
#include <string.h>
#include <limits.h>
#include "fips_locl.h"

#ifdef OPENSSL_FIPS

#include <openssl/fips.h>

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

static int fips_selftest_fail = 0;
static int fips_mode = 0;
static int fips_started = 0;

static int fips_is_owning_thread(void);
static int fips_set_owning_thread(void);
static int fips_clear_owning_thread(void);
static unsigned char *fips_signature_witness(void);

#define fips_w_lock()	CRYPTO_w_lock(CRYPTO_LOCK_FIPS)
#define fips_w_unlock()	CRYPTO_w_unlock(CRYPTO_LOCK_FIPS)
#define fips_r_lock()	CRYPTO_r_lock(CRYPTO_LOCK_FIPS)
#define fips_r_unlock()	CRYPTO_r_unlock(CRYPTO_LOCK_FIPS)

static void fips_set_mode(int onoff)
	{
	int owning_thread = fips_is_owning_thread();

	if (fips_started)
		{
		if (!owning_thread) fips_w_lock();
		fips_mode = onoff;
		if (!owning_thread) fips_w_unlock();
		}
	}

int FIPS_mode(void)
	{
	int ret = 0;
	int owning_thread = fips_is_owning_thread();

	if (fips_started)
		{
		if (!owning_thread) fips_r_lock();
		ret = fips_mode;
		if (!owning_thread) fips_r_unlock();
		}
	return ret;
	}

int FIPS_selftest_failed(void)
    {
    int ret = 0;
    if (fips_started)
	{
	int owning_thread = fips_is_owning_thread();

	if (!owning_thread) fips_r_lock();
	ret = fips_selftest_fail;
	if (!owning_thread) fips_r_unlock();
	}
    return ret;
    }

/* Selftest failure fatal exit routine. This will be called
 * during *any* cryptographic operation. It has the minimum
 * overhead possible to avoid too big a performance hit.
 */

void FIPS_selftest_check(void)
    {
    if (fips_selftest_fail)
	{
	OpenSSLDie(__FILE__,__LINE__, "FATAL FIPS SELFTEST FAILURE");
	}
    }

void fips_set_selftest_fail(void)
    {
    fips_selftest_fail = 1;
    }

int FIPS_selftest(void)
    {

    return FIPS_selftest_sha1()
	&& FIPS_selftest_hmac()
	&& FIPS_selftest_cmac()
	&& FIPS_selftest_aes()
	&& FIPS_selftest_aes_gcm()
	&& FIPS_selftest_des()
	&& FIPS_selftest_rsa()
	&& FIPS_selftest_ecdsa()
	&& FIPS_selftest_dsa();
    }

extern const void         *FIPS_text_start(),  *FIPS_text_end();
extern const unsigned char FIPS_rodata_start[], FIPS_rodata_end[];
unsigned char              FIPS_signature [20] = { 0 };
static const char          FIPS_hmac_key[]="etaonrishdlcupfm";

unsigned int FIPS_incore_fingerprint(unsigned char *sig,unsigned int len)
    {
    const unsigned char *p1 = FIPS_text_start();
    const unsigned char *p2 = FIPS_text_end();
    const unsigned char *p3 = FIPS_rodata_start;
    const unsigned char *p4 = FIPS_rodata_end;
    HMAC_CTX c;

    HMAC_CTX_init(&c);
    HMAC_Init(&c,FIPS_hmac_key,strlen(FIPS_hmac_key),EVP_sha1());

    /* detect overlapping regions */
    if (p1<=p3 && p2>=p3)
	p3=p1, p4=p2>p4?p2:p4, p1=NULL, p2=NULL;
    else if (p3<=p1 && p4>=p1)
	p3=p3, p4=p2>p4?p2:p4, p1=NULL, p2=NULL;

    if (p1)
	HMAC_Update(&c,p1,(size_t)p2-(size_t)p1);

    if (FIPS_signature>=p3 && FIPS_signature<p4)
	{
	/* "punch" hole */
	HMAC_Update(&c,p3,(size_t)FIPS_signature-(size_t)p3);
	p3 = FIPS_signature+sizeof(FIPS_signature);
	if (p3<p4)
	    HMAC_Update(&c,p3,(size_t)p4-(size_t)p3);
	}
    else
	HMAC_Update(&c,p3,(size_t)p4-(size_t)p3);

    HMAC_Final(&c,sig,&len);
    HMAC_CTX_cleanup(&c);

    return len;
    }

int FIPS_check_incore_fingerprint(void)
    {
    unsigned char sig[EVP_MAX_MD_SIZE];
    unsigned int len;
#if defined(__sgi) && (defined(__mips) || defined(mips))
    extern int __dso_displacement[];
#else
    extern int OPENSSL_NONPIC_relocated;
#endif

    if (FIPS_text_start()==NULL)
	{
	FIPSerr(FIPS_F_FIPS_CHECK_INCORE_FINGERPRINT,FIPS_R_UNSUPPORTED_PLATFORM);
	return 0;
	}

    len=FIPS_incore_fingerprint (sig,sizeof(sig));

    if (len!=sizeof(FIPS_signature) ||
	memcmp(FIPS_signature,sig,sizeof(FIPS_signature)))
	{
	if (FIPS_signature>=FIPS_rodata_start && FIPS_signature<FIPS_rodata_end)
	    FIPSerr(FIPS_F_FIPS_CHECK_INCORE_FINGERPRINT,FIPS_R_FINGERPRINT_DOES_NOT_MATCH_SEGMENT_ALIASING);
#if defined(__sgi) && (defined(__mips) || defined(mips))
	else if (__dso_displacement!=NULL)
#else
	else if (OPENSSL_NONPIC_relocated)
#endif
	    FIPSerr(FIPS_F_FIPS_CHECK_INCORE_FINGERPRINT,FIPS_R_FINGERPRINT_DOES_NOT_MATCH_NONPIC_RELOCATED);
	else
	    FIPSerr(FIPS_F_FIPS_CHECK_INCORE_FINGERPRINT,FIPS_R_FINGERPRINT_DOES_NOT_MATCH);
#ifdef OPENSSL_FIPS_DEBUGGER
    	return 1;
#else
	return 0;
#endif
	}
    return 1;
    }

int FIPS_mode_set(int onoff)
    {
    int fips_set_owning_thread();
    int fips_clear_owning_thread();
    int ret = 0;

    fips_w_lock();
    fips_started = 1;
    fips_set_owning_thread();

    if(onoff)
	{

	fips_selftest_fail = 0;

	/* Don't go into FIPS mode twice, just so we can do automagic
	   seeding */
	if(FIPS_mode())
	    {
	    FIPSerr(FIPS_F_FIPS_MODE_SET,FIPS_R_FIPS_MODE_ALREADY_SET);
	    fips_selftest_fail = 1;
	    ret = 0;
	    goto end;
	    }

#ifdef OPENSSL_IA32_SSE2
	if ((OPENSSL_ia32cap & (1<<25|1<<26)) != (1<<25|1<<26))
	    {
	    FIPSerr(FIPS_F_FIPS_MODE_SET,FIPS_R_UNSUPPORTED_PLATFORM);
	    fips_selftest_fail = 1;
	    ret = 0;
	    goto end;
	    }
#endif

	if(fips_signature_witness() != FIPS_signature)
	    {
	    FIPSerr(FIPS_F_FIPS_MODE_SET,FIPS_R_CONTRADICTING_EVIDENCE);
	    fips_selftest_fail = 1;
	    ret = 0;
	    goto end;
	    }

	if(!FIPS_check_incore_fingerprint())
	    {
	    fips_selftest_fail = 1;
	    ret = 0;
	    goto end;
	    }

	if (!FIPS_selftest_drbg())
	    {
	    fips_selftest_fail = 1;
	    ret = 0;
	    goto end;
	    }

	/* Perform RNG KAT before seeding */
	if (!FIPS_selftest_x931())
	    {
	    fips_selftest_fail = 1;
	    ret = 0;
	    goto end;
	    }

	if(FIPS_selftest())
	    fips_set_mode(1);
	else
	    {
	    fips_selftest_fail = 1;
	    ret = 0;
	    goto end;
	    }
	ret = 1;
	goto end;
	}
    fips_set_mode(0);
    fips_selftest_fail = 0;
    ret = 1;
end:
    fips_clear_owning_thread();
    fips_w_unlock();
    return ret;
    }

static CRYPTO_THREADID fips_thread;
static int fips_thread_set = 0;

static int fips_is_owning_thread(void)
	{
	int ret = 0;

	if (fips_started)
		{
		CRYPTO_r_lock(CRYPTO_LOCK_FIPS2);
		if (fips_thread_set)
			{
			CRYPTO_THREADID cur;
			CRYPTO_THREADID_current(&cur);
			if (!CRYPTO_THREADID_cmp(&cur, &fips_thread))
				ret = 1;
			}
		CRYPTO_r_unlock(CRYPTO_LOCK_FIPS2);
		}
	return ret;
	}

int fips_set_owning_thread(void)
	{
	int ret = 0;

	if (fips_started)
		{
		CRYPTO_w_lock(CRYPTO_LOCK_FIPS2);
		if (!fips_thread_set)
			{
			CRYPTO_THREADID_current(&fips_thread);
			ret = 1;
			fips_thread_set = 1;
			}
		CRYPTO_w_unlock(CRYPTO_LOCK_FIPS2);
		}
	return ret;
	}

int fips_clear_owning_thread(void)
	{
	int ret = 0;

	if (fips_started)
		{
		CRYPTO_w_lock(CRYPTO_LOCK_FIPS2);
		if (fips_thread_set)
			{
			CRYPTO_THREADID cur;
			CRYPTO_THREADID_current(&cur);
			if (!CRYPTO_THREADID_cmp(&cur, &fips_thread))
				fips_thread_set = 0;
			}
		CRYPTO_w_unlock(CRYPTO_LOCK_FIPS2);
		}
	return ret;
	}

unsigned char *fips_signature_witness(void)
	{
	extern unsigned char FIPS_signature[];
	return FIPS_signature;
	}

/* Generalized public key test routine. Signs and verifies the data
 * supplied in tbs using mesage digest md and setting RSA padding mode
 * pad_mode. If the 'kat' parameter is not NULL it will
 * additionally check the signature matches it: a known answer test
 * The string "fail_str" is used for identification purposes in case
 * of failure.
 */

int fips_pkey_signature_test(EVP_PKEY *pkey,
			const unsigned char *tbs, int tbslen,
			const unsigned char *kat, unsigned int katlen,
			const EVP_MD *digest, int pad_mode,
			const char *fail_str)
	{	
	int ret = 0;
	unsigned char sigtmp[256], *sig = sigtmp;
	unsigned int siglen;
	DSA_SIG *dsig = NULL;
	ECDSA_SIG *esig = NULL;
	EVP_MD_CTX mctx;
	FIPS_md_ctx_init(&mctx);

	if ((pkey->type == EVP_PKEY_RSA)
		&& ((size_t)RSA_size(pkey->pkey.rsa) > sizeof(sigtmp)))
		{
		sig = OPENSSL_malloc(RSA_size(pkey->pkey.rsa));
		if (!sig)
			{
			FIPSerr(FIPS_F_FIPS_PKEY_SIGNATURE_TEST,ERR_R_MALLOC_FAILURE);
			return 0;
			}
		}

	if (tbslen == -1)
		tbslen = strlen((char *)tbs);

	if (digest == NULL)
		digest = EVP_sha256();

	if (!FIPS_digestinit(&mctx, digest))
		goto error;
	if (!FIPS_digestupdate(&mctx, tbs, tbslen))
		goto error;
	if (pkey->type == EVP_PKEY_RSA)
		{
		if (!FIPS_rsa_sign_ctx(pkey->pkey.rsa, &mctx,
					pad_mode, 0, NULL, sig, &siglen))
			goto error;
		}
	else if (pkey->type == EVP_PKEY_DSA)
		{
		dsig = FIPS_dsa_sign_ctx(pkey->pkey.dsa, &mctx);
		if (!dsig)
			goto error;
		}
	else if (pkey->type == EVP_PKEY_EC)
		{
		esig = FIPS_ecdsa_sign_ctx(pkey->pkey.ec, &mctx);
		if (!esig)
			goto error;
		}
#if 0
	else if (!EVP_SignFinal(&mctx, sig, &siglen, pkey))
		goto error;
#endif

	if (kat && ((siglen != katlen) || memcmp(kat, sig, katlen)))
		goto error;

	if (!FIPS_digestinit(&mctx, digest))
		goto error;
	if (!FIPS_digestupdate(&mctx, tbs, tbslen))
		goto error;
	if (pkey->type == EVP_PKEY_RSA)
		{
		ret = FIPS_rsa_verify_ctx(pkey->pkey.rsa, &mctx,
						pad_mode, 0, NULL, sig, siglen);
		}
	else if (pkey->type == EVP_PKEY_DSA)
		{
		ret = FIPS_dsa_verify_ctx(pkey->pkey.dsa, &mctx, dsig);
		}
	else if (pkey->type == EVP_PKEY_EC)
		{
		ret = FIPS_ecdsa_verify_ctx(pkey->pkey.ec, &mctx, esig);
		}
#if 0
	else
		ret = EVP_VerifyFinal(&mctx, sig, siglen, pkey);
#endif

	error:
	if (dsig != NULL)
		FIPS_dsa_sig_free(dsig);
	if (esig != NULL)
		FIPS_ecdsa_sig_free(esig);
	if (sig != sigtmp)
		OPENSSL_free(sig);
	FIPS_md_ctx_cleanup(&mctx);
	if (ret != 1)
		{
		FIPSerr(FIPS_F_FIPS_PKEY_SIGNATURE_TEST,FIPS_R_TEST_FAILURE);
		if (fail_str)
			FIPS_add_error_data(2, "Type=", fail_str);
		return 0;
		}
	return 1;
	}

/* Generalized symmetric cipher test routine. Encrypt data, verify result
 * against known answer, decrypt and compare with original plaintext.
 */

int fips_cipher_test(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
			const unsigned char *key,
			const unsigned char *iv,
			const unsigned char *plaintext,
			const unsigned char *ciphertext,
			int len)
	{
	unsigned char pltmp[FIPS_MAX_CIPHER_TEST_SIZE];
	unsigned char citmp[FIPS_MAX_CIPHER_TEST_SIZE];
	OPENSSL_assert(len <= FIPS_MAX_CIPHER_TEST_SIZE);
	memset(pltmp, 0, FIPS_MAX_CIPHER_TEST_SIZE);
	memset(citmp, 0, FIPS_MAX_CIPHER_TEST_SIZE);
	if (FIPS_cipherinit(ctx, cipher, key, iv, 1) <= 0)
		return 0;
	if (!FIPS_cipher(ctx, citmp, plaintext, len))
		return 0;
	if (memcmp(citmp, ciphertext, len))
		return 0;
	if (FIPS_cipherinit(ctx, cipher, key, iv, 0) <= 0)
		return 0;
	FIPS_cipher(ctx, pltmp, citmp, len);
	if (memcmp(pltmp, plaintext, len))
		return 0;
	return 1;
	}

#if 0
/* The purpose of this is to ensure the error code exists and the function
 * name is to keep the error checking script quiet
 */
void hash_final(void)
	{
	FIPSerr(FIPS_F_HASH_FINAL,FIPS_R_NON_FIPS_METHOD);
	}
#endif


#endif

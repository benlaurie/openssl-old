/* ====================================================================
 * Copyright (c) 2003 The OpenSSL Project.  All rights reserved.
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

#include <openssl/fips.h>
#include <openssl/rand.h>
#include <openssl/fips_rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/hmac.h>
#include <string.h>
#include <limits.h>
#include "fips_locl.h"

#ifdef OPENSSL_FIPS

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

int FIPS_md5_allowed;
int FIPS_selftest_fail;

int FIPS_selftest()
    {
    ERR_load_crypto_strings();

    return FIPS_selftest_sha1()
	&& FIPS_selftest_aes()
	&& FIPS_selftest_des()
	&& FIPS_selftest_rsa()
	&& FIPS_selftest_dsa();
    }

static int FIPS_check_exe(const char *path)
    {
    char buf[1024];
    char p2[PATH_MAX];
    int n;
    char mdbuf[EVP_MAX_MD_SIZE];
    FILE *f;
    static char key[]="etaonrishdlcupfm";
    HMAC_CTX hmac;

    f=fopen(path,"rb");
    if(!f)
	{
	FIPSerr(FIPS_F_FIPS_CHECK_EXE,FIPS_R_CANNOT_READ_EXE);
	return 0;
	}
    HMAC_Init(&hmac,key,strlen(key),EVP_sha1());
    do
	{
	n=fread(buf,1,sizeof buf,f);
	if(n < 0)
	    {
	    fclose(f);
	    FIPSerr(FIPS_F_FIPS_CHECK_EXE,FIPS_R_CANNOT_READ_EXE);
	    return 0;
	    }
	HMAC_Update(&hmac,buf,n);
	} while(n > 0);
    fclose(f);
    HMAC_Final(&hmac,mdbuf,&n);
    BIO_snprintf(p2,sizeof p2,"%s.sha1",path);
    f=fopen(p2,"rb");
    if(!f || fread(buf,1,20,f) != 20)
	{
	if (f) fclose(f);
	FIPSerr(FIPS_F_FIPS_CHECK_EXE,FIPS_R_CANNOT_READ_EXE_DIGEST);
	return 0;
	}
    fclose(f);
    if(memcmp(buf,mdbuf,20))
	{
	FIPSerr(FIPS_F_FIPS_CHECK_EXE,FIPS_R_EXE_DIGEST_DOES_NOT_MATCH);
	return 0;
	}
    return 1;
    }

int FIPS_mode_set(int onoff,const char *path)
    {
    if(onoff)
	{
	unsigned char buf[24];

	FIPS_selftest_fail=0;

	/* Don't go into FIPS mode twice, just so we can do automagic
	   seeding */
	if(FIPS_mode)
	    {
	    FIPSerr(FIPS_F_FIPS_MODE_SET,FIPS_R_FIPS_MODE_ALREADY_SET);
	    FIPS_selftest_fail=1;
	    return 0;
	    }

	if(!FIPS_check_exe(path))
	    {
	    FIPS_selftest_fail=1;
	    return 0;
	    }

	/* automagically seed PRNG if not already seeded */
	if(!FIPS_rand_seeded())
	    {
	    if(RAND_bytes(buf,sizeof buf) <= 0)
		{
		FIPS_selftest_fail=1;
		return 0;
		}
	    FIPS_set_prng_key(buf,buf+8);
	    FIPS_rand_seed(buf+16,8);
	    }

	/* now switch into FIPS mode */
	FIPS_rand_check=FIPS_rand_method();
	RAND_set_rand_method(FIPS_rand_method());
	if(FIPS_selftest())
	    FIPS_mode=1;
	else
	    {
	    FIPS_selftest_fail=1;
	    return 0;
	    }
	return 1;
	}
    FIPS_mode=0;
    FIPS_selftest_fail=0;
    return 1;
    }

void FIPS_allow_md5(int onoff)
    {
    FIPS_md5_allowed=onoff;
    }

#if 0
/* here just to cause error codes to exist */
static void dummy()
    {
    FIPSerr(FIPS_F_HASH_FINAL,FIPS_F_NON_FIPS_METHOD);
    FIPSerr(FIPS_F_HASH_FINAL,FIPS_R_FIPS_SELFTEST_FAILED);
    }
#endif

#endif

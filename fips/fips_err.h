/* fips/fips_err.h */
/* ====================================================================
 * Copyright (c) 1999-2005 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/* NOTE: this file was auto generated by the mkerr.pl script: any changes
 * made to it will be overwritten when the script next updates this file,
 * only reason strings will be preserved.
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/fips.h>

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

#define ERR_FUNC(func) ERR_PACK(ERR_LIB_FIPS,func,0)
#define ERR_REASON(reason) ERR_PACK(ERR_LIB_FIPS,0,reason)

static ERR_STRING_DATA FIPS_str_functs[]=
	{
{ERR_FUNC(FIPS_F_DH_GENERATE_PARAMETERS),	"DH_generate_parameters"},
{ERR_FUNC(FIPS_F_DSA_DO_SIGN),	"DSA_do_sign"},
{ERR_FUNC(FIPS_F_DSA_DO_VERIFY),	"DSA_do_verify"},
{ERR_FUNC(FIPS_F_DSA_GENERATE_PARAMETERS),	"DSA_generate_parameters"},
{ERR_FUNC(FIPS_F_FIPS_CHECK_DSA),	"FIPS_CHECK_DSA"},
{ERR_FUNC(FIPS_F_FIPS_CHECK_EXE),	"FIPS_CHECK_EXE"},
{ERR_FUNC(FIPS_F_FIPS_CHECK_RSA),	"FIPS_CHECK_RSA"},
{ERR_FUNC(FIPS_F_FIPS_DSA_CHECK),	"FIPS_dsa_check"},
{ERR_FUNC(FIPS_F_FIPS_MODE_SET),	"FIPS_mode_set"},
{ERR_FUNC(FIPS_F_FIPS_SELFTEST_AES),	"FIPS_selftest_aes"},
{ERR_FUNC(FIPS_F_FIPS_SELFTEST_DES),	"FIPS_selftest_des"},
{ERR_FUNC(FIPS_F_FIPS_SELFTEST_DSA),	"FIPS_selftest_dsa"},
{ERR_FUNC(FIPS_F_FIPS_SELFTEST_RNG),	"FIPS_selftest_rng"},
{ERR_FUNC(FIPS_F_FIPS_SELFTEST_RSA),	"FIPS_selftest_rsa"},
{ERR_FUNC(FIPS_F_FIPS_SELFTEST_SHA1),	"FIPS_selftest_sha1"},
{ERR_FUNC(FIPS_F_HASH_FINAL),	"HASH_FINAL"},
{ERR_FUNC(FIPS_F_RSA_EAY_PUBLIC_ENCRYPT),	"RSA_EAY_PUBLIC_ENCRYPT"},
{ERR_FUNC(FIPS_F_RSA_GENERATE_KEY),	"RSA_generate_key"},
{ERR_FUNC(FIPS_F_SSLEAY_RAND_BYTES),	"SSLEAY_RAND_BYTES"},
{0,NULL}
	};

static ERR_STRING_DATA FIPS_str_reasons[]=
	{
{ERR_REASON(FIPS_R_CANNOT_READ_EXE)      ,"cannot read exe"},
{ERR_REASON(FIPS_R_CANNOT_READ_EXE_DIGEST),"cannot read exe digest"},
{ERR_REASON(FIPS_R_EXE_DIGEST_DOES_NOT_MATCH),"exe digest does not match"},
{ERR_REASON(FIPS_R_FIPS_MODE_ALREADY_SET),"fips mode already set"},
{ERR_REASON(FIPS_R_FIPS_SELFTEST_FAILED) ,"fips selftest failed"},
{ERR_REASON(FIPS_R_NON_FIPS_METHOD)      ,"non fips method"},
{ERR_REASON(FIPS_R_PAIRWISE_TEST_FAILED) ,"pairwise test failed"},
{ERR_REASON(FIPS_R_SELFTEST_FAILED)      ,"selftest failed"},
{0,NULL}
	};

#endif

void ERR_load_FIPS_strings(void)
	{
	static int init;

	if (!init)
		{
		init=1;
#ifndef OPENSSL_NO_ERR
		ERR_load_strings(0,FIPS_str_functs);
		ERR_load_strings(0,FIPS_str_reasons);
#endif

		}
	}

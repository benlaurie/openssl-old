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

#include <openssl/opensslconf.h>

#ifdef OPENSSL_FIPS

#ifdef  __cplusplus
extern "C" {
#endif

/* Note that these are defined in crypto/cryptlib.c so they're
 * available even without -lfips.
 */
extern int FIPS_mode;
extern int FIPS_selftest_fail;
extern void *FIPS_rand_check;
struct dsa_st;

int FIPS_mode_set(int onoff,const char *path);
void FIPS_allow_md5(int onoff);
int FIPS_dsa_check(struct dsa_st *dsa);
void FIPS_corrupt_sha1(void);
int FIPS_selftest_sha1(void);
void FIPS_corrupt_aes(void);
int FIPS_selftest_aes(void);
void FIPS_corrupt_des(void);
int FIPS_selftest_des(void);
void FIPS_corrupt_rsa(void);
int FIPS_selftest_rsa(void);
void FIPS_corrupt_dsa(void);
int FIPS_selftest_dsa(void);

/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_FIPS_strings(void);

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_FIPS_strings(void);

/* Error codes for the FIPS functions. */

/* Function codes. */
#define FIPS_F_DSA_DO_SIGN				 111
#define FIPS_F_DSA_DO_VERIFY				 112
#define FIPS_F_DSA_GENERATE_PARAMETERS			 110
#define FIPS_F_FIPS_CHECK_DSA				 116
#define FIPS_F_FIPS_CHECK_EXE				 106
#define FIPS_F_FIPS_CHECK_RSA				 115
#define FIPS_F_FIPS_DSA_CHECK				 102
#define FIPS_F_FIPS_MODE_SET				 105
#define FIPS_F_FIPS_SELFTEST_AES			 104
#define FIPS_F_FIPS_SELFTEST_DES			 107
#define FIPS_F_FIPS_SELFTEST_DSA			 109
#define FIPS_F_FIPS_SELFTEST_RSA			 108
#define FIPS_F_FIPS_SELFTEST_SHA1			 103
#define FIPS_F_HASH_FINAL				 100
#define FIPS_F_RSA_EAY_PUBLIC_ENCRYPT			 114
#define FIPS_F_RSA_GENERATE_KEY				 113
#define FIPS_F_SSLEAY_RAND_BYTES			 101

/* Reason codes. */
#define FIPS_R_CANNOT_READ_EXE				 103
#define FIPS_R_CANNOT_READ_EXE_DIGEST			 104
#define FIPS_R_EXE_DIGEST_DOES_NOT_MATCH		 105
#define FIPS_R_FIPS_MODE_ALREADY_SET			 102
#define FIPS_R_FIPS_SELFTEST_FAILED			 106
#define FIPS_R_NON_FIPS_METHOD				 100
#define FIPS_R_PAIRWISE_TEST_FAILED			 107
#define FIPS_R_SELFTEST_FAILED				 101

#ifdef  __cplusplus
}
#endif
#endif

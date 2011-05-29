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

#include <openssl/opensslconf.h>

#ifndef OPENSSL_FIPS
#error FIPS is disabled.
#endif

#ifdef OPENSSL_FIPS

#ifdef  __cplusplus
extern "C" {
#endif

struct dsa_st;
struct ec_key_st;
struct rsa_st;
struct evp_pkey_st;
struct env_md_st;
struct evp_cipher_st;
struct evp_cipher_ctx_st;

int FIPS_module_mode_set(int onoff);
int FIPS_module_mode(void);
const void *FIPS_rand_check(void);
int FIPS_selftest(void);
int FIPS_selftest_failed(void);
void FIPS_selftest_check(void);
int FIPS_selftest_sha1(void);
int FIPS_selftest_aes_ccm(void);
int FIPS_selftest_aes_gcm(void);
int FIPS_selftest_aes_xts(void);
int FIPS_selftest_aes(void);
int FIPS_selftest_des(void);
int FIPS_selftest_rsa(void);
int FIPS_selftest_dsa(void);
int FIPS_selftest_ecdsa(void);
void FIPS_corrupt_drbg(void);
void FIPS_x931_stick(void);
void FIPS_drbg_stick(void);
int FIPS_selftest_x931(void);
int FIPS_selftest_hmac(void);
int FIPS_selftest_drbg(void);
int FIPS_selftest_cmac(void);

unsigned int FIPS_incore_fingerprint(unsigned char *sig,unsigned int len);
int FIPS_check_incore_fingerprint(void);

void fips_set_selftest_fail(void);
int fips_check_rsa(struct rsa_st *rsa);
int fips_check_rsa_prng(struct rsa_st *rsa, int bits);
int fips_check_dsa_prng(struct dsa_st *dsa, size_t L, size_t N);
int fips_check_ec_prng(struct ec_key_st *ec);

void FIPS_set_locking_callbacks(void (*func)(int mode, int type,
				const char *file,int line),
				int (*add_cb)(int *pointer, int amount,
					int type, const char *file, int line));

void FIPS_set_malloc_callbacks(
		void *(*malloc_cb)(int num, const char *file, int line),
		void (*free_cb)(void *));

void FIPS_get_timevec(unsigned char *buf, unsigned long *pctr);

/* POST callback operation value: */
/* All tests started */
#define	FIPS_POST_BEGIN		1
/* All tests end: result in id */
#define	FIPS_POST_END		2
/* One individual test started */
#define	FIPS_POST_STARTED	3
/* Individual test success */
#define	FIPS_POST_SUCCESS	4
/* Individual test failure */
#define	FIPS_POST_FAIL		5
/* Induce failure in test if zero return */
#define FIPS_POST_CORRUPT	6

/* Test IDs */
/* HMAC integrity test */
#define FIPS_TEST_INTEGRITY	1
/* Digest test */
#define FIPS_TEST_DIGEST	2
/* Symmetric cipher test */
#define FIPS_TEST_CIPHER	3
/* Public key signature test */
#define FIPS_TEST_SIGNATURE	4
/* HMAC test */
#define FIPS_TEST_HMAC		5
/* CMAC test */
#define FIPS_TEST_CMAC		6
/* GCM test */
#define FIPS_TEST_GCM		7
/* CCM test */
#define FIPS_TEST_CCM		8
/* XTS test */
#define FIPS_TEST_XTS		9
/* X9.31 PRNG */
#define FIPS_TEST_X931		10
/* DRNB */
#define FIPS_TEST_DRBG		11
/* Keygen pairwise consistency test */
#define FIPS_TEST_PAIRWISE	12
/* Continuous PRNG test */
#define FIPS_TEST_CONTINUOUS	13

void FIPS_post_set_callback(
	int (*post_cb)(int op, int id, int subid, void *ex));

#define FIPS_ERROR_IGNORED(alg) OpenSSLDie(__FILE__, __LINE__, \
		alg " previous FIPS forbidden algorithm error ignored");

int fips_pkey_signature_test(int id, struct evp_pkey_st *pkey,
			const unsigned char *tbs, size_t tbslen,
			const unsigned char *kat, size_t katlen,
			const struct env_md_st *digest, int pad_mode,
			const char *fail_str);

int fips_cipher_test(int id, struct evp_cipher_ctx_st *ctx,
			const struct evp_cipher_st *cipher,
			const unsigned char *key,
			const unsigned char *iv,
			const unsigned char *plaintext,
			const unsigned char *ciphertext,
			int len);

#ifndef OPENSSL_FIPSCANISTER

int FIPS_digestinit(EVP_MD_CTX *ctx, const EVP_MD *type);
int FIPS_digestupdate(EVP_MD_CTX *ctx, const void *data, size_t count);
int FIPS_digestfinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *size);
int FIPS_md_ctx_cleanup(EVP_MD_CTX *ctx);

int FIPS_cipherinit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
	     const unsigned char *key, const unsigned char *iv, int enc);
int FIPS_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			const unsigned char *in, unsigned int inl);
int FIPS_cipher_ctx_cleanup(EVP_CIPHER_CTX *c);

const EVP_CIPHER *FIPS_evp_aes_128_cbc(void);
const EVP_CIPHER *FIPS_evp_aes_128_ccm(void);
const EVP_CIPHER *FIPS_evp_aes_128_cfb1(void);
const EVP_CIPHER *FIPS_evp_aes_128_cfb128(void);
const EVP_CIPHER *FIPS_evp_aes_128_cfb8(void);
const EVP_CIPHER *FIPS_evp_aes_128_ctr(void);
const EVP_CIPHER *FIPS_evp_aes_128_ecb(void);
const EVP_CIPHER *FIPS_evp_aes_128_gcm(void);
const EVP_CIPHER *FIPS_evp_aes_128_ofb(void);
const EVP_CIPHER *FIPS_evp_aes_128_xts(void);
const EVP_CIPHER *FIPS_evp_aes_192_cbc(void);
const EVP_CIPHER *FIPS_evp_aes_192_ccm(void);
const EVP_CIPHER *FIPS_evp_aes_192_cfb1(void);
const EVP_CIPHER *FIPS_evp_aes_192_cfb128(void);
const EVP_CIPHER *FIPS_evp_aes_192_cfb8(void);
const EVP_CIPHER *FIPS_evp_aes_192_ctr(void);
const EVP_CIPHER *FIPS_evp_aes_192_ecb(void);
const EVP_CIPHER *FIPS_evp_aes_192_gcm(void);
const EVP_CIPHER *FIPS_evp_aes_192_ofb(void);
const EVP_CIPHER *FIPS_evp_aes_256_cbc(void);
const EVP_CIPHER *FIPS_evp_aes_256_ccm(void);
const EVP_CIPHER *FIPS_evp_aes_256_cfb1(void);
const EVP_CIPHER *FIPS_evp_aes_256_cfb128(void);
const EVP_CIPHER *FIPS_evp_aes_256_cfb8(void);
const EVP_CIPHER *FIPS_evp_aes_256_ctr(void);
const EVP_CIPHER *FIPS_evp_aes_256_ecb(void);
const EVP_CIPHER *FIPS_evp_aes_256_gcm(void);
const EVP_CIPHER *FIPS_evp_aes_256_ofb(void);
const EVP_CIPHER *FIPS_evp_aes_256_xts(void);
const EVP_CIPHER *FIPS_evp_des_ede(void);
const EVP_CIPHER *FIPS_evp_des_ede3(void);
const EVP_CIPHER *FIPS_evp_des_ede3_cbc(void);
const EVP_CIPHER *FIPS_evp_des_ede3_cfb1(void);
const EVP_CIPHER *FIPS_evp_des_ede3_cfb64(void);
const EVP_CIPHER *FIPS_evp_des_ede3_cfb8(void);
const EVP_CIPHER *FIPS_evp_des_ede3_ecb(void);
const EVP_CIPHER *FIPS_evp_des_ede3_ofb(void);
const EVP_CIPHER *FIPS_evp_des_ede_cbc(void);
const EVP_CIPHER *FIPS_evp_des_ede_cfb64(void);
const EVP_CIPHER *FIPS_evp_des_ede_ecb(void);
const EVP_CIPHER *FIPS_evp_des_ede_ofb(void);
const EVP_MD *FIPS_evp_sha1(void);
const EVP_MD *FIPS_evp_sha224(void);
const EVP_MD *FIPS_evp_sha256(void);
const EVP_MD *FIPS_evp_sha384(void);
const EVP_MD *FIPS_evp_sha512(void);

#endif

/* Where necessary redirect standard OpenSSL APIs to FIPS versions */

#if defined(OPENSSL_FIPSCANISTER) && defined(OPENSSL_FIPSAPI)

#define CRYPTO_lock FIPS_lock
#define CRYPTO_add_lock FIPS_add_lock
#define CRYPTO_malloc FIPS_malloc
#define CRYPTO_free FIPS_free

#define ERR_put_error FIPS_put_error
#define ERR_add_error_data FIPS_add_error_data

#define EVP_MD_CTX_init FIPS_md_ctx_init
#define EVP_MD_CTX_cleanup FIPS_md_ctx_cleanup
#define EVP_MD_CTX_create FIPS_md_ctx_create
#define EVP_MD_CTX_destroy FIPS_md_ctx_destroy
#define EVP_DigestInit_ex(ctx, type, impl) FIPS_digestinit(ctx, type)
#define EVP_DigestInit FIPS_digestinit
#define EVP_DigestUpdate FIPS_digestupdate
#define EVP_Digest(data, count, md, size, type, impl) \
			FIPS_digest(data, count, md, size, type)
#define EVP_DigestFinal_ex FIPS_digestfinal
#define EVP_MD_CTX_copy_ex FIPS_md_ctx_copy

#define EVP_CipherInit_ex(ctx, cipher, impl, key, iv, enc) \
				FIPS_cipherinit(ctx, cipher, key, iv, enc)

#define EVP_CipherInit FIPS_cipherinit

#define EVP_CIPHER_CTX_init FIPS_cipher_ctx_init
#define EVP_CIPHER_CTX_cleanup FIPS_cipher_ctx_cleanup
#define EVP_Cipher FIPS_cipher
#define EVP_CIPHER_CTX_ctrl FIPS_cipher_ctx_ctrl
#define EVP_CIPHER_CTX_new FIPS_cipher_ctx_new
#define EVP_CIPHER_CTX_free FIPS_cipher_ctx_free
#define EVP_CIPHER_CTX_copy FIPS_cipher_ctx_copy
#define EVP_CIPHER_CTX_set_key_length FIPS_cipher_ctx_set_key_length

#define DSA_SIG_new FIPS_dsa_sig_new
#define DSA_SIG_free FIPS_dsa_sig_free

#define ECDSA_SIG_new FIPS_ecdsa_sig_new
#define ECDSA_SIG_free FIPS_ecdsa_sig_free

#define ecdsa_check fips_ecdsa_check
#define ecdh_check fips_ecdh_check

#define RAND_bytes FIPS_rand_bytes
#define RAND_pseudo_bytes FIPS_rand_pseudo_bytes
#define RAND_add FIPS_rand_add
#define RAND_seed FIPS_rand_seed
#define RAND_status FIPS_rand_status

#endif

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_FIPS_strings(void);

/* Error codes for the FIPS functions. */

/* Function codes. */
#define FIPS_F_DH_BUILTIN_GENPARAMS			 100
#define FIPS_F_DH_INIT					 148
#define FIPS_F_DSA_BUILTIN_PARAMGEN			 101
#define FIPS_F_DSA_BUILTIN_PARAMGEN2			 102
#define FIPS_F_DSA_DO_SIGN				 103
#define FIPS_F_DSA_DO_VERIFY				 104
#define FIPS_F_FIPS_CHECK_DSA				 105
#define FIPS_F_FIPS_CHECK_DSA_PRNG			 151
#define FIPS_F_FIPS_CHECK_EC				 106
#define FIPS_F_FIPS_CHECK_EC_PRNG			 152
#define FIPS_F_FIPS_CHECK_INCORE_FINGERPRINT		 107
#define FIPS_F_FIPS_CHECK_RSA				 108
#define FIPS_F_FIPS_CHECK_RSA_PRNG			 150
#define FIPS_F_FIPS_CIPHER				 160
#define FIPS_F_FIPS_CIPHERINIT				 109
#define FIPS_F_FIPS_CIPHER_CTX_CTRL			 161
#define FIPS_F_FIPS_DIGESTFINAL				 158
#define FIPS_F_FIPS_DIGESTINIT				 110
#define FIPS_F_FIPS_DIGESTUPDATE			 159
#define FIPS_F_FIPS_DRBG_BYTES				 111
#define FIPS_F_FIPS_DRBG_CHECK				 146
#define FIPS_F_FIPS_DRBG_CPRNG_TEST			 112
#define FIPS_F_FIPS_DRBG_GENERATE			 113
#define FIPS_F_FIPS_DRBG_HEALTH_CHECK			 114
#define FIPS_F_FIPS_DRBG_INIT				 115
#define FIPS_F_FIPS_DRBG_INSTANTIATE			 116
#define FIPS_F_FIPS_DRBG_NEW				 117
#define FIPS_F_FIPS_DRBG_RESEED				 118
#define FIPS_F_FIPS_DRBG_SINGLE_KAT			 119
#define FIPS_F_FIPS_DSA_SIGN_DIGEST			 154
#define FIPS_F_FIPS_DSA_VERIFY_DIGEST			 155
#define FIPS_F_FIPS_GET_ENTROPY				 147
#define FIPS_F_FIPS_MODULE_MODE_SET			 120
#define FIPS_F_FIPS_PKEY_SIGNATURE_TEST			 121
#define FIPS_F_FIPS_RAND_ADD				 122
#define FIPS_F_FIPS_RAND_BYTES				 123
#define FIPS_F_FIPS_RAND_PSEUDO_BYTES			 124
#define FIPS_F_FIPS_RAND_SEED				 125
#define FIPS_F_FIPS_RAND_SET_METHOD			 126
#define FIPS_F_FIPS_RAND_STATUS				 127
#define FIPS_F_FIPS_RSA_SIGN_DIGEST			 156
#define FIPS_F_FIPS_RSA_VERIFY_DIGEST			 157
#define FIPS_F_FIPS_SELFTEST_AES			 128
#define FIPS_F_FIPS_SELFTEST_AES_CCM			 145
#define FIPS_F_FIPS_SELFTEST_AES_GCM			 129
#define FIPS_F_FIPS_SELFTEST_AES_XTS			 144
#define FIPS_F_FIPS_SELFTEST_CMAC			 130
#define FIPS_F_FIPS_SELFTEST_DES			 131
#define FIPS_F_FIPS_SELFTEST_DSA			 132
#define FIPS_F_FIPS_SELFTEST_ECDSA			 133
#define FIPS_F_FIPS_SELFTEST_HMAC			 134
#define FIPS_F_FIPS_SELFTEST_SHA1			 135
#define FIPS_F_FIPS_SELFTEST_X931			 136
#define FIPS_F_FIPS_SET_PRNG_KEY			 153
#define FIPS_F_HASH_FINAL				 137
#define FIPS_F_RSA_BUILTIN_KEYGEN			 138
#define FIPS_F_RSA_EAY_INIT				 149
#define FIPS_F_RSA_EAY_PRIVATE_DECRYPT			 139
#define FIPS_F_RSA_EAY_PRIVATE_ENCRYPT			 140
#define FIPS_F_RSA_EAY_PUBLIC_DECRYPT			 141
#define FIPS_F_RSA_EAY_PUBLIC_ENCRYPT			 142
#define FIPS_F_RSA_X931_GENERATE_KEY_EX			 143

/* Reason codes. */
#define FIPS_R_ADDITIONAL_INPUT_TOO_LONG		 100
#define FIPS_R_ALREADY_INSTANTIATED			 101
#define FIPS_R_CONTRADICTING_EVIDENCE			 102
#define FIPS_R_DRBG_STUCK				 103
#define FIPS_R_ENTROPY_ERROR_UNDETECTED			 104
#define FIPS_R_ENTROPY_NOT_REQUESTED_FOR_RESEED		 105
#define FIPS_R_ENTROPY_SOURCE_STUCK			 142
#define FIPS_R_ERROR_INITIALISING_DRBG			 106
#define FIPS_R_ERROR_INSTANTIATING_DRBG			 107
#define FIPS_R_ERROR_RETRIEVING_ADDITIONAL_INPUT	 108
#define FIPS_R_ERROR_RETRIEVING_ENTROPY			 109
#define FIPS_R_ERROR_RETRIEVING_NONCE			 110
#define FIPS_R_FINGERPRINT_DOES_NOT_MATCH		 111
#define FIPS_R_FINGERPRINT_DOES_NOT_MATCH_NONPIC_RELOCATED 112
#define FIPS_R_FINGERPRINT_DOES_NOT_MATCH_SEGMENT_ALIASING 113
#define FIPS_R_FIPS_MODE_ALREADY_SET			 114
#define FIPS_R_FIPS_SELFTEST_FAILED			 115
#define FIPS_R_FUNCTION_ERROR				 116
#define FIPS_R_GENERATE_ERROR				 117
#define FIPS_R_GENERATE_ERROR_UNDETECTED		 118
#define FIPS_R_INSTANTIATE_ERROR			 119
#define FIPS_R_INSUFFICIENT_SECURITY_STRENGTH		 120
#define FIPS_R_INTERNAL_ERROR				 121
#define FIPS_R_INVALID_KEY_LENGTH			 122
#define FIPS_R_INVALID_PARAMETERS			 144
#define FIPS_R_IN_ERROR_STATE				 123
#define FIPS_R_KEY_TOO_SHORT				 124
#define FIPS_R_NON_FIPS_METHOD				 125
#define FIPS_R_NOT_INSTANTIATED				 126
#define FIPS_R_PAIRWISE_TEST_FAILED			 127
#define FIPS_R_PERSONALISATION_ERROR_UNDETECTED		 128
#define FIPS_R_PERSONALISATION_STRING_TOO_LONG		 129
#define FIPS_R_PRNG_STRENGTH_TOO_LOW			 143
#define FIPS_R_REQUEST_LENGTH_ERROR_UNDETECTED		 130
#define FIPS_R_REQUEST_TOO_LARGE_FOR_DRBG		 131
#define FIPS_R_RESEED_COUNTER_ERROR			 132
#define FIPS_R_RESEED_ERROR				 133
#define FIPS_R_SELFTEST_FAILED				 134
#define FIPS_R_SELFTEST_FAILURE				 135
#define FIPS_R_STRENGTH_ERROR_UNDETECTED		 136
#define FIPS_R_TEST_FAILURE				 137
#define FIPS_R_UNINSTANTIATE_ERROR			 141
#define FIPS_R_UNINSTANTIATE_ZEROISE_ERROR		 138
#define FIPS_R_UNSUPPORTED_DRBG_TYPE			 139
#define FIPS_R_UNSUPPORTED_PLATFORM			 140

#ifdef  __cplusplus
}
#endif
#endif

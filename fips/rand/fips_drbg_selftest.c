/* fips/rand/fips_drbg_selftest.c */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
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
 */

#define OPENSSL_FIPSAPI

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/fips_rand.h>
#include "fips_rand_lcl.h"

typedef struct {
	int nid;
	unsigned int flags;
	const unsigned char *ent;
	size_t entlen;
	const unsigned char *nonce;
	size_t noncelen;
	const unsigned char *pers;
	size_t perslen;
	const unsigned char *adin;
	size_t adinlen;
	const unsigned char *entpr;
	size_t entprlen;
	const unsigned char *ading;
	size_t adinglen;
	const unsigned char *entg;
	size_t entglen;
	const unsigned char *kat;
	size_t katlen;
	} DRBG_SELFTEST_DATA;

#define make_drbg_test_data(nid, flag, pr) { nid, flag | DRBG_FLAG_TEST, \
	pr##_entropyinput, sizeof(pr##_entropyinput), \
	pr##_nonce, sizeof(pr##_nonce), \
	pr##_personalizationstring, sizeof(pr##_personalizationstring), \
	pr##_additionalinput, sizeof(pr##_additionalinput), \
	pr##_entropyinputpr, sizeof(pr##_entropyinputpr), \
	pr##_additionalinput2, sizeof(pr##_additionalinput2), \
	pr##_entropyinputpr2, sizeof(pr##_entropyinputpr2), \
	pr##_returnedbits, sizeof(pr##_returnedbits), \
	}

#define make_drbg_test_data_df(nid, pr) \
	make_drbg_test_data(nid, DRBG_FLAG_CTR_USE_DF, pr)

/* AES-128 use df PR */
static const unsigned char aes_128_use_df_entropyinput[] =
	{
	0x98,0x38,0x99,0x81,0x1d,0x56,0x1a,0x04,0xb0,0x50,0xcd,0x14,
	0xc3,0x90,0x0b,0x4f
	};

static const unsigned char aes_128_use_df_nonce[] =
	{
	0xa8,0xa0,0x80,0x8a,0x65,0xb7,0x38,0x22
	};

static const unsigned char aes_128_use_df_personalizationstring[] =
	{
	0x67,0x4f,0x85,0x01,0x15,0x51,0x85,0xdd,0x97,0xda,0xf7,0x09,
	0xbc,0x61,0xaf,0x23
	};

static const unsigned char aes_128_use_df_additionalinput[] =
	{
	0x01,0xba,0xa8,0x13,0x9e,0xd4,0xb7,0xff,0x86,0x34,0x01,0xa0,
	0xb6,0x17,0x96,0x55
	};

static const unsigned char aes_128_use_df_entropyinputpr[] =
	{
	0x60,0x76,0xf6,0x12,0x6b,0x92,0xbe,0xd7,0x75,0x6e,0x78,0x1f,
	0x0d,0xc1,0x0d,0x56
	};

static const unsigned char aes_128_use_df_additionalinput2[] =
	{
	0xf0,0xd6,0x5b,0xa3,0x7c,0x1e,0xa3,0x65,0x08,0xf9,0xdd,0x90,
	0xde,0x5f,0xb4,0x27
	};

static const unsigned char aes_128_use_df_entropyinputpr2[] =
	{
	0x34,0x55,0x02,0xa9,0x30,0xf0,0x78,0x0a,0xa2,0xae,0x74,0x46,
	0xe5,0xad,0xbb,0xd6
	};

static const unsigned char aes_128_use_df_returnedbits[] =
	{
	0x48,0x52,0xb6,0x9f,0xf2,0xfe,0xe1,0x12,0xaf,0x22,0x87,0xd7,
	0x46,0x64,0x96,0xec
	};


/* AES-192 use df PR */
static const unsigned char aes_192_use_df_entropyinput[] =
	{
	0x12,0xf6,0xff,0xc5,0x81,0x8c,0x15,0xd7,0x33,0x0c,0x4f,0x45,
	0xbf,0x2a,0x97,0xd2,0xe0,0xe0,0xbd,0x48,0x4e,0x83,0x76,0x25
	};

static const unsigned char aes_192_use_df_nonce[] =
	{
	0x35,0xc8,0x16,0x8c,0xbd,0x1f,0x53,0xc4,0x6e,0x47,0x3a,0x74,
	0x83,0xe6,0xe4,0x78
	};

static const unsigned char aes_192_use_df_personalizationstring[] =
	{
	0xd6,0xe2,0x27,0x88,0xf4,0xce,0x9d,0xfc,0x92,0xde,0x07,0x57,
	0x43,0x74,0x17,0x6e,0x63,0x54,0xaf,0x5a,0x3c,0xf8,0x23,0x65,
	0x5a,0x15,0xb0,0x35,0x2a,0x6c,0x3c,0x3a
	};

static const unsigned char aes_192_use_df_additionalinput[] =
	{
	0xad,0xa4,0x47,0xa4,0xcf,0x46,0x7b,0xf7,0x19,0xcc,0xda,0xbe,
	0x11,0x42,0x85,0xaa,0x21,0x16,0x27,0xe6,0x35,0xdf,0xb5,0x87,
	0x96,0x68,0x64,0x35,0x08,0x02,0xe9,0x19
	};

static const unsigned char aes_192_use_df_entropyinputpr[] =
	{
	0x6f,0x41,0x2d,0x5e,0xd6,0xc9,0xf8,0x6a,0x22,0x00,0xe0,0xfb,
	0x4b,0xcd,0xbe,0x2d,0x98,0xff,0x1b,0xe2,0xb9,0x95,0x73,0xac
	};

static const unsigned char aes_192_use_df_additionalinput2[] =
	{
	0x51,0xea,0xd8,0x8e,0xa0,0xd7,0x9c,0x22,0x3c,0x01,0xf6,0xdb,
	0xe9,0xe4,0x60,0x1e,0x54,0x56,0x3b,0x5c,0xd2,0xf3,0xa0,0x1d,
	0x5c,0xd0,0x85,0x48,0xc9,0x5f,0x12,0xb7
	};

static const unsigned char aes_192_use_df_entropyinputpr2[] =
	{
	0xf7,0x1f,0x9f,0x0e,0x14,0x30,0xde,0x4c,0xf9,0x34,0x49,0xc5,
	0x24,0x91,0xe3,0x30,0xfd,0x5f,0x1e,0x79,0x30,0xf5,0x58,0xe6
	};

static const unsigned char aes_192_use_df_returnedbits[] =
	{
	0x5b,0x8a,0xca,0x2e,0x74,0xb6,0x6f,0x96,0x48,0xb0,0xe4,0xc1,
	0x68,0x40,0xac,0xc7
	};


/* AES-256 use df PR */
static const unsigned char aes_256_use_df_entropyinput[] =
	{
	0x2a,0x02,0xbe,0xaa,0xba,0xb4,0x6a,0x73,0x53,0x85,0xa9,0x2a,
	0xae,0x4a,0xdc,0xeb,0xe8,0x07,0xfb,0xf3,0xbc,0xe3,0xf4,0x2e,
	0x00,0x53,0x46,0x00,0x64,0x80,0xdd,0x57
	};

static const unsigned char aes_256_use_df_nonce[] =
	{
	0x2c,0x86,0xa2,0xf9,0x70,0xb5,0xca,0xd3,0x9a,0x08,0xdc,0xb6,
	0x6b,0xce,0xe5,0x05
	};

static const unsigned char aes_256_use_df_personalizationstring[] =
	{
	0xdb,0x6c,0xe1,0x84,0xbe,0x07,0xae,0x55,0x4e,0x34,0x5d,0xb8,
	0x47,0x98,0x85,0xe0,0x3d,0x3e,0x9f,0x60,0xfa,0x1c,0x7d,0x57,
	0x19,0xe5,0x09,0xdc,0xe2,0x10,0x41,0xab
	};

static const unsigned char aes_256_use_df_additionalinput[] =
	{
	0x1d,0xc3,0x11,0x93,0xcb,0xc4,0xf6,0xbb,0x57,0xb0,0x09,0x70,
	0xb9,0xc6,0x05,0x86,0x4e,0x75,0x95,0x7d,0x3d,0xec,0xce,0xb4,
	0x0b,0xe4,0xef,0xd1,0x7b,0xab,0x56,0x6f
	};

static const unsigned char aes_256_use_df_entropyinputpr[] =
	{
	0x8f,0xb9,0xab,0xf9,0x33,0xcc,0xbe,0xc6,0xbd,0x8b,0x61,0x5a,
	0xec,0xc6,0x4a,0x5b,0x03,0x21,0xe7,0x37,0x03,0x02,0xbc,0xa5,
	0x28,0xb9,0xfe,0x7a,0xa8,0xef,0x6f,0xb0
	};

static const unsigned char aes_256_use_df_additionalinput2[] =
	{
	0xd6,0x98,0x63,0x48,0x94,0x9f,0x26,0xf7,0x1f,0x44,0x13,0x23,
	0xa7,0xde,0x09,0x12,0x90,0x04,0xce,0xbc,0xac,0x82,0x70,0x58,
	0xba,0x7d,0xdc,0x25,0x1e,0xe4,0xbf,0x7c
	};

static const unsigned char aes_256_use_df_entropyinputpr2[] =
	{
	0xe5,0x04,0xef,0x7c,0x8d,0x02,0xd7,0x68,0x95,0x4c,0x64,0x34,
	0x30,0x3a,0xcb,0x07,0xc9,0x0a,0xef,0x26,0xc6,0x57,0x43,0xfb,
	0x7d,0xbe,0xe2,0x61,0x75,0xcd,0xee,0x34
	};

static const unsigned char aes_256_use_df_returnedbits[] =
	{
	0x75,0x6d,0x16,0xef,0x14,0xae,0xd9,0xc2,0x28,0x0b,0x66,0xff,
	0x20,0x1f,0x21,0x33
	};


/* AES-128 no df PR */
static const unsigned char aes_128_no_df_entropyinput[] =
	{
	0xbe,0x91,0xb9,0x09,0x91,0x13,0x0b,0xbd,0x7b,0x95,0x77,0xed,
	0xf2,0x00,0xff,0x2a,0xec,0xbd,0x7a,0x11,0x59,0xe1,0x32,0x1a,
	0xe3,0x9a,0xbd,0xa2,0xe4,0xd9,0x1a,0x39
	};

static const unsigned char aes_128_no_df_nonce[] =
	{
	0x39,0xeb,0x7a,0x42,0x0b,0x7f,0x4f,0xd5
	};

static const unsigned char aes_128_no_df_personalizationstring[] =
	{
	0xd0,0xe4,0x9c,0xf6,0x2f,0xc8,0xba,0x6d,0xb9,0x91,0x8f,0xc1,
	0x45,0x5b,0xb9,0x4f,0xdb,0x36,0xd6,0x71,0x2c,0x4b,0x2a,0x4c,
	0x50,0x4c,0x74,0xdb,0xc5,0x20,0x0b,0x3b
	};

static const unsigned char aes_128_no_df_additionalinput[] =
	{
	0x7c,0x35,0x81,0x03,0x58,0x93,0x24,0xf7,0x9c,0x98,0x4a,0x9d,
	0x94,0xbd,0x9d,0x77,0x64,0xda,0xa4,0x67,0x66,0xb7,0x43,0xde,
	0xc5,0xd5,0x72,0x42,0x5a,0x7c,0x41,0x9f
	};

static const unsigned char aes_128_no_df_entropyinputpr[] =
	{
	0x63,0xf6,0x0e,0xfe,0x56,0xad,0x8f,0x37,0xa8,0xa1,0x6a,0x83,
	0x01,0xac,0x51,0xe0,0x86,0x26,0xce,0x5c,0x57,0x14,0xd8,0xde,
	0x4d,0x93,0xb6,0x35,0xf4,0x85,0x18,0x60
	};

static const unsigned char aes_128_no_df_additionalinput2[] =
	{
	0x90,0x0f,0x35,0x81,0xc5,0xf5,0xc8,0x1b,0x80,0x99,0xcd,0xe2,
	0xbb,0xe2,0xc7,0x65,0x40,0x74,0x50,0x2b,0x89,0xb4,0x16,0x60,
	0xd7,0x1e,0x15,0xbf,0x91,0xc9,0x15,0xc2
	};

static const unsigned char aes_128_no_df_entropyinputpr2[] =
	{
	0xc7,0x9f,0xd6,0x9b,0xe2,0x74,0x3e,0x8c,0x12,0xdd,0x41,0xcd,
	0x51,0x6b,0xd4,0x71,0x3e,0xd0,0x36,0xc7,0xb9,0xa6,0xaf,0xca,
	0xc0,0x7e,0x89,0xc4,0x88,0x2b,0x4e,0x43
	};

static const unsigned char aes_128_no_df_returnedbits[] =
	{
	0x8c,0x7f,0x69,0xbf,0xb8,0x07,0x17,0xa6,0x09,0xef,0xd2,0x0a,
	0x5f,0x20,0x18,0x2f
	};


/* AES-192 no df PR */
static const unsigned char aes_192_no_df_entropyinput[] =
	{
	0xd5,0xcb,0x5b,0xc5,0x5b,0xa6,0x97,0xb6,0x1e,0x57,0x92,0xbb,
	0x14,0x72,0xeb,0xae,0x44,0x85,0x99,0xa3,0xa3,0x24,0xe5,0x91,
	0x2e,0x34,0xa7,0x3f,0x48,0x7a,0xc4,0x72,0x54,0x65,0xe6,0x57,
	0x94,0x1a,0x7c,0x2d
	};

static const unsigned char aes_192_no_df_nonce[] =
	{
	0x74,0x7a,0x38,0x81,0xef,0xca,0xd1,0xb6,0x7b,0xb5,0x1e,0x62,
	0xf9,0x80,0x2c,0xe5
	};

static const unsigned char aes_192_no_df_personalizationstring[] =
	{
	0x03,0xf8,0xbe,0xe8,0x6a,0x90,0x2a,0x4f,0xbd,0x80,0xd0,0x31,
	0xf0,0x59,0xa3,0xf6,0x87,0xd8,0x8d,0x0d,0xac,0x27,0xa2,0xd2,
	0x91,0x72,0xa5,0xc1,0x07,0xac,0xbf,0xdb,0x5d,0xa1,0x7d,0x56,
	0x7d,0x3f,0x09,0x8b
	};

static const unsigned char aes_192_no_df_additionalinput[] =
	{
	0x3e,0x89,0x1b,0x17,0xcb,0xe3,0xc8,0x76,0x71,0x0d,0xaf,0x97,
	0x1e,0x73,0xa6,0xc4,0x88,0x3d,0x46,0xad,0xf0,0xba,0xc3,0x7e,
	0x17,0x10,0x0d,0x20,0x80,0x23,0x26,0xcc,0xe6,0xc4,0xc4,0xd8,
	0xfe,0x1d,0x2a,0xbc
	};

static const unsigned char aes_192_no_df_entropyinputpr[] =
	{
	0x3f,0x33,0xb8,0x1b,0xe1,0x1b,0xe7,0xbe,0x68,0x6f,0xd2,0xd8,
	0x6f,0xb6,0xf0,0xd2,0xa1,0x1c,0x83,0x24,0xfe,0x5d,0xf2,0xe9,
	0x4b,0xf0,0x63,0xa2,0xd8,0x76,0x9e,0x49,0x78,0x64,0x1f,0x98,
	0xbc,0xee,0x7c,0x99
	};

static const unsigned char aes_192_no_df_additionalinput2[] =
	{
	0x54,0x48,0xf9,0x6a,0x86,0x93,0xf3,0x7b,0x02,0x1b,0xf6,0x46,
	0x3a,0x49,0x02,0x87,0x3f,0x54,0x82,0x7f,0xa1,0x45,0x41,0xa5,
	0x88,0x4b,0xaa,0x90,0x12,0x40,0x46,0x22,0xed,0x7a,0x72,0xf7,
	0x36,0xd5,0x5f,0x0f
	};

static const unsigned char aes_192_no_df_entropyinputpr2[] =
	{
	0x00,0xdf,0xa1,0x50,0xc1,0xb9,0x82,0x7f,0x65,0xea,0x0f,0x14,
	0x79,0xfe,0x6a,0x95,0x4b,0x96,0xae,0x89,0x28,0x52,0x49,0x05,
	0xd9,0x00,0x9e,0x79,0x5e,0x04,0xdb,0xbb,0xec,0x09,0x16,0x53,
	0x23,0xe9,0xac,0x08
	};

static const unsigned char aes_192_no_df_returnedbits[] =
	{
	0x48,0xd6,0x66,0x61,0x93,0x8d,0xff,0x7d,0x42,0xf4,0x41,0x9a,
	0x01,0x2a,0x34,0x09
	};


/* AES-256 no df PR */
static const unsigned char aes_256_no_df_entropyinput[] =
	{
	0x7e,0x83,0x3f,0xa6,0x39,0xdc,0xcb,0x38,0x17,0x6a,0xa3,0x59,
	0xa9,0x8c,0x1f,0x50,0xd3,0xdb,0x34,0xdd,0xa4,0x39,0x65,0xe4,
	0x77,0x17,0x08,0x57,0x49,0x04,0xbd,0x68,0x5c,0x7d,0x2a,0xee,
	0x0c,0xf2,0xfb,0x16,0xef,0x16,0x18,0x4d,0x32,0x6a,0x26,0x6c
	};

static const unsigned char aes_256_no_df_nonce[] =
	{
	0xa3,0x8a,0xa4,0x6d,0xa6,0xc1,0x40,0xf8,0xa3,0x02,0xf1,0xac,
	0xf3,0xea,0x7f,0x2d
	};

static const unsigned char aes_256_no_df_personalizationstring[] =
	{
	0xc0,0x54,0x1e,0xa5,0x93,0xd9,0x8b,0x2b,0x43,0x15,0x2c,0x07,
	0x26,0x25,0xc7,0x08,0xf0,0xb3,0x4b,0x44,0x96,0xfe,0xc7,0xc5,
	0x64,0x27,0xaa,0x78,0x5b,0xbc,0x40,0x51,0xce,0x89,0x6b,0xc1,
	0x3f,0x9c,0xa0,0x5c,0x75,0x98,0x24,0xc5,0xe1,0x3e,0x86,0xdb
	};

static const unsigned char aes_256_no_df_additionalinput[] =
	{
	0x0e,0xe3,0x0f,0x07,0x90,0xe2,0xde,0x20,0xb6,0xf7,0x6f,0xef,
	0x87,0xdc,0x7f,0xc4,0x0d,0x9d,0x05,0x31,0x91,0x87,0x8c,0x9a,
	0x19,0x53,0xd2,0xf8,0x20,0x91,0xa0,0xef,0x97,0x59,0xea,0x12,
	0x1b,0x2f,0x29,0x74,0x76,0x35,0xf7,0x71,0x5a,0x96,0xeb,0xbc
	};

static const unsigned char aes_256_no_df_entropyinputpr[] =
	{
	0x37,0x26,0x9a,0xa6,0x28,0xe0,0x35,0x78,0x12,0x42,0x44,0x5c,
	0x55,0xbc,0xc8,0xb6,0x1f,0x24,0xf3,0x32,0x88,0x02,0x69,0xa7,
	0xed,0x1d,0xb7,0x4d,0x8b,0x44,0x12,0x21,0x5e,0x60,0x53,0x96,
	0x3b,0xb9,0x31,0x7f,0x2a,0x87,0xbf,0x3c,0x07,0xbb,0x27,0x22
	};

static const unsigned char aes_256_no_df_additionalinput2[] =
	{
	0xf1,0x24,0x35,0xa6,0x8c,0x93,0x28,0x7e,0x84,0xea,0x3d,0x27,
	0x44,0x18,0xc9,0x13,0x73,0x49,0xb9,0x83,0x79,0x15,0x29,0x53,
	0x2f,0xef,0x43,0x06,0xe7,0xcb,0x5c,0x0f,0x9f,0x10,0x4c,0x60,
	0x7f,0xbf,0x0c,0x37,0x9b,0xe4,0x94,0x26,0xe5,0x3b,0xf5,0x63
	};

static const unsigned char aes_256_no_df_entropyinputpr2[] =
	{
	0xdc,0x91,0x48,0x11,0x63,0x7b,0x79,0x41,0x36,0x8c,0x4f,0xe2,
	0xc9,0x84,0x04,0x9c,0xdc,0x5b,0x6c,0x8d,0x61,0x52,0xea,0xfa,
	0x92,0x3b,0xb4,0x36,0x4c,0x06,0x4a,0xd1,0xb1,0x8e,0x32,0x03,
	0xfd,0xa4,0xf7,0x5a,0xa6,0x5c,0x63,0xa1,0xb9,0x96,0xfa,0x12
	};

static const unsigned char aes_256_no_df_returnedbits[] =
	{
	0x1c,0xba,0xfd,0x48,0x0f,0xf4,0x85,0x63,0xd6,0x7d,0x91,0x14,
	0xef,0x67,0x6b,0x7f
	};

/* SHA-1 PR */
static const unsigned char sha1_entropyinput[] =
	{
	0x5b,0xaf,0x30,0x1a,0xdc,0xd1,0x04,0xd7,0x95,0x72,0xd2,0xfb,
	0xec,0x2d,0x62,0x2b
	};

static const unsigned char sha1_nonce[] =
	{
	0xf3,0xd9,0xcb,0x92,0x5f,0x50,0x4c,0x99
	};

static const unsigned char sha1_personalizationstring[] =
	{
	0x8f,0x56,0x70,0xd9,0x27,0xa2,0xb4,0xf1,0xb3,0xad,0xcf,0x10,
	0x06,0x16,0x5c,0x11
	};

static const unsigned char sha1_additionalinput[] =
	{
	0x49,0xdd,0x0c,0xb4,0xab,0x84,0xe1,0x7e,0x94,0x20,0xad,0x6c,
	0xd7,0xd2,0x0b,0x84
	};

static const unsigned char sha1_entropyinputpr[] =
	{
	0x23,0x4a,0xaf,0xf7,0x1a,0x0b,0x7e,0x51,0xdd,0x23,0x51,0x82,
	0x2c,0x8c,0xa6,0xc5
	};

static const unsigned char sha1_additionalinput2[] =
	{
	0x59,0xe6,0x93,0xcb,0x38,0x23,0xf5,0x7b,0x93,0x5a,0x4d,0xfa,
	0x11,0xb8,0x88,0xde
	};

static const unsigned char sha1_entropyinputpr2[] =
	{
	0x2e,0x00,0x78,0x5a,0xcd,0x30,0xea,0x73,0x37,0x8a,0x0d,0x12,
	0x50,0x28,0x28,0x03
	};

static const unsigned char sha1_returnedbits[] =
	{
	0xe7,0x87,0x8b,0x01,0xc1,0xd3,0xd8,0x43,0xd4,0x8f,0xcd,0x24,
	0x54,0x67,0xa2,0x6e,0x17,0x94,0x73,0x1c
	};


/* SHA-224 PR */
static const unsigned char sha224_entropyinput[] =
	{
	0xfc,0x31,0xc1,0x87,0x43,0x07,0xb1,0xe5,0x71,0x48,0x5d,0x0e,
	0xad,0xf8,0x68,0x09,0x6f,0xfe,0x80,0x2a,0xc1,0x12,0xb8,0xa6
	};

static const unsigned char sha224_nonce[] =
	{
	0xfd,0xba,0x25,0x2e,0xc1,0x7c,0x4e,0xa1,0x4d,0xef,0xeb,0x5d
	};

static const unsigned char sha224_personalizationstring[] =
	{
	0xc9,0x15,0xe4,0x8c,0x2a,0x4c,0xc9,0xe6,0x23,0x5c,0xb8,0x5a,
	0x97,0x89,0x6a,0x10,0x75,0x68,0x27,0x00,0x0e,0x6f,0x44,0x1e
	};

static const unsigned char sha224_additionalinput[] =
	{
	0xd3,0xab,0x74,0x74,0xe7,0x80,0x87,0x9e,0x89,0x08,0xbe,0xf1,
	0x99,0x09,0x26,0xa4,0x2b,0x8c,0xb7,0xa0,0xc2,0xcc,0xae,0x0a
	};

static const unsigned char sha224_entropyinputpr[] =
	{
	0xbd,0xc1,0x21,0x62,0x43,0x19,0x25,0x15,0x19,0xc5,0xcd,0x53,
	0x9e,0xb4,0x17,0xff,0xaa,0x03,0xf6,0x5a,0x4d,0x69,0x28,0x0b
	};

static const unsigned char sha224_additionalinput2[] =
	{
	0xdb,0xf5,0x57,0xea,0x5b,0xc8,0x0a,0xa9,0x32,0x72,0xcf,0x7d,
	0xa4,0xeb,0x4f,0xbf,0x64,0x5d,0x74,0x04,0x0e,0x4e,0x0f,0xed
	};

static const unsigned char sha224_entropyinputpr2[] =
	{
	0xab,0xce,0xe1,0xfd,0xaa,0x35,0x5c,0x0a,0xfe,0xd8,0x18,0xac,
	0x92,0x79,0x79,0x53,0xbc,0xb5,0x45,0xf6,0xf9,0x73,0x7f,0x24
	};

static const unsigned char sha224_returnedbits[] =
	{
	0xb2,0xc2,0x40,0xc4,0x2a,0x25,0x63,0xdb,0x99,0x59,0x7b,0x7b,
	0xee,0xdb,0x51,0x8d,0x18,0x4c,0x09,0x26,0x22,0x1a,0xe9,0x76,
	0x54,0x5f,0xb5,0x28
	};


/* SHA-256 PR */
static const unsigned char sha256_entropyinput[] =
	{
	0xbc,0x67,0x4e,0x95,0xf1,0xca,0x71,0xdd,0xd3,0x97,0x3a,0x39,
	0x3f,0x3d,0x7f,0xf2,0x99,0x02,0xcf,0x12,0x02,0xea,0xcc,0xf3,
	0xd7,0xe7,0xcc,0x08,0x6c,0x41,0xb1,0xed
	};

static const unsigned char sha256_nonce[] =
	{
	0x44,0x06,0xa7,0x61,0x15,0x0a,0x6a,0x2d,0xa9,0x18,0x10,0xb5,
	0x6d,0xf0,0xd4,0xf7
	};

static const unsigned char sha256_personalizationstring[] =
	{
	0x8f,0x39,0xd5,0x6a,0x46,0xde,0xa2,0x57,0xdf,0x39,0xdb,0xca,
	0x13,0xca,0x51,0x0f,0x43,0x2a,0x77,0x3a,0x38,0x7a,0x3b,0x35,
	0x1e,0x13,0x26,0x0e,0xc1,0x6b,0xb6,0x81
	};

static const unsigned char sha256_additionalinput[] =
	{
	0x95,0x01,0xbe,0x52,0xaa,0xc4,0x32,0x5a,0x3c,0xea,0x57,0xc4,
	0x5c,0xfa,0x25,0x4e,0xc5,0xf3,0xc2,0xa6,0x39,0xce,0x00,0x97,
	0x19,0x50,0x17,0x71,0x44,0x13,0xa5,0xbd
	};

static const unsigned char sha256_entropyinputpr[] =
	{
	0x8e,0x8a,0x19,0x03,0xa7,0x77,0xaa,0x64,0x4f,0x11,0x45,0x1d,
	0x66,0x74,0x88,0xdf,0x2c,0x9b,0xc3,0xc8,0xbb,0x8c,0x99,0x34,
	0xc6,0xc7,0xdb,0xc1,0x92,0xef,0xa3,0xa3
	};

static const unsigned char sha256_additionalinput2[] =
	{
	0x2b,0x91,0x7f,0xf3,0x78,0x3f,0x18,0x73,0x7c,0x5f,0xc2,0xda,
	0x1d,0x8c,0xc4,0xcd,0x74,0x4d,0xc1,0x7a,0x6c,0xe2,0x73,0x07,
	0x9d,0x55,0xa8,0x42,0x69,0xc0,0x7c,0x85
	};

static const unsigned char sha256_entropyinputpr2[] =
	{
	0x4c,0x3f,0xee,0x8b,0x98,0x0e,0x55,0x7e,0xab,0xc3,0xd3,0x0e,
	0x35,0x33,0x72,0x75,0x9f,0x4b,0x87,0xce,0x05,0xbe,0xd4,0x6b,
	0x70,0xec,0xdb,0x5a,0x57,0x14,0x83,0x34
	};

static const unsigned char sha256_returnedbits[] =
	{
	0xa5,0x2c,0xab,0x93,0x63,0x57,0x5d,0x60,0x80,0x4c,0x71,0xbb,
	0xc2,0x3d,0x43,0x13,0xd8,0xe1,0x60,0x63,0x5e,0xf8,0xb1,0x4c,
	0x93,0x06,0x86,0x9e,0x03,0x0a,0x16,0x75
	};


/* SHA-384 PR */
static const unsigned char sha384_entropyinput[] =
	{
	0xad,0x6c,0xfb,0xdd,0x40,0xd9,0xf1,0x0a,0xc6,0xe4,0x28,0xf9,
	0x8c,0xb1,0x66,0xce,0x7e,0x7f,0xbb,0xea,0xcd,0x79,0x3d,0x54,
	0xc6,0xc0,0x07,0x68,0xf0,0xb7,0x73,0xc5
	};

static const unsigned char sha384_nonce[] =
	{
	0xfb,0xe1,0xb2,0x81,0x77,0xb0,0x14,0x94,0xae,0xbb,0x8d,0x01,
	0xfb,0x74,0xc9,0xa1
	};

static const unsigned char sha384_personalizationstring[] =
	{
	0x02,0x8e,0xa9,0xc2,0x7e,0x0e,0x78,0xea,0x29,0xca,0x19,0xd4,
	0x58,0x89,0x71,0x45,0x18,0xd9,0x1f,0xc0,0x8f,0x92,0x02,0xb8,
	0x90,0xa7,0xec,0xf6,0x7f,0x33,0xa6,0x47
	};

static const unsigned char sha384_additionalinput[] =
	{
	0x98,0x0e,0xe3,0x3c,0x8e,0x6b,0x82,0xc0,0x56,0xd0,0x93,0x14,
	0x6a,0x79,0xa8,0xec,0x09,0xb7,0x49,0x01,0x71,0xdb,0x58,0x97,
	0x5a,0x61,0xa5,0x4e,0xb4,0x5f,0xce,0x2b
	};

static const unsigned char sha384_entropyinputpr[] =
	{
	0x50,0xef,0xaa,0x65,0x95,0x0d,0x4f,0x97,0x3e,0x57,0x59,0x48,
	0xf9,0x4e,0xee,0x51,0xf8,0x46,0xec,0x4c,0x2d,0x55,0x47,0x23,
	0xc5,0x7b,0xa3,0xda,0xe5,0x12,0x34,0x9a
	};

static const unsigned char sha384_additionalinput2[] =
	{
	0x1c,0xcd,0xe0,0xc1,0x15,0xd4,0x7f,0xfa,0x9e,0x16,0xe7,0x6d,
	0x22,0x55,0xfd,0x34,0x3f,0xec,0x1d,0x40,0x9e,0xdd,0x15,0x07,
	0x13,0x1c,0x65,0x6e,0xf7,0x1c,0xb6,0xf8
	};

static const unsigned char sha384_entropyinputpr2[] =
	{
	0xa0,0x8b,0x48,0xdc,0x7b,0x74,0x54,0xd0,0x0a,0x10,0x0e,0xc9,
	0xf2,0xe0,0xf0,0x30,0x38,0xf5,0x46,0x27,0xf4,0x54,0x06,0x95,
	0x56,0xab,0xf4,0x74,0xd8,0x34,0xf5,0x5d
	};

static const unsigned char sha384_returnedbits[] =
	{
	0x03,0x54,0x62,0xaa,0x5c,0x61,0x28,0xfc,0x96,0x04,0xd6,0x4f,
	0x50,0x5c,0x9e,0x7c,0x9e,0x1d,0x41,0x76,0x41,0xa0,0x60,0x70,
	0x62,0x4f,0x42,0x1a,0x69,0xce,0x30,0xc4,0xf7,0x89,0xc8,0x93,
	0xed,0xe9,0x42,0xf4,0x59,0x55,0x7c,0x6c,0xd3,0x4e,0xff,0x05
	};


/* SHA-512 PR */
static const unsigned char sha512_entropyinput[] =
	{
	0x22,0xb1,0x72,0xe3,0xc4,0x87,0xe7,0x76,0x4e,0x85,0xb5,0xca,
	0x86,0x4f,0x21,0x2b,0x4f,0x29,0x8e,0x8a,0xfc,0x88,0xfc,0xa1,
	0xf6,0xd7,0xc1,0x63,0x90,0x8d,0x85,0xa9
	};

static const unsigned char sha512_nonce[] =
	{
	0xcc,0x8b,0x86,0x21,0xa7,0xbe,0xd3,0xe1,0xde,0xd2,0x47,0xfc,
	0x9c,0x4a,0xdb,0x85
	};

static const unsigned char sha512_personalizationstring[] =
	{
	0xb7,0x7c,0xb3,0x4f,0xf8,0xcd,0x19,0x89,0xdb,0x0c,0xcf,0xc9,
	0xce,0xcd,0x48,0xcd,0x62,0x9c,0x51,0x38,0x85,0xe4,0x6c,0x17,
	0x02,0x1b,0x6b,0xb5,0x3c,0x31,0x4f,0xa1
	};

static const unsigned char sha512_additionalinput[] =
	{
	0x69,0x3f,0xcf,0xf5,0x38,0x09,0x0d,0x3c,0xfb,0xea,0x94,0xa6,
	0xf3,0xdc,0xb3,0xa8,0xcb,0x61,0x3b,0x8d,0x8e,0x31,0x94,0xc2,
	0xe8,0x20,0x1c,0x62,0xa0,0x54,0xc2,0x03
	};

static const unsigned char sha512_entropyinputpr[] =
	{
	0xa0,0xcf,0x6f,0x0f,0x55,0x88,0x84,0xad,0x8d,0x2e,0x08,0x91,
	0x8a,0x65,0xc0,0xb4,0xc9,0xbe,0x21,0x29,0xbe,0x23,0x2d,0x2b,
	0xd1,0x81,0x90,0x66,0x97,0xb6,0xfa,0x84
	};

static const unsigned char sha512_additionalinput2[] =
	{
	0x1f,0x5e,0x49,0xb5,0xa3,0xfa,0xe8,0x89,0xc5,0x1b,0x39,0x2b,
	0x9e,0xc7,0x36,0x85,0x5b,0xa9,0x9f,0x91,0x79,0xfe,0x5c,0xe6,
	0x41,0xbe,0x14,0x87,0x81,0x08,0x0d,0xee
	};
/* NB: not constant so we can corrupt it */
static unsigned char sha512_entropyinputpr2[] =
	{
	0xed,0x22,0x42,0x61,0xa7,0x4c,0xed,0xc7,0x10,0x82,0x61,0x17,
	0xaa,0x7d,0xdb,0x4e,0x1c,0x96,0x61,0x23,0xcd,0x8f,0x84,0x77,
	0xc3,0xa2,0x55,0xff,0xbb,0xc9,0xa6,0x2f
	};

static const unsigned char sha512_returnedbits[] =
	{
	0x79,0x60,0x41,0xaa,0x6c,0xdd,0x17,0x28,0xc0,0x4d,0xc0,0x17,
	0xc0,0x66,0x46,0x67,0x0d,0x20,0xe2,0x67,0x96,0xd5,0x2a,0xf4,
	0x58,0x0a,0x06,0xab,0xc1,0x4c,0x70,0xc1,0xb8,0x9d,0x68,0x79,
	0x28,0x07,0x38,0x4a,0xc3,0xec,0x3b,0x19,0x02,0xe7,0x13,0x82,
	0x8f,0xc3,0xed,0x59,0x88,0xdd,0x88,0xaf,0xac,0xf0,0x57,0x6c,
	0x14,0x0b,0x50,0x11
	};



static DRBG_SELFTEST_DATA drbg_test[] = {
	make_drbg_test_data_df(NID_aes_128_ctr, aes_128_use_df),
	make_drbg_test_data_df(NID_aes_192_ctr, aes_192_use_df),
	make_drbg_test_data_df(NID_aes_256_ctr, aes_256_use_df),
	make_drbg_test_data(NID_aes_128_ctr, 0, aes_128_no_df),
	make_drbg_test_data(NID_aes_192_ctr, 0, aes_192_no_df),
	make_drbg_test_data(NID_aes_256_ctr, 0, aes_256_no_df),
	make_drbg_test_data(NID_sha1, 0, sha1),
	make_drbg_test_data(NID_sha224, 0, sha224),
	make_drbg_test_data(NID_sha256, 0, sha256),
	make_drbg_test_data(NID_sha384, 0, sha384),
	make_drbg_test_data(NID_sha512, 0, sha512),
	{0,0,0}
	};

typedef struct 
	{
	const unsigned char *ent;
	size_t entlen;
	int entcnt;
	const unsigned char *nonce;
	size_t noncelen;
	int noncecnt;
	} TEST_ENT;

static size_t test_entropy(DRBG_CTX *dctx, unsigned char *out,
                                int entropy, size_t min_len, size_t max_len)
	{
	TEST_ENT *t = FIPS_drbg_get_app_data(dctx);
	memcpy(out, t->ent, t->entlen);
	t->entcnt++;
	return t->entlen;
	}

static size_t test_nonce(DRBG_CTX *dctx, unsigned char *out,
                                int entropy, size_t min_len, size_t max_len)
	{
	TEST_ENT *t = FIPS_drbg_get_app_data(dctx);
	memcpy(out, t->nonce, t->noncelen);
	t->noncecnt++;
	return t->noncelen;
	}

void FIPS_corrupt_drbg(void)
	{
	sha512_entropyinputpr2[0]++;
	}

static int fips_drbg_single_kat(DRBG_CTX *dctx, DRBG_SELFTEST_DATA *td)
	{
	TEST_ENT t;
	int rv = 0;
	unsigned char randout[1024];
	if (!FIPS_drbg_init(dctx, td->nid, td->flags))
		return 0;
	if (!FIPS_drbg_set_callbacks(dctx, test_entropy, test_nonce))
		return 0;

	FIPS_drbg_set_app_data(dctx, &t);

	t.ent = td->ent;
	t.entlen = td->entlen;
	t.nonce = td->nonce;
	t.noncelen = td->noncelen;
	t.entcnt = 0;
	t.noncecnt = 0;

	if (!FIPS_drbg_instantiate(dctx, td->pers, td->perslen))
		goto err;

	t.ent = td->entpr;
	t.entlen = td->entprlen;

	if (!FIPS_drbg_generate(dctx, randout, td->katlen, 0, 1,
				td->adin, td->adinlen))
		goto err;

	t.ent = td->entg;
	t.entlen = td->entglen;

	if (!FIPS_drbg_generate(dctx, randout, td->katlen, 0, 1,
				td->ading, td->adinglen))
		goto err;

	if (memcmp(randout, td->kat, td->katlen))
		goto err;

	rv = 1;

	err:
	FIPS_drbg_uninstantiate(dctx);
	
	return rv;
	}

/* This is the "health check" function required by SP800-90. Induce several
 * failure modes and check an error condition is set.
 */

static int fips_drbg_health_check(DRBG_CTX *dctx, DRBG_SELFTEST_DATA *td)
	{
	unsigned char randout[1024];
	TEST_ENT t;
	size_t i;
	unsigned char *p = (unsigned char *)dctx;

	/* Initialise DRBG */

	if (!FIPS_drbg_init(dctx, td->nid, td->flags))
		goto err;

	if (!FIPS_drbg_set_callbacks(dctx, test_entropy, test_nonce))
		goto err;

	FIPS_drbg_set_app_data(dctx, &t);

	t.ent = td->ent;
	t.entlen = td->entlen;
	t.nonce = td->nonce;
	t.noncelen = td->noncelen;
	t.entcnt = 0;
	t.noncecnt = 0;

	/* Don't report induced errors */
	dctx->flags |= DRBG_FLAG_NOERR;

	/* Try too large a personalisation length */
	if (FIPS_drbg_instantiate(dctx, td->pers, dctx->max_pers + 1) > 0)
		{
		FIPSerr(FIPS_F_FIPS_DRBG_HEALTH_CHECK, FIPS_R_PERSONALISATION_ERROR_UNDETECTED);
		goto err;
		}

	/* Test entropy source failure detection */

	t.entlen = 0;
	if (FIPS_drbg_instantiate(dctx, td->pers, td->perslen) > 0)
		{
		FIPSerr(FIPS_F_FIPS_DRBG_HEALTH_CHECK, FIPS_R_ENTROPY_ERROR_UNDETECTED);
		goto err;
		}

	/* Try to generate output from uninstantiated DRBG */
	if (FIPS_drbg_generate(dctx, randout, td->katlen, 0, 0,
				td->adin, td->adinlen))
		{
		FIPSerr(FIPS_F_FIPS_DRBG_HEALTH_CHECK, FIPS_R_GENERATE_ERROR_UNDETECTED);
		goto err;
		}

	/* Instantiate with valid data. NB: errors now reported again */
	if (!FIPS_drbg_init(dctx, td->nid, td->flags))
		goto err;
	if (!FIPS_drbg_set_callbacks(dctx, test_entropy, test_nonce))
		goto err;
	FIPS_drbg_set_app_data(dctx, &t);

	t.entlen = td->entlen;
	if (!FIPS_drbg_instantiate(dctx, td->pers, td->perslen))
		goto err;

	/* Check generation is now OK */
	if (!FIPS_drbg_generate(dctx, randout, td->katlen, 0, 0,
				td->adin, td->adinlen))
		goto err;

	/* Try to generate with too high a strength.
	 */

	dctx->flags |= DRBG_FLAG_NOERR;
	if (dctx->strength != 256)
		{
		if (FIPS_drbg_generate(dctx, randout, td->katlen, 256, 0,
					td->adin, td->adinlen))
			{
			FIPSerr(FIPS_F_FIPS_DRBG_HEALTH_CHECK, FIPS_R_STRENGTH_ERROR_UNDETECTED);

			goto err;
			}
		}

	/* Request too much data for one request */
	if (FIPS_drbg_generate(dctx, randout, dctx->max_request + 1, 0, 0,
				td->adin, td->adinlen))
		{
		FIPSerr(FIPS_F_FIPS_DRBG_HEALTH_CHECK, FIPS_R_REQUEST_LENGTH_ERROR_UNDETECTED);
		goto err;
		}

	/* Check prediction resistance request fails if entropy source
	 * failure.
	 */

	t.entlen = 0;

	if (FIPS_drbg_generate(dctx, randout, td->katlen, 0, 1,
				td->adin, td->adinlen))
		{
		FIPSerr(FIPS_F_FIPS_DRBG_HEALTH_CHECK, FIPS_R_ENTROPY_ERROR_UNDETECTED);
		goto err;
		}
		

	/* Instantiate again with valid data */

	if (!FIPS_drbg_init(dctx, td->nid, td->flags))
		goto err;
	if (!FIPS_drbg_set_callbacks(dctx, test_entropy, test_nonce))
		goto err;
	FIPS_drbg_set_app_data(dctx, &t);

	t.entlen = td->entlen;
	/* Test reseeding works */
	dctx->reseed_interval = 2;
	if (!FIPS_drbg_instantiate(dctx, td->pers, td->perslen))
		goto err;

	/* Check generation is now OK */
	if (!FIPS_drbg_generate(dctx, randout, td->katlen, 0, 0,
				td->adin, td->adinlen))
		goto err;
	if (!FIPS_drbg_generate(dctx, randout, td->katlen, 0, 0,
				td->adin, td->adinlen))
		goto err;

	/* DRBG should now require a reseed */
	if (dctx->status != DRBG_STATUS_RESEED)
		{
		FIPSerr(FIPS_F_FIPS_DRBG_HEALTH_CHECK, FIPS_R_RESEED_COUNTER_ERROR);
		goto err;
		}


	/* Generate again and check entropy has been requested for reseed */
	t.entcnt = 0;
	if (!FIPS_drbg_generate(dctx, randout, td->katlen, 0, 0,
				td->adin, td->adinlen))
		goto err;
	if (t.entcnt != 1)
		{
		FIPSerr(FIPS_F_FIPS_DRBG_HEALTH_CHECK, FIPS_R_ENTROPY_NOT_REQUESTED_FOR_RESEED);
		goto err;
		}

	FIPS_drbg_uninstantiate(dctx);
	p = (unsigned char *)dctx;
	/* Standard says we have to check uninstantiate really zeroes
	 * the data...
	 */
	for (i = 0; i < sizeof(DRBG_CTX); i++)
		{
		if (*p != 0)
			{
			FIPSerr(FIPS_F_FIPS_DRBG_HEALTH_CHECK, FIPS_R_UNINSTANTIATE_ZEROISE_ERROR);
			goto err;
			}
		p++;
		}

	return 1;

	err:
	/* A real error as opposed to an induced one: underlying function will
	 * indicate the error.
	 */
	if (!(dctx->flags & DRBG_FLAG_NOERR))
		FIPSerr(FIPS_F_FIPS_DRBG_HEALTH_CHECK, FIPS_R_FUNCTION_ERROR);
	FIPS_drbg_uninstantiate(dctx);
	return 0;

	}
		

int fips_drbg_kat(DRBG_CTX *dctx, int nid, unsigned int flags)
	{
	int rv;
	DRBG_SELFTEST_DATA *td;
	for (td = drbg_test; td->nid != 0; td++)
		{
		if (td->nid == nid && td->flags == flags)
			{
			rv = fips_drbg_single_kat(dctx, td);
			if (rv <= 0)
				return rv;
			return fips_drbg_health_check(dctx, td);
			}
		}
	return 0;
	}

int FIPS_selftest_drbg(void)
	{
	DRBG_CTX *dctx;
	DRBG_SELFTEST_DATA *td;
	dctx = FIPS_drbg_new(0, 0);
	if (!dctx)
		return 0;
	for (td = drbg_test; td->nid != 0; td++)
		{
		if (!fips_drbg_single_kat(dctx, td))
			break;
		if (!fips_drbg_health_check(dctx, td))
			break;
		}
	FIPS_drbg_free(dctx);
	if (td->nid == 0)
		return 1;
	return 0;
	}





/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 2006.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include "evp_locl.h"

extern int int_rsa_verify(int dtype, const unsigned char *m, unsigned int m_len,
		unsigned char *rm, unsigned int *prm_len,
		const unsigned char *sigbuf, unsigned int siglen,
		RSA *rsa);

/* RSA pkey context structure */

typedef struct
	{
	/* Key gen parameters */
	int nbits;
	BIGNUM *pub_exp;
	/* RSA padding mode */
	int pad_mode;
	/* message digest */
	const EVP_MD *md;
	/* PSS seedlength */
	int pss_seedlen;
	/* Temp buffer */
	unsigned char *tbuf;
	} RSA_PKEY_CTX;

static int pkey_rsa_init(EVP_PKEY_CTX *ctx)
	{
	RSA_PKEY_CTX *rctx;
	rctx = OPENSSL_malloc(sizeof(RSA_PKEY_CTX));
	if (!rctx)
		return 0;
	rctx->nbits = 1024;
	rctx->pub_exp = NULL;
	rctx->pad_mode = RSA_PKCS1_PADDING;
	rctx->md = NULL;
	rctx->tbuf = NULL;

	rctx->pss_seedlen = 0;

	ctx->data = rctx;
	
	return 1;
	}

static int setup_tbuf(RSA_PKEY_CTX *ctx, EVP_PKEY_CTX *pk)
	{
	if (ctx->tbuf)
		return 1;
	ctx->tbuf = OPENSSL_malloc(EVP_PKEY_size(pk->pkey));
	if (!ctx->tbuf)
		return 0;
	return 1;
	}

static void pkey_rsa_cleanup(EVP_PKEY_CTX *ctx)
	{
	RSA_PKEY_CTX *rctx = ctx->data;
	if (rctx)
		{
		if (rctx->pub_exp)
			BN_free(rctx->pub_exp);
		if (rctx->tbuf)
			OPENSSL_free(rctx->tbuf);
		}
	OPENSSL_free(rctx);
	}

static int pkey_rsa_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, int *siglen,
					const unsigned char *tbs, int tbslen)
	{
	int ret;
	RSA_PKEY_CTX *rctx = ctx->data;

	if (rctx->md)
		{
		if (tbslen != EVP_MD_size(rctx->md))
			{
			RSAerr(RSA_F_PKEY_RSA_SIGN,
					RSA_R_INVALID_DIGEST_LENGTH);
			return -1;
			}
		if (rctx->pad_mode == RSA_X931_PADDING)
			{
			if (!setup_tbuf(rctx, ctx))
				return -1;
			memcpy(rctx->tbuf, tbs, tbslen);
			rctx->tbuf[tbslen] =
				RSA_X931_hash_id(EVP_MD_type(rctx->md));
			ret = RSA_private_encrypt(tbslen + 1, rctx->tbuf,
						sig, ctx->pkey->pkey.rsa,
						RSA_X931_PADDING);
			}
		else if (rctx->pad_mode == RSA_PKCS1_PADDING)
			{
			unsigned int sltmp;
			ret = RSA_sign(EVP_MD_type(rctx->md),
						tbs, tbslen, sig, &sltmp,
							ctx->pkey->pkey.rsa);
			if (ret <= 0)
				return ret;
			ret = sltmp;
			}
		else
			return -1;
		}
	else
		ret = RSA_private_encrypt(tbslen, tbs, sig, ctx->pkey->pkey.rsa,
							rctx->pad_mode);
	if (ret < 0)
		return ret;
	*siglen = ret;
	return 1;
	}


static int pkey_rsa_verifyrecover(EVP_PKEY_CTX *ctx,
					unsigned char *rout, int *routlen,
                                        const unsigned char *sig, int siglen)
	{
	int ret;
	RSA_PKEY_CTX *rctx = ctx->data;

	if (rctx->md)
		{
		if (rctx->pad_mode == RSA_X931_PADDING)
			{
			if (!setup_tbuf(rctx, ctx))
				return -1;
			ret = RSA_public_decrypt(siglen, sig,
						rctx->tbuf, ctx->pkey->pkey.rsa,
						RSA_X931_PADDING);
			if (ret < 1)
				return 0;
			ret--;
			if (rctx->tbuf[ret] !=
				RSA_X931_hash_id(EVP_MD_type(rctx->md)))
				{
				RSAerr(RSA_F_PKEY_RSA_VERIFYRECOVER,
						RSA_R_ALGORITHM_MISMATCH);
				return 0;
				}
			if (ret != EVP_MD_size(rctx->md))
				{
				RSAerr(RSA_F_PKEY_RSA_VERIFYRECOVER,
					RSA_R_INVALID_DIGEST_LENGTH);
				return 0;
				}
			if (rout)
				memcpy(rout, rctx->tbuf, ret);
			}
		else if (rctx->pad_mode == RSA_PKCS1_PADDING)
			{
			unsigned int sltmp;
			ret = int_rsa_verify(EVP_MD_type(rctx->md),
						NULL, 0, rout, &sltmp,
					sig, siglen, ctx->pkey->pkey.rsa);
			ret = sltmp;
			}
		else
			return -1;
		}
	else
		ret = RSA_public_decrypt(siglen, sig, rout, ctx->pkey->pkey.rsa,
							rctx->pad_mode);
	if (ret < 0)
		return ret;
	*routlen = ret;
	return 1;
	}

static int pkey_rsa_verify(EVP_PKEY_CTX *ctx,
					const unsigned char *sig, int siglen,
                                        const unsigned char *tbs, int tbslen)
	{
	RSA_PKEY_CTX *rctx = ctx->data;
	int rslen;
	if (rctx->md)
		{
		if (rctx->pad_mode == RSA_PKCS1_PADDING)
			return RSA_verify(EVP_MD_type(rctx->md), tbs, tbslen,
					sig, siglen, ctx->pkey->pkey.rsa);
		if (rctx->pad_mode == RSA_X931_PADDING)
			{
			if (pkey_rsa_verifyrecover(ctx, NULL, &rslen,
					sig, siglen) <= 0)
				return 0;
			}
		else
			return -1;
		}
	else
		{
		if (!setup_tbuf(rctx, ctx))
			return -1;
		rslen = RSA_public_decrypt(siglen, sig, rctx->tbuf,
					ctx->pkey->pkey.rsa, rctx->pad_mode);
		if (rslen <= 0)
			return 0;
		}

	if ((rslen != tbslen) || memcmp(tbs, rctx->tbuf, rslen))
		return 0;

	return 1;
			
	}
	

static int pkey_rsa_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, int *outlen,
                                        const unsigned char *in, int inlen)
	{
	int ret;
	RSA_PKEY_CTX *rctx = ctx->data;
	ret = RSA_public_encrypt(inlen, in, out, ctx->pkey->pkey.rsa,
							rctx->pad_mode);
	if (ret < 0)
		return ret;
	*outlen = ret;
	return 1;
	}

static int pkey_rsa_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, int *outlen,
                                        const unsigned char *in, int inlen)
	{
	int ret;
	RSA_PKEY_CTX *rctx = ctx->data;
	ret = RSA_private_decrypt(inlen, in, out, ctx->pkey->pkey.rsa,
							rctx->pad_mode);
	if (ret < 0)
		return ret;
	*outlen = ret;
	return 1;
	}

static int check_padding_md(const EVP_MD *md, int padding)
	{
	if (!md)
		return 1;
	if (padding == RSA_NO_PADDING)
		{
		RSAerr(RSA_F_CHECK_PADDING_NID, RSA_R_INVALID_PADDING_MODE);
		return 0;
		}

	if (padding == RSA_X931_PADDING)
		{
		if (RSA_X931_hash_id(EVP_MD_type(md)) == -1)
			{
			RSAerr(RSA_F_CHECK_PADDING_NID,
						RSA_R_INVALID_X931_DIGEST);
			return 0;
			}
		return 1;
		}

	return 1;
	}
			

static int pkey_rsa_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
	{
	RSA_PKEY_CTX *rctx = ctx->data;
	switch (type)
		{
		case EVP_PKEY_CTRL_RSA_PADDING:
		if ((p1 >= RSA_PKCS1_PADDING) && (p1 <= RSA_PKCS1_PSS_PADDING))
			{
			if (ctx->operation & EVP_PKEY_OP_TYPE_GEN)
				return -2;
			if (!check_padding_md(rctx->md, p1))
				return 0;
			if ((p1 == RSA_PKCS1_PSS_PADDING) 
				&& !(ctx->operation & EVP_PKEY_OP_TYPE_SIG))
				return -2;
			if ((p1 == RSA_PKCS1_OAEP_PADDING) 
				&& !(ctx->operation & EVP_PKEY_OP_TYPE_CRYPT))
				return -2;
			rctx->pad_mode = p1;
			return 1;
			}
		return -2;

		case EVP_PKEY_CTRL_MD:
		if (!check_padding_md(p2, rctx->pad_mode))
			return 0;
		rctx->md = p2;
		return 1;

		default:
		return -2;

		}
	}
			
static int pkey_rsa_ctrl_str(EVP_PKEY_CTX *ctx,
			const char *type, const char *value)
	{
	if (!strcmp(type, "rsa_padding_mode"))
		{
		int pm;
		if (!value)
			return 0;
		if (!strcmp(value, "pkcs1"))
			pm = RSA_PKCS1_PADDING;
		else if (!strcmp(value, "sslv23"))
			pm = RSA_SSLV23_PADDING;
		else if (!strcmp(value, "none"))
			pm = RSA_NO_PADDING;
		else if (!strcmp(value, "oeap"))
			pm = RSA_PKCS1_OAEP_PADDING;
		else if (!strcmp(value, "x931"))
			pm = RSA_X931_PADDING;
		else if (!strcmp(value, "pss"))
			pm = RSA_PKCS1_PSS_PADDING;
		else
			return -2;
		return EVP_PKEY_CTX_set_rsa_padding(ctx, pm);
		}
	return -2;
	}

const EVP_PKEY_METHOD rsa_pkey_meth = 
	{
	EVP_PKEY_RSA,
	0,
	pkey_rsa_init,
	pkey_rsa_cleanup,

	0,0,

	0,0,

	0,
	pkey_rsa_sign,

	0,
	pkey_rsa_verify,

	0,
	pkey_rsa_verifyrecover,


	0,0,0,0,

	0,
	pkey_rsa_encrypt,

	0,
	pkey_rsa_decrypt,

	pkey_rsa_ctrl,
	pkey_rsa_ctrl_str


	};

/* crypto/evp/digest.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/objects.h>
#include <openssl/evp.h>

void EVP_MD_CTX_init(EVP_MD_CTX *ctx)
	{
	memset(ctx,'\0',sizeof *ctx);
	}

EVP_MD_CTX *EVP_MD_CTX_create(void)
	{
	EVP_MD_CTX *ctx=OPENSSL_malloc(sizeof *ctx);

	EVP_MD_CTX_init(ctx);

	return ctx;
	}

int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type)
	{
	if(ctx->digest != type)
		{
		OPENSSL_free(ctx->md_data);
		ctx->digest=type;
		ctx->md_data=OPENSSL_malloc(type->ctx_size);
		}
	return type->init(ctx->md_data);
	}

int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *data,
	     unsigned int count)
	{
	return ctx->digest->update(ctx->md_data,data,(unsigned long)count);
	}

/* The caller can assume that this removes any secret data from the context */
int EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *size)
	{
	int ret;
	ret=ctx->digest->final(md,ctx->md_data);
	if (size != NULL)
		*size=ctx->digest->md_size;
	/* FIXME: add a cleanup function to the ctx? */
	memset(ctx->md_data,0,ctx->digest->ctx_size);
	return ret;
	}

int EVP_MD_CTX_copy(EVP_MD_CTX *out, const EVP_MD_CTX *in)
{
    if ((in == NULL) || (in->digest == NULL)) {
        EVPerr(EVP_F_EVP_MD_CTX_COPY,EVP_R_INPUT_NOT_INITIALIZED);
	return 0;
    }
    EVP_MD_CTX_cleanup(out);
    memcpy(out,in,sizeof *out);
    out->md_data=OPENSSL_malloc(out->digest->ctx_size);
    /* FIXME: we really need a per-MD copy function */
    memcpy(out->md_data,in->md_data,out->digest->ctx_size);
    return 1;
}

int EVP_Digest(void *data, unsigned int count,
		unsigned char *md, unsigned int *size, const EVP_MD *type)
{
	EVP_MD_CTX ctx;
	int ret;

	EVP_MD_CTX_init(&ctx);
	ret=EVP_DigestInit(&ctx, type)
	  && EVP_DigestUpdate(&ctx, data, count)
	  && EVP_DigestFinal(&ctx, md, size);
	EVP_MD_CTX_cleanup(&ctx);

	return ret;
}

void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx)
	{
	EVP_MD_CTX_cleanup(ctx);
	OPENSSL_free(ctx);
	}

/* This call frees resources associated with the context */
int EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx)
	{
	/* assume ctx->md_data was cleaned in EVP_Digest_Final */
	OPENSSL_free(ctx->md_data);
	memset(ctx,'\0',sizeof *ctx);

	return 1;
	}

/* crypto/engine/hw_cswift.c */
/* Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
#include <openssl/crypto.h>
#include "cryptlib.h"
#include <openssl/dso.h>
#include "engine_int.h"
#include <openssl/engine.h>

#ifdef HW_CSWIFT

/* Attribution notice: Rainbow have generously allowed me to reproduce
 * the necessary definitions here from their API. This means the support
 * can build independantly of whether application builders have the
 * API or hardware. This will allow developers to easily produce software
 * that has latent hardware support for any users that have accelerators
 * installed, without the developers themselves needing anything extra.
 *
 * I have only clipped the parts from the CryptoSwift header files that
 * are (or seem) relevant to the CryptoSwift support code. This is
 * simply to keep the file sizes reasonable.
 * [Geoff]
 */
#include "vendor_defns/cswift.h"

static int cswift_init();
static int cswift_finish();

static int cswift_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx);
static int cswift_mod_exp_crt(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *q, const BIGNUM *dmp1, const BIGNUM *dmq1,
		const BIGNUM *iqmp, BN_CTX *ctx);

static int cswift_rsa_mod_exp(BIGNUM *r0, BIGNUM *I, RSA *rsa);
/* This function is aliased to mod_exp (with the mont stuff dropped). */
static int cswift_mod_exp_mont(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);

/* Our internal RSA_METHOD that we provide const pointers to */
static RSA_METHOD cswift_rsa =
	{
	"CryptoSwift RSA method",
	NULL,
	NULL,
	NULL,
	NULL,
	cswift_rsa_mod_exp,
	cswift_mod_exp_mont,
	NULL,
	NULL,
	0,
	NULL,
	NULL,
	NULL
	};

/* Our ENGINE structure. */
static ENGINE engine_cswift =
        {
	"cswift",
	"CryptoSwift hardware support",
	&cswift_rsa,
	NULL,
	NULL,
	NULL,
	cswift_mod_exp,
	cswift_mod_exp_crt,
	cswift_init,
	cswift_finish,
	0, /* no flags */
	0, 0, /* no references */
	NULL, NULL /* unlinked */
        };

/* As this is only ever called once, there's no need for locking
 * (indeed - the lock will already be held by our caller!!!) */
ENGINE *ENGINE_cswift()
	{
	RSA_METHOD *meth;

	/* We know that the "PKCS1_SSLeay()" functions hook properly
	 * to the cswift-specific mod_exp and mod_exp_crt so we use
	 * those functions. NB: We don't use ENGINE_openssl() or
	 * anything "more generic" because something like the RSAref
	 * code may not hook properly, and if you own one of these
	 * cards then you have the right to do RSA operations on it
	 * anyway! */ 
	meth = RSA_PKCS1_SSLeay();
	cswift_rsa.rsa_pub_enc = meth->rsa_pub_enc;
	cswift_rsa.rsa_pub_dec = meth->rsa_pub_dec;
	cswift_rsa.rsa_priv_enc = meth->rsa_priv_enc;
	cswift_rsa.rsa_priv_dec = meth->rsa_priv_dec;
	return &engine_cswift;
	}

/* This is a process-global DSO handle used for loading and unloading
 * the CryptoSwift library. NB: This is only set (or unset) during an
 * init() or finish() call (reference counts permitting) and they're
 * operating with global locks, so this should be thread-safe
 * implicitly. */
static DSO *cswift_dso = NULL;

/* These are the function pointers that are (un)set when the library has
 * successfully (un)loaded. */
t_swAcquireAccContext *p_CSwift_AcquireAccContext = NULL;
t_swAttachKeyParam *p_CSwift_AttachKeyParam = NULL;
t_swSimpleRequest *p_CSwift_SimpleRequest = NULL;
t_swReleaseAccContext *p_CSwift_ReleaseAccContext = NULL;

/* Used in the DSO operations. */
static const char *CSWIFT_LIBNAME = "swift";
static const char *CSWIFT_F1 = "swAcquireAccContext";
static const char *CSWIFT_F2 = "swAttachKeyParam";
static const char *CSWIFT_F3 = "swSimpleRequest";
static const char *CSWIFT_F4 = "swReleaseAccContext";


/* CryptoSwift library functions and mechanics - these are used by the
 * higher-level functions further down. NB: As and where there's no
 * error checking, take a look lower down where these functions are
 * called, the checking and error handling is probably down there. */

/* utility function to obtain a context */
static int get_context(SW_CONTEXT_HANDLE *hac)
	{
        SW_STATUS status;
 
        status = p_CSwift_AcquireAccContext(hac);
        if(status != SW_OK)
                return 0;
        return 1;
	}
 
/* similarly to release one. */
static void release_context(SW_CONTEXT_HANDLE hac)
	{
        p_CSwift_ReleaseAccContext(hac);
	}

/* (de)initialisation functions. */
static int cswift_init()
	{
        SW_CONTEXT_HANDLE hac;
        t_swAcquireAccContext *p1;
        t_swAttachKeyParam *p2;
        t_swSimpleRequest *p3;
        t_swReleaseAccContext *p4;

	if(cswift_dso != NULL)
		{
		ENGINEerr(ENGINE_F_CSWIFT_INIT,ENGINE_R_ALREADY_LOADED);
		goto err;
		}
	/* Attempt to load libswift.so/swift.dll/whatever. */
	cswift_dso = DSO_load(NULL, CSWIFT_LIBNAME, NULL,
		DSO_FLAG_NAME_TRANSLATION);
	if(cswift_dso == NULL)
		{
		ENGINEerr(ENGINE_F_CSWIFT_INIT,ENGINE_R_DSO_FAILURE);
		goto err;
		}
	if(!(p1 = DSO_bind(cswift_dso, CSWIFT_F1)) ||
			!(p2 = DSO_bind(cswift_dso, CSWIFT_F2)) ||
			!(p3 = DSO_bind(cswift_dso, CSWIFT_F3)) ||
			!(p4 = DSO_bind(cswift_dso, CSWIFT_F4)))
		{
		ENGINEerr(ENGINE_F_CSWIFT_INIT,ENGINE_R_DSO_FAILURE);
		goto err;
		}
	/* Copy the pointers */
	p_CSwift_AcquireAccContext = p1;
	p_CSwift_AttachKeyParam = p2;
	p_CSwift_SimpleRequest = p3;
	p_CSwift_ReleaseAccContext = p4;
	/* Try and get a context - if not, we may have a DSO but no
	 * accelerator! */
	if(!get_context(&hac))
		{
		ENGINEerr(ENGINE_F_CSWIFT_INIT,ENGINE_R_UNIT_FAILURE);
		goto err;
		}
	release_context(hac);
	/* Everything's fine. */
	return 1;
err:
	if(cswift_dso)
		DSO_free(cswift_dso);
	return 0;
	}

static int cswift_finish()
	{
	if(cswift_dso == NULL)
		{
		ENGINEerr(ENGINE_F_CSWIFT_FINISH,ENGINE_R_NOT_LOADED);
		return 0;
		}
	if(!DSO_free(cswift_dso))
		{
		ENGINEerr(ENGINE_F_CSWIFT_FINISH,ENGINE_R_DSO_FAILURE);
		return 0;
		}
	cswift_dso = NULL;
	p_CSwift_AcquireAccContext = NULL;
	p_CSwift_AttachKeyParam = NULL;
	p_CSwift_SimpleRequest = NULL;
	p_CSwift_ReleaseAccContext = NULL;
	return 1;
	}

/* Un petit mod_exp */
static int cswift_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
			const BIGNUM *m, BN_CTX *ctx)
	{
	/* I need somewhere to store temporary serialised values for
	 * use with the CryptoSwift API calls. A neat cheat - I'll use
	 * BIGNUMs from the BN_CTX but access their arrays directly as
	 * byte arrays <grin>. This way I don't have to clean anything
	 * up. */
	BIGNUM *modulus;
	BIGNUM *exponent;
	BIGNUM *argument;
	BIGNUM *result;
	SW_LARGENUMBER arg, res;
	SW_PARAM sw_param;
	SW_CONTEXT_HANDLE hac;
	int to_return, acquired;
 
	modulus = exponent = argument = result = NULL;
	to_return = 0; /* expect failure */
	acquired = 0;
 
	if(!get_context(&hac))
		{
		ENGINEerr(ENGINE_F_CSWIFT_MOD_EXP,ENGINE_R_GET_HANDLE_FAILED);
		goto err;
		}
	acquired = 1;
	/* Prepare the params */
	modulus = BN_CTX_get(ctx);
	exponent = BN_CTX_get(ctx);
	argument = BN_CTX_get(ctx);
	result = BN_CTX_get(ctx);
	if(!modulus || !exponent || !argument || !result)
		{
		ENGINEerr(ENGINE_F_CSWIFT_MOD_EXP,ENGINE_R_BN_CTX_FULL);
		goto err;
		}
	if(!bn_wexpand(modulus, m->top) || !bn_wexpand(exponent, p->top) ||
		!bn_wexpand(argument, a->top) || !bn_wexpand(result, m->top))
		{
		ENGINEerr(ENGINE_F_CSWIFT_MOD_EXP,ENGINE_R_BN_EXPAND_FAIL);
		goto err;
		}
	sw_param.type = SW_ALG_EXP;
	sw_param.up.exp.modulus.nbytes = BN_bn2bin(m, (char *)modulus->d);
	sw_param.up.exp.modulus.value = (char *)modulus->d;
	sw_param.up.exp.exponent.nbytes = BN_bn2bin(p, (char *)exponent->d);
	sw_param.up.exp.exponent.value = (char *)exponent->d;
	/* Attach the key params */
	if(p_CSwift_AttachKeyParam(hac, &sw_param) != SW_OK)
		{
		ENGINEerr(ENGINE_F_CSWIFT_MOD_EXP,ENGINE_R_PROVIDE_PARAMETERS);
		goto err;
		}
	/* Prepare the argument and response */
	arg.nbytes = BN_bn2bin(a, (char *)argument->d);
	arg.value = (char *)argument->d;
	res.nbytes = BN_num_bytes(m);
	memset(result->d, 0, res.nbytes);
	res.value = (char *)result->d;
	/* Perform the operation */
	if(p_CSwift_SimpleRequest(hac, SW_CMD_MODEXP, &arg, 1, &res, 1) != SW_OK)
		{
		ENGINEerr(ENGINE_F_CSWIFT_MOD_EXP,ENGINE_R_REQUEST_FAILED);
		goto err;
		}
	/* Convert the response */
	BN_bin2bn((char *)result->d, res.nbytes, r);
	to_return = 1;
err:
	if(acquired)
		release_context(hac);
	if(modulus) ctx->tos--;
	if(exponent) ctx->tos--;
	if(argument) ctx->tos--;
	if(result) ctx->tos--;
	return to_return;
	}

/* Un petit mod_exp chinois */
static int cswift_mod_exp_crt(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
			const BIGNUM *q, const BIGNUM *dmp1,
			const BIGNUM *dmq1, const BIGNUM *iqmp, BN_CTX *ctx)
	{
	BIGNUM *rsa_p;
	BIGNUM *rsa_q;
	BIGNUM *rsa_dmp1;
	BIGNUM *rsa_dmq1;
	BIGNUM *rsa_iqmp;
	BIGNUM *argument;
	BIGNUM *result;
	SW_LARGENUMBER arg, res;
	SW_PARAM sw_param;
	SW_CONTEXT_HANDLE hac;
	int to_return, acquired;
 
	rsa_p = rsa_q = rsa_dmp1 = rsa_dmq1 = rsa_iqmp =
		argument = result = NULL;
	to_return = 0; /* expect failure */
	acquired = 0;
 
	if(!get_context(&hac))
		{
		ENGINEerr(ENGINE_F_CSWIFT_MOD_EXP_CRT,ENGINE_R_GET_HANDLE_FAILED);
		goto err;
		}
	acquired = 1;
	/* Prepare the params */
	rsa_p = BN_CTX_get(ctx);
	rsa_q = BN_CTX_get(ctx);
	rsa_dmp1 = BN_CTX_get(ctx);
	rsa_dmq1 = BN_CTX_get(ctx);
	rsa_iqmp = BN_CTX_get(ctx);
	argument = BN_CTX_get(ctx);
	result = BN_CTX_get(ctx);
	if(!rsa_p || !rsa_q || !rsa_dmp1 || !rsa_dmq1 || !rsa_iqmp ||
			!argument || !result)
		{
		ENGINEerr(ENGINE_F_CSWIFT_MOD_EXP_CRT,ENGINE_R_BN_CTX_FULL);
		goto err;
		}
	if(!bn_wexpand(rsa_p, p->top) || !bn_wexpand(rsa_q, q->top) ||
			!bn_wexpand(rsa_dmp1, dmp1->top) ||
			!bn_wexpand(rsa_dmq1, dmq1->top) ||
			!bn_wexpand(rsa_iqmp, iqmp->top) ||
			!bn_wexpand(argument, a->top) ||
			!bn_wexpand(result, p->top + q->top))
		{
		ENGINEerr(ENGINE_F_CSWIFT_MOD_EXP_CRT,ENGINE_R_BN_EXPAND_FAIL);
		goto err;
		}
	sw_param.type = SW_ALG_CRT;
	sw_param.up.crt.p.nbytes = BN_bn2bin(p, (char *)rsa_p->d);
	sw_param.up.crt.p.value = (char *)rsa_p->d;
	sw_param.up.crt.q.nbytes = BN_bn2bin(q, (char *)rsa_q->d);
	sw_param.up.crt.q.value = (char *)rsa_q->d;
	sw_param.up.crt.dmp1.nbytes = BN_bn2bin(dmp1, (char *)rsa_dmp1->d);
	sw_param.up.crt.dmp1.value = (char *)rsa_dmp1->d;
	sw_param.up.crt.dmq1.nbytes = BN_bn2bin(dmq1, (char *)rsa_dmq1->d);
	sw_param.up.crt.dmq1.value = (char *)rsa_dmq1->d;
	sw_param.up.crt.iqmp.nbytes = BN_bn2bin(iqmp, (char *)rsa_iqmp->d);
	sw_param.up.crt.iqmp.value = (char *)rsa_iqmp->d;
	/* Attach the key params */
	if(p_CSwift_AttachKeyParam(hac, &sw_param) != SW_OK)
		{
		ENGINEerr(ENGINE_F_CSWIFT_MOD_EXP_CRT,ENGINE_R_PROVIDE_PARAMETERS);
		goto err;
		}
	/* Prepare the argument and response */
	arg.nbytes = BN_bn2bin(a, (char *)argument->d);
	arg.value = (char *)argument->d;
	res.nbytes = 2 * BN_num_bytes(p);
	memset(result->d, 0, res.nbytes);
	res.value = (char *)result->d;
	/* Perform the operation */
	if(p_CSwift_SimpleRequest(hac, SW_CMD_MODEXP_CRT, &arg, 1,
			&res, 1) != SW_OK)
		{
		ENGINEerr(ENGINE_F_CSWIFT_MOD_EXP_CRT,ENGINE_R_REQUEST_FAILED);
		goto err;
		}
	/* Convert the response */
	BN_bin2bn((char *)result->d, res.nbytes, r);
	to_return = 1;
err:
	if(acquired)
		release_context(hac);
	if(rsa_p) ctx->tos--;
	if(rsa_q) ctx->tos--;
	if(rsa_dmp1) ctx->tos--;
	if(rsa_dmq1) ctx->tos--;
	if(rsa_iqmp) ctx->tos--;
	if(argument) ctx->tos--;
	if(result) ctx->tos--;
	return to_return;
	}
 
static int cswift_rsa_mod_exp(BIGNUM *r0, BIGNUM *I, RSA *rsa)
	{
	BN_CTX *ctx;
	int to_return = 0;

	if((ctx = BN_CTX_new()) == NULL)
		goto err;
	if(!rsa->p || !rsa->q || !rsa->dmp1 || !rsa->dmq1 || !rsa->iqmp)
		{
		ENGINEerr(ENGINE_F_CSWIFT_RSA_MOD_EXP,ENGINE_R_MISSING_KEY_COMPONENTS);
		goto err;
		}
	to_return = cswift_mod_exp_crt(r0, I, rsa->p, rsa->q, rsa->dmp1,
		rsa->dmq1, rsa->iqmp, ctx);
err:
	if(ctx)
		BN_CTX_free(ctx);
	return to_return;
	}

/* This function is aliased to mod_exp (with the mont stuff dropped). */
static int cswift_mod_exp_mont(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
	{
	return cswift_mod_exp(r, a, p, m, ctx);
	}

#endif /* HW_CSWIFT */


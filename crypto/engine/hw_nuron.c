/* crypto/engine/hw_nuron.c */
/* Written by Ben Laurie for the OpenSSL Project, leaning heavily on Geoff
 * Thorpe's Atalla implementation.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
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
#include <openssl/engine.h>


#ifndef OPENSSL_NO_HW
#ifndef OPENSSL_NO_HW_NURON

static const char def_NURON_LIBNAME[] = "nuronssl";
static const char *NURON_LIBNAME = def_NURON_LIBNAME;
static const char *NURON_F1 = "nuron_mod_exp";

/* The definitions for control commands specific to this engine */
#define NURON_CMD_SO_PATH		ENGINE_CMD_BASE
static const ENGINE_CMD_DEFN nuron_cmd_defns[] = {
	{NURON_CMD_SO_PATH,
		"SO_PATH",
		"Specifies the path to the 'nuronssl' shared library",
		ENGINE_CMD_FLAG_STRING},
	{0, NULL, NULL, 0}
	};

#ifndef OPENSSL_NO_ERR
/* Error function codes for use in nuron operation */
#define NURON_F_NURON_INIT			100
#define NURON_F_NURON_FINISH			101
#define NURON_F_NURON_CTRL			102
#define NURON_F_NURON_MOD_EXP			103
/* Error reason codes */
#define NURON_R_ALREADY_LOADED			104
#define NURON_R_DSO_NOT_FOUND			105
#define NURON_R_DSO_FUNCTION_NOT_FOUND		106
#define NURON_R_NOT_LOADED			107
#define NURON_R_DSO_FAILURE			108
#define NURON_R_CTRL_COMMAND_NOT_IMPLEMENTED	109
static ERR_STRING_DATA nuron_str_functs[] =
	{
	/* This first element is changed to match the dynamic 'lib' number */
{ERR_PACK(0,0,0),				"nuron engine code"},
{ERR_PACK(0,NURON_F_NURON_INIT,0),		"nuron_init"},
{ERR_PACK(0,NURON_F_NURON_FINISH,0),		"nuron_finish"},
{ERR_PACK(0,NURON_F_NURON_CTRL,0),		"nuron_ctrl"},
{ERR_PACK(0,NURON_F_NURON_MOD_EXP,0),		"nuron_mod_exp"},
/* Error reason codes */
{NURON_R_ALREADY_LOADED			,"already loaded"},
{NURON_R_DSO_NOT_FOUND			,"DSO not found"},
{NURON_R_DSO_FUNCTION_NOT_FOUND		,"DSO function not found"},
{NURON_R_NOT_LOADED			,"not loaded"},
{NURON_R_DSO_FAILURE			,"DSO failure"},
{NURON_R_CTRL_COMMAND_NOT_IMPLEMENTED	,"ctrl command not implemented"},
{0,NULL}
	};
/* The library number we obtain dynamically from the ERR code */
static int nuron_err_lib = -1;
#define NURONerr(f,r) ERR_PUT_error(nuron_err_lib,(f),(r),__FILE__,__LINE__)
static void nuron_load_error_strings(void)
	{
	if(nuron_err_lib < 0)
		{
		if((nuron_err_lib = ERR_get_next_error_library()) <= 0)
			return;
		nuron_str_functs[0].error = ERR_PACK(nuron_err_lib,0,0);
		ERR_load_strings(nuron_err_lib, nuron_str_functs);
		}
	}
static void nuron_unload_error_strings(void)
	{
	if(nuron_err_lib >= 0)
		{
		ERR_unload_strings(nuron_err_lib, nuron_str_functs);
		nuron_err_lib = -1;
		}
	}
#else
#define NURONerr(f,r)					/* NOP */
static void nuron_load_error_strings(void) { }		/* NOP */
static void nuron_unload_error_strings(void) { }	/* NOP */
#endif

typedef int tfnModExp(BIGNUM *r,const BIGNUM *a,const BIGNUM *p,const BIGNUM *m);
static tfnModExp *pfnModExp = NULL;

static DSO *pvDSOHandle = NULL;

static int nuron_destroy(ENGINE *e)
	{
	nuron_unload_error_strings();
	return 1;
	}

static int nuron_init(ENGINE *e)
	{
	if(pvDSOHandle != NULL)
		{
		NURONerr(NURON_F_NURON_INIT,NURON_R_ALREADY_LOADED);
		return 0;
		}

	pvDSOHandle = DSO_load(NULL, NURON_LIBNAME, NULL,
		DSO_FLAG_NAME_TRANSLATION_EXT_ONLY);
	if(!pvDSOHandle)
		{
		NURONerr(NURON_F_NURON_INIT,NURON_R_DSO_NOT_FOUND);
		return 0;
		}

	pfnModExp = (tfnModExp *)DSO_bind_func(pvDSOHandle, NURON_F1);
	if(!pfnModExp)
		{
		NURONerr(NURON_F_NURON_INIT,NURON_R_DSO_FUNCTION_NOT_FOUND);
		return 0;
		}

	return 1;
	}

static int nuron_finish(ENGINE *e)
	{
	if(pvDSOHandle == NULL)
		{
		NURONerr(NURON_F_NURON_FINISH,NURON_R_NOT_LOADED);
		return 0;
		}
	if(!DSO_free(pvDSOHandle))
		{
		NURONerr(NURON_F_NURON_FINISH,NURON_R_DSO_FAILURE);
		return 0;
		}
	pvDSOHandle=NULL;
	pfnModExp=NULL;
	return 1;
	}

static int nuron_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)())
	{
	int initialised = ((pvDSOHandle == NULL) ? 0 : 1);
	switch(cmd)
		{
	case NURON_CMD_SO_PATH:
		if(p == NULL)
			{
			NURONerr(NURON_F_NURON_CTRL,ERR_R_PASSED_NULL_PARAMETER);
			return 0;
			}
		if(initialised)
			{
			NURONerr(NURON_F_NURON_CTRL,NURON_R_ALREADY_LOADED);
			return 0;
			}
		NURON_LIBNAME = (const char *)p;
		return 1;
	default:
		break;
		}
	NURONerr(NURON_F_NURON_CTRL,NURON_R_CTRL_COMMAND_NOT_IMPLEMENTED);
	return 0;
}

static int nuron_mod_exp(BIGNUM *r,const BIGNUM *a,const BIGNUM *p,
			 const BIGNUM *m,BN_CTX *ctx)
	{
	if(!pvDSOHandle)
		{
		NURONerr(NURON_F_NURON_MOD_EXP,NURON_R_NOT_LOADED);
		return 0;
		}
	return pfnModExp(r,a,p,m);
	}

#ifndef OPENSSL_NO_RSA
static int nuron_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa)
	{
	return nuron_mod_exp(r0,I,rsa->d,rsa->n,NULL);
	}
#endif

#ifndef OPENSSL_NO_DSA
/* This code was liberated and adapted from the commented-out code in
 * dsa_ossl.c. Because of the unoptimised form of the Atalla acceleration
 * (it doesn't have a CRT form for RSA), this function means that an
 * Atalla system running with a DSA server certificate can handshake
 * around 5 or 6 times faster/more than an equivalent system running with
 * RSA. Just check out the "signs" statistics from the RSA and DSA parts
 * of "openssl speed -engine atalla dsa1024 rsa1024". */
static int nuron_dsa_mod_exp(DSA *dsa, BIGNUM *rr, BIGNUM *a1,
			     BIGNUM *p1, BIGNUM *a2, BIGNUM *p2, BIGNUM *m,
			     BN_CTX *ctx, BN_MONT_CTX *in_mont)
	{
	BIGNUM t;
	int to_return = 0;
 
	BN_init(&t);
	/* let rr = a1 ^ p1 mod m */
	if (!nuron_mod_exp(rr,a1,p1,m,ctx))
		goto end;
	/* let t = a2 ^ p2 mod m */
	if (!nuron_mod_exp(&t,a2,p2,m,ctx))
		goto end;
	/* let rr = rr * t mod m */
	if (!BN_mod_mul(rr,rr,&t,m,ctx))
		goto end;
	to_return = 1;
end:
	BN_free(&t);
	return to_return;
	}


static int nuron_mod_exp_dsa(DSA *dsa, BIGNUM *r, BIGNUM *a,
			     const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
			     BN_MONT_CTX *m_ctx)
	{
	return nuron_mod_exp(r, a, p, m, ctx);
	}
#endif

/* This function is aliased to mod_exp (with the mont stuff dropped). */
static int nuron_mod_exp_mont(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
			      const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
	{
	return nuron_mod_exp(r, a, p, m, ctx);
	}

#ifndef OPENSSL_NO_DH
/* This function is aliased to mod_exp (with the dh and mont dropped). */
static int nuron_mod_exp_dh(const DH *dh, BIGNUM *r,
		const BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
	{
	return nuron_mod_exp(r, a, p, m, ctx);
	}
#endif

#ifndef OPENSSL_NO_RSA
static RSA_METHOD nuron_rsa =
	{
	"Nuron RSA method",
	NULL,
	NULL,
	NULL,
	NULL,
	nuron_rsa_mod_exp,
	nuron_mod_exp_mont,
	NULL,
	NULL,
	0,
	NULL,
	NULL,
	NULL
	};
#endif

#ifndef OPENSSL_NO_DSA
static DSA_METHOD nuron_dsa =
	{
	"Nuron DSA method",
	NULL, /* dsa_do_sign */
	NULL, /* dsa_sign_setup */
	NULL, /* dsa_do_verify */
	nuron_dsa_mod_exp, /* dsa_mod_exp */
	nuron_mod_exp_dsa, /* bn_mod_exp */
	NULL, /* init */
	NULL, /* finish */
	0, /* flags */
	NULL /* app_data */
	};
#endif

#ifndef OPENSSL_NO_DH
static DH_METHOD nuron_dh =
	{
	"Nuron DH method",
	NULL,
	NULL,
	nuron_mod_exp_dh,
	NULL,
	NULL,
	0,
	NULL
	};
#endif

/* Constants used when creating the ENGINE */
static const char *engine_nuron_id = "nuron";
static const char *engine_nuron_name = "Nuron hardware engine support";

/* This internal function is used by ENGINE_nuron() and possibly by the
 * "dynamic" ENGINE support too */
static int bind_helper(ENGINE *e)
	{
#ifndef OPENSSL_NO_RSA
	const RSA_METHOD *meth1;
#endif
#ifndef OPENSSL_NO_DSA
	const DSA_METHOD *meth2;
#endif
#ifndef OPENSSL_NO_DH
	const DH_METHOD *meth3;
#endif
	if(!ENGINE_set_id(e, engine_nuron_id) ||
			!ENGINE_set_name(e, engine_nuron_name) ||
#ifndef OPENSSL_NO_RSA
			!ENGINE_set_RSA(e, &nuron_rsa) ||
#endif
#ifndef OPENSSL_NO_DSA
			!ENGINE_set_DSA(e, &nuron_dsa) ||
#endif
#ifndef OPENSSL_NO_DH
			!ENGINE_set_DH(e, &nuron_dh) ||
#endif
			!ENGINE_set_BN_mod_exp(e, nuron_mod_exp) ||
			!ENGINE_set_destroy_function(e, nuron_destroy) ||
			!ENGINE_set_init_function(e, nuron_init) ||
			!ENGINE_set_finish_function(e, nuron_finish) ||
			!ENGINE_set_ctrl_function(e, nuron_ctrl) ||
			!ENGINE_set_cmd_defns(e, nuron_cmd_defns))
		return 0;

#ifndef OPENSSL_NO_RSA
	/* We know that the "PKCS1_SSLeay()" functions hook properly
	 * to the nuron-specific mod_exp and mod_exp_crt so we use
	 * those functions. NB: We don't use ENGINE_openssl() or
	 * anything "more generic" because something like the RSAref
	 * code may not hook properly, and if you own one of these
	 * cards then you have the right to do RSA operations on it
	 * anyway! */ 
	meth1=RSA_PKCS1_SSLeay();
	nuron_rsa.rsa_pub_enc=meth1->rsa_pub_enc;
	nuron_rsa.rsa_pub_dec=meth1->rsa_pub_dec;
	nuron_rsa.rsa_priv_enc=meth1->rsa_priv_enc;
	nuron_rsa.rsa_priv_dec=meth1->rsa_priv_dec;
#endif

#ifndef OPENSSL_NO_DSA
	/* Use the DSA_OpenSSL() method and just hook the mod_exp-ish
	 * bits. */
	meth2=DSA_OpenSSL();
	nuron_dsa.dsa_do_sign=meth2->dsa_do_sign;
	nuron_dsa.dsa_sign_setup=meth2->dsa_sign_setup;
	nuron_dsa.dsa_do_verify=meth2->dsa_do_verify;
#endif

#ifndef OPENSSL_NO_DH
	/* Much the same for Diffie-Hellman */
	meth3=DH_OpenSSL();
	nuron_dh.generate_key=meth3->generate_key;
	nuron_dh.compute_key=meth3->compute_key;
#endif

	/* Ensure the nuron error handling is set up */
	nuron_load_error_strings();
	return 1;
	}

/* As this is only ever called once, there's no need for locking
 * (indeed - the lock will already be held by our caller!!!) */
ENGINE *ENGINE_nuron(void)
	{
	ENGINE *ret = ENGINE_new();
	if(!ret)
		return NULL;
	if(!bind_helper(ret))
		{
		ENGINE_free(ret);
		return NULL;
		}
	return ret;
	}

/* This stuff is needed if this ENGINE is being compiled into a self-contained
 * shared-library. */	   
#ifdef ENGINE_DYNAMIC_SUPPORT
static int bind_fn(ENGINE *e, const char *id)
	{
	if(id && (strcmp(id, engine_nuron_id) != 0))
		return 0;
	if(!bind_helper(e))
		return 0;
	return 1;
	}       
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
#endif /* ENGINE_DYNAMIC_SUPPORT */

#endif /* !OPENSSL_NO_HW_NURON */
#endif /* !OPENSSL_NO_HW */

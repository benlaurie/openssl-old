/* crypto/engine/hw_ncipher.c -*- mode: C; c-file-style: "eay" -*- */
/* Written by Richard Levitte (richard@levitte.org), Geoff Thorpe
 * (geoff@geoffthorpe.net) and Dr Stephen N Henson (shenson@bigfoot.com)
 * for the OpenSSL project 2000.
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

#ifdef HW_NCIPHER

/* Attribution notice: nCipher har said several times that it's OK for
 * us to implement a general interface to their boxes, and recently declared
 * their HWCryptoHook to be public, adn therefore available for us to use.
 * Thanks, nCipher.
 *
 * The hwcryptohook.h included here is from May 2000.
 * [Richard Levitte]
 */
#include "vendor_defns/hwcryptohook.h"

static int hwcrhk_init();
static int hwcrhk_finish();

/* Functions to handle mutexes */
static int hwcrhk_mutex_init(HWCryptoHook_Mutex*, HWCryptoHook_CallerContext*);
static int hwcrhk_mutex_lock(HWCryptoHook_Mutex*);
static void hwcrhk_mutex_unlock(HWCryptoHook_Mutex*);
static void hwcrhk_mutex_destroy(HWCryptoHook_Mutex*);

/* BIGNUM stuff */
static int hwcrhk_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx);

/* RSA stuff */
static int hwcrhk_rsa_mod_exp(BIGNUM *r, BIGNUM *I, RSA *rsa);
/* This function is aliased to mod_exp (with the mont stuff dropped). */
static int hwcrhk_mod_exp_mont(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);

/* DH stuff */
/* This function is alised to mod_exp (with the DH and mont dropped). */
static int hwcrhk_mod_exp_dh(DH *dh, BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);

/* RAND stuff */
static int hwcrhk_rand_bytes(unsigned char *buf, int num);

/* KM stuff */
static void hwcrhk_ex_free(void *obj, void *item, CRYPTO_EX_DATA *ad,
	int index,long argl, void *argp);


/* Our internal RSA_METHOD that we provide pointers to */
static RSA_METHOD hwcrhk_rsa =
	{
	"nCipher RSA method",
	NULL,
	NULL,
	NULL,
	NULL,
	hwcrhk_rsa_mod_exp,
	hwcrhk_mod_exp_mont,
	NULL,
	NULL,
	0,
	NULL,
	NULL,
	NULL
	};

/* Our internal DH_METHOD that we provide pointers to */
static DH_METHOD hwcrhk_dh =
	{
	"nCipher DH method",
	NULL,
	NULL,
	hwcrhk_mod_exp_dh,
	NULL,
	NULL,
	0,
	NULL
	};

static RAND_METHOD hwcrhk_rand =
	{
	/* "nCipher RAND method", */
	NULL,
	hwcrhk_rand_bytes,
	NULL,
	NULL,
	hwcrhk_rand_bytes,
	NULL
	};

/* Our ENGINE structure. */
static ENGINE engine_hwcrhk =
        {
	"hwcrhk",
	"nCipher hardware engine support",
	&hwcrhk_rsa,
	NULL,
	&hwcrhk_dh,
	&hwcrhk_rand,
	hwcrhk_mod_exp,
	NULL,
	hwcrhk_init,
	hwcrhk_finish,
	0, /* no flags */
	0, 0, /* no references */
	NULL, NULL /* unlinked */
        };

/* Internal stuff for HWCryptoHook */

/* Some structures needed for proper use of thread locks */
/* hwcryptohook.h has some typedefs that turn struct HWCryptoHook_MutexValue
   into HWCryptoHook_Mutex */
struct HWCryptoHook_MutexValue
	{
	int lockid;
	};

/* hwcryptohook.h has some typedefs that turn
   struct HWCryptoHook_PassphraseContextValue
   into HWCryptoHook_PassphraseContext */
struct HWCryptoHook_PassphraseContextValue
	{
	void *any;
	};

/* hwcryptohook.h has some typedefs that turn
   struct HWCryptoHook_CallerContextValue
   into HWCryptoHook_CallerContext */
struct HWCryptoHook_CallerContextValue
	{
	void *any;
	};

/* The MPI structure in HWCryptoHook is pretty compatible with OpenSSL
   BIGNUM's, so lets define a couple of conversion macros */
#define BN2MPI(mp, bn) \
    {mp.size = bn->top * sizeof(BN_ULONG); mp.buf = (unsigned char *)bn->d;}
#define MPI2BN(bn, mp) \
    {mp.size = bn->max * sizeof(BN_ULONG); mp.buf = (unsigned char *)bn->d;}

#if 0 /* Card and password management is not yet supported */
/* HWCryptoHook callbacks.  insert_cart() and get_pass() are not yet
   defined, because we haven't quite decided on the proper form yet.
   log_message() just adds an entry in the error stack.  I don't know
   if that's good or bad...  */
static int insert_card(const char *prompt_info,
	const char *wrong_info,
	HWCryptoHook_PassphraseContext *ppctx,
	HWCryptoHook_CallerContext *cactx);
static int get_pass(const char *prompt_info,
	int *len_io, char *buf,
	HWCryptoHook_PassphraseContext *ppctx,
	HWCryptoHook_CallerContext *cactx);
#endif
static void log_message(void *logstream, const char *message);

/* Stuff to pass to the HWCryptoHook library */
static HWCryptoHook_InitInfo hwcrhk_globals = {
	0,			/* Flags */
	NULL,			/* logstream */
	sizeof(BN_ULONG),	/* limbsize */
	0,			/* mslimb first: false for BNs */
	-1,			/* msbyte first: use native */
	0,			/* Max mutexes, 0 = no small limit */
	0,			/* Max simultaneous, 0 = default */

	/* The next few are mutex stuff: we write wrapper functions
	   round the OS mutex functions.
	   Currently, the support in OpenSSL is just not good enough,
	   so this part is currently skipped, but worked on. */
	sizeof(HWCryptoHook_Mutex),
	0, /* hwcrhk_mutex_init, */
	0, /* hwcrhk_mutex_lock, */
	0, /* hwcrhk_mutex_unlock, */
	0, /* hwcrhk_mutex_destroy, */

	/* The next few are condvar stuff: we write wrapper functions
	   round the OS functions.  Currently not implemented and not
	   and absolute necessity even in threaded programs, therefore
	   0'ed.  Will hopefully be implemented some day, since it
	   enhances the efficiency of HWCryptoHook.  */
	0, /* sizeof(HWCryptoHook_CondVar), */
	0, /* hwcrhk_cv_init, */
	0, /* hwcrhk_cv_wait, */
	0, /* hwcrhk_cv_signal, */
	0, /* hwcrhk_cv_broadcast, */
	0, /* hwcrhk_cv_destroy, */

	0, /* get_pass,	*/	/* pass phrase */
	0, /* insert_card, */	/* insert a card */
	log_message		/* Log message */
};


/* Now, to our own code */

/* As this is only ever called once, there's no need for locking
 * (indeed - the lock will already be held by our caller!!!) */
ENGINE *ENGINE_hwcrhk()
	{
	RSA_METHOD *meth1;
	DH_METHOD *meth2;

	/* We know that the "PKCS1_SSLeay()" functions hook properly
	 * to the cswift-specific mod_exp and mod_exp_crt so we use
	 * those functions. NB: We don't use ENGINE_openssl() or
	 * anything "more generic" because something like the RSAref
	 * code may not hook properly, and if you own one of these
	 * cards then you have the right to do RSA operations on it
	 * anyway! */ 
	meth1 = RSA_PKCS1_SSLeay();
	hwcrhk_rsa.rsa_pub_enc = meth1->rsa_pub_enc;
	hwcrhk_rsa.rsa_pub_dec = meth1->rsa_pub_dec;
	hwcrhk_rsa.rsa_priv_enc = meth1->rsa_priv_enc;
	hwcrhk_rsa.rsa_priv_dec = meth1->rsa_priv_dec;

	/* Much the same for Diffie-Hellman */
	meth2 = DH_OpenSSL();
	hwcrhk_dh.generate_key = meth2->generate_key;
	hwcrhk_dh.compute_key = meth2->compute_key;
	return &engine_hwcrhk;
	}

/* This is a process-global DSO handle used for loading and unloading
 * the HWCryptoHook library. NB: This is only set (or unset) during an
 * init() or finish() call (reference counts permitting) and they're
 * operating with global locks, so this should be thread-safe
 * implicitly. */
static DSO *hwcrhk_dso = NULL;
static HWCryptoHook_ContextHandle hwcrhk_context = 0;
static int hndidx = -1;	/* Index for KM handle.  Not really used yet. */

/* These are the function pointers that are (un)set when the library has
 * successfully (un)loaded. */
HWCryptoHook_Init_t *p_hwcrhk_Init = NULL;
HWCryptoHook_Finish_t *p_hwcrhk_Finish = NULL;
HWCryptoHook_ModExp_t *p_hwcrhk_ModExp = NULL;
HWCryptoHook_RSA_t *p_hwcrhk_RSA = NULL;
HWCryptoHook_RandomBytes_t *p_hwcrhk_RandomBytes = NULL;
HWCryptoHook_RSAUnloadKey_t *p_hwcrhk_RSAUnloadKey = NULL;
HWCryptoHook_ModExpCRT_t *p_hwcrhk_ModExpCRT = NULL;

/* Used in the DSO operations. */
static const char *HWCRHK_LIBNAME = "nfhwcrhk";
static const char *n_hwcrhk_Init = "HWCryptoHook_Init";
static const char *n_hwcrhk_Finish = "HWCryptoHook_Finish";
static const char *n_hwcrhk_ModExp = "HWCryptoHook_ModExp";
static const char *n_hwcrhk_RSA = "HWCryptoHook_RSA";
static const char *n_hwcrhk_RandomBytes = "HWCryptoHook_RandomBytes";
static const char *n_hwcrhk_RSAUnloadKey = "HWCryptoHook_RSAUnloadKey";
static const char *n_hwcrhk_ModExpCRT = "HWCryptoHook_ModExpCRT";

/* HWCryptoHook library functions and mechanics - these are used by the
 * higher-level functions further down. NB: As and where there's no
 * error checking, take a look lower down where these functions are
 * called, the checking and error handling is probably down there. */

/* utility function to obtain a context */
static int get_context(HWCryptoHook_ContextHandle *hac)
	{
	char tempbuf[1024];
	HWCryptoHook_ErrMsgBuf rmsg;

	rmsg.buf = tempbuf;
	rmsg.size = 1024;

        *hac = p_hwcrhk_Init(&hwcrhk_globals, sizeof(hwcrhk_globals), &rmsg,
		NULL);
	if (!*hac)
                return 0;
        return 1;
	}
 
/* similarly to release one. */
static void release_context(HWCryptoHook_ContextHandle hac)
	{
	p_hwcrhk_Finish(hac);
	}

/* (de)initialisation functions. */
static int hwcrhk_init()
	{
	HWCryptoHook_Init_t *p1;
	HWCryptoHook_Finish_t *p2;
	HWCryptoHook_ModExp_t *p3;
	HWCryptoHook_RSA_t *p4;
	HWCryptoHook_RSAUnloadKey_t *p5;
	HWCryptoHook_RandomBytes_t *p6;
	HWCryptoHook_ModExpCRT_t *p7;

	if(hwcrhk_dso != NULL)
		{
		ENGINEerr(ENGINE_F_HWCRHK_INIT,ENGINE_R_ALREADY_LOADED);
		goto err;
		}
	/* Attempt to load libnfhwcrhk.so/nfhwcrhk.dll/whatever. */
	hwcrhk_dso = DSO_load(NULL, HWCRHK_LIBNAME, NULL,
		DSO_FLAG_NAME_TRANSLATION);
	if(hwcrhk_dso == NULL)
		{
		ENGINEerr(ENGINE_F_HWCRHK_INIT,ENGINE_R_DSO_FAILURE);
		goto err;
		}
	if(!(p1 = (HWCryptoHook_Init_t *)
			DSO_bind_func(hwcrhk_dso, n_hwcrhk_Init)) ||
		!(p2 = (HWCryptoHook_Finish_t *)
			DSO_bind_func(hwcrhk_dso, n_hwcrhk_Finish)) ||
		!(p3 = (HWCryptoHook_ModExp_t *)
			DSO_bind_func(hwcrhk_dso, n_hwcrhk_ModExp)) ||
		!(p4 = (HWCryptoHook_RSA_t *)
			DSO_bind_func(hwcrhk_dso, n_hwcrhk_RSA)) ||
		!(p5 = (HWCryptoHook_RSAUnloadKey_t *)
			DSO_bind_func(hwcrhk_dso, n_hwcrhk_RSAUnloadKey)) ||
		!(p6 = (HWCryptoHook_RandomBytes_t *)
			DSO_bind_func(hwcrhk_dso, n_hwcrhk_RandomBytes)) ||
		!(p7 = (HWCryptoHook_ModExpCRT_t *)
			DSO_bind_func(hwcrhk_dso, n_hwcrhk_ModExpCRT)))
		{
		ENGINEerr(ENGINE_F_HWCRHK_INIT,ENGINE_R_DSO_FAILURE);
		goto err;
		}
	/* Copy the pointers */
	p_hwcrhk_Init = p1;
	p_hwcrhk_Finish = p2;
	p_hwcrhk_ModExp = p3;
	p_hwcrhk_RSA = p4;
	p_hwcrhk_RSAUnloadKey = p5;
	p_hwcrhk_RandomBytes = p6;
	p_hwcrhk_ModExpCRT = p7;

	/* Check if the application decided to support dynamic locks,
	   and if it does, use them. */
	if (CRYPTO_get_dynlock_create_callback() != NULL &&
		CRYPTO_get_dynlock_lock_callback() != NULL &&
		CRYPTO_get_dynlock_destroy_callback() != NULL)
		{
		hwcrhk_globals.mutex_init = hwcrhk_mutex_init;
		hwcrhk_globals.mutex_acquire = hwcrhk_mutex_lock;
		hwcrhk_globals.mutex_release = hwcrhk_mutex_unlock;
		hwcrhk_globals.mutex_destroy = hwcrhk_mutex_destroy;
		}

	/* Try and get a context - if not, we may have a DSO but no
	 * accelerator! */
	if(!get_context(&hwcrhk_context))
		{
		ENGINEerr(ENGINE_F_HWCRHK_INIT,ENGINE_R_UNIT_FAILURE);
		goto err;
		}
	/* Everything's fine. */
	if (hndidx == -1)
		hndidx = RSA_get_ex_new_index(0,
			"nFast HWCryptoHook RSA key handle",
			NULL, NULL, hwcrhk_ex_free);
	return 1;
err:
	if(hwcrhk_dso)
		DSO_free(hwcrhk_dso);
	hwcrhk_dso = NULL;
	p_hwcrhk_Init = NULL;
	p_hwcrhk_Finish = NULL;
	p_hwcrhk_ModExp = NULL;
	p_hwcrhk_RSA = NULL;
	p_hwcrhk_RSAUnloadKey = NULL;
	p_hwcrhk_ModExpCRT = NULL;
	p_hwcrhk_RandomBytes = NULL;
	return 0;
	}

static int hwcrhk_finish()
	{
	int to_return = 1;
	if(hwcrhk_dso == NULL)
		{
		ENGINEerr(ENGINE_F_HWCRHK_FINISH,ENGINE_R_NOT_LOADED);
		to_return = 0;
		goto err;
		}
	release_context(hwcrhk_context);
	if(!DSO_free(hwcrhk_dso))
		{
		ENGINEerr(ENGINE_F_HWCRHK_FINISH,ENGINE_R_DSO_FAILURE);
		to_return = 0;
		goto err;
		}
 err:
	hwcrhk_dso = NULL;
	p_hwcrhk_Init = NULL;
	p_hwcrhk_Finish = NULL;
	p_hwcrhk_ModExp = NULL;
	p_hwcrhk_RSA = NULL;
	p_hwcrhk_RSAUnloadKey = NULL;
	p_hwcrhk_ModExpCRT = NULL;
	p_hwcrhk_RandomBytes = NULL;
	return to_return;
	}

/* A little mod_exp */
static int hwcrhk_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
			const BIGNUM *m, BN_CTX *ctx)
	{
	char tempbuf[1024];
	HWCryptoHook_ErrMsgBuf rmsg;
	/* Since HWCryptoHook_MPI is pretty compatible with BIGNUM's,
	   we use them directly, plus a little macro magic.  We only
	   thing we need to make sure of is that enough space is allocated. */
	HWCryptoHook_MPI m_a, m_p, m_n, m_r;
	int to_return, ret;
 
	to_return = 0; /* expect failure */
	rmsg.buf = tempbuf;
	rmsg.size = 1024;

	if(!hwcrhk_context)
		{
		ENGINEerr(ENGINE_F_HWCRHK_MOD_EXP,ENGINE_R_NOT_INITIALISED);
		goto err;
		}
	/* Prepare the params */
	bn_expand2(r, m->top);	/* Check for error !! */
	BN2MPI(m_a, a);
	BN2MPI(m_p, p);
	BN2MPI(m_n, m);
	MPI2BN(r, m_r);

	/* Perform the operation */
	ret = p_hwcrhk_ModExp(hwcrhk_context, m_a, m_p, m_n, &m_r, &rmsg);

	/* Convert the response */
	r->top = m_r.size / sizeof(BN_ULONG);
	bn_fix_top(r);

	if (ret < 0)
		{
		/* FIXME: When this error is returned, HWCryptoHook is
		   telling us that falling back to software computation
		   might be a good thing. */
		if(ret == HWCRYPTOHOOK_ERROR_FALLBACK)
			{
			ENGINEerr(ENGINE_F_HWCRHK_MOD_EXP,ENGINE_R_REQUEST_FALLBACK);
			}
		else
			{
			ENGINEerr(ENGINE_F_HWCRHK_MOD_EXP,ENGINE_R_REQUEST_FAILED);
			}
		ERR_add_error_data(1,rmsg.buf);
		goto err;
		}

	to_return = 1;
err:
	return to_return;
	}
 
static int hwcrhk_rsa_mod_exp(BIGNUM *r, BIGNUM *I, RSA *rsa)
	{
	char tempbuf[1024];
	HWCryptoHook_ErrMsgBuf rmsg;
	HWCryptoHook_RSAKeyHandle *hptr;
	int to_return = 0, ret;

	if(!rsa->p || !rsa->q || !rsa->dmp1 || !rsa->dmq1 || !rsa->iqmp)
		{
		ENGINEerr(ENGINE_F_HWCRHK_RSA_MOD_EXP,ENGINE_R_MISSING_KEY_COMPONENTS);
		goto err;
		}
	if(!hwcrhk_context)
		{
		ENGINEerr(ENGINE_F_HWCRHK_MOD_EXP,ENGINE_R_NOT_INITIALISED);
		goto err;
		}

	/* This provides support for nForce keys.  Since that's opaque data
	   all we do is provide a handle to the proper key and let HWCryptoHook
	   take care of the rest. */
	if ((hptr = (HWCryptoHook_RSAKeyHandle *) RSA_get_ex_data(rsa, hndidx))
		!= NULL)
		{
		HWCryptoHook_MPI m_a, m_r;

		rmsg.buf = tempbuf;
		rmsg.size = 1024;

		/* Prepare the params */
		bn_expand2(r, rsa->n->top); /* Check for error !! */
		BN2MPI(m_a, I);
		MPI2BN(r, m_r);

		/* Perform the operation */
		ret = p_hwcrhk_RSA(m_a, *hptr, &m_r, &rmsg);

		/* Convert the response */
		r->top = m_r.size / sizeof(BN_ULONG);
		bn_fix_top(r);

		if (ret < 0)
			{
			/* FIXME: When this error is returned, HWCryptoHook is
			   telling us that falling back to software computation
			   might be a good thing. */
			if(ret == HWCRYPTOHOOK_ERROR_FALLBACK)
				{
				ENGINEerr(ENGINE_F_HWCRHK_RSA_MOD_EXP,ENGINE_R_REQUEST_FALLBACK);
				}
			else
				{
				ENGINEerr(ENGINE_F_HWCRHK_RSA_MOD_EXP,ENGINE_R_REQUEST_FAILED);
				}
			ERR_add_error_data(1,rmsg.buf);
			goto err;
			}
		}
	else
		{
		HWCryptoHook_MPI m_a, m_p, m_q, m_dmp1, m_dmq1, m_iqmp, m_r;

		rmsg.buf = tempbuf;
		rmsg.size = 1024;

		/* Prepare the params */
		bn_expand2(r, rsa->n->top); /* Check for error !! */
		BN2MPI(m_a, I);
		BN2MPI(m_p, rsa->p);
		BN2MPI(m_q, rsa->q);
		BN2MPI(m_dmp1, rsa->dmp1);
		BN2MPI(m_dmq1, rsa->dmq1);
		BN2MPI(m_iqmp, rsa->iqmp);
		MPI2BN(r, m_r);

		/* Perform the operation */
		ret = p_hwcrhk_ModExpCRT(hwcrhk_context, m_a, m_p, m_q,
			m_dmp1, m_dmq1, m_iqmp, &m_r, NULL);

		/* Convert the response */
		r->top = m_r.size / sizeof(BN_ULONG);
		bn_fix_top(r);

		if (ret < 0)
			{
			/* FIXME: When this error is returned, HWCryptoHook is
			   telling us that falling back to software computation
			   might be a good thing. */
			if(ret == HWCRYPTOHOOK_ERROR_FALLBACK)
				{
				ENGINEerr(ENGINE_F_HWCRHK_RSA_MOD_EXP,ENGINE_R_REQUEST_FALLBACK);
				}
			else
				{
				ENGINEerr(ENGINE_F_HWCRHK_RSA_MOD_EXP,ENGINE_R_REQUEST_FAILED);
				}
			ERR_add_error_data(1,rmsg.buf);
			goto err;
			}
		}
	/* If we're here, we must be here with some semblance of success :-) */
	to_return = 1;
err:
	return to_return;
	}

/* This function is aliased to mod_exp (with the mont stuff dropped). */
static int hwcrhk_mod_exp_mont(BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
	{
	return hwcrhk_mod_exp(r, a, p, m, ctx);
	}

/* This function is aliased to mod_exp (with the dh and mont dropped). */
static int hwcrhk_mod_exp_dh(DH *dh, BIGNUM *r, BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
	{
	return hwcrhk_mod_exp(r, a, p, m, ctx);
	}

/* Random bytes are good */
static int hwcrhk_rand_bytes(unsigned char *buf, int num)
	{
	char tempbuf[1024];
	HWCryptoHook_ErrMsgBuf rmsg;
	int to_return = 0; /* assume failure */
	int ret;

	rmsg.buf = tempbuf;
	rmsg.size = 1024;

	if(!hwcrhk_context)
		{
		ENGINEerr(ENGINE_F_HWCRHK_RAND_BYTES,ENGINE_R_NOT_INITIALISED);
		goto err;
		}

	ret = p_hwcrhk_RandomBytes(hwcrhk_context, buf, num, &rmsg);
	if (ret < 0)
		{
		/* FIXME: When this error is returned, HWCryptoHook is
		   telling us that falling back to software computation
		   might be a good thing. */
		if(ret == HWCRYPTOHOOK_ERROR_FALLBACK)
			{
			ENGINEerr(ENGINE_F_HWCRHK_RAND_BYTES,ENGINE_R_REQUEST_FALLBACK);
			}
		else
			{
			ENGINEerr(ENGINE_F_HWCRHK_RAND_BYTES,ENGINE_R_REQUEST_FAILED);
			}
		ERR_add_error_data(1,rmsg.buf);
		goto err;
		}
	to_return = 1;
 err:
	return to_return;
	}

/* This cleans up an RSA KM key, called when ex_data is freed */

static void hwcrhk_ex_free(void *obj, void *item, CRYPTO_EX_DATA *ad,
	int index,long argl, void *argp)
{
	char tempbuf[1024];
	HWCryptoHook_ErrMsgBuf rmsg;
	HWCryptoHook_RSAKeyHandle *hptr;
	int ret;

	rmsg.buf = tempbuf;
	rmsg.size = 1024;

	hptr = (HWCryptoHook_RSAKeyHandle *) item;
	if(!hptr) return;
	ret = p_hwcrhk_RSAUnloadKey(*hptr, NULL);
	OPENSSL_free(hptr);
}

/* Mutex calls: since the HWCryptoHook model closely follows the POSIX model
 * these just wrap the POSIX functions and add some logging.
 */

static int hwcrhk_mutex_init(HWCryptoHook_Mutex* mt,
	HWCryptoHook_CallerContext *cactx)
	{
	mt->lockid = CRYPTO_get_new_dynlockid();
	if (mt->lockid == 0)
		return 0;
	return 1;
	}

static int hwcrhk_mutex_lock(HWCryptoHook_Mutex *mt)
	{
	CRYPTO_w_lock(mt->lockid);
	return 1;
	}

void hwcrhk_mutex_unlock(HWCryptoHook_Mutex * mt)
	{
	CRYPTO_w_unlock(mt->lockid);
	}

static void hwcrhk_mutex_destroy(HWCryptoHook_Mutex *mt)
	{
	CRYPTO_destroy_dynlockid(mt->lockid);
	}

static void log_message(void *logstream, const char *message)
	{
	ENGINEerr(ENGINE_F_LOG_MESSAGE,ENGINE_R_HWCRYPTOHOOK_REPORTS);
	ERR_add_error_data(1,message);
	}

#endif /* HW_NCIPHER */


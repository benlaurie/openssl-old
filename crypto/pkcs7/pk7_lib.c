/* crypto/pkcs7/pk7_lib.c */
/* Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
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
#include "objects.h"
#include "x509.h"

long PKCS7_ctrl(p7,cmd,larg,parg)
PKCS7 *p7;
int cmd;
long larg;
char *parg;
	{
	int nid;
	long ret;

	nid=OBJ_obj2nid(p7->type);

	switch (cmd)
		{
	case PKCS7_OP_SET_DETACHED_SIGNATURE:
		if (nid == NID_pkcs7_signed)
			{
			ret=p7->detached=(int)larg;
			}
		else
			{
			PKCS7err(PKCS7_F_PKCS7_CTRL,PKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE);
			ret=0;
			}
		break;
	case PKCS7_OP_GET_DETACHED_SIGNATURE:
		if (nid == NID_pkcs7_signed)
			{
			ret=p7->detached;
			}
		else
			{
			PKCS7err(PKCS7_F_PKCS7_CTRL,PKCS7_R_OPERATION_NOT_SUPPORTED_ON_THIS_TYPE);
			ret=0;
			}
			
		break;
	default:
		abort();
		}
	return(ret);
	}

int PKCS7_content_new(p7,type)
PKCS7 *p7;
int type;
	{
	PKCS7 *ret=NULL;

	if ((ret=PKCS7_new()) == NULL) goto err;
	if (!PKCS7_set_type(ret,type)) goto err;
	if (!PKCS7_set_content(p7,ret)) goto err;

	return(1);
err:
	if (ret != NULL) PKCS7_free(ret);
	return(0);
	}

int PKCS7_set_content(p7,p7_data)
PKCS7 *p7;
PKCS7 *p7_data;
	{
	int i;

	i=OBJ_obj2nid(p7->type);
	switch (i)
		{
	case NID_pkcs7_signed:
		if (p7->d.sign->contents != NULL)
			PKCS7_content_free(p7->d.sign->contents);
		p7->d.sign->contents=p7_data;
		break;
	case NID_pkcs7_digest:
	case NID_pkcs7_data:
	case NID_pkcs7_enveloped:
	case NID_pkcs7_signedAndEnveloped:
	case NID_pkcs7_encrypted:
	default:
		PKCS7err(PKCS7_F_PKCS7_SET_CONTENT,PKCS7_R_UNSUPPORTED_CONTENT_TYPE);
		goto err;
		}
	return(1);
err:
	return(0);
	}

int PKCS7_set_type(p7,type)
PKCS7 *p7;
int type;
	{
	ASN1_OBJECT *obj;

	PKCS7_content_free(p7);
	obj=OBJ_nid2obj(type); /* will not fail */

	switch (type)
		{
	case NID_pkcs7_signed:
		p7->type=obj;
		if ((p7->d.sign=PKCS7_SIGNED_new()) == NULL)
			goto err;
		ASN1_INTEGER_set(p7->d.sign->version,1);
		break;
	case NID_pkcs7_data:
		p7->type=obj;
		if ((p7->d.data=ASN1_OCTET_STRING_new()) == NULL)
			goto err;
		break;
	case NID_pkcs7_digest:
	case NID_pkcs7_enveloped:
	case NID_pkcs7_signedAndEnveloped:
	case NID_pkcs7_encrypted:
	default:
		PKCS7err(PKCS7_F_PKCS7_SET_TYPE,PKCS7_R_UNSUPPORTED_CONTENT_TYPE);
		goto err;
		}
	return(1);
err:
	return(0);
	}

int PKCS7_add_signer(p7,psi)
PKCS7 *p7;
PKCS7_SIGNER_INFO *psi;
	{
	int i,j,nid;
	X509_ALGOR *alg;
	PKCS7_SIGNED *p7s;

	i=OBJ_obj2nid(p7->type);
	if (i != NID_pkcs7_signed)
		{
		PKCS7err(PKCS7_F_PKCS7_ADD_SIGNER,PKCS7_R_WRONG_CONTENT_TYPE);
		return(0);
		}

	p7s=p7->d.sign;

	nid=OBJ_obj2nid(psi->digest_alg->algorithm);

	/* If the digest is not currently listed, add it */
	j=0;
	for (i=0; i<sk_num(p7s->md_algs); i++)
		{
		alg=(X509_ALGOR *)sk_value(p7s->md_algs,i);
		if (OBJ_obj2nid(alg->algorithm) == nid)
			{
			j=1;
			break;
			}
		}
	if (!j) /* we need to add another algorithm */
		{
		alg=X509_ALGOR_new();
		alg->algorithm=OBJ_nid2obj(nid);
		sk_push(p7s->md_algs,(char *)alg);
		}

	sk_push(p7s->signer_info,(char *)psi);
	return(1);
	}

int PKCS7_add_certificate(p7,x509)
PKCS7 *p7;
X509 *x509;
	{
	int i;

	i=OBJ_obj2nid(p7->type);
	if (i != NID_pkcs7_signed)
		{
		PKCS7err(PKCS7_F_PKCS7_ADD_SIGNER,PKCS7_R_WRONG_CONTENT_TYPE);
		return(0);
		}

	if (p7->d.sign->cert == NULL)
		p7->d.sign->cert=sk_new_null();
	CRYPTO_add(&x509->references,1,CRYPTO_LOCK_X509);
	sk_push(p7->d.sign->cert,(char *)x509);
	return(1);
	}

int PKCS7_add_crl(p7,crl)
PKCS7 *p7;
X509_CRL *crl;
	{
	int i;
	i=OBJ_obj2nid(p7->type);
	if (i != NID_pkcs7_signed)
		{
		PKCS7err(PKCS7_F_PKCS7_ADD_SIGNER,PKCS7_R_WRONG_CONTENT_TYPE);
		return(0);
		}

	if (p7->d.sign->crl == NULL)
		p7->d.sign->crl=sk_new_null();

	CRYPTO_add(&crl->references,1,CRYPTO_LOCK_X509_CRL);
	sk_push(p7->d.sign->crl,(char *)crl);
	return(1);
	}

int PKCS7_SIGNER_INFO_set(p7i,x509,pkey,dgst)
PKCS7_SIGNER_INFO *p7i;
X509 *x509;
EVP_PKEY *pkey;
EVP_MD *dgst;
	{
	/* We now need to add another PKCS7_SIGNER_INFO entry */
	ASN1_INTEGER_set(p7i->version,1);
	X509_NAME_set(&p7i->issuer_and_serial->issuer,
		X509_get_issuer_name(x509));

	/* because ASN1_INTEGER_set is used to set a 'long' we will do
	 * things the ugly way. */
	ASN1_INTEGER_free(p7i->issuer_and_serial->serial);
	p7i->issuer_and_serial->serial=
		ASN1_INTEGER_dup(X509_get_serialNumber(x509));

	/* lets keep the pkey around for a while */
	CRYPTO_add(&pkey->references,1,CRYPTO_LOCK_EVP_PKEY);
	p7i->pkey=pkey;

	/* Set the algorithms */
	p7i->digest_alg->algorithm=OBJ_nid2obj(EVP_MD_type(dgst));
	p7i->digest_enc_alg->algorithm=OBJ_nid2obj(EVP_MD_pkey_type(dgst));

#if 1
	if (p7i->digest_enc_alg->parameter != NULL)
		ASN1_TYPE_free(p7i->digest_enc_alg->parameter);
	if ((p7i->digest_enc_alg->parameter=ASN1_TYPE_new()) == NULL)
		goto err;
	p7i->digest_enc_alg->parameter->type=V_ASN1_NULL;
#endif


	return(1);
err:
	return(0);
	}

PKCS7_SIGNER_INFO *PKCS7_add_signature(p7,x509,pkey,dgst)
PKCS7 *p7;
X509 *x509;
EVP_PKEY *pkey;
EVP_MD *dgst;
	{
	PKCS7_SIGNER_INFO *si;

	if ((si=PKCS7_SIGNER_INFO_new()) == NULL) goto err;
	if (!PKCS7_SIGNER_INFO_set(si,x509,pkey,dgst)) goto err;
	if (!PKCS7_add_signer(p7,si)) goto err;
	return(si);
err:
	return(NULL);
	}

STACK *PKCS7_get_signer_info(p7)
PKCS7 *p7;
	{
	if (PKCS7_type_is_signed(p7))
		{
		return(p7->d.sign->signer_info);
		}
	else
		return(NULL);
	}

X509 *PKCS7_cert_from_signer_info(p7,si)
PKCS7 *p7;
PKCS7_SIGNER_INFO *si;
	{
	if (PKCS7_type_is_signed(p7))
		return(X509_find_by_issuer_and_serial(p7->d.sign->cert,
			si->issuer_and_serial->issuer,
			si->issuer_and_serial->serial));
	else
		return(NULL);
	}


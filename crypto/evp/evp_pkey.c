/* evp_pkey.c */
/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 1999.
 */
/* ====================================================================
 * Copyright (c) 1999-2002 The OpenSSL Project.  All rights reserved.
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
#include <stdlib.h>
#include "cryptlib.h"
#include <openssl/x509.h>
#include <openssl/rand.h>

#ifndef OPENSSL_NO_DSA
static int dsa_pkey2pkcs8(PKCS8_PRIV_KEY_INFO *p8inf, EVP_PKEY *pkey);
#endif
#ifndef OPENSSL_NO_ECDSA
static int ecdsa_pkey2pkcs8(PKCS8_PRIV_KEY_INFO *p8inf, EVP_PKEY *pkey);
#endif

/* Extract a private key from a PKCS8 structure */

EVP_PKEY *EVP_PKCS82PKEY (PKCS8_PRIV_KEY_INFO *p8)
{
	EVP_PKEY *pkey = NULL;
#ifndef OPENSSL_NO_RSA
	RSA *rsa = NULL;
#endif
#ifndef OPENSSL_NO_DSA
	DSA *dsa = NULL;
#endif
#ifndef OPENSSL_NO_ECDSA
	ECDSA    *ecdsa = NULL;
#endif
#if !defined(OPENSSL_NO_DSA) || !defined(OPENSSL_NO_ECDSA)
	ASN1_INTEGER *privkey;
	ASN1_TYPE    *t1, *t2, *param = NULL;
	STACK_OF(ASN1_TYPE) *n_stack = NULL;
	BN_CTX *ctx = NULL;
	int plen;
#endif
	X509_ALGOR *a;
	unsigned char *p;
	const unsigned char *cp;
	int pkeylen;
	int  nid;
	char obj_tmp[80];

	if(p8->pkey->type == V_ASN1_OCTET_STRING) {
		p8->broken = PKCS8_OK;
		p = p8->pkey->value.octet_string->data;
		pkeylen = p8->pkey->value.octet_string->length;
	} else {
		p8->broken = PKCS8_NO_OCTET;
		p = p8->pkey->value.sequence->data;
		pkeylen = p8->pkey->value.sequence->length;
	}
	if (!(pkey = EVP_PKEY_new())) {
		EVPerr(EVP_F_EVP_PKCS82PKEY,ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	a = p8->pkeyalg;
	nid = OBJ_obj2nid(a->algorithm);
	switch(nid)
	{
#ifndef OPENSSL_NO_RSA
		case NID_rsaEncryption:
		cp = p;
		if (!(rsa = d2i_RSAPrivateKey (NULL,&cp, pkeylen))) {
			EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_DECODE_ERROR);
			return NULL;
		}
		EVP_PKEY_assign_RSA (pkey, rsa);
		break;
#endif
#if !defined(OPENSSL_NO_DSA) || !defined(OPENSSL_NO_ECDSA)
		case NID_ecdsa_with_SHA1:
		case NID_dsa:
		/* PKCS#8 DSA/ECDSA is weird: you just get a private key integer
	         * and parameters in the AlgorithmIdentifier the pubkey must
		 * be recalculated.
		 */
	
		/* Check for broken DSA/ECDSA PKCS#8, UGH! */
		if(*p == (V_ASN1_SEQUENCE|V_ASN1_CONSTRUCTED)) 
		{
		    	if(!(n_stack = ASN1_seq_unpack_ASN1_TYPE(p, pkeylen, 
							  d2i_ASN1_TYPE,
							  ASN1_TYPE_free))) 
			{
				EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_DECODE_ERROR);
				goto err;
		    	}
		    	if(sk_ASN1_TYPE_num(n_stack) != 2 ) 
			{
				EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_DECODE_ERROR);
				goto err;
		    	}
		    /* Handle Two broken types:
		     * SEQUENCE {parameters, priv_key}
		     * SEQUENCE {pub_key, priv_key}
		     */

		    t1 = sk_ASN1_TYPE_value(n_stack, 0);
		    t2 = sk_ASN1_TYPE_value(n_stack, 1);
		    if(t1->type == V_ASN1_SEQUENCE) 
		    {
			p8->broken = PKCS8_EMBEDDED_PARAM;
			param = t1;
		    } 
		    else if(a->parameter->type == V_ASN1_SEQUENCE) 
		    {
			p8->broken = PKCS8_NS_DB;
			param = a->parameter;
		    } 
		    else 
		    {
			EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_DECODE_ERROR);
			goto err;
		    }

		    if(t2->type != V_ASN1_INTEGER) {
			EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_DECODE_ERROR);
			goto err;
		    }
		    privkey = t2->value.integer;
		} 
		else 
		{
			if (!(privkey=d2i_ASN1_INTEGER (NULL, &p, pkeylen))) 
			{
				EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_DECODE_ERROR);
				goto err;
			}
			param = p8->pkeyalg->parameter;
		}
		if (!param || (param->type != V_ASN1_SEQUENCE)) 
		{
			EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_DECODE_ERROR);
			goto err;
		}
		cp = p = param->value.sequence->data;
		plen = param->value.sequence->length;
		if (!(ctx = BN_CTX_new())) 
		{
			EVPerr(EVP_F_EVP_PKCS82PKEY,ERR_R_MALLOC_FAILURE);
			goto err;
		}
		if (nid == NID_dsa)
		{
#ifndef OPENSSL_NO_DSA
			if (!(dsa = d2i_DSAparams (NULL, &cp, plen))) 
			{
				EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_DECODE_ERROR);
				goto err;
			}
			/* We have parameters now set private key */
			if (!(dsa->priv_key = ASN1_INTEGER_to_BN(privkey, NULL))) 
			{
				EVPerr(EVP_F_EVP_PKCS82PKEY,EVP_R_BN_DECODE_ERROR);
				goto err;
			}
			/* Calculate public key (ouch!) */
			if (!(dsa->pub_key = BN_new())) 
			{
				EVPerr(EVP_F_EVP_PKCS82PKEY,ERR_R_MALLOC_FAILURE);
				goto err;
			}
			if (!BN_mod_exp(dsa->pub_key, dsa->g,
						 dsa->priv_key, dsa->p, ctx)) 
			{
				EVPerr(EVP_F_EVP_PKCS82PKEY,EVP_R_BN_PUBKEY_ERROR);
				goto err;
			}

			EVP_PKEY_assign_DSA(pkey, dsa);
			BN_CTX_free(ctx);
			if(n_stack) sk_ASN1_TYPE_pop_free(n_stack, ASN1_TYPE_free);
			else ASN1_INTEGER_free(privkey);
#else
			EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM);
			goto err;
#endif 
		} 
		else /* nid == NID_ecdsa_with_SHA1 */
		{
#ifndef OPENSSL_NO_ECDSA
			if ((ecdsa = d2i_ECDSAParameters(NULL, &cp, plen)) == NULL)
			{
				EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_DECODE_ERROR);
				goto err;
			}
			if ((ecdsa->priv_key = ASN1_INTEGER_to_BN(privkey, NULL)) == NULL)
			{
				EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_DECODE_ERROR);
				goto err;
			}
			if ((ecdsa->pub_key = EC_POINT_new(ecdsa->group)) == NULL)
			{
				EVPerr(EVP_F_EVP_PKCS82PKEY, ERR_R_EC_LIB);
				goto err;
			}
			if (!EC_POINT_copy(ecdsa->pub_key, EC_GROUP_get0_generator(ecdsa->group)))
			{
				EVPerr(EVP_F_EVP_PKCS82PKEY, ERR_R_EC_LIB);
				goto err;
			}
			if (!EC_POINT_mul(ecdsa->group, ecdsa->pub_key, ecdsa->priv_key,
					  NULL, NULL, ctx))
			{
				EVPerr(EVP_F_EVP_PKCS82PKEY, ERR_R_EC_LIB);
				goto err;
			}
			
			EVP_PKEY_assign_ECDSA(pkey, ecdsa);
			BN_CTX_free(ctx);
			if (n_stack) sk_ASN1_TYPE_pop_free(n_stack, ASN1_TYPE_free);
			else
				ASN1_INTEGER_free(privkey);
#else
			EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM);
			goto err;
#endif
		}
		break;
err:
		if (ctx)   BN_CTX_free(ctx);
		sk_ASN1_TYPE_pop_free(n_stack, ASN1_TYPE_free);
#ifndef OPENSSL_NO_DSA
		if (dsa)   DSA_free(dsa);
#endif
#ifndef OPENSSL_NO_ECDSA
		if (ecdsa) ECDSA_free(ecdsa);
#endif
		if (pkey)  EVP_PKEY_free(pkey);
		return NULL;
		break;
#endif
		default:
		EVPerr(EVP_F_EVP_PKCS82PKEY, EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM);
		if (!a->algorithm) strcpy (obj_tmp, "NULL");
		else i2t_ASN1_OBJECT(obj_tmp, 80, a->algorithm);
		ERR_add_error_data(2, "TYPE=", obj_tmp);
		EVP_PKEY_free (pkey);
		return NULL;
	}
	return pkey;
}

PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8(EVP_PKEY *pkey)
{
	return EVP_PKEY2PKCS8_broken(pkey, PKCS8_OK);
}

/* Turn a private key into a PKCS8 structure */

PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8_broken(EVP_PKEY *pkey, int broken)
{
	PKCS8_PRIV_KEY_INFO *p8;

	if (!(p8 = PKCS8_PRIV_KEY_INFO_new())) {	
		EVPerr(EVP_F_EVP_PKEY2PKCS8,ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	p8->broken = broken;
	ASN1_INTEGER_set (p8->version, 0);
	if (!(p8->pkeyalg->parameter = ASN1_TYPE_new ())) {
		EVPerr(EVP_F_EVP_PKEY2PKCS8,ERR_R_MALLOC_FAILURE);
		PKCS8_PRIV_KEY_INFO_free (p8);
		return NULL;
	}
	p8->pkey->type = V_ASN1_OCTET_STRING;
	switch (EVP_PKEY_type(pkey->type)) {
#ifndef OPENSSL_NO_RSA
		case EVP_PKEY_RSA:

		if(p8->broken == PKCS8_NO_OCTET) p8->pkey->type = V_ASN1_SEQUENCE;

		p8->pkeyalg->algorithm = OBJ_nid2obj(NID_rsaEncryption);
		p8->pkeyalg->parameter->type = V_ASN1_NULL;
		if (!ASN1_pack_string ((char *)pkey, i2d_PrivateKey,
					 &p8->pkey->value.octet_string)) {
			EVPerr(EVP_F_EVP_PKEY2PKCS8,ERR_R_MALLOC_FAILURE);
			PKCS8_PRIV_KEY_INFO_free (p8);
			return NULL;
		}
		break;
#endif
#ifndef OPENSSL_NO_DSA
		case EVP_PKEY_DSA:
		if(!dsa_pkey2pkcs8(p8, pkey)) {
			PKCS8_PRIV_KEY_INFO_free (p8);
			return NULL;
		}

		break;
#endif
#ifndef OPENSSL_NO_ECDSA
		case EVP_PKEY_ECDSA:
		if (!ecdsa_pkey2pkcs8(p8, pkey))
		{
			PKCS8_PRIV_KEY_INFO_free(p8);
			return(NULL);
		}
		break;
#endif
		default:
		EVPerr(EVP_F_EVP_PKEY2PKCS8, EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM);
		PKCS8_PRIV_KEY_INFO_free (p8);
		return NULL;
	}
	RAND_add(p8->pkey->value.octet_string->data,
		 p8->pkey->value.octet_string->length, 0);
	return p8;
}

PKCS8_PRIV_KEY_INFO *PKCS8_set_broken(PKCS8_PRIV_KEY_INFO *p8, int broken)
{
	switch (broken) {

		case PKCS8_OK:
		p8->broken = PKCS8_OK;
		return p8;
		break;

		case PKCS8_NO_OCTET:
		p8->broken = PKCS8_NO_OCTET;
		p8->pkey->type = V_ASN1_SEQUENCE;
		return p8;
		break;

		default:
		EVPerr(EVP_F_EVP_PKCS8_SET_BROKEN,EVP_R_PKCS8_UNKNOWN_BROKEN_TYPE);
		return NULL;
		break;
		
	}
}

#ifndef OPENSSL_NO_DSA
static int dsa_pkey2pkcs8(PKCS8_PRIV_KEY_INFO *p8, EVP_PKEY *pkey)
{
	ASN1_STRING *params;
	ASN1_INTEGER *prkey;
	ASN1_TYPE *ttmp;
	STACK_OF(ASN1_TYPE) *ndsa;
	unsigned char *p, *q;
	int len;

	p8->pkeyalg->algorithm = OBJ_nid2obj(NID_dsa);
	len = i2d_DSAparams (pkey->pkey.dsa, NULL);
	if (!(p = OPENSSL_malloc(len))) {
		EVPerr(EVP_F_EVP_PKEY2PKCS8,ERR_R_MALLOC_FAILURE);
		PKCS8_PRIV_KEY_INFO_free (p8);
		return 0;
	}
	q = p;
	i2d_DSAparams (pkey->pkey.dsa, &q);
	params = ASN1_STRING_new();
	ASN1_STRING_set(params, p, len);
	OPENSSL_free(p);
	/* Get private key into integer */
	if (!(prkey = BN_to_ASN1_INTEGER (pkey->pkey.dsa->priv_key, NULL))) {
		EVPerr(EVP_F_EVP_PKEY2PKCS8,EVP_R_ENCODE_ERROR);
		return 0;
	}

	switch(p8->broken) {

		case PKCS8_OK:
		case PKCS8_NO_OCTET:

		if (!ASN1_pack_string((char *)prkey, i2d_ASN1_INTEGER,
					 &p8->pkey->value.octet_string)) {
			EVPerr(EVP_F_EVP_PKEY2PKCS8,ERR_R_MALLOC_FAILURE);
			M_ASN1_INTEGER_free (prkey);
			return 0;
		}

		M_ASN1_INTEGER_free (prkey);
		p8->pkeyalg->parameter->value.sequence = params;
		p8->pkeyalg->parameter->type = V_ASN1_SEQUENCE;

		break;

		case PKCS8_NS_DB:

		p8->pkeyalg->parameter->value.sequence = params;
		p8->pkeyalg->parameter->type = V_ASN1_SEQUENCE;
		ndsa = sk_ASN1_TYPE_new_null();
		ttmp = ASN1_TYPE_new();
		if (!(ttmp->value.integer = BN_to_ASN1_INTEGER (pkey->pkey.dsa->pub_key, NULL))) {
			EVPerr(EVP_F_EVP_PKEY2PKCS8,EVP_R_ENCODE_ERROR);
			PKCS8_PRIV_KEY_INFO_free(p8);
			return 0;
		}
		ttmp->type = V_ASN1_INTEGER;
		sk_ASN1_TYPE_push(ndsa, ttmp);

		ttmp = ASN1_TYPE_new();
		ttmp->value.integer = prkey;
		ttmp->type = V_ASN1_INTEGER;
		sk_ASN1_TYPE_push(ndsa, ttmp);

		p8->pkey->value.octet_string = ASN1_OCTET_STRING_new();

		if (!ASN1_seq_pack_ASN1_TYPE(ndsa, i2d_ASN1_TYPE,
					 &p8->pkey->value.octet_string->data,
					 &p8->pkey->value.octet_string->length)) {

			EVPerr(EVP_F_EVP_PKEY2PKCS8,ERR_R_MALLOC_FAILURE);
			sk_ASN1_TYPE_pop_free(ndsa, ASN1_TYPE_free);
			M_ASN1_INTEGER_free(prkey);
			return 0;
		}
		sk_ASN1_TYPE_pop_free(ndsa, ASN1_TYPE_free);
		break;

		case PKCS8_EMBEDDED_PARAM:

		p8->pkeyalg->parameter->type = V_ASN1_NULL;
		ndsa = sk_ASN1_TYPE_new_null();
		ttmp = ASN1_TYPE_new();
		ttmp->value.sequence = params;
		ttmp->type = V_ASN1_SEQUENCE;
		sk_ASN1_TYPE_push(ndsa, ttmp);

		ttmp = ASN1_TYPE_new();
		ttmp->value.integer = prkey;
		ttmp->type = V_ASN1_INTEGER;
		sk_ASN1_TYPE_push(ndsa, ttmp);

		p8->pkey->value.octet_string = ASN1_OCTET_STRING_new();

		if (!ASN1_seq_pack_ASN1_TYPE(ndsa, i2d_ASN1_TYPE,
					 &p8->pkey->value.octet_string->data,
					 &p8->pkey->value.octet_string->length)) {

			EVPerr(EVP_F_EVP_PKEY2PKCS8,ERR_R_MALLOC_FAILURE);
			sk_ASN1_TYPE_pop_free(ndsa, ASN1_TYPE_free);
			M_ASN1_INTEGER_free (prkey);
			return 0;
		}
		sk_ASN1_TYPE_pop_free(ndsa, ASN1_TYPE_free);
		break;
	}
	return 1;
}
#endif

#ifndef OPENSSL_NO_ECDSA
static int ecdsa_pkey2pkcs8(PKCS8_PRIV_KEY_INFO *p8, EVP_PKEY *pkey)
{
	ASN1_STRING 	  *params=NULL;
	ASN1_INTEGER      *prkey=NULL;
	ASN1_TYPE         *ttmp=NULL;
	STACK_OF(ASN1_TYPE) *necdsa=NULL;
	unsigned char 	  *p=NULL, *q=NULL;
	int len=0;
	EC_POINT	  *point=NULL;

	if (pkey->pkey.ecdsa == NULL || pkey->pkey.ecdsa->group == NULL)
	{
		EVPerr(EVP_F_ECDSA_PKEY2PKCS8, EVP_R_MISSING_PARAMETERS);
		return 0;
	}
	p8->pkeyalg->algorithm = OBJ_nid2obj(NID_ecdsa_with_SHA1);
	len = i2d_ECDSAParameters(pkey->pkey.ecdsa, NULL);
	if ((p = OPENSSL_malloc(len)) == NULL)
	{
		EVPerr(EVP_F_ECDSA_PKEY2PKCS8, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	q = p;
	if (!i2d_ECDSAParameters(pkey->pkey.ecdsa, &q))
	{
		EVPerr(EVP_F_ECDSA_PKEY2PKCS8, ERR_R_ECDSA_LIB);
		OPENSSL_free(p);
		return 0;
	}
	if ((params = ASN1_STRING_new()) == NULL)
	{
		EVPerr(EVP_F_ECDSA_PKEY2PKCS8, ERR_R_MALLOC_FAILURE);
		OPENSSL_free(p);
		return 0;
		
	}
	if (!ASN1_STRING_set(params, p, len))
	{
		EVPerr(EVP_F_ECDSA_PKEY2PKCS8, ERR_R_ASN1_LIB);
		OPENSSL_free(p);
		return 0;
	}
	OPENSSL_free(p);
	if ((prkey = BN_to_ASN1_INTEGER(pkey->pkey.ecdsa->priv_key, NULL)) == NULL)
	{
		EVPerr(EVP_F_ECDSA_PKEY2PKCS8, ERR_R_ASN1_LIB);
		return 0;
	}

	switch(p8->broken) {

		case PKCS8_OK:
		case PKCS8_NO_OCTET:

		if (!ASN1_pack_string((char *)prkey, i2d_ASN1_INTEGER,
					 &p8->pkey->value.octet_string)) 
		{
			EVPerr(EVP_F_ECDSA_PKEY2PKCS8, ERR_R_MALLOC_FAILURE);
			M_ASN1_INTEGER_free(prkey);
			return 0;
		}

		ASN1_INTEGER_free(prkey);
		p8->pkeyalg->parameter->value.sequence = params;
		p8->pkeyalg->parameter->type = V_ASN1_SEQUENCE;

		break;

		case PKCS8_NS_DB:

		p8->pkeyalg->parameter->value.sequence = params;
		p8->pkeyalg->parameter->type = V_ASN1_SEQUENCE;
		necdsa = sk_ASN1_TYPE_new_null();
		if (necdsa == NULL || (ttmp = ASN1_TYPE_new()) == NULL)
		{
			EVPerr(EVP_F_ECDSA_PKEY2PKCS8, ERR_R_MALLOC_FAILURE);
			sk_ASN1_TYPE_pop_free(necdsa, ASN1_TYPE_free);
			return 0;
		}

		if ((point = EC_GROUP_get0_generator(pkey->pkey.ecdsa->group)) == NULL)
		{
			EVPerr(EVP_F_ECDSA_PKEY2PKCS8, ERR_R_EC_LIB);
			return 0;
		}
		len = EC_POINT_point2oct(pkey->pkey.ecdsa->group, point, POINT_CONVERSION_COMPRESSED,
				         NULL, 0, NULL);
		p = OPENSSL_malloc(len);
		if (!len || !p || !EC_POINT_point2oct(pkey->pkey.ecdsa->group, point,
			POINT_CONVERSION_COMPRESSED, p, len, NULL))
		{
			EVPerr(EVP_F_ECDSA_PKEY2PKCS8, ERR_R_EC_LIB);
			OPENSSL_free(p);
			return 0;
		}
		if ((ttmp->value.octet_string = ASN1_OCTET_STRING_new()) == NULL)
		{
			EVPerr(EVP_F_ECDSA_PKEY2PKCS8, ERR_R_MALLOC_FAILURE);
			return 0;
		}
		if (!ASN1_OCTET_STRING_set(ttmp->value.octet_string, p, len))
		{
			EVPerr(EVP_F_ECDSA_PKEY2PKCS8, EVP_R_ASN1_LIB);
			return 0;
		}
		OPENSSL_free(p);
		
		ttmp->type = V_ASN1_OCTET_STRING;
		if (!sk_ASN1_TYPE_push(necdsa, ttmp))
		{
			sk_ASN1_TYPE_pop_free(necdsa, ASN1_TYPE_free);
			ASN1_INTEGER_free(prkey);
			return 0;
		}

		if ((ttmp = ASN1_TYPE_new()) == NULL)
		{
			EVPerr(EVP_F_ECDSA_PKEY2PKCS8, ERR_R_MALLOC_FAILURE);
			return 0;
		}
		ttmp->value.integer = prkey;
		ttmp->type = V_ASN1_INTEGER;
		if (!sk_ASN1_TYPE_push(necdsa, ttmp))
		{
			sk_ASN1_TYPE_pop_free(necdsa, ASN1_TYPE_free);
			ASN1_INTEGER_free(prkey);
			return 0;
		}

		if ((p8->pkey->value.octet_string = ASN1_OCTET_STRING_new()) == NULL)
		{	
			EVPerr(EVP_F_ECDSA_PKEY2PKCS8, ERR_R_MALLOC_FAILURE);
			sk_ASN1_TYPE_pop_free(necdsa, ASN1_TYPE_free);
			return 0;
		}

		if (!ASN1_seq_pack_ASN1_TYPE(necdsa, i2d_ASN1_TYPE,
					 &p8->pkey->value.octet_string->data,
					 &p8->pkey->value.octet_string->length)) 
		{

			EVPerr(EVP_F_ECDSA_PKEY2PKCS8, ERR_R_MALLOC_FAILURE);
			sk_ASN1_TYPE_pop_free(necdsa, ASN1_TYPE_free);
			return 0;
		}
		sk_ASN1_TYPE_pop_free(necdsa, ASN1_TYPE_free);
		break;

		case PKCS8_EMBEDDED_PARAM:

		p8->pkeyalg->parameter->type = V_ASN1_NULL;
		necdsa = sk_ASN1_TYPE_new_null();
		if ((ttmp = ASN1_TYPE_new()) == NULL)
		{
			EVPerr(EVP_F_ECDSA_PKEY2PKCS8, ERR_R_MALLOC_FAILURE);
			sk_ASN1_TYPE_pop_free(necdsa, ASN1_TYPE_free);
			ASN1_INTEGER_free(prkey);
			return 0;
		}
		ttmp->value.sequence = params;
		ttmp->type = V_ASN1_SEQUENCE;
		if (!sk_ASN1_TYPE_push(necdsa, ttmp))
		{
			sk_ASN1_TYPE_pop_free(necdsa, ASN1_TYPE_free);
			ASN1_INTEGER_free(prkey);
			return 0;
		}

		if ((ttmp = ASN1_TYPE_new()) == NULL)
		{
			EVPerr(EVP_F_ECDSA_PKEY2PKCS8, ERR_R_MALLOC_FAILURE);
			sk_ASN1_TYPE_pop_free(necdsa, ASN1_TYPE_free);
			ASN1_INTEGER_free(prkey);
			return 0;
		}
		ttmp->value.integer = prkey;
		ttmp->type = V_ASN1_INTEGER;
		if (!sk_ASN1_TYPE_push(necdsa, ttmp))
		{
			sk_ASN1_TYPE_pop_free(necdsa, ASN1_TYPE_free);
			ASN1_INTEGER_free(prkey);
			return 0;
		}

		if ((p8->pkey->value.octet_string = ASN1_OCTET_STRING_new()) == NULL)
		{
			EVPerr(EVP_F_ECDSA_PKEY2PKCS8, ERR_R_MALLOC_FAILURE);
			sk_ASN1_TYPE_pop_free(necdsa, ASN1_TYPE_free);
			return 0;
		}

		if (!ASN1_seq_pack_ASN1_TYPE(necdsa, i2d_ASN1_TYPE,
					 &p8->pkey->value.octet_string->data,
					 &p8->pkey->value.octet_string->length)) 
		{
			EVPerr(EVP_F_ECDSA_PKEY2PKCS8, ERR_R_MALLOC_FAILURE);
			sk_ASN1_TYPE_pop_free(necdsa, ASN1_TYPE_free);
			return 0;
		}
		sk_ASN1_TYPE_pop_free(necdsa, ASN1_TYPE_free);
		break;
	}
	return 1;
}
#endif

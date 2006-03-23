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
#include <openssl/ec.h>
#include "asn1_locl.h"

extern const EVP_PKEY_ASN1_METHOD rsa_asn1_meths[];
extern const EVP_PKEY_ASN1_METHOD dsa_asn1_meths[];
extern const EVP_PKEY_ASN1_METHOD dh_asn1_meth;
extern const EVP_PKEY_ASN1_METHOD eckey_asn1_meth;

/* Keep this sorted in type order !! */
const EVP_PKEY_ASN1_METHOD *standard_methods[] = 
	{
	&rsa_asn1_meths[0],
	&rsa_asn1_meths[1],
	&dh_asn1_meth,
	&dsa_asn1_meths[0],
	&dsa_asn1_meths[1],
	&dsa_asn1_meths[2],
	&dsa_asn1_meths[3],
	&dsa_asn1_meths[4],
	&eckey_asn1_meth
	};

typedef int sk_cmp_fn_type(const char * const *a, const char * const *b);
static STACK *app_methods = NULL;



#ifdef TEST
void main()
	{
	int i;
	for (i = 0;
		i < sizeof(standard_methods)/sizeof(EVP_PKEY_ASN1_METHOD *);
		i++)
		fprintf(stderr, "Number %d id=%d (%s)\n", i,
			standard_methods[i]->pkey_id,
			OBJ_nid2sn(standard_methods[i]->pkey_id));
	}
#endif

static int ameth_cmp(const EVP_PKEY_ASN1_METHOD * const *a,
                const EVP_PKEY_ASN1_METHOD * const *b)
	{
        return ((*a)->pkey_id - (*b)->pkey_id);
	}

const EVP_PKEY_ASN1_METHOD *EVP_PKEY_asn1_find(int type)
	{
	EVP_PKEY_ASN1_METHOD tmp, *t = &tmp, **ret;
	tmp.pkey_id = type;
	if (app_methods)
		{
		int idx;
		idx = sk_find(app_methods, (char *)&t);
		if (idx > 0)
			return (EVP_PKEY_ASN1_METHOD *)
				sk_value(app_methods, idx);
		}
	ret = (EVP_PKEY_ASN1_METHOD **) OBJ_bsearch((char *)&t,
        		(char *)standard_methods,
			sizeof(standard_methods)/sizeof(EVP_PKEY_ASN1_METHOD *),
        		sizeof(EVP_PKEY_ASN1_METHOD *),
			(int (*)(const void *, const void *))ameth_cmp);
	if (!ret || !*ret)
		return NULL;
	if ((*ret)->pkey_flags & ASN1_PKEY_ALIAS)
		return EVP_PKEY_asn1_find((*ret)->pkey_base_id);
	return *ret;
	}

int EVP_PKEY_asn1_add(const EVP_PKEY_ASN1_METHOD *ameth)
	{
	if (app_methods == NULL)
		{
		app_methods = sk_new((sk_cmp_fn_type *)ameth_cmp);
		if (!app_methods)
			return 0;
		}
	if (!sk_push(app_methods, (char *)ameth))
		return 0;
	sk_sort(app_methods);
	return 1;
	}

EVP_PKEY_ASN1_METHOD* EVP_PKEY_asn1_new(int id,
					const char *pem_str, const char *info)
	{
	EVP_PKEY_ASN1_METHOD *ameth;
	ameth = OPENSSL_malloc(sizeof(EVP_PKEY_ASN1_METHOD));
	if (!ameth)
		return NULL;

	ameth->pkey_id = id;
	ameth->pkey_base_id = id;
	ameth->pkey_flags = ASN1_PKEY_DYNAMIC;

	if (info)
		{
		ameth->info = BUF_strdup(info);
		if (!ameth->info)
			goto err;
		}

	if (pem_str)
		{
		ameth->pem_str = BUF_strdup(pem_str);
		if (!ameth->pem_str)
			goto err;
		}
	
	ameth->pub_decode = 0;
	ameth->pub_encode = 0;
	ameth->pub_cmp = 0;
	ameth->pub_print = 0;


	ameth->priv_decode = 0;
	ameth->priv_encode = 0;
	ameth->priv_print = 0;
	

	ameth->pkey_size = 0;
	ameth->pkey_bits = 0;

	ameth->param_decode = 0;
	ameth->param_encode = 0;
	ameth->param_missing = 0;
	ameth->param_copy = 0;
	ameth->param_cmp = 0;
	ameth->param_print = 0;


	ameth->pkey_free = 0;
	ameth->pkey_ctrl = 0;

	return ameth;

	err:

	EVP_PKEY_asn1_free(ameth);
	return NULL;

	}

void EVP_PKEY_asn1_free(EVP_PKEY_ASN1_METHOD *ameth)
	{
	if (ameth && (ameth->pkey_flags & ASN1_PKEY_DYNAMIC))
		{
		if (ameth->pem_str)
			OPENSSL_free(ameth->pem_str);
		if (ameth->info)
			OPENSSL_free(ameth->info);
		OPENSSL_free(ameth);
		}
	}

void EVP_PKEY_asn1_set_public(EVP_PKEY_ASN1_METHOD *ameth,
		int (*pub_decode)(EVP_PKEY *pk, X509_PUBKEY *pub),
		int (*pub_encode)(X509_PUBKEY *pub, const EVP_PKEY *pk),
		int (*pub_cmp)(const EVP_PKEY *a, const EVP_PKEY *b),
		int (*pub_print)(BIO *out, const EVP_PKEY *pkey, int indent,
							ASN1_PCTX *pctx),
		int (*pkey_size)(const EVP_PKEY *pk),
		int (*pkey_bits)(const EVP_PKEY *pk))
	{
	ameth->pub_decode = pub_decode;
	ameth->pub_encode = pub_encode;
	ameth->pub_cmp = pub_cmp;
	ameth->pub_print = pub_print;
	ameth->pkey_size = pkey_size;
	ameth->pkey_bits = pkey_bits;
	}

void EVP_PKEY_asn1_set_private(EVP_PKEY_ASN1_METHOD *ameth,
		int (*priv_decode)(EVP_PKEY *pk, PKCS8_PRIV_KEY_INFO *p8inf),
		int (*priv_encode)(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pk),
		int (*priv_print)(BIO *out, const EVP_PKEY *pkey, int indent,
							ASN1_PCTX *pctx))
	{
	ameth->priv_decode = priv_decode;
	ameth->priv_encode = priv_encode;
	ameth->priv_print = priv_print;
	}

void EVP_PKEY_asn1_set_param(EVP_PKEY_ASN1_METHOD *ameth,
		int (*param_decode)(const EVP_PKEY *pk, X509_PUBKEY *pub),
		int (*param_encode)(X509_PUBKEY *pub, const EVP_PKEY *pk),
		int (*param_missing)(const EVP_PKEY *pk),
		int (*param_copy)(EVP_PKEY *to, const EVP_PKEY *from),
		int (*param_cmp)(const EVP_PKEY *a, const EVP_PKEY *b),
		int (*param_print)(BIO *out, const EVP_PKEY *pkey, int indent,
							ASN1_PCTX *pctx))
	{
	ameth->param_decode = param_decode;
	ameth->param_encode = param_encode;
	ameth->param_missing = param_missing;
	ameth->param_copy = param_copy;
	ameth->param_cmp = param_cmp;
	ameth->param_print = param_print;
	}

void EVP_PKEY_asn1_set_free(EVP_PKEY_ASN1_METHOD *ameth,
		void (*pkey_free)(EVP_PKEY *pkey))
	{
	ameth->pkey_free = pkey_free;
	}

void EVP_PKEY_asn1_set_ctrl(EVP_PKEY_ASN1_METHOD *ameth,
		void (*pkey_ctrl)(EVP_PKEY *pkey, int op,
							long arg1, void *arg2))
	{
	ameth->pkey_ctrl = pkey_ctrl;
	}

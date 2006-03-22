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
#include "asn1_locl.h"

static int rsa_pub_encode(X509_PUBKEY *pk, const EVP_PKEY *pkey)
	{
	unsigned char *penc = NULL;
	int penclen;
	penclen = i2d_RSAPublicKey(pkey->pkey.rsa, &penc);
	if (penclen <= 0)
		return 0;
	if (X509_PUBKEY_set0_param(pk, OBJ_nid2obj(EVP_PKEY_RSA),
				V_ASN1_NULL, NULL, penc, penclen))
		return 1;

	OPENSSL_free(penc);
	return 0;
	}

static int rsa_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
	{
	const unsigned char *p;
	int pklen;
	RSA *rsa = NULL;
	if (!X509_PUBKEY_get0_param(NULL, &p, &pklen, NULL, pubkey))
		return 0;
	if (!(rsa = d2i_RSAPublicKey(NULL, &p, pklen)))
		{
		RSAerr(RSA_F_RSA_PUB_DECODE, ERR_R_RSA_LIB);
		return 0;
		}
	EVP_PKEY_assign_RSA (pkey, rsa);
	return 1;
	}

static int rsa_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
	{
	if (BN_cmp(b->pkey.rsa->n,a->pkey.rsa->n) != 0
		|| BN_cmp(b->pkey.rsa->e,a->pkey.rsa->e) != 0)
			return 0;
	return 1;
	}

static int rsa_priv_decode(EVP_PKEY *pkey, PKCS8_PRIV_KEY_INFO *p8)
	{
	const unsigned char *p;
	int pklen;
	RSA *rsa = NULL;
	if (!PKCS8_pkey_get0(NULL, &p, &pklen, NULL, p8))
		return 0;
	if (!(rsa = d2i_RSAPrivateKey (NULL, &p, pklen)))
		{
		RSAerr(RSA_F_RSA_PRIV_DECODE, ERR_R_RSA_LIB);
		return 0;
		}
	EVP_PKEY_assign_RSA (pkey, rsa);
	return 1;
	}

static int rsa_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
	{
	unsigned char *rk = NULL;
	int rklen;
	rklen = i2d_RSAPrivateKey(pkey->pkey.rsa, &rk);

	if (rklen <= 0)
		{
		RSAerr(RSA_F_RSA_PRIV_ENCODE,ERR_R_MALLOC_FAILURE);
		return 0;
		}

	if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(NID_rsaEncryption), 0,
				V_ASN1_NULL, NULL, rk, rklen))
		{
		RSAerr(RSA_F_RSA_PRIV_ENCODE,ERR_R_MALLOC_FAILURE);
		return 0;
		}

	return 1;
	}

static int int_rsa_size(const EVP_PKEY *pkey)
	{
	return RSA_size(pkey->pkey.rsa);
	}

static int rsa_bits(const EVP_PKEY *pkey)
	{
	return BN_num_bits(pkey->pkey.rsa->n);
	}

static void int_rsa_free(EVP_PKEY *pkey)
	{
	RSA_free(pkey->pkey.rsa);
	}


static void update_buflen(const BIGNUM *b, size_t *pbuflen)
	{
	int i;
	if (!b)
		return;
	if (*pbuflen < (i = (size_t)BN_num_bytes(b)))
			*pbuflen = i;
	}

static int do_rsa_print(BIO *bp, const RSA *x, int off, int priv)
	{
	char *str;
	const char *s;
	unsigned char *m=NULL;
	int ret=0, mod_len = 0;
	size_t buf_len=0;

	update_buflen(x->n, &buf_len);
	update_buflen(x->e, &buf_len);

	if (priv)
		{
		update_buflen(x->d, &buf_len);
		update_buflen(x->p, &buf_len);
		update_buflen(x->q, &buf_len);
		update_buflen(x->dmp1, &buf_len);
		update_buflen(x->dmq1, &buf_len);
		update_buflen(x->iqmp, &buf_len);
		}

	m=(unsigned char *)OPENSSL_malloc(buf_len+10);
	if (m == NULL)
		{
		RSAerr(RSA_F_RSA_PRINT,ERR_R_MALLOC_FAILURE);
		goto err;
		}

	if (x->n != NULL)
		mod_len = BN_num_bits(x->n);

	if(!BIO_indent(bp,off,128))
		goto err;

	if (priv && x->d)
		{
		if (BIO_printf(bp,"Private-Key: (%d bit)\n", mod_len)
			<= 0) goto err;
		str = "modulus:";
		s = "publicExponent:";
		}
	else
		{
		if (BIO_printf(bp,"Public-Key: (%d bit)\n", mod_len)
			<= 0) goto err;
		str = "Modulus:";
		s= "Exponent:";
		}
	if (!ASN1_bn_print(bp,str,x->n,m,off)) goto err;
	if (!ASN1_bn_print(bp,s,x->e,m,off))
		goto err;
	if (priv)
		{
		if (!ASN1_bn_print(bp,"privateExponent:",x->d,m,off))
			goto err;
		if (!ASN1_bn_print(bp,"prime1:",x->p,m,off))
			goto err;
		if (!ASN1_bn_print(bp,"prime2:",x->q,m,off))
			goto err;
		if (!ASN1_bn_print(bp,"exponent1:",x->dmp1,m,off))
			goto err;
		if (!ASN1_bn_print(bp,"exponent2:",x->dmq1,m,off))
			goto err;
		if (!ASN1_bn_print(bp,"coefficient:",x->iqmp,m,off))
			goto err;
		}
	ret=1;
err:
	if (m != NULL) OPENSSL_free(m);
	return(ret);
	}

static int rsa_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent,
							ASN1_PCTX *ctx)
	{
	return do_rsa_print(bp, pkey->pkey.rsa, indent, 0);
	}


static int rsa_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent,
							ASN1_PCTX *ctx)
	{
	return do_rsa_print(bp, pkey->pkey.rsa, indent, 1);
	}

const EVP_PKEY_ASN1_METHOD rsa_asn1_meths[] = 
	{
		{
		EVP_PKEY_RSA,
		EVP_PKEY_RSA,
		0,

		rsa_pub_decode,
		rsa_pub_encode,
		rsa_pub_cmp,
		rsa_pub_print,

		rsa_priv_decode,
		rsa_priv_encode,
		rsa_priv_print,

		int_rsa_size,
		rsa_bits,

		0,0,0,0,0,0,

		int_rsa_free,
		0
		},

		{
		EVP_PKEY_RSA2,
		EVP_PKEY_RSA,
		ASN1_PKEY_ALIAS
		}
	};

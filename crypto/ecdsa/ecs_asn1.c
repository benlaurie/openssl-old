/* crypto/ecdsa/ecs_asn1.c */
/* ====================================================================
 * Copyright (c) 2000-2002 The OpenSSL Project.  All rights reserved.
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

#include "ecdsa.h"
#include <openssl/err.h>
#include <openssl/asn1t.h>

ASN1_SEQUENCE(ECDSA_SIG) = {
	ASN1_SIMPLE(ECDSA_SIG, r, CBIGNUM),
	ASN1_SIMPLE(ECDSA_SIG, s, CBIGNUM)
} ASN1_SEQUENCE_END(ECDSA_SIG)

DECLARE_ASN1_FUNCTIONS_const(ECDSA_SIG)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(ECDSA_SIG, ECDSA_SIG)
IMPLEMENT_ASN1_FUNCTIONS_const(ECDSA_SIG)

int i2d_ECDSAParameters(ECDSA *a, unsigned char **out)
	{
	if (a == NULL)
		{
		ECDSAerr(ECDSA_F_I2D_ECDSAPARAMETERS, 
                         ERR_R_PASSED_NULL_PARAMETER);
		return 0;
		}
	return i2d_ECPKParameters(a->group, out);
	}

ECDSA *d2i_ECDSAParameters(ECDSA **a, const unsigned char **in, long len)
	{
	EC_GROUP *group;
	ECDSA    *ret;

	if (in == NULL || *in == NULL)
		{
		ECDSAerr(ECDSA_F_D2I_ECDSAPARAMETERS, 
                         ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
		}

	group = d2i_ECPKParameters(NULL, in, len);

	if (group == NULL)
		{
		ECDSAerr(ECDSA_F_D2I_ECDSAPARAMETERS, 
                         ERR_R_EC_LIB);
		return NULL;
		}

	if (a == NULL || *a == NULL)
		{
		if ((ret = ECDSA_new()) == NULL)
			{
			ECDSAerr(ECDSA_F_D2I_ECDSAPARAMETERS, 
                                 ERR_R_MALLOC_FAILURE);
			return NULL;
			}
		if (a)
			*a = ret;
		}
	else
		ret = *a;

	if (ret->group)
		EC_GROUP_clear_free(ret->group);

	ret->group = group;
	
	return ret;
	}

ECDSA *d2i_ECDSAPrivateKey(ECDSA **a, const unsigned char **in, long len)
	{
	int             ok=0;
	ECDSA           *ret=NULL;
	EC_PRIVATEKEY   *priv_key=NULL;

	if ((priv_key = EC_PRIVATEKEY_new()) == NULL)
		{
		ECDSAerr(ECDSA_F_D2I_ECDSAPRIVATEKEY, ERR_R_MALLOC_FAILURE);
		return NULL;
		}

	if ((priv_key = d2i_EC_PRIVATEKEY(&priv_key, in, len)) == NULL)
		{
		ECDSAerr(ECDSA_F_D2I_ECDSAPRIVATEKEY, ERR_R_EC_LIB);
		EC_PRIVATEKEY_free(priv_key);
		return NULL;
		}

	if (a == NULL || *a == NULL)
		{
		if ((ret = ECDSA_new()) == NULL)	
			{
			ECDSAerr(ECDSA_F_D2I_ECDSAPRIVATEKEY,
                                 ERR_R_MALLOC_FAILURE);
			goto err;
			}
		if (a)
			*a = ret;
		}
	else
		ret = *a;

	if (priv_key->parameters)
		{
		if (ret->group)
			EC_GROUP_clear_free(ret->group);
		ret->group = EC_ASN1_pkparameters2group(priv_key->parameters);
		}

	if (ret->group == NULL)
		{
		ECDSAerr(ECDSA_F_D2I_ECDSAPRIVATEKEY, ERR_R_EC_LIB);
		goto err;
		}

	ret->version = priv_key->version;

	if (priv_key->privateKey)
		{
		ret->priv_key = BN_bin2bn(
			M_ASN1_STRING_data(priv_key->privateKey),
			M_ASN1_STRING_length(priv_key->privateKey),
			ret->priv_key);
		if (ret->priv_key == NULL)
			{
			ECDSAerr(ECDSA_F_D2I_ECDSAPRIVATEKEY,
                                 ERR_R_BN_LIB);
			goto err;
			}
		}
	else
		{
		ECDSAerr(ECDSA_F_D2I_ECDSAPRIVATEKEY, 
                         ECDSA_R_MISSING_PRIVATE_KEY);
		goto err;
		}

	if (priv_key->publicKey)
		{
		if (ret->pub_key)
			EC_POINT_clear_free(ret->pub_key);
		ret->pub_key = EC_POINT_new(ret->group);
		if (ret->pub_key == NULL)
			{
			ECDSAerr(ECDSA_F_D2I_ECDSAPRIVATEKEY, ERR_R_EC_LIB);
			goto err;
			}
		if (!EC_POINT_oct2point(ret->group, ret->pub_key,
			M_ASN1_STRING_data(priv_key->publicKey),
			M_ASN1_STRING_length(priv_key->publicKey), NULL))
			{
			ECDSAerr(ECDSA_F_D2I_ECDSAPRIVATEKEY, ERR_R_EC_LIB);
			goto err;
			}
		}

	ok = 1;
err:
	if (!ok)
		{
		if (ret)
			ECDSA_free(ret);
		ret = NULL;
		}

	if (priv_key)
		EC_PRIVATEKEY_free(priv_key);

	return(ret);
	}

int	i2d_ECDSAPrivateKey(ECDSA *a, unsigned char **out)
	{
	int             ret=0, ok=0;
	unsigned char   *buffer=NULL;
	size_t          buf_len=0, tmp_len;
	EC_PRIVATEKEY   *priv_key=NULL;

	if (a == NULL || a->group == NULL || a->priv_key == NULL)
		{
		ECDSAerr(ECDSA_F_I2D_ECDSAPRIVATEKEY,
                         ERR_R_PASSED_NULL_PARAMETER);
		goto err;
		}

	if ((priv_key = EC_PRIVATEKEY_new()) == NULL)
		{
		ECDSAerr(ECDSA_F_I2D_ECDSAPRIVATEKEY,
                         ERR_R_MALLOC_FAILURE);
		goto err;
		}

	priv_key->version = a->version;

	buf_len = (size_t)BN_num_bytes(a->priv_key);
	buffer = OPENSSL_malloc(buf_len);
	if (buffer == NULL)
		{
		ECDSAerr(ECDSA_F_I2D_ECDSAPRIVATEKEY,
                         ERR_R_MALLOC_FAILURE);
		goto err;
		}
	
	if (!BN_bn2bin(a->priv_key, buffer))
		{
		ECDSAerr(ECDSA_F_I2D_ECDSAPRIVATEKEY, ERR_R_BN_LIB);
		goto err;
		}

	if (!M_ASN1_OCTET_STRING_set(priv_key->privateKey, buffer, buf_len))
		{
		ECDSAerr(ECDSA_F_I2D_ECDSAPRIVATEKEY, ERR_R_ASN1_LIB);
		goto err;
		}	

	if (!(ECDSA_get_enc_flag(a) & ECDSA_PKEY_NO_PARAMETERS))
		{
		if ((priv_key->parameters = EC_ASN1_group2pkparameters(
			a->group, priv_key->parameters)) == NULL)
			{
			ECDSAerr(ECDSA_F_I2D_ECDSAPRIVATEKEY, ERR_R_EC_LIB);
			goto err;
			}
		}

	if (!(ECDSA_get_enc_flag(a) & ECDSA_PKEY_NO_PUBKEY))
		{
		priv_key->publicKey = M_ASN1_BIT_STRING_new();
		if (priv_key->publicKey == NULL)
			{
			ECDSAerr(ECDSA_F_I2D_ECDSAPRIVATEKEY,
				ERR_R_MALLOC_FAILURE);
			goto err;
			}

		tmp_len = EC_POINT_point2oct(a->group, a->pub_key, 
                           ECDSA_get_conversion_form(a), NULL, 0, NULL);

		if (tmp_len > buf_len)
			buffer = OPENSSL_realloc(buffer, tmp_len);
		if (buffer == NULL)
			{
			ECDSAerr(ECDSA_F_I2D_ECDSAPRIVATEKEY,
				ERR_R_MALLOC_FAILURE);
			goto err;
			}

		buf_len = tmp_len;

		if (!EC_POINT_point2oct(a->group, a->pub_key, 
			ECDSA_get_conversion_form(a), buffer, buf_len, NULL))
			{
			ECDSAerr(ECDSA_F_I2D_ECDSAPRIVATEKEY, ERR_R_EC_LIB);
			goto err;
			}

		if (!M_ASN1_BIT_STRING_set(priv_key->publicKey, buffer, 
				buf_len))
			{
			ECDSAerr(ECDSA_F_I2D_ECDSAPRIVATEKEY, ERR_R_ASN1_LIB);
			goto err;
			}
		}

	if ((ret = i2d_EC_PRIVATEKEY(priv_key, out)) == 0)
		{
		ECDSAerr(ECDSA_F_I2D_ECDSAPRIVATEKEY, ERR_R_EC_LIB);
		goto err;
		}
	ok=1;
err:
	if (buffer)
		OPENSSL_free(buffer);
	if (priv_key)
		EC_PRIVATEKEY_free(priv_key);
	return(ok?ret:0);
	}


ECDSA 	*ECDSAPublicKey_set_octet_string(ECDSA **a, const unsigned char **in, long len)
{
	ECDSA *ret=NULL;

	if (a == NULL || (*a) == NULL || (*a)->group == NULL)
	{
		/* sorry, but a EC_GROUP-structur is necessary
                 * to set the public key */
		ECDSAerr(ECDSA_F_D2I_ECDSAPRIVATEKEY, ECDSA_R_MISSING_PARAMETERS);
		return 0;
	}
	ret = *a;
	if (ret->pub_key == NULL && (ret->pub_key = EC_POINT_new(ret->group)) == NULL)
	{
		ECDSAerr(ECDSA_F_D2I_ECDSAPRIVATEKEY, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	if (!EC_POINT_oct2point(ret->group, ret->pub_key, *in, len, NULL))
	{
		ECDSAerr(ECDSA_F_D2I_ECDSAPRIVATEKEY, ERR_R_EC_LIB);
		return 0;
	}
	ECDSA_set_conversion_form(ret, (point_conversion_form_t)(*in[0] & ~0x01));
	return ret;
}

int 	ECDSAPublicKey_get_octet_string(ECDSA *a, unsigned char **out)
{
        size_t  buf_len=0;

        if (a == NULL) 
	{
		ECDSAerr(ECDSA_F_I2D_ECDSAPUBLICKEY, ECDSA_R_MISSING_PARAMETERS);
		return 0;
	}
        buf_len = EC_POINT_point2oct(a->group, a->pub_key, 
                              ECDSA_get_conversion_form(a), NULL, 0, NULL);
	if (out == NULL || buf_len == 0)
	/* out == NULL => just return the length of the octet string */
		return buf_len;
	if (*out == NULL)
		if ((*out = OPENSSL_malloc(buf_len)) == NULL)
		{
			ECDSAerr(ECDSA_F_I2D_ECDSAPUBLICKEY, ERR_R_MALLOC_FAILURE);
			return 0;
		}
        if (!EC_POINT_point2oct(a->group, a->pub_key, ECDSA_get_conversion_form(a),
				*out, buf_len, NULL))
	{
		ECDSAerr(ECDSA_F_I2D_ECDSAPUBLICKEY, ERR_R_EC_LIB);
		OPENSSL_free(*out);
		*out = NULL;
		return 0;
	}
	return buf_len;
}

/* unused */
/* crypto/ec/ecp_mont2.c */
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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

#define NDEBUG

#include <openssl/err.h>

#include "ec_lcl.h"

#include "../bn/bn_mont2.c"

int ec_GFp_mont2_group_init(EC_GROUP *);
int ec_GFp_mont2_group_set_curve_GFp(EC_GROUP *, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
void ec_GFp_mont2_group_finish(EC_GROUP *);
void ec_GFp_mont2_group_clear_finish(EC_GROUP *);
/* int ec_GFp_mont2_group_copy(EC_GROUP *, const EC_GROUP *); */
int ec_GFp_mont2_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *);
int ec_GFp_mont2_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
int ec_GFp_mont2_field_encode(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
int ec_GFp_mont2_field_decode(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
int ec_GFp_mont2_field_set_to_one(const EC_GROUP *, BIGNUM *r, BN_CTX *);

const EC_METHOD *EC_GFp_mont2_method(void)
	{
	static const EC_METHOD ret = {
		ec_GFp_mont2_group_init,
		ec_GFp_mont2_group_finish,
		ec_GFp_mont2_group_clear_finish,
		0 /* ec_GFp_mont2_group_copy */,
		ec_GFp_mont2_group_set_curve_GFp,
		ec_GFp_simple_group_get_curve_GFp,
		ec_GFp_simple_group_set_generator,
		ec_GFp_simple_group_get0_generator,
		ec_GFp_simple_group_get_order,
		ec_GFp_simple_group_get_cofactor,
		ec_GFp_simple_point_init,
		ec_GFp_simple_point_finish,
		ec_GFp_simple_point_clear_finish,
		ec_GFp_simple_point_copy,
		ec_GFp_simple_point_set_to_infinity,
		ec_GFp_simple_set_Jprojective_coordinates_GFp,
		ec_GFp_simple_get_Jprojective_coordinates_GFp,
		ec_GFp_simple_point_set_affine_coordinates_GFp,
		ec_GFp_simple_point_get_affine_coordinates_GFp,
		ec_GFp_simple_set_compressed_coordinates_GFp,
		ec_GFp_simple_point2oct,
		ec_GFp_simple_oct2point,
		ec_GFp_simple_add,
		ec_GFp_simple_dbl,
		ec_GFp_simple_invert,
		ec_GFp_simple_is_at_infinity,
		ec_GFp_simple_is_on_curve,
		ec_GFp_simple_cmp,
		ec_GFp_simple_make_affine,
		ec_GFp_simple_points_make_affine,
		ec_GFp_mont2_field_mul,
		ec_GFp_mont2_field_sqr,
		ec_GFp_mont2_field_encode,
		ec_GFp_mont2_field_decode,
		ec_GFp_mont2_field_set_to_one };

	return &ret;
	}


int ec_GFp_mont2_group_init(EC_GROUP *group)
	{
	int ok;

	ok = ec_GFp_simple_group_init(group);
	group->field_data1 = NULL;
	group->field_data2 = NULL;
	return ok;
	}


int ec_GFp_mont2_group_set_curve_GFp(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	BN_CTX *new_ctx = NULL;
	BN_MONTGOMERY *mont = NULL;
	BIGNUM *one = NULL;
	int ret = 0;

	if (group->field_data1 != NULL)
		{
		BN_mont_clear_free(group->field_data1);
		group->field_data1 = NULL;
		}
	if (group->field_data2 != NULL)
		{
		BN_free(group->field_data2);
		group->field_data2 = NULL;
		}
	
	if (ctx == NULL)
		{
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			return 0;
		}

	mont = BN_mont_new();
	if (mont == NULL) goto err;
	if (!BN_mont_set(p, mont, ctx))
		{
		ECerr(EC_F_GFP_MONT2_GROUP_SET_CURVE_GFP, ERR_R_BN_LIB);
		goto err;
		}
	one = BN_new();
	if (one == NULL) goto err;
	if (!BN_one(one)) goto err;
	if (!BN_to_mont(one, mont, ctx)) goto err;

	group->field_data1 = mont;
	mont = NULL;
	group->field_data2 = one;
	one = NULL;

	ret = ec_GFp_simple_group_set_curve_GFp(group, p, a, b, ctx);

	if (!ret)
		{
		BN_mont_clear_free(group->field_data1);
		group->field_data1 = NULL;
		BN_free(group->field_data2);
		group->field_data2 = NULL;
		}

 err:
	if (new_ctx != NULL)
		BN_CTX_free(new_ctx);
	if (mont != NULL)
		BN_mont_clear_free(mont);
	return ret;
	}


void ec_GFp_mont2_group_finish(EC_GROUP *group)
	{
	if (group->field_data1 != NULL)
		{
		BN_mont_clear_free(group->field_data1);
		group->field_data1 = NULL;
		}
	if (group->field_data2 != NULL)
		{
		BN_free(group->field_data2);
		group->field_data2 = NULL;
		}
	ec_GFp_simple_group_finish(group);
	}


void ec_GFp_mont2_group_clear_finish(EC_GROUP *group)
	{
	if (group->field_data1 != NULL)
		{
		BN_mont_clear_free(group->field_data1);
		group->field_data1 = NULL;
		}
	if (group->field_data2 != NULL)
		{
		BN_clear_free(group->field_data2);
		group->field_data2 = NULL;
		}
	ec_GFp_simple_group_clear_finish(group);
	}


int ec_GFp_mont2_field_mul(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
	if (group->field_data1 == NULL)
		{
		ECerr(EC_F_EC_GFP_MONT2_FIELD_MUL, EC_R_NOT_INITIALIZED);
		return 0;
		}

	return BN_mont_mod_mul(r, a, b, group->field_data1, ctx);
	}


int ec_GFp_mont2_field_sqr(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, BN_CTX *ctx)
	{
	if (group->field_data1 == NULL)
		{
		ECerr(EC_F_EC_GFP_MONT2_FIELD_SQR, EC_R_NOT_INITIALIZED);
		return 0;
		}

	return BN_mont_mod_mul(r, a, a, group->field_data1, ctx);
	}


int ec_GFp_mont2_field_encode(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, BN_CTX *ctx)
	{
	if (group->field_data1 == NULL)
		{
		ECerr(EC_F_EC_GFP_MONT2_FIELD_ENCODE, EC_R_NOT_INITIALIZED);
		return 0;
		}

	if (!BN_copy(r, a)) return 0;
	return BN_to_mont(r, (BN_MONTGOMERY *)group->field_data1, ctx);
	}


int ec_GFp_mont2_field_decode(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a, BN_CTX *ctx)
	{
	if (group->field_data1 == NULL)
		{
		ECerr(EC_F_EC_GFP_MONT2_FIELD_DECODE, EC_R_NOT_INITIALIZED);
		return 0;
		}

	if (!BN_copy(r, a)) return 0;
	return BN_mont_red(r, (BN_MONTGOMERY *)group->field_data1);
	}


int ec_GFp_mont2_field_set_to_one(const EC_GROUP *group, BIGNUM *r, BN_CTX *ctx)
	{
	if (group->field_data2 == NULL)
		{
		ECerr(EC_F_EC_GFP_MONT2_FIELD_DECODE, EC_R_NOT_INITIALIZED);
		return 0;
		}

	if (!BN_copy(r, group->field_data2)) return 0;
	return 1;
	}

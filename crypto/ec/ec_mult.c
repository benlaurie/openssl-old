/* crypto/ec/ec_mult.c */
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

#include <openssl/err.h>

#include "ec_lcl.h"


/* TODO: width-m NAFs */

/* TODO: optional Lim-Lee precomputation for the generator */


/* this is just BN_window_bits_for_exponent_size from bn_lcl.h for now;
 * the table should be updated for EC */ /* TODO */
#define EC_window_bits_for_scalar_size(b) \
		((b) > 671 ? 6 : \
		 (b) > 239 ? 5 : \
		 (b) >  79 ? 4 : \
	 	 (b) >  23 ? 3 : 1)

/* Compute
 *      \sum scalar[i]*points[i]
 * where
 *      scalar*generator
 * is included in the addition if scalar != NULL
 */
int EC_POINTs_mul(const EC_GROUP *group, EC_POINT *r, BIGNUM *scalar,
	size_t num, EC_POINT *points[], BIGNUM *scalars[], BN_CTX *ctx)
	{
	BN_CTX *new_ctx = NULL;
	EC_POINT *generator = NULL;
	EC_POINT *tmp = NULL;
	size_t totalnum;
	size_t i, j;
	int k, t;
	int r_is_at_infinity = 1;
	size_t max_bits = 0;
	size_t *wsize = NULL; /* individual window sizes */
	unsigned long *wbits = NULL; /* individual window contents */
	int *wpos = NULL; /* position of bottom bit of current individual windows
	                   * (wpos[i] is valid if wbits[i] != 0) */
	size_t num_val;
	EC_POINT **val = NULL; /* precomputation */
	EC_POINT **v;
	EC_POINT ***val_sub = NULL; /* pointers to sub-arrays of 'val' */
	int ret = 0;
	
	if (scalar != NULL)
		{
		generator = EC_GROUP_get0_generator(group);
		if (generator == NULL)
			{
			ECerr(EC_F_EC_POINTS_MUL, EC_R_NO_GENERATOR_SET);
			return 0;
			}
		}
	
	for (i = 0; i < num; i++)
		{
		if (group->meth != points[i]->meth)
			{
			ECerr(EC_F_EC_POINTS_MUL, EC_R_INCOMPATIBLE_OBJECTS);
			return 0;
			}
		}

	totalnum = num + (scalar != NULL);

	wsize = OPENSSL_malloc(totalnum * sizeof wsize[0]);
	wbits = OPENSSL_malloc(totalnum * sizeof wbits[0]);
	wpos = OPENSSL_malloc(totalnum * sizeof wpos[0]);
	if (wsize == NULL || wbits == NULL || wpos == NULL) goto err;

	/* num_val := total number of points to precompute */
	num_val = 0;
	for (i = 0; i < totalnum; i++)
		{
		size_t bits;

		bits = i < num ? BN_num_bits(scalars[i]) : BN_num_bits(scalar);
		wsize[i] = EC_window_bits_for_scalar_size(bits);
		num_val += 1 << (wsize[i] - 1);
		if (bits > max_bits)
			max_bits = bits;
		wbits[i] = 0;
		wpos[i] = 0;
		}

	/* all precomputed points go into a single array 'val',
	 * 'val_sub[i]' is a pointer to the subarray for the i-th point */
	val = OPENSSL_malloc((num_val + 1) * sizeof val[0]);
	if (val == NULL) goto err;
	val[num_val] = NULL; /* pivot element */

	val_sub = OPENSSL_malloc(totalnum * sizeof val_sub[0]);
	if (val_sub == NULL) goto err;

	/* allocate points for precomputation */
	v = val;
	for (i = 0; i < totalnum; i++)
		{
		val_sub[i] = v;
		for (j = 0; j < (1 << (wsize[i] - 1)); j++)
			{
			*v = EC_POINT_new(group);
			if (*v == NULL) goto err;
			v++;
			}
		}
	if (!(v == val + num_val))
		{
		ECerr(EC_F_EC_POINTS_MUL, ERR_R_INTERNAL_ERROR);
		goto err;
		}

	if (ctx == NULL)
		{
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			goto err;
		}
	
	tmp = EC_POINT_new(group);
	if (tmp == NULL) goto err;

	/* prepare precomputed values:
	 *    val_sub[i][0] :=     points[i]
	 *    val_sub[i][1] := 3 * points[i]
	 *    val_sub[i][2] := 5 * points[i]
	 *    ...
	 */
	for (i = 0; i < totalnum; i++)
		{
		if (i < num)
			{
			if (!EC_POINT_copy(val_sub[i][0], points[i])) goto err;
			}
		else
			{
			if (!EC_POINT_copy(val_sub[i][0], generator)) goto err;
			}

		if (wsize[i] > 1)
			{
			if (!EC_POINT_dbl(group, tmp, val_sub[i][0], ctx)) goto err;
			for (j = 1; j < (1 << (wsize[i] - 1)); j++)
				{
				if (!EC_POINT_add(group, val_sub[i][j], val_sub[i][j - 1], tmp, ctx)) goto err;
				}
			}
		}

#if 1 /* optional, maybe we should only do this if total_num > 1 */
	if (!EC_POINTs_make_affine(group, num_val, val, ctx)) goto err;
#endif

	r_is_at_infinity = 1;

	for (k = max_bits - 1; k >= 0; k--)
		{
		if (!r_is_at_infinity)
			{
			if (!EC_POINT_dbl(group, r, r, ctx)) goto err;
			}
		
		for (i = 0; i < totalnum; i++)
			{
			if (wbits[i] == 0)
				{
				BIGNUM *s;

				s = i < num ? scalars[i] : scalar;

				if (BN_is_bit_set(s, k))
					{
					/* look at bits  k - wsize[i] + 1 .. k  for this window */
					t = k - wsize[i] + 1;
					while (!BN_is_bit_set(s, t)) /* BN_is_bit_set is false for t < 0 */
						t++;
					wpos[i] = t;
					wbits[i] = 1;
					for (t = k - 1; t >= wpos[i]; t--)
						{
						wbits[i] <<= 1;
						if (BN_is_bit_set(s, t))
							wbits[i]++;
						}
					/* now wbits[i] is the odd bit pattern at bits wpos[i] .. k */
					}
				}
			
			if ((wbits[i] != 0) && (wpos[i] == k))
				{
				if (r_is_at_infinity)
					{
					if (!EC_POINT_copy(r, val_sub[i][wbits[i] >> 1])) goto err;
					r_is_at_infinity = 0;
					}
				else
					{
					if (!EC_POINT_add(group, r, r, val_sub[i][wbits[i] >> 1], ctx)) goto err;
					}
				wbits[i] = 0;
				}
			}
		}

	if (r_is_at_infinity)
		if (!EC_POINT_set_to_infinity(group, r)) goto err;
	
	ret = 1;

 err:
	if (new_ctx != NULL)
		BN_CTX_free(new_ctx);
	if (tmp != NULL)
		EC_POINT_free(tmp);
	if (wsize != NULL)
		OPENSSL_free(wsize);
	if (wbits != NULL)
		OPENSSL_free(wbits);
	if (wpos != NULL)
		OPENSSL_free(wpos);
	if (val != NULL)
		{
		for (v = val; *v != NULL; v++)
			EC_POINT_clear_free(*v);

		OPENSSL_free(val);
		}
	if (val_sub != NULL)
		{
		OPENSSL_free(val_sub);
		}
	return ret;
	}

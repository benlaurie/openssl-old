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


#define EC_window_bits_for_scalar_size(b) \
		((b) >= 2000 ? 6 : \
		 (b) >=  800 ? 5 : \
		 (b) >=  300 ? 4 : \
		 (b) >=   70 ? 3 : \
		 (b) >=   20 ? 2 : \
		  1)
/* For window size 'w' (w >= 2), we compute the odd multiples
 *      1*P .. (2^w-1)*P.
 * This accounts for  2^(w-1)  point additions (neglecting constants),
 * each of which requires 16 field multiplications (4 squarings
 * and 12 general multiplications) in the case of curves defined
 * over GF(p), which are the only curves we have so far.
 *
 * Converting these precomputed points into affine form takes
 * three field multiplications for inverting Z and one squaring
 * and three multiplications for adjusting X and Y, i.e.
 * 7 multiplications in total (1 squaring and 6 general multiplications),
 * again except for constants.
 *
 * The average number of windows for a 'b' bit scalar is roughly
 *          b/(w+1).
 * Each of these windows (except possibly for the first one, but
 * we are ignoring constants anyway) requires one point addition.
 * As the precomputed table stores points in affine form, these
 * additions take only 11 field multiplications each (3 squarings
 * and 8 general multiplications).
 *
 * So the total workload, except for constants, is
 *
 *        2^(w-1)*[5 squarings + 18 multiplications]
 *      + (b/(w+1))*[3 squarings + 8 multiplications]
 *
 * If we assume that 10 squarings are as costly as 9 multiplications,
 * our task is to find the 'w' that, given 'b', minimizes
 *
 *        2^(w-1)*(5*9 + 18*10) + (b/(w+1))*(3*9 + 8*10)
 *      = 2^(w-1)*225 +           (b/(w+1))*107.
 *
 * Thus optimal window sizes should be roughly as follows:
 *
 *    w >= 6  if         b >= 1414
 *     w = 5  if 1413 >= b >=  505
 *     w = 4  if  504 >= b >=  169
 *     w = 3  if  168 >= b >=   51
 *     w = 2  if   50 >= b >=   13
 *     w = 1  if   12 >= b
 *
 * If we assume instead that squarings are exactly as costly as
 * multiplications, we have to minimize
 *      2^(w-1)*23 + (b/(w+1))*11.
 *
 * This gives us the following (nearly unchanged) table of optimal
 * windows sizes:
 *
 *    w >= 6  if         b >= 1406
 *     w = 5  if 1405 >= b >=  502
 *     w = 4  if  501 >= b >=  168
 *     w = 3  if  167 >= b >=   51
 *     w = 2  if   50 >= b >=   13
 *     w = 1  if   12 >= b
 *
 * Note that neither table tries to take into account memory usage
 * (allocation overhead, code locality etc.).  Actual timings with
 * NIST curves P-192, P-224, and P-256 with scalars of 192, 224,
 * and 256 bits, respectively, show that  w = 3  (instead of 4) is
 * preferrable; timings with NIST curve P-384 and 384-bit scalars
 * confirm that  w = 4  is optimal for this case; and timings with
 * NIST curve P-521 and 521-bit scalars show that  w = 4  (instead
 * of 5) is preferrable.  So we generously round up all the
 * boundaries and use the following table:
 *
 *    w >= 6  if         b >= 2000
 *     w = 5  if 1999 >= b >=  800
 *     w = 4  if  799 >= b >=  300
 *     w = 3  if  299 >= b >=   70
 *     w = 2  if   69 >= b >=   20
 *     w = 1  if   19 >= b
 */



/* Compute
 *      \sum scalars[i]*points[i]
 * where
 *      scalar*generator
 * is included in the addition if scalar != NULL
 */
int EC_POINTs_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
	size_t num, const EC_POINT *points[], const BIGNUM *scalars[], BN_CTX *ctx)
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
			ECerr(EC_F_EC_POINTS_MUL, EC_R_UNDEFINED_GENERATOR);
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
		num_val += 1u << (wsize[i] - 1);
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
		for (j = 0; j < (1u << (wsize[i] - 1)); j++)
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
			if (scalars[i]->neg)
				{
				if (!EC_POINT_invert(group, val_sub[i][0], ctx)) goto err;
				}
			}
		else
			{
			if (!EC_POINT_copy(val_sub[i][0], generator)) goto err;
			if (scalar->neg)
				{
				if (!EC_POINT_invert(group, val_sub[i][0], ctx)) goto err;
				}
			}

		if (wsize[i] > 1)
			{
			if (!EC_POINT_dbl(group, tmp, val_sub[i][0], ctx)) goto err;
			for (j = 1; j < (1u << (wsize[i] - 1)); j++)
				{
				if (!EC_POINT_add(group, val_sub[i][j], val_sub[i][j - 1], tmp, ctx)) goto err;
				}
			}
		}

#if 1 /* optional; EC_window_bits_for_scalar_size assumes we do this step */
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
				const BIGNUM *s;

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


int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *g_scalar, const EC_POINT *point, const BIGNUM *p_scalar, BN_CTX *ctx)
	{
	const EC_POINT *points[1];
	const BIGNUM *scalars[1];

	points[0] = point;
	scalars[0] = p_scalar;

	return EC_POINTs_mul(group, r, g_scalar, (point != NULL && p_scalar != NULL), points, scalars, ctx);
	}


int EC_GROUP_precompute_mult(EC_GROUP *group, BN_CTX *ctx)
	{
	const EC_POINT *generator;
	BN_CTX *new_ctx = NULL;
	BIGNUM *order;
	int ret = 0;

	generator = EC_GROUP_get0_generator(group);
	if (generator == NULL)
		{
		ECerr(EC_F_EC_GROUP_PRECOMPUTE_MULT, EC_R_UNDEFINED_GENERATOR);
		return 0;
		}

	if (ctx == NULL)
		{
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			return 0;
		}
	
	BN_CTX_start(ctx);
	order = BN_CTX_get(ctx);
	if (order == NULL) goto err;
	
	if (!EC_GROUP_get_order(group, order, ctx)) return 0;
	if (BN_is_zero(order))
		{
		ECerr(EC_F_EC_GROUP_PRECOMPUTE_MULT, EC_R_UNKNOWN_ORDER);
		goto err;
		}

	/* TODO */

	ret = 1;
	
 err:
	BN_CTX_end(ctx);
	if (new_ctx != NULL)
		BN_CTX_free(new_ctx);
	return ret;
	}

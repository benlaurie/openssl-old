/* crypto/bn/bn_err.c */
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
 *    openssl-core@OpenSSL.org.
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

/* NOTE: this file was auto generated by the mkerr.pl script: any changes
 * made to it will be overwritten when the script next updates this file,
 * only reason strings will be preserved.
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/bn.h>

/* BEGIN ERROR CODES */
#ifndef NO_ERR
static ERR_STRING_DATA BN_str_functs[]=
	{
{ERR_PACK(0,BN_F_BN_BLINDING_CONVERT,0),	"BN_BLINDING_convert"},
{ERR_PACK(0,BN_F_BN_BLINDING_INVERT,0),	"BN_BLINDING_invert"},
{ERR_PACK(0,BN_F_BN_BLINDING_NEW,0),	"BN_BLINDING_new"},
{ERR_PACK(0,BN_F_BN_BLINDING_UPDATE,0),	"BN_BLINDING_update"},
{ERR_PACK(0,BN_F_BN_BN2DEC,0),	"BN_bn2dec"},
{ERR_PACK(0,BN_F_BN_BN2HEX,0),	"BN_bn2hex"},
{ERR_PACK(0,BN_F_BN_CTX_GET,0),	"BN_CTX_get"},
{ERR_PACK(0,BN_F_BN_CTX_NEW,0),	"BN_CTX_new"},
{ERR_PACK(0,BN_F_BN_DIV,0),	"BN_div"},
{ERR_PACK(0,BN_F_BN_EXPAND2,0),	"bn_expand2"},
{ERR_PACK(0,BN_F_BN_EXPAND_INTERNAL,0),	"BN_EXPAND_INTERNAL"},
{ERR_PACK(0,BN_F_BN_MOD_EXP2_MONT,0),	"BN_mod_exp2_mont"},
{ERR_PACK(0,BN_F_BN_MOD_EXP_MONT,0),	"BN_mod_exp_mont"},
{ERR_PACK(0,BN_F_BN_MOD_EXP_MONT_WORD,0),	"BN_mod_exp_mont_word"},
{ERR_PACK(0,BN_F_BN_MOD_INVERSE,0),	"BN_mod_inverse"},
{ERR_PACK(0,BN_F_BN_MOD_LSHIFT_QUICK,0),	"BN_mod_lshift_quick"},
{ERR_PACK(0,BN_F_BN_MOD_MUL_RECIPROCAL,0),	"BN_mod_mul_reciprocal"},
{ERR_PACK(0,BN_F_BN_MOD_SQRT,0),	"BN_mod_sqrt"},
{ERR_PACK(0,BN_F_BN_MPI2BN,0),	"BN_mpi2bn"},
{ERR_PACK(0,BN_F_BN_NEW,0),	"BN_new"},
{ERR_PACK(0,BN_F_BN_RAND,0),	"BN_rand"},
{ERR_PACK(0,BN_F_BN_USUB,0),	"BN_usub"},
{0,NULL}
	};

static ERR_STRING_DATA BN_str_reasons[]=
	{
{BN_R_ARG2_LT_ARG3                       ,"arg2 lt arg3"},
{BN_R_BAD_RECIPROCAL                     ,"bad reciprocal"},
{BN_R_CALLED_WITH_EVEN_MODULUS           ,"called with even modulus"},
{BN_R_DIV_BY_ZERO                        ,"div by zero"},
{BN_R_ENCODING_ERROR                     ,"encoding error"},
{BN_R_EXPAND_ON_STATIC_BIGNUM_DATA       ,"expand on static bignum data"},
{BN_R_INPUT_NOT_REDUCED                  ,"input not reduced"},
{BN_R_INVALID_LENGTH                     ,"invalid length"},
{BN_R_NOT_A_SQUARE                       ,"not a square"},
{BN_R_NOT_INITIALIZED                    ,"not initialized"},
{BN_R_NO_INVERSE                         ,"no inverse"},
{BN_R_P_IS_NOT_PRIME                     ,"p is not prime"},
{BN_R_TOO_MANY_ITERATIONS                ,"too many iterations"},
{BN_R_TOO_MANY_TEMPORARY_VARIABLES       ,"too many temporary variables"},
{0,NULL}
	};

#endif

void ERR_load_BN_strings(void)
	{
	static int init=1;

	if (init)
		{
		init=0;
#ifndef NO_ERR
		ERR_load_strings(ERR_LIB_BN,BN_str_functs);
		ERR_load_strings(ERR_LIB_BN,BN_str_reasons);
#endif

		}
	}

/* lib/x509v3/x509v3_err.c */
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
#include "err.h"
#include "x509v3.h"

/* BEGIN ERROR CODES */
#ifndef NO_ERR
static ERR_STRING_DATA X509V3_str_functs[]=
	{
{ERR_PACK(0,X509V3_F_S2I_ASN1_IA5STRING,0),	"S2I_ASN1_IA5STRING"},
{ERR_PACK(0,X509V3_F_V2I_ASN1_BIT_STRING,0),	"V2I_ASN1_BIT_STRING"},
{ERR_PACK(0,X509V3_F_V2I_BASIC_CONSTRAINTS,0),	"V2I_BASIC_CONSTRAINTS"},
{ERR_PACK(0,X509V3_F_V2I_EXT_KU,0),	"V2I_EXT_KU"},
{ERR_PACK(0,X509V3_F_X509V3_ADD_EXT,0),	"X509V3_ADD_EXT"},
{ERR_PACK(0,X509V3_F_X509V3_ADD_VALUE,0),	"X509V3_add_value"},
{ERR_PACK(0,X509V3_F_X509V3_EXT_ADD_ALIAS,0),	"X509V3_EXT_add_alias"},
{ERR_PACK(0,X509V3_F_X509V3_EXT_CONF,0),	"X509V3_EXT_conf"},
{ERR_PACK(0,X509V3_F_X509V3_GET_VALUE_INT,0),	"X509V3_get_value_int"},
{ERR_PACK(0,X509V3_F_X509V3_PARSE_LIST,0),	"X509V3_parse_list"},
{ERR_PACK(0,X509V3_F_X509V3_VALUE_GET_BOOL,0),	"X509V3_VALUE_GET_BOOL"},
{0,NULL},
	};

static ERR_STRING_DATA X509V3_str_reasons[]=
	{
{X509V3_R_BN_DEC2BN_ERROR                ,"bn dec2bn error"},
{X509V3_R_BN_TO_ASN1_INTEGER_ERROR       ,"bn to asn1 integer error"},
{X509V3_R_EXTENSION_NOT_FOUND            ,"extension not found"},
{X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED,"extension setting not supported"},
{X509V3_R_INVALID_BOOLEAN_STRING         ,"invalid boolean string"},
{X509V3_R_INVALID_EXTENSION_STRING       ,"invalid extension string"},
{X509V3_R_INVALID_NAME                   ,"invalid name"},
{X509V3_R_INVALID_NULL_ARGUMENT          ,"invalid null argument"},
{X509V3_R_INVALID_NULL_NAME              ,"invalid null name"},
{X509V3_R_INVALID_NULL_VALUE             ,"invalid null value"},
{X509V3_R_INVALID_OBJECT_IDENTIFIER      ,"invalid object identifier"},
{X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT    ,"unknown bit string argument"},
{0,NULL},
	};

#endif

void ERR_load_X509V3_strings()
	{
	static int init=1;

	if (init)
		{
		init=0;
#ifndef NO_ERR
		ERR_load_strings(ERR_LIB_X509V3,X509V3_str_functs);
		ERR_load_strings(ERR_LIB_X509V3,X509V3_str_reasons);
#endif

		}
	}

/* crypto/ecdsa/ecs_err.c */
/* ====================================================================
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
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
#include <openssl/ecdsa.h>

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR
static ERR_STRING_DATA ECDSA_str_functs[]=
	{
{ERR_PACK(0,ECDSA_F_D2I_ECDSAPARAMETERS,0),	"d2i_ECDSAParameters"},
{ERR_PACK(0,ECDSA_F_D2I_ECDSAPRIVATEKEY,0),	"d2i_ECDSAPrivateKey"},
{ERR_PACK(0,ECDSA_F_ECDSAPARAMETERS_PRINT,0),	"ECDSAParameters_print"},
{ERR_PACK(0,ECDSA_F_ECDSAPARAMETERS_PRINT_FP,0),	"ECDSAParameters_print_fp"},
{ERR_PACK(0,ECDSA_F_ECDSA_DO_SIGN,0),	"ECDSA_do_sign"},
{ERR_PACK(0,ECDSA_F_ECDSA_DO_VERIFY,0),	"ECDSA_do_verify"},
{ERR_PACK(0,ECDSA_F_ECDSA_GENERATE_KEY,0),	"ECDSA_generate_key"},
{ERR_PACK(0,ECDSA_F_ECDSA_GET,0),	"ECDSA_GET"},
{ERR_PACK(0,ECDSA_F_ECDSA_GET_CURVE_NID,0),	"ECDSA_GET_CURVE_NID"},
{ERR_PACK(0,ECDSA_F_ECDSA_GET_ECDSA,0),	"ECDSA_GET_ECDSA"},
{ERR_PACK(0,ECDSA_F_ECDSA_GET_EC_PARAMETERS,0),	"ECDSA_get_EC_PARAMETERS"},
{ERR_PACK(0,ECDSA_F_ECDSA_GET_X9_62_CURVE,0),	"ECDSA_get_X9_62_CURVE"},
{ERR_PACK(0,ECDSA_F_ECDSA_GET_X9_62_EC_PARAMETERS,0),	"ECDSA_get_X9_62_EC_PARAMETERS"},
{ERR_PACK(0,ECDSA_F_ECDSA_GET_X9_62_FIELDID,0),	"ECDSA_get_X9_62_FIELDID"},
{ERR_PACK(0,ECDSA_F_ECDSA_NEW,0),	"ECDSA_NEW"},
{ERR_PACK(0,ECDSA_F_ECDSA_PRINT,0),	"ECDSA_print"},
{ERR_PACK(0,ECDSA_F_ECDSA_PRINT_FP,0),	"ECDSA_print_fp"},
{ERR_PACK(0,ECDSA_F_ECDSA_SET_GROUP_P,0),	"ECDSA_set_group_p"},
{ERR_PACK(0,ECDSA_F_ECDSA_SET_PRIME_GROUP,0),	"ECDSA_SET_PRIME_GROUP"},
{ERR_PACK(0,ECDSA_F_ECDSA_SIGN_SETUP,0),	"ECDSA_sign_setup"},
{ERR_PACK(0,ECDSA_F_I2D_ECDSAPARAMETERS,0),	"i2d_ECDSAParameters"},
{ERR_PACK(0,ECDSA_F_I2D_ECDSAPRIVATEKEY,0),	"i2d_ECDSAPrivateKey"},
{ERR_PACK(0,ECDSA_F_I2D_ECDSAPUBLICKEY,0),	"i2d_ECDSAPublicKey"},
{ERR_PACK(0,ECDSA_F_SIG_CB,0),	"SIG_CB"},
{0,NULL}
	};

static ERR_STRING_DATA ECDSA_str_reasons[]=
	{
{ECDSA_R_BAD_SIGNATURE                   ,"bad signature"},
{ECDSA_R_CAN_NOT_GET_GENERATOR           ,"can not get generator"},
{ECDSA_R_D2I_ECDSAPRIVATEKEY_MISSING_PRIVATE_KEY,"d2i ecdsaprivatekey missing private key"},
{ECDSA_R_D2I_ECDSA_PRIVATEKEY_FAILURE    ,"d2i ecdsa privatekey failure"},
{ECDSA_R_D2I_EC_PARAMETERS_FAILURE       ,"d2i ec parameters failure"},
{ECDSA_R_D2I_X9_62_EC_PARAMETERS_FAILURE ,"d2i x9 62 ec parameters failure"},
{ECDSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE     ,"data too large for key size"},
{ECDSA_R_ECDSAPRIVATEKEY_NEW_FAILURE     ,"ecdsaprivatekey new failure"},
{ECDSA_R_ECDSA_F_ECDSA_NEW               ,"ecdsa f ecdsa new"},
{ECDSA_R_ECDSA_GET_EC_PARAMETERS_FAILURE ,"ecdsa get ec parameters failure"},
{ECDSA_R_ECDSA_GET_FAILURE               ,"ecdsa get failure"},
{ECDSA_R_ECDSA_GET_X9_62_CURVE_FAILURE   ,"ecdsa get x9 62 curve failure"},
{ECDSA_R_ECDSA_GET_X9_62_EC_PARAMETERS_FAILURE,"ecdsa get x9 62 ec parameters failure"},
{ECDSA_R_ECDSA_GET_X9_62_FIELDID_FAILURE ,"ecdsa get x9 62 fieldid failure"},
{ECDSA_R_ECDSA_NEW_FAILURE               ,"ecdsa new failure"},
{ECDSA_R_ECDSA_R_D2I_EC_PARAMETERS_FAILURE,"ecdsa r d2i ec parameters failure"},
{ECDSA_R_ECDSA_R_D2I_X9_62_EC_PARAMETERS_FAILURE,"ecdsa r d2i x9 62 ec parameters failure"},
{ECDSA_R_ECPARAMETERS2ECDSA_FAILURE      ,"ecparameters2ecdsa failure"},
{ECDSA_R_EC_GROUP_NID2CURVE_FAILURE      ,"ec group nid2curve failure"},
{ECDSA_R_ERR_EC_LIB                      ,"err ec lib"},
{ECDSA_R_I2D_ECDSA_PRIVATEKEY            ,"i2d ecdsa privatekey"},
{ECDSA_R_I2D_ECDSA_PUBLICKEY             ,"i2d ecdsa publickey"},
{ECDSA_R_MISSING_PARAMETERS              ,"missing parameters"},
{ECDSA_R_NOT_SUPPORTED                   ,"not supported"},
{ECDSA_R_NO_CURVE_PARAMETER_A_SPECIFIED  ,"no curve parameter a specified"},
{ECDSA_R_NO_CURVE_PARAMETER_B_SPECIFIED  ,"no curve parameter b specified"},
{ECDSA_R_NO_CURVE_SPECIFIED              ,"no curve specified"},
{ECDSA_R_NO_FIELD_SPECIFIED              ,"no field specified"},
{ECDSA_R_PRIME_MISSING                   ,"prime missing"},
{ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED ,"random number generation failed"},
{ECDSA_R_SIGNATURE_MALLOC_FAILED         ,"signature malloc failed"},
{ECDSA_R_UNEXPECTED_ASN1_TYPE            ,"unexpected asn1 type"},
{ECDSA_R_UNEXPECTED_PARAMETER            ,"unexpected parameter"},
{ECDSA_R_UNEXPECTED_PARAMETER_LENGTH     ,"unexpected parameter length"},
{ECDSA_R_UNEXPECTED_VERSION_NUMER        ,"unexpected version numer"},
{ECDSA_R_UNKNOWN_PARAMETERS_TYPE         ,"unknown parameters type"},
{ECDSA_R_WRONG_FIELD_IDENTIFIER          ,"wrong field identifier"},
{ECDSA_R_X9_62_CURVE_NEW_FAILURE         ,"x9 62 curve new failure"},
{ECDSA_R_X9_62_EC_PARAMETERS_NEW_FAILURE ,"x9 62 ec parameters new failure"},
{0,NULL}
	};

#endif

void ERR_load_ECDSA_strings(void)
	{
	static int init=1;

	if (init)
		{
		init=0;
#ifndef OPENSSL_NO_ERR
		ERR_load_strings(ERR_LIB_ECDSA,ECDSA_str_functs);
		ERR_load_strings(ERR_LIB_ECDSA,ECDSA_str_reasons);
#endif

		}
	}

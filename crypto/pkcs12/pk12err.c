/* lib/pkcs12/pkcs12_err.c */
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
#include <openssl/err.h>
#include <openssl/pkcs12.h>

/* BEGIN ERROR CODES */
#ifndef NO_ERR
static ERR_STRING_DATA PKCS12_str_functs[]=
	{
{ERR_PACK(0,PKCS12_F_ADD_FRIENDLYNAME,0),	"ADD_FRIENDLYNAME"},
{ERR_PACK(0,PKCS12_F_ADD_FRIENDLYNAME_ASC,0),	"ADD_FRIENDLYNAME_ASC"},
{ERR_PACK(0,PKCS12_F_ADD_FRIENDLYNAME_UNI,0),	"ADD_FRIENDLYNAME_UNI"},
{ERR_PACK(0,PKCS12_F_PARSE_BAGS,0),	"PARSE_BAGS"},
{ERR_PACK(0,PKCS12_F_PKCS12_ADD_LOCALKEYID,0),	"PKCS12_add_localkeyid"},
{ERR_PACK(0,PKCS12_F_PKCS12_CREATE,0),	"PKCS12_create"},
{ERR_PACK(0,PKCS12_F_PKCS12_DECRYPT_D2I,0),	"PKCS12_decrypt_d2i"},
{ERR_PACK(0,PKCS12_F_PKCS12_GEN_MAC,0),	"PKCS12_gen_mac"},
{ERR_PACK(0,PKCS12_F_PKCS12_I2D_ENCRYPT,0),	"PKCS12_i2d_encrypt"},
{ERR_PACK(0,PKCS12_F_PKCS12_INIT,0),	"PKCS12_init"},
{ERR_PACK(0,PKCS12_F_PKCS12_KEY_GEN_ASC,0),	"PKCS12_key_gen_asc"},
{ERR_PACK(0,PKCS12_F_PKCS12_KEY_GEN_UNI,0),	"PKCS12_key_gen_uni"},
{ERR_PACK(0,PKCS12_F_PKCS12_MAKE_SAFEBAG,0),	"PKCS12_MAKE_SAFEBAG"},
{ERR_PACK(0,PKCS12_F_PKCS12_MAKE_SHKEYBAG,0),	"PKCS12_MAKE_SHKEYBAG"},
{ERR_PACK(0,PKCS12_F_PKCS12_PACK_P7DATA,0),	"PKCS12_pack_p7data"},
{ERR_PACK(0,PKCS12_F_PKCS12_PACK_P7ENCDATA,0),	"PKCS12_pack_p7encdata"},
{ERR_PACK(0,PKCS12_F_PKCS12_PACK_P7_DATA,0),	"PKCS12_PACK_P7_DATA"},
{ERR_PACK(0,PKCS12_F_PKCS12_PACK_SAFEBAG,0),	"PKCS12_pack_safebag"},
{ERR_PACK(0,PKCS12_F_PKCS12_PARSE,0),	"PKCS12_parse"},
{ERR_PACK(0,PKCS12_F_PKCS12_PBE_CRYPT,0),	"PKCS12_pbe_crypt"},
{ERR_PACK(0,PKCS12_F_PKCS12_PBE_KEYIVGEN,0),	"PKCS12_PBE_KEYIVGEN"},
{ERR_PACK(0,PKCS12_F_PKCS12_PKCS12_SET_MAC,0),	"PKCS12_PKCS12_SET_MAC"},
{ERR_PACK(0,PKCS12_F_PKCS12_SETUP_MAC,0),	"PKCS12_setup_mac"},
{ERR_PACK(0,PKCS12_F_PKCS12_SET_MAC,0),	"PKCS12_set_mac"},
{ERR_PACK(0,PKCS12_F_PKCS8_ADD_KEYUSAGE,0),	"PKCS8_add_keyusage"},
{ERR_PACK(0,PKCS12_F_PKCS8_ENCRYPT,0),	"PKCS8_encrypt"},
{ERR_PACK(0,PKCS12_F_VERIFY_MAC,0),	"VERIFY_MAC"},
{0,NULL},
	};

static ERR_STRING_DATA PKCS12_str_reasons[]=
	{
{PKCS12_R_CANT_PACK_STRUCTURE            ,"cant pack structure"},
{PKCS12_R_DECODE_ERROR                   ,"decode error"},
{PKCS12_R_ENCODE_ERROR                   ,"encode error"},
{PKCS12_R_ENCRYPT_ERROR                  ,"encrypt error"},
{PKCS12_R_INVALID_NULL_ARGUMENT          ,"invalid null argument"},
{PKCS12_R_INVALID_NULL_PKCS12_POINTER    ,"invalid null pkcs12 pointer"},
{PKCS12_R_IV_GEN_ERROR                   ,"iv gen error"},
{PKCS12_R_KEY_GEN_ERROR                  ,"key gen error"},
{PKCS12_R_MAC_ABSENT                     ,"mac absent"},
{PKCS12_R_MAC_GENERATION_ERROR           ,"mac generation error"},
{PKCS12_R_MAC_SETUP_ERROR                ,"mac setup error"},
{PKCS12_R_MAC_STRING_SET_ERROR           ,"mac string set error"},
{PKCS12_R_MAC_VERIFY_ERROR               ,"mac verify error"},
{PKCS12_R_MAC_VERIFY_FAILURE             ,"mac verify failure"},
{PKCS12_R_PARSE_ERROR                    ,"parse error"},
{PKCS12_R_PKCS12_ALGOR_CIPHERINIT_ERROR  ,"pkcs12 algor cipherinit error"},
{PKCS12_R_PKCS12_CIPHERFINAL_ERROR       ,"pkcs12 cipherfinal error"},
{PKCS12_R_PKCS12_PBE_CRYPT_ERROR         ,"pkcs12 pbe crypt error"},
{PKCS12_R_UNKNOWN_DIGEST_ALGORITHM       ,"unknown digest algorithm"},
{PKCS12_R_UNSUPPORTED_PKCS12_MODE        ,"unsupported pkcs12 mode"},
{0,NULL},
	};

#endif

void ERR_load_PKCS12_strings(void)
	{
	static int init=1;

	if (init)
		{
		init=0;
#ifndef NO_ERR
		ERR_load_strings(ERR_LIB_PKCS12,PKCS12_str_functs);
		ERR_load_strings(ERR_LIB_PKCS12,PKCS12_str_reasons);
#endif

		}
	}

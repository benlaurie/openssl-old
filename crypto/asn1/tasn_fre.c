/* tasn_fre.c */
/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
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


#include <stddef.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>

/* Free up an ASN1 structure */

void ASN1_item_free(ASN1_VALUE *val, const ASN1_ITEM *it)
{
	const ASN1_TEMPLATE *tt = NULL, *seqtt;
	const ASN1_EXTERN_FUNCS *ef;
	const ASN1_COMPAT_FUNCS *cf;
	int i;
	if(!val) return;

	switch(it->itype) {

		case ASN1_ITYPE_PRIMITIVE:
		ASN1_primitive_free(val, it->utype);
		break;

		case ASN1_ITYPE_MSTRING:
		ASN1_primitive_free(val, -1);
		break;

		case ASN1_ITYPE_CHOICE:
		i = asn1_get_choice_selector(val, it);
		if((i >= 0) && (i < it->tcount)) {
			ASN1_VALUE *chval;
			tt = it->templates + i;
			chval = asn1_get_field(val, tt);
			ASN1_template_free(chval, tt);
		} 
		OPENSSL_free(val);
		break;

		case ASN1_ITYPE_COMPAT:
		cf = it->funcs;
		if(cf && cf->asn1_free) cf->asn1_free(val);
		break;

		case ASN1_ITYPE_EXTERN:
		ef = it->funcs;
		if(ef && ef->asn1_ex_free) ef->asn1_ex_free(val, it);
		break;

		case ASN1_ITYPE_SEQUENCE:
		for(i = 0, tt = it->templates; i < it->tcount; tt++, i++) {
			ASN1_VALUE *seqval;
			seqtt = asn1_do_adb(val, tt);
			seqval = asn1_get_field(val, seqtt);
			ASN1_template_free(seqval, seqtt);
		}
		OPENSSL_free(val);
		break;
	}
}

void ASN1_template_free(ASN1_VALUE *val, const ASN1_TEMPLATE *tt)
{
	int i;
	if(tt->flags & ASN1_TFLG_SK_MASK) {
		STACK *sk = (STACK *)val;
		for(i = 0; i < sk_num(sk); i++) {
			ASN1_item_free((ASN1_VALUE *)sk_value(sk, i), tt->item);
		}
		sk_free(sk);
	} else ASN1_item_free(val, tt->item);
}

void ASN1_primitive_free(ASN1_VALUE *type, long utype)
{
	switch(utype) {
		case V_ASN1_OBJECT:
		ASN1_OBJECT_free((ASN1_OBJECT *)type);
		break;

		case V_ASN1_NULL:
		ASN1_NULL_free((ASN1_NULL *)type);
		break;

		case V_ASN1_ANY:
		ASN1_TYPE_free((ASN1_TYPE *)type);
		break;

		case V_ASN1_BOOLEAN:
		break;

		default:
		ASN1_STRING_free((ASN1_STRING*)type);
		break;
	}
}

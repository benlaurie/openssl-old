/* tasn_new.c */
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
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/asn1t.h>

static int asn1_item_ex_combine_new(ASN1_VALUE **pval, const ASN1_ITEM *it, int combine);

ASN1_VALUE *ASN1_item_new(const ASN1_ITEM *it)
{
	ASN1_VALUE *ret = NULL;
	if(ASN1_item_ex_new(&ret, it) > 0) return ret;
	return NULL;
}

/* Allocate an ASN1 structure */

int ASN1_item_ex_new(ASN1_VALUE **pval, const ASN1_ITEM *it)
{
	return asn1_item_ex_combine_new(pval, it, 0);
}

static int asn1_item_ex_combine_new(ASN1_VALUE **pval, const ASN1_ITEM *it, int combine)
{
	const ASN1_TEMPLATE *tt = NULL;
	const ASN1_COMPAT_FUNCS *cf;
	const ASN1_EXTERN_FUNCS *ef;
	const ASN1_AUX *aux = it->funcs;
	ASN1_aux_cb *asn1_cb;
	ASN1_VALUE **pseqval;
	int i;
	if(aux && aux->asn1_cb) asn1_cb = aux->asn1_cb;
	else asn1_cb = 0;

	if(!combine) *pval = NULL;

	switch(it->itype) {

		case ASN1_ITYPE_EXTERN:
		ef = it->funcs;
		if(ef && ef->asn1_ex_new) {
			if(!ef->asn1_ex_new(pval, it))
				goto memerr;
		}
		break;

		case ASN1_ITYPE_COMPAT:
		cf = it->funcs;
		if(cf && cf->asn1_new) {
			*pval = cf->asn1_new();
			if(!*pval) goto memerr;
		}
		break;

		case ASN1_ITYPE_PRIMITIVE:
		if(it->templates) {
			if(!ASN1_template_new(pval, it->templates))
				goto memerr;
		} else {
			if(!ASN1_primitive_new(pval, it->utype))
				goto memerr;
		}
		break;

		case ASN1_ITYPE_MSTRING:
		if(!ASN1_primitive_new(pval, -1))
				goto memerr;
		break;

		case ASN1_ITYPE_CHOICE:
		if(!combine) {
			*pval = OPENSSL_malloc(it->size);
			if(!*pval) goto memerr;
			memset(*pval, 0, it->size);
		}
		asn1_set_choice_selector(pval, -1, it);
		if(asn1_cb && !asn1_cb(ASN1_OP_NEW_POST, pval, it))
				goto auxerr;
		break;

		case ASN1_ITYPE_SEQUENCE:
		if(!combine) {
			*pval = OPENSSL_malloc(it->size);
			if(!*pval) goto memerr;
			memset(*pval, 0, it->size);
			asn1_do_lock(pval, 0, it);
		}
		if(asn1_cb && !asn1_cb(ASN1_OP_NEW_PRE, pval, it))
				goto auxerr;
		for(i = 0, tt = it->templates; i < it->tcount; tt++, i++) {
			pseqval = asn1_get_field_ptr(pval, tt);
			if(!ASN1_template_new(pseqval, tt)) goto memerr;
		}
		if(asn1_cb && !asn1_cb(ASN1_OP_NEW_POST, pval, it))
				goto auxerr;
		break;
	}
	return 1;

	memerr:
	ASN1err(ASN1_F_ASN1_ITEM_NEW, ERR_R_MALLOC_FAILURE);
	return 0;

	auxerr:
	ASN1err(ASN1_F_ASN1_ITEM_NEW, ASN1_R_AUX_ERROR);
	ASN1_item_free(*pval, it);
	return 0;
	
}

int ASN1_template_new(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
{
	const ASN1_ITEM *it = tt->item;
	/* Special BOOLEAN handling */
	if(asn1_template_is_bool(tt))
		return ASN1_item_ex_new(pval, it);
		
	/* If OPTIONAL or ANY DEFINED BY nothing to do */
	if(tt->flags & (ASN1_TFLG_OPTIONAL|ASN1_TFLG_ADB_MASK)) {
		/* Maybe free it first? */
		*pval = NULL;
		return 1;
	}
	/* If SET OF or SEQUENCE OF, its a STACK */
	if(tt->flags & ASN1_TFLG_SK_MASK) {
		*pval = (ASN1_VALUE *)sk_new_null();
		if(!*pval) {
			ASN1err(ASN1_F_ASN1_TEMPLATE_NEW, ERR_R_MALLOC_FAILURE);
			return 0;
		}
		return 1;
	}
	/* Otherwise pass it back to the item routine */
	return asn1_item_ex_combine_new(pval, it, tt->flags & ASN1_TFLG_COMBINE);
}

/* NB: could probably combine most of the real XXX_new() behaviour and junk all the old
 * functions.
 */

int ASN1_primitive_new(ASN1_VALUE **pval, long utype)
{
	ASN1_TYPE *typ;
	switch(utype) {
		case V_ASN1_OBJECT:
		*pval = (ASN1_VALUE *)OBJ_nid2obj(NID_undef);
		return 1;

		case V_ASN1_BOOLEAN:
		*(ASN1_BOOLEAN *)pval = -1;
		return 1;

		case V_ASN1_NULL:
		*pval = (ASN1_VALUE *)1;
		return 1;

		case V_ASN1_ANY:
		typ = OPENSSL_malloc(sizeof(ASN1_TYPE));
		if(!typ) return 0;
		typ->value.ptr = NULL;
		typ->type = -1;
		*pval = (ASN1_VALUE *)typ;
		break;

		default:
		*pval = (ASN1_VALUE *)ASN1_STRING_type_new(utype);
		break;
	}
	if(*pval) return 1;
	return 0;
}

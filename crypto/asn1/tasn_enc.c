/* tasn_enc.c */
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

static int asn1_i2d_ex_primitive(ASN1_VALUE *val, unsigned char **out, int utype, int tag, int aclass);
static int asn1_set_seq_out(STACK *seq, unsigned char **out, int skcontlen, const ASN1_ITEM *item, int isset);

/* Encode an ASN1 item, this currently behaves just 
 * like a standard 'i2d' function. 'out' points to 
 * a buffer to output the data to, in future we will
 * have more advanced versions that can output data
 * a piece at a time and this will simply be a special
 * case.
 */


int ASN1_item_i2d(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it)
{
	return ASN1_item_ex_i2d(val, out, it, -1, 0);
}

/* Encode an item, taking care of IMPLICIT tagging (if any).
 * This function performs the normal item handling: it can be
 * used in external types.
 */

int ASN1_item_ex_i2d(ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it, int tag, int aclass)
{
	const ASN1_TEMPLATE *tt = NULL;
	unsigned char *p = NULL;
	int i, seqcontlen, seqlen;
	ASN1_STRING *strtmp;
	const ASN1_COMPAT_FUNCS *cf;
	const ASN1_EXTERN_FUNCS *ef;
	if(!val) return 0;

	switch(it->itype) {

		case ASN1_ITYPE_PRIMITIVE:
		if(it->templates)
			return ASN1_template_i2d(val, out, it->templates);
		return asn1_i2d_ex_primitive(val, out, it->utype, tag, aclass);
		break;

		case ASN1_ITYPE_MSTRING:
		strtmp = (ASN1_STRING *)val;
		return asn1_i2d_ex_primitive(val, out, strtmp->type, tag, aclass);

		case ASN1_ITYPE_CHOICE:
		i = asn1_get_choice_selector(val, it);
		if((i >= 0) && (i < it->tcount)) {
			ASN1_VALUE *chval;
			const ASN1_TEMPLATE *chtt;
			chtt = it->templates + i;
			chval = asn1_get_field(val, chtt);
			return ASN1_template_i2d(chval, out, chtt);
		} 
		/* Fixme: error condition if selector out of range */
		break;

		case ASN1_ITYPE_EXTERN:
		/* If new style i2d it does all the work */
		ef = it->funcs;
		return ef->asn1_ex_i2d(val, out, it, tag, aclass);

		case ASN1_ITYPE_COMPAT:
		/* old style hackery... */
		cf = it->funcs;
		if(out) p = *out;
		i = cf->asn1_i2d(val, out);
		/* Fixup for IMPLICIT tag: note this messes up for tags > 30,
		 * but so did the old code. Tags > 30 are very rare anyway.
		 */
		if(out && (tag != -1))
			*p = aclass | tag | (*p & V_ASN1_CONSTRUCTED);
		return i;
		
		case ASN1_ITYPE_SEQUENCE:
		seqcontlen = 0;
		/* If no IMPLICIT tagging set to SEQUENCE, UNIVERSAL */
		if(tag == -1) {
			tag = V_ASN1_SEQUENCE;
			aclass = V_ASN1_UNIVERSAL;
		}
		/* First work out sequence content length */
		for(i = 0, tt = it->templates; i < it->tcount; tt++, i++) {
			const ASN1_TEMPLATE *seqtt;
			ASN1_VALUE *seqval;
			seqtt = asn1_do_adb(val, tt);
			if(!seqtt) return 0;
			seqval = asn1_get_field(val, seqtt);
			/* FIXME: check for errors in enhanced version */
			/* FIXME: special handling of indefinite length encoding */
			seqcontlen += ASN1_template_i2d(seqval, NULL, seqtt);
		}
		seqlen = ASN1_object_size(1, seqcontlen, tag);
		if(!out) return seqlen;
		/* Output SEQUENCE header */
		ASN1_put_object(out, 1, seqcontlen, tag, aclass);
		for(i = 0, tt = it->templates; i < it->tcount; tt++, i++) {
			const ASN1_TEMPLATE *seqtt;
			ASN1_VALUE *seqval;
			seqtt = asn1_do_adb(val, tt);
			if(!seqtt) return 0;
			seqval = asn1_get_field(val, seqtt);
			/* FIXME: check for errors in enhanced version */
			ASN1_template_i2d(seqval, out, seqtt);
		}
		return seqlen;

		default:
		return 0;
	}
	return 0;
}

int ASN1_template_i2d(ASN1_VALUE *val, unsigned char **out, const ASN1_TEMPLATE *tt)
{
	int i, ret, flags, aclass;
	if(!val) return 0;
	flags = tt->flags;
	aclass = flags & ASN1_TFLG_TAG_CLASS;
	if(flags & ASN1_TFLG_SK_MASK) {
		/* SET OF, SEQUENCE OF */
		STACK *sk = (STACK *)val;
		int isset, sktag, skaclass;
		int skcontlen, sklen;
		ASN1_VALUE *skitem;
		isset = flags & ASN1_TFLG_SET_OF;
		/* First work out inner tag value */
		if(flags & ASN1_TFLG_IMPTAG) {
			sktag = tt->tag;
			skaclass = aclass;
		} else {
			skaclass = V_ASN1_UNIVERSAL;
			if(isset) sktag = V_ASN1_SET;
			else sktag = V_ASN1_SEQUENCE;
		}
		/* Now work out length of items */
		skcontlen = 0;
		for(i = 0; i < sk_num(sk); i++) {
			skitem = (ASN1_VALUE *)sk_value(sk, i);
			skcontlen += ASN1_item_ex_i2d(skitem, NULL, tt->item, -1, 0);
		}
		sklen = ASN1_object_size(1, skcontlen, sktag);
		/* If EXPLICIT need length of surrounding tag */
		if(flags & ASN1_TFLG_EXPTAG)
			ret = ASN1_object_size(1, sklen, tt->tag);
		else ret = sklen;

		if(!out) return ret;

		/* Now encode this lot... */
		/* EXPLICIT tag */
		if(flags & ASN1_TFLG_EXPTAG)
			ASN1_put_object(out, 1, sklen, tt->tag, aclass);
		/* SET or SEQUENCE and IMPLICIT tag */
		ASN1_put_object(out, 1, skcontlen, sktag, skaclass);
		/* And finally the stuff itself */
		asn1_set_seq_out(sk, out, skcontlen, tt->item, isset);

		return ret;
	}
			
	if(flags & ASN1_TFLG_EXPTAG) {
		/* EXPLICIT tagging */
		/* Find length of tagged item */
		i = ASN1_item_ex_i2d(val, NULL, tt->item, -1, 0);
		/* Find length of EXPLICIT tag */
		ret = ASN1_object_size(1, i, tt->tag);
		if(out) {
			/* Output tag and item */
			ASN1_put_object(out, 1, i, tt->tag, aclass);
			ASN1_item_ex_i2d(val, out, tt->item, -1, 0);
		}
		return ret;
	}
	if(flags & ASN1_TFLG_IMPTAG) {
		/* IMPLICIT tagging */
		return ASN1_item_ex_i2d(val, out, tt->item, tt->tag, aclass);
	}
	/* Nothing special: treat as normal */
	return ASN1_item_ex_i2d(val, out, tt->item, -1, 0);
}

/* Temporary structure used to hold DER encoding of items for SET OF */

typedef	struct {
	unsigned char *data;
	int length;
} DER_ENC;

static int der_cmp(const void *a, const void *b)
{
	const DER_ENC *d1 = a, *d2 = b;
	int cmplen, i;
	cmplen = (d1->length < d2->length) ? d1->length : d2->length;
	i = memcmp(d1->data, d2->data, cmplen);
	if(i) return i;
	return d1->length - d2->length;
}

/* Output the content octets of SET OF or SEQUENCE OF */

static int asn1_set_seq_out(STACK *sk, unsigned char **out, int skcontlen, const ASN1_ITEM *item, int do_sort)
{
	int i;
	void *skitem;
	unsigned char *tmpdat, *p;
	DER_ENC *derlst, *tder;
	if(do_sort) {
		/* Don't need to sort less than 2 items */
		if(sk_num(sk) < 2) do_sort = 0;
		else {
			derlst = OPENSSL_malloc(sk_num(sk) * sizeof(*derlst));
			tmpdat = OPENSSL_malloc(skcontlen);
			if(!derlst || !tmpdat) return 0;
		}
	}
	/* If not sorting just output each item */
	if(!do_sort) {
		for(i = 0; i < sk_num(sk); i++) {
			skitem = sk_value(sk, i);
			ASN1_item_i2d(skitem, out, item);
		}
		return 1;
	}
	p = tmpdat;
	/* Doing sort: build up a list of each member's DER encoding */
	for(i = 0, tder = derlst; i < sk_num(sk); i++, tder++) {
		skitem = sk_value(sk, i);
		tder->data = p;
		tder->length = ASN1_item_i2d(skitem, &p, item);
	}
	/* Now sort them */
	qsort(derlst, sk_num(sk), sizeof(*derlst), der_cmp);
	/* Output sorted DER encoding */	
	p = *out;
	for(i = 0, tder = derlst; i < sk_num(sk); i++, tder++) {
		memcpy(p, tder->data, tder->length);
		p += tder->length;
	}
	*out = p;
	OPENSSL_free(derlst);
	OPENSSL_free(tmpdat);
	return 1;
}

static int asn1_i2d_ex_primitive(ASN1_VALUE *val, unsigned char **out, int utype, int tag, int aclass)
{
	int len;
	unsigned char *cont = NULL, c;
	ASN1_OBJECT *otmp;
	ASN1_STRING *stmp;
	int btmp;
	if(!val) return 0;
	if(utype == V_ASN1_ANY) {
		ASN1_TYPE *atype;
		atype = (ASN1_TYPE *)val;
		utype = atype->type;
		/* NB: not a leak because ASN1_NULL_new()
		 * doesn't allocate anything
		 */
		if(utype == V_ASN1_NULL) val = (ASN1_VALUE *)ASN1_NULL_new();
		else val = (ASN1_VALUE *)atype->value.ptr;
	}
	if(tag == -1) {
		tag = utype;
		aclass = V_ASN1_UNIVERSAL;
	}
	/* Setup cont and len to point to content octets and
	 * their length.
	 */
	switch(utype) {
		case V_ASN1_OBJECT:
		otmp = (ASN1_OBJECT *)val;
		cont = otmp->data;
		len = otmp->length;
		break;

		case V_ASN1_NULL:
		cont = NULL;
		len = 0;
		break;

		case V_ASN1_BOOLEAN:
		btmp = *(ASN1_BOOLEAN *)val;
		/* -1 means undefined and thus omitted */
		if(btmp < 0 ) return 0;
		c = (unsigned char)btmp;
		cont = &c;
		len = 1;
		break;

		case V_ASN1_BIT_STRING:
		len = i2c_ASN1_BIT_STRING((ASN1_BIT_STRING *)val, NULL);
		if(out) {
			ASN1_put_object(out, 0, len, tag, aclass);
			i2c_ASN1_BIT_STRING((ASN1_BIT_STRING *)val, out);
		}
		return ASN1_object_size(0, len, tag);
		break;

		case V_ASN1_INTEGER:
		case V_ASN1_NEG_INTEGER:
		case V_ASN1_ENUMERATED:
		case V_ASN1_NEG_ENUMERATED:
		/* These are all have the same content format
		 * as ASN1_INTEGER
		 */
		len = i2c_ASN1_INTEGER((ASN1_INTEGER *)val, NULL);
		if(out) {
			ASN1_put_object(out, 0, len, tag, aclass);
			i2c_ASN1_INTEGER((ASN1_INTEGER *)val, out);
		}
		return ASN1_object_size(0, len, tag);

		case V_ASN1_OCTET_STRING:
		case V_ASN1_NUMERICSTRING:
		case V_ASN1_PRINTABLESTRING:
		case V_ASN1_T61STRING:
		case V_ASN1_VIDEOTEXSTRING:
		case V_ASN1_IA5STRING:
		case V_ASN1_UTCTIME:
		case V_ASN1_GENERALIZEDTIME:
		case V_ASN1_GRAPHICSTRING:
		case V_ASN1_VISIBLESTRING:
		case V_ASN1_GENERALSTRING:
		case V_ASN1_UNIVERSALSTRING:
		case V_ASN1_BMPSTRING:
		case V_ASN1_UTF8STRING:
		/* All based on ASN1_STRING and handled the same */
		stmp = (ASN1_STRING *)val;
		cont = stmp->data;
		len = stmp->length;

		break;


		case V_ASN1_SEQUENCE:
		case V_ASN1_SET:
		default:
		stmp = (ASN1_STRING *)val;
		if(stmp->data && out) {
			memcpy(*out, stmp->data, stmp->length);
			*out += stmp->length;
		}
		return stmp->length;

	}
	if(out) {
		ASN1_put_object(out, 0, len, tag, aclass);
		if(cont) memcpy(*out, cont, len);
		*out += len;
	}
	return ASN1_object_size(0, len, tag);
}

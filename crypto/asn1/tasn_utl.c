/* tasn_utl.c */
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

/* Utility functions for manipulating fields and offsets */

/* Add 'offset' to 'addr' */
#define offset2ptr(addr, offset) (void *)(((char *) addr) + offset)

/* Given an ASN1_ITEM CHOICE type return
 * the selector value
 */

int asn1_get_choice_selector(ASN1_VALUE *val, const ASN1_ITEM *it)
{
	int *sel = offset2ptr(val, it->utype);
	return *sel;
}

/* Given an ASN1_ITEM CHOICE type set
 * the selector value, return old value.
 */

int asn1_set_choice_selector(ASN1_VALUE **pval, int value, const ASN1_ITEM *it)
{	
	int *sel, ret;
	sel = offset2ptr(*pval, it->utype);
	ret = *sel;
	*sel = value;
	return ret;
}

/* Given an ASN1_TEMPLATE get a field */

ASN1_VALUE *asn1_get_field(ASN1_VALUE *val, const ASN1_TEMPLATE *tt)
{
	ASN1_VALUE **ptr = offset2ptr(val, tt->offset);
	/* NOTE for BOOLEAN types the field is just a plain
 	 * int so we don't dereference it. This means that
	 * BOOLEAN is an (int *).
	 */
	if(asn1_template_is_bool(tt)) {
		ASN1_BOOLEAN *bool = (ASN1_BOOLEAN *)ptr;
		/* If BOOLEAN is -1 it is absent so return
		 * NULL for compatibility with other types
		 */
		if(*bool == -1)
			return NULL;
		return (ASN1_VALUE *)ptr;
	}
	return *ptr;
}

/* Given an ASN1_TEMPLATE get a pointer to a field */
ASN1_VALUE ** asn1_get_field_ptr(ASN1_VALUE **pval, const ASN1_TEMPLATE *tt)
{
	ASN1_VALUE **pvaltmp = offset2ptr(*pval, tt->offset);
	/* NOTE for BOOLEAN types the field is just a plain
 	 * int so we can't return int **, so settle for
	 * (int *).
	 */
	return pvaltmp;
}

/* Handle ANY DEFINED BY template, find the selector, look up
 * the relevant ASN1_TEMPLATE in the table and return it.
 */

const ASN1_TEMPLATE *asn1_do_adb(ASN1_VALUE *val, const ASN1_TEMPLATE *tt)
{
	const ASN1_ADB *adb;
	const ASN1_ADB_TABLE *atbl;
	long selector;
	ASN1_VALUE *sfld;
	int i;
	if(!(tt->flags & ASN1_TFLG_ADB_MASK)) return tt;

	/* Else ANY DEFINED BY ... get the table */
	adb = tt->item;

	/* Get the selector field */
	sfld = offset2ptr(val, adb->offset);

	/* Check if NULL */
	if(!sfld) return adb->null_tt;

	/* Convert type to a long:
	 * NB: don't check for NID_undef here because it
	 * might be a legitimate value in the table
	 */
	if(tt->flags & ASN1_TFLG_ADB_OID) 
		selector = OBJ_obj2nid((ASN1_OBJECT *)sfld);
	else 
		selector = ASN1_INTEGER_get((ASN1_INTEGER *)sfld);

	/* Try to find matching entry in table
	 * Maybe should check application types first to
	 * allow application override? Might also be useful
	 * to have a flag which indicates table is sorted and
	 * we can do a binary search. For now stick to a
	 * linear search.
	 */

	for(atbl = adb->tbl, i = 0; i < adb->tblcount; i++, atbl++)
		if(atbl->value == selector) return atbl->tt;

	/* FIXME: need to search application table too */

	/* No match, return default type */
	return adb->default_tt;		
}

int asn1_template_is_bool(const ASN1_TEMPLATE *tt)
{
	if(tt->flags & ASN1_TFLG_SK_MASK) return 0;
	else return asn1_item_is_bool(tt->item);
}

int asn1_item_is_bool(const ASN1_ITEM *it)
{
	if((it->utype == V_ASN1_BOOLEAN) &&
	  (it->itype == ASN1_ITYPE_PRIMITIVE)) return 1;
	return 0;
}

/* tasn_typ.c */
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
#include <stdio.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>



#define IMPLEMENT_ASN1_TYPE(type) const ASN1_ITEM type##_it = { ASN1_ITYPE_PRIMITIVE, V_##type, NULL, 0, NULL, sizeof(type)}


IMPLEMENT_ASN1_TYPE(ASN1_BOOLEAN);
IMPLEMENT_ASN1_TYPE(ASN1_INTEGER);
IMPLEMENT_ASN1_TYPE(ASN1_BIT_STRING);
IMPLEMENT_ASN1_TYPE(ASN1_OCTET_STRING);
IMPLEMENT_ASN1_TYPE(ASN1_NULL);
IMPLEMENT_ASN1_TYPE(ASN1_OBJECT);
IMPLEMENT_ASN1_TYPE(ASN1_ENUMERATED);
IMPLEMENT_ASN1_TYPE(ASN1_UTF8STRING);
IMPLEMENT_ASN1_TYPE(ASN1_PRINTABLESTRING);
IMPLEMENT_ASN1_TYPE(ASN1_T61STRING);
IMPLEMENT_ASN1_TYPE(ASN1_IA5STRING);
IMPLEMENT_ASN1_TYPE(ASN1_UTCTIME);
IMPLEMENT_ASN1_TYPE(ASN1_GENERALIZEDTIME);
IMPLEMENT_ASN1_TYPE(ASN1_VISIBLESTRING);
IMPLEMENT_ASN1_TYPE(ASN1_UNIVERSALSTRING);
IMPLEMENT_ASN1_TYPE(ASN1_BMPSTRING);
const ASN1_ITEM ASN1_ANY_it = { ASN1_ITYPE_PRIMITIVE, V_ASN1_ANY, NULL, 0, NULL, sizeof(ASN1_TYPE)};


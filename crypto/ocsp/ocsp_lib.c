/* ocsp_lib.c */
/* Written by Tom Titchener <Tom_Titchener@groove.net> for the OpenSSL
 * project. */

/* History:
   This file was transfered to Richard Levitte from CertCo by Kathy
   Weinhold in mid-spring 2000 to be included in OpenSSL or released
   as a patch kit. */

/* ====================================================================
 * Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
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

#include <stdio.h>
#include <cryptlib.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>

/* Convert a certificate and its issuer to an OCSP_CERTID */

OCSP_CERTID *OCSP_cert_to_id(const EVP_MD *dgst, X509 *subject, X509 *issuer)
{
	X509_NAME *iname;
	ASN1_INTEGER *serial;
	ASN1_BIT_STRING *ikey;
#ifndef NO_SHA1
	if(!dgst) dgst = EVP_sha1();
#endif
	iname = X509_get_issuer_name(subject);
	serial = X509_get_serialNumber(subject);
	ikey = X509_get0_pubkey_bitstr(issuer);
	return OCSP_cert_id_new(dgst, iname, ikey, serial);
}


OCSP_CERTID *OCSP_cert_id_new(const EVP_MD *dgst, 
			      X509_NAME *issuerName, 
			      ASN1_BIT_STRING* issuerKey, 
			      ASN1_INTEGER *serialNumber)
        {
	int nid;
        unsigned int i;
	X509_ALGOR *alg;
	OCSP_CERTID *cid = NULL;
	unsigned char md[EVP_MAX_MD_SIZE];

	if (!(cid = OCSP_CERTID_new())) goto err;

	alg = cid->hashAlgorithm;
	if (alg->algorithm != NULL) ASN1_OBJECT_free(alg->algorithm);
	if ((nid = EVP_MD_type(dgst)) == NID_undef)
	        {
		OCSPerr(OCSP_F_CERT_ID_NEW,OCSP_R_UNKNOWN_NID);
		goto err;
		}
	if (!(alg->algorithm=OBJ_nid2obj(nid))) goto err;
	if ((alg->parameter=ASN1_TYPE_new()) == NULL) goto err;
	alg->parameter->type=V_ASN1_NULL;

	if (!X509_NAME_digest(issuerName, dgst, md, &i)) goto digerr;
	if (!(ASN1_OCTET_STRING_set(cid->issuerNameHash, md, i))) goto err;

	/* Calculate the issuerKey hash, excluding tag and length */
	EVP_Digest(issuerKey->data, issuerKey->length, md, &i, dgst);

	if (!(ASN1_OCTET_STRING_set(cid->issuerKeyHash, md, i))) goto err;
	
	if (cid->serialNumber != NULL) ASN1_INTEGER_free(cid->serialNumber);
	if (!(cid->serialNumber = ASN1_INTEGER_dup(serialNumber))) goto err;
	return cid;
digerr:
	OCSPerr(OCSP_F_CERT_ID_NEW,OCSP_R_DIGEST_ERR);
err:
	if (cid) OCSP_CERTID_free(cid);
	return NULL;
	}

int OCSP_id_issuer_cmp(OCSP_CERTID *a, OCSP_CERTID *b)
	{
	int ret;
	ret = OBJ_cmp(a->hashAlgorithm->algorithm, b->hashAlgorithm->algorithm);
	if (ret) return ret;
	ret = ASN1_OCTET_STRING_cmp(a->issuerNameHash, b->issuerNameHash);
	if (ret) return ret;
	return ASN1_OCTET_STRING_cmp(a->issuerKeyHash, b->issuerKeyHash);
	}

int OCSP_id_cmp(OCSP_CERTID *a, OCSP_CERTID *b)
	{
	int ret;
	ret = OCSP_id_issuer_cmp(a, b);
	if (ret) return ret;
	return ASN1_INTEGER_cmp(a->serialNumber, b->serialNumber);
	}

/* XXX assumes certs in signature are sorted root to leaf XXX */
int OCSP_request_verify(OCSP_REQUEST *req, EVP_PKEY *pkey)
        {
	STACK_OF(X509) *sk;

	if (!req->optionalSignature) return 0;
	if (pkey == NULL)
	        {
	        if (!(sk = req->optionalSignature->certs)) return 0;
		if (!(pkey=X509_get_pubkey(sk_X509_value(sk, sk_X509_num(sk)-1))))
		        {
		        OCSPerr(OCSP_F_REQUEST_VERIFY,OCSP_R_NO_PUBLIC_KEY);
			return 0;
		        }
		}
	return OCSP_REQUEST_verify(req, pkey);
        }

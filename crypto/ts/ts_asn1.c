/* crypto/ts/ts_asn1.c */
/* Written by Nils Larsch for the OpenSSL project 2004.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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

#include <openssl/ts.h>
#include <openssl/err.h>
#include <openssl/asn1t.h>

ASN1_SEQUENCE(TS_MSG_IMPRINT) = {
	ASN1_SIMPLE(TS_MSG_IMPRINT, hash_algo, X509_ALGOR),
	ASN1_SIMPLE(TS_MSG_IMPRINT, hashed_msg, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(TS_MSG_IMPRINT)

IMPLEMENT_ASN1_FUNCTIONS_const(TS_MSG_IMPRINT)
IMPLEMENT_ASN1_DUP_FUNCTION(TS_MSG_IMPRINT)
#ifndef OPENSSL_NO_BIO
int i2d_TS_MSG_IMPRINT_bio(BIO *bp, TS_MSG_IMPRINT *a)
{
	return ASN1_i2d_bio(i2d_TS_MSG_IMPRINT, bp, (unsigned char *) a);
}
#endif
#ifndef OPENSSL_NO_FP_API
TS_MSG_IMPRINT *d2i_TS_MSG_IMPRINT_fp(FILE *fp, TS_MSG_IMPRINT **a)
	{
	return (TS_MSG_IMPRINT *) ASN1_d2i_fp((char *(*)()) TS_MSG_IMPRINT_new,
		(char *(*)()) d2i_TS_MSG_IMPRINT, fp, (unsigned char **) a);
	}

int i2d_TS_MSG_IMPRINT_fp(FILE *fp, TS_MSG_IMPRINT *a)
	{
	return ASN1_i2d_fp(i2d_TS_MSG_IMPRINT, fp, (unsigned char *) a);
	}
#endif

ASN1_SEQUENCE(TS_REQ) = {
	ASN1_SIMPLE(TS_REQ, version, ASN1_INTEGER),
	ASN1_SIMPLE(TS_REQ, msg_imprint, TS_MSG_IMPRINT),
	ASN1_OPT(TS_REQ, policy_id, ASN1_OBJECT),
	ASN1_OPT(TS_REQ, nonce, ASN1_INTEGER),
	ASN1_OPT(TS_REQ, cert_req, ASN1_BOOLEAN),
	ASN1_IMP_SEQUENCE_OF_OPT(TS_REQ, extensions, X509_EXTENSION, 0)
} ASN1_SEQUENCE_END(TS_REQ)

IMPLEMENT_ASN1_FUNCTIONS_const(TS_REQ)
IMPLEMENT_ASN1_DUP_FUNCTION(TS_REQ)
#ifndef OPENSSL_NO_BIO
TS_REQ *d2i_TS_REQ_bio(BIO *bp, TS_REQ **a)
	{
	return (TS_REQ *) ASN1_d2i_bio((char *(*)()) TS_REQ_new,
		(char *(*)()) d2i_TS_REQ, bp, (unsigned char **) a);
	}

int i2d_TS_REQ_bio(BIO *bp, TS_REQ *a)
	{
	return ASN1_i2d_bio(i2d_TS_REQ, bp, (unsigned char *) a);
	}
#endif
#ifndef OPENSSL_NO_FP_API
TS_REQ *d2i_TS_REQ_fp(FILE *fp, TS_REQ **a)
	{
	return (TS_REQ *) ASN1_d2i_fp((char *(*)()) TS_REQ_new,
		(char *(*)()) d2i_TS_REQ, fp, (unsigned char **) a);
	}

int i2d_TS_REQ_fp(FILE *fp, TS_REQ *a)
	{
	return ASN1_i2d_fp(i2d_TS_REQ, fp, (unsigned char *) a);
	}
#endif

ASN1_SEQUENCE(TS_ACCURACY) = {
	ASN1_OPT(TS_ACCURACY, seconds, ASN1_INTEGER),
	ASN1_IMP_OPT(TS_ACCURACY, millis, ASN1_INTEGER, 0),
	ASN1_IMP_OPT(TS_ACCURACY, micros, ASN1_INTEGER, 1)
} ASN1_SEQUENCE_END(TS_ACCURACY)

IMPLEMENT_ASN1_FUNCTIONS_const(TS_ACCURACY)
IMPLEMENT_ASN1_DUP_FUNCTION(TS_ACCURACY)

ASN1_SEQUENCE(TS_TST_INFO) = {
	ASN1_SIMPLE(TS_TST_INFO, version, ASN1_INTEGER),
	ASN1_SIMPLE(TS_TST_INFO, policy_id, ASN1_OBJECT),
	ASN1_SIMPLE(TS_TST_INFO, msg_imprint, TS_MSG_IMPRINT),
	ASN1_SIMPLE(TS_TST_INFO, serial, ASN1_INTEGER),
	ASN1_SIMPLE(TS_TST_INFO, time, ASN1_GENERALIZEDTIME),
	ASN1_OPT(TS_TST_INFO, accuracy, TS_ACCURACY),
	ASN1_OPT(TS_TST_INFO, ordering, ASN1_BOOLEAN),
	ASN1_OPT(TS_TST_INFO, nonce, ASN1_INTEGER),
	ASN1_EXP_OPT(TS_TST_INFO, tsa, GENERAL_NAME, 0),
	ASN1_IMP_SEQUENCE_OF_OPT(TS_TST_INFO, extensions, X509_EXTENSION, 1)
} ASN1_SEQUENCE_END(TS_TST_INFO)

IMPLEMENT_ASN1_FUNCTIONS_const(TS_TST_INFO)
IMPLEMENT_ASN1_DUP_FUNCTION(TS_TST_INFO)
#ifndef OPENSSL_NO_BIO
TS_TST_INFO *d2i_TS_TST_INFO_bio(BIO *bp, TS_TST_INFO **a)
	{
	return (TS_TST_INFO *) ASN1_d2i_bio((char *(*)()) TS_TST_INFO_new,
					    (char *(*)()) d2i_TS_TST_INFO,
					    bp, (unsigned char **) a);
	}

int i2d_TS_TST_INFO_bio(BIO *bp, TS_TST_INFO *a)
	{
	return ASN1_i2d_bio(i2d_TS_TST_INFO, bp, (unsigned char *) a);
	}
#endif
#ifndef OPENSSL_NO_FP_API
TS_TST_INFO *d2i_TS_TST_INFO_fp(FILE *fp, TS_TST_INFO **a)
	{
	return (TS_TST_INFO *) ASN1_d2i_fp((char *(*)()) TS_TST_INFO_new,
					   (char *(*)()) d2i_TS_TST_INFO,
					   fp, (unsigned char **) a);
	}

int i2d_TS_TST_INFO_fp(FILE *fp, TS_TST_INFO *a)
	{
	return ASN1_i2d_fp(i2d_TS_TST_INFO, fp, (unsigned char *) a);
	}
#endif

ASN1_SEQUENCE(TS_STATUS_INFO) = {
	ASN1_SIMPLE(TS_STATUS_INFO, status, ASN1_INTEGER),
	ASN1_SEQUENCE_OF_OPT(TS_STATUS_INFO, text, ASN1_UTF8STRING),
	ASN1_OPT(TS_STATUS_INFO, failure_info, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(TS_STATUS_INFO)

IMPLEMENT_ASN1_FUNCTIONS_const(TS_STATUS_INFO)
IMPLEMENT_ASN1_DUP_FUNCTION(TS_STATUS_INFO)

ASN1_SEQUENCE(TS_RESP) = {
	ASN1_SIMPLE(TS_RESP, status_info, TS_STATUS_INFO),
	ASN1_OPT(TS_RESP, token, PKCS7),
} ASN1_SEQUENCE_END(TS_RESP)

IMPLEMENT_ASN1_ALLOC_FUNCTIONS_fname(TS_RESP, TS_RESP, TS_RESP_int)
IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(TS_RESP, TS_RESP, TS_RESP_int)

TS_RESP *TS_RESP_new(void)
{
	TS_RESP *ret = TS_RESP_int_new();
	if (!ret)
		return NULL;
	ret->tst_info = NULL;
	return ret;
}

void TS_RESP_free(TS_RESP *a)
{
	if (!a)
		return;
	if (a->tst_info)
		TS_TST_INFO_free(a->tst_info);
	TS_RESP_int_free(a);
}

int i2d_TS_RESP(const TS_RESP *a, unsigned char **pp)
{
	return i2d_TS_RESP_int(a, pp);
}

TS_RESP *d2i_TS_RESP(TS_RESP **a, const unsigned char **pp, long len)
{
	long    status;
	TS_RESP *ret;

	ret = d2i_TS_RESP_int(a, pp, len);
	if (!ret) {
		TSerr(TS_F_D2I_TS_RESP, TS_R_D2I_TS_RESP_INT_FAILED);
		return NULL;
	}
	status = ASN1_INTEGER_get(ret->status_info->status);

	if (ret->token) {
		if (status != 0 && status != 1) {
			TSerr(TS_F_D2I_TS_RESP, TS_R_TOKEN_PRESENT);
			if (!*a)
				TS_RESP_free(ret);
			return NULL;
		}
		ret->tst_info = PKCS7_to_TS_TST_INFO(ret->token);
		if (!ret->tst_info) {
			TSerr(TS_F_D2I_TS_RESP, TS_R_PKCS7_TO_TS_TST_INFO_FAILED);
			if (!*a)
				TS_RESP_free(ret);
			return NULL;
		}
	} else if (status == 0 || status == 1) {
		TSerr(TS_F_D2I_TS_RESP, TS_R_TOKEN_NOT_PRESENT);
		if (!*a)
			TS_RESP_free(ret);
		return NULL;
	}

	return ret;
}

IMPLEMENT_ASN1_DUP_FUNCTION(TS_RESP)
#ifndef OPENSSL_NO_BIO
TS_RESP *d2i_TS_RESP_bio(BIO *bp, TS_RESP **a)
	{
	return (TS_RESP *) ASN1_d2i_bio((char *(*)()) TS_RESP_new,
				       (char *(*)()) d2i_TS_RESP,
				       bp, (unsigned char **) a);
	}

int i2d_TS_RESP_bio(BIO *bp, TS_RESP *a)
	{
	return ASN1_i2d_bio(i2d_TS_RESP, bp, (unsigned char *) a);
	}
#endif
#ifndef OPENSSL_NO_FP_API
TS_RESP *d2i_TS_RESP_fp(FILE *fp, TS_RESP **a)
	{
	return (TS_RESP *) ASN1_d2i_fp((char *(*)()) TS_RESP_new,
				       (char *(*)()) d2i_TS_RESP,
				       fp, (unsigned char **) a);
	}

int i2d_TS_RESP_fp(FILE *fp, TS_RESP *a)
	{
	return ASN1_i2d_fp(i2d_TS_RESP, fp, (unsigned char *) a);
	}
#endif

ASN1_SEQUENCE(ESS_ISSUER_SERIAL) = {
	ASN1_SEQUENCE_OF(ESS_ISSUER_SERIAL, issuer, GENERAL_NAME),
	ASN1_SIMPLE(ESS_ISSUER_SERIAL, serial, ASN1_INTEGER)
} ASN1_SEQUENCE_END(ESS_ISSUER_SERIAL)

IMPLEMENT_ASN1_FUNCTIONS_const(ESS_ISSUER_SERIAL)
IMPLEMENT_ASN1_DUP_FUNCTION(ESS_ISSUER_SERIAL)

ASN1_SEQUENCE(ESS_CERT_ID) = {
	ASN1_SIMPLE(ESS_CERT_ID, hash, ASN1_OCTET_STRING),
	ASN1_OPT(ESS_CERT_ID, issuer_serial, ESS_ISSUER_SERIAL)
} ASN1_SEQUENCE_END(ESS_CERT_ID)

IMPLEMENT_ASN1_FUNCTIONS_const(ESS_CERT_ID)
IMPLEMENT_ASN1_DUP_FUNCTION(ESS_CERT_ID)

ASN1_SEQUENCE(ESS_SIGNING_CERT) = {
	ASN1_SEQUENCE_OF(ESS_SIGNING_CERT, cert_ids, ESS_CERT_ID),
	ASN1_SEQUENCE_OF_OPT(ESS_SIGNING_CERT, policy_info, POLICYINFO)
} ASN1_SEQUENCE_END(ESS_SIGNING_CERT)

IMPLEMENT_ASN1_FUNCTIONS_const(ESS_SIGNING_CERT)
IMPLEMENT_ASN1_DUP_FUNCTION(ESS_SIGNING_CERT)

/* Getting encapsulated TS_TST_INFO object from PKCS7. */
TS_TST_INFO *PKCS7_to_TS_TST_INFO(PKCS7 *token)
{
	PKCS7_SIGNED *pkcs7_signed;
	PKCS7 *enveloped;
	ASN1_TYPE *tst_info_wrapper;
	ASN1_OCTET_STRING *tst_info_der;
	const unsigned char *p;

	if (!PKCS7_type_is_signed(token))
		{
		TSerr(TS_F_PKCS7_TO_TS_TST_INFO, TS_R_BAD_PKCS7_TYPE);
		return NULL;
		}

	/* Content must be present. */
	if (PKCS7_get_detached(token))
		{
		TSerr(TS_F_PKCS7_TO_TS_TST_INFO, TS_R_DETACHED_CONTENT);
		return NULL;
		}

	/* We have a signed data with content. */
	pkcs7_signed = token->d.sign;
	enveloped = pkcs7_signed->contents;
	if (OBJ_obj2nid(enveloped->type) != NID_id_smime_ct_TSTInfo)
		{
		TSerr(TS_F_PKCS7_TO_TS_TST_INFO, TS_R_BAD_PKCS7_TYPE);
		return NULL;
		}

	/* We have a DER encoded TST_INFO as the signed data. */
	tst_info_wrapper = enveloped->d.other;
	if (tst_info_wrapper->type != V_ASN1_OCTET_STRING)
		{
		TSerr(TS_F_PKCS7_TO_TS_TST_INFO, TS_R_BAD_TYPE);
		return NULL;
		}

	/* We have the correct ASN1_OCTET_STRING type. */
	tst_info_der = tst_info_wrapper->value.octet_string;
	/* At last, decode the TST_INFO. */
	p = tst_info_der->data;
	return d2i_TS_TST_INFO(NULL, &p, tst_info_der->length);
}

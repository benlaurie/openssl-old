/* ocsp.h */
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

#ifndef HEADER_OCSP_H
#define HEADER_OCSP_H

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/safestack.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*   CertID ::= SEQUENCE {
 *       hashAlgorithm            AlgorithmIdentifier,
 *       issuerNameHash     OCTET STRING, -- Hash of Issuer's DN
 *       issuerKeyHash      OCTET STRING, -- Hash of Issuers public key (excluding the tag & length fields)
 *       serialNumber       CertificateSerialNumber }
 */
typedef struct ocsp_cert_id_st
	{
	X509_ALGOR *hashAlgorithm;
	ASN1_OCTET_STRING *issuerNameHash;
	ASN1_OCTET_STRING *issuerKeyHash;
	ASN1_INTEGER *serialNumber;
	} OCSP_CERTID;

/*   Request ::=     SEQUENCE {
 *       reqCert                    CertID,
 *       singleRequestExtensions    [0] EXPLICIT Extensions OPTIONAL }
 */
typedef struct ocsp_one_request_st
	{
	OCSP_CERTID *reqCert;
	STACK_OF(X509_EXTENSION) *singleRequestExtensions;
	} OCSP_ONEREQ;

DECLARE_STACK_OF(OCSP_ONEREQ)
DECLARE_ASN1_SET_OF(OCSP_ONEREQ)


/*   TBSRequest      ::=     SEQUENCE {
 *       version             [0] EXPLICIT Version DEFAULT v1,
 *       requestorName       [1] EXPLICIT GeneralName OPTIONAL,
 *       requestList             SEQUENCE OF Request,
 *       requestExtensions   [2] EXPLICIT Extensions OPTIONAL }
 */
typedef struct ocsp_req_info_st
	{
	ASN1_INTEGER *version;
	GENERAL_NAME *requestorName;
	STACK_OF(OCSP_ONEREQ) *requestList;
	STACK_OF(X509_EXTENSION) *requestExtensions;
	} OCSP_REQINFO;

/*   Signature       ::=     SEQUENCE {
 *       signatureAlgorithm   AlgorithmIdentifier,
 *       signature            BIT STRING,
 *       certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
 */
typedef struct ocsp_signature_st
	{
	X509_ALGOR *signatureAlgorithm;
	ASN1_BIT_STRING *signature;
	STACK_OF(X509) *certs;
	} OCSP_SIGNATURE;

/*   OCSPRequest     ::=     SEQUENCE {
 *       tbsRequest                  TBSRequest,
 *       optionalSignature   [0]     EXPLICIT Signature OPTIONAL }
 */
typedef struct ocsp_request_st
	{
	OCSP_REQINFO *tbsRequest;
	OCSP_SIGNATURE *optionalSignature; /* OPTIONAL */
	} OCSP_REQUEST;

/*   OCSPResponseStatus ::= ENUMERATED {
 *       successful            (0),      --Response has valid confirmations
 *       malformedRequest      (1),      --Illegal confirmation request
 *       internalError         (2),      --Internal error in issuer
 *       tryLater              (3),      --Try again later
 *                                       --(4) is not used
 *       sigRequired           (5),      --Must sign the request
 *       unauthorized          (6)       --Request unauthorized
 *   }
 */
#define OCSP_RESPONSE_STATUS_SUCCESSFULL          0
#define OCSP_RESPONSE_STATUS_MALFORMEDREQUEST     1
#define OCSP_RESPONSE_STATUS_INTERNALERROR        2
#define OCSP_RESPONSE_STATUS_TRYLATER             3
#define OCSP_RESPONSE_STATUS_SIGREQUIRED          5
#define OCSP_RESPONSE_STATUS_UNAUTHORIZED         6

/*   ResponseBytes ::=       SEQUENCE {
 *       responseType   OBJECT IDENTIFIER,
 *       response       OCTET STRING }
 */
typedef struct ocsp_resp_bytes_st
	{
	ASN1_OBJECT *responseType;
	ASN1_OCTET_STRING *response;
	} OCSP_RESPBYTES;

/*   OCSPResponse ::= SEQUENCE {
 *      responseStatus         OCSPResponseStatus,
 *      responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
 */
typedef struct ocsp_response_st
	{
	ASN1_ENUMERATED *responseStatus;
	OCSP_RESPBYTES  *responseBytes;
	} OCSP_RESPONSE;

/*   ResponderID ::= CHOICE {
 *      byName   [1] Name,
 *      byKey    [2] KeyHash }
 */
#define V_OCSP_RESPID_NAME 0
#define V_OCSP_RESPID_KEY  1
typedef struct ocsp_responder_id_st
	{
	int type;
	union   {
		X509_NAME* byName;
        	ASN1_OCTET_STRING *byKey;
		} value;
	} OCSP_RESPID;
/*   KeyHash ::= OCTET STRING --SHA-1 hash of responder's public key
 *                            --(excluding the tag and length fields)
 */

/*   RevokedInfo ::= SEQUENCE {
 *       revocationTime              GeneralizedTime,
 *       revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }
 */
typedef struct ocsp_revoked_info_st
	{
	ASN1_GENERALIZEDTIME *revocationTime;
	ASN1_ENUMERATED *revocationReason;
	} OCSP_REVOKEDINFO;

/*   CertStatus ::= CHOICE {
 *       good                [0]     IMPLICIT NULL,
 *       revoked             [1]     IMPLICIT RevokedInfo,
 *       unknown             [2]     IMPLICIT UnknownInfo }
 */
#define V_OCSP_CERTSTATUS_GOOD    0
#define V_OCSP_CERTSTATUS_REVOKED 1
#define V_OCSP_CERTSTATUS_UNKNOWN 2
typedef struct ocsp_cert_status_st
	{
	int type;
	union	{
		ASN1_NULL *good;
		OCSP_REVOKEDINFO *revoked;
		ASN1_NULL *unknown;
		} value;
	} OCSP_CERTSTATUS;

/*   SingleResponse ::= SEQUENCE {
 *      certID                       CertID,
 *      certStatus                   CertStatus,
 *      thisUpdate                   GeneralizedTime,
 *      nextUpdate           [0]     EXPLICIT GeneralizedTime OPTIONAL,
 *      singleExtensions     [1]     EXPLICIT Extensions OPTIONAL }
 */
typedef struct ocsp_single_response_st
	{
	OCSP_CERTID *certId;
	OCSP_CERTSTATUS *certStatus;
	ASN1_GENERALIZEDTIME *thisUpdate;
	ASN1_GENERALIZEDTIME *nextUpdate;
	STACK_OF(X509_EXTENSION) *singleExtensions;
	} OCSP_SINGLERESP;

DECLARE_STACK_OF(OCSP_SINGLERESP)
DECLARE_ASN1_SET_OF(OCSP_SINGLERESP)

/*   ResponseData ::= SEQUENCE {
 *      version              [0] EXPLICIT Version DEFAULT v1,
 *      responderID              ResponderID,
 *      producedAt               GeneralizedTime,
 *      responses                SEQUENCE OF SingleResponse,
 *      responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
 */
typedef struct ocsp_response_data_st
	{
	ASN1_INTEGER *version;
	OCSP_RESPID  *responderId;
	ASN1_GENERALIZEDTIME *producedAt;
	STACK_OF(OCSP_SINGLERESP) *responses;
	STACK_OF(X509_EXTENSION) *responseExtensions;
	} OCSP_RESPDATA;

/*   BasicOCSPResponse       ::= SEQUENCE {
 *      tbsResponseData      ResponseData,
 *      signatureAlgorithm   AlgorithmIdentifier,
 *      signature            BIT STRING,
 *      certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
 */
  /* Note 1:
     The value for "signature" is specified in the OCSP rfc2560 as follows:
     "The value for the signature SHALL be computed on the hash of the DER
     encoding ResponseData."  This means that you must hash the DER-encoded
     tbsResponseData, and then run it through a crypto-signing function, which
     will (at least w/RSA) do a hash-'n'-private-encrypt operation.  This seems
     a bit odd, but that's the spec.  Also note that the data structures do not
     leave anywhere to independently specify the algorithm used for the initial
     hash. So, we look at the signature-specification algorithm, and try to do
     something intelligent.	-- Kathy Weinhold, CertCo */
  /* Note 2:
     It seems that the mentioned passage from RFC 2560 (section 4.2.1) is open
     for interpretation.  I've done tests against another responder, and found
     that it doesn't do the double hashing that the RFC seems to say one
     should.  Therefore, all relevant functions take a flag saying which
     variant should be used.	-- Richard Levitte, OpenSSL team and CeloCom */
typedef struct ocsp_basic_response_st
	{
	OCSP_RESPDATA *tbsResponseData;
	X509_ALGOR *signatureAlgorithm;
	ASN1_BIT_STRING *signature;
	STACK_OF(X509) *certs;
	} OCSP_BASICRESP;

/*
 *   CRLReason ::= ENUMERATED {
 *        unspecified             (0),
 *        keyCompromise           (1),
 *        cACompromise            (2),
 *        affiliationChanged      (3),
 *        superseded              (4),
 *        cessationOfOperation    (5),
 *        certificateHold         (6),
 *        removeFromCRL           (8) }
 */
#define OCSP_REVOKED_STATUS_NOSTATUS               -1
#define OCSP_REVOKED_STATUS_UNSPECIFIED             0
#define OCSP_REVOKED_STATUS_KEYCOMPROMISE           1
#define OCSP_REVOKED_STATUS_CACOMPROMISE            2
#define OCSP_REVOKED_STATUS_AFFILIATIONCHANGED      3
#define OCSP_REVOKED_STATUS_SUPERSEDED              4
#define OCSP_REVOKED_STATUS_CESSATIONOFOPERATION    5
#define OCSP_REVOKED_STATUS_CERTIFICATEHOLD         6
#define OCSP_REVOKED_STATUS_REMOVEFROMCRL           8

/* CrlID ::= SEQUENCE {
 *     crlUrl               [0]     EXPLICIT IA5String OPTIONAL,
 *     crlNum               [1]     EXPLICIT INTEGER OPTIONAL,
 *     crlTime              [2]     EXPLICIT GeneralizedTime OPTIONAL }
 */
typedef struct ocsp_crl_id_st
        {
	ASN1_IA5STRING *crlUrl;
	ASN1_INTEGER *crlNum;
	ASN1_GENERALIZEDTIME *crlTime;
        } OCSP_CRLID;

/* ServiceLocator ::= SEQUENCE {
 *      issuer    Name,
 *      locator   AuthorityInfoAccessSyntax OPTIONAL }
 */
typedef struct ocsp_service_locator_st
        {
	X509_NAME* issuer;
	STACK_OF(ACCESS_DESCRIPTION) *locator;
        } OCSP_SERVICELOC;
 
#define PEM_STRING_OCSP_REQUEST	"OCSP REQUEST"
#define PEM_STRING_OCSP_RESPONSE "OCSP RESPONSE"

#define d2i_OCSP_REQUEST_bio(bp,p) (OCSP_REQUEST*)ASN1_d2i_bio((char*(*)()) \
		OCSP_REQUEST_new,(char *(*)())d2i_OCSP_REQUEST, (bp),\
		(unsigned char **)(p))

#define d2i_OCSP_RESPONSE_bio(bp,p) (OCSP_RESPONSE*)ASN1_d2i_bio((char*(*)())\
		OCSP_REQUEST_new,(char *(*)())d2i_OCSP_RESPONSE, (bp),\
		(unsigned char **)(p))

#define	PEM_read_bio_OCSP_REQUEST(bp,x,cb) (OCSP_REQUEST *)PEM_ASN1_read_bio( \
     (char *(*)())d2i_OCSP_REQUEST,PEM_STRING_OCSP_REQUEST,bp,(char **)x,cb,NULL)

#define	PEM_read_bio_OCSP_RESPONSE(bp,x,cb)(OCSP_RESPONSE *)PEM_ASN1_read_bio(\
     (char *(*)())d2i_OCSP_RESPONSE,PEM_STRING_OCSP_RESPONSE,bp,(char **)x,cb,NULL)

#define PEM_write_bio_OCSP_REQUEST(bp,o) \
    PEM_ASN1_write_bio((int (*)())i2d_OCSP_REQUEST,PEM_STRING_OCSP_REQUEST,\
			bp,(char *)o, NULL,NULL,0,NULL,NULL)

#define PEM_write_bio_OCSP_RESPONSE(bp,o) \
    PEM_ASN1_write_bio((int (*)())i2d_OCSP_RESPONSE,PEM_STRING_OCSP_RESPONSE,\
			bp,(char *)o, NULL,NULL,0,NULL,NULL)

#define i2d_OCSP_RESPONSE_bio(bp,o) ASN1_i2d_bio(i2d_OCSP_RESPONSE,bp,\
		(unsigned char *)o)

#define i2d_OCSP_REQUEST_bio(bp,o) ASN1_i2d_bio(i2d_OCSP_REQUEST,bp,\
		(unsigned char *)o)

#define OCSP_REQUEST_sign(o,pkey,md) \
	ASN1_item_sign(&OCSP_REQINFO_it,\
		o->optionalSignature->signatureAlgorithm,NULL,\
	        o->optionalSignature->signature,(char *)o->tbsRequest,pkey,md)

#define OCSP_BASICRESP_sign(o,pkey,md,d) \
	ASN1_item_sign(&OCSP_RESPDATA_it,o->signatureAlgorithm,NULL,\
		o->signature,(char *)o->tbsResponseData,pkey,md)

#define OCSP_REQUEST_verify(a,r) ASN1_item_verify(&OCSP_REQINFO_it,\
        a->optionalSignature->signatureAlgorithm,\
	a->optionalSignature->signature,(char *)a->tbsRequest,r)

#define OCSP_BASICRESP_verify(a,r,d) ASN1_item_verify(&OCSP_RESPDATA_it,\
	a->signatureAlgorithm,a->signature,(char *)a->tbsResponseData,r)

#define ASN1_BIT_STRING_digest(data,type,md,len) \
	ASN1_item_digest(&ASN1_BIT_STRING_it,type,(char *)data,md,len)

#define OCSP_CERTID_dup(cid) (OCSP_CERTID*)ASN1_dup((int(*)())i2d_OCSP_CERTID,\
		(char *(*)())d2i_OCSP_CERTID,(char *)(cid))

#define OCSP_CERTSTATUS_dup(cs)\
                (OCSP_CERTSTATUS*)ASN1_dup((int(*)())i2d_OCSP_CERTSTATUS,\
		(char *(*)())d2i_OCSP_CERTSTATUS,(char *)(cs))

OCSP_RESPONSE *OCSP_sendreq_bio(BIO *b, char *path, OCSP_REQUEST *req);

OCSP_CERTID *OCSP_cert_to_id(const EVP_MD *dgst, X509 *subject, X509 *issuer);

OCSP_CERTID *OCSP_cert_id_new(const EVP_MD *dgst, 
			      X509_NAME *issuerName, 
			      ASN1_BIT_STRING* issuerKey, 
			      ASN1_INTEGER *serialNumber);

OCSP_CERTSTATUS *OCSP_cert_status_new(int status, int reason, char *tim);

OCSP_ONEREQ *OCSP_request_add0(OCSP_REQUEST *req, OCSP_CERTID *cid);

int OCSP_request_sign(OCSP_REQUEST   *req,
		      EVP_PKEY       *key,
		      const EVP_MD   *dgst,
		      STACK_OF(X509) *certs);

int OCSP_request_verify(OCSP_REQUEST *req, EVP_PKEY *pkey);

OCSP_BASICRESP *OCSP_basic_response_new(int tag,
					X509* cert);

int OCSP_basic_response_add(OCSP_BASICRESP           *rsp,
			    OCSP_CERTID              *cid,
			    OCSP_CERTSTATUS          *cst,
			    char                     *thisUpdate,
			    char                     *nextUpdate);

int OCSP_basic_response_sign(OCSP_BASICRESP *brsp, 
			     EVP_PKEY       *key,
			     const EVP_MD   *dgst,
			     STACK_OF(X509) *certs);

int OCSP_response_verify(OCSP_RESPONSE *rsp, EVP_PKEY *pkey);

int OCSP_basic_response_verify(OCSP_BASICRESP *rsp, EVP_PKEY *pkey);


OCSP_RESPONSE *OCSP_response_new(int status,
				 int nid,
				 int (*i2d)(),
				 char *data);

ASN1_STRING *ASN1_STRING_encode(ASN1_STRING *s, int (*i2d)(), 
				char *data, STACK_OF(ASN1_OBJECT) *sk);

X509_EXTENSION *OCSP_nonce_new(void *p, unsigned int len);

X509_EXTENSION *OCSP_crlID_new(char *url, long *n, char *tim);

X509_EXTENSION *OCSP_accept_responses_new(char **oids);

X509_EXTENSION *OCSP_archive_cutoff_new(char* tim);

X509_EXTENSION *OCSP_url_svcloc_new(X509_NAME* issuer, char **urls);

int OCSP_REQUEST_get_ext_count(OCSP_REQUEST *x);
int OCSP_REQUEST_get_ext_by_NID(OCSP_REQUEST *x, int nid, int lastpos);
int OCSP_REQUEST_get_ext_by_OBJ(OCSP_REQUEST *x, ASN1_OBJECT *obj, int lastpos);
int OCSP_REQUEST_get_ext_by_critical(OCSP_REQUEST *x, int crit, int lastpos);
X509_EXTENSION *OCSP_REQUEST_get_ext(OCSP_REQUEST *x, int loc);
X509_EXTENSION *OCSP_REQUEST_delete_ext(OCSP_REQUEST *x, int loc);
void *OCSP_REQUEST_get1_ext_d2i(OCSP_REQUEST *x, int nid, int *crit, int *idx);
int OCSP_REQUEST_add1_ext_i2d(OCSP_REQUEST *x, int nid, void *value, int crit,
							unsigned long flags);
int OCSP_REQUEST_add_ext(OCSP_REQUEST *x, X509_EXTENSION *ex, int loc);

int OCSP_ONEREQ_get_ext_count(OCSP_ONEREQ *x);
int OCSP_ONEREQ_get_ext_by_NID(OCSP_ONEREQ *x, int nid, int lastpos);
int OCSP_ONEREQ_get_ext_by_OBJ(OCSP_ONEREQ *x, ASN1_OBJECT *obj, int lastpos);
int OCSP_ONEREQ_get_ext_by_critical(OCSP_ONEREQ *x, int crit, int lastpos);
X509_EXTENSION *OCSP_ONEREQ_get_ext(OCSP_ONEREQ *x, int loc);
X509_EXTENSION *OCSP_ONEREQ_delete_ext(OCSP_ONEREQ *x, int loc);
void *OCSP_ONEREQ_get1_ext_d2i(OCSP_ONEREQ *x, int nid, int *crit, int *idx);
int OCSP_ONEREQ_add1_ext_i2d(OCSP_ONEREQ *x, int nid, void *value, int crit,
							unsigned long flags);
int OCSP_ONEREQ_add_ext(OCSP_ONEREQ *x, X509_EXTENSION *ex, int loc);

int OCSP_BASICRESP_get_ext_count(OCSP_BASICRESP *x);
int OCSP_BASICRESP_get_ext_by_NID(OCSP_BASICRESP *x, int nid, int lastpos);
int OCSP_BASICRESP_get_ext_by_OBJ(OCSP_BASICRESP *x, ASN1_OBJECT *obj, int lastpos);
int OCSP_BASICRESP_get_ext_by_critical(OCSP_BASICRESP *x, int crit, int lastpos);
X509_EXTENSION *OCSP_BASICRESP_get_ext(OCSP_BASICRESP *x, int loc);
X509_EXTENSION *OCSP_BASICRESP_delete_ext(OCSP_BASICRESP *x, int loc);
void *OCSP_BASICRESP_get1_ext_d2i(OCSP_BASICRESP *x, int nid, int *crit, int *idx);
int OCSP_BASICRESP_add1_ext_i2d(OCSP_BASICRESP *x, int nid, void *value, int crit,
							unsigned long flags);
int OCSP_BASICRESP_add_ext(OCSP_BASICRESP *x, X509_EXTENSION *ex, int loc);

int OCSP_SINGLERESP_get_ext_count(OCSP_SINGLERESP *x);
int OCSP_SINGLERESP_get_ext_by_NID(OCSP_SINGLERESP *x, int nid, int lastpos);
int OCSP_SINGLERESP_get_ext_by_OBJ(OCSP_SINGLERESP *x, ASN1_OBJECT *obj, int lastpos);
int OCSP_SINGLERESP_get_ext_by_critical(OCSP_SINGLERESP *x, int crit, int lastpos);
X509_EXTENSION *OCSP_SINGLERESP_get_ext(OCSP_SINGLERESP *x, int loc);
X509_EXTENSION *OCSP_SINGLERESP_delete_ext(OCSP_SINGLERESP *x, int loc);
void *OCSP_SINGLERESP_get1_ext_d2i(OCSP_SINGLERESP *x, int nid, int *crit, int *idx);
int OCSP_SINGLERESP_add1_ext_i2d(OCSP_SINGLERESP *x, int nid, void *value, int crit,
							unsigned long flags);
int OCSP_SINGLERESP_add_ext(OCSP_SINGLERESP *x, X509_EXTENSION *ex, int loc);

DECLARE_ASN1_FUNCTIONS(OCSP_SINGLERESP)
DECLARE_ASN1_FUNCTIONS(OCSP_CERTSTATUS)
DECLARE_ASN1_FUNCTIONS(OCSP_REVOKEDINFO)
DECLARE_ASN1_FUNCTIONS(OCSP_BASICRESP)
DECLARE_ASN1_FUNCTIONS(OCSP_RESPDATA)
DECLARE_ASN1_FUNCTIONS(OCSP_RESPID)
DECLARE_ASN1_FUNCTIONS(OCSP_RESPONSE)
DECLARE_ASN1_FUNCTIONS(OCSP_RESPBYTES)
DECLARE_ASN1_FUNCTIONS(OCSP_ONEREQ)
DECLARE_ASN1_FUNCTIONS(OCSP_CERTID)
DECLARE_ASN1_FUNCTIONS(OCSP_REQUEST)
DECLARE_ASN1_FUNCTIONS(OCSP_SIGNATURE)
DECLARE_ASN1_FUNCTIONS(OCSP_REQINFO)
DECLARE_ASN1_FUNCTIONS(OCSP_CRLID)
DECLARE_ASN1_FUNCTIONS(OCSP_SERVICELOC)

int OCSP_REQUEST_print(BIO *bp, OCSP_REQUEST* a, unsigned long flags);


void ERR_load_OCSP_strings(void);

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

/* Error codes for the OCSP functions. */

/* Function codes. */
#define OCSP_F_ASN1_STRING_ENCODE			 106
#define OCSP_F_BASIC_RESPONSE_NEW			 100
#define OCSP_F_BASIC_RESPONSE_VERIFY			 101
#define OCSP_F_CERT_ID_NEW				 102
#define OCSP_F_CERT_STATUS_NEW				 103
#define OCSP_F_D2I_OCSP_NONCE				 109
#define OCSP_F_OCSP_SENDREQ_BIO				 110
#define OCSP_F_REQUEST_VERIFY				 104
#define OCSP_F_RESPONSE_VERIFY				 105
#define OCSP_F_S2I_OCSP_NONCE				 107
#define OCSP_F_V2I_OCSP_CRLID				 108

/* Reason codes. */
#define OCSP_R_BAD_DATA					 108
#define OCSP_R_BAD_TAG					 100
#define OCSP_R_DIGEST_ERR				 101
#define OCSP_R_FAILED_TO_OPEN				 109
#define OCSP_R_FAILED_TO_READ				 110
#define OCSP_R_FAILED_TO_STAT				 111
#define OCSP_R_MISSING_VALUE				 112
#define OCSP_R_NO_CERTIFICATE				 102
#define OCSP_R_NO_CONTENT				 115
#define OCSP_R_NO_PUBLIC_KEY				 103
#define OCSP_R_NO_RESPONSE_DATA				 104
#define OCSP_R_NO_SIGNATURE				 105
#define OCSP_R_REVOKED_NO_TIME				 106
#define OCSP_R_SERVER_READ_ERROR			 116
#define OCSP_R_SERVER_RESPONSE_ERROR			 117
#define OCSP_R_SERVER_RESPONSE_PARSE_ERROR		 118
#define OCSP_R_SERVER_WRITE_ERROR			 119
#define OCSP_R_UNKNOWN_NID				 107
#define OCSP_R_UNSUPPORTED_OPTION			 113
#define OCSP_R_VALUE_ALREADY				 114

#ifdef  __cplusplus
}
#endif
#endif


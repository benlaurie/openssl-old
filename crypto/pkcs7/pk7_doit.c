/* crypto/pkcs7/pk7_doit.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
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
#include "cryptlib.h"
#include "rand.h"
#include "objects.h"
#include "x509.h"

static int add_attribute(STACK **sk, int nid, int atrtype, char *value);
static ASN1_TYPE *get_attribute(STACK *sk, int nid);

#if 1
BIO *PKCS7_dataInit(p7,bio)
PKCS7 *p7;
BIO *bio;
	{
	int i,j;
	BIO *out=NULL,*btmp=NULL;
	X509_ALGOR *xa;
	EVP_MD *evp_md;
	EVP_CIPHER *evp_cipher=NULL;
	STACK *md_sk=NULL,*rsk=NULL;
	X509_ALGOR *xalg=NULL;
	PKCS7_RECIP_INFO *ri=NULL;
	EVP_PKEY *pkey;

	i=OBJ_obj2nid(p7->type);
	p7->state=PKCS7_S_HEADER;

	switch (i)
		{
	case NID_pkcs7_signed:
		md_sk=p7->d.sign->md_algs;
		break;
	case NID_pkcs7_signedAndEnveloped:
		rsk=p7->d.signed_and_enveloped->recipientinfo;
		md_sk=p7->d.signed_and_enveloped->md_algs;
		evp_cipher=EVP_get_cipherbyname(OBJ_nid2sn(OBJ_obj2nid(p7->d.signed_and_enveloped->enc_data->algorithm->algorithm)));
		if (evp_cipher == NULL)
			{
			PKCS7err(PKCS7_F_PKCS7_DATAINIT,PKCS7_R_UNSUPPORTED_CIPHER_TYPE);
			goto err;
			}
		xalg=p7->d.signed_and_enveloped->enc_data->algorithm;
		break;
	case NID_pkcs7_enveloped:
		rsk=p7->d.enveloped->recipientinfo;
		evp_cipher=EVP_get_cipherbyname(OBJ_nid2sn(OBJ_obj2nid(p7->d.enveloped->enc_data->algorithm->algorithm)));
		if (evp_cipher == NULL)
			{
			PKCS7err(PKCS7_F_PKCS7_DATAINIT,PKCS7_R_UNSUPPORTED_CIPHER_TYPE);
			goto err;
			}
		xalg=p7->d.enveloped->enc_data->algorithm;
		break;
	default:
		PKCS7err(PKCS7_F_PKCS7_DATAINIT,PKCS7_R_UNSUPPORTED_CONTENT_TYPE);
	        goto err;
		}

	if (md_sk != NULL)
		{
		for (i=0; i<sk_num(md_sk); i++)
			{
			xa=(X509_ALGOR *)sk_value(md_sk,i);
			if ((btmp=BIO_new(BIO_f_md())) == NULL)
				{
				PKCS7err(PKCS7_F_PKCS7_DATAINIT,ERR_R_BIO_LIB);
				goto err;
				}

			j=OBJ_obj2nid(xa->algorithm);
			evp_md=EVP_get_digestbyname(OBJ_nid2sn(j));
			if (evp_md == NULL)
				{
				PKCS7err(PKCS7_F_PKCS7_DATAINIT,PKCS7_R_UNKNOWN_DIGEST_TYPE);
				goto err;
				}

			BIO_set_md(btmp,evp_md);
			if (out == NULL)
				out=btmp;
			else
				BIO_push(out,btmp);
			btmp=NULL;
			}
		}

	if (evp_cipher != NULL)
		{
		unsigned char key[EVP_MAX_KEY_LENGTH];
		unsigned char iv[EVP_MAX_IV_LENGTH];
		int keylen,ivlen;
		int jj,max;
		unsigned char *tmp;

		if ((btmp=BIO_new(BIO_f_cipher())) == NULL)
			{
			PKCS7err(PKCS7_F_PKCS7_DATAINIT,ERR_R_BIO_LIB);
			goto err;
			}
		keylen=EVP_CIPHER_key_length(evp_cipher);
		ivlen=EVP_CIPHER_iv_length(evp_cipher);

		if (ivlen > 0)
			{
			ASN1_OCTET_STRING *os;

			RAND_bytes(iv,ivlen);
			os=ASN1_OCTET_STRING_new();
			ASN1_OCTET_STRING_set(os,iv,ivlen);
/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX this needs to change */
			if (xalg->parameter == NULL)
				xalg->parameter=ASN1_TYPE_new();
			ASN1_TYPE_set(xalg->parameter,V_ASN1_OCTET_STRING,
				(char *)os);
			}
		RAND_bytes(key,keylen);

		/* Lets do the pub key stuff :-) */
		max=0;
		for (i=0; i<sk_num(rsk); i++)
			{
			ri=(PKCS7_RECIP_INFO *)sk_value(rsk,i);
			if (ri->cert == NULL)
				{
				PKCS7err(PKCS7_F_PKCS7_DATAINIT,PKCS7_R_MISSING_CERIPEND_INFO);
				goto err;
				}
			pkey=X509_get_pubkey(ri->cert);
			jj=EVP_PKEY_size(pkey);
			EVP_PKEY_free(pkey);
			if (max < jj) max=jj;
			}
		if ((tmp=(unsigned char *)Malloc(max)) == NULL)
			{
			PKCS7err(PKCS7_F_PKCS7_DATAINIT,ERR_R_MALLOC_FAILURE);
			goto err;
			}
		for (i=0; i<sk_num(rsk); i++)
			{
			ri=(PKCS7_RECIP_INFO *)sk_value(rsk,i);
			pkey=X509_get_pubkey(ri->cert);
			jj=EVP_PKEY_encrypt(tmp,key,keylen,pkey);
			EVP_PKEY_free(pkey);
			if (jj <= 0)
				{
				PKCS7err(PKCS7_F_PKCS7_DATAINIT,ERR_R_EVP_LIB);
				Free(tmp);
				goto err;
				}
			ASN1_OCTET_STRING_set(ri->enc_key,tmp,jj);
			}
		Free(tmp);

		BIO_set_cipher(btmp,evp_cipher,key,iv,1);

		if (out == NULL)
			out=btmp;
		else
			BIO_push(out,btmp);
		btmp=NULL;
		}

	if (bio == NULL) /* ??????????? */
		{
		if (p7->detached)
			bio=BIO_new(BIO_s_null());
		else
			{
			bio=BIO_new(BIO_s_mem());
			/* We need to set this so that when we have read all
			 * the data, the encrypt BIO, if present, will read
			 * EOF and encode the last few bytes */
			BIO_set_mem_eof_return(bio,0);

			if (PKCS7_type_is_signed(p7) &&
				PKCS7_type_is_data(p7->d.sign->contents))
				{
				ASN1_OCTET_STRING *os;

				os=p7->d.sign->contents->d.data;
				if (os->length > 0)
					BIO_write(bio,(char *)os->data,
						os->length);
				}
			}
		}
	BIO_push(out,bio);
	bio=NULL;
	if (0)
		{
err:
		if (out != NULL)
			BIO_free_all(out);
		if (btmp != NULL)
			BIO_free_all(btmp);
		out=NULL;
		}
	return(out);
	}

/* int */
BIO *PKCS7_dataDecode(p7,pkey,in_bio,xs)
PKCS7 *p7;
EVP_PKEY *pkey;
BIO *in_bio;
X509_STORE *xs;
	{
	int i,j;
	BIO *out=NULL,*btmp=NULL,*etmp=NULL,*bio=NULL;
	char *tmp=NULL;
	X509_ALGOR *xa;
	ASN1_OCTET_STRING *data_body=NULL;
	EVP_MD *evp_md;
	EVP_CIPHER *evp_cipher=NULL;
	EVP_CIPHER_CTX *evp_ctx=NULL;
	X509_ALGOR *enc_alg=NULL;
	STACK *md_sk=NULL,*rsk=NULL;
	X509_ALGOR *xalg=NULL;
	PKCS7_RECIP_INFO *ri=NULL;
/*	EVP_PKEY *pkey; */
#if 0
	X509_STORE_CTX s_ctx;
#endif

	i=OBJ_obj2nid(p7->type);
	p7->state=PKCS7_S_HEADER;

	switch (i)
		{
	case NID_pkcs7_signed:
		data_body=p7->d.sign->contents->d.data;
		md_sk=p7->d.sign->md_algs;
		break;
	case NID_pkcs7_signedAndEnveloped:
		rsk=p7->d.signed_and_enveloped->recipientinfo;
		md_sk=p7->d.signed_and_enveloped->md_algs;
		data_body=p7->d.signed_and_enveloped->enc_data->enc_data;
		enc_alg=p7->d.signed_and_enveloped->enc_data->algorithm;
		evp_cipher=EVP_get_cipherbyname(OBJ_nid2sn(OBJ_obj2nid(enc_alg->algorithm)));
		if (evp_cipher == NULL)
			{
			PKCS7err(PKCS7_F_PKCS7_SIGNENVELOPEDECRYPT,PKCS7_R_UNSUPPORTED_CIPHER_TYPE);
			goto err;
			}
		xalg=p7->d.signed_and_enveloped->enc_data->algorithm;
		break;
	case NID_pkcs7_enveloped:
		rsk=p7->d.enveloped->recipientinfo;
		enc_alg=p7->d.enveloped->enc_data->algorithm;
		data_body=p7->d.enveloped->enc_data->enc_data;
		evp_cipher=EVP_get_cipherbyname(OBJ_nid2sn(OBJ_obj2nid(enc_alg->algorithm)));
		if (evp_cipher == NULL)
			{
			PKCS7err(PKCS7_F_PKCS7_SIGNENVELOPEDECRYPT,PKCS7_R_UNSUPPORTED_CIPHER_TYPE);
			goto err;
			}
		xalg=p7->d.enveloped->enc_data->algorithm;
		break;
	default:
		PKCS7err(PKCS7_F_PKCS7_SIGNENVELOPEDECRYPT,PKCS7_R_UNSUPPORTED_CONTENT_TYPE);
	        goto err;
		}

	/* We will be checking the signature */
	if (md_sk != NULL)
		{
		for (i=0; i<sk_num(md_sk); i++)
			{
			xa=(X509_ALGOR *)sk_value(md_sk,i);
			if ((btmp=BIO_new(BIO_f_md())) == NULL)
				{
				PKCS7err(PKCS7_F_PKCS7_SIGNENVELOPEDECRYPT,ERR_R_BIO_LIB);
				goto err;
				}

			j=OBJ_obj2nid(xa->algorithm);
			evp_md=EVP_get_digestbyname(OBJ_nid2sn(j));
			if (evp_md == NULL)
				{
				PKCS7err(PKCS7_F_PKCS7_SIGNENVELOPEDECRYPT,PKCS7_R_UNKNOWN_DIGEST_TYPE);
				goto err;
				}

			BIO_set_md(btmp,evp_md);
			if (out == NULL)
				out=btmp;
			else
				BIO_push(out,btmp);
			btmp=NULL;
			}
		}

	if (evp_cipher != NULL)
		{
#if 0
		unsigned char key[EVP_MAX_KEY_LENGTH];
		unsigned char iv[EVP_MAX_IV_LENGTH];
		unsigned char *p;
		int keylen,ivlen;
		int max;
		X509_OBJECT ret;
#endif
		int jj;

		if ((etmp=BIO_new(BIO_f_cipher())) == NULL)
			{
			PKCS7err(PKCS7_F_PKCS7_SIGNENVELOPEDECRYPT,ERR_R_BIO_LIB);
			goto err;
			}

		/* It was encrypted, we need to decrypt the secret key
		 * with the private key */

		/* We need to find a private key for one of the people in the
		 * recipentinfo list */
		if (rsk == NULL)
			return(NULL);

		ri=(PKCS7_RECIP_INFO *)sk_value(rsk,0);
#if 0
		X509_STORE_CTX_init(&s_ctx,xs,NULL,NULL);
		for (i=0; i<sk_num(rsk); i++)
			{
			ri=(PKCS7_RECIP_INFO *)sk_value(rsk,i);
			uf (X509_STORE_get_by_issuer_serial(&s_ctx,
				X509_LU_PKEY,
				ri->issuer_and_serial->issuer,
				ri->issuer_and_serial->serial,
				&ret))
				break;
			ri=NULL;
			}
		if (ri == NULL) return(NULL);	
		pkey=ret.data.pkey;
#endif
		if (pkey == NULL)
			{
			return(NULL);
			}

		jj=EVP_PKEY_size(pkey);
		tmp=Malloc(jj+10);
		if (tmp == NULL)
			{
			PKCS7err(PKCS7_F_PKCS7_SIGNENVELOPEDECRYPT,ERR_R_MALLOC_FAILURE);
			goto err;
			}

		jj=EVP_PKEY_decrypt((unsigned char *)tmp,
			ASN1_STRING_data(ri->enc_key),
			ASN1_STRING_length(ri->enc_key),
			pkey);
		if (jj <= 0)
			{
			PKCS7err(PKCS7_F_PKCS7_SIGNENVELOPEDECRYPT,ERR_R_EVP_LIB);
			goto err;
			}

		evp_ctx=NULL;
		BIO_get_cipher_ctx(etmp,&evp_ctx);
		EVP_CipherInit(evp_ctx,evp_cipher,NULL,NULL,0);
		if (EVP_CIPHER_asn1_to_param(evp_ctx,enc_alg->parameter) < 0)
			return(NULL);

		if (jj != EVP_CIPHER_CTX_key_length(evp_ctx))
			{
			PKCS7err(PKCS7_F_PKCS7_SIGNENVELOPEDECRYPT,PKCS7_R_DECRYPTED_KEY_IS_WRONG_LENGTH);
			goto err;
			}
		EVP_CipherInit(evp_ctx,NULL,(unsigned char *)tmp,NULL,0);

		memset(tmp,0,jj);

		if (out == NULL)
			out=etmp;
		else
			BIO_push(out,etmp);
		etmp=NULL;
		}

#if 1
	if (p7->detached || (in_bio != NULL))
		{
		bio=in_bio;
		}
	else 
		{
		bio=BIO_new(BIO_s_mem());
		/* We need to set this so that when we have read all
		 * the data, the encrypt BIO, if present, will read
		 * EOF and encode the last few bytes */
		BIO_set_mem_eof_return(bio,0);

		if (data_body->length > 0)
			BIO_write(bio,(char *)data_body->data,data_body->length);
		}
	BIO_push(out,bio);
	bio=NULL;
#endif
	if (0)
		{
err:
		if (out != NULL) BIO_free_all(out);
		if (btmp != NULL) BIO_free_all(btmp);
		if (etmp != NULL) BIO_free_all(etmp);
		if (bio != NULL) BIO_free_all(bio);
		out=NULL;
		}
	if (tmp != NULL)
		Free(tmp);
	return(out);
	}
#endif

int PKCS7_dataFinal(p7,bio)
PKCS7 *p7;
BIO *bio;
	{
	int ret=0;
	int i,j;
	BIO *btmp;
	BUF_MEM *buf_mem=NULL;
	BUF_MEM *buf=NULL;
	PKCS7_SIGNER_INFO *si;
	EVP_MD_CTX *mdc,ctx_tmp;
	STACK *sk,*si_sk=NULL;
	unsigned char *p,*pp=NULL;
	int x;
	ASN1_OCTET_STRING *os=NULL;

	i=OBJ_obj2nid(p7->type);
	p7->state=PKCS7_S_HEADER;

	switch (i)
		{
	case NID_pkcs7_signedAndEnveloped:
		/* XXXXXXXXXXXXXXXX */
		si_sk=p7->d.signed_and_enveloped->signer_info;
		os=ASN1_OCTET_STRING_new();
		p7->d.signed_and_enveloped->enc_data->enc_data=os;
		break;
	case NID_pkcs7_enveloped:
		/* XXXXXXXXXXXXXXXX */
		os=ASN1_OCTET_STRING_new();
		p7->d.enveloped->enc_data->enc_data=os;
		break;
	case NID_pkcs7_signed:
		si_sk=p7->d.sign->signer_info;
		os=p7->d.sign->contents->d.data;
		/* If detached data then the content is excluded */
		if(p7->detached) {
			ASN1_OCTET_STRING_free(os);
			p7->d.sign->contents->d.data = NULL;
		}
		break;
		}

	if (si_sk != NULL)
		{
		if ((buf=BUF_MEM_new()) == NULL)
			{
			PKCS7err(PKCS7_F_PKCS7_DATASIGN,ERR_R_BIO_LIB);
			goto err;
			}
		for (i=0; i<sk_num(si_sk); i++)
			{
			si=(PKCS7_SIGNER_INFO *)
				sk_value(si_sk,i);
			if (si->pkey == NULL) continue;

			j=OBJ_obj2nid(si->digest_alg->algorithm);

			btmp=bio;
			for (;;)
				{
				if ((btmp=BIO_find_type(btmp,BIO_TYPE_MD)) 
					== NULL)
					{
					PKCS7err(PKCS7_F_PKCS7_DATASIGN,PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST);
					goto err;
					}
				BIO_get_md_ctx(btmp,&mdc);
				if (mdc == NULL)
					{
					PKCS7err(PKCS7_F_PKCS7_DATASIGN,PKCS7_R_INTERNAL_ERROR);
					goto err;
					}
				if (EVP_MD_type(EVP_MD_CTX_type(mdc)) == j)
					break;
				else
					btmp=btmp->next_bio;
				}
			
			/* We now have the EVP_MD_CTX, lets do the
			 * signing. */
			memcpy(&ctx_tmp,mdc,sizeof(ctx_tmp));
			if (!BUF_MEM_grow(buf,EVP_PKEY_size(si->pkey)))
				{
				PKCS7err(PKCS7_F_PKCS7_DATASIGN,ERR_R_BIO_LIB);
				goto err;
				}

			sk=si->auth_attr;

			/* If there are attributes, we add the digest
			 * attribute and only sign the attributes */
			if ((sk != NULL) && (sk_num(sk) != 0))
				{
				unsigned char md_data[EVP_MAX_MD_SIZE];
				unsigned int md_len;
				ASN1_OCTET_STRING *digest;
				ASN1_UTCTIME *sign_time;
				EVP_MD *md_tmp;

				/* Add signing time */
				sign_time=X509_gmtime_adj(NULL,0);
				PKCS7_add_signed_attribute(si,
					NID_pkcs9_signingTime,
					V_ASN1_UTCTIME,(char *)sign_time);

				/* Add digest */
				md_tmp=EVP_MD_CTX_type(&ctx_tmp);
				EVP_DigestFinal(&ctx_tmp,md_data,&md_len);
				digest=ASN1_OCTET_STRING_new();
				ASN1_OCTET_STRING_set(digest,md_data,md_len);
				PKCS7_add_signed_attribute(si,NID_pkcs9_messageDigest,
					V_ASN1_OCTET_STRING,(char *)digest);

				/* Now sign the mess */
				EVP_SignInit(&ctx_tmp,md_tmp);
				x=i2d_ASN1_SET(sk,NULL,i2d_X509_ATTRIBUTE,
					V_ASN1_SET,V_ASN1_UNIVERSAL, IS_SET);
				pp=(unsigned char *)Malloc(x);
				p=pp;
				i2d_ASN1_SET(sk,&p,i2d_X509_ATTRIBUTE,
					V_ASN1_SET,V_ASN1_UNIVERSAL, IS_SET);
				EVP_SignUpdate(&ctx_tmp,pp,x);
				Free(pp);
				pp=NULL;
				}

			if (si->pkey->type == EVP_PKEY_DSA)
				ctx_tmp.digest=EVP_dss1();

			if (!EVP_SignFinal(&ctx_tmp,(unsigned char *)buf->data,
				(unsigned int *)&buf->length,si->pkey))
				{
				PKCS7err(PKCS7_F_PKCS7_DATASIGN,ERR_R_EVP_LIB);
				goto err;
				}
			if (!ASN1_STRING_set(si->enc_digest,
				(unsigned char *)buf->data,buf->length))
				{
				PKCS7err(PKCS7_F_PKCS7_DATASIGN,ERR_R_ASN1_LIB);
				goto err;
				}
			}
		}

	if (!p7->detached)
		{
		btmp=BIO_find_type(bio,BIO_TYPE_MEM);
		if (btmp == NULL)
			{
			PKCS7err(PKCS7_F_PKCS7_DATASIGN,PKCS7_R_UNABLE_TO_FIND_MEM_BIO);
			goto err;
			}
		BIO_get_mem_ptr(btmp,&buf_mem);
		ASN1_OCTET_STRING_set(os,
			(unsigned char *)buf_mem->data,buf_mem->length);
		}
	if (pp != NULL) Free(pp);
	pp=NULL;

	ret=1;
err:
	if (buf != NULL) BUF_MEM_free(buf);
	return(ret);
	}

int PKCS7_dataVerify(cert_store,ctx,bio,p7,si)
X509_STORE *cert_store;
X509_STORE_CTX *ctx;
BIO *bio;
PKCS7 *p7;
PKCS7_SIGNER_INFO *si;
	{
/*	PKCS7_SIGNED *s; */
	ASN1_OCTET_STRING *os;
	EVP_MD_CTX mdc_tmp,*mdc;
	unsigned char *pp,*p;
	PKCS7_ISSUER_AND_SERIAL *ias;
	int ret=0,i;
	int md_type;
	STACK *sk;
	STACK_OF(X509) *cert;
	BIO *btmp;
	X509 *x509;
	EVP_PKEY *pkey;

	if (PKCS7_type_is_signed(p7))
		{
		cert=p7->d.sign->cert;
		}
	else if (PKCS7_type_is_signedAndEnveloped(p7))
		{
		cert=p7->d.signed_and_enveloped->cert;
		}
	else
		{
		PKCS7err(PKCS7_F_PKCS7_DATAVERIFY,PKCS7_R_WRONG_PKCS7_TYPE);
		goto err;
		}
	/* XXXXXXXXXXXXXXXXXXXXXXX */
	ias=si->issuer_and_serial;

	x509=X509_find_by_issuer_and_serial(cert,ias->issuer,ias->serial);

	/* were we able to find the cert in passed to us */
	if (x509 == NULL)
		{
		PKCS7err(PKCS7_F_PKCS7_DATAVERIFY,PKCS7_R_UNABLE_TO_FIND_CERTIFICATE);
		goto err;
		}

	/* Lets verify */
	X509_STORE_CTX_init(ctx,cert_store,x509,cert);
	i=X509_verify_cert(ctx);
	if (i <= 0) 
		{
		PKCS7err(PKCS7_F_PKCS7_DATAVERIFY,ERR_R_X509_LIB);
		goto err;
		}
	X509_STORE_CTX_cleanup(ctx);

	/* So we like 'x509', lets check the signature. */
	md_type=OBJ_obj2nid(si->digest_alg->algorithm);

	btmp=bio;
	for (;;)
		{
		if ((btmp == NULL) ||
			((btmp=BIO_find_type(btmp,BIO_TYPE_MD)) == NULL))
			{
			PKCS7err(PKCS7_F_PKCS7_DATAVERIFY,PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST);
			goto err;
			}
		BIO_get_md_ctx(btmp,&mdc);
		if (mdc == NULL)
			{
			PKCS7err(PKCS7_F_PKCS7_DATAVERIFY,PKCS7_R_INTERNAL_ERROR);
			goto err;
			}
		if (EVP_MD_type(EVP_MD_CTX_type(mdc)) == md_type)
			break;
		btmp=btmp->next_bio;	
		}

	/* mdc is the digest ctx that we want, unless there are attributes,
	 * in which case the digest is the signed attributes */
	memcpy(&mdc_tmp,mdc,sizeof(mdc_tmp));

	sk=si->auth_attr;
	if ((sk != NULL) && (sk_num(sk) != 0))
		{
		unsigned char md_dat[EVP_MAX_MD_SIZE];
                unsigned int md_len;
		ASN1_OCTET_STRING *message_digest;

		EVP_DigestFinal(&mdc_tmp,md_dat,&md_len);
		message_digest=PKCS7_digest_from_attributes(sk);
		if (!message_digest)
			{
			PKCS7err(PKCS7_F_PKCS7_DATAVERIFY,PKCS7_R_UNABLE_TO_FIND_MESSAGE_DIGEST);
			goto err;
			}
		if ((message_digest->length != (int)md_len) ||
			(memcmp(message_digest->data,md_dat,md_len)))
			{
#if 0
{
int ii;
for (ii=0; ii<message_digest->length; ii++)
	printf("%02X",message_digest->data[ii]); printf(" sent\n");
for (ii=0; ii<md_len; ii++) printf("%02X",md_dat[ii]); printf(" calc\n");
}
#endif
			PKCS7err(PKCS7_F_PKCS7_DATAVERIFY,PKCS7_R_DIGEST_FAILURE);
			ret= -1;
			goto err;
			}

		EVP_VerifyInit(&mdc_tmp,EVP_get_digestbynid(md_type));
		/* Note: when forming the encoding of the attributes we
		 * shouldn't reorder them or this will break the signature.
		 * This is done by using the IS_SEQUENCE flag.
		 */
		i=i2d_ASN1_SET(sk,NULL,i2d_X509_ATTRIBUTE,
			V_ASN1_SET,V_ASN1_UNIVERSAL, IS_SEQUENCE);
		pp=(unsigned char *)Malloc(i);
		p=pp;
		i2d_ASN1_SET(sk,&p,i2d_X509_ATTRIBUTE,
			V_ASN1_SET,V_ASN1_UNIVERSAL, IS_SEQUENCE);
		EVP_VerifyUpdate(&mdc_tmp,pp,i);

		Free(pp);
		}

	os=si->enc_digest;
	pkey = X509_get_pubkey(x509);
	if(pkey->type == EVP_PKEY_DSA) mdc_tmp.digest=EVP_dss1();

	i=EVP_VerifyFinal(&mdc_tmp,os->data,os->length, pkey);
	EVP_PKEY_free(pkey);
	if (i <= 0)
		{
		PKCS7err(PKCS7_F_PKCS7_DATAVERIFY,PKCS7_R_SIGNATURE_FAILURE);
		ret= -1;
		goto err;
		}
	else
		ret=1;
err:
	return(ret);
	}

PKCS7_ISSUER_AND_SERIAL *PKCS7_get_issuer_and_serial(p7,idx)
PKCS7 *p7;
int idx;
	{
	STACK *rsk;
	PKCS7_RECIP_INFO *ri;
	int i;

	i=OBJ_obj2nid(p7->type);
	if (i != NID_pkcs7_signedAndEnveloped) return(NULL);
	rsk=p7->d.signed_and_enveloped->recipientinfo;
	ri=(PKCS7_RECIP_INFO *)sk_value(rsk,0);
	if (sk_num(rsk) <= idx) return(NULL);
	ri=(PKCS7_RECIP_INFO *)sk_value(rsk,idx);
	return(ri->issuer_and_serial);
	}

ASN1_TYPE *PKCS7_get_signed_attribute(si,nid)
PKCS7_SIGNER_INFO *si;
int nid;
	{
	return(get_attribute(si->auth_attr,nid));
	}

ASN1_TYPE *PKCS7_get_attribute(si,nid)
PKCS7_SIGNER_INFO *si;
int nid;
	{
	return(get_attribute(si->unauth_attr,nid));
	}

static ASN1_TYPE *get_attribute(sk,nid)
STACK *sk;
int nid;
	{
	int i;
	X509_ATTRIBUTE *xa;
	ASN1_OBJECT *o;

	o=OBJ_nid2obj(nid);
	if (o == NULL) return(NULL);
	for (i=0; i<sk_num(sk); i++)
		{
		xa=(X509_ATTRIBUTE *)sk_value(sk,i);
		if (OBJ_cmp(xa->object,o) == 0)
			{
			if (xa->set && sk_num(xa->value.set))
				return((ASN1_TYPE *)sk_value(xa->value.set,0));
			else
				return(NULL);
			}
		}
	return(NULL);
	}

ASN1_OCTET_STRING *PKCS7_digest_from_attributes(sk)
STACK *sk;
	{
	X509_ATTRIBUTE *attr;
	ASN1_TYPE *astype;
	int i;
	if (!sk || !sk_num(sk)) return NULL;
	/* Search the attributes for a digest */
	for (i = 0; i < sk_num(sk); i++)
		{
		attr = (X509_ATTRIBUTE *) sk_value(sk, i);
		if (OBJ_obj2nid(attr->object) == NID_pkcs9_messageDigest)
			{
			if (!attr->set) return NULL;
			if (!attr->value.set ||
				 !sk_num (attr->value.set) ) return NULL;
			astype = (ASN1_TYPE *) sk_value(attr->value.set, 0);
			return astype->value.octet_string;
			}
		}
	return NULL;
	}

int PKCS7_set_signed_attributes(p7si,sk)
PKCS7_SIGNER_INFO *p7si;
STACK *sk;
	{
	int i;

	if (p7si->auth_attr != NULL)
		sk_pop_free(p7si->auth_attr,X509_ATTRIBUTE_free);
	p7si->auth_attr=sk_dup(sk);
	for (i=0; i<sk_num(sk); i++)
		{
		if ((sk_value(p7si->auth_attr,i)=(char *)X509_ATTRIBUTE_dup(
			(X509_ATTRIBUTE *)sk_value(sk,i))) == NULL)
			return(0);
		}
	return(1);
	}

int PKCS7_set_attributes(p7si,sk)
PKCS7_SIGNER_INFO *p7si;
STACK *sk;
	{
	int i;

	if (p7si->unauth_attr != NULL)
		sk_pop_free(p7si->unauth_attr,X509_ATTRIBUTE_free);
	p7si->unauth_attr=sk_dup(sk);
	for (i=0; i<sk_num(sk); i++)
		{
		if ((sk_value(p7si->unauth_attr,i)=(char *)X509_ATTRIBUTE_dup(
			(X509_ATTRIBUTE *)sk_value(sk,i))) == NULL)
			return(0);
		}
	return(1);
	}

int PKCS7_add_signed_attribute(p7si,nid,atrtype,value)
PKCS7_SIGNER_INFO *p7si;
int nid;
int atrtype;
char *value;
	{
	return(add_attribute(&(p7si->auth_attr),nid,atrtype,value));
	}

int PKCS7_add_attribute(p7si,nid,atrtype,value)
PKCS7_SIGNER_INFO *p7si;
int nid;
int atrtype;
char *value;
	{
	return(add_attribute(&(p7si->unauth_attr),nid,atrtype,value));
	}

static int add_attribute(sk, nid, atrtype, value)
STACK **sk;
int nid;
int atrtype;
char *value;
	{
	X509_ATTRIBUTE *attr=NULL;

	if (*sk == NULL)
		{
		*sk = sk_new(NULL);
new_attrib:
		attr=X509_ATTRIBUTE_create(nid,atrtype,value);
		sk_push(*sk,(char *)attr);
		}
	else
		{
		int i;

		for (i=0; i<sk_num(*sk); i++)
			{
			attr=(X509_ATTRIBUTE *)sk_value(*sk,i);
			if (OBJ_obj2nid(attr->object) == nid)
				{
				X509_ATTRIBUTE_free(attr);
				attr=X509_ATTRIBUTE_create(nid,atrtype,value);
				sk_value(*sk,i)=(char *)attr;
				goto end;
				}
			}
		goto new_attrib;
		}
end:
	return(1);
	}


/* crypto/cms/cms_smime.c */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
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
 */

#include "cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/cms.h>
#include "cms_lcl.h"

static int cms_copy_content(BIO *out, BIO *in, unsigned int flags)
	{
	unsigned char buf[4096];
	int r = 0, i;
	BIO *tmpout = NULL;

	if(flags & CMS_TEXT)
		{
		tmpout = BIO_new(BIO_s_mem());
		if(!tmpout)
			{
			CMSerr(CMS_F_CMS_COPY_CONTENT,ERR_R_MALLOC_FAILURE);
			goto err;
			}
		}
	else
		tmpout = out;

	/* Read all content through chain to process digest, decrypt etc */
	for (;;)
	{
		i=BIO_read(in,buf,sizeof(buf));
		if (i <= 0)
			{
			if (BIO_method_type(in) == BIO_TYPE_CIPHER)
				{
				if (!BIO_get_cipher_status(in))
					goto err;
				}
			break;
			}
				
		if (tmpout)
			BIO_write(tmpout, buf, i);
	}

	if(flags & CMS_TEXT)
		{
		if(!SMIME_text(tmpout, out))
			{
			CMSerr(CMS_F_CMS_COPY_CONTENT,CMS_R_SMIME_TEXT_ERROR);
			goto err;
			}
		}

	r = 1;

	err:
	if (tmpout && (tmpout != out))
		BIO_free(tmpout);
	return r;

	}

static int check_content(CMS_ContentInfo *cms)
	{
	ASN1_OCTET_STRING **pos = CMS_get0_content(cms);
	if (!pos || !*pos)
		{
		CMSerr(CMS_F_CHECK_CONTENT, CMS_R_NO_CONTENT);
		return 0;
		}
	return 1;
	}

int CMS_data(CMS_ContentInfo *cms, BIO *out, unsigned int flags)
	{
	BIO *cont;
	int r;
	if (OBJ_obj2nid(CMS_get0_type(cms)) != NID_pkcs7_data)
		{
		CMSerr(CMS_F_CMS_DATA, CMS_R_TYPE_NOT_DATA);
		return 0;
		}
	cont = CMS_dataInit(cms, NULL);
	if (!cont)
		return 0;
	r = cms_copy_content(out, cont, flags);
	BIO_free_all(cont);
	return r;
	}

CMS_ContentInfo *CMS_data_create(BIO *in, unsigned int flags)
	{
	CMS_ContentInfo *cms;
	cms = cms_Data_create();
	if (!cms)
		return NULL;

	if ((flags & CMS_STREAM) || CMS_final(cms, in, flags))
		return cms;

	CMS_ContentInfo_free(cms);

	return NULL;
	}

int CMS_digest_verify(CMS_ContentInfo *cms, BIO *dcont, BIO *out,
							unsigned int flags)
	{
	BIO *cont;
	int r;
	if (OBJ_obj2nid(CMS_get0_type(cms)) != NID_pkcs7_digest)
		{
		CMSerr(CMS_F_CMS_DIGEST_VERIFY, CMS_R_TYPE_NOT_DIGESTED_DATA);
		return 0;
		}

	if (!dcont && !check_content(cms))
		return 0;

	cont = CMS_dataInit(cms, dcont);
	if (!cont)
		return 0;
	r = cms_copy_content(out, cont, flags);
	if (r)
		r = cms_DigestedData_do_final(cms, cont, 1);
	BIO_free_all(cont);
	return r;
	}

CMS_ContentInfo *CMS_digest_create(BIO *in, const EVP_MD *md,
					unsigned int flags)
	{
	CMS_ContentInfo *cms;
	if (!md)
		md = EVP_sha1();
	cms = cms_DigestedData_create(md);
	if (!cms)
		return NULL;

	if(!(flags & CMS_DETACHED))
		CMS_set_detached(cms, 0);

	if ((flags & CMS_STREAM) || CMS_final(cms, in, flags))
		return cms;

	CMS_ContentInfo_free(cms);
	return NULL;
	}

int CMS_EncryptedData_decrypt(CMS_ContentInfo *cms,
				const unsigned char *key, size_t keylen,
				BIO *dcont, BIO *out, unsigned int flags)
	{
	BIO *cont;
	int r;
	if (OBJ_obj2nid(CMS_get0_type(cms)) != NID_pkcs7_encrypted)
		{
		CMSerr(CMS_F_CMS_ENCRYPTEDDATA_DECRYPT,
					CMS_R_TYPE_NOT_ENCRYPTED_DATA);
		return 0;
		}

	if (!dcont && !check_content(cms))
		return 0;

	if (CMS_EncryptedData_set1_key(cms, NULL, key, keylen) <= 0)
		return 0;
	cont = CMS_dataInit(cms, dcont);
	if (!cont)
		return 0;
	r = cms_copy_content(out, cont, flags);
	BIO_free_all(cont);
	return r;
	}

CMS_ContentInfo *CMS_EncryptedData_encrypt(BIO *in, const EVP_CIPHER *cipher,
					const unsigned char *key, size_t keylen,
					unsigned int flags)
	{
	CMS_ContentInfo *cms;
	if (!cipher)
		{
		CMSerr(CMS_F_CMS_ENCRYPTEDDATA_ENCRYPT, CMS_R_NO_CIPHER);
		return NULL;
		}
	cms = CMS_ContentInfo_new();
	if (!cms)
		return NULL;
	if (!CMS_EncryptedData_set1_key(cms, cipher, key, keylen))
		return NULL;

	if(!(flags & CMS_DETACHED))
		CMS_set_detached(cms, 0);

	if ((flags & (CMS_STREAM|CMS_PARTIAL)) || CMS_final(cms, in, flags))
		return cms;

	CMS_ContentInfo_free(cms);
	return NULL;
	}

static int cms_signerinfo_verify_cert(CMS_SignerInfo *si,
					X509_STORE *store,
					STACK_OF(X509) *certs,
					STACK_OF(X509_CRL) *crls,
					unsigned int flags)
	{
	X509_STORE_CTX ctx;
	X509 *signer;
	int i, j, r = 0;
	CMS_SignerInfo_get0_algs(si, NULL, &signer, NULL, NULL);
	if (!X509_STORE_CTX_init(&ctx, store, signer, certs))
		{
		CMSerr(CMS_F_CMS_SIGNERINFO_VERIFY_CERT,
						CMS_R_STORE_INIT_ERROR);
		goto err;
		}
	X509_STORE_CTX_set_purpose(&ctx, X509_PURPOSE_SMIME_SIGN);
	if (crls)
		X509_STORE_CTX_set0_crls(&ctx, crls);

	i = X509_verify_cert(&ctx);
	if (i <= 0)
		{
		j = X509_STORE_CTX_get_error(&ctx);
		CMSerr(CMS_F_CMS_SIGNERINFO_VERIFY_CERT,
						CMS_R_CERTIFICATE_VERIFY_ERROR);
		ERR_add_error_data(2, "Verify error:",
					 X509_verify_cert_error_string(j));
		goto err;
		}
	r = 1;
	err:
	X509_STORE_CTX_cleanup(&ctx);
	return r;

	}

int CMS_verify(CMS_ContentInfo *cms, STACK_OF(X509) *certs,
		 X509_STORE *store, BIO *dcont, BIO *out, unsigned int flags)
	{
	CMS_SignerInfo *si;
	STACK_OF(CMS_SignerInfo) *sinfos;
	STACK_OF(X509) *cms_certs = NULL;
	STACK_OF(X509_CRL) *crls = NULL;
	X509 *signer;
	int i, scount = 0, ret = 0;
	BIO *cmsbio = NULL, *tmpin = NULL;

	if (!dcont && !check_content(cms))
		return 0;

	/* Attempt to find all signer certificates */

	sinfos = CMS_get0_SignerInfos(cms);

	if (sk_CMS_SignerInfo_num(sinfos) <= 0)
		{
		CMSerr(CMS_F_CMS_VERIFY, CMS_R_NO_SIGNERS);
		goto err;
		}

	for (i = 0; i < sk_CMS_SignerInfo_num(sinfos); i++)
		{
		si = sk_CMS_SignerInfo_value(sinfos, i);
		CMS_SignerInfo_get0_algs(si, NULL, &signer, NULL, NULL);
		if (signer)
			scount++;
		}

	if (scount != sk_CMS_SignerInfo_num(sinfos))
		scount += CMS_set1_signers_certs(cms, certs, flags);

	if (scount != sk_CMS_SignerInfo_num(sinfos))
		{
		CMSerr(CMS_F_CMS_VERIFY, CMS_R_SIGNER_CERTIFICATE_NOT_FOUND);
		goto err;
		}

	/* Attempt to verify all signers certs */

	if (!(flags & CMS_NO_SIGNER_CERT_VERIFY))
		{
		cms_certs = CMS_get1_certs(cms);
		crls = CMS_get1_crls(cms);
		for (i = 0; i < sk_CMS_SignerInfo_num(sinfos); i++)
			{
			si = sk_CMS_SignerInfo_value(sinfos, i);
			if (!cms_signerinfo_verify_cert(si, store,
							cms_certs, crls, flags))
				goto err;
			}
		}

	/* Attempt to verify all SignerInfo signed attribute signatures */

	if (!(flags & CMS_NO_ATTR_VERIFY))
		{
		for (i = 0; i < sk_CMS_SignerInfo_num(sinfos); i++)
			{
			si = sk_CMS_SignerInfo_value(sinfos, i);
			if (CMS_signed_get_attr_count(si) < 0)
				continue;
			if (CMS_SignerInfo_verify(si) <= 0)
				goto err;
			}
		}

	/* Performance optimization: if the content is a memory BIO then
	 * store its contents in a temporary read only memory BIO. This
	 * avoids potentially large numbers of slow copies of data which will
	 * occur when reading from a read write memory BIO when signatures
	 * are calculated.
	 */

	if (dcont && (BIO_method_type(dcont) == BIO_TYPE_MEM))
		{
		char *ptr;
		long len;
		len = BIO_get_mem_data(dcont, &ptr);
		tmpin = BIO_new_mem_buf(ptr, len);
		if (tmpin == NULL)
			{
			CMSerr(CMS_F_CMS_VERIFY,ERR_R_MALLOC_FAILURE);
			return 0;
			}
		}
	else
		tmpin = dcont;
		

	cmsbio=CMS_dataInit(cms, tmpin);
	if (!cmsbio)
		goto err;

	if (!cms_copy_content(out, cmsbio, flags))
		goto err;

	if (!(flags & CMS_NO_CONTENT_VERIFY))
		{
		for (i = 0; i < sk_CMS_SignerInfo_num(sinfos); i++)
			{
			si = sk_CMS_SignerInfo_value(sinfos, i);
			if (!CMS_SignerInfo_verify_content(si, cmsbio))
				{
				CMSerr(CMS_F_CMS_VERIFY,
					CMS_R_CONTENT_VERIFY_ERROR);
				goto err;
				}
			}
		}

	ret = 1;

	err:
	
	if (dcont && (tmpin == dcont))
		BIO_pop(cmsbio);
	BIO_free_all(cmsbio);

	if (cms_certs)
		sk_X509_pop_free(cms_certs, X509_free);
	if (crls)
		sk_X509_CRL_pop_free(crls, X509_CRL_free);

	return ret;
	}

CMS_ContentInfo *CMS_sign(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs,
						BIO *data, unsigned int flags)
	{
	CMS_ContentInfo *cms;
	int i;
	cms = CMS_ContentInfo_new();
	if (!cms)
		goto merr;
	if (pkey && !CMS_add1_signer(cms, signcert, pkey, NULL, flags))
		{
		CMSerr(CMS_F_CMS_SIGN, CMS_R_ADD_SIGNER_ERROR);
		goto err;
		}
	for (i = 0; i < sk_X509_num(certs); i++)
		{
		X509 *x = sk_X509_value(certs, i);
		if (!CMS_add1_cert(cms, x))
			goto merr;
		}
	/* If no signer or certs initialize signedData */
	if (!pkey && !i && !CMS_SignedData_init(cms))
		goto merr;

	if(!(flags & CMS_DETACHED))
		CMS_set_detached(cms, 0);

	if ((flags & (CMS_STREAM|CMS_PARTIAL)) || CMS_final(cms, data, flags))
		return cms;

	return cms;

	merr:
	CMSerr(CMS_F_CMS_SIGN, ERR_R_MALLOC_FAILURE);

	err:
	if (cms)
		CMS_ContentInfo_free(cms);
	return NULL;
	}

CMS_ContentInfo *CMS_encrypt(STACK_OF(X509) *certs, BIO *data,
				const EVP_CIPHER *cipher, unsigned int flags)
	{
	CMS_ContentInfo *cms;
	int i;
	X509 *recip;
	cms = CMS_EnvelopedData_create(cipher);
	if (!cms)
		goto merr;
	for (i = 0; i < sk_X509_num(certs); i++)
		{
		recip = sk_X509_value(certs, i);
		if (!CMS_add1_recipient_cert(cms, recip, flags))
			{
			CMSerr(CMS_F_CMS_ENCRYPT, CMS_R_RECIPIENT_ERROR);
			goto err;
			}
		}

	if(!(flags & CMS_DETACHED))
		CMS_set_detached(cms, 0);

	if ((flags & (CMS_STREAM|CMS_PARTIAL)) || CMS_final(cms, data, flags))
		return cms;

	return cms;

	merr:
	CMSerr(CMS_F_CMS_ENCRYPT, ERR_R_MALLOC_FAILURE);
	err:
	if (cms)
		CMS_ContentInfo_free(cms);
	return NULL;
	}
	
int CMS_decrypt(CMS_ContentInfo *cms, EVP_PKEY *pk, X509 *cert,
				BIO *dcont, BIO *out,
				unsigned int flags)
	{
	STACK_OF(CMS_RecipientInfo) *ris;
	CMS_RecipientInfo *ri;
	int i, r;
	BIO *cont;
	if (OBJ_obj2nid(CMS_get0_type(cms)) != NID_pkcs7_enveloped)
		{
		CMSerr(CMS_F_CMS_DECRYPT, CMS_R_TYPE_NOT_ENVELOPED_DATA);
		return 0;
		}
	if (!dcont && !check_content(cms))
		return 0;
	ris = CMS_get0_RecipientInfos(cms);
	for (i = 0; i < sk_CMS_RecipientInfo_num(ris); i++)
		{
		ri = sk_CMS_RecipientInfo_value(ris, i);
		if (CMS_RecipientInfo_type(ri) != CMS_RECIPINFO_TRANS)
			continue;
		/* If we have a cert try matching RecipientInfo otherwise
		 * try them all.
		 */
		if (!cert || (CMS_RecipientInfo_ktri_cert_cmp(ri, cert) == 0))
			{
			if (CMS_RecipientInfo_decrypt(cms, ri, pk) > 0)
				break;
			else if (cert)
				return 0;
			}
		}

	if (i == sk_CMS_RecipientInfo_num(ris))
		{
		CMSerr(CMS_F_CMS_DECRYPT, CMS_R_NO_MATCHING_RECIPIENT);
		return 0;
		}
	cont = CMS_dataInit(cms, dcont);
	if (!cont)
		return 0;
	r = cms_copy_content(out, cont, flags);
	BIO_free_all(cont);
	return r;
	}

int CMS_final(CMS_ContentInfo *cms, BIO *data, int flags)
	{
	BIO *cmsbio;
	int ret = 0;
	if (!(cmsbio = CMS_dataInit(cms, NULL)))
		{
		CMSerr(CMS_F_CMS_FINAL,ERR_R_MALLOC_FAILURE);
		return 0;
		}

	SMIME_crlf_copy(data, cmsbio, flags);

	(void)BIO_flush(cmsbio);


        if (!CMS_dataFinal(cms, cmsbio))
		{
		CMSerr(CMS_F_CMS_FINAL,CMS_R_CMS_DATAFINAL_ERROR);
		goto err;
		}

	ret = 1;

	err:
	BIO_free_all(cmsbio);

	return ret;

	}

#ifdef ZLIB

int CMS_uncompress(CMS_ContentInfo *cms, BIO *dcont, BIO *out,
							unsigned int flags)
	{
	BIO *cont;
	int r;
	if (OBJ_obj2nid(CMS_get0_type(cms)) != NID_id_smime_ct_compressedData)
		{
		CMSerr(CMS_F_CMS_UNCOMPRESS,
					CMS_R_TYPE_NOT_COMPRESSED_DATA);
		return 0;
		}

	if (!dcont && !check_content(cms))
		return 0;

	cont = CMS_dataInit(cms, dcont);
	if (!cont)
		return 0;
	r = cms_copy_content(out, cont, flags);
	BIO_free_all(cont);
	return r;
	}

CMS_ContentInfo *CMS_compress(BIO *in, int comp_nid, unsigned int flags)
	{
	CMS_ContentInfo *cms;
	if (comp_nid <= 0)
		comp_nid = NID_zlib_compression;
	cms = cms_CompressedData_create(comp_nid);
	if (!cms)
		return NULL;

	if(!(flags & CMS_DETACHED))
		CMS_set_detached(cms, 0);

	if ((flags & CMS_STREAM) || CMS_final(cms, in, flags))
		return cms;

	CMS_ContentInfo_free(cms);
	return NULL;
	}

#else

int CMS_uncompress(CMS_ContentInfo *cms, BIO *dcont, BIO *out,
							unsigned int flags)
	{
	CMSerr(CMS_F_CMS_UNCOMPRESS, CMS_R_UNSUPPORTED_COMPRESSION_ALGORITHM);
	return 0;
	}

CMS_ContentInfo *CMS_compress(BIO *in, int comp_nid, unsigned int flags)
	{
	CMSerr(CMS_F_CMS_COMPRESS, CMS_R_UNSUPPORTED_COMPRESSION_ALGORITHM);
	return NULL;
	}

#endif

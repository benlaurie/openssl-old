/*! \file ssl/ssl_cert.c */
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
#include <sys/types.h>
#ifndef WIN32
#include <dirent.h>
#endif
#include <openssl/objects.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include "ssl_locl.h"

int SSL_get_ex_data_X509_STORE_CTX_idx(void)
	{
	static int ssl_x509_store_ctx_idx= -1;

	if (ssl_x509_store_ctx_idx < 0)
		{
		ssl_x509_store_ctx_idx=X509_STORE_CTX_get_ex_new_index(
			0,"SSL for verify callback",NULL,NULL,NULL);
		}
	return(ssl_x509_store_ctx_idx);
	}

CERT *ssl_cert_new(void)
	{
	CERT *ret;

	ret=(CERT *)Malloc(sizeof(CERT));
	if (ret == NULL)
		{
		SSLerr(SSL_F_SSL_CERT_NEW,ERR_R_MALLOC_FAILURE);
		return(NULL);
		}
	memset(ret,0,sizeof(CERT));
/*
	ret->valid=0;
	ret->mask=0;
	ret->export_mask=0;
	ret->cert_type=0;
	ret->key->x509=NULL;
	ret->key->publickey=NULL;
	ret->key->privatekey=NULL; */

	ret->key= &(ret->pkeys[SSL_PKEY_RSA_ENC]);
	ret->references=1;

	return(ret);
	}

void ssl_cert_free(CERT *c)
	{
	int i;

	if(c == NULL)
	    return;

	i=CRYPTO_add(&c->references,-1,CRYPTO_LOCK_SSL_CERT);
#ifdef REF_PRINT
	REF_PRINT("CERT",c);
#endif
	if (i > 0) return;
#ifdef REF_CHECK
	if (i < 0)
		{
		fprintf(stderr,"ssl_cert_free, bad reference count\n");
		abort(); /* ok */
		}
#endif

#ifndef NO_RSA
	if (c->rsa_tmp) RSA_free(c->rsa_tmp);
#endif
#ifndef NO_DH
	if (c->dh_tmp) DH_free(c->dh_tmp);
#endif

	for (i=0; i<SSL_PKEY_NUM; i++)
		{
		if (c->pkeys[i].x509 != NULL)
			X509_free(c->pkeys[i].x509);
		if (c->pkeys[i].privatekey != NULL)
			EVP_PKEY_free(c->pkeys[i].privatekey);
#if 0
		if (c->pkeys[i].publickey != NULL)
			EVP_PKEY_free(c->pkeys[i].publickey);
#endif
		}
	if (c->cert_chain != NULL)
		sk_X509_pop_free(c->cert_chain,X509_free);
	Free(c);
	}

int ssl_cert_instantiate(CERT **o, CERT *d)
	{
	CERT *n;
	if (o == NULL) 
		{
		SSLerr(SSL_F_SSL_CERT_INSTANTIATE, ERR_R_PASSED_NULL_PARAMETER);
		return(0);
		}
	if (*o != NULL && (d == NULL || *o != d))
	    return(1);
	if ((n = ssl_cert_new()) == NULL) 
		{
		SSLerr(SSL_F_SSL_CERT_INSTANTIATE, ERR_R_MALLOC_FAILURE);
		return(0);
		}
	if (*o != NULL) 
		ssl_cert_free(*o);
	*o = n;
	return(1);
	}

int ssl_set_cert_type(CERT *c,int type)
	{
	c->cert_type=type;
	return(1);
	}

int ssl_verify_cert_chain(SSL *s,STACK_OF(X509) *sk)
	{
	X509 *x;
	int i;
	X509_STORE_CTX ctx;

	if ((sk == NULL) || (sk_X509_num(sk) == 0))
		return(0);

	x=sk_X509_value(sk,0);
	X509_STORE_CTX_init(&ctx,s->ctx->cert_store,x,sk);
	if (SSL_get_verify_depth(s) >= 0)
		X509_STORE_CTX_set_depth(&ctx, SSL_get_verify_depth(s));
	X509_STORE_CTX_set_ex_data(&ctx,SSL_get_ex_data_X509_STORE_CTX_idx(),
		(char *)s);

	if (s->ctx->app_verify_callback != NULL)
		i=s->ctx->app_verify_callback(&ctx);
	else
		{
#ifndef NO_X509_VERIFY
		i=X509_verify_cert(&ctx);
#else
		i=0;
		ctx.error=X509_V_ERR_APPLICATION_VERIFICATION;
		SSLerr(SSL_F_SSL_VERIFY_CERT_CHAIN,SSL_R_NO_VERIFY_CALLBACK);
#endif
		}

	s->verify_result=ctx.error;
	X509_STORE_CTX_cleanup(&ctx);

	return(i);
	}

static void set_client_CA_list(STACK_OF(X509_NAME) **ca_list,STACK_OF(X509_NAME) *list)
	{
	if (*ca_list != NULL)
		sk_X509_NAME_pop_free(*ca_list,X509_NAME_free);

	*ca_list=list;
	}

STACK *SSL_dup_CA_list(STACK *sk)
	{
	int i;
	STACK *ret;
	X509_NAME *name;

	ret=sk_new_null();
	for (i=0; i<sk_num(sk); i++)
		{
		name=X509_NAME_dup((X509_NAME *)sk_value(sk,i));
		if ((name == NULL) || !sk_push(ret,(char *)name))
			{
			sk_pop_free(ret,X509_NAME_free);
			return(NULL);
			}
		}
	return(ret);
	}

void SSL_set_client_CA_list(SSL *s,STACK_OF(X509_NAME) *list)
	{
	set_client_CA_list(&(s->client_CA),list);
	}

void SSL_CTX_set_client_CA_list(SSL_CTX *ctx,STACK_OF(X509_NAME) *list)
	{
	set_client_CA_list(&(ctx->client_CA),list);
	}

STACK_OF(X509_NAME) *SSL_CTX_get_client_CA_list(SSL_CTX *ctx)
	{
	return(ctx->client_CA);
	}

STACK_OF(X509_NAME) *SSL_get_client_CA_list(SSL *s)
	{
	if (s->type == SSL_ST_CONNECT)
		{ /* we are in the client */
		if (((s->version>>8) == SSL3_VERSION_MAJOR) &&
			(s->s3 != NULL))
			return(s->s3->tmp.ca_names);
		else
			return(NULL);
		}
	else
		{
		if (s->client_CA != NULL)
			return(s->client_CA);
		else
			return(s->ctx->client_CA);
		}
	}

static int add_client_CA(STACK_OF(X509_NAME) **sk,X509 *x)
	{
	X509_NAME *name;

	if (x == NULL) return(0);
	if ((*sk == NULL) && ((*sk=sk_X509_NAME_new_null()) == NULL))
		return(0);
		
	if ((name=X509_NAME_dup(X509_get_subject_name(x))) == NULL)
		return(0);

	if (!sk_X509_NAME_push(*sk,name))
		{
		X509_NAME_free(name);
		return(0);
		}
	return(1);
	}

int SSL_add_client_CA(SSL *ssl,X509 *x)
	{
	return(add_client_CA(&(ssl->client_CA),x));
	}

int SSL_CTX_add_client_CA(SSL_CTX *ctx,X509 *x)
	{
	return(add_client_CA(&(ctx->client_CA),x));
	}

static int name_cmp(X509_NAME **a,X509_NAME **b)
	{
	return(X509_NAME_cmp(*a,*b));
	}

#ifndef NO_STDIO
/*!
 * Load CA certs from a file into a ::STACK. Note that it is somewhat misnamed;
 * it doesn't really have anything to do with clients (except that a common use
 * for a stack of CAs is to send it to the client). Actually, it doesn't have
 * much to do with CAs, either, since it will load any old cert.
 * \param file the file containing one or more certs.
 * \return a ::STACK containing the certs.
 */
STACK_OF(X509_NAME) *SSL_load_client_CA_file(const char *file)
	{
	BIO *in;
	X509 *x=NULL;
	X509_NAME *xn=NULL;
	STACK_OF(X509_NAME) *ret,*sk;

	ret=sk_X509_NAME_new(NULL);
	sk=sk_X509_NAME_new(name_cmp);

	in=BIO_new(BIO_s_file_internal());

	if ((ret == NULL) || (sk == NULL) || (in == NULL))
		{
		SSLerr(SSL_F_SSL_LOAD_CLIENT_CA_FILE,ERR_R_MALLOC_FAILURE);
		goto err;
		}
	
	if (!BIO_read_filename(in,file))
		goto err;

	for (;;)
		{
		if (PEM_read_bio_X509(in,&x,NULL) == NULL)
			break;
		if ((xn=X509_get_subject_name(x)) == NULL) goto err;
		/* check for duplicates */
		xn=X509_NAME_dup(xn);
		if (xn == NULL) goto err;
		if (sk_X509_NAME_find(sk,xn) >= 0)
			X509_NAME_free(xn);
		else
			{
			sk_X509_NAME_push(sk,xn);
			sk_X509_NAME_push(ret,xn);
			}
		}

	if (0)
		{
err:
		if (ret != NULL) sk_X509_NAME_pop_free(ret,X509_NAME_free);
		ret=NULL;
		}
	if (sk != NULL) sk_X509_NAME_free(sk);
	if (in != NULL) BIO_free(in);
	if (x != NULL) X509_free(x);
	return(ret);
	}
#endif

/*!
 * Add a file of certs to a stack.
 * \param stack the stack to add to.
 * \param file the file to add from. All certs in this file that are not
 * already in the stack will be added.
 * \return 1 for success, 0 for failure. Note that in the case of failure some
 * certs may have been added to \c stack.
 */

int SSL_add_file_cert_subjects_to_stack(STACK_OF(X509_NAME) *stack,
					const char *file)
    {
    BIO *in;
    X509 *x=NULL;
    X509_NAME *xn=NULL;
    int ret=1;
    int (*oldcmp)(X509_NAME **a, X509_NAME **b);

    oldcmp=sk_X509_NAME_set_cmp_func(stack,name_cmp);

    in=BIO_new(BIO_s_file_internal());

    if (in == NULL)
	{
	SSLerr(SSL_F_SSL_ADD_FILE_CERT_SUBJECTS_TO_STACK,ERR_R_MALLOC_FAILURE);
	goto err;
	}
	
    if (!BIO_read_filename(in,file))
	goto err;

    for (;;)
	{
	if (PEM_read_bio_X509(in,&x,NULL) == NULL)
	    break;
	if ((xn=X509_get_subject_name(x)) == NULL) goto err;
	xn=X509_NAME_dup(xn);
	if (xn == NULL) goto err;
	if (sk_X509_NAME_find(stack,xn) >= 0)
	    X509_NAME_free(xn);
	else
	    sk_X509_NAME_push(stack,xn);
	}

    if (0)
	{
err:
	ret=0;
	}
    if(in != NULL)
	BIO_free(in);
    if(x != NULL)
	X509_free(x);

    sk_X509_NAME_set_cmp_func(stack,oldcmp);

    return ret;
    }

/*!
 * Add a directory of certs to a stack.
 * \param stack the stack to append to.
 * \param dir the directory to append from. All files in this directory will be
 * examined as potential certs. Any that are acceptable to
 * SSL_add_dir_cert_subjects_to_stack() that are not already in the stack will be
 * included.
 * \return 1 for success, 0 for failure. Note that in the case of failure some
 * certs may have been added to \c stack.
 */

#ifndef WIN32

int SSL_add_dir_cert_subjects_to_stack(STACK_OF(X509_NAME) *stack,
				       const char *dir)
    {
    DIR *d=opendir(dir);
    struct dirent *dstruct;

    /* Note that a side effect is that the CAs will be sorted by name */
    if(!d)
	{
	SSLerr(SSL_F_SSL_ADD_DIR_CERT_SUBJECTS_TO_STACK,ERR_R_MALLOC_FAILURE);
	return 0;
	}

    while((dstruct=readdir(d)))
	{
	char buf[1024];

	if(strlen(dir)+strlen(dstruct->d_name)+2 > sizeof buf)
	    {
	    SSLerr(SSL_F_SSL_ADD_DIR_CERT_SUBJECTS_TO_STACK,SSL_R_PATH_TOO_LONG);
	    return 0;
	    }
	
	sprintf(buf,"%s/%s",dir,dstruct->d_name);
	if(!SSL_add_file_cert_subjects_to_stack(stack,buf))
	    return 0;
	}

    return 1;
    }

#endif

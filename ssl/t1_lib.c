/* ssl/t1_lib.c */
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
#include <openssl/objects.h>
#include "ssl_locl.h"

const char *tls1_version_str="TLSv1" OPENSSL_VERSION_PTEXT;

SSL3_ENC_METHOD TLSv1_enc_data={
	tls1_enc,
	tls1_mac,
	tls1_setup_key_block,
	tls1_generate_master_secret,
	tls1_change_cipher_state,
	tls1_final_finish_mac,
	TLS1_FINISH_MAC_LENGTH,
	tls1_cert_verify_mac,
	TLS_MD_CLIENT_FINISH_CONST,TLS_MD_CLIENT_FINISH_CONST_SIZE,
	TLS_MD_SERVER_FINISH_CONST,TLS_MD_SERVER_FINISH_CONST_SIZE,
	tls1_alert_code,
	};

long tls1_default_timeout(void)
	{
	/* 2 hours, the 24 hours mentioned in the TLSv1 spec
	 * is way too long for http, the cache would over fill */
	return(60*60*2);
	}

int tls1_new(SSL *s)
	{
	if (!ssl3_new(s)) return(0);
	s->method->ssl_clear(s);
	return(1);
	}

void tls1_free(SSL *s)
	{
	ssl3_free(s);
	}

void tls1_clear(SSL *s)
	{
	ssl3_clear(s);
	s->version=TLS1_VERSION;
	}

#ifndef OPENSSL_NO_TLSEXT
unsigned char *ssl_add_ClientHello_TLS_extensions(SSL *s, unsigned char *p, unsigned char *limit) {
	int extdatalen=0;
	unsigned char *ret = p;

	ret+=2;

	if (ret>=limit) return NULL; /* this really never occurs, but ... */
 	if (s->servername_done == 0 && s->tlsext_hostname != NULL) { 
		/* Add TLS extension servername to the Client Hello message */
		unsigned long size_str;
		long lenmax; 

		if ((lenmax = limit - p - 7) < 0) return NULL; 
		if ((size_str = strlen(s->tlsext_hostname)) > (unsigned long)lenmax) return NULL;

		s2n(TLSEXT_TYPE_server_name,ret);
		s2n(size_str+3,ret);
		*(ret++) = (unsigned char) TLSEXT_TYPE_SERVER_host;
		s2n(size_str,ret);
	
		memcpy(ret, s->tlsext_hostname, size_str);
		ret+=size_str;
	}

	
	if ((extdatalen = ret-p-2)== 0) 
		return p;

	s2n(extdatalen,p);
	return ret;

}

unsigned char *ssl_add_ServerHello_TLS_extensions(SSL *s, unsigned char *p, unsigned char *limit) {
	int extdatalen=0;
	unsigned char *ret = p;
	if (s->hit || s->servername_done == 2)
		return p;
	ret+=2;
	if (s->servername_done == 1)  
		s->servername_done = 2;

	if (ret>=limit) return NULL; /* this really never occurs, but ... */

	if (s->session->tlsext_hostname != NULL) { 

		if (limit - p - 4 < 0) return NULL; 

		s2n(TLSEXT_TYPE_server_name,ret);
		s2n(0,ret);
	}

	
	if ((extdatalen = ret-p-2)== 0) 
		return p;

	s2n(extdatalen,p);
	return ret;

}

int ssl_parse_ClientHello_TLS_extensions(SSL *s, unsigned char **p, unsigned char *d, int n) {
	unsigned short type;
	unsigned short size;
	unsigned short len;
	unsigned char * data = *p;

	if (data >= (d+n-2))
	   return SSL_ERROR_NONE;
	n2s(data,len);

        if (data > (d+n-len)) 
	   return SSL_ERROR_NONE;

	while(data <= (d+n-4)){
		n2s(data,type);
		n2s(data,size);

		if (data+size > (d+n))
	   		return SSL_ERROR_SSL;

		if (type == TLSEXT_TYPE_server_name) {
			unsigned char *sdata = data;
			int servname_type;
			int dsize = size-3 ;
                        
			if (dsize > 0 ) {
 				servname_type = *(sdata++); 
				n2s(sdata,len);
				if (len != dsize) 
			   		return SSL_ERROR_SSL;

				switch (servname_type) {
				case TLSEXT_TYPE_SERVER_host:
                                        if (s->session->tlsext_hostname == NULL) {
						if (len > 255 || 
							((s->session->tlsext_hostname = OPENSSL_malloc(len+1)) == NULL))
							return SSL_ERROR_SSL;
						memcpy(s->session->tlsext_hostname, sdata, len);
						s->session->tlsext_hostname[len]='\0'; 
					}
					break;
				default:
					break;
				}
                                 
			}
		}

		data+=size;		
	}
	*p = data;

	return SSL_ERROR_NONE;
}
int ssl_parse_ServerHello_TLS_extensions(SSL *s, unsigned char **p, unsigned char *d, int n) {
	unsigned short type;
	unsigned short size;
	unsigned short len;  
	unsigned char *data = *p;

	int tlsext_servername = 0;

	if (data >= (d+n-2))
	   return SSL_ERROR_NONE;


	n2s(data,len);

	while(data <= (d+n-4)){
		n2s(data,type);
		n2s(data,size);

		if (data+size > (d+n))
	   		return SSL_ERROR_SSL;

		if (type == TLSEXT_TYPE_server_name) {
			if ( s->tlsext_hostname == NULL || size > 0 ) {
				return SSL_ERROR_SSL;
			}
			tlsext_servername = 1;   
		} 

		data+=size;		
	}

	

	if (data != d+n)
	   	return SSL_ERROR_SSL;

	if (!s->hit && tlsext_servername == 1) {
 		if (s->tlsext_hostname) {
			if (s->session->tlsext_hostname == NULL) {
				s->session->tlsext_hostname = BUF_strdup(s->tlsext_hostname);	
				if (!s->session->tlsext_hostname)
					return SSL_ERROR_SSL;
			}
		} else 
			return SSL_ERROR_SSL;
	}
	*p = data;

	return SSL_ERROR_NONE;
}

int ssl_check_Hello_TLS_extensions(SSL *s,int *ad)
{
	int ret = SSL_ERROR_NONE;

	*ad = SSL_AD_UNRECOGNIZED_NAME;
	if (s->servername_done == 0 && (s->ctx != NULL && s->ctx->tlsext_servername_callback != NULL) 
		&& ((ret = s->ctx->tlsext_servername_callback(s, ad, s->ctx->tlsext_servername_arg))!= SSL_ERROR_NONE)) 
  		return ret;

	else if (s->servername_done == 1) 	
		s->servername_done = 2;

	return ret;
}
#endif


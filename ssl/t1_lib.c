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
/* ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
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
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "ssl_locl.h"

const char tls1_version_str[]="TLSv1" OPENSSL_VERSION_PTEXT;

#ifndef OPENSSL_NO_TLSEXT
static int tls_decrypt_ticket(SSL *s, const unsigned char *tick, int ticklen,
				const unsigned char *sess_id, int sesslen,
				SSL_SESSION **psess);
#endif

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

#ifndef OPENSSL_NO_EC
static int nid_list[] =
	{
		NID_sect163k1, /* sect163k1 (1) */
		NID_sect163r1, /* sect163r1 (2) */
		NID_sect163r2, /* sect163r2 (3) */
		NID_sect193r1, /* sect193r1 (4) */ 
		NID_sect193r2, /* sect193r2 (5) */ 
		NID_sect233k1, /* sect233k1 (6) */
		NID_sect233r1, /* sect233r1 (7) */ 
		NID_sect239k1, /* sect239k1 (8) */ 
		NID_sect283k1, /* sect283k1 (9) */
		NID_sect283r1, /* sect283r1 (10) */ 
		NID_sect409k1, /* sect409k1 (11) */ 
		NID_sect409r1, /* sect409r1 (12) */
		NID_sect571k1, /* sect571k1 (13) */ 
		NID_sect571r1, /* sect571r1 (14) */ 
		NID_secp160k1, /* secp160k1 (15) */
		NID_secp160r1, /* secp160r1 (16) */ 
		NID_secp160r2, /* secp160r2 (17) */ 
		NID_secp192k1, /* secp192k1 (18) */
		NID_X9_62_prime192v1, /* secp192r1 (19) */ 
		NID_secp224k1, /* secp224k1 (20) */ 
		NID_secp224r1, /* secp224r1 (21) */
		NID_secp256k1, /* secp256k1 (22) */ 
		NID_X9_62_prime256v1, /* secp256r1 (23) */ 
		NID_secp384r1, /* secp384r1 (24) */
		NID_secp521r1  /* secp521r1 (25) */	
	};
	
int tls1_ec_curve_id2nid(int curve_id)
	{
	/* ECC curves from draft-ietf-tls-ecc-12.txt (Oct. 17, 2005) */
	if ((curve_id < 1) || (curve_id > sizeof(nid_list)/sizeof(nid_list[0]))) return 0;
	return nid_list[curve_id-1];
	}

int tls1_ec_nid2curve_id(int nid)
	{
	/* ECC curves from draft-ietf-tls-ecc-12.txt (Oct. 17, 2005) */
	switch (nid)
		{
	case NID_sect163k1: /* sect163k1 (1) */
		return 1;
	case NID_sect163r1: /* sect163r1 (2) */
		return 2;
	case NID_sect163r2: /* sect163r2 (3) */
		return 3;
	case NID_sect193r1: /* sect193r1 (4) */ 
		return 4;
	case NID_sect193r2: /* sect193r2 (5) */ 
		return 5;
	case NID_sect233k1: /* sect233k1 (6) */
		return 6;
	case NID_sect233r1: /* sect233r1 (7) */ 
		return 7;
	case NID_sect239k1: /* sect239k1 (8) */ 
		return 8;
	case NID_sect283k1: /* sect283k1 (9) */
		return 9;
	case NID_sect283r1: /* sect283r1 (10) */ 
		return 10;
	case NID_sect409k1: /* sect409k1 (11) */ 
		return 11;
	case NID_sect409r1: /* sect409r1 (12) */
		return 12;
	case NID_sect571k1: /* sect571k1 (13) */ 
		return 13;
	case NID_sect571r1: /* sect571r1 (14) */ 
		return 14;
	case NID_secp160k1: /* secp160k1 (15) */
		return 15;
	case NID_secp160r1: /* secp160r1 (16) */ 
		return 16;
	case NID_secp160r2: /* secp160r2 (17) */ 
		return 17;
	case NID_secp192k1: /* secp192k1 (18) */
		return 18;
	case NID_X9_62_prime192v1: /* secp192r1 (19) */ 
		return 19;
	case NID_secp224k1: /* secp224k1 (20) */ 
		return 20;
	case NID_secp224r1: /* secp224r1 (21) */
		return 21;
	case NID_secp256k1: /* secp256k1 (22) */ 
		return 22;
	case NID_X9_62_prime256v1: /* secp256r1 (23) */ 
		return 23;
	case NID_secp384r1: /* secp384r1 (24) */
		return 24;
	case NID_secp521r1:  /* secp521r1 (25) */	
		return 25;
	default:
		return 0;
		}
	}
#endif /* OPENSSL_NO_EC */

#ifndef OPENSSL_NO_TLSEXT
unsigned char *ssl_add_clienthello_tlsext(SSL *s, unsigned char *p, unsigned char *limit)
	{
	int extdatalen=0;
	unsigned char *ret = p;

	ret+=2;

	if (ret>=limit) return NULL; /* this really never occurs, but ... */

 	if (s->tlsext_hostname != NULL)
		{ 
		/* Add TLS extension servername to the Client Hello message */
		unsigned long size_str;
		long lenmax; 

		/* check for enough space.
		   4 for the servername type and entension length
		   2 for servernamelist length
		   1 for the hostname type
		   2 for hostname length
		   + hostname length 
		*/
		   
		if ((lenmax = limit - p - 9) < 0 
		|| (size_str = strlen(s->tlsext_hostname)) > (unsigned long)lenmax) 
			return NULL;
			
		/* extension type and length */
		s2n(TLSEXT_TYPE_server_name,ret); 
		s2n(size_str+5,ret);
		
		/* length of servername list */
		s2n(size_str+3,ret);
	
		/* hostname type, length and hostname */
		*(ret++) = (unsigned char) TLSEXT_NAMETYPE_host_name;
		s2n(size_str,ret);
		memcpy(ret, s->tlsext_hostname, size_str);
		ret+=size_str;

		}
#ifndef OPENSSL_NO_EC
	if (s->tlsext_ecpointformatlist != NULL)
		{
		/* Add TLS extension ECPointFormats to the ClientHello message */
		long lenmax; 

		if ((lenmax = limit - p - 5) < 0) return NULL; 
		if (s->tlsext_ecpointformatlist_length > (unsigned long)lenmax) return NULL;
		if (s->tlsext_ecpointformatlist_length > 255)
			{
			SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
			return NULL;
			}
		
		s2n(TLSEXT_TYPE_ec_point_formats,ret);
		s2n(s->tlsext_ecpointformatlist_length + 1,ret);
		*(ret++) = (unsigned char) s->tlsext_ecpointformatlist_length;
		memcpy(ret, s->tlsext_ecpointformatlist, s->tlsext_ecpointformatlist_length);
		ret+=s->tlsext_ecpointformatlist_length;
		}
	if (s->tlsext_ellipticcurvelist != NULL)
		{
		/* Add TLS extension EllipticCurves to the ClientHello message */
		long lenmax; 

		if ((lenmax = limit - p - 6) < 0) return NULL; 
		if (s->tlsext_ellipticcurvelist_length > (unsigned long)lenmax) return NULL;
		if (s->tlsext_ellipticcurvelist_length > 65532)
			{
			SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
			return NULL;
			}
		
		s2n(TLSEXT_TYPE_elliptic_curves,ret);
		s2n(s->tlsext_ellipticcurvelist_length + 2, ret);

		/* NB: draft-ietf-tls-ecc-12.txt uses a one-byte prefix for
		 * elliptic_curve_list, but the examples use two bytes.
		 * http://www1.ietf.org/mail-archive/web/tls/current/msg00538.html
		 * resolves this to two bytes.
		 */
		s2n(s->tlsext_ellipticcurvelist_length, ret);
		memcpy(ret, s->tlsext_ellipticcurvelist, s->tlsext_ellipticcurvelist_length);
		ret+=s->tlsext_ellipticcurvelist_length;
		}
#endif /* OPENSSL_NO_EC */

	if (!(SSL_get_options(s) & SSL_OP_NO_TICKET))
		{
		int ticklen;
		if (s->session && s->session->tlsext_tick)
			ticklen = s->session->tlsext_ticklen;
		else
			ticklen = 0;
		/* Check for enough room 2 for extension type, 2 for len
 		 * rest for ticket
  		 */
		if (limit - p - 4 - ticklen < 0)
			return NULL;
		s2n(TLSEXT_TYPE_session_ticket,ret); 
		s2n(ticklen,ret);
		if (ticklen)
			{
			memcpy(ret, s->session->tlsext_tick, ticklen);
			ret += ticklen;
			}
		}

	if ((extdatalen = ret-p-2)== 0) 
		return p;

	s2n(extdatalen,p);
	return ret;
	}

unsigned char *ssl_add_serverhello_tlsext(SSL *s, unsigned char *p, unsigned char *limit)
	{
	int extdatalen=0;
	unsigned char *ret = p;

	ret+=2;
	if (ret>=limit) return NULL; /* this really never occurs, but ... */

	if (!s->hit && s->servername_done == 1 && s->session->tlsext_hostname != NULL)
		{ 
		if (limit - p - 4 < 0) return NULL; 

		s2n(TLSEXT_TYPE_server_name,ret);
		s2n(0,ret);
		}
#ifndef OPENSSL_NO_EC
	if (s->tlsext_ecpointformatlist != NULL)
		{
		/* Add TLS extension ECPointFormats to the ServerHello message */
		long lenmax; 

		if ((lenmax = limit - p - 5) < 0) return NULL; 
		if (s->tlsext_ecpointformatlist_length > (unsigned long)lenmax) return NULL;
		if (s->tlsext_ecpointformatlist_length > 255)
			{
			SSLerr(SSL_F_SSL_ADD_SERVERHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
			return NULL;
			}
		
		s2n(TLSEXT_TYPE_ec_point_formats,ret);
		s2n(s->tlsext_ecpointformatlist_length + 1,ret);
		*(ret++) = (unsigned char) s->tlsext_ecpointformatlist_length;
		memcpy(ret, s->tlsext_ecpointformatlist, s->tlsext_ecpointformatlist_length);
		ret+=s->tlsext_ecpointformatlist_length;

		}
	/* Currently the server should not respond with a SupportedCurves extension */
#endif /* OPENSSL_NO_EC */
	
	if (s->tlsext_ticket_expected
		&& !(SSL_get_options(s) & SSL_OP_NO_TICKET)) 
		{ 
		if (limit - p - 4 < 0) return NULL; 
		s2n(TLSEXT_TYPE_session_ticket,ret);
		s2n(0,ret);
		}
		
	if ((extdatalen = ret-p-2)== 0) 
		return p;

	s2n(extdatalen,p);
	return ret;
	}

int ssl_parse_clienthello_tlsext(SSL *s, unsigned char **p, unsigned char *d, int n, int *al)
	{
	unsigned short type;
	unsigned short size;
	unsigned short len;
	unsigned char *data = *p;
	s->servername_done = 0;

	if (data >= (d+n-2))
		return 1;
	n2s(data,len);

	if (data > (d+n-len)) 
		return 1;

	while (data <= (d+n-4))
		{
		n2s(data,type);
		n2s(data,size);

		if (data+size > (d+n))
	   		return 1;

		if (s->tlsext_debug_cb)
			s->tlsext_debug_cb(s, 0, type, data, size,
						s->tlsext_debug_arg);
/* The servername extension is treated as follows:

   - Only the hostname type is supported with a maximum length of 255.
   - The servername is rejected if too long or if it contains zeros,
     in which case an fatal alert is generated.
   - The servername field is maintained together with the session cache.
   - When a session is resumed, the servername call back invoked in order
     to allow the application to position itself to the right context. 
   - The servername is acknowledged if it is new for a session or when 
     it is identical to a previously used for the same session. 
     Applications can control the behaviour.  They can at any time
     set a 'desirable' servername for a new SSL object. This can be the
     case for example with HTTPS when a Host: header field is received and
     a renegotiation is requested. In this case, a possible servername
     presented in the new client hello is only acknowledged if it matches
     the value of the Host: field. 
   - Applications must  use SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
     if they provide for changing an explicit servername context for the session,
     i.e. when the session has been established with a servername extension. 
   - On session reconnect, the servername extension may be absent. 

*/      

		if (type == TLSEXT_TYPE_server_name)
			{
			unsigned char *sdata;
			int servname_type;
			int dsize; 
		
			if (size < 2) 
				{
				*al = SSL_AD_DECODE_ERROR;
				return 0;
				}
			n2s(data,dsize);  
			size -= 2;
			if (dsize > size  ) 
				{
				*al = SSL_AD_DECODE_ERROR;
				return 0;
				} 

			sdata = data;
			while (dsize > 3) 
				{
	 			servname_type = *(sdata++); 
				n2s(sdata,len);
				dsize -= 3;

				if (len > dsize) 
					{
					*al = SSL_AD_DECODE_ERROR;
					return 0;
					}
				if (s->servername_done == 0)
				switch (servname_type)
					{
				case TLSEXT_NAMETYPE_host_name:
					if (s->session->tlsext_hostname == NULL)
						{
						if (len > TLSEXT_MAXLEN_host_name || 
							((s->session->tlsext_hostname = OPENSSL_malloc(len+1)) == NULL))
							{
							*al = TLS1_AD_UNRECOGNIZED_NAME;
							return 0;
							}
						memcpy(s->session->tlsext_hostname, sdata, len);
						s->session->tlsext_hostname[len]='\0';
						if (strlen(s->session->tlsext_hostname) != len) {
							OPENSSL_free(s->session->tlsext_hostname);
							*al = TLS1_AD_UNRECOGNIZED_NAME;
							return 0;
						}
						s->servername_done = 1; 

						}
					else 
						s->servername_done = strlen(s->session->tlsext_hostname) == len 
							&& strncmp(s->session->tlsext_hostname, (char *)sdata, len) == 0;
					
					break;

				default:
					break;
					}
				 
				dsize -= len;
				}
			if (dsize != 0) 
				{
				*al = SSL_AD_DECODE_ERROR;
				return 0;
				}

			}

#ifndef OPENSSL_NO_EC
		else if (type == TLSEXT_TYPE_ec_point_formats)
			{
			unsigned char *sdata = data;
			int ecpointformatlist_length = *(sdata++);

			if (ecpointformatlist_length != size - 1)
				{
				*al = TLS1_AD_DECODE_ERROR;
				return 0;
				}
			s->session->tlsext_ecpointformatlist_length = 0;
			if (s->session->tlsext_ecpointformatlist != NULL) OPENSSL_free(s->session->tlsext_ecpointformatlist);
			if ((s->session->tlsext_ecpointformatlist = OPENSSL_malloc(ecpointformatlist_length)) == NULL)
				{
				*al = TLS1_AD_INTERNAL_ERROR;
				return 0;
				}
			s->session->tlsext_ecpointformatlist_length = ecpointformatlist_length;
			memcpy(s->session->tlsext_ecpointformatlist, sdata, ecpointformatlist_length);
#if 0
			fprintf(stderr,"ssl_parse_clienthello_tlsext s->session->tlsext_ecpointformatlist (length=%i) ", s->session->tlsext_ecpointformatlist_length);
			sdata = s->session->tlsext_ecpointformatlist;
			for (i = 0; i < s->session->tlsext_ecpointformatlist_length; i++)
				fprintf(stderr,"%i ",*(sdata++));
			fprintf(stderr,"\n");
#endif
			}
		else if (type == TLSEXT_TYPE_elliptic_curves)
			{
			unsigned char *sdata = data;
			int ellipticcurvelist_length = (*(sdata++) << 8);
			ellipticcurvelist_length += (*(sdata++));

			if (ellipticcurvelist_length != size - 2)
				{
				*al = TLS1_AD_DECODE_ERROR;
				return 0;
				}
			s->session->tlsext_ellipticcurvelist_length = 0;
			if (s->session->tlsext_ellipticcurvelist != NULL) OPENSSL_free(s->session->tlsext_ellipticcurvelist);
			if ((s->session->tlsext_ellipticcurvelist = OPENSSL_malloc(ellipticcurvelist_length)) == NULL)
				{
				*al = TLS1_AD_INTERNAL_ERROR;
				return 0;
				}
			s->session->tlsext_ellipticcurvelist_length = ellipticcurvelist_length;
			memcpy(s->session->tlsext_ellipticcurvelist, sdata, ellipticcurvelist_length);
#if 0
			fprintf(stderr,"ssl_parse_clienthello_tlsext s->session->tlsext_ellipticcurvelist (length=%i) ", s->session->tlsext_ellipticcurvelist_length);
			sdata = s->session->tlsext_ellipticcurvelist;
			for (i = 0; i < s->session->tlsext_ellipticcurvelist_length; i++)
				fprintf(stderr,"%i ",*(sdata++));
			fprintf(stderr,"\n");
#endif
			}
#endif /* OPENSSL_NO_EC */
		/* session ticket processed earlier */
		data+=size;
		}
				
	*p = data;
	return 1;
	}

int ssl_parse_serverhello_tlsext(SSL *s, unsigned char **p, unsigned char *d, int n, int *al)
	{
	unsigned short type;
	unsigned short size;
	unsigned short len;  
	unsigned char *data = *p;

	int tlsext_servername = 0;

	if (data >= (d+n-2))
		return 1;

	n2s(data,len);

	while(data <= (d+n-4))
		{
		n2s(data,type);
		n2s(data,size);

		if (data+size > (d+n))
	   		return 1;

		if (s->tlsext_debug_cb)
			s->tlsext_debug_cb(s, 1, type, data, size,
						s->tlsext_debug_arg);

		if (type == TLSEXT_TYPE_server_name)
			{
			if (s->tlsext_hostname == NULL || size > 0)
				{
				*al = TLS1_AD_UNRECOGNIZED_NAME;
				return 0;
				}
			tlsext_servername = 1;   
			}

#ifndef OPENSSL_NO_EC
		else if (type == TLSEXT_TYPE_ec_point_formats)
			{
			unsigned char *sdata = data;
			int ecpointformatlist_length = *(sdata++);

			if (ecpointformatlist_length != size - 1)
				{
				*al = TLS1_AD_DECODE_ERROR;
				return 0;
				}
			s->session->tlsext_ecpointformatlist_length = 0;
			if (s->session->tlsext_ecpointformatlist != NULL) OPENSSL_free(s->session->tlsext_ecpointformatlist);
			if ((s->session->tlsext_ecpointformatlist = OPENSSL_malloc(ecpointformatlist_length)) == NULL)
				{
				*al = TLS1_AD_INTERNAL_ERROR;
				return 0;
				}
			s->session->tlsext_ecpointformatlist_length = ecpointformatlist_length;
			memcpy(s->session->tlsext_ecpointformatlist, sdata, ecpointformatlist_length);
#if 0
			fprintf(stderr,"ssl_parse_serverhello_tlsext s->session->tlsext_ecpointformatlist ");
			sdata = s->session->tlsext_ecpointformatlist;
			for (i = 0; i < s->session->tlsext_ecpointformatlist_length; i++)
				fprintf(stderr,"%i ",*(sdata++));
			fprintf(stderr,"\n");
#endif
			}
#endif /* OPENSSL_NO_EC */

		else if (type == TLSEXT_TYPE_session_ticket)
			{
			if ((SSL_get_options(s) & SSL_OP_NO_TICKET)
				|| (size > 0))
				{
				*al = TLS1_AD_UNSUPPORTED_EXTENSION;
				return 0;
				}
			s->tlsext_ticket_expected = 1;
			}
		data+=size;		
		}

	if (data != d+n)
		{
		*al = SSL_AD_DECODE_ERROR;
		return 0;
		}

	if (!s->hit && tlsext_servername == 1)
		{
 		if (s->tlsext_hostname)
			{
			if (s->session->tlsext_hostname == NULL)
				{
				s->session->tlsext_hostname = BUF_strdup(s->tlsext_hostname);	
				if (!s->session->tlsext_hostname)
					{
					*al = SSL_AD_UNRECOGNIZED_NAME;
					return 0;
					}
				}
			else 
				{
				*al = SSL_AD_DECODE_ERROR;
				return 0;
				}
			}
		}

	*p = data;
	return 1;
	}


int ssl_prepare_clienthello_tlsext(SSL *s)
	{
#ifndef OPENSSL_NO_EC
	/* If we are client and using an elliptic curve cryptography cipher suite, send the point formats 
	 * and elliptic curves we support.
	 */
	int using_ecc = 0;
	int i;
	unsigned char *j;
	unsigned long alg_k, alg_a;
	STACK_OF(SSL_CIPHER) *cipher_stack = SSL_get_ciphers(s);

	for (i = 0; i < sk_SSL_CIPHER_num(cipher_stack); i++)
		{
		SSL_CIPHER *c = sk_SSL_CIPHER_value(cipher_stack, i);

		alg_k = c->algorithm_mkey;
		alg_a = c->algorithm_auth;
		if ((alg_k & (SSL_kEECDH|SSL_kECDHr|SSL_kECDHe) || (alg_a & SSL_aECDSA)))
			{
			using_ecc = 1;
			break;
			}
		}
	using_ecc = using_ecc && (s->version == TLS1_VERSION);
	if (using_ecc)
		{
		if (s->tlsext_ecpointformatlist != NULL) OPENSSL_free(s->tlsext_ecpointformatlist);
		if ((s->tlsext_ecpointformatlist = OPENSSL_malloc(3)) == NULL)
			{
			SSLerr(SSL_F_SSL_PREPARE_CLIENTHELLO_TLSEXT,ERR_R_MALLOC_FAILURE);
			return -1;
			}
		s->tlsext_ecpointformatlist_length = 3;
		s->tlsext_ecpointformatlist[0] = TLSEXT_ECPOINTFORMAT_uncompressed;
		s->tlsext_ecpointformatlist[1] = TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime;
		s->tlsext_ecpointformatlist[2] = TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2;

		/* we support all named elliptic curves in draft-ietf-tls-ecc-12 */
		if (s->tlsext_ellipticcurvelist != NULL) OPENSSL_free(s->tlsext_ellipticcurvelist);
		s->tlsext_ellipticcurvelist_length = sizeof(nid_list)/sizeof(nid_list[0]) * 2;
		if ((s->tlsext_ellipticcurvelist = OPENSSL_malloc(s->tlsext_ellipticcurvelist_length)) == NULL)
			{
			s->tlsext_ellipticcurvelist_length = 0;
			SSLerr(SSL_F_SSL_PREPARE_CLIENTHELLO_TLSEXT,ERR_R_MALLOC_FAILURE);
			return -1;
			}
		for (i = 1, j = s->tlsext_ellipticcurvelist; i <= sizeof(nid_list)/sizeof(nid_list[0]); i++)
			s2n(i,j);
		}
#endif /* OPENSSL_NO_EC */
	return 1;
	}

int ssl_prepare_serverhello_tlsext(SSL *s)
	{
#ifndef OPENSSL_NO_EC
	/* If we are server and using an ECC cipher suite, send the point formats we support 
	 * if the client sent us an ECPointsFormat extension.  Note that the server is not
	 * supposed to send an EllipticCurves extension.
	 */

	unsigned long alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
	unsigned long alg_a = s->s3->tmp.new_cipher->algorithm_auth;
	int using_ecc = (alg_k & (SSL_kEECDH|SSL_kECDHr|SSL_kECDHe)) || (alg_a & SSL_aECDSA);
	using_ecc = using_ecc && (s->session->tlsext_ecpointformatlist != NULL);
	
	if (using_ecc)
		{
		if (s->tlsext_ecpointformatlist != NULL) OPENSSL_free(s->tlsext_ecpointformatlist);
		if ((s->tlsext_ecpointformatlist = OPENSSL_malloc(3)) == NULL)
			{
			SSLerr(SSL_F_SSL_PREPARE_SERVERHELLO_TLSEXT,ERR_R_MALLOC_FAILURE);
			return -1;
			}
		s->tlsext_ecpointformatlist_length = 3;
		s->tlsext_ecpointformatlist[0] = TLSEXT_ECPOINTFORMAT_uncompressed;
		s->tlsext_ecpointformatlist[1] = TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime;
		s->tlsext_ecpointformatlist[2] = TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2;
		}
#endif /* OPENSSL_NO_EC */
	return 1;
	}

int ssl_check_clienthello_tlsext(SSL *s)
	{
	int ret=SSL_TLSEXT_ERR_NOACK;
	int al = SSL_AD_UNRECOGNIZED_NAME;

#ifndef OPENSSL_NO_EC
	/* The handling of the ECPointFormats extension is done elsewhere, namely in 
	 * ssl3_choose_cipher in s3_lib.c.
	 */
	/* The handling of the EllipticCurves extension is done elsewhere, namely in 
	 * ssl3_choose_cipher in s3_lib.c.
	 */
#endif

	if (s->ctx != NULL && s->ctx->tlsext_servername_callback != 0) 
		ret = s->ctx->tlsext_servername_callback(s, &al, s->ctx->tlsext_servername_arg);
	else if (s->initial_ctx != NULL && s->initial_ctx->tlsext_servername_callback != 0) 		
		ret = s->initial_ctx->tlsext_servername_callback(s, &al, s->initial_ctx->tlsext_servername_arg);

	switch (ret)
		{
		case SSL_TLSEXT_ERR_ALERT_FATAL:
			ssl3_send_alert(s,SSL3_AL_FATAL,al); 
			return -1;

		case SSL_TLSEXT_ERR_ALERT_WARNING:
			ssl3_send_alert(s,SSL3_AL_WARNING,al);
			return 1; 
					
		case SSL_TLSEXT_ERR_NOACK:
			s->servername_done=0;
			default:
		return 1;
		}
	}

int ssl_check_serverhello_tlsext(SSL *s)
	{
	int ret=SSL_TLSEXT_ERR_NOACK;
	int al = SSL_AD_UNRECOGNIZED_NAME;

#ifndef OPENSSL_NO_EC
	/* If we are client and using an elliptic curve cryptography cipher suite, then server
	 * must return a an EC point formats lists containing uncompressed.
	 */
	unsigned long alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
	unsigned long alg_a = s->s3->tmp.new_cipher->algorithm_auth;
	if ((s->tlsext_ecpointformatlist != NULL) && (s->tlsext_ecpointformatlist_length > 0) && 
	    ((alg_k & (SSL_kEECDH|SSL_kECDHr|SSL_kECDHe)) || (alg_a & SSL_aECDSA)))
		{
		/* we are using an ECC cipher */
		size_t i;
		unsigned char *list;
		int found_uncompressed = 0;
		if ((s->session->tlsext_ecpointformatlist == NULL) || (s->session->tlsext_ecpointformatlist_length == 0))
			{
			SSLerr(SSL_F_SSL_CHECK_SERVERHELLO_TLSEXT,SSL_R_TLS_INVALID_ECPOINTFORMAT_LIST);
			return -1;
			}
		list = s->session->tlsext_ecpointformatlist;
		for (i = 0; i < s->session->tlsext_ecpointformatlist_length; i++)
			{
			if (*(list++) == TLSEXT_ECPOINTFORMAT_uncompressed)
				{
				found_uncompressed = 1;
				break;
				}
			}
		if (!found_uncompressed)
			{
			SSLerr(SSL_F_SSL_CHECK_SERVERHELLO_TLSEXT,SSL_R_TLS_INVALID_ECPOINTFORMAT_LIST);
			return -1;
			}
		}
	ret = SSL_TLSEXT_ERR_OK;
#endif /* OPENSSL_NO_EC */

	if (s->ctx != NULL && s->ctx->tlsext_servername_callback != 0) 
		ret = s->ctx->tlsext_servername_callback(s, &al, s->ctx->tlsext_servername_arg);
	else if (s->initial_ctx != NULL && s->initial_ctx->tlsext_servername_callback != 0) 		
		ret = s->initial_ctx->tlsext_servername_callback(s, &al, s->initial_ctx->tlsext_servername_arg);

	switch (ret)
		{
		case SSL_TLSEXT_ERR_ALERT_FATAL:
			ssl3_send_alert(s,SSL3_AL_FATAL,al); 
			return -1;

		case SSL_TLSEXT_ERR_ALERT_WARNING:
			ssl3_send_alert(s,SSL3_AL_WARNING,al);
			return 1; 
					
		case SSL_TLSEXT_ERR_NOACK:
			s->servername_done=0;
			default:
		return 1;
		}
	}

/* Since the server cache lookup is done early on in the processing of client
 * hello and other operations depend on the result we need to handle any TLS
 * session ticket extension at the same time.
 */

int tls1_process_ticket(SSL *s, unsigned char *session_id, int len,
				const unsigned char *limit, SSL_SESSION **ret)
	{
	/* Point after session ID in client hello */
	const unsigned char *p = session_id + len;
	unsigned short i;
	if ((s->version <= SSL3_VERSION) || !limit)
		return 1;
	if (p >= limit)
		return -1;
	/* Skip past cipher list */
	n2s(p, i);
	p+= i;
	if (p >= limit)
		return -1;
	/* Skip past compression algorithm list */
	i = *(p++);
	p += i;
	if (p > limit)
		return -1;
	/* Now at start of extensions */
	if ((p + 2) >= limit)
		return 1;
	n2s(p, i);
	while ((p + 4) <= limit)
		{
		unsigned short type, size;
		n2s(p, type);
		n2s(p, size);
		if (p + size > limit)
			return 1;
		if (type == TLSEXT_TYPE_session_ticket)
			{
			/* If tickets disabled indicate cache miss which will
 			 * trigger a full handshake
 			 */
			if (SSL_get_options(s) & SSL_OP_NO_TICKET)
				return 0;
			/* If zero length not client will accept a ticket
 			 * and indicate cache miss to trigger full handshake
 			 */
			if (size == 0)
				{
				s->tlsext_ticket_expected = 1;
				return 0;	/* Cache miss */
				}
			return tls_decrypt_ticket(s, p, size, session_id, len,
									ret);
			}
		p += size;
		}
	return 1;
	}

static int tls_decrypt_ticket(SSL *s, const unsigned char *etick, int eticklen,
				const unsigned char *sess_id, int sesslen,
				SSL_SESSION **psess)
	{
	SSL_SESSION *sess;
	unsigned char *sdec;
	const unsigned char *p;
	int slen, mlen;
	unsigned char tick_hmac[EVP_MAX_MD_SIZE];
	HMAC_CTX hctx;
	EVP_CIPHER_CTX ctx;
	/* Attempt to process session ticket, first conduct sanity and
 	 * integrity checks on ticket.
 	 */
	mlen = EVP_MD_size(EVP_sha1());
	eticklen -= mlen;
	/* Need at least keyname + iv + some encrypted data */
	if (eticklen < 48)
		goto tickerr;
	/* Check key name matches */
	if (memcmp(etick, s->ctx->tlsext_tick_key_name, 16))
		goto tickerr;
	/* Check HMAC of encrypted ticket */
	HMAC_CTX_init(&hctx);
	HMAC_Init_ex(&hctx, s->ctx->tlsext_tick_hmac_key, 16,
				EVP_sha1(), NULL);
	HMAC_Update(&hctx, etick, eticklen);
	HMAC_Final(&hctx, tick_hmac, NULL);
	HMAC_CTX_cleanup(&hctx);
	if (memcmp(tick_hmac, etick + eticklen, mlen))
		goto tickerr;
	/* Set p to start of IV */
	p = etick + 16;
	EVP_CIPHER_CTX_init(&ctx);
	/* Attempt to decrypt session data */
	EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL,
					s->ctx->tlsext_tick_aes_key, p);
	/* Move p after IV to start of encrypted ticket, update length */
	p += 16;
	eticklen -= 32;
	sdec = OPENSSL_malloc(eticklen);
	if (!sdec)
		{
		EVP_CIPHER_CTX_cleanup(&ctx);
		return -1;
		}
	EVP_DecryptUpdate(&ctx, sdec, &slen, p, eticklen);
	if (EVP_DecryptFinal(&ctx, sdec + slen, &mlen) <= 0)
		goto tickerr;
	slen += mlen;
	EVP_CIPHER_CTX_cleanup(&ctx);
	p = sdec;
		
	sess = d2i_SSL_SESSION(NULL, &p, slen);
	OPENSSL_free(sdec);
	if (sess)
		{
		/* The session ID if non-empty is used by some clients to
 		 * detect that the ticket has been accepted. So we copy it to
 		 * the session structure. If it is empty set length to zero
 		 * as required by standard.
 		 */
		if (sesslen)
			memcpy(sess->session_id, sess_id, sesslen);
		sess->session_id_length = sesslen;
		*psess = sess;
		return 1;
		}
	/* If session decrypt failure indicate a cache miss and set state to
 	 * send a new ticket
 	 */
	tickerr:	
	s->tlsext_ticket_expected = 1;
	return 0;
	}

#endif

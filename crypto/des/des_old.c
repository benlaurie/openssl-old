/* crypto/des/des_comp.c -*- mode:C; c-file-style: "eay" -*- */

/* WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 * The function names in here are deprecated and are only present to
 * provide an interface compatible with libdes.  OpenSSL now provides
 * functions where "des_" has been replaced with "DES_" in the names,
 * to make it possible to make incompatible changes that are needed
 * for C type security and other stuff.
 *
 * Please consider starting to use the DES_ functions rather than the
 * des_ ones.  The des_ functions will dissapear completely before
 * OpenSSL 1.0!
 *
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 */

/* Written by Richard Levitte (richard@levitte.org) for the OpenSSL
 * project 2001.
 */
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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

#include <openssl/des_old.h>

const char *des_options(void)
	{
	return DES_options();
	}
void des_ecb3_encrypt(des_cblock *input,des_cblock *output,
	des_key_schedule ks1,des_key_schedule ks2,
	des_key_schedule ks3, int enc)
	{
	DES_ecb3_encrypt((const_DES_cblock *)input, output,
		(DES_key_schedule *)ks1, (DES_key_schedule *)ks2,
		(DES_key_schedule *)ks3, enc);
	}
DES_LONG des_cbc_cksum(des_cblock *input,des_cblock *output,
	long length,des_key_schedule schedule,des_cblock *ivec)
	{
	return DES_cbc_cksum((unsigned char *)input, output, length,
		(DES_key_schedule *)schedule, ivec);
	}
void des_cbc_encrypt(des_cblock *input,des_cblock *output,long length,
	des_key_schedule schedule,des_cblock *ivec,int enc)
	{
	DES_cbc_encrypt((unsigned char *)input, (unsigned char *)output,
		length, (DES_key_schedule *)schedule, ivec, enc);
	}
void des_ncbc_encrypt(des_cblock *input,des_cblock *output,long length,
	des_key_schedule schedule,des_cblock *ivec,int enc)
	{
	DES_ncbc_encrypt((unsigned char *)input, (unsigned char *)output,
		length, (DES_key_schedule *)schedule, ivec, enc);
	}
void des_xcbc_encrypt(des_cblock *input,des_cblock *output,long length,
	des_key_schedule schedule,des_cblock *ivec,
	des_cblock *inw,des_cblock *outw,int enc)
	{
	DES_xcbc_encrypt((unsigned char *)input, (unsigned char *)output,
		length, (DES_key_schedule *)schedule, ivec, inw, outw, enc);
	}
void des_cfb_encrypt(unsigned char *in,unsigned char *out,int numbits,
	long length,des_key_schedule schedule,des_cblock *ivec,int enc)
	{
	DES_cfb_encrypt(in, out, numbits, length,
		(DES_key_schedule *)schedule, ivec, enc);
	}
void des_ecb_encrypt(des_cblock *input,des_cblock *output,
	des_key_schedule ks,int enc)
	{
	DES_ecb_encrypt(input, output, (DES_key_schedule *)ks, enc);
	}
void des_encrypt(DES_LONG *data,des_key_schedule ks, int enc)
	{
	DES_encrypt1(data, (DES_key_schedule *)ks, enc);
	}
void des_encrypt2(DES_LONG *data,des_key_schedule ks, int enc)
	{
	DES_encrypt2(data, (DES_key_schedule *)ks, enc);
	}
void des_encrypt3(DES_LONG *data, des_key_schedule ks1,
	des_key_schedule ks2, des_key_schedule ks3)
	{
	DES_encrypt3(data, (DES_key_schedule *)ks1, (DES_key_schedule *)ks2,
		(DES_key_schedule *)ks3);
	}
void des_decrypt3(DES_LONG *data, des_key_schedule ks1,
	des_key_schedule ks2, des_key_schedule ks3)
	{
	DES_decrypt3(data, (DES_key_schedule *)ks1, (DES_key_schedule *)ks2,
		(DES_key_schedule *)ks3);
	}
void des_ede3_cbc_encrypt(des_cblock *input, des_cblock *output, 
	long length, des_key_schedule ks1, des_key_schedule ks2, 
	des_key_schedule ks3, des_cblock *ivec, int enc)
	{
	DES_ede3_cbc_encrypt((unsigned char *)input, (unsigned char *)output,
		length, (DES_key_schedule *)ks1, (DES_key_schedule *)ks2,
		(DES_key_schedule *)ks3, ivec, enc);
	}
void des_ede3_cfb64_encrypt(unsigned char *in, unsigned char *out,
	long length, des_key_schedule ks1, des_key_schedule ks2,
	des_key_schedule ks3, des_cblock *ivec, int *num, int enc)
	{
	DES_ede3_cfb64_encrypt(in, out, length,
		(DES_key_schedule *)ks1, (DES_key_schedule *)ks2,
		(DES_key_schedule *)ks3, ivec, num, enc);
	}
void des_ede3_ofb64_encrypt(unsigned char *in, unsigned char *out,
	long length, des_key_schedule ks1, des_key_schedule ks2,
	des_key_schedule ks3, des_cblock *ivec, int *num)
	{
	DES_ede3_ofb64_encrypt(in, out, length,
		(DES_key_schedule *)ks1, (DES_key_schedule *)ks2,
		(DES_key_schedule *)ks3, ivec, num);
	}

void des_xwhite_in2out(des_cblock (*des_key), des_cblock (*in_white),
	des_cblock (*out_white))
	{
	DES_xwhite_in2out(des_key, in_white, out_white);
	}

int des_enc_read(int fd,char *buf,int len,des_key_schedule sched,
	des_cblock *iv)
	{
	return DES_enc_read(fd, buf, len, (DES_key_schedule *)sched, iv);
	}
int des_enc_write(int fd,char *buf,int len,des_key_schedule sched,
	des_cblock *iv)
	{
	return DES_enc_write(fd, buf, len, (DES_key_schedule *)sched, iv);
	}
char *des_fcrypt(const char *buf,const char *salt, char *ret)
	{
	return DES_fcrypt(buf, salt, ret);
	}
char *des_crypt(const char *buf,const char *salt)
	{
	return DES_crypt(buf, salt);
	}
#if !defined(PERL5) && !defined(__FreeBSD__) && !defined(NeXT)
char *crypt(const char *buf,const char *salt)
	{
	return DES_crypt(buf, salt);
	}
#endif
void des_ofb_encrypt(unsigned char *in,unsigned char *out,
	int numbits,long length,des_key_schedule schedule,des_cblock *ivec)
	{
	DES_ofb_encrypt(in, out, numbits, length, (DES_key_schedule *)schedule,
		ivec);
	}
void des_pcbc_encrypt(des_cblock *input,des_cblock *output,long length,
	des_key_schedule schedule,des_cblock *ivec,int enc)
	{
	DES_pcbc_encrypt((unsigned char *)input, (unsigned char *)output,
		length, (DES_key_schedule *)schedule, ivec, enc);
	}
DES_LONG des_quad_cksum(des_cblock *input,des_cblock *output,
	long length,int out_count,des_cblock *seed)
	{
	return DES_quad_cksum((unsigned char *)input, output, length,
		out_count, seed);
	}
void des_random_seed(des_cblock key)
	{
	RAND_seed(key, sizeof(des_cblock));
	}
void des_random_key(des_cblock ret)
	{
	DES_random_key((DES_cblock *)ret);
	}
void des_set_odd_parity(des_cblock *key)
	{
	DES_set_odd_parity(key);
	}
int des_is_weak_key(des_cblock *key)
	{
	return DES_is_weak_key(key);
	}
int des_set_key(des_cblock *key,des_key_schedule schedule)
	{
	return DES_set_key(key, (DES_key_schedule *)schedule);
	}
int des_key_sched(des_cblock *key,des_key_schedule schedule)
	{
	return DES_key_sched(key, (DES_key_schedule *)schedule);
	}
void des_string_to_key(char *str,des_cblock *key)
	{
	DES_string_to_key(str, key);
	}
void des_string_to_2keys(char *str,des_cblock *key1,des_cblock *key2)
	{
	DES_string_to_2keys(str, key1, key2);
	}
void des_cfb64_encrypt(unsigned char *in, unsigned char *out, long length,
	des_key_schedule schedule, des_cblock *ivec, int *num, int enc)
	{
	DES_cfb64_encrypt(in, out, length, (DES_key_schedule *)schedule,
		ivec, num, enc);
	}
void des_ofb64_encrypt(unsigned char *in, unsigned char *out, long length,
	des_key_schedule schedule, des_cblock *ivec, int *num)
	{
	DES_ofb64_encrypt(in, out, length, (DES_key_schedule *)schedule,
		ivec, num);
	}

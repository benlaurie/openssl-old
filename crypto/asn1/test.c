/* crypto/asn1/test.c */
/* Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
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
#include "../error/err.h"
#include "./asn1.h"
#include "rsa.h"
#include "../x509/x509.h"
#include "x509.h"

main()
	{
	main1();
	main2();
	main3();
	main4();
	}

main1()
	{
	FILE *in;
	unsigned char buf[10240],buf2[10240],*p;
	int num,i;

	X509 *nx=NULL,*mx=NULL;

	in=fopen("x.der","r");
	if (in == NULL)
		{
		perror("x.der");
		exit(1);
		}
	num=fread(buf,1,10240,in);
	fclose(in);


		p=buf;
		if (d2i_X509(&nx,&p,num) == NULL) goto err;
		printf("num=%d p-buf=%d\n",num,p-buf);

		p=buf2;
		num=i2d_X509(nx,&p);
		printf("num=%d p-buf=%d\n",num,p-buf2);

		if (memcmp(buf,buf2,num) != 0)
			{
			fprintf(stderr,"data difference\n");
			for (i=0; i<num; i++)
				fprintf(stderr,"%c%03d <%02X-%02X>\n",
					(buf[i] == buf2[i])?' ':'*',i,
					buf[i],buf2[i]);
			fprintf(stderr,"\n");
			exit(1);
			}

		p=buf2;
		if (d2i_X509(&mx,&p,num) == NULL) goto err;
		printf("num=%d p-buf=%d\n",num,p-buf2);

	return(1);
err:
	ERR_load_crypto_strings();
	ERR_print_errors(stderr);
	return(0);
	}

main2()
	{
	FILE *in;
	unsigned char buf[10240],buf2[10240],*p;
	int num,i;

	X509_CRL *nx=NULL,*mx=NULL;

	in=fopen("crl.der","r");
	if (in == NULL)
		{
		perror("crl.der");
		exit(1);
		}
	num=fread(buf,1,10240,in);
	fclose(in);


		p=buf;
		if (d2i_X509_CRL(&nx,&p,num) == NULL) goto err;
		printf("num=%d p-buf=%d\n",num,p-buf);

		p=buf2;
		num=i2d_X509_CRL(nx,&p);
		printf("num=%d p-buf=%d\n",num,p-buf2);

		if (memcmp(buf,buf2,num) != 0)
			{
			fprintf(stderr,"data difference\n");
			for (i=0; i<num; i++)
				fprintf(stderr,"%c%03d <%02X-%02X>\n",
					(buf[i] == buf2[i])?' ':'*',i,
					buf[i],buf2[i]);
			fprintf(stderr,"\n");
			exit(1);
			}

	return(1);
err:
	ERR_load_crypto_strings();
	ERR_print_errors(stderr);
	return(0);
	}

main3()
	{
	FILE *in;
	unsigned char buf[10240],buf2[10240],*p;
	int num,i;

	X509_REQ *nx=NULL,*mx=NULL;

	in=fopen("req.der","r");
	if (in == NULL)
		{
		perror("req.der");
		exit(1);
		}
	num=fread(buf,1,10240,in);
	fclose(in);


		p=buf;
		if (d2i_X509_REQ(&nx,&p,num) == NULL) goto err;
		printf("num=%d p-buf=%d\n",num,p-buf);

		p=buf2;
		num=i2d_X509_REQ(nx,&p);
		printf("num=%d p-buf=%d\n",num,p-buf2);

		if (memcmp(buf,buf2,num) != 0)
			{
			fprintf(stderr,"data difference\n");
			for (i=0; i<num; i++)
				fprintf(stderr,"%c%03d <%02X-%02X>\n",
					(buf[i] == buf2[i])?' ':'*',i,
					buf[i],buf2[i]);
			fprintf(stderr,"\n");
			exit(1);
			}

	return(1);
err:
	ERR_load_crypto_strings();
	ERR_print_errors(stderr);
	return(0);
	}

main4()
	{
	FILE *in;
	unsigned char buf[10240],buf2[10240],*p;
	int num,i;

	RSA *nx=NULL,*mx=NULL;

	in=fopen("rsa.der","r");
	if (in == NULL)
		{
		perror("rsa.der");
		exit(1);
		}
	num=fread(buf,1,10240,in);
	fclose(in);


		p=buf;
		if (d2i_RSAPrivateKey(&nx,&p,num) == NULL) goto err;
		printf("num=%d p-buf=%d\n",num,p-buf);

		p=buf2;
		num=i2d_RSAPrivateKey(nx,&p);
		printf("num=%d p-buf=%d\n",num,p-buf2);

		if (memcmp(buf,buf2,num) != 0)
			{
			fprintf(stderr,"data difference\n");
			for (i=0; i<num; i++)
				fprintf(stderr,"%c%03d <%02X-%02X>\n",
					(buf[i] == buf2[i])?' ':'*',i,
					buf[i],buf2[i]);
			fprintf(stderr,"\n");
			exit(1);
			}

	return(1);
err:
	ERR_load_crypto_strings();
	ERR_print_errors(stderr);
	return(0);
	}


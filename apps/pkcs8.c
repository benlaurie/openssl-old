/* pkcs8.c */
/* Written by Dr Stephen N Henson (shenson@bigfoot.com) for the OpenSSL
 * project 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>

#include "apps.h"
#define PROG pkcs8_main


int MAIN(int argc, char **argv)
{
	char **args, *infile = NULL, *outfile = NULL;
	BIO *in = NULL, *out = NULL;
	int topk8 = 0;
	int pbe_nid = -1;
	int iter = PKCS12_DEFAULT_ITER;
	int p8_broken = PKCS8_OK;
	X509_SIG *p8;
	PKCS8_PRIV_KEY_INFO *p8inf;
	EVP_PKEY *pkey;
	char pass[50];
	int badarg = 0;
	if (bio_err == NULL) bio_err = BIO_new_fp (stderr, BIO_NOCLOSE);
	ERR_load_crypto_strings();
	SSLeay_add_all_algorithms();
	args = argv + 1;
	while (!badarg && *args && *args[0] == '-') {
		if (!strcmp (*args, "-topk8")) topk8 = 1;
		else if (!strcmp (*args, "-noiter")) iter = 1;
		else if (!strcmp (*args, "-nooct")) p8_broken = PKCS8_NO_OCTET;
		else if (!strcmp (*args, "-in")) {
			if (args[1]) {
				args++;
				infile = *args;
			} else badarg = 1;
		} else if (!strcmp (*args, "-out")) {
			if (args[1]) {
				args++;
				outfile = *args;
			} else badarg = 1;
		} else badarg = 1;
		args++;
	}

	if (badarg) {
		BIO_printf (bio_err, "Usage pkcs8 [options]\n");
		BIO_printf (bio_err, "where options are\n");
		BIO_printf (bio_err, "-in file	input file\n");
		BIO_printf (bio_err, "-out file	output file\n");
		BIO_printf (bio_err, "-topk8    output PKCS8 file\n");
		BIO_printf (bio_err, "-nooct    use (broken) no octet form\n");
		BIO_printf (bio_err, "-noiter   use 1 as iteration cound\n");
		return (1);
	}

	if (pbe_nid == -1) pbe_nid = NID_pbeWithMD5AndDES_CBC;

	if (infile) {
		if (!(in = BIO_new_file (infile, "r"))) {
			BIO_printf (bio_err,
				 "Can't open input file %s\n", infile);
			return (1);
		}
	} else in = BIO_new_fp (stdin, BIO_NOCLOSE);

	if (outfile) {
		if (!(out = BIO_new_file (outfile, "w"))) {
			BIO_printf (bio_err,
				 "Can't open output file %s\n", outfile);
			return (1);
		}
	} else out = BIO_new_fp (stdout, BIO_NOCLOSE);

	if (topk8) {
		if (!(pkey = PEM_read_bio_PrivateKey(in, NULL, NULL))) {
			BIO_printf (bio_err, "Error reading key\n", outfile);
			ERR_print_errors(bio_err);
			return (1);
		}
		if (!(p8inf = EVP_PKEY2PKCS8(pkey))) {
			BIO_printf (bio_err, "Error converting key\n", outfile);
			ERR_print_errors(bio_err);
			return (1);
		}
		PKCS8_set_broken(p8inf, p8_broken);
		EVP_read_pw_string(pass, 50, "Enter Encryption Password:", 1);
		if (!(p8 = PKCS8_encrypt(pbe_nid, pass, strlen(pass),
				 NULL, 0, iter, p8inf))) {
			BIO_printf (bio_err, "Error encrypting key\n", outfile);
			ERR_print_errors(bio_err);
			return (1);
		}
		PKCS8_PRIV_KEY_INFO_free (p8inf);
		PEM_write_bio_PKCS8 (out, p8);
		X509_SIG_free(p8);
		return (0);
	}

	if (!(p8 = PEM_read_bio_PKCS8 (in, NULL, NULL))) {
		BIO_printf (bio_err, "Error reading key\n", outfile);
		ERR_print_errors(bio_err);
		return (1);
	}
	EVP_read_pw_string(pass, 50, "Enter Password:", 0);
	p8inf = M_PKCS8_decrypt(p8, pass, strlen(pass));
	if (!p8inf) {
		BIO_printf(bio_err, "Error decrypting key\n", outfile);
		ERR_print_errors(bio_err);
		return (1);
	}

	if (!(pkey = EVP_PKCS82PKEY(p8inf))) {
		BIO_printf(bio_err, "Error converting key\n", outfile);
		ERR_print_errors(bio_err);
		return (1);
	}
	
	if (p8inf->broken) {
		BIO_printf(bio_err, "Warning: broken key encoding: ");
		switch (p8inf->broken) {
			case PKCS8_NO_OCTET:
			BIO_printf(bio_err, "No Octet String\n");
			break;

			default:
			BIO_printf(bio_err, "Unknown broken type\n");
			break;
		}
	}
	
	PKCS8_PRIV_KEY_INFO_free(p8inf);

	PEM_write_bio_PrivateKey (out, pkey, NULL, NULL, 0, NULL);

	return (0);
}

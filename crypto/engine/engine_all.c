/* crypto/engine/engine_all.c -*- mode: C; c-file-style: "eay" -*- */
/* Written by Richard Levitte <richard@levitte.org> for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
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

#include <openssl/engine.h>
#include "engine_int.h"
static int engine_add(ENGINE *e)
	{
	if (!ENGINE_by_id(ENGINE_get_id(e)))
		{
		(void)ERR_get_error();
		return ENGINE_add(e);
		}
	return 1;
	}

void ENGINE_load_cswift(void)
	{
#ifndef NO_HW
#ifndef NO_HW_CSWIFT
	engine_add(ENGINE_cswift());
#endif /* !NO_HW_CSWIFT */
#endif /* !NO_HW */
	}

void ENGINE_load_chil(void)
	{
#ifndef NO_HW
#ifndef NO_HW_CSWIFT
	engine_add(ENGINE_ncipher());
#endif /* !NO_HW_CSWIFT */
#endif /* !NO_HW */
	}

void ENGINE_load_atalla(void)
	{
#ifndef NO_HW
#ifndef NO_HW_CSWIFT
	engine_add(ENGINE_atalla());
#endif /* !NO_HW_CSWIFT */
#endif /* !NO_HW */
	}

void ENGINE_load_nuron(void)
	{
#ifndef NO_HW
#ifndef NO_HW_CSWIFT
	engine_add(ENGINE_nuron());
#endif /* !NO_HW_CSWIFT */
#endif /* !NO_HW */
	}

void ENGINE_load_builtin_engines(void)
	{
	static int done=0;

	if (done) return;
	done=1;

	ENGINE_load_cswift();
	ENGINE_load_chil();
	ENGINE_load_atalla();
	ENGINE_load_nuron();
	}

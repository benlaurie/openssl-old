/* crypto/bio/bss_sock.c */
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

#ifndef OPENSSL_NO_SOCK

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#define USE_SOCKETS
#include "cryptlib.h"
#include <openssl/bio.h>

/* The following types are required to work in a 64-bit environment on
   OpenVMS for Alpha.  In that environment, the pointer types char_pp
   and char_p will be 32 bits wide.  In all other environments (including
   all other platforms), they will have whatever size is the appropriate
   default there.
   Additionally, let's define special variants of malloc and friends that
   give the expected result visavi 32-bit pointers in an otherwise 64-bit
   environment.  These would normally be declared with the OpenVMSy string.h,
   if we wouldn't compile with /STANDARD=ANSI.  */
#if !defined(OPENSSL_SYS_VMS) && __INITIAL_POINTER_SIZE == 64
#pragma __required_pointer_size __save
#pragma __required_pointer_size 32
#endif
typedef char * char_32p;
#ifdef OPENSSL_SYS_VMS
void *_malloc32(size_t);
#define _free32 free
void *_memset32(void *__s, int __c, size_t __n);
#else
#define _malloc32 OPENSSL_malloc
#define _free32 OPENSSL_free
#define _memset32 memset
#endif
#if !defined(OPENSSL_SYS_VMS) && __INITIAL_POINTER_SIZE == 64
#pragma __required_pointer_size __restore
#endif


#ifdef WATT32
#define sock_write SockWrite  /* Watt-32 uses same names */
#define sock_read  SockRead
#define sock_puts  SockPuts
#endif

static int sock_write(BIO *h, const char *buf, int num);
static int sock_read(BIO *h, char *buf, int size);
static int sock_puts(BIO *h, const char *str);
static long sock_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int sock_new(BIO *h);
static int sock_free(BIO *data);
int BIO_sock_should_retry(int s);

static BIO_METHOD methods_sockp=
	{
	BIO_TYPE_SOCKET,
	"socket",
	sock_write,
	sock_read,
	sock_puts,
	NULL, /* sock_gets, */
	sock_ctrl,
	sock_new,
	sock_free,
	NULL,
	};

BIO_METHOD *BIO_s_socket(void)
	{
	return(&methods_sockp);
	}

BIO *BIO_new_socket(int fd, int close_flag)
	{
	BIO *ret;

	ret=BIO_new(BIO_s_socket());
	if (ret == NULL) return(NULL);
	BIO_set_fd(ret,fd,close_flag);
	return(ret);
	}

static int sock_new(BIO *bi)
	{
	bi->init=0;
	bi->num=0;
	bi->ptr=NULL;
	bi->flags=0;
	return(1);
	}

static int sock_free(BIO *a)
	{
	if (a == NULL) return(0);
	if (a->shutdown)
		{
		if (a->init)
			{
			SHUTDOWN2(a->num);
			}
		a->init=0;
		a->flags=0;
		}
	return(1);
	}
	
static int sock_read(BIO *b, char *out, int outl)
	{
	int ret=0;

#if defined(OPENSSL_SYS_VMS) && __INITIAL_POINTER_SIZE == 64
#pragma __required_pointer_size __save
#pragma __required_pointer_size 32

	char_32p out32 = NULL;

	if (out != NULL)
		{
		out32 = (char_32p)_malloc32(outl*sizeof(char_32p));  	/* changed for 64-bit */
		_memset32(out32, 0, outl*sizeof(char_32p));		/* changed for 64-bit */
		memcpy(out32,out,outl);					/* changed for 64-bit */
		}

#pragma __required_pointer_size __restore
#endif

#if defined(OPENSSL_SYS_VMS) && __INITIAL_POINTER_SIZE == 64
	if (out32 != NULL)
#else
	if (out != NULL)
#endif
		{
		clear_socket_error();
#if defined(OPENSSL_SYS_VMS) &&  __INITIAL_POINTER_SIZE == 64
		ret=readsocket(b->num,out32,outl);
		memcpy(out,out32,outl);
		_free32(out32);
#else
		ret=readsocket(b->num,out,outl);
#endif		
		BIO_clear_retry_flags(b);
		if (ret <= 0)
			{
			if (BIO_sock_should_retry(ret))
				BIO_set_retry_read(b);
			}
		}
	return(ret);
	}

static int sock_write(BIO *b, const char *in, int inl)
	{
	int ret;
	
#if defined(OPENSSL_SYS_VMS) && __INITIAL_POINTER_SIZE == 64
#pragma __required_pointer_size __save
#pragma __required_pointer_size 32

        char_32p in32;

        in32 = (char_32p)_malloc32(inl*sizeof(char_32p));   /* changed for 64-bit */
        _memset32(in32, 0, inl*sizeof(char_32p));           /* changed for 64-bit */
        memcpy(in32,in,inl);                                /* changed for 64-bit */

#pragma __required_pointer_size __restore
#endif

	clear_socket_error();

#if defined(OPENSSL_SYS_VMS) && __INITIAL_POINTER_SIZE == 64
	ret=writesocket(b->num,in32,inl);
	_free32(in32);
#else
	ret=writesocket(b->num,in,inl);
#endif

	BIO_clear_retry_flags(b);
	if (ret <= 0)
		{
		if (BIO_sock_should_retry(ret))
			BIO_set_retry_write(b);
		}
	return(ret);
	}

static long sock_ctrl(BIO *b, int cmd, long num, void *ptr)
	{
	long ret=1;
	int *ip;

	switch (cmd)
		{
	case BIO_CTRL_RESET:
		num=0;
	case BIO_C_FILE_SEEK:
		ret=0;
		break;
	case BIO_C_FILE_TELL:
	case BIO_CTRL_INFO:
		ret=0;
		break;
	case BIO_C_SET_FD:
		sock_free(b);
		b->num= *((int *)ptr);
		b->shutdown=(int)num;
		b->init=1;
		break;
	case BIO_C_GET_FD:
		if (b->init)
			{
			ip=(int *)ptr;
			if (ip != NULL) *ip=b->num;
			ret=b->num;
			}
		else
			ret= -1;
		break;
	case BIO_CTRL_GET_CLOSE:
		ret=b->shutdown;
		break;
	case BIO_CTRL_SET_CLOSE:
		b->shutdown=(int)num;
		break;
	case BIO_CTRL_PENDING:
	case BIO_CTRL_WPENDING:
		ret=0;
		break;
	case BIO_CTRL_DUP:
	case BIO_CTRL_FLUSH:
		ret=1;
		break;
	default:
		ret=0;
		break;
		}
	return(ret);
	}

static int sock_puts(BIO *bp, const char *str)
	{
	int n,ret;

	n=strlen(str);
	ret=sock_write(bp,str,n);
	return(ret);
	}

int BIO_sock_should_retry(int i)
	{
	int err;

	if ((i == 0) || (i == -1))
		{
		err=get_last_socket_error();

#if defined(OPENSSL_SYS_WINDOWS) && 0 /* more microsoft stupidity? perhaps not? Ben 4/1/99 */
		if ((i == -1) && (err == 0))
			return(1);
#endif

		return(BIO_sock_non_fatal_error(err));
		}
	return(0);
	}

int BIO_sock_non_fatal_error(int err)
	{
	switch (err)
		{
#if defined(OPENSSL_SYS_WINDOWS)
# if defined(WSAEWOULDBLOCK)
	case WSAEWOULDBLOCK:
# endif

# if 0 /* This appears to always be an error */
#  if defined(WSAENOTCONN)
	case WSAENOTCONN:
#  endif
# endif
#endif

#ifdef EWOULDBLOCK
# ifdef WSAEWOULDBLOCK
#  if WSAEWOULDBLOCK != EWOULDBLOCK
	case EWOULDBLOCK:
#  endif
# else
	case EWOULDBLOCK:
# endif
#endif

#if defined(ENOTCONN)
	case ENOTCONN:
#endif

#ifdef EINTR
	case EINTR:
#endif

#ifdef EAGAIN
#if EWOULDBLOCK != EAGAIN
	case EAGAIN:
# endif
#endif

#ifdef EPROTO
	case EPROTO:
#endif

#ifdef EINPROGRESS
	case EINPROGRESS:
#endif

#ifdef EALREADY
	case EALREADY:
#endif
		return(1);
		/* break; */
	default:
		break;
		}
	return(0);
	}
#endif

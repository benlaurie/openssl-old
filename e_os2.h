/* e_os2.h */

#ifndef HEADER_E_OS2_H
#define HEADER_E_OS2_H

#ifdef  __cplusplus
extern "C" {
#endif

/* Definitions of OPENSSL_GLOBAL and OPENSSL_EXTERN,
   to define and declare certain global
   symbols that, with some compilers under VMS, have to be defined and
   declared explicitely with globaldef and globalref.  On other OS:es,
   these macros are defined with something sensible. */

#if defined(VMS) && !defined(__DECC)
# define OPENSSL_EXTERN globalref
# define OPENSSL_GLOBAL globaldef
#else
# define OPENSSL_EXTERN extern
# define OPENSSL_GLOBAL
#endif

/* The above definitions should be used throughout the library,
 * but as long as EXTERN and GLOBAL occur there, we keep the following
 * definitions, too: */
#if defined(VMS) && !defined(__DECC)
# define EXTERN globalref
# define GLOBAL globaldef
#else
# define EXTERN extern
# define GLOBAL
#endif


#ifdef  __cplusplus
}
#endif
#endif


/* openssl/engine.h */
/* Written by Geoff Thorpe (geoff@geoffthorpe.net) for the OpenSSL
 * project 2000.
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

#ifndef HEADER_ENGINE_H
#define HEADER_ENGINE_H

#include <openssl/types.h>
#include <openssl/bn.h>
#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif
#ifndef OPENSSL_NO_DH
#include <openssl/dh.h>
#endif
#include <openssl/rand.h>
#include <openssl/ui.h>
#include <openssl/symhacks.h>
#include <openssl/err.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* Fixups for missing algorithms */
#ifdef OPENSSL_NO_RSA
typedef void RSA_METHOD;
#endif
#ifdef OPENSSL_NO_DSA
typedef void DSA_METHOD;
#endif
#ifdef OPENSSL_NO_DH
typedef void DH_METHOD;
#endif

/* These flags are used to control combinations of algorithm (methods)
 * by bitwise "OR"ing. */
#define ENGINE_METHOD_RSA		(unsigned int)0x0001
#define ENGINE_METHOD_DSA		(unsigned int)0x0002
#define ENGINE_METHOD_DH		(unsigned int)0x0004
#define ENGINE_METHOD_RAND		(unsigned int)0x0008
#define ENGINE_METHOD_BN_MOD_EXP	(unsigned int)0x0010
#define ENGINE_METHOD_BN_MOD_EXP_CRT	(unsigned int)0x0020
/* Obvious all-or-nothing cases. */
#define ENGINE_METHOD_ALL		(unsigned int)0xFFFF
#define ENGINE_METHOD_NONE		(unsigned int)0x0000

/* ENGINE flags that can be set by ENGINE_set_flags(). */
/* #define ENGINE_FLAGS_MALLOCED	0x0001 */ /* Not used */

/* This flag is for ENGINEs that wish to handle the various 'CMD'-related
 * control commands on their own. Without this flag, ENGINE_ctrl() handles these
 * control commands on behalf of the ENGINE using their "cmd_defns" data. */
#define ENGINE_FLAGS_MANUAL_CMD_CTRL	(int)0x0002

/* This flag is for ENGINEs who return new duplicate structures when found via
 * "ENGINE_by_id()". When an ENGINE must store state (eg. if ENGINE_ctrl()
 * commands are called in sequence as part of some stateful process like
 * key-generation setup and execution), it can set this flag - then each attempt
 * to obtain the ENGINE will result in it being copied into a new structure.
 * Normally, ENGINEs don't declare this flag so ENGINE_by_id() just increments
 * the existing ENGINE's structural reference count. */
#define ENGINE_FLAGS_BY_ID_COPY		(int)0x0004

/* ENGINEs can support their own command types, and these flags are used in
 * ENGINE_CTRL_GET_CMD_FLAGS to indicate to the caller what kind of input each
 * command expects. Currently only numeric and string input is supported. If a
 * control command supports none of the _NUMERIC, _STRING, or _NO_INPUT options,
 * then it is regarded as an "internal" control command - and not for use in
 * config setting situations. As such, they're not available to the
 * ENGINE_ctrl_cmd_string() function, only raw ENGINE_ctrl() access. Changes to
 * this list of 'command types' should be reflected carefully in
 * ENGINE_cmd_is_executable() and ENGINE_ctrl_cmd_string(). */

/* accepts a 'long' input value (3rd parameter to ENGINE_ctrl) */
#define ENGINE_CMD_FLAG_NUMERIC		(unsigned int)0x0001
/* accepts string input (cast from 'void*' to 'const char *', 4th parameter to
 * ENGINE_ctrl) */
#define ENGINE_CMD_FLAG_STRING		(unsigned int)0x0002
/* Indicates that the control command takes *no* input. Ie. the control command
 * is unparameterised. */
#define ENGINE_CMD_FLAG_NO_INPUT	(unsigned int)0x0004
/* Indicates that the control command is internal. This control command won't
 * be shown in any output, and is only usable through the ENGINE_ctrl_cmd()
 * function. */
#define ENGINE_CMD_FLAG_INTERNAL	(unsigned int)0x0008

/* NB: These 3 control commands are deprecated and should not be used. ENGINEs
 * relying on these commands should compile conditional support for
 * compatibility (eg. if these symbols are defined) but should also migrate the
 * same functionality to their own ENGINE-specific control functions that can be
 * "discovered" by calling applications. The fact these control commands
 * wouldn't be "executable" (ie. usable by text-based config) doesn't change the
 * fact that application code can find and use them without requiring per-ENGINE
 * hacking. */

/* These flags are used to tell the ctrl function what should be done.
 * All command numbers are shared between all engines, even if some don't
 * make sense to some engines.  In such a case, they do nothing but return
 * the error ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED. */
#define ENGINE_CTRL_SET_LOGSTREAM		1
#define ENGINE_CTRL_SET_PASSWORD_CALLBACK	2
#define ENGINE_CTRL_HUP				3 /* Close and reinitialise any
						     handles/connections etc. */
#define ENGINE_CTRL_SET_USER_INTERFACE          4 /* Alternative to callback */
#define ENGINE_CTRL_SET_CALLBACK_DATA           5 /* User-specific data, used
                                                     when calling the password
                                                     callback and the user
                                                     interface */

/* These control commands allow an application to deal with an arbitrary engine
 * in a dynamic way. Warn: Negative return values indicate errors FOR THESE
 * COMMANDS because zero is used to indicate 'end-of-list'. Other commands,
 * including ENGINE-specific command types, return zero for an error.
 *
 * An ENGINE can choose to implement these ctrl functions, and can internally
 * manage things however it chooses - it does so by setting the
 * ENGINE_FLAGS_MANUAL_CMD_CTRL flag (using ENGINE_set_flags()). Otherwise the
 * ENGINE_ctrl() code handles this on the ENGINE's behalf using the cmd_defns
 * data (set using ENGINE_set_cmd_defns()). This means an ENGINE's ctrl()
 * handler need only implement its own commands - the above "meta" commands will
 * be taken care of. */

/* Returns non-zero if the supplied ENGINE has a ctrl() handler. If "not", then
 * all the remaining control commands will return failure, so it is worth
 * checking this first if the caller is trying to "discover" the engine's
 * capabilities and doesn't want errors generated unnecessarily. */
#define ENGINE_CTRL_HAS_CTRL_FUNCTION		10
/* Returns a positive command number for the first command supported by the
 * engine. Returns zero if no ctrl commands are supported. */
#define ENGINE_CTRL_GET_FIRST_CMD_TYPE		11
/* The 'long' argument specifies a command implemented by the engine, and the
 * return value is the next command supported, or zero if there are no more. */
#define ENGINE_CTRL_GET_NEXT_CMD_TYPE		12
/* The 'void*' argument is a command name (cast from 'const char *'), and the
 * return value is the command that corresponds to it. */
#define ENGINE_CTRL_GET_CMD_FROM_NAME		13
/* The next two allow a command to be converted into its corresponding string
 * form. In each case, the 'long' argument supplies the command. In the NAME_LEN
 * case, the return value is the length of the command name (not counting a
 * trailing EOL). In the NAME case, the 'void*' argument must be a string buffer
 * large enough, and it will be populated with the name of the command (WITH a
 * trailing EOL). */
#define ENGINE_CTRL_GET_NAME_LEN_FROM_CMD	14
#define ENGINE_CTRL_GET_NAME_FROM_CMD		15
/* The next two are similar but give a "short description" of a command. */
#define ENGINE_CTRL_GET_DESC_LEN_FROM_CMD	16
#define ENGINE_CTRL_GET_DESC_FROM_CMD		17
/* With this command, the return value is the OR'd combination of
 * ENGINE_CMD_FLAG_*** values that indicate what kind of input a given
 * engine-specific ctrl command expects. */
#define ENGINE_CTRL_GET_CMD_FLAGS		18

/* ENGINE implementations should start the numbering of their own control
 * commands from this value. (ie. ENGINE_CMD_BASE, ENGINE_CMD_BASE + 1, etc). */
#define ENGINE_CMD_BASE		200

/* NB: These 2 nCipher "chil" control commands are deprecated, and their
 * functionality is now available through ENGINE-specific control commands
 * (exposed through the above-mentioned 'CMD'-handling). Code using these 2
 * commands should be migrated to the more general command handling before these
 * are removed. */

/* Flags specific to the nCipher "chil" engine */
#define ENGINE_CTRL_CHIL_SET_FORKCHECK		100
	/* Depending on the value of the (long)i argument, this sets or
	 * unsets the SimpleForkCheck flag in the CHIL API to enable or
	 * disable checking and workarounds for applications that fork().
	 */
#define ENGINE_CTRL_CHIL_NO_LOCKING		101
	/* This prevents the initialisation function from providing mutex
	 * callbacks to the nCipher library. */

/* If an ENGINE supports its own specific control commands and wishes the
 * framework to handle the above 'ENGINE_CMD_***'-manipulation commands on its
 * behalf, it should supply a null-terminated array of ENGINE_CMD_DEFN entries
 * to ENGINE_set_cmd_defns(). It should also implement a ctrl() handler that
 * supports the stated commands (ie. the "cmd_num" entries as described by the
 * array). NB: The array must be ordered in increasing order of cmd_num.
 * "null-terminated" means that the last ENGINE_CMD_DEFN element has cmd_num set
 * to zero and/or cmd_name set to NULL. */
typedef struct ENGINE_CMD_DEFN_st
	{
	unsigned int cmd_num; /* The command number */
	const char *cmd_name; /* The command name itself */
	const char *cmd_desc; /* A short description of the command */
	unsigned int cmd_flags; /* The input the command expects */
	} ENGINE_CMD_DEFN;

/* As we're missing a BIGNUM_METHOD, we need a couple of locally
 * defined function types that engines can implement. */

/* mod_exp operation, calculates; r = a ^ p mod m
 * NB: ctx can be NULL, but if supplied, the implementation may use
 * it if it wishes. */
typedef int (*BN_MOD_EXP)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
		const BIGNUM *m, BN_CTX *ctx);

/* private key operation for RSA, provided seperately in case other
 * RSA implementations wish to use it. */
typedef int (*BN_MOD_EXP_CRT)(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
		const BIGNUM *q, const BIGNUM *dmp1, const BIGNUM *dmq1,
		const BIGNUM *iqmp, BN_CTX *ctx);

/* The list of "engine" types is a static array of (const ENGINE*)
 * pointers (not dynamic because static is fine for now and we otherwise
 * have to hook an appropriate load/unload function in to initialise and
 * cleanup). */
struct engine_st;
typedef struct engine_st ENGINE;

/* Generic function pointer */
typedef int (*ENGINE_GEN_FUNC_PTR)();
/* Generic function pointer taking no arguments */
typedef int (*ENGINE_GEN_INT_FUNC_PTR)(ENGINE *);
/* Specific control function pointer */
typedef int (*ENGINE_CTRL_FUNC_PTR)(ENGINE *, int, long, void *, void (*f)());
/* Generic load_key function pointer */
typedef EVP_PKEY * (*ENGINE_LOAD_KEY_PTR)(ENGINE *, const char *,
	UI_METHOD *ui_method, void *callback_data);

/* STRUCTURE functions ... all of these functions deal with pointers to ENGINE
 * structures where the pointers have a "structural reference". This means that
 * their reference is to allowed access to the structure but it does not imply
 * that the structure is functional. To simply increment or decrement the
 * structural reference count, use ENGINE_by_id and ENGINE_free. NB: This is not
 * required when iterating using ENGINE_get_next as it will automatically
 * decrement the structural reference count of the "current" ENGINE and
 * increment the structural reference count of the ENGINE it returns (unless it
 * is NULL). */

/* Get the first/last "ENGINE" type available. */
ENGINE *ENGINE_get_first(void);
ENGINE *ENGINE_get_last(void);
/* Iterate to the next/previous "ENGINE" type (NULL = end of the list). */
ENGINE *ENGINE_get_next(ENGINE *e);
ENGINE *ENGINE_get_prev(ENGINE *e);
/* Add another "ENGINE" type into the array. */
int ENGINE_add(ENGINE *e);
/* Remove an existing "ENGINE" type from the array. */
int ENGINE_remove(ENGINE *e);
/* Retrieve an engine from the list by its unique "id" value. */
ENGINE *ENGINE_by_id(const char *id);
/* Add all the built-in engines.  By default, only the OpenSSL software
   engine is loaded */
void ENGINE_load_cswift(void);
void ENGINE_load_chil(void);
void ENGINE_load_atalla(void);
void ENGINE_load_nuron(void);
void ENGINE_load_ubsec(void);
void ENGINE_load_openbsd_dev_crypto(void);
void ENGINE_load_builtin_engines(void);

/* Load all the currently known ciphers from all engines */
void ENGINE_load_ciphers(void);

/* Send parametrised control commands to the engine. The possibilities to send
 * down an integer, a pointer to data or a function pointer are provided. Any of
 * the parameters may or may not be NULL, depending on the command number. In
 * actuality, this function only requires a structural (rather than functional)
 * reference to an engine, but many control commands may require the engine be
 * functional. The caller should be aware of trying commands that require an
 * operational ENGINE, and only use functional references in such situations. */
int ENGINE_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)());

/* This function tests if an ENGINE-specific command is usable as a "setting".
 * Eg. in an application's config file that gets processed through
 * ENGINE_ctrl_cmd_string(). If this returns zero, it is not available to
 * ENGINE_ctrl_cmd_string(), only ENGINE_ctrl(). */
int ENGINE_cmd_is_executable(ENGINE *e, int cmd);

/* This function works like ENGINE_ctrl() with the exception of taking a
 * command name instead of a command number, and can handle optional commands.
 * See the comment on ENGINE_ctrl_cmd_string() for an explanation on how to
 * use the cmd_name and cmd_optional. */
int ENGINE_ctrl_cmd(ENGINE *e, const char *cmd_name,
        long i, void *p, void (*f)(), int cmd_optional);

/* This function passes a command-name and argument to an ENGINE. The cmd_name
 * is converted to a command number and the control command is called using
 * 'arg' as an argument (unless the ENGINE doesn't support such a command, in
 * which case no control command is called). The command is checked for input
 * flags, and if necessary the argument will be converted to a numeric value. If
 * cmd_optional is non-zero, then if the ENGINE doesn't support the given
 * cmd_name the return value will be success anyway. This function is intended
 * for applications to use so that users (or config files) can supply
 * engine-specific config data to the ENGINE at run-time to control behaviour of
 * specific engines. As such, it shouldn't be used for calling ENGINE_ctrl()
 * functions that return data, deal with binary data, or that are otherwise
 * supposed to be used directly through ENGINE_ctrl() in application code. Any
 * "return" data from an ENGINE_ctrl() operation in this function will be lost -
 * the return value is interpreted as failure if the return value is zero,
 * success otherwise, and this function returns a boolean value as a result. In
 * other words, vendors of 'ENGINE'-enabled devices should write ENGINE
 * implementations with parameterisations that work in this scheme, so that
 * compliant ENGINE-based applications can work consistently with the same
 * configuration for the same ENGINE-enabled devices, across applications. */
int ENGINE_ctrl_cmd_string(ENGINE *e, const char *cmd_name, const char *arg,
				int cmd_optional);

/* These functions are useful for manufacturing new ENGINE structures. They
 * don't address reference counting at all - one uses them to populate an ENGINE
 * structure with personalised implementations of things prior to using it
 * directly or adding it to the builtin ENGINE list in OpenSSL. These are also
 * here so that the ENGINE structure doesn't have to be exposed and break binary
 * compatibility! */
ENGINE *ENGINE_new(void);
int ENGINE_free(ENGINE *e);
int ENGINE_set_id(ENGINE *e, const char *id);
int ENGINE_set_name(ENGINE *e, const char *name);
int ENGINE_set_RSA(ENGINE *e, const RSA_METHOD *rsa_meth);
int ENGINE_set_DSA(ENGINE *e, const DSA_METHOD *dsa_meth);
int ENGINE_set_DH(ENGINE *e, const DH_METHOD *dh_meth);
int ENGINE_set_RAND(ENGINE *e, const RAND_METHOD *rand_meth);
int ENGINE_set_BN_mod_exp(ENGINE *e, BN_MOD_EXP bn_mod_exp);
int ENGINE_set_BN_mod_exp_crt(ENGINE *e, BN_MOD_EXP_CRT bn_mod_exp_crt);
int ENGINE_set_init_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR init_f);
int ENGINE_set_finish_function(ENGINE *e, ENGINE_GEN_INT_FUNC_PTR finish_f);
int ENGINE_set_ctrl_function(ENGINE *e, ENGINE_CTRL_FUNC_PTR ctrl_f);
int ENGINE_set_load_privkey_function(ENGINE *e, ENGINE_LOAD_KEY_PTR loadpriv_f);
int ENGINE_set_load_pubkey_function(ENGINE *e, ENGINE_LOAD_KEY_PTR loadpub_f);
int ENGINE_set_flags(ENGINE *e, int flags);
int ENGINE_set_cmd_defns(ENGINE *e, const ENGINE_CMD_DEFN *defns);
int ENGINE_add_cipher(ENGINE *e,const EVP_CIPHER *c);
/* Copies across all ENGINE methods and pointers. NB: This does *not* change
 * reference counts however. */
int ENGINE_cpy(ENGINE *dest, const ENGINE *src);
/* These functions (and the "get" function lower down) allow control over any
 * per-structure ENGINE data. */
int ENGINE_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
		CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int ENGINE_set_ex_data(ENGINE *e, int idx, void *arg);
/* Cleans the internal engine list. This should only be used when the
 * application is about to exit or restart operation (the next operation
 * requiring the ENGINE list will re-initialise it with defaults). NB: Dynamic
 * ENGINEs will only truly unload (including any allocated data or loaded
 * shared-libraries) if all remaining references are released too - so keys,
 * certificates, etc all need to be released for an in-use ENGINE to unload. */
void ENGINE_cleanup(void);

/* These return values from within the ENGINE structure. These can be useful
 * with functional references as well as structural references - it depends
 * which you obtained. Using the result for functional purposes if you only
 * obtained a structural reference may be problematic! */
const char *ENGINE_get_id(const ENGINE *e);
const char *ENGINE_get_name(const ENGINE *e);
const RSA_METHOD *ENGINE_get_RSA(const ENGINE *e);
const DSA_METHOD *ENGINE_get_DSA(const ENGINE *e);
const DH_METHOD *ENGINE_get_DH(const ENGINE *e);
const RAND_METHOD *ENGINE_get_RAND(const ENGINE *e);
int ENGINE_cipher_num(const ENGINE *e);
const EVP_CIPHER *ENGINE_get_cipher(const ENGINE *e, int n);
BN_MOD_EXP ENGINE_get_BN_mod_exp(const ENGINE *e);
BN_MOD_EXP_CRT ENGINE_get_BN_mod_exp_crt(const ENGINE *e);
ENGINE_GEN_INT_FUNC_PTR ENGINE_get_init_function(const ENGINE *e);
ENGINE_GEN_INT_FUNC_PTR ENGINE_get_finish_function(const ENGINE *e);
ENGINE_CTRL_FUNC_PTR ENGINE_get_ctrl_function(const ENGINE *e);
ENGINE_LOAD_KEY_PTR ENGINE_get_load_privkey_function(const ENGINE *e);
ENGINE_LOAD_KEY_PTR ENGINE_get_load_pubkey_function(const ENGINE *e);
const ENGINE_CMD_DEFN *ENGINE_get_cmd_defns(const ENGINE *e);
int ENGINE_get_flags(const ENGINE *e);
void *ENGINE_get_ex_data(const ENGINE *e, int idx);

/* FUNCTIONAL functions. These functions deal with ENGINE structures
 * that have (or will) be initialised for use. Broadly speaking, the
 * structural functions are useful for iterating the list of available
 * engine types, creating new engine types, and other "list" operations.
 * These functions actually deal with ENGINEs that are to be used. As
 * such these functions can fail (if applicable) when particular
 * engines are unavailable - eg. if a hardware accelerator is not
 * attached or not functioning correctly. Each ENGINE has 2 reference
 * counts; structural and functional. Every time a functional reference
 * is obtained or released, a corresponding structural reference is
 * automatically obtained or released too. */

/* Initialise a engine type for use (or up its reference count if it's
 * already in use). This will fail if the engine is not currently
 * operational and cannot initialise. */
int ENGINE_init(ENGINE *e);
/* Free a functional reference to a engine type. This does not require
 * a corresponding call to ENGINE_free as it also releases a structural
 * reference. */
int ENGINE_finish(ENGINE *e);

/* The following functions handle keys that are stored in some secondary
 * location, handled by the engine.  The storage may be on a card or
 * whatever. */
EVP_PKEY *ENGINE_load_private_key(ENGINE *e, const char *key_id,
	UI_METHOD *ui_method, void *callback_data);
EVP_PKEY *ENGINE_load_public_key(ENGINE *e, const char *key_id,
	UI_METHOD *ui_method, void *callback_data);

/* This returns a pointer for the current ENGINE structure that
 * is (by default) performing any RSA operations. The value returned
 * is an incremented reference, so it should be free'd (ENGINE_finish)
 * before it is discarded. */
ENGINE *ENGINE_get_default_RSA(void);
/* Same for the other "methods" */
ENGINE *ENGINE_get_default_DSA(void);
ENGINE *ENGINE_get_default_DH(void);
ENGINE *ENGINE_get_default_RAND(void);
ENGINE *ENGINE_get_default_BN_mod_exp(void);
ENGINE *ENGINE_get_default_BN_mod_exp_crt(void);

/* This sets a new default ENGINE structure for performing RSA
 * operations. If the result is non-zero (success) then the ENGINE
 * structure will have had its reference count up'd so the caller
 * should still free their own reference 'e'. */
int ENGINE_set_default_RSA(ENGINE *e);
/* Same for the other "methods" */
int ENGINE_set_default_DSA(ENGINE *e);
int ENGINE_set_default_DH(ENGINE *e);
int ENGINE_set_default_RAND(ENGINE *e);
int ENGINE_set_default_BN_mod_exp(ENGINE *e);
int ENGINE_set_default_BN_mod_exp_crt(ENGINE *e);

/* The combination "set" - the flags are bitwise "OR"d from the
 * ENGINE_METHOD_*** defines above. */
int ENGINE_set_default(ENGINE *e, unsigned int flags);

/* This function resets all the internal "default" ENGINEs (there's one for each
 * of the various algorithms) to NULL, releasing any references as appropriate.
 * This function is called as part of the ENGINE_cleanup() function, so there's
 * no need to call both (although no harm is done). */
int ENGINE_clear_defaults(void);

/* Instruct an engine to load any EVP ciphers it knows of */
/* XXX make this work via defaults? */
void ENGINE_load_engine_ciphers(ENGINE *e);
/* Get a particular cipher from a particular engine - NULL if the engine
 * doesn't have it */
const EVP_CIPHER *ENGINE_get_cipher_by_name(ENGINE *e,const char *name);

/**************************/
/* DYNAMIC ENGINE SUPPORT */
/**************************/

/* Binary/behaviour compatibility levels */
#define OSSL_DYNAMIC_VERSION		(unsigned long)0x00010100
/* Binary versions older than this are too old for us (whether we're a loader or
 * a loadee) */
#define OSSL_DYNAMIC_OLDEST		(unsigned long)0x00010100

/* When compiling an ENGINE entirely as an external shared library, loadable by
 * the "dynamic" ENGINE, these types are needed. The 'dynamic_fns' structure
 * type provides the calling application's (or library's) error functionality
 * and memory management function pointers to the loaded library. These should
 * be used/set in the loaded library code so that the loading application's
 * 'state' will be used/changed in all operations. */
typedef void *(*dynamic_MEM_malloc_cb)(size_t);
typedef void *(*dynamic_MEM_realloc_cb)(void *, size_t);
typedef void (*dynamic_MEM_free_cb)(void *);
typedef struct st_dynamic_MEM_fns {
	dynamic_MEM_malloc_cb			malloc_cb;
	dynamic_MEM_realloc_cb			realloc_cb;
	dynamic_MEM_free_cb			free_cb;
	} dynamic_MEM_fns;
typedef struct st_dynamic_fns {
	const ERR_FNS				*err_fns;
	const CRYPTO_EX_DATA_IMPL		*ex_data_fns;
	dynamic_MEM_fns				mem_fns;
	} dynamic_fns;

/* The version checking function should be of this prototype. NB: The
 * ossl_version value passed in is the OSSL_DYNAMIC_VERSION of the loading code.
 * If this function returns zero, it indicates a (potential) version
 * incompatibility and the loaded library doesn't believe it can proceed.
 * Otherwise, the returned value is the (latest) version supported by the
 * loading library. The loader may still decide that the loaded code's version
 * is unsatisfactory and could veto the load. The function is expected to
 * be implemented with the symbol name "v_check", and a default implementation
 * can be fully instantiated with IMPLEMENT_DYNAMIC_CHECK_FN(). */
typedef unsigned long (*dynamic_v_check_fn)(unsigned long ossl_version);
#define IMPLEMENT_DYNAMIC_CHECK_FN() \
	unsigned long v_check(unsigned long v) { \
		if(v >= OSSL_DYNAMIC_OLDEST) return OSSL_DYNAMIC_VERSION; \
		return 0; }

/* This function is passed the ENGINE structure to initialise with its own
 * function and command settings. It should not adjust the structural or
 * functional reference counts. If this function returns zero, (a) the load will
 * be aborted, (b) the previous ENGINE state will be memcpy'd back onto the
 * structure, and (c) the shared library will be unloaded. So implementations
 * should do their own internal cleanup in failure circumstances otherwise they
 * could leak. The 'id' parameter, if non-NULL, represents the ENGINE id that
 * the loader is looking for. If this is NULL, the shared library can choose to
 * return failure or to initialise a 'default' ENGINE. If non-NULL, the shared
 * library must initialise only an ENGINE matching the passed 'id'. The function
 * is expected to be implemented with the symbol name "bind_engine". A standard
 * implementation can be instantiated with IMPLEMENT_DYNAMIC_BIND_FN(fn) where
 * the parameter 'fn' is a callback function that populates the ENGINE structure
 * and returns an int value (zero for failure). 'fn' should have prototype;
 *    [static] int fn(ENGINE *e, const char *id); */
typedef int (*dynamic_bind_engine)(ENGINE *e, const char *id,
				const dynamic_fns *fns);
#define IMPLEMENT_DYNAMIC_BIND_FN(fn) \
	int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns) { \
		if(!CRYPTO_set_mem_functions(fns->mem_fns.malloc_cb, \
			fns->mem_fns.realloc_cb, fns->mem_fns.free_cb)) \
			return 0; \
		if(!CRYPTO_set_ex_data_implementation(fns->ex_data_fns)) \
			return 0; \
		if(!ERR_set_implementation(fns->err_fns)) return 0; \
		if(!fn(e,id)) return 0; \
		return 1; }

/* Obligatory error function. */
void ERR_load_ENGINE_strings(void);

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_ENGINE_strings(void);

/* Error codes for the ENGINE functions. */

/* Function codes. */
#define ENGINE_F_ATALLA_CTRL				 173
#define ENGINE_F_ATALLA_FINISH				 159
#define ENGINE_F_ATALLA_INIT				 160
#define ENGINE_F_ATALLA_MOD_EXP				 161
#define ENGINE_F_ATALLA_RSA_MOD_EXP			 162
#define ENGINE_F_CSWIFT_CTRL				 174
#define ENGINE_F_CSWIFT_DSA_SIGN			 133
#define ENGINE_F_CSWIFT_DSA_VERIFY			 134
#define ENGINE_F_CSWIFT_FINISH				 100
#define ENGINE_F_CSWIFT_INIT				 101
#define ENGINE_F_CSWIFT_MOD_EXP				 102
#define ENGINE_F_CSWIFT_MOD_EXP_CRT			 103
#define ENGINE_F_CSWIFT_RSA_MOD_EXP			 104
#define ENGINE_F_DYNAMIC_CTRL				 180
#define ENGINE_F_DYNAMIC_GET_DATA_CTX			 181
#define ENGINE_F_DYNAMIC_LOAD				 182
#define ENGINE_F_ENGINE_ADD				 105
#define ENGINE_F_ENGINE_BY_ID				 106
#define ENGINE_F_ENGINE_CMD_IS_EXECUTABLE		 170
#define ENGINE_F_ENGINE_CTRL				 142
#define ENGINE_F_ENGINE_CTRL_CMD			 178
#define ENGINE_F_ENGINE_CTRL_CMD_STRING			 171
#define ENGINE_F_ENGINE_FINISH				 107
#define ENGINE_F_ENGINE_FREE				 108
#define ENGINE_F_ENGINE_GET_DEFAULT_TYPE		 177
#define ENGINE_F_ENGINE_GET_NEXT			 115
#define ENGINE_F_ENGINE_GET_PREV			 116
#define ENGINE_F_ENGINE_INIT				 119
#define ENGINE_F_ENGINE_LIST_ADD			 120
#define ENGINE_F_ENGINE_LIST_REMOVE			 121
#define ENGINE_F_ENGINE_LOAD_PRIVATE_KEY		 150
#define ENGINE_F_ENGINE_LOAD_PUBLIC_KEY			 151
#define ENGINE_F_ENGINE_NEW				 122
#define ENGINE_F_ENGINE_REMOVE				 123
#define ENGINE_F_ENGINE_SET_DEFAULT_TYPE		 126
#define ENGINE_F_ENGINE_SET_ID				 129
#define ENGINE_F_ENGINE_SET_NAME			 130
#define ENGINE_F_ENGINE_UNLOAD_KEY			 152
#define ENGINE_F_HWCRHK_CTRL				 143
#define ENGINE_F_HWCRHK_FINISH				 135
#define ENGINE_F_HWCRHK_GET_PASS			 155
#define ENGINE_F_HWCRHK_INIT				 136
#define ENGINE_F_HWCRHK_INSERT_CARD			 179
#define ENGINE_F_HWCRHK_LOAD_PRIVKEY			 153
#define ENGINE_F_HWCRHK_LOAD_PUBKEY			 154
#define ENGINE_F_HWCRHK_MOD_EXP				 137
#define ENGINE_F_HWCRHK_MOD_EXP_CRT			 138
#define ENGINE_F_HWCRHK_RAND_BYTES			 139
#define ENGINE_F_HWCRHK_RSA_MOD_EXP			 140
#define ENGINE_F_INT_CTRL_HELPER			 172
#define ENGINE_F_LOG_MESSAGE				 141
#define ENGINE_F_NURON_CTRL				 175
#define ENGINE_F_NURON_FINISH				 157
#define ENGINE_F_NURON_INIT				 156
#define ENGINE_F_NURON_MOD_EXP				 158
#define ENGINE_F_SET_DATA_CTX				 183
#define ENGINE_F_UBSEC_CTRL				 176
#define ENGINE_F_UBSEC_DSA_SIGN				 163
#define ENGINE_F_UBSEC_DSA_VERIFY			 164
#define ENGINE_F_UBSEC_FINISH				 165
#define ENGINE_F_UBSEC_INIT				 166
#define ENGINE_F_UBSEC_MOD_EXP				 167
#define ENGINE_F_UBSEC_RSA_MOD_EXP			 168
#define ENGINE_F_UBSEC_RSA_MOD_EXP_CRT			 169

/* Reason codes. */
#define ENGINE_R_ALREADY_LOADED				 100
#define ENGINE_R_ARGUMENT_IS_NOT_A_NUMBER		 133
#define ENGINE_R_BIO_WAS_FREED				 121
#define ENGINE_R_BN_CTX_FULL				 101
#define ENGINE_R_BN_EXPAND_FAIL				 102
#define ENGINE_R_CHIL_ERROR				 123
#define ENGINE_R_CMD_NOT_EXECUTABLE			 134
#define ENGINE_R_COMMAND_TAKES_INPUT			 135
#define ENGINE_R_COMMAND_TAKES_NO_INPUT			 136
#define ENGINE_R_CONFLICTING_ENGINE_ID			 103
#define ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED		 119
#define ENGINE_R_DH_NOT_IMPLEMENTED			 139
#define ENGINE_R_DSA_NOT_IMPLEMENTED			 140
#define ENGINE_R_DSO_FAILURE				 104
#define ENGINE_R_DSO_FUNCTION_NOT_FOUND			 131
#define ENGINE_R_DSO_NOT_FOUND				 132
#define ENGINE_R_ENGINE_IS_NOT_IN_LIST			 105
#define ENGINE_R_FAILED_LOADING_PRIVATE_KEY		 128
#define ENGINE_R_FAILED_LOADING_PUBLIC_KEY		 129
#define ENGINE_R_FINISH_FAILED				 106
#define ENGINE_R_GET_HANDLE_FAILED			 107
#define ENGINE_R_ID_OR_NAME_MISSING			 108
#define ENGINE_R_INIT_FAILED				 109
#define ENGINE_R_INTERNAL_LIST_ERROR			 110
#define ENGINE_R_INVALID_ARGUMENT			 143
#define ENGINE_R_INVALID_CMD_NAME			 137
#define ENGINE_R_INVALID_CMD_NUMBER			 138
#define ENGINE_R_MISSING_KEY_COMPONENTS			 111
#define ENGINE_R_NOT_INITIALISED			 117
#define ENGINE_R_NOT_LOADED				 112
#define ENGINE_R_NO_CALLBACK				 127
#define ENGINE_R_NO_CONTROL_FUNCTION			 120
#define ENGINE_R_NO_INDEX				 144
#define ENGINE_R_NO_KEY					 124
#define ENGINE_R_NO_LOAD_FUNCTION			 125
#define ENGINE_R_NO_REFERENCE				 130
#define ENGINE_R_NO_SUCH_ENGINE				 116
#define ENGINE_R_NO_UNLOAD_FUNCTION			 126
#define ENGINE_R_PRIVATE_KEY_ALGORITHMS_DISABLED	 142
#define ENGINE_R_PROVIDE_PARAMETERS			 113
#define ENGINE_R_REQUEST_FAILED				 114
#define ENGINE_R_REQUEST_FALLBACK			 118
#define ENGINE_R_RSA_NOT_IMPLEMENTED			 141
#define ENGINE_R_SIZE_TOO_LARGE_OR_TOO_SMALL		 122
#define ENGINE_R_UNIT_FAILURE				 115
#define ENGINE_R_VERSION_INCOMPATIBILITY		 145

#ifdef  __cplusplus
}
#endif
#endif

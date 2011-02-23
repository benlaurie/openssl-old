
#define OPENSSL_FIPSAPI
#include <openssl/opensslconf.h>

#ifndef OPENSSL_FIPS
#include <stdio.h>

int main(int argc, char **argv)
{
    printf("No FIPS DSA support\n");
    return(0);
}
#else

#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/fips.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>
#include <ctype.h>

#include "fips_utl.h"

static int parse_mod(char *line, int *pdsa2, int *pL, int *pN,
				const EVP_MD **pmd)
	{
	char lbuf[10240];
	char *keyword, *value;

	char *p;
	p = strchr(line, ',');
	if (!p)
		{
		*pL = atoi(line);
		*pdsa2 = 0;
		*pN = 160;
		if (pmd)
			*pmd = EVP_sha1();
		return 1;
		}
	*pdsa2 = 1;
	*p = 0;
	if (!parse_line(&keyword, &value, lbuf, line))
		return 0;
	if (strcmp(keyword, "L"))
		return 0;
	*pL = atoi(value);
	strcpy(line, p + 1);
	if (pmd)
		p = strchr(line, ',');
	else
		p = strchr(line, ']');
	if (!p)
		return 0;
	*p = 0;
	if (!parse_line(&keyword, &value, lbuf, line))
		return 0;
	if (strcmp(keyword, "N"))
		return 0;
	*pN = atoi(value);
	if (!pmd)
		return 1;
	strcpy(line, p + 1);
	p = strchr(line, ']');
	if (!p)
		return 0;
	*p = 0;
	p = line;
	while(isspace(*p))
		p++;
	if (!strcmp(p, "SHA-1"))
		*pmd = EVP_sha1();
	else if (!strcmp(p, "SHA-224"))
		*pmd = EVP_sha224();
	else if (!strcmp(p, "SHA-256"))
		*pmd = EVP_sha256();
	else if (!strcmp(p, "SHA-384"))
		*pmd = EVP_sha384();
	else if (!strcmp(p, "SHA-512"))
		*pmd = EVP_sha512();
	else
		return 0;
	return 1;
	}



static void pbn(const char *name, BIGNUM *bn)
	{
	int len, i;
	unsigned char *tmp;
	len = BN_num_bytes(bn);
	tmp = OPENSSL_malloc(len);
	if (!tmp)
		{
		fprintf(stderr, "Memory allocation error\n");
		return;
		}
	BN_bn2bin(bn, tmp);
	printf("%s = ", name);
	for (i = 0; i < len; i++)
		printf("%02X", tmp[i]);
	fputs("\n", stdout);
	OPENSSL_free(tmp);
	return;
	}

static void primes()
    {
    char buf[10240];
    char lbuf[10240];
    char *keyword, *value;

    while(fgets(buf,sizeof buf,stdin) != NULL)
	{
	fputs(buf,stdout);
	if (!parse_line(&keyword, &value, lbuf, buf))
		continue;
	if(!strcmp(keyword,"Prime"))
	    {
	    BIGNUM *pp;

	    pp=BN_new();
	    do_hex2bn(&pp,value);
	    printf("result= %c\n",
		   BN_is_prime_ex(pp,20,NULL,NULL) ? 'P' : 'F');
	    }	    
	}
    }

int dsa_builtin_paramgen(DSA *ret, size_t bits, size_t qbits,
	const EVP_MD *evpmd, const unsigned char *seed_in, size_t seed_len,
	unsigned char *seed_out,
	int *counter_ret, unsigned long *h_ret, BN_GENCB *cb);
int dsa_builtin_paramgen2(DSA *ret, size_t bits, size_t qbits,
	const EVP_MD *evpmd, const unsigned char *seed_in, size_t seed_len,
	unsigned char *seed_out,
	int *counter_ret, unsigned long *h_ret, BN_GENCB *cb);

static void pqg()
    {
    char buf[1024];
    char lbuf[1024];
    char *keyword, *value;
    int dsa2, L, N;
    const EVP_MD *md = NULL;

    while(fgets(buf,sizeof buf,stdin) != NULL)
	{
	if (!parse_line(&keyword, &value, lbuf, buf))
		{
		fputs(buf,stdout);
		continue;
		}
	if(!strcmp(keyword,"[mod"))
	    {
	    fputs(buf,stdout);
	    if (!parse_mod(value, &dsa2, &L, &N, &md))
		{
		fprintf(stderr, "Mod Parse Error\n");
		exit (1);
		}
	    }
	else if(!strcmp(keyword,"N"))
	    {
	    int n=atoi(value);

	    while(n--)
		{
		unsigned char seed[EVP_MAX_MD_SIZE];
		DSA *dsa;
		int counter;
		unsigned long h;
		dsa = FIPS_dsa_new();

		if (!dsa2 && !dsa_builtin_paramgen(dsa, L, N, md,
						NULL, 0, seed,
						&counter, &h, NULL))
			{
			fprintf(stderr, "Parameter Generation error\n");
			exit(1);
			}
		if (dsa2 && dsa_builtin_paramgen2(dsa, L, N, md,
						NULL, 0, seed,
						&counter, &h, NULL) <= 0)
			{
			fprintf(stderr, "Parameter Generation error\n");
			exit(1);
			}
 
		pbn("P",dsa->p);
		pbn("Q",dsa->q);
		pbn("G",dsa->g);
		pv("Seed",seed, M_EVP_MD_size(md));
		printf("c = %d\n",counter);
		printf("H = %lx\n",h);
		putc('\n',stdout);
		}
	    }
	else
	    fputs(buf,stdout);
	}
    }

static void pqgver()
    {
    char buf[1024];
    char lbuf[1024];
    char *keyword, *value;
    BIGNUM *p = NULL, *q = NULL, *g = NULL;
    int counter=-1, counter2;
    unsigned long h=-1, h2;
    DSA *dsa=NULL;
    int dsa2, L, N, part_test = 0;
    const EVP_MD *md = NULL;
    int seedlen=-1;
    unsigned char seed[1024];

    while(fgets(buf,sizeof buf,stdin) != NULL)
	{
	if (!parse_line(&keyword, &value, lbuf, buf))
		{
		if (p && q)
			{
			part_test = 1;
			goto partial;
			}
		fputs(buf,stdout);
		continue;
		}
	fputs(buf, stdout);
	if(!strcmp(keyword,"[mod"))
	    {
	    if (!parse_mod(value, &dsa2, &L, &N, &md))
		{
		fprintf(stderr, "Mod Parse Error\n");
		exit (1);
		}
	    }
	else if(!strcmp(keyword,"P"))
	    p=hex2bn(value);
	else if(!strcmp(keyword,"Q"))
	    q=hex2bn(value);
	else if(!strcmp(keyword,"G"))
	    g=hex2bn(value);
	else if(!strcmp(keyword,"Seed"))
	    {
	    seedlen = hex2bin(value, seed);
	    if (!dsa2 && seedlen != 20)
		{
		fprintf(stderr, "Seed parse length error\n");
		exit (1);
		}
	    }
	else if(!strcmp(keyword,"c"))
	    counter =atoi(buf+4);
	partial:
	if(!strcmp(keyword,"H") || part_test)
	    {
	    if (!part_test)
	    	h = atoi(value);
	    if (!p || !q || (!g && !part_test))
		{
		fprintf(stderr, "Parse Error\n");
		exit (1);
		}
	    dsa = FIPS_dsa_new();
	    if (!dsa2 && !dsa_builtin_paramgen(dsa, L, N, md,
					seed, seedlen, NULL,
					&counter2, &h2, NULL))
			{
			fprintf(stderr, "Parameter Generation error\n");
			exit(1);
			}
	    if (dsa2 && dsa_builtin_paramgen2(dsa, L, N, md,
					seed, seedlen, NULL,
					&counter2, &h2, NULL) < 0)
			{
			fprintf(stderr, "Parameter Generation error\n");
			exit(1);
			}
            if (BN_cmp(dsa->p, p) || BN_cmp(dsa->q, q) || 
		(!part_test &&
		((BN_cmp(dsa->g, g) || (counter != counter2) || (h != h2)))))
	    	printf("Result = F\n");
	    else
	    	printf("Result = P\n");
	    BN_free(p);
	    BN_free(q);
	    BN_free(g);
	    p = NULL;
	    q = NULL;
	    g = NULL;
	    FIPS_dsa_free(dsa);
	    dsa = NULL;
	    if (part_test)
		{
		fputs(buf,stdout);
		part_test = 0;
		}
	    }
	}
    }

/* Keypair verification routine. NB: this isn't part of the standard FIPS140-2
 * algorithm tests. It is an additional test to perform sanity checks on the
 * output of the KeyPair test.
 */

static int dss_paramcheck(int L, int N, BIGNUM *p, BIGNUM *q, BIGNUM *g,
							BN_CTX *ctx)
    {
    BIGNUM *rem = NULL;
    if (BN_num_bits(p) != L)
	return 0;
    if (BN_num_bits(q) != N)
	return 0;
    if (BN_is_prime_ex(p, BN_prime_checks, ctx, NULL) != 1)
	return 0;
    if (BN_is_prime_ex(q, BN_prime_checks, ctx, NULL) != 1)
	return 0;
    rem = BN_new();
    if (!BN_mod(rem, p, q, ctx) || !BN_is_one(rem)
    	|| (BN_cmp(g, BN_value_one()) <= 0)
	|| !BN_mod_exp(rem, g, q, p, ctx) || !BN_is_one(rem))
	{
	BN_free(rem);
	return 0;
	}
    /* Todo: check g */
    BN_free(rem);
    return 1;
    }

static void keyver()
    {
    char buf[1024];
    char lbuf[1024];
    char *keyword, *value;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *X = NULL, *Y = NULL;
    BIGNUM *Y2;
    BN_CTX *ctx = NULL;
    int dsa2, L, N;
    int paramcheck = 0;

    ctx = BN_CTX_new();
    Y2 = BN_new();

    while(fgets(buf,sizeof buf,stdin) != NULL)
	{
	if (!parse_line(&keyword, &value, lbuf, buf))
		{
		fputs(buf,stdout);
		continue;
		}
	if(!strcmp(keyword,"[mod"))
	    {
	    if (p)
		BN_free(p);
	    p = NULL;
	    if (q)
		BN_free(q);
	    q = NULL;
	    if (g)
		BN_free(g);
	    g = NULL;
	    paramcheck = 0;
	    if (!parse_mod(value, &dsa2, &L, &N, NULL))
		{
		fprintf(stderr, "Mod Parse Error\n");
		exit (1);
		}
	    }
	else if(!strcmp(keyword,"P"))
	    p=hex2bn(value);
	else if(!strcmp(keyword,"Q"))
	    q=hex2bn(value);
	else if(!strcmp(keyword,"G"))
	    g=hex2bn(value);
	else if(!strcmp(keyword,"X"))
	    X=hex2bn(value);
	else if(!strcmp(keyword,"Y"))
	    {
	    Y=hex2bn(value);
	    if (!p || !q || !g || !X || !Y)
		{
		fprintf(stderr, "Parse Error\n");
		exit (1);
		}
	    pbn("P",p);
	    pbn("Q",q);
	    pbn("G",g);
	    pbn("X",X);
	    pbn("Y",Y);
	    if (!paramcheck)
		{
		if (dss_paramcheck(L, N, p, q, g, ctx))
			paramcheck = 1;
		else
			paramcheck = -1;
		}
	    if (paramcheck != 1)
	   	printf("Result = F\n");
	    else
		{
		if (!BN_mod_exp(Y2, g, X, p, ctx) || BN_cmp(Y2, Y))
	    		printf("Result = F\n");
	        else
	    		printf("Result = P\n");
		}
	    BN_free(X);
	    BN_free(Y);
	    X = NULL;
	    Y = NULL;
	    }
	}
	if (p)
	    BN_free(p);
	if (q)
	    BN_free(q);
	if (g)
	    BN_free(g);
	if (Y2)
	    BN_free(Y2);
    }

static void keypair()
    {
    char buf[1024];
    char lbuf[1024];
    char *keyword, *value;
    int dsa2, L, N;

    while(fgets(buf,sizeof buf,stdin) != NULL)
	{
	if (!parse_line(&keyword, &value, lbuf, buf))
		{
		continue;
		}
	if(!strcmp(keyword,"[mod"))
	    {
	    if (!parse_mod(value, &dsa2, &L, &N, NULL))
		{
		fprintf(stderr, "Mod Parse Error\n");
		exit (1);
		}
	    fputs(buf,stdout);
	    }
	else if(!strcmp(keyword,"N"))
	    {
	    DSA *dsa;
	    int n=atoi(value);

	    dsa = FIPS_dsa_new();
	    if (!dsa2 && !dsa_builtin_paramgen(dsa, L, N, NULL, NULL, 0,
						NULL, NULL, NULL, NULL))
			{
			fprintf(stderr, "Parameter Generation error\n");
			exit(1);
			}
	    if (dsa2 && dsa_builtin_paramgen2(dsa, L, N, NULL, NULL, 0,
						NULL, NULL, NULL, NULL) <= 0)
			{
			fprintf(stderr, "Parameter Generation error\n");
			exit(1);
			}
	    pbn("P",dsa->p);
	    pbn("Q",dsa->q);
	    pbn("G",dsa->g);
	    putc('\n',stdout);

	    while(n--)
		{
		if (!DSA_generate_key(dsa))
			exit(1);

		pbn("X",dsa->priv_key);
		pbn("Y",dsa->pub_key);
		putc('\n',stdout);
		}
	    }
	}
    }

static void siggen()
    {
    char buf[1024];
    char lbuf[1024];
    char *keyword, *value;
    int dsa2, L, N;
    const EVP_MD *md = NULL;
    DSA *dsa=NULL;

    while(fgets(buf,sizeof buf,stdin) != NULL)
	{
	if (!parse_line(&keyword, &value, lbuf, buf))
		{
		fputs(buf,stdout);
		continue;
		}
	fputs(buf,stdout);
	if(!strcmp(keyword,"[mod"))
	    {
	    if (!parse_mod(value, &dsa2, &L, &N, &md))
		{
		fprintf(stderr, "Mod Parse Error\n");
		exit (1);
		}
	    if (dsa)
		FIPS_dsa_free(dsa);
	    dsa = FIPS_dsa_new();
	    if (!dsa2 && !dsa_builtin_paramgen(dsa, L, N, md, NULL, 0,
						NULL, NULL, NULL, NULL))
			{
			fprintf(stderr, "Parameter Generation error\n");
			exit(1);
			}
	    if (dsa2 && dsa_builtin_paramgen2(dsa, L, N, md, NULL, 0,
						NULL, NULL, NULL, NULL) <= 0)
			{
			fprintf(stderr, "Parameter Generation error\n");
			exit(1);
			}
	    pbn("P",dsa->p);
	    pbn("Q",dsa->q);
	    pbn("G",dsa->g);
	    putc('\n',stdout);
	    }
	else if(!strcmp(keyword,"Msg"))
	    {
	    unsigned char msg[1024];
	    int n;
	    EVP_MD_CTX mctx;
	    DSA_SIG *sig;
	    FIPS_md_ctx_init(&mctx);

	    n=hex2bin(value,msg);

	    if (!DSA_generate_key(dsa))
		exit(1);
	    pbn("Y",dsa->pub_key);

	    FIPS_digestinit(&mctx, md);
	    FIPS_digestupdate(&mctx, msg, n);
	    sig = FIPS_dsa_sign_ctx(dsa, &mctx);

	    pbn("R",sig->r);
	    pbn("S",sig->s);
	    putc('\n',stdout);
	    FIPS_dsa_sig_free(sig);
	    FIPS_md_ctx_cleanup(&mctx);
	    }
	}
	if (dsa)
		FIPS_dsa_free(dsa);
    }

static void sigver()
    {
    DSA *dsa=NULL;
    char buf[1024];
    char lbuf[1024];
    unsigned char msg[1024];
    char *keyword, *value;
    int n=0;
    int dsa2, L, N;
    const EVP_MD *md = NULL;
    DSA_SIG sg, *sig = &sg;

    sig->r = NULL;
    sig->s = NULL;

    while(fgets(buf,sizeof buf,stdin) != NULL)
	{
	if (!parse_line(&keyword, &value, lbuf, buf))
		{
		fputs(buf,stdout);
		continue;
		}
	fputs(buf,stdout);
	if(!strcmp(keyword,"[mod"))
	    {
	    if (!parse_mod(value, &dsa2, &L, &N, &md))
		{
		fprintf(stderr, "Mod Parse Error\n");
		exit (1);
		}
	    if (dsa)
		FIPS_dsa_free(dsa);
	    dsa = FIPS_dsa_new();
	    }
	else if(!strcmp(keyword,"P"))
	    dsa->p=hex2bn(value);
	else if(!strcmp(keyword,"Q"))
	    dsa->q=hex2bn(value);
	else if(!strcmp(keyword,"G"))
	    dsa->g=hex2bn(value);
	else if(!strcmp(keyword,"Msg"))
	    n=hex2bin(value,msg);
	else if(!strcmp(keyword,"Y"))
	    dsa->pub_key=hex2bn(value);
	else if(!strcmp(keyword,"R"))
	    sig->r=hex2bn(value);
	else if(!strcmp(keyword,"S"))
	    {
	    EVP_MD_CTX mctx;
	    int r;
	    FIPS_md_ctx_init(&mctx);
	    sig->s=hex2bn(value);

	    FIPS_digestinit(&mctx, md);
	    FIPS_digestupdate(&mctx, msg, n);
	    no_err = 1;
	    r = FIPS_dsa_verify_ctx(dsa, &mctx, sig);
	    no_err = 0;
	    FIPS_md_ctx_cleanup(&mctx);
	
	    printf("Result = %c\n", r == 1 ? 'P' : 'F');
	    putc('\n',stdout);
	    }
	}
    }

int main(int argc,char **argv)
    {
    if(argc != 2)
	{
	fprintf(stderr,"%s [prime|pqg|pqgver|keypair|keyver|siggen|sigver]\n",argv[0]);
	exit(1);
	}
    fips_set_error_print();
    if(!FIPS_mode_set(1))
	exit(1);
    if(!strcmp(argv[1],"prime"))
	primes();
    else if(!strcmp(argv[1],"pqg"))
	pqg();
    else if(!strcmp(argv[1],"pqgver"))
	pqgver();
    else if(!strcmp(argv[1],"keypair"))
	keypair();
    else if(!strcmp(argv[1],"keyver"))
	keyver();
    else if(!strcmp(argv[1],"siggen"))
	siggen();
    else if(!strcmp(argv[1],"sigver"))
	sigver();
    else
	{
	fprintf(stderr,"Don't know how to %s.\n",argv[1]);
	exit(1);
	}

    return 0;
    }

#endif

/*
 * Crude test driver for processing the VST and MCT testvector files generated by the CMVP
 * RNGVS product.
 *
 * Note the input files are assumed to have a _very_ specific format as described in the
 * NIST document "The Random Number Generator Validation System (RNGVS)", May 25, 2004.
 *
*/
#include <openssl/opensslconf.h>

#ifndef OPENSSL_FIPS
#include <stdio.h>
int main()
{
    printf("No FIPS RNG support\n");
    exit(0);
}
#else

#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/fips.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/fips_rand.h>
#include <string.h>

int hex2bin(const char *in, unsigned char *out)
    {
    int n1, n2;
    unsigned char ch;

    for (n1=0,n2=0 ; in[n1] && in[n1] != '\n' ; )
	{ /* first byte */
	if ((in[n1] >= '0') && (in[n1] <= '9'))
	    ch = in[n1++] - '0';
	else if ((in[n1] >= 'A') && (in[n1] <= 'F'))
	    ch = in[n1++] - 'A' + 10;
	else if ((in[n1] >= 'a') && (in[n1] <= 'f'))
	    ch = in[n1++] - 'a' + 10;
	else
	    return -1;
	if(!in[n1])
	    {
	    out[n2++]=ch;
	    break;
	    }
	out[n2] = ch << 4;
	/* second byte */
	if ((in[n1] >= '0') && (in[n1] <= '9'))
	    ch = in[n1++] - '0';
	else if ((in[n1] >= 'A') && (in[n1] <= 'F'))
	    ch = in[n1++] - 'A' + 10;
	else if ((in[n1] >= 'a') && (in[n1] <= 'f'))
	    ch = in[n1++] - 'a' + 10;
	else
	    return -1;
	out[n2++] |= ch;
	}
    return n2;
    }

int bin2hex(const unsigned char *in,int len,char *out)
    {
    int n1, n2;
    unsigned char ch;

    for (n1=0,n2=0 ; n1 < len ; ++n1)
	{
	ch=in[n1] >> 4;
	if (ch <= 0x09)
	    out[n2++]=ch+'0';
	else
	    out[n2++]=ch-10+'a';
	ch=in[n1] & 0x0f;
	if(ch <= 0x09)
	    out[n2++]=ch+'0';
	else
	    out[n2++]=ch-10+'a';
	}
    out[n2]='\0';
    return n2;
    }

void pv(const char *tag,const unsigned char *val,int len)
    {
    char obuf[2048];

    bin2hex(val,len,obuf);
    printf("%s = %s\n",tag,obuf);
    }

void vst()
    {
    unsigned char key1[8];
    unsigned char key2[8];
    unsigned char v[8];
    unsigned char dt[8];
    unsigned char ret[8];
    char buf[1024];
    int n;

    while(fgets(buf,sizeof buf,stdin) != NULL)
	{
	if(!strncmp(buf,"Key1 = ",7))
	    {
	    n=hex2bin(buf+7,key1);
	    pv("Key1",key1,n);
	    }
	else if(!strncmp(buf,"Key2 = ",7))
	    {
	    n=hex2bin(buf+7,key2);
	    pv("Key1",key2,n);
	    }
	else if(!strncmp(buf,"DT = ",5))
	    {
	    n=hex2bin(buf+5,dt);
	    pv("DT",dt,n);
	    }
	else if(!strncmp(buf,"V = ",4))
	    {
	    n=hex2bin(buf+4,v);
	    pv("V",v,n);

	    FIPS_rand_method()->cleanup();
	    FIPS_set_prng_key(key1,key2);
	    FIPS_rand_seed(v,8);
	    FIPS_test_mode(1,dt);
	    if (FIPS_rand_method()->bytes(ret,8) <= 0)
	        {
	        FIPS_test_mode(0,NULL);
	        FIPSerr(FIPS_F_FIPS_SELFTEST_RNG,FIPS_R_SELFTEST_FAILED);
	        return;
	        }

	    pv("R",ret,8);
	    putc('\n',stdout);
	    }
	else
	    fputs(buf,stdout);
	}
    }


void mct()
    {
    unsigned char key1[8];
    unsigned char key2[8];
    unsigned char v[8];
    unsigned char dt[8];
    unsigned char ret[8];
    char buf[1024];
    int n;

    BIGNUM *bn;
    BIGNUM *pbn;
    bn = BN_new();

    while(fgets(buf,sizeof buf,stdin) != NULL)
	{
	if(!strncmp(buf,"Key1 = ",7))
	    {
	    n=hex2bin(buf+7,key1);
	    pv("Key1",key1,n);
	    }
	else if(!strncmp(buf,"Key2 = ",7))
	    {
	    n=hex2bin(buf+7,key2);
	    pv("Key1",key2,n);
	    }
	else if(!strncmp(buf,"DT = ",5))
	    {
	    n=hex2bin(buf+5,dt);
	    pv("DT",dt,n);
	    }
	else if(!strncmp(buf,"V = ",4))
	    {
	    int iter;
	    n=hex2bin(buf+4,v);
	    pv("V",v,n);

	    FIPS_rand_method()->cleanup();
	    FIPS_set_prng_key(key1,key2);
	    FIPS_rand_seed(v,8);
	    for (iter=0; iter < 10000; ++iter)
		{
	        FIPS_test_mode(1,dt);
		if (FIPS_rand_method()->bytes(ret,8) <= 0)
		    {
		    FIPS_test_mode(0,NULL);
		    FIPSerr(FIPS_F_FIPS_SELFTEST_RNG,FIPS_R_SELFTEST_FAILED);
		    return;
		    }
		pbn = BN_bin2bn(dt,8,bn);
		n = BN_add(bn,bn,BN_value_one());
		n = BN_bn2bin(bn,dt);
		}

	    pv("R",ret,8);
	    putc('\n',stdout);
	    }
	else
	    fputs(buf,stdout);
	}
    BN_free(bn);
    }

int main(int argc,char **argv)
    {
    if(argc != 2)
	{
	fprintf(stderr,"%s [mct|vst]\n",argv[0]);
	exit(1);
	}
    if(!FIPS_mode_set(1,argv[0]))
	{
	ERR_load_crypto_strings();
	ERR_print_errors(BIO_new_fp(stderr,BIO_NOCLOSE));
	exit(1);
	}
    if(!strcmp(argv[1],"mct"))
	mct();
    else if(!strcmp(argv[1],"vst"))
	vst();
    else
	{
	fprintf(stderr,"Don't know how to %s.\n",argv[1]);
	exit(1);
	}

    return 0;
    }
#endif

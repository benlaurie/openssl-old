/*---------------------------------------------
  NIST DES Modes of Operation Validation System
  Test Program

  Based on the AES Validation Suite, which was:
  Copyright
  V-ONE Corporation
  20250 Century Blvd, Suite 300
  Germantown, MD 20874
  U.S.A.
  ----------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/fips.h>
#include <openssl/err.h>

//#define AES_BLOCK_SIZE 16

#define VERBOSE 0

/*-----------------------------------------------*/

int DESTest(EVP_CIPHER_CTX *ctx,
	    char *amode, int akeysz, unsigned char *aKey, 
	    unsigned char *iVec, 
	    int dir,  /* 0 = decrypt, 1 = encrypt */
	    unsigned char *plaintext, unsigned char *ciphertext, int len)
    {
    const EVP_CIPHER *cipher = NULL;
    int ret = 1;
    int kt = 0;

    if (ctx)
	memset(ctx, 0, sizeof(EVP_CIPHER_CTX));

    if (strcasecmp(amode, "CBC") == 0)
	kt = 1000;
    else if (strcasecmp(amode, "ECB") == 0)
	kt = 2000;
    else if (strcasecmp(amode, "CFB64") == 0)
	kt = 3000;
    else if (strncasecmp(amode, "OFB", 3) == 0)
	kt = 4000;
    else if(!strcasecmp(amode,"CFB1"))
	kt=5000;
    else if(!strcasecmp(amode,"CFB8"))
	kt=6000;
    else
	{
	printf("Unknown mode: %s\n", amode);
	exit(1);
	}
    if (ret)
	{
	if (akeysz != 64)
	    {
	    printf("Invalid key size: %d\n", akeysz);
	    ret = 0;
	    }
	else
	    {
	    kt += akeysz;
	    switch (kt)
		{
	    case 1064:
		cipher=EVP_des_cbc();
		break;
	    case 2064:
		cipher=EVP_des_ecb();
		break;
	    case 3064:
		cipher=EVP_des_cfb64();
		break;
	    case 4064:
		cipher=EVP_des_ofb();
		break;
	    case 5064:
		cipher=EVP_des_cfb1();
		break;
	    case 6064:
		cipher=EVP_des_cfb8();
		break;
	    default:
		printf("Didn't handle mode %d\n",kt);
		exit(1);
		}
	    if (dir)
		{ /* encrypt */
		if(!EVP_CipherInit(ctx, cipher, aKey, iVec, AES_ENCRYPT))
		    {
		    ERR_print_errors_fp(stderr);
		    exit(1);
		    }
		  
		EVP_Cipher(ctx, ciphertext, (unsigned char*)plaintext, len);
		}
	    else
		{ /* decrypt */
		if(!EVP_CipherInit(ctx, cipher, aKey, iVec, AES_DECRYPT))
		    {
		    ERR_print_errors_fp(stderr);
		    exit(1);
		    }
		EVP_Cipher(ctx, (unsigned char*)plaintext, ciphertext, len);
		}
	    }
	}
    return ret;
    }

/*-----------------------------------------------*/

int hex2bin(char *in, int len, unsigned char *out)
    {
    int n1, n2;
    unsigned char ch;

    for (n1 = 0, n2 = 0; n1 < len; )
	{ /* first byte */
	if ((in[n1] >= '0') && (in[n1] <= '9'))
	    ch = in[n1++] - '0';
	else if ((in[n1] >= 'A') && (in[n1] <= 'F'))
	    ch = in[n1++] - 'A' + 10;
	else if ((in[n1] >= 'a') && (in[n1] <= 'f'))
	    ch = in[n1++] - 'a' + 10;
	else
	    return -1;
	if(len == 1)
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

/*-----------------------------------------------*/

int bin2hex(unsigned char *in, int len, char *out)
    {
    int n1, n2;
    unsigned char ch;

    for (n1 = 0, n2 = 0; n1 < len; ++n1)
	{
	/* first nibble */
	ch = in[n1] >> 4;
	if (ch <= 0x09)
	    out[n2++] = ch + '0';
	else
	    out[n2++] = ch - 10 + 'a';
	/* second nibble */
	ch = in[n1] & 0x0f;
	if (ch <= 0x09)
	    out[n2++] = ch + '0';
	else
	    out[n2++] = ch - 10 + 'a';
	}
    return n2;
    }

/* NB: this return the number of _bits_ read */
int bint2bin(const char *in, int len, unsigned char *out)
    {
    int n;

    memset(out,0,len);
    for(n=0 ; n < len ; ++n)
	if(in[n] == '1')
	    out[n/8]|=(0x80 >> (n%8));
    return len;
    }

int bin2bint(const unsigned char *in,int len,char *out)
    {
    int n;

    for(n=0 ; n < len ; ++n)
	out[n]=(in[n/8]&(0x80 >> (n%8))) ? '1' : '0';
    return n;
    }

/*-----------------------------------------------*/

void PrintValue(char *tag, unsigned char *val, int len)
    {
#if VERBOSE
    char obuf[2048];
    int olen;
    olen = bin2hex(val, len, obuf);
    printf("%s = %.*s\n", tag, olen, obuf);
#endif
    }

void OutputValue(char *tag, unsigned char *val, int len, FILE *rfp,int bitmode)
    {
    char obuf[2048];
    int olen;

    if(bitmode)
	olen=bin2bint(val,len,obuf);
    else
	olen=bin2hex(val,len,obuf);

    fprintf(rfp, "%s = %.*s\n", tag, olen, obuf);
#if VERBOSE
    printf("%s = %.*s\n", tag, olen, obuf);
#endif
    }

/*-----------------------------------------------*/
char *t_tag[2] = {"PLAINTEXT", "CIPHERTEXT"};
char *t_mode[6] = {"CBC","ECB","OFB","CFB1","CFB8","CFB64"};
enum Mode {CBC, ECB, OFB, CFB1, CFB8, CFB128};
enum XCrypt {XDECRYPT, XENCRYPT};

void do_mct(char *amode, 
	    int akeysz, unsigned char *akey,unsigned char *ivec,
	    int dir, unsigned char *text, int len,
	    FILE *rfp)
    {
    int i,imode;

    for (imode=0 ; imode < 6 ; ++imode)
	if(!strcmp(amode,t_mode[imode]))
	    break;
    if (imode == 6)
	{ 
	printf("Unrecognized mode: %s\n", amode);
	exit(1);
	}

    for(i=0 ; i < 400 ; ++i)
	{
	int j;
	int n;
	EVP_CIPHER_CTX ctx;

	fprintf(rfp,"\nCOUNT = %d\n",i);
	OutputValue("KEY",akey,akeysz/8,rfp,0);
	if(imode != ECB)
	    OutputValue("IV",ivec,8,rfp,0);
	OutputValue(t_tag[dir^1],text,len,rfp,imode == CFB1);


	for(j=0 ; j < 10000 ; ++j)
	    {
	    unsigned char in[8];

	    if(imode == ECB)
		memcpy(in,text,8);
	    else
		for(n=0 ; n < 8 ; ++n)
		    in[n]=text[n]^ivec[n];
		
	    if(j == 0)
		DESTest(&ctx,amode,akeysz,akey,ivec,dir,text,text,len);
	    else
		EVP_Cipher(&ctx,text,text,len);
	    if(imode != ECB)
		{
		unsigned char tmp[8];

		memcpy(tmp,text,8);
		memcpy(text,ivec,8);
		memcpy(ivec,tmp,8);
		}
	    }
	OutputValue(t_tag[dir],ivec,len,rfp,imode == CFB1);
	for(n=0 ; n < 8 ; ++n)
	    akey[n]^=ivec[n];
	}
    }
    
int proc_file(char *rqfile)
    {
    char afn[256], rfn[256];
    FILE *afp = NULL, *rfp = NULL;
    char ibuf[2048];
    int ilen, len, ret = 0;
    char algo[8] = "";
    char amode[8] = "";
    char atest[100] = "";
    int akeysz=0;
    unsigned char iVec[20], aKey[40];
    int dir = -1, err = 0, step = 0;
    unsigned char plaintext[2048];
    unsigned char ciphertext[2048];
    char *rp;
    EVP_CIPHER_CTX ctx;

    if (!rqfile || !(*rqfile))
	{
	printf("No req file\n");
	return -1;
	}
    strcpy(afn, rqfile);

    if ((afp = fopen(afn, "r")) == NULL)
	{
	printf("Cannot open file: %s, %s\n", 
	       afn, strerror(errno));
	return -1;
	}
    strcpy(rfn,afn);
    rp=strstr(rfn,"req/");
    assert(rp);
    memcpy(rp,"rsp",3);
    rp = strstr(rfn, ".req");
    memcpy(rp, ".rsp", 4);
    if ((rfp = fopen(rfn, "w")) == NULL)
	{
	printf("Cannot open file: %s, %s\n", 
	       rfn, strerror(errno));
	fclose(afp);
	afp = NULL;
	return -1;
	}
    while (!err && (fgets(ibuf, sizeof(ibuf), afp)) != NULL)
	{
	ilen = strlen(ibuf);
	//	printf("step=%d ibuf=%s",step,ibuf);
	switch (step)
	    {
	case 0:  /* read preamble */
	    if (ibuf[0] == '\n')
		{ /* end of preamble */
		if ((*algo == '\0') ||
		    (*amode == '\0') ||
		    (akeysz == 0))
		    {
		    printf("Missing Algorithm, Mode or KeySize (%s/%s/%d)\n",
			   algo,amode,akeysz);
		    err = 1;
		    }
		else
		    {
		    fputs(ibuf, rfp);
		    ++ step;
		    }
		}
	    else if (ibuf[0] != '#')
		{
		printf("Invalid preamble item: %s\n", ibuf);
		err = 1;
		}
	    else
		{ /* process preamble */
		char *xp, *pp = ibuf+2;
		int n;
		if (akeysz)
		    { /* insert current time & date */
		    time_t rtim = time(0);
		    fprintf(rfp, "# %s", ctime(&rtim));
		    }
		else
		    {
		    fputs(ibuf, rfp);
		    if(!strncmp(pp,"INVERSE ",8) || !strncmp(pp,"DES ",4)
		       || !strncmp(pp,"PERMUTATION ",12)
		       || !strncmp(pp,"SUBSTITUTION ",13)
		       || !strncmp(pp,"VARIABLE ",9))
			{
			strcpy(algo, "DES");
			/* get test type */
			if(!strncmp(pp,"DES ",4))
			    pp+=4;
			xp = strchr(pp, ' ');
			n = xp-pp;
			strncpy(atest, pp, n);
			atest[n] = '\0';
			/* get mode */
			xp = strrchr(pp, ' '); /* get mode" */
			n = strlen(xp+1)-1;
			strncpy(amode, xp+1, n);
			amode[n] = '\0';
			/* amode[3] = '\0'; */
			printf("Test = %s, Mode = %s\n", atest, amode);
			}
		    else if(!strncmp(pp,"State :",7))
			akeysz=64;
		    }
		}
	    break;

	case 1:  /* [ENCRYPT] | [DECRYPT] */
	    if(ibuf[0] == '\n')
		break;
	    if (ibuf[0] == '[')
		{
		fputs(ibuf, rfp);
		++step;
		if (strncasecmp(ibuf, "[ENCRYPT]", 9) == 0)
		    dir = 1;
		else if (strncasecmp(ibuf, "[DECRYPT]", 9) == 0)
		    dir = 0;
		else
		    {
		    printf("Invalid keyword: %s\n", ibuf);
		    err = 1;
		    }
		break;
		}
	    else if (dir == -1)
		{
		err = 1;
		printf("Missing ENCRYPT/DECRYPT keyword\n");
		break;
		}
	    else 
		step = 2;

	case 2: /* KEY = xxxx */
	    fputs(ibuf, rfp);
	    if(*ibuf == '\n')
		break;
	    if(!strncasecmp(ibuf,"COUNT = ",8))
		break;
	  
	    if (strncasecmp(ibuf, "KEY = ", 6) != 0)
		{
		printf("Missing KEY\n");
		err = 1;
		}
	    else
		{
		len = hex2bin((char*)ibuf+6, strlen(ibuf+6)-1, aKey);
		if (len < 0)
		    {
		    printf("Invalid KEY\n");
		    err =1;
		    break;
		    }
		PrintValue("KEY", aKey, len);
		if (strcmp(amode, "ECB") == 0)
		    {
		    memset(iVec, 0, sizeof(iVec));
		    step = (dir)? 4: 5;  /* no ivec for ECB */
		    }
		else
		    ++step;
		}
	    break;

	case 3: /* IV = xxxx */
	    fputs(ibuf, rfp);
	    if (strncasecmp(ibuf, "IV = ", 5) != 0)
		{
		printf("Missing IV\n");
		err = 1;
		}
	    else
		{
		len = hex2bin((char*)ibuf+5, strlen(ibuf+5)-1, iVec);
		if (len < 0)
		    {
		    printf("Invalid IV\n");
		    err =1;
		    break;
		    }
		PrintValue("IV", iVec, len);
		step = (dir)? 4: 5;
		}
	    break;

	case 4: /* PLAINTEXT = xxxx */
	    fputs(ibuf, rfp);
	    if (strncasecmp(ibuf, "PLAINTEXT = ", 12) != 0)
		{
		printf("Missing PLAINTEXT\n");
		err = 1;
		}
	    else
		{
		int nn = strlen(ibuf+12);
		if(!strcmp(amode,"CFB1"))
		    len=bint2bin(ibuf+12,nn-1,plaintext);
		else
		    len=hex2bin(ibuf+12, nn-1,plaintext);
		if (len < 0)
		    {
		    printf("Invalid PLAINTEXT: %s", ibuf+12);
		    err =1;
		    break;
		    }
		if (len >= sizeof(plaintext))
		    {
		    printf("Buffer overflow\n");
		    }
		PrintValue("PLAINTEXT", (unsigned char*)plaintext, len);
		if (strcmp(atest, "Monte") == 0)  /* Monte Carlo Test */
		    {
		    do_mct(amode,akeysz,aKey,iVec,dir,plaintext,len,rfp);
		    }
		else
		    {
		    ret = DESTest(&ctx, amode, akeysz, aKey, iVec, 
				  dir,  /* 0 = decrypt, 1 = encrypt */
				  plaintext, ciphertext, len);
		    OutputValue("CIPHERTEXT",ciphertext,len,rfp,
				!strcmp(amode,"CFB1"));
		    }
		step = 6;
		}
	    break;

	case 5: /* CIPHERTEXT = xxxx */
	    fputs(ibuf, rfp);
	    if (strncasecmp(ibuf, "CIPHERTEXT = ", 13) != 0)
		{
		printf("Missing KEY\n");
		err = 1;
		}
	    else
		{
		if(!strcmp(amode,"CFB1"))
		    len=bint2bin(ibuf+13,strlen(ibuf+13)-1,ciphertext);
		else
		    len = hex2bin(ibuf+13,strlen(ibuf+13)-1,ciphertext);
		if (len < 0)
		    {
		    printf("Invalid CIPHERTEXT\n");
		    err =1;
		    break;
		    }
		
		PrintValue("CIPHERTEXT", ciphertext, len);
		if (strcmp(atest, "Monte") == 0)  /* Monte Carlo Test */
		    {
		    do_mct(amode, akeysz, aKey, iVec, 
			   dir, ciphertext, len, rfp);
		    }
		else
		    {
		    ret = DESTest(&ctx, amode, akeysz, aKey, iVec, 
				  dir,  /* 0 = decrypt, 1 = encrypt */
				  plaintext, ciphertext, len);
		    OutputValue("PLAINTEXT",(unsigned char *)plaintext,len,rfp,
				!strcmp(amode,"CFB1"));
		    }
		step = 6;
		}
	    break;

	case 6:
	    if (ibuf[0] != '\n')
		{
		err = 1;
		printf("Missing terminator\n");
		}
	    else if (strcmp(atest, "MCT") != 0)
		{ /* MCT already added terminating nl */
		fputs(ibuf, rfp);
		}
	    step = 1;
	    break;
	    }
	}
    if (rfp)
	fclose(rfp);
    if (afp)
	fclose(afp);
    return err;
    }

/*--------------------------------------------------
  Processes either a single file or 
  a set of files whose names are passed in a file.
  A single file is specified as:
    aes_test -f xxx.req
  A set of files is specified as:
    aes_test -d xxxxx.xxx
  The default is: -d req.txt
--------------------------------------------------*/
int main(int argc, char **argv)
    {
    char *rqlist = "req.txt";
    FILE *fp = NULL;
    char fn[250] = "", rfn[256] = "";
    int f_opt = 0, d_opt = 1;

#ifdef FIPS
    FIPS_mode_set(1);
#endif
    ERR_load_crypto_strings();
    if (argc > 1)
	{
	if (strcasecmp(argv[1], "-d") == 0)
	    {
	    d_opt = 1;
	    }
	else if (strcasecmp(argv[1], "-f") == 0)
	    {
	    f_opt = 1;
	    d_opt = 0;
	    }
	else
	    {
	    printf("Invalid parameter: %s\n", argv[1]);
	    return 0;
	    }
	if (argc < 3)
	    {
	    printf("Missing parameter\n");
	    return 0;
	    }
	if (d_opt)
	    rqlist = argv[2];
	else
	    strcpy(fn, argv[2]);
	}
    if (d_opt)
	{ /* list of files (directory) */
	if (!(fp = fopen(rqlist, "r")))
	    {
	    printf("Cannot open req list file\n");
	    return -1;
	    }
	while (fgets(fn, sizeof(fn), fp))
	    {
	    strtok(fn, "\r\n");
	    strcpy(rfn, fn);
	    printf("Processing: %s\n", rfn);
	    if (proc_file(rfn))
		{
		printf(">>> Processing failed for: %s <<<\n", rfn);
		exit(1);
		}
	    }
	fclose(fp);
	}
    else /* single file */
	{
	printf("Processing: %s\n", fn);
	if (proc_file(fn))
	    {
	    printf(">>> Processing failed for: %s <<<\n", fn);
	    }
	}
    return 0;
    }

/* crypto/dsa/dsa_asn1.c */

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/dsa.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

ASN1_SEQUENCE(DSA_SIG) = {
	ASN1_SIMPLE(DSA_SIG, r, CBIGNUM),
	ASN1_SIMPLE(DSA_SIG, s, CBIGNUM)
} ASN1_SEQUENCE_END(DSA_SIG);

IMPLEMENT_ASN1_FUNCTIONS(DSA_SIG)

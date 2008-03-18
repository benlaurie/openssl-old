# test/cms-test.pl
# Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
# project.
#
# ====================================================================
# Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. All advertising materials mentioning features or use of this
#    software must display the following acknowledgment:
#    "This product includes software developed by the OpenSSL Project
#    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
#
# 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
#    endorse or promote products derived from this software without
#    prior written permission. For written permission, please contact
#    licensing@OpenSSL.org.
#
# 5. Products derived from this software may not be called "OpenSSL"
#    nor may "OpenSSL" appear in their names without prior written
#    permission of the OpenSSL Project.
#
# 6. Redistributions of any form whatsoever must retain the following
#    acknowledgment:
#    "This product includes software developed by the OpenSSL Project
#    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
#
# THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
# EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
# ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.
# ====================================================================

# CMS, PKCS7 consistency test script. Run extensive tests on
# OpenSSL PKCS#7 and CMS implementations.


my $ossl_path = "../apps/openssl";
my $cmd       = "$ossl_path cms ";
my $cmd2      = "$ossl_path smime ";
my $smdir     = "smime-certs";

my $badcmd = 0;

my @smime_pkcs7_tests = (

    [
        "signed content DER format, RSA key",
        "-sign -in smcont.txt -outform DER -nodetach"
          . " -signer $smdir/smrsa1.pem -out test.cms",
        "-verify -in test.cms -inform DER "
	  . " -CAfile $smdir/smroot.pem -out smtst.txt"
    ],

    [
        "signed detached content DER format, RSA key",

        "-sign -in smcont.txt -outform DER"
          . " -signer $smdir/smrsa1.pem -out test.cms",
        "-verify -in test.cms -inform DER "
          . " -CAfile $smdir/smroot.pem -out smtst.txt -content smcont.txt"
    ],

    [
        "signed content test streaming BER format, RSA",
        "-sign -in smcont.txt -outform DER -nodetach"
          . " -stream -signer $smdir/smrsa1.pem -out test.cms",
        "-verify -in test.cms -inform DER "
	  . " -CAfile $smdir/smroot.pem -out smtst.txt"
    ],

    [
        "signed content DER format, DSA key",
        "-sign -in smcont.txt -outform DER -nodetach"
          . " -signer $smdir/smdsa1.pem -out test.cms",
        "-verify -in test.cms -inform DER "
	  . " -CAfile $smdir/smroot.pem -out smtst.txt"
    ],

    [
        "signed detached content DER format, DSA key",

        "-sign -in smcont.txt -outform DER"
          . " -signer $smdir/smdsa1.pem -out test.cms",
        "-verify -in test.cms -inform DER "
          . " -CAfile $smdir/smroot.pem -out smtst.txt -content smcont.txt"
    ],

    [
        "signed detached content DER format, add RSA signer",

        "-resign -inform DER -in test.cms -outform DER"
          . " -signer $smdir/smrsa1.pem -out test2.cms",
        "-verify -in test2.cms -inform DER "
          . " -CAfile $smdir/smroot.pem -out smtst.txt -content smcont.txt"
    ],

    [
        "signed content test streaming BER format, DSA key",
        "-sign -in smcont.txt -outform DER -nodetach"
          . " -stream -signer $smdir/smdsa1.pem -out test.cms",
        "-verify -in test.cms -inform DER "
	  . " -CAfile $smdir/smroot.pem -out smtst.txt"
    ],

    [
        "signed content test streaming BER format, 2 DSA and 2 RSA keys",
        "-sign -in smcont.txt -outform DER -nodetach"
          . " -signer $smdir/smrsa1.pem -signer $smdir/smrsa2.pem"
          . " -signer $smdir/smdsa1.pem -signer $smdir/smdsa2.pem"
          . " -stream -out test.cms",
        "-verify -in test.cms -inform DER "
	  . " -CAfile $smdir/smroot.pem -out smtst.txt"
    ],

    [
"signed content test streaming BER format, 2 DSA and 2 RSA keys, no attributes",
        "-sign -in smcont.txt -outform DER -noattr -nodetach"
          . " -signer $smdir/smrsa1.pem -signer $smdir/smrsa2.pem"
          . " -signer $smdir/smdsa1.pem -signer $smdir/smdsa2.pem"
          . " -stream -out test.cms",
        "-verify -in test.cms -inform DER "
	  . " -CAfile $smdir/smroot.pem -out smtst.txt"
    ],

    [
        "signed content test streaming S/MIME format, 2 DSA and 2 RSA keys",
        "-sign -in smcont.txt -nodetach"
          . " -signer $smdir/smrsa1.pem -signer $smdir/smrsa2.pem"
          . " -signer $smdir/smdsa1.pem -signer $smdir/smdsa2.pem"
          . " -stream -out test.cms",
        "-verify -in test.cms "
	  . " -CAfile $smdir/smroot.pem -out smtst.txt"
    ],

    [
"signed content test streaming multipart S/MIME format, 2 DSA and 2 RSA keys",
        "-sign -in smcont.txt"
          . " -signer $smdir/smrsa1.pem -signer $smdir/smrsa2.pem"
          . " -signer $smdir/smdsa1.pem -signer $smdir/smdsa2.pem"
          . " -stream -out test.cms",
        "-verify -in test.cms "
	  . " -CAfile $smdir/smroot.pem -out smtst.txt"
    ],

    [
        "enveloped content test streaming S/MIME format, 3 recipients",
        "-encrypt -in smcont.txt"
          . " -stream -out test.cms"
          . " $smdir/smrsa1.pem $smdir/smrsa2.pem $smdir/smrsa3.pem ",
        "-decrypt -recip $smdir/smrsa1.pem -in test.cms -out smtst.txt"
    ],

    [
"enveloped content test streaming S/MIME format, 3 recipients, 3rd used",
        "-encrypt -in smcont.txt"
          . " -stream -out test.cms"
          . " $smdir/smrsa1.pem $smdir/smrsa2.pem $smdir/smrsa3.pem ",
        "-decrypt -recip $smdir/smrsa3.pem -in test.cms -out smtst.txt"
    ],

    [
"enveloped content test streaming S/MIME format, 3 recipients, key only used",
        "-encrypt -in smcont.txt"
          . " -stream -out test.cms"
          . " $smdir/smrsa1.pem $smdir/smrsa2.pem $smdir/smrsa3.pem ",
        "-decrypt -inkey $smdir/smrsa3.pem -in test.cms -out smtst.txt"
    ],

    [
"enveloped content test streaming S/MIME format, AES-256 cipher, 3 recipients",
        "-encrypt -in smcont.txt"
          . " -aes256 -stream -out test.cms"
          . " $smdir/smrsa1.pem $smdir/smrsa2.pem $smdir/smrsa3.pem ",
        "-decrypt -recip $smdir/smrsa1.pem -in test.cms -out smtst.txt"
    ],

);

my @smime_cms_tests = (

    [
        "signed content test streaming BER format, 2 DSA and 2 RSA keys, keyid",
        "-sign -in smcont.txt -outform DER -nodetach -keyid"
          . " -signer $smdir/smrsa1.pem -signer $smdir/smrsa2.pem"
          . " -signer $smdir/smdsa1.pem -signer $smdir/smdsa2.pem"
          . " -stream -out test.cms",
        "-verify -in test.cms -inform DER "
	  . " -CAfile $smdir/smroot.pem -out smtst.txt"
    ],

    [
        "signed content test streaming PEM format, 2 DSA and 2 RSA keys",
        "-sign -in smcont.txt -outform PEM -nodetach"
          . " -signer $smdir/smrsa1.pem -signer $smdir/smrsa2.pem"
          . " -signer $smdir/smdsa1.pem -signer $smdir/smdsa2.pem"
          . " -stream -out test.cms",
        "-verify -in test.cms -inform PEM "
	  . " -CAfile $smdir/smroot.pem -out smtst.txt"
    ],

    [
        "data content test streaming PEM format",
        "-data_create -in smcont.txt -outform PEM -nodetach"
          . " -stream -out test.cms",
        "-data_out -in test.cms -inform PEM -out smtst.txt"
    ],

    [
        "encrypted content test streaming PEM format, 128 bit RC2 key",
        "-EncryptedData_encrypt -in smcont.txt -outform PEM"
          . " -rc2 -secretkey 000102030405060708090A0B0C0D0E0F"
          . " -stream -out test.cms",
        "-EncryptedData_decrypt -in test.cms -inform PEM "
          . " -secretkey 000102030405060708090A0B0C0D0E0F -out smtst.txt"
    ],

    [
        "encrypted content test streaming PEM format, 40 bit RC2 key",
        "-EncryptedData_encrypt -in smcont.txt -outform PEM"
          . " -rc2 -secretkey 0001020304"
          . " -stream -out test.cms",
        "-EncryptedData_decrypt -in test.cms -inform PEM "
          . " -secretkey 0001020304 -out smtst.txt"
    ],

    [
        "encrypted content test streaming PEM format, triple DES key",
        "-EncryptedData_encrypt -in smcont.txt -outform PEM"
          . " -des3 -secretkey 000102030405060708090A0B0C0D0E0F1011121314151617"
          . " -stream -out test.cms",
        "-EncryptedData_decrypt -in test.cms -inform PEM "
          . " -secretkey 000102030405060708090A0B0C0D0E0F1011121314151617"
          . " -out smtst.txt"
    ],

    [
        "encrypted content test streaming PEM format, 128 bit AES key",
        "-EncryptedData_encrypt -in smcont.txt -outform PEM"
          . " -aes128 -secretkey 000102030405060708090A0B0C0D0E0F"
          . " -stream -out test.cms",
        "-EncryptedData_decrypt -in test.cms -inform PEM "
          . " -secretkey 000102030405060708090A0B0C0D0E0F -out smtst.txt"
    ],

);

my @smime_cms_comp_tests = (

    [
        "compressed content test streaming PEM format",
        "-compress -in smcont.txt -outform PEM -nodetach"
          . " -stream -out test.cms",
        "-uncompress -in test.cms -inform PEM -out smtst.txt"
    ]

);

print "CMS => PKCS#7 compatibility tests\n";

run_smime_tests( \$badcmd, \@smime_pkcs7_tests, $cmd, $cmd2 );

print "CMS <= PKCS#7 compatibility tests\n";

run_smime_tests( \$badcmd, \@smime_pkcs7_tests, $cmd2, $cmd );

print "CMS <=> CMS consistency tests\n";

run_smime_tests( \$badcmd, \@smime_pkcs7_tests, $cmd, $cmd );
run_smime_tests( \$badcmd, \@smime_cms_tests,   $cmd, $cmd );

if ( `$ossl_path version -f` =~ /ZLIB/ ) {
    run_smime_tests( \$badcmd, \@smime_cms_comp_tests, $cmd, $cmd );
}
else {
    print "Zlib not supported: compression tests skipped\n";
}

if ($badcmd) {
    print "$badcmd TESTS FAILED!!\n";
}
else {
    print "ALL TESTS SUCCESSFUL.\n";
}

sub run_smime_tests {
    my ( $rv, $aref, $scmd, $vcmd ) = @_;

    foreach $smtst (@$aref) {
        my ( $tnam, $rscmd, $rvcmd ) = @$smtst;
        system( $scmd . $rscmd );
        if ($?) {
            print "$tnam: generation error\n";
            $$rv++;
            next;
        }
        system( $vcmd . $rvcmd );
        if ($?) {
            print "$tnam: verify error\n";
            $$rv++;
            next;
        }
        print "$tnam: OK\n";
    }
}


#!/usr/local/bin/perl -w

my @fips_tests = (

# FIPS test descriptions

# DSA tests

["dsa", "PQGGen", "fips_dssvs pqg"],
["dsa", "KeyPair", "fips_dssvs keypair"],
["dsa", "SigGen", "fips_dssvs siggen"],
["dsa", "SigVer", "fips_dssvs sigver"],

# SHA tests

["sha", "SHA1LongMsg", "fips_shatest"],
["sha", "SHA1Monte", "fips_shatest"],
["sha", "SHA1ShortMsg", "fips_shatest"],
["sha", "SHA224LongMsg", "fips_shatest"],
["sha", "SHA224Monte", "fips_shatest"],
["sha", "SHA224ShortMsg", "fips_shatest"],
["sha", "SHA256LongMsg", "fips_shatest"],
["sha", "SHA256Monte", "fips_shatest"],
["sha", "SHA256ShortMsg", "fips_shatest"],
["sha", "SHA384LongMsg", "fips_shatest"],
["sha", "SHA384Monte", "fips_shatest"],
["sha", "SHA384ShortMsg", "fips_shatest"],
["sha", "SHA512LongMsg", "fips_shatest"],
["sha", "SHA512Monte", "fips_shatest"],
["sha", "SHA512ShortMsg", "fips_shatest"],

# AES tests, file search mode
["aes", "\@dir", "fips_aesavs -f"],

# DES tests, file search mode
["tdes", "\@dir", "fips_desmovs -f"],

# HMAC

["hmac", "HMAC", "fips_hmactest"],

# RAND tests

["rng", "ANSI931_TDES2MCT", "fips_rngvs mct"],
["rng", "ANSI931_TDES2VST", "fips_rngvs vst"],

# RSA tests

["rsa", "SigGen15", "fips_rsastest"],
["rsa", "SigVer15", "fips_rsavtest"],
["rsa", "SigGenPSS", "fips_rsastest -saltlen 0"],
["rsa", "SigVerPSS", "fips_rsavtest -saltlen 0"],
["rsa", "SigGenRSA", "fips_rsastest -x931"],
["rsa", "SigVerRSA", "fips_rsavtest -x931"],
["rsa", "KeyGenRSA", "fips_rsagtest"],
["rsa_salt_62", "SigGenPSS", "fips_rsastest -saltlen 62"],
["rsa_salt_62", "SigVerPSS", "fips_rsavtest -saltlen 62"]

);

my $lnum = 0;
my $win32 = 0;
my $onedir = 0;
my $ltdir = "";
my $tvdir;
my $tvprefix;
my $tprefix;
my $shwrap_prefix;

foreach (@ARGV)
	{
	if ($_ eq "--win32")
		{
		$win32 = 1;
		}
	elsif ($_ eq "--onedir")
		{
		$onedir = 1;
		}
	elsif (/--dir=(.*)$/)
		{
		$tvdir = $1;
		}
	elsif (/--tprefix=(.*)$/)
		{
		$tprefix = $1;
		}
	elsif (/--tvprefix=(.*)$/)
		{
		$tvprefix = $1;
		}
	elsif (/--shwrap_prefix=(.*)$/)
		{
		$shwrap_prefix = $1;
		}
	elsif (/--outfile=(.*)$/)
		{
		$outfile = $1;
		}
	}

$tvdir = "testvectors" unless defined $tvdir;
$shwrap_prefix = "../util/" unless defined $shwrap_prefix;

if ($win32)
	{
	if ($onedir)
		{
		$tvprefix = "" unless defined $tvprefix;
		}
	else
		{
		$tvprefix = "..\\fips-1.0\\" unless defined $tvprefix;
		}
	$tprefix = ".\\" unless defined $tprefix;
	$outfile = "fipstests.bat" unless defined $outfile;
	open(OUT, ">$outfile");

	print OUT <<END;
\@echo off
rem Test vector run script
rem Auto generated by mkfipsscr.pl script
rem Do not edit

END

	}
else
	{
	$tvprefix = "" unless defined $tvprefix;
	if ($onedir)
		{
		$tprefix = "./" unless defined $tprefix;
		}
	else
		{
		$tprefix = "../test/" unless defined $tprefix;
		}
	$outfile = "fipstests.sh" unless defined $outfile;
	open(OUT, ">$outfile");

	print OUT <<END;
#!/bin/sh

# Test vector run script
# Auto generated by mkfipsscr.pl script
# Do not edit

END

	}

foreach(@fips_tests)
	{
	my ($tdir, $fprefix, $tcmd) = @$_;
	$lnum++;
	if ($tdir ne $ltdir)
		{
		$ltdir = $tdir;
		test_dir($win32, $ltdir);
		}
	test_line($win32, $tdir, $fprefix, $tcmd);
	}

sub test_dir
	{
	my ($win32, $tdir) = @_;
	if ($win32)
		{
		my $rsp = "$tvprefix$tvdir\\$tdir\\rsp";
		print OUT <<END;

echo $tdir tests
rd /s /q $rsp
md $rsp
END
		}
	else
		{
		my $rsp = "$tvdir/$tdir/rsp";
		print OUT <<END;

# $tdir tests
rm -rf $rsp
mkdir $rsp

END
		}
	}

sub test_line
	{
	my ($win32, $tdir, $fprefix, $tcmd) = @_;
	if ($fprefix =~ /\@/)
		{
		foreach(<$tvprefix$tvdir/$tdir/req/*.req>)
			{
			if ($win32)
				{
				$_ =~ tr|/|\\|;
				print OUT "$tprefix$tcmd $_\n";
				}
			else
				{
				print OUT <<END;
${shwrap_prefix}shlib_wrap.sh $tprefix$tcmd $_
END
				}
			}
		return;
		}
	if ($win32)
		{
		my $req = "$tvprefix$tvdir\\$tdir\\req\\$fprefix.req";
		my $rsp = "$tvprefix$tvdir\\$tdir\\rsp\\$fprefix.rsp";
	print OUT "$tprefix$tcmd < $req > $rsp\n";
END
		}
	else
		{
		my $req = "tvdir/$tdir/req/$fprefix.req";
		my $rsp = "$tvdir/$tdir/rsp/$fprefix.rsp";
		print OUT <<END;
if [ -f $req ] ; then ${shwrap_prefix}shlib_wrap.sh $tprefix$tcmd < $req > $rsp; fi
END
		}
	}
	

#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# Bit-sliced AES for ARM NEON
#
# February 2012.
#
# This implementation is direct adaptation of bsaes-x86_64 module for
# ARM NEON. Except that this module is endian-neutral [in sense that
# it can be compiled for either endianness] by courtesy of vld1.8's
# neutrality. Initial version doesn't implement interface to OpenSSL,
# only low-level primitives and unsupported entry points, just enough
# to collect performance results, which for Cortex-A8 core are:
#
# encrypt	20.9 cycles per byte processed with 128-bit key
# decrypt	25.6 cycles per byte processed with 128-bit key
# key conv.	900  cycles per 128-bit key/0.34 of 8x block
#
# When comparing to x86_64 results keep in mind that NEON unit is
# [mostly] single-issue and thus can't benefit from parallelism. And
# when comparing to aes-armv4 results keep in mind key schedule
# conversion overhead (see bsaes-x86_64.pl for details)...
#
#						<appro@openssl.org>

while (($output=shift) && ($output!~/^\w[\w\-]*\.\w+$/)) {}
open STDOUT,">$output";

my ($inp,$out,$len,$key)=("r0","r1","r2","r3");
my @XMM=map("q$_",(0..15));

{
my ($key,$rounds,$const)=("r4","r5","r6");

sub Dlo()   { shift=~m|q([1]?[0-9])|?"d".($1*2):"";     }
sub Dhi()   { shift=~m|q([1]?[0-9])|?"d".($1*2+1):"";   }

sub Sbox {
# input in  lsb > [b0, b1, b2, b3, b4, b5, b6, b7] < msb
# output in lsb > [b0, b1, b4, b6, b3, b7, b2, b5] < msb
my @b=@_[0..7];
my @t=@_[8..11];
my @s=@_[12..15];
	&InBasisChange	(@b);
	&Inv_GF256	(@b[6,5,0,3,7,1,4,2],@t,@s);
	&OutBasisChange	(@b[7,1,4,2,6,5,0,3]);
}

sub InBasisChange {
# input in  lsb > [b0, b1, b2, b3, b4, b5, b6, b7] < msb
# output in lsb > [b6, b5, b0, b3, b7, b1, b4, b2] < msb 
my @b=@_[0..7];
$code.=<<___;
	veor	@b[5], @b[5], @b[6]
	veor	@b[2], @b[2], @b[1]
	veor	@b[3], @b[3], @b[0]
	veor	@b[6], @b[6], @b[2]
	veor	@b[5], @b[5], @b[0]

	veor	@b[6], @b[6], @b[3]
	veor	@b[3], @b[3], @b[7]
	veor	@b[7], @b[7], @b[5]
	veor	@b[3], @b[3], @b[4]
	veor	@b[4], @b[4], @b[5]
	veor	@b[3], @b[3], @b[1]

	veor	@b[2], @b[2], @b[7]
	veor	@b[1], @b[1], @b[5]
___
}

sub OutBasisChange {
# input in  lsb > [b0, b1, b2, b3, b4, b5, b6, b7] < msb
# output in lsb > [b6, b1, b2, b4, b7, b0, b3, b5] < msb
my @b=@_[0..7];
$code.=<<___;
	veor	@b[0], @b[0], @b[6]
	veor	@b[1], @b[1], @b[4]
	veor	@b[2], @b[2], @b[0]
	veor	@b[4], @b[4], @b[6]
	veor	@b[6], @b[6], @b[1]

	veor	@b[1], @b[1], @b[5]
	veor	@b[5], @b[5], @b[3]
	veor	@b[3], @b[3], @b[7]
	veor	@b[7], @b[7], @b[5]
	veor	@b[2], @b[2], @b[5]

	veor	@b[4], @b[4], @b[7]
___
}

sub InvSbox {
# input in lsb 	> [b0, b1, b2, b3, b4, b5, b6, b7] < msb
# output in lsb	> [b0, b1, b6, b4, b2, b7, b3, b5] < msb
my @b=@_[0..7];
my @t=@_[8..11];
my @s=@_[12..15];
	&InvInBasisChange	(@b);
	&Inv_GF256		(@b[5,1,2,6,3,7,0,4],@t,@s);
	&InvOutBasisChange	(@b[3,7,0,4,5,1,2,6]);
}

sub InvInBasisChange {		# OutBasisChange in reverse
my @b=@_[5,1,2,6,3,7,0,4];
$code.=<<___
	veor	@b[4], @b[4], @b[7]

	veor	@b[7], @b[7], @b[5]
	veor	@b[2], @b[2], @b[5]
	veor	@b[3], @b[3], @b[7]
	veor	@b[5], @b[5], @b[3]
	veor	@b[1], @b[1], @b[5]

	veor	@b[6], @b[6], @b[1]
	veor	@b[2], @b[2], @b[0]
	veor	@b[4], @b[4], @b[6]
	veor	@b[0], @b[0], @b[6]
	veor	@b[1], @b[1], @b[4]
___
}

sub InvOutBasisChange {		# InBasisChange in reverse
my @b=@_[2,5,7,3,6,1,0,4];
$code.=<<___;
	veor	@b[1], @b[1], @b[5]
	veor	@b[2], @b[2], @b[7]

	veor	@b[3], @b[3], @b[1]
	veor	@b[4], @b[4], @b[5]
	veor	@b[7], @b[7], @b[5]
	veor	@b[3], @b[3], @b[4]
	 veor 	@b[5], @b[5], @b[0]
	veor	@b[3], @b[3], @b[7]
	 veor	@b[6], @b[6], @b[2]
	 veor	@b[2], @b[2], @b[1]
	veor	@b[6], @b[6], @b[3]

	veor	@b[3], @b[3], @b[0]
	veor	@b[5], @b[5], @b[6]
___
}

sub Mul_GF4 {
#;*************************************************************
#;* Mul_GF4: Input x0-x1,y0-y1 Output x0-x1 Temp t0 (8) *
#;*************************************************************
my ($x0,$x1,$y0,$y1,$t0)=@_;
$code.=<<___;
	veor 	$t0, $y0, $y1
	vand	$t0, $t0, $x0
	veor	$x0, $x0, $x1
	vand	$x1, $x1, $y0
	vand	$x0, $x0, $y1
	veor	$x0, $x0, $x1
	veor	$x1, $x1, $t0
___
}

sub Mul_GF4_N {				# not used, see next subroutine
# multiply and scale by N
my ($x0,$x1,$y0,$y1,$t0)=@_;
$code.=<<___;
	veor	$t0, $y0, $y1
	vand	$t0, $t0, $x0
	veor	$x0, $x0, $x1
	vand	$x1, $x1, $y0
	vand	$x0, $x0, $y1
	veor	$x1, $x1, $x0
	veor	$x0, $x0, $t0
___
}

sub Mul_GF4_N_GF4 {
# interleaved Mul_GF4_N and Mul_GF4
my ($x0,$x1,$y0,$y1,$t0,
    $x2,$x3,$y2,$y3,$t1)=@_;
$code.=<<___;
	veor	$t0, $y0, $y1
	 veor 	$t1, $y2, $y3
	vand	$t0, $t0, $x0
	 vand	$t1, $t1, $x2
	veor	$x0, $x0, $x1
	 veor	$x2, $x2, $x3
	vand	$x1, $x1, $y0
	 vand	$x3, $x3, $y2
	vand	$x0, $x0, $y1
	 vand	$x2, $x2, $y3
	veor	$x1, $x1, $x0
	 veor	$x2, $x2, $x3
	veor	$x0, $x0, $t0
	 veor	$x3, $x3, $t1
___
}
sub Mul_GF16_2 {
my @x=@_[0..7];
my @y=@_[8..11];
my @t=@_[12..15];
$code.=<<___;
	vmov	@t[0], @x[0]
	vmov	@t[1], @x[1]
___
	&Mul_GF4  	(@x[0], @x[1], @y[0], @y[1], @t[2]);
$code.=<<___;
	veor	@t[0], @t[0], @x[2]
	veor	@t[1], @t[1], @x[3]
	veor	@y[0], @y[0], @y[2]
	veor	@y[1], @y[1], @y[3]
___
	Mul_GF4_N_GF4	(@t[0], @t[1], @y[0], @y[1], @t[3],
			 @x[2], @x[3], @y[2], @y[3], @t[2]);
$code.=<<___;
	veor	@x[0], @x[0], @t[0]
	veor	@x[2], @x[2], @t[0]
	veor	@x[1], @x[1], @t[1]
	veor	@x[3], @x[3], @t[1]

	veor	@t[0], @x[4], @x[6]
	veor	@t[1], @x[5], @x[7]
___
	&Mul_GF4_N_GF4	(@t[0], @t[1], @y[0], @y[1], @t[3],
			 @x[6], @x[7], @y[2], @y[3], @t[2]);
$code.=<<___;
	veor	@y[0], @y[0], @y[2]
	veor	@y[1], @y[1], @y[3]
___
	&Mul_GF4  	(@x[4], @x[5], @y[0], @y[1], @t[3]);
$code.=<<___;
	veor	@x[4], @x[4], @t[0]
	veor	@x[6], @x[6], @t[0]
	veor	@x[5], @x[5], @t[1]
	veor	@x[7], @x[7], @t[1]
___
}
sub Inv_GF256 {
#;********************************************************************
#;* Inv_GF256: Input x0-x7 Output x0-x7 Temp t0-t3,s0-s3 (144)       *
#;********************************************************************
my @x=@_[0..7];
my @t=@_[8..11];
my @s=@_[12..15];
# direct optimizations from hardware
$code.=<<___;
	veor	@t[3], @x[4], @x[6]
	veor	@t[2], @x[5], @x[7]
	veor	@t[1], @x[1], @x[3]
	veor	@s[1], @x[7], @x[6]
	 vmov	@t[0], @t[2]
	veor	@s[0], @x[0], @x[2]

	vorr	@t[2], @t[2], @t[1]
	veor	@s[3], @t[3], @t[0]
	vand	@s[2], @t[3], @s[0]
	vorr	@t[3], @t[3], @s[0]
	veor	@s[0], @s[0], @t[1]
	vand	@t[0], @t[0], @t[1]
	vand	@s[3], @s[3], @s[0]
	veor	@s[0], @x[3], @x[2]
	vand	@s[1], @s[1], @s[0]
	veor	@t[3], @t[3], @s[1]
	veor	@t[2], @t[2], @s[1]
	veor	@s[1], @x[4], @x[5]
	veor	@s[0], @x[1], @x[0]
	vorr	@t[1], @s[1], @s[0]
	vand	@s[1], @s[1], @s[0]
	veor	@t[0], @t[0], @s[1]
	veor	@t[3], @t[3], @s[3]
	veor	@t[2], @t[2], @s[2]
	veor	@t[1], @t[1], @s[3]
	veor	@t[0], @t[0], @s[2]
	veor	@t[1], @t[1], @s[2]
	vand	@s[0], @x[7], @x[3]
	vand	@s[1], @x[6], @x[2]
	vand	@s[2], @x[5], @x[1]
	vorr	@s[3], @x[4], @x[0]
	veor	@t[3], @t[3], @s[0]
	veor	@t[2], @t[2], @s[1]
	veor	@t[1], @t[1], @s[2]
	veor	@t[0], @t[0], @s[3]

	@ Inv_GF16 \t0, \t1, \t2, \t3, \s0, \s1, \s2, \s3

	@ new smaller inversion

	veor	@s[0], @t[3], @t[2]
	vand	@t[3], @t[3], @t[1]

	veor	@s[2], @t[0], @t[3]
	vand	@s[3], @s[0], @s[2]

	veor	@s[3], @s[3], @t[2]
	veor	@s[1], @t[1], @t[0]

	veor	@t[3], @t[3], @t[2]

	vand	@s[1], @s[1], @t[3]

	veor	@s[1], @s[1], @t[0]

	veor	@t[2], @s[2], @s[1]
	veor	@t[1], @t[1], @s[1]

	vand	@t[2], @t[2], @t[0]

	veor	@s[2], @s[2], @t[2]
	veor	@t[1], @t[1], @t[2]

	vand	@s[2], @s[2], @s[3]

	veor	@s[2], @s[2], @s[0]
___
# output in s3, s2, s1, t1

# Mul_GF16_2 \x0, \x1, \x2, \x3, \x4, \x5, \x6, \x7, \t2, \t3, \t0, \t1, \s0, \s1, \s2, \s3

# Mul_GF16_2 \x0, \x1, \x2, \x3, \x4, \x5, \x6, \x7, \s3, \s2, \s1, \t1, \s0, \t0, \t2, \t3
	&Mul_GF16_2(@x,@s[3,2,1],@t[1],@s[0],@t[0,2,3]);

### output msb > [x3,x2,x1,x0,x7,x6,x5,x4] < lsb
}

# AES linear components

sub ShiftRows {
my @x=@_[0..7];
my @t=@_[8..11];
my $mask=pop;
$code.=<<___;
	vldmia	$key!, {@t[0]-@t[3]}
	veor	@t[0], @t[0], @x[0]
	veor	@t[1], @t[1], @x[1]
	vtbl.8	`&Dlo(@x[0])`, {@t[0]}, `&Dlo($mask)`
	vtbl.8	`&Dhi(@x[0])`, {@t[0]}, `&Dhi($mask)`
	vldmia	$key!, {@t[0]}
	veor	@t[2], @t[2], @x[2]
	vtbl.8	`&Dlo(@x[1])`, {@t[1]}, `&Dlo($mask)`
	vtbl.8	`&Dhi(@x[1])`, {@t[1]}, `&Dhi($mask)`
	vldmia	$key!, {@t[1]}
	veor	@t[3], @t[3], @x[3]
	vtbl.8	`&Dlo(@x[2])`, {@t[2]}, `&Dlo($mask)`
	vtbl.8	`&Dhi(@x[2])`, {@t[2]}, `&Dhi($mask)`
	vldmia	$key!, {@t[2]}
	vtbl.8	`&Dlo(@x[3])`, {@t[3]}, `&Dlo($mask)`
	vtbl.8	`&Dhi(@x[3])`, {@t[3]}, `&Dhi($mask)`
	vldmia	$key!, {@t[3]}
	veor	@t[0], @t[0], @x[4]
	veor	@t[1], @t[1], @x[5]
	vtbl.8	`&Dlo(@x[4])`, {@t[0]}, `&Dlo($mask)`
	vtbl.8	`&Dhi(@x[4])`, {@t[0]}, `&Dhi($mask)`
	veor	@t[2], @t[2], @x[6]
	vtbl.8	`&Dlo(@x[5])`, {@t[1]}, `&Dlo($mask)`
	vtbl.8	`&Dhi(@x[5])`, {@t[1]}, `&Dhi($mask)`
	veor	@t[3], @t[3], @x[7]
	vtbl.8	`&Dlo(@x[6])`, {@t[2]}, `&Dlo($mask)`
	vtbl.8	`&Dhi(@x[6])`, {@t[2]}, `&Dhi($mask)`
	vtbl.8	`&Dlo(@x[7])`, {@t[3]}, `&Dlo($mask)`
	vtbl.8	`&Dhi(@x[7])`, {@t[3]}, `&Dhi($mask)`
___
}

sub MixColumns {
# modified to emit output in order suitable for feeding back to aesenc[last]
my @x=@_[0..7];
my @t=@_[8..15];
$code.=<<___;
	vext.8	@t[0], @x[0], @x[0], #12	@ x0 <<< 32
	vext.8	@t[1], @x[1], @x[1], #12
	 veor	@x[0], @x[0], @t[0]		@ x0 ^ (x0 <<< 32)
	vext.8	@t[2], @x[2], @x[2], #12
	 veor	@x[1], @x[1], @t[1]
	vext.8	@t[3], @x[3], @x[3], #12
	 veor	@x[2], @x[2], @t[2]
	vext.8	@t[4], @x[4], @x[4], #12
	 veor	@x[3], @x[3], @t[3]
	vext.8	@t[5], @x[5], @x[5], #12
	 veor	@x[4], @x[4], @t[4]
	vext.8	@t[6], @x[6], @x[6], #12
	 veor	@x[5], @x[5], @t[5]
	vext.8	@t[7], @x[7], @x[7], #12
	 veor	@x[6], @x[6], @t[6]
	 veor	@x[7], @x[7], @t[7]

	veor	@t[1], @t[1], @x[0]
	 vext.8	@x[0], @x[0], @x[0], #8		@ (x0 ^ (x0 <<< 32)) <<< 64)
	veor	@t[0], @t[0], @x[7]
	veor	@t[1], @t[1], @x[7]
	veor	@t[2], @t[2], @x[1]
	 vext.8	@x[1], @x[1], @x[1], #8
	veor	@t[5], @t[5], @x[4]
	 veor	@x[0], @x[0], @t[0]
	veor	@t[6], @t[6], @x[5]
	 veor	@x[1], @x[1], @t[1]
	 vext.8	@t[0], @x[4], @x[4], #8
	veor	@t[4], @t[4], @x[3]
	 vext.8	@t[1], @x[5], @x[5], #8
	veor	@t[7], @t[7], @x[6]
	 vext.8	@x[4], @x[3], @x[3], #8
	veor	@t[3], @t[3], @x[2]
	 vext.8	@x[5], @x[7], @x[7], #8
	veor	@t[3], @t[3], @x[7]
	 vext.8	@x[3], @x[6], @x[6], #8
	veor	@t[4], @t[4], @x[7]
	 vext.8	@x[6], @x[2], @x[2], #8
	veor	@x[2], @t[0], @t[4]
	veor	@x[7], @t[1], @t[5]

	veor	@x[4], @x[4], @t[3]
	veor	@x[5], @x[5], @t[7]
	veor	@x[3], @x[3], @t[6]
	 @ vmov	@x[2], @t[0]
	veor	@x[6], @x[6], @t[2]
	 @ vmov	@x[7], @t[1]
___
}

sub InvMixColumns {
my @x=@_[0..7];
my @t=@_[8..15];

$code.=<<___;
	@ multiplication by 0x0e
	vext.8	@t[7], @x[7], @x[7], #12
	vmov	@t[2], @x[2]
	veor	@x[7], @x[7], @x[5]		@ 7 5
	veor	@x[2], @x[2], @x[5]		@ 2 5
	vext.8	@t[0], @x[0], @x[0], #12
	vmov	@t[5], @x[5]
	veor	@x[5], @x[5], @x[0]		@ 5 0		[1]
	veor	@x[0], @x[0], @x[1]		@ 0 1
	vext.8	@t[1], @x[1], @x[1], #12
	veor	@x[1], @x[1], @x[2]		@ 1 25
	veor	@x[0], @x[0], @x[6]		@ 01 6		[2]
	veor	@x[1], @x[1], @x[3]		@ 125 3		[4]
	vext.8	@t[3], @x[3], @x[3], #12
	veor	@x[2], @x[2], @x[0]		@ 25 016	[3]
	veor	@x[3], @x[3], @x[7]		@ 3 75
	veor	@x[7], @x[7], @x[6]		@ 75 6		[0]
	vext.8	@t[6], @x[6], @x[6], #12
	vmov	@t[4], @x[4]
	veor	@x[6], @x[6], @x[4]		@ 6 4
	veor	@x[4], @x[4], @x[3]		@ 4 375		[6]
	veor	@x[3], @x[3], @x[7]		@ 375 756=36
	veor	@x[6], @x[6], @t[5]		@ 64 5		[7]
	veor	@x[3], @x[3], @t[2]		@ 36 2
	vext.8	@t[5], @t[5], @t[5], #12
	veor	@x[3], @x[3], @t[4]		@ 362 4		[5]
___
					my @y = @x[7,5,0,2,1,3,4,6];
$code.=<<___;
	@ multiplication by 0x0b
	veor	@y[1], @y[1], @y[0]
	veor	@y[0], @y[0], @t[0]
	veor	@y[1], @y[1], @t[1]
	vext.8	@t[2], @t[2], @t[2], #12
	veor	@y[0], @y[0], @t[5]
	veor	@y[1], @y[1], @t[6]
	veor	@y[0], @y[0], @t[7]
	vext.8	@t[4], @t[4], @t[4], #12
	veor	@t[7], @t[7], @t[6]		@ clobber t[7]
	veor	@y[1], @y[1], @y[0]

	veor	@y[3], @y[3], @t[0]
	vext.8	@t[0], @t[0], @t[0], #12
	veor	@y[2], @y[2], @t[1]
	veor	@y[4], @y[4], @t[1]
	veor	@y[2], @y[2], @t[2]
	vext.8	@t[1], @t[1], @t[1], #12
	veor	@y[3], @y[3], @t[2]
	veor	@y[5], @y[5], @t[2]
	veor	@y[2], @y[2], @t[7]
	vext.8	@t[2], @t[2], @t[2], #12
	veor	@y[3], @y[3], @t[3]
	veor	@y[6], @y[6], @t[3]
	veor	@y[4], @y[4], @t[3]
	vext.8	@t[3], @t[3], @t[3], #12
	veor	@y[7], @y[7], @t[4]
	veor	@y[5], @y[5], @t[4]
	veor	@y[7], @y[7], @t[7]
	veor	@y[3], @y[3], @t[5]
	veor	@y[4], @y[4], @t[4]
	veor	@t[7], @t[7], @t[5]		@ clobber t[7] even more

	veor	@y[5], @y[5], @t[7]
	vext.8	@t[4], @t[4], @t[4], #12
	veor	@y[6], @y[6], @t[7]
	veor	@y[4], @y[4], @t[7]

	veor	@t[7], @t[7], @t[5]
	vext.8	@t[5], @t[5], @t[5], #12
	veor	@t[7], @t[7], @t[6]		@ restore t[7]

	@ multiplication by 0x0d
	veor	@y[4], @y[4], @y[7]
	veor	@y[7], @y[7], @t[4]
	vext.8	@t[6], @t[6], @t[6], #12
	veor	@y[2], @y[2], @t[0]
	veor	@y[7], @y[7], @t[5]
	veor	@y[2], @y[2], @t[2]
	vext.8	@t[7], @t[7], @t[7], #12

	veor	@y[3], @y[3], @y[1]
	veor	@y[1], @y[1], @t[1]
	veor	@y[0], @y[0], @t[0]
	veor	@y[3], @y[3], @t[0]
	veor	@y[1], @y[1], @t[5]
	veor	@y[0], @y[0], @t[5]
	veor	@y[1], @y[1], @t[7]
	vext.8	@t[0], @t[0], @t[0], #12
	veor	@y[0], @y[0], @t[6]
	veor	@y[3], @y[3], @y[1]
	veor	@y[4], @y[4], @t[1]
	vext.8	@t[1], @t[1], @t[1], #12

	veor	@y[7], @y[7], @t[7]
	veor	@y[4], @y[4], @t[2]
	veor	@y[5], @y[5], @t[2]
	vext.8	@t[2], @t[2], @t[2], #12
	veor	@y[2], @y[2], @t[6]
	veor	@t[6], @t[6], @t[3]		@ clobber t[6]
	veor	@y[4], @y[4], @y[7]
	veor	@y[3], @y[3], @t[6]

	veor	@y[6], @y[6], @t[6]
	veor	@y[5], @y[5], @t[5]
	vext.8	@t[5], @t[5], @t[5], #12
	veor	@y[6], @y[6], @t[4]
	vext.8	@t[4], @t[4], @t[4], #12
	veor	@y[5], @y[5], @t[6]
	veor	@y[6], @y[6], @t[7]
	vext.8	@t[7], @t[7], @t[7], #12
	veor	@t[6], @t[6], @t[3]		@ restore t[6]
	vext.8	@t[3], @t[3], @t[3], #12

	@ multiplication by 0x09
	veor	@y[4], @y[4], @y[1]
	veor	@t[1], @t[1], @y[1]		@ t[1]=y[1]
	veor	@t[0], @t[0], @t[5]		@ clobber t[0]
	vext.8	@t[6], @t[6], @t[6], #12
	veor	@t[1], @t[1], @t[5]
	veor	@y[3], @y[3], @t[0]
	veor	@t[0], @t[0], @y[0]		@ t[0]=y[0]
	veor	@t[1], @t[1], @t[6]
	veor	@t[6], @t[6], @t[7]		@ clobber t[6]
	veor	@y[4], @y[4], @t[1]
	veor	@y[7], @y[7], @t[4]
	veor	@t[4], @t[4], @y[4]		@ t[4]=y[4]
	veor	@y[6], @y[6], @t[3]
	veor	@t[3], @t[3], @y[3]		@ t[3]=y[3]
	veor	@y[5], @y[5], @t[2]
	veor	@t[2], @t[2], @y[2]		@ t[2]=y[2]
	veor	@t[3], @t[3], @t[7]
	veor	@t[5], @t[5], @y[5]		@ t[5]=y[5]
	veor	@XMM[5], @t[5], @t[6]
	veor	@XMM[6], @t[6], @y[6]		@ t[6]=y[6]
	veor	@XMM[2], @t[2], @t[6]
	veor	@XMM[7], @t[7], @y[7]		@ t[7]=y[7]

	vmov	@XMM[0], @t[0]
	vmov	@XMM[1], @t[1]
	@ vmov	@XMM[2], @t[2]
	vmov	@XMM[3], @t[3]
	vmov	@XMM[4], @t[4]
	@ vmov	@XMM[5], @t[5]
	@ vmov	@XMM[6], @t[6]
	@ vmov	@XMM[7], @t[7]
___
}

sub swapmove {
my ($a,$b,$n,$mask,$t)=@_;
$code.=<<___;
	vshr.u64	$t, $b, #$n
	veor		$t, $t, $a
	vand		$t, $t, $mask
	veor		$a, $a, $t
	vshl.u64	$t, $t, #$n
	veor		$b, $b, $t
___
}
sub swapmove2x {
my ($a0,$b0,$a1,$b1,$n,$mask,$t0,$t1)=@_;
$code.=<<___;
	vshr.u64	$t0, $b0, #$n
	 vshr.u64	$t1, $b1, #$n
	veor		$t0, $t0, $a0
	 veor		$t1, $t1, $a1
	vand		$t0, $t0, $mask
	 vand		$t1, $t1, $mask
	veor		$a0, $a0, $t0
	vshl.u64	$t0, $t0, #$n
	 veor		$a1, $a1, $t1
	 vshl.u64	$t1, $t1, #$n
	veor		$b0, $b0, $t0
	 veor		$b1, $b1, $t1
___
}

sub bitslice {
my @x=reverse(@_[0..7]);
my ($t0,$t1,$t2,$t3)=@_[8..11];
$code.=<<___;
	vmov.i8	$t0,#0x55			@ compose .LBS0
	vmov.i8	$t1,#0x33			@ compose .LBS1
___
	&swapmove2x(@x[0,1,2,3],1,$t0,$t2,$t3);
	&swapmove2x(@x[4,5,6,7],1,$t0,$t2,$t3);
$code.=<<___;
	vmov.i8	$t0,#0x0f			@ compose .LBS2
___
	&swapmove2x(@x[0,2,1,3],2,$t1,$t2,$t3);
	&swapmove2x(@x[4,6,5,7],2,$t1,$t2,$t3);

	&swapmove2x(@x[0,4,1,5],4,$t0,$t2,$t3);
	&swapmove2x(@x[2,6,3,7],4,$t0,$t2,$t3);
}

$code.=<<___;
.text
.code	32
.fpu	neon

.type	_bsaes_decrypt8,%function
.align	4
_bsaes_decrypt8:
	sub	$const,pc,#8			@ _bsaes_decrypt8
	vldmia	$key!, {@XMM[9]}		@ round 0 key
	add	$const,$const,#.LM0ISR-_bsaes_decrypt8

	vldmia	$const!, {@XMM[8]}		@ .LM0ISR
	veor	@XMM[10], @XMM[0], @XMM[9]	@ xor with round0 key
	veor	@XMM[11], @XMM[1], @XMM[9]
	 vtbl.8	`&Dlo(@XMM[0])`, {@XMM[10]}, `&Dlo(@XMM[8])`
	 vtbl.8	`&Dhi(@XMM[0])`, {@XMM[10]}, `&Dhi(@XMM[8])`
	veor	@XMM[12], @XMM[2], @XMM[9]
	 vtbl.8	`&Dlo(@XMM[1])`, {@XMM[11]}, `&Dlo(@XMM[8])`
	 vtbl.8	`&Dhi(@XMM[1])`, {@XMM[11]}, `&Dhi(@XMM[8])`
	veor	@XMM[13], @XMM[3], @XMM[9]
	 vtbl.8	`&Dlo(@XMM[2])`, {@XMM[12]}, `&Dlo(@XMM[8])`
	 vtbl.8	`&Dhi(@XMM[2])`, {@XMM[12]}, `&Dhi(@XMM[8])`
	veor	@XMM[14], @XMM[4], @XMM[9]
	 vtbl.8	`&Dlo(@XMM[3])`, {@XMM[13]}, `&Dlo(@XMM[8])`
	 vtbl.8	`&Dhi(@XMM[3])`, {@XMM[13]}, `&Dhi(@XMM[8])`
	veor	@XMM[15], @XMM[5], @XMM[9]
	 vtbl.8	`&Dlo(@XMM[4])`, {@XMM[14]}, `&Dlo(@XMM[8])`
	 vtbl.8	`&Dhi(@XMM[4])`, {@XMM[14]}, `&Dhi(@XMM[8])`
	veor	@XMM[10], @XMM[6], @XMM[9]
	 vtbl.8	`&Dlo(@XMM[5])`, {@XMM[15]}, `&Dlo(@XMM[8])`
	 vtbl.8	`&Dhi(@XMM[5])`, {@XMM[15]}, `&Dhi(@XMM[8])`
	veor	@XMM[11], @XMM[7], @XMM[9]
	 vtbl.8	`&Dlo(@XMM[6])`, {@XMM[10]}, `&Dlo(@XMM[8])`
	 vtbl.8	`&Dhi(@XMM[6])`, {@XMM[10]}, `&Dhi(@XMM[8])`
	 vtbl.8	`&Dlo(@XMM[7])`, {@XMM[11]}, `&Dlo(@XMM[8])`
	 vtbl.8	`&Dhi(@XMM[7])`, {@XMM[11]}, `&Dhi(@XMM[8])`
___
	&bitslice	(@XMM[0..7, 8..11]);
$code.=<<___;
	sub	$rounds,$rounds,#1
	b	.Ldec_sbox
.align	4
.Ldec_loop:
___
	&ShiftRows	(@XMM[0..7, 8..12]);
$code.=".Ldec_sbox:\n";
	&InvSbox	(@XMM[0..7, 8..15]);
$code.=<<___;
	subs	$rounds,$rounds,#1
	bcc	.Ldec_done
___
	&InvMixColumns	(@XMM[0,1,6,4,2,7,3,5, 8..15]);
$code.=<<___;
	vldmia	$const, {@XMM[12]}		@ .LISR
	addeq	$const,$const,#0x10
	bne	.Ldec_loop
	vldmia	$const, {@XMM[12]}		@ .LISRM0
	b	.Ldec_loop
.align	4
.Ldec_done:
___
	&bitslice	(@XMM[0,1,6,4,2,7,3,5, 8..11]);
$code.=<<___;
	vldmia	$key, {@XMM[8]}			@ last round key
	veor	@XMM[6], @XMM[6], @XMM[8]
	veor	@XMM[4], @XMM[4], @XMM[8]
	veor	@XMM[2], @XMM[2], @XMM[8]
	veor	@XMM[7], @XMM[7], @XMM[8]
	veor	@XMM[3], @XMM[3], @XMM[8]
	veor	@XMM[5], @XMM[5], @XMM[8]
	veor	@XMM[0], @XMM[0], @XMM[8]
	veor	@XMM[1], @XMM[1], @XMM[8]
	bx	lr
.size	_bsaes_decrypt8,.-_bsaes_decrypt8

.type	_bsaes_const,%object
.align	6
_bsaes_const:
.LM0ISR:	@ InvShiftRows constants
	.quad	0x0a0e0206070b0f03, 0x0004080c0d010509
.LISR:
	.quad	0x0504070602010003, 0x0f0e0d0c080b0a09
.LISRM0:
	.quad	0x01040b0e0205080f, 0x0306090c00070a0d
.LM0SR:		@ ShiftRows constants
	.quad	0x0a0e02060f03070b, 0x0004080c05090d01
.LSR:
	.quad	0x0504070600030201, 0x0f0e0d0c0a09080b
.LSRM0:
	.quad	0x0304090e00050a0f, 0x01060b0c0207080d
.LM0:
	.quad	0x02060a0e03070b0f, 0x0004080c0105090d
.asciz	"Bit-sliced AES for NEON, CRYPTOGAMS by <appro\@openssl.org>"
.align	6
.size	_bsaes_const,.-_bsaes_const

.type	_bsaes_encrypt8,%function
.align	4
_bsaes_encrypt8:
	sub	$const,pc,#8			@ _bsaes_encrypt8
	vldmia	$key!, {@XMM[9]}		@ round 0 key
	sub	$const,$const,#_bsaes_encrypt8-.LM0SR

	vldmia	$const!, {@XMM[8]}		@ .LM0SR
	veor	@XMM[10], @XMM[0], @XMM[9]	@ xor with round0 key
	veor	@XMM[11], @XMM[1], @XMM[9]
	 vtbl.8	`&Dlo(@XMM[0])`, {@XMM[10]}, `&Dlo(@XMM[8])`
	 vtbl.8	`&Dhi(@XMM[0])`, {@XMM[10]}, `&Dhi(@XMM[8])`
	veor	@XMM[12], @XMM[2], @XMM[9]
	 vtbl.8	`&Dlo(@XMM[1])`, {@XMM[11]}, `&Dlo(@XMM[8])`
	 vtbl.8	`&Dhi(@XMM[1])`, {@XMM[11]}, `&Dhi(@XMM[8])`
	veor	@XMM[13], @XMM[3], @XMM[9]
	 vtbl.8	`&Dlo(@XMM[2])`, {@XMM[12]}, `&Dlo(@XMM[8])`
	 vtbl.8	`&Dhi(@XMM[2])`, {@XMM[12]}, `&Dhi(@XMM[8])`
	veor	@XMM[14], @XMM[4], @XMM[9]
	 vtbl.8	`&Dlo(@XMM[3])`, {@XMM[13]}, `&Dlo(@XMM[8])`
	 vtbl.8	`&Dhi(@XMM[3])`, {@XMM[13]}, `&Dhi(@XMM[8])`
	veor	@XMM[15], @XMM[5], @XMM[9]
	 vtbl.8	`&Dlo(@XMM[4])`, {@XMM[14]}, `&Dlo(@XMM[8])`
	 vtbl.8	`&Dhi(@XMM[4])`, {@XMM[14]}, `&Dhi(@XMM[8])`
	veor	@XMM[10], @XMM[6], @XMM[9]
	 vtbl.8	`&Dlo(@XMM[5])`, {@XMM[15]}, `&Dlo(@XMM[8])`
	 vtbl.8	`&Dhi(@XMM[5])`, {@XMM[15]}, `&Dhi(@XMM[8])`
	veor	@XMM[11], @XMM[7], @XMM[9]
	 vtbl.8	`&Dlo(@XMM[6])`, {@XMM[10]}, `&Dlo(@XMM[8])`
	 vtbl.8	`&Dhi(@XMM[6])`, {@XMM[10]}, `&Dhi(@XMM[8])`
	 vtbl.8	`&Dlo(@XMM[7])`, {@XMM[11]}, `&Dlo(@XMM[8])`
	 vtbl.8	`&Dhi(@XMM[7])`, {@XMM[11]}, `&Dhi(@XMM[8])`
_bsaes_encrypt8_bitslice:
___
	&bitslice	(@XMM[0..7, 8..11]);
$code.=<<___;
	sub	$rounds,$rounds,#1
	b	.Lenc_sbox
.align	4
.Lenc_loop:
___
	&ShiftRows	(@XMM[0..7, 8..12]);
$code.=".Lenc_sbox:\n";
	&Sbox		(@XMM[0..7, 8..15]);
$code.=<<___;
	subs	$rounds,$rounds,#1
	bcc	.Lenc_done
___
	&MixColumns	(@XMM[0,1,4,6,3,7,2,5, 8..15]);
$code.=<<___;
	vldmia	$const, {@XMM[12]}		@ .LSR
	addeq	$const,$const,#0x10
	bne	.Lenc_loop
	vldmia	$const, {@XMM[12]}		@ .LSRM0
	b	.Lenc_loop
.align	4
.Lenc_done:
___
	# output in lsb > [t0, t1, t4, t6, t3, t7, t2, t5] < msb
	&bitslice	(@XMM[0,1,4,6,3,7,2,5, 8..11]);
$code.=<<___;
	vldmia	$key, {@XMM[8]}			@ last round key
	veor	@XMM[4], @XMM[4], @XMM[8]
	veor	@XMM[6], @XMM[6], @XMM[8]
	veor	@XMM[3], @XMM[3], @XMM[8]
	veor	@XMM[7], @XMM[7], @XMM[8]
	veor	@XMM[2], @XMM[2], @XMM[8]
	veor	@XMM[5], @XMM[5], @XMM[8]
	veor	@XMM[0], @XMM[0], @XMM[8]
	veor	@XMM[1], @XMM[1], @XMM[8]
	bx	lr
.size	_bsaes_encrypt8,.-_bsaes_encrypt8
___
}
{
my ($out,$inp,$rounds,$const)=("r12","r4","r5","r6");

sub bitslice_key {
my @x=reverse(@_[0..7]);
my ($bs0,$bs1,$bs2,$t2,$t3)=@_[8..12];

	&swapmove	(@x[0,1],1,$bs0,$t2,$t3);
$code.=<<___;
	@ &swapmove(@x[2,3],1,$t0,$t2,$t3);
	vmov	@x[2], @x[0]
	vmov	@x[3], @x[1]
___
	#&swapmove2x(@x[4,5,6,7],1,$t0,$t2,$t3);

	&swapmove2x	(@x[0,2,1,3],2,$bs1,$t2,$t3);
$code.=<<___;
	@ &swapmove2x(@x[4,6,5,7],2,$t1,$t2,$t3);
	vmov	@x[4], @x[0]
	vmov	@x[6], @x[2]
	vmov	@x[5], @x[1]
	vmov	@x[7], @x[3]
___
	&swapmove2x	(@x[0,4,1,5],4,$bs2,$t2,$t3);
	&swapmove2x	(@x[2,6,3,7],4,$bs2,$t2,$t3);
}

$code.=<<___;
.type	_bsaes_key_convert,%function
.align	4
_bsaes_key_convert:
	sub	$const,pc,#8			@ _bsaes_key_convert
	vld1.8	{@XMM[7]},  [$inp]!		@ load round 0 key
	sub	$const,$const,#_bsaes_key_convert-.LM0
	vld1.8	{@XMM[15]}, [$inp]!		@ load round 1 key

	vmov.i8	@XMM[8], #0x55			@ compose .LBS0
	vmov.i8	@XMM[9], #0x33			@ compose .LBS1
	vmov.i8	@XMM[10],#0x0f			@ compose .LBS2
	vldmia	$const, {@XMM[13]}		@ .LM0

#ifdef __ARMEL__
	vrev32.8	@XMM[7],  @XMM[7]
	vrev32.8	@XMM[15], @XMM[15]
#endif
	sub	$rounds,$rounds,#1
	vstmia	$out!, {@XMM[7]}		@ save round 0 key
	b	.Lkey_loop

.align	4
.Lkey_loop:
	vtbl.8	`&Dlo(@XMM[6])`,{@XMM[15]},`&Dlo(@XMM[13])`
	vtbl.8	`&Dhi(@XMM[6])`,{@XMM[15]},`&Dhi(@XMM[13])`
	vmov	@XMM[7], @XMM[6]
___
	&bitslice_key	(@XMM[0..7, 8..12]);
$code.=<<___;
	vld1.8	{@XMM[15]}, [$inp]!		@ load next round key
	vmvn	@XMM[5], @XMM[5]		@ "pnot"
	vmvn	@XMM[6], @XMM[6]
	vmvn	@XMM[0], @XMM[0]
	vmvn	@XMM[1], @XMM[1]
#ifdef __ARMEL__
	vrev32.8	@XMM[15], @XMM[15]
#endif
	subs	$rounds,$rounds,#1
	vstmia	$out!,{@XMM[0]-@XMM[7]}		@ write bit-sliced round key
	bne	.Lkey_loop

	vmov.i8	@XMM[7],#0x63			@ compose .L63
	@ don't save last round key
	bx	lr
.size	_bsaes_key_convert,.-_bsaes_key_convert
___
}

if (1) {		# following four functions are unsupported interface
			# used for benchmarking...
$code.=<<___;
.globl	bsaes_enc_key_convert
.type	bsaes_enc_key_convert,%function
.align	4
bsaes_enc_key_convert:
	stmdb	sp!,{r4-r6,lr}
	vstmdb	sp!,{d8-d15}		@ ABI specification says so

	ldr	r5,[$inp,#240]			@ pass rounds
	mov	r4,$inp				@ pass key
	mov	r12,$out			@ pass key schedule
	bl	_bsaes_key_convert
	veor	@XMM[7],@XMM[7],@XMM[15]	@ fix up last round key
	vstmia	r12, {@XMM[7]}			@ save last round key

	vldmia	sp!,{d8-d15}
	ldmia	sp!,{r4-r6,pc}
.size	bsaes_enc_key_convert,.-bsaes_enc_key_convert

.globl	bsaes_encrypt_128
.type	bsaes_encrypt_128,%function
.align	4
bsaes_encrypt_128:
	stmdb	sp!,{r4-r6,lr}
	vstmdb	sp!,{d8-d15}		@ ABI specification says so
.Lenc128_loop:
	vld1.8	{@XMM[0]}, [$inp]!		@ load input
	vld1.8	{@XMM[1]}, [$inp]!
	vld1.8	{@XMM[2]}, [$inp]!
	vld1.8	{@XMM[3]}, [$inp]!
	vld1.8	{@XMM[4]}, [$inp]!
	vld1.8	{@XMM[5]}, [$inp]!
	mov	r4,$key				@ pass the key
	vld1.8	{@XMM[6]}, [$inp]!
	mov	r5,#10				@ pass rounds
	vld1.8	{@XMM[7]}, [$inp]!

	bl	_bsaes_encrypt8

	vst1.8	{@XMM[0]}, [$out]!		@ write output
	vst1.8	{@XMM[1]}, [$out]!
	vst1.8	{@XMM[4]}, [$out]!
	vst1.8	{@XMM[6]}, [$out]!
	vst1.8	{@XMM[3]}, [$out]!
	vst1.8	{@XMM[7]}, [$out]!
	vst1.8	{@XMM[2]}, [$out]!
	subs	$len,$len,#0x80
	vst1.8	{@XMM[5]}, [$out]!
	bhi	.Lenc128_loop

	vldmia	sp!,{d8-d15}
	ldmia	sp!,{r4-r6,pc}
.size	bsaes_encrypt_128,.-bsaes_encrypt_128

.globl	bsaes_dec_key_convert
.type	bsaes_dec_key_convert,%function
.align	4
bsaes_dec_key_convert:
	stmdb	sp!,{r4-r6,lr}
	vstmdb	sp!,{d8-d15}		@ ABI specification says so

	ldr	r5,[$inp,#240]			@ pass rounds
	mov	r4,$inp				@ pass key
	mov	r12,$out			@ pass key schedule
	bl	_bsaes_key_convert
	vldmia	$out, {@XMM[6]}
	vstmia	r12,  {@XMM[15]}		@ save last round key
	veor	@XMM[7], @XMM[7], @XMM[6]	@ fix up round 0 key
	vstmia	$out, {@XMM[7]}

	vldmia	sp!,{d8-d15}
	ldmia	sp!,{r4-r6,pc}
.size	bsaes_dec_key_convert,.-bsaes_dec_key_convert

.globl	bsaes_decrypt_128
.type	bsaes_decrypt_128,%function
.align	4
bsaes_decrypt_128:
	stmdb	sp!,{r4-r6,lr}
	vstmdb	sp!,{d8-d15}		@ ABI specification says so
.Ldec128_loop:
	vld1.8	{@XMM[0]}, [$inp]!		@ load input
	vld1.8	{@XMM[1]}, [$inp]!
	vld1.8	{@XMM[2]}, [$inp]!
	vld1.8	{@XMM[3]}, [$inp]!
	vld1.8	{@XMM[4]}, [$inp]!
	vld1.8	{@XMM[5]}, [$inp]!
	mov	r4,$key				@ pass the key
	vld1.8	{@XMM[6]}, [$inp]!
	mov	r5,#10				@ pass rounds
	vld1.8	{@XMM[7]}, [$inp]!

	bl	_bsaes_decrypt8

	vst1.8	{@XMM[0]}, [$out]!		@ write output
	vst1.8	{@XMM[1]}, [$out]!
	vst1.8	{@XMM[6]}, [$out]!
	vst1.8	{@XMM[4]}, [$out]!
	vst1.8	{@XMM[2]}, [$out]!
	vst1.8	{@XMM[7]}, [$out]!
	vst1.8	{@XMM[3]}, [$out]!
	subs	$len,$len,#0x80
	vst1.8	{@XMM[5]}, [$out]!
	bhi	.Ldec128_loop

	vldmia	sp!,{d8-d15}
	ldmia	sp!,{r4-r6,pc}
.size	bsaes_decrypt_128,.-bsaes_decrypt_128
___
}

$code =~ s/\`([^\`]*)\`/eval($1)/gem;

print $code;

close STDOUT;

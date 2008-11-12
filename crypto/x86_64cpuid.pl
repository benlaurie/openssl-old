#!/usr/bin/env perl

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
open STDOUT,"| $^X ${dir}perlasm/x86_64-xlate.pl $flavour $output";

if ($win64)	{ $arg1="%rcx"; $arg2="%rdx"; }
else		{ $arg1="%rdi"; $arg2="%rsi"; }
print<<___;
.extern		OPENSSL_cpuid_setup
.section	.init
	call	OPENSSL_cpuid_setup

.text

.globl	OPENSSL_atomic_add
.type	OPENSSL_atomic_add,\@abi-omnipotent
.align	16
OPENSSL_atomic_add:
	movl	($arg1),%eax
.Lspin:	leaq	($arg2,%rax),%r8
	.byte	0xf0		# lock
	cmpxchgl	%r8d,($arg1)
	jne	.Lspin
	movl	%r8d,%eax
	.byte	0x48,0x98	# cltq/cdqe
	ret
.size	OPENSSL_atomic_add,.-OPENSSL_atomic_add

.globl	OPENSSL_rdtsc
.type	OPENSSL_rdtsc,\@abi-omnipotent
.align	16
OPENSSL_rdtsc:
	rdtsc
	shl	\$32,%rdx
	or	%rdx,%rax
	ret
.size	OPENSSL_rdtsc,.-OPENSSL_rdtsc

.globl	OPENSSL_ia32_cpuid
.type	OPENSSL_ia32_cpuid,\@abi-omnipotent
.align	16
OPENSSL_ia32_cpuid:
	mov	%rbx,%r8

	xor	%eax,%eax
	cpuid
	xor	%eax,%eax
	cmp	\$0x756e6547,%ebx	# "Genu"
	setne	%al
	mov	%eax,%r9d
	cmp	\$0x49656e69,%edx	# "ineI"
	setne	%al
	or	%eax,%r9d
	cmp	\$0x6c65746e,%ecx	# "ntel"
	setne	%al
	or	%eax,%r9d

	mov	\$1,%eax
	cpuid
	cmp	\$0,%r9d
	jne	.Lnotintel
	or	\$0x00100000,%edx	# use reserved 20th bit to engage RC4_CHAR
	and	\$15,%ah
	cmp	\$15,%ah		# examine Family ID
	je	.Lnotintel
	or	\$0x40000000,%edx	# use reserved bit to skip unrolled loop
.Lnotintel:
	bt	\$28,%edx		# test hyper-threading bit
	jnc	.Ldone
	shr	\$16,%ebx
	cmp	\$1,%bl			# see if cache is shared
	ja	.Ldone
	and	\$0xefffffff,%edx	# ~(1<<28)
.Ldone:
	shl	\$32,%rcx
	mov	%edx,%eax
	mov	%r8,%rbx
	or	%rcx,%rax
	ret
.size	OPENSSL_ia32_cpuid,.-OPENSSL_ia32_cpuid

.globl  OPENSSL_cleanse
.type   OPENSSL_cleanse,\@abi-omnipotent
.align  16
OPENSSL_cleanse:
	xor	%rax,%rax
	cmp	\$15,$arg2
	jae	.Lot
.Little:
	mov	%al,($arg1)
	sub	\$1,$arg2
	lea	1($arg1),$arg1
	jnz	.Little
	ret
.align	16
.Lot:
	test	\$7,$arg1
	jz	.Laligned
	mov	%al,($arg1)
	lea	-1($arg2),$arg2
	lea	1($arg1),$arg1
	jmp	.Lot
.Laligned:
	mov	%rax,($arg1)
	lea	-8($arg2),$arg2
	test	\$-8,$arg2
	lea	8($arg1),$arg1
	jnz	.Laligned
	cmp	\$0,$arg2
	jne	.Little
	ret
.size	OPENSSL_cleanse,.-OPENSSL_cleanse
___

print<<___ if (!$win64);
.globl	OPENSSL_wipe_cpu
.type	OPENSSL_wipe_cpu,\@abi-omnipotent
.align	16
OPENSSL_wipe_cpu:
	pxor	%xmm0,%xmm0
	pxor	%xmm1,%xmm1
	pxor	%xmm2,%xmm2
	pxor	%xmm3,%xmm3
	pxor	%xmm4,%xmm4
	pxor	%xmm5,%xmm5
	pxor	%xmm6,%xmm6
	pxor	%xmm7,%xmm7
	pxor	%xmm8,%xmm8
	pxor	%xmm9,%xmm9
	pxor	%xmm10,%xmm10
	pxor	%xmm11,%xmm11
	pxor	%xmm12,%xmm12
	pxor	%xmm13,%xmm13
	pxor	%xmm14,%xmm14
	pxor	%xmm15,%xmm15
	xorq	%rcx,%rcx
	xorq	%rdx,%rdx
	xorq	%rsi,%rsi
	xorq	%rdi,%rdi
	xorq	%r8,%r8
	xorq	%r9,%r9
	xorq	%r10,%r10
	xorq	%r11,%r11
	leaq	8(%rsp),%rax
	ret
.size	OPENSSL_wipe_cpu,.-OPENSSL_wipe_cpu
___
print<<___ if ($win64);
.globl	OPENSSL_wipe_cpu
.type	OPENSSL_wipe_cpu,\@abi-omnipotent
.align	16
OPENSSL_wipe_cpu:
	pxor	%xmm0,%xmm0
	pxor	%xmm1,%xmm1
	pxor	%xmm2,%xmm2
	pxor	%xmm3,%xmm3
	pxor	%xmm4,%xmm4
	pxor	%xmm5,%xmm5
	xorq	%rcx,%rcx
	xorq	%rdx,%rdx
	xorq	%r8,%r8
	xorq	%r9,%r9
	xorq	%r10,%r10
	xorq	%r11,%r11
	leaq	8(%rsp),%rax
	ret
.size	OPENSSL_wipe_cpu,.-OPENSSL_wipe_cpu
___

close STDOUT;	# flush

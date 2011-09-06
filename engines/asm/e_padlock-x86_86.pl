#!/usr/bin/env perl

# ====================================================================
# Written by Andy Polyakov <appro@openssl.org> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# September 2011
#
# Assembler helpers for Padlock engine.

$flavour = shift;
$output  = shift;
if ($flavour =~ /\./) { $output = $flavour; undef $flavour; }

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../crypto/perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open STDOUT,"| $^X $xlate $flavour $output";

$code=".text\n";

$PADLOCK_CHUNK=512;	# Must be a power of 2 larger than 16

$ctx="%rdx";
$out="%rdi";
$inp="%rsi";
$len="%rcx";
$chunk="%rbx";

($arg1,$arg2,$arg3,$arg4)=$win64?("%rcx","%rdx","%r8", "%r9") : # Win64 order
                                 ("%rdi","%rsi","%rdx","%rcx"); # Unix order

$code.=<<___;
.globl	padlock_capability
.type	padlock_capability,\@abi-omnipotent
.align	16
padlock_capability:
	mov	%rbx,%r8
	xor	%eax,%eax
	cpuid
	xor	%eax,%eax
	cmp	\$`"0x".unpack("H*",'tneC')`,%ebx
	jne	.Lnoluck
	cmp	\$`"0x".unpack("H*",'Hrua')`,%edx
	jne	.Lnoluck
	cmp	\$`"0x".unpack("H*",'slua')`,%ecx
	jne	.Lnoluck
	mov	\$0xC0000000,%eax
	cpuid
	mov	%eax,%edx
	xor	%eax,%eax
	cmp	\$0xC0000001,%edx
	jb	.Lnoluck
	mov	\$0xC0000001,%eax
	cpuid
	mov	%edx,%eax
	and	\$0xffffffef,%eax
	or	\$0x10,%eax		# set Nano bit#4
.Lnoluck:
	mov	%r8,%rbx
	ret
.size	padlock_capability,.-padlock_capability

.globl	padlock_key_bswap
.type	padlock_key_bswap,\@abi-omnipotent,0
.align	16
padlock_key_bswap:
	mov	240($arg1),%edx
.Lbswap_loop:
	mov	($arg1),%eax
	bswap	%eax
	mov	%eax,($arg1)
	lea	4($arg1),$arg1
	sub	\$1,%edx
	jnz	.Lbswap_loop
	ret
.size	padlock_key_bswap,.-padlock_key_bswap

.globl	padlock_verify_context
.type	padlock_verify_context,\@abi-omnipotent
.align	16
padlock_verify_context:
	mov	$arg1,$ctx
	pushf
	lea	.Lpadlock_saved_context(%rip),%rax
	call	_padlock_verify_ctx
	lea	8(%rsp),%rsp
	ret
.size	padlock_verify_context,.-padlock_verify_context

.type	_padlock_verify_ctx,\@abi-omnipotent
.align	16
_padlock_verify_ctx:
	mov	8(%rsp),%r8
	bt	\$30,%r8
	jnc	.Lverified
	cmp	(%rax),$ctx
	je	.Lverified
	pushf
	popf
.Lverified:
	mov	$ctx,(%rax)
	ret
.size	_padlock_verify_ctx,.-_padlock_verify_ctx

.globl	padlock_reload_key
.type	padlock_reload_key,\@abi-omnipotent
.align	16
padlock_reload_key:
	pushf
	popf
	ret
.size	padlock_reload_key,.-padlock_reload_key

.globl	padlock_aes_block
.type	padlock_aes_block,\@function,3
.align	16
padlock_aes_block:
	mov	%rbx,%r8
	mov	\$1,$len
	lea	32($ctx),%rbx		# key
	lea	16($ctx),$ctx		# control word
	.byte	0xf3,0x0f,0xa7,0xc8	# rep xcryptecb
	mov	%r8,%rbx
	ret
.size	padlock_aes_block,.-padlock_aes_block

.globl	padlock_xstore
.type	padlock_xstore,\@function,2
.align	16
padlock_xstore:
	mov	%esi,%edx
	.byte	0x0f,0xa7,0xc0		# xstore
	ret
.size	padlock_xstore,.-padlock_xstore

.globl	padlock_sha1_oneshot
.type	padlock_sha1_oneshot,\@function,3
.align	16
padlock_sha1_oneshot:
	xor	%rax,%rax
	mov	%rdx,%rcx
	.byte	0xf3,0x0f,0xa6,0xc8	# rep xsha1
	ret
.size	padlock_sha1_oneshot,.-padlock_sha1_oneshot

.globl	padlock_sha1
.type	padlock_sha1,\@function,3
.align	16
padlock_sha1:
	mov	\$-1,%rax
	mov	%rdx,%rcx
	.byte	0xf3,0x0f,0xa6,0xc8	# rep xsha1
	ret
.size	padlock_sha1,.-padlock_sha1

.globl	padlock_sha256_oneshot
.type	padlock_sha256_oneshot,\@function,3
.align	16
padlock_sha256_oneshot:
	xor	%rax,%rax
	mov	%rdx,%rcx
	.byte	0xf3,0x0f,0xa6,0xd0	# rep xsha256
	ret
.size	padlock_sha256_oneshot,.-padlock_sha256_oneshot

.globl	padlock_sha256
.type	padlock_sha256,\@function,3
.align	16
padlock_sha256:
	mov	\$-1,%rax
	mov	%rdx,%rcx
	.byte	0xf3,0x0f,0xa6,0xd0	# rep xsha256
	ret
.size	padlock_sha256,.-padlock_sha256
___

sub generate_mode {
my ($mode,$opcode) = @_;
# int padlock_$mode_encrypt(void *out, const void *inp,
#		struct padlock_cipher_data *ctx, size_t len);
$code.=<<___;
.globl	padlock_${mode}_encrypt
.type	padlock_${mode}_encrypt,\@function,4
.align	16
padlock_${mode}_encrypt:
	push	%rbp
	push	%rbx

	xor	%eax,%eax
	test	\$15,$ctx
	jnz	.L${mode}_abort
	test	\$15,$len
	jnz	.L${mode}_abort
	lea	.Lpadlock_saved_context(%rip),%rax
	pushf
	cld
	call	_padlock_verify_ctx
	lea	16($ctx),$ctx		# control word
	xor	%eax,%eax
	xor	%ebx,%ebx
	test	\$`1<<5`,($ctx)		# align bit in control word
	test	\$0x0f,$out
	setz	%al			# !out_misaligned
	test	\$0x0f,$inp
	setz	%bl			# !inp_misaligned
	test	%ebx,%eax
	jnz	.L${mode}_aligned
	neg	%rax
	mov	\$$PADLOCK_CHUNK,$chunk
	not	%rax			# out_misaligned?-1:0
	lea	(%rsp),%rbp
	cmp	$chunk,$len
	cmovc	$len,$chunk		# chunk=len>PADLOCK_CHUNK?PADLOCK_CHUNK:len
	and	$chunk,%rax		# out_misaligned?chunk:0
	mov	$len,$chunk
	neg	%rax
	and	\$$PADLOCK_CHUNK-1,$chunk	# chunk%=PADLOCK_CHUNK
	lea	(%rax,%rbp),%rsp
	jmp	.L${mode}_loop
.align	16
.L${mode}_loop:
	mov	$out,%r8		# save parameters
	mov	$inp,%r9
	mov	$len,%r10
	mov	$chunk,$len
	mov	$chunk,%r11
	test	\$0x0f,$out		# out_misaligned
	cmovnz	%rsp,$out
	test	\$0x0f,$inp		# inp_misaligned
	jz	.L${mode}_inp_aligned
	shr	\$3,$len
	.byte	0xf3,0x48,0xa5		# rep movsq
	sub	$chunk,$out
	mov	$chunk,$len
	mov	$out,$inp
.L${mode}_inp_aligned:
	lea	-16($ctx),%rax		# ivp
	lea	16($ctx),%rbx		# key
	shr	\$4,$len
	.byte	0xf3,0x0f,0xa7,$opcode	# rep xcrypt*
___
$code.=<<___				if ($mode !~ /ecb|ctr/);
	movdqa	(%rax),%xmm0
	movdqa	%xmm0,-16($ctx)		# copy [or refresh] iv
___
$code.=<<___;
	mov	%r8,$out		# restore paramters
	mov	%r11,$chunk
	test	\$0x0f,$out
	jz	.L${mode}_out_aligned
	mov	$chunk,$len
	shr	\$3,$len
	lea	(%rsp),$inp
	.byte	0xf3,0x48,0xa5		# rep movsq
	sub	$chunk,$out
.L${mode}_out_aligned:
	mov	%r9,$inp
	mov	%r10,$len
	add	$chunk,$out
	add	$chunk,$inp
	sub	$chunk,$len
	mov	\$$PADLOCK_CHUNK,$chunk
	jnz	.L${mode}_loop

	test	\$0x0f,$out
	jz	.L${mode}_done

	mov	%rbp,$len
	mov	%rsp,$out
	sub	%rsp,$len
	xor	%rax,%rax
	shr	\$3,$len
	.byte	0xf3,0x48,0xab		# rep stosq
.L${mode}_done:
	lea	(%rbp),%rsp
	jmp	.L${mode}_exit

.align	16
.L${mode}_aligned:
	lea	-16($ctx),%rax		# ivp
	lea	16($ctx),%rbx		# key
	shr	\$4,$len		# len/=AES_BLOCK_SIZE
	.byte	0xf3,0x0f,0xa7,$opcode	# rep xcrypt*
___
$code.=<<___				if ($mode !~ /ecb|ctr/);
	movdqa	(%rax),%xmm0
	movdqa	%xmm0,-16($ctx)		# copy [or refresh] iv
___
$code.=<<___;
.L${mode}_exit:
	mov	\$1,%eax
	lea	8(%rsp),%rsp
.L${mode}_abort:
	pop	%rbx
	pop	%rbp
	ret
.size	padlock_${mode}_encrypt,.-padlock_${mode}_encrypt
___
}

&generate_mode("ecb",0xc8);
&generate_mode("cbc",0xd0);
&generate_mode("cfb",0xe0);
&generate_mode("ofb",0xe8);
&generate_mode("ctr16",0xd8);

$code.=<<___;
.asciz	"VIA Padlock x86_64 module, CRYPTOGAMS by <appro\@openssl.org>"
.align	16
.data
.align	8
.Lpadlock_saved_context:
	.quad	0
___
$code =~ s/\`([^\`]*)\`/eval($1)/gem;

print $code;

close STDOUT;

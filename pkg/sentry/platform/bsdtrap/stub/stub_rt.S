/*
 * Copyright 2026 The gVisor Authors.
 * SPDX-License-Identifier: Apache-2.0
 *
 * bsdtrap stub runtime: gsb ELF brand note, syscall gate, entry point.
 */
#include <osreldate.h>

	.section .note.gsb,"a",@note
	.p2align 2
	.long	4, 4, 1
	.asciz	"GSB"
	.p2align 2
	.long	__FreeBSD_version

	.text
/* long sc(long nr, a1..a6): -errno on failure. */
	.globl	sc
sc:
	movq	%rdi, %rax
	movq	%rsi, %rdi
	movq	%rdx, %rsi
	movq	%rcx, %rdx
	movq	%r8, %r10
	movq	%r9, %r8
	movq	8(%rsp), %r9
	syscall
	jb	1f
	ret
1:	negq	%rax
	ret

	.globl	_start
_start:
	andq	$-16, %rsp		/* argc/argv block is in %rdi */
	call	stub_main
	ud2

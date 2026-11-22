// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build freebsd

#include "textflag.h"

// FreeBSD/amd64: errors are signalled with CF=1 and a positive errno in AX.

TEXT ·RawSyscall6(SB),NOSPLIT,$0-72
	MOVQ a1+8(FP), DI
	MOVQ a2+16(FP), SI
	MOVQ a3+24(FP), DX
	MOVQ a4+32(FP), R10
	MOVQ a5+40(FP), R8
	MOVQ a6+48(FP), R9
	MOVQ trap+0(FP), AX
	SYSCALL
	JCC ok6
	MOVQ $-1, r1+56(FP)
	MOVQ AX, errno+64(FP)
	RET
ok6:
	MOVQ AX, r1+56(FP)
	MOVQ $0, errno+64(FP)
	RET

TEXT ·RawSyscall(SB),NOSPLIT,$0-48
	MOVQ a1+8(FP), DI
	MOVQ a2+16(FP), SI
	MOVQ a3+24(FP), DX
	MOVQ $0, R10
	MOVQ $0, R8
	MOVQ $0, R9
	MOVQ trap+0(FP), AX
	SYSCALL
	JCC ok3
	MOVQ $-1, r1+32(FP)
	MOVQ AX, errno+40(FP)
	RET
ok3:
	MOVQ AX, r1+32(FP)
	MOVQ $0, errno+40(FP)
	RET

TEXT ·RawSyscallErrno6(SB),NOSPLIT,$0-64
	MOVQ a1+8(FP), DI
	MOVQ a2+16(FP), SI
	MOVQ a3+24(FP), DX
	MOVQ a4+32(FP), R10
	MOVQ a5+40(FP), R8
	MOVQ a6+48(FP), R9
	MOVQ trap+0(FP), AX
	SYSCALL
	JCC oke6
	MOVQ AX, ret+56(FP)
	RET
oke6:
	MOVQ $0, ret+56(FP)
	RET

TEXT ·RawSyscallErrno(SB),NOSPLIT,$0-40
	MOVQ a1+8(FP), DI
	MOVQ a2+16(FP), SI
	MOVQ a3+24(FP), DX
	MOVQ $0, R10
	MOVQ $0, R8
	MOVQ $0, R9
	MOVQ trap+0(FP), AX
	SYSCALL
	JCC oke3
	MOVQ AX, ret+32(FP)
	RET
oke3:
	MOVQ $0, ret+32(FP)
	RET

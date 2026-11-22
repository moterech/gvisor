/*
 * Copyright 2026 The gVisor Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Shared-memory protocol between the bsdtrap platform (Go, in the Sentry)
 * and its stub process. Must match pkg/sentry/platform/bsdtrap/abi.go.
 *
 * Stub virtual memory (all fixed, above the app's MaxUserAddress):
 *   STUB_TEXT_BASE   stub image (linked here)
 *   CTL_BASE         shared control area: struct ctl + MAX_THREADS slots
 *   STACK_BASE + i*STACK_SIZE   thread i stack
 *   ALT_BASE   + i*ALT_SIZE     thread i signal (alternate) stack; the
 *                               handler derives i from its stack pointer
 */
#ifndef BSDTRAP_ABI_H
#define BSDTRAP_ABI_H

#define STUB_TEXT_BASE  0x7f0000000000UL
#define APP_MAX_ADDR    0x7f0000000000UL
#define CTL_BASE        0x7f1000000000UL
#define STACK_BASE      0x7f2000000000UL
#define ALT_BASE        0x7f3000000000UL
#define STACK_SIZE      (64 * 1024)
#define ALT_SIZE        (64 * 1024)
#define MAX_THREADS     512

#define CTL_FD          3   /* inherited: shared control area (shm) */
#define SOCK_FD         4   /* inherited: AF_UNIX socket for fd passing */

#define CTL_SIZE        4096
#define SLOT_SIZE       16384
#define CTL_AREA_SIZE   (CTL_SIZE + MAX_THREADS * SLOT_SIZE)

#define NR_ENTER        9999  /* unlisted syscall: first SIGSYS of a thread */

/* struct ctl (offset 0): Sentry -> control thread requests. */
#define CTL_REQ_SEQ      0    /* u32 */
#define CTL_RESP_SEQ     4    /* u32 */
#define CTL_STUB_SLEEP   8    /* u32 */
#define CTL_SENTRY_SLEEP 12   /* u32 */
#define CTL_OP           16   /* u32 */
#define CTL_ARGS         24   /* u64[6] */
#define CTL_RET          72   /* i64: result or -errno */

#define OP_MMAP       1  /* addr, len, prot, flags, stubfd, off */
#define OP_MUNMAP     2  /* addr, len */
#define OP_MPROTECT   3  /* addr, len, prot */
#define OP_RECVFD     4  /* -> stub fd number */
#define OP_CLOSE      5  /* stubfd */
#define OP_NEWTHREAD  6  /* slot index */
#define OP_EXIT       7

/* struct slot (CTL_BASE + CTL_SIZE + i*SLOT_SIZE): one app thread. */
#define SLOT_CMD_SEQ      0    /* u32, Sentry bumps to send cmd */
#define SLOT_EV_SEQ       4    /* u32, stub bumps on each event */
#define SLOT_STUB_SLEEP   8    /* u32 */
#define SLOT_SENTRY_SLEEP 12   /* u32 */
#define SLOT_CMD          16   /* u32 */
#define SLOT_EV_SIG       20   /* u32: host signal number of the event */
#define SLOT_TID          24   /* i64: host thread id (thr_new child_tid) */
#define SLOT_XFPU_LEN     32   /* u32 */
#define SLOT_SIGINFO      64   /* 80 bytes: FreeBSD siginfo_t */
#define SLOT_MCONTEXT     256  /* 800 bytes: FreeBSD mcontext_t */
#define SLOT_XFPU         1088 /* extended FP state (mc_xfpustate) */
#define XFPU_MAX          (SLOT_SIZE - SLOT_XFPU)

#define CMD_RUN   1
#define CMD_EXIT  2

#endif

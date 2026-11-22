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
 * bsdtrap stub: hosts one application address space under gsb.ko.
 *
 * The main thread is the control thread. It performs address-space
 * operations the Sentry requests through the shared control area: mmap,
 * munmap, mprotect, fd passing, thread creation.
 *
 * Each app thread starts in thread_main(), immediately traps (NR_ENTER) and
 * from then on lives in handler(). For every event (redirected syscall,
 * fault, interrupt) handler() publishes the raw FreeBSD mcontext/siginfo to
 * its slot, waits for the Sentry's next command, loads the mcontext the
 * Sentry wrote and sigreturn()s into the app. The Sentry does all register
 * translation; this program only moves bytes.
 *
 * Freestanding: no libc, only the syscalls gsb.ko passes through.
 */
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/thr.h>
#include <sys/ucontext.h>
#include <sys/uio.h>
#include <sys/umtx.h>

#include "bsdtrap_abi.h"

long sc(long, long, long, long, long, long, long);
#define	SC(n, a, b, c, d, e, f)	sc((n), (long)(a), (long)(b), (long)(c), \
	(long)(d), (long)(e), (long)(f))

#define	U32(base, off)	((volatile unsigned int *)((char *)(base) + (off)))
#define	I64(base, off)	((volatile long *)((char *)(base) + (off)))
#define	PTR(base, off)	((void *)((char *)(base) + (off)))

#define	CTL		((char *)CTL_BASE)
#define	SLOT(i)		(CTL + CTL_SIZE + (long)(i) * SLOT_SIZE)
#define	SPIN		20000

void *memset(void *d, int c, size_t n)
{ unsigned char *p = d; while (n--) *p++ = (unsigned char)c; return d; }
void *memcpy(void *d, const void *s, size_t n)
{
	unsigned char *p = d;
	const unsigned char *q = s;

	/* Word copies: everything we move per event is 8-byte aligned. */
	if ((((unsigned long)p | (unsigned long)q) & 7) == 0) {
		for (; n >= 8; n -= 8, p += 8, q += 8)
			*(unsigned long *)p = *(const unsigned long *)q;
	}
	while (n--)
		*p++ = *q++;
	return d;
}

static __attribute__((noreturn)) void
die(int code)
{
	for (;;)
		SC(SYS_exit, code, 0, 0, 0, 0, 0);
}

static inline unsigned int
ld(volatile unsigned int *p)
{
	return __atomic_load_n(p, __ATOMIC_SEQ_CST);
}

/* Publish: bump *seq, wake the Sentry if it sleeps on it. */
static void
publish(volatile unsigned int *seq, volatile unsigned int *peer_sleeping)
{
	__atomic_add_fetch(seq, 1, __ATOMIC_SEQ_CST);
	if (ld(peer_sleeping))
		SC(SYS__umtx_op, seq, UMTX_OP_WAKE, 1, 0, 0, 0);
}

/* Wait until *seq != old: spin, then sleep on it. */
static void
await(volatile unsigned int *seq, unsigned int old, volatile unsigned int *sleeping)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000 };
	int i;

	for (i = 0; i < SPIN; i++) {
		if (ld(seq) != old)
			return;
		__asm__ volatile("pause");
	}
	for (;;) {
		__atomic_store_n(sleeping, 1, __ATOMIC_SEQ_CST);
		if (ld(seq) != old)
			break;
		/*
		 * Timed (10ms) so that a lost wakeup costs a delay, never a
		 * deadlock between stub and Sentry.
		 */
		SC(SYS__umtx_op, seq, UMTX_OP_WAIT_UINT, old,
		    sizeof(struct timespec), &ts, 0);
	}
	__atomic_store_n(sleeping, 0, __ATOMIC_SEQ_CST);
}

/* ---------------------------------------------------------- app threads */

static void
handler(int sig, siginfo_t *si, void *ctx)
{
	ucontext_t *uc = ctx;
	mcontext_t *mc = &uc->uc_mcontext;
	long here = (long)&uc;
	long i = (here - (long)ALT_BASE) / ALT_SIZE;
	char *s;
	unsigned int cmd_seq, len;

	if (here < (long)ALT_BASE || i >= MAX_THREADS)
		die(120);	/* not on a slot's altstack: cannot happen */
	s = SLOT(i);

	/* Publish the event. */
	cmd_seq = ld(U32(s, SLOT_CMD_SEQ));
	memcpy(PTR(s, SLOT_SIGINFO), si, sizeof(*si));
	memcpy(PTR(s, SLOT_MCONTEXT), mc, sizeof(*mc));
	len = 0;
	if ((mc->mc_flags & _MC_HASFPXSTATE) != 0 && mc->mc_xfpustate != 0 &&
	    mc->mc_xfpustate_len <= XFPU_MAX) {
		len = (unsigned int)mc->mc_xfpustate_len;
		memcpy(PTR(s, SLOT_XFPU), (void *)mc->mc_xfpustate, len);
	}
	*U32(s, SLOT_XFPU_LEN) = len;
	*U32(s, SLOT_EV_SIG) = (unsigned int)sig;
	publish(U32(s, SLOT_EV_SEQ), U32(s, SLOT_SENTRY_SLEEP));

	/* Wait for the next command. Signals stay blocked (sa_mask). */
	await(U32(s, SLOT_CMD_SEQ), cmd_seq, U32(s, SLOT_STUB_SLEEP));
	if (*U32(s, SLOT_CMD) != CMD_RUN) {
		/* The kernel stores 1 in the tid word once we are gone. */
		SC(SYS_thr_exit, I64(s, SLOT_TID), 0, 0, 0, 0, 0);
	}

	/* Load the context the Sentry prepared and enter the app. */
	memcpy(mc, PTR(s, SLOT_MCONTEXT), sizeof(*mc));
	len = *U32(s, SLOT_XFPU_LEN);
	if (len != 0 && len <= XFPU_MAX) {
		mc->mc_xfpustate = (long)PTR(s, SLOT_XFPU);
		mc->mc_xfpustate_len = len;
		mc->mc_flags |= _MC_HASFPXSTATE;
	} else {
		mc->mc_xfpustate = 0;
		mc->mc_xfpustate_len = 0;
		mc->mc_flags &= ~_MC_HASFPXSTATE;
	}
	memset(&uc->uc_sigmask, 0, sizeof(uc->uc_sigmask));
	SC(SYS_sigreturn, uc, 0, 0, 0, 0, 0);
	die(121);
}

static void
thread_main(void *arg)
{
	long i = (long)arg;
	stack_t ss = {
		.ss_sp = (void *)(ALT_BASE + i * ALT_SIZE),
		.ss_size = ALT_SIZE,
	};

	if (SC(SYS_sigaltstack, &ss, 0, 0, 0, 0, 0) != 0)
		die(122);
	/* First event: gives the Sentry a valid context template. */
	SC(NR_ENTER, 0, 0, 0, 0, 0, 0);
	die(123);
}

/* ------------------------------------------------------- control thread */

static long
map_fixed(unsigned long addr, unsigned long len)
{
	return SC(SYS_mmap, addr, len, PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_PRIVATE | MAP_FIXED | MAP_EXCL, -1, 0);
}

static long
new_thread(long i)
{
	struct thr_param tp;
	unsigned long stk = STACK_BASE + i * STACK_SIZE;
	long r;

	if (i < 0 || i >= MAX_THREADS)
		return -22;	/* EINVAL */
	/* Reuse stacks of a slot whose thread exited. */
	r = map_fixed(stk, STACK_SIZE);
	if (r < 0 && r != -12 /* ENOMEM: already mapped */)
		return r;
	r = map_fixed(ALT_BASE + i * ALT_SIZE, ALT_SIZE);
	if (r < 0 && r != -12)
		return r;

	memset(&tp, 0, sizeof(tp));
	tp.start_func = thread_main;
	tp.arg = (void *)i;
	tp.stack_base = (char *)stk;
	tp.stack_size = STACK_SIZE;
	tp.child_tid = (long *)I64(SLOT(i), SLOT_TID);
	tp.parent_tid = (long *)I64(SLOT(i), SLOT_TID);
	return SC(SYS_thr_new, &tp, sizeof(tp), 0, 0, 0, 0);
}

static long
recv_fd(void)
{
	char byte;
	struct iovec iov = { .iov_base = &byte, .iov_len = 1 };
	union {
		struct cmsghdr h;
		char buf[CMSG_SPACE(sizeof(int))];
	} cm;
	struct msghdr msg;
	struct cmsghdr *c;
	long r;

	memset(&msg, 0, sizeof(msg));
	memset(&cm, 0, sizeof(cm));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cm.buf;
	msg.msg_controllen = sizeof(cm.buf);
	r = SC(SYS_recvmsg, SOCK_FD, &msg, MSG_CMSG_CLOEXEC, 0, 0, 0);
	if (r < 0)
		return r;
	c = CMSG_FIRSTHDR(&msg);
	if (c == 0 || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS)
		return -5;	/* EIO */
	return *(int *)CMSG_DATA(c);
}

static void
install(int sig)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = handler;
	sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
	memset(&sa.sa_mask, 0xff, sizeof(sa.sa_mask));
	if (SC(SYS_sigaction, sig, &sa, 0, 0, 0, 0) != 0)
		die(124);
}

void
stub_main(long *sp)
{
	unsigned int seen;
	long r, *a;
	(void)sp;

	if (SC(SYS_mmap, CTL_BASE, CTL_AREA_SIZE, PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_FIXED | MAP_EXCL, CTL_FD, 0) != (long)CTL_BASE)
		die(125);
	SC(SYS_close, CTL_FD, 0, 0, 0, 0, 0);

	install(SIGSYS);
	install(SIGSEGV);
	install(SIGBUS);
	install(SIGILL);
	install(SIGFPE);
	install(SIGTRAP);
	install(SIGUSR1);	/* platform interrupt */

	a = (long *)PTR(CTL, CTL_ARGS);
	seen = ld(U32(CTL, CTL_REQ_SEQ));
	for (;;) {
		await(U32(CTL, CTL_REQ_SEQ), seen, U32(CTL, CTL_STUB_SLEEP));
		seen++;
		switch (*U32(CTL, CTL_OP)) {
		case OP_MMAP:
			r = SC(SYS_mmap, a[0], a[1], a[2], a[3], a[4], a[5]);
			break;
		case OP_MUNMAP:
			r = SC(SYS_munmap, a[0], a[1], 0, 0, 0, 0);
			break;
		case OP_MPROTECT:
			r = SC(SYS_mprotect, a[0], a[1], a[2], 0, 0, 0);
			break;
		case OP_RECVFD:
			r = recv_fd();
			break;
		case OP_CLOSE:
			r = SC(SYS_close, a[0], 0, 0, 0, 0, 0);
			break;
		case OP_NEWTHREAD:
			r = new_thread(a[0]);
			break;
		case OP_EXIT:
			die(0);
		default:
			r = -22;
		}
		*I64(CTL, CTL_RET) = r;
		publish(U32(CTL, CTL_RESP_SEQ), U32(CTL, CTL_SENTRY_SLEEP));
	}
}

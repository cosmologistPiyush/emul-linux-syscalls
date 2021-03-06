/*	$NetBSD: linux_pipe.c,v 1.69 2021/09/23 06:56:27 ryo Exp $	*/

/*-
 * Copyright (c) 1995, 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Frank van der Linden and Eric Haszlakiewicz.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: linux_pipe.c,v 1.69 2021/09/23 06:56:27 ryo Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/fcntl.h>
#include <sys/filedesc.h>

#include <sys/sched.h>
#include <sys/syscallargs.h>

#include <compat/linux/common/linux_types.h>
#include <compat/linux/common/linux_mmap.h>
#include <compat/linux/common/linux_signal.h>
#include <compat/linux/common/linux_ipc.h>
#include <compat/linux/common/linux_sem.h>
#include <compat/linux/common/linux_fcntl.h>

#include <compat/linux/linux_syscallargs.h>

/* Used on: aarch64, arm, i386, m68k, ppc, amd64 */
/* Not used on: alpha, mips, sparc, sparc64 */
/* Alpha, mips, sparc and sparc64 pass one of the fds in a register */

#if !defined(__aarch64__)
int
linux_sys_pipe(struct lwp *l, const struct linux_sys_pipe_args *uap,
    register_t *retval)
{
	/* {
		syscallarg(int *) pfds;
	} */
	int fd[2], error;

	if ((error = pipe1(l, fd, 0)))
		return error;

	if ((error = copyout(fd, SCARG(uap, pfds), sizeof(fd))) != 0)
		return error;
	retval[0] = 0;
	return 0;
}
#endif

int
linux_sys_pipe2(struct lwp *l, const struct linux_sys_pipe2_args *uap,
    register_t *retval)
{
	/* {
		syscallarg(int *) pfds;
		syscallarg(int) flags;
	} */
	int fd[2], error, flags;

	flags = linux_to_bsd_ioflags(SCARG(uap, flags));
	if ((flags & ~(O_CLOEXEC|O_NONBLOCK)) != 0)
		return EINVAL;

	if ((error = pipe1(l, fd, flags)))
		return error;

	if ((error = copyout(fd, SCARG(uap, pfds), sizeof(fd))) != 0)
		return error;
	retval[0] = 0;
	return 0;
}

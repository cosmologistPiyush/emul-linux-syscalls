/*	$NetBSD: tty_60.c,v 1.11 2021/07/21 06:35:44 skrll Exp $	*/

/*-
 * Copyright (c) 2012 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Alan Barrett
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
__KERNEL_RCSID(0, "$NetBSD: tty_60.c,v 1.11 2021/07/21 06:35:44 skrll Exp $");

#if defined(_KERNEL_OPT)
#include "opt_compat_netbsd.h"
#endif

#include <sys/param.h>
#include <sys/types.h>

#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/compat_stub.h>
#include <sys/kmem.h>

#include <sys/tty.h>

#include <compat/common/compat_mod.h>
#include <compat/sys/ttycom.h>

/* convert struct ptmget to struct compat_60_ptmget */
static int
ptmget_to_ptmget60(struct ptmget *pg, struct compat_60_ptmget *pg60)
{
	memset(pg60, 0, sizeof(*pg60));
	pg60->cfd = pg->cfd;
	pg60->sfd = pg->sfd;
	strlcpy(pg60->cn, pg->cn, sizeof(pg60->cn));
	strlcpy(pg60->sn, pg->sn, sizeof(pg60->sn));
	if (strlen(pg->cn) >= sizeof(pg60->cn)
	    || strlen(pg->sn) >= sizeof(pg60->sn))
		return E2BIG;
	return 0;
}

/* Helper for compat ioctls that use struct compat_60_ptmget. */
static int
compat_60_ptmget_ioctl(dev_t dev, u_long cmd, void *data, int flag,
	struct lwp *l)
{
	int ret;
	u_long newcmd;
	struct ptmget *pg;
	const struct cdevsw *cd = cdevsw_lookup(dev);

	if (cd == NULL || cd->d_ioctl == NULL)
		return ENXIO;

	switch (cmd) {
	case COMPAT_60_TIOCPTMGET:  newcmd = TIOCPTMGET; break;
	case COMPAT_60_TIOCPTSNAME: newcmd = TIOCPTSNAME; break;
	default: return ENOTTY;
	}

	pg = kmem_alloc(sizeof(*pg), KM_SLEEP);

	ret = (cd->d_ioctl)(dev, newcmd, pg, flag, l);
	if (ret != 0)
		goto out;

	ret = ptmget_to_ptmget60(pg, data);

out:
	kmem_free(pg, sizeof(*pg));
	return ret;
}

/*
 * COMPAT_60 versions of ttioctl and ptmioctl.
 */
int
compat_60_ttioctl(struct tty *tp, u_long cmd, void *data, int flag,
	struct lwp *l)
{

	switch (cmd) {
	case COMPAT_60_TIOCPTMGET:
	case COMPAT_60_TIOCPTSNAME:
		return compat_60_ptmget_ioctl(tp->t_dev, cmd, data, flag, l);
	default:
		return EPASSTHROUGH;
	}
}

int
compat_60_ptmioctl(dev_t dev, u_long cmd, void *data, int flag,
    struct lwp *l)
{

	switch (cmd) {
	case COMPAT_60_TIOCPTMGET:
		return compat_60_ptmget_ioctl(dev, cmd, data, flag, l);
	default:
		return EPASSTHROUGH;
	}
}

void
kern_tty_60_init(void)
{

	MODULE_HOOK_SET(tty_ttioctl_60_hook, compat_60_ttioctl);
	MODULE_HOOK_SET(tty_ptmioctl_60_hook, compat_60_ptmioctl);
}

void
kern_tty_60_fini(void)
{
	MODULE_HOOK_UNSET(tty_ttioctl_60_hook);
	MODULE_HOOK_UNSET(tty_ptmioctl_60_hook);
}

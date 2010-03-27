/*	$NetBSD: fifo_vnops.c,v 1.67 2010/03/27 02:33:11 pooka Exp $	*/

/*-
 * Copyright (c) 2008 The NetBSD Foundation, Inc.
 * All rights reserved.
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

/*
 * Copyright (c) 1990, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)fifo_vnops.c	8.10 (Berkeley) 5/27/95
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: fifo_vnops.c,v 1.67 2010/03/27 02:33:11 pooka Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/time.h>
#include <sys/namei.h>
#include <sys/vnode.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/socketvar.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <sys/event.h>
#include <sys/condvar.h>

#include <miscfs/fifofs/fifo.h>
#include <miscfs/genfs/genfs.h>

/*
 * This structure is associated with the FIFO vnode and stores
 * the state associated with the FIFO.
 */
struct fifoinfo {
	struct socket	*fi_readsock;
	struct socket	*fi_writesock;
	kcondvar_t	fi_rcv;
	int		fi_readers;
	kcondvar_t	fi_wcv;
	int		fi_writers;
};

int (**fifo_vnodeop_p)(void *);
const struct vnodeopv_entry_desc fifo_vnodeop_entries[] = {
	{ &vop_default_desc, vn_default_error },
	{ &vop_lookup_desc, fifo_lookup },		/* lookup */
	{ &vop_create_desc, fifo_create },		/* create */
	{ &vop_mknod_desc, fifo_mknod },		/* mknod */
	{ &vop_open_desc, fifo_open },			/* open */
	{ &vop_close_desc, fifo_close },		/* close */
	{ &vop_access_desc, fifo_access },		/* access */
	{ &vop_getattr_desc, fifo_getattr },		/* getattr */
	{ &vop_setattr_desc, fifo_setattr },		/* setattr */
	{ &vop_read_desc, fifo_read },			/* read */
	{ &vop_write_desc, fifo_write },		/* write */
	{ &vop_ioctl_desc, fifo_ioctl },		/* ioctl */
	{ &vop_poll_desc, fifo_poll },			/* poll */
	{ &vop_kqfilter_desc, fifo_kqfilter },		/* kqfilter */
	{ &vop_revoke_desc, fifo_revoke },		/* revoke */
	{ &vop_mmap_desc, fifo_mmap },			/* mmap */
	{ &vop_fsync_desc, fifo_fsync },		/* fsync */
	{ &vop_seek_desc, fifo_seek },			/* seek */
	{ &vop_remove_desc, fifo_remove },		/* remove */
	{ &vop_link_desc, fifo_link },			/* link */
	{ &vop_rename_desc, fifo_rename },		/* rename */
	{ &vop_mkdir_desc, fifo_mkdir },		/* mkdir */
	{ &vop_rmdir_desc, fifo_rmdir },		/* rmdir */
	{ &vop_symlink_desc, fifo_symlink },		/* symlink */
	{ &vop_readdir_desc, fifo_readdir },		/* readdir */
	{ &vop_readlink_desc, fifo_readlink },		/* readlink */
	{ &vop_abortop_desc, fifo_abortop },		/* abortop */
	{ &vop_inactive_desc, fifo_inactive },		/* inactive */
	{ &vop_reclaim_desc, fifo_reclaim },		/* reclaim */
	{ &vop_lock_desc, fifo_lock },			/* lock */
	{ &vop_unlock_desc, fifo_unlock },		/* unlock */
	{ &vop_bmap_desc, fifo_bmap },			/* bmap */
	{ &vop_strategy_desc, fifo_strategy },		/* strategy */
	{ &vop_print_desc, fifo_print },		/* print */
	{ &vop_islocked_desc, fifo_islocked },		/* islocked */
	{ &vop_pathconf_desc, fifo_pathconf },		/* pathconf */
	{ &vop_advlock_desc, fifo_advlock },		/* advlock */
	{ &vop_bwrite_desc, fifo_bwrite },		/* bwrite */
	{ &vop_putpages_desc, fifo_putpages }, 		/* putpages */
	{ (struct vnodeop_desc*)NULL, (int(*)(void *))NULL }
};
const struct vnodeopv_desc fifo_vnodeop_opv_desc =
	{ &fifo_vnodeop_p, fifo_vnodeop_entries };

/*
 * Trivial lookup routine that always fails.
 */
/* ARGSUSED */
int
fifo_lookup(void *v)
{
	struct vop_lookup_args /* {
		struct vnode		*a_dvp;
		struct vnode		**a_vpp;
		struct componentname	*a_cnp;
	} */ *ap = v;

	*ap->a_vpp = NULL;
	return (ENOTDIR);
}

/*
 * Open called to set up a new instance of a fifo or
 * to find an active instance of a fifo.
 */
/* ARGSUSED */
int
fifo_open(void *v)
{
	struct vop_open_args /* {
		struct vnode	*a_vp;
		int		a_mode;
		kauth_cred_t	a_cred;
	} */ *ap = v;
	struct lwp	*l = curlwp;
	struct vnode	*vp;
	struct fifoinfo	*fip;
	struct proc	*p;
	struct socket	*rso, *wso;
	int		error;

	vp = ap->a_vp;
	p = l->l_proc;

	if ((fip = vp->v_fifoinfo) == NULL) {
		fip = kmem_alloc(sizeof(*fip), KM_SLEEP);
		vp->v_fifoinfo = fip;
		error = socreate(AF_LOCAL, &rso, SOCK_STREAM, 0, l, NULL);
		if (error != 0) {
			kmem_free(fip, sizeof(*fip));
			vp->v_fifoinfo = NULL;
			return (error);
		}
		fip->fi_readsock = rso;
		error = socreate(AF_LOCAL, &wso, SOCK_STREAM, 0, l, rso);
		if (error != 0) {
			(void)soclose(rso);
			kmem_free(fip, sizeof(*fip));
			vp->v_fifoinfo = NULL;
			return (error);
		}
		fip->fi_writesock = wso;
		solock(wso);
		if ((error = unp_connect2(wso, rso, PRU_CONNECT2)) != 0) {
			sounlock(wso);
			(void)soclose(wso);
			(void)soclose(rso);
			kmem_free(fip, sizeof(*fip));
			vp->v_fifoinfo = NULL;
			return (error);
		}
		fip->fi_readers = 0;
		fip->fi_writers = 0;
		wso->so_state |= SS_CANTRCVMORE;
		rso->so_state |= SS_CANTSENDMORE;
		cv_init(&fip->fi_rcv, "fiford");
		cv_init(&fip->fi_wcv, "fifowr");
	} else {
		wso = fip->fi_writesock;
		rso = fip->fi_readsock;
		solock(wso);
	}

	if (ap->a_mode & FREAD) {
		if (fip->fi_readers++ == 0) {
			wso->so_state &= ~SS_CANTSENDMORE;
			cv_broadcast(&fip->fi_wcv);
		}
	}
	if (ap->a_mode & FWRITE) {
		if (fip->fi_writers++ == 0) {
			rso->so_state &= ~SS_CANTRCVMORE;
			cv_broadcast(&fip->fi_rcv);
		}
	}
	if (ap->a_mode & FREAD) {
		if (ap->a_mode & O_NONBLOCK) {
		} else {
			while (!soreadable(rso) && fip->fi_writers == 0) {
				VOP_UNLOCK(vp, 0);
				error = cv_wait_sig(&fip->fi_rcv,
				    wso->so_lock);
				sounlock(wso);
				vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
				if (error)
					goto bad;
				solock(wso);
			}
		}
	}
	if (ap->a_mode & FWRITE) {
		if (ap->a_mode & O_NONBLOCK) {
			if (fip->fi_readers == 0) {
				error = ENXIO;
				sounlock(wso);
				goto bad;
			}
		} else {
			while (fip->fi_readers == 0) {
				VOP_UNLOCK(vp, 0);
				error = cv_wait_sig(&fip->fi_wcv,
				    wso->so_lock);
				sounlock(wso);
				vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
				if (error)
					goto bad;
				solock(wso);
			}
		}
	}
	sounlock(wso);
	return (0);
 bad:
	VOP_CLOSE(vp, ap->a_mode, ap->a_cred);
	return (error);
}

/*
 * Vnode op for read
 */
/* ARGSUSED */
int
fifo_read(void *v)
{
	struct vop_read_args /* {
		struct vnode	*a_vp;
		struct uio	*a_uio;
		int		a_ioflag;
		kauth_cred_t	a_cred;
	} */ *ap = v;
	struct uio	*uio;
	struct socket	*rso;
	int		error;
	size_t		startresid;

	uio = ap->a_uio;
	rso = ap->a_vp->v_fifoinfo->fi_readsock;
#ifdef DIAGNOSTIC
	if (uio->uio_rw != UIO_READ)
		panic("fifo_read mode");
#endif
	if (uio->uio_resid == 0)
		return (0);
	startresid = uio->uio_resid;
	VOP_UNLOCK(ap->a_vp, 0);
	if (ap->a_ioflag & IO_NDELAY) {
		/* XXX Bogus, affects other threads. */
		rso->so_nbio = 1;
	}
	error = (*rso->so_receive)(rso, NULL, uio, NULL, NULL, NULL);
	/*
	 * Clear EOF indication after first such return.
	 */
	if (uio->uio_resid == startresid)
		rso->so_state &= ~SS_CANTRCVMORE;
	if (ap->a_ioflag & IO_NDELAY) {
		rso->so_nbio = 0;
		if (error == EWOULDBLOCK &&
		    ap->a_vp->v_fifoinfo->fi_writers == 0)
			error = 0;
	}
	vn_lock(ap->a_vp, LK_EXCLUSIVE | LK_RETRY);
	return (error);
}

/*
 * Vnode op for write
 */
/* ARGSUSED */
int
fifo_write(void *v)
{
	struct vop_write_args /* {
		struct vnode	*a_vp;
		struct uio	*a_uio;
		int		a_ioflag;
		kauth_cred_t	a_cred;
	} */ *ap = v;
	struct socket	*wso;
	int		error;

	wso = ap->a_vp->v_fifoinfo->fi_writesock;
#ifdef DIAGNOSTIC
	if (ap->a_uio->uio_rw != UIO_WRITE)
		panic("fifo_write mode");
#endif
	VOP_UNLOCK(ap->a_vp, 0);
	if (ap->a_ioflag & IO_NDELAY) {
		/* XXX Bogus, affects other threads. */
		wso->so_nbio = 1;
	}
	error = (*wso->so_send)(wso, NULL, ap->a_uio, 0, NULL, 0, curlwp);
	if (ap->a_ioflag & IO_NDELAY)
		wso->so_nbio = 0;
	vn_lock(ap->a_vp, LK_EXCLUSIVE | LK_RETRY);
	return (error);
}

/*
 * Device ioctl operation.
 */
/* ARGSUSED */
int
fifo_ioctl(void *v)
{
	struct vop_ioctl_args /* {
		struct vnode	*a_vp;
		u_long		a_command;
		void		*a_data;
		int		a_fflag;
		kauth_cred_t	a_cred;
		struct lwp	*a_l;
	} */ *ap = v;
	struct file	filetmp;
	int		error;

	if (ap->a_command == FIONBIO)
		return (0);
	if (ap->a_fflag & FREAD) {
		filetmp.f_data = ap->a_vp->v_fifoinfo->fi_readsock;
		error = soo_ioctl(&filetmp, ap->a_command, ap->a_data);
		if (error)
			return (error);
	}
	if (ap->a_fflag & FWRITE) {
		filetmp.f_data = ap->a_vp->v_fifoinfo->fi_writesock;
		error = soo_ioctl(&filetmp, ap->a_command, ap->a_data);
		if (error)
			return (error);
	}
	return (0);
}

/* ARGSUSED */
int
fifo_poll(void *v)
{
	struct vop_poll_args /* {
		struct vnode	*a_vp;
		int		a_events;
		struct lwp	*a_l;
	} */ *ap = v;
	struct socket	*so;
	int		revents;

	revents = 0;
	if (ap->a_events & (POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND)) {
		so = ap->a_vp->v_fifoinfo->fi_readsock;
		if (so)
			revents |= sopoll(so, ap->a_events);
	}
	if (ap->a_events & (POLLOUT | POLLWRNORM | POLLWRBAND)) {
		so = ap->a_vp->v_fifoinfo->fi_writesock;
		if (so)
			revents |= sopoll(so, ap->a_events);
	}

	return (revents);
}

int
fifo_inactive(void *v)
{
	struct vop_inactive_args /* {
		struct vnode	*a_vp;
		struct lwp	*a_l;
	} */ *ap = v;

	VOP_UNLOCK(ap->a_vp, 0);
	return (0);
}

/*
 * This is a noop, simply returning what one has been given.
 */
int
fifo_bmap(void *v)
{
	struct vop_bmap_args /* {
		struct vnode	*a_vp;
		daddr_t		a_bn;
		struct vnode	**a_vpp;
		daddr_t		*a_bnp;
		int		*a_runp;
	} */ *ap = v;

	if (ap->a_vpp != NULL)
		*ap->a_vpp = ap->a_vp;
	if (ap->a_bnp != NULL)
		*ap->a_bnp = ap->a_bn;
	if (ap->a_runp != NULL)
		*ap->a_runp = 0;
	return (0);
}

/*
 * Device close routine
 */
/* ARGSUSED */
int
fifo_close(void *v)
{
	struct vop_close_args /* {
		struct vnode	*a_vp;
		int		a_fflag;
		kauth_cred_t	a_cred;
		struct lwp	*a_l;
	} */ *ap = v;
	struct vnode	*vp;
	struct fifoinfo	*fip;
	struct socket *wso, *rso;
	int isrevoke;

	vp = ap->a_vp;
	fip = vp->v_fifoinfo;
	isrevoke = (ap->a_fflag & (FREAD | FWRITE | FNONBLOCK)) == FNONBLOCK;
	wso = fip->fi_writesock;
	rso = fip->fi_readsock;
	solock(wso);
	if (isrevoke) {
		if (fip->fi_readers != 0) {
			fip->fi_readers = 0;
			socantsendmore(wso);
		}
		if (fip->fi_writers != 0) {
			fip->fi_writers = 0;
			socantrcvmore(rso);
		}
	} else {
		if ((ap->a_fflag & FREAD) && --fip->fi_readers == 0)
			socantsendmore(wso);
		if ((ap->a_fflag & FWRITE) && --fip->fi_writers == 0)
			socantrcvmore(rso);
	}
	if ((fip->fi_readers + fip->fi_writers) == 0) {
		sounlock(wso);
		(void) soclose(rso);
		(void) soclose(wso);
		cv_destroy(&fip->fi_rcv);
		cv_destroy(&fip->fi_wcv);
		kmem_free(fip, sizeof(*fip));
		vp->v_fifoinfo = NULL;
	} else
		sounlock(wso);
	return (0);
}

/*
 * Print out the contents of a fifo vnode.
 */
int
fifo_print(void *v)
{
	struct vop_print_args /* {
		struct vnode	*a_vp;
	} */ *ap = v;

	printf("tag VT_NON");
	fifo_printinfo(ap->a_vp);
	printf("\n");
	return 0;
}

/*
 * Print out internal contents of a fifo vnode.
 */
void
fifo_printinfo(struct vnode *vp)
{
	struct fifoinfo	*fip;

	if ((fip = vp->v_fifoinfo) != NULL) {
		printf(", fifo with %d readers and %d writers",
		    fip->fi_readers, fip->fi_writers);
	}
}

/*
 * Return POSIX pathconf information applicable to fifo's.
 */
int
fifo_pathconf(void *v)
{
	struct vop_pathconf_args /* {
		struct vnode	*a_vp;
		int		a_name;
		register_t	*a_retval;
	} */ *ap = v;

	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*ap->a_retval = LINK_MAX;
		return (0);
	case _PC_PIPE_BUF:
		*ap->a_retval = PIPE_BUF;
		return (0);
	case _PC_CHOWN_RESTRICTED:
		*ap->a_retval = 1;
		return (0);
	case _PC_SYNC_IO:
		*ap->a_retval = 1;
		return (0);
	default:
		return (EINVAL);
	}
	/* NOTREACHED */
}

static void
filt_fifordetach(struct knote *kn)
{
	struct socket *so;

	so = (struct socket *)kn->kn_hook;
	solock(so);
	SLIST_REMOVE(&so->so_rcv.sb_sel.sel_klist, kn, knote, kn_selnext);
	if (SLIST_EMPTY(&so->so_rcv.sb_sel.sel_klist))
		so->so_rcv.sb_flags &= ~SB_KNOTE;
	sounlock(so);
}

static int
filt_fiforead(struct knote *kn, long hint)
{
	struct socket *so;
	int rv;

	so = (struct socket *)kn->kn_hook;
	if (hint != NOTE_SUBMIT)
		solock(so);
	kn->kn_data = so->so_rcv.sb_cc;
	if (so->so_state & SS_CANTRCVMORE) {
		kn->kn_flags |= EV_EOF;
		rv = 1;
	} else {
		kn->kn_flags &= ~EV_EOF;
		rv = (kn->kn_data > 0);
	}
	if (hint != NOTE_SUBMIT)
		sounlock(so);
	return rv;
}

static void
filt_fifowdetach(struct knote *kn)
{
	struct socket *so;

	so = (struct socket *)kn->kn_hook;
	solock(so);
	SLIST_REMOVE(&so->so_snd.sb_sel.sel_klist, kn, knote, kn_selnext);
	if (SLIST_EMPTY(&so->so_snd.sb_sel.sel_klist))
		so->so_snd.sb_flags &= ~SB_KNOTE;
	sounlock(so);
}

static int
filt_fifowrite(struct knote *kn, long hint)
{
	struct socket *so;
	int rv;

	so = (struct socket *)kn->kn_hook;
	if (hint != NOTE_SUBMIT)
		solock(so);
	kn->kn_data = sbspace(&so->so_snd);
	if (so->so_state & SS_CANTSENDMORE) {
		kn->kn_flags |= EV_EOF;
		rv = 1;
	} else {
		kn->kn_flags &= ~EV_EOF;
		rv = (kn->kn_data >= so->so_snd.sb_lowat);
	}
	if (hint != NOTE_SUBMIT)
		sounlock(so);
	return rv;
}

static const struct filterops fiforead_filtops =
	{ 1, NULL, filt_fifordetach, filt_fiforead };
static const struct filterops fifowrite_filtops =
	{ 1, NULL, filt_fifowdetach, filt_fifowrite };

/* ARGSUSED */
int
fifo_kqfilter(void *v)
{
	struct vop_kqfilter_args /* {
		struct vnode *a_vp;
		struct knote *a_kn;
	} */ *ap = v;
	struct socket	*so;
	struct sockbuf	*sb;

	so = (struct socket *)ap->a_vp->v_fifoinfo->fi_readsock;
	switch (ap->a_kn->kn_filter) {
	case EVFILT_READ:
		ap->a_kn->kn_fop = &fiforead_filtops;
		sb = &so->so_rcv;
		break;
	case EVFILT_WRITE:
		ap->a_kn->kn_fop = &fifowrite_filtops;
		sb = &so->so_snd;
		break;
	default:
		return (EINVAL);
	}

	ap->a_kn->kn_hook = so;

	solock(so);
	SLIST_INSERT_HEAD(&sb->sb_sel.sel_klist, ap->a_kn, kn_selnext);
	sb->sb_flags |= SB_KNOTE;
	sounlock(so);

	return (0);
}

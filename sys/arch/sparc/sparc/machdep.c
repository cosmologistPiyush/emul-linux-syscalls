/*	$NetBSD: machdep.c,v 1.46 1995/06/26 22:41:23 pk Exp $ */

/*
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This software was developed by the Computer Systems Engineering group
 * at Lawrence Berkeley Laboratory under DARPA contract BG 91-66 and
 * contributed to Berkeley.
 *
 * All advertising materials mentioning features or use of this software
 * must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Lawrence Berkeley Laboratory.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
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
 *	@(#)machdep.c	8.6 (Berkeley) 1/14/94
 */

#include <sys/param.h>
#include <sys/signal.h>
#include <sys/signalvar.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/map.h>
#include <sys/buf.h>
#include <sys/device.h>
#include <sys/reboot.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/clist.h>
#include <sys/callout.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/mount.h>
#include <sys/msgbuf.h>
#include <sys/syscallargs.h>
#ifdef SYSVMSG
#include <sys/msg.h>
#endif
#ifdef SYSVSEM
#include <sys/sem.h>
#endif
#ifdef SYSVSHM
#include <sys/shm.h>
#endif
#include <sys/exec.h>
#include <sys/sysctl.h>

#include <machine/autoconf.h>
#include <machine/frame.h>
#include <machine/cpu.h>

#include <vm/vm_kern.h>
#include <vm/vm_page.h>

#include <sparc/sparc/asm.h>
#include <sparc/sparc/cache.h>
#include <sparc/sparc/vaddrs.h>

vm_map_t buffer_map;
extern vm_offset_t avail_end;

/*
 * Declare these as initialized data so we can patch them.
 */
int	nswbuf = 0;
#ifdef	NBUF
int	nbuf = NBUF;
#else
int	nbuf = 0;
#endif
#ifdef	BUFPAGES
int	bufpages = BUFPAGES;
#else
int	bufpages = 0;
#endif

int	physmem;

extern struct msgbuf msgbuf;
struct	msgbuf *msgbufp = &msgbuf;
int	msgbufmapped = 1;	/* message buffer is always mapped */

/*
 * safepri is a safe priority for sleep to set for a spin-wait
 * during autoconfiguration or after a panic.
 */
int   safepri = 0;

/*
 * dvmamap is used to manage DVMA memory. Note: this coincides with
 * the memory range in `phys_map' (which is mostly a place-holder).
 */
struct map *dvmamap;
vm_offset_t dvmabase;
static int ndvmamap;	/* # of entries in dvmamap */

caddr_t allocsys();

/*
 * Machine-dependent startup code
 */
void
cpu_startup()
{
	register unsigned i;
	register caddr_t v;
	register int sz;
	int base, residual;
#ifdef DEBUG
	extern int pmapdebug;
	int opmapdebug = pmapdebug;
#endif
	vm_offset_t minaddr, maxaddr;
	vm_size_t size;
	extern struct user *proc0paddr;

#ifdef DEBUG
	pmapdebug = 0;
#endif

	proc0.p_addr = proc0paddr;

	/*
	 * Good {morning,afternoon,evening,night}.
	 */
	printf(version);
	/*identifycpu();*/
#ifndef MACHINE_NONCONTIG
	physmem = btoc(avail_end);
#endif
	printf("real mem = %d\n", ctob(physmem));

	/*
	 * Find out how much space we need, allocate it,
	 * and then give everything true virtual addresses.
	 */
	sz = (int)allocsys((caddr_t)0);
	if ((v = (caddr_t)kmem_alloc(kernel_map, round_page(sz))) == 0)
		panic("startup: no room for tables");
	if (allocsys(v) - v != sz)
		panic("startup: table size inconsistency");

	/*
	 * Now allocate buffers proper.  They are different than the above
	 * in that they usually occupy more virtual memory than physical.
	 */
	size = MAXBSIZE * nbuf;
	buffer_map = kmem_suballoc(kernel_map, (vm_offset_t *)&buffers,
	    &maxaddr, size, TRUE);
	minaddr = (vm_offset_t)buffers;
	if (vm_map_find(buffer_map, vm_object_allocate(size), (vm_offset_t)0,
			&minaddr, size, FALSE) != KERN_SUCCESS)
		panic("startup: cannot allocate buffers");
	base = bufpages / nbuf;
	residual = bufpages % nbuf;
	if (base >= MAXBSIZE) {
		/* don't want to alloc more physical mem than needed */
		base = MAXBSIZE;
		residual = 0;
	}
	for (i = 0; i < nbuf; i++) {
		vm_size_t curbufsize;
		vm_offset_t curbuf;

		/*
		 * First <residual> buffers get (base+1) physical pages
		 * allocated for them.  The rest get (base) physical pages.
		 *
		 * The rest of each buffer occupies virtual space,
		 * but has no physical memory allocated for it.
		 */
		curbuf = (vm_offset_t)buffers + i * MAXBSIZE;
		curbufsize = CLBYTES * (i < residual ? base+1 : base);
		vm_map_pageable(buffer_map, curbuf, curbuf+curbufsize, FALSE);
		vm_map_simplify(buffer_map, curbuf);
	}

	/*
	 * Allocate a submap for exec arguments.  This map effectively
	 * limits the number of processes exec'ing at any time.
	 */
	exec_map = kmem_suballoc(kernel_map, &minaddr, &maxaddr,
	    16*NCARGS, TRUE);

	/*
	 * Allocate a map for physio.  Others use a submap of the kernel
	 * map, but we want one completely separate, even though it uses
	 * the same pmap.
	 */
	phys_map = vm_map_create(pmap_kernel(), DVMA_BASE, DVMA_END, 1);
	if (phys_map == NULL)
		panic("unable to create DVMA map");
	/*
	 * For now, allocate half of DVMA space for a (privately managed)
	 * pool of addresses for double mappings.
	 */
	dvmabase = kmem_alloc_wait(phys_map, (DVMA_END-DVMA_BASE)/2);
	rminit(dvmamap, btoc((DVMA_END-DVMA_BASE)/2),
		vtorc(dvmabase), "dvmamap", ndvmamap);

	/*
	 * Finally, allocate mbuf pool.  Since mclrefcnt is an off-size
	 * we use the more space efficient malloc in place of kmem_alloc.
	 */
	mclrefcnt = (char *)malloc(NMBCLUSTERS+CLBYTES/MCLBYTES,
				   M_MBUF, M_NOWAIT);
	bzero(mclrefcnt, NMBCLUSTERS+CLBYTES/MCLBYTES);
	mb_map = kmem_suballoc(kernel_map, (vm_offset_t *)&mbutl, &maxaddr,
			       VM_MBUF_SIZE, FALSE);
	/*
	 * Initialize callouts
	 */
	callfree = callout;
	for (i = 1; i < ncallout; i++)
		callout[i-1].c_next = &callout[i];
	callout[i-1].c_next = NULL;

#ifdef DEBUG
	pmapdebug = opmapdebug;
#endif
	printf("avail mem = %d\n", ptoa(cnt.v_free_count));
	printf("using %d buffers containing %d bytes of memory\n",
		nbuf, bufpages * CLBYTES);

	/*
	 * Set up buffers, so they can be used to read disk labels.
	 */
	bufinit();

	/*
	 * Configure the system.  The cpu code will turn on the cache.
	 */
	configure();

	/*
	 * fix message buffer mapping, note phys addr of msgbuf is 0
	 */

	pmap_enter(pmap_kernel(), MSGBUF_VA, 0x0, VM_PROT_READ|VM_PROT_WRITE, 1);
	if (cputyp == CPU_SUN4)
		msgbufp = (struct msgbuf *)(MSGBUF_VA + 4096);
	else
		msgbufp = (struct msgbuf *)MSGBUF_VA;
	pmap_redzone();
}

/*
 * Allocate space for system data structures.  We are given
 * a starting virtual address and we return a final virtual
 * address; along the way we set each data structure pointer.
 *
 * You call allocsys() with 0 to find out how much space we want,
 * allocate that much and fill it with zeroes, and then call
 * allocsys() again with the correct base virtual address.
 */
caddr_t
allocsys(v)
	register caddr_t v;
{

#define	valloc(name, type, num) \
	    v = (caddr_t)(((name) = (type *)v) + (num))
	valloc(callout, struct callout, ncallout);
	valloc(swapmap, struct map, nswapmap = maxproc * 2);
#ifdef SYSVSHM
	valloc(shmsegs, struct shmid_ds, shminfo.shmmni);
#endif
#ifdef SYSVSEM
	valloc(sema, struct semid_ds, seminfo.semmni);
	valloc(sem, struct sem, seminfo.semmns);
	/* This is pretty disgusting! */
	valloc(semu, int, (seminfo.semmnu * seminfo.semusz) / sizeof(int));
#endif
#ifdef SYSVMSG
	valloc(msgpool, char, msginfo.msgmax);
	valloc(msgmaps, struct msgmap, msginfo.msgseg);
	valloc(msghdrs, struct msg, msginfo.msgtql);
	valloc(msqids, struct msqid_ds, msginfo.msgmni);
#endif
	
	/*
	 * Determine how many buffers to allocate (enough to
	 * hold 5% of total physical memory, but at least 16).
	 * Allocate 1/2 as many swap buffer headers as file i/o buffers.
	 */
	if (bufpages == 0)
		bufpages = (physmem / 20) / CLSIZE;
	if (nbuf == 0) {
		nbuf = bufpages;
		if (nbuf < 16)
			nbuf = 16;
	}
	if (nswbuf == 0) {
		nswbuf = (nbuf / 2) &~ 1;	/* force even */
		if (nswbuf > 256)
			nswbuf = 256;		/* sanity */
	}
	valloc(swbuf, struct buf, nswbuf);
	valloc(buf, struct buf, nbuf);
	/*
	 * Allocate DVMA slots for 1/4 of the number of i/o buffers
	 * and one for each process too (PHYSIO).
	 */
	valloc(dvmamap, struct map, ndvmamap = maxproc + ((nbuf / 4) &~ 1));
	return (v);
}

/*
 * Set up registers on exec.
 *
 * XXX this entire mess must be fixed
 */
/* ARGSUSED */
void
setregs(p, pack, stack, retval)
	struct proc *p;
	struct exec_package *pack;
	u_long stack;
	register_t *retval;
{
	register struct trapframe *tf = p->p_md.md_tf;
	register struct fpstate *fs;
	register int psr;

	/*
	 * The syscall will ``return'' to npc or %g7 or %g2; set them all.
	 * Set the rest of the registers to 0 except for %o6 (stack pointer,
	 * built in exec()) and psr (retain CWP and PSR_S bits).
	 */
	psr = tf->tf_psr & (PSR_S | PSR_CWP);
	if ((fs = p->p_md.md_fpstate) != NULL) {
		/*
		 * We hold an FPU state.  If we own *the* FPU chip state
		 * we must get rid of it, and the only way to do that is
		 * to save it.  In any case, get rid of our FPU state.
		 */
		if (p == fpproc) {
			savefpstate(fs);
			fpproc = NULL;
		}
		free((void *)fs, M_SUBPROC);
		p->p_md.md_fpstate = NULL;
	}
	bzero((caddr_t)tf, sizeof *tf);
	tf->tf_psr = psr;
	tf->tf_pc = pack->ep_entry & ~3;
	tf->tf_npc = tf->tf_pc + 4;
	tf->tf_global[1] = (int)PS_STRINGS;
	tf->tf_global[2] = tf->tf_global[7] = tf->tf_npc;
	stack -= sizeof(struct rwindow);
	tf->tf_out[6] = stack;
	retval[1] = 0;
}

#ifdef DEBUG
int sigdebug = 0;
int sigpid = 0;
#define SDB_FOLLOW	0x01
#define SDB_KSTACK	0x02
#define SDB_FPSTATE	0x04
#endif

struct sigframe {
	int	sf_signo;		/* signal number */
	int	sf_code;		/* code */
#ifdef COMPAT_SUNOS
	struct	sigcontext *sf_scp;	/* points to user addr of sigcontext */
#else
	int	sf_xxx;			/* placeholder */
#endif
	int	sf_addr;		/* SunOS compat, always 0 for now */
	struct	sigcontext sf_sc;	/* actual sigcontext */
};

/*
 * machine dependent system variables.
 */
cpu_sysctl(name, namelen, oldp, oldlenp, newp, newlen, p)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	struct proc *p;
{

	/* all sysctl names are this level are terminal */
	if (namelen != 1)
		return (ENOTDIR);	/* overloaded */

	switch (name[0]) {
	default:
		return (EOPNOTSUPP);
	}
	/* NOTREACHED */
}

/*
 * Send an interrupt to process.
 */
void
sendsig(catcher, sig, mask, code)
	sig_t catcher;
	int sig, mask;
	u_long code;
{
	register struct proc *p = curproc;
	register struct sigacts *psp = p->p_sigacts;
	register struct sigframe *fp;
	register struct trapframe *tf;
	register int addr, oonstack, oldsp, newsp;
	struct sigframe sf;
	extern char sigcode[], esigcode[];
#define	szsigcode	(esigcode - sigcode)

	tf = p->p_md.md_tf;
	oldsp = tf->tf_out[6];
	oonstack = psp->ps_sigstk.ss_flags & SA_ONSTACK;
	/*
	 * Compute new user stack addresses, subtract off
	 * one signal frame, and align.
	 */
	if ((psp->ps_flags & SAS_ALTSTACK) && !oonstack &&
	    (psp->ps_sigonstack & sigmask(sig))) {
		fp = (struct sigframe *)(psp->ps_sigstk.ss_base +
					 psp->ps_sigstk.ss_size);
		psp->ps_sigstk.ss_flags |= SA_ONSTACK;
	} else
		fp = (struct sigframe *)oldsp;
	fp = (struct sigframe *)((int)(fp - 1) & ~7);

#ifdef DEBUG
	if ((sigdebug & SDB_KSTACK) && p->p_pid == sigpid)
		printf("sendsig: %s[%d] sig %d newusp %x scp %x\n",
		    p->p_comm, p->p_pid, sig, fp, &fp->sf_sc);
#endif
	/* 
	 * Now set up the signal frame.  We build it in kernel space
	 * and then copy it out.  We probably ought to just build it
	 * directly in user space....
	 */
	sf.sf_signo = sig;
	sf.sf_code = code;
#ifdef COMPAT_SUNOS
	sf.sf_scp = &fp->sf_sc;
#endif
	sf.sf_addr = 0;			/* XXX */

	/*
	 * Build the signal context to be used by sigreturn.
	 */
	sf.sf_sc.sc_onstack = oonstack;
	sf.sf_sc.sc_mask = mask;
	sf.sf_sc.sc_sp = oldsp;
	sf.sf_sc.sc_pc = tf->tf_pc;
	sf.sf_sc.sc_npc = tf->tf_npc;
	sf.sf_sc.sc_psr = tf->tf_psr;
	sf.sf_sc.sc_g1 = tf->tf_global[1];
	sf.sf_sc.sc_o0 = tf->tf_out[0];

	/*
	 * Put the stack in a consistent state before we whack away
	 * at it.  Note that write_user_windows may just dump the
	 * registers into the pcb; we need them in the process's memory.
	 * We also need to make sure that when we start the signal handler,
	 * its %i6 (%fp), which is loaded from the newly allocated stack area,
	 * joins seamlessly with the frame it was in when the signal occurred,
	 * so that the debugger and _longjmp code can back up through it.
	 */
	newsp = (int)fp - sizeof(struct rwindow);
	write_user_windows();
	if (rwindow_save(p) || copyout((caddr_t)&sf, (caddr_t)fp, sizeof sf) ||
	    suword(&((struct rwindow *)newsp)->rw_in[6], oldsp)) {
		/*
		 * Process has trashed its stack; give it an illegal
		 * instruction to halt it in its tracks.
		 */
#ifdef DEBUG
		if ((sigdebug & SDB_KSTACK) && p->p_pid == sigpid)
			printf("sendsig: window save or copyout error\n");
#endif
		sigexit(p, SIGILL);
		/* NOTREACHED */
	}
#ifdef DEBUG
	if (sigdebug & SDB_FOLLOW)
		printf("sendsig: %s[%d] sig %d scp %x\n",
		       p->p_comm, p->p_pid, sig, &fp->sf_sc);
#endif
	/*
	 * Arrange to continue execution at the code copied out in exec().
	 * It needs the function to call in %g1, and a new stack pointer.
	 */
#ifdef COMPAT_SUNOS
	if (psp->ps_usertramp & sigmask(sig)) {
		addr = (int)catcher;	/* user does his own trampolining */
	} else
#endif
	{
		addr = (int)PS_STRINGS - szsigcode;
		tf->tf_global[1] = (int)catcher;
	}
	tf->tf_pc = addr;
	tf->tf_npc = addr + 4;
	tf->tf_out[6] = newsp;
#ifdef DEBUG
	if ((sigdebug & SDB_KSTACK) && p->p_pid == sigpid)
		printf("sendsig: about to return to catcher\n");
#endif
}

/*
 * System call to cleanup state after a signal
 * has been taken.  Reset signal mask and
 * stack state from context left by sendsig (above),
 * and return to the given trap frame (if there is one).
 * Check carefully to make sure that the user has not
 * modified the state to gain improper privileges or to cause
 * a machine fault.
 */
/* ARGSUSED */
sigreturn(p, uap, retval)
	register struct proc *p;
	struct sigreturn_args /* {
		syscallarg(struct sigcontext *) sigcntxp;
	} */ *uap;
	register_t *retval;
{
	register struct sigcontext *scp;
	register struct trapframe *tf;

	/* First ensure consistent stack state (see sendsig). */
	write_user_windows();
	if (rwindow_save(p))
		sigexit(p, SIGILL);
#ifdef DEBUG
	if (sigdebug & SDB_FOLLOW)
		printf("sigreturn: %s[%d], sigcntxp %x\n",
		    p->p_comm, p->p_pid, SCARG(uap, sigcntxp));
#endif
	scp = SCARG(uap, sigcntxp);
	if ((int)scp & 3 || useracc((caddr_t)scp, sizeof *scp, B_WRITE) == 0)
		return (EINVAL);
	tf = p->p_md.md_tf;
	/*
	 * Only the icc bits in the psr are used, so it need not be
	 * verified.  pc and npc must be multiples of 4.  This is all
	 * that is required; if it holds, just do it.
	 */
	if (((scp->sc_pc | scp->sc_npc) & 3) != 0)
		return (EINVAL);
	/* take only psr ICC field */
	tf->tf_psr = (tf->tf_psr & ~PSR_ICC) | (scp->sc_psr & PSR_ICC);
	tf->tf_pc = scp->sc_pc;
	tf->tf_npc = scp->sc_npc;
	tf->tf_global[1] = scp->sc_g1;
	tf->tf_out[0] = scp->sc_o0;
	tf->tf_out[6] = scp->sc_sp;
	if (scp->sc_onstack & 1)
		p->p_sigacts->ps_sigstk.ss_flags |= SA_ONSTACK;
	else
		p->p_sigacts->ps_sigstk.ss_flags &= ~SA_ONSTACK;
	p->p_sigmask = scp->sc_mask & ~sigcantmask;
	return (EJUSTRETURN);
}

int	waittime = -1;

void
boot(howto)
	register int howto;
{
	int i;
	static char str[4];	/* room for "-sd\0" */
	extern volatile void romhalt(void);
	extern volatile void romboot(char *);

	fb_unblank();
	boothowto = howto;
	if ((howto & RB_NOSYNC) == 0 && waittime < 0) {
#if 1
		extern struct proc proc0;

		/* protect against curproc->p_stats.foo refs in sync()   XXX */
		if (curproc == NULL)
			curproc = &proc0;
#endif
		waittime = 0;
		vfs_shutdown();

		/*
		 * If we've been adjusting the clock, the todr
		 * will be out of synch; adjust it now.
		 */
		resettodr();
	}
	(void) splhigh();		/* ??? */
	if (howto & RB_HALT) {
		printf("halted\n\n");
		romhalt();
	}
	if (howto & RB_DUMP)
		dumpsys();
	printf("rebooting\n\n");
	i = 1;
	if (howto & RB_SINGLE)
		str[i++] = 's';
	if (howto & RB_KDB)
		str[i++] = 'd';
	if (i > 1) {
		str[0] = '-';
		str[i] = 0;
	} else
		str[0] = 0;
	romboot(str);
	/*NOTREACHED*/
}

u_long	dumpmag = 0x8fca0101;	/* magic number for savecore */
int	dumpsize = 0;		/* also for savecore */
long	dumplo = 0;

dumpconf()
{
	int nblks;

	dumpsize = physmem;
#define DUMPMMU
#undef DUMPMMU
#ifdef DUMPMMU
#define NPMEG 128
	/*
	 * savecore views the image in units of pages (i.e., dumpsize is in
	 * pages) so we round the two mmu entities into page-sized chunks.
	 * The PMEGs (32kB) and the segment table (512 bytes plus padding)
	 * are appending to the end of the crash dump.
	 */
	dumpsize += btoc(sizeof(((struct ksegmap *)0)->ks_segmap)) +
		btoc(NPMEG * NPTESG * sizeof(int));
#endif
	if (dumpdev != NODEV && bdevsw[major(dumpdev)].d_psize) {
		nblks = (*bdevsw[major(dumpdev)].d_psize)(dumpdev);
		/*
		 * Don't dump on the first CLBYTES (why CLBYTES?)
		 * in case the dump device includes a disk label.
		 */
		if (dumplo < btodb(CLBYTES))
			dumplo = btodb(CLBYTES);

		/*
		 * If dumpsize is too big for the partition, truncate it.
		 * Otherwise, put the dump at the end of the partition
		 * by making dumplo as large as possible.
		 */
		if (dumpsize > btoc(dbtob(nblks - dumplo)))
			dumpsize = btoc(dbtob(nblks - dumplo));
		else if (dumplo + ctod(dumpsize) > nblks)
			dumplo = nblks - ctod(dumpsize);
	}
}

#ifdef DUMPMMU
/* XXX */
#include <machine/ctlreg.h>
#define	getpte(va)		lda(va, ASI_PTE)
#define	setsegmap(va, pmeg)	stba(va, ASI_SEGMAP, pmeg)

/*
 * Write the mmu contents to the dump device.
 * This gets appended to the end of a crash dump since
 * there is no in-core copy of kernel memory mappings.
 */
int
dumpmmu(blkno)
	register daddr_t blkno;
{
	register int (*dump)	__P((dev_t, daddr_t, caddr_t, int));
	register int pmeg;
	register int addr;	/* unused kernel virtual address */
	register int i;
	register int *pte, *ptend;
	register int error;
	register struct ksegmap *kpmap = &kernel_segmap_store;
	int buffer[dbtob(1) / sizeof(int)];
	extern int seginval;	/* from pmap.c */
	

	dump = bdevsw[major(dumpdev)].d_dump;

	/*
	 * dump page table entries
	 *
	 * We dump each pmeg in order (by segment number).  Since the MMU
	 * automatically maps the given virtual segment to a pmeg we must
	 * iterate over the segments by incrementing an unused segment slot
	 * in the MMU.  This fixed segment number is used in the virtual
	 * address argument to getpte().
	 */

	/* First find an unused virtual segment. */
	i = NKSEG;
	while (kpmap->ks_segmap[--i] != seginval)
		if (i <= 0)
			return (-1);
	/*
	 * Compute the base address corresponding to the unused segment.
	 * Note that the kernel segments start after all the user segments
	 * so we must account for this offset.
	 */
	addr = VSTOVA(i + NUSEG);
	/*
	 * Go through the pmegs and dump each one.
	 */
	pte = buffer;
	ptend = &buffer[sizeof(buffer) / sizeof(buffer[0])];
	for (pmeg = 0; pmeg < NPMEG; ++pmeg) {
		register int va = addr;

		setsegmap(addr, pmeg);
		i = NPTESG;
		do {
			*pte++ = getpte(va);
			if (pte >= ptend) {
				/*
				 * Note that we'll dump the last block
				 * the last time through the loops because
				 * all the PMEGs occupy 32KB which is 
				 * a multiple of the block size.
				 */
				error = (*dump)(dumpdev, blkno,
						(caddr_t)buffer,
						dbtob(1));
				if (error != 0)
					return (error);
				++blkno;
				pte = buffer;
			}
			va += NBPG;
		} while (--i > 0);
	}
	setsegmap(addr, seginval);

	/*
	 * dump (512 byte) segment map 
	 * XXX assume it's a multiple of the block size
	 */
	error = (*dump)(dumpdev, blkno, (caddr_t)kpmap->ks_segmap,
			sizeof(kpmap->ks_segmap));
	return (error);
}
#endif

#define	BYTES_PER_DUMP	(32 * 1024)	/* must be a multiple of pagesize */
static vm_offset_t dumpspace;

caddr_t
reserve_dumppages(p)
	caddr_t p;
{

	dumpspace = (vm_offset_t)p;
	return (p + BYTES_PER_DUMP);
}

/*
 * Write a crash dump.
 */
dumpsys()
{
	register unsigned bytes, i, n;
	register int maddr, psize;
	register daddr_t blkno;
	register int (*dump)	__P((dev_t, daddr_t, caddr_t, int));
	int error = 0;

	/* copy registers to memory */
	snapshot(cpcb);
	stackdump();

	if (dumpdev == NODEV)
		return;

	/*
	 * For dumps during autoconfiguration,
	 * if dump device has already configured...
	 */
	if (dumpsize == 0)
		dumpconf();
	if (dumplo < 0)
		return;
	printf("\ndumping to dev %x, offset %d\n", dumpdev, dumplo);

	psize = (*bdevsw[major(dumpdev)].d_psize)(dumpdev);
	printf("dump ");
	if (psize == -1) {
		printf("area unavailable\n");
		return;
	}
	bytes = physmem << PGSHIFT;
	maddr = 0;
	blkno = dumplo;
	dump = bdevsw[major(dumpdev)].d_dump;
	for (i = 0; i < bytes; i += n) {
		n = bytes - i;
		if (n > BYTES_PER_DUMP)
			 n = BYTES_PER_DUMP;
#ifdef DEBUG
		/* print out how many MBs we have dumped */
		if (i && (i % (1024*1024)) == 0)
			printf("%d ", i / (1024*1024));
#endif
		(void) pmap_map(dumpspace, maddr, maddr + n, VM_PROT_READ);
		error = (*dump)(dumpdev, blkno, (caddr_t)dumpspace, (int)n);
		if (error)
			break;
		maddr += n;
		blkno += btodb(n);
	}
#ifdef DUMPMMU
	if (!error)
		error = dumpmmu(blkno);
#endif
	switch (error) {

	case ENXIO:
		printf("device bad\n");
		break;

	case EFAULT:
		printf("device not ready\n");
		break;

	case EINVAL:
		printf("area improper\n");
		break;

	case EIO:
		printf("i/o error\n");
		break;

	case 0:
		printf("succeeded\n");
		break;

	default:
		printf("error %d\n", error);
		break;
	}
}

/*
 * get the fp and dump the stack as best we can.  don't leave the
 * current stack page
 */
stackdump()
{
	struct frame *fp = (struct frame *)getfp(), *sfp;

	sfp = fp;
	printf("Frame pointer is at 0x%x\n", fp);
	printf("Call traceback:\n");
	while (fp && ((u_long)fp >> PGSHIFT) == ((u_long)sfp >> PGSHIFT)) {
		printf("  pc = %x  args = (%x, %x, %x, %x, %x, %x) fp = %x\n",
		    fp->fr_pc, fp->fr_arg[0], fp->fr_arg[1], fp->fr_arg[2],
		    fp->fr_arg[3], fp->fr_arg[4], fp->fr_arg[5], fp->fr_arg[6],
		    fp->fr_fp);
		fp = fp->fr_fp;
	}
}

int bt2pmt[] = {
	PMAP_OBIO,
	PMAP_OBIO,
	PMAP_VME16,
	PMAP_VME32,
	PMAP_OBIO
};

/*
 * Map an I/O device given physical address and size in bytes, e.g.,
 *
 *	mydev = (struct mydev *)mapdev(myioaddr, 0, sizeof(struct mydev), pmtype);
 *
 * See also machine/autoconf.h.
 */
void *
mapdev(phys, virt, size, bustype)
	register void *phys;
	register int virt, size;
	register int bustype;
{
	register vm_offset_t v;
	register void *ret;
	static vm_offset_t iobase;
	int pmtype = bt2pmt[bustype];

	if (iobase == NULL)
		iobase = IODEV_BASE;

	size = round_page(size);
	if (virt)
		v = trunc_page(virt);
	else {
		v = iobase;
		iobase += size;
		if (iobase > IODEV_END)	/* unlikely */
			panic("mapiodev");
	}
	ret = (void *)v;
	phys = (void *)trunc_page(phys);
	do {
		pmap_enter(pmap_kernel(), v,
		    (vm_offset_t)phys | pmtype | PMAP_NC,
		    VM_PROT_READ | VM_PROT_WRITE, 1);
		v += PAGE_SIZE;
		phys += PAGE_SIZE;
	} while ((size -= PAGE_SIZE) > 0);
	return (ret);
}

int
cpu_exec_aout_makecmds(p, epp)
	struct proc *p;
	struct exec_package *epp;
{
	int error = ENOEXEC;

#ifdef COMPAT_SUNOS
	extern sunos_exec_aout_makecmds __P((struct proc *, struct exec_package *));
	if ((error = sunos_exec_aout_makecmds(p, epp)) == 0)
		return 0;
#endif
	return error;
}

#ifdef SUN4
void
oldmon_w_trace(va)
	u_long va;
{
	u_long stop;
	extern u_long *par_err_reg;
	volatile u_long *memreg = (u_long *) par_err_reg;
	struct frame *fp;

	if (curproc)
		printf("curproc = %x, pid %d\n", curproc, curproc->p_pid);
	else
		printf("no curproc\n");

	printf("cnt: swtch %d, trap %d, sys %d, intr %d, soft %d, faults %d\n",
	    cnt.v_swtch, cnt.v_trap, cnt.v_syscall, cnt.v_intr, cnt.v_soft,
	    cnt.v_faults);
	write_user_windows();

#define round_up(x) (( (x) + (NBPG-1) ) & (~(NBPG-1)) )

	printf("\nstack trace with sp = %x\n", va);
	stop = round_up(va);
	printf("stop at %x\n", stop);
	fp = (struct frame *) va;
	while (round_up((u_long) fp) == stop) {
		printf("  %x(%x, %x, %x, %x, %x, %x) fp %x\n", fp->fr_pc, 
		    fp->fr_arg[0], fp->fr_arg[1], fp->fr_arg[2], fp->fr_arg[3], 
		    fp->fr_arg[4], fp->fr_arg[5], fp->fr_arg[6], fp->fr_fp);
		fp = fp->fr_fp;
		if (fp == NULL)
			break;
	}
	printf("end of stack trace\n"); 
}

void
oldmon_w_cmd(va, ar)
	u_long va;
	char *ar;
{
	switch (*ar) {
	case '\0':
		switch (va) {
		case 0:
			panic("g0 panic");
		case 4:
			printf("w: case 4\n");
			break;
		default:
			printf("w: unknown case %d\n", va);
			break;
		}
		break;
	case 't':
		oldmon_w_trace(va);
		break;
	default:
		printf("w: arg not allowed\n");
	}
}
#endif /* SUN4 */

u_int
ldcontrolb(addr)
caddr_t addr;
{
	struct pcb *xpcb;
	extern struct user *proc0paddr;
	u_long saveonfault, res;
	int s;

	s = splhigh();
	if (curproc == NULL)
		xpcb = (struct pcb *)proc0paddr;
	else
		xpcb = &curproc->p_addr->u_pcb;

	saveonfault = (u_long)xpcb->pcb_onfault;
	res = xldcontrolb(addr, xpcb);
	xpcb->pcb_onfault = (caddr_t)saveonfault;

	splx(s);
	return (res);
}

void
wzero(vb, l)
	void *vb;
	u_int l;
{
	u_char *b = vb;
	u_char *be = b + l;
	u_short *sp;

	if (l == 0)
		return;

	/* front, */
	if ((u_long)b & 1)
		*b++ = 0;

	/* back, */
	if (b != be && ((u_long)be & 1) != 0) {
		be--;
		*be = 0;
	}

	/* and middle. */
	sp = (u_short *)b;
	while (sp != (u_short *)be)
		*sp++ = 0;
}

void
wcopy(vb1, vb2, l)
	const void *vb1;
	void *vb2;
	u_int l;
{
	const u_char *b1e, *b1 = vb1;
	u_char *b2 = vb2;
	u_short *sp;
	int bstore = 0;

	if (l == 0)
		return;

	/* front, */
	if ((u_long)b1 & 1) {
		*b2++ = *b1++;
		l--;
	}

	/* middle, */
	sp = (u_short *)b1;
	b1e = b1 + l;
	if (l & 1)
		b1e--;
	bstore = (u_long)b2 & 1;

	while (sp < (u_short *)b1e) {
		if (bstore) {
			b2[1] = *sp & 0xff;
			b2[0] = *sp >> 8;
		} else
			*((short *)b2) = *sp;
		sp++;
		b2 += 2;
	}

	/* and back. */
	if (l & 1)
		*b2 = *b1e;
}

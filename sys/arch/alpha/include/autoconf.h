/* $NetBSD: autoconf.h,v 1.8 1997/07/25 00:03:47 thorpej Exp $ */

/*
 * Copyright (c) 1994, 1995, 1996 Carnegie-Mellon University.
 * All rights reserved.
 *
 * Author: Chris G. Demetriou
 * 
 * Permission to use, copy, modify and distribute this software and
 * its documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS" 
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND 
 * FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie the
 * rights to redistribute these changes.
 */

/*
 * Machine-dependent structures of autoconfiguration
 */

struct confargs;

typedef int (*intr_handler_t) __P((void *));

struct abus {
	struct	device *ab_dv;		/* back-pointer to device */
	int	ab_type;		/* bus type (see below) */
	void	(*ab_intr_establish)	/* bus's set-handler function */
		    __P((struct confargs *, intr_handler_t, void *));
	void	(*ab_intr_disestablish)	/* bus's unset-handler function */
		    __P((struct confargs *));
	caddr_t	(*ab_cvtaddr)		/* convert slot/offset to address */
		    __P((struct confargs *));
	int	(*ab_matchname)		/* see if name matches driver */
		    __P((struct confargs *, char *));
};

#define	BUS_MAIN	1		/* mainbus */
#define	BUS_TC		2		/* TurboChannel */
#define	BUS_ASIC	3		/* IOCTL ASIC; under TurboChannel */
#define	BUS_TCDS	4		/* TCDS ASIC; under TurboChannel */

#define	BUS_INTR_ESTABLISH(ca, handler, val)				\
	    (*(ca)->ca_bus->ab_intr_establish)((ca), (handler), (val))
#define	BUS_INTR_DISESTABLISH(ca)					\
	    (*(ca)->ca_bus->ab_intr_establish)(ca)
#define	BUS_CVTADDR(ca)							\
	    (*(ca)->ca_bus->ab_cvtaddr)(ca)
#define	BUS_MATCHNAME(ca, name)						\
	    (*(ca)->ca_bus->ab_matchname)((ca), (name))

struct confargs {
	char	*ca_name;		/* Device name. */
	int	ca_slot;		/* Device slot. */
	int	ca_offset;		/* Offset into slot. */
	struct	abus *ca_bus;		/* bus device resides on. */
};

struct bootdev_data {
	char	*protocol;
	int	bus;
	int	slot;
	int	channel;
	char	*remote_address;
	int	unit;
	int	boot_dev_type;
	char	*ctrl_dev_type;
};

/*
 * The boot program passes a pointer to a bootinfo to the kernel
 * using the following convention:
 *
 *	a0 contains first free page frame number
 *	a1 contains page number of current level 1 page table
 *	if a2 contains BOOTINFO_MAGIC
 *		a3 contains address of bootinfo
 */

#define	BOOTINFO_MAGIC		0xdeadbeeffeedface

struct bootinfo_v1 {
	u_long	ssym;		/* start of kernel symbol table */
	u_long	esym;		/* end of kernel symbol table */
	char	boot_flags[64];	/* boot flags */
	char	booted_kernel[64]; /* name of booted kernel */
};

struct bootinfo {
	u_int	version;		/* version number */
	union {
		struct bootinfo_v1 v1;	/* version 1 boot info */
		char pad[256];		/* reserve space for future use */
	} un;
};

#ifdef EVCNT_COUNTERS
extern struct evcnt clock_intr_evcnt;
#endif

extern struct device *booted_device;
extern int booted_partition;
extern struct bootdev_data *bootdev_data;

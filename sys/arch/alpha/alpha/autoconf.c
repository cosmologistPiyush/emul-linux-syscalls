/* $NetBSD: autoconf.c,v 1.24 1997/04/07 23:39:37 cgd Exp $ */

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
 *	@(#)autoconf.c	8.4 (Berkeley) 10/1/93
 */

#include <machine/options.h>		/* Config options headers */
#include <sys/cdefs.h>			/* RCS ID & Copyright macro defns */

__KERNEL_RCSID(0, "$NetBSD: autoconf.c,v 1.24 1997/04/07 23:39:37 cgd Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/disklabel.h>
#include <sys/reboot.h>
#include <sys/device.h>
#include <dev/cons.h>

#include <machine/autoconf.h>
#include <machine/prom.h>
#include <machine/conf.h>

struct device		*booted_device;
int			booted_partition;
struct bootdev_data	*bootdev_data;
char			boot_dev[128];

void	parse_prom_bootdev __P((void));
int	atoi __P((char *));

struct devnametobdevmaj alpha_nam2blk[] = {
	{ "st",		2 },
	{ "cd",		3 },
	{ "md",		6 },
	{ "sd",		8 },
	{ "fd",		0 },
	{ "wd",		4 },
	{ NULL,		0 },
};

/*
 * configure:
 * called at boot time, configure all devices on system
 */
void
configure()
{

	parse_prom_bootdev();

	(void)splhigh();
	if (config_rootfound("mainbus", "mainbus") == NULL)
		panic("no mainbus found");
	(void)spl0();
	cold = 0;
}

void
cpu_rootconf()
{

	if (booted_device == NULL)
		printf("WARNING: can't figure what device matches \"%s\"\n",
		    boot_dev);
	setroot(booted_device, booted_partition, alpha_nam2blk);
}

void
parse_prom_bootdev()
{
	static char hacked_boot_dev[128];
	static struct bootdev_data bd;
	char *cp, *scp, *boot_fields[8];
	int i, done;

	booted_device = NULL;
	booted_partition = 0;
	bootdev_data = NULL;

        prom_getenv(PROM_E_BOOTED_DEV, boot_dev, sizeof(boot_dev));
	bcopy(boot_dev, hacked_boot_dev, sizeof hacked_boot_dev);
#if 0
	printf("parse_prom_bootdev: boot dev = \"%s\"\n", boot_dev);
#endif

	i = 0;
	scp = cp = hacked_boot_dev;
	for (done = 0; !done; cp++) {
		if (*cp != ' ' && *cp != '\0')
			continue;
		if (*cp == '\0')
			done = 1;

		*cp = '\0';
		boot_fields[i++] = scp;
		scp = cp + 1;
		if (i == 8)
			done = 1;
	}
	if (i != 8)
		return;		/* doesn't look like anything we know! */

#if 0
	printf("i = %d, done = %d\n", i, done);
	for (i--; i >= 0; i--)
		printf("%d = %s\n", i, boot_fields[i]);
#endif

	bd.protocol = boot_fields[0];
	bd.bus = atoi(boot_fields[1]);
	bd.slot = atoi(boot_fields[2]);
	bd.channel = atoi(boot_fields[3]);
	bd.remote_address = boot_fields[4];
	bd.unit = atoi(boot_fields[5]);
	bd.boot_dev_type = atoi(boot_fields[6]);
	bd.ctrl_dev_type = boot_fields[7];

#if 0
	printf("parsed: proto = %s, bus = %d, slot = %d, channel = %d,\n",
	    bd.protocol, bd.bus, bd.slot, bd.channel);
	printf("\tremote = %s, unit = %d, dev_type = %d, ctrl_type = %s\n",
	    bd.remote_address, bd.unit, bd.boot_dev_type, bd.ctrl_dev_type);
#endif

	bootdev_data = &bd;
}

int
atoi(s)
	char *s;
{
	int n, neg;

	n = 0;
	neg = 0;

	while (*s == '-') {
		s++;
		neg = !neg;
	}

	while (*s != '\0') {
		if (*s < '0' && *s > '9')
			break;

		n = (10 * n) + (*s - '0');
		s++;
	}

	return (neg ? -n : n);
}

void
device_register(dev, aux)
	struct device *dev;
	void *aux;
{
	extern const struct cpusw *cpu_fn_switch;

	if (bootdev_data == NULL) {
		/*
		 * There is no hope.
		 */

		return;
	}

	(*cpu_fn_switch->device_register)(dev, aux);
}

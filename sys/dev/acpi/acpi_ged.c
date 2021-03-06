/* $NetBSD: acpi_ged.c,v 1.4 2022/01/11 10:53:08 jmcneill Exp $ */

/*-
 * Copyright (c) 2018 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jared McNeill <jmcneill@invisible.ca>.
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
__KERNEL_RCSID(0, "$NetBSD: acpi_ged.c,v 1.4 2022/01/11 10:53:08 jmcneill Exp $");

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/cpu.h>
#include <sys/device.h>
#include <sys/intr.h>
#include <sys/kmem.h>

#include <dev/acpi/acpireg.h>
#include <dev/acpi/acpivar.h>
#include <dev/acpi/acpi_event.h>
#include <dev/acpi/acpi_intr.h>

static int	acpi_ged_match(device_t, cfdata_t, void *);
static void	acpi_ged_attach(device_t, device_t, void *);

static void	acpi_ged_register_event(void *, struct acpi_event *, struct acpi_irq *);
static int	acpi_ged_intr(void *);

CFATTACH_DECL_NEW(acpiged, 0, acpi_ged_match, acpi_ged_attach, NULL, NULL);

static const struct device_compatible_entry compat_data[] = {
	{ .compat = "ACPI0013" },
	DEVICE_COMPAT_EOL
};

static int
acpi_ged_match(device_t parent, cfdata_t cf, void *aux)
{
	struct acpi_attach_args *aa = aux;

	return acpi_compatible_match(aa, compat_data);
}

static void
acpi_ged_attach(device_t parent, device_t self, void *aux)
{
	struct acpi_attach_args * const aa = aux;
	ACPI_HANDLE handle = aa->aa_node->ad_handle;

        if (ACPI_FAILURE(acpi_event_create_int(self, handle, acpi_ged_register_event, self)))
                aprint_error_dev(self, "failed to create events\n");
}

static void
acpi_ged_register_event(void *priv, struct acpi_event *ev, struct acpi_irq *irq)
{
	device_t dev = priv;
	void *ih;

	ih = acpi_intr_establish_irq(dev, irq, IPL_VM, true,
	    acpi_ged_intr, ev, device_xname(dev));
	if (ih == NULL) {
		aprint_error_dev(dev, "couldn't establish interrupt (irq %d)\n", irq->ar_irq);
		return;
	}
	acpi_event_set_intrcookie(ev, ih);
}

static int
acpi_ged_intr(void *priv)
{
	struct acpi_event * const ev = priv;

	acpi_event_notify(ev);

	return 1;
}

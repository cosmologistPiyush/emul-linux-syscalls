/*	$NetBSD: mainbus.c,v 1.84 2009/04/17 21:07:58 dyoung Exp $	*/

/*
 * Copyright (c) 1996 Christopher G. Demetriou.  All rights reserved.
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
 *      This product includes software developed by Christopher G. Demetriou
 *	for the NetBSD Project.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: mainbus.c,v 1.84 2009/04/17 21:07:58 dyoung Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/device.h>
#include <sys/reboot.h>
#include <sys/bus.h>

#include <dev/isa/isavar.h>
#include <dev/eisa/eisavar.h>
#include <dev/pci/pcivar.h>

#include <dev/isa/isareg.h>		/* for ISA_HOLE_VADDR */

#include "pci.h"
#include "eisa.h"
#include "isa.h"
#include "isadma.h"
#include "mca.h"
#include "apmbios.h"
#include "pnpbios.h"
#include "acpi.h"
#include "ipmi.h"

#include "opt_acpi.h"
#include "opt_mpbios.h"
#include "opt_pcifixup.h"

#include <machine/cpuvar.h>
#include <machine/i82093var.h>
#include <machine/mpbiosvar.h>
#include <machine/mpacpi.h>

#if NAPMBIOS > 0
#include <machine/bioscall.h>
#include <machine/apmvar.h>
#endif

#if NPNPBIOS > 0
#include <arch/i386/pnpbios/pnpbiosvar.h>
#endif

#if NACPI > 0
#include <dev/acpi/acpivar.h>
#endif

#if NMCA > 0
#include <dev/mca/mcavar.h>
#endif

#if NIPMI > 0
#include <x86/ipmivar.h>
#endif

#if NPCI > 0
#if defined(PCI_BUS_FIXUP)
#include <arch/x86/pci/pci_bus_fixup.h>
#if defined(PCI_ADDR_FIXUP)
#include <arch/x86/pci/pci_addr_fixup.h>
#endif
#endif
#endif

void	mainbus_childdetached(device_t, device_t);
int	mainbus_match(device_t, cfdata_t, void *);
void	mainbus_attach(device_t, device_t, void *);

static int	mainbus_rescan(device_t, const char *, const int *);

struct mainbus_softc {
	device_t	sc_acpi;
	device_t	sc_dev;
	device_t	sc_ipmi;
	device_t	sc_pci;
	device_t	sc_mca;
	device_t	sc_pnpbios;
	bool		sc_acpi_present;
	bool		sc_mpacpi_active;
};

CFATTACH_DECL2_NEW(mainbus, sizeof(struct mainbus_softc),
    mainbus_match, mainbus_attach, NULL, NULL, mainbus_rescan,
    mainbus_childdetached);

int	mainbus_print(void *, const char *);

union mainbus_attach_args {
	const char *mba_busname;		/* first elem of all */
	struct pcibus_attach_args mba_pba;
	struct eisabus_attach_args mba_eba;
	struct isabus_attach_args mba_iba;
#if NMCA > 0
	struct mcabus_attach_args mba_mba;
#endif
#if NPNPBIOS > 0
	struct pnpbios_attach_args mba_paa;
#endif
	struct cpu_attach_args mba_caa;
	struct apic_attach_args aaa_caa;
#if NACPI > 0
	struct acpibus_attach_args mba_acpi;
#endif
#if NIPMI > 0
	struct ipmi_attach_args mba_ipmi;
#endif
};

/*
 * This is set when the ISA bus is attached.  If it's not set by the
 * time it's checked below, then mainbus attempts to attach an ISA.
 */
int	isa_has_been_seen;
struct x86_isa_chipset x86_isa_chipset;
#if NISA > 0
struct isabus_attach_args mba_iba = {
	"isa",
	X86_BUS_SPACE_IO, X86_BUS_SPACE_MEM,
	&isa_bus_dma_tag,
	&x86_isa_chipset
};
#endif

/*
 * Same as above, but for EISA.
 */
int	eisa_has_been_seen;

#if defined(MPBIOS) || NACPI > 0
struct mp_bus *mp_busses;
int mp_nbus;
struct mp_intr_map *mp_intrs;
int mp_nintr;
 
int mp_isa_bus = -1;            /* XXX */
int mp_eisa_bus = -1;           /* XXX */

#ifdef MPVERBOSE
int mp_verbose = 1;
#else
int mp_verbose = 0;
#endif
#endif

void
mainbus_childdetached(device_t self, device_t child)
{
	struct mainbus_softc *sc = device_private(self);

	if (sc->sc_acpi == child)
		sc->sc_acpi = NULL;
	if (sc->sc_ipmi == child)
		sc->sc_ipmi = NULL;
	if (sc->sc_mca == child)
		sc->sc_mca = NULL;
	if (sc->sc_pnpbios == child)
		sc->sc_pnpbios = NULL;
	if (sc->sc_pci == child)
		sc->sc_pci = NULL;

	mp_pci_childdetached(self, child);
}

/*
 * Probe for the mainbus; always succeeds.
 */
int
mainbus_match(device_t parent, cfdata_t match, void *aux)
{

	return 1;
}

/*
 * Attach the mainbus.
 */
void
mainbus_attach(device_t parent, device_t self, void *aux)
{
	struct mainbus_softc *sc = device_private(self);
	union mainbus_attach_args mba;
#ifdef MPBIOS
	int mpbios_present = 0;
#endif
#if defined(PCI_BUS_FIXUP)
	int pci_maxbus = 0;
#endif
	int numcpus = 0;

	sc->sc_dev = self;

	aprint_naive("\n");
	aprint_normal("\n");

#ifdef MPBIOS
	mpbios_present = mpbios_probe(self);
#endif

#if NPCI > 0
	/*
	 * ACPI needs to be able to access PCI configuration space.
	 */
	pci_mode = pci_mode_detect();
#if defined(PCI_BUS_FIXUP)
	if (pci_mode != 0) {
		pci_maxbus = pci_bus_fixup(NULL, 0);
		aprint_debug("PCI bus max, after pci_bus_fixup: %i\n",
		    pci_maxbus);
#if defined(PCI_ADDR_FIXUP)
		pciaddr.extent_port = NULL;
		pciaddr.extent_mem = NULL;
		pci_addr_fixup(NULL, pci_maxbus);
#endif
	}
#endif
#endif

#if NACPI > 0
	if ((boothowto & RB_MD2) == 0 && acpi_check(self, "acpibus"))
		sc->sc_acpi_present = acpi_probe() != 0;
	/*
	 * First, see if the MADT contains CPUs, and possibly I/O APICs.
	 * Building the interrupt routing structures can only
	 * be done later (via a callback).
	 */
	if (sc->sc_acpi_present)
		sc->sc_mpacpi_active = mpacpi_scan_apics(self, &numcpus) != 0;
#endif

	if (!sc->sc_mpacpi_active) {
#ifdef MPBIOS
		if (mpbios_present)
			mpbios_scan(self, &numcpus);
		else
#endif
		if (numcpus == 0) {
			struct cpu_attach_args caa;

			memset(&caa, 0, sizeof(caa));
			caa.cpu_number = 0;
			caa.cpu_role = CPU_ROLE_SP;
			caa.cpu_func = 0;

			config_found_ia(self, "cpubus", &caa, mainbus_print);
		}
	}

#if NISADMA > 0 && (NACPI > 0 || NPNPBIOS > 0)
	/*
	 * ACPI and PNPBIOS need ISA DMA initialized before they start probing.
	 */
	isa_dmainit(&x86_isa_chipset, X86_BUS_SPACE_IO, &isa_bus_dma_tag,
	    self);
#endif

	mainbus_rescan(self, "acpibus", NULL);

	mainbus_rescan(self, "pnpbiosbus", NULL);

	mainbus_rescan(self, "ipmibus", NULL);

	mainbus_rescan(self, "pcibus", NULL);

	mainbus_rescan(self, "mcabus", NULL);

	if (memcmp(ISA_HOLE_VADDR(EISA_ID_PADDR), EISA_ID, EISA_ID_LEN) == 0 &&
	    eisa_has_been_seen == 0) {
		mba.mba_eba.eba_iot = X86_BUS_SPACE_IO;
		mba.mba_eba.eba_memt = X86_BUS_SPACE_MEM;
#if NEISA > 0
		mba.mba_eba.eba_dmat = &eisa_bus_dma_tag;
#endif
		config_found_ia(self, "eisabus", &mba.mba_eba, eisabusprint);
	}

#if NISA > 0
	if (isa_has_been_seen == 0)
		config_found_ia(self, "isabus", &mba_iba, isabusprint);
#endif

#if NAPMBIOS > 0
#if NACPI > 0
	if (acpi_active == 0)
#endif
	if (apm_busprobe())
		config_found_ia(self, "apmbus", 0, 0);
#endif

	if (!pmf_device_register(self, NULL, NULL))
		aprint_error_dev(self, "couldn't establish power handler\n");
}

/* XXX share this with sys/arch/i386/pci/elan520.c */
static bool
ifattr_match(const char *snull, const char *t)
{
	return (snull == NULL) || strcmp(snull, t) == 0;
}

/* scan for new children */
static int
mainbus_rescan(device_t self, const char *ifattr, const int *locators)
{
	struct mainbus_softc *sc = device_private(self);
#if NACPI > 0 || NIPMI > 0 || NMCA > 0 || NPCI > 0 || NPNPBIOS > 0
	union mainbus_attach_args mba;
#endif

	if (ifattr_match(ifattr, "acpibus") && sc->sc_acpi == NULL &&
	    sc->sc_acpi_present) {
#if NACPI > 0
		mba.mba_acpi.aa_iot = X86_BUS_SPACE_IO;
		mba.mba_acpi.aa_memt = X86_BUS_SPACE_MEM;
		mba.mba_acpi.aa_pc = NULL;
		mba.mba_acpi.aa_pciflags =
		    PCI_FLAGS_IO_ENABLED | PCI_FLAGS_MEM_ENABLED |
		    PCI_FLAGS_MRL_OKAY | PCI_FLAGS_MRM_OKAY |
		    PCI_FLAGS_MWI_OKAY;
		mba.mba_acpi.aa_ic = &x86_isa_chipset;
		sc->sc_acpi =
		    config_found_ia(self, "acpibus", &mba.mba_acpi, 0);
#if 0 /* XXXJRT not yet */
		if (acpi_active) {
			/*
			 * ACPI already did all the work for us, there
			 * is nothing more for us to do.
			 */
			return;
		}
#endif
#endif
	}

	if (ifattr_match(ifattr, "pnpbiosbus") && sc->sc_pnpbios == NULL) {
#if NPNPBIOS > 0
#if NACPI > 0
		if (acpi_active == 0)
#endif
		if (pnpbios_probe()) {
			mba.mba_paa.paa_ic = &x86_isa_chipset;
			sc->sc_pnpbios = config_found_ia(self, "pnpbiosbus",
			    &mba.mba_paa, 0);
		}
#endif
	}

	if (ifattr_match(ifattr, "ipmibus") && sc->sc_ipmi == NULL) {
#if NIPMI > 0
		memset(&mba.mba_ipmi, 0, sizeof(mba.mba_ipmi));
		mba.mba_ipmi.iaa_iot = X86_BUS_SPACE_IO;
		mba.mba_ipmi.iaa_memt = X86_BUS_SPACE_MEM;
		if (ipmi_probe(&mba.mba_ipmi)) {
			sc->sc_ipmi =
			    config_found_ia(self, "ipmibus", &mba.mba_ipmi, 0);
		}
#endif
	}

	/*
	 * XXX Note also that the presence of a PCI bus should
	 * XXX _always_ be checked, and if present the bus should be
	 * XXX 'found'.  However, because of the structure of the code,
	 * XXX that's not currently possible.
	 */
#if NPCI > 0
	if (pci_mode != 0 && ifattr_match(ifattr, "pcibus")) {
		mba.mba_pba.pba_iot = X86_BUS_SPACE_IO;
		mba.mba_pba.pba_memt = X86_BUS_SPACE_MEM;
		mba.mba_pba.pba_dmat = &pci_bus_dma_tag;
		mba.mba_pba.pba_dmat64 = NULL;
		mba.mba_pba.pba_pc = NULL;
		mba.mba_pba.pba_flags = pci_bus_flags();
		mba.mba_pba.pba_bus = 0;
		mba.mba_pba.pba_bridgetag = NULL;
#if NACPI > 0 && defined(ACPI_SCANPCI)
		if (sc->sc_mpacpi_active)
			mp_pci_scan(self, &mba.mba_pba, pcibusprint);
		else
#endif
#if defined(MPBIOS) && defined(MPBIOS_SCANPCI)
		if (mpbios_scanned != 0)
			mp_pci_scan(self, &mba.mba_pba, pcibusprint);
		else
#endif
		if (sc->sc_pci == NULL) {
			sc->sc_pci = config_found_ia(self, "pcibus",
			    &mba.mba_pba, pcibusprint);
		}
#if NACPI > 0
		if (mp_verbose)
			acpi_pci_link_state();
#endif
	}
#endif


	if (ifattr_match(ifattr, "mcabus") && sc->sc_mca == NULL) {
#if NMCA > 0
	/* Note: MCA bus probe is done in i386/machdep.c */
		if (MCA_system) {
			mba.mba_mba.mba_iot = X86_BUS_SPACE_IO;
			mba.mba_mba.mba_memt = X86_BUS_SPACE_MEM;
			mba.mba_mba.mba_dmat = &mca_bus_dma_tag;
			mba.mba_mba.mba_mc = NULL;
			mba.mba_mba.mba_bus = 0;
			sc->sc_mca = config_found_ia(self, "mcabus",
			    &mba.mba_mba, mcabusprint);
		}
#endif
	}
	return 0;
}

int
mainbus_print(void *aux, const char *pnp)
{
	union mainbus_attach_args *mba = aux;

	if (pnp)
		aprint_normal("%s at %s", mba->mba_busname, pnp);
	return (UNCONF);
}

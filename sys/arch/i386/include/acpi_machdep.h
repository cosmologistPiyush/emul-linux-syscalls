/*	$NetBSD: acpi_machdep.h,v 1.6 2003/01/07 18:48:44 fvdl Exp $	*/

/*
 * Copyright 2001 Wasabi Systems, Inc.
 * All rights reserved.
 *
 * Written by Jason R. Thorpe for Wasabi Systems, Inc.
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
 *	This product includes software developed for the NetBSD Project by
 *	Wasabi Systems, Inc.
 * 4. The name of Wasabi Systems, Inc. may not be used to endorse
 *    or promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY WASABI SYSTEMS, INC. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL WASABI SYSTEMS, INC
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Machine-dependent code for ACPI.  This is provided to the Osd
 * portion of the ACPICA.
 */

#include <machine/pio.h>

ACPI_STATUS	acpi_md_OsInitialize(void);
ACPI_STATUS	acpi_md_OsTerminate(void);
ACPI_STATUS	acpi_md_OsGetRootPointer(UINT32, ACPI_POINTER *);

#define	acpi_md_OsIn8(x)	inb((x))
#define	acpi_md_OsIn16(x)	inw((x))
#define	acpi_md_OsIn32(x)	inl((x))

#define	acpi_md_OsOut8(x, v)	outb((x), (v))
#define	acpi_md_OsOut16(x, v)	outw((x), (v))
#define	acpi_md_OsOut32(x, v)	outl((x), (v))

ACPI_STATUS	acpi_md_OsInstallInterruptHandler(UINT32, OSD_HANDLER, void *,
		    void **);
void		acpi_md_OsRemoveInterruptHandler(void *);

ACPI_STATUS	acpi_md_OsMapMemory(ACPI_PHYSICAL_ADDRESS, UINT32, void **);
void		acpi_md_OsUnmapMemory(void *, UINT32);
ACPI_STATUS	acpi_md_OsGetPhysicalAddress(void *LogicalAddress,
		    ACPI_PHYSICAL_ADDRESS *PhysicalAddress);

BOOLEAN		acpi_md_OsReadable(void *, UINT32);
BOOLEAN		acpi_md_OsWritable(void *, UINT32);
void		acpi_md_OsDisableInterrupt(void);

int		acpi_md_sleep(int);
void		acpi_md_callback(struct device *);

#ifdef ACPI_MACHDEP_PRIVATE
u_int32_t	acpi_md_get_npages_of_wakecode(void);
void		acpi_md_install_wakecode(paddr_t);
#endif

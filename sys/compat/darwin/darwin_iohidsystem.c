/*	$NetBSD: darwin_iohidsystem.c,v 1.8 2003/06/03 06:48:49 manu Exp $ */

/*-
 * Copyright (c) 2003 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Emmanuel Dreyfus.
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
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
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
__KERNEL_RCSID(0, "$NetBSD: darwin_iohidsystem.c,v 1.8 2003/06/03 06:48:49 manu Exp $");

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/signal.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/device.h>
#include <sys/kthread.h>

#include <uvm/uvm_extern.h>
#include <uvm/uvm_map.h>
#include <uvm/uvm.h>

#include <compat/mach/mach_types.h>
#include <compat/mach/mach_message.h>
#include <compat/mach/mach_port.h>
#include <compat/mach/mach_errno.h>
#include <compat/mach/mach_iokit.h>

#include <compat/darwin/darwin_iokit.h>
#include <compat/darwin/darwin_iohidsystem.h>

static struct uvm_object *darwin_iohidsystem_shmem = NULL;
static void darwin_iohidsystem_shmeminit(vaddr_t);
static void darwin_iohidsystem_thread(void *);

#if 0
static char darwin_iohidsystem_properties[] = "<dict ID=\"0\"><key>IOKit</key><string ID=\"1\">IOService</string><key>AccessMPC106PerformanceRegister</key><string ID=\"2\">AppleGracklePCI is not serializable</string><key>IONVRAM</key><reference IDREF=\"1\"/><key>IOiic0</key><string ID=\"3\">ApplePMU is not serializable</string><key>IORTC</key><reference IDREF=\"3\"/><key>IOBSD</key><reference IDREF=\"1\"/><key>setModemSound</key><string ID=\"4\">AppleScreamerAudio is not serializable</string><key>kdp</key><reference IDREF=\"1\"/></dict>";
#endif
static char darwin_iohidsystem_properties[] = "<dict ID=\"0\"><key>IOClass</key><string ID=\"1\">AppleADBKeyboard</string><key>ADBVirtualKeys</key><string ID=\"2\">0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,0x31,0x32,0x33,0x34,0x35,0x3B,0x37,0x38,0x39,0x3A,0x7B,0x7C,0x7D,0x7E,0x3F,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5A,0x5B,0x5C,0x5D,0x5E,0x5F,0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6A,0x6B,0x6C,0x6D,0x6E,0x6F,0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7A,0x3C,0x3D,0x3E,0x36,0x7F</string><key>IOProbeScore</key><integer size=\"32\" ID=\"3\">0x3e8</integer><key>IOProviderClass</key><string ID=\"4\">IOADBDevice</string><key>CFBundleIdentifier</key><string ID=\"5\">com.apple.driver.AppleADBKeyboard</string><key>ADB Match</key><string ID=\"6\">2</string><key>PowerBook fn Foward Delete</key><integer size=\"64\" ID=\"7\">0x1</integer><key>IOMatchCategory</key><string ID=\"8\">IODefaultMatchCategory</string><key>HIDKeyMapping</key><data ID=\"10\">AAAIAAE5AQE4AgE7AwE6BAE3BRVSQUxTVFVFWFdWW1xDS1F7fX58TlkGAXIHAT9/DQBhAEEAAQABAMoAxwABAAENAHMAUwATABMA+wCnABMAEw0AZABEAAQABAFEAbYABAAEDQBmAEYABgAGAKYBrAAGAAYNAGgASAAIAAgA4wDrAAAYAA0AZwBHAAcABwDxAOEABwAHDQB6AFoAGgAaAM8BVwAaABoNAHgAWAAYABgBtAHOABgAGA0AYwBDAAMAAwHjAdMAAwADDQB2AFYAFgAWAdYB4AAWABYCADwAPg0AYgBCAAIAAgHlAfIAAgACDQBxAFEAEQARAPoA6gARABENAHcAVwAXABcByAHHABcAFw0AZQBFAAUABQDCAMUABQAFDQByAFIAEgASAeIB0gASABINAHkAWQAZABkApQHbABkAGQ0AdABUABQAFAHkAdQAFAAUCgAxACEBrQChDgAyAEAAMgAAALIAswAAAAAKADMAIwCjAboKADQAJACiAKgOADYAXgA2AB4AtgDDAB4AHgoANQAlAaUAvQoAPQArAbkBsQoAOQAoAKwAqwoANwAmAbABqw4ALQBfAB8AHwCxANAAHwAfCgA4ACoAtwC0CgAwACkArQC7DgBdAH0AHQAdACcAugAdAB0NAG8ATwAPAA8A+QDpAA8ADw0AdQBVABUAFQDIAM0AFQAVDgBbAHsAGwAbAGAAqgAbABsNAGkASQAJAAkAwQD1AAkACQ0AcABQABAAEAFwAVAAEAAQEAANAAMNAGwATAAMAAwA+ADoAAwADA0AagBKAAoACgDGAK4ACgAKCgAnACIAqQGuDQBrAEsACwALAM4ArwALAAsKADsAOgGyAaIOAFwAfAAcABwA4wDrABwAHAoALAA8AMsBowoALwA/AbgAvw0AbgBOAA4ADgDEAa8ADgAODQBtAE0ADQANAW0B2AANAA0KAC4APgC8AbMCAAkAGQwAIAAAAIAAAAoAYAB+AGABuwIAfwAI/wIAGwB+//////////////8AAC7/AAAq/wAAK/8AABv///8OAC8AXAAvABwALwBcAAAKAAAADf8AAC3//w4APQB8AD0AHAA9AHwAABhGAAAwAAAxAAAyAAAzAAA0AAA1AAA2AAA3/wAAOAAAOf///wD+JAD+JQD+JgD+IgD+JwD+KP8A/ir/AP4y/wD+M/8A/in/AP4r/wD+NP8A/i4A/jAA/i0A/iMA/i8A/iEA/jEA/iAAAawAAa4AAa8AAa0PAv8EADEC/wQAMgL/BAAzAv8EADQC/wQANQL/BAA2Av8EADcC/wQAOAL/BAA5Av8EADAC/wQALQL/BAA9Av8EAHAC/wQAXQL/BABbBgVyBn8HSgg+CT0KRw==</data><key>HIDKind</key><integer size=\"32\" ID=\"11\">0x1</integer><key>HIDInterfaceID</key><integer size=\"32\" ID=\"12\">0x2</integer><key>HIDSubinterfaceID</key><integer size=\"32\" ID=\"13\">0xc4</integer></dict>";

struct mach_iokit_devclass darwin_iohidsystem_devclass = {
	"<dict ID=\"0\"><key>IOProviderClass</key>"
	    "<string ID=\"1\">IOHIDSystem</string></dict>",
	darwin_iohidsystem_properties,
	NULL,
	darwin_iohidsystem_connect_method_scalari_scalaro,
	NULL,
	NULL,
	NULL,
	darwin_iohidsystem_connect_map_memory,
	"IOHIDSystem",
};

int
darwin_iohidsystem_connect_method_scalari_scalaro(args)
	struct mach_trap_args *args;
{
	mach_io_connect_method_scalari_scalaro_request_t *req = args->smsg;
	mach_io_connect_method_scalari_scalaro_reply_t *rep = args->rmsg;
	size_t *msglen = args->rsize;
	int maxoutcount;

#ifdef DEBUG_DARWIN
	printf("darwin_iohidsystem_connect_method_scalari_scalaro()\n");
#endif
	rep->rep_msgh.msgh_bits =
	    MACH_MSGH_REPLY_LOCAL_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE);
	rep->rep_msgh.msgh_size = sizeof(*rep) - sizeof(rep->rep_trailer);
	rep->rep_msgh.msgh_local_port = req->req_msgh.msgh_local_port;
	rep->rep_msgh.msgh_id = req->req_msgh.msgh_id + 100;
	rep->rep_outcount = 0;

	maxoutcount = req->req_in[req->req_incount];

	switch (req->req_selector) {
	case DARWIN_IOHIDCREATESHMEM: {
		/* Create the shared memory for HID events */
		int version;
		struct proc *newpp;
		int error;
		size_t memsize;
		vaddr_t kvaddr;

		version = req->req_in[0]; /* 1 */
#ifdef DEBUG_DARWIN
		printf("DARWIN_IOHIDCREATESHMEM: version = %d\n", version);
#endif
		memsize = round_page(sizeof(struct darwin_iohidsystem_shmem));

		/* If it has not been used yet, initialize it */
		if (darwin_iohidsystem_shmem == NULL) {
			darwin_iohidsystem_shmem = uao_create(memsize, 0);

			error = uvm_map(kernel_map, &kvaddr, memsize, 
			    darwin_iohidsystem_shmem, 0, PAGE_SIZE,
			    UVM_MAPFLAG(UVM_PROT_RW, UVM_PROT_RW, 
			    UVM_INH_SHARE, UVM_ADV_RANDOM, 0));
			if (error != 0) {
				uao_detach(darwin_iohidsystem_shmem);
				darwin_iohidsystem_shmem = NULL;
				return mach_msg_error(args, error);
			}

			error = uvm_map_pageable(kernel_map, kvaddr, 
			    kvaddr + memsize, FALSE, 0);
			if (error != 0) {
				uao_detach(darwin_iohidsystem_shmem);
				darwin_iohidsystem_shmem = NULL;
				return mach_msg_error(args, error);
			}

			darwin_iohidsystem_shmeminit(kvaddr);

			kthread_create1(darwin_iohidsystem_thread, 
			    (void *)kvaddr, &newpp, "iohidsystem");
		}
		rep->rep_outcount = 0;
		break;
	}

	case DARWIN_IOHIDSETEVENTSENABLE: {
		/* Enable or disable events */
		int enable;

		enable = req->req_in[0];
#ifdef DEBUG_DARWIN
		printf("DARWIN_IOHIDSETEVENTSENABLE: enable = %d\n", enable);
#endif
		/* For now, this is a no-op */
		rep->rep_outcount = 0;
		break;
	}

	case DARWIN_IOHIDSETCURSORENABLE: {
		/* Enable or disable the cursor */	
		int enable;

		enable = req->req_in[0];
#ifdef DEBUG_DARWIN
		printf("DARWIN_IOHIDSETCURSORENABLE: enable = %d\n", enable);
#endif
		/* We don't support it */
		rep->rep_outcount = 0;
		break;
	}

	default:
#ifdef DEBUG_DARWIN
		printf("Unknown selector %d\n", req->req_selector);
#endif
		return mach_msg_error(args, EINVAL);
		break;
	}

	rep->rep_out[rep->rep_outcount + 1] = 8; /* XXX Trailer */

	*msglen = sizeof(*rep) - ((16 + rep->rep_outcount) * sizeof(int));
	rep->rep_msgh.msgh_size = *msglen - sizeof(rep->rep_trailer);
	return 0;
}

int
darwin_iohidsystem_connect_map_memory(args)
	struct mach_trap_args *args;
{
	mach_io_connect_map_memory_request_t *req = args->smsg;
	mach_io_connect_map_memory_reply_t *rep = args->rmsg;
	size_t *msglen = args->rsize;
	struct proc *p = args->l->l_proc;
	int error;
	size_t memsize;
	vaddr_t pvaddr;

#ifdef DEBUG_DARWIN
	printf("darwin_iohidsystem_connect_map_memory()\n");
#endif
	memsize = round_page(sizeof(struct darwin_iohidsystem_shmem));

	if (darwin_iohidsystem_shmem == NULL) 
		return mach_msg_error(args, ENOMEM);

	uao_reference(darwin_iohidsystem_shmem);
	pvaddr = VM_DEFAULT_ADDRESS(p->p_vmspace->vm_daddr, memsize);

	if ((error = uvm_map(&p->p_vmspace->vm_map, &pvaddr, 
	    memsize, darwin_iohidsystem_shmem, 0, PAGE_SIZE, 
	    UVM_MAPFLAG(UVM_PROT_RW, UVM_PROT_RW,
	    UVM_INH_SHARE, UVM_ADV_RANDOM, 0))) != 0)
		return mach_msg_error(args, error);

#ifdef DEBUG_DARWIN
	printf("pvaddr = 0x%08lx\n", (long)pvaddr);
#endif
	rep->rep_msgh.msgh_bits =
	    MACH_MSGH_REPLY_LOCAL_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE);
	rep->rep_msgh.msgh_size = sizeof(*rep) - sizeof(rep->rep_trailer);
	rep->rep_msgh.msgh_local_port = req->req_msgh.msgh_local_port;
	rep->rep_msgh.msgh_id = req->req_msgh.msgh_id + 100;
	rep->rep_retval = 0;
	rep->rep_addr = pvaddr;
	rep->rep_len = sizeof(struct darwin_iohidsystem_shmem);
	rep->rep_trailer.msgh_trailer_size = 8;

	*msglen = sizeof(*rep);

	return 0;
}

static void
darwin_iohidsystem_thread(shmem)
	void *shmem;
{
#ifdef DEBUG_DARWIN
	printf("darwin_iohidsystem_thread: start\n");
#endif
	/* 
	 * This will receive wscons events and modify the IOHIDSystem
	 * shared page. But for now it just sleep forever.
	 */
	(void)tsleep(shmem, PZERO | PCATCH, "iohidsystem", 0);
#ifdef DEBUG_DARWIN
	printf("darwin_iohidsystem_thread: exit\n");
#endif
	return;
};

static void
darwin_iohidsystem_shmeminit(kvaddr)
	vaddr_t kvaddr;
{
	struct darwin_iohidsystem_shmem *shmem;
	struct darwin_iohidsystem_evglobals *evglobals;

	shmem = (struct darwin_iohidsystem_shmem *)kvaddr;
	shmem->dis_global_offset = 
	    (size_t)&shmem->dis_evglobals - (size_t)&shmem->dis_global_offset;
	shmem->dis_private_offset = 
	    shmem->dis_global_offset + sizeof(*evglobals);

	evglobals = &shmem->dis_evglobals;
	evglobals->die_struct_size = sizeof(*evglobals);

	return;
}

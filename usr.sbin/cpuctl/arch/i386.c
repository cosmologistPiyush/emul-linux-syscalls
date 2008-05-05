/*	$NetBSD: i386.c,v 1.1 2008/05/05 17:54:14 ad Exp $	*/

/*-
 * Copyright (c) 1999, 2000, 2001, 2006, 2007, 2008 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Frank van der Linden,  and by Jason R. Thorpe.
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

/*-
 * Copyright (c)2008 YAMAMOTO Takashi,
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#ifndef lint
__RCSID("$NetBSD: i386.c,v 1.1 2008/05/05 17:54:14 ad Exp $");
#endif /* not lint */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/bitops.h>
#include <sys/sysctl.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <assert.h>
#include <math.h>

#include <machine/specialreg.h>
#include <machine/cpu.h>

#include <x86/cpuvar.h>
#include <x86/cputypes.h>

#include "../cpuctl.h"

#define       x86_cpuid(a,b)  x86_cpuid2((a),0,(b))

void	x86_cpuid2(uint32_t, uint32_t, uint32_t *);
void	x86_identify(void);

struct x86_cache_info {
	uint8_t		cai_index;
	uint8_t		cai_desc;
	uint8_t		cai_associativity;
	u_int		cai_totalsize; /* #entries for TLB, bytes for cache */
	u_int		cai_linesize;	/* or page size for TLB */
	const char	*cai_string;
};

#define	CAI_ITLB	0		/* Instruction TLB (4K pages) */
#define	CAI_ITLB2	1		/* Instruction TLB (2/4M pages) */
#define	CAI_DTLB	2		/* Data TLB (4K pages) */
#define	CAI_DTLB2	3		/* Data TLB (2/4M pages) */
#define	CAI_ICACHE	4		/* Instruction cache */
#define	CAI_DCACHE	5		/* Data cache */
#define	CAI_L2CACHE	6		/* Level 2 cache */

#define	CAI_COUNT	7

/*
 * AMD Cache Info:
 *
 *	Athlon, Duron:
 *
 *		Function 8000.0005 L1 TLB/Cache Information
 *		EAX -- L1 TLB 2/4MB pages
 *		EBX -- L1 TLB 4K pages
 *		ECX -- L1 D-cache
 *		EDX -- L1 I-cache
 *
 *		Function 8000.0006 L2 TLB/Cache Information
 *		EAX -- L2 TLB 2/4MB pages
 *		EBX -- L2 TLB 4K pages
 *		ECX -- L2 Unified cache
 *		EDX -- reserved
 *
 *	K5, K6:
 *
 *		Function 8000.0005 L1 TLB/Cache Information
 *		EAX -- reserved
 *		EBX -- TLB 4K pages
 *		ECX -- L1 D-cache
 *		EDX -- L1 I-cache
 *
 *	K6-III:
 *
 *		Function 8000.0006 L2 Cache Information
 *		EAX -- reserved
 *		EBX -- reserved
 *		ECX -- L2 Unified cache
 *		EDX -- reserved
 */

/* L1 TLB 2/4MB pages */
#define	AMD_L1_EAX_DTLB_ASSOC(x)	(((x) >> 24) & 0xff)
#define	AMD_L1_EAX_DTLB_ENTRIES(x)	(((x) >> 16) & 0xff)
#define	AMD_L1_EAX_ITLB_ASSOC(x)	(((x) >> 8)  & 0xff)
#define	AMD_L1_EAX_ITLB_ENTRIES(x)	( (x)        & 0xff)

/* L1 TLB 4K pages */
#define	AMD_L1_EBX_DTLB_ASSOC(x)	(((x) >> 24) & 0xff)
#define	AMD_L1_EBX_DTLB_ENTRIES(x)	(((x) >> 16) & 0xff)
#define	AMD_L1_EBX_ITLB_ASSOC(x)	(((x) >> 8)  & 0xff)
#define	AMD_L1_EBX_ITLB_ENTRIES(x)	( (x)        & 0xff)

/* L1 Data Cache */
#define	AMD_L1_ECX_DC_SIZE(x)		((((x) >> 24) & 0xff) * 1024)
#define	AMD_L1_ECX_DC_ASSOC(x)		 (((x) >> 16) & 0xff)
#define	AMD_L1_ECX_DC_LPT(x)		 (((x) >> 8)  & 0xff)
#define	AMD_L1_ECX_DC_LS(x)		 ( (x)        & 0xff)

/* L1 Instruction Cache */
#define	AMD_L1_EDX_IC_SIZE(x)		((((x) >> 24) & 0xff) * 1024)
#define	AMD_L1_EDX_IC_ASSOC(x)		 (((x) >> 16) & 0xff)
#define	AMD_L1_EDX_IC_LPT(x)		 (((x) >> 8)  & 0xff)
#define	AMD_L1_EDX_IC_LS(x)		 ( (x)        & 0xff)

/* Note for L2 TLB -- if the upper 16 bits are 0, it is a unified TLB */

/* L2 TLB 2/4MB pages */
#define	AMD_L2_EAX_DTLB_ASSOC(x)	(((x) >> 28)  & 0xf)
#define	AMD_L2_EAX_DTLB_ENTRIES(x)	(((x) >> 16)  & 0xfff)
#define	AMD_L2_EAX_IUTLB_ASSOC(x)	(((x) >> 12)  & 0xf)
#define	AMD_L2_EAX_IUTLB_ENTRIES(x)	( (x)         & 0xfff)

/* L2 TLB 4K pages */
#define	AMD_L2_EBX_DTLB_ASSOC(x)	(((x) >> 28)  & 0xf)
#define	AMD_L2_EBX_DTLB_ENTRIES(x)	(((x) >> 16)  & 0xfff)
#define	AMD_L2_EBX_IUTLB_ASSOC(x)	(((x) >> 12)  & 0xf)
#define	AMD_L2_EBX_IUTLB_ENTRIES(x)	( (x)         & 0xfff)

/* L2 Cache */
#define	AMD_L2_ECX_C_SIZE(x)		((((x) >> 16) & 0xffff) * 1024)
#define	AMD_L2_ECX_C_ASSOC(x)		 (((x) >> 12) & 0xf)
#define	AMD_L2_ECX_C_LPT(x)		 (((x) >> 8)  & 0xf)
#define	AMD_L2_ECX_C_LS(x)		 ( (x)        & 0xff)

/*
 * VIA Cache Info:
 *
 *	Nehemiah (at least)
 *
 *		Function 8000.0005 L1 TLB/Cache Information
 *		EAX -- reserved
 *		EBX -- L1 TLB 4K pages
 *		ECX -- L1 D-cache
 *		EDX -- L1 I-cache
 *
 *		Function 8000.0006 L2 Cache Information
 *		EAX -- reserved
 *		EBX -- reserved
 *		ECX -- L2 Unified cache
 *		EDX -- reserved
 */

/* L1 TLB 4K pages */
#define	VIA_L1_EBX_DTLB_ASSOC(x)	(((x) >> 24) & 0xff)
#define	VIA_L1_EBX_DTLB_ENTRIES(x)	(((x) >> 16) & 0xff)
#define	VIA_L1_EBX_ITLB_ASSOC(x)	(((x) >> 8)  & 0xff)
#define	VIA_L1_EBX_ITLB_ENTRIES(x)	( (x)        & 0xff)

/* L1 Data Cache */
#define	VIA_L1_ECX_DC_SIZE(x)		((((x) >> 24) & 0xff) * 1024)
#define	VIA_L1_ECX_DC_ASSOC(x)		 (((x) >> 16) & 0xff)
#define	VIA_L1_ECX_DC_LPT(x)		 (((x) >> 8)  & 0xff)
#define	VIA_L1_ECX_DC_LS(x)		 ( (x)        & 0xff)

/* L1 Instruction Cache */
#define	VIA_L1_EDX_IC_SIZE(x)		((((x) >> 24) & 0xff) * 1024)
#define	VIA_L1_EDX_IC_ASSOC(x)		 (((x) >> 16) & 0xff)
#define	VIA_L1_EDX_IC_LPT(x)		 (((x) >> 8)  & 0xff)
#define	VIA_L1_EDX_IC_LS(x)		 ( (x)        & 0xff)

/* L2 Cache (pre-Nehemiah) */
#define	VIA_L2_ECX_C_SIZE(x)		((((x) >> 24) & 0xff) * 1024)
#define	VIA_L2_ECX_C_ASSOC(x)		 (((x) >> 16) & 0xff)
#define	VIA_L2_ECX_C_LPT(x)		 (((x) >> 8)  & 0xff)
#define	VIA_L2_ECX_C_LS(x)		 ( (x)        & 0xff)

/* L2 Cache (Nehemiah and newer) */
#define	VIA_L2N_ECX_C_SIZE(x)		((((x) >> 16) & 0xffff) * 1024)
#define	VIA_L2N_ECX_C_ASSOC(x)		 (((x) >> 12) & 0xf)
#define	VIA_L2N_ECX_C_LPT(x)		 (((x) >> 8)  & 0xf)
#define	VIA_L2N_ECX_C_LS(x)		 ( (x)        & 0xff)

struct cpu_info {
	const char	*ci_dev;
	int32_t		ci_cpuid_level;
	uint32_t	ci_signature;	 /* X86 cpuid type */
	uint32_t	ci_feature_flags;/* X86 %edx CPUID feature bits */
	uint32_t	ci_feature2_flags;/* X86 %ecx CPUID feature bits */
	uint32_t	ci_feature3_flags;/* X86 extended feature bits */
	uint32_t	ci_padlock_flags;/* VIA PadLock feature bits */
	uint32_t	ci_cpu_class;	 /* CPU class */
	uint32_t	ci_brand_id;	 /* Intel brand id */
	uint32_t	ci_vendor[4];	 /* vendor string */
	uint32_t	ci_cpu_serial[3]; /* PIII serial number */
	uint64_t	ci_tsc_freq;	 /* cpu cycles/second */
	uint8_t		ci_packageid;
	uint8_t		ci_coreid;
	uint8_t		ci_smtid;
	uint32_t	ci_initapicid;
	struct x86_cache_info ci_cinfo[CAI_COUNT];
	void		(*ci_info)(struct cpu_info *);
};

struct cpu_nocpuid_nameclass {
	int cpu_vendor;
	const char *cpu_vendorname;
	const char *cpu_name;
	int cpu_class;
	void (*cpu_setup)(struct cpu_info *);
	void (*cpu_cacheinfo)(struct cpu_info *);
	void (*cpu_info)(struct cpu_info *);
};


struct cpu_cpuid_nameclass {
	const char *cpu_id;
	int cpu_vendor;
	const char *cpu_vendorname;
	struct cpu_cpuid_family {
		int cpu_class;
		const char *cpu_models[CPU_MAXMODEL+2];
		void (*cpu_setup)(struct cpu_info *);
		void (*cpu_probe)(struct cpu_info *);
		void (*cpu_info)(struct cpu_info *);
	} cpu_family[CPU_MAXFAMILY - CPU_MINFAMILY + 1];
};

static const struct x86_cache_info intel_cpuid_cache_info[] = {
	{ CAI_ITLB, 	0x01,	 4, 32,        4 * 1024, NULL },
	{ CAI_ITLB,     0xb0,    4,128,        4 * 1024, NULL },
	{ CAI_ITLB2, 	0x02, 0xff,  2, 4 * 1024 * 1024, NULL },
	{ CAI_DTLB, 	0x03,    4, 64,        4 * 1024, NULL },
	{ CAI_DTLB,     0xb3,    4,128,        4 * 1024, NULL },
	{ CAI_DTLB2,    0x04,    4,  8, 4 * 1024 * 1024, NULL },
	{ CAI_ITLB,     0x50, 0xff, 64,        4 * 1024, "4K/4M: 64 entries" },
	{ CAI_ITLB,     0x51, 0xff, 64,        4 * 1024, "4K/4M: 128 entries" },
	{ CAI_ITLB,     0x52, 0xff, 64,        4 * 1024, "4K/4M: 256 entries" },
	{ CAI_DTLB,     0x5b, 0xff, 64,        4 * 1024, "4K/4M: 64 entries" },
	{ CAI_DTLB,     0x5c, 0xff, 64,        4 * 1024, "4K/4M: 128 entries" },
	{ CAI_DTLB,     0x5d, 0xff, 64,        4 * 1024, "4K/4M: 256 entries" },
	{ CAI_ICACHE,   0x06,  4,        8 * 1024, 32, NULL },
	{ CAI_ICACHE,   0x08,  4,       16 * 1024, 32, NULL },
	{ CAI_ICACHE,   0x30,  8,       32 * 1024, 64, NULL },
	{ CAI_DCACHE,   0x0a,  2,        8 * 1024, 32, NULL },
	{ CAI_DCACHE,   0x0c,  4,       16 * 1024, 32, NULL },
	{ CAI_L2CACHE,  0x40,  0,               0,  0, "not present" },
	{ CAI_L2CACHE,  0x41,  4,      128 * 1024, 32, NULL },
	{ CAI_L2CACHE,  0x42,  4,      256 * 1024, 32, NULL },
	{ CAI_L2CACHE,  0x43,  4,      512 * 1024, 32, NULL },
	{ CAI_L2CACHE,  0x44,  4, 1 * 1024 * 1024, 32, NULL },
	{ CAI_L2CACHE,  0x45,  4, 2 * 1024 * 1024, 32, NULL },
	{ CAI_L2CACHE,  0x49, 16, 4 * 1024 * 1024, 64, NULL },
	{ CAI_DCACHE,   0x66,  4,        8 * 1024, 64, NULL },
	{ CAI_DCACHE,   0x67,  4,       16 * 1024, 64, NULL },
	{ CAI_DCACHE,   0x2c,  8,       32 * 1024, 64, NULL },
	{ CAI_DCACHE,   0x68,  4,  	32 * 1024, 64, NULL },
	{ CAI_ICACHE,   0x70,  8,       12 * 1024, 64, "12K uOp cache"},
	{ CAI_ICACHE,   0x71,  8,       16 * 1024, 64, "16K uOp cache"},
	{ CAI_ICACHE,   0x72,  8,       32 * 1024, 64, "32K uOp cache"},
	{ CAI_L2CACHE,  0x79,  8,      128 * 1024, 64, NULL },
	{ CAI_L2CACHE,  0x7a,  8,      256 * 1024, 64, NULL },
	{ CAI_L2CACHE,  0x7b,  8,      512 * 1024, 64, NULL },
	{ CAI_L2CACHE,  0x7c,  8, 1 * 1024 * 1024, 64, NULL },
	{ CAI_L2CACHE,  0x7d,  8, 2 * 1024 * 1024, 64, NULL },
	{ CAI_L2CACHE,  0x82,  8,      256 * 1024, 32, NULL },
	{ CAI_L2CACHE,  0x83,  8,      512 * 1024, 32, NULL },
	{ CAI_L2CACHE,  0x84,  8, 1 * 1024 * 1024, 32, NULL },
	{ CAI_L2CACHE,  0x85,  8, 2 * 1024 * 1024, 32, NULL },
	{ CAI_L2CACHE,  0x86,  4,      512 * 1024, 64, NULL },
	{ 0,               0,  0,	        0,  0, NULL },
};

/*
 * Map Brand ID from cpuid instruction to brand name.
 * Source: Intel Processor Identification and the CPUID Instruction, AP-485
 */
static const char * const i386_intel_brand[] = {
	"",		    /* Unsupported */
	"Celeron",	    /* Intel (R) Celeron (TM) processor */
	"Pentium III",      /* Intel (R) Pentium (R) III processor */
	"Pentium III Xeon", /* Intel (R) Pentium (R) III Xeon (TM) processor */
	"Pentium III",      /* Intel (R) Pentium (R) III processor */
	"",		    /* Reserved */
	"Mobile Pentium III", /* Mobile Intel (R) Pentium (R) III processor-M */
	"Mobile Celeron",   /* Mobile Intel (R) Celeron (R) processor */    
	"Pentium 4",	    /* Intel (R) Pentium (R) 4 processor */
	"Pentium 4",	    /* Intel (R) Pentium (R) 4 processor */
	"Celeron",	    /* Intel (R) Celeron (TM) processor */
	"Xeon",		    /* Intel (R) Xeon (TM) processor */
	"Xeon MP",	    /* Intel (R) Xeon (TM) processor MP */
	"",		    /* Reserved */
	"Mobile Pentium 4", /* Mobile Intel (R) Pentium (R) 4 processor-M */
	"Mobile Celeron",   /* Mobile Intel (R) Celeron (R) processor */
};

/*
 * AMD processors don't have Brand IDs, so we need these names for probe.
 */
static const char * const amd_brand[] = {
	"",
	"Duron",	/* AMD Duron(tm) */
	"MP",		/* AMD Athlon(tm) MP */
	"XP",		/* AMD Athlon(tm) XP */
	"4"		/* AMD Athlon(tm) 4 */
};

static int cpu_vendor;
static char cpu_brand_string[49];
static char amd_brand_name[48];

static void via_cpu_probe(struct cpu_info *);
static void amd_family6_probe(struct cpu_info *);
static void intel_family_new_probe(struct cpu_info *);
static const char *intel_family6_name(struct cpu_info *);
static const char *amd_amd64_name(struct cpu_info *);
static void amd_family5_setup(struct cpu_info *);
static void transmeta_cpu_info(struct cpu_info *);
static const char *print_cache_config(struct cpu_info *, int, const char *,
    const char *);
static const char *print_tlb_config(struct cpu_info *, int, const char *,
    const char *);
static void 	amd_cpu_cacheinfo(struct cpu_info *);
static void	via_cpu_cacheinfo(struct cpu_info *);
static void	x86_print_cacheinfo(struct cpu_info *);
static const struct x86_cache_info *cache_info_lookup(
    const struct x86_cache_info *, uint8_t);
static void cyrix6x86_cpu_setup(struct cpu_info *);
static void winchip_cpu_setup(struct cpu_info *);
static void amd_family5_setup(struct cpu_info *);

/*
 * Info for CTL_HW
 */
static char	cpu_model[120];

/*
 * Note: these are just the ones that may not have a cpuid instruction.
 * We deal with the rest in a different way.
 */
const struct cpu_nocpuid_nameclass i386_nocpuid_cpus[] = {
	{ CPUVENDOR_INTEL, "Intel", "386SX",	CPUCLASS_386,
	  NULL, NULL, NULL },			/* CPU_386SX */
	{ CPUVENDOR_INTEL, "Intel", "386DX",	CPUCLASS_386,
	  NULL, NULL, NULL },			/* CPU_386   */
	{ CPUVENDOR_INTEL, "Intel", "486SX",	CPUCLASS_486,
	  NULL, NULL, NULL },			/* CPU_486SX */
	{ CPUVENDOR_INTEL, "Intel", "486DX",	CPUCLASS_486,
	  NULL, NULL, NULL },			/* CPU_486   */
	{ CPUVENDOR_CYRIX, "Cyrix", "486DLC",	CPUCLASS_486,
	  NULL, NULL, NULL },			/* CPU_486DLC */
	{ CPUVENDOR_CYRIX, "Cyrix", "6x86",	CPUCLASS_486,
	  NULL, NULL, NULL },		/* CPU_6x86 */
	{ CPUVENDOR_NEXGEN,"NexGen","586",      CPUCLASS_386,
	  NULL, NULL, NULL },			/* CPU_NX586 */
};

const char *classnames[] = {
	"386",
	"486",
	"586",
	"686"
};

const char *modifiers[] = {
	"",
	"OverDrive",
	"Dual",
	""
};

const struct cpu_cpuid_nameclass i386_cpuid_cpus[] = {
	{
		"GenuineIntel",
		CPUVENDOR_INTEL,
		"Intel",
		/* Family 4 */
		{ {
			CPUCLASS_486,
			{
				"486DX", "486DX", "486SX", "486DX2", "486SL",
				"486SX2", 0, "486DX2 W/B Enhanced",
				"486DX4", 0, 0, 0, 0, 0, 0, 0,
				"486"		/* Default */
			},
			NULL,
			NULL,
			NULL,
		},
		/* Family 5 */
		{
			CPUCLASS_586,
			{
				"Pentium (P5 A-step)", "Pentium (P5)",
				"Pentium (P54C)", "Pentium (P24T)",
				"Pentium/MMX", "Pentium", 0,
				"Pentium (P54C)", "Pentium/MMX (Tillamook)",
				0, 0, 0, 0, 0, 0, 0,
				"Pentium"	/* Default */
			},
			NULL,
			NULL,
			NULL,
		},
		/* Family 6 */
		{
			CPUCLASS_686,
			{
				"Pentium Pro (A-step)", "Pentium Pro", 0,
				"Pentium II (Klamath)", "Pentium Pro",
				"Pentium II/Celeron (Deschutes)",
				"Celeron (Mendocino)",
				"Pentium III (Katmai)",
				"Pentium III (Coppermine)",
				"Pentium M (Banias)", 
				"Pentium III Xeon (Cascades)",
				"Pentium III (Tualatin)", 0,
				"Pentium M (Dothan)", 
				"Pentium M (Yonah)",
				"Core 2 (Merom)",
				"Pentium Pro, II or III"	/* Default */
			},
			NULL,
			intel_family_new_probe,
			NULL,
		},
		/* Family > 6 */
		{
			CPUCLASS_686,
			{
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				"Pentium 4"	/* Default */
			},
			NULL,
			intel_family_new_probe,
			NULL,
		} }
	},
	{
		"AuthenticAMD",
		CPUVENDOR_AMD,
		"AMD",
		/* Family 4 */
		{ {
			CPUCLASS_486,
			{
				0, 0, 0, "Am486DX2 W/T",
				0, 0, 0, "Am486DX2 W/B",
				"Am486DX4 W/T or Am5x86 W/T 150",
				"Am486DX4 W/B or Am5x86 W/B 150", 0, 0,
				0, 0, "Am5x86 W/T 133/160",
				"Am5x86 W/B 133/160",
				"Am486 or Am5x86"	/* Default */
			},
			NULL,
			NULL,
			NULL,
		},
		/* Family 5 */
		{
			CPUCLASS_586,
			{
				"K5", "K5", "K5", "K5", 0, 0, "K6",
				"K6", "K6-2", "K6-III", "Geode LX", 0, 0,
				"K6-2+/III+", 0, 0,
				"K5 or K6"		/* Default */
			},
			amd_family5_setup,
			NULL,
			amd_cpu_cacheinfo,
		},
		/* Family 6 */
		{
			CPUCLASS_686,
			{
				0, "Athlon Model 1", "Athlon Model 2",
				"Duron", "Athlon Model 4 (Thunderbird)",
				0, "Athlon", "Duron", "Athlon", 0,
				"Athlon", 0, 0, 0, 0, 0,
				"K7 (Athlon)"	/* Default */
			},
			NULL,
			amd_family6_probe,
			amd_cpu_cacheinfo,
		},
		/* Family > 6 */
		{
			CPUCLASS_686,
			{
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				"Unknown K8 (Athlon)"	/* Default */
			},
			NULL,
			amd_family6_probe,
			amd_cpu_cacheinfo,
		} }
	},
	{
		"CyrixInstead",
		CPUVENDOR_CYRIX,
		"Cyrix",
		/* Family 4 */
		{ {
			CPUCLASS_486,
			{
				0, 0, 0,
				"MediaGX",
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				"486"		/* Default */
			},
			cyrix6x86_cpu_setup, /* XXX ?? */
			NULL,
			NULL,
		},
		/* Family 5 */
		{
			CPUCLASS_586,
			{
				0, 0, "6x86", 0,
				"MMX-enhanced MediaGX (GXm)", /* or Geode? */
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				"6x86"		/* Default */
			},
			cyrix6x86_cpu_setup,
			NULL,
			NULL,
		},
		/* Family 6 */
		{
			CPUCLASS_686,
			{
				"6x86MX", 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				"6x86MX"		/* Default */
			},
			cyrix6x86_cpu_setup,
			NULL,
			NULL,
		},
		/* Family > 6 */
		{
			CPUCLASS_686,
			{
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				"Unknown 6x86MX"		/* Default */
			},
			NULL,
			NULL,
			NULL,
		} }
	},
	{	/* MediaGX is now owned by National Semiconductor */
		"Geode by NSC",
		CPUVENDOR_CYRIX, /* XXX */
		"National Semiconductor",
		/* Family 4, NSC never had any of these */
		{ {
			CPUCLASS_486,
			{
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				"486 compatible"	/* Default */
			},
			NULL,
			NULL,
			NULL,
		},
		/* Family 5: Geode family, formerly MediaGX */
		{
			CPUCLASS_586,
			{
				0, 0, 0, 0,
				"Geode GX1",
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				"Geode"		/* Default */
			},
			cyrix6x86_cpu_setup,
			NULL,
			amd_cpu_cacheinfo,
		},
		/* Family 6, not yet available from NSC */
		{
			CPUCLASS_686,
			{
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				"Pentium Pro compatible" /* Default */
			},
			NULL,
			NULL,
			NULL,
		},
		/* Family > 6, not yet available from NSC */
		{
			CPUCLASS_686,
			{
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				"Pentium Pro compatible"	/* Default */
			},
			NULL,
			NULL,
			NULL,
		} }
	},
	{
		"CentaurHauls",
		CPUVENDOR_IDT,
		"IDT",
		/* Family 4, IDT never had any of these */
		{ {
			CPUCLASS_486,
			{
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				"486 compatible"	/* Default */
			},
			NULL,
			NULL,
			NULL,
		},
		/* Family 5 */
		{
			CPUCLASS_586,
			{
				0, 0, 0, 0, "WinChip C6", 0, 0, 0,
				"WinChip 2", "WinChip 3", 0, 0, 0, 0, 0, 0,
				"WinChip"		/* Default */
			},
			winchip_cpu_setup,
			NULL,
			NULL,
		},
		/* Family 6, VIA acquired IDT Centaur design subsidiary */
		{
			CPUCLASS_686,
			{
				0, 0, 0, 0, 0, 0, "C3 Samuel",
				"C3 Samuel 2/Ezra", "C3 Ezra-T",
				"C3 Nehemiah", "C7 Esther", 0, 0, 0, 0, 0,
				"C3"	/* Default */
			},
			NULL,
			via_cpu_probe,
			via_cpu_cacheinfo,
		},
		/* Family > 6, not yet available from VIA */
		{
			CPUCLASS_686,
			{
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				"Pentium Pro compatible"	/* Default */
			},
			NULL,
			NULL,
			NULL,
		} }
	},
	{
		"GenuineTMx86",
		CPUVENDOR_TRANSMETA,
		"Transmeta",
		/* Family 4, Transmeta never had any of these */
		{ {
			CPUCLASS_486,
			{
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				"486 compatible"	/* Default */
			},
			NULL,
			NULL,
			NULL,
		},
		/* Family 5 */
		{
			CPUCLASS_586,
			{
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				"Crusoe"		/* Default */
			},
			NULL,
			NULL,
			transmeta_cpu_info,
		},
		/* Family 6, not yet available from Transmeta */
		{
			CPUCLASS_686,
			{
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				"Pentium Pro compatible"	/* Default */
			},
			NULL,
			NULL,
			NULL,
		},
		/* Family > 6, not yet available from Transmeta */
		{
			CPUCLASS_686,
			{
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				"Pentium Pro compatible"	/* Default */
			},
			NULL,
			NULL,
			NULL,
		} }
	}
};

/*
 * disable the TSC such that we don't use the TSC in microtime(9)
 * because some CPUs got the implementation wrong.
 */
static void
disable_tsc(struct cpu_info *ci)
{
	if (ci->ci_feature_flags & CPUID_TSC) {
		ci->ci_feature_flags &= ~CPUID_TSC;
		aprint_error("WARNING: broken TSC disabled\n");
	}
}

static void
cyrix6x86_cpu_setup(struct cpu_info *ci)
{

	/* 
	 * Do not disable the TSC on the Geode GX, it's reported to
	 * work fine.
	 */
	if (ci->ci_signature != 0x552)
		disable_tsc(ci);
}

void
winchip_cpu_setup(struct cpu_info *ci)
{
	switch (CPUID2MODEL(ci->ci_signature)) { /* model */
	case 4:	/* WinChip C6 */
		disable_tsc(ci);
	}
}


static void
identifycpu_cpuids(struct cpu_info *ci)
{
	const char *cpuname = ci->ci_dev;
	u_int lp_max = 1;	/* logical processors per package */
	u_int smt_max;		/* smt per core */
	u_int core_max = 1;	/* core per package */
	int smt_bits, core_bits;
	uint32_t descs[4];

	aprint_verbose("%s: Initial APIC ID %u\n", cpuname, ci->ci_initapicid);
	ci->ci_packageid = ci->ci_initapicid;
	ci->ci_coreid = 0;
	ci->ci_smtid = 0;
	if (cpu_vendor != CPUVENDOR_INTEL) {
		return;
	}

	/*
	 * 253668.pdf 7.10.2
	 */

	if ((ci->ci_feature_flags & CPUID_HTT) != 0) {
		x86_cpuid(1, descs);
		lp_max = (descs[1] >> 16) & 0xff;
	}
	x86_cpuid(0, descs);
	if (descs[0] >= 4) {
		x86_cpuid2(4, 0, descs);
		core_max = (descs[0] >> 26) + 1;
	}
	assert(lp_max >= core_max);
	smt_max = lp_max / core_max;
	smt_bits = ilog2(smt_max - 1) + 1;
	core_bits = ilog2(core_max - 1) + 1;
	if (smt_bits + core_bits) {
		ci->ci_packageid = ci->ci_initapicid >> (smt_bits + core_bits);
	}
	aprint_verbose("%s: Cluster/Package ID %u\n", cpuname,
	    ci->ci_packageid);
	if (core_bits) {
		u_int core_mask = __BITS(smt_bits, smt_bits + core_bits - 1);

		ci->ci_coreid =
		    __SHIFTOUT(ci->ci_initapicid, core_mask);
		aprint_verbose("%s: Core ID %u\n", cpuname, ci->ci_coreid);
	}
	if (smt_bits) {
		u_int smt_mask = __BITS(0, smt_bits - 1);

		ci->ci_smtid = __SHIFTOUT(ci->ci_initapicid, smt_mask);
		aprint_verbose("%s: SMT ID %u\n", cpuname, ci->ci_smtid);
	}
}

static void
via_cpu_probe(struct cpu_info *ci)
{
	u_int model = CPUID2MODEL(ci->ci_signature);
	u_int stepping = CPUID2STEPPING(ci->ci_signature);
	u_int descs[4];
	u_int lfunc;

	/*
	 * Determine the largest extended function value.
	 */
	x86_cpuid(0x80000000, descs);
	lfunc = descs[0];

	/*
	 * Determine the extended feature flags.
	 */
	if (lfunc >= 0x80000001) {
		x86_cpuid(0x80000001, descs);
		ci->ci_feature_flags |= descs[3];
	}

	if (model < 0x9)
		return;

	/* Nehemiah or Esther */
	x86_cpuid(0xc0000000, descs);
	lfunc = descs[0];
	if (lfunc < 0xc0000001)	/* no ACE, no RNG */
		return;

	x86_cpuid(0xc0000001, descs);
	lfunc = descs[3];
	if (model > 0x9 || stepping >= 8) {	/* ACE */
		if (lfunc & CPUID_VIA_HAS_ACE) {
			ci->ci_padlock_flags = lfunc;
		}
	}
}

static const char *
intel_family6_name(struct cpu_info *ci)
{
	int model = CPUID2MODEL(ci->ci_signature);
	const char *ret = NULL;
	u_int l2cache = ci->ci_cinfo[CAI_L2CACHE].cai_totalsize;

	if (model == 5) {
		switch (l2cache) {
		case 0:
		case 128 * 1024:
			ret = "Celeron (Covington)";
			break;
		case 256 * 1024:
			ret = "Mobile Pentium II (Dixon)";
			break;
		case 512 * 1024:
			ret = "Pentium II";
			break;
		case 1 * 1024 * 1024:
		case 2 * 1024 * 1024:
			ret = "Pentium II Xeon";
			break;
		}
	} else if (model == 6) {
		switch (l2cache) {
		case 256 * 1024:
		case 512 * 1024:
			ret = "Mobile Pentium II";
			break;
		}
	} else if (model == 7) {
		switch (l2cache) {
		case 512 * 1024:
			ret = "Pentium III";
			break;
		case 1 * 1024 * 1024:
		case 2 * 1024 * 1024:
			ret = "Pentium III Xeon";
			break;
		}
	} else if (model >= 8) {
		if (ci->ci_brand_id && ci->ci_brand_id < 0x10) {
			switch (ci->ci_brand_id) {
			case 0x3:
				if (ci->ci_signature == 0x6B1)
					ret = "Celeron";
				break;
			case 0x8:
				if (ci->ci_signature >= 0xF13)
					ret = "genuine processor";
				break;
			case 0xB:
				if (ci->ci_signature >= 0xF13)
					ret = "Xeon MP";
				break;
			case 0xE:
				if (ci->ci_signature < 0xF13)
					ret = "Xeon";
				break;
			}
			if (ret == NULL)
				ret = i386_intel_brand[ci->ci_brand_id];
		}
	}

	return ret;
}

/*
 * Identify AMD64 CPU names from cpuid.
 *
 * Based on:
 * "Revision Guide for AMD Athlon 64 and AMD Opteron Processors"
 * http://www.amd.com/us-en/assets/content_type/white_papers_and_tech_docs/25759.pdf
 * "Revision Guide for AMD NPT Family 0Fh Processors"
 * http://www.amd.com/us-en/assets/content_type/white_papers_and_tech_docs/33610.pdf
 * and other miscellaneous reports.
 */
static const char *
amd_amd64_name(struct cpu_info *ci)
{
	int extfamily, extmodel, model;
	const char *ret = NULL;

	model = CPUID2MODEL(ci->ci_signature);
	extfamily = CPUID2EXTFAMILY(ci->ci_signature);
	extmodel  = CPUID2EXTMODEL(ci->ci_signature);

	if (extfamily == 0x00) {
		switch (model) {
		case 0x1:
			switch (extmodel) {
			case 0x2:	/* rev JH-E1/E6 */
			case 0x4:	/* rev JH-F2 */
				ret = "Dual-Core Opteron";
				break;
			}
			break;
		case 0x3:
			switch (extmodel) {
			case 0x2:	/* rev JH-E6 (Toledo) */
				ret = "Dual-Core Opteron or Athlon 64 X2";
				break;
			case 0x4:	/* rev JH-F2 (Windsor) */
				ret = "Athlon 64 FX or Athlon 64 X2";
				break;
			}
			break;
		case 0x4:
			switch (extmodel) {
			case 0x0:	/* rev SH-B0/C0/CG (ClawHammer) */
			case 0x1:	/* rev SH-D0 */
				ret = "Athlon 64";
				break;
			case 0x2:	/* rev SH-E5 (Lancaster?) */
				ret = "Mobile Athlon 64 or Turion 64";
				break;
			}
			break;
		case 0x5:
			switch (extmodel) {
			case 0x0:	/* rev SH-B0/B3/C0/CG (SledgeHammer?) */
				ret = "Opteron or Athlon 64 FX";
				break;
			case 0x1:	/* rev SH-D0 */
			case 0x2:	/* rev SH-E4 */
				ret = "Opteron";
				break;
			}
			break;
		case 0x7:
			switch (extmodel) {
			case 0x0:	/* rev SH-CG (ClawHammer) */
			case 0x1:	/* rev SH-D0 */
				ret = "Athlon 64";
				break;
			case 0x2:	/* rev DH-E4, SH-E4 */
				ret = "Athlon 64 or Athlon 64 FX or Opteron";
				break;
			}
			break;
		case 0x8:
			switch (extmodel) {
			case 0x0:	/* rev CH-CG */
			case 0x1:	/* rev CH-D0 */
				ret = "Athlon 64 or Sempron";
				break;
			case 0x4:	/* rev BH-F2 */
				ret = "Turion 64 X2";
				break;
			}
			break;
		case 0xb:
			switch (extmodel) {
			case 0x0:	/* rev CH-CG */
			case 0x1:	/* rev CH-D0 */
				ret = "Athlon 64";
				break;
			case 0x2:	/* rev BH-E4 (Manchester) */
			case 0x4:	/* rev BH-F2 (Windsor) */
				ret = "Athlon 64 X2";
				break;
			case 0x6:	/* rev BH-G1 (Brisbane) */
				ret = "Athlon X2 or Athlon 64 X2";
				break;
			}
			break;
		case 0xc:
			switch (extmodel) {
			case 0x0:	/* rev DH-CG (Newcastle) */
			case 0x1:	/* rev DH-D0 (Winchester) */
			case 0x2:	/* rev DH-E3/E6 */
				ret = "Athlon 64 or Sempron";
				break;
			}
			break;
		case 0xe:
			switch (extmodel) {
			case 0x0:	/* rev DH-CG (Newcastle?) */
				ret = "Athlon 64 or Sempron";
				break;
			}
			break;
		case 0xf:
			switch (extmodel) {
			case 0x0:	/* rev DH-CG (Newcastle/Paris) */
			case 0x1:	/* rev DH-D0 (Winchester/Victoria) */
			case 0x2:	/* rev DH-E3/E6 (Venice/Palermo) */
			case 0x4:	/* rev DH-F2 (Orleans/Manila) */
			case 0x5:	/* rev DH-F2 (Orleans/Manila) */
			case 0x6:	/* rev DH-G1 */
				ret = "Athlon 64 or Sempron";
				break;
			}
			break;
		default:
			ret = "Unknown AMD64 CPU";
		}
	}

	return ret;
}

static void
cpu_probe_base_features(struct cpu_info *ci)
{
	const struct x86_cache_info *cai;
	u_int descs[4];
	int iterations, i, j;
	uint8_t desc;
	uint32_t miscbytes;
	uint32_t brand[12];

	if (ci->ci_cpuid_level < 0)
		return;

	x86_cpuid(0, descs);
	ci->ci_cpuid_level = descs[0];
	ci->ci_vendor[0] = descs[1];
	ci->ci_vendor[2] = descs[2];
	ci->ci_vendor[1] = descs[3];
	ci->ci_vendor[3] = 0;

	x86_cpuid(0x80000000, brand);
	if (brand[0] >= 0x80000004) {
		x86_cpuid(0x80000002, brand);
		x86_cpuid(0x80000003, brand + 4);
		x86_cpuid(0x80000004, brand + 8);
		for (i = 0; i < 48; i++)
			if (((char *) brand)[i] != ' ')
				break;
		memcpy(cpu_brand_string, ((char *) brand) + i, 48 - i);
	}

	if (ci->ci_cpuid_level < 1)
		return;

	x86_cpuid(1, descs);
	ci->ci_signature = descs[0];
	miscbytes = descs[1];
	ci->ci_feature2_flags = descs[2];
	ci->ci_feature_flags = descs[3];

	/* Brand is low order 8 bits of ebx */
	ci->ci_brand_id = miscbytes & 0xff;
	ci->ci_initapicid = (miscbytes >> 24) & 0xff;
	if (ci->ci_cpuid_level < 2)
		return;

	/*
	 * Parse the cache info from `cpuid', if we have it.
	 * XXX This is kinda ugly, but hey, so is the architecture...
	 */

	x86_cpuid(2, descs);

	iterations = descs[0] & 0xff;
	while (iterations-- > 0) {
		for (i = 0; i < 4; i++) {
			if (descs[i] & 0x80000000)
				continue;
			for (j = 0; j < 4; j++) {
				if (i == 0 && j == 0)
					continue;
				desc = (descs[i] >> (j * 8)) & 0xff;
				if (desc == 0)
					continue;
				cai = cache_info_lookup(intel_cpuid_cache_info,
				    desc);
				if (cai != NULL)
					ci->ci_cinfo[cai->cai_index] = *cai;
			}
		}
		x86_cpuid(2, descs);
	}

	if (ci->ci_cpuid_level < 3)
		return;

	/*
	 * If the processor serial number misfeature is present and supported,
	 * extract it here.
	 */
	if ((ci->ci_feature_flags & CPUID_PN) != 0) {
		ci->ci_cpu_serial[0] = ci->ci_signature;
		x86_cpuid(3, descs);
		ci->ci_cpu_serial[2] = descs[2];
		ci->ci_cpu_serial[1] = descs[3];
	}
}

static void
cpu_probe_features(struct cpu_info *ci)
{
	const struct cpu_cpuid_nameclass *cpup = NULL;
	int i, xmax, family;

	cpu_probe_base_features(ci);

	if (ci->ci_cpuid_level < 1)
		return;

	xmax = sizeof(__arraycount(i386_cpuid_cpus));
	for (i = 0; i < xmax; i++) {
		if (!strncmp((char *)ci->ci_vendor,
		    i386_cpuid_cpus[i].cpu_id, 12)) {
			cpup = &i386_cpuid_cpus[i];
			break;
		}
	}

	if (cpup == NULL)
		return;

	family = (ci->ci_signature >> 8) & 0xf;

	if (family > CPU_MAXFAMILY) {
		family = CPU_MAXFAMILY;
	}
	i = family - CPU_MINFAMILY;

	if (cpup->cpu_family[i].cpu_probe == NULL)
		return;

	(*cpup->cpu_family[i].cpu_probe)(ci);
}

static void
intel_family_new_probe(struct cpu_info *ci)
{
	uint32_t descs[4];

	x86_cpuid(0x80000000, descs);

	/*
	 * Determine extended feature flags.
	 */
	if (descs[0] >= 0x80000001) {
		x86_cpuid(0x80000001, descs);
		ci->ci_feature3_flags |= descs[3];
	}
}

static void
amd_family6_probe(struct cpu_info *ci)
{
	uint32_t descs[4];
	char *p;
	int i;

	x86_cpuid(0x80000000, descs);

	/*
	 * Determine the extended feature flags.
	 */
	if (descs[0] >= 0x80000001) {
		x86_cpuid(0x80000001, descs);
		ci->ci_feature_flags |= descs[3];
	}

	if (*cpu_brand_string == '\0')
		return;
	
	for (i = 1; i < sizeof(__arraycount(amd_brand)); i++)
		if ((p = strstr(cpu_brand_string, amd_brand[i])) != NULL) {
			ci->ci_brand_id = i;
			strlcpy(amd_brand_name, p, sizeof(amd_brand_name));
			break;
		}
}

static void
amd_family5_setup(struct cpu_info *ci)
{

	switch (CPUID2MODEL(ci->ci_signature)) {
	case 0:		/* AMD-K5 Model 0 */
		/*
		 * According to the AMD Processor Recognition App Note,
		 * the AMD-K5 Model 0 uses the wrong bit to indicate
		 * support for global PTEs, instead using bit 9 (APIC)
		 * rather than bit 13 (i.e. "0x200" vs. 0x2000".  Oops!).
		 */
		if (ci->ci_feature_flags & CPUID_APIC)
			ci->ci_feature_flags = (ci->ci_feature_flags & ~CPUID_APIC) | CPUID_PGE;
		/*
		 * XXX But pmap_pg_g is already initialized -- need to kick
		 * XXX the pmap somehow.  How does the MP branch do this?
		 */
		break;
	}
}

static void
tmx86_get_longrun_status(u_int *frequency, u_int *voltage, u_int *percentage)
{
	u_int descs[4];

	x86_cpuid(0x80860007, descs);
	*frequency = descs[0];
	*voltage = descs[1];
	*percentage = descs[2];
}

static void
transmeta_cpu_info(struct cpu_info *ci)
{
	u_int descs[4], nreg;
	u_int frequency, voltage, percentage;

	x86_cpuid(0x80860000, descs);
	nreg = descs[0];
	if (nreg >= 0x80860001) {
		x86_cpuid(0x80860001, descs);
		aprint_verbose_dev(ci->ci_dev, "Processor revision %u.%u.%u.%u\n",
		    (descs[1] >> 24) & 0xff,
		    (descs[1] >> 16) & 0xff,
		    (descs[1] >> 8) & 0xff,
		    descs[1] & 0xff);
	}
	if (nreg >= 0x80860002) {
		x86_cpuid(0x80860002, descs);
		aprint_verbose_dev(ci->ci_dev, "Code Morphing Software Rev: %u.%u.%u-%u-%u\n",
		    (descs[1] >> 24) & 0xff,
		    (descs[1] >> 16) & 0xff,
		    (descs[1] >> 8) & 0xff,
		    descs[1] & 0xff,
		    descs[2]);
	}
	if (nreg >= 0x80860006) {
		union {
			char text[65];
			u_int descs[4][4];
		} info;
		int i;

		for (i=0; i<4; i++) {
			x86_cpuid(0x80860003 + i, info.descs[i]);
		}
		info.text[64] = '\0';
		aprint_verbose_dev(ci->ci_dev, "%s\n", info.text);
	}

	if (nreg >= 0x80860007) {
		tmx86_get_longrun_status(&frequency,
		    &voltage, &percentage);
		aprint_verbose_dev(ci->ci_dev, "LongRun <%dMHz %dmV %d%%>\n",
		    frequency, voltage, percentage);
	}
}

void
identifycpu(const char *cpuname)
{
	const char *name, *modifier, *vendorname, *brand = "";
	int class = CPUCLASS_386, i, xmax;
	int modif, family, model;
	const struct cpu_cpuid_nameclass *cpup = NULL;
	const struct cpu_cpuid_family *cpufam;
	char *buf;
	const char *feature_str[3];
	struct cpu_info *ci, cistore;
	extern int cpu;
	extern int cpu_info_level;
	size_t sz;

	ci = &cistore;
	memset(ci, 0, sizeof(*ci));
	ci->ci_dev = cpuname;

	x86_identify();
	ci->ci_cpuid_level = cpu_info_level;
	cpu_probe_features(ci);

	buf = malloc(MAXPATHLEN);
	if (ci->ci_cpuid_level == -1) {
		if (cpu < 0 || cpu >= __arraycount(i386_nocpuid_cpus))
			errx(1, "unknown cpu type %d", cpu);
		name = i386_nocpuid_cpus[cpu].cpu_name;
		cpu_vendor = i386_nocpuid_cpus[cpu].cpu_vendor;
		vendorname = i386_nocpuid_cpus[cpu].cpu_vendorname;
		class = i386_nocpuid_cpus[cpu].cpu_class;
		ci->ci_info = i386_nocpuid_cpus[cpu].cpu_info;
		modifier = "";
	} else {
		xmax = __arraycount(i386_cpuid_cpus);
		modif = (ci->ci_signature >> 12) & 0x3;
		family = CPUID2FAMILY(ci->ci_signature);
		if (family < CPU_MINFAMILY)
			errx(1, "identifycpu: strange family value");
		model = CPUID2MODEL(ci->ci_signature);

		for (i = 0; i < xmax; i++) {
			if (!strncmp((char *)ci->ci_vendor,
			    i386_cpuid_cpus[i].cpu_id, 12)) {
				cpup = &i386_cpuid_cpus[i];
				break;
			}
		}

		if (cpup == NULL) {
			cpu_vendor = CPUVENDOR_UNKNOWN;
			if (ci->ci_vendor[0] != '\0')
				vendorname = (char *)&ci->ci_vendor[0];
			else
				vendorname = "Unknown";
			if (family >= CPU_MAXFAMILY)
				family = CPU_MINFAMILY;
			class = family - 3;
			modifier = "";
			name = "";
			ci->ci_info = NULL;
		} else {
			cpu_vendor = cpup->cpu_vendor;
			vendorname = cpup->cpu_vendorname;
			modifier = modifiers[modif];
			if (family > CPU_MAXFAMILY) {
				family = CPU_MAXFAMILY;
				model = CPU_DEFMODEL;
			} else if (model > CPU_MAXMODEL)
				model = CPU_DEFMODEL;
			cpufam = &cpup->cpu_family[family - CPU_MINFAMILY];
			name = cpufam->cpu_models[model];
			if (name == NULL)
			    name = cpufam->cpu_models[CPU_DEFMODEL];
			class = cpufam->cpu_class;
			ci->ci_info = cpufam->cpu_info;

			if (cpu_vendor == CPUVENDOR_INTEL) {
				if (family == 6 && model >= 5) {
					const char *tmp;
					tmp = intel_family6_name(ci);
					if (tmp != NULL)
						name = tmp;
				}
				if (family == CPU_MAXFAMILY &&
				    ci->ci_brand_id <
				    __arraycount(i386_intel_brand) &&
				    i386_intel_brand[ci->ci_brand_id])
					name =
					     i386_intel_brand[ci->ci_brand_id];
			}

			if (cpu_vendor == CPUVENDOR_AMD) {
				if (family == 6 && model >= 6) {
					if (ci->ci_brand_id == 1)
						/* 
						 * It's Duron. We override the 
						 * name, since it might have
						 * been misidentified as Athlon.
						 */
						name =
						    amd_brand[ci->ci_brand_id];
					else
						brand = amd_brand_name;
				}
				if (CPUID2FAMILY(ci->ci_signature) == 0xf) {
					/*
					 * Identify AMD64 CPU names.
					 * Note family value is clipped by
					 * CPU_MAXFAMILY.
					 */
					const char *tmp;
					tmp = amd_amd64_name(ci);
					if (tmp != NULL)
						name = tmp;
				}
			}
			
			if (cpu_vendor == CPUVENDOR_IDT && family >= 6)
				vendorname = "VIA";
		}
	}

	ci->ci_cpu_class = class;

	sz = sizeof(ci->ci_tsc_freq);
	(void)sysctlbyname("machdep.tsc_freq", &ci->ci_tsc_freq, &sz, NULL, 0);

	snprintf(cpu_model, sizeof(cpu_model), "%s%s%s%s%s%s%s (%s-class)",
	    vendorname,
	    *modifier ? " " : "", modifier,
	    *name ? " " : "", name,
	    *brand ? " " : "", brand,
	    classnames[class]);
	aprint_normal("%s: %s", cpuname, cpu_model);

	if (ci->ci_tsc_freq != 0)
		aprint_normal(", %qd.%02qd MHz",
		    (ci->ci_tsc_freq + 4999) / 1000000,
		    ((ci->ci_tsc_freq + 4999) / 10000) % 100);
	if (ci->ci_signature != 0)
		aprint_normal(", id 0x%x", ci->ci_signature);
	aprint_normal("\n");

	if (ci->ci_info)
		(*ci->ci_info)(ci);

	if (cpu_vendor == CPUVENDOR_INTEL) {
		feature_str[0] = CPUID_FLAGS1;
		feature_str[1] = CPUID_FLAGS2;
		feature_str[2] = CPUID_FLAGS3;
	} else {
		feature_str[0] = CPUID_FLAGS1;
		feature_str[1] = CPUID_EXT_FLAGS2;
		feature_str[2] = CPUID_EXT_FLAGS3;
	}	
	
	if (ci->ci_feature_flags) {
		if ((ci->ci_feature_flags & CPUID_MASK1) != 0) {
			bitmask_snprintf(ci->ci_feature_flags,
			    feature_str[0], buf, MAXPATHLEN);
			aprint_verbose("%s: features %s\n", cpuname, buf);
		}
		if ((ci->ci_feature_flags & CPUID_MASK2) != 0) {
			bitmask_snprintf(ci->ci_feature_flags,
			    feature_str[1], buf, MAXPATHLEN);
			aprint_verbose("%s: features %s\n", cpuname, buf);
		}
		if ((ci->ci_feature_flags & CPUID_MASK3) != 0) {
			bitmask_snprintf(ci->ci_feature_flags,
			    feature_str[2], buf, MAXPATHLEN);
			aprint_verbose("%s: features %s\n", cpuname, buf);
		}
	}

	if (ci->ci_feature2_flags) {
		bitmask_snprintf(ci->ci_feature2_flags,
		    CPUID2_FLAGS, buf, MAXPATHLEN);
		aprint_verbose("%s: features2 %s\n", cpuname, buf);
	}

	if (ci->ci_feature3_flags) {
		bitmask_snprintf(ci->ci_feature3_flags,
			CPUID_FLAGS4, buf, MAXPATHLEN);
		aprint_verbose("%s: features3 %s\n", cpuname, buf);
	}

	if (ci->ci_padlock_flags) {
		bitmask_snprintf(ci->ci_padlock_flags,
			CPUID_FLAGS_PADLOCK, buf, MAXPATHLEN);
		aprint_verbose("%s: padlock features %s\n", cpuname, buf);
	}

	free(buf);

	if (*cpu_brand_string != '\0')
		aprint_normal("%s: \"%s\"\n", cpuname, cpu_brand_string);

	x86_print_cacheinfo(ci);

	if (ci->ci_cpuid_level >= 3 && (ci->ci_feature_flags & CPUID_PN)) {
		aprint_verbose("%s: serial number %04X-%04X-%04X-%04X-%04X-%04X\n",
		    cpuname,
		    ci->ci_cpu_serial[0] / 65536, ci->ci_cpu_serial[0] % 65536,
		    ci->ci_cpu_serial[1] / 65536, ci->ci_cpu_serial[1] % 65536,
		    ci->ci_cpu_serial[2] / 65536, ci->ci_cpu_serial[2] % 65536);
	}

	if (ci->ci_cpu_class == CPUCLASS_386) {
		errx(1, "NetBSD requires an 80486 or later processor");
	}

	if (cpu == CPU_486DLC) {
#ifndef CYRIX_CACHE_WORKS
		aprint_error("WARNING: CYRIX 486DLC CACHE UNCHANGED.\n");
#else
#ifndef CYRIX_CACHE_REALLY_WORKS
		aprint_error("WARNING: CYRIX 486DLC CACHE ENABLED IN HOLD-FLUSH MODE.\n");
#else
		aprint_error("WARNING: CYRIX 486DLC CACHE ENABLED.\n");
#endif
#endif
	}

	/*
	 * Everything past this point requires a Pentium or later.
	 */
	if (ci->ci_cpuid_level < 0)
		return;

	identifycpu_cpuids(ci);

#ifdef INTEL_CORETEMP
	if (cpu_vendor == CPUVENDOR_INTEL && ci->ci_cpuid_level >= 0x06)
		coretemp_register(ci);
#endif

#if defined(POWERNOW_K7) || defined(POWERNOW_K8)
	if (cpu_vendor == CPUVENDOR_AMD && powernow_probe(ci)) {
		switch (CPUID2FAMILY(ci->ci_signature)) {
#ifdef POWERNOW_K7
		case 6:
			k7_powernow_init();
			break;
#endif
#ifdef POWERNOW_K8
		case 15:
			k8_powernow_init();
			break;
#endif
		default:
			break;
		}
	}
#endif /* POWERNOW_K7 || POWERNOW_K8 */

#ifdef INTEL_ONDEMAND_CLOCKMOD
	clockmod_init();
#endif
}

static const char *
print_cache_config(struct cpu_info *ci, int cache_tag, const char *name,
    const char *sep)
{
	struct x86_cache_info *cai = &ci->ci_cinfo[cache_tag];

	if (cai->cai_totalsize == 0)
		return sep;

	if (sep == NULL)
		aprint_verbose_dev(ci->ci_dev, "");
	else
		aprint_verbose("%s", sep);
	if (name != NULL)
		aprint_verbose("%s ", name);

	if (cai->cai_string != NULL) {
		aprint_verbose("%s ", cai->cai_string);
	} else {
		aprint_verbose("%dkB %dB/line ", cai->cai_totalsize / 1024,
		    cai->cai_linesize);
	}
	switch (cai->cai_associativity) {
	case    0:
		aprint_verbose("disabled");
		break;
	case    1:
		aprint_verbose("direct-mapped");
		break;
	case 0xff:
		aprint_verbose("fully associative");
		break;
	default:
		aprint_verbose("%d-way", cai->cai_associativity);
		break;
	}
	return ", ";
}

static const char *
print_tlb_config(struct cpu_info *ci, int cache_tag, const char *name,
    const char *sep)
{
	struct x86_cache_info *cai = &ci->ci_cinfo[cache_tag];

	if (cai->cai_totalsize == 0)
		return sep;

	if (sep == NULL)
		aprint_verbose_dev(ci->ci_dev, "");
	else
		aprint_verbose("%s", sep);
	if (name != NULL)
		aprint_verbose("%s ", name);

	if (cai->cai_string != NULL) {
		aprint_verbose("%s", cai->cai_string);
	} else {
		aprint_verbose("%d %dB entries ", cai->cai_totalsize,
		    cai->cai_linesize);
		switch (cai->cai_associativity) {
		case 0:
			aprint_verbose("disabled");
			break;
		case 1:
			aprint_verbose("direct-mapped");
			break;
		case 0xff:
			aprint_verbose("fully associative");
			break;
		default:
			aprint_verbose("%d-way", cai->cai_associativity);
			break;
		}
	}
	return ", ";
}

static const struct x86_cache_info *
cache_info_lookup(const struct x86_cache_info *cai, uint8_t desc)
{
	int i;

	for (i = 0; cai[i].cai_desc != 0; i++) {
		if (cai[i].cai_desc == desc)
			return (&cai[i]);
	}

	return (NULL);
}


static const struct x86_cache_info amd_cpuid_l2cache_assoc_info[] = {
	{ 0, 0x01,    1, 0, 0, NULL },
	{ 0, 0x02,    2, 0, 0, NULL },
	{ 0, 0x04,    4, 0, 0, NULL },
	{ 0, 0x06,    8, 0, 0, NULL },
	{ 0, 0x08,   16, 0, 0, NULL },
	{ 0, 0x0f, 0xff, 0, 0, NULL },
	{ 0, 0x00,    0, 0, 0, NULL },
};

static void
amd_cpu_cacheinfo(struct cpu_info *ci)
{
	const struct x86_cache_info *cp;
	struct x86_cache_info *cai;
	int family, model;
	u_int descs[4];
	u_int lfunc;

	family = (ci->ci_signature >> 8) & 15;
	model = CPUID2MODEL(ci->ci_signature);

	/*
	 * K5 model 0 has none of this info.
	 */
	if (family == 5 && model == 0)
		return;

	/*
	 * Get extended values for K8 and up.
	 */
	if (family == 0xf) {
		family += CPUID2EXTFAMILY(ci->ci_signature);
		model += CPUID2EXTMODEL(ci->ci_signature);
	}

	/*
	 * Determine the largest extended function value.
	 */
	x86_cpuid(0x80000000, descs);
	lfunc = descs[0];

	/*
	 * Determine L1 cache/TLB info.
	 */
	if (lfunc < 0x80000005) {
		/* No L1 cache info available. */
		return;
	}

	x86_cpuid(0x80000005, descs);

	/*
	 * K6-III and higher have large page TLBs.
	 */
	if ((family == 5 && model >= 9) || family >= 6) {
		cai = &ci->ci_cinfo[CAI_ITLB2];
		cai->cai_totalsize = AMD_L1_EAX_ITLB_ENTRIES(descs[0]);
		cai->cai_associativity = AMD_L1_EAX_ITLB_ASSOC(descs[0]);
		cai->cai_linesize = (4 * 1024 * 1024);

		cai = &ci->ci_cinfo[CAI_DTLB2];
		cai->cai_totalsize = AMD_L1_EAX_DTLB_ENTRIES(descs[0]);
		cai->cai_associativity = AMD_L1_EAX_DTLB_ASSOC(descs[0]);
		cai->cai_linesize = (4 * 1024 * 1024);
	}

	cai = &ci->ci_cinfo[CAI_ITLB];
	cai->cai_totalsize = AMD_L1_EBX_ITLB_ENTRIES(descs[1]);
	cai->cai_associativity = AMD_L1_EBX_ITLB_ASSOC(descs[1]);
	cai->cai_linesize = (4 * 1024);

	cai = &ci->ci_cinfo[CAI_DTLB];
	cai->cai_totalsize = AMD_L1_EBX_DTLB_ENTRIES(descs[1]);
	cai->cai_associativity = AMD_L1_EBX_DTLB_ASSOC(descs[1]);
	cai->cai_linesize = (4 * 1024);

	cai = &ci->ci_cinfo[CAI_DCACHE];
	cai->cai_totalsize = AMD_L1_ECX_DC_SIZE(descs[2]);
	cai->cai_associativity = AMD_L1_ECX_DC_ASSOC(descs[2]);
	cai->cai_linesize = AMD_L1_EDX_IC_LS(descs[2]);

	cai = &ci->ci_cinfo[CAI_ICACHE];
	cai->cai_totalsize = AMD_L1_EDX_IC_SIZE(descs[3]);
	cai->cai_associativity = AMD_L1_EDX_IC_ASSOC(descs[3]);
	cai->cai_linesize = AMD_L1_EDX_IC_LS(descs[3]);

	/*
	 * Determine L2 cache/TLB info.
	 */
	if (lfunc < 0x80000006) {
		/* No L2 cache info available. */
		return;
	}

	x86_cpuid(0x80000006, descs);

	cai = &ci->ci_cinfo[CAI_L2CACHE];
	cai->cai_totalsize = AMD_L2_ECX_C_SIZE(descs[2]);
	cai->cai_associativity = AMD_L2_ECX_C_ASSOC(descs[2]);
	cai->cai_linesize = AMD_L2_ECX_C_LS(descs[2]);

	cp = cache_info_lookup(amd_cpuid_l2cache_assoc_info,
	    cai->cai_associativity);
	if (cp != NULL)
		cai->cai_associativity = cp->cai_associativity;
	else
		cai->cai_associativity = 0;	/* XXX Unknown/reserved */
}

static void
via_cpu_cacheinfo(struct cpu_info *ci)
{
	struct x86_cache_info *cai;
	int family, model, stepping;
	u_int descs[4];
	u_int lfunc;

	family = (ci->ci_signature >> 8) & 15;
	model = CPUID2MODEL(ci->ci_signature);
	stepping = CPUID2STEPPING(ci->ci_signature);

	/*
	 * Determine the largest extended function value.
	 */
	x86_cpuid(0x80000000, descs);
	lfunc = descs[0];

	/*
	 * Determine L1 cache/TLB info.
	 */
	if (lfunc < 0x80000005) {
		/* No L1 cache info available. */
		return;
	}

	x86_cpuid(0x80000005, descs);

	cai = &ci->ci_cinfo[CAI_ITLB];
	cai->cai_totalsize = VIA_L1_EBX_ITLB_ENTRIES(descs[1]);
	cai->cai_associativity = VIA_L1_EBX_ITLB_ASSOC(descs[1]);
	cai->cai_linesize = (4 * 1024);

	cai = &ci->ci_cinfo[CAI_DTLB];
	cai->cai_totalsize = VIA_L1_EBX_DTLB_ENTRIES(descs[1]);
	cai->cai_associativity = VIA_L1_EBX_DTLB_ASSOC(descs[1]);
	cai->cai_linesize = (4 * 1024);

	cai = &ci->ci_cinfo[CAI_DCACHE];
	cai->cai_totalsize = VIA_L1_ECX_DC_SIZE(descs[2]);
	cai->cai_associativity = VIA_L1_ECX_DC_ASSOC(descs[2]);
	cai->cai_linesize = VIA_L1_EDX_IC_LS(descs[2]);
	if (model == 9 && stepping == 8) {
		/* Erratum: stepping 8 reports 4 when it should be 2 */
		cai->cai_associativity = 2;
	}

	cai = &ci->ci_cinfo[CAI_ICACHE];
	cai->cai_totalsize = VIA_L1_EDX_IC_SIZE(descs[3]);
	cai->cai_associativity = VIA_L1_EDX_IC_ASSOC(descs[3]);
	cai->cai_linesize = VIA_L1_EDX_IC_LS(descs[3]);
	if (model == 9 && stepping == 8) {
		/* Erratum: stepping 8 reports 4 when it should be 2 */
		cai->cai_associativity = 2;
	}

	/*
	 * Determine L2 cache/TLB info.
	 */
	if (lfunc < 0x80000006) {
		/* No L2 cache info available. */
		return;
	}

	x86_cpuid(0x80000006, descs);

	cai = &ci->ci_cinfo[CAI_L2CACHE];
	if (model >= 9) {
		cai->cai_totalsize = VIA_L2N_ECX_C_SIZE(descs[2]);
		cai->cai_associativity = VIA_L2N_ECX_C_ASSOC(descs[2]);
		cai->cai_linesize = VIA_L2N_ECX_C_LS(descs[2]);
	} else {
		cai->cai_totalsize = VIA_L2_ECX_C_SIZE(descs[2]);
		cai->cai_associativity = VIA_L2_ECX_C_ASSOC(descs[2]);
		cai->cai_linesize = VIA_L2_ECX_C_LS(descs[2]);
	}
}

static void
x86_print_cacheinfo(struct cpu_info *ci)
{
	const char *sep;

	if (ci->ci_cinfo[CAI_ICACHE].cai_totalsize != 0 ||
	    ci->ci_cinfo[CAI_DCACHE].cai_totalsize != 0) {
		sep = print_cache_config(ci, CAI_ICACHE, "I-cache", NULL);
		sep = print_cache_config(ci, CAI_DCACHE, "D-cache", sep);
		if (sep != NULL)
			aprint_verbose("\n");
	}
	if (ci->ci_cinfo[CAI_L2CACHE].cai_totalsize != 0) {
		sep = print_cache_config(ci, CAI_L2CACHE, "L2 cache", NULL);
		if (sep != NULL)
			aprint_verbose("\n");
	}
	if (ci->ci_cinfo[CAI_ITLB].cai_totalsize != 0) {
		sep = print_tlb_config(ci, CAI_ITLB, "ITLB", NULL);
		sep = print_tlb_config(ci, CAI_ITLB2, NULL, sep);
		if (sep != NULL)
			aprint_verbose("\n");
	}
	if (ci->ci_cinfo[CAI_DTLB].cai_totalsize != 0) {
		sep = print_tlb_config(ci, CAI_DTLB, "DTLB", NULL);
		sep = print_tlb_config(ci, CAI_DTLB2, NULL, sep);
		if (sep != NULL)
			aprint_verbose("\n");
	}
}

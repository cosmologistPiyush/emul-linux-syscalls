/* This file is automatically generated.  DO NOT EDIT! */
/* Generated from: 	NetBSD: mknative-gcc,v 1.17 2006/05/15 22:03:03 mrg Exp  */
/* and from: NetBSD: mknative.common,v 1.7 2006/05/17 03:27:19 mrg Exp  */

#ifndef GCC_TM_H
#define GCC_TM_H
#define TARGET_CPU_DEFAULT (SELECT_SH3)
#ifndef NETBSD_ENABLE_PTHREADS
# define NETBSD_ENABLE_PTHREADS
#endif
#ifndef SH_MULTILIB_CPU_DEFAULT
# define SH_MULTILIB_CPU_DEFAULT "m3"
#endif
#ifndef SUPPORT_SH3
# define SUPPORT_SH3 1
#endif
#ifndef SUPPORT_SH3E
# define SUPPORT_SH3E 1
#endif
#ifndef SUPPORT_SH4
# define SUPPORT_SH4 1
#endif
#ifndef SUPPORT_SH3
# define SUPPORT_SH3 1
#endif
#ifdef IN_GCC
# include "options.h"
# include "config/sh/sh.h"
# include "config/dbxelf.h"
# include "config/elfos.h"
# include "config/sh/elf.h"
# include "config/netbsd.h"
# include "config/netbsd-elf.h"
# include "config/sh/netbsd-elf.h"
# include "defaults.h"
#endif
#if defined IN_GCC && !defined GENERATOR_FILE && !defined USED_FOR_TARGET
# include "insn-constants.h"
# include "insn-flags.h"
#endif
#endif /* GCC_TM_H */

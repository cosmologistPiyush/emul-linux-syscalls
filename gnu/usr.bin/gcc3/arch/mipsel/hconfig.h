/* This file is automatically generated.  DO NOT EDIT! */
/* Generated from: 	NetBSD: mknative-gcc,v 1.1 2003/07/25 16:26:53 mrg Exp  */

#define TARGET_CPU_DEFAULT ((MASK_GAS|MASK_ABICALLS|MASK_GAS))
#ifndef TARGET_ENDIAN_DEFAULT
# define TARGET_ENDIAN_DEFAULT 0
#endif
#include "auto-build.h"
#ifdef IN_GCC
/* Provide three core typedefs used by everything, if we are compiling
   GCC.  These used to be found in rtl.h and tree.h, but this is no
   longer practical.  Providing these here rather that system.h allows
   the typedefs to be used everywhere within GCC. */
struct rtx_def;
typedef struct rtx_def *rtx;
struct rtvec_def;
typedef struct rtvec_def *rtvec;
union tree_node;
typedef union tree_node *tree;
#endif
#define GTY(x)
#ifdef IN_GCC
# include "ansidecl.h"
# include "elfos.h"
# include "mips/mips.h"
# include "mips/netbsd.h"
# include "defaults.h"
#endif
#ifndef POSIX
# define POSIX
#endif

# This file is automatically generated.  DO NOT EDIT!
# Generated from: 	NetBSD: mknative-gcc,v 1.22 2006/06/25 03:06:15 mrg Exp 
# Generated from: NetBSD: mknative.common,v 1.8 2006/05/26 19:17:21 mrg Exp 
#
G_INCLUDES=-I. -I. -I${GNUHOSTDIST}/gcc -I${GNUHOSTDIST}/gcc/. -I${GNUHOSTDIST}/gcc/../include -I${GNUHOSTDIST}/gcc/../libcpp/include 
G_LIB2ADD=
G_LIB2ADDEH=${GNUHOSTDIST}/gcc/unwind-dw2.c ${GNUHOSTDIST}/gcc/unwind-dw2-fde.c ${GNUHOSTDIST}/gcc/unwind-sjlj.c ${GNUHOSTDIST}/gcc/gthr-gnat.c ${GNUHOSTDIST}/gcc/unwind-c.c
G_LIB1ASMFUNCS=_sdivsi3 _sdivsi3_i4 _udivsi3 _udivsi3_i4 _set_fpscr _shcompact_call_trampoline _shcompact_return_trampoline _shcompact_incoming_args _ic_invalidate _nested_trampoline _push_pop_shmedia_regs _udivdi3 _divdi3 _umoddi3 _moddi3 _div_table
G_LIB1ASMSRC=sh/lib1funcs.asm
G_LIB2_DIVMOD_FUNCS=_divdi3 _moddi3 _udivdi3 _umoddi3 _udiv_w_sdiv _udivmoddi4
G_LIB2FUNCS_ST=_eprintf __gcc_bcmp
G_LIBGCC2_CFLAGS=-O2   -DIN_GCC    -W -Wall -Wwrite-strings -Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition  -isystem ./include  -fpic -g -DHAVE_GTHR_DEFAULT -DIN_LIBGCC2 -D__GCC_FLOAT_NOT_NEEDED 
G_SHLIB_MKMAP=${GNUHOSTDIST}/gcc/mkmap-symver.awk
G_SHLIB_MKMAP_OPTS=
G_SHLIB_MAPFILES=${GNUHOSTDIST}/gcc/config/sh/libgcc-std.ver
G_SHLIB_NM_FLAGS=-pg
G_EXTRA_HEADERS=
G_xm_defines=
G_tm_defines=NETBSD_ENABLE_PTHREADS SH_MULTILIB_CPU_DEFAULT="m5-32media" SUPPORT_SH5_32MEDIA=1 SUPPORT_SH5_32MEDIA_NOFPU=1 SUPPORT_SH5_64MEDIA=1 SUPPORT_SH5_64MEDIA_NOFPU=1 SUPPORT_SH5_32MEDIA=1
G_COLLECT2=collect2
G_UNWIND_H=${GNUHOSTDIST}/gcc/unwind-generic.h
G_xm_include_list=auto-host.h ansidecl.h

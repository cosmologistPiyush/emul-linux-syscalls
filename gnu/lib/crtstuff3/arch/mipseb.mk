# This file is automatically generated.  DO NOT EDIT!
# Generated from: 	NetBSD: mknative-gcc,v 1.14 2004/08/24 20:24:43 thorpej Exp 
#
G_INCLUDES=-I. -I. -I${GNUHOSTDIST}/gcc -I${GNUHOSTDIST}/gcc/.  -I${GNUHOSTDIST}/gcc/config -I${GNUHOSTDIST}/gcc/../include
G_CRTSTUFF_CFLAGS=-O2 -DIN_GCC   -W -Wall -Wwrite-strings -Wstrict-prototypes -Wmissing-prototypes -isystem ./include  -I. -I. -I${GNUHOSTDIST}/gcc -I${GNUHOSTDIST}/gcc/.  -I${GNUHOSTDIST}/gcc/config -I${GNUHOSTDIST}/gcc/../include  -g0  -finhibit-size-directive -fno-inline-functions -fno-exceptions  -fno-zero-initialized-in-bss
G_CRTSTUFF_T_CFLAGS=-fPIC
G_tm_defines=NETBSD_ENABLE_PTHREADS
G_xm_file=ansidecl.h  elfos.h mips/mips.h mips/netbsd.h defaults.h
G_xm_defines=POSIX

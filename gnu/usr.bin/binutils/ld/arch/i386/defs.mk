# This file is automatically generated.  DO NOT EDIT!
# Generated from: 	NetBSD: toolchain2netbsd,v 1.6 2001/08/06 19:58:25 tv Exp 
#
G_DEFS=-DHAVE_CONFIG_H -I. -I${DIST}/ld -I.
G_EMUL=elf_i386
G_EMULATION_OFILES=eelf_i386.o ei386nbsd.o
G_INCLUDES=-D_GNU_SOURCE -I. -I${DIST}/ld -I../bfd -I${DIST}/ld/../bfd -I${DIST}/ld/../include -I${DIST}/ld/../intl -I../intl  -g -O2 -DLOCALEDIR="\"/usr/local/share/locale\""
G_OFILES=ldgram.o ldlex.o lexsup.o ldlang.o mri.o ldctor.o ldmain.o 	ldwrite.o ldexp.o  ldemul.o ldver.o ldmisc.o 	ldfile.o ldcref.o eelf_i386.o ei386nbsd.o 
G_STRINGIFY=astring.sed
G_TEXINFOS=ld.texinfo
G_target_alias=i386-unknown-netbsdelf

#	$NetBSD: bfd-h.sed,v 1.6 1999/02/02 20:00:39 tv Exp $
# Preparse bfd.h such that it can be used on multiple machines.

s/@VERSION@/2.9.1/
/@wordsize@/{
	i\
#if defined(__alpha__) || defined (__sparc_v9__)\
#define BFD_ARCH_SIZE 64\
#else\
#define BFD_ARCH_SIZE 32\
#endif
	d
}
/@BFD_HOST_64BIT_LONG@/ {
	i\
#if defined(__alpha__) || defined (__sparc_v9__)\
#define BFD_HOST_64BIT_LONG 1\
#else\
#define BFD_HOST_64BIT_LONG 0\
#endif
	d
}
s/@BFD_HOST_64_BIT_DEFINED@/1/
s/@BFD_HOST_64_BIT@/long long/
s/@BFD_HOST_U_64_BIT@/unsigned long long/

/*	$NetBSD: report.h,v 1.2 1998/01/09 08:09:15 perry Exp $	*/

/* report.h */

#ifdef	__STDC__
#define P(args) args
#else
#define P(args) ()
#endif

extern void report_init P((int nolog));
extern void report P((int, char *, ...));
extern char *get_errmsg P((void));

#undef P

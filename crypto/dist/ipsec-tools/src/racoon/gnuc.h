/*	$NetBSD: gnuc.h,v 1.5 2022/04/21 19:14:46 rillig Exp $	*/

/* Id: gnuc.h,v 1.4 2004/11/18 15:14:44 ludvigm Exp */

/* Define __P() macro, if necessary */
#undef __P
#ifndef __P
#if __STDC__
#define __P(protos) protos
#else
#define __P(protos) ()
#endif
#endif

/* inline foo */
#if defined(__GNUC__) || defined(lint)
#define inline __inline
#else
#define inline
#endif

/*
 * Handle new and old "dead" routine prototypes
 *
 * For example:
 *
 *	__dead void foo(void) __attribute__((volatile));
 *
 */
#ifdef __GNUC__
#ifndef __dead
#define __dead volatile
#endif
#if __GNUC__ < 2  || (__GNUC__ == 2 && __GNUC_MINOR__ < 5)
#ifndef __attribute__
#define __attribute__(args)
#endif
#endif
#else
#ifndef __dead
#define __dead
#endif
#ifndef __attribute__
#define __attribute__(args)
#endif
#endif

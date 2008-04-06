/*	$NetBSD: icmp_var.h,v 1.26 2008/04/06 19:04:50 thorpej Exp $	*/

/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)icmp_var.h	8.1 (Berkeley) 6/10/93
 */

#ifndef _NETINET_ICMP_VAR_H_
#define _NETINET_ICMP_VAR_H_

/*
 * Variables related to this implementation
 * of the internet control message protocol.
 */

/*
 * ICMP stastistics.
 * Each counter is an unsigned 64-bit value.
 */
#define	ICMP_STAT_ERROR		0	/* # of calls to icmp_error */
#define	ICMP_STAT_OLDSHORT	1	/* no error (old ip too short) */
#define	ICMP_STAT_OLDICMP	2	/* no error (old was icmp) */
#define	ICMP_STAT_OUTHIST	3	/* # of output messages */
		/* space for ICMP_MAXTYPE + 1 (19) counters */
#define	ICMP_STAT_BADCODE	22	/* icmp_code out of range */
#define	ICMP_STAT_TOOSHORT	23	/* packet < ICMP_MINLEN */
#define	ICMP_STAT_CHECKSUM	24	/* bad checksum */
#define	ICMP_STAT_BADLEN	25	/* calculated bound mismatch */
#define	ICMP_STAT_REFLECT	26	/* number of responses */
#define	ICMP_STAT_INHIST	27	/* # of input messages */
		/* space for ICMP_MAXTYPE + 1 (19) counters */
#define	ICMP_STAT_PMTUCHG	46	/* path MTU changes */

#define	ICMP_NSTATS		47

#if ICMP_MAXTYPE != 18
#error ICMP_MAXTYPE too large for ICMP statistics
#endif

/*
 * Names for ICMP sysctl objects
 */
#define	ICMPCTL_MASKREPL	1	/* allow replies to netmask requests */
#if 0	/*obsoleted*/
#define ICMPCTL_ERRRATELIMIT	2	/* error rate limit */
#endif
#define ICMPCTL_RETURNDATABYTES	3	/* # of bytes to include in errors */
#define ICMPCTL_ERRPPSLIMIT	4	/* ICMP error pps limitation */
#define ICMPCTL_REDIRACCEPT	5	/* Accept redirects from routers */
#define ICMPCTL_REDIRTIMEOUT	6	/* Remove routes added via redirects */
#define	ICMPCTL_STATS		7	/* ICMP statistics */
#define ICMPCTL_MAXID		8

#define ICMPCTL_NAMES { \
	{ 0, 0 }, \
	{ "maskrepl", CTLTYPE_INT }, \
	{ 0, 0 }, \
	{ "returndatabytes", CTLTYPE_INT }, \
	{ "errppslimit", CTLTYPE_INT }, \
	{ "rediraccept", CTLTYPE_INT }, \
	{ "redirtimeout", CTLTYPE_INT }, \
	{ "stats", CTLTYPE_STRUCT }, \
}

#ifdef _KERNEL
extern uint64_t	icmpstat[ICMP_NSTATS];

#ifdef __NO_STRICT_ALIGNMENT
#define	ICMP_HDR_ALIGNED_P(ic)	1
#else
#define	ICMP_HDR_ALIGNED_P(ic)	((((vaddr_t) (ic)) & 3) == 0)
#endif
#endif /* _KERNEL_ */

#endif /* !_NETINET_ICMP_VAR_H_ */

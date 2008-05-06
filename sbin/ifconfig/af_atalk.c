/*	$NetBSD: af_atalk.c,v 1.8 2008/05/06 15:02:49 dyoung Exp $	*/

/*
 * Copyright (c) 1983, 1993
 *      The Regents of the University of California.  All rights reserved.
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
 */

#ifndef INET_ONLY

#include <sys/cdefs.h>
#ifndef lint
__RCSID("$NetBSD: af_atalk.c,v 1.8 2008/05/06 15:02:49 dyoung Exp $");
#endif /* not lint */

#include <sys/param.h> 
#include <sys/ioctl.h> 
#include <sys/socket.h>

#include <net/if.h> 

#include <netatalk/at.h>

#include <err.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <util.h>

#include "env.h"
#include "parse.h"
#include "extern.h"
#include "af_atalk.h"

struct ifaliasreq at_addreq __attribute__((aligned(4)));
static struct netrange at_nr;	/* AppleTalk net range */

struct pinteger phase = PINTEGER_INITIALIZER1(&phase, "phase",
    1, 2, 10, setatphase, "phase", &command_root.pb_parser);

struct pstr parse_range = PSTR_INITIALIZER(&range, "range", setatrange, "range",
    &command_root.pb_parser);

void
at_getaddr(const struct paddr_prefix *pfx, int which)
{
	if (which == MASK)
		errx(EXIT_FAILURE, "AppleTalk does not use netmasks");

	memcpy(&at_addreq.ifra_addr, &pfx->pfx_addr,
	    MIN(sizeof(at_addreq.ifra_addr), pfx->pfx_addr.sa_len));
}

int
setatrange(prop_dictionary_t env, prop_dictionary_t xenv)
{
	char range[24];
	u_short	first = 123, last = 123;

	if (getargstr(env, "range", range, sizeof(range)) == -1)
		return -1;

	if (sscanf(range, "%hu-%hu", &first, &last) != 2 ||
	    first == 0 || last == 0 || first > last)
		errx(EXIT_FAILURE, "%s: illegal net range: %u-%u", range,
		    first, last);
	at_nr.nr_firstnet = htons(first);
	at_nr.nr_lastnet = htons(last);
	return 0;
}

int
setatphase(prop_dictionary_t env, prop_dictionary_t xenv)
{
	prop_number_t num;

	num = (prop_number_t)prop_dictionary_get(env, "phase");
	if (num == NULL) {
		errno = ENOENT;
		return -1;
	}
	at_nr.nr_phase = (uint8_t)prop_number_integer_value(num);
	return 0;
}

void
checkatrange(struct sockaddr *sa)
{
	struct sockaddr_at *sat = (struct sockaddr_at *) sa;

	if (at_nr.nr_phase == 0)
		at_nr.nr_phase = 2;	/* Default phase 2 */
	if (at_nr.nr_firstnet == 0)
		at_nr.nr_firstnet =	/* Default range of one */
		at_nr.nr_lastnet = sat->sat_addr.s_net;
	printf("\tatalk %d.%d range %d-%d phase %d\n",
	    ntohs(sat->sat_addr.s_net), sat->sat_addr.s_node,
	    ntohs(at_nr.nr_firstnet), ntohs(at_nr.nr_lastnet), at_nr.nr_phase);
	if (ntohs(at_nr.nr_firstnet) > ntohs(sat->sat_addr.s_net) ||
	    ntohs(at_nr.nr_lastnet) < ntohs(sat->sat_addr.s_net))
		errx(EXIT_FAILURE, "AppleTalk address is not in range");
	*((struct netrange *)&sat->sat_zero) = at_nr;
}

void
at_status(prop_dictionary_t env, prop_dictionary_t oenv, int force)
{
	struct sockaddr_at *sat, null_sat;
	struct netrange *nr;
	struct ifreq ifr;
	int af, s;
	const char *ifname;
	unsigned short flags;

	if ((s = getsock(AF_APPLETALK)) == -1) {
		if (errno == EAFNOSUPPORT)
			return;
		err(EXIT_FAILURE, "getsock");
	}
	if ((ifname = getifinfo(env, oenv, &flags)) == NULL)
		err(EXIT_FAILURE, "%s: getifinfo", __func__);

	if ((af = getaf(env)) == -1)
		af = AF_APPLETALK;
	else if (af != AF_APPLETALK)
		return;

	memset(&ifr, 0, sizeof(ifr));
	estrlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_addr.sa_family = af;
	if (ioctl(s, SIOCGIFADDR, &ifr) == -1) {
		if (errno == EADDRNOTAVAIL || errno == EAFNOSUPPORT) {
			if (!force)
				return;
			(void) memset(&ifr.ifr_addr, 0, sizeof(ifr.ifr_addr));
		} else
			warn("SIOCGIFADDR");
	}
	estrlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	sat = (struct sockaddr_at *)&ifr.ifr_addr;

	(void) memset(&null_sat, 0, sizeof(null_sat));

	nr = (struct netrange *) &sat->sat_zero;
	printf("\tatalk %d.%d range %d-%d phase %d",
	    ntohs(sat->sat_addr.s_net), sat->sat_addr.s_node,
	    ntohs(nr->nr_firstnet), ntohs(nr->nr_lastnet), nr->nr_phase);

	if (flags & IFF_POINTOPOINT) {
		if (ioctl(s, SIOCGIFDSTADDR, &ifr) == -1) {
			if (errno == EADDRNOTAVAIL)
				memset(&ifr.ifr_addr, 0, sizeof(ifr.ifr_addr));
			else
				warn("SIOCGIFDSTADDR");
		}
		estrlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		sat = (struct sockaddr_at *)&ifr.ifr_dstaddr;
		if (!sat)
			sat = &null_sat;
		printf("--> %d.%d",
		    ntohs(sat->sat_addr.s_net), sat->sat_addr.s_node);
	}
	if (flags & IFF_BROADCAST) {
		/* note RTAX_BRD overlap with IFF_POINTOPOINT */
		sat = (struct sockaddr_at *)&ifr.ifr_broadaddr;
		if (sat)
			printf(" broadcast %d.%d", ntohs(sat->sat_addr.s_net),
			    sat->sat_addr.s_node);
	}
	printf("\n");
}

#endif /* ! INET_ONLY */

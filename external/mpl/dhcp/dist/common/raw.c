/*	$NetBSD: raw.c,v 1.4 2022/04/03 01:10:58 christos Exp $	*/

/* raw.c

   BSD raw socket interface code... */

/* XXX

   It's not clear how this should work, and that lack of clarity is
   terribly detrimental to the NetBSD 1.1 kernel - it crashes and
   burns.

   Using raw sockets ought to be a big win over using BPF or something
   like it, because you don't need to deal with the complexities of
   the physical layer, but it appears not to be possible with existing
   raw socket implementations.  This may be worth revisiting in the
   future.  For now, this code can probably be considered a curiosity.
   Sigh. */

/*
 * Copyright (C) 2004-2022 Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1995-2003 by Internet Software Consortium
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *   Internet Systems Consortium, Inc.
 *   PO Box 360
 *   Newmarket, NH 03857 USA
 *   <info@isc.org>
 *   https://www.isc.org/
 *
 */

#include <sys/cdefs.h>
__RCSID("$NetBSD: raw.c,v 1.4 2022/04/03 01:10:58 christos Exp $");

#include "dhcpd.h"

#if defined (USE_RAW_SEND)
#include <sys/uio.h>

/* Generic interface registration routine... */
void if_register_send (info)
	struct interface_info *info;
{
	struct sockaddr_in name;
	int sock;
	struct socklist *tmp;
	int flag;

	/* Set up the address we're going to connect to. */
	name.sin_family = AF_INET;
	name.sin_port = relay_port ? relay_port : *libdhcp_callbacks.local_port;
	name.sin_addr.s_addr = htonl (INADDR_BROADCAST);
	memset (name.sin_zero, 0, sizeof (name.sin_zero));

	/* List addresses on which we're listening. */
        if (!quiet_interface_discovery)
		log_info ("Sending on %s, port %d",
		      piaddr (info -> address), htons (name.sin_port));
	if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		log_fatal ("Can't create dhcp socket: %m");

	/* Set the BROADCAST option so that we can broadcast DHCP responses. */
	flag = 1;
	if (setsockopt (sock, SOL_SOCKET, SO_BROADCAST,
			&flag, sizeof flag) < 0)
		log_fatal ("Can't set SO_BROADCAST option on dhcp socket: %m");

	/* Set the IP_HDRINCL flag so that we can supply our own IP
	   headers... */
	if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, &flag, sizeof flag) < 0)
		log_fatal ("Can't set IP_HDRINCL flag: %m");

	info -> wfdesc = sock;
        if (!quiet_interface_discovery)
		log_info ("Sending on   Raw/%s%s%s",
		      info -> name,
		      (info -> shared_network ? "/" : ""),
		      (info -> shared_network ?
		       info -> shared_network -> name : ""));
}

void if_deregister_send (info)
	struct interface_info *info;
{
	close (info -> wfdesc);
	info -> wfdesc = -1;

        if (!quiet_interface_discovery)
		log_info ("Disabling output on Raw/%s%s%s",
		      info -> name,
		      (info -> shared_network ? "/" : ""),
		      (info -> shared_network ?
		       info -> shared_network -> name : ""));
}

size_t send_packet (interface, packet, raw, len, from, to, hto)
	struct interface_info *interface;
	struct packet *packet;
	struct dhcp_packet *raw;
	size_t len;
	struct in_addr from;
	struct sockaddr_in *to;
	struct hardware *hto;
{
	unsigned char buf [256];
	int bufp = 0;
	struct iovec iov [2];
	int result;

	/* Assemble the headers... */
	assemble_udp_ip_header (interface, buf, &bufp, from.s_addr,
				to -> sin_addr.s_addr, to -> sin_port,
				(unsigned char *)raw, len);

	/* Fire it off */
	iov [0].iov_base = (char *)buf;
	iov [0].iov_len = bufp;
	iov [1].iov_base = (char *)raw;
	iov [1].iov_len = len;

	result = writev(interface -> wfdesc, iov, 2);
	if (result < 0)
		log_error ("send_packet: %m");
	return result;
}
#endif /* USE_SOCKET_SEND */

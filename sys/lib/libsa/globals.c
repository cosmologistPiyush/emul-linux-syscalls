/*	$NetBSD: globals.c,v 1.12 2022/04/24 06:52:59 mlelstv Exp $	*/

/*
 *	globals.c:
 *
 *	global variables should be separate, so nothing else
 *	must be included extraneously.
 */

#include <sys/param.h>
#include <net/if_ether.h>		/* for ETHER_ADDR_LEN */
#include <netinet/in.h>
#include <netinet/in_systm.h>

#include "stand.h"
#include "net.h"

u_char	bcea[ETHER_ADDR_LEN] = BA;	/* broadcast ethernet address */

char	rootpath[FNAME_SIZE];		/* root mount path */
char	bootfile[FNAME_SIZE];		/* bootp says to boot this */
char	hostname[FNAME_SIZE];		/* our hostname */
struct	in_addr myip;			/* my ip address */
struct	in_addr rootip;			/* root ip address */
struct	in_addr gateip;			/* swap ip address */
n_long	netmask = 0xffffff00;		/* subnet or net mask */
